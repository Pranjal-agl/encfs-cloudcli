#include "file_contents.h"
#include "crypto.h"
#include "util.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace encfs {

namespace {
constexpr size_t kNonce = 12;
constexpr size_t kTag = 16;

bool PreadAll(int fd, uint8_t* buf, size_t len, uint64_t off) {
    while (len > 0) {
        ssize_t n = ::pread(fd, buf, len, static_cast<off_t>(off));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        buf += n;
        len -= static_cast<size_t>(n);
        off += static_cast<uint64_t>(n);
    }
    return true;
}

bool PwriteAll(int fd, const uint8_t* buf, size_t len, uint64_t off) {
    while (len > 0) {
        ssize_t n = ::pwrite(fd, buf, len, static_cast<off_t>(off));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        buf += n;
        len -= static_cast<size_t>(n);
        off += static_cast<uint64_t>(n);
    }
    return true;
}

std::vector<uint8_t> IndexAad(uint64_t index) {
    std::vector<uint8_t> aad;
    AppendU64LE(aad, index);
    return aad;
}
} // namespace

FileContents::FileContents(std::unique_ptr<ChunkedReader> base, size_t chunk_size,
                           std::string scratch_dir, size_t cache_bytes)
    : base_(std::move(base)),
      chunk_size_(chunk_size),
      scratch_dir_(std::move(scratch_dir)),
      max_slots_(std::max<size_t>(2, cache_bytes / std::max<size_t>(1, chunk_size))) {
    if (base_) {
        size_ = base_->plaintext_size();
        base_limit_ = size_;
    }
}

FileContents::~FileContents() {
    for (auto& [index, slot] : cache_) SecureWipe(slot.data);
    SecureWipe(scratch_key_);
    if (scratch_fd_ >= 0) ::close(scratch_fd_);
}

uint64_t FileContents::max_size() const {
    return static_cast<uint64_t>(chunk_size_) * (static_cast<uint64_t>(UINT32_MAX) + 1);
}

uint64_t FileContents::ChunkCount() const {
    return std::max<uint64_t>(1, (size_ + chunk_size_ - 1) / chunk_size_);
}

// ── Scratch file ────────────────────────────────────────────────────────────
// Slot i lives at offset i * (12 + chunk_size + 16): nonce | ciphertext | tag,
// sealed with a random in-memory key and the chunk index as AAD.

bool FileContents::EnsureScratch() {
    if (scratch_fd_ >= 0) return true;
#ifdef O_TMPFILE
    scratch_fd_ = ::open(scratch_dir_.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
#endif
    if (scratch_fd_ < 0) {
        // No O_TMPFILE support: create a uniquely named file and unlink it at once.
        std::string tmpl = scratch_dir_ + "/.scratch.XXXXXX";
        std::vector<char> name(tmpl.begin(), tmpl.end());
        name.push_back('\0');
        scratch_fd_ = ::mkostemp(name.data(), O_CLOEXEC);
        if (scratch_fd_ < 0) return false;
        ::unlink(name.data());
    }
    scratch_key_ = KeyManager::RandomBytes(32);
    return true;
}

bool FileContents::SpillChunk(uint64_t index, const std::vector<uint8_t>& data) {
    if (!EnsureScratch()) return false;
    std::vector<uint8_t> sealed = SimpleCrypto::Encrypt(data, scratch_key_, IndexAad(index));
    const uint64_t off = index * (kNonce + chunk_size_ + kTag);
    if (!PwriteAll(scratch_fd_, sealed.data(), sealed.size(), off)) return false;
    spilled_.insert(index);
    return true;
}

bool FileContents::UnspillChunk(uint64_t index, std::vector<uint8_t>& out) {
    std::vector<uint8_t> sealed(kNonce + chunk_size_ + kTag);
    const uint64_t off = index * sealed.size();
    if (!PreadAll(scratch_fd_, sealed.data(), sealed.size(), off)) return false;
    try {
        out = SimpleCrypto::Decrypt(sealed, scratch_key_, IndexAad(index));
    } catch (const std::exception&) {
        return false;
    }
    return out.size() == chunk_size_;
}

// ── Chunk access ────────────────────────────────────────────────────────────

bool FileContents::LoadInto(uint64_t index, std::vector<uint8_t>& out) {
    auto cached = cache_.find(index);
    if (cached != cache_.end()) {
        out = cached->second.data;
        return true;
    }
    if (spilled_.count(index)) return UnspillChunk(index, out);

    out.assign(chunk_size_, 0);
    const uint64_t start = index * chunk_size_;
    if (base_ && start < base_limit_) {
        std::vector<uint8_t> plain;
        if (!base_->ReadChunk(index, plain)) return false;  // authentication failure
        size_t keep = static_cast<size_t>(std::min<uint64_t>(plain.size(), base_limit_ - start));
        std::memcpy(out.data(), plain.data(), keep);
        SecureWipe(plain);
    }
    return true;
}

bool FileContents::EvictOne() {
    auto victim = cache_.begin();
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->second.last_use < victim->second.last_use) victim = it;
    }
    if (victim == cache_.end()) return true;
    if (victim->second.dirty && !SpillChunk(victim->first, victim->second.data)) return false;
    SecureWipe(victim->second.data);
    cache_.erase(victim);
    return true;
}

FileContents::Slot* FileContents::Get(uint64_t index) {
    auto it = cache_.find(index);
    if (it == cache_.end()) {
        if (cache_.size() >= max_slots_ && !EvictOne()) return nullptr;
        Slot slot;
        bool from_scratch = spilled_.count(index) > 0;
        if (!LoadInto(index, slot.data)) return nullptr;
        slot.dirty = from_scratch;  // its only up-to-date copy is in scratch
        it = cache_.emplace(index, std::move(slot)).first;
    }
    it->second.last_use = ++clock_;
    return &it->second;
}

int64_t FileContents::Read(uint64_t offset, uint8_t* buf, size_t len) {
    if (offset >= size_) return 0;
    len = static_cast<size_t>(std::min<uint64_t>({len, size_ - offset, static_cast<uint64_t>(INT64_MAX)}));
    size_t done = 0;
    while (done < len) {
        const uint64_t pos = offset + done;
        const uint64_t index = pos / chunk_size_;
        Slot* slot = Get(index);
        if (!slot) return -1;
        const size_t in_chunk = static_cast<size_t>(pos - index * chunk_size_);
        const size_t n = std::min(len - done, chunk_size_ - in_chunk);
        std::memcpy(buf + done, slot->data.data() + in_chunk, n);
        done += n;
    }
    return static_cast<int64_t>(done);
}

bool FileContents::Write(uint64_t offset, const uint8_t* buf, size_t len) {
    if (len == 0) return true;
    if (offset > max_size() || len > max_size() - offset) return false;
    size_t done = 0;
    while (done < len) {
        const uint64_t pos = offset + done;
        const uint64_t index = pos / chunk_size_;
        Slot* slot = Get(index);
        if (!slot) return false;
        const size_t in_chunk = static_cast<size_t>(pos - index * chunk_size_);
        const size_t n = std::min(len - done, chunk_size_ - in_chunk);
        std::memcpy(slot->data.data() + in_chunk, buf + done, n);
        slot->dirty = true;
        done += n;
    }
    size_ = std::max(size_, offset + len);
    return true;
}

bool FileContents::Truncate(uint64_t new_size) {
    if (new_size > max_size()) return false;
    if (new_size < size_) {
        // Drop every chunk that now lies entirely past the end.
        const uint64_t keep = (new_size + chunk_size_ - 1) / chunk_size_;
        for (auto it = cache_.begin(); it != cache_.end();) {
            if (it->first >= keep) {
                SecureWipe(it->second.data);
                it = cache_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = spilled_.begin(); it != spilled_.end();) {
            it = (*it >= keep) ? spilled_.erase(it) : std::next(it);
        }
        // Zero the tail of the new last chunk, so growing later reads zeros.
        if (new_size % chunk_size_ != 0) {
            const uint64_t index = new_size / chunk_size_;
            Slot* slot = Get(index);
            if (!slot) return false;
            const size_t from = static_cast<size_t>(new_size - index * chunk_size_);
            std::memset(slot->data.data() + from, 0, chunk_size_ - from);
            slot->dirty = true;
        }
        base_limit_ = std::min(base_limit_, new_size);
    }
    size_ = new_size;
    return true;
}

bool FileContents::ForEachChunk(const std::function<bool(const uint8_t*, size_t, bool)>& sink) {
    const uint64_t count = ChunkCount();
    std::vector<uint8_t> chunk;
    bool ok = true;
    for (uint64_t i = 0; i < count && ok; ++i) {
        const bool last = (i + 1 == count);
        const size_t len = static_cast<size_t>(std::min<uint64_t>(chunk_size_, size_ - i * chunk_size_));
        ok = LoadInto(i, chunk) && sink(chunk.data(), len, last);
    }
    SecureWipe(chunk);
    return ok;
}

void FileContents::Rebase(std::unique_ptr<ChunkedReader> new_base) {
    base_ = std::move(new_base);
    base_limit_ = size_;
    spilled_.clear();
    if (scratch_fd_ >= 0 && ::ftruncate(scratch_fd_, 0) != 0) {
        // Not fatal: stale slots are never read once forgotten.
    }
    for (auto& [index, slot] : cache_) slot.dirty = false;
}

} // namespace encfs

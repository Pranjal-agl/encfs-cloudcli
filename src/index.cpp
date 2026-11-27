#include "index.h"
#include "crypto.h"
#include "util.h"

#include <cerrno>
#include <sys/stat.h>

namespace encfs {

namespace {
constexpr uint32_t kMaxNameLen = 1024 * 1024;
constexpr uint32_t kMaxRemoteIdLen = 1024;
} // namespace

EncryptedIndex::EncryptedIndex(const std::string& backing_dir, const std::vector<uint8_t>& key)
    : index_path_(backing_dir + "/index.enc"), key_(key) {
}

std::vector<uint8_t> EncryptedIndex::DeriveIndexKey() const {
    // Separate key for the index, derived from the master key.
    return KeyManager::DeriveSubkey(key_, "encfs_index_key_derivation");
}

// Format (all integers little-endian):
//   count:u32, then per entry:
//   name_len:u32 | name | remote_id_len:u32 | remote_id | version:u64 | size:u64 | mtime:i64
std::vector<uint8_t> EncryptedIndex::Serialize() const {
    std::vector<uint8_t> out;
    AppendU32LE(out, static_cast<uint32_t>(index_.size()));
    for (const auto& [name, meta] : index_) {
        AppendU32LE(out, static_cast<uint32_t>(name.size()));
        out.insert(out.end(), name.begin(), name.end());
        AppendU32LE(out, static_cast<uint32_t>(meta.remote_id.size()));
        out.insert(out.end(), meta.remote_id.begin(), meta.remote_id.end());
        AppendU64LE(out, meta.version);
        AppendU64LE(out, meta.size);
        AppendU64LE(out, static_cast<uint64_t>(meta.mtime));
    }
    return out;
}

bool EncryptedIndex::Deserialize(const std::vector<uint8_t>& data, ForwardMap& fwd, ReverseMap& rev) {
    size_t pos = 0;
    auto need = [&](size_t n) { return data.size() - pos >= n; };

    if (!need(4)) return false;
    uint32_t count = LoadU32LE(data.data());
    pos += 4;

    for (uint32_t i = 0; i < count; ++i) {
        if (!need(4)) return false;
        uint32_t name_len = LoadU32LE(data.data() + pos);
        pos += 4;
        if (name_len > kMaxNameLen || !need(name_len)) return false;
        std::string name(data.begin() + pos, data.begin() + pos + name_len);
        pos += name_len;

        if (!need(4)) return false;
        uint32_t id_len = LoadU32LE(data.data() + pos);
        pos += 4;
        if (id_len > kMaxRemoteIdLen || !need(id_len)) return false;
        std::string remote_id(data.begin() + pos, data.begin() + pos + id_len);
        pos += id_len;

        if (!need(24)) return false;
        FileMetadata meta;
        meta.remote_id = remote_id;
        meta.version = LoadU64LE(data.data() + pos);
        meta.size = LoadU64LE(data.data() + pos + 8);
        meta.mtime = static_cast<int64_t>(LoadU64LE(data.data() + pos + 16));
        pos += 24;

        fwd[name] = meta;
        rev[remote_id] = name;
    }
    return pos == data.size();
}

bool EncryptedIndex::FileExists() const {
    struct stat st;
    return ::stat(index_path_.c_str(), &st) == 0;
}

bool EncryptedIndex::Load() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<uint8_t> encrypted;
    if (!ReadWholeFile(index_path_, encrypted)) {
        return errno == ENOENT;  // no index yet → start empty
    }
    if (encrypted.empty()) {
        return true;
    }

    try {
        std::vector<uint8_t> plain = SimpleCrypto::Decrypt(encrypted, DeriveIndexKey());
        ForwardMap fwd;
        ReverseMap rev;
        bool ok = Deserialize(plain, fwd, rev);
        SecureWipe(plain);
        if (!ok) return false;
        index_.swap(fwd);
        reverse_index_.swap(rev);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool EncryptedIndex::Save() {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        std::vector<uint8_t> plain = Serialize();
        std::vector<uint8_t> encrypted = SimpleCrypto::Encrypt(plain, DeriveIndexKey());
        SecureWipe(plain);
        return WriteFileAtomic(index_path_, encrypted);
    } catch (const std::exception&) {
        return false;
    }
}

bool EncryptedIndex::GetMetadata(const std::string& plaintext_name, FileMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.find(plaintext_name);
    if (it == index_.end()) {
        return false;
    }
    metadata = it->second;
    return true;
}

void EncryptedIndex::SetMetadata(const std::string& plaintext_name, const FileMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto old_it = index_.find(plaintext_name);
    if (old_it != index_.end()) {
        reverse_index_.erase(old_it->second.remote_id);
    }
    index_[plaintext_name] = metadata;
    reverse_index_[metadata.remote_id] = plaintext_name;
}

bool EncryptedIndex::GetPlaintextName(const std::string& remote_id, std::string& plaintext_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = reverse_index_.find(remote_id);
    if (it == reverse_index_.end()) {
        return false;
    }
    plaintext_name = it->second;
    return true;
}

void EncryptedIndex::Remove(const std::string& plaintext_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.find(plaintext_name);
    if (it != index_.end()) {
        reverse_index_.erase(it->second.remote_id);
        index_.erase(it);
    }
}

bool EncryptedIndex::Exists(const std::string& plaintext_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    return index_.find(plaintext_name) != index_.end();
}

uint64_t EncryptedIndex::IncrementVersion(const std::string& plaintext_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.find(plaintext_name);
    if (it != index_.end()) {
        it->second.version++;
        return it->second.version;
    }
    return 1;
}

std::vector<std::string> EncryptedIndex::GetAllPlaintextNames() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    names.reserve(index_.size());
    for (const auto& pair : index_) {
        names.push_back(pair.first);
    }
    return names;
}

size_t EncryptedIndex::Size() {
    std::lock_guard<std::mutex> lock(mutex_);
    return index_.size();
}

} // namespace encfs

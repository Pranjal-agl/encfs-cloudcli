#include "index.h"
#include "crypto.h"
#include "util.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/stat.h>

namespace encfs {

namespace {
constexpr uint32_t kMaxNameLen = 1024 * 1024;
constexpr uint32_t kMaxIdLen = 1024;
const uint8_t kMagicV2[4] = {'E', 'I', 'X', '2'};
const uint8_t kMagicV3[4] = {'E', 'I', 'X', '3'};
constexpr uint32_t kMaxSegments = 1u << 24;

std::string ParentOf(const std::string& path) {
    auto slash = path.find_last_of('/');
    return slash == std::string::npos ? std::string() : path.substr(0, slash);
}

std::string BaseName(const std::string& path) {
    auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

void AppendString(std::vector<uint8_t>& out, const std::string& s) {
    AppendU32LE(out, static_cast<uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

struct Reader {
    const std::vector<uint8_t>& d;
    size_t pos = 0;
    bool ok = true;
    bool Need(size_t n) {
        if (!ok || d.size() - pos < n) ok = false;
        return ok;
    }
    uint8_t U8() { return Need(1) ? d[pos++] : 0; }
    uint32_t U32() {
        if (!Need(4)) return 0;
        uint32_t v = LoadU32LE(d.data() + pos);
        pos += 4;
        return v;
    }
    uint64_t U64() {
        if (!Need(8)) return 0;
        uint64_t v = LoadU64LE(d.data() + pos);
        pos += 8;
        return v;
    }
    std::string Str(uint32_t max) {
        uint32_t n = U32();
        if (n > max || !Need(n)) {
            ok = false;
            return {};
        }
        std::string s(d.begin() + static_cast<long>(pos), d.begin() + static_cast<long>(pos + n));
        pos += n;
        return s;
    }
};
} // namespace

std::string NewInodeId() {
    std::vector<uint8_t> r = KeyManager::RandomBytes(32);
    return HexEncode(r.data(), r.size());
}

EncryptedIndex::EncryptedIndex(const std::string& backing_dir, const std::vector<uint8_t>& key)
    : index_path_(backing_dir + "/index.enc"), key_(key) {
}

void EncryptedIndex::Retarget(const std::string& backing_dir, const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(mutex_);
    index_path_ = backing_dir + "/index.enc";
    SecureWipe(key_);
    key_ = key;
}

std::vector<uint8_t> EncryptedIndex::DeriveIndexKey() const {
    return KeyManager::DeriveSubkey(key_, "encfs_index_key_derivation");
}

// ── State helpers ───────────────────────────────────────────────────────────

void EncryptedIndex::AddPath(State& s, const std::string& path, const std::string& id) {
    s.paths[path] = id;
    s.children[ParentOf(path)].insert(BaseName(path));
}

void EncryptedIndex::RemovePath(State& s, const std::string& path) {
    s.paths.erase(path);
    auto it = s.children.find(ParentOf(path));
    if (it != s.children.end()) {
        it->second.erase(BaseName(path));
        if (it->second.empty()) s.children.erase(it);
    }
}

// Recompute link counts from the paths and drop unreferenced inodes.
void EncryptedIndex::Relink(State& s) {
    for (auto& [id, meta] : s.inodes) meta.nlink = 0;
    for (const auto& [path, id] : s.paths) s.inodes[id].nlink++;
    for (auto it = s.inodes.begin(); it != s.inodes.end();) {
        it = it->second.nlink == 0 ? s.inodes.erase(it) : std::next(it);
    }
}

// ── Serialization ───────────────────────────────────────────────────────────

std::vector<uint8_t> EncryptedIndex::SerializeLocked() const {
    std::vector<uint8_t> out(kMagicV3, kMagicV3 + 4);
    AppendU64LE(out, state_.generation);
    AppendU32LE(out, static_cast<uint32_t>(state_.inodes.size()));
    for (const auto& [id, m] : state_.inodes) {
        AppendString(out, id);
        out.push_back(static_cast<uint8_t>(m.type));
        AppendU64LE(out, m.version);
        AppendU64LE(out, m.size);
        AppendU64LE(out, static_cast<uint64_t>(m.mtime));
        AppendU32LE(out, m.mode);
        AppendString(out, m.target);
        AppendU32LE(out, m.segment_size);
        AppendU32LE(out, m.chunk_size);
        AppendU32LE(out, static_cast<uint32_t>(m.segments.size()));
        for (uint64_t v : m.segments) AppendU64LE(out, v);
    }
    AppendU32LE(out, static_cast<uint32_t>(state_.paths.size()));
    for (const auto& [path, id] : state_.paths) {
        AppendString(out, path);
        AppendString(out, id);
    }
    return out;
}

bool EncryptedIndex::Deserialize(const std::vector<uint8_t>& data, State& out) {
    const bool v3 = data.size() >= 4 && std::memcmp(data.data(), kMagicV3, 4) == 0;
    const bool v2 = data.size() >= 4 && std::memcmp(data.data(), kMagicV2, 4) == 0;
    if (!v2 && !v3) return DeserializeV1(data, out);

    Reader r{data};
    r.pos = 4;
    State s;
    s.generation = r.U64();
    const uint32_t inode_count = r.U32();
    for (uint32_t i = 0; i < inode_count && r.ok; ++i) {
        FileMetadata m;
        m.remote_id = r.Str(kMaxIdLen);
        uint8_t type = r.U8();
        if (type < 1 || type > 3 || m.remote_id.empty()) return false;
        m.type = static_cast<EntryType>(type);
        m.version = r.U64();
        m.size = r.U64();
        m.mtime = static_cast<int64_t>(r.U64());
        m.mode = r.U32() & 07777;
        m.target = r.Str(kMaxNameLen);
        if (v3) {
            m.segment_size = r.U32();
            m.chunk_size = r.U32();
            const uint32_t n = r.U32();
            // A segmented layout has both a size and at least one segment,
            // and only files have one.
            if (n > kMaxSegments || (n > 0) != (m.segment_size > 0)) return false;
            if (n > 0 && !m.IsFile()) return false;
            // Segments are whole chunks.
            if (n > 0 && (m.chunk_size == 0 || m.chunk_size > ChunkedCrypto::MAX_CHUNK_SIZE ||
                          m.segment_size % m.chunk_size != 0)) {
                return false;
            }
            for (uint32_t k = 0; k < n && r.ok; ++k) m.segments.push_back(r.U64());
        }
        m.nlink = 0;
        if (!r.ok || s.inodes.count(m.remote_id)) return false;
        s.inodes[m.remote_id] = m;
    }
    const uint32_t path_count = r.U32();
    for (uint32_t i = 0; i < path_count && r.ok; ++i) {
        std::string path = r.Str(kMaxNameLen);
        std::string id = r.Str(kMaxIdLen);
        if (!r.ok || path.empty() || s.paths.count(path)) return false;
        auto inode = s.inodes.find(id);
        if (inode == s.inodes.end()) return false;
        // Only files may have several names.
        if (!inode->second.IsFile() && inode->second.nlink > 0) return false;
        inode->second.nlink++;
        AddPath(s, path, id);
    }
    if (!r.ok || r.pos != data.size()) return false;
    Relink(s);
    out = std::move(s);
    return true;
}

// v1: count:u32, then per entry name | remote_id | version:u64 | size:u64 | mtime:i64.
bool EncryptedIndex::DeserializeV1(const std::vector<uint8_t>& data, State& out) {
    Reader r{data};
    State s;
    const uint32_t count = r.U32();
    for (uint32_t i = 0; i < count && r.ok; ++i) {
        std::string name = r.Str(kMaxNameLen);
        FileMetadata m;
        m.remote_id = r.Str(kMaxIdLen);
        m.version = r.U64();
        m.size = r.U64();
        m.mtime = static_cast<int64_t>(r.U64());
        if (!r.ok || name.empty() || s.paths.count(name)) return false;
        if (m.remote_id.empty()) {  // v1 directories had no ID
            m.type = EntryType::kDirectory;
            m.mode = 0755;
            m.remote_id = NewInodeId();
        } else if (s.inodes.count(m.remote_id)) {
            return false;
        }
        s.inodes[m.remote_id] = m;
        AddPath(s, name, m.remote_id);
    }
    if (!r.ok || r.pos != data.size()) return false;
    Relink(s);
    out = std::move(s);
    return true;
}

// ── Persistence ─────────────────────────────────────────────────────────────

bool EncryptedIndex::FileExists() const {
    struct stat st;
    return ::stat(index_path_.c_str(), &st) == 0;
}

bool EncryptedIndex::Load() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<uint8_t> encrypted;
    if (!ReadWholeFile(index_path_, encrypted)) return errno == ENOENT;
    if (encrypted.empty()) return true;
    try {
        std::vector<uint8_t> plain = SimpleCrypto::Decrypt(encrypted, DeriveIndexKey());
        State s;
        bool ok = Deserialize(plain, s);
        SecureWipe(plain);
        if (!ok) return false;
        state_ = std::move(s);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool EncryptedIndex::Save() {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        state_.generation++;
        std::vector<uint8_t> plain = SerializeLocked();
        std::vector<uint8_t> encrypted = SimpleCrypto::Encrypt(plain, DeriveIndexKey());
        SecureWipe(plain);
        return WriteFileAtomic(index_path_, encrypted);
    } catch (const std::exception&) {
        return false;
    }
}

uint64_t EncryptedIndex::generation() {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_.generation;
}

void EncryptedIndex::set_generation(uint64_t g) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.generation = g;
}

// ── Paths ───────────────────────────────────────────────────────────────────

bool EncryptedIndex::GetMetadata(const std::string& path, FileMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto p = state_.paths.find(path);
    if (p == state_.paths.end()) return false;
    metadata = state_.inodes.at(p->second);
    return true;
}

bool EncryptedIndex::Exists(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_.paths.count(path) > 0;
}

void EncryptedIndex::SetMetadata(const std::string& path, const FileMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    FileMetadata m = metadata;
    if (m.remote_id.empty()) m.remote_id = NewInodeId();

    auto old = state_.paths.find(path);
    if (old != state_.paths.end() && old->second != m.remote_id) {
        auto inode = state_.inodes.find(old->second);
        if (inode != state_.inodes.end() && --inode->second.nlink == 0) state_.inodes.erase(inode);
        RemovePath(state_, path);
    }
    const bool linked = state_.paths.count(path) > 0;
    auto existing = state_.inodes.find(m.remote_id);
    uint32_t links = existing == state_.inodes.end() ? 0 : existing->second.nlink;
    m.nlink = links + (linked ? 0 : 1);
    state_.inodes[m.remote_id] = m;
    if (!linked) AddPath(state_, path, m.remote_id);
}

bool EncryptedIndex::Remove(const std::string& path, FileMetadata* removed) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto p = state_.paths.find(path);
    if (p == state_.paths.end()) return false;
    const std::string id = p->second;
    RemovePath(state_, path);
    auto inode = state_.inodes.find(id);
    if (inode == state_.inodes.end()) return false;
    if (--inode->second.nlink > 0) return false;
    if (removed) *removed = inode->second;
    state_.inodes.erase(inode);
    return true;
}

bool EncryptedIndex::Link(const std::string& existing, const std::string& new_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto p = state_.paths.find(existing);
    if (p == state_.paths.end() || state_.paths.count(new_path)) return false;
    FileMetadata& inode = state_.inodes.at(p->second);
    if (!inode.IsFile()) return false;
    inode.nlink++;
    AddPath(state_, new_path, p->second);
    return true;
}

bool EncryptedIndex::Rename(const std::string& src, const std::string& dst) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!state_.paths.count(src) || state_.paths.count(dst) || src == dst) return false;
    if (dst.compare(0, src.size() + 1, src + "/") == 0) return false;  // into itself

    // src itself, then everything below it.
    std::vector<std::pair<std::string, std::string>> moving = {{src, state_.paths[src]}};
    const std::string prefix = src + "/";
    for (auto it = state_.paths.lower_bound(prefix);
         it != state_.paths.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it) {
        moving.emplace_back(it->first, it->second);
    }
    for (const auto& [path, id] : moving) RemovePath(state_, path);
    for (const auto& [path, id] : moving) AddPath(state_, dst + path.substr(src.size()), id);
    return true;
}

std::vector<std::string> EncryptedIndex::GetAllPlaintextNames() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> names;
    names.reserve(state_.paths.size());
    for (const auto& [path, id] : state_.paths) names.push_back(path);
    return names;
}

std::vector<std::string> EncryptedIndex::ListDirectory(const std::string& dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = state_.children.find(dir);
    if (it == state_.children.end()) return {};
    return std::vector<std::string>(it->second.begin(), it->second.end());
}

bool EncryptedIndex::HasChildren(const std::string& dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_.children.count(dir) > 0;
}

std::vector<std::string> EncryptedIndex::Descendants(const std::string& dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    const std::string prefix = dir.empty() ? "" : dir + "/";
    for (auto it = state_.paths.lower_bound(prefix);
         it != state_.paths.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it) {
        if (it->first.size() > prefix.size()) out.push_back(it->first);
    }
    return out;
}

size_t EncryptedIndex::Size() {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_.paths.size();
}

// ── Inodes ──────────────────────────────────────────────────────────────────

bool EncryptedIndex::GetInode(const std::string& remote_id, FileMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = state_.inodes.find(remote_id);
    if (it == state_.inodes.end()) return false;
    metadata = it->second;
    return true;
}

bool EncryptedIndex::UpdateInode(const FileMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = state_.inodes.find(metadata.remote_id);
    if (it == state_.inodes.end()) return false;
    const uint32_t nlink = it->second.nlink;
    it->second = metadata;
    it->second.nlink = nlink;
    return true;
}

bool EncryptedIndex::GetPlaintextName(const std::string& remote_id, std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [p, id] : state_.paths) {
        if (id == remote_id) {
            path = p;
            return true;
        }
    }
    return false;
}

std::vector<FileMetadata> EncryptedIndex::AllInodes() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FileMetadata> out;
    out.reserve(state_.inodes.size());
    for (const auto& [id, m] : state_.inodes) out.push_back(m);
    return out;
}

uint64_t EncryptedIndex::IncrementVersion(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto p = state_.paths.find(path);
    if (p == state_.paths.end()) return 1;
    return ++state_.inodes.at(p->second).version;
}

} // namespace encfs

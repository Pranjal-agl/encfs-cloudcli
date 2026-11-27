#pragma once

#include <cstdint>
#include <ctime>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace encfs {

enum class EntryType : uint8_t { kFile = 1, kDirectory = 2, kSymlink = 3 };

// One inode: the object a path refers to. Several paths can share a file
// inode (hard links).
struct FileMetadata {
    // Opaque inode ID (64 hex chars). For files it is also the blob's name in
    // the backing directory and the cloud, and is bound into the blob's AAD.
    // New inodes get random IDs, so paths and IDs are unrelated.
    std::string remote_id;
    EntryType type = EntryType::kFile;
    uint64_t version = 1;  // bumped on every write; bound into the blob for rollback detection
    uint64_t size = 0;
    int64_t mtime = 0;
    uint32_t mode = 0644;  // permission bits only
    uint32_t nlink = 1;    // number of paths referring to this inode (maintained by the index)
    std::string target;    // symlink target

    bool IsDirectory() const { return type == EntryType::kDirectory; }
    bool IsSymlink() const { return type == EntryType::kSymlink; }
    bool IsFile() const { return type == EntryType::kFile; }
};

// A fresh random inode ID.
std::string NewInodeId();

// Encrypted index: paths (e.g. "docs/notes.txt", no leading slash) → inodes.
// Stored as `<backing_dir>/index.enc`. All methods are thread-safe.
//
// Format v2 (plaintext, inside the AES-GCM envelope):
//   "EIX2" | generation:u64 | inode_count:u32 | inodes | path_count:u32 | paths
//   inode: id | type:u8 | version:u64 | size:u64 | mtime:i64 | mode:u32 | target
//   path:  path | inode id                       (strings are u32-length-prefixed)
// v1 indexes (one flat entry per path, empty ID = directory) are still read
// and are rewritten as v2 on the next save.
class EncryptedIndex {
public:
    EncryptedIndex(const std::string& backing_dir, const std::vector<uint8_t>& key);

    // Load from disk. True if loaded or absent; false if present but unreadable
    // (e.g. wrong key). On failure the in-memory index is left unchanged.
    bool Load();
    // Durably save (encrypted, atomic replace). Increments the generation.
    bool Save();
    bool FileExists() const;
    const std::string& path() const { return index_path_; }

    // Bumped on every save; lets copies of the index be ordered.
    uint64_t generation();
    void set_generation(uint64_t g);

    // ── Paths ──
    // The inode behind `path`.
    bool GetMetadata(const std::string& path, FileMetadata& metadata);
    bool Exists(const std::string& path);
    // Point `path` at inode `metadata.remote_id` (an empty ID gets a fresh
    // one) and store `metadata` as that inode's data. If `path` referred to
    // another inode, that link is dropped first.
    void SetMetadata(const std::string& path, const FileMetadata& metadata);
    // Unlink `path`. Returns true if that removed the inode's last link; its
    // data is then copied to `*removed` if given.
    bool Remove(const std::string& path, FileMetadata* removed = nullptr);
    // Add `new_path` as another name for the file inode at `existing`.
    bool Link(const std::string& existing, const std::string& new_path);
    // Move `src` (and, for a directory, everything below it) to `dst`, which
    // must not exist. Index-only: no data moves.
    bool Rename(const std::string& src, const std::string& dst);

    std::vector<std::string> GetAllPlaintextNames();
    // Direct children of directory `dir` ("" = root), as base names, sorted.
    std::vector<std::string> ListDirectory(const std::string& dir);
    bool HasChildren(const std::string& dir);
    // Every path strictly below `dir`, sorted (parents before children).
    std::vector<std::string> Descendants(const std::string& dir);
    size_t Size();  // number of paths

    // ── Inodes ──
    bool GetInode(const std::string& remote_id, FileMetadata& metadata);
    // Update an existing inode's data (not its links). False if it is gone.
    bool UpdateInode(const FileMetadata& metadata);
    // Any path referring to the inode.
    bool GetPlaintextName(const std::string& remote_id, std::string& path);
    std::vector<FileMetadata> AllInodes();

    uint64_t IncrementVersion(const std::string& path);

private:
    struct State {
        std::map<std::string, std::string> paths;                   // path → inode id
        std::unordered_map<std::string, FileMetadata> inodes;        // id → data
        std::unordered_map<std::string, std::set<std::string>> children;  // dir → base names
        uint64_t generation = 0;
    };

    std::string index_path_;
    std::vector<uint8_t> key_;
    State state_;
    std::mutex mutex_;

    std::vector<uint8_t> DeriveIndexKey() const;
    std::vector<uint8_t> SerializeLocked() const;
    static bool Deserialize(const std::vector<uint8_t>& data, State& out);
    static bool DeserializeV1(const std::vector<uint8_t>& data, State& out);
    static void AddPath(State& s, const std::string& path, const std::string& id);
    static void RemovePath(State& s, const std::string& path);
    static void Relink(State& s);
};

} // namespace encfs

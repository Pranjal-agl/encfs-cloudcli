#pragma once

#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace encfs {

struct FileMetadata {
    std::string remote_id;
    uint64_t version;  // bumped on every write; bound into the blob for rollback detection
    uint64_t size;
    int64_t mtime;

    FileMetadata() : version(1), size(0), mtime(0) {}
};

// Encrypted index that maps plaintext filenames to remote IDs + metadata.
// Stored as `<backing_dir>/index.enc`. All methods are thread-safe.
class EncryptedIndex {
public:
    EncryptedIndex(const std::string& backing_dir, const std::vector<uint8_t>& key);

    // Load index from disk. Returns true if the index was loaded or doesn't
    // exist yet; false if it exists but can't be read or decrypted (e.g. wrong
    // key). On failure the in-memory index is left unchanged.
    bool Load();

    // Durably save the index (encrypted, atomic replace).
    bool Save();

    // True if an index file is present on disk.
    bool FileExists() const;

    bool GetMetadata(const std::string& plaintext_name, FileMetadata& metadata);
    void SetMetadata(const std::string& plaintext_name, const FileMetadata& metadata);
    bool GetPlaintextName(const std::string& remote_id, std::string& plaintext_name);
    void Remove(const std::string& plaintext_name);
    bool Exists(const std::string& plaintext_name);
    uint64_t IncrementVersion(const std::string& plaintext_name);
    std::vector<std::string> GetAllPlaintextNames();
    size_t Size();

    const std::string& path() const { return index_path_; }

private:
    using ForwardMap = std::unordered_map<std::string, FileMetadata>;
    using ReverseMap = std::unordered_map<std::string, std::string>;

    std::string index_path_;
    std::vector<uint8_t> key_;
    ForwardMap index_;          // plaintext -> metadata
    ReverseMap reverse_index_;  // remote_id -> plaintext
    std::mutex mutex_;

    std::vector<uint8_t> DeriveIndexKey() const;
    std::vector<uint8_t> Serialize() const;
    static bool Deserialize(const std::vector<uint8_t>& data, ForwardMap& fwd, ReverseMap& rev);
};

} // namespace encfs

#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <mutex>

namespace encfs {

struct FileMetadata {
    std::string remote_id;
    uint64_t version;
    size_t size;
    time_t mtime;
    
    FileMetadata() : version(1), size(0), mtime(0) {}
};

// Encrypted index that maps plaintext filenames to remote IDs
class EncryptedIndex {
public:
    EncryptedIndex(const std::string& backing_dir, const std::vector<uint8_t>& key);
    
    // Load index from disk
    bool Load();
    
    // Save index to disk (encrypted)
    bool Save();
    
    // Get metadata for a file
    bool GetMetadata(const std::string& plaintext_name, FileMetadata& metadata);
    
    // Set metadata for a file
    void SetMetadata(const std::string& plaintext_name, const FileMetadata& metadata);
    
    // Get plaintext name from remote ID
    bool GetPlaintextName(const std::string& remote_id, std::string& plaintext_name);
    
    // Remove entry
    void Remove(const std::string& plaintext_name);
    
    // Check if file exists
    bool Exists(const std::string& plaintext_name);
    
    // Increment version for a file
    uint64_t IncrementVersion(const std::string& plaintext_name);
    
    // Get all plaintext names
    std::vector<std::string> GetAllPlaintextNames();
    
private:
    std::string index_path_;
    std::vector<uint8_t> key_;
    std::unordered_map<std::string, FileMetadata> index_; // plaintext -> metadata
    std::unordered_map<std::string, std::string> reverse_index_; // remote_id -> plaintext
    std::mutex mutex_;
    
    // Derive index encryption key from master key
    std::vector<uint8_t> DeriveIndexKey();
    
    // Serialize index to binary format
    std::vector<uint8_t> Serialize();
    
    // Deserialize index from binary format
    bool Deserialize(const std::vector<uint8_t>& data);
};

} // namespace encfs


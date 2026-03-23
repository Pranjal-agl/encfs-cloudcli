#include "index.h"
#include "crypto.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace encfs {

EncryptedIndex::EncryptedIndex(const std::string& backing_dir, const std::vector<uint8_t>& key)
    : index_path_(backing_dir + "/index.enc"), key_(key) {
}

std::vector<uint8_t> EncryptedIndex::DeriveIndexKey() {
    // Derive a separate key for index encryption using HMAC
    // Use a fixed context string to derive from master key
    std::string context = "encfs_index_key_derivation";
    return HMAC::Compute(key_, std::vector<uint8_t>(context.begin(), context.end()));
}

std::vector<uint8_t> EncryptedIndex::Serialize() {
    std::ostringstream oss;
    
    // Format: number of entries (4 bytes) + entries
    // Each entry: plaintext_len (4) + plaintext + remote_id_len (4) + remote_id + 
    //             version (8) + size (8) + mtime (8)
    uint32_t count = static_cast<uint32_t>(index_.size());
    oss.write(reinterpret_cast<const char*>(&count), 4);
    
    for (const auto& pair : index_) {
        const std::string& plaintext = pair.first;
        const FileMetadata& meta = pair.second;
        
        uint32_t plaintext_len = static_cast<uint32_t>(plaintext.size());
        oss.write(reinterpret_cast<const char*>(&plaintext_len), 4);
        oss.write(plaintext.c_str(), plaintext_len);
        
        uint32_t remote_id_len = static_cast<uint32_t>(meta.remote_id.size());
        oss.write(reinterpret_cast<const char*>(&remote_id_len), 4);
        oss.write(meta.remote_id.c_str(), remote_id_len);
        
        oss.write(reinterpret_cast<const char*>(&meta.version), 8);
        oss.write(reinterpret_cast<const char*>(&meta.size), 8);
        oss.write(reinterpret_cast<const char*>(&meta.mtime), 8);
    }
    
    std::string data = oss.str();
    return std::vector<uint8_t>(data.begin(), data.end());
}

bool EncryptedIndex::Deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return false;
    }
    
    std::istringstream iss(std::string(data.begin(), data.end()));
    
    uint32_t count;
    iss.read(reinterpret_cast<char*>(&count), 4);
    if (iss.fail()) return false;
    
    index_.clear();
    reverse_index_.clear();
    
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t plaintext_len;
        iss.read(reinterpret_cast<char*>(&plaintext_len), 4);
        if (iss.fail() || plaintext_len > 1024 * 1024) return false; // Sanity check
        
        std::string plaintext(plaintext_len, '\0');
        iss.read(&plaintext[0], plaintext_len);
        if (iss.fail()) return false;
        
        uint32_t remote_id_len;
        iss.read(reinterpret_cast<char*>(&remote_id_len), 4);
        if (iss.fail() || remote_id_len > 1024) return false;
        
        std::string remote_id(remote_id_len, '\0');
        iss.read(&remote_id[0], remote_id_len);
        if (iss.fail()) return false;
        
        FileMetadata meta;
        iss.read(reinterpret_cast<char*>(&meta.version), 8);
        iss.read(reinterpret_cast<char*>(&meta.size), 8);
        iss.read(reinterpret_cast<char*>(&meta.mtime), 8);
        if (iss.fail()) return false;
        
        meta.remote_id = remote_id;
        index_[plaintext] = meta;
        reverse_index_[remote_id] = plaintext;
    }
    
    return true;
}

bool EncryptedIndex::Load() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ifstream file(index_path_, std::ios::binary);
    if (!file) {
        // Index doesn't exist yet, start empty
        return true;
    }
    
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (file_size == 0) {
        return true; // Empty index
    }
    
    std::vector<uint8_t> encrypted_data(file_size);
    file.read(reinterpret_cast<char*>(encrypted_data.data()), file_size);
    if (file.fail()) {
        return false;
    }
    
    try {
        std::vector<uint8_t> index_key = DeriveIndexKey();
        std::vector<uint8_t> decrypted_data = SimpleCrypto::Decrypt(encrypted_data, index_key);
        return Deserialize(decrypted_data);
    } catch (const std::exception&) {
        return false;
    }
}

bool EncryptedIndex::Save() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<uint8_t> serialized = Serialize();
    std::vector<uint8_t> index_key = DeriveIndexKey();
    
    try {
        std::vector<uint8_t> encrypted_data = SimpleCrypto::Encrypt(serialized, index_key);
        
        // Write to temp file first, then rename (atomic)
        std::string temp_path = index_path_ + ".tmp";
        std::ofstream file(temp_path, std::ios::binary);
        if (!file) {
            return false;
        }
        
        file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
        file.close();
        
        if (file.fail()) {
            return false;
        }
        
        // Atomic rename
        if (rename(temp_path.c_str(), index_path_.c_str()) != 0) {
            return false;
        }
        
        return true;
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
    
    // Remove old reverse mapping if exists
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

} // namespace encfs


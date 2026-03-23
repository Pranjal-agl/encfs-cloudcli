#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>

namespace encfs {

// Key management
class KeyManager {
public:
    // Load key from file (~/.encfs/key)
    static std::vector<uint8_t> LoadKeyFromFile(const std::string& key_path);
    
    // Derive key from passphrase using PBKDF2
    static std::vector<uint8_t> DeriveKeyFromPassphrase(
        const std::string& passphrase,
        const std::vector<uint8_t>& salt,
        int iterations = 200000
    );
    
    // Generate random bytes
    static std::vector<uint8_t> RandomBytes(size_t count);
};

// HMAC-SHA256 for filename mapping
class HMAC {
public:
    // Compute HMAC-SHA256 of data using key
    static std::vector<uint8_t> Compute(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data
    );
    
    // Compute HMAC and return as hex string
    static std::string ComputeHex(
        const std::vector<uint8_t>& key,
        const std::string& data
    );
};

// Chunked AES-256-GCM encryption/decryption
class ChunkedCrypto {
public:
    static constexpr size_t DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
    
    // Encrypt data in chunks
    // Returns encrypted blob
    static std::vector<uint8_t> Encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        size_t chunk_size = DEFAULT_CHUNK_SIZE
    );
    
    // Decrypt chunked encrypted data
    // Returns plaintext
    static std::vector<uint8_t> Decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key
    );
    
    // Encrypt stream (for large files)
    // Caller provides callbacks for reading plaintext and writing ciphertext
    static bool EncryptStream(
        std::function<size_t(uint8_t*, size_t)> read_fn,
        std::function<bool(const uint8_t*, size_t)> write_fn,
        const std::vector<uint8_t>& key,
        size_t chunk_size = DEFAULT_CHUNK_SIZE
    );
    
    // Decrypt stream
    static bool DecryptStream(
        std::function<size_t(uint8_t*, size_t)> read_fn,
        std::function<bool(const uint8_t*, size_t)> write_fn,
        const std::vector<uint8_t>& key
    );
    
private:
    // Generate nonce for a chunk (file_nonce + chunk_index)
    static std::vector<uint8_t> GenerateChunkNonce(
        const std::vector<uint8_t>& file_nonce,
        uint32_t chunk_index
    );
    
    // Encrypt single chunk
    static bool EncryptChunk(
        const uint8_t* plaintext,
        size_t plaintext_len,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        std::vector<uint8_t>& ciphertext,
        std::vector<uint8_t>& tag
    );
    
    // Decrypt single chunk
    static bool DecryptChunk(
        const uint8_t* ciphertext,
        size_t ciphertext_len,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& nonce,
        const uint8_t* tag,
        std::vector<uint8_t>& plaintext
    );
};

// Simple AES-GCM (non-chunked) for small data like index
class SimpleCrypto {
public:
    // Encrypt data
    static std::vector<uint8_t> Encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key
    );
    
    // Decrypt data
    static std::vector<uint8_t> Decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key
    );
};

} // namespace encfs


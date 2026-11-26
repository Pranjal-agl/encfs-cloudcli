#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace encfs {

constexpr size_t kKeySize = 32;  // AES-256 / HMAC-SHA256 key length

// Key management
class KeyManager {
public:
    // Load a 32-byte master key from a key file. Accepted formats:
    //   * 64 hex characters (what `openssl rand -hex 32` produces), optionally
    //     followed by whitespace/newline — decoded to 32 bytes;
    //   * exactly 32 raw bytes (what `openssl rand 32` produces).
    // Throws std::runtime_error for anything else.
    static std::vector<uint8_t> LoadKeyFromFile(const std::string& key_path);

    // How versions < 2 interpreted a key file: the first 32 raw bytes. For a
    // hex key file that is 32 ASCII hex digits, i.e. only 128 bits of entropy.
    // Kept solely so existing backing stores can still be opened.
    static std::vector<uint8_t> LoadLegacyKeyFromFile(const std::string& key_path);

    // Derive key from passphrase using PBKDF2-HMAC-SHA256
    static std::vector<uint8_t> DeriveKeyFromPassphrase(
        const std::string& passphrase,
        const std::vector<uint8_t>& salt,
        int iterations = 600000
    );

    // Derive an independent sub-key: HMAC-SHA256(key, label). Used for domain
    // separation so the master key is never used directly by two algorithms.
    static std::vector<uint8_t> DeriveSubkey(const std::vector<uint8_t>& key,
                                             const std::string& label);

    // Generate random bytes from the OpenSSL CSPRNG
    static std::vector<uint8_t> RandomBytes(size_t count);
};

// HMAC-SHA256 for filename mapping and key derivation
class HMAC {
public:
    static std::vector<uint8_t> Compute(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data
    );

    // Compute HMAC and return as lowercase hex string
    static std::string ComputeHex(
        const std::vector<uint8_t>& key,
        const std::string& data
    );
};

// Chunked AES-256-GCM encryption (blob format v2).
//
//   header  = "ENCFS" | 0x02 | chunk_size:u32le | salt:32
//   chunk_i = len:u32le | ciphertext[len] | tag[16]
//
// * Each blob gets a fresh random 32-byte salt and its own AES key,
//   file_key = HMAC-SHA256(key, "encfs-v2-chunk-key" || salt), so nonces can
//   never repeat across files no matter how many are written.
// * nonce_i = 0^7 | i:u32be | last_flag:u8. Binding the index and a "final
//   chunk" flag into the nonce (the STREAM construction) means chunks can't
//   be reordered, dropped, duplicated, or the blob truncated/extended without
//   failing authentication.
// * Every chunk authenticates header || caller AAD, so the header can't be
//   altered and a blob can be bound to a context (e.g. which file it is).
// * There is always at least one chunk (empty plaintext → one empty final
//   chunk), so even an empty file is authenticated.
class ChunkedCrypto {
public:
    static constexpr size_t DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
    static constexpr size_t MAX_CHUNK_SIZE = 64 * 1024 * 1024;    // decode sanity limit
    static constexpr uint8_t FORMAT_VERSION = 2;
    static constexpr size_t HEADER_SIZE = 5 + 1 + 4 + 32;
    static constexpr size_t TAG_SIZE = 16;

    // Encrypt a whole buffer. Throws std::runtime_error on failure.
    static std::vector<uint8_t> Encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        size_t chunk_size = DEFAULT_CHUNK_SIZE,
        const std::vector<uint8_t>& aad = {}
    );

    // Decrypt a whole v2 blob. Throws std::runtime_error if the blob is
    // malformed or fails authentication (wrong key, wrong AAD, tampering).
    static std::vector<uint8_t> Decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& aad = {}
    );

    // Streaming variants for data that shouldn't be held in memory at once.
    // read_fn(buf, n) returns bytes read (0 at EOF); write_fn(buf, n) returns
    // success. Plaintext is only handed to write_fn after its chunk has been
    // authenticated — but a failure part-way means earlier chunks were already
    // written, so callers must discard the output when false is returned.
    static bool EncryptStream(
        std::function<size_t(uint8_t*, size_t)> read_fn,
        std::function<bool(const uint8_t*, size_t)> write_fn,
        const std::vector<uint8_t>& key,
        size_t chunk_size = DEFAULT_CHUNK_SIZE,
        const std::vector<uint8_t>& aad = {}
    );

    static bool DecryptStream(
        std::function<size_t(uint8_t*, size_t)> read_fn,
        std::function<bool(const uint8_t*, size_t)> write_fn,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& aad = {}
    );

    // Returns the format version byte of a blob, or 0 if it isn't one.
    static uint8_t PeekFormatVersion(const std::vector<uint8_t>& blob);

    // Decrypt a blob written by the original (v1) format, where the master key
    // was used directly and chunks weren't bound to their position. Read-only
    // support so existing data stays accessible; files are rewritten as v2 on
    // their next modification.
    static std::vector<uint8_t> DecryptLegacyV1(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key
    );
};

// Single-shot AES-256-GCM for small data such as the index.
// Layout: nonce(12) | ciphertext | tag(16).
class SimpleCrypto {
public:
    static std::vector<uint8_t> Encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& aad = {}
    );

    static std::vector<uint8_t> Decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& aad = {}
    );
};

} // namespace encfs

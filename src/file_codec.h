#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace encfs {

// Turns plaintext file contents into encrypted blobs and back.
//
// Owns every key derived from the master key, so the rest of the code never
// touches the master key directly:
//   * filename key  — HMAC key that maps a plaintext name to its remote ID
//   * content key   — encrypts file contents (blob format v2)
//
// Each blob is cryptographically bound to (remote_id, version) via AAD:
//   * swapping two files' blobs in the backing store / cloud is detected;
//   * serving an older copy of a file (rollback) is detected, because the
//     version recorded in the local index no longer matches.
class FileCodec {
public:
    explicit FileCodec(const std::vector<uint8_t>& master_key);
    ~FileCodec();

    FileCodec(const FileCodec&) = delete;
    FileCodec& operator=(const FileCodec&) = delete;

    // Deterministic, opaque remote ID for a plaintext filename (64 hex chars).
    std::string RemoteIdFor(const std::string& plaintext_name) const;

    // Encrypt `plaintext` as version `version` of `remote_id`.
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext,
                                 const std::string& remote_id,
                                 uint64_t version) const;

    enum class Result {
        kOk,              // decrypted; *actual_version is set
        kRollback,        // authentic blob for this file, but an older version
        kCorrupt,         // malformed, wrong key, wrong file, or tampered
    };

    // Decrypt a blob for `remote_id`, expecting `expected_version`.
    //
    // A blob that is exactly one version *ahead* of the index is accepted: that
    // happens if we crashed after writing the blob but before saving the index.
    // `*actual_version` tells the caller which version it got so the index can
    // be repaired. Legacy v1 blobs carry no version and are accepted as-is.
    Result Decrypt(const std::vector<uint8_t>& blob,
                   const std::string& remote_id,
                   uint64_t expected_version,
                   std::vector<uint8_t>& plaintext,
                   uint64_t* actual_version) const;

    // Chunk size for new blobs (tests use small values to exercise chunking).
    void set_chunk_size(size_t chunk_size) { chunk_size_ = chunk_size; }

private:
    std::vector<uint8_t> master_key_;    // only for legacy v1 blobs
    std::vector<uint8_t> filename_key_;
    std::vector<uint8_t> content_key_;
    size_t chunk_size_;

    static std::vector<uint8_t> Aad(const std::string& remote_id, uint64_t version);
};

} // namespace encfs

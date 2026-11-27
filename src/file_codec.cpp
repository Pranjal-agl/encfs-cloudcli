#include "file_codec.h"
#include "crypto.h"
#include "util.h"

#include <stdexcept>

namespace encfs {

namespace {
// Labels are part of the on-disk format: changing one changes every key.
const char kFilenameKeyLabel[] = "encfs_filename_hmac";  // unchanged from v1
const char kContentKeyLabel[] = "encfs_content_key_v2";
const char kAadLabel[] = "encfs-file-v2";
constexpr uint64_t kRollbackProbe = 4;  // how many older versions to probe for diagnostics
} // namespace

FileCodec::FileCodec(const std::vector<uint8_t>& master_key)
    : master_key_(master_key),
      filename_key_(KeyManager::DeriveSubkey(master_key, kFilenameKeyLabel)),
      content_key_(KeyManager::DeriveSubkey(master_key, kContentKeyLabel)),
      chunk_size_(ChunkedCrypto::DEFAULT_CHUNK_SIZE) {
    if (master_key.size() != kKeySize) {
        throw std::runtime_error("Master key must be 32 bytes");
    }
}

FileCodec::~FileCodec() {
    SecureWipe(master_key_);
    SecureWipe(filename_key_);
    SecureWipe(content_key_);
}

std::string FileCodec::RemoteIdFor(const std::string& plaintext_name) const {
    return HMAC::ComputeHex(filename_key_, plaintext_name);
}

std::vector<uint8_t> FileCodec::Aad(const std::string& remote_id, uint64_t version) {
    std::vector<uint8_t> aad(kAadLabel, kAadLabel + sizeof(kAadLabel));  // includes NUL separator
    aad.insert(aad.end(), remote_id.begin(), remote_id.end());
    aad.push_back(0);
    AppendU64LE(aad, version);
    return aad;
}

std::vector<uint8_t> FileCodec::Encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::string& remote_id,
                                        uint64_t version) const {
    return ChunkedCrypto::Encrypt(plaintext, content_key_, chunk_size_, Aad(remote_id, version));
}

FileCodec::Result FileCodec::Decrypt(const std::vector<uint8_t>& blob,
                                     const std::string& remote_id,
                                     uint64_t expected_version,
                                     std::vector<uint8_t>& plaintext,
                                     uint64_t* actual_version) const {
    uint8_t format = ChunkedCrypto::PeekFormatVersion(blob);

    if (format == 1) {
        try {
            plaintext = ChunkedCrypto::DecryptLegacyV1(blob, master_key_);
            if (actual_version) *actual_version = expected_version;
            return Result::kOk;
        } catch (const std::exception&) {
            return Result::kCorrupt;
        }
    }
    if (format != ChunkedCrypto::FORMAT_VERSION) {
        return Result::kCorrupt;
    }

    auto try_version = [&](uint64_t v) {
        try {
            plaintext = ChunkedCrypto::Decrypt(blob, content_key_, Aad(remote_id, v));
            if (actual_version) *actual_version = v;
            return true;
        } catch (const std::exception&) {
            return false;
        }
    };

    if (try_version(expected_version) || try_version(expected_version + 1)) {
        return Result::kOk;
    }

    // Not the expected version. If it's an authentic older version of this
    // file, report rollback (stale cloud copy / replay) rather than corruption.
    std::vector<uint8_t> scratch;
    for (uint64_t back = 1; back <= kRollbackProbe && back < expected_version; ++back) {
        try {
            scratch = ChunkedCrypto::Decrypt(blob, content_key_, Aad(remote_id, expected_version - back));
            SecureWipe(scratch);
            return Result::kRollback;
        } catch (const std::exception&) {
        }
    }
    return Result::kCorrupt;
}

FileCodec::Result FileCodec::OpenReader(const std::string& path,
                                        const std::string& remote_id,
                                        uint64_t expected_version,
                                        std::unique_ptr<ChunkedReader>* reader,
                                        uint64_t* actual_version) const {
    reader->reset();
    std::vector<uint8_t> chunk;
    auto try_version = [&](uint64_t v) -> std::unique_ptr<ChunkedReader> {
        auto r = ChunkedReader::Open(path, content_key_, Aad(remote_id, v));
        if (r && r->ReadChunk(0, chunk)) return r;
        return nullptr;
    };

    // Structurally not a v2 blob (e.g. legacy v1): let the caller decide.
    if (!ChunkedReader::Open(path, content_key_)) return Result::kOk;

    for (uint64_t v : {expected_version, expected_version + 1}) {
        if (auto r = try_version(v)) {
            SecureWipe(chunk);
            *reader = std::move(r);
            if (actual_version) *actual_version = v;
            return Result::kOk;
        }
    }
    for (uint64_t back = 1; back <= kRollbackProbe && back < expected_version; ++back) {
        if (try_version(expected_version - back)) {
            SecureWipe(chunk);
            return Result::kRollback;
        }
    }
    return Result::kCorrupt;
}

} // namespace encfs

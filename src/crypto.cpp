#include "crypto.h"
#include "util.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace encfs {

namespace {

const uint8_t kMagic[5] = {'E', 'N', 'C', 'F', 'S'};
constexpr size_t kNonceSize = 12;
constexpr size_t kTagSize = 16;
constexpr size_t kSaltSize = 32;
const char kChunkKeyLabel[] = "encfs-v2-chunk-key";

struct CtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

// AES-256-GCM encrypt `len` bytes. `ct` must have room for `len` bytes.
bool GcmEncrypt(const uint8_t* key, const uint8_t* nonce,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* pt, size_t len,
                uint8_t* ct, uint8_t* tag) {
    if (len > INT_MAX || aad_len > INT_MAX) return false;
    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return false;

    int outlen = 0;
    uint8_t final_buf[16];
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key, nonce) != 1) return false;
    if (aad_len > 0 &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, aad, static_cast<int>(aad_len)) != 1) {
        return false;
    }
    if (len > 0 &&
        EVP_EncryptUpdate(ctx.get(), ct, &outlen, pt, static_cast<int>(len)) != 1) {
        return false;
    }
    return EVP_EncryptFinal_ex(ctx.get(), final_buf, &outlen) == 1 &&
           EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kTagSize, tag) == 1;
}

// AES-256-GCM decrypt + verify. `pt` must have room for `len` bytes. Returns
// false if authentication fails; `pt` contents are then unspecified.
bool GcmDecrypt(const uint8_t* key, const uint8_t* nonce,
                const uint8_t* aad, size_t aad_len,
                const uint8_t* ct, size_t len,
                const uint8_t* tag, uint8_t* pt) {
    if (len > INT_MAX || aad_len > INT_MAX) return false;
    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return false;

    int outlen = 0;
    uint8_t final_buf[16];
    uint8_t tag_copy[kTagSize];
    std::memcpy(tag_copy, tag, kTagSize);  // ctrl() takes a non-const pointer

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key, nonce) != 1) return false;
    if (aad_len > 0 &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &outlen, aad, static_cast<int>(aad_len)) != 1) {
        return false;
    }
    if (len > 0 &&
        EVP_DecryptUpdate(ctx.get(), pt, &outlen, ct, static_cast<int>(len)) != 1) {
        return false;
    }
    return EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kTagSize, tag_copy) == 1 &&
           EVP_DecryptFinal_ex(ctx.get(), final_buf, &outlen) == 1;
}

// STREAM nonce: 7 zero bytes | chunk index (big-endian u32) | final flag.
void ChunkNonce(uint32_t index, bool last, uint8_t out[kNonceSize]) {
    std::memset(out, 0, kNonceSize);
    out[7] = static_cast<uint8_t>(index >> 24);
    out[8] = static_cast<uint8_t>(index >> 16);
    out[9] = static_cast<uint8_t>(index >> 8);
    out[10] = static_cast<uint8_t>(index);
    out[11] = last ? 1 : 0;
}

std::vector<uint8_t> BuildHeader(size_t chunk_size, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> header(kMagic, kMagic + sizeof(kMagic));
    header.push_back(ChunkedCrypto::FORMAT_VERSION);
    AppendU32LE(header, static_cast<uint32_t>(chunk_size));
    header.insert(header.end(), salt.begin(), salt.end());
    return header;
}

std::vector<uint8_t> FileKey(const std::vector<uint8_t>& key, const uint8_t* salt) {
    std::vector<uint8_t> info(kChunkKeyLabel, kChunkKeyLabel + sizeof(kChunkKeyLabel) - 1);
    info.insert(info.end(), salt, salt + kSaltSize);
    return HMAC::Compute(key, info);
}

std::vector<uint8_t> Concat(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

// Parse and validate a v2 header. Returns the chunk size.
size_t ParseHeader(const uint8_t* header) {
    if (std::memcmp(header, kMagic, sizeof(kMagic)) != 0) {
        throw std::runtime_error("Invalid magic bytes");
    }
    if (header[5] != ChunkedCrypto::FORMAT_VERSION) {
        throw std::runtime_error("Unsupported format version " + std::to_string(header[5]));
    }
    size_t chunk_size = LoadU32LE(header + 6);
    if (chunk_size == 0 || chunk_size > ChunkedCrypto::MAX_CHUNK_SIZE) {
        throw std::runtime_error("Invalid chunk size in header");
    }
    return chunk_size;
}

// Call read_fn until `n` bytes are read or it reports EOF.
size_t ReadFull(const std::function<size_t(uint8_t*, size_t)>& read_fn, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        size_t got = read_fn(buf + total, n - total);
        if (got == 0) break;
        total += got;
    }
    return total;
}

void CheckKey(const std::vector<uint8_t>& key) {
    if (key.size() != kKeySize) throw std::runtime_error("Key must be 32 bytes");
}

} // namespace

// ── KeyManager ──────────────────────────────────────────────────────────────

std::vector<uint8_t> KeyManager::LoadKeyFromFile(const std::string& key_path) {
    std::vector<uint8_t> raw;
    if (!ReadWholeFile(key_path, raw)) {
        throw std::runtime_error("Failed to open key file: " + key_path);
    }
    if (raw.size() == kKeySize) {
        return raw;  // raw binary key
    }

    std::string text(raw.begin(), raw.end());
    SecureWipe(raw);
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    text.erase(text.begin(), std::find_if(text.begin(), text.end(), not_space));
    text.erase(std::find_if(text.rbegin(), text.rend(), not_space).base(), text.end());

    std::vector<uint8_t> key;
    bool ok = text.size() == kKeySize * 2 && HexDecode(text, key);
    SecureWipe(text);
    if (!ok) {
        throw std::runtime_error(
            "Key file must contain 64 hex characters or exactly 32 raw bytes: " + key_path);
    }
    return key;
}

std::vector<uint8_t> KeyManager::LoadLegacyKeyFromFile(const std::string& key_path) {
    std::vector<uint8_t> raw;
    if (!ReadWholeFile(key_path, raw)) {
        throw std::runtime_error("Failed to open key file: " + key_path);
    }
    if (raw.size() < kKeySize) {
        SecureWipe(raw);
        throw std::runtime_error("Key file must be at least 32 bytes");
    }
    std::vector<uint8_t> key(raw.begin(), raw.begin() + kKeySize);
    SecureWipe(raw);
    return key;
}

std::vector<uint8_t> KeyManager::DeriveKeyFromPassphrase(
    const std::string& passphrase,
    const std::vector<uint8_t>& salt,
    int iterations
) {
    if (iterations <= 0) throw std::runtime_error("PBKDF2 iterations must be positive");
    std::vector<uint8_t> key(kKeySize);
    if (PKCS5_PBKDF2_HMAC(
            passphrase.data(), static_cast<int>(passphrase.size()),
            salt.data(), static_cast<int>(salt.size()),
            iterations,
            EVP_sha256(),
            static_cast<int>(key.size()), key.data()) != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed");
    }
    return key;
}

std::vector<uint8_t> KeyManager::DeriveSubkey(const std::vector<uint8_t>& key,
                                              const std::string& label) {
    return HMAC::Compute(key, std::vector<uint8_t>(label.begin(), label.end()));
}

std::vector<uint8_t> KeyManager::RandomBytes(size_t count) {
    std::vector<uint8_t> bytes(count);
    if (count > INT_MAX || RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return bytes;
}

// ── HMAC ────────────────────────────────────────────────────────────────────

std::vector<uint8_t> HMAC::Compute(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data
) {
    std::vector<uint8_t> result(32);
    unsigned int len = 32;
    // ::HMAC — the OpenSSL function, not this class.
    if (::HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
               data.data(), data.size(), result.data(), &len) == nullptr || len != 32) {
        throw std::runtime_error("HMAC computation failed");
    }
    return result;
}

std::string HMAC::ComputeHex(
    const std::vector<uint8_t>& key,
    const std::string& data
) {
    std::vector<uint8_t> mac = Compute(key, std::vector<uint8_t>(data.begin(), data.end()));
    return HexEncode(mac.data(), mac.size());
}

// ── SimpleCrypto ────────────────────────────────────────────────────────────

std::vector<uint8_t> SimpleCrypto::Encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad
) {
    CheckKey(key);
    std::vector<uint8_t> out = KeyManager::RandomBytes(kNonceSize);
    out.resize(kNonceSize + plaintext.size() + kTagSize);
    if (!GcmEncrypt(key.data(), out.data(), aad.data(), aad.size(),
                    plaintext.data(), plaintext.size(),
                    out.data() + kNonceSize, out.data() + kNonceSize + plaintext.size())) {
        throw std::runtime_error("Encryption failed");
    }
    return out;
}

std::vector<uint8_t> SimpleCrypto::Decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad
) {
    CheckKey(key);
    if (ciphertext.size() < kNonceSize + kTagSize) {
        throw std::runtime_error("Ciphertext too short");
    }
    size_t len = ciphertext.size() - kNonceSize - kTagSize;
    std::vector<uint8_t> plaintext(len);
    if (!GcmDecrypt(key.data(), ciphertext.data(), aad.data(), aad.size(),
                    ciphertext.data() + kNonceSize, len,
                    ciphertext.data() + kNonceSize + len, plaintext.data())) {
        SecureWipe(plaintext);
        throw std::runtime_error("Decryption failed");
    }
    return plaintext;
}

// ── ChunkedCrypto (v2) ──────────────────────────────────────────────────────

uint8_t ChunkedCrypto::PeekFormatVersion(const std::vector<uint8_t>& blob) {
    if (blob.size() < 6 || std::memcmp(blob.data(), kMagic, sizeof(kMagic)) != 0) return 0;
    return blob[5];
}

std::vector<uint8_t> ChunkedCrypto::Encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    size_t chunk_size,
    const std::vector<uint8_t>& aad
) {
    CheckKey(key);
    if (chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE) {
        throw std::runtime_error("Invalid chunk size");
    }
    size_t num_chunks = std::max<size_t>(1, (plaintext.size() + chunk_size - 1) / chunk_size);
    if (num_chunks > UINT32_MAX) throw std::runtime_error("Plaintext too large");

    std::vector<uint8_t> salt = KeyManager::RandomBytes(kSaltSize);
    std::vector<uint8_t> header = BuildHeader(chunk_size, salt);
    std::vector<uint8_t> file_key = FileKey(key, salt.data());
    std::vector<uint8_t> full_aad = Concat(header, aad);

    std::vector<uint8_t> out;
    out.reserve(header.size() + plaintext.size() + num_chunks * (4 + kTagSize));
    out.insert(out.end(), header.begin(), header.end());

    for (size_t i = 0; i < num_chunks; ++i) {
        size_t offset = i * chunk_size;
        size_t len = std::min(chunk_size, plaintext.size() - offset);
        bool last = (i + 1 == num_chunks);

        uint8_t nonce[kNonceSize];
        ChunkNonce(static_cast<uint32_t>(i), last, nonce);

        AppendU32LE(out, static_cast<uint32_t>(len));
        size_t ct_pos = out.size();
        out.resize(ct_pos + len + kTagSize);
        if (!GcmEncrypt(file_key.data(), nonce, full_aad.data(), full_aad.size(),
                        plaintext.data() + offset, len,
                        out.data() + ct_pos, out.data() + ct_pos + len)) {
            SecureWipe(file_key);
            throw std::runtime_error("Chunk encryption failed");
        }
    }
    SecureWipe(file_key);
    return out;
}

std::vector<uint8_t> ChunkedCrypto::Decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad
) {
    CheckKey(key);
    if (ciphertext.size() < HEADER_SIZE) {
        throw std::runtime_error("Ciphertext too short");
    }
    size_t chunk_size = ParseHeader(ciphertext.data());
    std::vector<uint8_t> header(ciphertext.begin(), ciphertext.begin() + HEADER_SIZE);
    std::vector<uint8_t> full_aad = Concat(header, aad);
    std::vector<uint8_t> file_key = FileKey(key, ciphertext.data() + 10);

    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());

    const size_t total = ciphertext.size();
    size_t offset = HEADER_SIZE;
    uint64_t index = 0;
    bool saw_last = false;

    try {
        while (offset < total) {
            if (index > UINT32_MAX) throw std::runtime_error("Too many chunks");
            if (total - offset < 4) throw std::runtime_error("Truncated chunk header");
            size_t len = LoadU32LE(ciphertext.data() + offset);
            offset += 4;
            if (len > chunk_size) throw std::runtime_error("Chunk larger than chunk size");
            if (total - offset < len + kTagSize) throw std::runtime_error("Truncated chunk");

            bool last = (offset + len + kTagSize == total);
            if (!last && len != chunk_size) throw std::runtime_error("Short non-final chunk");

            uint8_t nonce[kNonceSize];
            ChunkNonce(static_cast<uint32_t>(index), last, nonce);

            size_t pt_pos = plaintext.size();
            plaintext.resize(pt_pos + len);
            if (!GcmDecrypt(file_key.data(), nonce, full_aad.data(), full_aad.size(),
                            ciphertext.data() + offset, len,
                            ciphertext.data() + offset + len, plaintext.data() + pt_pos)) {
                throw std::runtime_error("Chunk authentication failed");
            }
            offset += len + kTagSize;
            ++index;
            saw_last = last;
        }
        if (!saw_last) throw std::runtime_error("Truncated ciphertext: no chunks");
    } catch (...) {
        SecureWipe(plaintext);
        SecureWipe(file_key);
        throw;
    }
    SecureWipe(file_key);
    return plaintext;
}

bool ChunkedCrypto::EncryptStream(
    std::function<size_t(uint8_t*, size_t)> read_fn,
    std::function<bool(const uint8_t*, size_t)> write_fn,
    const std::vector<uint8_t>& key,
    size_t chunk_size,
    const std::vector<uint8_t>& aad
) {
    if (key.size() != kKeySize || chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE) return false;

    std::vector<uint8_t> salt = KeyManager::RandomBytes(kSaltSize);
    std::vector<uint8_t> header = BuildHeader(chunk_size, salt);
    std::vector<uint8_t> file_key = FileKey(key, salt.data());
    std::vector<uint8_t> full_aad = Concat(header, aad);

    if (!write_fn(header.data(), header.size())) return false;

    // One chunk of look-ahead: we can only set the "final" flag on a chunk
    // once we know nothing follows it.
    std::vector<uint8_t> cur(chunk_size), next(chunk_size), ct(chunk_size);
    size_t cur_len = ReadFull(read_fn, cur.data(), chunk_size);
    uint32_t index = 0;
    bool ok = true;

    while (ok) {
        size_t next_len = 0;
        bool last = true;
        if (cur_len == chunk_size) {
            next_len = ReadFull(read_fn, next.data(), chunk_size);
            last = (next_len == 0);
        }

        uint8_t nonce[kNonceSize];
        uint8_t tag[kTagSize];
        std::vector<uint8_t> len_le;
        ChunkNonce(index, last, nonce);
        AppendU32LE(len_le, static_cast<uint32_t>(cur_len));

        ok = GcmEncrypt(file_key.data(), nonce, full_aad.data(), full_aad.size(),
                        cur.data(), cur_len, ct.data(), tag) &&
             write_fn(len_le.data(), len_le.size()) &&
             (cur_len == 0 || write_fn(ct.data(), cur_len)) &&
             write_fn(tag, kTagSize);

        if (!ok || last) break;
        if (index == UINT32_MAX) { ok = false; break; }
        ++index;
        std::swap(cur, next);
        cur_len = next_len;
    }

    SecureWipe(file_key);
    SecureWipe(cur);
    SecureWipe(next);
    return ok;
}

bool ChunkedCrypto::DecryptStream(
    std::function<size_t(uint8_t*, size_t)> read_fn,
    std::function<bool(const uint8_t*, size_t)> write_fn,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& aad
) {
    if (key.size() != kKeySize) return false;

    std::vector<uint8_t> header(HEADER_SIZE);
    if (ReadFull(read_fn, header.data(), HEADER_SIZE) != HEADER_SIZE) return false;
    size_t chunk_size;
    try {
        chunk_size = ParseHeader(header.data());
    } catch (const std::exception&) {
        return false;
    }

    std::vector<uint8_t> file_key = FileKey(key, header.data() + 10);
    std::vector<uint8_t> full_aad = Concat(header, aad);
    std::vector<uint8_t> ct, pt;
    bool ok = false;

    for (uint64_t index = 0; index <= UINT32_MAX; ++index) {
        uint8_t len_le[4];
        if (ReadFull(read_fn, len_le, 4) != 4) break;  // EOF before final chunk
        size_t len = LoadU32LE(len_le);
        if (len > chunk_size) break;

        ct.resize(len + kTagSize);
        pt.resize(len);
        if (ReadFull(read_fn, ct.data(), ct.size()) != ct.size()) break;

        // A short chunk can only be the final one. A full-size chunk is
        // normally not final, but may be when the plaintext length is an
        // exact multiple of the chunk size.
        uint8_t nonce[kNonceSize];
        bool last = (len < chunk_size);
        ChunkNonce(static_cast<uint32_t>(index), last, nonce);
        bool authed = GcmDecrypt(file_key.data(), nonce, full_aad.data(), full_aad.size(),
                                 ct.data(), len, ct.data() + len, pt.data());
        if (!authed && !last) {
            last = true;
            ChunkNonce(static_cast<uint32_t>(index), last, nonce);
            authed = GcmDecrypt(file_key.data(), nonce, full_aad.data(), full_aad.size(),
                                ct.data(), len, ct.data() + len, pt.data());
        }
        if (!authed) break;
        if (len > 0 && !write_fn(pt.data(), len)) break;

        if (last) {
            uint8_t extra;
            ok = (read_fn(&extra, 1) == 0);  // nothing may follow the final chunk
            break;
        }
    }

    SecureWipe(file_key);
    SecureWipe(pt);
    return ok;
}

// ── Legacy v1 format (read-only) ────────────────────────────────────────────
// header: "ENCFS" | 0x01 | file_nonce(12) | num_chunks:u32
// chunk:  len:u32 | nonce(12) | ciphertext | tag(16)

std::vector<uint8_t> ChunkedCrypto::DecryptLegacyV1(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key
) {
    CheckKey(key);
    constexpr size_t kV1Header = 22;
    if (ciphertext.size() < kV1Header) throw std::runtime_error("Ciphertext too short");
    if (std::memcmp(ciphertext.data(), kMagic, sizeof(kMagic)) != 0) {
        throw std::runtime_error("Invalid magic bytes");
    }
    if (ciphertext[5] != 1) throw std::runtime_error("Not a v1 blob");

    uint32_t num_chunks = LoadU32LE(ciphertext.data() + 18);
    std::vector<uint8_t> plaintext;
    size_t offset = kV1Header;

    for (uint32_t i = 0; i < num_chunks; ++i) {
        if (ciphertext.size() - offset < 4 + kNonceSize) throw std::runtime_error("Truncated ciphertext");
        size_t len = LoadU32LE(ciphertext.data() + offset);
        offset += 4;
        const uint8_t* nonce = ciphertext.data() + offset;
        offset += kNonceSize;
        if (ciphertext.size() - offset < len + kTagSize) throw std::runtime_error("Truncated chunk");

        size_t pt_pos = plaintext.size();
        plaintext.resize(pt_pos + len);
        if (!GcmDecrypt(key.data(), nonce, nullptr, 0,
                        ciphertext.data() + offset, len,
                        ciphertext.data() + offset + len, plaintext.data() + pt_pos)) {
            SecureWipe(plaintext);
            throw std::runtime_error("Chunk decryption failed");
        }
        offset += len + kTagSize;
    }
    return plaintext;
}

} // namespace encfs

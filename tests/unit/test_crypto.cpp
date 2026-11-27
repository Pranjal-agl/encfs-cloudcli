#include "crypto.h"
#include "util.h"
#include "../test_util.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <fstream>

using namespace encfs;
using namespace encfs_test;

namespace {

const std::vector<uint8_t> kKey(32, 0x42);

std::vector<uint8_t> Pattern(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>((i * 31 + 7) & 0xff);
    return v;
}

void WriteFile(const std::string& path, const std::string& content) {
    std::ofstream(path, std::ios::binary) << content;
}

// Offset of chunk `i` in a v2 blob whose chunks are all full-size up to i.
size_t ChunkOffset(size_t i, size_t chunk_size) {
    return ChunkedCrypto::HEADER_SIZE + i * (4 + chunk_size + ChunkedCrypto::TAG_SIZE);
}

bool DecryptFails(const std::vector<uint8_t>& blob, const std::vector<uint8_t>& aad = {}) {
    try {
        ChunkedCrypto::Decrypt(blob, kKey, aad);
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

// Stream helpers over in-memory buffers. `max_read` simulates short reads.
std::function<size_t(uint8_t*, size_t)> Reader(const std::vector<uint8_t>& src, size_t& pos,
                                               size_t max_read = SIZE_MAX) {
    return [&src, &pos, max_read](uint8_t* buf, size_t n) {
        size_t take = std::min({n, src.size() - pos, max_read});
        std::memcpy(buf, src.data() + pos, take);
        pos += take;
        return take;
    };
}

std::function<bool(const uint8_t*, size_t)> Writer(std::vector<uint8_t>& dst) {
    return [&dst](const uint8_t* buf, size_t n) {
        dst.insert(dst.end(), buf, buf + n);
        return true;
    };
}

// Build a blob in the original v1 format, to test read compatibility.
std::vector<uint8_t> MakeV1Blob(const std::vector<uint8_t>& plaintext, size_t chunk_size) {
    std::vector<uint8_t> file_nonce = KeyManager::RandomBytes(12);
    size_t n = (plaintext.size() + chunk_size - 1) / chunk_size;
    std::vector<uint8_t> out = {'E', 'N', 'C', 'F', 'S', 1};
    out.insert(out.end(), file_nonce.begin(), file_nonce.end());
    AppendU32LE(out, static_cast<uint32_t>(n));
    for (size_t i = 0; i < n; ++i) {
        size_t off = i * chunk_size;
        size_t len = std::min(chunk_size, plaintext.size() - off);
        std::vector<uint8_t> nonce(file_nonce.begin(), file_nonce.begin() + 8);
        AppendU32LE(nonce, static_cast<uint32_t>(i));
        std::vector<uint8_t> ct(len), tag(16);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        uint8_t fin[16];
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, kKey.data(), nonce.data());
        EVP_EncryptUpdate(ctx, ct.data(), &outl, plaintext.data() + off, static_cast<int>(len));
        EVP_EncryptFinal_ex(ctx, fin, &outl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
        EVP_CIPHER_CTX_free(ctx);
        AppendU32LE(out, static_cast<uint32_t>(len));
        out.insert(out.end(), nonce.begin(), nonce.end());
        out.insert(out.end(), ct.begin(), ct.end());
        out.insert(out.end(), tag.begin(), tag.end());
    }
    return out;
}

// ── Tests ───────────────────────────────────────────────────────────────────

void TestKeyManager() {
    auto r1 = KeyManager::RandomBytes(32);
    auto r2 = KeyManager::RandomBytes(32);
    CHECK(r1.size() == 32);
    CHECK(r1 != r2);

    auto salt = KeyManager::RandomBytes(16);
    auto k1 = KeyManager::DeriveKeyFromPassphrase("test_passphrase", salt, 1000);
    auto k2 = KeyManager::DeriveKeyFromPassphrase("test_passphrase", salt, 1000);
    auto k3 = KeyManager::DeriveKeyFromPassphrase("test_passphrase", KeyManager::RandomBytes(16), 1000);
    auto k4 = KeyManager::DeriveKeyFromPassphrase("other", salt, 1000);
    CHECK(k1.size() == 32);
    CHECK(k1 == k2);
    CHECK(k1 != k3);
    CHECK(k1 != k4);
    CHECK_THROWS(KeyManager::DeriveKeyFromPassphrase("x", salt, 0));

    CHECK(KeyManager::DeriveSubkey(kKey, "a") != KeyManager::DeriveSubkey(kKey, "b"));
    CHECK(KeyManager::DeriveSubkey(kKey, "a") == KeyManager::DeriveSubkey(kKey, "a"));
}

void TestKeyFiles() {
    TempDir dir;
    const std::string hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    std::vector<uint8_t> expected(32);
    for (int i = 0; i < 32; ++i) expected[i] = static_cast<uint8_t>(i);

    // Hex, as written by `openssl rand -hex 32` (trailing newline).
    WriteFile(dir / "hex", hex + "\n");
    CHECK(KeyManager::LoadKeyFromFile(dir / "hex") == expected);

    // Upper-case hex and surrounding whitespace are fine.
    std::string upper = hex;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    WriteFile(dir / "upper", "  " + upper + "\r\n");
    CHECK(KeyManager::LoadKeyFromFile(dir / "upper") == expected);

    // Raw 32 bytes, as written by `openssl rand 32`.
    WriteFile(dir / "raw", std::string(expected.begin(), expected.end()));
    CHECK(KeyManager::LoadKeyFromFile(dir / "raw") == expected);

    // Malformed key files are rejected rather than silently used.
    WriteFile(dir / "short", std::string(31, 'a'));
    CHECK_THROWS(KeyManager::LoadKeyFromFile(dir / "short"));
    WriteFile(dir / "nothex", std::string(64, 'z'));
    CHECK_THROWS(KeyManager::LoadKeyFromFile(dir / "nothex"));
    WriteFile(dir / "hex16", hex.substr(0, 32) + "\n");
    CHECK_THROWS(KeyManager::LoadKeyFromFile(dir / "hex16"));
    CHECK_THROWS(KeyManager::LoadKeyFromFile(dir / "missing"));

    // Legacy interpretation: the first 32 bytes verbatim.
    auto legacy = KeyManager::LoadLegacyKeyFromFile(dir / "hex");
    CHECK(legacy == Bytes(hex.substr(0, 32)));
}

void TestHmacVector() {
    // RFC 4231, test case 2.
    auto mac = HMAC::ComputeHex(Bytes("Jefe"), "what do ya want for nothing?");
    CHECK(mac == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    CHECK(HMAC::Compute(kKey, Bytes("x")).size() == 32);
}

void TestHexAndEndian() {
    std::vector<uint8_t> out;
    CHECK(HexDecode("00ff10", out) && out == std::vector<uint8_t>({0x00, 0xff, 0x10}));
    CHECK(!HexDecode("abc", out));
    CHECK(!HexDecode("zz", out));
    CHECK(HexEncode(out.data(), out.size()) == "00ff10");

    std::vector<uint8_t> le;
    AppendU32LE(le, 0x01020304u);
    AppendU64LE(le, 0x0102030405060708ull);
    CHECK(le[0] == 0x04 && le[3] == 0x01 && le[4] == 0x08 && le[11] == 0x01);
    CHECK(LoadU32LE(le.data()) == 0x01020304u);
    CHECK(LoadU64LE(le.data() + 4) == 0x0102030405060708ull);
}

void TestSimpleCrypto() {
    auto plaintext = Bytes("Hello, encrypted world!");
    auto ct = SimpleCrypto::Encrypt(plaintext, kKey);
    CHECK(ct.size() == plaintext.size() + 28);
    CHECK(SimpleCrypto::Decrypt(ct, kKey) == plaintext);
    CHECK(SimpleCrypto::Encrypt(plaintext, kKey) != ct);  // fresh nonce each time

    CHECK_THROWS(SimpleCrypto::Decrypt(ct, std::vector<uint8_t>(32, 0x43)));
    auto bad = ct;
    bad[15] ^= 1;
    CHECK_THROWS(SimpleCrypto::Decrypt(bad, kKey));
    CHECK_THROWS(SimpleCrypto::Decrypt(std::vector<uint8_t>(10), kKey));

    auto with_aad = SimpleCrypto::Encrypt(plaintext, kKey, Bytes("ctx"));
    CHECK(SimpleCrypto::Decrypt(with_aad, kKey, Bytes("ctx")) == plaintext);
    CHECK_THROWS(SimpleCrypto::Decrypt(with_aad, kKey, Bytes("other")));

    CHECK(SimpleCrypto::Decrypt(SimpleCrypto::Encrypt({}, kKey), kKey).empty());
    CHECK_THROWS(SimpleCrypto::Encrypt(plaintext, std::vector<uint8_t>(16)));
}

void TestChunkedRoundTrips() {
    const size_t cs = 1024;
    for (size_t n : {size_t(0), size_t(1), cs - 1, cs, cs + 1, 3 * cs, 3 * cs + 17}) {
        auto pt = Pattern(n);
        auto blob = ChunkedCrypto::Encrypt(pt, kKey, cs);
        CHECK(ChunkedCrypto::PeekFormatVersion(blob) == 2);
        CHECK(ChunkedCrypto::Decrypt(blob, kKey) == pt);
    }

    // Default 8 MiB chunks with a multi-chunk file.
    auto big = Pattern(10 * 1024 * 1024);
    CHECK(ChunkedCrypto::Decrypt(ChunkedCrypto::Encrypt(big, kKey), kKey) == big);

    // Same input encrypts differently every time (fresh salt → fresh file key).
    auto pt = Pattern(1000);
    auto c1 = ChunkedCrypto::Encrypt(pt, kKey);
    auto c2 = ChunkedCrypto::Encrypt(pt, kKey);
    CHECK(c1 != c2);
    CHECK(ChunkedCrypto::Decrypt(c1, kKey) == pt);
    CHECK(ChunkedCrypto::Decrypt(c2, kKey) == pt);

    CHECK_THROWS(ChunkedCrypto::Encrypt(pt, kKey, 0));
    CHECK_THROWS(ChunkedCrypto::Encrypt(pt, std::vector<uint8_t>(31)));
}

void TestEmptyFileIsAuthenticated() {
    auto blob = ChunkedCrypto::Encrypt({}, kKey, 64);
    CHECK(blob.size() == ChunkedCrypto::HEADER_SIZE + 4 + 16);
    CHECK(ChunkedCrypto::Decrypt(blob, kKey).empty());
    // The header alone (all chunks stripped) must not decrypt to "empty".
    std::vector<uint8_t> header_only(blob.begin(), blob.begin() + ChunkedCrypto::HEADER_SIZE);
    CHECK(DecryptFails(header_only));
    CHECK(DecryptFails(blob, Bytes("wrong context")));
}

void TestTamperingDetected() {
    const size_t cs = 256;
    auto blob = ChunkedCrypto::Encrypt(Pattern(3 * cs + 10), kKey, cs);
    // Flip one bit in every byte position in turn: header, lengths, data, tags.
    int undetected = 0;
    for (size_t i = 0; i < blob.size(); ++i) {
        auto bad = blob;
        bad[i] ^= 0x01;
        if (!DecryptFails(bad)) ++undetected;
    }
    CHECK(undetected == 0);
    CHECK(DecryptFails(blob, Bytes("aad")));
    CHECK(DecryptFails(std::vector<uint8_t>(blob.begin(), blob.begin() + 5)));
}

void TestTruncationAndExtensionDetected() {
    const size_t cs = 256;
    auto blob = ChunkedCrypto::Encrypt(Pattern(3 * cs), kKey, cs);  // exactly 3 full chunks

    // Dropping whole trailing chunks leaves a structurally valid blob — the
    // final-chunk flag is what catches it.
    for (size_t keep = 1; keep < 3; ++keep) {
        std::vector<uint8_t> cut(blob.begin(), blob.begin() + ChunkOffset(keep, cs));
        CHECK(DecryptFails(cut));
    }
    // Chopping bytes off the end.
    CHECK(DecryptFails(std::vector<uint8_t>(blob.begin(), blob.end() - 1)));

    // Appending a copy of an earlier chunk.
    auto extended = blob;
    extended.insert(extended.end(), blob.begin() + ChunkOffset(0, cs), blob.begin() + ChunkOffset(1, cs));
    CHECK(DecryptFails(extended));
    // Appending junk.
    auto junk = blob;
    junk.push_back(0);
    CHECK(DecryptFails(junk));
}

void TestReorderAndSpliceDetected() {
    const size_t cs = 256;
    auto blob = ChunkedCrypto::Encrypt(Pattern(3 * cs + 5), kKey, cs);

    // Swap chunks 0 and 1.
    auto swapped = blob;
    const size_t span = 4 + cs + 16;
    std::copy(blob.begin() + ChunkOffset(1, cs), blob.begin() + ChunkOffset(1, cs) + span,
              swapped.begin() + ChunkOffset(0, cs));
    std::copy(blob.begin() + ChunkOffset(0, cs), blob.begin() + ChunkOffset(0, cs) + span,
              swapped.begin() + ChunkOffset(1, cs));
    CHECK(DecryptFails(swapped));

    // Splice a chunk from another file encrypted under the same key.
    auto other = ChunkedCrypto::Encrypt(Pattern(3 * cs + 5), kKey, cs);
    auto spliced = blob;
    std::copy(other.begin() + ChunkOffset(1, cs), other.begin() + ChunkOffset(1, cs) + span,
              spliced.begin() + ChunkOffset(1, cs));
    CHECK(DecryptFails(spliced));

    // Graft another file's header onto this file's chunks.
    auto grafted = blob;
    std::copy(other.begin(), other.begin() + ChunkedCrypto::HEADER_SIZE, grafted.begin());
    CHECK(DecryptFails(grafted));
}

void TestMalformedHeaders() {
    auto blob = ChunkedCrypto::Encrypt(Pattern(100), kKey, 64);
    auto bad_version = blob;
    bad_version[5] = 9;
    CHECK_THROWS(ChunkedCrypto::Decrypt(bad_version, kKey));

    auto zero_chunk = blob;
    zero_chunk[6] = zero_chunk[7] = zero_chunk[8] = zero_chunk[9] = 0;
    CHECK_THROWS(ChunkedCrypto::Decrypt(zero_chunk, kKey));

    auto huge_chunk = blob;
    huge_chunk[9] = 0x7f;  // ~2 GiB chunk size: must be rejected before allocating
    CHECK_THROWS(ChunkedCrypto::Decrypt(huge_chunk, kKey));

    CHECK(ChunkedCrypto::PeekFormatVersion(Bytes("garbage")) == 0);
}

void TestStreaming() {
    const size_t cs = 128;
    const std::vector<uint8_t> aad = Bytes("stream-aad");
    for (size_t n : {size_t(0), size_t(5), cs, 2 * cs, 5 * cs + 3}) {
        auto pt = Pattern(n);

        // Stream-encrypt (with 7-byte short reads) → in-memory decrypt.
        std::vector<uint8_t> blob;
        size_t pos = 0;
        CHECK(ChunkedCrypto::EncryptStream(Reader(pt, pos, 7), Writer(blob), kKey, cs, aad));
        CHECK(ChunkedCrypto::Decrypt(blob, kKey, aad) == pt);

        // In-memory encrypt → stream-decrypt (with 5-byte short reads).
        auto blob2 = ChunkedCrypto::Encrypt(pt, kKey, cs, aad);
        std::vector<uint8_t> out;
        pos = 0;
        CHECK(ChunkedCrypto::DecryptStream(Reader(blob2, pos, 5), Writer(out), kKey, aad));
        CHECK(out == pt);

        // Stream-decrypt rejects truncation, trailing data, and wrong AAD.
        if (!blob2.empty()) {
            std::vector<uint8_t> cut(blob2.begin(), blob2.end() - 1), sink;
            pos = 0;
            CHECK(!ChunkedCrypto::DecryptStream(Reader(cut, pos), Writer(sink), kKey, aad));
        }
        auto longer = blob2;
        longer.push_back(0);
        std::vector<uint8_t> sink;
        pos = 0;
        CHECK(!ChunkedCrypto::DecryptStream(Reader(longer, pos), Writer(sink), kKey, aad));
        pos = 0;
        sink.clear();
        CHECK(!ChunkedCrypto::DecryptStream(Reader(blob2, pos), Writer(sink), kKey, Bytes("x")));
    }
}

void TestLegacyV1() {
    auto pt = Pattern(5000);
    auto v1 = MakeV1Blob(pt, 1024);
    CHECK(ChunkedCrypto::PeekFormatVersion(v1) == 1);
    CHECK(ChunkedCrypto::DecryptLegacyV1(v1, kKey) == pt);
    CHECK_THROWS(ChunkedCrypto::Decrypt(v1, kKey));  // v2 decoder refuses v1
    auto bad = v1;
    bad[bad.size() - 1] ^= 1;
    CHECK_THROWS(ChunkedCrypto::DecryptLegacyV1(bad, kKey));
    CHECK_THROWS(ChunkedCrypto::DecryptLegacyV1(v1, std::vector<uint8_t>(32, 1)));
}

} // namespace

int main() {
    return RunTests("crypto", {
        {"KeyManager: random bytes, PBKDF2, sub-keys", TestKeyManager},
        {"Key files: hex, raw, malformed, legacy", TestKeyFiles},
        {"HMAC-SHA256 matches RFC 4231 vector", TestHmacVector},
        {"Hex and little-endian helpers", TestHexAndEndian},
        {"SimpleCrypto round trip, tamper, AAD", TestSimpleCrypto},
        {"ChunkedCrypto round trips at chunk boundaries", TestChunkedRoundTrips},
        {"Empty plaintext is still authenticated", TestEmptyFileIsAuthenticated},
        {"Any single-bit flip is detected", TestTamperingDetected},
        {"Truncation and extension are detected", TestTruncationAndExtensionDetected},
        {"Chunk reorder / cross-file splice detected", TestReorderAndSpliceDetected},
        {"Malformed headers rejected", TestMalformedHeaders},
        {"Streaming API interoperates with in-memory API", TestStreaming},
        {"Legacy v1 blobs still decrypt", TestLegacyV1},
    });
}

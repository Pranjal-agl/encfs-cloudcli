// Cross-implementation fixtures for web/encfs.js.
//
//   web_fixtures gen <dir>     write a backing dir + expectations with the C++ code
//   web_fixtures verify <dir>  check blobs/index that encfs.js wrote into <dir>/js
//
// See tests/web/run_cross_check.sh.

#include "crypto.h"
#include "file_codec.h"
#include "index.h"
#include "key_setup.h"
#include "util.h"

#include <openssl/evp.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>

using namespace encfs;

namespace {

std::vector<uint8_t> MasterKey() {
    std::vector<uint8_t> k(32);
    for (int i = 0; i < 32; ++i) k[i] = static_cast<uint8_t>(i);
    return k;
}

std::vector<uint8_t> Pattern(size_t n, int seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>((i * 31 + static_cast<size_t>(seed) * 7) & 0xff);
    return v;
}

std::vector<uint8_t> Bytes(const std::string& s) { return {s.begin(), s.end()}; }

void Write(const std::string& path, const std::vector<uint8_t>& data) {
    if (!WriteFileAtomic(path, data, 0644)) throw std::runtime_error("write failed: " + path);
}

// Original v1 format, to check the JS legacy decoder.
std::vector<uint8_t> V1Blob(const std::vector<uint8_t>& pt, const std::vector<uint8_t>& key, size_t cs) {
    std::vector<uint8_t> file_nonce(12, 0x5a);
    size_t n = (pt.size() + cs - 1) / cs;
    std::vector<uint8_t> out = {'E', 'N', 'C', 'F', 'S', 1};
    out.insert(out.end(), file_nonce.begin(), file_nonce.end());
    AppendU32LE(out, static_cast<uint32_t>(n));
    for (size_t i = 0; i < n; ++i) {
        size_t off = i * cs, len = std::min(cs, pt.size() - off);
        std::vector<uint8_t> nonce(file_nonce.begin(), file_nonce.begin() + 8);
        AppendU32LE(nonce, static_cast<uint32_t>(i));
        std::vector<uint8_t> ct(len + 16);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int outl = 0;
        uint8_t fin[16];
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data());
        EVP_EncryptUpdate(ctx, ct.data(), &outl, pt.data() + off, static_cast<int>(len));
        EVP_EncryptFinal_ex(ctx, fin, &outl);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ct.data() + len);
        EVP_CIPHER_CTX_free(ctx);
        AppendU32LE(out, static_cast<uint32_t>(len));
        out.insert(out.end(), nonce.begin(), nonce.end());
        out.insert(out.end(), ct.begin(), ct.end());
    }
    return out;
}

int Gen(const std::string& dir) {
    const auto master = MasterKey();
    const std::string backing = dir + "/backing";
    ::mkdir(backing.c_str(), 0700);
    Write(dir + "/key", Bytes(HexEncode(master.data(), master.size()) + "\n"));

    FileCodec codec(master);
    codec.set_chunk_size(64);
    EncryptedIndex index(backing, master);
    std::ostringstream expected;  // name \t status \t hex(content)
    int seed = 0;

    auto add = [&](const std::string& name, const std::vector<uint8_t>& pt, uint64_t index_version,
                   uint64_t blob_version, const std::string& status) {
        FileMetadata meta;
        meta.remote_id = codec.RemoteIdFor(name);
        meta.version = index_version;
        meta.size = pt.size();
        meta.mtime = 1700000000 + seed;
        index.SetMetadata(name, meta);
        Write(backing + "/" + meta.remote_id + ".enc", codec.Encrypt(pt, meta.remote_id, blob_version));
        expected << name << "\t" << status << "\t" << HexEncode(pt.data(), pt.size()) << "\n";
    };

    add("hello.txt", Bytes("Hello from C++"), 2, 2, "ok");
    add("empty", {}, 3, 3, "ok");
    add("exact.bin", Pattern(128, ++seed), 2, 2, "ok");
    add("docs/big.bin", Pattern(1000, ++seed), 5, 5, "ok");
    add("docs/ünïcødé name.txt", Bytes("names are UTF-8"), 2, 2, "ok");
    add("ahead.txt", Bytes("index lags one version"), 4, 5, "ok");
    add("rolled.txt", Bytes("stale copy"), 6, 4, "rollback");

    FileMetadata dir_meta;
    dir_meta.mtime = 1700000100;
    index.SetMetadata("docs", dir_meta);
    expected << "docs\tdir\t\n";

    // A blob that's authentic but belongs to another file.
    FileMetadata swapped;
    swapped.remote_id = codec.RemoteIdFor("swapped.txt");
    swapped.version = 2;
    swapped.size = 5;
    index.SetMetadata("swapped.txt", swapped);
    Write(backing + "/" + swapped.remote_id + ".enc", codec.Encrypt(Bytes("other"), codec.RemoteIdFor("x"), 2));
    expected << "swapped.txt\tcorrupt\t\n";

    // Legacy v1 blob (master key used directly).
    auto legacy_pt = Pattern(150, ++seed);
    FileMetadata legacy;
    legacy.remote_id = codec.RemoteIdFor("legacy.bin");
    legacy.size = legacy_pt.size();
    index.SetMetadata("legacy.bin", legacy);
    Write(backing + "/" + legacy.remote_id + ".enc", V1Blob(legacy_pt, master, 64));
    expected << "legacy.bin\tok\t" << HexEncode(legacy_pt.data(), legacy_pt.size()) << "\n";

    if (!index.Save()) throw std::runtime_error("index save failed");
    std::string exp = expected.str();
    Write(dir + "/expected.tsv", Bytes(exp));

    // Passphrase KDF: file + the key it must produce.
    std::vector<uint8_t> kdf = Bytes("ENCFSKDF");
    AppendU32LE(kdf, 10000);
    std::vector<uint8_t> salt(16, 0xab);
    kdf.insert(kdf.end(), salt.begin(), salt.end());
    Write(dir + "/encfs.kdf", kdf);
    auto pkey = KeyManager::DeriveKeyFromPassphrase("correct horse battery staple", salt, 10000);
    Write(dir + "/kdf_expected.hex", Bytes(HexEncode(pkey.data(), pkey.size())));

    // v2 (wrapped) KDF file, as `encfsctl init --passphrase` writes it.
    const std::string v2dir = dir + "/kdf_v2";
    ::mkdir(v2dir.c_str(), 0700);
    std::vector<uint8_t> wrapped_master;
    std::string error;
    if (!CreatePassphraseStore(v2dir, "correct horse battery staple", wrapped_master, error)) {
        throw std::runtime_error(error);
    }
    Write(dir + "/kdf_v2_expected.hex", Bytes(HexEncode(wrapped_master.data(), wrapped_master.size())));
    return 0;
}

// <dir>/js/manifest.tsv lines: name \t blob_file \t version \t hex(content)
int Verify(const std::string& dir) {
    const auto master = MasterKey();
    FileCodec codec(master);
    std::ifstream manifest(dir + "/js/manifest.tsv");
    std::string line;
    int checked = 0, failed = 0;
    std::vector<std::string> names;
    while (std::getline(manifest, line)) {
        std::istringstream fields(line);
        std::string name, file, version, hex;
        std::getline(fields, name, '\t');
        std::getline(fields, file, '\t');
        std::getline(fields, version, '\t');
        std::getline(fields, hex, '\t');
        names.push_back(name);
        std::vector<uint8_t> blob, pt, want;
        HexDecode(hex, want);
        bool ok = ReadWholeFile(dir + "/js/" + file, blob) &&
                  codec.Decrypt(blob, codec.RemoteIdFor(name), std::stoull(version), pt, nullptr) ==
                      FileCodec::Result::kOk &&
                  pt == want;
        // The random-access reader must agree too.
        std::unique_ptr<ChunkedReader> reader;
        uint64_t actual = 0;
        ok = ok && codec.OpenReader(dir + "/js/" + file, codec.RemoteIdFor(name), std::stoull(version),
                                    &reader, &actual) == FileCodec::Result::kOk && reader &&
             reader->plaintext_size() == want.size();
        std::cout << (ok ? "  ✓ " : "  ✗ ") << "C++ decrypts JS blob '" << name << "' (" << want.size()
                  << " bytes)\n";
        ++checked;
        if (!ok) ++failed;
    }

    EncryptedIndex index(dir + "/js", master);
    bool index_ok = index.Load() && index.Size() == names.size();
    for (const auto& n : names) {
        FileMetadata m;
        index_ok = index_ok && index.GetMetadata(n, m) && m.remote_id == codec.RemoteIdFor(n);
    }
    std::cout << (index_ok ? "  ✓ " : "  ✗ ") << "C++ loads the JS-written index\n";
    if (!index_ok) ++failed;

    if (checked == 0) {
        std::cout << "  ✗ no JS blobs found\n";
        return 1;
    }
    return failed ? 1 : 0;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: web_fixtures gen|verify <dir>\n";
        return 2;
    }
    try {
        std::string mode = argv[1];
        if (mode == "gen") return Gen(argv[2]);
        if (mode == "verify") return Verify(argv[2]);
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    std::cerr << "unknown mode\n";
    return 2;
}

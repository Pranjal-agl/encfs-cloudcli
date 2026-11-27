// Fuzz the index deserializer. Random bytes would never get past AES-GCM, so
// the input is encrypted with the real index key first: this reaches the
// parser exactly as a (hypothetically) malicious-but-authentic index would.

#include "crypto.h"
#include "index.h"
#include "util.h"

#include <cstdlib>
#include <string>

using namespace encfs;

namespace {
const std::vector<uint8_t> kKey(32, 0x42);

const std::string& Dir() {
    static const std::string dir = [] {
        char tmpl[] = "/tmp/fuzz_index_XXXXXX";
        return std::string(mkdtemp(tmpl));
    }();
    return dir;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const std::vector<uint8_t> index_key =
        KeyManager::DeriveSubkey(kKey, "encfs_index_key_derivation");

    std::vector<uint8_t> plain(data, data + size);
    if (!WriteFileAtomic(Dir() + "/index.enc", SimpleCrypto::Encrypt(plain, index_key))) return 0;

    EncryptedIndex index(Dir(), kKey);
    if (index.Load()) {
        // Whatever loaded must be internally consistent and re-serializable.
        for (const auto& name : index.GetAllPlaintextNames()) {
            FileMetadata meta;
            if (!index.GetMetadata(name, meta)) abort();
            if (!meta.IsDirectory()) {
                std::string back;
                if (!index.GetPlaintextName(meta.remote_id, back)) abort();
            }
        }
        if (!index.Save()) abort();
        EncryptedIndex again(Dir(), kKey);
        if (!again.Load() || again.Size() != index.Size()) abort();
    }
    return 0;
}

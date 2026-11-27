// Fuzz every decoder that reads blob bytes from disk or the cloud: the v2
// in-memory and streaming decoders, the random-access reader, and the legacy
// v1 decoder. They must reject garbage cleanly (no crash, no UB, no huge
// allocation) and never "authenticate" anything without the key.

#include "crypto.h"

#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

using namespace encfs;

namespace {
const std::vector<uint8_t> kKey(32, 0x42);
const std::vector<uint8_t> kAad = {'f', 'u', 'z', 'z'};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> blob(data, data + size);

    (void)ChunkedCrypto::PeekFormatVersion(blob);

    try {
        (void)ChunkedCrypto::Decrypt(blob, kKey, kAad);
    } catch (const std::exception&) {
    }
    try {
        (void)ChunkedCrypto::DecryptLegacyV1(blob, kKey);
    } catch (const std::exception&) {
    }

    size_t pos = 0;
    std::vector<uint8_t> out;
    (void)ChunkedCrypto::DecryptStream(
        [&](uint8_t* buf, size_t n) {
            size_t take = std::min(n, blob.size() - pos);
            std::memcpy(buf, blob.data() + pos, take);
            pos += take;
            return take;
        },
        [&](const uint8_t* buf, size_t n) {
            out.insert(out.end(), buf, buf + n);
            return true;
        },
        kKey, kAad);

    // The random-access reader works on files: use an in-memory one.
    int fd = memfd_create("blob", MFD_CLOEXEC);
    if (fd >= 0) {
        if (size == 0 || write(fd, data, size) == static_cast<ssize_t>(size)) {
            const std::string path = "/proc/self/fd/" + std::to_string(fd);
            if (auto reader = ChunkedReader::Open(path, kKey, kAad)) {
                uint8_t buf[64];
                (void)reader->ReadAt(0, buf, sizeof(buf));
                (void)reader->ReadAt(reader->plaintext_size() / 2, buf, sizeof(buf));
                if (reader->num_chunks() > 0) {
                    std::vector<uint8_t> chunk;
                    (void)reader->ReadChunk(reader->num_chunks() - 1, chunk);
                }
            }
        }
        close(fd);
    }
    return 0;
}

// Differential fuzzing of FileContents: the input is decoded into a sequence
// of writes, truncates, reads and save-and-rebase cycles, applied both to a
// FileContents (tiny chunks, two-chunk cache, so it spills constantly) and to
// a plain std::vector. Any divergence aborts.

#include "crypto.h"
#include "file_contents.h"
#include "util.h"

#include <cstdlib>
#include <string>

using namespace encfs;

namespace {
const std::vector<uint8_t> kKey(32, 0x42);
constexpr size_t kChunk = 8;
constexpr uint64_t kMaxModel = 4096;

const std::string& Dir() {
    static const std::string dir = [] {
        char tmpl[] = "/tmp/fuzz_contents_XXXXXX";
        return std::string(mkdtemp(tmpl));
    }();
    return dir;
}

struct Input {
    const uint8_t* p;
    size_t n;
    uint8_t Byte() {
        if (n == 0) return 0;
        --n;
        return *p++;
    }
    uint16_t Short() { return static_cast<uint16_t>(Byte() | (Byte() << 8)); }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    Input in{data, size};
    std::vector<uint8_t> model;
    FileContents contents(nullptr, kChunk, Dir(), 2 * kChunk);

    while (in.n > 0) {
        switch (in.Byte() % 4) {
        case 0: {  // write
            uint64_t off = in.Short() % kMaxModel;
            size_t len = 1 + in.Byte() % 40;
            std::vector<uint8_t> buf(len);
            for (auto& b : buf) b = in.Byte();
            if (!contents.Write(off, buf.data(), len)) abort();
            if (model.size() < off + len) model.resize(off + len);
            std::copy(buf.begin(), buf.end(), model.begin() + static_cast<long>(off));
            break;
        }
        case 1: {  // truncate
            uint64_t n = in.Short() % kMaxModel;
            if (!contents.Truncate(n)) abort();
            model.resize(n);
            break;
        }
        case 2: {  // read
            uint64_t off = in.Short() % (kMaxModel + 16);
            std::vector<uint8_t> buf(1 + in.Byte() % 50);
            int64_t got = contents.Read(off, buf.data(), buf.size());
            size_t want = off >= model.size() ? 0 : std::min(buf.size(), model.size() - off);
            if (got != static_cast<int64_t>(want)) abort();
            for (size_t i = 0; i < want; ++i) {
                if (buf[i] != model[off + i]) abort();
            }
            break;
        }
        case 3: {  // save as a real blob, then continue from it
            const std::string path = Dir() + "/blob";
            AtomicFile out(path);
            if (!out.Open()) abort();
            ChunkedWriter writer([&](const uint8_t* d, size_t n) { return out.Write(d, n); },
                                 kKey, kChunk);
            if (!contents.ForEachChunk([&](const uint8_t* d, size_t n, bool last) {
                    return writer.Add(d, n, last);
                }) || !writer.finished() || !out.Commit()) {
                abort();
            }
            auto reader = ChunkedReader::Open(path, kKey);
            if (!reader || reader->plaintext_size() != model.size()) abort();
            contents.Rebase(std::move(reader));
            break;
        }
        }
        if (contents.size() != model.size()) abort();
    }
    return 0;
}

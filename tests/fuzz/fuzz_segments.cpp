// Fuzz segmented storage: object-name parsing, padding arithmetic, and
// SegmentedReader against segments of forged lengths, missing segments and
// arbitrary read orders. Every read must either fail or return exactly the
// bytes of the file; nothing may crash or read out of bounds.

#include "file_codec.h"
#include "segments.h"
#include "util.h"

#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <unistd.h>

using namespace encfs;

namespace {
const std::vector<uint8_t> kMaster(32, 0x42);
const std::string kInode(64, 'f');

const std::string& Dir() {
    static const std::string dir = [] {
        char tmpl[] = "/tmp/fuzz_segments_XXXXXX";
        return std::string(mkdtemp(tmpl));
    }();
    return dir;
}

struct Input {
    const uint8_t* p;
    size_t n;
    uint8_t U8() { if (!n) return 0; --n; return *p++; }
    uint32_t U16() { return static_cast<uint32_t>(U8()) | (static_cast<uint32_t>(U8()) << 8); }
};
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // 1. Names: parsing never crashes, and what parses round-trips.
    {
        std::string name(reinterpret_cast<const char*>(data), std::min<size_t>(size, 120));
        std::string inode, id;
        uint64_t seg = 0, ver = 0;
        if (ParseSegmentObjectId(name, &inode, &seg, &ver) && SegmentObjectId(inode, seg, ver) != name) abort();
        if (IsObjectFileName(name, &id) && id + ".enc" != name) abort();
    }

    Input in{data, size};
    // 2. Padding: never shrinks, never exceeds max(len, segment).
    {
        const uint64_t seg = 1 + in.U16() * 64ull;
        const uint64_t len = in.U16() * 3ull;
        const uint64_t p = PaddedLength(len, seg);
        if (p < len || p > std::max(len, seg)) abort();
    }

    // 3. A reader over fuzzed segments.
    const size_t cs = 16 + (in.U8() % 4) * 16;              // 16..64
    const uint32_t per = 1 + in.U8() % 4;                   // chunks per segment
    const uint32_t seg_size = static_cast<uint32_t>(cs * per);
    const uint64_t file_size = in.U16() % (seg_size * 6 + 1);
    const uint64_t count = std::max<uint64_t>(1, (file_size + seg_size - 1) / seg_size);

    FileCodec codec(kMaster);
    FileMetadata meta;
    meta.remote_id = kInode;
    meta.size = file_size;
    meta.segment_size = seg_size;
    meta.chunk_size = static_cast<uint32_t>(cs);
    std::vector<uint8_t> truth(file_size);
    for (size_t i = 0; i < truth.size(); ++i) truth[i] = static_cast<uint8_t>(i * 13 + 7);

    std::map<uint64_t, bool> honest;  // segment → stored with its true length and identity
    for (uint64_t i = 0; i < count; ++i) {
        meta.segments.push_back(1 + i);
        const uint64_t start = i * seg_size;
        const uint64_t need = std::min<uint64_t>(seg_size, file_size - std::min(file_size, start));
        const uint8_t how = in.U8() % 8;
        uint64_t len = need;
        uint64_t as_seg = i;
        size_t chunk = cs;
        switch (how) {
        case 1: len = in.U8() % (seg_size + 8); break;      // forged length
        case 2: as_seg = i + 1; break;                      // sealed for another position
        case 3: chunk = cs * 2; break;                      // other chunk size
        case 4: break;                                      // missing (below)
        default: break;                                     // honest
        }
        std::vector<uint8_t> part(len, 0);
        for (uint64_t k = 0; k < len && start + k < file_size; ++k) part[k] = truth[start + k];
        const std::string path = Dir() + "/" + std::to_string(i);
        if (how == 4) {
            ::unlink(path.c_str());
        } else {
            WriteFileAtomic(path, codec.EncryptSegment(part, kInode, as_seg, 1 + i, chunk));
        }
        const bool last = i + 1 == count;
        const bool len_ok = last ? (len >= need && len <= seg_size) : len == seg_size;
        honest[i] = how != 2 && how != 3 && how != 4 && len_ok;
    }

    SegmentedReader reader(meta, cs, [&](uint64_t seg) {
        std::unique_ptr<ChunkedReader> r;
        codec.OpenSegmentReader(Dir() + "/" + std::to_string(seg), kInode, seg, meta.segments[seg], &r);
        return r;
    });
    const uint64_t chunks = (file_size + cs - 1) / cs + 2;
    std::vector<uint8_t> out;
    while (in.n) {
        const uint64_t idx = in.U8() % (chunks + 1);
        const bool ok = reader.ReadChunk(idx, out);
        const uint64_t seg = idx / per;
        if (seg >= count) {
            if (ok) abort();  // past the end
            continue;
        }
        const uint64_t off = idx * cs;
        if (off >= file_size) continue;  // padding or nothing: either answer is fine
        if (ok != honest[seg]) abort();  // accepted a forgery, or rejected a genuine segment
        if (ok) {
            for (size_t k = 0; k < out.size() && off + k < file_size; ++k) {
                if (out[k] != truth[off + k]) abort();
            }
        }
    }
    return 0;
}

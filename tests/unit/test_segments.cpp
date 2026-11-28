// Segmented storage: object names, padding, the per-segment AAD binding,
// SegmentedReader's validation and laziness, the EIX3 index fields, and
// FileContents' record of which chunks an edit touched.

#include "crypto.h"
#include "file_codec.h"
#include "file_contents.h"
#include "index.h"
#include "segments.h"
#include "util.h"
#include "../test_util.h"

#include <map>
#include <unistd.h>

using namespace encfs;
using namespace encfs_test;

namespace {

const std::vector<uint8_t> kMaster(32, 0x24);
const std::string kInode(64, 'a');

std::vector<uint8_t> Pattern(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(i * 7 + seed);
    return v;
}

void TestObjectNames() {
    CHECK(SegmentObjectId(kInode, 3, 17) == kInode + ".3.17");

    std::string inode;
    uint64_t seg = 0, ver = 0;
    CHECK(ParseSegmentObjectId(kInode + ".3.17", &inode, &seg, &ver) && inode == kInode && seg == 3 && ver == 17);
    CHECK(!ParseSegmentObjectId(kInode, &inode, &seg, &ver));                     // legacy blob
    CHECK(!ParseSegmentObjectId(kInode + ".3", &inode, &seg, &ver));
    CHECK(!ParseSegmentObjectId(kInode + ".3.17.1", &inode, &seg, &ver));
    CHECK(!ParseSegmentObjectId(kInode + ".x.1", &inode, &seg, &ver));
    CHECK(!ParseSegmentObjectId(kInode + "..1", &inode, &seg, &ver));
    CHECK(!ParseSegmentObjectId(std::string(63, 'a') + ".1.1", &inode, &seg, &ver));
    CHECK(!ParseSegmentObjectId(std::string(64, 'G') + ".1.1", &inode, &seg, &ver));
    CHECK(!ParseSegmentObjectId(kInode + ".1.99999999999999999999999", &inode, &seg, &ver));  // overflow

    std::string id;
    CHECK(IsObjectFileName(kInode + ".enc", &id) && id == kInode);
    CHECK(IsObjectFileName(kInode + ".0.2.enc", &id) && id == kInode + ".0.2");
    CHECK(!IsObjectFileName("index.enc", &id));
    CHECK(!IsObjectFileName(kInode + ".0.2.enc.tmp.123", &id));
    CHECK(!IsObjectFileName(kInode + ".0.2.enc.download", &id));
    CHECK(!IsObjectFileName(kInode, &id));

    FileMetadata legacy;
    legacy.remote_id = kInode;
    CHECK(ObjectIds(legacy) == std::vector<std::string>{kInode});
    FileMetadata segmented = legacy;
    segmented.segment_size = 4096;
    segmented.chunk_size = 1024;
    segmented.segments = {5, 2, 9};
    CHECK((ObjectIds(segmented) == std::vector<std::string>{kInode + ".0.5", kInode + ".1.2", kInode + ".2.9"}));
}

void TestSizes() {
    CHECK(DefaultSegmentSize(1024 * 1024) == 4u * 1024 * 1024);
    CHECK(DefaultSegmentSize(64) == 4u * 1024 * 1024);
    CHECK(DefaultSegmentSize(3000) % 3000 == 0);                 // whole chunks
    CHECK(DefaultSegmentSize(8 * 1024 * 1024) == 8u * 1024 * 1024);  // at least one chunk

    const uint64_t seg = 4 * 1024 * 1024;
    CHECK(PaddedLength(0, seg) == 1024);
    CHECK(PaddedLength(10, seg) == 1024);
    CHECK(PaddedLength(1024, seg) == 1024);
    CHECK(PaddedLength(1025, seg) == 2048);
    CHECK(PaddedLength(2500, seg) == PaddedLength(4000, seg));
    CHECK(PaddedLength(3 * 1024 * 1024, seg) == seg);           // never past the segment
    CHECK(PaddedLength(seg, seg) == seg);
    CHECK(PaddedLength(100, 512) == 512);                       // small segments cap it
    for (uint64_t n : {1ull, 777ull, 65536ull, 1000000ull}) CHECK(PaddedLength(n, seg) >= n);
}

void TestSegmentAadBinding() {
    FileCodec codec(kMaster);
    const auto pt = Pattern(300, 1);
    const auto blob = codec.EncryptSegment(pt, kInode, 2, 7, 64);
    std::vector<uint8_t> out;
    CHECK(codec.DecryptSegment(blob, kInode, 2, 7, out) == FileCodec::Result::kOk && out == pt);
    // The same bytes can't pass as another position, version or file...
    CHECK(codec.DecryptSegment(blob, kInode, 1, 7, out) == FileCodec::Result::kCorrupt);
    CHECK(codec.DecryptSegment(blob, kInode, 2, 6, out) == FileCodec::Result::kCorrupt);
    CHECK(codec.DecryptSegment(blob, kInode, 2, 8, out) == FileCodec::Result::kCorrupt);
    CHECK(codec.DecryptSegment(blob, std::string(64, 'b'), 2, 7, out) == FileCodec::Result::kCorrupt);
    // ...or as a whole-file blob, and vice versa.
    CHECK(codec.Decrypt(blob, kInode, 7, out, nullptr) != FileCodec::Result::kOk);
    CHECK(codec.DecryptSegment(codec.Encrypt(pt, kInode, 7), kInode, 0, 7, out) == FileCodec::Result::kCorrupt);
    // Tampering is caught.
    auto bad = blob;
    bad[bad.size() - 5] ^= 1;
    CHECK(codec.DecryptSegment(bad, kInode, 2, 7, out) == FileCodec::Result::kCorrupt);

    // The streaming reader agrees.
    TempDir dir;
    WriteFileAtomic(dir / "seg", blob);
    std::unique_ptr<ChunkedReader> reader;
    CHECK(codec.OpenSegmentReader(dir / "seg", kInode, 2, 7, &reader) == FileCodec::Result::kOk && reader &&
          reader->plaintext_size() == pt.size());
    CHECK(codec.OpenSegmentReader(dir / "seg", kInode, 3, 7, &reader) == FileCodec::Result::kCorrupt && !reader);
}

// A segmented file in memory: blobs by segment, and an opener that counts.
struct Store {
    FileCodec codec{kMaster};
    TempDir dir;
    FileMetadata meta;
    std::map<uint64_t, int> opened;

    Store(const std::vector<uint8_t>& pt, uint32_t seg_size, uint32_t cs, bool pad_last = false) {
        meta.remote_id = kInode;
        meta.size = pt.size();
        meta.segment_size = seg_size;
        meta.chunk_size = cs;
        const uint64_t n = std::max<uint64_t>(1, (pt.size() + seg_size - 1) / seg_size);
        for (uint64_t i = 0; i < n; ++i) {
            const size_t start = static_cast<size_t>(i * seg_size);
            std::vector<uint8_t> part(pt.begin() + static_cast<long>(std::min(start, pt.size())),
                                      pt.begin() + static_cast<long>(std::min<size_t>(start + seg_size, pt.size())));
            if (pad_last && i + 1 == n) part.resize(PaddedLength(part.size(), seg_size), 0);
            Put(i, 1 + i, part);
            meta.segments.push_back(1 + i);
        }
    }
    void Put(uint64_t seg, uint64_t ver, const std::vector<uint8_t>& part) {
        WriteFileAtomic(dir / std::to_string(seg), codec.EncryptSegment(part, kInode, seg, ver, meta.chunk_size));
    }
    std::unique_ptr<SegmentedReader> Reader() {
        return std::make_unique<SegmentedReader>(meta, meta.chunk_size, [this](uint64_t seg) {
            ++opened[seg];
            std::unique_ptr<ChunkedReader> r;
            codec.OpenSegmentReader(dir / std::to_string(seg), kInode, seg, meta.segments[seg], &r);
            return r;
        });
    }
};

std::vector<uint8_t> ReadAll(ChunkSource& src) {
    std::vector<uint8_t> all, chunk;
    const uint64_t n = (src.plaintext_size() + src.chunk_size() - 1) / src.chunk_size();
    for (uint64_t i = 0; i < n; ++i) {
        if (!src.ReadChunk(i, chunk)) return {0xEE};
        all.insert(all.end(), chunk.begin(), chunk.end());
    }
    all.resize(std::min<size_t>(all.size(), src.plaintext_size()));
    return all;
}

void TestSegmentedReader() {
    const auto pt = Pattern(1000, 3);
    {
        Store s(pt, 256, 64);
        auto r = s.Reader();
        CHECK(r->plaintext_size() == 1000 && r->chunk_size() == 64);
        std::vector<uint8_t> chunk;
        CHECK(r->ReadChunk(5, chunk) && chunk.size() == 64 && std::equal(chunk.begin(), chunk.end(), pt.begin() + 320));
        CHECK(s.opened.size() == 1 && s.opened[1] == 1);  // lazy: only segment 1 so far
        CHECK(ReadAll(*r) == pt);
        CHECK(s.opened.size() == 4);
        for (auto& [seg, n] : s.opened) CHECK(n == 1);     // each opened once
        CHECK(!r->ReadChunk(16, chunk));                    // past the last segment
    }
    {
        Store s(pt, 256, 64, /*pad_last=*/true);
        auto r = s.Reader();
        CHECK(ReadAll(*r) == pt);                           // padding is never data
    }
    {
        // A non-final segment that's short (cut or swapped for a shorter
        // one) is rejected, even though it authenticates.
        Store s(pt, 256, 64);
        s.Put(1, 2, Pattern(200, 9));
        auto r = s.Reader();
        std::vector<uint8_t> chunk;
        CHECK(r->ReadChunk(0, chunk));
        CHECK(!r->ReadChunk(4, chunk));
    }
    {
        // The last segment must hold at least the file's remaining bytes...
        Store s(pt, 256, 64);
        s.Put(3, 4, Pattern(100, 9));                       // needs 232
        auto r = s.Reader();
        std::vector<uint8_t> chunk;
        CHECK(!r->ReadChunk(12, chunk));
    }
    {
        // ...and no more than a segment.
        Store s(pt, 256, 64);
        s.Put(3, 4, Pattern(320, 9));
        auto r = s.Reader();
        std::vector<uint8_t> chunk;
        CHECK(!r->ReadChunk(12, chunk));
    }
    {
        // A segment stored with a different chunk size is rejected.
        Store s(pt, 256, 64);
        WriteFileAtomic(s.dir / "2", s.codec.EncryptSegment(Pattern(256, 1), kInode, 2, 3, 128));
        auto r = s.Reader();
        std::vector<uint8_t> chunk;
        CHECK(!r->ReadChunk(8, chunk));
    }
    {
        // A missing segment fails only the reads that need it.
        Store s(pt, 256, 64);
        ::unlink((s.dir / "2").c_str());
        auto r = s.Reader();
        std::vector<uint8_t> chunk;
        CHECK(r->ReadChunk(0, chunk) && r->ReadChunk(15, chunk));
        CHECK(!r->ReadChunk(9, chunk));
    }
    {
        // Many segments: readers are recycled, so reading everything twice
        // opens some again, and every read is still right.
        const auto big = Pattern(64 * 40, 5);
        Store s(big, 64, 64);
        auto r = s.Reader();
        CHECK(ReadAll(*r) == big && ReadAll(*r) == big);
        CHECK(s.opened.size() == 40);
    }
    {
        // An empty segmented file: one empty segment.
        Store s({}, 256, 64);
        auto r = s.Reader();
        CHECK(r->plaintext_size() == 0 && s.meta.segments.size() == 1);
    }
}

void TestIndexSegments() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kMaster);
    FileMetadata m;
    m.remote_id = NewInodeId();
    m.version = 9;
    m.size = 10000;
    m.segment_size = 4096;
    m.chunk_size = 1024;
    m.segments = {9, 3, 7};
    index.SetMetadata("big", m);
    FileMetadata legacy;
    legacy.remote_id = NewInodeId();
    legacy.version = 2;
    legacy.size = 5;
    index.SetMetadata("small", legacy);
    CHECK(index.Save());

    EncryptedIndex reloaded(dir.path(), kMaster);
    CHECK(reloaded.Load());
    FileMetadata got;
    CHECK(reloaded.GetMetadata("big", got) && got.segment_size == 4096 && got.chunk_size == 1024 &&
          (got.segments == std::vector<uint64_t>{9, 3, 7}));
    CHECK(reloaded.GetMetadata("small", got) && got.segment_size == 0 && got.segments.empty());

    CHECK(IndexReferencesObject(reloaded, m.remote_id + ".1.3"));
    CHECK(!IndexReferencesObject(reloaded, m.remote_id + ".1.2"));      // superseded version
    CHECK(!IndexReferencesObject(reloaded, m.remote_id + ".3.9"));      // past the end
    CHECK(!IndexReferencesObject(reloaded, m.remote_id));               // not a whole-file blob any more
    CHECK(IndexReferencesObject(reloaded, legacy.remote_id));
    CHECK(!IndexReferencesObject(reloaded, legacy.remote_id + ".0.2"));
    CHECK(!IndexReferencesObject(reloaded, NewInodeId()));
}

void TestTouchedChunks() {
    TempDir dir;
    const size_t cs = 64;
    const auto pt = Pattern(1000, 1);
    auto blob = ChunkedCrypto::Encrypt(pt, kMaster, cs, Bytes("aad"));
    WriteFileAtomic(dir / "base", blob);
    FileContents c(ChunkedReader::Open(dir / "base", kMaster, Bytes("aad")), cs, dir.path());
    CHECK(c.base_size() == 1000 && c.touched_chunks().empty());

    uint8_t b = 1;
    std::vector<uint8_t> buf(10);
    CHECK(c.Read(500, buf.data(), buf.size()) == 10);
    CHECK(c.touched_chunks().empty());                 // reads don't count
    CHECK(c.Write(130, &b, 1));
    CHECK(c.Write(127, buf.data(), 2));                // spans chunks 1 and 2
    CHECK((c.touched_chunks() == std::set<uint64_t>{1, 2}));
    CHECK(c.Truncate(100));                            // chunk 2 is gone; chunk 1 is cut
    CHECK((c.touched_chunks() == std::set<uint64_t>{1}));
    CHECK(c.base_size() == 1000);                      // until rebased

    c.Rebase(ChunkedReader::Open(dir / "base", kMaster, Bytes("aad")));
    CHECK(c.touched_chunks().empty() && c.base_size() == 100);  // the size it was saved at
}

}  // namespace

int main() {
    TestObjectNames();
    TestSizes();
    TestSegmentAadBinding();
    TestSegmentedReader();
    TestIndexSegments();
    TestTouchedChunks();
    if (Failures()) {
        std::cerr << Failures() << " check(s) failed\n";
        return 1;
    }
    std::cout << "All segment tests passed\n";
    return 0;
}

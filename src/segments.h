#pragma once

#include "crypto.h"
#include "index.h"

#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace encfs {

// ── Object names ────────────────────────────────────────────────────────────
// Each stored object is a file `<object id>.enc` in the backing directory and
// an object `<object id>` in the cloud:
//   legacy blob:  <inode>                 (64 hex)
//   segment:      <inode>.<seg>.<version>
// Segment objects are immutable: a new version is a new object.

std::string SegmentObjectId(const std::string& inode, uint64_t seg, uint64_t version);
// Every object a file inode's contents occupy.
std::vector<std::string> ObjectIds(const FileMetadata& meta);
// Split an object ID. Returns false for anything else (incl. legacy blobs).
bool ParseSegmentObjectId(const std::string& id, std::string* inode, uint64_t* seg, uint64_t* version);
// Is `file_name` an object file? Sets `*id` (the name minus ".enc").
bool IsObjectFileName(const std::string& file_name, std::string* id);
// Does the index still refer to object `id`?
bool IndexReferencesObject(EncryptedIndex& index, const std::string& id);

// Segment size for new segmented files: 4 MiB, rounded to a whole number of
// chunks.
uint32_t DefaultSegmentSize(size_t chunk_size);

// --pad: stored length of a file's final segment holding `len` bytes. Rounds
// up to a power of two (at least 1 KiB, at most the segment size), so the
// cloud learns sizes only to within a factor of two.
uint64_t PaddedLength(uint64_t len, uint64_t segment_size);

// ── Reading a segmented file ────────────────────────────────────────────────
// Presents a segmented file as one ChunkSource. Segments are opened lazily
// through `opener` (which may download them), so reading part of a large
// file only touches the segments involved. At most a few are kept open.
class SegmentedReader : public ChunkSource {
public:
    using Opener = std::function<std::unique_ptr<ChunkedReader>(uint64_t seg)>;

    SegmentedReader(const FileMetadata& meta, size_t chunk_size, Opener opener);

    uint64_t plaintext_size() const override { return size_; }
    size_t chunk_size() const override { return chunk_size_; }
    bool ReadChunk(uint64_t index, std::vector<uint8_t>& out) override;

private:
    uint64_t size_;
    size_t chunk_size_;
    uint64_t segment_size_;
    uint64_t segment_count_;
    Opener opener_;

    static constexpr size_t kMaxOpen = 16;
    std::list<uint64_t> lru_;
    std::unordered_map<uint64_t, std::pair<std::unique_ptr<ChunkedReader>, std::list<uint64_t>::iterator>> open_;

    ChunkedReader* Segment(uint64_t seg);
};

} // namespace encfs

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

namespace encfs {

class ChunkSource;

// The contents of one open file, read and written chunk by chunk in bounded
// memory, whatever the file's size.
//
//   * Unmodified chunks are read from the file's current blob (`base`) and
//     authenticated as they are read.
//   * Modified chunks live in a small in-memory cache. When it is full the
//     least recently used dirty chunk is spilled to a scratch file in
//     `scratch_dir`, encrypted with a random key that exists only in memory.
//     The scratch file is unlinked as soon as it is created, so no plaintext
//     ever touches disk and nothing is left behind after a crash.
//   * ForEachChunk() streams the current contents in order, which is how a
//     new blob is written.
//
// Not thread-safe; the filesystem serialises access.
class FileContents {
public:
    // `base` may be null (a new or empty file). `chunk_size` must match the
    // base's chunk size when there is one. `cache_bytes` bounds the memory
    // used for chunks (at least two chunks are always allowed).
    FileContents(std::unique_ptr<ChunkSource> base, size_t chunk_size,
                 std::string scratch_dir, size_t cache_bytes = 8 * 1024 * 1024);
    ~FileContents();

    FileContents(const FileContents&) = delete;
    FileContents& operator=(const FileContents&) = delete;

    uint64_t size() const { return size_; }
    size_t chunk_size() const { return chunk_size_; }

    // Largest size this layout can represent (2^32 chunks).
    uint64_t max_size() const;

    // Copy up to `len` bytes at `offset`. Returns the number copied (short at
    // end of file), or -1 if a chunk failed authentication or I/O failed.
    int64_t Read(uint64_t offset, uint8_t* buf, size_t len);

    // Returns false on I/O or authentication failure, or if the result would
    // exceed max_size(). Writing past the end leaves a zero-filled gap.
    bool Write(uint64_t offset, const uint8_t* buf, size_t len);

    // Shrink (discarding data) or grow (with zeros).
    bool Truncate(uint64_t new_size);

    // Call `sink(data, len, last)` for every chunk in order. An empty file is
    // a single empty chunk. Stops and returns false if `sink` returns false or
    // a chunk can't be read (including a base chunk failing authentication,
    // so tampered data is never re-encrypted as if it were genuine).
    bool ForEachChunk(const std::function<bool(const uint8_t*, size_t, bool)>& sink);

    // After the contents have been written out as a new blob: adopt it as the
    // base and forget all dirty state.
    void Rebase(std::unique_ptr<ChunkSource> new_base);

    // The plaintext of chunk `index` (chunk_size() bytes, zero past the end)
    // as it is now, without caching it. False if it can't be read.
    bool LoadChunk(uint64_t index, std::vector<uint8_t>& out) { return LoadInto(index, out); }

    // Chunks written or cut since construction / the last Rebase, and the
    // size at that point: what a save needs to know to rewrite only the
    // segments that changed.
    const std::set<uint64_t>& touched_chunks() const { return touched_; }
    uint64_t base_size() const { return base_size_; }

    // For tests: how many chunks currently live in the scratch file.
    size_t spilled_chunks() const { return spilled_.size(); }

private:
    struct Slot {
        std::vector<uint8_t> data;  // always chunk_size_ bytes; past EOF is zero
        bool dirty = false;
        uint64_t last_use = 0;
    };

    std::unique_ptr<ChunkSource> base_;
    size_t chunk_size_;
    std::string scratch_dir_;
    size_t max_slots_;

    uint64_t size_ = 0;
    uint64_t base_limit_ = 0;  // base bytes at or past this offset are stale (truncated)
    uint64_t base_size_ = 0;   // size at construction / last Rebase
    std::set<uint64_t> touched_;
    std::map<uint64_t, Slot> cache_;
    std::unordered_set<uint64_t> spilled_;
    uint64_t clock_ = 0;

    int scratch_fd_ = -1;
    std::vector<uint8_t> scratch_key_;

    uint64_t ChunkCount() const;
    // Fill `out` (chunk_size_ bytes) with chunk `index` without caching it.
    bool LoadInto(uint64_t index, std::vector<uint8_t>& out);
    Slot* Get(uint64_t index);
    bool EvictOne();
    bool SpillChunk(uint64_t index, const std::vector<uint8_t>& data);
    bool UnspillChunk(uint64_t index, std::vector<uint8_t>& out);
    bool EnsureScratch();
};

} // namespace encfs

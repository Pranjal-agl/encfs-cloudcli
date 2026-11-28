#include "segments.h"

#include <algorithm>
#include <cstdlib>

namespace encfs {

namespace {
bool IsHex64(const std::string& s, size_t from = 0) {
    return s.size() >= from + 64 && s.find_first_not_of("0123456789abcdef", from) >= from + 64;
}

bool ParseU64(const std::string& s, uint64_t* out) {
    if (s.empty() || s.size() > 20 || s.find_first_not_of("0123456789") != std::string::npos) return false;
    if (s.size() > 1 && s[0] == '0') return false;  // one spelling per number
    *out = std::strtoull(s.c_str(), nullptr, 10);
    return true;
}
} // namespace

std::string SegmentObjectId(const std::string& inode, uint64_t seg, uint64_t version) {
    return inode + "." + std::to_string(seg) + "." + std::to_string(version);
}

std::vector<std::string> ObjectIds(const FileMetadata& meta) {
    if (!meta.IsFile()) return {};
    if (meta.segment_size == 0) return {meta.remote_id};
    std::vector<std::string> ids;
    ids.reserve(meta.segments.size());
    for (size_t i = 0; i < meta.segments.size(); ++i) {
        ids.push_back(SegmentObjectId(meta.remote_id, i, meta.segments[i]));
    }
    return ids;
}

bool ParseSegmentObjectId(const std::string& id, std::string* inode, uint64_t* seg, uint64_t* version) {
    if (id.size() < 68 || !IsHex64(id) || id[64] != '.') return false;
    const auto dot = id.find('.', 65);
    if (dot == std::string::npos) return false;
    uint64_t s = 0, v = 0;
    if (!ParseU64(id.substr(65, dot - 65), &s) || !ParseU64(id.substr(dot + 1), &v)) return false;
    if (inode) *inode = id.substr(0, 64);
    if (seg) *seg = s;
    if (version) *version = v;
    return true;
}

bool IsObjectFileName(const std::string& file_name, std::string* id) {
    if (file_name.size() < 68 || file_name.compare(file_name.size() - 4, 4, ".enc") != 0) return false;
    std::string base = file_name.substr(0, file_name.size() - 4);
    const bool ok = (base.size() == 64 && IsHex64(base)) || ParseSegmentObjectId(base, nullptr, nullptr, nullptr);
    if (ok && id) *id = base;
    return ok;
}

bool IndexReferencesObject(EncryptedIndex& index, const std::string& id) {
    FileMetadata meta;
    std::string inode;
    uint64_t seg = 0, version = 0;
    if (ParseSegmentObjectId(id, &inode, &seg, &version)) {
        return index.GetInode(inode, meta) && meta.IsFile() && meta.segment_size > 0 &&
               seg < meta.segments.size() && meta.segments[seg] == version;
    }
    return id.size() == 64 && index.GetInode(id, meta) && meta.IsFile() && meta.segment_size == 0;
}

uint32_t DefaultSegmentSize(size_t chunk_size) {
    const size_t target = 4 * 1024 * 1024;
    const size_t chunks = std::max<size_t>(1, target / std::max<size_t>(1, chunk_size));
    return static_cast<uint32_t>(chunks * chunk_size);
}

uint64_t PaddedLength(uint64_t len, uint64_t segment_size) {
    uint64_t padded = 1024;
    while (padded < len && padded < segment_size) padded <<= 1;
    return std::min(std::max(padded, len), std::max<uint64_t>(segment_size, len));
}

// ── SegmentedReader ─────────────────────────────────────────────────────────

SegmentedReader::SegmentedReader(const FileMetadata& meta, size_t chunk_size, Opener opener)
    : size_(meta.size),
      chunk_size_(chunk_size),
      segment_size_(meta.segment_size),
      segment_count_(meta.segments.size()),
      opener_(std::move(opener)) {
}

ChunkedReader* SegmentedReader::Segment(uint64_t seg) {
    auto it = open_.find(seg);
    if (it != open_.end()) {
        lru_.splice(lru_.begin(), lru_, it->second.second);
        return it->second.first.get();
    }
    if (seg >= segment_count_) return nullptr;
    std::unique_ptr<ChunkedReader> reader = opener_(seg);
    if (!reader || reader->chunk_size() != chunk_size_) return nullptr;

    // Every segment but the last holds exactly segment_size bytes; the last
    // holds the rest, possibly padded. Anything else is a forgery or damage.
    const uint64_t start = seg * segment_size_;
    const uint64_t needed = std::min<uint64_t>(segment_size_, size_ > start ? size_ - start : 0);
    const bool last = seg + 1 == segment_count_;
    if (last ? reader->plaintext_size() < needed || reader->plaintext_size() > segment_size_
             : reader->plaintext_size() != segment_size_) {
        return nullptr;
    }

    if (open_.size() >= kMaxOpen) {
        open_.erase(lru_.back());
        lru_.pop_back();
    }
    lru_.push_front(seg);
    ChunkedReader* raw = reader.get();
    open_.emplace(seg, std::make_pair(std::move(reader), lru_.begin()));
    return raw;
}

bool SegmentedReader::ReadChunk(uint64_t index, std::vector<uint8_t>& out) {
    if (segment_size_ == 0 || segment_size_ % chunk_size_ != 0) return false;
    const uint64_t per_segment = segment_size_ / chunk_size_;
    ChunkedReader* reader = Segment(index / per_segment);
    return reader && reader->ReadChunk(index % per_segment, out);
}

} // namespace encfs

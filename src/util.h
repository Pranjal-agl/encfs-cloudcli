#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace encfs {

// ── Fixed-width little-endian encoding ──────────────────────────────────────
// All on-disk integers are little-endian regardless of host byte order, so
// blobs and the index stay portable between machines.
void AppendU32LE(std::vector<uint8_t>& out, uint32_t v);
void AppendU64LE(std::vector<uint8_t>& out, uint64_t v);
uint32_t LoadU32LE(const uint8_t* p);
uint64_t LoadU64LE(const uint8_t* p);

// ── Hex ─────────────────────────────────────────────────────────────────────
std::string HexEncode(const uint8_t* data, size_t len);
// Returns false if `hex` has odd length or contains non-hex characters.
bool HexDecode(const std::string& hex, std::vector<uint8_t>& out);

// ── File I/O ────────────────────────────────────────────────────────────────
// Read a whole file. Returns false (and sets errno) on failure.
bool ReadWholeFile(const std::string& path, std::vector<uint8_t>& out);

// Durably replace `path` with `data`: write to a sibling temp file, fsync it,
// rename over the target, then fsync the directory. Readers see either the
// old or the new contents, never a torn write. Returns false (errno set) on
// failure; the temp file is removed.
bool WriteFileAtomic(const std::string& path, const uint8_t* data, size_t len,
                     unsigned mode = 0600);
inline bool WriteFileAtomic(const std::string& path, const std::vector<uint8_t>& data,
                            unsigned mode = 0600) {
    return WriteFileAtomic(path, data.data(), data.size(), mode);
}

// Overwrite a buffer with zeros in a way the optimiser can't elide.
void SecureWipe(std::vector<uint8_t>& buf);
void SecureWipe(std::string& buf);

} // namespace encfs

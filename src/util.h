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

// Streaming counterpart of WriteFileAtomic: Open() creates a temp file next
// to `path`, Write() appends, Commit() fsyncs and renames it into place. If
// Commit() isn't reached (or fails) the temp file is removed.
class AtomicFile {
public:
    explicit AtomicFile(std::string path, unsigned mode = 0600);
    ~AtomicFile();
    AtomicFile(const AtomicFile&) = delete;
    AtomicFile& operator=(const AtomicFile&) = delete;

    bool Open();
    bool Write(const uint8_t* data, size_t len);
    bool Commit();

private:
    std::string path_;
    std::string tmp_path_;
    unsigned mode_;
    int fd_ = -1;
    bool ok_ = true;
};

// An exclusive advisory lock on `<dir>/.lock`, so one backing directory is
// never used by two processes at once (two mounts, or a mount and
// `encfsctl rekey`). Held until the object is destroyed or the process
// exits; a forked child (e.g. a daemonised mount) keeps holding it. The
// descriptor is close-on-exec, so cloudcli children don't inherit it.
class DirLock {
public:
    DirLock() = default;
    ~DirLock();
    DirLock(const DirLock&) = delete;
    DirLock& operator=(const DirLock&) = delete;

    // False if another process holds the lock (or it can't be taken).
    bool Acquire(const std::string& dir);

private:
    int fd_ = -1;
};

// Overwrite a buffer with zeros in a way the optimiser can't elide.
void SecureWipe(std::vector<uint8_t>& buf);
void SecureWipe(std::string& buf);

} // namespace encfs

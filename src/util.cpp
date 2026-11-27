#include "util.h"

#include <openssl/crypto.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace encfs {

void AppendU32LE(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void AppendU64LE(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

uint32_t LoadU32LE(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 3; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

uint64_t LoadU64LE(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

std::string HexEncode(const uint8_t* data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += kHex[data[i] >> 4];
        out += kHex[data[i] & 0xf];
    }
    return out;
}

static int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool HexDecode(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = HexNibble(hex[i]);
        int lo = HexNibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    out.swap(result);
    return true;
}

bool ReadWholeFile(const std::string& path, std::vector<uint8_t>& out) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    std::vector<uint8_t> data;
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_size > 0) {
        data.reserve(static_cast<size_t>(st.st_size));
    }

    uint8_t buf[64 * 1024];
    for (;;) {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            ::close(fd);
            errno = saved;
            return false;
        }
        if (n == 0) break;
        data.insert(data.end(), buf, buf + n);
    }
    ::close(fd);
    out.swap(data);
    return true;
}

static bool WriteAll(int fd, const uint8_t* data, size_t len) {
    while (len > 0) {
        ssize_t n = ::write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += n;
        len -= static_cast<size_t>(n);
    }
    return true;
}

static void FsyncParentDir(const std::string& path) {
    std::string dir = ".";
    auto slash = path.find_last_of('/');
    if (slash == 0) {
        dir = "/";
    } else if (slash != std::string::npos) {
        dir = path.substr(0, slash);
    }
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        ::fsync(dfd);  // best effort: some filesystems don't support it
        ::close(dfd);
    }
}

bool WriteFileAtomic(const std::string& path, const uint8_t* data, size_t len, unsigned mode) {
    // Unique temp name so concurrent writers to the same target can't collide.
    std::string tmpl = path + ".tmp.XXXXXX";
    std::vector<char> tmp_path(tmpl.begin(), tmpl.end());
    tmp_path.push_back('\0');

    int fd = ::mkostemp(tmp_path.data(), O_CLOEXEC);
    if (fd < 0) return false;

    bool ok = ::fchmod(fd, static_cast<mode_t>(mode)) == 0 &&
              WriteAll(fd, data, len) &&
              ::fsync(fd) == 0;
    int saved = errno;
    if (::close(fd) != 0 && ok) {
        ok = false;
        saved = errno;
    }
    if (ok && ::rename(tmp_path.data(), path.c_str()) != 0) {
        ok = false;
        saved = errno;
    }
    if (!ok) {
        ::unlink(tmp_path.data());
        errno = saved;
        return false;
    }
    FsyncParentDir(path);
    return true;
}

AtomicFile::AtomicFile(std::string path, unsigned mode) : path_(std::move(path)), mode_(mode) {}

AtomicFile::~AtomicFile() {
    if (fd_ >= 0) {
        ::close(fd_);
        ::unlink(tmp_path_.c_str());
    }
}

bool AtomicFile::Open() {
    std::string tmpl = path_ + ".tmp.XXXXXX";
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    fd_ = ::mkostemp(buf.data(), O_CLOEXEC);
    if (fd_ < 0) return false;
    tmp_path_ = buf.data();
    return ::fchmod(fd_, static_cast<mode_t>(mode_)) == 0;
}

bool AtomicFile::Write(const uint8_t* data, size_t len) {
    if (fd_ < 0 || !ok_) return false;
    ok_ = WriteAll(fd_, data, len);
    return ok_;
}

bool AtomicFile::Commit() {
    if (fd_ < 0 || !ok_) return false;
    bool ok = ::fsync(fd_) == 0;
    int saved = errno;
    if (::close(fd_) != 0 && ok) {
        ok = false;
        saved = errno;
    }
    fd_ = -1;
    if (ok && ::rename(tmp_path_.c_str(), path_.c_str()) != 0) {
        ok = false;
        saved = errno;
    }
    if (!ok) {
        ::unlink(tmp_path_.c_str());
        errno = saved;
        return false;
    }
    FsyncParentDir(path_);
    return true;
}

void SecureWipe(std::vector<uint8_t>& buf) {
    if (!buf.empty()) OPENSSL_cleanse(buf.data(), buf.size());
}

void SecureWipe(std::string& buf) {
    if (!buf.empty()) OPENSSL_cleanse(&buf[0], buf.size());
}

} // namespace encfs

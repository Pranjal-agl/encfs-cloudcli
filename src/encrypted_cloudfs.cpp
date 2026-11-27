#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <getopt.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "cloudcli_wrapper.h"
#include "crypto.h"
#include "file_codec.h"
#include "index.h"
#include "key_setup.h"
#include "util.h"

#ifndef ENCFS_VERSION
#define ENCFS_VERSION "dev"
#endif

using namespace encfs;

namespace {

// Cloud object names for the index and the passphrase KDF parameters. Blob IDs
// are 64 hex characters, so these can't collide with them.
const char kCloudIndexId[] = "index";
const char kCloudKdfId[] = "encfs.kdf";

// Largest file we'll hold in memory. Files are buffered whole while open, so
// this bounds memory use from a single runaway writer.
constexpr uint64_t kMaxFileSize = 4ULL * 1024 * 1024 * 1024;

// Plaintext of a file that's currently open. Every handle for the same file
// shares one OpenFile, so concurrent readers/writers see a consistent view.
struct OpenFile {
    std::string name;
    std::string remote_id;
    std::vector<uint8_t> data;
    int64_t mtime = 0;
    bool loaded = false;   // `data` holds the file's contents
    bool dirty = false;    // `data` differs from what's on disk
    bool deleted = false;  // unlinked while open; never write it back
    int refs = 0;
};

struct Handle {
    std::shared_ptr<OpenFile> file;
    bool writable = false;
};

struct Context {
    std::string backing_dir;
    std::unique_ptr<FileCodec> codec;
    std::unique_ptr<EncryptedIndex> index;
    std::unique_ptr<CloudCLIWrapper> cloud;

    std::unordered_map<std::string, std::shared_ptr<OpenFile>> open_files;  // by name
    std::unordered_map<uint64_t, Handle> handles;
    uint64_t next_fh = 1;

    uid_t uid = 0;
    gid_t gid = 0;
    int64_t mount_time = 0;

    // Set when we started with a brand-new index because none could be found
    // locally or downloaded. Before the first upload we check the cloud again,
    // so a transient download failure can't make us replace a real index.
    bool index_guard_pending = false;
    // Set if that check found an existing cloud index: we refuse all writes
    // until the user remounts (and the index is restored).
    bool read_only = false;

    // One lock around all filesystem state. FUSE runs us single-threaded
    // (-s), so this costs nothing today but keeps us correct if that changes.
    std::mutex mutex;
};

Context* g_ctx = nullptr;

int SaveIndex();

void Log(const std::string& msg) {
    std::cerr << "[encfs] " << msg << "\n";
}

// Run a FUSE callback body, turning exceptions into errno values instead of
// letting them unwind into libfuse's C code (which would abort the process).
template <typename Fn>
int Guarded(const char* op, Fn&& fn) {
    try {
        return fn();
    } catch (const std::bad_alloc&) {
        Log(std::string(op) + ": out of memory");
        return -ENOMEM;
    } catch (const std::exception& e) {
        Log(std::string(op) + ": " + e.what());
        return -EIO;
    }
}

// The filesystem is flat: "/name" only. Returns 0 and sets `name`, or -errno.
int NameFromPath(const char* path, std::string& name) {
    if (path[0] != '/' || path[1] == '\0') return -ENOENT;
    name = path + 1;
    if (name.find('/') != std::string::npos) return -ENOENT;
    if (name.size() > 255) return -ENAMETOOLONG;
    return 0;
}

std::string BlobPath(const std::string& remote_id) {
    return g_ctx->backing_dir + "/" + remote_id + ".enc";
}

// Decrypt a blob for `name`, repairing the index if the blob is one version
// ahead (crash between writing the blob and saving the index).
int DecryptBlob(const std::string& name, FileMetadata meta,
                const std::vector<uint8_t>& blob, std::vector<uint8_t>& out) {
    uint64_t actual = meta.version;
    switch (g_ctx->codec->Decrypt(blob, meta.remote_id, meta.version, out, &actual)) {
    case FileCodec::Result::kOk:
        if (actual != meta.version) {
            meta.version = actual;
            meta.size = out.size();
            g_ctx->index->SetMetadata(name, meta);
            SaveIndex();
        }
        return 0;
    case FileCodec::Result::kRollback:
        Log("'" + name + "': blob is an older version than the index expects "
            "(stale copy or rollback attempt) — refusing to read it");
        return -EIO;
    case FileCodec::Result::kCorrupt:
    default:
        Log("'" + name + "': blob failed authentication (corrupt, tampered, or wrong file)");
        return -EIO;
    }
}

// Read and decrypt a file's contents, downloading the blob if needed.
int LoadContents(const std::string& name, const FileMetadata& meta, std::vector<uint8_t>& out) {
    const std::string path = BlobPath(meta.remote_id);
    std::vector<uint8_t> blob;

    if (ReadWholeFile(path, blob)) {
        return DecryptBlob(name, meta, blob, out);
    }
    if (errno != ENOENT) return -EIO;

    // Not cached locally: fetch it, and only keep it once it has verified.
    std::string tmp = path + ".download";
    if (!g_ctx->cloud->Download(meta.remote_id, tmp) || !ReadWholeFile(tmp, blob)) {
        ::unlink(tmp.c_str());
        if (meta.size == 0) {
            // Older versions never wrote a blob for empty files.
            out.clear();
            return 0;
        }
        Log("'" + name + "': not cached locally and download failed");
        return -EIO;
    }
    int rc = DecryptBlob(name, meta, blob, out);
    if (rc == 0) {
        if (::rename(tmp.c_str(), path.c_str()) != 0) ::unlink(tmp.c_str());
    } else {
        ::unlink(tmp.c_str());
    }
    return rc;
}

std::shared_ptr<OpenFile> Acquire(const std::string& name, const FileMetadata& meta) {
    auto it = g_ctx->open_files.find(name);
    if (it != g_ctx->open_files.end() && !it->second->deleted) {
        it->second->refs++;
        return it->second;
    }
    auto file = std::make_shared<OpenFile>();
    file->name = name;
    file->remote_id = meta.remote_id;
    file->mtime = meta.mtime;
    file->refs = 1;
    g_ctx->open_files[name] = file;
    return file;
}

void ReleaseRef(const std::shared_ptr<OpenFile>& file) {
    if (--file->refs > 0) return;
    auto it = g_ctx->open_files.find(file->name);
    if (it != g_ctx->open_files.end() && it->second == file) {
        g_ctx->open_files.erase(it);
    }
    SecureWipe(file->data);
}

int EnsureLoaded(OpenFile& file) {
    if (file.loaded) return 0;
    FileMetadata meta;
    if (!g_ctx->index->GetMetadata(file.name, meta)) return -ENOENT;
    int rc = LoadContents(file.name, meta, file.data);
    if (rc == 0) file.loaded = true;
    return rc;
}

// Encrypt and write back a dirty file, update the index, queue the upload.
int Persist(OpenFile& file) {
    if (!file.dirty || file.deleted) return 0;
    if (g_ctx->read_only) return -EROFS;

    FileMetadata meta;
    if (!g_ctx->index->GetMetadata(file.name, meta)) return 0;  // removed meanwhile

    const uint64_t version = meta.version + 1;
    std::vector<uint8_t> blob = g_ctx->codec->Encrypt(file.data, file.remote_id, version);
    const std::string path = BlobPath(file.remote_id);
    if (!WriteFileAtomic(path, blob, 0600)) {
        int err = errno ? errno : EIO;
        Log("'" + file.name + "': cannot write " + path + ": " + std::strerror(err));
        return -err;
    }

    meta.remote_id = file.remote_id;
    meta.version = version;
    meta.size = file.data.size();
    meta.mtime = file.mtime;
    g_ctx->index->SetMetadata(file.name, meta);
    if (int rc = SaveIndex()) {
        // The blob is now one version ahead of the saved index; DecryptBlob
        // accepts and repairs that on the next read.
        return rc;
    }

    file.dirty = false;
    g_ctx->cloud->QueueUpload(path);
    return 0;
}

// Remove a file's index entry, local blob and (in the background) cloud copy.
void RemoveFile(const std::string& name, const FileMetadata& meta) {
    g_ctx->index->Remove(name);
    SaveIndex();
    ::unlink(BlobPath(meta.remote_id).c_str());
    g_ctx->cloud->QueueDelete(meta.remote_id);

    auto it = g_ctx->open_files.find(name);
    if (it != g_ctx->open_files.end()) {
        it->second->deleted = true;  // open handles keep their in-memory view
        g_ctx->open_files.erase(it);
    }
}

Handle* FindHandle(struct fuse_file_info* fi) {
    if (!fi) return nullptr;
    auto it = g_ctx->handles.find(fi->fh);
    return it == g_ctx->handles.end() ? nullptr : &it->second;
}

int64_t Now() {
    return static_cast<int64_t>(std::time(nullptr));
}

// Save the index locally and queue its upload, so the cloud copy is enough to
// restore the filesystem (with the key) on another machine.
int SaveIndex() {
    if (!g_ctx->index->Save()) {
        Log("failed to save index");
        return -EIO;
    }
    if (g_ctx->index_guard_pending) {
        g_ctx->index_guard_pending = false;
        const std::string probe = g_ctx->index->path() + ".probe";
        bool cloud_has_index = g_ctx->cloud->Download(kCloudIndexId, probe);
        ::unlink(probe.c_str());
        if (cloud_has_index) {
            // Our fresh index would overwrite the real one. Throw it away so
            // the next mount restores the cloud copy, and stop accepting writes.
            ::unlink(g_ctx->index->path().c_str());
            g_ctx->read_only = true;
            Log("the cloud already has an index that could not be downloaded at mount time. "
                "Writes are disabled; unmount and mount again to restore it.");
            return -EROFS;
        }
    }
    g_ctx->cloud->QueueUpload(g_ctx->index->path());
    return 0;
}

// ── FUSE operations ─────────────────────────────────────────────────────────

void* encfs_init(struct fuse_conn_info* conn, struct fuse_config* cfg) {
    (void)conn;
    (void)cfg;
    // Started here rather than in main(): with --background, fuse_main forks
    // before calling init, and threads don't survive a fork.
    g_ctx->cloud->StartBackgroundUploader();
    return g_ctx;
}

void encfs_destroy(void* private_data) {
    (void)private_data;
    {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        for (auto& [name, file] : g_ctx->open_files) {
            Persist(*file);
        }
    }
    size_t pending = g_ctx->cloud->PendingCount();
    if (pending > 0) {
        Log("finishing " + std::to_string(pending) + " pending cloud operation(s)...");
    }
    g_ctx->cloud->StopBackgroundUploader();  // drains the queue
}

int encfs_getattr(const char* path, struct stat* st, struct fuse_file_info* fi) {
    (void)fi;
    return Guarded("getattr", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        std::memset(st, 0, sizeof(*st));
        st->st_uid = g_ctx->uid;
        st->st_gid = g_ctx->gid;

        if (std::strcmp(path, "/") == 0) {
            st->st_mode = S_IFDIR | 0755;
            st->st_nlink = 2;
            st->st_mtime = st->st_ctime = st->st_atime = g_ctx->mount_time;
            return 0;
        }

        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;

        uint64_t size = meta.size;
        int64_t mtime = meta.mtime;
        auto it = g_ctx->open_files.find(name);
        if (it != g_ctx->open_files.end() && it->second->loaded) {
            size = it->second->data.size();  // reflect unsaved writes
            mtime = it->second->mtime;
        }

        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = static_cast<off_t>(size);
        st->st_blocks = static_cast<blkcnt_t>((size + 511) / 512);
        st->st_mtime = st->st_ctime = st->st_atime = static_cast<time_t>(mtime);
        return 0;
    });
}

int encfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset,
                  struct fuse_file_info* fi, enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;
    return Guarded("readdir", [&]() -> int {
        if (std::strcmp(path, "/") != 0) return -ENOENT;
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        filler(buf, ".", nullptr, 0, fuse_fill_dir_flags(0));
        filler(buf, "..", nullptr, 0, fuse_fill_dir_flags(0));
        for (const auto& name : g_ctx->index->GetAllPlaintextNames()) {
            filler(buf, name.c_str(), nullptr, 0, fuse_fill_dir_flags(0));
        }
        return 0;
    });
}

int RegisterHandle(std::shared_ptr<OpenFile> file, bool writable, struct fuse_file_info* fi) {
    uint64_t fh = g_ctx->next_fh++;
    g_ctx->handles[fh] = Handle{std::move(file), writable};
    fi->fh = fh;
    return 0;
}

int encfs_open(const char* path, struct fuse_file_info* fi) {
    return Guarded("open", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;

        const bool writable = (fi->flags & O_ACCMODE) != O_RDONLY;
        if (writable && g_ctx->read_only) return -EROFS;
        auto file = Acquire(name, meta);

        if (writable && (fi->flags & O_TRUNC)) {
            file->data.clear();
            file->loaded = true;
            file->dirty = true;
            file->mtime = Now();
        } else if (int rc = EnsureLoaded(*file)) {
            // Load for writers too: without the existing contents, appends
            // and partial overwrites would destroy the rest of the file.
            ReleaseRef(file);
            return rc;
        }
        return RegisterHandle(std::move(file), writable, fi);
    });
}

int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void)mode;
    return Guarded("create", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;

        FileMetadata meta;
        const bool existed = g_ctx->index->GetMetadata(name, meta);
        if (existed && (fi->flags & O_EXCL)) return -EEXIST;
        if (!existed) {
            meta = FileMetadata();
            meta.remote_id = g_ctx->codec->RemoteIdFor(name);
            meta.mtime = Now();
            g_ctx->index->SetMetadata(name, meta);
            if (int rc = SaveIndex()) {
                g_ctx->index->Remove(name);
                return rc;
            }
        }

        auto file = Acquire(name, meta);
        if (!existed || (fi->flags & O_TRUNC)) {
            file->data.clear();
            file->loaded = true;
            file->dirty = true;  // ensure even an empty file gets a blob
            file->mtime = Now();
        } else if (int rc = EnsureLoaded(*file)) {
            ReleaseRef(file);
            return rc;
        }
        return RegisterHandle(std::move(file), true, fi);
    });
}

int encfs_read(const char* path, char* buf, size_t size, off_t offset,
               struct fuse_file_info* fi) {
    (void)path;
    return Guarded("read", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        Handle* h = FindHandle(fi);
        if (!h) return -EBADF;
        if (int rc = EnsureLoaded(*h->file)) return rc;

        const auto& data = h->file->data;
        if (offset < 0) return -EINVAL;
        if (static_cast<uint64_t>(offset) >= data.size()) return 0;
        size_t n = std::min(size, data.size() - static_cast<size_t>(offset));
        n = std::min<size_t>(n, INT_MAX);
        std::memcpy(buf, data.data() + offset, n);
        return static_cast<int>(n);
    });
}

int encfs_write(const char* path, const char* buf, size_t size, off_t offset,
                struct fuse_file_info* fi) {
    (void)path;
    return Guarded("write", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        Handle* h = FindHandle(fi);
        if (!h || !h->writable) return -EBADF;
        if (offset < 0 || size > INT_MAX) return -EINVAL;
        if (static_cast<uint64_t>(offset) + size > kMaxFileSize) return -EFBIG;

        OpenFile& file = *h->file;
        if (int rc = EnsureLoaded(file)) return rc;
        size_t end = static_cast<size_t>(offset) + size;
        if (file.data.size() < end) file.data.resize(end);
        std::memcpy(file.data.data() + offset, buf, size);
        file.dirty = true;
        file.mtime = Now();
        return static_cast<int>(size);
    });
}

int encfs_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
    return Guarded("truncate", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        if (size < 0) return -EINVAL;
        if (static_cast<uint64_t>(size) > kMaxFileSize) return -EFBIG;

        std::shared_ptr<OpenFile> file;
        bool temporary = false;
        if (Handle* h = FindHandle(fi)) {
            if (!h->writable) return -EBADF;
            file = h->file;
        } else {
            std::string name;
            if (int rc = NameFromPath(path, name)) return rc;
            FileMetadata meta;
            if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;
            file = Acquire(name, meta);
            temporary = true;
        }

        int rc = 0;
        if (size == 0) {
            file->data.clear();
            file->loaded = true;  // no need to decrypt what we're discarding
        } else {
            rc = EnsureLoaded(*file);
        }
        if (rc == 0) {
            file->data.resize(static_cast<size_t>(size));
            file->dirty = true;
            file->mtime = Now();
            // Path-based truncate has no close() to piggy-back on: save now.
            if (temporary) rc = Persist(*file);
        }
        if (temporary) ReleaseRef(file);
        return rc;
    });
}

int encfs_flush(const char* path, struct fuse_file_info* fi) {
    (void)path;
    return Guarded("flush", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        Handle* h = FindHandle(fi);
        if (!h) return -EBADF;
        // Saving on flush means close() reports write errors to the caller.
        return Persist(*h->file);
    });
}

int encfs_fsync(const char* path, int datasync, struct fuse_file_info* fi) {
    (void)datasync;
    return encfs_flush(path, fi);
}

int encfs_release(const char* path, struct fuse_file_info* fi) {
    (void)path;
    return Guarded("release", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        auto it = g_ctx->handles.find(fi->fh);
        if (it == g_ctx->handles.end()) return 0;
        std::shared_ptr<OpenFile> file = std::move(it->second.file);
        g_ctx->handles.erase(it);

        if (int rc = Persist(*file)) {
            Log("'" + file->name + "': changes could not be saved (" +
                std::strerror(-rc) + ")");
        }
        ReleaseRef(file);
        return 0;
    });
}

int encfs_unlink(const char* path) {
    return Guarded("unlink", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;
        RemoveFile(name, meta);
        return 0;
    });
}

// Remote IDs are derived from the name, so a rename re-encrypts the contents
// under the new ID (the blob is also bound to its ID) and removes the old one.
int encfs_rename(const char* from, const char* to, unsigned int flags) {
    return Guarded("rename", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        if (flags & RENAME_EXCHANGE) return -EINVAL;

        std::string src, dst;
        if (int rc = NameFromPath(from, src)) return rc;
        if (int rc = NameFromPath(to, dst)) return rc;

        FileMetadata src_meta, dst_meta;
        if (!g_ctx->index->GetMetadata(src, src_meta)) return -ENOENT;
        if (src == dst) return 0;
        const bool dst_exists = g_ctx->index->GetMetadata(dst, dst_meta);
        if (dst_exists && (flags & RENAME_NOREPLACE)) return -EEXIST;

        auto file = Acquire(src, src_meta);
        if (int rc = EnsureLoaded(*file)) {
            ReleaseRef(file);
            return rc;
        }

        if (dst_exists) RemoveFile(dst, dst_meta);

        const std::string old_id = file->remote_id;
        FileMetadata new_meta = src_meta;
        new_meta.remote_id = g_ctx->codec->RemoteIdFor(dst);

        g_ctx->index->Remove(src);
        g_ctx->index->SetMetadata(dst, new_meta);
        g_ctx->open_files.erase(src);
        file->name = dst;
        file->remote_id = new_meta.remote_id;
        file->dirty = true;
        g_ctx->open_files[dst] = file;

        int rc = Persist(*file);
        if (rc != 0) {
            // Undo the in-memory move so the source is still intact.
            g_ctx->index->Remove(dst);
            g_ctx->index->SetMetadata(src, src_meta);
            SaveIndex();
            g_ctx->open_files.erase(dst);
            file->name = src;
            file->remote_id = old_id;
            g_ctx->open_files[src] = file;
        } else {
            ::unlink(BlobPath(old_id).c_str());
            g_ctx->cloud->QueueDelete(old_id);
        }
        ReleaseRef(file);
        return rc;
    });
}

int encfs_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info* fi) {
    (void)fi;
    return Guarded("utimens", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;

        // Only mtime is stored; atime is ignored.
        if (tv == nullptr || tv[1].tv_nsec == UTIME_NOW) {
            meta.mtime = Now();
        } else if (tv[1].tv_nsec != UTIME_OMIT) {
            meta.mtime = static_cast<int64_t>(tv[1].tv_sec);
        } else {
            return 0;
        }

        g_ctx->index->SetMetadata(name, meta);
        auto it = g_ctx->open_files.find(name);
        if (it != g_ctx->open_files.end()) it->second->mtime = meta.mtime;
        return SaveIndex();
    });
}

// Permissions and ownership aren't stored (everything belongs to the mounting
// user). Accept the calls so tools like `cp -p` and `rsync -a` work.
int encfs_chmod(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void)mode;
    (void)fi;
    return Guarded("chmod", [&]() -> int {
        if (std::strcmp(path, "/") == 0) return 0;
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        return g_ctx->index->Exists(name) ? 0 : -ENOENT;
    });
}

int encfs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info* fi) {
    (void)uid;
    (void)gid;
    return encfs_chmod(path, 0, fi);
}

int encfs_statfs(const char* path, struct statvfs* st) {
    (void)path;
    if (::statvfs(g_ctx->backing_dir.c_str(), st) != 0) return -errno;
    st->f_namemax = 255;
    return 0;
}

struct fuse_operations MakeOperations() {
    struct fuse_operations ops;
    std::memset(&ops, 0, sizeof(ops));
    ops.init = encfs_init;
    ops.destroy = encfs_destroy;
    ops.getattr = encfs_getattr;
    ops.readdir = encfs_readdir;
    ops.open = encfs_open;
    ops.create = encfs_create;
    ops.read = encfs_read;
    ops.write = encfs_write;
    ops.truncate = encfs_truncate;
    ops.flush = encfs_flush;
    ops.fsync = encfs_fsync;
    ops.release = encfs_release;
    ops.unlink = encfs_unlink;
    ops.rename = encfs_rename;
    ops.utimens = encfs_utimens;
    ops.chmod = encfs_chmod;
    ops.chown = encfs_chown;
    ops.statfs = encfs_statfs;
    return ops;
}

// ── Command line ────────────────────────────────────────────────────────────

bool LocalFileExists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

// Download a cloud object to `path` atomically (temp file + rename).
bool FetchFromCloud(CloudCLIWrapper& cloud, const std::string& remote_id, const std::string& path) {
    const std::string tmp = path + ".download";
    if (cloud.Download(remote_id, tmp) && ::rename(tmp.c_str(), path.c_str()) == 0) {
        return true;
    }
    ::unlink(tmp.c_str());
    return false;
}

void PrintUsage(const char* prog) {
    std::cout <<
        "Usage: " << prog << " [options] <mountpoint> <backing_dir> [-- <fuse options>]\n"
        "\n"
        "Mounts an encrypted view of <backing_dir> at <mountpoint>. Files are\n"
        "encrypted with AES-256-GCM and synced to the cloud via cloudcli.\n"
        "\n"
        "Options:\n"
        "  -k, --key FILE      key file: 64 hex chars or 32 raw bytes\n"
        "                      (default: $ENCFS_KEY_FILE or ~/.encfs/key)\n"
        "  -p, --passphrase    derive the key from a passphrase instead\n"
        "                      ($ENCFS_PASSPHRASE, or prompt)\n"
        "  -c, --cloudcli CMD  cloudcli executable (default: $ENCFS_CLOUDCLI or cloudcli)\n"
        "  -b, --background    detach from the terminal once mounted\n"
        "  -d, --debug         print FUSE debug output\n"
        "  -h, --help          show this help\n"
        "  -V, --version       show version\n"
        "\n"
        "Unmount with: fusermount3 -u <mountpoint>\n";
}

} // namespace

int main(int argc, char* argv[]) {
    KeyOptions key_options;
    std::string cloudcli_cmd = CloudCLIWrapper::DefaultCommand();
    bool background = false;
    bool debug = false;

    static const struct option long_opts[] = {
        {"key", required_argument, nullptr, 'k'},
        {"passphrase", no_argument, nullptr, 'p'},
        {"cloudcli", required_argument, nullptr, 'c'},
        {"background", no_argument, nullptr, 'b'},
        {"debug", no_argument, nullptr, 'd'},
        {"help", no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'V'},
        {nullptr, 0, nullptr, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "+k:pc:bdhV", long_opts, nullptr)) != -1) {
        switch (opt) {
        case 'k': key_options.key_path = optarg; break;
        case 'p': key_options.use_passphrase = true; break;
        case 'c': cloudcli_cmd = optarg; break;
        case 'b': background = true; break;
        case 'd': debug = true; break;
        case 'h': PrintUsage(argv[0]); return 0;
        case 'V': std::cout << "encfs-cloudcli " << ENCFS_VERSION << "\n"; return 0;
        default: PrintUsage(argv[0]); return 2;
        }
    }
    if (argc - optind < 2) {
        PrintUsage(argv[0]);
        return 2;
    }
    if (!key_options.key_path.empty() && key_options.use_passphrase) {
        std::cerr << "--key and --passphrase are mutually exclusive\n";
        return 2;
    }

    namespace fs = std::filesystem;
    std::error_code ec;
    // Absolute paths: in --background mode the daemon chdir()s to "/".
    std::string mount_point = fs::absolute(argv[optind], ec).lexically_normal().string();
    std::string backing_dir = fs::absolute(argv[optind + 1], ec).lexically_normal().string();
    while (backing_dir.size() > 1 && backing_dir.back() == '/') backing_dir.pop_back();
    int extra_start = optind + 2;
    if (extra_start < argc && std::strcmp(argv[extra_start], "--") == 0) ++extra_start;

    if (mount_point == backing_dir) {
        std::cerr << "The mount point and backing directory must be different\n";
        return 2;
    }
    fs::create_directories(backing_dir, ec);
    if (ec) {
        std::cerr << "Cannot create backing directory " << backing_dir << ": " << ec.message() << "\n";
        return 1;
    }
    ::chmod(backing_dir.c_str(), 0700);

    // A new machine (or a lost backing directory): fetch the index, and the
    // passphrase KDF parameters if needed, from the cloud before checking the key.
    CloudCLIWrapper bootstrap(cloudcli_cmd);
    const std::string index_path = backing_dir + "/index.enc";
    const std::string kdf_path = backing_dir + "/encfs.kdf";
    bool fresh_index = false;
    if (!LocalFileExists(index_path)) {
        if (FetchFromCloud(bootstrap, kCloudIndexId, index_path)) {
            std::cerr << "[encfs] restored the index from the cloud\n";
        } else {
            fresh_index = true;
            std::cerr << "[encfs] no index found locally or in the cloud: starting a new "
                         "filesystem\n";
        }
    }
    bool had_kdf = LocalFileExists(kdf_path);
    if (key_options.use_passphrase && !had_kdf) {
        had_kdf = FetchFromCloud(bootstrap, kCloudKdfId, kdf_path);
    }

    std::vector<uint8_t> master_key;
    std::string error;
    if (!ResolveMasterKey(key_options, backing_dir, /*allow_create=*/true, master_key, error)) {
        std::cerr << "Error: " << error << "\n";
        return 1;
    }

    auto ctx = std::make_unique<Context>();
    ctx->backing_dir = backing_dir;
    ctx->codec = std::make_unique<FileCodec>(master_key);
    ctx->index = std::make_unique<EncryptedIndex>(backing_dir, master_key);
    ctx->cloud = std::make_unique<CloudCLIWrapper>(cloudcli_cmd);
    ctx->uid = getuid();
    ctx->gid = getgid();
    ctx->mount_time = Now();
    SecureWipe(master_key);

    if (!ctx->index->Load()) {
        // ResolveMasterKey already checked the key, so this is real damage.
        std::cerr << "Error: cannot read " << ctx->index->path() << "\n";
        return 1;
    }

    ctx->index_guard_pending = fresh_index;
    ctx->cloud->SetJournalPath(backing_dir + "/sync.journal");
    if (size_t resumed = ctx->cloud->RecoverJournal()) {
        std::cerr << "[encfs] resuming " << resumed << " unfinished cloud operation(s)\n";
    }
    if (!had_kdf && LocalFileExists(kdf_path)) {
        ctx->cloud->QueueUpload(kdf_path);  // KDF parameters were just created
    }
    g_ctx = ctx.get();

    std::vector<std::string> fuse_args = {argv[0], mount_point, "-s",
                                          "-o", "fsname=encfs-cloudcli,subtype=encfs"};
    if (!background) fuse_args.push_back("-f");
    if (debug) fuse_args.push_back("-d");
    for (int i = extra_start; i < argc; ++i) fuse_args.push_back(argv[i]);

    std::vector<char*> fuse_argv;
    for (auto& a : fuse_args) fuse_argv.push_back(&a[0]);
    fuse_argv.push_back(nullptr);

    struct fuse_operations ops = MakeOperations();
    int ret = fuse_main(static_cast<int>(fuse_args.size()), fuse_argv.data(), &ops, nullptr);

    // Normally done in destroy(); this covers mount failures.
    ctx->cloud->StopBackgroundUploader();
    g_ctx = nullptr;
    return ret;
}

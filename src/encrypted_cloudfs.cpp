#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <unordered_set>
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
#include "file_contents.h"
#include "index.h"
#include "index_sync.h"
#include "segments.h"
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


// ── Locking ─────────────────────────────────────────────────────────────────
// FUSE calls us from several threads. Locks, outermost first:
//
//   1. Context::mutex   the namespace: open_files, handles, refcounts, and every
//                       operation that adds, removes or renames entries. Held
//                       briefly, except by rename (which re-encrypts).
//   2. OpenFile::mu     one file's contents. Downloads, reads, writes and saves
//                       run under this alone, so a slow file blocks nobody else.
//   3. leaf locks       EncryptedIndex's, synced_mutex, guard_mutex, and the
//                       cloud wrapper's. Holders take no other lock.
//
// A thread may take a lock only if it holds none further down the list: in
// particular, code holding a file lock never takes the namespace lock.
// unlink/rename take a file's lock (under the namespace lock) to mark it
// deleted or moved, which also makes them wait for a save in progress.

// Plaintext of a file that's currently open. Every handle for the same file
// shares one OpenFile, so concurrent readers/writers see a consistent view.
struct OpenFile {
    std::mutex mu;
    std::string name;       // a path it was opened by (for log messages only)
    std::string remote_id;  // inode ID: the key in open_files, never changes
    // Guarded by `mu`. Chunk-level view of the contents (null until first
    // needed); bounded memory whatever the file's size.
    std::unique_ptr<FileContents> contents;
    bool dirty = false;  // contents differ from what's on disk

    // Readable without `mu` (getattr holds only the namespace lock).
    std::atomic<bool> deleted{false};  // unlinked while open; never write back
    std::atomic<bool> loaded{false};   // `contents` exists; size_hint is current
    std::atomic<uint64_t> size_hint{0};
    std::atomic<int64_t> mtime{0};

    int refs = 0;  // guarded by the namespace lock
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

    // By inode ID, so every path to a hard-linked file shares one OpenFile
    // and renames don't affect open files.
    std::unordered_map<std::string, std::shared_ptr<OpenFile>> open_files;
    std::unordered_map<uint64_t, Handle> handles;
    uint64_t next_fh = 1;

    uid_t uid = 0;
    gid_t gid = 0;
    int64_t mount_time = 0;

    // Set when we started with a brand-new index because none could be found
    // locally or downloaded. Before the first upload we check the cloud again,
    // so a transient download failure can't make us replace a real index.
    // guard_mutex makes every SaveIndex wait for that check.
    std::atomic<bool> index_guard_pending{false};
    std::mutex guard_mutex;
    // Set if that check found an existing cloud index: we refuse all writes
    // until the user remounts (and the index is restored).
    std::atomic<bool> read_only{false};

    // Multi-machine bookkeeping (see index_sync.h). The master key is kept to
    // read generations of index snapshots and cloud copies.
    std::vector<uint8_t> master_key;
    std::atomic<uint64_t> synced_gen{0};      // cloud generation we last synced with
    std::atomic<bool> synced_gen_known{true};  // false: pre-3.1 store, learned at first check
    std::atomic<uint64_t> uploading_gen{0};   // generation of the index snapshot in flight
    std::atomic<bool> force_index_upload{false};  // --prefer-local over an unreadable cloud copy
    bool pad = false;  // --pad: round final segments up to hide exact sizes

    // Local cache limit for blobs (0 = keep everything). See EnforceCacheLimit.
    uint64_t cache_limit = 0;
    // remote ID → the file version the cloud is known to hold (confirmed by a
    // finished upload or a verified download). Persisted in synced.list.
    std::unordered_map<std::string, uint64_t> synced;  // guarded by synced_mutex
    bool synced_dirty = false;
    std::mutex synced_mutex;
    // Set by code that can't take the namespace lock; the cache limit is then
    // enforced once that code has released its file lock.
    std::atomic<bool> cache_check_pending{false};

    // The namespace lock (see "Locking" above).
    std::mutex mutex;
};

Context* g_ctx = nullptr;

int SaveIndex();
void MarkSynced(const std::string& id, uint64_t version);
void Unsync(const std::string& id);
void TouchBlob(const std::string& path);
void EnforceCacheLimit();

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

// Turn a FUSE path ("/a/b.txt") into an index key ("a/b.txt"). Returns 0, or
// -errno for the root or a malformed path.
int NameFromPath(const char* path, std::string& name) {
    if (path[0] != '/' || path[1] == '\0') return -ENOENT;
    name = path + 1;
    if (name.size() >= PATH_MAX) return -ENAMETOOLONG;
    size_t start = 0;
    for (;;) {
        size_t slash = name.find('/', start);
        size_t len = (slash == std::string::npos ? name.size() : slash) - start;
        if (len == 0) return -EINVAL;
        if (len > 255) return -ENAMETOOLONG;
        if ((len == 1 && name[start] == '.') ||
            (len == 2 && name[start] == '.' && name[start + 1] == '.')) {
            return -EINVAL;
        }
        if (slash == std::string::npos) return 0;
        start = slash + 1;
    }
}

// "a/b/c.txt" → "a/b"; top-level names → "" (the root).
std::string ParentOf(const std::string& name) {
    auto slash = name.find_last_of('/');
    return slash == std::string::npos ? std::string() : name.substr(0, slash);
}

// The parent of `name` must be the root or an existing directory.
int CheckParent(const std::string& name) {
    const std::string parent = ParentOf(name);
    if (parent.empty()) return 0;
    FileMetadata meta;
    if (!g_ctx->index->GetMetadata(parent, meta)) return -ENOENT;
    return meta.IsDirectory() ? 0 : -ENOTDIR;
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
            g_ctx->index->UpdateInode(meta);
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

std::unique_ptr<FileContents> NewContents(std::unique_ptr<ChunkSource> base) {
    size_t chunk = base ? base->chunk_size() : g_ctx->codec->chunk_size();
    return std::make_unique<FileContents>(std::move(base), chunk, g_ctx->backing_dir);
}

// Opens segment `seg` of a segmented file for SegmentedReader: from the local
// cache, or downloaded (and verified before it is kept). Runs under the
// file's lock, so only this file waits for a download.
SegmentedReader::Opener SegmentOpener(const FileMetadata& meta) {
    return [meta](uint64_t seg) -> std::unique_ptr<ChunkedReader> {
        const uint64_t version = meta.segments[seg];
        const std::string object = SegmentObjectId(meta.remote_id, seg, version);
        const std::string path = BlobPath(object);
        std::unique_ptr<ChunkedReader> reader;
        struct stat st;
        if (::stat(path.c_str(), &st) == 0) {
            if (g_ctx->codec->OpenSegmentReader(path, meta.remote_id, seg, version, &reader) ==
                FileCodec::Result::kOk) {
                TouchBlob(path);
                return reader;
            }
            Log("segment " + object + " failed authentication (corrupt, tampered, or misplaced)");
            return nullptr;
        }
        const std::string tmp = path + ".download";
        if (!g_ctx->cloud->Download(object, tmp)) {
            ::unlink(tmp.c_str());
            Log("segment " + object + " is not cached locally and could not be downloaded");
            return nullptr;
        }
        if (g_ctx->codec->OpenSegmentReader(tmp, meta.remote_id, seg, version, &reader) !=
            FileCodec::Result::kOk) {
            ::unlink(tmp.c_str());
            Log("downloaded segment " + object + " failed authentication");
            return nullptr;
        }
        if (::rename(tmp.c_str(), path.c_str()) == 0) {
            MarkSynced(object, version);  // the cloud verifiably holds it
            g_ctx->cache_check_pending = true;
        } else {
            ::unlink(tmp.c_str());
        }
        return reader;  // the open descriptor survives the rename
    };
}

// Publish size/state for getattr, which reads them without the file lock.
// Caller holds file.mu.
void Publish(OpenFile& file) {
    file.size_hint = file.contents ? file.contents->size() : 0;
    file.loaded = file.contents != nullptr;
}

// Make a file's contents available: a chunk-level view over its blob
// (downloading the blob first if it isn't cached). Legacy v1 blobs, which
// have no random access, are decrypted once and copied into the view.
int OpenContents(OpenFile& file) {
    if (file.contents) return 0;
    FileMetadata meta;
    if (!g_ctx->index->GetInode(file.remote_id, meta)) return -ENOENT;

    if (meta.segment_size > 0) {
        // Segments are opened (and downloaded) only as they're read.
        file.contents = std::make_unique<FileContents>(
            std::make_unique<SegmentedReader>(meta, meta.chunk_size, SegmentOpener(meta)),
            meta.chunk_size, g_ctx->backing_dir);
        Publish(file);
        return 0;
    }

    const std::string path = BlobPath(meta.remote_id);
    std::string source = path;
    bool downloaded = false;
    struct stat st;
    if (::stat(path.c_str(), &st) != 0) {
        // Not cached locally: fetch it, and only keep it once it has verified.
        source = path + ".download";
        if (!g_ctx->cloud->Download(meta.remote_id, source)) {
            ::unlink(source.c_str());
            if (meta.size == 0) {  // older versions never wrote a blob for empty files
                file.contents = NewContents(nullptr);
                return 0;
            }
            Log("'" + file.name + "': not cached locally and download failed");
            return -EIO;
        }
        downloaded = true;
    }

    int rc = 0;
    std::unique_ptr<ChunkedReader> reader;
    uint64_t actual = meta.version;
    switch (g_ctx->codec->OpenReader(source, meta.remote_id, meta.version, &reader, &actual)) {
    case FileCodec::Result::kOk:
        if (!reader) {
            // Legacy v1 blob: decrypt it in one go, then hold it chunk-wise.
            std::vector<uint8_t> blob, plain;
            rc = ReadWholeFile(source, blob) ? DecryptBlob(file.name, meta, blob, plain) : -EIO;
            if (rc == 0) {
                file.contents = NewContents(nullptr);
                if (!file.contents->Write(0, plain.data(), plain.size())) rc = -EIO;
                SecureWipe(plain);
            }
        } else if (actual != meta.version) {
            // Blob is one version ahead (crash before the index was saved).
            meta.version = actual;
            meta.size = reader->plaintext_size();
            g_ctx->index->UpdateInode(meta);
            SaveIndex();
            file.contents = NewContents(std::move(reader));
        } else if (reader->plaintext_size() != meta.size) {
            Log("'" + file.name + "': blob length doesn't match the index (truncated or extended)");
            rc = -EIO;
        } else {
            file.contents = NewContents(std::move(reader));
        }
        break;
    case FileCodec::Result::kRollback:
        Log("'" + file.name + "': blob is an older version than the index expects "
            "(stale copy or rollback attempt) — refusing to read it");
        rc = -EIO;
        break;
    case FileCodec::Result::kCorrupt:
    default:
        Log("'" + file.name + "': blob failed authentication (corrupt, tampered, or wrong file)");
        rc = -EIO;
        break;
    }

    if (downloaded) {
        if (rc == 0 && ::rename(source.c_str(), path.c_str()) == 0) {
            // Verified, so the cloud holds exactly this version.
            FileMetadata now;
            if (g_ctx->index->GetInode(file.remote_id, now)) MarkSynced(now.remote_id, now.version);
            g_ctx->cache_check_pending = true;  // can't take the namespace lock here
        } else {
            ::unlink(source.c_str());
        }
    } else if (rc == 0) {
        TouchBlob(path);
    }
    if (rc != 0) file.contents.reset();
    Publish(file);
    return rc;
}

// Start the file over as empty, without reading what was there. Caller holds
// file.mu.
void ResetContents(OpenFile& file) {
    if (file.contents) {
        file.contents->Truncate(0);
    } else {
        file.contents = NewContents(nullptr);
    }
    Publish(file);
}

// Caller holds the namespace lock.
std::shared_ptr<OpenFile> Acquire(const std::string& name, const FileMetadata& meta) {
    auto it = g_ctx->open_files.find(meta.remote_id);
    if (it != g_ctx->open_files.end() && !it->second->deleted) {
        it->second->refs++;
        return it->second;
    }
    auto file = std::make_shared<OpenFile>();
    file->name = name;
    file->remote_id = meta.remote_id;
    file->mtime = meta.mtime;
    file->refs = 1;
    g_ctx->open_files[meta.remote_id] = file;
    return file;
}

// Caller holds the namespace lock (and not file->mu).
void ReleaseRef(const std::shared_ptr<OpenFile>& file) {
    if (--file->refs > 0) return;
    auto it = g_ctx->open_files.find(file->remote_id);
    if (it != g_ctx->open_files.end() && it->second == file) {
        g_ctx->open_files.erase(it);
    }
    std::lock_guard<std::mutex> file_lock(file->mu);
    file->contents.reset();  // wipes cached chunks, drops the scratch file
    Publish(*file);
}

// Save a dirty file. Files are stored as segments; only segments whose
// contents or length changed are re-encrypted and uploaded, as new objects
// (new version → new name). The index then switches to them in one atomic
// save; superseded objects are deleted locally at once and in the cloud only
// after the new index is there. A crash before the index save leaves the old
// version intact (the new objects are unreferenced and cleaned up at mount).
// Caller holds file.mu (only).
int Persist(OpenFile& file) {
    if (!file.dirty || file.deleted) return 0;
    if (g_ctx->read_only) return -EROFS;
    if (int rc = OpenContents(file)) return rc;

    FileMetadata old_meta;
    if (!g_ctx->index->GetInode(file.remote_id, old_meta)) return 0;  // removed meanwhile

    FileContents& contents = *file.contents;
    const size_t cs = contents.chunk_size();
    const uint64_t seg_size =
        (old_meta.segment_size > 0 && old_meta.chunk_size == cs) ? old_meta.segment_size : DefaultSegmentSize(cs);
    const uint64_t chunks_per_segment = seg_size / cs;
    const uint64_t size = contents.size();
    const uint64_t count = std::max<uint64_t>(1, (size + seg_size - 1) / seg_size);
    const uint64_t version = old_meta.version + 1;

    // Which segments need writing?
    const bool same_layout = old_meta.segment_size == seg_size && old_meta.chunk_size == cs;
    std::vector<bool> dirty(count, !same_layout);
    for (uint64_t i = 0; i < count; ++i) {
        if (i >= old_meta.segments.size()) dirty[i] = true;
    }
    for (uint64_t chunk : contents.touched_chunks()) {
        if (chunk / chunks_per_segment < count) dirty[chunk / chunks_per_segment] = true;
    }
    if (size != contents.base_size()) {
        // Every segment from the one holding the shorter end onwards changes length.
        for (uint64_t i = std::min(size, contents.base_size()) / seg_size; i < count; ++i) dirty[i] = true;
    }

    FileMetadata meta = old_meta;
    meta.segment_size = static_cast<uint32_t>(seg_size);
    meta.chunk_size = static_cast<uint32_t>(cs);
    meta.segments.assign(count, version);
    for (uint64_t i = 0; i < count; ++i) {
        if (!dirty[i]) meta.segments[i] = old_meta.segments[i];
    }
    meta.version = version;
    meta.size = size;
    meta.mtime = file.mtime.load();

    // Write the changed segments as new objects.
    std::vector<std::string> written;
    std::vector<uint8_t> chunk;
    const std::vector<uint8_t> zeros(g_ctx->pad ? cs : 1);  // padding source (never null)
    auto abandon = [&](const std::string& what) {
        int err = errno ? errno : EIO;
        for (const auto& id : written) ::unlink(BlobPath(id).c_str());
        Log("'" + file.name + "': " + what + ": " + std::strerror(err));
        return -err;
    };
    for (uint64_t i = 0; i < count; ++i) {
        if (!dirty[i]) continue;
        const std::string object = SegmentObjectId(file.remote_id, i, version);
        const uint64_t start = i * seg_size;
        const uint64_t length = size > start ? std::min(seg_size, size - start) : 0;
        const uint64_t stored = (g_ctx->pad && i + 1 == count) ? PaddedLength(length, seg_size) : length;
        const uint64_t n_chunks = std::max<uint64_t>(1, (stored + cs - 1) / cs);

        AtomicFile out(BlobPath(object), 0600);
        if (!out.Open()) return abandon("cannot create segment");
        auto writer = g_ctx->codec->NewSegmentWriter(
            [&out](const uint8_t* d, size_t n) { return out.Write(d, n); }, file.remote_id, i, version, cs);
        bool ok = true;
        for (uint64_t k = 0; k < n_chunks && ok; ++k) {
            const uint64_t offset = k * cs;
            const size_t len = static_cast<size_t>(std::min<uint64_t>(cs, stored - std::min(stored, offset)));
            const uint8_t* data = zeros.data();  // padding
            if (offset < length) {
                // A base chunk that fails authentication stops the save:
                // tampered data is never re-sealed as genuine.
                ok = contents.LoadChunk(i * chunks_per_segment + k, chunk);
                data = chunk.data();
            }
            ok = ok && writer->Add(data, len, k + 1 == n_chunks);
        }
        SecureWipe(chunk);
        if (!ok || !writer->finished() || !out.Commit()) return abandon("cannot write segment " + object);
        written.push_back(object);
    }

    // Commit: one index save switches the file to the new segments.
    g_ctx->index->UpdateInode(meta);
    if (int rc = SaveIndex()) {
        g_ctx->index->UpdateInode(old_meta);
        for (const auto& id : written) ::unlink(BlobPath(id).c_str());
        return rc;
    }

    // Read from the new layout from now on.
    contents.Rebase(std::make_unique<SegmentedReader>(meta, cs, SegmentOpener(meta)));
    file.dirty = false;
    Publish(file);

    for (const auto& id : written) g_ctx->cloud->QueueUpload(BlobPath(id));
    const std::vector<std::string> now_ids = ObjectIds(meta);
    for (const auto& id : ObjectIds(old_meta)) {
        if (std::find(now_ids.begin(), now_ids.end(), id) != now_ids.end()) continue;
        Unsync(id);
        ::unlink(BlobPath(id).c_str());
        g_ctx->cloud->QueueDelete(id);  // runs only after the new index is uploaded
    }
    g_ctx->cache_check_pending = true;
    return 0;
}

// Unlink a path. If it was the inode's last link, the blob goes too (locally
// now, in the cloud in the background); open handles keep their view.
// Caller holds the namespace lock.
void RemovePath(const std::string& name) {
    FileMetadata removed;
    if (!g_ctx->index->Remove(name, &removed)) {
        SaveIndex();  // just one of several links: the inode lives on
        return;
    }
    if (removed.IsFile()) {
        auto open = g_ctx->open_files.find(removed.remote_id);
        if (open != g_ctx->open_files.end()) {
            // Taking the file lock waits out a save in progress, so it can't
            // write the file back after we've removed it.
            std::lock_guard<std::mutex> file_lock(open->second->mu);
            open->second->deleted = true;
            g_ctx->open_files.erase(open);
        }
    }
    SaveIndex();
    for (const auto& id : ObjectIds(removed)) {
        Unsync(id);
        ::unlink(BlobPath(id).c_str());
        g_ctx->cloud->QueueDelete(id);
    }
}

Handle* FindHandle(struct fuse_file_info* fi) {
    if (!fi) return nullptr;
    auto it = g_ctx->handles.find(fi->fh);
    return it == g_ctx->handles.end() ? nullptr : &it->second;
}

// st_ino for an inode: the first 64 bits of its (random or HMAC) ID. 1 is
// the root's.
ino_t InodeNumber(const std::string& remote_id) {
    uint64_t n = 0;
    for (size_t i = 0; i < 16 && i < remote_id.size(); ++i) {
        char c = remote_id[i];
        n = (n << 4) | static_cast<uint64_t>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    return static_cast<ino_t>(n <= 1 ? n + 2 : n);
}

int64_t Now() {
    return static_cast<int64_t>(std::time(nullptr));
}

// Save the index locally and queue its upload, so the cloud copy is enough to
// restore the filesystem (with the key) on another machine.
int SaveIndex() {
    // Serialises with the first-save cloud check below, so no other save can
    // queue an index upload before that check has finished.
    std::lock_guard<std::mutex> guard(g_ctx->guard_mutex);
    if (g_ctx->read_only) return -EROFS;
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

// ── Local cache limit ───────────────────────────────────────────────────────
// With --cache-size, the backing directory is a cache: blobs the cloud is
// known to hold at their current version can be deleted locally and are
// downloaded again on demand. A blob is only ever evicted if
//   * synced[id] equals the file's version in the index (the cloud has
//     exactly this version — not an older one),
//   * nothing is queued, in flight or journaled for it, and
//   * the file isn't open.
// Least recently used blobs go first.

std::string SyncedPath() { return g_ctx->backing_dir + "/synced.list"; }

void LoadSynced() {
    std::lock_guard<std::mutex> lock(g_ctx->synced_mutex);
    std::vector<uint8_t> data;
    if (!ReadWholeFile(SyncedPath(), data)) return;
    std::string text(data.begin(), data.end());
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = nl == std::string::npos ? text.size() : nl + 1;
        auto sp = line.rfind(' ');
        if (sp != std::string::npos && sp >= 64) {
            g_ctx->synced[line.substr(0, sp)] = std::strtoull(line.c_str() + sp + 1, nullptr, 10);
        }
    }
}

void SaveSynced() {
    std::lock_guard<std::mutex> lock(g_ctx->synced_mutex);
    if (!g_ctx->synced_dirty || g_ctx->cache_limit == 0) return;
    std::string text;
    for (const auto& [id, version] : g_ctx->synced) text += id + " " + std::to_string(version) + "\n";
    if (WriteFileAtomic(SyncedPath(), reinterpret_cast<const uint8_t*>(text.data()), text.size())) {
        g_ctx->synced_dirty = false;
    }
}

void MarkSynced(const std::string& id, uint64_t version) {
    std::lock_guard<std::mutex> lock(g_ctx->synced_mutex);
    auto it = g_ctx->synced.find(id);
    if (it != g_ctx->synced.end() && it->second == version) return;
    g_ctx->synced[id] = version;
    g_ctx->synced_dirty = true;
}

void Unsync(const std::string& id) {
    std::lock_guard<std::mutex> lock(g_ctx->synced_mutex);
    if (g_ctx->synced.erase(id)) g_ctx->synced_dirty = true;
}

// Record a use of a blob for LRU ordering (explicitly, so noatime mounts work).
void TouchBlob(const std::string& path) {
    struct timespec times[2];
    times[0].tv_sec = 0;
    times[0].tv_nsec = UTIME_NOW;
    times[1].tv_sec = 0;
    times[1].tv_nsec = UTIME_OMIT;
    ::utimensat(AT_FDCWD, path.c_str(), times, 0);
}

// The version the index currently expects of stored object `id` (segment
// objects carry it in their name). False if the index no longer refers to it.
bool CurrentObjectVersion(const std::string& id, uint64_t* version) {
    if (!IndexReferencesObject(*g_ctx->index, id)) return false;
    std::string inode;
    uint64_t seg = 0;
    if (ParseSegmentObjectId(id, &inode, &seg, version)) return true;
    FileMetadata meta;
    if (!g_ctx->index->GetInode(id, meta)) return false;
    *version = meta.version;  // legacy whole-file blob
    return true;
}

std::string InodeOfObject(const std::string& id) { return id.substr(0, 64); }

bool SyncedVersion(const std::string& id, uint64_t* version) {
    std::lock_guard<std::mutex> lock(g_ctx->synced_mutex);
    auto it = g_ctx->synced.find(id);
    if (it == g_ctx->synced.end()) return false;
    *version = it->second;
    return true;
}

// Caller holds the namespace lock.
void EnforceCacheLimit() {
    if (g_ctx->cache_limit == 0) return;
    g_ctx->cache_check_pending = false;

    struct Blob { std::string id; uint64_t bytes; struct timespec used; };
    std::vector<Blob> blobs;
    uint64_t total = 0;
    if (DIR* d = ::opendir(g_ctx->backing_dir.c_str())) {
        while (struct dirent* e = ::readdir(d)) {
            std::string id;
            if (!IsObjectFileName(e->d_name, &id)) continue;
            struct stat st;
            if (::stat(BlobPath(id).c_str(), &st) != 0) continue;
            total += static_cast<uint64_t>(st.st_size);
            blobs.push_back({id, static_cast<uint64_t>(st.st_size), st.st_atim});
        }
        ::closedir(d);
    }
    if (total <= g_ctx->cache_limit) return;

    std::unordered_set<std::string> open_ids;
    for (const auto& [name, file] : g_ctx->open_files) open_ids.insert(file->remote_id);

    std::sort(blobs.begin(), blobs.end(), [](const Blob& a, const Blob& b) {
        return a.used.tv_sec != b.used.tv_sec ? a.used.tv_sec < b.used.tv_sec
                                              : a.used.tv_nsec < b.used.tv_nsec;
    });
    for (const auto& blob : blobs) {
        if (total <= g_ctx->cache_limit) break;
        uint64_t synced_version = 0, current = 0;
        if (!SyncedVersion(blob.id, &synced_version) || open_ids.count(InodeOfObject(blob.id)) ||
            !CurrentObjectVersion(blob.id, &current) || current != synced_version ||
            g_ctx->cloud->IsPending(blob.id)) {
            continue;  // not provably safe in the cloud
        }
        if (::unlink(BlobPath(blob.id).c_str()) == 0) total -= blob.bytes;
    }
    SaveSynced();
}

// For code that just released a file lock: enforce the cache limit if
// something asked for it while the namespace lock couldn't be taken.
void MaybeEnforceCacheLimit() {
    if (g_ctx->cache_limit == 0 || !g_ctx->cache_check_pending) return;
    std::lock_guard<std::mutex> lock(g_ctx->mutex);
    EnforceCacheLimit();
}

// Called by the sync worker after an upload finishes.
void OnUploaded(const std::string& id) {
    if (id == kCloudIndexId) {
        g_ctx->synced_gen = g_ctx->uploading_gen.load();
        g_ctx->synced_gen_known = true;
        SaveSyncedGeneration(g_ctx->backing_dir, g_ctx->synced_gen);
        return;
    }
    if (id == kCloudKdfId) {
        ::unlink((g_ctx->backing_dir + "/encfs.kdf.pending").c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(g_ctx->mutex);
    uint64_t version = 0;
    if (!CurrentObjectVersion(id, &version)) return;
    // If another save is already queued, the cloud may still lag behind.
    if (g_ctx->cloud->IsPending(id)) return;
    MarkSynced(id, version);
    EnforceCacheLimit();
    SaveSynced();
}

// Runs on the sync worker before each upload. For the index: snapshot it,
// and check that the cloud copy is still the one we last synced with. If
// another machine has uploaded since, stop: overwriting would lose its work.
CloudCLIWrapper::PreUpload BeforeUpload(const std::string& id, std::string& path) {
    using P = CloudCLIWrapper::PreUpload;
    if (id != kCloudIndexId) return P::kProceed;

    const std::string dir = g_ctx->backing_dir + "/.upload";
    ::mkdir(dir.c_str(), 0700);
    std::vector<uint8_t> bytes;
    uint64_t snapshot_gen = 0;
    if (!ReadWholeFile(g_ctx->index->path(), bytes) || !WriteFileAtomic(dir + "/index.enc", bytes) ||
        !IndexFileGeneration(dir, g_ctx->master_key, &snapshot_gen)) {
        return P::kRetry;
    }

    if (!g_ctx->force_index_upload.exchange(false)) {
        uint64_t cloud_gen = 0;
        bool conflict = false;
        switch (FetchCloudIndex(*g_ctx->cloud, g_ctx->master_key, g_ctx->backing_dir, &cloud_gen)) {
        case CloudIndexStatus::kUnavailable:
            // Nothing there yet (new store) — or unreachable, in which case
            // the upload fails too and is retried.
            if (g_ctx->synced_gen_known && g_ctx->synced_gen == 0) break;
            return P::kRetry;
        case CloudIndexStatus::kUnreadable:
            conflict = true;
            break;
        case CloudIndexStatus::kFound:
            if (!g_ctx->synced_gen_known && cloud_gen <= snapshot_gen) {
                g_ctx->synced_gen = cloud_gen;  // pre-3.1 store: learn the base now
                g_ctx->synced_gen_known = true;
            }
            conflict = !g_ctx->synced_gen_known || cloud_gen != g_ctx->synced_gen;
            break;
        }
        if (conflict) {
            g_ctx->read_only = true;
            Log("the cloud index was changed by another machine while this one was mounted. "
                "Not uploading (that would overwrite its changes); writes are now disabled. "
                "Unmount and mount again with --prefer-cloud or --prefer-local to resolve.");
            return P::kAbort;
        }
    }
    g_ctx->uploading_gen = snapshot_gen;
    path = dir + "/index.enc";
    return P::kProceed;
}

enum class Prefer { kNone, kCloud, kLocal };

bool JournalHasWork(const std::string& backing_dir) {
    struct stat st;
    return ::stat((backing_dir + "/sync.journal").c_str(), &st) == 0 && st.st_size > 0;
}

// At mount, before anything is queued: bring the local index in line with the
// cloud's (see index_sync.h). Returns 0, or an exit status to refuse the mount.
int ReconcileIndexAtMount(Context& ctx, bool restored, bool fresh, Prefer prefer) {
    const std::string& dir = ctx.backing_dir;
    const uint64_t local = ctx.index->generation();
    if (fresh) {
        ctx.synced_gen = 0;  // the first save re-checks the cloud (index guard)
        return 0;
    }
    if (restored) {
        ctx.synced_gen = local;
        SaveSyncedGeneration(dir, local);
        return 0;
    }

    uint64_t base = 0;
    bool have_base = LoadSyncedGeneration(dir, &base);
    uint64_t cloud = 0;
    const CloudIndexStatus status = FetchCloudIndex(*ctx.cloud, ctx.master_key, dir, &cloud);
    const char* how = "\n  --prefer-cloud  use the cloud's index, discarding this machine's unsynced changes"
                      "\n  --prefer-local  keep this machine's index and overwrite the cloud's\n";

    if (status == CloudIndexStatus::kUnavailable) {
        std::cerr << "[encfs] can't reach the cloud index; using the local copy (it is checked "
                     "against the cloud again before anything is uploaded)\n";
        ctx.synced_gen = base;
        ctx.synced_gen_known = have_base;
        return 0;
    }
    if (status == CloudIndexStatus::kUnreadable) {
        if (prefer != Prefer::kLocal) {
            std::cerr << "Error: the cloud's index can't be decrypted with this key (it was "
                         "replaced, or is corrupt). Mount with --prefer-local to overwrite it "
                         "with this machine's copy.\n";
            return 1;
        }
        ctx.force_index_upload = true;
        ctx.cloud->QueueUpload(ctx.index->path());
        return 0;
    }

    if (!have_base) {
        if (cloud <= local) {
            base = cloud;  // a store from before multi-machine tracking:
            have_base = true;  // single-machine history, the cloud just lags
        } else if (prefer == Prefer::kNone) {
            std::cerr << "Error: the cloud's index (generation " << cloud << ") is newer than this "
                      << "machine's (" << local << "), and this backing directory predates change "
                      << "tracking, so it can't tell whose changes are whose. Choose:" << how;
            return 1;
        }
    }

    const bool local_dirty = local != base || JournalHasWork(dir);
    auto adopt = [&]() -> int {
        if (local_dirty) {
            std::cerr << "[encfs] discarding this machine's unsynced changes (--prefer-cloud)\n";
            ::unlink((dir + "/sync.journal").c_str());
        }
        int dropped = AdoptFetchedCloudIndex(dir, *ctx.index, *ctx.codec);
        if (dropped < 0) {
            std::cerr << "Error: could not adopt the cloud's index\n";
            return 1;
        }
        std::cerr << "[encfs] took the newer index from the cloud (generation " << cloud << ")";
        if (dropped) std::cerr << "; " << dropped << " outdated local blob(s) will be re-downloaded";
        std::cerr << "\n";
        ctx.synced_gen = cloud;
        SaveSyncedGeneration(dir, cloud);
        return 0;
    };
    auto keep_local = [&]() -> bool {
        // The copy we upload must be newer than anything the cloud has seen,
        // or other machines would take it for a rollback. Save bumps it.
        ctx.index->set_generation(std::max(local, cloud));
        if (!ctx.index->Save()) return false;
        ctx.synced_gen = cloud;
        SaveSyncedGeneration(dir, cloud);
        ctx.cloud->QueueUpload(ctx.index->path());
        std::cerr << "[encfs] keeping this machine's index; it will replace the cloud's (--prefer-local)\n";
        return true;
    };

    if (cloud == base && have_base) {
        ctx.synced_gen = base;
        return 0;
    }
    if (cloud > base || !have_base) {
        if (!local_dirty || prefer == Prefer::kCloud) return adopt();
        if (prefer == Prefer::kLocal) return keep_local() ? 0 : 1;
        std::cerr << "Error: conflict. Another machine changed the store (cloud generation " << cloud
                  << ") and this machine also has unsynced changes (generation " << local
                  << ", last synced " << base << "). Choose:" << how;
        return 1;
    }
    // cloud < base: the cloud's index went backwards.
    if (prefer == Prefer::kCloud) return adopt();
    if (prefer == Prefer::kLocal) return keep_local() ? 0 : 1;
    std::cerr << "Error: the cloud's index (generation " << cloud << ") is older than the one this "
              << "machine last synced (" << base << "): it may have been rolled back or replaced "
              << "with an old copy. Choose:" << how;
    return 1;
}

// At mount: upload any local blob the cloud isn't known to have at its
// current version (e.g. an upload lost in a crash), and forget stale records.
void ReconcileWithCloud() {
    std::unordered_set<std::string> live;
    for (const FileMetadata& meta : g_ctx->index->AllInodes()) {
        for (const auto& id : ObjectIds(meta)) {
            live.insert(id);
            uint64_t synced_version = 0, current = 0;
            const std::string path = BlobPath(id);
            struct stat st;
            if (CurrentObjectVersion(id, &current) &&
                (!SyncedVersion(id, &synced_version) || synced_version != current) &&
                ::stat(path.c_str(), &st) == 0 && !g_ctx->cloud->IsPending(id)) {
                g_ctx->cloud->QueueUpload(path);
            }
        }
    }
    std::lock_guard<std::mutex> lock(g_ctx->synced_mutex);
    for (auto it = g_ctx->synced.begin(); it != g_ctx->synced.end();) {
        if (!live.count(it->first)) {
            it = g_ctx->synced.erase(it);
            g_ctx->synced_dirty = true;
        } else {
            ++it;
        }
    }
}

// At mount: remove what a crash can leave behind in the backing directory:
// temp files, and objects the index no longer refers to (e.g. segments
// written by a save that never committed). Never touches referenced objects.
void CleanBackingDir() {
    std::vector<std::string> doomed;
    if (DIR* d = ::opendir(g_ctx->backing_dir.c_str())) {
        while (struct dirent* e = ::readdir(d)) {
            const std::string n = e->d_name;
            std::string id;
            if (IsObjectFileName(n, &id)) {
                if (!IndexReferencesObject(*g_ctx->index, id)) doomed.push_back(n);
            } else if (n.find(".enc.tmp.") != std::string::npos ||
                       (n.size() > 9 && n.compare(n.size() - 9, 9, ".download") == 0)) {
                doomed.push_back(n);
            }
        }
        ::closedir(d);
    }
    for (const auto& n : doomed) ::unlink((g_ctx->backing_dir + "/" + n).c_str());
    if (!doomed.empty()) Log("removed " + std::to_string(doomed.size()) + " leftover file(s) from the backing directory");
}

uint64_t ParseSize(const std::string& text) {
    char* end = nullptr;
    double value = std::strtod(text.c_str(), &end);
    if (end == text.c_str() || value < 0) return UINT64_MAX;
    std::string unit(end);
    for (auto& c : unit) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (!unit.empty() && unit.back() == 'B') unit.pop_back();
    if (!unit.empty() && unit.back() == 'I') unit.pop_back();  // "GiB" etc.
    double mult = 1;
    if (unit == "K") mult = 1024.0;
    else if (unit == "M") mult = 1024.0 * 1024;
    else if (unit == "G") mult = 1024.0 * 1024 * 1024;
    else if (unit == "T") mult = 1024.0 * 1024 * 1024 * 1024;
    else if (!unit.empty()) return UINT64_MAX;
    return static_cast<uint64_t>(value * mult);
}

// ── FUSE operations ─────────────────────────────────────────────────────────

void* encfs_init(struct fuse_conn_info* conn, struct fuse_config* cfg) {
    (void)conn;
    // Report our own inode numbers (from the inode ID), so hard links share
    // st_ino and tools like `cp -a`, `rsync -H` and `tar` recognise them.
    cfg->use_ino = 1;
    // The high-level API gives every *path* its own kernel node, so the
    // kernel can't know two names are one file. Don't let it cache attributes,
    // or a write or link through one name would leave another's size and link
    // count stale. getattr is an in-memory lookup, so this is cheap.
    cfg->attr_timeout = 0;
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
            std::lock_guard<std::mutex> file_lock(file->mu);
            Persist(*file);
        }
    }
    size_t pending = g_ctx->cloud->PendingCount();
    if (pending > 0) {
        Log("finishing " + std::to_string(pending) + " pending cloud operation(s)...");
    }
    g_ctx->cloud->StopBackgroundUploader();  // drains the queue
    std::lock_guard<std::mutex> lock(g_ctx->mutex);
    EnforceCacheLimit();
    SaveSynced();
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
            st->st_ino = 1;
            st->st_mtime = st->st_ctime = st->st_atime = g_ctx->mount_time;
            return 0;
        }

        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;

        st->st_ino = InodeNumber(meta.remote_id);
        st->st_mtime = st->st_ctime = st->st_atime = static_cast<time_t>(meta.mtime);
        if (meta.IsDirectory()) {
            st->st_mode = S_IFDIR | meta.mode;
            st->st_nlink = 2;
            return 0;
        }
        if (meta.IsSymlink()) {
            st->st_mode = S_IFLNK | 0777;
            st->st_nlink = 1;
            st->st_size = static_cast<off_t>(meta.target.size());
            return 0;
        }

        uint64_t size = meta.size;
        int64_t mtime = meta.mtime;
        auto it = g_ctx->open_files.find(meta.remote_id);
        if (it != g_ctx->open_files.end() && it->second->loaded) {
            size = it->second->size_hint;  // reflect unsaved writes
            mtime = it->second->mtime;
        }

        st->st_mode = S_IFREG | meta.mode;
        st->st_nlink = meta.nlink;
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
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        std::string dir;
        if (std::strcmp(path, "/") != 0) {
            if (int rc = NameFromPath(path, dir)) return rc;
            FileMetadata meta;
            if (!g_ctx->index->GetMetadata(dir, meta)) return -ENOENT;
            if (!meta.IsDirectory()) return -ENOTDIR;
        }
        filler(buf, ".", nullptr, 0, fuse_fill_dir_flags(0));
        filler(buf, "..", nullptr, 0, fuse_fill_dir_flags(0));
        for (const auto& child : g_ctx->index->ListDirectory(dir)) {
            filler(buf, child.c_str(), nullptr, 0, fuse_fill_dir_flags(0));
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

// Handle lookup under the namespace lock; the returned shared_ptr keeps the
// file alive after the lock is dropped.
std::shared_ptr<OpenFile> HandleFile(struct fuse_file_info* fi, bool* writable = nullptr) {
    std::lock_guard<std::mutex> lock(g_ctx->mutex);
    Handle* h = FindHandle(fi);
    if (!h) return nullptr;
    if (writable) *writable = h->writable;
    return h->file;
}

int encfs_open(const char* path, struct fuse_file_info* fi) {
    return Guarded("open", [&]() -> int {
        const bool writable = (fi->flags & O_ACCMODE) != O_RDONLY;
        std::shared_ptr<OpenFile> file;
        {
            std::lock_guard<std::mutex> lock(g_ctx->mutex);
            std::string name;
            if (int rc = NameFromPath(path, name)) return rc;
            FileMetadata meta;
            if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;
            if (meta.IsDirectory()) return -EISDIR;
            if (meta.IsSymlink()) return -ELOOP;
            if (writable && g_ctx->read_only) return -EROFS;
            file = Acquire(name, meta);
        }

        int rc = 0;
        {
            // Only this file is locked while its blob is downloaded/verified.
            std::lock_guard<std::mutex> file_lock(file->mu);
            if (writable && (fi->flags & O_TRUNC)) {
                ResetContents(*file);
                file->dirty = true;
                file->mtime = Now();
            } else {
                rc = OpenContents(*file);
            }
        }

        {
            std::lock_guard<std::mutex> lock(g_ctx->mutex);
            if (rc != 0) {
                ReleaseRef(file);
            } else {
                RegisterHandle(std::move(file), writable, fi);
            }
        }
        MaybeEnforceCacheLimit();
        return rc;
    });
}

int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    return Guarded("create", [&]() -> int {
        // Namespace change: hold the namespace lock throughout.
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        if (int rc = CheckParent(name)) return rc;

        FileMetadata meta;
        const bool existed = g_ctx->index->GetMetadata(name, meta);
        if (existed && (fi->flags & O_EXCL)) return -EEXIST;
        if (existed && meta.IsDirectory()) return -EISDIR;
        if (existed && meta.IsSymlink()) return -ELOOP;
        if (!existed) {
            meta = FileMetadata();
            meta.remote_id = NewInodeId();  // random: unrelated to the path
            meta.mode = mode & 07777;
            meta.mtime = Now();
            g_ctx->index->SetMetadata(name, meta);
            if (int rc = SaveIndex()) {
                g_ctx->index->Remove(name);
                return rc;
            }
        }

        auto file = Acquire(name, meta);
        int rc = 0;
        {
            std::lock_guard<std::mutex> file_lock(file->mu);
            if (!existed || (fi->flags & O_TRUNC)) {
                ResetContents(*file);
                file->dirty = true;  // ensure even an empty file gets a blob
                file->mtime = Now();
            } else {
                rc = OpenContents(*file);
            }
        }
        if (rc != 0) {
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
        if (offset < 0) return -EINVAL;
        auto file = HandleFile(fi);
        if (!file) return -EBADF;

        int64_t n;
        {
            std::lock_guard<std::mutex> file_lock(file->mu);
            if (int rc = OpenContents(*file)) return rc;
            n = file->contents->Read(static_cast<uint64_t>(offset),
                                     reinterpret_cast<uint8_t*>(buf),
                                     std::min<size_t>(size, INT_MAX));
        }
        if (n < 0) {
            Log("'" + file->name + "': chunk failed authentication");
            return -EIO;
        }
        MaybeEnforceCacheLimit();
        return static_cast<int>(n);
    });
}

int encfs_write(const char* path, const char* buf, size_t size, off_t offset,
                struct fuse_file_info* fi) {
    (void)path;
    return Guarded("write", [&]() -> int {
        if (offset < 0 || size > INT_MAX) return -EINVAL;
        bool writable = false;
        auto file = HandleFile(fi, &writable);
        if (!file || !writable) return -EBADF;

        std::lock_guard<std::mutex> file_lock(file->mu);
        if (int rc = OpenContents(*file)) return rc;
        const uint64_t off = static_cast<uint64_t>(offset);
        if (off > file->contents->max_size() || size > file->contents->max_size() - off) return -EFBIG;
        if (!file->contents->Write(off, reinterpret_cast<const uint8_t*>(buf), size)) {
            Log("'" + file->name + "': write failed (scratch space or authentication)");
            return -EIO;
        }
        file->dirty = true;
        file->mtime = Now();
        Publish(*file);
        return static_cast<int>(size);
    });
}

int encfs_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
    return Guarded("truncate", [&]() -> int {
        if (g_ctx->read_only) return -EROFS;
        if (size < 0) return -EINVAL;

        std::shared_ptr<OpenFile> file;
        bool temporary = false;
        {
            std::lock_guard<std::mutex> lock(g_ctx->mutex);
            if (Handle* h = FindHandle(fi)) {
                if (!h->writable) return -EBADF;
                file = h->file;
            } else {
                std::string name;
                if (int rc = NameFromPath(path, name)) return rc;
                FileMetadata meta;
                if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;
                if (meta.IsDirectory()) return -EISDIR;
                if (!meta.IsFile()) return -EINVAL;
                file = Acquire(name, meta);
                temporary = true;
            }
        }

        int rc = 0;
        {
            std::lock_guard<std::mutex> file_lock(file->mu);
            if (size == 0) {
                ResetContents(*file);  // no need to read what we're discarding
            } else {
                rc = OpenContents(*file);
            }
            if (rc == 0) {
                if (static_cast<uint64_t>(size) > file->contents->max_size()) {
                    rc = -EFBIG;
                } else if (!file->contents->Truncate(static_cast<uint64_t>(size))) {
                    rc = -EIO;
                } else {
                    file->dirty = true;
                    file->mtime = Now();
                    Publish(*file);
                    // Path-based truncate has no close() to piggy-back on: save now.
                    if (temporary) rc = Persist(*file);
                }
            }
        }
        if (temporary) {
            std::lock_guard<std::mutex> lock(g_ctx->mutex);
            ReleaseRef(file);
        }
        MaybeEnforceCacheLimit();
        return rc;
    });
}

int encfs_flush(const char* path, struct fuse_file_info* fi) {
    (void)path;
    return Guarded("flush", [&]() -> int {
        auto file = HandleFile(fi);
        if (!file) return -EBADF;
        int rc;
        {
            // Saving on flush means close() reports write errors to the caller.
            std::lock_guard<std::mutex> file_lock(file->mu);
            rc = Persist(*file);
        }
        MaybeEnforceCacheLimit();
        return rc;
    });
}

int encfs_fsync(const char* path, int datasync, struct fuse_file_info* fi) {
    (void)datasync;
    return encfs_flush(path, fi);
}

int encfs_release(const char* path, struct fuse_file_info* fi) {
    (void)path;
    return Guarded("release", [&]() -> int {
        std::shared_ptr<OpenFile> file;
        {
            std::lock_guard<std::mutex> lock(g_ctx->mutex);
            auto it = g_ctx->handles.find(fi->fh);
            if (it == g_ctx->handles.end()) return 0;
            file = std::move(it->second.file);
            g_ctx->handles.erase(it);
        }
        {
            std::lock_guard<std::mutex> file_lock(file->mu);
            if (int rc = Persist(*file)) {
                Log("'" + file->name + "': changes could not be saved (" +
                    std::strerror(-rc) + ")");
            }
        }
        {
            std::lock_guard<std::mutex> lock(g_ctx->mutex);
            ReleaseRef(file);
        }
        MaybeEnforceCacheLimit();
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
        if (meta.IsDirectory()) return -EISDIR;
        RemovePath(name);
        return 0;
    });
}

int encfs_mkdir(const char* path, mode_t mode) {
    return Guarded("mkdir", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        if (int rc = CheckParent(name)) return rc;
        if (g_ctx->index->Exists(name)) return -EEXIST;

        FileMetadata meta;
        meta.remote_id = NewInodeId();
        meta.type = EntryType::kDirectory;
        meta.mode = mode & 07777;
        meta.mtime = Now();
        g_ctx->index->SetMetadata(name, meta);
        if (int rc = SaveIndex()) {
            g_ctx->index->Remove(name);
            return rc;
        }
        return 0;
    });
}

int encfs_rmdir(const char* path) {
    return Guarded("rmdir", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;
        if (!meta.IsDirectory()) return -ENOTDIR;
        if (g_ctx->index->HasChildren(name)) return -ENOTEMPTY;
        g_ctx->index->Remove(name);
        return SaveIndex();
    });
}

// Renames only edit the index: inode IDs are random and unrelated to paths,
// so no data moves, a directory of any size moves in one step, and the
// change is atomic (one index save). Open files are keyed by inode, so they
// are unaffected.
int encfs_rename(const char* from, const char* to, unsigned int flags) {
    return Guarded("rename", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        if ((flags & RENAME_EXCHANGE) && (flags & RENAME_NOREPLACE)) return -EINVAL;

        std::string src, dst;
        if (int rc = NameFromPath(from, src)) return rc;
        if (int rc = NameFromPath(to, dst)) return rc;

        FileMetadata src_meta, dst_meta;
        if (!g_ctx->index->GetMetadata(src, src_meta)) return -ENOENT;
        if (int rc = CheckParent(dst)) return rc;
        if (dst.compare(0, src.size() + 1, src + "/") == 0) return -EINVAL;  // into itself
        const bool dst_exists = g_ctx->index->GetMetadata(dst, dst_meta);

        if (flags & RENAME_EXCHANGE) {
            if (!dst_exists) return -ENOENT;
            if (src.compare(0, dst.size() + 1, dst + "/") == 0) return -EINVAL;
            if (src == dst) return 0;
            // Swap through a name no real path can have.
            const std::string tmp = src + std::string(1, '\x01') + "exchange";
            if (!g_ctx->index->Rename(src, tmp) || !g_ctx->index->Rename(dst, src) ||
                !g_ctx->index->Rename(tmp, dst)) {
                return -EIO;
            }
            return SaveIndex();
        }

        if (src == dst) return 0;
        if (dst_exists) {
            if (flags & RENAME_NOREPLACE) return -EEXIST;
            if (dst_meta.remote_id == src_meta.remote_id) return 0;  // hard links to one inode
            if (src_meta.IsDirectory()) {
                if (!dst_meta.IsDirectory()) return -ENOTDIR;
                if (g_ctx->index->HasChildren(dst)) return -ENOTEMPTY;
                g_ctx->index->Remove(dst);
            } else {
                if (dst_meta.IsDirectory()) return -EISDIR;
                RemovePath(dst);
            }
        }
        if (!g_ctx->index->Rename(src, dst)) return -EIO;
        int rc = SaveIndex();
        EnforceCacheLimit();
        return rc;
    });
}

int encfs_link(const char* from, const char* to) {
    return Guarded("link", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string src, dst;
        if (int rc = NameFromPath(from, src)) return rc;
        if (int rc = NameFromPath(to, dst)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(src, meta)) return -ENOENT;
        if (!meta.IsFile()) return -EPERM;  // no hard links to directories or symlinks
        if (int rc = CheckParent(dst)) return rc;
        if (g_ctx->index->Exists(dst)) return -EEXIST;
        if (!g_ctx->index->Link(src, dst)) return -EIO;
        return SaveIndex();
    });
}

int encfs_symlink(const char* target, const char* link_path) {
    return Guarded("symlink", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string name;
        if (int rc = NameFromPath(link_path, name)) return rc;
        if (int rc = CheckParent(name)) return rc;
        if (g_ctx->index->Exists(name)) return -EEXIST;
        if (std::strlen(target) >= PATH_MAX) return -ENAMETOOLONG;
        FileMetadata meta;
        meta.remote_id = NewInodeId();
        meta.type = EntryType::kSymlink;
        meta.mode = 0777;
        meta.target = target;
        meta.size = meta.target.size();
        meta.mtime = Now();
        g_ctx->index->SetMetadata(name, meta);
        if (int rc = SaveIndex()) {
            g_ctx->index->Remove(name);
            return rc;
        }
        return 0;
    });
}

int encfs_readlink(const char* path, char* buf, size_t size) {
    return Guarded("readlink", [&]() -> int {
        if (size == 0) return -EINVAL;
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;
        if (!meta.IsSymlink()) return -EINVAL;
        size_t n = std::min(size - 1, meta.target.size());  // FUSE wants it NUL-terminated
        std::memcpy(buf, meta.target.data(), n);
        buf[n] = '\0';
        return 0;
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

        g_ctx->index->UpdateInode(meta);
        auto it = g_ctx->open_files.find(meta.remote_id);
        if (it != g_ctx->open_files.end()) it->second->mtime = meta.mtime;
        return SaveIndex();
    });
}

// Permission bits are stored per inode (and enforced by the kernel via
// default_permissions). Ownership isn't: everything belongs to the mounting
// user.
int encfs_chmod(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void)fi;
    return Guarded("chmod", [&]() -> int {
        if (std::strcmp(path, "/") == 0) return 0;
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (g_ctx->read_only) return -EROFS;
        std::string name;
        if (int rc = NameFromPath(path, name)) return rc;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(name, meta)) return -ENOENT;
        if (meta.IsSymlink()) return 0;
        meta.mode = mode & 07777;
        g_ctx->index->UpdateInode(meta);
        return SaveIndex();
    });
}

int encfs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info* fi) {
    (void)fi;
    return Guarded("chown", [&]() -> int {
        std::lock_guard<std::mutex> lock(g_ctx->mutex);
        if (std::strcmp(path, "/") != 0) {
            std::string name;
            if (int rc = NameFromPath(path, name)) return rc;
            if (!g_ctx->index->Exists(name)) return -ENOENT;
        }
        // Ownership isn't stored; accepting (and ignoring) the change keeps
        // tools like `cp -p` and `rsync -a` (even as root) working.
        (void)uid;
        (void)gid;
        return 0;
    });
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
    ops.link = encfs_link;
    ops.symlink = encfs_symlink;
    ops.readlink = encfs_readlink;
    ops.mkdir = encfs_mkdir;
    ops.rmdir = encfs_rmdir;
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
        "      --prefer-cloud  on a conflict with another machine, take the cloud's index\n"
        "      --prefer-local  on a conflict, keep this machine's index and upload it\n"
        "      --pad           pad files so the cloud learns their sizes only to within\n"
        "                      a factor of two (costs up to 2x space for small files)\n"
        "      --cache-size N  keep at most N of encrypted blobs locally (e.g. 500M, 20G);\n"
        "                      older ones the cloud already has are removed and\n"
        "                      downloaded again when needed (default: keep everything)\n"
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
    Prefer prefer = Prefer::kNone;
    bool pad = false;
    uint64_t cache_limit = 0;
    bool debug = false;

    static const struct option long_opts[] = {
        {"key", required_argument, nullptr, 'k'},
        {"passphrase", no_argument, nullptr, 'p'},
        {"cloudcli", required_argument, nullptr, 'c'},
        {"background", no_argument, nullptr, 'b'},
        {"cache-size", required_argument, nullptr, 'S'},
        {"prefer-cloud", no_argument, nullptr, 'C'},
        {"pad", no_argument, nullptr, 'P'},
        {"prefer-local", no_argument, nullptr, 'L'},
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
        case 'C': prefer = Prefer::kCloud; break;
        case 'P': pad = true; break;
        case 'L': prefer = Prefer::kLocal; break;
        case 'S':
            cache_limit = ParseSize(optarg);
            if (cache_limit == UINT64_MAX) {
                std::cerr << "Invalid --cache-size: " << optarg << " (try e.g. 500M or 20G)\n";
                return 2;
            }
            break;
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
    bool restored_index = false;
    if (!LocalFileExists(index_path)) {
        if (FetchFromCloud(bootstrap, kCloudIndexId, index_path)) {
            restored_index = true;
            std::cerr << "[encfs] restored the index from the cloud\n";
        } else {
            fresh_index = true;
            std::cerr << "[encfs] no index found locally or in the cloud: starting a new "
                         "filesystem\n";
        }
    }
    if (key_options.use_passphrase && !LocalFileExists(kdf_path)) {
        FetchFromCloud(bootstrap, kCloudKdfId, kdf_path);
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
    ctx->master_key = master_key;
    SecureWipe(master_key);

    if (!ctx->index->Load()) {
        // ResolveMasterKey already checked the key, so this is real damage.
        std::cerr << "Error: cannot read " << ctx->index->path() << "\n";
        return 1;
    }

    ctx->index_guard_pending = fresh_index;
    ctx->cache_limit = cache_limit;
    ctx->pad = pad;
    if (int rc = ReconcileIndexAtMount(*ctx, restored_index, fresh_index, prefer)) return rc;

    // Passphrase stores: a changed encfs.kdf travels with a ".pending" marker
    // from the machine that changed it. Without one, the cloud's copy wins, so
    // a passphrase changed elsewhere isn't reverted from here.
    const bool kdf_pending = LocalFileExists(kdf_path + ".pending");
    if (key_options.use_passphrase && !kdf_pending && !restored_index) {
        const std::string theirs = kdf_path + ".cloud";
        std::vector<uint8_t> a, b;
        if (FetchFromCloud(bootstrap, kCloudKdfId, theirs) && ReadWholeFile(theirs, a) &&
            ReadWholeFile(kdf_path, b) && a != b && ::rename(theirs.c_str(), kdf_path.c_str()) == 0) {
            std::cerr << "[encfs] the passphrase was changed on another machine; "
                         "use the new one from now on\n";
        }
        ::unlink(theirs.c_str());
    }

    ctx->cloud->SetJournalPath(backing_dir + "/sync.journal");
    if (size_t resumed = ctx->cloud->RecoverJournal()) {
        std::cerr << "[encfs] resuming " << resumed << " unfinished cloud operation(s)\n";
    }
    if (kdf_pending) ctx->cloud->QueueUpload(kdf_path);
    g_ctx = ctx.get();
    CleanBackingDir();
    ctx->cloud->SetPreUploadHook(BeforeUpload);
    ctx->cloud->SetUploadCallback(OnUploaded);
    if (cache_limit > 0) {
        LoadSynced();
        ReconcileWithCloud();
        std::lock_guard<std::mutex> lock(ctx->mutex);
        EnforceCacheLimit();
    }

    std::vector<std::string> fuse_args = {argv[0], mount_point,
                                          "-o", "fsname=encfs-cloudcli,subtype=encfs,default_permissions"};
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

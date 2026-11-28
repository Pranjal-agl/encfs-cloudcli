#include "rekey.h"

#include "cloudcli_wrapper.h"
#include "crypto.h"
#include "file_codec.h"
#include "index.h"
#include "index_sync.h"
#include "segments.h"
#include "util.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <functional>
#include <dirent.h>
#include <iostream>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace encfs {

const char kKeyIdObject[] = "encfs.keyid";

namespace {

const char kKeyIdMagic[] = "ENCFS-KEYID-1 ";

bool Exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

bool ReadText(const std::string& path, std::string* text) {
    std::vector<uint8_t> data;
    if (!ReadWholeFile(path, data)) return false;
    text->assign(data.begin(), data.end());
    return true;
}

bool WriteText(const std::string& path, const std::string& text) {
    return WriteFileAtomic(path, reinterpret_cast<const uint8_t*>(text.data()), text.size(), 0600);
}

bool IsHex(const std::string& s) {
    return std::all_of(s.begin(), s.end(), [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); });
}

// Everything in a backing directory that belongs to one key: the index, the
// data objects, the passphrase file and the sync bookkeeping.
bool BelongsToKey(const std::string& name) {
    static const std::set<std::string> kFiles = {
        "index.enc", "encfs.kdf", "encfs.kdf.pending", "encfs.keyid",
        "cloud.gen", "synced.list", "sync.journal",
    };
    std::string id;
    return kFiles.count(name) > 0 || IsObjectFileName(name, &id);
}

} // namespace

// ── Key IDs ─────────────────────────────────────────────────────────────────

std::string KeyId(const std::vector<uint8_t>& master) {
    static const std::string label = "encfs-key-id-v1";
    std::vector<uint8_t> mac = HMAC::Compute(master, std::vector<uint8_t>(label.begin(), label.end()));
    return HexEncode(mac.data(), 16);
}

std::string KeyIdPath(const std::string& backing_dir) { return backing_dir + "/" + kKeyIdObject; }

bool ReadKeyId(const std::string& path, std::string* id) {
    std::string text;
    if (!ReadText(path, &text)) return false;
    const size_t magic = std::strlen(kKeyIdMagic);
    if (text.size() < magic + 32 || text.compare(0, magic, kKeyIdMagic) != 0) return false;
    std::string hex = text.substr(magic, 32);
    if (!IsHex(hex)) return false;
    *id = hex;
    return true;
}

bool WriteKeyId(const std::string& path, const std::string& id) {
    return WriteText(path, kKeyIdMagic + id + "\n");
}

bool FetchCloudKeyId(CloudCLIWrapper& cloud, const std::string& backing_dir, std::string* id) {
    const std::string path = backing_dir + "/encfs.keyid.cloud";
    bool ok = FetchFromCloud(cloud, kKeyIdObject, path) && ReadKeyId(path, id);
    ::unlink(path.c_str());
    return ok;
}

// ── Re-keyed on another machine ─────────────────────────────────────────────

std::string SetAsideForRekey(const std::string& backing_dir, const std::string& old_key_id) {
    std::string where = backing_dir + "/rekeyed-" + old_key_id.substr(0, 8) + "-" +
                        std::to_string(static_cast<long long>(std::time(nullptr)));
    for (int n = 2; Exists(where); ++n) where += "-" + std::to_string(n);
    if (::mkdir(where.c_str(), 0700) != 0) return "";

    std::vector<std::string> names;
    if (DIR* d = ::opendir(backing_dir.c_str())) {
        while (struct dirent* e = ::readdir(d)) {
            if (BelongsToKey(e->d_name)) names.push_back(e->d_name);
        }
        ::closedir(d);
    }
    for (const auto& name : names) {
        const std::string from = backing_dir + "/" + name, to = where + "/" + name;
        if (::rename(from.c_str(), to.c_str()) != 0) return "";
    }
    return where;
}

// ── encfsctl rekey ──────────────────────────────────────────────────────────

std::string RekeyStagingDir(const std::string& backing_dir) { return backing_dir + "/rekey"; }

bool RekeyInProgress(const std::string& backing_dir) { return Exists(RekeyStagingDir(backing_dir)); }

namespace {

// A whole file in memory as a ChunkSource (for legacy v1 blobs only).
class MemorySource : public ChunkSource {
public:
    explicit MemorySource(std::vector<uint8_t> data) : data_(std::move(data)) {}
    ~MemorySource() override { SecureWipe(data_); }
    uint64_t plaintext_size() const override { return data_.size(); }
    size_t chunk_size() const override { return kChunk; }
    bool ReadChunk(uint64_t index, std::vector<uint8_t>& out) override {
        const uint64_t start = index * kChunk;
        if (start > data_.size() || (start == data_.size() && start != 0)) return false;
        out.assign(data_.begin() + static_cast<long>(start),
                   data_.begin() + static_cast<long>(std::min<uint64_t>(data_.size(), start + kChunk)));
        return true;
    }

private:
    static constexpr size_t kChunk = 1 << 20;
    std::vector<uint8_t> data_;
};

// Reads arbitrary plaintext ranges from a ChunkSource.
class RangeReader {
public:
    explicit RangeReader(ChunkSource& src) : src_(src) {}
    ~RangeReader() { SecureWipe(chunk_); }

    // Fill `out` with bytes [offset, offset + len). False on a read failure.
    bool Read(uint64_t offset, size_t len, std::vector<uint8_t>& out) {
        out.resize(len);
        const size_t cs = src_.chunk_size();
        size_t done = 0;
        while (done < len) {
            const uint64_t pos = offset + done;
            const uint64_t index = pos / cs;
            if (index != cached_ || !have_) {
                if (!src_.ReadChunk(index, chunk_)) return false;
                cached_ = index;
                have_ = true;
            }
            const size_t in = static_cast<size_t>(pos - index * cs);
            if (in >= chunk_.size()) return false;  // shorter than the file claims
            const size_t n = std::min(len - done, chunk_.size() - in);
            std::memcpy(out.data() + done, chunk_.data() + in, n);
            done += n;
        }
        return true;
    }

private:
    ChunkSource& src_;
    std::vector<uint8_t> chunk_;
    uint64_t cached_ = 0;
    bool have_ = false;
};

class Rekeyer {
public:
    Rekeyer(const RekeyOptions& options, const std::string& backing_dir)
        : opts_(options), dir_(backing_dir), staging_(RekeyStagingDir(backing_dir)), cloud_(options.cloudcli) {}
    ~Rekeyer() {
        SecureWipe(old_master_);
        SecureWipe(new_master_);
        SecureWipe(passphrase_);
    }

    int Run();

private:
    const RekeyOptions& opts_;
    const std::string dir_;
    const std::string staging_;
    CloudCLIWrapper cloud_;
    std::vector<uint8_t> old_master_, new_master_;
    std::string passphrase_;

    std::string KeyPath() const { return opts_.key.key_path.empty() ? DefaultKeyPath() : opts_.key.key_path; }
    std::string NewKeyPath() const { return KeyPath() + ".new"; }
    std::string BlobPath(const std::string& id) const { return dir_ + "/" + id + ".enc"; }

    int Fail(const std::string& message) const {
        std::cerr << "Error: " << message << "\n";
        if (Exists(staging_)) {
            std::cerr << "Nothing is lost: run `encfsctl rekey` again to carry on from here.\n";
        }
        return 1;
    }

    bool Retry(const std::function<bool()>& op) {
        for (int attempt = 0; attempt < 3; ++attempt) {
            if (op()) return true;
            ::usleep(200000u << attempt);
        }
        return false;
    }

    int Prepare();
    bool ReencryptFile(const FileCodec& old_codec, const FileCodec& new_codec, const FileMetadata& old_meta,
                       FileMetadata* new_meta, std::string* error);
    bool OpenOld(const FileCodec& codec, const FileMetadata& meta, std::unique_ptr<ChunkSource>* src,
                 bool* padded, std::string* error);
    bool LoadNewMaster(std::string* error);
    int Upload();
    int CommitLocally();
    int Cleanup();
};

int Rekeyer::Run() {
    DirLock lock;
    if (!lock.Acquire(dir_)) {
        return Fail(dir_ + " is in use (mounted, or another encfsctl is working on it). Unmount it first.");
    }
    if (opts_.key.use_passphrase) {
        std::string error;
        if (!ReadPassphrase("ENCFS_PASSPHRASE", "Passphrase", false, passphrase_, error)) return Fail(error);
    }

    std::string state;
    if (!Exists(staging_) || !ReadText(staging_ + "/state", &state) ||
        (state != "prepared\n" && state != "uploaded\n")) {
        // Nothing staged, or a preparation that didn't finish (nothing of it
        // was uploaded): start over.
        if (Exists(staging_)) std::cout << "Discarding an unfinished preparation and starting again.\n";
        if (int rc = Prepare()) return rc;
    } else {
        std::cout << "Resuming an interrupted re-key.\n";
        std::string error;
        if (!LoadNewMaster(&error)) return Fail(error);
    }
    if (Exists(staging_ + "/index.enc")) {
        ReadText(staging_ + "/state", &state);
        if (state != "uploaded\n") {
            if (int rc = Upload()) return rc;
        }
        if (int rc = CommitLocally()) return rc;
    }
    return Cleanup();
}

// Phase 1: a new key, every file re-encrypted under it into new objects, and
// a new index. Nothing leaves this machine yet, and the old key still opens
// everything, so a failure here costs nothing but the work.
int Rekeyer::Prepare() {
    std::string error;
    if (opts_.key.use_passphrase) {
        if (!UnlockPassphraseStore(dir_, passphrase_, old_master_, error)) return Fail(error);
    } else {
        // ResolveMasterKey also accepts legacy (128-bit) key files, so this
        // doubles as their upgrade path.
        if (!ResolveMasterKey(opts_.key, dir_, false, old_master_, error)) return Fail(error);
    }
    EncryptedIndex index(dir_, old_master_);
    if (!index.FileExists() || !index.Load()) {
        return Fail(opts_.key.use_passphrase ? "wrong passphrase, or no readable index in " + dir_
                                             : "no readable index in " + dir_);
    }

    // This machine must hold exactly what the cloud holds: otherwise
    // re-encrypting it would drop someone's changes.
    if (JournalHasWork(dir_)) {
        return Fail("this machine has cloud operations still pending. Mount and unmount once to "
                    "finish syncing, then re-key.");
    }
    uint64_t cloud_gen = 0;
    switch (FetchCloudIndex(cloud_, old_master_, dir_, &cloud_gen)) {
    case CloudIndexStatus::kUnavailable:
        return Fail("can't download the cloud's index. Re-keying needs the cloud.");
    case CloudIndexStatus::kUnreadable:
        return Fail("the cloud's index doesn't open with this key: re-key from a machine that is in sync.");
    case CloudIndexStatus::kFound:
        break;
    }
    if (cloud_gen != index.generation()) {
        return Fail("this machine isn't in sync with the cloud (local index generation " +
                    std::to_string(index.generation()) + ", cloud " + std::to_string(cloud_gen) +
                    "). Mount once to sync, then re-key.");
    }

    // Start from a clean slate.
    if (Exists(staging_)) {
        if (DIR* d = ::opendir(staging_.c_str())) {
            while (struct dirent* e = ::readdir(d)) {
                if (e->d_name[0] != '.') ::unlink((staging_ + "/" + e->d_name).c_str());
            }
            ::closedir(d);
        }
    }
    if (::mkdir(staging_.c_str(), 0700) != 0 && errno != EEXIST) return Fail("cannot create " + staging_);

    // The new key.
    new_master_ = KeyManager::RandomBytes(kKeySize);
    if (opts_.key.use_passphrase) {
        if (!RewrapPassphraseStore(staging_, new_master_, passphrase_, error)) return Fail(error);
        ::unlink((staging_ + "/encfs.kdf.pending").c_str());
    } else {
        std::string hex = HexEncode(new_master_.data(), new_master_.size()) + "\n";
        bool ok = WriteText(NewKeyPath(), hex);
        SecureWipe(hex);
        if (!ok) return Fail("cannot write " + NewKeyPath());
    }
    if (!WriteKeyId(staging_ + "/encfs.keyid", KeyId(new_master_))) return Fail("cannot write the key ID");

    // Re-encrypt every file into new objects (new versions, so their names
    // never collide with the objects they replace).
    FileCodec old_codec(old_master_), new_codec(new_master_);
    std::ostringstream old_objects;
    const std::vector<FileMetadata> inodes = index.AllInodes();
    size_t files = 0, total = 0;
    for (const auto& m : inodes) total += m.IsFile();
    for (const FileMetadata& meta : inodes) {
        if (!meta.IsFile()) continue;
        FileMetadata fresh;
        std::string path;
        index.GetPlaintextName(meta.remote_id, path);
        if (!ReencryptFile(old_codec, new_codec, meta, &fresh, &error)) {
            return Fail("'" + path + "': " + error);
        }
        index.UpdateInode(fresh);
        for (const auto& id : ObjectIds(meta)) {
            // Very old stores wrote no blob for empty files.
            if (meta.segment_size == 0 && meta.size == 0 && !Exists(BlobPath(id))) continue;
            old_objects << id << "\n";
        }
        ++files;
        std::cout << "\rRe-encrypted " << files << " of " << total << " file(s)" << std::flush;
    }
    std::cout << "\n";
    if (!WriteText(staging_ + "/old-objects", old_objects.str())) return Fail("cannot write the object list");

    // The new index, encrypted under the new key, one generation on.
    index.Retarget(staging_, new_master_);
    if (!index.Save()) return Fail("cannot write the new index");

    // Everything is staged. From here on the job is resumable.
    if (!WriteText(staging_ + "/state", "prepared\n")) return Fail("cannot write the re-key state");
    return 0;
}

bool Rekeyer::OpenOld(const FileCodec& codec, const FileMetadata& meta, std::unique_ptr<ChunkSource>* src,
                      bool* padded, std::string* error) {
    *padded = false;
    // A local object, or a temporary download (unlinked once open: the
    // reader keeps it alive).
    auto fetch = [&](const std::string& id, std::string* path, bool* temp) -> bool {
        *path = BlobPath(id);
        *temp = false;
        if (Exists(*path)) return true;
        *path = staging_ + "/" + id + ".download";
        *temp = true;
        return Retry([&] { return cloud_.Download(id, *path); });
    };

    if (meta.segment_size == 0) {
        std::string path;
        bool temp = false;
        if (!fetch(meta.remote_id, &path, &temp)) {
            if (meta.size == 0) {  // very old stores wrote no blob for empty files
                *src = std::make_unique<MemorySource>(std::vector<uint8_t>());
                return true;
            }
            *error = "its data is neither here nor in the cloud";
            return false;
        }
        std::unique_ptr<ChunkedReader> reader;
        FileCodec::Result r = codec.OpenReader(path, meta.remote_id, meta.version, &reader, nullptr);
        if (r == FileCodec::Result::kOk && !reader) {
            // Not a v2 blob: a legacy v1 one, decrypted in memory.
            std::vector<uint8_t> blob, plain;
            if (ReadWholeFile(path, blob) &&
                codec.Decrypt(blob, meta.remote_id, meta.version, plain, nullptr) == FileCodec::Result::kOk) {
                *src = std::make_unique<MemorySource>(std::move(plain));
            } else {
                r = FileCodec::Result::kCorrupt;
            }
        } else if (reader) {
            *src = std::move(reader);
        }
        if (temp) ::unlink(path.c_str());
        if (!*src) {
            *error = r == FileCodec::Result::kRollback ? "its data is an older version than the index expects"
                                                       : "its data failed authentication";
            return false;
        }
        return true;
    }

    auto open_segment = [this, &codec, &meta, fetch](uint64_t seg) -> std::unique_ptr<ChunkedReader> {
        std::string path;
        bool temp = false;
        std::unique_ptr<ChunkedReader> r;
        const std::string id = SegmentObjectId(meta.remote_id, seg, meta.segments[seg]);
        if (fetch(id, &path, &temp)) {
            codec.OpenSegmentReader(path, meta.remote_id, seg, meta.segments[seg], &r);
            if (temp) ::unlink(path.c_str());
        }
        return r;
    };
    // Keep padding if the file had it.
    const uint64_t last = meta.segments.size() - 1;
    if (auto r = open_segment(last)) {
        *padded = r->plaintext_size() > meta.size - std::min<uint64_t>(meta.size, last * meta.segment_size);
    }
    *src = std::make_unique<SegmentedReader>(meta, meta.chunk_size, open_segment);
    return true;
}

bool Rekeyer::ReencryptFile(const FileCodec& old_codec, const FileCodec& new_codec, const FileMetadata& old_meta,
                            FileMetadata* new_meta, std::string* error) {
    std::unique_ptr<ChunkSource> src;
    bool padded = false;
    if (!OpenOld(old_codec, old_meta, &src, &padded, error)) return false;
    if (src->plaintext_size() < old_meta.size) {
        *error = "its data is shorter than the index says";
        return false;
    }
    RangeReader in(*src);

    const size_t cs = new_codec.chunk_size();
    const uint64_t seg_size = DefaultSegmentSize(cs);
    const uint64_t size = old_meta.size;
    const uint64_t count = std::max<uint64_t>(1, (size + seg_size - 1) / seg_size);
    const uint64_t version = old_meta.version + 1;

    *new_meta = old_meta;
    new_meta->version = version;
    new_meta->segment_size = static_cast<uint32_t>(seg_size);
    new_meta->chunk_size = static_cast<uint32_t>(cs);
    new_meta->segments.assign(count, version);

    std::vector<uint8_t> chunk;
    const std::vector<uint8_t> zeros(cs);
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t start = i * seg_size;
        const uint64_t length = size > start ? std::min(seg_size, size - start) : 0;
        const uint64_t stored = (padded && i + 1 == count) ? PaddedLength(length, seg_size) : length;
        const uint64_t n_chunks = std::max<uint64_t>(1, (stored + cs - 1) / cs);
        const std::string object = SegmentObjectId(old_meta.remote_id, i, version);

        AtomicFile out(BlobPath(object), 0600);
        if (!out.Open()) {
            *error = std::string("cannot create ") + object + ": " + std::strerror(errno);
            return false;
        }
        auto writer = new_codec.NewSegmentWriter([&out](const uint8_t* d, size_t n) { return out.Write(d, n); },
                                                 old_meta.remote_id, i, version, cs);
        bool ok = true;
        for (uint64_t k = 0; k < n_chunks && ok; ++k) {
            const uint64_t offset = k * cs;
            const size_t len = static_cast<size_t>(std::min<uint64_t>(cs, stored - std::min(stored, offset)));
            const size_t data = static_cast<size_t>(std::min<uint64_t>(len, length - std::min(length, offset)));
            ok = in.Read(start + offset, data, chunk);
            if (ok && data < len) chunk.insert(chunk.end(), zeros.begin(), zeros.begin() + static_cast<long>(len - data));
            ok = ok && writer->Add(chunk.empty() ? zeros.data() : chunk.data(), len, k + 1 == n_chunks);
        }
        SecureWipe(chunk);
        if (!ok || !writer->finished() || !out.Commit()) {
            *error = ok ? "cannot write " + object : "its data failed authentication";
            return false;
        }
    }
    return true;
}

bool Rekeyer::LoadNewMaster(std::string* error) {
    if (opts_.key.use_passphrase) {
        // Staged until committed, then in place.
        const std::string where = Exists(staging_ + "/encfs.kdf") ? staging_ : dir_;
        return UnlockPassphraseStore(where, passphrase_, new_master_, *error);
    }
    const std::string path = Exists(NewKeyPath()) ? NewKeyPath() : KeyPath();
    try {
        new_master_ = KeyManager::LoadKeyFromFile(path);
    } catch (const std::exception& e) {
        *error = e.what();
        return false;
    }
    std::string staged;
    if (!ReadKeyId(Exists(staging_ + "/encfs.keyid") ? staging_ + "/encfs.keyid" : KeyIdPath(dir_), &staged) ||
        staged != KeyId(new_master_)) {
        *error = path + " isn't the new key this re-key was started with";
        return false;
    }
    return true;
}

// Phase 2: upload the new objects, then switch the cloud over: the index,
// the passphrase file, and last the key ID, which tells other machines the
// store was re-keyed. The old objects stay until phase 4, so until the
// index is replaced the cloud is still entirely valid under the old key.
int Rekeyer::Upload() {
    EncryptedIndex staged(staging_, new_master_);
    if (!staged.Load()) return Fail("the staged index doesn't open with the new key");

    // Someone may have changed the cloud since we prepared. Unless the cloud
    // already switched to the new key (a resumed run), its index must still
    // be exactly the one we started from.
    uint64_t cloud_gen = 0;
    const CloudIndexStatus now = FetchCloudIndex(cloud_, new_master_, dir_, &cloud_gen);
    if (now == CloudIndexStatus::kUnavailable) return Fail("can't reach the cloud");
    if (now != CloudIndexStatus::kFound) {
        std::vector<uint8_t> old;
        std::string error;
        bool have_old = false;
        if (opts_.key.use_passphrase) {
            have_old = UnlockPassphraseStore(dir_, passphrase_, old, error);
        } else {
            // Before the local commit the key file still holds the old key
            // (possibly a legacy one, which this resolves too).
            have_old = ResolveMasterKey(opts_.key, dir_, false, old, error);
        }
        if (!old_master_.empty()) old = old_master_, have_old = true;  // e.g. a legacy key
        const bool unchanged = have_old && FetchCloudIndex(cloud_, old, dir_, &cloud_gen) == CloudIndexStatus::kFound &&
                               cloud_gen + 1 == staged.generation();
        SecureWipe(old);
        if (!unchanged) {
            return Fail("the cloud's index changed since the re-key started (another machine wrote to "
                        "the store). Delete " + staging_ +
                        (opts_.key.use_passphrase ? "" : " and " + NewKeyPath()) +
                        ", mount once to sync, and re-key again.");
        }
    }

    size_t done = 0, total = 0;
    const std::vector<FileMetadata> inodes = staged.AllInodes();
    for (const auto& m : inodes) total += ObjectIds(m).size() * m.IsFile();
    for (const FileMetadata& meta : inodes) {
        if (!meta.IsFile()) continue;
        for (const auto& id : ObjectIds(meta)) {
            if (!Retry([&] { return cloud_.Upload(BlobPath(id)); })) return Fail("could not upload " + id);
            std::cout << "\rUploaded " << ++done << " of " << total << " object(s)" << std::flush;
        }
    }
    std::cout << "\n";

    if (!Retry([&] { return cloud_.Upload(staging_ + "/index.enc"); })) return Fail("could not upload the new index");
    if (opts_.key.use_passphrase && Exists(staging_ + "/encfs.kdf") &&
        !Retry([&] { return cloud_.Upload(staging_ + "/encfs.kdf"); })) {
        return Fail("could not upload the new encfs.kdf");
    }
    if (!Retry([&] { return cloud_.Upload(staging_ + "/encfs.keyid"); })) return Fail("could not upload the key ID");
    if (!WriteText(staging_ + "/state", "uploaded\n")) return Fail("cannot write the re-key state");
    std::cout << "The cloud now holds the store under the new key.\n";
    return 0;
}

// Phase 3: switch this machine over. Each step is an atomic rename, and each
// is skipped if it already happened.
int Rekeyer::CommitLocally() {
    EncryptedIndex staged(staging_, new_master_);
    if (!staged.Load()) return Fail("the staged index doesn't open with the new key");

    if (!opts_.key.use_passphrase && Exists(NewKeyPath())) {
        // Keep the old key next to the new one: it still opens copies of the
        // old objects (e.g. a provider's version history, or backups).
        std::string old_id = "old";
        try {
            std::vector<uint8_t> old = KeyManager::LoadKeyFromFile(KeyPath());
            old_id = KeyId(old).substr(0, 8);
            SecureWipe(old);
        } catch (const std::exception&) {
        }
        const std::string kept = KeyPath() + "." + old_id + ".old";
        if (Exists(KeyPath()) && ::rename(KeyPath().c_str(), kept.c_str()) != 0) {
            return Fail("cannot rename " + KeyPath());
        }
        if (::rename(NewKeyPath().c_str(), KeyPath().c_str()) != 0) return Fail("cannot install the new key");
        std::cout << "The old key is kept as " << kept << ".\n";
    }
    if (opts_.key.use_passphrase && Exists(staging_ + "/encfs.kdf")) {
        if (::rename((staging_ + "/encfs.kdf").c_str(), (dir_ + "/encfs.kdf").c_str()) != 0) {
            return Fail("cannot install the new encfs.kdf");
        }
        ::unlink((dir_ + "/encfs.kdf.pending").c_str());
    }

    // Every new object is in the cloud at its current version.
    std::ostringstream synced;
    for (const FileMetadata& meta : staged.AllInodes()) {
        if (!meta.IsFile()) continue;
        for (size_t i = 0; i < meta.segments.size(); ++i) {
            synced << SegmentObjectId(meta.remote_id, i, meta.segments[i]) << " " << meta.segments[i] << "\n";
        }
    }
    if (!WriteText(dir_ + "/synced.list", synced.str()) ||
        !SaveSyncedGeneration(dir_, staged.generation()) ||
        ::rename((staging_ + "/encfs.keyid").c_str(), KeyIdPath(dir_).c_str()) != 0 ||
        ::rename((staging_ + "/index.enc").c_str(), (dir_ + "/index.enc").c_str()) != 0) {
        return Fail("cannot install the new index");
    }
    return 0;
}

// Phase 4: delete the old objects, here and in the cloud. Deletes that fail
// stay in the sync journal, and the next mount finishes them.
int Rekeyer::Cleanup() {
    std::string list;
    ReadText(staging_ + "/old-objects", &list);
    std::vector<std::string> ids;
    std::istringstream lines(list);
    for (std::string id; std::getline(lines, id);) {
        if (!id.empty()) ids.push_back(id);
    }

    // Journal them first, so an interruption can't forget any.
    std::string journal;
    for (const auto& id : ids) journal += "D " + id + "\n";
    if (!ids.empty() && !WriteText(dir_ + "/sync.journal", journal)) return Fail("cannot write the sync journal");

    std::string failed;
    size_t done = 0;
    for (const auto& id : ids) {
        ::unlink(BlobPath(id).c_str());
        if (Retry([&] { return cloud_.Delete(id); })) {
            std::cout << "\rDeleted " << ++done << " of " << ids.size() << " old object(s)" << std::flush;
        } else {
            failed += "D " + id + "\n";
        }
    }
    if (!ids.empty()) std::cout << "\n";
    if (failed.empty()) {
        ::unlink((dir_ + "/sync.journal").c_str());
    } else {
        WriteText(dir_ + "/sync.journal", failed);
        std::cout << "Some old objects couldn't be deleted from the cloud yet; the next mount will retry.\n";
    }

    // Done: remove the staging area.
    if (DIR* d = ::opendir(staging_.c_str())) {
        while (struct dirent* e = ::readdir(d)) {
            if (e->d_name[0] != '.') ::unlink((staging_ + "/" + e->d_name).c_str());
        }
        ::closedir(d);
    }
    ::rmdir(staging_.c_str());

    std::cout << "\nRe-keyed. Every file is now encrypted under a new key (ID " << KeyId(new_master_).substr(0, 8)
              << ").\n";
    if (opts_.key.use_passphrase) {
        std::cout << "Your passphrase is unchanged; it now unlocks the new key. Other machines pick up\n"
                     "the new encfs.kdf on their next mount.\n";
    } else {
        std::cout << "The new key is in " << KeyPath() << ". Back it up, and copy it to your other\n"
                     "machines: they need it from their next mount on.\n";
    }
    std::cout << "Other machines set their old local copy aside (readable with the old key) and\n"
                 "restore from the cloud. If your provider keeps old versions of objects, those\n"
                 "remain readable with the old key: delete them there if the old key leaked.\n";
    return 0;
}

} // namespace

int RunRekey(const RekeyOptions& options, const std::string& backing_dir) {
    Rekeyer rekeyer(options, backing_dir);
    return rekeyer.Run();
}

} // namespace encfs

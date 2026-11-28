#include "index_sync.h"
#include "cloudcli_wrapper.h"
#include "crypto.h"
#include "file_codec.h"
#include "index.h"
#include "segments.h"
#include "util.h"

#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

namespace encfs {

namespace {
std::string FetchDir(const std::string& backing_dir) { return backing_dir + "/.cloud-index"; }

} // namespace

std::string FetchedCloudIndexPath(const std::string& backing_dir) {
    return FetchDir(backing_dir) + "/index.enc";
}

bool IndexFileGeneration(const std::string& dir, const std::vector<uint8_t>& key, uint64_t* generation) {
    EncryptedIndex index(dir, key);
    if (!index.FileExists() || !index.Load()) return false;
    *generation = index.generation();
    return true;
}

CloudIndexStatus FetchCloudIndex(CloudCLIWrapper& cloud, const std::vector<uint8_t>& key,
                                 const std::string& backing_dir, uint64_t* generation) {
    const std::string dir = FetchDir(backing_dir);
    ::mkdir(dir.c_str(), 0700);
    const std::string path = FetchedCloudIndexPath(backing_dir);
    const std::string tmp = path + ".download";
    ::unlink(path.c_str());
    if (!cloud.Download("index", tmp) || ::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return CloudIndexStatus::kUnavailable;
    }
    return IndexFileGeneration(dir, key, generation) ? CloudIndexStatus::kFound
                                                     : CloudIndexStatus::kUnreadable;
}

bool LoadSyncedGeneration(const std::string& backing_dir, uint64_t* generation) {
    std::vector<uint8_t> data;
    if (!ReadWholeFile(backing_dir + "/cloud.gen", data) || data.empty()) return false;
    std::string text(data.begin(), data.end());
    char* end = nullptr;
    unsigned long long v = std::strtoull(text.c_str(), &end, 10);
    if (end == text.c_str()) return false;
    *generation = v;
    return true;
}

bool SaveSyncedGeneration(const std::string& backing_dir, uint64_t generation) {
    std::string text = std::to_string(generation) + "\n";
    return WriteFileAtomic(backing_dir + "/cloud.gen", reinterpret_cast<const uint8_t*>(text.data()),
                           text.size(), 0600);
}

int AdoptFetchedCloudIndex(const std::string& backing_dir, EncryptedIndex& index, const FileCodec& codec) {
    if (::rename(FetchedCloudIndexPath(backing_dir).c_str(), index.path().c_str()) != 0) return -1;
    if (!index.Load()) return -1;

    // Local blobs written against the old index may be older (or newer) than
    // what the adopted index expects; reading them would fail the version
    // check. Keep only exact matches.
    int removed = 0;
    if (DIR* d = ::opendir(backing_dir.c_str())) {
        std::vector<std::string> ids;
        while (struct dirent* e = ::readdir(d)) {
            std::string id;
            if (IsObjectFileName(e->d_name, &id)) ids.push_back(id);
        }
        ::closedir(d);
        for (const auto& id : ids) {
            const std::string path = backing_dir + "/" + id + ".enc";
            bool keep = IndexReferencesObject(index, id);
            if (keep && id.size() == 64) {
                // A legacy whole-file blob: its name doesn't say its version.
                FileMetadata meta;
                std::unique_ptr<ChunkedReader> reader;
                uint64_t actual = 0;
                keep = index.GetInode(id, meta) &&
                       codec.OpenReader(path, id, meta.version, &reader, &actual) == FileCodec::Result::kOk &&
                       reader && actual == meta.version;
            }
            if (!keep && ::unlink(path.c_str()) == 0) ++removed;
        }
    }
    return removed;
}

bool FetchFromCloud(CloudCLIWrapper& cloud, const std::string& remote_id, const std::string& path) {
    const std::string tmp = path + ".download";
    if (cloud.Download(remote_id, tmp) && ::rename(tmp.c_str(), path.c_str()) == 0) {
        return true;
    }
    ::unlink(tmp.c_str());
    return false;
}

bool JournalHasWork(const std::string& backing_dir) {
    struct stat st;
    return ::stat((backing_dir + "/sync.journal").c_str(), &st) == 0 && st.st_size > 0;
}

} // namespace encfs

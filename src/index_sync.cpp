#include "index_sync.h"
#include "cloudcli_wrapper.h"
#include "crypto.h"
#include "file_codec.h"
#include "index.h"
#include "util.h"

#include <cerrno>
#include <cstdlib>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

namespace encfs {

namespace {
std::string FetchDir(const std::string& backing_dir) { return backing_dir + "/.cloud-index"; }

bool IsBlobName(const std::string& n) {
    return n.size() == 68 && n.compare(64, 4, ".enc") == 0 &&
           n.find_first_not_of("0123456789abcdef") == 64;
}
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
        std::vector<std::string> names;
        while (struct dirent* e = ::readdir(d)) {
            if (IsBlobName(e->d_name)) names.emplace_back(e->d_name);
        }
        ::closedir(d);
        for (const auto& n : names) {
            const std::string id = n.substr(0, 64);
            const std::string path = backing_dir + "/" + n;
            FileMetadata meta;
            bool keep = false;
            if (index.GetInode(id, meta) && meta.IsFile()) {
                std::unique_ptr<ChunkedReader> reader;
                uint64_t actual = 0;
                keep = codec.OpenReader(path, id, meta.version, &reader, &actual) ==
                           FileCodec::Result::kOk &&
                       reader && actual == meta.version;
            }
            if (!keep && ::unlink(path.c_str()) == 0) ++removed;
        }
    }
    return removed;
}

} // namespace encfs

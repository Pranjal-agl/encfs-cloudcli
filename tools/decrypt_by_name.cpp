// decrypt_by_name — work with a backing directory without mounting it.
//
//   decrypt_by_name [options] <backing_dir> <path> <output_path|->   one file
//   decrypt_by_name [options] --list <backing_dir>                   list the index
//   decrypt_by_name [options] --verify <backing_dir>                 check every file
//   decrypt_by_name [options] --extract-all <out_dir> <backing_dir>  export everything
//
// Blobs that aren't cached locally are fetched with cloudcli (and not kept).

#include "cloudcli_wrapper.h"
#include "crypto.h"
#include "file_codec.h"
#include "index.h"
#include "key_setup.h"
#include "util.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <iostream>
#include <map>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

using namespace encfs;

namespace {

void PrintUsage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " [options] <backing_dir> <path> <output_path|->\n"
        "       " << prog << " [options] --list <backing_dir>\n"
        "       " << prog << " [options] --verify <backing_dir>\n"
        "       " << prog << " [options] --extract-all <out_dir> <backing_dir>\n"
        "\n"
        "<path> is the path inside the filesystem, e.g. docs/notes.txt\n"
        "\n"
        "Options:\n"
        "  -k, --key FILE          key file (default: $ENCFS_KEY_FILE or ~/.encfs/key)\n"
        "  -p, --passphrase        derive the key from a passphrase\n"
        "  -c, --cloudcli CMD      cloudcli used to fetch blobs not cached locally\n"
        "  -l, --list              list the files in the index\n"
        "  -v, --verify            decrypt and authenticate every file; report problems\n"
        "                          and leftover blobs (exit status 1 if any)\n"
        "  -x, --extract-all DIR   decrypt every file into DIR, recreating directories\n"
        "                          and modification times (DIR must be empty or new)\n"
        "  -h, --help              show this help\n";
}

void FetchIfMissing(CloudCLIWrapper& cloud, const std::string& remote_id, const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) == 0) return;
    const std::string tmp = path + ".download";
    if (cloud.Download(remote_id, tmp) && ::rename(tmp.c_str(), path.c_str()) == 0) {
        std::cerr << "Fetched " << remote_id << " from the cloud\n";
    } else {
        ::unlink(tmp.c_str());
    }
}

bool WriteAllTo(FILE* f, const std::vector<uint8_t>& data) {
    return std::fwrite(data.data(), 1, data.size(), f) == data.size() && std::fflush(f) == 0;
}

enum class Outcome { kOk, kMissing, kRollback, kCorrupt };

const char* Describe(Outcome o) {
    switch (o) {
    case Outcome::kOk: return "ok";
    case Outcome::kMissing: return "MISSING (not cached locally and download failed)";
    case Outcome::kRollback: return "ROLLBACK (older version than the index expects)";
    default: return "CORRUPT (tampered, wrong file, or wrong key)";
    }
}

struct Context {
    std::string backing_dir;
    CloudCLIWrapper* cloud;
    FileCodec* codec;
};

// Fetch (if needed) and decrypt one file.
Outcome Decrypt(Context& ctx, const FileMetadata& meta, std::vector<uint8_t>& plaintext) {
    const std::string blob_path = ctx.backing_dir + "/" + meta.remote_id + ".enc";
    std::vector<uint8_t> blob;
    if (!ReadWholeFile(blob_path, blob)) {
        const std::string tmp = blob_path + ".download";
        bool fetched = ctx.cloud->Download(meta.remote_id, tmp) && ReadWholeFile(tmp, blob);
        ::unlink(tmp.c_str());
        if (!fetched) {
            if (meta.size == 0) {  // older versions wrote no blob for empty files
                plaintext.clear();
                return Outcome::kOk;
            }
            return Outcome::kMissing;
        }
    }
    switch (ctx.codec->Decrypt(blob, meta.remote_id, meta.version, plaintext, nullptr)) {
    case FileCodec::Result::kOk: return Outcome::kOk;
    case FileCodec::Result::kRollback: return Outcome::kRollback;
    default: return Outcome::kCorrupt;
    }
}

int Verify(Context& ctx, EncryptedIndex& index) {
    auto names = index.GetAllPlaintextNames();
    std::sort(names.begin(), names.end());
    std::set<std::string> referenced;
    size_t files = 0, problems = 0;
    uint64_t bytes = 0;

    for (const auto& name : names) {
        FileMetadata meta;
        index.GetMetadata(name, meta);
        if (!meta.IsFile()) continue;
        if (!referenced.insert(meta.remote_id + ".enc").second) continue;  // hard link: checked already
        ++files;
        std::vector<uint8_t> plaintext;
        Outcome o = Decrypt(ctx, meta, plaintext);
        if (o == Outcome::kOk && plaintext.size() != meta.size) o = Outcome::kCorrupt;
        if (o != Outcome::kOk) {
            ++problems;
            std::cout << Describe(o) << "\t" << name << "\n";
        }
        bytes += plaintext.size();
        SecureWipe(plaintext);
    }

    // Blobs in the backing dir that no index entry points at (e.g. left over
    // from an interrupted rename). Harmless, but worth knowing about.
    size_t leftovers = 0;
    if (DIR* d = ::opendir(ctx.backing_dir.c_str())) {
        while (struct dirent* e = ::readdir(d)) {
            std::string n = e->d_name;
            if (n.size() == 68 && n.compare(64, 4, ".enc") == 0 && !referenced.count(n)) {
                std::cout << "LEFTOVER\t" << n << "\n";
                ++leftovers;
            }
        }
        ::closedir(d);
    }

    std::cerr << files << " files (" << bytes << " bytes) checked: "
              << files - problems << " ok, " << problems << " with problems";
    if (leftovers) std::cerr << ", " << leftovers << " unreferenced blob(s)";
    std::cerr << "\n";
    return problems || leftovers ? 1 : 0;
}

// Reject anything that could escape the output directory. The index is
// authenticated, but defence in depth costs nothing here.
bool SafeRelativePath(const std::string& p) {
    if (p.empty() || p[0] == '/') return false;
    size_t start = 0;
    for (;;) {
        size_t slash = p.find('/', start);
        std::string comp = p.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (comp.empty() || comp == "." || comp == "..") return false;
        if (slash == std::string::npos) return true;
        start = slash + 1;
    }
}

void SetMtime(const std::string& path, int64_t mtime) {
    if (mtime <= 0) return;
    struct timespec times[2];
    times[0].tv_sec = times[1].tv_sec = static_cast<time_t>(mtime);
    times[0].tv_nsec = times[1].tv_nsec = 0;
    ::utimensat(AT_FDCWD, path.c_str(), times, 0);
}

int ExtractAll(Context& ctx, EncryptedIndex& index, const std::string& out_dir) {
    if (::mkdir(out_dir.c_str(), 0700) != 0 && errno != EEXIST) {
        std::cerr << "Cannot create " << out_dir << ": " << std::strerror(errno) << "\n";
        return 1;
    }
    if (DIR* d = ::opendir(out_dir.c_str())) {
        bool empty = true;
        while (struct dirent* e = ::readdir(d)) {
            if (std::strcmp(e->d_name, ".") != 0 && std::strcmp(e->d_name, "..") != 0) empty = false;
        }
        ::closedir(d);
        if (!empty) {
            std::cerr << out_dir << " is not empty; refusing to overwrite anything\n";
            return 1;
        }
    }

    // Sorted, so every directory is created before anything inside it.
    auto names = index.GetAllPlaintextNames();
    std::sort(names.begin(), names.end());
    size_t written = 0, failed = 0;
    std::vector<std::pair<std::string, int64_t>> dir_times;
    std::vector<std::pair<std::string, uint32_t>> dir_modes;
    std::map<std::string, std::string> extracted;  // inode → first path written (for hard links)

    for (const auto& name : names) {
        FileMetadata meta;
        index.GetMetadata(name, meta);
        if (!SafeRelativePath(name)) {
            std::cerr << "skipping unsafe path in index: " << name << "\n";
            ++failed;
            continue;
        }
        const std::string dest = out_dir + "/" + name;
        // Make sure parent directories exist even if the index lacks entries for them.
        for (size_t pos = name.find('/'); pos != std::string::npos; pos = name.find('/', pos + 1)) {
            ::mkdir((out_dir + "/" + name.substr(0, pos)).c_str(), 0700);
        }
        if (meta.IsDirectory()) {
            ::mkdir(dest.c_str(), 0700);
            dir_times.emplace_back(dest, meta.mtime);
            dir_modes.emplace_back(dest, meta.mode);
            continue;
        }
        if (meta.IsSymlink()) {
            if (::symlink(meta.target.c_str(), dest.c_str()) != 0) {
                std::cerr << "cannot create symlink " << dest << ": " << std::strerror(errno) << "\n";
                ++failed;
            }
            continue;
        }
        auto first = extracted.find(meta.remote_id);
        if (first != extracted.end()) {  // another name for a file already written
            if (::link(first->second.c_str(), dest.c_str()) != 0) {
                std::cerr << "cannot create hard link " << dest << ": " << std::strerror(errno) << "\n";
                ++failed;
            }
            continue;
        }
        std::vector<uint8_t> plaintext;
        Outcome o = Decrypt(ctx, meta, plaintext);
        if (o != Outcome::kOk) {
            std::cerr << Describe(o) << "\t" << name << "\n";
            ++failed;
            continue;
        }
        if (!WriteFileAtomic(dest, plaintext, 0600)) {
            std::cerr << "cannot write " << dest << ": " << std::strerror(errno) << "\n";
            ++failed;
        } else {
            ::chmod(dest.c_str(), static_cast<mode_t>(meta.mode));
            SetMtime(dest, meta.mtime);
            extracted[meta.remote_id] = dest;
            ++written;
        }
        SecureWipe(plaintext);
    }
    // Directory modes and times last (deepest first): writing into a directory
    // updates its mtime, and a read-only mode would stop us writing into it.
    for (auto it = dir_modes.rbegin(); it != dir_modes.rend(); ++it) {
        ::chmod(it->first.c_str(), static_cast<mode_t>(it->second));
    }
    for (auto it = dir_times.rbegin(); it != dir_times.rend(); ++it) SetMtime(it->first, it->second);

    std::cerr << "Extracted " << written << " file(s) to " << out_dir;
    if (failed) std::cerr << "; " << failed << " failed";
    std::cerr << "\n";
    return failed ? 1 : 0;
}

} // namespace

int main(int argc, char* argv[]) {
    KeyOptions key_options;
    std::string cloudcli_cmd = CloudCLIWrapper::DefaultCommand();
    enum class Mode { kOne, kList, kVerify, kExtract } mode = Mode::kOne;
    std::string extract_dir;

    static const struct option long_opts[] = {
        {"key", required_argument, nullptr, 'k'},
        {"passphrase", no_argument, nullptr, 'p'},
        {"cloudcli", required_argument, nullptr, 'c'},
        {"list", no_argument, nullptr, 'l'},
        {"verify", no_argument, nullptr, 'v'},
        {"extract-all", required_argument, nullptr, 'x'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "k:pc:lvx:h", long_opts, nullptr)) != -1) {
        switch (opt) {
        case 'k': key_options.key_path = optarg; break;
        case 'p': key_options.use_passphrase = true; break;
        case 'c': cloudcli_cmd = optarg; break;
        case 'l': mode = Mode::kList; break;
        case 'v': mode = Mode::kVerify; break;
        case 'x': mode = Mode::kExtract; extract_dir = optarg; break;
        case 'h': PrintUsage(argv[0]); return 0;
        default: PrintUsage(argv[0]); return 2;
        }
    }
    const int positional = argc - optind;
    if (positional != (mode == Mode::kOne ? 3 : 1)) {
        PrintUsage(argv[0]);
        return 2;
    }

    const std::string backing_dir = argv[optind];

    // No local copy (e.g. recovering on a new machine): fetch the index, and
    // the passphrase KDF parameters, from the cloud.
    ::mkdir(backing_dir.c_str(), 0700);
    CloudCLIWrapper cloudcli(cloudcli_cmd);
    FetchIfMissing(cloudcli, "index", backing_dir + "/index.enc");
    if (key_options.use_passphrase) {
        FetchIfMissing(cloudcli, "encfs.kdf", backing_dir + "/encfs.kdf");
    }

    std::vector<uint8_t> master_key;
    std::string error;
    if (!ResolveMasterKey(key_options, backing_dir, /*allow_create=*/false, master_key, error)) {
        std::cerr << "Error: " << error << "\n";
        return 1;
    }

    EncryptedIndex index(backing_dir, master_key);
    if (!index.FileExists() || !index.Load()) {
        std::cerr << "Error: cannot load index from " << backing_dir << "\n";
        return 1;
    }

    if (mode == Mode::kList) {
        auto names = index.GetAllPlaintextNames();
        std::sort(names.begin(), names.end());
        for (const auto& name : names) {
            FileMetadata meta;
            index.GetMetadata(name, meta);
            if (meta.IsDirectory()) {
                std::cout << "-\t" << name << "/\n";
            } else if (meta.IsSymlink()) {
                std::cout << "-\t" << name << " -> " << meta.target << "\n";
            } else {
                std::cout << meta.size << "\t" << name << "\n";
            }
        }
        return 0;
    }

    FileCodec codec(master_key);
    SecureWipe(master_key);
    Context ctx{backing_dir, &cloudcli, &codec};

    if (mode == Mode::kVerify) return Verify(ctx, index);
    if (mode == Mode::kExtract) return ExtractAll(ctx, index, extract_dir);

    const std::string plaintext_name = argv[optind + 1];
    const std::string output_path = argv[optind + 2];
    FileMetadata meta;
    if (!index.GetMetadata(plaintext_name, meta)) {
        std::cerr << "File not found in index: " << plaintext_name << "\n";
        return 1;
    }
    if (meta.IsDirectory()) {
        std::cerr << plaintext_name << " is a directory (use --extract-all for everything)\n";
        return 1;
    }
    if (meta.IsSymlink()) {
        std::cerr << plaintext_name << " is a symbolic link to " << meta.target << "\n";
        return 1;
    }

    std::vector<uint8_t> plaintext;
    Outcome o = Decrypt(ctx, meta, plaintext);
    if (o != Outcome::kOk) {
        std::cerr << "Cannot decrypt " << plaintext_name << ": " << Describe(o) << "\n";
        return 1;
    }

    bool ok = output_path == "-" ? WriteAllTo(stdout, plaintext)
                                 : WriteFileAtomic(output_path, plaintext, 0600);
    SecureWipe(plaintext);
    if (!ok) {
        std::cerr << "Failed to write output: " << std::strerror(errno) << "\n";
        return 1;
    }
    if (output_path != "-") {
        std::cerr << "Decrypted " << plaintext_name << " to " << output_path << "\n";
    }
    return 0;
}

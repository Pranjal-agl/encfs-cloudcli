// encfsctl — set up and look after an encfs-cloudcli store.
//
//   encfsctl init   [--key FILE | --passphrase] <backing_dir>
//   encfsctl passwd [--cloudcli CMD] <backing_dir>
//   encfsctl status [--key FILE | --passphrase] <backing_dir>
//   encfsctl rekey  [--key FILE | --passphrase] [--cloudcli CMD] <backing_dir>

#include "cloudcli_wrapper.h"
#include "crypto.h"
#include "index.h"
#include "segments.h"
#include "index_sync.h"
#include "key_setup.h"
#include "rekey.h"
#include "util.h"

#include <dirent.h>
#include <getopt.h>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

using namespace encfs;

namespace {

void Usage() {
    std::cerr <<
        "Usage: encfsctl <command> [options] <backing_dir>\n"
        "\n"
        "Commands:\n"
        "  init     Set up a new store: create a key file (mode 0600), or with\n"
        "           --passphrase, a passphrase-protected key in <backing_dir>/encfs.kdf\n"
        "  passwd   Change the passphrase of a passphrase-protected store. Nothing is\n"
        "           re-encrypted; the new encfs.kdf is uploaded to the cloud.\n"
        "           Reads $ENCFS_PASSPHRASE / $ENCFS_NEW_PASSPHRASE, or prompts.\n"
        "  status   Show files, sizes, local cache use and pending cloud operations\n"
        "  rekey    Re-encrypt everything under a new master key (if a key file or\n"
        "           passphrase may have leaked). Key file: the new key replaces the\n"
        "           old one, which is kept as <key>.<id>.old. Passphrase: unchanged,\n"
        "           it now unlocks the new key. Resumable; needs the cloud.\n"
        "\n"
        "Options:\n"
        "  -k, --key FILE      key file (default: $ENCFS_KEY_FILE or ~/.encfs/key)\n"
        "  -p, --passphrase    the store is passphrase-protected\n"
        "  -c, --cloudcli CMD  cloudcli executable (default: $ENCFS_CLOUDCLI or cloudcli)\n";
}

bool Exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

std::string HumanBytes(uint64_t n) {
    const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1024 && u < 4) {
        v /= 1024;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), u == 0 ? "%.0f %s" : "%.1f %s", v, units[u]);
    return buf;
}

int Init(const KeyOptions& opts, const std::string& backing_dir) {
    if (Exists(backing_dir + "/index.enc") || PassphraseStoreExists(backing_dir)) {
        std::cerr << backing_dir << " already holds a store; refusing to set up another\n";
        return 1;
    }
    ::mkdir(backing_dir.c_str(), 0700);

    if (opts.use_passphrase) {
        std::string passphrase, error;
        std::vector<uint8_t> master;
        if (!ReadPassphrase("ENCFS_PASSPHRASE", "New passphrase", true, passphrase, error) ||
            !CreatePassphraseStore(backing_dir, passphrase, master, error)) {
            std::cerr << "Error: " << error << "\n";
            return 1;
        }
        SecureWipe(passphrase);
        SecureWipe(master);
        std::cout << "Created a passphrase-protected store in " << backing_dir << ".\n"
                  << "Mount it with: encrypted_cloudfs --passphrase <mountpoint> " << backing_dir << "\n";
        return 0;
    }

    const std::string key_path = opts.key_path.empty() ? DefaultKeyPath() : opts.key_path;
    if (Exists(key_path)) {
        std::cerr << key_path << " already exists; not overwriting it.\n"
                  << "To use it, just mount: encrypted_cloudfs <mountpoint> " << backing_dir << "\n";
        return 1;
    }
    const auto slash = key_path.find_last_of('/');
    if (slash != std::string::npos && slash > 0) ::mkdir(key_path.substr(0, slash).c_str(), 0700);
    std::vector<uint8_t> key = KeyManager::RandomBytes(kKeySize);
    std::string hex = HexEncode(key.data(), key.size()) + "\n";
    SecureWipe(key);
    bool ok = WriteFileAtomic(key_path, reinterpret_cast<const uint8_t*>(hex.data()), hex.size(), 0600);
    SecureWipe(hex);
    if (!ok) {
        std::cerr << "Cannot write " << key_path << "\n";
        return 1;
    }
    std::cout << "Created a 256-bit key at " << key_path << " (mode 0600).\n"
              << "Back it up somewhere safe: without it your files cannot be recovered.\n"
              << "Mount with: encrypted_cloudfs -k " << key_path << " <mountpoint> " << backing_dir << "\n";
    return 0;
}

int Passwd(const std::string& cloudcli_cmd, const std::string& backing_dir) {
    DirLock lock;
    if (!lock.Acquire(backing_dir)) {
        std::cerr << "Error: " << backing_dir << " is in use (mounted, or being re-keyed). Unmount it first.\n";
        return 1;
    }
    if (RekeyInProgress(backing_dir)) {
        std::cerr << "Error: a re-key of this store is unfinished; run `encfsctl rekey` again first.\n";
        return 1;
    }
    CloudCLIWrapper cloud(cloudcli_cmd);
    const std::string kdf_path = backing_dir + "/encfs.kdf";
    if (!PassphraseStoreExists(backing_dir)) {
        // New machine: fetch it, like mounting would.
        const std::string tmp = kdf_path + ".download";
        if (cloud.Download("encfs.kdf", tmp)) ::rename(tmp.c_str(), kdf_path.c_str());
        ::unlink(tmp.c_str());
        if (!PassphraseStoreExists(backing_dir)) {
            std::cerr << "No encfs.kdf in " << backing_dir << " or the cloud: not a passphrase store\n";
            return 1;
        }
    }

    std::string current, error;
    std::vector<uint8_t> master;
    int version = 0;
    if (!ReadPassphrase("ENCFS_PASSPHRASE", "Current passphrase", false, current, error) ||
        !UnlockPassphraseStore(backing_dir, current, master, error, &version)) {
        std::cerr << "Error: " << error << "\n";
        return 1;
    }
    SecureWipe(current);

    // v1 files can't tell a wrong passphrase on their own: check the index.
    EncryptedIndex index(backing_dir, master);
    if (index.FileExists() ? !index.Load() : version == 1) {
        std::cerr << "Error: " << (index.FileExists() ? "wrong passphrase"
                                                       : "can't verify the passphrase without index.enc")
                  << "\n";
        return 1;
    }

    std::string fresh;
    if (!ReadPassphrase("ENCFS_NEW_PASSPHRASE", "New passphrase", true, fresh, error) ||
        !RewrapPassphraseStore(backing_dir, master, fresh, error)) {
        std::cerr << "Error: " << error << "\n";
        return 1;
    }
    SecureWipe(fresh);
    SecureWipe(master);

    std::cout << "Passphrase changed" << (version == 1 ? " (and encfs.kdf upgraded to v2)" : "") << ".\n";
    if (cloud.Upload(kdf_path)) {
        ::unlink((kdf_path + ".pending").c_str());
        std::cout << "Uploaded the new encfs.kdf to the cloud.\n";
    } else {
        std::cout << "Warning: could not upload encfs.kdf; the cloud still has the old one.\n"
                     "It will be uploaded the next time this store is mounted.\n";
    }
    std::cout << "Note: the master key is unchanged, so anyone holding an old copy of encfs.kdf\n"
                 "and the old passphrase can still unlock the store. If the old passphrase was\n"
                 "compromised, also run `encfsctl rekey --passphrase` to replace the key.\n";
    return 0;
}

int Status(const KeyOptions& opts, const std::string& backing_dir) {
    std::vector<uint8_t> master;
    std::string error;
    if (!ResolveMasterKey(opts, backing_dir, false, master, error)) {
        std::cerr << "Error: " << error << "\n";
        return 1;
    }
    EncryptedIndex index(backing_dir, master);
    const std::string key_id = KeyId(master);
    SecureWipe(master);
    if (!index.FileExists() || !index.Load()) {
        std::cerr << "Error: no readable index in " << backing_dir << "\n";
        return 1;
    }

    uint64_t files = 0, dirs = 0, links = 0, bytes = 0, segmented = 0;
    uint64_t objects = 0, cached = 0, cached_bytes = 0, local_files = 0;
    for (const FileMetadata& m : index.AllInodes()) {
        if (m.IsDirectory()) {
            ++dirs;
            continue;
        }
        if (m.IsSymlink()) {
            ++links;
            continue;
        }
        ++files;
        bytes += m.size;
        if (m.segment_size > 0) ++segmented;
        bool all_here = true;
        for (const std::string& id : ObjectIds(m)) {
            ++objects;
            struct stat st;
            if (::stat((backing_dir + "/" + id + ".enc").c_str(), &st) == 0) {
                ++cached;
                cached_bytes += static_cast<uint64_t>(st.st_size);
            } else {
                all_here = false;
            }
        }
        if (all_here) ++local_files;
    }

    auto count_lines = [](const std::string& path) {
        std::vector<uint8_t> data;
        size_t n = 0;
        if (ReadWholeFile(path, data)) {
            for (uint8_t c : data) n += (c == '\n');
        }
        return n;
    };
    const size_t pending = count_lines(backing_dir + "/sync.journal");
    const bool has_synced = Exists(backing_dir + "/synced.list");

    std::cout << "Store:          " << backing_dir << "\n"
              << "Files:          " << files << " in " << dirs << " directories, " << HumanBytes(bytes)
              << (links ? ", plus " + std::to_string(links) + " symbolic link(s)" : std::string()) << "\n"
              << "Stored as:      " << objects << " encrypted object(s)"
              << (segmented ? " (" + std::to_string(segmented) + " large file(s) split into segments)" : std::string())
              << "\n"
              << "Cached locally: " << cached << " of " << objects << " objects, " << HumanBytes(cached_bytes) << "; "
              << local_files << " of " << files << " files entirely local"
              << (cached < objects ? " (the rest are fetched from the cloud when read)" : "") << "\n"
              << "Pending sync:   " << pending << " operation(s)"
              << (pending ? " (finished on the next mount)" : "") << "\n";
    {
        uint64_t base = 0;
        const bool known = LoadSyncedGeneration(backing_dir, &base);
        const uint64_t local = index.generation();
        std::cout << "Index:          generation " << local;
        if (known) {
            std::cout << (local == base ? ", in sync with the cloud"
                                        : ", last synced with the cloud at " + std::to_string(base) +
                                              " (unsynced changes)");
        }
        std::cout << "\n";
    }
    if (has_synced) {
        std::cout << "Confirmed:      " << count_lines(backing_dir + "/synced.list")
                  << " object(s) known to be in the cloud at their current version\n";
    }
    if (opts.use_passphrase) {
        std::vector<uint8_t> raw;
        ReadWholeFile(backing_dir + "/encfs.kdf", raw);
        bool v1 = raw.size() >= 8 && raw[7] == 'F';
        std::cout << "Key:            passphrase (encfs.kdf " << (v1 ? "v1, run `encfsctl passwd` to upgrade" : "v2")
                  << ")\n";
    } else {
        std::cout << "Key:            " << (opts.key_path.empty() ? DefaultKeyPath() : opts.key_path) << "\n";
    }
    std::cout << "Key ID:         " << key_id.substr(0, 8) << "\n";
    if (RekeyInProgress(backing_dir)) {
        std::cout << "Re-key:         unfinished — run `encfsctl rekey` again to complete it\n";
    }
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        Usage();
        return 2;
    }
    const std::string command = argv[1];
    if (command == "-h" || command == "--help" || command == "help") {
        Usage();
        return 0;
    }

    KeyOptions opts;
    std::string cloudcli_cmd = CloudCLIWrapper::DefaultCommand();
    static const struct option long_opts[] = {
        {"key", required_argument, nullptr, 'k'},
        {"passphrase", no_argument, nullptr, 'p'},
        {"cloudcli", required_argument, nullptr, 'c'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    optind = 2;
    int opt;
    while ((opt = getopt_long(argc, argv, "k:pc:h", long_opts, nullptr)) != -1) {
        switch (opt) {
        case 'k': opts.key_path = optarg; break;
        case 'p': opts.use_passphrase = true; break;
        case 'c': cloudcli_cmd = optarg; break;
        case 'h': Usage(); return 0;
        default: Usage(); return 2;
        }
    }
    if (argc - optind != 1) {
        Usage();
        return 2;
    }
    const std::string backing_dir = argv[optind];

    try {
        if (command == "init") return Init(opts, backing_dir);
        if (command == "passwd") return Passwd(cloudcli_cmd, backing_dir);
        if (command == "status") return Status(opts, backing_dir);
        if (command == "rekey") return RunRekey(RekeyOptions{opts, cloudcli_cmd}, backing_dir);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    std::cerr << "Unknown command: " << command << "\n";
    Usage();
    return 2;
}

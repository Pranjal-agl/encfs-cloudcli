// decrypt_by_name — recover a file from a backing directory without mounting.
//
//   decrypt_by_name [options] <backing_dir> <plaintext_name> <output_path|->
//   decrypt_by_name [options] --list <backing_dir>

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
#include <getopt.h>
#include <sys/stat.h>
#include <iostream>
#include <unistd.h>

using namespace encfs;

static void PrintUsage(const char* prog) {
    std::cerr <<
        "Usage: " << prog << " [options] <backing_dir> <plaintext_name> <output_path|->\n"
        "       " << prog << " [options] --list <backing_dir>\n"
        "\n"
        "Options:\n"
        "  -k, --key FILE      key file (default: $ENCFS_KEY_FILE or ~/.encfs/key)\n"
        "  -p, --passphrase    derive the key from a passphrase\n"
        "  -c, --cloudcli CMD  cloudcli used to fetch blobs not cached locally\n"
        "  -l, --list          list the files in the index\n"
        "  -h, --help          show this help\n";
}

static void FetchIfMissing(CloudCLIWrapper& cloud, const std::string& remote_id,
                           const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) == 0) return;
    const std::string tmp = path + ".download";
    if (cloud.Download(remote_id, tmp) && ::rename(tmp.c_str(), path.c_str()) == 0) {
        std::cerr << "Fetched " << remote_id << " from the cloud\n";
    } else {
        ::unlink(tmp.c_str());
    }
}

static bool WriteAllTo(FILE* f, const std::vector<uint8_t>& data) {
    return std::fwrite(data.data(), 1, data.size(), f) == data.size() && std::fflush(f) == 0;
}

int main(int argc, char* argv[]) {
    KeyOptions key_options;
    std::string cloudcli_cmd = CloudCLIWrapper::DefaultCommand();
    bool list = false;

    static const struct option long_opts[] = {
        {"key", required_argument, nullptr, 'k'},
        {"passphrase", no_argument, nullptr, 'p'},
        {"cloudcli", required_argument, nullptr, 'c'},
        {"list", no_argument, nullptr, 'l'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "k:pc:lh", long_opts, nullptr)) != -1) {
        switch (opt) {
        case 'k': key_options.key_path = optarg; break;
        case 'p': key_options.use_passphrase = true; break;
        case 'c': cloudcli_cmd = optarg; break;
        case 'l': list = true; break;
        case 'h': PrintUsage(argv[0]); return 0;
        default: PrintUsage(argv[0]); return 2;
        }
    }
    const int positional = argc - optind;
    if ((list && positional != 1) || (!list && positional != 3)) {
        PrintUsage(argv[0]);
        return 2;
    }

    std::string backing_dir = argv[optind];

    // No local copy (e.g. recovering on a new machine): fetch the index, and
    // the passphrase KDF parameters, from the cloud.
    ::mkdir(backing_dir.c_str(), 0700);  // may not exist yet on a new machine
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

    if (list) {
        auto names = index.GetAllPlaintextNames();
        std::sort(names.begin(), names.end());
        for (const auto& name : names) {
            FileMetadata meta;
            index.GetMetadata(name, meta);
            std::cout << meta.size << "\t" << name << "\n";
        }
        return 0;
    }

    std::string plaintext_name = argv[optind + 1];
    std::string output_path = argv[optind + 2];

    FileMetadata meta;
    if (!index.GetMetadata(plaintext_name, meta)) {
        std::cerr << "File not found in index: " << plaintext_name << "\n";
        return 1;
    }

    std::string blob_path = backing_dir + "/" + meta.remote_id + ".enc";
    std::vector<uint8_t> blob;
    if (!ReadWholeFile(blob_path, blob)) {
        std::string tmp = blob_path + ".download";
        bool fetched = cloudcli.Download(meta.remote_id, tmp) && ReadWholeFile(tmp, blob);
        ::unlink(tmp.c_str());
        if (!fetched && meta.size != 0) {
            std::cerr << "Blob not cached locally and download failed\n";
            return 1;
        }
    }

    FileCodec codec(master_key);
    SecureWipe(master_key);
    std::vector<uint8_t> plaintext;
    if (!blob.empty()) {
        switch (codec.Decrypt(blob, meta.remote_id, meta.version, plaintext, nullptr)) {
        case FileCodec::Result::kOk:
            break;
        case FileCodec::Result::kRollback:
            std::cerr << "Decryption refused: blob is an older version than the index expects\n";
            return 1;
        default:
            std::cerr << "Decryption failed: blob is corrupt, tampered with, or for another file\n";
            return 1;
        }
    }

    bool ok;
    if (output_path == "-") {
        ok = WriteAllTo(stdout, plaintext);
    } else {
        ok = WriteFileAtomic(output_path, plaintext, 0600);
    }
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

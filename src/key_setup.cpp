#include "key_setup.h"
#include "crypto.h"
#include "index.h"
#include "util.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

namespace encfs {

namespace {

const uint8_t kKdfMagic[8] = {'E', 'N', 'C', 'F', 'S', 'K', 'D', 'F'};
constexpr size_t kKdfSaltSize = 16;
constexpr uint32_t kDefaultIterations = 600000;  // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
constexpr uint32_t kMinIterations = 10000;
// encfs.kdf can come from the cloud: cap the work factor it can demand so a
// corrupted or malicious file can't make mounting hang for hours.
constexpr uint32_t kMaxIterations = 50'000'000;

struct KdfParams {
    uint32_t iterations = kDefaultIterations;
    std::vector<uint8_t> salt;
};

// <backing_dir>/encfs.kdf: "ENCFSKDF" | iterations:u32le | salt[16]
bool LoadKdfParams(const std::string& path, KdfParams& params, std::string& error) {
    std::vector<uint8_t> data;
    if (!ReadWholeFile(path, data)) {
        error = "cannot read " + path + ": " + std::strerror(errno);
        return false;
    }
    if (data.size() != sizeof(kKdfMagic) + 4 + kKdfSaltSize ||
        std::memcmp(data.data(), kKdfMagic, sizeof(kKdfMagic)) != 0) {
        error = path + " is not a valid KDF parameter file";
        return false;
    }
    params.iterations = LoadU32LE(data.data() + sizeof(kKdfMagic));
    if (params.iterations < kMinIterations || params.iterations > kMaxIterations) {
        error = path + " specifies an unreasonable PBKDF2 iteration count (" +
                std::to_string(params.iterations) + ")";
        return false;
    }
    params.salt.assign(data.begin() + sizeof(kKdfMagic) + 4, data.end());
    return true;
}

bool SaveKdfParams(const std::string& path, const KdfParams& params) {
    std::vector<uint8_t> data(kKdfMagic, kKdfMagic + sizeof(kKdfMagic));
    AppendU32LE(data, params.iterations);
    data.insert(data.end(), params.salt.begin(), params.salt.end());
    return WriteFileAtomic(path, data, 0644);
}

// Read one line from the controlling terminal with echo disabled.
bool PromptHidden(const std::string& prompt, std::string& out) {
    int fd = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (fd < 0) return false;

    struct termios old_attr;
    bool have_attr = tcgetattr(fd, &old_attr) == 0;
    if (have_attr) {
        struct termios quiet = old_attr;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(fd, TCSAFLUSH, &quiet);
    }
    ssize_t ignored = ::write(fd, prompt.data(), prompt.size());
    (void)ignored;

    std::string line;
    char c;
    bool ok = false;
    for (;;) {
        ssize_t n = ::read(fd, &c, 1);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (c == '\n' || c == '\r') { ok = true; break; }
        line += c;
    }

    if (have_attr) tcsetattr(fd, TCSAFLUSH, &old_attr);
    ignored = ::write(fd, "\n", 1);
    ::close(fd);

    if (ok) out.swap(line);
    SecureWipe(line);
    return ok;
}

bool GetPassphrase(bool confirm, std::string& passphrase, std::string& error) {
    if (const char* env = std::getenv("ENCFS_PASSPHRASE")) {
        passphrase = env;
    } else {
        if (!PromptHidden("Passphrase: ", passphrase)) {
            error = "no passphrase: set ENCFS_PASSPHRASE or run from a terminal";
            return false;
        }
        if (confirm) {
            std::string again;
            bool same = PromptHidden("Confirm passphrase: ", again) && again == passphrase;
            SecureWipe(again);
            if (!same) {
                SecureWipe(passphrase);
                error = "passphrases do not match";
                return false;
            }
        }
    }
    if (passphrase.empty()) {
        error = "passphrase must not be empty";
        return false;
    }
    return true;
}

bool KeyFromPassphrase(const std::string& backing_dir, bool allow_create,
                       std::vector<uint8_t>& key, std::string& error) {
    std::string kdf_path = backing_dir + "/encfs.kdf";
    KdfParams params;
    bool creating = false;

    struct stat st;
    if (::stat(kdf_path.c_str(), &st) == 0) {
        if (!LoadKdfParams(kdf_path, params, error)) return false;
    } else if (!allow_create) {
        error = "no " + kdf_path + " — this backing directory was not set up with --passphrase";
        return false;
    } else {
        params.salt = KeyManager::RandomBytes(kKdfSaltSize);
        creating = true;
    }

    std::string passphrase;
    if (!GetPassphrase(creating, passphrase, error)) return false;
    key = KeyManager::DeriveKeyFromPassphrase(passphrase, params.salt,
                                              static_cast<int>(params.iterations));
    SecureWipe(passphrase);

    if (creating && !SaveKdfParams(kdf_path, params)) {
        error = "cannot write " + kdf_path + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

void WarnIfKeyFileExposed(const std::string& path) {
    struct stat st;
    if (::stat(path.c_str(), &st) == 0 && (st.st_mode & 077) != 0) {
        std::cerr << "Warning: key file " << path << " is accessible by other users; "
                  << "run: chmod 600 " << path << "\n";
    }
}

bool IndexOpensWith(const std::string& backing_dir, const std::vector<uint8_t>& key) {
    EncryptedIndex probe(backing_dir, key);
    return probe.Load();
}

} // namespace

std::string DefaultKeyPath() {
    if (const char* env = std::getenv("ENCFS_KEY_FILE")) {
        if (*env) return env;
    }
    const char* home = std::getenv("HOME");
    return std::string(home ? home : ".") + "/.encfs/key";
}

bool ResolveMasterKey(const KeyOptions& options,
                      const std::string& backing_dir,
                      bool allow_create,
                      std::vector<uint8_t>& master_key,
                      std::string& error) {
    EncryptedIndex index_probe(backing_dir, {});
    const bool have_index = index_probe.FileExists();

    try {
        if (options.use_passphrase) {
            std::vector<uint8_t> key;
            if (!KeyFromPassphrase(backing_dir, allow_create, key, error)) return false;
            if (have_index && !IndexOpensWith(backing_dir, key)) {
                SecureWipe(key);
                error = "wrong passphrase (cannot decrypt " + index_probe.path() + ")";
                return false;
            }
            master_key.swap(key);
            return true;
        }

        const std::string path = options.key_path.empty() ? DefaultKeyPath() : options.key_path;
        WarnIfKeyFileExposed(path);

        std::vector<uint8_t> key;
        std::string parse_error;
        try {
            key = KeyManager::LoadKeyFromFile(path);
        } catch (const std::exception& e) {
            parse_error = e.what();
        }

        if (!have_index) {
            if (key.empty()) {
                error = parse_error;
                return false;
            }
            master_key.swap(key);
            return true;
        }

        if (!key.empty() && IndexOpensWith(backing_dir, key)) {
            master_key.swap(key);
            return true;
        }

        // Older versions used the first 32 bytes of the key file verbatim, so a
        // hex key file contributed only 128 bits. Accept it for existing data.
        std::vector<uint8_t> legacy;
        try {
            legacy = KeyManager::LoadLegacyKeyFromFile(path);
        } catch (const std::exception&) {
        }
        if (!legacy.empty() && legacy != key && IndexOpensWith(backing_dir, legacy)) {
            SecureWipe(key);
            std::cerr << "Warning: this backing directory was created by an older version that "
                         "used the hex text of the key file directly (only 128-bit strength).\n"
                         "         It still works, but consider copying your files into a new "
                         "backing directory to upgrade.\n";
            master_key.swap(legacy);
            return true;
        }

        SecureWipe(key);
        SecureWipe(legacy);
        error = parse_error.empty()
                    ? "key in " + path + " cannot decrypt " + index_probe.path() +
                          " (wrong key, or the index is corrupt). Refusing to continue so the "
                          "existing index is not overwritten."
                    : parse_error;
        return false;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

} // namespace encfs

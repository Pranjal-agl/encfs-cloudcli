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

// <backing_dir>/encfs.kdf, two versions:
//
//   v1 "ENCFSKDF" | iterations:u32le | salt[16]
//      master key = PBKDF2(passphrase, salt). Changing the passphrase would
//      change the key, so it couldn't be changed.
//   v2 "ENCFSKD2" | iterations:u32le | salt[16] | wrapped[60]
//      master key is random; wrapped = AES-256-GCM(KEK, master) with
//      KEK = PBKDF2(passphrase, salt) and the first 28 bytes as AAD.
//      Changing the passphrase just re-wraps the same master key, and a wrong
//      passphrase is detected even before any index exists.
const uint8_t kKdfMagicV1[8] = {'E', 'N', 'C', 'F', 'S', 'K', 'D', 'F'};
const uint8_t kKdfMagicV2[8] = {'E', 'N', 'C', 'F', 'S', 'K', 'D', '2'};
constexpr size_t kKdfSaltSize = 16;
constexpr size_t kKdfHeaderSize = 8 + 4 + kKdfSaltSize;
constexpr size_t kWrappedSize = 12 + kKeySize + 16;
constexpr uint32_t kDefaultIterations = 600000;  // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
constexpr uint32_t kMinIterations = 10000;
// encfs.kdf can come from the cloud: cap the work factor it can demand so a
// corrupted or malicious file can't make mounting hang for hours.
constexpr uint32_t kMaxIterations = 50'000'000;

struct KdfFile {
    int version = 2;
    uint32_t iterations = kDefaultIterations;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> header;   // the authenticated first 28 bytes (v2)
    std::vector<uint8_t> wrapped;  // v2 only
};

std::string KdfPath(const std::string& backing_dir) { return backing_dir + "/encfs.kdf"; }

bool LoadKdf(const std::string& path, KdfFile& kdf, std::string& error) {
    std::vector<uint8_t> data;
    if (!ReadWholeFile(path, data)) {
        error = "cannot read " + path + ": " + std::strerror(errno);
        return false;
    }
    if (data.size() == kKdfHeaderSize && std::memcmp(data.data(), kKdfMagicV1, 8) == 0) {
        kdf.version = 1;
    } else if (data.size() == kKdfHeaderSize + kWrappedSize &&
               std::memcmp(data.data(), kKdfMagicV2, 8) == 0) {
        kdf.version = 2;
        kdf.wrapped.assign(data.begin() + kKdfHeaderSize, data.end());
    } else {
        error = path + " is not a valid KDF parameter file";
        return false;
    }
    kdf.iterations = LoadU32LE(data.data() + 8);
    if (kdf.iterations < kMinIterations || kdf.iterations > kMaxIterations) {
        error = path + " specifies an unreasonable PBKDF2 iteration count (" +
                std::to_string(kdf.iterations) + ")";
        return false;
    }
    kdf.salt.assign(data.begin() + 12, data.begin() + kKdfHeaderSize);
    kdf.header.assign(data.begin(), data.begin() + kKdfHeaderSize);
    return true;
}

// Write a v2 file wrapping `master` under `passphrase` (fresh salt).
bool WriteWrappedKdf(const std::string& path, const std::vector<uint8_t>& master,
                     const std::string& passphrase, std::string& error) {
    std::vector<uint8_t> header(kKdfMagicV2, kKdfMagicV2 + 8);
    AppendU32LE(header, kDefaultIterations);
    std::vector<uint8_t> salt = KeyManager::RandomBytes(kKdfSaltSize);
    header.insert(header.end(), salt.begin(), salt.end());

    std::vector<uint8_t> kek = KeyManager::DeriveKeyFromPassphrase(passphrase, salt, kDefaultIterations);
    std::vector<uint8_t> wrapped = SimpleCrypto::Encrypt(master, kek, header);
    SecureWipe(kek);

    std::vector<uint8_t> data = header;
    data.insert(data.end(), wrapped.begin(), wrapped.end());
    if (!WriteFileAtomic(path, data, 0644)) {  // not secret without the passphrase
        error = "cannot write " + path + ": " + std::strerror(errno);
        return false;
    }
    return true;
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

} // namespace

bool ReadPassphrase(const char* env_var, const std::string& prompt, bool confirm,
                    std::string& passphrase, std::string& error) {
    if (const char* env = std::getenv(env_var)) {
        passphrase = env;
    } else {
        if (!PromptHidden(prompt + ": ", passphrase)) {
            error = std::string("no passphrase: set ") + env_var + " or run from a terminal";
            return false;
        }
        if (confirm) {
            std::string again;
            bool same = PromptHidden("Confirm " + prompt + ": ", again) && again == passphrase;
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

bool PassphraseStoreExists(const std::string& backing_dir) {
    struct stat st;
    return ::stat(KdfPath(backing_dir).c_str(), &st) == 0;
}

bool CreatePassphraseStore(const std::string& backing_dir, const std::string& passphrase,
                           std::vector<uint8_t>& master, std::string& error) {
    if (PassphraseStoreExists(backing_dir)) {
        error = KdfPath(backing_dir) + " already exists";
        return false;
    }
    std::vector<uint8_t> key = KeyManager::RandomBytes(kKeySize);
    if (!WriteWrappedKdf(KdfPath(backing_dir), key, passphrase, error)) return false;
    master.swap(key);
    return true;
}

bool UnlockPassphraseStore(const std::string& backing_dir, const std::string& passphrase,
                           std::vector<uint8_t>& master, std::string& error, int* kdf_version) {
    KdfFile kdf;
    if (!LoadKdf(KdfPath(backing_dir), kdf, error)) return false;
    if (kdf_version) *kdf_version = kdf.version;
    std::vector<uint8_t> derived = KeyManager::DeriveKeyFromPassphrase(
        passphrase, kdf.salt, static_cast<int>(kdf.iterations));
    if (kdf.version == 1) {
        master.swap(derived);  // v1: the derived key is the master key
        return true;
    }
    try {
        std::vector<uint8_t> key = SimpleCrypto::Decrypt(kdf.wrapped, derived, kdf.header);
        SecureWipe(derived);
        if (key.size() != kKeySize) throw std::runtime_error("bad key size");
        master.swap(key);
        return true;
    } catch (const std::exception&) {
        SecureWipe(derived);
        error = "wrong passphrase";
        return false;
    }
}

bool RewrapPassphraseStore(const std::string& backing_dir, const std::vector<uint8_t>& master,
                           const std::string& new_passphrase, std::string& error) {
    return WriteWrappedKdf(KdfPath(backing_dir), master, new_passphrase, error);
}

namespace {

bool KeyFromPassphrase(const std::string& backing_dir, bool allow_create,
                       std::vector<uint8_t>& key, std::string& error) {
    const bool exists = PassphraseStoreExists(backing_dir);
    if (!exists && !allow_create) {
        error = "no " + KdfPath(backing_dir) + " — this backing directory was not set up with --passphrase";
        return false;
    }
    std::string passphrase;
    if (!ReadPassphrase("ENCFS_PASSPHRASE", "Passphrase", /*confirm=*/!exists, passphrase, error)) {
        return false;
    }
    bool ok = exists ? UnlockPassphraseStore(backing_dir, passphrase, key, error)
                     : CreatePassphraseStore(backing_dir, passphrase, key, error);
    SecureWipe(passphrase);
    return ok;
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

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace encfs {

struct KeyOptions {
    // Path to a key file. Empty → $ENCFS_KEY_FILE, else ~/.encfs/key.
    std::string key_path;
    // Derive the key from a passphrase instead of reading a key file. The
    // passphrase comes from $ENCFS_PASSPHRASE or an interactive prompt; the
    // PBKDF2 salt and iteration count live in <backing_dir>/encfs.kdf.
    bool use_passphrase = false;
};

// Default key file location ($ENCFS_KEY_FILE or ~/.encfs/key).
std::string DefaultKeyPath();

// Work out the master key for `backing_dir`.
//
// If the backing directory already has an index, the key must decrypt it —
// otherwise we refuse, instead of silently starting with an empty index and
// overwriting the real one on the next save. Key files written for older
// versions (which used the hex text itself as key material) are detected and
// still accepted, with a warning.
//
// `allow_create` permits creating a new KDF salt file for passphrase mode.
// Returns false and fills `error` on failure. Warnings go to stderr.
bool ResolveMasterKey(const KeyOptions& options,
                      const std::string& backing_dir,
                      bool allow_create,
                      std::vector<uint8_t>& master_key,
                      std::string& error);

} // namespace encfs

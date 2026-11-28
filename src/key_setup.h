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

// ── Passphrase-protected stores ─────────────────────────────────────────────
// <backing_dir>/encfs.kdf. Version 2 (written by everything new) stores a
// random master key wrapped with a passphrase-derived key, so the passphrase
// can be changed without re-encrypting anything. Version 1 files (master key
// derived directly from the passphrase) are still read, and RewrapPassphraseStore
// upgrades them in place.

// Read a passphrase from `env_var`, or prompt on the terminal (twice if
// `confirm`). Returns false with `error` set on failure or empty input.
bool ReadPassphrase(const char* env_var, const std::string& prompt, bool confirm,
                    std::string& passphrase, std::string& error);

bool PassphraseStoreExists(const std::string& backing_dir);

// Create encfs.kdf (v2) around a new random master key.
bool CreatePassphraseStore(const std::string& backing_dir, const std::string& passphrase,
                           std::vector<uint8_t>& master, std::string& error);

// Recover the master key. Fails with "wrong passphrase" for v2 files.
// (v1 files can't tell; ResolveMasterKey checks those against the index.)
bool UnlockPassphraseStore(const std::string& backing_dir, const std::string& passphrase,
                           std::vector<uint8_t>& master, std::string& error,
                           int* kdf_version = nullptr);

// Creating or re-wrapping encfs.kdf also writes encfs.kdf.pending: the file
// changed here and must be uploaded. Whoever uploads it removes the marker.

// Replace encfs.kdf with a v2 file wrapping `master` under `new_passphrase`.
bool RewrapPassphraseStore(const std::string& backing_dir, const std::vector<uint8_t>& master,
                           const std::string& new_passphrase, std::string& error);

} // namespace encfs

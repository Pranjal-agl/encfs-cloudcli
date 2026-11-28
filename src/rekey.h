#pragma once

#include "key_setup.h"

#include <cstdint>
#include <string>
#include <vector>

namespace encfs {

class CloudCLIWrapper;

// ── Key IDs ─────────────────────────────────────────────────────────────────
// A public fingerprint of a master key: the first 16 bytes of
// HMAC-SHA256(key, "encfs-key-id-v1"), in hex. It reveals nothing about the
// key. Each backing directory keeps the ID of the key its index is encrypted
// with in `encfs.keyid`, and the cloud holds the current one under the same
// name, so a machine can tell that the store was re-keyed elsewhere even when
// its own key can't decrypt anything any more.
extern const char kKeyIdObject[];  // "encfs.keyid"
std::string KeyId(const std::vector<uint8_t>& master);
std::string KeyIdPath(const std::string& backing_dir);
bool ReadKeyId(const std::string& path, std::string* id);
bool WriteKeyId(const std::string& path, const std::string& id);
// The cloud's key ID. False if absent, unreachable or malformed.
bool FetchCloudKeyId(CloudCLIWrapper& cloud, const std::string& backing_dir, std::string* id);

// ── Re-keyed on another machine ─────────────────────────────────────────────
// Move this machine's copy of the store (index, data objects, encfs.kdf and
// sync bookkeeping) into a new subdirectory <backing_dir>/rekeyed-<id>-<time>,
// which stays a complete backing directory for the old key: nothing is
// deleted. Returns that path, or "" on failure.
std::string SetAsideForRekey(const std::string& backing_dir, const std::string& old_key_id);

// ── encfsctl rekey ──────────────────────────────────────────────────────────
// Re-encrypts every file under a new random master key, so a leaked key (or
// passphrase-wrapped key) no longer opens the store. The work is staged in
// <backing_dir>/rekey/ and is resumable: running it again after a crash or a
// cloud failure finishes the job. Mounting is refused while it's unfinished.
std::string RekeyStagingDir(const std::string& backing_dir);
bool RekeyInProgress(const std::string& backing_dir);

struct RekeyOptions {
    KeyOptions key;        // how the store is unlocked today
    std::string cloudcli;  // cloudcli command
};

// Returns a process exit status. Progress and errors go to stdout/stderr.
int RunRekey(const RekeyOptions& options, const std::string& backing_dir);

} // namespace encfs

# encfs-cloudcli

A FUSE-based encrypted filesystem written in C++17. Files written to the mount point are transparently encrypted with **AES-256-GCM** and synced to cloud storage via `cloudcli`. Plaintext never touches the backing directory or the network.

Built as a systems programming project to explore FUSE internals, OpenSSL cryptography, and concurrent C++.

---

## Features

- **Transparent, authenticated encryption** — AES-256-GCM, with a fresh per-file key for every write
- **Tamper-evident chunked format** — large files are split into 8 MiB chunks bound to their position, so chunks can't be reordered, dropped, duplicated or spliced between files
- **Blobs bound to their file and version** — swapping two files' blobs, or serving an old copy of a file (rollback), is detected
- **Filename privacy** — plaintext names never leave the machine; blobs are named by an HMAC-SHA256 of the name
- **Encrypted index** — the local name ↔ remote-ID mapping is itself AES-GCM encrypted
- **Background sync** — uploads and deletes run in a worker thread with retries and exponential back-off; redundant operations are coalesced
- **Crash-safe** — all writes are atomic (temp file + `fsync` + `rename`), and unfinished cloud operations are journaled and resumed on the next mount
- **On-demand downloads** — blobs are fetched from the cloud only when read, and verified before being cached
- **Restore anywhere** — the encrypted index is synced too, so your key (or passphrase) plus the cloud is enough to mount your files on a new machine
- **Key flexibility** — hex or raw key file, or a passphrase (PBKDF2-HMAC-SHA256, 600k iterations)
- **Works with everyday tools** — append, partial overwrite, truncate, `mv`, `touch`, `cp -p`, `rsync`, `df`

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              FUSE Mount Point               │
│         (plaintext read/write API)          │
└────────────────────┬────────────────────────┘
                     │ FUSE3 kernel interface
┌────────────────────▼────────────────────────┐
│           encrypted_cloudfs.cpp             │
│  getattr readdir open create read write     │
│  truncate flush fsync release unlink rename │
│  utimens chmod chown statfs                 │
│  (shared per-file buffers, one big lock)    │
└──────┬──────────────┬───────────────┬───────┘
       │              │               │
┌──────▼───────┐ ┌────▼───────┐ ┌─────▼────────────┐
│file_codec.cpp│ │ index.cpp  │ │cloudcli_wrapper  │
│ key derivation│ │ encrypted  │ │ worker thread,   │
│ blob ⇄ file   │ │ name→ID map│ │ retries, journal │
├──────────────┤ └────────────┘ └─────┬────────────┘
│  crypto.cpp  │                      │ posix_spawn (no shell)
│ AES-256-GCM  │              ┌───────▼───────┐
│ HMAC, PBKDF2 │              │   cloudcli    │
└──────────────┘              └───────────────┘
```

`key_setup.cpp` (key files / passphrases) and `util.cpp` (atomic file writes, little-endian encoding) are shared by the filesystem and the `decrypt_by_name` tool.

### Keys

Everything is derived from one 32-byte master key with HMAC-SHA256, so the master key is never used directly by two algorithms:

| Key | Derivation | Used for |
|---|---|---|
| filename key | `HMAC(master, "encfs_filename_hmac")` | remote ID = `HMAC(filename key, name)` |
| index key | `HMAC(master, "encfs_index_key_derivation")` | encrypting `index.enc` |
| content key | `HMAC(master, "encfs_content_key_v2")` | parent of the per-file keys |
| per-file key | `HMAC(content key, "encfs-v2-chunk-key" ‖ salt)` | encrypting one blob |

### Blob format (v2)

```
header (42 B):  "ENCFS" | 0x02 | chunk_size:u32le | salt:32
chunk i:        len:u32le | ciphertext[len] | tag:16
```

- Every blob has a random 32-byte salt and therefore its own AES key, so nonces can never collide across files.
- Chunk `i` uses nonce `0⁷ ‖ i:u32be ‖ last_flag` (the STREAM construction). Changing the order, dropping chunks or appending chunks all fail authentication.
- Every chunk authenticates `header ‖ "encfs-file-v2" ‖ remote_id ‖ version` as AAD, tying the blob to one file and one version.
- An empty file is still one (empty) authenticated chunk.
- All integers are little-endian, regardless of host.

Blobs written by v1 are still readable and are rewritten as v2 the next time the file is modified.

### Index format

`index.enc` holds, per file: plaintext name, remote ID, version counter, size and mtime. It is serialized little-endian, then encrypted with AES-256-GCM under the index key. After every change it is also uploaded to the cloud as the object `index` (still encrypted), and in passphrase mode the non-secret KDF parameters are uploaded as `encfs.kdf`.

### Restoring on a new machine

When you mount and the backing directory has no `index.enc`, it is downloaded from the cloud first, so pointing a fresh, empty backing directory at the same cloud with the same key restores everything. Blobs are then fetched as files are opened. `decrypt_by_name` does the same.

If no index can be downloaded, the mount starts a new, empty filesystem. If that was only because the cloud was briefly unreachable, the first write checks the cloud again before uploading anything. If an index turns up there, the write fails with `EROFS`, writes stay disabled, and the local fresh index is discarded, so the real index is never overwritten. Remount to restore it.

### Rollback detection

Every write increments the file's version in the index and binds the new version into the blob. When a blob is read:

- matching version: accepted;
- one version *ahead* of the index: accepted, and the index is repaired (this means we crashed after writing the blob but before saving the index);
- an older version of the same file: rejected as a rollback (for example a stale copy served by the cloud);
- anything else: rejected as corrupt or tampered.

---

## Building

### Prerequisites

```bash
sudo apt-get install build-essential cmake libfuse3-dev libssl-dev pkg-config fuse3
```

### Build

```bash
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

| Binary | Description |
|---|---|
| `encrypted_cloudfs` | The FUSE filesystem |
| `decrypt_by_name` | List or recover files from a backing directory without mounting |
| `test_crypto`, `test_index`, `test_integration` | Test suites |

CMake options: `-DENCFS_WERROR=ON` (warnings are errors), `-DENCFS_SANITIZE=ON` (ASan + UBSan), `-DENCFS_E2E=ON` (registers the FUSE end-to-end test).

---

## Usage

```bash
# Generate a key (either format works)
mkdir -p ~/.encfs && (umask 077 && openssl rand -hex 32 > ~/.encfs/key)

mkdir -p ~/enc_mount ~/enc_backing
./build/encrypted_cloudfs ~/enc_mount ~/enc_backing        # stays in the foreground
#   or: ./build/encrypted_cloudfs --background ~/enc_mount ~/enc_backing

echo "secret" > ~/enc_mount/notes.txt
cat ~/enc_mount/notes.txt    # → secret

fusermount3 -u ~/enc_mount   # waits for pending uploads to finish
```

```
encrypted_cloudfs [options] <mountpoint> <backing_dir> [-- <fuse options>]

  -k, --key FILE      key file: 64 hex chars or 32 raw bytes
                      (default: $ENCFS_KEY_FILE or ~/.encfs/key)
  -p, --passphrase    derive the key from a passphrase ($ENCFS_PASSPHRASE, or prompt)
  -c, --cloudcli CMD  cloudcli executable (default: $ENCFS_CLOUDCLI or cloudcli)
  -b, --background    detach from the terminal once mounted
  -d, --debug         print FUSE debug output
```

If the backing directory already has an index, the key must be able to decrypt it. Otherwise the filesystem refuses to mount, so a wrong key can't overwrite your index.

### Recovering files without mounting

```bash
./build/decrypt_by_name --list ~/enc_backing              # size and name of every file
./build/decrypt_by_name ~/enc_backing notes.txt out.txt   # or "-" for stdout
```

### Testing locally with cloudcli_stub

```bash
export ENCFS_STUB_STORE=/tmp/fake-cloud   # default: ~/.encfs_stub_store
./build/encrypted_cloudfs -c "$PWD/tools/cloudcli_stub" ~/enc_mount ~/enc_backing
```

Set `ENCFS_STUB_FAIL=1` to make the stub fail every command, which is useful for exercising retries and the sync journal.

---

## Tests

```bash
ctest --test-dir build --output-on-failure      # unit + integration
./run_and_prove.sh                              # build, all tests incl. FUSE e2e, live demo
```

- **test_crypto**: RFC 4231 HMAC vector; round trips at every chunk boundary; a single-bit flip at *every* byte position of a blob; truncation, extension, reordering, cross-file splicing and header grafting; streaming ↔ in-memory interoperability; v1 compatibility.
- **test_index**: persistence, wrong key/corruption handling (state left untouched), on-disk format stability, unusual filenames.
- **test_integration**: blob ↔ file/version binding, key resolution (hex, raw, legacy, wrong key, passphrase), the cloudcli wrapper against the stub (including shell-metacharacter paths), queue coalescing, retries and journal recovery.
- **tests/e2e/run_e2e.sh**: mounts the real filesystem and drives it with `echo`, `cat`, `dd`, `truncate`, `mv`, `cp -p`, `touch -d`. Also checks that the cloud matches the backing dir after unmount, that evicted blobs are re-downloaded, and that tampered or swapped blobs and wrong keys are rejected.

CI runs everything, including the FUSE tests, in Release and in ASan/UBSan builds, and lints the shell scripts with shellcheck.

---

## Security notes

- Keep the key file at mode `0600`; the tools warn if it's readable by others.
- Plaintext filenames and contents never appear in cloud storage or the backing directory.
- What *is* visible to the cloud: the number of files, their approximate sizes, and when they change.
- Remote IDs are deterministic per name, so re-creating a deleted file with the same name reuses its remote ID. This is what lets you recover a file by name without the index.
- Key material and decrypted buffers are wiped (`OPENSSL_cleanse`) when no longer needed.

## Limitations

- **Flat namespace**: there are no subdirectories.
- **Whole-file buffering**: an open file is held in memory (capped at 4 GiB per file), and each save re-encrypts the whole file.
- **Single writer**: don't mount the same cloud store from two machines at once. Each machine's index would overwrite the other's.
- **Permissions aren't stored**: everything belongs to the mounting user. `chmod`/`chown` are accepted but ignored.
- **Rename isn't atomic across a crash**: it re-encrypts the file under the new name's ID before removing the old one, so a crash mid-rename can leave both copies.

### Upgrading from v1

v2 reads everything v1 wrote. One difference: v1 used the first 32 *characters* of a hex key file as the key (128 bits of entropy), whereas v2 decodes the hex properly (256 bits). Backing directories created by v1 are detected and still open, with a warning. To upgrade one, mount it, copy the files out, and copy them into a fresh backing directory.

---

## Roadmap

- Subdirectory support (the namespace is currently flat)
- Chunk-level reads and writes, so large files aren't buffered whole
- Optional filename padding to hide size/length patterns

---

## Changelog

### v2.1 — restore from the cloud

- The encrypted index (and, in passphrase mode, the KDF parameters) is uploaded after every change.
- Mounting, or running `decrypt_by_name`, with an empty backing directory restores from the cloud.
- A guard stops a new filesystem from overwriting an existing cloud index when the download at mount time failed.
- New end-to-end tests: full restore from the cloud, the overwrite guard, and recovery with `decrypt_by_name`.

### v2.0 — review and hardening

| Area | Problem | Fix |
|---|---|---|
| Data loss | Appending (`>>`) or writing part of an existing file replaced it with zeros plus the new bytes, because writes went into an empty buffer | Files are loaded on open; all handles to a file share one buffer |
| Data loss | Mounting with the wrong key "started with an empty index" and overwrote the real one on the next save | Refuse to mount unless the key decrypts the existing index |
| Data loss | Unmounting discarded queued uploads | The worker drains the queue on unmount; unfinished work is journaled and resumed |
| Correctness | `: > file` didn't truncate; empty files couldn't be read (EIO); `O_RDWR` reads ignored pending writes | Proper truncate/empty-file handling with shared buffers |
| Correctness | `mv`, `touch`, `cp -p`, `df`, `fsync` failed with ENOSYS | Added rename, utimens, chmod/chown, statfs, flush/fsync |
| Correctness | Files appeared to be owned by root | Report the mounting user's uid/gid |
| Security | `openssl rand -hex 32`, as documented, produced a 128-bit key (hex text used as raw bytes) | Hex key files are decoded; v1 directories detected for compatibility |
| Security | Chunk count and chunk order weren't authenticated: chunks could be dropped, reordered or spliced between files | STREAM-style nonces with a final-chunk flag, header in the AAD, per-file keys |
| Security | Blobs could be swapped between files; README claimed rollback detection that didn't exist | Blobs are bound to (remote ID, version), and version checks run on read |
| Security | Master key used directly for AES and as the HMAC key for derivation | Domain-separated sub-keys |
| Security | cloudcli was run through `system()` and the shell | `posix_spawnp` with an argument vector |
| Robustness | Exceptions (e.g. `bad_alloc`) could escape into libfuse and abort | Every callback converts exceptions to errno |
| Robustness | Unsynced writes; host-endian, `size_t`-width on-disk integers | `fsync` + atomic rename; explicit little-endian `u64` |
| Robustness | Background mode lost the uploader thread (started before `fork`) and relative paths broke after `chdir("/")` | Start the worker in `init`; absolute paths |
| Performance | Every `read()` decrypted the whole file (O(n²) for `cat` of a large file) | Decrypt once per open file |
| Performance | Unlinks blocked on a synchronous cloud delete | Deletes are queued; repeated saves are coalesced |
| Tests | Tests used `assert` (compiled out under `-DNDEBUG`); the stub test was silently skipped under ctest | `CHECK` macros; fixed stub path; tamper and e2e suites |
| Tooling | `run_and_prove.sh` overwrote `~/.encfs/key` and deleted `~/enc_*` | Runs entirely in a temp dir |
| Feature | Passphrase mode was documented but not wired up | `--passphrase` with a stored salt and iteration count |

### v1.0 — bugs fixed during initial development

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | `crypto.cpp` | `#include <openssl/pkcs5.h>`: the header was removed in OpenSSL 3, and `PKCS5_PBKDF2_HMAC` now lives in `evp.h` | Removed the stale include |
| 2 | `crypto.h` | `std::function<>` used without `#include <functional>` | Added the missing include |
| 3 | `crypto.cpp` | `HMAC(...)` resolved to the `encfs::HMAC` class instead of OpenSSL's function | Called `::HMAC(...)` |
| 4 | `crypto.cpp` | `tag.data()` called on a raw pointer in `DecryptChunk` | Passed the pointer directly |
| 5 | `encrypted_cloudfs.cpp` | `encfs_release` called `.unlock()`/`.lock()` on a `std::lock_guard`, causing a `std::system_error` deadlock | Copied the handle data out under the lock and did the I/O lock-free |

The `fuse_operations` struct also used C++20-style out-of-order designated initializers. That was replaced with `memset` plus explicit field assignments.

---

## License

MIT — see [LICENSE](LICENSE)

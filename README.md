# encfs-cloudcli

A FUSE-based encrypted filesystem written in C++17. Files written to the mount point are transparently encrypted with **AES-256-GCM** and synced to cloud storage via `cloudcli`. Plaintext never touches the backing directory or the network.

Built as a systems programming project to explore FUSE internals, OpenSSL cryptography, and concurrent C++.

**[Try it in your browser](https://pranjal-agl.github.io/encfs-cloudcli/)** Watch a file get encrypted byte by byte, try to forge it, or recover files from a backing folder without installing anything. Everything runs locally, and the page is technically unable to make network requests.

---

## Features

- **Transparent, authenticated encryption** — AES-256-GCM, with a fresh per-file key for every write
- **Tamper-evident chunked format** — files are split into 1 MiB chunks bound to their position, so chunks can't be reordered, dropped, duplicated or spliced between files
- **Blobs bound to their file and version** — swapping two files' blobs, or serving an old copy of a file (rollback), is detected
- **Filename privacy** — plaintext names never leave the machine; blobs are named by an HMAC-SHA256 of the name
- **Encrypted index** — the local name ↔ remote-ID mapping is itself AES-GCM encrypted
- **Background sync** — uploads and deletes run in a worker thread with retries and exponential back-off; redundant operations are coalesced
- **Crash-safe** — all writes are atomic (temp file + `fsync` + `rename`), and unfinished cloud operations are journaled and resumed on the next mount
- **Constant memory, any file size** — reads decrypt only the chunks they touch, and writes keep only a few chunks in RAM. Copying in a 1 GB file peaks at 21 MB, where buffering it whole took about 2 GB.
- **Concurrent** — FUSE runs multi-threaded with per-file locking, so a slow download of one file doesn't stall `ls`, other reads or other writes
- **Bounded local cache** — with `--cache-size 20G` the backing directory becomes a cache. Blobs the cloud provably holds at their current version are evicted least-recently-used first, and nothing is evicted while an upload is pending.
- **On-demand downloads** — blobs are fetched from the cloud only when read, and verified before being cached
- **Restore anywhere** — the encrypted index is synced too, so your key (or passphrase) plus the cloud is enough to mount your files on a new machine
- **Key flexibility** — a key file, or a passphrase that wraps a random master key (PBKDF2-HMAC-SHA256, 600k iterations). The passphrase can be changed without re-encrypting anything.
- **A real POSIX namespace** — directories, hard links, symbolic links and stored permission bits. Renames, including whole directories and `RENAME_EXCHANGE`, are atomic and instant because they only touch the index.
- **Works with everyday tools** — append, partial overwrite, truncate, `mv`, `touch`, `cp -rp`, `tar`, `rsync -a`, `find`, `df`

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
│  mkdir rmdir                                │
│  utimens chmod chown statfs                 │
│  (multi-threaded, per-file locks)           │
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

`file_contents.cpp` holds an open file's contents in bounded memory, described in the next section. `key_setup.cpp` (key files and passphrases) and `util.cpp` (atomic file writes, little-endian encoding) are shared by the filesystem and the `decrypt_by_name` tool.

### Concurrency

FUSE calls the filesystem from several threads. The locks are strictly ordered, and a thread only takes a lock lower in the list than any it already holds:

1. **Namespace lock**: open-file table, handles, refcounts, and the operations that add, remove or rename entries. It's held briefly, except by `rename`, which re-encrypts.
2. **Per-file lock**: one file's contents. Downloads, reads, writes and saves run under this lock alone.
3. **Leaf locks**: the index, the synced-version map, the first-save guard, and the sync queue.

Code holding a file lock never takes the namespace lock. Work that needs it, such as cache eviction, is flagged and done after the file lock is released. `unlink` and `rename` take the affected file's lock, so they wait for a save in progress instead of racing it.

### Open files in bounded memory

An open file is a `FileContents` with three parts:

1. **The current blob** (`ChunkedReader`): unmodified chunks are read from it and authenticated on demand.
2. **A small cache** of chunks, 8 MiB per open file.
3. **A scratch file** for modified chunks that don't fit in the cache. Each slot is sealed with AES-GCM under a random key that exists only in memory, with the chunk index as AAD. The file is unlinked the moment it's created (`O_TMPFILE` where available), so plaintext never reaches the disk and a crash leaves nothing behind.

Saving streams every chunk, from cache, scratch or the old blob, through a `ChunkedWriter` into a new blob, with a fresh salt and the next version number. Then it switches to reading from the new blob. If an old chunk fails authentication while being copied, the save fails: tampered data is never re-encrypted as if it were genuine.

### Keys

Everything is derived from one 32-byte master key with HMAC-SHA256, so the master key is never used directly by two algorithms:

| Key | Derivation | Used for |
|---|---|---|
| filename key | `HMAC(master, "encfs_filename_hmac")` | remote IDs of files created before v3.0 (new files get random IDs) |
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

Because every non-final chunk is exactly `chunk_size` bytes, chunk *i* sits at a fixed offset. Reads decrypt only the chunks they cover. The plaintext length comes from the blob's length, and the final-chunk flag authenticates it.

Blobs written by v1 are still readable and are rewritten as v2 the next time the file is modified.

### Index format

`index.enc` maps paths (e.g. `docs/notes.txt`) to **inodes**.

- **Inode fields:** an ID, a type (file, directory or symlink), a version counter, size, mtime, permission bits, and a symlink target.
- **Where data lives:** a file inode's ID is also the name of its blob. New inodes get **random** IDs, so a blob's name says nothing about its path, and renaming never touches data.
- **Hard links** are several paths pointing to one inode.
- **Generation counter:** the index carries one, incremented on every save.
- **Encoding:** it is serialized little-endian as format `EIX2`, then encrypted with AES-256-GCM under the index key. Indexes written by v1 and v2 are read and converted on the next save. After every change it is also uploaded to the cloud as the object `index` (still encrypted), and in passphrase mode the non-secret KDF parameters are uploaded as `encfs.kdf`.

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

## In the browser

[`web/`](web/) is a static page, published to GitHub Pages, built on [`web/encfs.js`](web/encfs.js): a WebCrypto implementation of the key, index and blob formats (v1 and v2, version rules, passphrase KDF).

- **Live blob:** type text, see the exact bytes of its encrypted blob colour-coded by region, then try to forge it. You can flip any bit, drop or swap chunks, present it as another file, or serve an older version, and each attempt is rejected with the reason.
- **Recover files:** choose a backing folder (or files fetched from the cloud) and a key file, hex key or passphrase. You can then browse the tree, check every file, and save any of them.

A Content-Security-Policy forbids the page from making any network connection, so keys and files can't leave the browser. `tests/web/` cross-checks `encfs.js` against the C++ code in both directions on every CI run: C++-written legacy, rollback and swapped blobs are read by JS, and JS-written blobs and indexes are read by C++.

To run it locally, use `python3 -m http.server -d web`. ES modules need HTTP, not `file://`.

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
| `encfsctl` | Set up a store (`init`), change its passphrase (`passwd`), show its state (`status`) |
| `decrypt_by_name` | List, verify, recover or export files without mounting |
| `test_crypto`, `test_index`, `test_integration` | Test suites |

CMake options: `-DENCFS_WERROR=ON` (warnings are errors), `-DENCFS_SANITIZE=ON` (ASan + UBSan), `-DENCFS_E2E=ON` (registers the FUSE end-to-end test).

---

## Usage

```bash
# Set up a store: creates ~/.encfs/key (mode 0600). Back that file up!
./build/encfsctl init ~/enc_backing
#   or, protected by a passphrase instead of a key file:
#   ./build/encfsctl init --passphrase ~/enc_backing

mkdir -p ~/enc_mount
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
      --cache-size N  keep at most N of blobs locally (e.g. 500M, 20G); default: keep all
  -d, --debug         print FUSE debug output
```

If the backing directory already has an index, the key must be able to decrypt it. Otherwise the filesystem refuses to mount, so a wrong key can't overwrite your index.

### Passphrases

`encfsctl init --passphrase` creates `encfs.kdf`, which holds a random 256-bit master key wrapped (AES-256-GCM) with a key derived from your passphrase. It isn't secret, and it's synced to the cloud so you can restore on a new machine.

```bash
./build/encfsctl passwd ~/enc_backing     # change it; nothing is re-encrypted
./build/encfsctl status -p ~/enc_backing  # files, cache use, pending uploads
```

- A wrong passphrase is rejected immediately, even before the store has any files.
- `passwd` uploads the new `encfs.kdf` straight away, and every mount uploads it again in case that failed.
- Stores created before v2.10 used the passphrase to derive the master key directly (KDF v1). `passwd` upgrades them in place, around the same key.
- Changing a passphrase doesn't change the master key. If an old passphrase leaked *and* someone kept an old `encfs.kdf`, they can still unlock the store. To fully re-key, `decrypt_by_name --extract-all` and copy the files into a new store.

### Limiting local disk use

By default the backing directory keeps every blob, so it is a complete local copy. With `--cache-size N` it becomes a cache:

- Every confirmed upload, and every verified download, records which version of a file the cloud holds, in `synced.list`.
- When the cache is over its limit, least-recently-used blobs are deleted, but only if all of these hold:
  - the cloud holds exactly the version the index expects;
  - no upload or delete is queued, in flight or journaled for it;
  - the file isn't open.
- Evicted files are downloaded and verified again when they're next opened.
- On each mount, any local blob that isn't confirmed in the cloud at its current version is uploaded again. This also catches uploads lost in a crash.

If the cloud is unreachable, nothing is evicted and the cache can grow past its limit. Running out of disk space is better than losing data.

### Recovering and checking files without mounting

```bash
./build/decrypt_by_name --list ~/enc_backing                  # every path, with sizes
./build/decrypt_by_name ~/enc_backing docs/notes.txt out.txt  # one file ("-" for stdout)
./build/decrypt_by_name --verify ~/enc_backing                # authenticate every file
./build/decrypt_by_name --extract-all ~/export ~/enc_backing  # decrypt the whole tree
```

`--verify` decrypts every file and reports anything that is missing, corrupt or rolled back, plus unreferenced blobs. It exits with status 1 if there's a problem, so it fits in a cron job. `--extract-all` recreates the directory tree with modification times. It's also the way to migrate a store, for example away from a legacy 128-bit key.

### Testing locally with cloudcli_stub

```bash
export ENCFS_STUB_STORE=/tmp/fake-cloud   # default: ~/.encfs_stub_store
./build/encrypted_cloudfs -c "$PWD/tools/cloudcli_stub" ~/enc_mount ~/enc_backing
```

Set `ENCFS_STUB_FAIL=1` to make the stub fail every command, which is useful for exercising retries and the sync journal.

---

## Tests

```bash
ctest --test-dir build --output-on-failure      # all suites (add -DENCFS_E2E=ON for FUSE)
./run_and_prove.sh                              # build, all tests incl. FUSE e2e, live demo
```

- **test_crypto**: RFC 4231 HMAC vector; round trips at every chunk boundary; a single-bit flip at *every* byte position of a blob; truncation, extension, reordering, cross-file splicing and header grafting; streaming ↔ in-memory interoperability; v1 compatibility.
- **test_index**: persistence, wrong key/corruption handling (state left untouched), on-disk format stability, unusual filenames.
- **test_integration**: blob ↔ file/version binding, key resolution (hex, raw, legacy, wrong key, passphrase), the cloudcli wrapper against the stub (including shell-metacharacter paths), queue coalescing, retries and journal recovery.
- **tests/e2e/run_e2e.sh**: mounts the real filesystem and drives it with `echo`, `cat`, `dd`, `truncate`, `mv`, `cp -p`, `touch -d`. Also checks that the cloud matches the backing dir after unmount, that evicted blobs are re-downloaded, and that tampered or swapped blobs and wrong keys are rejected. It also covers directories, restoring from the cloud alone, the cache limit (including with the cloud down), and `decrypt_by_name --verify`/`--extract-all`.
- **test_contents**: thousands of random writes, truncates, reads and save-and-rebase cycles on `FileContents`, checked against an in-memory model with a 2-chunk cache to force spilling.
- **tests/web**: `web/encfs.js` and the C++ code read each other's blobs and indexes.
- **Fuzzing** (`-DENCFS_FUZZ=ON` with clang): libFuzzer targets for the blob decoders and random-access reader (`fuzz_blob`), the index deserializer (`fuzz_index`, whose inputs are encrypted with the real key so they reach the parser), differential checks of `FileContents` against a model (`fuzz_contents`), and the sync journal (`fuzz_journal`).

CI runs everything, including the FUSE tests, in Release, ASan/UBSan and TSan builds. It also fuzzes each target for 60 s and lints the shell scripts with shellcheck.

---

## Security notes

- Keep the key file at mode `0600`; the tools warn if it's readable by others.
- Plaintext filenames and contents never appear in cloud storage or the backing directory.
- What *is* visible to the cloud: the number of files, their approximate sizes, and when they change.
- New files get random IDs. Nothing in the cloud relates to a path, so re-creating a file under the same name, or renaming one, is invisible to the cloud. Files created before v3.0 keep their old path-derived IDs, which are still opaque.
- Key material and decrypted buffers are wiped (`OPENSSL_cleanse`) when no longer needed.

## Limitations

- **Each save rewrites the whole blob**: memory stays constant, but CPU and disk time are proportional to file size, and `cloudcli` uploads the whole blob. Small edits to very large files are therefore slow to sync.
- **Single writer**: don't mount the same cloud store from two machines at once. Each machine's index would overwrite the other's.
- **Ownership isn't stored**: everything belongs to the mounting user. Permission bits are stored and enforced (`default_permissions`). `chown` is accepted and ignored, so `rsync -a` and `cp -p` work.

### Upgrading from v1

v2 reads everything v1 wrote. One difference: v1 used the first 32 *characters* of a hex key file as the key (128 bits of entropy), whereas v2 decodes the hex properly (256 bits). Backing directories created by v1 are detected and still open, with a warning. To upgrade one, run `decrypt_by_name --extract-all` on it, then copy the export into a fresh mount.

---

## Roadmap

- Incremental saves: re-encrypt and upload only modified chunks. This would need per-chunk versioning in the format and a partial-upload operation in `cloudcli`.
- Optional filename padding to hide size/length patterns

---

## Changelog

### v3.0 — inodes

- **The index maps paths to inodes** (format `EIX2`). New files get random IDs, unrelated to their path.
- **Renames only touch the index.** That makes them instant and atomic, including whole directory trees and `RENAME_EXCHANGE`. Before, renaming a directory re-encrypted every file under it, and a crash mid-rename could leave both copies.
- **New POSIX features:** hard links (`link`, shared `st_ino`, `nlink`), symbolic links (`symlink`, `readlink`), and stored permission bits enforced with `default_permissions`.
- `readdir` and `rmdir` use a per-directory child list instead of scanning the whole index.
- `decrypt_by_name --extract-all` recreates symlinks, hard links and modes. `encfsctl status` and the browser recovery tool understand the new types.
- **Compatibility:** stores created by earlier versions open unchanged; their indexes are converted on the first save. Indexes written by v3.0 can't be read by earlier versions.

### v2.10 — key management

- **`encfs.kdf` v2**: passphrase stores now wrap a random master key, so `encfsctl passwd` changes the passphrase without re-encrypting anything, and a wrong passphrase is rejected even on an empty store. Before, a typo on first use locked the store to the typo. v1 files still work and are upgraded in place by `passwd`.
- **`encfsctl`**: `init` creates a key file with mode 0600 or a passphrase store, `passwd` changes the passphrase and pushes `encfs.kdf` to the cloud, and `status` shows files, cache use, pending sync operations and the KDF version.
- The browser recovery tool reads v2 KDF files, cross-checked against C++.
- e2e: fixed checks whose trailing `>/dev/null` had been hiding their own result line, including `df works` since v2.0.

### v2.9 — concurrency

- FUSE now runs multi-threaded (no more `-s`), with a three-level lock order: namespace, per-file, leaf. Downloads, reads, writes and saves hold only their file's lock.
- With downloads slowed to 4 s, `ls`, reading another file and creating a new one all finish while the download is still in progress. Before, they waited for it.
- New e2e tests: the slow-cloud check, and a stress test with 8 workers each running 25 rounds of create, append, partial overwrite, rename, read-back and delete, alongside a reader walking the tree. Every file is verified after remount.
- Three full e2e runs under ThreadSanitizer: no reports.

### v2.8 — fuzzing

- Four libFuzzer targets with seed corpora: blob decoders, index deserializer, `FileContents` checked differentially against a model, and the sync journal. CI fuzzes each for 60 s per run and uploads any crashing inputs.
- `encfs.kdf` now has an upper bound on PBKDF2 iterations (50M). It can arrive from the cloud, and a huge count would have made mounting hang.

### v2.7 — bounded local cache

- `--cache-size N` turns the backing directory into an LRU cache. It only evicts blobs that `synced.list` shows the cloud holds at their current version, with nothing pending and the file not open. Each mount re-uploads anything not confirmed.
- `cloudcli` wrapper: `IsPending()` and an upload-completion callback.
- e2e: nothing is evicted while the cloud is down; after reconnecting, the journal uploads and the cache shrinks to the limit; evicted files re-download intact and can be edited.
- CI adds a ThreadSanitizer build.

### v2.6 — constant-memory writes

- Files opened for writing no longer live in RAM. `FileContents` keeps a few chunks in memory and spills the rest to an encrypted, unlinked scratch file. On a 1 GB file, the copy-in peak dropped from 1,979 MB to 21 MB, and appending a line went from 4.6 s to 2.4 s at 13 MB. The 4 GiB file-size cap is gone.
- Saves stream into the new blob through `ChunkedWriter` and `AtomicFile`, and refuse to re-seal a tampered source chunk.
- New `test_contents` suite: thousands of random writes, truncates, reads and save-and-rebase cycles checked against an in-memory model, with a 2-chunk cache to force spilling. It also checks tamper handling, sparse files and the size limit.

### v2.5 — verify and export

- `decrypt_by_name --verify` authenticates every file and reports missing, corrupt and rolled-back files and leftover blobs, with a non-zero exit status if anything is wrong.
- `decrypt_by_name --extract-all DIR` decrypts the whole tree, with directories and mtimes. It refuses a non-empty target and paths that would escape it.
- Fixed two end-to-end checks that could fail at random: their short regex patterns sometimes matched random ciphertext.
### v2.4 — in the browser

- `web/`: an interactive blob explainer and a client-side recovery tool, deployed to GitHub Pages.
- `web/encfs.js`: an independent WebCrypto implementation of the formats, cross-checked against C++ in CI.

### v2.3 — random-access reads

- Files opened read-only are decrypted chunk by chunk (`ChunkedReader`), with memory use independent of file size. On a 300 MB file, `cat` went from 580 MB to 11 MB peak RSS and from 0.66 s to 0.31 s. The first random read is about 7× faster.
- The default chunk size went from 8 MiB to 1 MiB, so a small random read decrypts less. Existing blobs keep their own chunk size, which is stored in their headers.
- Downloaded blobs are verified before they're cached. A blob whose length doesn't match the index is rejected.

### v2.2 — subdirectories

- `mkdir`, `rmdir`, nested files, and renaming directories, including moving files between them.
- Path components are validated, `..` is rejected, and errors follow POSIX: `ENOTDIR`, `EISDIR`, `ENOTEMPTY`, `EINVAL` for moving a directory into itself.
- `decrypt_by_name` takes paths and lists directories.
- New end-to-end tests: directory trees, renames, persistence, `rm -r`, and no orphaned blobs. Also checked by hand with `tar`, `cp -r` and `rsync -a`.

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

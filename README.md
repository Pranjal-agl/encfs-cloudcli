# encfs-cloudcli

A FUSE-based encrypted filesystem written in C++17. Files written to the mount point are transparently encrypted with **AES-256-GCM** and uploaded to cloud storage via `cloudcli`. Plaintext data never touches disk or the network unencrypted.

Built as a systems programming project to explore FUSE internals, OpenSSL cryptography, and concurrent C++.

---

## Features

- **Transparent encryption** — AES-256-GCM authenticated encryption on every file
- **Chunked streaming** — large files encrypted in 8 MiB chunks to avoid loading them fully into memory
- **Filename privacy** — plaintext filenames are never stored; mapped to HMAC-SHA256 hashes
- **Encrypted index** — local filename↔remote-ID mapping is itself AES-GCM encrypted
- **Async uploads** — files are uploaded in a background thread after write completes
- **On-demand downloads** — encrypted blobs fetched from cloud only when read
- **Key flexibility** — 32-byte key file or PBKDF2-HMAC-SHA256 passphrase derivation (200k iterations)

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
│   getattr / readdir / open / read / write   │
│   create / release / unlink / truncate      │
└──────┬──────────────┬───────────────┬───────┘
       │              │               │
┌──────▼──────┐ ┌─────▼──────┐ ┌─────▼──────────┐
│  crypto.cpp │ │ index.cpp  │ │cloudcli_wrapper│
│ AES-256-GCM │ │ Encrypted  │ │  Async upload  │
│ HMAC-SHA256 │ │ index file │ │  queue thread  │
│   PBKDF2    │ │            │ │                │
└─────────────┘ └────────────┘ └────────────────┘
                                       │
                               ┌───────▼───────┐
                               │  Cloud store  │
                               │  (cloudcli)   │
                               └───────────────┘
```

### File format (encrypted blob)

```
[ 16B header: magic "ENCFS" + version + chunk count ]
[ chunk 0: 4B size | 12B nonce | N bytes ciphertext | 16B GCM tag ]
[ chunk 1: ... ]
...
```

Each chunk uses a unique nonce derived from `file_nonce XOR chunk_index`, preventing nonce reuse across chunks.

### Index format

`index.enc` in the backing directory stores:
- plaintext filename → remote ID (HMAC hash)
- remote ID → plaintext filename
- per-file metadata: version counter, size, mtime

The index is serialized, then encrypted with a key derived from the master key via HMAC.

---

## Building

### Prerequisites

```bash
sudo apt-get install build-essential cmake libfuse3-dev libssl-dev pkg-config fuse3
```

### Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

Produces:
| Binary | Description |
|---|---|
| `encrypted_cloudfs` | Main FUSE filesystem |
| `decrypt_by_name` | Offline decryption tool |
| `test_crypto` | Crypto unit tests |
| `test_index` | Index unit tests |
| `test_integration` | Integration tests |

---

## Usage

```bash
# Generate a key
mkdir -p ~/.encfs && openssl rand -hex 32 > ~/.encfs/key && chmod 600 ~/.encfs/key

# Create dirs
mkdir -p ~/enc_mount ~/enc_backing

# Mount
./build/encrypted_cloudfs ~/enc_mount ~/enc_backing

# Use it like any directory
echo "secret" > ~/enc_mount/notes.txt
cat ~/enc_mount/notes.txt   # → secret

# Unmount
fusermount3 -u ~/enc_mount
```

### Testing locally with cloudcli_stub

```bash
chmod +x tools/cloudcli_stub
export PATH="$(pwd)/tools:$PATH"
./build/encrypted_cloudfs ~/enc_mount ~/enc_backing
```

The stub stores uploaded blobs in `~/.encfs_stub_store/` instead of a real cloud.

---

## Tests

```bash
cd build
./test_crypto        # AES-GCM, HMAC, PBKDF2 unit tests
./test_index         # Index serialization + encryption tests
./test_integration   # End-to-end encrypt/decrypt, chunking, index + stub
```

---

## Bugs fixed during development

This project required diagnosing and fixing 5 bugs before it compiled and ran correctly on Ubuntu 24 / OpenSSL 3:

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | `crypto.cpp` | `#include <openssl/pkcs5.h>` — header removed in OpenSSL 3; `PKCS5_PBKDF2_HMAC` now lives in `evp.h` | Removed the stale include |
| 2 | `crypto.h` | `std::function<>` used in method signatures without `#include <functional>` | Added the missing include |
| 3 | `crypto.cpp` | `HMAC(...)` resolved to `encfs::HMAC` constructor (name collision with own class) instead of OpenSSL's C function | Changed to `::HMAC(...)` to force global namespace |
| 4 | `crypto.cpp` | `tag.data()` called on `const uint8_t*` (raw pointer, not `std::vector`) in `DecryptChunk` | Changed to `(void*)tag` |
| 5 | `encrypted_cloudfs.cpp` | `encfs_release` used `std::lock_guard` with manual `.unlock()`/`.lock()` calls — `lock_guard` is RAII-only, causing a `std::system_error` deadlock at runtime | Rewrote to copy all handle data out under `fh_mutex`, erase the handle, release the lock, then do all encryption/IO work lock-free |

Additionally, the `fuse_operations` struct used C++ designated initializers in the wrong declaration order (a C++20-only relaxation; C++17 requires order to match the struct), fixed by replacing with `memset` + explicit field assignments.

---

## Security notes

- Key file is stored at `~/.encfs/key` with mode `0600`
- Plaintext filenames never appear in cloud storage or the backing directory
- Each chunk uses a unique nonce — no nonce reuse across chunks of the same file
- Per-file version counters help detect rollback attempts
- GCM authentication tags detect any tampering with ciphertext

## Limitations

- Concurrent writes to the same file have undefined behavior (best-effort per-file locking)
- Crash during upload may require manual re-upload (detected on next mount)

---

## License

MIT — see [LICENSE](LICENSE)

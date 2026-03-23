# encfs-cloudcli

A production-ready C++ FUSE filesystem that provides encrypted, cloud-backed storage. Files are transparently encrypted with AES-256-GCM before being uploaded to cloud storage via `cloudcli`.

## Features

- **Transparent encryption**: Files are encrypted with AES-256-GCM before upload
- **Chunked streaming**: Large files (>32 MiB) are encrypted in chunks to avoid memory issues
- **Deterministic naming**: Plaintext filenames are mapped to HMAC-SHA256 hashes for privacy
- **Encrypted index**: Local index mapping plaintext ↔ remote IDs is encrypted
- **Background uploads**: Files are uploaded asynchronously after write completion
- **On-demand downloads**: Encrypted blobs are downloaded when needed

## Requirements

- Ubuntu 22.04+ (or similar Linux distribution)
- `libfuse3-dev` (FUSE3 library)
- `libssl-dev` (OpenSSL)
- `cmake` (>= 3.15)
- `g++` (C++17 support)
- `cloudcli` command-line tool (or `cloudcli_stub` for testing)

## Building

### Prerequisites

Install required dependencies:
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libfuse3-dev libssl-dev pkg-config
```

### Build Steps

```bash
mkdir build && cd build
cmake ..
make
```

This will create:
- `encrypted_cloudfs` - Main FUSE filesystem executable
- `decrypt_by_name` - CLI tool for offline decryption
- `test_crypto` - Unit tests for crypto module
- `test_index` - Unit tests for index module
- `test_integration` - Integration tests

## Installation

After building, the main executable is `encrypted_cloudfs` in the `build/` directory.

## Usage

### Basic Setup

1. Create backing directory and mount point:
```bash
mkdir -p ~/enc_backing
mkdir -p ~/enc_mount
```

2. Generate encryption key (if not using passphrase):
```bash
mkdir -p ~/.encfs
openssl rand -hex 32 > ~/.encfs/key
chmod 600 ~/.encfs/key
```

3. Mount the filesystem:
```bash
./encrypted_cloudfs ~/enc_mount ~/enc_backing
```

4. Use the mount point:
```bash
# Copy a file (will be encrypted and uploaded)
cp /path/to/file ~/enc_mount/

# Read a file (will download and decrypt if needed)
cat ~/enc_mount/file

# Unmount
fusermount3 -u ~/enc_mount
```

### Using cloudcli_stub for Testing

For local testing without a real cloud provider:

1. Make the stub executable and add to PATH:
```bash
chmod +x tools/cloudcli_stub
export PATH="$(pwd)/tools:$PATH"
```

2. Mount and use as normal. The stub will store files in `~/.encfs_stub_store/`.

3. Example test workflow:
```bash
# Setup
mkdir -p ~/enc_backing ~/enc_mount
./encrypted_cloudfs ~/enc_mount ~/enc_backing &

# In another terminal
echo "Hello World" > ~/enc_mount/test.txt
cat ~/enc_mount/test.txt  # Should print "Hello World"

# Check stub store
ls ~/.encfs_stub_store/  # Should show encrypted file

# Unmount
fusermount3 -u ~/enc_mount
```

### Decrypting Files Offline

Use the `decrypt_by_name` tool to download and decrypt a file by its plaintext name:

```bash
./decrypt_by_name ~/enc_backing "myfile.txt" output.txt
```

## Architecture

### File Format

Each encrypted file is stored as `<remote_id>.enc` where `remote_id` is the HMAC-SHA256 of the plaintext filename.

The encrypted format for chunked files:
- Header: 16 bytes (magic + version + chunk count)
- Chunks: Each chunk has:
  - 4 bytes: chunk size (encrypted data)
  - 12 bytes: nonce (unique per chunk)
  - N bytes: encrypted data
  - 16 bytes: authentication tag

For files < chunk size, a single chunk is used.

### Index Format

The index file `index.enc` in the backing directory stores the mapping:
- Plaintext filename → Remote ID
- Remote ID → Plaintext filename
- File metadata (version, size, mtime)

The index itself is encrypted with AES-256-GCM using a key derived from the master key.

### Key Management

- Default: 32-byte key stored in `~/.encfs/key` (mode 0600)
- Alternative: Passphrase-derived key using PBKDF2-HMAC-SHA256 with 200,000 iterations

### Chunking

- Default chunk size: 8 MiB (configurable)
- Each chunk uses a unique nonce derived from file nonce + chunk index
- Prevents rollback attacks via version counters in metadata

## Security Notes

- **Encryption**: AES-256-GCM provides authenticated encryption
- **Key storage**: Key file has restrictive permissions (0600)
- **Filename privacy**: Plaintext filenames never appear in cloud storage
- **Index encryption**: Local index is encrypted to prevent plaintext filename leakage
- **Nonce uniqueness**: Each chunk uses a unique nonce to prevent replay attacks
- **Version tracking**: Per-file version counters help detect rollback attempts

## Limitations

- Concurrent writes to the same file may have undefined behavior (best-effort per-file locking)
- Cloud version verification depends on `cloudcli` support (documented if unavailable)
- Crash during upload may require manual re-upload (detected on next mount)

## Testing

Run unit tests:
```bash
cd build
ctest
```

Or run individual test executables:
```bash
./test_crypto
./test_index
./test_integration
```

## License

MIT License - see LICENSE file for details.


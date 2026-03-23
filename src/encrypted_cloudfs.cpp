#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <fuse3/fuse_lowlevel.h>
#include <cstring>
#include <string>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <filesystem>
#include <memory>
#include <thread>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctime>
#include <algorithm>

#include "crypto.h"
#include "index.h"
#include "cloudcli_wrapper.h"
#include <iostream>

using namespace encfs;

struct FileHandle {
    std::string plaintext_name;
    std::string remote_id;
    std::string local_enc_path;
    std::vector<uint8_t> plaintext_buffer; // For writes
    size_t write_offset;
    bool is_write;
    std::mutex mutex;
    
    FileHandle() : write_offset(0), is_write(false) {}
};

struct EncFSContext {
    std::string backing_dir;
    std::string mount_point;
    std::vector<uint8_t> master_key;
    std::unique_ptr<EncryptedIndex> index;
    std::unique_ptr<CloudCLIWrapper> cloudcli;
    
    // File handle management
    std::unordered_map<uint64_t, std::unique_ptr<FileHandle>> file_handles;
    uint64_t next_fh;
    std::mutex fh_mutex;
    
    EncFSContext() : next_fh(1) {}
};

static EncFSContext* g_ctx = nullptr;

// Helper: Get remote ID from plaintext name
static std::string GetRemoteID(const std::string& plaintext_name, const std::vector<uint8_t>& key) {
    // Derive HMAC key from master key
    std::string context = "encfs_filename_hmac";
    std::vector<uint8_t> hmac_key = HMAC::Compute(key, std::vector<uint8_t>(context.begin(), context.end()));
    return HMAC::ComputeHex(hmac_key, plaintext_name);
}

// Helper: Get local encrypted file path
static std::string GetLocalEncPath(const std::string& backing_dir, const std::string& remote_id) {
    return backing_dir + "/" + remote_id + ".enc";
}

// Helper: Ensure encrypted file exists locally (download if needed)
static bool EnsureLocalEncFile(EncFSContext* ctx, const std::string& remote_id) {
    std::string local_path = GetLocalEncPath(ctx->backing_dir, remote_id);
    
    if (std::filesystem::exists(local_path)) {
        return true; // Already exists
    }
    
    // Download from cloud
    std::string temp_path = local_path + ".tmp";
    if (!ctx->cloudcli->Download(remote_id, temp_path)) {
        return false;
    }
    
    // Atomic rename
    if (rename(temp_path.c_str(), local_path.c_str()) != 0) {
        return false;
    }
    
    return true;
}

// FUSE operations
static int encfs_getattr(const char* path, struct stat* stbuf, struct fuse_file_info* fi) {
    (void)fi;
    
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    
    std::string plaintext_name = path + 1; // Skip leading /
    FileMetadata meta;
    
    if (!g_ctx->index->GetMetadata(plaintext_name, meta)) {
        return -ENOENT;
    }
    
    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = meta.size;
    stbuf->st_mtime = meta.mtime;
    return 0;
}

static int encfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info* fi,
                         enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;
    
    if (strcmp(path, "/") != 0) {
        return -ENOENT;
    }
    
    filler(buf, ".", nullptr, 0, fuse_fill_dir_flags(0));
    filler(buf, "..", nullptr, 0, fuse_fill_dir_flags(0));
    
    auto names = g_ctx->index->GetAllPlaintextNames();
    for (const auto& name : names) {
        filler(buf, name.c_str(), nullptr, 0, fuse_fill_dir_flags(0));
    }
    
    return 0;
}

static int encfs_open(const char* path, struct fuse_file_info* fi) {
    std::string plaintext_name = path + 1;
    
    FileMetadata meta;
    if (!g_ctx->index->GetMetadata(plaintext_name, meta)) {
        return -ENOENT;
    }
    
    // Create file handle
    auto fh = std::make_unique<FileHandle>();
    fh->plaintext_name = plaintext_name;
    fh->remote_id = meta.remote_id;
    fh->local_enc_path = GetLocalEncPath(g_ctx->backing_dir, meta.remote_id);
    fh->is_write = (fi->flags & O_WRONLY) || (fi->flags & O_RDWR);
    
    // For reads, ensure file is downloaded
    if (!fh->is_write) {
        if (!EnsureLocalEncFile(g_ctx, meta.remote_id)) {
            return -EIO;
        }
    }
    
    // Store handle
    std::lock_guard<std::mutex> lock(g_ctx->fh_mutex);
    uint64_t fh_num = g_ctx->next_fh++;
    fi->fh = fh_num;
    g_ctx->file_handles[fh_num] = std::move(fh);
    
    return 0;
}

static int encfs_read(const char* path, char* buf, size_t size, off_t offset,
                      struct fuse_file_info* fi) {
    (void)path;
    
    FileHandle* fh = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_ctx->fh_mutex);
        auto it = g_ctx->file_handles.find(fi->fh);
        if (it == g_ctx->file_handles.end()) {
            return -EBADF;
        }
        fh = it->second.get();
    }
    
    std::lock_guard<std::mutex> fh_lock(fh->mutex);
    
    // Read encrypted file
    std::ifstream file(fh->local_enc_path, std::ios::binary);
    if (!file) {
        return -EIO;
    }
    
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> encrypted_data(file_size);
    file.read(reinterpret_cast<char*>(encrypted_data.data()), file_size);
    file.close();
    
    // Decrypt
    std::vector<uint8_t> plaintext;
    try {
        plaintext = ChunkedCrypto::Decrypt(encrypted_data, g_ctx->master_key);
    } catch (const std::exception&) {
        return -EIO;
    }
    
    // Return requested range
    if (offset >= static_cast<off_t>(plaintext.size())) {
        return 0;
    }
    
    size_t to_read = std::min(size, plaintext.size() - offset);
    std::memcpy(buf, plaintext.data() + offset, to_read);
    
    return static_cast<int>(to_read);
}

static int encfs_write(const char* path, const char* buf, size_t size, off_t offset,
                       struct fuse_file_info* fi) {
    (void)path;
    
    FileHandle* fh = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_ctx->fh_mutex);
        auto it = g_ctx->file_handles.find(fi->fh);
        if (it == g_ctx->file_handles.end()) {
            return -EBADF;
        }
        fh = it->second.get();
    }
    
    std::lock_guard<std::mutex> fh_lock(fh->mutex);
    
    // Ensure buffer is large enough
    if (fh->plaintext_buffer.size() < offset + size) {
        fh->plaintext_buffer.resize(offset + size);
    }
    
    // Write to buffer
    std::memcpy(fh->plaintext_buffer.data() + offset, buf, size);
    fh->write_offset = std::max(fh->write_offset, offset + size);
    
    return static_cast<int>(size);
}

static int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    (void)mode;
    
    std::string plaintext_name = path + 1;
    
    // Generate remote ID
    std::string remote_id = GetRemoteID(plaintext_name, g_ctx->master_key);
    
    // Create metadata
    FileMetadata meta;
    meta.remote_id = remote_id;
    meta.version = 1;
    meta.size = 0;
    meta.mtime = time(nullptr);
    
    // Add to index
    g_ctx->index->SetMetadata(plaintext_name, meta);
    g_ctx->index->Save();
    
    // Create file handle
    auto fh = std::make_unique<FileHandle>();
    fh->plaintext_name = plaintext_name;
    fh->remote_id = remote_id;
    fh->local_enc_path = GetLocalEncPath(g_ctx->backing_dir, remote_id);
    fh->is_write = true;
    
    std::lock_guard<std::mutex> lock(g_ctx->fh_mutex);
    uint64_t fh_num = g_ctx->next_fh++;
    fi->fh = fh_num;
    g_ctx->file_handles[fh_num] = std::move(fh);
    
    return 0;
}

static int encfs_release(const char* path, struct fuse_file_info* fi) {
    (void)path;

    // Copy everything needed out of the handle under fh_mutex, erase the
    // handle, then do all heavy work (encryption, I/O) without holding any
    // lock.  The original code unlocked fh_mutex then tried to re-lock it
    // while holding fh->mutex, causing "Resource deadlock avoided".
    bool is_write = false;
    std::vector<uint8_t> plaintext_buffer;
    std::string local_enc_path;
    std::string plaintext_name;

    {
        std::lock_guard<std::mutex> lock(g_ctx->fh_mutex);
        auto it = g_ctx->file_handles.find(fi->fh);
        if (it == g_ctx->file_handles.end()) {
            return 0;
        }
        FileHandle* fh = it->second.get();
        is_write       = fh->is_write;
        local_enc_path = fh->local_enc_path;
        plaintext_name = fh->plaintext_name;
        if (is_write) {
            fh->plaintext_buffer.resize(fh->write_offset);
            plaintext_buffer = std::move(fh->plaintext_buffer);
        }
        g_ctx->file_handles.erase(it);
    } // fh_mutex released; fh pointer is now invalid

    if (!is_write || plaintext_buffer.empty()) {
        return 0;
    }

    // Encrypt
    std::vector<uint8_t> encrypted;
    try {
        encrypted = ChunkedCrypto::Encrypt(plaintext_buffer, g_ctx->master_key);
    } catch (const std::exception&) {
        return -EIO;
    }

    // Atomically write via temp file + rename
    std::string temp_path = local_enc_path + ".tmp";
    std::ofstream file(temp_path, std::ios::binary);
    if (!file) return -EIO;

    file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    file.close();

    if (file.fail() || rename(temp_path.c_str(), local_enc_path.c_str()) != 0) {
        return -EIO;
    }

    // Update index metadata
    FileMetadata meta;
    if (g_ctx->index->GetMetadata(plaintext_name, meta)) {
        meta.size  = plaintext_buffer.size();
        meta.mtime = time(nullptr);
        g_ctx->index->SetMetadata(plaintext_name, meta);
        g_ctx->index->Save();
    }

    g_ctx->cloudcli->QueueUpload(local_enc_path);
    return 0;
}

static int encfs_unlink(const char* path) {
    std::string plaintext_name = path + 1;
    
    FileMetadata meta;
    if (!g_ctx->index->GetMetadata(plaintext_name, meta)) {
        return -ENOENT;
    }
    
    // Delete from index
    g_ctx->index->Remove(plaintext_name);
    g_ctx->index->Save();
    
    // Delete local encrypted file
    std::string local_path = GetLocalEncPath(g_ctx->backing_dir, meta.remote_id);
    std::filesystem::remove(local_path);
    
    // Delete from cloud
    g_ctx->cloudcli->Delete(meta.remote_id);
    
    return 0;
}

static int encfs_truncate(const char* path, off_t size, struct fuse_file_info* fi) {
    if (fi) {
        // Truncate open file
        std::lock_guard<std::mutex> lock(g_ctx->fh_mutex);
        auto it = g_ctx->file_handles.find(fi->fh);
        if (it == g_ctx->file_handles.end()) {
            return -EBADF;
        }
        
        FileHandle* fh = it->second.get();
        std::lock_guard<std::mutex> fh_lock(fh->mutex);
        
        fh->plaintext_buffer.resize(size);
        fh->write_offset = size;
        return 0;
    } else {
        // Truncate by path - read, truncate, write back
        std::string plaintext_name = path + 1;
        FileMetadata meta;
        if (!g_ctx->index->GetMetadata(plaintext_name, meta)) {
            return -ENOENT;
        }
        
        // Read current file
        if (!EnsureLocalEncFile(g_ctx, meta.remote_id)) {
            return -EIO;
        }
        
        std::string local_path = GetLocalEncPath(g_ctx->backing_dir, meta.remote_id);
        std::ifstream file(local_path, std::ios::binary);
        if (!file) {
            return -EIO;
        }
        
        file.seekg(0, std::ios::end);
        size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::vector<uint8_t> encrypted_data(file_size);
        file.read(reinterpret_cast<char*>(encrypted_data.data()), file_size);
        file.close();
        
        // Decrypt
        std::vector<uint8_t> plaintext;
        try {
            plaintext = ChunkedCrypto::Decrypt(encrypted_data, g_ctx->master_key);
        } catch (const std::exception&) {
            return -EIO;
        }
        
        // Truncate
        plaintext.resize(size);
        
        // Re-encrypt
        std::vector<uint8_t> encrypted;
        try {
            encrypted = ChunkedCrypto::Encrypt(plaintext, g_ctx->master_key);
        } catch (const std::exception&) {
            return -EIO;
        }
        
        // Write back
        std::string temp_path = local_path + ".tmp";
        std::ofstream out_file(temp_path, std::ios::binary);
        if (!out_file) {
            return -EIO;
        }
        
        out_file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        out_file.close();
        
        if (out_file.fail() || rename(temp_path.c_str(), local_path.c_str()) != 0) {
            return -EIO;
        }
        
        // Update metadata
        meta.size = size;
        meta.mtime = time(nullptr);
        g_ctx->index->SetMetadata(plaintext_name, meta);
        g_ctx->index->Save();
        
        // Queue upload
        g_ctx->cloudcli->QueueUpload(local_path);
        
        return 0;
    }
}

static struct fuse_operations encfs_oper;

static void init_fuse_operations() {
    memset(&encfs_oper, 0, sizeof(encfs_oper));
    encfs_oper.getattr  = encfs_getattr;
    encfs_oper.readdir  = encfs_readdir;
    encfs_oper.open     = encfs_open;
    encfs_oper.read     = encfs_read;
    encfs_oper.write    = encfs_write;
    encfs_oper.create   = encfs_create;
    encfs_oper.release  = encfs_release;
    encfs_oper.unlink   = encfs_unlink;
    encfs_oper.truncate = encfs_truncate;
}

int main(int argc, char* argv[]) {
    init_fuse_operations();
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <mountpoint> <backing_dir>\n";
        return 1;
    }
    
    std::string mount_point = argv[1];
    std::string backing_dir = argv[2];
    
    // Create backing directory if needed
    std::filesystem::create_directories(backing_dir);
    
    // Load key
    const char* home = getenv("HOME");
    if (!home) {
        std::cerr << "HOME environment variable not set\n";
        return 1;
    }
    std::string key_path = std::string(home) + "/.encfs/key";
    std::vector<uint8_t> master_key;
    try {
        master_key = KeyManager::LoadKeyFromFile(key_path);
    } catch (const std::exception& e) {
        std::cerr << "Failed to load key: " << e.what() << "\n";
        return 1;
    }
    
    // Initialize context
    g_ctx = new EncFSContext();
    g_ctx->backing_dir = backing_dir;
    g_ctx->mount_point = mount_point;
    g_ctx->master_key = master_key;
    g_ctx->index = std::make_unique<EncryptedIndex>(backing_dir, master_key);
    g_ctx->cloudcli = std::make_unique<CloudCLIWrapper>();
    
    // Load index
    if (!g_ctx->index->Load()) {
        std::cerr << "Warning: Failed to load index, starting with empty index\n";
    }
    
    // Start background uploader
    g_ctx->cloudcli->StartBackgroundUploader();
    
    // Prepare FUSE arguments
    std::vector<char*> fuse_argv;
    fuse_argv.push_back(argv[0]);
    fuse_argv.push_back(const_cast<char*>(mount_point.c_str()));
    fuse_argv.push_back(const_cast<char*>("-f")); // Foreground
    fuse_argv.push_back(const_cast<char*>("-s")); // Single threaded (for simplicity)
    fuse_argv.push_back(nullptr);
    
    int fuse_argc = static_cast<int>(fuse_argv.size() - 1);
    
    // Mount and run
    int ret = fuse_main(fuse_argc, fuse_argv.data(), &encfs_oper, nullptr);
    
    // Cleanup
    g_ctx->cloudcli->StopBackgroundUploader();
    delete g_ctx;
    
    return ret;
}


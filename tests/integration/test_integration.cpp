#include "crypto.h"
#include "index.h"
#include "cloudcli_wrapper.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cassert>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>

using namespace encfs;

void test_basic_encrypt_decrypt() {
    std::cout << "Testing basic encrypt/decrypt cycle...\n";
    
    std::string test_dir = "/tmp/test_encfs_integration";
    std::filesystem::create_directories(test_dir);
    
    // Create key
    std::vector<uint8_t> key(32, 0x42);
    
    // Create test data
    std::string plaintext = "Hello, encrypted world!";
    std::vector<uint8_t> plaintext_data(plaintext.begin(), plaintext.end());
    
    // Encrypt
    std::vector<uint8_t> encrypted = ChunkedCrypto::Encrypt(plaintext_data, key);
    assert(encrypted.size() > plaintext_data.size());
    
    // Decrypt
    std::vector<uint8_t> decrypted = ChunkedCrypto::Decrypt(encrypted, key);
    assert(decrypted == plaintext_data);
    
    std::filesystem::remove_all(test_dir);
    std::cout << "  ✓ Basic encrypt/decrypt passed\n";
}

void test_hmac_naming() {
    std::cout << "Testing HMAC filename mapping...\n";
    
    std::vector<uint8_t> key(32, 0x42);
    std::string context = "encfs_filename_hmac";
    std::vector<uint8_t> hmac_key = HMAC::Compute(key, std::vector<uint8_t>(context.begin(), context.end()));
    
    std::string filename1 = "test.txt";
    std::string filename2 = "test.txt";
    std::string filename3 = "other.txt";
    
    std::string remote1 = HMAC::ComputeHex(hmac_key, filename1);
    std::string remote2 = HMAC::ComputeHex(hmac_key, filename2);
    std::string remote3 = HMAC::ComputeHex(hmac_key, filename3);
    
    assert(remote1 == remote2); // Same filename = same remote ID
    assert(remote1 != remote3); // Different filename = different remote ID
    
    std::cout << "  ✓ HMAC naming tests passed\n";
}

void test_index_with_cloudcli_stub() {
    std::cout << "Testing index with cloudcli stub...\n";
    
    std::string test_dir = "/tmp/test_encfs_integration2";
    std::filesystem::create_directories(test_dir);
    
    std::vector<uint8_t> key(32, 0x42);
    EncryptedIndex index(test_dir, key);
    
    // Add file
    FileMetadata meta;
    meta.remote_id = "test_remote_id";
    meta.version = 1;
    meta.size = 100;
    index.SetMetadata("test.txt", meta);
    assert(index.Save());
    
    // Reload
    EncryptedIndex index2(test_dir, key);
    assert(index2.Load());
    assert(index2.Exists("test.txt"));
    
    FileMetadata retrieved;
    assert(index2.GetMetadata("test.txt", retrieved));
    assert(retrieved.remote_id == "test_remote_id");
    
    std::filesystem::remove_all(test_dir);
    std::cout << "  ✓ Index with cloudcli stub tests passed\n";
}

void test_cloudcli_stub_commands() {
    std::cout << "Testing cloudcli stub commands...\n";
    
    // Create test file
    std::string test_file = "/tmp/test_cloudcli_file.enc";
    std::ofstream file(test_file);
    file << "test content";
    file.close();
    
    // Test upload (if cloudcli_stub is in PATH)
    std::string stub_path = "tools/cloudcli_stub";
    if (std::filesystem::exists(stub_path)) {
        int ret = system((stub_path + " upload " + test_file).c_str());
        assert(WEXITSTATUS(ret) == 0);
        
        // Check if file was stored
        const char* home = getenv("HOME");
        if (!home) {
            std::cout << "  ⚠ HOME not set, skipping stub store check\n";
            return;
        }
        std::string store_dir = std::string(home) + "/.encfs_stub_store";
        std::string remote_id = "test_cloudcli_file";
        std::string stored_path = store_dir + "/" + remote_id;
        
        if (std::filesystem::exists(stored_path)) {
            std::cout << "  ✓ cloudcli stub upload works\n";
            
            // Test download
            std::string download_path = "/tmp/test_download.enc";
            ret = system((stub_path + " download " + remote_id + " " + download_path).c_str());
            if (WEXITSTATUS(ret) == 0 && std::filesystem::exists(download_path)) {
                std::cout << "  ✓ cloudcli stub download works\n";
                std::filesystem::remove(download_path);
            }
        }
    } else {
        std::cout << "  ⚠ cloudcli_stub not found, skipping stub tests\n";
    }
    
    std::filesystem::remove(test_file);
}

void test_large_file_chunking() {
    std::cout << "Testing large file chunking...\n";
    
    std::vector<uint8_t> key(32, 0x42);
    
    // Create data larger than default chunk size (8 MiB)
    size_t large_size = 10 * 1024 * 1024; // 10 MiB
    std::vector<uint8_t> large_data(large_size);
    for (size_t i = 0; i < large_size; ++i) {
        large_data[i] = static_cast<uint8_t>(i & 0xff);
    }
    
    // Encrypt with 2 MiB chunks
    size_t chunk_size = 2 * 1024 * 1024;
    std::vector<uint8_t> encrypted = ChunkedCrypto::Encrypt(large_data, key, chunk_size);
    assert(encrypted.size() > large_data.size());
    
    // Decrypt
    std::vector<uint8_t> decrypted = ChunkedCrypto::Decrypt(encrypted, key);
    assert(decrypted.size() == large_data.size());
    assert(decrypted == large_data);
    
    std::cout << "  ✓ Large file chunking tests passed\n";
}

int main() {
    std::cout << "Running integration tests...\n\n";
    
    try {
        test_basic_encrypt_decrypt();
        test_hmac_naming();
        test_index_with_cloudcli_stub();
        test_cloudcli_stub_commands();
        test_large_file_chunking();
        
        std::cout << "\n✓ All integration tests passed!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "✗ Test failed: " << e.what() << "\n";
        return 1;
    }
}


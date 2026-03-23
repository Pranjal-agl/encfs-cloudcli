#include "index.h"
#include "crypto.h"
#include <cassert>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <cstring>

using namespace encfs;

void test_index_basic() {
    std::cout << "Testing EncryptedIndex (basic operations)...\n";
    
    // Create temp directory
    std::string test_dir = "/tmp/test_encfs_index";
    std::filesystem::create_directories(test_dir);
    
    // Create key
    std::vector<uint8_t> key(32, 0x42);
    
    EncryptedIndex index(test_dir, key);
    
    // Test empty index
    assert(!index.Exists("test.txt"));
    
    // Add entry
    FileMetadata meta;
    meta.remote_id = "abc123";
    meta.version = 1;
    meta.size = 100;
    meta.mtime = 1234567890;
    index.SetMetadata("test.txt", meta);
    
    assert(index.Exists("test.txt"));
    
    FileMetadata retrieved;
    assert(index.GetMetadata("test.txt", retrieved));
    assert(retrieved.remote_id == "abc123");
    assert(retrieved.version == 1);
    assert(retrieved.size == 100);
    
    // Test reverse lookup
    std::string plaintext;
    assert(index.GetPlaintextName("abc123", plaintext));
    assert(plaintext == "test.txt");
    
    // Save and reload
    assert(index.Save());
    
    EncryptedIndex index2(test_dir, key);
    assert(index2.Load());
    assert(index2.Exists("test.txt"));
    
    FileMetadata retrieved2;
    assert(index2.GetMetadata("test.txt", retrieved2));
    assert(retrieved2.remote_id == "abc123");
    
    // Cleanup
    std::filesystem::remove_all(test_dir);
    
    std::cout << "  ✓ Basic index tests passed\n";
}

void test_index_multiple_entries() {
    std::cout << "Testing EncryptedIndex (multiple entries)...\n";
    
    std::string test_dir = "/tmp/test_encfs_index2";
    std::filesystem::create_directories(test_dir);
    
    std::vector<uint8_t> key(32, 0x42);
    EncryptedIndex index(test_dir, key);
    
    // Add multiple entries
    for (int i = 0; i < 10; ++i) {
        FileMetadata meta;
        meta.remote_id = "remote_" + std::to_string(i);
        meta.version = i;
        meta.size = i * 100;
        index.SetMetadata("file" + std::to_string(i) + ".txt", meta);
    }
    
    assert(index.Save());
    
    EncryptedIndex index2(test_dir, key);
    assert(index2.Load());
    
    for (int i = 0; i < 10; ++i) {
        assert(index2.Exists("file" + std::to_string(i) + ".txt"));
        FileMetadata meta;
        assert(index2.GetMetadata("file" + std::to_string(i) + ".txt", meta));
        assert(meta.remote_id == "remote_" + std::to_string(i));
    }
    
    // Test removal
    index2.Remove("file5.txt");
    assert(!index2.Exists("file5.txt"));
    assert(index2.Save());
    
    EncryptedIndex index3(test_dir, key);
    assert(index3.Load());
    assert(!index3.Exists("file5.txt"));
    assert(index3.Exists("file4.txt"));
    
    std::filesystem::remove_all(test_dir);
    
    std::cout << "  ✓ Multiple entries tests passed\n";
}

void test_index_version_increment() {
    std::cout << "Testing EncryptedIndex (version increment)...\n";
    
    std::string test_dir = "/tmp/test_encfs_index3";
    std::filesystem::create_directories(test_dir);
    
    std::vector<uint8_t> key(32, 0x42);
    EncryptedIndex index(test_dir, key);
    
    FileMetadata meta;
    meta.remote_id = "remote1";
    meta.version = 1;
    index.SetMetadata("test.txt", meta);
    
    uint64_t v1 = index.IncrementVersion("test.txt");
    assert(v1 == 2);
    
    uint64_t v2 = index.IncrementVersion("test.txt");
    assert(v2 == 3);
    
    FileMetadata retrieved;
    assert(index.GetMetadata("test.txt", retrieved));
    assert(retrieved.version == 3);
    
    std::filesystem::remove_all(test_dir);
    
    std::cout << "  ✓ Version increment tests passed\n";
}

void test_index_encryption() {
    std::cout << "Testing EncryptedIndex (encryption)...\n";
    
    std::string test_dir = "/tmp/test_encfs_index4";
    std::filesystem::create_directories(test_dir);
    
    std::vector<uint8_t> key(32, 0x42);
    EncryptedIndex index(test_dir, key);
    
    FileMetadata meta;
    meta.remote_id = "secret_remote_id";
    meta.version = 1;
    index.SetMetadata("secret_file.txt", meta);
    assert(index.Save());
    
    // Try to load with wrong key - should fail
    std::vector<uint8_t> wrong_key(32, 0x43);
    EncryptedIndex index2(test_dir, wrong_key);
    bool loaded = index2.Load();
    // Should either fail to load or have wrong data
    if (loaded) {
        // If it loads, the data should be wrong
        assert(!index2.Exists("secret_file.txt"));
    }
    
    // Load with correct key - should work
    EncryptedIndex index3(test_dir, key);
    assert(index3.Load());
    assert(index3.Exists("secret_file.txt"));
    
    std::filesystem::remove_all(test_dir);
    
    std::cout << "  ✓ Encryption tests passed\n";
}

int main() {
    std::cout << "Running index unit tests...\n\n";
    
    try {
        test_index_basic();
        test_index_multiple_entries();
        test_index_version_increment();
        test_index_encryption();
        
        std::cout << "\n✓ All index tests passed!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "✗ Test failed: " << e.what() << "\n";
        return 1;
    }
}


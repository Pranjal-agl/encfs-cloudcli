#include "crypto.h"
#include <cassert>
#include <iostream>
#include <cstring>

using namespace encfs;

void test_key_manager() {
    std::cout << "Testing KeyManager...\n";
    
    // Test random bytes
    auto random1 = KeyManager::RandomBytes(32);
    auto random2 = KeyManager::RandomBytes(32);
    assert(random1.size() == 32);
    assert(random2.size() == 32);
    assert(random1 != random2); // Should be different
    
    // Test PBKDF2
    std::string passphrase = "test_passphrase";
    std::vector<uint8_t> salt = KeyManager::RandomBytes(16);
    auto key1 = KeyManager::DeriveKeyFromPassphrase(passphrase, salt, 1000);
    auto key2 = KeyManager::DeriveKeyFromPassphrase(passphrase, salt, 1000);
    assert(key1 == key2); // Same passphrase + salt = same key
    
    std::cout << "  ✓ KeyManager tests passed\n";
}

void test_hmac() {
    std::cout << "Testing HMAC...\n";
    
    std::vector<uint8_t> key(32, 0x42);
    std::string data = "test data";
    
    auto hmac1 = HMAC::Compute(key, std::vector<uint8_t>(data.begin(), data.end()));
    auto hmac2 = HMAC::Compute(key, std::vector<uint8_t>(data.begin(), data.end()));
    assert(hmac1 == hmac2);
    assert(hmac1.size() == 32);
    
    auto hex = HMAC::ComputeHex(key, data);
    assert(hex.length() == 64); // 32 bytes = 64 hex chars
    
    std::cout << "  ✓ HMAC tests passed\n";
}

void test_simple_crypto() {
    std::cout << "Testing SimpleCrypto...\n";
    
    std::vector<uint8_t> key(32, 0x42);
    std::string plaintext_str = "Hello, encrypted world!";
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());
    
    auto ciphertext = SimpleCrypto::Encrypt(plaintext, key);
    assert(ciphertext.size() > plaintext.size()); // Should include nonce + tag
    
    auto decrypted = SimpleCrypto::Decrypt(ciphertext, key);
    assert(decrypted == plaintext);
    
    // Test with wrong key
    std::vector<uint8_t> wrong_key(32, 0x43);
    try {
        auto bad = SimpleCrypto::Decrypt(ciphertext, wrong_key);
        assert(false && "Should have thrown");
    } catch (const std::exception&) {
        // Expected
    }
    
    std::cout << "  ✓ SimpleCrypto tests passed\n";
}

void test_chunked_crypto_small() {
    std::cout << "Testing ChunkedCrypto (small file)...\n";
    
    std::vector<uint8_t> key(32, 0x42);
    std::string plaintext_str = "Small file content";
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());
    
    auto ciphertext = ChunkedCrypto::Encrypt(plaintext, key, 1024);
    assert(ciphertext.size() > plaintext.size());
    
    auto decrypted = ChunkedCrypto::Decrypt(ciphertext, key);
    assert(decrypted == plaintext);
    
    std::cout << "  ✓ ChunkedCrypto small file tests passed\n";
}

void test_chunked_crypto_large() {
    std::cout << "Testing ChunkedCrypto (large file, multiple chunks)...\n";
    
    std::vector<uint8_t> key(32, 0x42);
    
    // Create data larger than chunk size (8 MiB default)
    size_t large_size = 10 * 1024 * 1024; // 10 MiB
    std::vector<uint8_t> plaintext(large_size);
    for (size_t i = 0; i < large_size; ++i) {
        plaintext[i] = static_cast<uint8_t>(i & 0xff);
    }
    
    size_t chunk_size = 2 * 1024 * 1024; // 2 MiB chunks for testing
    auto ciphertext = ChunkedCrypto::Encrypt(plaintext, key, chunk_size);
    assert(ciphertext.size() > plaintext.size());
    
    auto decrypted = ChunkedCrypto::Decrypt(ciphertext, key);
    assert(decrypted.size() == plaintext.size());
    assert(decrypted == plaintext);
    
    std::cout << "  ✓ ChunkedCrypto large file tests passed\n";
}

void test_chunked_crypto_multiple_rounds() {
    std::cout << "Testing ChunkedCrypto (multiple encrypt/decrypt rounds)...\n";
    
    std::vector<uint8_t> key(32, 0x42);
    std::vector<uint8_t> plaintext(1000);
    for (size_t i = 0; i < 1000; ++i) {
        plaintext[i] = static_cast<uint8_t>(i & 0xff);
    }
    
    // Encrypt multiple times - should get different ciphertexts (different nonces)
    auto ciphertext1 = ChunkedCrypto::Encrypt(plaintext, key);
    auto ciphertext2 = ChunkedCrypto::Encrypt(plaintext, key);
    assert(ciphertext1 != ciphertext2); // Different nonces
    
    // But both should decrypt to same plaintext
    auto decrypted1 = ChunkedCrypto::Decrypt(ciphertext1, key);
    auto decrypted2 = ChunkedCrypto::Decrypt(ciphertext2, key);
    assert(decrypted1 == plaintext);
    assert(decrypted2 == plaintext);
    
    std::cout << "  ✓ ChunkedCrypto multiple rounds tests passed\n";
}

int main() {
    std::cout << "Running crypto unit tests...\n\n";
    
    try {
        test_key_manager();
        test_hmac();
        test_simple_crypto();
        test_chunked_crypto_small();
        test_chunked_crypto_large();
        test_chunked_crypto_multiple_rounds();
        
        std::cout << "\n✓ All crypto tests passed!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "✗ Test failed: " << e.what() << "\n";
        return 1;
    }
}


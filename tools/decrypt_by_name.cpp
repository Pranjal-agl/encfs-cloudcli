#include "crypto.h"
#include "index.h"
#include "cloudcli_wrapper.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>

using namespace encfs;

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <backing_dir> <plaintext_name> <output_path>\n";
        return 1;
    }
    
    std::string backing_dir = argv[1];
    std::string plaintext_name = argv[2];
    std::string output_path = argv[3];
    
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
    
    // Load index
    EncryptedIndex index(backing_dir, master_key);
    if (!index.Load()) {
        std::cerr << "Failed to load index\n";
        return 1;
    }
    
    // Get metadata
    FileMetadata meta;
    if (!index.GetMetadata(plaintext_name, meta)) {
        std::cerr << "File not found in index: " << plaintext_name << "\n";
        return 1;
    }
    
    // Get local encrypted path
    std::string local_enc_path = backing_dir + "/" + meta.remote_id + ".enc";
    
    // Download if not present
    if (!std::filesystem::exists(local_enc_path)) {
        CloudCLIWrapper cloudcli;
        std::string temp_path = local_enc_path + ".tmp";
        if (!cloudcli.Download(meta.remote_id, temp_path)) {
            std::cerr << "Failed to download file\n";
            return 1;
        }
        if (rename(temp_path.c_str(), local_enc_path.c_str()) != 0) {
            std::cerr << "Failed to rename downloaded file\n";
            return 1;
        }
    }
    
    // Read encrypted file
    std::ifstream file(local_enc_path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open encrypted file\n";
        return 1;
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
        plaintext = ChunkedCrypto::Decrypt(encrypted_data, master_key);
    } catch (const std::exception& e) {
        std::cerr << "Decryption failed: " << e.what() << "\n";
        return 1;
    }
    
    // Write output
    std::ofstream out_file(output_path, std::ios::binary);
    if (!out_file) {
        std::cerr << "Failed to open output file\n";
        return 1;
    }
    
    out_file.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    out_file.close();
    
    if (out_file.fail()) {
        std::cerr << "Failed to write output file\n";
        return 1;
    }
    
    std::cout << "Decrypted " << plaintext_name << " to " << output_path << "\n";
    return 0;
}


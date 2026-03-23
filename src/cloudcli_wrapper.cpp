#include "cloudcli_wrapper.h"
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sys/wait.h>
#include <vector>

namespace encfs {

CloudCLIWrapper::CloudCLIWrapper() : stop_uploader_(false) {
}

CloudCLIWrapper::~CloudCLIWrapper() {
    StopBackgroundUploader();
}

bool CloudCLIWrapper::ExecuteCommand(const std::string& cmd, const std::vector<std::string>& args) {
    // Build command with proper escaping
    std::ostringstream oss;
    oss << cmd;
    for (const auto& arg : args) {
        oss << " '";
        // Escape single quotes in argument
        for (char c : arg) {
            if (c == '\'') {
                oss << "'\"'\"'";
            } else {
                oss << c;
            }
        }
        oss << "'";
    }
    
    int ret = system(oss.str().c_str());
    if (ret == -1) {
        return false; // System call failed
    }
    return (WEXITSTATUS(ret) == 0);
}

bool CloudCLIWrapper::Upload(const std::string& local_path) {
    if (!std::filesystem::exists(local_path)) {
        return false;
    }
    
    return ExecuteCommand("cloudcli", {"upload", local_path});
}

bool CloudCLIWrapper::Download(const std::string& remote_id, const std::string& local_path) {
    // Extract remote ID from path if it ends with .enc
    std::string remote = remote_id;
    if (remote_id.length() > 4 && remote_id.substr(remote_id.length() - 4) == ".enc") {
        remote = remote_id.substr(0, remote_id.length() - 4);
    }
    
    return ExecuteCommand("cloudcli", {"download", remote, local_path});
}

bool CloudCLIWrapper::Delete(const std::string& remote_id) {
    std::string remote = remote_id;
    if (remote_id.length() > 4 && remote_id.substr(remote_id.length() - 4) == ".enc") {
        remote = remote_id.substr(0, remote_id.length() - 4);
    }
    
    return ExecuteCommand("cloudcli", {"delete", remote});
}

bool CloudCLIWrapper::Exists(const std::string& remote_id) {
    // Try to download to /dev/null to check existence
    std::string remote = remote_id;
    if (remote_id.length() > 4 && remote_id.substr(remote_id.length() - 4) == ".enc") {
        remote = remote_id.substr(0, remote_id.length() - 4);
    }
    
    return ExecuteCommand("cloudcli", {"download", remote, "/dev/null"});
}

void CloudCLIWrapper::QueueUpload(const std::string& local_path) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    upload_queue_.push(local_path);
    queue_cv_.notify_one();
}

void CloudCLIWrapper::StartBackgroundUploader() {
    if (uploader_thread_.joinable()) {
        return; // Already started
    }
    stop_uploader_ = false;
    uploader_thread_ = std::thread(&CloudCLIWrapper::UploaderThread, this);
}

void CloudCLIWrapper::StopBackgroundUploader() {
    if (!uploader_thread_.joinable()) {
        return;
    }
    stop_uploader_ = true;
    queue_cv_.notify_all();
    uploader_thread_.join();
}

void CloudCLIWrapper::UploaderThread() {
    while (!stop_uploader_) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_cv_.wait(lock, [this] { return !upload_queue_.empty() || stop_uploader_; });
        
        if (stop_uploader_) {
            break;
        }
        
        if (!upload_queue_.empty()) {
            std::string path = upload_queue_.front();
            upload_queue_.pop();
            lock.unlock();
            
            // Upload in background
            Upload(path);
        }
    }
}

} // namespace encfs


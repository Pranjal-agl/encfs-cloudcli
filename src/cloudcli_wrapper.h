#pragma once

#include <string>
#include <functional>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace encfs {

// Wrapper for cloudcli commands
class CloudCLIWrapper {
public:
    CloudCLIWrapper();
    ~CloudCLIWrapper();
    
    // Upload a file (synchronous)
    bool Upload(const std::string& local_path);
    
    // Download a file (synchronous)
    bool Download(const std::string& remote_id, const std::string& local_path);
    
    // Delete a remote file (synchronous)
    bool Delete(const std::string& remote_id);
    
    // Queue an upload for background processing
    void QueueUpload(const std::string& local_path);
    
    // Start background uploader thread
    void StartBackgroundUploader();
    
    // Stop background uploader thread
    void StopBackgroundUploader();
    
    // Check if a remote file exists (by attempting download to /dev/null)
    bool Exists(const std::string& remote_id);
    
private:
    std::atomic<bool> stop_uploader_;
    std::thread uploader_thread_;
    std::queue<std::string> upload_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    void UploaderThread();
    bool ExecuteCommand(const std::string& cmd, const std::vector<std::string>& args);
};

} // namespace encfs


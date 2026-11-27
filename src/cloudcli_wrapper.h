#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace encfs {

// Talks to the `cloudcli` tool and keeps the cloud in sync in the background.
//
// cloudcli contract:
//   cloudcli upload   <local_path>             (remote ID = basename minus ".enc")
//   cloudcli download <remote_id> <local_path>
//   cloudcli delete   <remote_id>
// Exit status 0 means success.
//
// Background sync works on *desired state per remote ID*: queueing a new
// operation for an ID that is already pending replaces the pending one
// (e.g. upload-then-delete collapses to delete; three saves collapse to one
// upload). One worker thread processes IDs in FIFO order, retrying failures
// with exponential back-off.
//
// If a journal path is set, pending operations are persisted there so work
// interrupted by a crash or unmount is resumed on the next mount
// (see RecoverJournal).
class CloudCLIWrapper {
public:
    // `command` is the cloudcli executable (name looked up in PATH, or a path).
    explicit CloudCLIWrapper(std::string command = DefaultCommand());
    ~CloudCLIWrapper();

    CloudCLIWrapper(const CloudCLIWrapper&) = delete;
    CloudCLIWrapper& operator=(const CloudCLIWrapper&) = delete;

    // $ENCFS_CLOUDCLI if set, else "cloudcli".
    static std::string DefaultCommand();

    // ── Synchronous operations ──
    bool Upload(const std::string& local_path);
    bool Download(const std::string& remote_id, const std::string& local_path);
    bool Delete(const std::string& remote_id);
    bool Exists(const std::string& remote_id);

    // ── Background sync ──
    void QueueUpload(const std::string& local_path);
    void QueueDelete(const std::string& remote_id);

    void SetJournalPath(const std::string& path);
    // Re-queue operations left in the journal. Returns how many were queued.
    size_t RecoverJournal();

    void SetRetryPolicy(int max_attempts, std::chrono::milliseconds base_delay);

    void StartBackgroundUploader();
    // Finishes all queued work (including retries), then stops the worker.
    void StopBackgroundUploader();

    // Block until the queue is empty and nothing is in flight. Returns false
    // on timeout. Mainly for tests.
    bool WaitIdle(std::chrono::milliseconds timeout);
    size_t PendingCount();

    // True if an operation for `remote_id` is queued, in flight, or failed
    // and waiting for the next mount.
    bool IsPending(const std::string& remote_id);

    // Called on the worker thread (with no internal lock held) after an
    // upload succeeds, with the remote ID that was uploaded.
    void SetUploadCallback(std::function<void(const std::string&)> callback);

private:
    struct Op {
        enum Kind { kUpload, kDelete } kind = kUpload;
        std::string local_path;  // for uploads
        int attempts = 0;
        std::chrono::steady_clock::time_point not_before{};  // retry back-off
    };

    std::string command_;
    std::string journal_path_;
    int max_attempts_ = 4;
    std::chrono::milliseconds base_delay_{500};

    std::mutex mutex_;
    std::condition_variable cv_;       // wakes the worker
    std::condition_variable idle_cv_;  // signals WaitIdle
    std::deque<std::string> order_;                // remote IDs awaiting processing
    std::unordered_map<std::string, Op> pending_;  // remote ID -> desired op
    std::unordered_map<std::string, Op> failed_;   // gave up this session; kept in journal
    bool in_flight_ = false;
    std::string in_flight_id_;
    std::function<void(const std::string&)> upload_callback_;
    bool stop_ = false;
    std::thread worker_;

    void Enqueue(const std::string& remote_id, Op op);
    void WorkerLoop();
    bool Run(const Op& op, const std::string& remote_id);
    void WriteJournalLocked();
    bool ExecuteCommand(const std::vector<std::string>& args);

    static std::string RemoteIdFromPath(const std::string& path);
};

} // namespace encfs

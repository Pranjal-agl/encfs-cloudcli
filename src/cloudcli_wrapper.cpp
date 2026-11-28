#include "cloudcli_wrapper.h"
#include "util.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <spawn.h>
#include <sstream>
#include <sys/stat.h>
#include <sys/wait.h>

extern char** environ;

namespace encfs {

using Clock = std::chrono::steady_clock;

namespace {

bool FileExists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

} // namespace

CloudCLIWrapper::CloudCLIWrapper(std::string command) : command_(std::move(command)) {
}

CloudCLIWrapper::~CloudCLIWrapper() {
    StopBackgroundUploader();
}

std::string CloudCLIWrapper::DefaultCommand() {
    const char* env = std::getenv("ENCFS_CLOUDCLI");
    return (env && *env) ? env : "cloudcli";
}

std::string CloudCLIWrapper::RemoteIdFromPath(const std::string& path) {
    std::string base = path.substr(path.find_last_of('/') + 1);
    if (base.size() > 4 && base.compare(base.size() - 4, 4, ".enc") == 0) {
        base.resize(base.size() - 4);
    }
    return base;
}

// Run `command_ args...` directly (no shell, so no quoting/injection issues)
// and wait for it. The child's stdout is sent to our stderr so tool chatter
// ends up in the log rather than on the FUSE daemon's stdout.
bool CloudCLIWrapper::ExecuteCommand(const std::vector<std::string>& args) {
    std::vector<std::string> owned;
    owned.reserve(args.size() + 1);
    owned.push_back(command_);
    owned.insert(owned.end(), args.begin(), args.end());

    std::vector<char*> argv;
    for (auto& s : owned) argv.push_back(&s[0]);
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, STDERR_FILENO, STDOUT_FILENO);

    pid_t pid;
    int rc = posix_spawnp(&pid, command_.c_str(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        std::cerr << "[encfs] cannot run '" << command_ << "': " << std::strerror(rc) << "\n";
        return false;
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool CloudCLIWrapper::Upload(const std::string& local_path) {
    if (!FileExists(local_path)) {
        return false;
    }
    return ExecuteCommand({"upload", local_path});
}

bool CloudCLIWrapper::Download(const std::string& remote_id, const std::string& local_path) {
    return ExecuteCommand({"download", RemoteIdFromPath(remote_id), local_path});
}

bool CloudCLIWrapper::Delete(const std::string& remote_id) {
    return ExecuteCommand({"delete", RemoteIdFromPath(remote_id)});
}

bool CloudCLIWrapper::Exists(const std::string& remote_id) {
    return ExecuteCommand({"download", RemoteIdFromPath(remote_id), "/dev/null"});
}

// ── Background sync ─────────────────────────────────────────────────────────

void CloudCLIWrapper::SetRetryPolicy(int max_attempts, std::chrono::milliseconds base_delay) {
    std::lock_guard<std::mutex> lock(mutex_);
    max_attempts_ = std::max(1, max_attempts);
    base_delay_ = base_delay;
}

void CloudCLIWrapper::QueueUpload(const std::string& local_path) {
    Op op;
    op.kind = Op::kUpload;
    op.local_path = local_path;
    Enqueue(RemoteIdFromPath(local_path), std::move(op));
}

void CloudCLIWrapper::QueueDelete(const std::string& remote_id) {
    Op op;
    op.kind = Op::kDelete;
    Enqueue(RemoteIdFromPath(remote_id), std::move(op));
}

void CloudCLIWrapper::Enqueue(const std::string& remote_id, Op op) {
    std::lock_guard<std::mutex> lock(mutex_);
    failed_.erase(remote_id);
    bool already_queued = pending_.count(remote_id) > 0;
    pending_[remote_id] = std::move(op);  // newest desired state wins (and runs ASAP)
    if (!already_queued) order_.push_back(remote_id);
    WriteJournalLocked();
    cv_.notify_one();
}

bool CloudCLIWrapper::Run(const Op& op, const std::string& remote_id) {
    if (op.kind == Op::kDelete) {
        return Delete(remote_id);
    }
    if (!FileExists(op.local_path)) {
        return true;  // file was removed since; nothing left to upload
    }
    return Upload(op.local_path);
}

void CloudCLIWrapper::WorkerLoop() {
    std::unique_lock<std::mutex> lock(mutex_);
    for (;;) {
        // Find the first queued ID whose back-off has elapsed.
        auto now = Clock::now();
        auto earliest = Clock::time_point::max();
        // Order matters for anyone restoring from the cloud:
        //   1. uploads of data objects,
        //   2. then the index that refers to them,
        //   3. then deletes, and only once no index upload is queued, in
        //      flight or journaled — an object may only disappear after the
        //      cloud's index has stopped referring to it.
        auto tier = [](const std::string& id, const Op& op) {
            if (op.kind == Op::kDelete) return 3;
            return id == "index" ? 2 : 1;
        };
        int best_tier = 4;
        bool lower_tier_waiting[4] = {false, false, false, false};
        auto ready = order_.end();
        for (auto it = order_.begin(); it != order_.end(); ++it) {
            auto p = pending_.find(*it);
            if (p == pending_.end()) continue;
            const int t = tier(*it, p->second);
            lower_tier_waiting[t] = true;
            if (p->second.not_before > now) {
                earliest = std::min(earliest, p->second.not_before);
                continue;
            }
            if (t < best_tier) {
                best_tier = t;
                ready = it;
            }
        }
        if (ready != order_.end()) {
            const bool index_blocked = best_tier == 2 && lower_tier_waiting[1];
            const bool index_outstanding = pending_.count("index") || failed_.count("index") ||
                                           (in_flight_ && in_flight_id_ == "index");
            const bool delete_blocked =
                best_tier == 3 && (lower_tier_waiting[1] || lower_tier_waiting[2] || index_outstanding);
            if (index_blocked || delete_blocked) ready = order_.end();
        }
        if (ready == order_.end() && earliest == Clock::time_point::max() && !order_.empty() &&
            failed_.count("index")) {
            // Only deletes left, held back by an index upload that failed for
            // this session: they stay journaled for the next mount.
            for (const auto& id : order_) {
                auto p = pending_.find(id);
                if (p != pending_.end()) failed_[id] = p->second;
            }
            pending_.clear();
            order_.clear();
            WriteJournalLocked();
            continue;
        }

        if (ready == order_.end()) {
            if (order_.empty()) {
                idle_cv_.notify_all();
                if (stop_) break;
                cv_.wait(lock);
            } else {
                cv_.wait_until(lock, earliest);
            }
            continue;
        }

        std::string remote_id = *ready;
        order_.erase(ready);
        auto it = pending_.find(remote_id);
        if (it == pending_.end()) continue;
        Op op = it->second;
        pending_.erase(it);

        in_flight_ = true;
        in_flight_id_ = remote_id;
        failed_[remote_id] = op;  // keeps it in the journal while in flight
        auto callback = upload_callback_;
        auto hook = pre_upload_hook_;
        lock.unlock();
        PreUpload verdict = PreUpload::kProceed;
        Op run_op = op;
        if (op.kind == Op::kUpload && hook) verdict = hook(remote_id, run_op.local_path);
        bool ok = verdict == PreUpload::kProceed && Run(run_op, remote_id);
        lock.lock();
        in_flight_ = false;
        in_flight_id_.clear();
        failed_.erase(remote_id);
        if (ok && op.kind == Op::kUpload && callback) {
            // Outside our lock: the callback may take the filesystem's lock,
            // and the filesystem calls into us while holding it.
            lock.unlock();
            callback(remote_id);
            lock.lock();
        }

        // The file was removed while we uploaded it (superseded by a newer
        // version): nothing is left to upload, so this isn't a failure.
        const bool vanished = !ok && op.kind == Op::kUpload && verdict == PreUpload::kProceed &&
                              !FileExists(run_op.local_path);
        if (vanished) {
            // Nothing to retry; any delete for it is already queued.
        } else if (verdict == PreUpload::kAbort) {
            // Vetoed (e.g. a conflicting index in the cloud): no retries this
            // session, but keep it in the journal.
            if (pending_.count(remote_id) == 0) failed_[remote_id] = op;
        } else if (!ok && pending_.count(remote_id) == 0) {
            // Not superseded by a newer op — retry, or give up for this session.
            op.attempts++;
            const char* what = op.kind == Op::kUpload ? "upload" : "delete";
            if (op.attempts < max_attempts_) {
                auto delay = base_delay_ * (1 << std::min(op.attempts - 1, 10));
                std::cerr << "[encfs] " << what << " of " << remote_id << " failed (attempt "
                          << op.attempts << "/" << max_attempts_ << "), retrying\n";
                op.not_before = Clock::now() + delay;
                pending_[remote_id] = op;
                order_.push_back(remote_id);
            } else {
                std::cerr << "[encfs] " << what << " of " << remote_id << " failed after "
                          << op.attempts << " attempts; will retry on next mount\n";
                op.attempts = 0;
                failed_[remote_id] = op;
            }
        }
        WriteJournalLocked();
    }
}

void CloudCLIWrapper::StartBackgroundUploader() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (worker_.joinable()) {
        return;
    }
    stop_ = false;
    worker_ = std::thread(&CloudCLIWrapper::WorkerLoop, this);
}

void CloudCLIWrapper::StopBackgroundUploader() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!worker_.joinable()) return;
        stop_ = true;
    }
    cv_.notify_all();
    worker_.join();
}

bool CloudCLIWrapper::WaitIdle(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    return idle_cv_.wait_for(lock, timeout, [this] { return order_.empty() && !in_flight_; });
}

bool CloudCLIWrapper::IsPending(const std::string& remote_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_.count(remote_id) > 0 || failed_.count(remote_id) > 0 ||
           (in_flight_ && in_flight_id_ == remote_id);
}

void CloudCLIWrapper::SetPreUploadHook(
    std::function<PreUpload(const std::string&, std::string&)> hook) {
    std::lock_guard<std::mutex> lock(mutex_);
    pre_upload_hook_ = std::move(hook);
}

void CloudCLIWrapper::SetUploadCallback(std::function<void(const std::string&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    upload_callback_ = std::move(callback);
}

size_t CloudCLIWrapper::PendingCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_.size() + (in_flight_ ? 1 : 0);
}

// ── Journal ─────────────────────────────────────────────────────────────────
// One line per remote ID:  "U <remote_id> <local_path>"  or  "D <remote_id>"

void CloudCLIWrapper::SetJournalPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    journal_path_ = path;
}

void CloudCLIWrapper::WriteJournalLocked() {
    if (journal_path_.empty()) return;

    std::ostringstream out;
    auto emit = [&](const std::string& id, const Op& op) {
        if (op.kind == Op::kDelete) {
            out << "D " << id << "\n";
        } else if (op.local_path.find('\n') == std::string::npos) {
            out << "U " << id << " " << op.local_path << "\n";
        }
    };
    for (const auto& [id, op] : failed_) {
        if (!pending_.count(id)) emit(id, op);
    }
    for (const auto& [id, op] : pending_) emit(id, op);

    std::string text = out.str();
    if (text.empty()) {
        ::unlink(journal_path_.c_str());
        return;
    }
    if (!WriteFileAtomic(journal_path_, reinterpret_cast<const uint8_t*>(text.data()),
                         text.size())) {
        std::cerr << "[encfs] cannot write sync journal " << journal_path_ << ": "
                  << std::strerror(errno) << "\n";
    }
}

size_t CloudCLIWrapper::RecoverJournal() {
    std::string path;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        path = journal_path_;
    }
    std::vector<uint8_t> data;
    if (path.empty() || !ReadWholeFile(path, data)) return 0;

    std::istringstream in(std::string(data.begin(), data.end()));
    std::string line;
    size_t count = 0;
    while (std::getline(in, line)) {
        if (line.size() < 3 || line[1] != ' ') continue;
        std::string rest = line.substr(2);
        if (line[0] == 'D') {
            QueueDelete(rest);
            ++count;
        } else if (line[0] == 'U') {
            auto sp = rest.find(' ');
            if (sp == std::string::npos) continue;
            QueueUpload(rest.substr(sp + 1));
            ++count;
        }
    }
    return count;
}

} // namespace encfs

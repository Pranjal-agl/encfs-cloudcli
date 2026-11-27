#include "cloudcli_wrapper.h"
#include "crypto.h"
#include "file_codec.h"
#include "index.h"
#include "key_setup.h"
#include "util.h"
#include "../test_util.h"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

#ifndef ENCFS_STUB_PATH
#error "ENCFS_STUB_PATH must point at tools/cloudcli_stub"
#endif

using namespace encfs;
using namespace encfs_test;
using namespace std::chrono_literals;

namespace {

const std::vector<uint8_t> kKey(32, 0x42);

void WriteText(const std::string& path, const std::string& text) {
    std::ofstream(path, std::ios::binary) << text;
}

bool Exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

std::string ReadText(const std::string& path) {
    std::vector<uint8_t> data;
    if (!ReadWholeFile(path, data)) return "<missing>";
    return std::string(data.begin(), data.end());
}

// Points the stub at a private store for the lifetime of the object.
class StubStore {
public:
    StubStore() { setenv("ENCFS_STUB_STORE", dir_.path().c_str(), 1); }
    ~StubStore() {
        unsetenv("ENCFS_STUB_STORE");
        unsetenv("ENCFS_STUB_FAIL");
    }
    std::string operator/(const std::string& id) const { return dir_ / id; }

private:
    TempDir dir_;
};

// ── FileCodec ───────────────────────────────────────────────────────────────

void TestRemoteIds() {
    FileCodec codec(kKey);
    std::string a = codec.RemoteIdFor("test.txt");
    CHECK(a == codec.RemoteIdFor("test.txt"));
    CHECK(a != codec.RemoteIdFor("other.txt"));
    CHECK(a.size() == 64);
    CHECK(a.find("test") == std::string::npos);

    // Remote IDs are unchanged from v1, so existing cloud objects still match.
    auto v1_key = KeyManager::DeriveSubkey(kKey, "encfs_filename_hmac");
    CHECK(a == HMAC::ComputeHex(v1_key, "test.txt"));
    CHECK(FileCodec(std::vector<uint8_t>(32, 1)).RemoteIdFor("test.txt") != a);
}

void TestCodecRoundTripAndBinding() {
    FileCodec codec(kKey);
    codec.set_chunk_size(64);
    const std::string id_a = codec.RemoteIdFor("a"), id_b = codec.RemoteIdFor("b");
    auto pt = Bytes(std::string(500, 'x') + "end");
    auto blob = codec.Encrypt(pt, id_a, 5);

    std::vector<uint8_t> out;
    uint64_t actual = 0;
    CHECK(codec.Decrypt(blob, id_a, 5, out, &actual) == FileCodec::Result::kOk);
    CHECK(out == pt && actual == 5);

    // Blob one version ahead of the index (crash after write, before index
    // save) is accepted and reports the real version for repair.
    CHECK(codec.Decrypt(blob, id_a, 4, out, &actual) == FileCodec::Result::kOk);
    CHECK(actual == 5);

    // Index expects a newer version than the blob: rollback / stale copy.
    CHECK(codec.Decrypt(blob, id_a, 7, out, &actual) == FileCodec::Result::kRollback);

    // A blob presented under another file's ID (swapped blobs) is rejected.
    CHECK(codec.Decrypt(blob, id_b, 5, out, &actual) == FileCodec::Result::kCorrupt);

    // A different master key can't read it.
    FileCodec other(std::vector<uint8_t>(32, 7));
    CHECK(other.Decrypt(blob, id_a, 5, out, &actual) == FileCodec::Result::kCorrupt);

    // Empty files round-trip.
    auto empty = codec.Encrypt({}, id_a, 2);
    CHECK(codec.Decrypt(empty, id_a, 2, out, &actual) == FileCodec::Result::kOk && out.empty());

    CHECK(codec.Decrypt(Bytes("junk"), id_a, 1, out, &actual) == FileCodec::Result::kCorrupt);
}

void TestCodecReader() {
    TempDir dir;
    FileCodec codec(kKey);
    codec.set_chunk_size(64);
    const std::string id = codec.RemoteIdFor("r"), other = codec.RemoteIdFor("s");
    auto pt = Bytes(std::string(300, 'q'));
    CHECK(WriteFileAtomic(dir / "blob", codec.Encrypt(pt, id, 5)));

    std::unique_ptr<ChunkedReader> r;
    uint64_t actual = 0;
    CHECK(codec.OpenReader(dir / "blob", id, 5, &r, &actual) == FileCodec::Result::kOk);
    CHECK(r && actual == 5 && r->plaintext_size() == pt.size());
    std::vector<uint8_t> buf(pt.size());
    CHECK(r && r->ReadAt(0, buf.data(), buf.size()) == static_cast<int64_t>(pt.size()) && buf == pt);

    CHECK(codec.OpenReader(dir / "blob", id, 4, &r, &actual) == FileCodec::Result::kOk && actual == 5);
    CHECK(codec.OpenReader(dir / "blob", id, 7, &r, &actual) == FileCodec::Result::kRollback && !r);
    CHECK(codec.OpenReader(dir / "blob", other, 5, &r, &actual) == FileCodec::Result::kCorrupt && !r);

    // Not a v2 blob: OK with no reader, so the caller falls back to Decrypt().
    CHECK(WriteFileAtomic(dir / "junk", Bytes("junk")));
    CHECK(codec.OpenReader(dir / "junk", id, 1, &r, &actual) == FileCodec::Result::kOk && !r);
}

// ── Key setup ───────────────────────────────────────────────────────────────

void TestResolveMasterKey() {
    TempDir dir;
    const std::string backing = dir / "backing";
    ::mkdir(backing.c_str(), 0700);
    const std::string hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    WriteText(dir / "key", hex + "\n");
    ::chmod((dir / "key").c_str(), 0600);

    KeyOptions opts;
    opts.key_path = dir / "key";
    std::vector<uint8_t> key;
    std::string err;

    // Fresh backing dir: key is the decoded hex.
    CHECK(ResolveMasterKey(opts, backing, true, key, err));
    CHECK(key == KeyManager::LoadKeyFromFile(dir / "key"));

    // Once an index exists, only the right key is accepted.
    EncryptedIndex index(backing, key);
    index.SetMetadata("f", FileMetadata());
    CHECK(index.Save());
    CHECK(ResolveMasterKey(opts, backing, true, key, err));

    WriteText(dir / "wrong", std::string(64, 'a'));
    KeyOptions wrong;
    wrong.key_path = dir / "wrong";
    std::vector<uint8_t> wrong_key;
    CHECK(!ResolveMasterKey(wrong, backing, true, wrong_key, err));
    CHECK(err.find("cannot decrypt") != std::string::npos);

    // An index written by the old version with a hex key file used the hex
    // text itself as the key. That must still open (with a warning).
    const std::string legacy_backing = dir / "legacy";
    ::mkdir(legacy_backing.c_str(), 0700);
    EncryptedIndex legacy_index(legacy_backing, Bytes(hex.substr(0, 32)));
    legacy_index.SetMetadata("old", FileMetadata());
    CHECK(legacy_index.Save());
    std::vector<uint8_t> resolved;
    CHECK(ResolveMasterKey(opts, legacy_backing, true, resolved, err));
    CHECK(resolved == Bytes(hex.substr(0, 32)));

    // Missing key file on a fresh dir is an error, not a crash.
    KeyOptions missing;
    missing.key_path = dir / "nope";
    CHECK(!ResolveMasterKey(missing, dir / "fresh", true, key, err));
}

void TestPassphraseMode() {
    TempDir dir;
    KeyOptions opts;
    opts.use_passphrase = true;
    std::vector<uint8_t> k1, k2;
    std::string err;

    setenv("ENCFS_PASSPHRASE", "correct horse battery staple", 1);
    CHECK(!ResolveMasterKey(opts, dir.path(), /*allow_create=*/false, k1, err));
    CHECK(ResolveMasterKey(opts, dir.path(), true, k1, err));
    CHECK(Exists(dir / "encfs.kdf"));
    CHECK(ResolveMasterKey(opts, dir.path(), false, k2, err));
    CHECK(k1 == k2 && k1.size() == 32);

    EncryptedIndex index(dir.path(), k1);
    index.SetMetadata("f", FileMetadata());
    CHECK(index.Save());

    // A KDF file demanding an absurd work factor (it may come from the cloud)
    // is refused rather than hanging the mount.
    {
        TempDir evil;
        std::vector<uint8_t> kdf = Bytes("ENCFSKDF");
        AppendU32LE(kdf, 4000000000u);
        kdf.insert(kdf.end(), 16, 0x11);
        CHECK(WriteFileAtomic(evil / "encfs.kdf", kdf));
        std::vector<uint8_t> k3;
        CHECK(!ResolveMasterKey(opts, evil.path(), false, k3, err));
        CHECK(err.find("unreasonable") != std::string::npos);
    }

    setenv("ENCFS_PASSPHRASE", "wrong", 1);
    CHECK(!ResolveMasterKey(opts, dir.path(), false, k2, err));
    CHECK(err.find("wrong passphrase") != std::string::npos);
    unsetenv("ENCFS_PASSPHRASE");
}

// ── cloudcli wrapper (against tools/cloudcli_stub) ──────────────────────────

void TestSyncCommands() {
    StubStore store;
    TempDir dir;
    CloudCLIWrapper cloud(ENCFS_STUB_PATH);
    const std::string id = "abc123";
    WriteText(dir / (id + ".enc"), "blob contents");

    CHECK(cloud.Upload(dir / (id + ".enc")));
    CHECK(ReadText(store / id) == "blob contents");
    CHECK(cloud.Exists(id));

    CHECK(cloud.Download(id, dir / "copy"));
    CHECK(ReadText(dir / "copy") == "blob contents");

    CHECK(cloud.Delete(id));
    CHECK(!Exists(store / id));
    CHECK(!cloud.Exists(id));
    CHECK(!cloud.Download(id, dir / "copy2"));
    CHECK(!cloud.Upload(dir / "does-not-exist.enc"));

    // Arguments are passed without a shell: odd characters are harmless.
    const std::string odd = dir / "it's $(touch pwned) ;x.enc";
    WriteText(odd, "odd");
    CHECK(cloud.Upload(odd));
    CHECK(ReadText(store / "it's $(touch pwned) ;x") == "odd");
    CHECK(!Exists("pwned"));

    CloudCLIWrapper missing("/nonexistent/cloudcli");
    CHECK(!missing.Delete(id));
}

void TestBackgroundQueueCoalesces() {
    StubStore store;
    TempDir dir;
    CloudCLIWrapper cloud(ENCFS_STUB_PATH);
    cloud.SetJournalPath(dir / "journal");

    // Queue before starting the worker so the coalescing is deterministic.
    WriteText(dir / "a.enc", "v1");
    cloud.QueueUpload(dir / "a.enc");
    WriteText(dir / "a.enc", "v2");
    cloud.QueueUpload(dir / "a.enc");   // collapses with the first
    WriteText(dir / "b.enc", "bbb");
    cloud.QueueUpload(dir / "b.enc");
    cloud.QueueDelete("b");             // upload-then-delete → just delete
    CHECK(cloud.PendingCount() == 2);
    CHECK(Exists(dir / "journal"));

    cloud.StartBackgroundUploader();
    CHECK(cloud.WaitIdle(10s));
    CHECK(ReadText(store / "a") == "v2");
    CHECK(!Exists(store / "b"));
    CHECK(!Exists(dir / "journal"));  // nothing left to do → journal removed

    // Stop drains anything queued after the last WaitIdle.
    WriteText(dir / "c.enc", "ccc");
    cloud.QueueUpload(dir / "c.enc");
    cloud.StopBackgroundUploader();
    CHECK(ReadText(store / "c") == "ccc");
}

void TestRetriesAndJournalRecovery() {
    StubStore store;
    TempDir dir;
    WriteText(dir / "x.enc", "important");

    {
        setenv("ENCFS_STUB_FAIL", "1", 1);  // cloud is "down"
        CloudCLIWrapper cloud(ENCFS_STUB_PATH);
        cloud.SetRetryPolicy(3, 5ms);
        cloud.SetJournalPath(dir / "journal");
        cloud.StartBackgroundUploader();
        cloud.QueueUpload(dir / "x.enc");
        cloud.QueueDelete("gone");
        CHECK(cloud.WaitIdle(10s));
        cloud.StopBackgroundUploader();
        CHECK(!Exists(store / "x"));
    }
    // The failed work survives in the journal...
    std::string journal = ReadText(dir / "journal");
    CHECK(journal.find("U x ") != std::string::npos);
    CHECK(journal.find("D gone") != std::string::npos);

    // ...and is completed on the next "mount".
    unsetenv("ENCFS_STUB_FAIL");
    CloudCLIWrapper cloud(ENCFS_STUB_PATH);
    cloud.SetJournalPath(dir / "journal");
    CHECK(cloud.RecoverJournal() == 2);
    cloud.StartBackgroundUploader();
    CHECK(cloud.WaitIdle(10s));
    CHECK(ReadText(store / "x") == "important");
    CHECK(!Exists(dir / "journal"));
}

void TestEndToEndWithoutFuse() {
    // What the filesystem does on write + read-after-eviction, minus FUSE.
    StubStore store;
    TempDir backing;
    FileCodec codec(kKey);
    EncryptedIndex index(backing.path(), kKey);
    CloudCLIWrapper cloud(ENCFS_STUB_PATH);

    const std::string name = "report.txt";
    FileMetadata meta;
    meta.remote_id = codec.RemoteIdFor(name);
    meta.version = 2;
    auto pt = Bytes("quarterly numbers");
    meta.size = pt.size();
    const std::string blob_path = backing / (meta.remote_id + ".enc");
    CHECK(WriteFileAtomic(blob_path, codec.Encrypt(pt, meta.remote_id, meta.version)));
    index.SetMetadata(name, meta);
    CHECK(index.Save());
    CHECK(cloud.Upload(blob_path));

    // Nothing in the backing dir or the cloud reveals the name or contents.
    for (const auto& path : {blob_path, backing / "index.enc", store / meta.remote_id}) {
        std::string raw = ReadText(path);
        CHECK(raw.find("report") == std::string::npos);
        CHECK(raw.find("quarterly") == std::string::npos);
    }

    // Evict the local copy and fetch it back from the cloud.
    ::unlink(blob_path.c_str());
    EncryptedIndex reloaded(backing.path(), kKey);
    CHECK(reloaded.Load());
    FileMetadata m;
    CHECK(reloaded.GetMetadata(name, m));
    CHECK(cloud.Download(m.remote_id, blob_path));
    std::vector<uint8_t> blob, out;
    CHECK(ReadWholeFile(blob_path, blob));
    CHECK(codec.Decrypt(blob, m.remote_id, m.version, out, nullptr) == FileCodec::Result::kOk);
    CHECK(out == pt);
}

} // namespace

int main() {
    return RunTests("integration", {
        {"Remote IDs are deterministic, opaque, v1-compatible", TestRemoteIds},
        {"FileCodec binds blobs to file and version", TestCodecRoundTripAndBinding},
        {"FileCodec random-access reader", TestCodecReader},
        {"Master key resolution (hex, wrong key, legacy)", TestResolveMasterKey},
        {"Passphrase-derived keys", TestPassphraseMode},
        {"cloudcli upload/download/delete via stub", TestSyncCommands},
        {"Background queue coalesces and drains", TestBackgroundQueueCoalesces},
        {"Failed ops are retried and journaled", TestRetriesAndJournalRecovery},
        {"Encrypt → upload → evict → download → decrypt", TestEndToEndWithoutFuse},
    });
}

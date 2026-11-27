#include "crypto.h"
#include "index.h"
#include "util.h"
#include "../test_util.h"

#include <fstream>

using namespace encfs;
using namespace encfs_test;

namespace {

const std::vector<uint8_t> kKey(32, 0x42);

FileMetadata Meta(const std::string& remote_id, uint64_t version, uint64_t size, int64_t mtime = 0) {
    FileMetadata m;
    m.remote_id = remote_id;
    m.version = version;
    m.size = size;
    m.mtime = mtime;
    return m;
}

void TestBasic() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    CHECK(!index.FileExists());
    CHECK(index.Load());  // missing index → empty, not an error
    CHECK(!index.Exists("test.txt"));

    index.SetMetadata("test.txt", Meta("abc123", 1, 100, 1234567890));
    CHECK(index.Exists("test.txt"));

    FileMetadata got;
    CHECK(index.GetMetadata("test.txt", got));
    CHECK(got.remote_id == "abc123" && got.version == 1 && got.size == 100 && got.mtime == 1234567890);

    std::string name;
    CHECK(index.GetPlaintextName("abc123", name) && name == "test.txt");

    CHECK(index.Save());
    CHECK(index.FileExists());

    EncryptedIndex reloaded(dir.path(), kKey);
    CHECK(reloaded.Load());
    FileMetadata got2;
    CHECK(reloaded.GetMetadata("test.txt", got2));
    CHECK(got2.remote_id == "abc123" && got2.size == 100 && got2.mtime == 1234567890);
}

void TestMultipleEntriesAndRemoval() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    for (int i = 0; i < 10; ++i) {
        index.SetMetadata("file" + std::to_string(i) + ".txt",
                          Meta("remote_" + std::to_string(i), i, i * 100));
    }
    CHECK(index.Size() == 10);
    CHECK(index.Save());

    EncryptedIndex index2(dir.path(), kKey);
    CHECK(index2.Load());
    for (int i = 0; i < 10; ++i) {
        FileMetadata m;
        CHECK(index2.GetMetadata("file" + std::to_string(i) + ".txt", m));
        CHECK(m.remote_id == "remote_" + std::to_string(i));
    }

    index2.Remove("file5.txt");
    std::string name;
    CHECK(!index2.Exists("file5.txt"));
    CHECK(!index2.GetPlaintextName("remote_5", name));  // reverse map cleaned too
    CHECK(index2.Save());

    EncryptedIndex index3(dir.path(), kKey);
    CHECK(index3.Load());
    CHECK(!index3.Exists("file5.txt"));
    CHECK(index3.Exists("file4.txt"));
    CHECK(index3.GetAllPlaintextNames().size() == 9);
}

void TestReplacingEntryUpdatesReverseMap() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    index.SetMetadata("a", Meta("id1", 1, 0));
    index.SetMetadata("a", Meta("id2", 2, 0));
    std::string name;
    CHECK(!index.GetPlaintextName("id1", name));
    CHECK(index.GetPlaintextName("id2", name) && name == "a");
}

void TestVersionIncrement() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    index.SetMetadata("test.txt", Meta("remote1", 1, 0));
    CHECK(index.IncrementVersion("test.txt") == 2);
    CHECK(index.IncrementVersion("test.txt") == 3);
    FileMetadata m;
    CHECK(index.GetMetadata("test.txt", m) && m.version == 3);
}

void TestWrongKeyFailsWithoutClobbering() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    index.SetMetadata("secret_file.txt", Meta("secret_remote_id", 1, 0));
    CHECK(index.Save());

    std::vector<uint8_t> before;
    CHECK(ReadWholeFile(dir / "index.enc", before));
    // The plaintext name must not appear in the file on disk.
    std::string raw(before.begin(), before.end());
    CHECK(raw.find("secret_file") == std::string::npos);

    EncryptedIndex wrong(dir.path(), std::vector<uint8_t>(32, 0x43));
    wrong.SetMetadata("keep_me", Meta("x", 1, 0));
    CHECK(!wrong.Load());            // must report failure...
    CHECK(wrong.Exists("keep_me"));  // ...and leave in-memory state alone

    std::vector<uint8_t> after;
    CHECK(ReadWholeFile(dir / "index.enc", after) && after == before);

    EncryptedIndex right(dir.path(), kKey);
    CHECK(right.Load() && right.Exists("secret_file.txt"));
}

void TestCorruptIndexRejected() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    index.SetMetadata("f", Meta("id", 1, 0));
    CHECK(index.Save());

    std::vector<uint8_t> data;
    CHECK(ReadWholeFile(dir / "index.enc", data));
    data[data.size() / 2] ^= 0x80;
    CHECK(WriteFileAtomic(dir / "index.enc", data));
    EncryptedIndex corrupt(dir.path(), kKey);
    CHECK(!corrupt.Load());

    // A validly-encrypted but malformed payload is rejected too.
    auto index_key = KeyManager::DeriveSubkey(kKey, "encfs_index_key_derivation");
    std::vector<uint8_t> garbage = {5, 0, 0, 0, 0xff, 0xff};  // claims 5 entries, has none
    CHECK(WriteFileAtomic(dir / "index.enc", SimpleCrypto::Encrypt(garbage, index_key)));
    EncryptedIndex malformed(dir.path(), kKey);
    CHECK(!malformed.Load());
}

void TestOnDiskFormatIsStable() {
    // The serialized layout must stay compatible with indexes written by
    // earlier versions. Build one by hand and make sure it loads.
    TempDir dir;
    std::vector<uint8_t> plain;
    AppendU32LE(plain, 1);
    std::string name = "notes.txt", id = "deadbeef";
    AppendU32LE(plain, static_cast<uint32_t>(name.size()));
    plain.insert(plain.end(), name.begin(), name.end());
    AppendU32LE(plain, static_cast<uint32_t>(id.size()));
    plain.insert(plain.end(), id.begin(), id.end());
    AppendU64LE(plain, 7);           // version
    AppendU64LE(plain, 42);          // size
    AppendU64LE(plain, 1700000000);  // mtime

    auto index_key = KeyManager::DeriveSubkey(kKey, "encfs_index_key_derivation");
    CHECK(WriteFileAtomic(dir / "index.enc", SimpleCrypto::Encrypt(plain, index_key)));

    EncryptedIndex index(dir.path(), kKey);
    CHECK(index.Load());
    FileMetadata m;
    CHECK(index.GetMetadata("notes.txt", m));
    CHECK(m.remote_id == "deadbeef" && m.version == 7 && m.size == 42 && m.mtime == 1700000000);
}

void TestUnicodeAndOddNames() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    const std::vector<std::string> names = {"résumé.pdf", "with space", "日本語.txt", "a'quote\"",
                                            std::string("nul\0byte", 8)};
    for (size_t i = 0; i < names.size(); ++i) {
        index.SetMetadata(names[i], Meta("id" + std::to_string(i), 1, i));
    }
    CHECK(index.Save());
    EncryptedIndex reloaded(dir.path(), kKey);
    CHECK(reloaded.Load());
    for (const auto& n : names) CHECK(reloaded.Exists(n));
}

FileMetadata Dir() {
    FileMetadata m;
    m.type = EntryType::kDirectory;
    m.mode = 0755;
    return m;
}

void TestDirectoryEntries() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    index.SetMetadata("docs", Dir());
    index.SetMetadata("docs/old", Dir());
    index.SetMetadata("docs/a.txt", Meta("id-a", 1, 5));

    FileMetadata m;
    CHECK(index.GetMetadata("docs", m) && m.IsDirectory() && m.remote_id.size() == 64);
    CHECK(index.ListDirectory("docs") == std::vector<std::string>({"a.txt", "old"}));
    CHECK(index.ListDirectory("") == std::vector<std::string>({"docs"}));
    CHECK(index.HasChildren("docs") && !index.HasChildren("docs/old"));

    index.Remove("docs/old");
    CHECK(index.ListDirectory("docs") == std::vector<std::string>({"a.txt"}));
    std::string name;
    CHECK(index.GetPlaintextName("id-a", name) && name == "docs/a.txt");

    CHECK(index.Save());
    EncryptedIndex reloaded(dir.path(), kKey);
    CHECK(reloaded.Load());
    CHECK(reloaded.GetMetadata("docs", m) && m.IsDirectory() && m.mode == 0755);
    CHECK(reloaded.GetMetadata("docs/a.txt", m) && m.IsFile());
    CHECK(reloaded.ListDirectory("docs") == std::vector<std::string>({"a.txt"}));
}

void TestHardLinks() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    index.SetMetadata("a", Meta("inode1", 3, 10));
    CHECK(index.Link("a", "b"));
    CHECK(!index.Link("a", "b"));       // already exists
    CHECK(!index.Link("missing", "c"));

    FileMetadata m;
    CHECK(index.GetMetadata("b", m) && m.remote_id == "inode1" && m.nlink == 2);

    // Updating the inode through one name shows through the other.
    m.size = 99;
    CHECK(index.UpdateInode(m));
    CHECK(index.GetMetadata("a", m) && m.size == 99 && m.nlink == 2);

    CHECK(index.Save());
    EncryptedIndex reloaded(dir.path(), kKey);
    CHECK(reloaded.Load() && reloaded.GetMetadata("a", m) && m.nlink == 2);

    // Only the last unlink removes the inode.
    FileMetadata removed;
    CHECK(!reloaded.Remove("a", &removed));
    CHECK(reloaded.GetInode("inode1", m) && m.nlink == 1);
    CHECK(reloaded.Remove("b", &removed) && removed.remote_id == "inode1");
    CHECK(!reloaded.GetInode("inode1", m));

    // No hard links to directories.
    reloaded.SetMetadata("d", Dir());
    CHECK(!reloaded.Link("d", "d2"));
}

void TestRenameMovesSubtree() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    index.SetMetadata("p", Dir());
    index.SetMetadata("p/q", Dir());
    index.SetMetadata("p/q/f", Meta("f-id", 1, 1));
    index.SetMetadata("p/g", Meta("g-id", 1, 1));
    index.SetMetadata("pz", Meta("pz-id", 1, 1));  // shares a prefix but isn't inside p

    CHECK(!index.Rename("p", "p/q/inside"));  // into itself
    CHECK(!index.Rename("p", "pz"));          // destination exists
    CHECK(index.Rename("p", "r"));
    FileMetadata m;
    CHECK(!index.Exists("p") && !index.Exists("p/q/f") && !index.Exists("p/g"));
    CHECK(index.GetMetadata("r/q/f", m) && m.remote_id == "f-id");  // same inode: no re-encryption
    CHECK(index.GetMetadata("r/g", m) && m.remote_id == "g-id");
    CHECK(index.GetMetadata("pz", m) && m.remote_id == "pz-id");   // untouched
    CHECK(index.ListDirectory("") == std::vector<std::string>({"pz", "r"}));
    CHECK(index.ListDirectory("r") == std::vector<std::string>({"g", "q"}));
    CHECK(index.Descendants("r") == std::vector<std::string>({"r/g", "r/q", "r/q/f"}));
}

void TestSymlinksAndModesRoundTrip() {
    TempDir dir;
    EncryptedIndex index(dir.path(), kKey);
    FileMetadata link;
    link.type = EntryType::kSymlink;
    link.target = "../somewhere/else";
    link.mode = 0777;
    index.SetMetadata("ln", link);
    FileMetadata exe = Meta("exe-id", 1, 4);
    exe.mode = 04755;
    index.SetMetadata("run.sh", exe);
    const uint64_t gen = index.generation();
    CHECK(index.Save() && index.generation() == gen + 1);

    EncryptedIndex reloaded(dir.path(), kKey);
    CHECK(reloaded.Load());
    FileMetadata m;
    CHECK(reloaded.GetMetadata("ln", m) && m.IsSymlink() && m.target == "../somewhere/else");
    CHECK(reloaded.GetMetadata("run.sh", m) && m.mode == 04755);
    CHECK(reloaded.generation() == gen + 1);
}

void TestV1IndexMigrates() {
    // An index exactly as v1 wrote it: a directory with an empty ID and a file.
    TempDir dir;
    std::vector<uint8_t> plain;
    AppendU32LE(plain, 2);
    auto entry = [&](const std::string& name, const std::string& id) {
        AppendU32LE(plain, static_cast<uint32_t>(name.size()));
        plain.insert(plain.end(), name.begin(), name.end());
        AppendU32LE(plain, static_cast<uint32_t>(id.size()));
        plain.insert(plain.end(), id.begin(), id.end());
        AppendU64LE(plain, 4);
        AppendU64LE(plain, 7);
        AppendU64LE(plain, 1700000000);
    };
    entry("docs", "");
    entry("docs/x", std::string(64, 'a'));
    auto index_key = KeyManager::DeriveSubkey(kKey, "encfs_index_key_derivation");
    CHECK(WriteFileAtomic(dir / "index.enc", SimpleCrypto::Encrypt(plain, index_key)));

    EncryptedIndex index(dir.path(), kKey);
    CHECK(index.Load());
    FileMetadata m;
    CHECK(index.GetMetadata("docs", m) && m.IsDirectory() && m.remote_id.size() == 64);
    CHECK(index.GetMetadata("docs/x", m) && m.IsFile() && m.remote_id == std::string(64, 'a') &&
          m.version == 4 && m.size == 7 && m.mode == 0644);
    CHECK(index.ListDirectory("docs") == std::vector<std::string>({"x"}));
    CHECK(index.Save());  // rewritten as v2
    EncryptedIndex again(dir.path(), kKey);
    CHECK(again.Load() && again.Exists("docs/x"));
}

} // namespace

int main() {
    return RunTests("index", {
        {"Basic set/get/save/load", TestBasic},
        {"Multiple entries and removal", TestMultipleEntriesAndRemoval},
        {"Replacing an entry updates the reverse map", TestReplacingEntryUpdatesReverseMap},
        {"Version increment", TestVersionIncrement},
        {"Wrong key fails without clobbering state", TestWrongKeyFailsWithoutClobbering},
        {"Corrupt or malformed index rejected", TestCorruptIndexRejected},
        {"On-disk format is stable", TestOnDiskFormatIsStable},
        {"Unicode and unusual filenames", TestUnicodeAndOddNames},
        {"Directory entries and listings", TestDirectoryEntries},
        {"Hard links share an inode", TestHardLinks},
        {"Rename moves a whole subtree, index-only", TestRenameMovesSubtree},
        {"Symlinks, modes and generation round-trip", TestSymlinksAndModesRoundTrip},
        {"v1 indexes are read and migrated", TestV1IndexMigrates},
    });
}

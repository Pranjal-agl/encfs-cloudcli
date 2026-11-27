#include "crypto.h"
#include "file_contents.h"
#include "util.h"
#include "../test_util.h"

#include <dirent.h>
#include <random>

using namespace encfs;
using namespace encfs_test;

namespace {

const std::vector<uint8_t> kKey(32, 0x42);
const std::vector<uint8_t> kAad = Bytes("contents-test");

// Write `contents` out as a blob at `path` and return a reader over it.
std::unique_ptr<ChunkedReader> Persist(FileContents& contents, const std::string& path) {
    AtomicFile out(path);
    if (!out.Open()) return nullptr;
    ChunkedWriter writer([&](const uint8_t* d, size_t n) { return out.Write(d, n); }, kKey,
                         contents.chunk_size(), kAad);
    bool ok = contents.ForEachChunk([&](const uint8_t* d, size_t n, bool last) {
        return writer.Add(d, n, last);
    });
    if (!ok || !writer.finished() || !out.Commit()) return nullptr;
    return ChunkedReader::Open(path, kKey, kAad);
}

std::vector<uint8_t> ReadAll(FileContents& c) {
    std::vector<uint8_t> out(c.size());
    int64_t n = c.Read(0, out.data(), out.size());
    if (n != static_cast<int64_t>(out.size())) out.assign(1, 0xEE);  // poison on failure
    return out;
}

std::vector<uint8_t> Streamed(FileContents& c) {
    std::vector<uint8_t> out;
    c.ForEachChunk([&](const uint8_t* d, size_t n, bool) {
        out.insert(out.end(), d, d + n);
        return true;
    });
    return out;
}

size_t VisibleFiles(const std::string& dir) {
    size_t n = 0;
    if (DIR* d = ::opendir(dir.c_str())) {
        while (auto* e = ::readdir(d)) {
            if (e->d_name[0] != '.') ++n;
        }
        ::closedir(d);
    }
    return n;
}

void TestModelBasedFuzz() {
    TempDir dir;
    std::mt19937_64 rng(12345);
    const size_t cs = 16;
    int mismatches = 0;

    for (int round = 0; round < 40; ++round) {
        // Start from either nothing or an existing blob.
        std::vector<uint8_t> model(rng() % 200);
        for (auto& b : model) b = static_cast<uint8_t>(rng());
        std::unique_ptr<ChunkedReader> base;
        if (round % 2 == 1) {
            auto blob = ChunkedCrypto::Encrypt(model, kKey, cs, kAad);
            WriteFileAtomic(dir / "base", blob);
            base = ChunkedReader::Open(dir / "base", kKey, kAad);
        } else {
            model.clear();
        }
        // 32-byte cache = 2 chunks, so almost every access spills or reloads.
        FileContents contents(std::move(base), cs, dir.path(), 32);

        for (int op = 0; op < 150; ++op) {
            switch (rng() % 6) {
            case 0: case 1: case 2: {  // write, sometimes past EOF
                uint64_t off = rng() % (model.size() + 40);
                std::vector<uint8_t> data(1 + rng() % 50);
                for (auto& b : data) b = static_cast<uint8_t>(rng());
                CHECK(contents.Write(off, data.data(), data.size()));
                if (model.size() < off + data.size()) model.resize(off + data.size());
                std::copy(data.begin(), data.end(), model.begin() + static_cast<long>(off));
                break;
            }
            case 3: {  // truncate: shrink or grow
                uint64_t n = rng() % (model.size() + 30);
                CHECK(contents.Truncate(n));
                model.resize(n);
                break;
            }
            case 4: {  // random read
                uint64_t off = rng() % (model.size() + 10);
                std::vector<uint8_t> buf(1 + rng() % 60);
                int64_t got = contents.Read(off, buf.data(), buf.size());
                size_t want = off >= model.size() ? 0 : std::min(buf.size(), model.size() - off);
                if (got != static_cast<int64_t>(want) ||
                    !std::equal(buf.begin(), buf.begin() + static_cast<long>(want),
                                model.begin() + static_cast<long>(std::min<uint64_t>(off, model.size())))) {
                    ++mismatches;
                }
                break;
            }
            case 5: {  // save to a real blob and continue from it
                auto reader = Persist(contents, dir / "persisted");
                CHECK(reader != nullptr);
                if (!reader) break;
                CHECK(reader->plaintext_size() == model.size());
                contents.Rebase(std::move(reader));
                CHECK(contents.spilled_chunks() == 0);
                break;
            }
            }
            if (contents.size() != model.size()) ++mismatches;
        }
        if (ReadAll(contents) != model) ++mismatches;
        if (Streamed(contents) != model) ++mismatches;

        // And the final state round-trips through a real blob.
        auto reader = Persist(contents, dir / "final");
        std::vector<uint8_t> blob, decrypted;
        CHECK(reader && ReadWholeFile(dir / "final", blob));
        decrypted = ChunkedCrypto::Decrypt(blob, kKey, kAad);
        if (decrypted != model) ++mismatches;
    }
    CHECK(mismatches == 0);
}

void TestSpillsStayHidden() {
    TempDir dir;
    FileContents contents(nullptr, 64, dir.path(), 128);  // 2 chunks in memory
    std::vector<uint8_t> data(64 * 50, 0xAB);
    CHECK(contents.Write(0, data.data(), data.size()));
    CHECK(contents.spilled_chunks() >= 40);   // most chunks went to scratch...
    CHECK(VisibleFiles(dir.path()) == 0);     // ...which has no name on disk
    CHECK(ReadAll(contents) == data);
}

void TestTamperedBaseIsNeverResealed() {
    TempDir dir;
    const size_t cs = 32;
    auto blob = ChunkedCrypto::Encrypt(std::vector<uint8_t>(100, 7), kKey, cs, kAad);
    const size_t span = 4 + cs + ChunkedCrypto::TAG_SIZE;
    blob[ChunkedCrypto::HEADER_SIZE + span + 4 + 5] ^= 1;  // corrupt chunk 1's ciphertext
    WriteFileAtomic(dir / "base", blob);
    FileContents contents(ChunkedReader::Open(dir / "base", kKey, kAad), cs, dir.path());

    uint8_t b;
    CHECK(contents.Read(0, &b, 1) == 1);          // chunk 0 is fine
    CHECK(contents.Read(40, &b, 1) == -1);        // chunk 1 is not
    CHECK(contents.Write(0, &b, 1));              // editing elsewhere still works
    CHECK(!contents.ForEachChunk([](const uint8_t*, size_t, bool) { return true; }));
    CHECK(!contents.Write(41, &b, 1));            // can't build on a tampered chunk

    // Overwriting the whole bad chunk... still needs to load it first, and
    // truncating before it removes it altogether.
    CHECK(contents.Truncate(32));
    CHECK(contents.ForEachChunk([](const uint8_t*, size_t, bool) { return true; }));
}

void TestEdgeCases() {
    TempDir dir;
    FileContents empty(nullptr, 16, dir.path());
    CHECK(empty.size() == 0);
    size_t chunks = 0, total = 0;
    CHECK(empty.ForEachChunk([&](const uint8_t*, size_t n, bool last) {
        ++chunks;
        total += n;
        return last;
    }));
    CHECK(chunks == 1 && total == 0);

    // A sparse write far past the end reads back as zeros before it.
    FileContents sparse(nullptr, 16, dir.path());
    uint8_t x = 9;
    CHECK(sparse.Write(1000, &x, 1));
    CHECK(sparse.size() == 1001);
    auto all = ReadAll(sparse);
    CHECK(all.size() == 1001 && all[1000] == 9 &&
          std::all_of(all.begin(), all.begin() + 1000, [](uint8_t v) { return v == 0; }));

    // Shrinking then growing doesn't resurrect old bytes.
    std::vector<uint8_t> ones(40, 1);
    FileContents regrow(nullptr, 16, dir.path());
    CHECK(regrow.Write(0, ones.data(), ones.size()));
    CHECK(regrow.Truncate(5));
    CHECK(regrow.Truncate(40));
    auto r = ReadAll(regrow);
    CHECK(std::all_of(r.begin(), r.begin() + 5, [](uint8_t v) { return v == 1; }));
    CHECK(std::all_of(r.begin() + 5, r.end(), [](uint8_t v) { return v == 0; }));

    // Size limit: 2^32 chunks.
    FileContents limits(nullptr, 16, dir.path());
    CHECK(limits.max_size() == 16ULL << 32);
    CHECK(!limits.Write(limits.max_size(), &x, 1));
    CHECK(!limits.Truncate(limits.max_size() + 1));
}

void TestChunkedWriterRules() {
    std::vector<uint8_t> out;
    auto sink = [&](const uint8_t* d, size_t n) { out.insert(out.end(), d, d + n); return true; };
    std::vector<uint8_t> full(16, 1), part(5, 2);

    ChunkedWriter ok(sink, kKey, 16, kAad);
    CHECK(ok.Add(full.data(), 16, false) && ok.Add(part.data(), 5, true) && ok.finished());
    CHECK(!ok.Add(part.data(), 5, true));  // nothing after the last chunk
    auto pt = ChunkedCrypto::Decrypt(out, kKey, kAad);
    CHECK(pt.size() == 21);

    ChunkedWriter bad(sink, kKey, 16, kAad);
    CHECK(!bad.Add(part.data(), 5, false));  // short non-final chunk
    ChunkedWriter big(sink, kKey, 16, kAad);
    std::vector<uint8_t> too_big(17);
    CHECK(!big.Add(too_big.data(), 17, true));
}

} // namespace

int main() {
    return RunTests("contents", {
        {"Random ops match an in-memory model (with spills and saves)", TestModelBasedFuzz},
        {"Spilled chunks never appear on disk by name", TestSpillsStayHidden},
        {"A tampered base is never re-encrypted as genuine", TestTamperedBaseIsNeverResealed},
        {"Empty, sparse, shrink-then-grow, size limit", TestEdgeCases},
        {"ChunkedWriter enforces the chunk rules", TestChunkedWriterRules},
    });
}

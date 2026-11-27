// Fuzz the sync-journal parser (RecoverJournal). The journal is a local text
// file, but a damaged one must never crash the mount. The worker isn't
// started, so nothing is executed; queued operations are just parsed.

#include "cloudcli_wrapper.h"
#include "util.h"

#include <cstdlib>
#include <string>

using namespace encfs;

namespace {
const std::string& Dir() {
    static const std::string dir = [] {
        char tmpl[] = "/tmp/fuzz_journal_XXXXXX";
        return std::string(mkdtemp(tmpl));
    }();
    return dir;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string path = Dir() + "/journal";
    if (!WriteFileAtomic(path, data, size)) return 0;

    CloudCLIWrapper cloud("/bin/false");
    cloud.SetJournalPath(path);
    size_t recovered = cloud.RecoverJournal();
    if (cloud.PendingCount() > recovered) abort();
    return 0;
}

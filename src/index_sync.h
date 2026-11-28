#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace encfs {

class CloudCLIWrapper;
class FileCodec;
class EncryptedIndex;

// Keeping several machines that share one cloud store consistent.
//
// Every save bumps the index's generation. Each backing directory records in
// `cloud.gen` the generation of the cloud index it last synced with (uploaded
// or adopted): its *base*. Comparing local, base and cloud generations says
// who changed what since the last sync:
//
//   cloud == base               nobody else wrote: the local copy is current
//   cloud >  base, local clean  another machine wrote: adopt the cloud index
//   cloud >  base, local dirty  both wrote: conflict, the user must choose
//   cloud <  base               the cloud index went backwards (rollback)
//
// The same check runs before every index upload, so a machine that finds the
// cloud changed underneath it stops instead of overwriting the other's work.

enum class CloudIndexStatus {
    kFound,        // downloaded and decrypted; *generation is set
    kUnavailable,  // couldn't download (absent or cloud unreachable)
    kUnreadable,   // downloaded but doesn't decrypt with our key, or is corrupt
};

// Download the cloud index into `<backing_dir>/.cloud-index/index.enc` and
// read its generation.
CloudIndexStatus FetchCloudIndex(CloudCLIWrapper& cloud, const std::vector<uint8_t>& key,
                                 const std::string& backing_dir, uint64_t* generation);

// Path FetchCloudIndex downloads to.
std::string FetchedCloudIndexPath(const std::string& backing_dir);

// Generation of an index file on disk (0 if absent/unreadable).
bool IndexFileGeneration(const std::string& dir, const std::vector<uint8_t>& key, uint64_t* generation);

// <backing_dir>/cloud.gen
bool LoadSyncedGeneration(const std::string& backing_dir, uint64_t* generation);
bool SaveSyncedGeneration(const std::string& backing_dir, uint64_t generation);

// Replace the local index with the fetched cloud copy, reload `index`, and
// delete local blobs that aren't exactly the version the new index expects
// (they'll be downloaded again when needed). Returns the number deleted, or
// -1 on failure.
int AdoptFetchedCloudIndex(const std::string& backing_dir, EncryptedIndex& index, const FileCodec& codec);

} // namespace encfs

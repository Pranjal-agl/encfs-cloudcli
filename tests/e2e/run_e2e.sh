#!/usr/bin/env bash
# End-to-end test: mounts the real filesystem with FUSE and exercises it with
# ordinary shell tools. Needs /dev/fuse and fusermount3.
#
#   tests/e2e/run_e2e.sh <encrypted_cloudfs> <decrypt_by_name> <encfsctl> <cloudcli_stub>

set -uo pipefail

FS_BIN=$(realpath "$1")
DECRYPT_BIN=$(realpath "$2")
CTL_BIN=$(realpath "$3")
STUB=$(realpath "$4")

WORK=$(mktemp -d /tmp/encfs_e2e.XXXXXX)
MNT="$WORK/mnt"
BACK="$WORK/backing"
KEY="$WORK/key"
LOG="$WORK/fs.log"
export ENCFS_STUB_STORE="$WORK/cloud"
mkdir -p "$MNT" "$BACK"
(umask 077 && openssl rand -hex 32 > "$KEY")

FS_PID=""
FAILURES=0

pass() { echo "  ✓ $1"; }
fail() { echo "  ✗ $1"; FAILURES=$((FAILURES + 1)); }
check() { local desc=$1; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }
check_fails() { local desc=$1; shift; if "$@"; then fail "$desc"; else pass "$desc"; fi; }
# Run a command with its output discarded (redirecting a `check` line itself
# would also hide the ✓/✗ line).
quiet() { "$@" >/dev/null 2>&1; }

CLOUDCLI="$STUB"
EXTRA_ARGS=()
mount_fs() {
    "$FS_BIN" -k "$KEY" -c "$CLOUDCLI" "${EXTRA_ARGS[@]}" "$MNT" "$BACK" >>"$LOG" 2>&1 &
    FS_PID=$!
    for _ in $(seq 50); do
        mountpoint -q "$MNT" && return 0
        kill -0 "$FS_PID" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}

unmount_fs() {
    fusermount3 -u "$MNT" 2>/dev/null || true
    [ -n "$FS_PID" ] && wait "$FS_PID" 2>/dev/null
    FS_PID=""
}

cleanup() {
    unmount_fs
    if [ "$FAILURES" -ne 0 ]; then
        echo "--- filesystem log ---"
        grep -v -E '^(Uploaded|Downloaded|Deleted) ' "$LOG" || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

blob_ids() { find "$BACK" -maxdepth 1 -name '*.enc' ! -name index.enc -printf '%f\n' | sed 's/\.enc$//' | sort; }
cloud_ids() { find "$ENCFS_STUB_STORE" -maxdepth 1 -type f ! -name '.*' ! -name index ! -name encfs.kdf -printf '%f\n' | sort; }
cloud_files() { cloud_ids | cut -c1-64 | sort -u; }  # one inode may span several segment objects

echo "Running FUSE end-to-end tests in $WORK"
if ! mount_fs; then
    echo "  ✗ could not mount (is /dev/fuse available?)"
    cat "$LOG"
    exit 1
fi
pass "mounted"

# ── Basic I/O ──
echo "hello" > "$MNT/hello.txt"
check "write + read"            [ "$(cat "$MNT/hello.txt")" = "hello" ]

echo "more" >> "$MNT/hello.txt"
check "append keeps old data"   [ "$(cat "$MNT/hello.txt")" = $'hello\nmore' ]

echo "replaced" > "$MNT/hello.txt"
check "overwrite"               [ "$(cat "$MNT/hello.txt")" = "replaced" ]

: > "$MNT/hello.txt"
check "truncate via >"          [ ! -s "$MNT/hello.txt" ]

printf '0123456789' > "$MNT/rw.bin"
printf 'XY' | dd of="$MNT/rw.bin" bs=1 seek=3 conv=notrunc status=none
check "partial overwrite"       [ "$(cat "$MNT/rw.bin")" = "012XY56789" ]

truncate -s 4 "$MNT/rw.bin"
check "truncate -s shrink"      [ "$(cat "$MNT/rw.bin")" = "012X" ]
truncate -s 6 "$MNT/rw.bin"
check "truncate -s grow"        [ "$(stat -c %s "$MNT/rw.bin")" = 6 ]

touch "$MNT/empty"
check "touch creates file"      [ -f "$MNT/empty" ]
check "...which is empty"       [ ! -s "$MNT/empty" ]
check "read empty file"         cat "$MNT/empty"

touch -d '2001-02-03 04:05:06 UTC' "$MNT/empty"
check "touch -d sets mtime"     [ "$(stat -c %Y "$MNT/empty")" = 981173106 ]

head -c 20000000 /dev/urandom > "$WORK/big"
cp "$WORK/big" "$MNT/big.bin"
check "20 MB multi-chunk copy"  cmp -s "$WORK/big" "$MNT/big.bin"

check "files owned by user"     [ "$(stat -c %u "$MNT/big.bin")" = "$(id -u)" ]
check "cp -p works"             cp -p "$MNT/rw.bin" "$MNT/rw-copy.bin"
check "df works"                quiet df "$MNT"

# ── Rename / delete ──
echo "moving" > "$MNT/a.txt"
mv "$MNT/a.txt" "$MNT/b.txt"
check "mv removes source"       [ ! -e "$MNT/a.txt" ]
check "mv keeps contents"       [ "$(cat "$MNT/b.txt")" = "moving" ]
echo "target" > "$MNT/c.txt"
mv -f "$MNT/b.txt" "$MNT/c.txt"
check "mv over existing file"   [ "$(cat "$MNT/c.txt")" = "moving" ]
check "...source gone"          [ ! -e "$MNT/b.txt" ]

echo "bye" > "$MNT/gone.txt"
rm "$MNT/gone.txt"
check "rm"                      [ ! -e "$MNT/gone.txt" ]

check "readdir lists files" \
    [ "$(find "$MNT" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = "big.bin c.txt empty hello.txt rw-copy.bin rw.bin " ]


# ── Nothing leaks in plaintext ──
check "no plaintext names/data in backing dir" \
    bash -c "! grep -rqasF -e moving -e 'c.txt' -e big.bin '$BACK'"

# ── Unmount: pending uploads/deletes must be flushed ──
unmount_fs
check "cloud matches backing dir after unmount" [ "$(blob_ids)" = "$(cloud_ids)" ]
check "cloud holds every file (and only those)"  [ "$(cloud_files | wc -l)" = 6 ]
check "no sync journal left behind"             [ ! -e "$BACK/sync.journal" ]
check "encrypted index uploaded to the cloud"   cmp -s "$BACK/index.enc" "$ENCFS_STUB_STORE/index"

# ── Remount: data persists; evicted blobs are fetched from the cloud ──
find "$BACK" -name '*.enc' ! -name index.enc -delete
mount_fs || fail "remount"
check "persisted across remount" [ "$(cat "$MNT/c.txt")" = "moving" ]
check "large file fetched from cloud" cmp -s "$WORK/big" "$MNT/big.bin"
unmount_fs

# ── Offline decrypt tool ──
check "decrypt_by_name --list" \
    bash -c "'$DECRYPT_BIN' -k '$KEY' --list '$BACK' | grep -q 'c.txt'"
check "decrypt_by_name to stdout" \
    [ "$("$DECRYPT_BIN" -k "$KEY" -c "$STUB" "$BACK" c.txt - 2>/dev/null)" = "moving" ]

# ── Tampering and wrong keys ──
# Flip one byte in every blob; every file must now fail to read.
mkdir "$WORK/saved"
cp "$BACK"/*.enc "$WORK/saved/"
for blob in "$BACK"/*.enc; do
    [ "$(basename "$blob")" = index.enc ] && continue
    printf '\xff' | dd of="$blob" bs=1 seek=50 conv=notrunc status=none
done
mount_fs
check_fails "tampered blob → I/O error"     bash -c "cat '$MNT/c.txt' >/dev/null 2>&1"
check_fails "tampered big blob → I/O error" bash -c "cat '$MNT/big.bin' >/dev/null 2>&1"
unmount_fs
cp "$WORK/saved"/*.enc "$BACK/"

# Swap two blobs: each is authentic, but bound to a different file.
mapfile -t BLOBS < <(blob_ids)
mv "$BACK/${BLOBS[0]}.enc" "$WORK/swap"
mv "$BACK/${BLOBS[1]}.enc" "$BACK/${BLOBS[0]}.enc"
mv "$WORK/swap" "$BACK/${BLOBS[1]}.enc"
mount_fs
FAILED_READS=0
for f in "$MNT"/*; do cat "$f" >/dev/null 2>&1 || FAILED_READS=$((FAILED_READS + 1)); done
check "swapped blobs are detected" [ "$FAILED_READS" -ge 1 ]
unmount_fs
cp "$WORK/saved"/*.enc "$BACK/"

INDEX_SUM=$(md5sum < "$BACK/index.enc")
(umask 077 && openssl rand -hex 32 > "$WORK/wrong_key")
check_fails "wrong key refuses to mount" "$FS_BIN" -k "$WORK/wrong_key" -c "$STUB" "$MNT" "$BACK" 2>/dev/null
check "wrong key leaves index untouched" [ "$(md5sum < "$BACK/index.enc")" = "$INDEX_SUM" ]

# ── Restore everything from the cloud alone (new machine) ──
EXPECTED_LIST=$("$DECRYPT_BIN" -k "$KEY" --list "$BACK" | sort)
rm -rf "$BACK"
mount_fs || fail "mount with empty backing dir"
check "index restored from cloud"     [ "$(find "$MNT" -mindepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = "big.bin c.txt empty hello.txt rw-copy.bin rw.bin " ]
check "contents restored from cloud"  [ "$(cat "$MNT/c.txt")" = "moving" ]
unmount_fs
check "decrypt_by_name restores into a new dir" \
    [ "$("$DECRYPT_BIN" -k "$KEY" -c "$STUB" "$WORK/elsewhere" c.txt - 2>/dev/null)" = "moving" ]
check "decrypt_by_name --list from cloud" \
    [ "$("$DECRYPT_BIN" -k "$KEY" -c "$STUB" --list "$WORK/elsewhere2" 2>/dev/null | sort)" = "$EXPECTED_LIST" ]

# ── A cloud index we failed to download must not be overwritten ──
# Simulate the cloud being unreachable for the index download at mount time
# only, then reachable again.
FLAKY="$WORK/flaky_cloudcli"
cat > "$FLAKY" <<FLAKY_EOF
#!/usr/bin/env bash
if [ -e "$WORK/cloud_down" ] && [ "\$1" = download ]; then exit 1; fi
exec "$STUB" "\$@"
FLAKY_EOF
chmod +x "$FLAKY"
CLOUD_INDEX_SUM=$(md5sum < "$ENCFS_STUB_STORE/index")
rm -rf "$BACK"
touch "$WORK/cloud_down"
CLOUDCLI="$FLAKY"
mount_fs || fail "mount while cloud is down"
rm "$WORK/cloud_down"
check_fails "write refused when a cloud index exists" bash -c "echo x > '$MNT/new.txt'" 2>/dev/null
unmount_fs
check "cloud index left untouched"   [ "$(md5sum < "$ENCFS_STUB_STORE/index")" = "$CLOUD_INDEX_SUM" ]
check "no stale local index kept"    [ ! -e "$BACK/index.enc" ]
mount_fs || fail "remount after cloud recovers"
check "remount restores the real index" [ "$(cat "$MNT/c.txt")" = "moving" ]
unmount_fs
CLOUDCLI="$STUB"

# ── Subdirectories ──
mount_fs || fail "mount for directory tests"
mkdir -p "$MNT/proj/src/deep"
echo "main" > "$MNT/proj/src/main.c"
echo "deep" > "$MNT/proj/src/deep/x.txt"
echo "readme" > "$MNT/proj/README"
check "mkdir -p and nested files"      [ "$(cat "$MNT/proj/src/deep/x.txt")" = "deep" ]
check "stat reports a directory"       [ -d "$MNT/proj/src" ]
check "readdir lists direct children"  [ "$(find "$MNT/proj" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')" = "README src " ]
check "find walks the tree"            [ "$(find "$MNT/proj" -type f | wc -l)" = 3 ]
check_fails "create in missing dir"    bash -c "echo x > '$MNT/nope/x'" 2>/dev/null
check_fails "mkdir existing"           mkdir "$MNT/proj" 2>/dev/null
check_fails "rmdir non-empty"          rmdir "$MNT/proj/src" 2>/dev/null
check_fails "rm on a directory"        rm "$MNT/proj" 2>/dev/null
check_fails "mv dir into itself"       mv "$MNT/proj" "$MNT/proj/src/" 2>/dev/null

mv "$MNT/proj/src" "$MNT/proj/lib"
check "mv directory moves contents"    [ "$(cat "$MNT/proj/lib/deep/x.txt")" = "deep" ]
check "...old path gone"               [ ! -e "$MNT/proj/src" ]
mv "$MNT/proj/README" "$MNT/proj/lib/deep/README"
check "mv file between directories"    [ "$(cat "$MNT/proj/lib/deep/README")" = "readme" ]
check "names stay private"             bash -c "! grep -rqasF -e proj/src -e main.c -e deep/x.txt '$BACK'"

unmount_fs
mount_fs || fail "remount for directory tests"
check "tree persists across remount"   [ "$(cat "$MNT/proj/lib/main.c")" = "main" ]
check "decrypt_by_name with a path" \
    [ "$("$DECRYPT_BIN" -k "$KEY" "$BACK" proj/lib/deep/x.txt - 2>/dev/null)" = "deep" ]
rm -r "$MNT/proj"
check "rm -r removes the tree"         [ ! -e "$MNT/proj" ]
unmount_fs
check "no orphaned blobs in the cloud" [ "$(cloud_files | wc -l)" = 6 ]

# ── Offline verify and export ──
check "decrypt_by_name --verify passes" \
    "$DECRYPT_BIN" -k "$KEY" -c "$STUB" --verify "$BACK" 2>/dev/null
"$DECRYPT_BIN" -k "$KEY" -c "$STUB" --extract-all "$WORK/export" "$BACK" 2>/dev/null
check "--extract-all writes every file"      [ "$(find "$WORK/export" -type f | wc -l)" = 6 ]
check "--extract-all contents match"         cmp -s "$WORK/big" "$WORK/export/big.bin"
check "--extract-all restores mtimes"        [ "$(stat -c %Y "$WORK/export/empty")" = 981173106 ]
check_fails "--extract-all refuses a non-empty dir" \
    "$DECRYPT_BIN" -k "$KEY" -c "$STUB" --extract-all "$WORK/export" "$BACK" 2>/dev/null

SOME_BLOB=$(find "$BACK" -name '*.enc' ! -name index.enc | head -1)
cp "$SOME_BLOB" "$WORK/blob_backup"
printf '\xff' | dd of="$SOME_BLOB" bs=1 seek=70 conv=notrunc status=none
check "--verify reports a tampered blob" \
    bash -c "'$DECRYPT_BIN' -k '$KEY' -c '$STUB' --verify '$BACK' 2>/dev/null | grep -q CORRUPT"
cp "$WORK/blob_backup" "$SOME_BLOB"
cp "$SOME_BLOB" "$BACK/$(printf 'f%.0s' $(seq 64)).enc"
check "--verify reports leftover blobs" \
    bash -c "'$DECRYPT_BIN' -k '$KEY' -c '$STUB' --verify '$BACK' 2>/dev/null | grep -q LEFTOVER"
rm "$BACK/$(printf 'f%.0s' $(seq 64)).enc"

# ── Local cache limit ──
# A separate store and backing dir, so the counts below are self-contained.
MAIN_BACK="$BACK"; MAIN_STORE="$ENCFS_STUB_STORE"
BACK="$WORK/cache_backing"; export ENCFS_STUB_STORE="$WORK/cache_cloud"
local_bytes() { find "$BACK" -maxdepth 1 -name '*.enc' ! -name index.enc -printf '%s\n' | awk '{s+=$1} END {print s+0}'; }
for i in 1 2 3 4; do head -c 600000 /dev/urandom > "$WORK/cache_src$i"; done
EXTRA_ARGS=(--cache-size 1M)

# Cloud down: nothing may be evicted, whatever the limit says.
export ENCFS_STUB_FAIL=1
mount_fs || fail "mount (cloud down)"
for i in 1 2 3 4; do cp "$WORK/cache_src$i" "$MNT/f$i"; done
unmount_fs
unset ENCFS_STUB_FAIL
check "cloud down: every blob kept locally"  [ "$(local_bytes)" -gt 2400000 ]
check "cloud down: work left in the journal" [ -s "$BACK/sync.journal" ]

# Cloud back: the journal uploads them, and the cache shrinks to the limit.
mount_fs || fail "mount (cloud up)"
check "files readable after reconnect"      cmp -s "$WORK/cache_src2" "$MNT/f2"
unmount_fs
check "cloud got all four blobs"            [ "$(cloud_ids | wc -l)" = 4 ]
check "local cache within 1 MiB"            [ "$(local_bytes)" -le 1048576 ]
check "synced.list records the uploads"     [ "$(wc -l < "$BACK/synced.list")" = 4 ]

# Evicted files come back from the cloud on demand, and stay within the limit.
mount_fs || fail "mount (evicted cache)"
ALL_OK=1
for i in 1 2 3 4; do cmp -s "$WORK/cache_src$i" "$MNT/f$i" || ALL_OK=0; done
check "evicted files re-download intact"    [ "$ALL_OK" = 1 ]
echo "edit" >> "$MNT/f1"
check "evicted file can be edited"          [ "$(tail -c 5 "$MNT/f1")" = "edit" ]
unmount_fs
check "still within 1 MiB after reads"      [ "$(local_bytes)" -le 1048576 ]
mount_fs || fail "mount (after edit)"
check "edit survived eviction"              [ "$(tail -c 5 "$MNT/f1")" = "edit" ]
unmount_fs
EXTRA_ARGS=()
BACK="$MAIN_BACK"; export ENCFS_STUB_STORE="$MAIN_STORE"

# ── Concurrency ──
# A slow download of one file must not stall the rest of the filesystem.
SLOW="$WORK/slow_cloudcli"
cat > "$SLOW" <<SLOW_EOF
#!/usr/bin/env bash
if [ "\$1" = download ] && [ -e "$WORK/slow_on" ]; then sleep 4; fi
exec "$STUB" "\$@"
SLOW_EOF
chmod +x "$SLOW"
mount_fs || fail "mount for concurrency tests"
head -c 300000 /dev/urandom > "$WORK/slow_src"
cp "$WORK/slow_src" "$MNT/slow.bin"
echo "fast" > "$MNT/fast.txt"
unmount_fs
find "$BACK" -name '*.enc' ! -name index.enc -delete   # force downloads
CLOUDCLI="$SLOW"
mount_fs || fail "mount with slow cloud"
cat "$MNT/fast.txt" >/dev/null   # fetch this one before the cloud slows down
touch "$WORK/slow_on"
START=$(date +%s.%N)
cat "$MNT/slow.bin" > "$WORK/slow_out" &
SLOW_PID=$!
sleep 0.5
T0=$(date +%s.%N)
ls "$MNT" >/dev/null
cat "$MNT/fast.txt" >/dev/null
echo "meanwhile" > "$MNT/meanwhile.txt"
T1=$(date +%s.%N)
wait "$SLOW_PID"
END=$(date +%s.%N)
rm -f "$WORK/slow_on"
check "slow download really was slow"     [ "$(echo "$END - $START > 3.5" | bc)" = 1 ]
check "other operations didn't wait for it" [ "$(echo "$T1 - $T0 < 1.5" | bc)" = 1 ]
check "slow file arrived intact"          cmp -s "$WORK/slow_src" "$WORK/slow_out"
unmount_fs
CLOUDCLI="$STUB"

# Many writers, readers and renamers at once.
mount_fs || fail "mount for stress test"
mkdir "$MNT/stress"
worker() {
    local w=$1
    for i in $(seq 25); do
        local f="$MNT/stress/w${w}_$i"
        printf 'worker %s round %s\n' "$w" "$i" > "$f"
        printf 'appended %s\n' "$i" >> "$f"
        printf 'X' | dd of="$f" bs=1 seek=0 conv=notrunc status=none
        mv "$f" "$f.done"
        [ "$(head -c 7 "$f.done")" = "Xorker " ] || echo "bad $f.done" >> "$WORK/stress_errors"
        if [ $((i % 5)) = 0 ]; then rm "$f.done"; fi
    done
}
STRESS_PIDS=()
for w in 1 2 3 4 5 6 7 8; do worker "$w" & STRESS_PIDS+=($!); done
( for _ in $(seq 40); do find "$MNT/stress" -type f -exec cat {} + >/dev/null 2>&1; done ) &
STRESS_PIDS+=($!)
wait "${STRESS_PIDS[@]}"   # not a bare `wait`: that would also wait for the daemon
check "no worker saw a corrupt file"      [ ! -e "$WORK/stress_errors" ]
check "every surviving file is present"   [ "$(find "$MNT/stress" -type f | wc -l)" = 160 ]
unmount_fs
mount_fs || fail "remount after stress test"
STRESS_OK=1
for w in 1 2 3 4 5 6 7 8; do
    for i in $(seq 25); do
        [ $((i % 5)) = 0 ] && continue
        [ "$(cat "$MNT/stress/w${w}_$i.done")" = "$(printf 'Xorker %s round %s\nappended %s' "$w" "$i" "$i")" ] || STRESS_OK=0
    done
done
check "all stress files intact after remount" [ "$STRESS_OK" = 1 ]
rm -r "$MNT/stress"
unmount_fs

# ── Inodes: hard links, symlinks, modes, index-only renames ──
mount_fs || fail "mount for inode tests"
mkdir -p "$MNT/ino/sub"
echo "shared" > "$MNT/ino/orig"
ln "$MNT/ino/orig" "$MNT/ino/sub/hard"
check "hard link reads the same data"    [ "$(cat "$MNT/ino/sub/hard")" = "shared" ]
check "link count is 2"                  [ "$(stat -c %h "$MNT/ino/orig")" = 2 ]
check "hard links share an inode number" [ "$(stat -c %i "$MNT/ino/orig")" = "$(stat -c %i "$MNT/ino/sub/hard")" ]
echo "edited via link" >> "$MNT/ino/sub/hard"
check "write via one name shows in other" [ "$(tail -1 "$MNT/ino/orig")" = "edited via link" ]
rm "$MNT/ino/orig"
check "data survives unlinking one name" [ "$(head -1 "$MNT/ino/sub/hard")" = "shared" ]
check "link count back to 1"             [ "$(stat -c %h "$MNT/ino/sub/hard")" = 1 ]

ln -s sub/hard "$MNT/ino/sym"
check "symlink resolves"                 [ "$(head -1 "$MNT/ino/sym")" = "shared" ]
check "readlink returns the target"      [ "$(readlink "$MNT/ino/sym")" = "sub/hard" ]
check "lstat sees a symlink"             [ -L "$MNT/ino/sym" ]

echo "#!/bin/sh" > "$MNT/ino/run.sh"
chmod 750 "$MNT/ino/run.sh"
check "chmod is stored"                  [ "$(stat -c %a "$MNT/ino/run.sh")" = 750 ]

# Exchange two paths atomically (renameat2 RENAME_EXCHANGE).
echo "A" > "$MNT/ino/a"; echo "B" > "$MNT/ino/b"
python3 - "$MNT/ino/a" "$MNT/ino/b" <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
AT_FDCWD, RENAME_EXCHANGE = -100, 2
if libc.renameat2(AT_FDCWD, sys.argv[1].encode(), AT_FDCWD, sys.argv[2].encode(), RENAME_EXCHANGE):
    sys.exit(os.strerror(ctypes.get_errno()))
PY
check "RENAME_EXCHANGE swaps"            [ "$(cat "$MNT/ino/a")$(cat "$MNT/ino/b")" = "BA" ]

# A directory rename is index-only: not one blob is rewritten.
for i in $(seq 20); do head -c 50000 /dev/urandom > "$MNT/ino/sub/f$i"; done
cp "$MNT/ino/sub/f7" "$WORK/ino_f7"
unmount_fs
BEFORE=$(cd "$BACK" && find . -name '*.enc' ! -name index.enc -printf '%f %s %T@\n' | sort | md5sum)
mount_fs || fail "remount for rename"
T0=$(date +%s.%N); mv "$MNT/ino/sub" "$MNT/ino/moved"; T1=$(date +%s.%N)
unmount_fs
AFTER=$(cd "$BACK" && find . -name '*.enc' ! -name index.enc -printf '%f %s %T@\n' | sort | md5sum)
check "directory rename rewrote no blobs" [ "$BEFORE" = "$AFTER" ]
check "...and was quick"                  [ "$(echo "$T1 - $T0 < 1" | bc)" = 1 ]
mount_fs || fail "remount after rename"
check "renamed tree persists"            cmp -s "$WORK/ino_f7" "$MNT/ino/moved/f7"
check "symlink still dangles correctly"  [ "$(readlink "$MNT/ino/sym")" = "sub/hard" ]
check "mode persists across remount"     [ "$(stat -c %a "$MNT/ino/run.sh")" = 750 ]
check "hard link persists"               [ "$(head -1 "$MNT/ino/moved/hard")" = "shared" ]
ln "$MNT/ino/moved/hard" "$MNT/ino/hard2"
unmount_fs

"$DECRYPT_BIN" -k "$KEY" -c "$STUB" --extract-all "$WORK/ino_export" "$BACK" >/dev/null 2>&1
check "export recreates symlinks"        [ "$(readlink "$WORK/ino_export/ino/sym")" = "sub/hard" ]
check "export recreates hard links"      [ "$(stat -c %i "$WORK/ino_export/ino/hard2")" = "$(stat -c %i "$WORK/ino_export/ino/moved/hard")" ]
check "export restores modes"            [ "$(stat -c %a "$WORK/ino_export/ino/run.sh")" = 750 ]
mount_fs || fail "mount to clean up"
rm -r "$MNT/ino"
unmount_fs

# ── Several machines sharing one cloud store ──
# Machines A and B: separate backing dirs (and mount points), same cloud + key.
MM="$WORK/mm"; mkdir -p "$MM/mntA" "$MM/mntB"
MAIN_STORE="$ENCFS_STUB_STORE"; export ENCFS_STUB_STORE="$MM/cloud"
mm_mount() {  # mm_mount <A|B> [args...]; sets MM_PID
    local m=$1; shift
    "$FS_BIN" -k "$KEY" -c "$STUB" "$@" "$MM/mnt$m" "$MM/back$m" >>"$LOG" 2>&1 &
    MM_PID=$!
    for _ in $(seq 50); do mountpoint -q "$MM/mnt$m" && return 0; kill -0 "$MM_PID" 2>/dev/null || return 1; sleep 0.1; done
    return 1
}
mm_umount() { fusermount3 -u "$MM/mnt$1"; while kill -0 "$2" 2>/dev/null; do sleep 0.1; done; }
mm_refused() {  # the mount must exit by itself (refused) instead of mounting
    local m=$1; shift
    if timeout 10 "$FS_BIN" -k "$KEY" -c "$STUB" "$@" "$MM/mnt$m" "$MM/back$m" >"$MM/refusal" 2>&1; then
        return 1
    fi
    if mountpoint -q "$MM/mnt$m"; then fusermount3 -u "$MM/mnt$m"; return 1; fi
    return 0
}
cloud_list() { rm -rf "$MM/peek"; "$DECRYPT_BIN" -k "$KEY" -c "$STUB" --list "$MM/peek" 2>/dev/null | cut -f2 | tr '\n' ' '; }

# Hand-off: A writes, B restores and writes, A picks B's change up.
mm_mount A || fail "mount A"; echo one > "$MM/mntA/f1"; mm_umount A "$MM_PID"
mm_mount B || fail "mount B"
check "B restores A's file"              [ "$(cat "$MM/mntB/f1")" = one ]
echo two > "$MM/mntB/f2"; mm_umount B "$MM_PID"
mm_mount A || fail "remount A"
check "A adopts B's newer index"         [ "$(cat "$MM/mntA/f2")" = two ]
echo "one, edited on A" > "$MM/mntA/f1"; mm_umount A "$MM_PID"
mm_mount B || fail "remount B"
check "B sees A's edit (stale blob dropped)" [ "$(cat "$MM/mntB/f1")" = "one, edited on A" ]
mm_umount B "$MM_PID"

# Conflict: A changes things offline while B changes the cloud.
export ENCFS_STUB_FAIL=1
mm_mount A || fail "mount A offline"; echo "A offline" > "$MM/mntA/fA"; mm_umount A "$MM_PID"
unset ENCFS_STUB_FAIL
mm_mount B || fail "mount B"; echo "B online" > "$MM/mntB/fB"; mm_umount B "$MM_PID"
check "conflicting mount is refused"     mm_refused A
check "...with an explanation"           grep -q -e "--prefer-cloud" "$MM/refusal"
mm_mount A --prefer-cloud || fail "mount A --prefer-cloud"
check "--prefer-cloud takes B's changes" [ -e "$MM/mntA/fB" ]
check "...and drops A's unsynced ones"   [ ! -e "$MM/mntA/fA" ]
mm_umount A "$MM_PID"

export ENCFS_STUB_FAIL=1
mm_mount A || fail "mount A offline 2"; echo "A wins" > "$MM/mntA/fA2"; mm_umount A "$MM_PID"
unset ENCFS_STUB_FAIL
mm_mount B || fail "mount B 2"; echo "B loses" > "$MM/mntB/fB2"; mm_umount B "$MM_PID"
mm_mount A --prefer-local || fail "mount A --prefer-local"
check "--prefer-local keeps A's changes" [ "$(cat "$MM/mntA/fA2")" = "A wins" ]
mm_umount A "$MM_PID"
LIST=$(cloud_list)
check "cloud index has A's file, not B's" bash -c "[[ \"$LIST\" == *fA2* && \"$LIST\" != *fB2* ]]"
mm_mount B || fail "mount B after prefer-local"
check "B follows the cloud"              [ "$(cat "$MM/mntB/fA2")" = "A wins" ]
mm_umount B "$MM_PID"

# Both mounted at once: whoever uploads second must not overwrite the first.
mm_mount A || fail "mount A (concurrent)"; PID_A=$MM_PID
mm_mount B || fail "mount B (concurrent)"; PID_B=$MM_PID
echo "from B" > "$MM/mntB/fB3"; mm_umount B "$PID_B"
echo "from A" > "$MM/mntA/fA3"
for _ in $(seq 50); do grep -q "changed by another machine" "$LOG" && break; sleep 0.1; done
check "A detects the concurrent change"  grep -q "changed by another machine" "$LOG"
check_fails "A refuses further writes"   bash -c "echo more > '$MM/mntA/fA4'" 2>/dev/null
mm_umount A "$PID_A"
LIST=$(cloud_list)
check "cloud kept B's index intact"      bash -c "[[ \"$LIST\" == *fB3* && \"$LIST\" != *fA3* ]]"
check "A must then resolve the conflict" mm_refused A
mm_mount A --prefer-cloud || fail "resolve A"; mm_umount A "$MM_PID"

# Rollback: an old copy of the index put back in the cloud is refused.
cp "$MM/cloud/index" "$MM/old_index"
mm_mount B || fail "mount B (rollback)"; echo newer > "$MM/mntB/f_new"; mm_umount B "$MM_PID"
cp "$MM/old_index" "$MM/cloud/index"
check "rolled-back cloud index refused"  mm_refused B
check "...with an explanation"           grep -q "rolled back" "$MM/refusal"
mm_mount B --prefer-local || fail "repair rollback"
check "--prefer-local restores it"       [ "$(cat "$MM/mntB/f_new")" = newer ]
mm_umount B "$MM_PID"
export ENCFS_STUB_STORE="$MAIN_STORE"

# ── encfsctl: init, passphrase changes, status ──
CTL_WORK="$WORK/ctl"; mkdir -p "$CTL_WORK"
check "init creates a key file"            quiet "$CTL_BIN" init -k "$CTL_WORK/new.key" "$CTL_WORK/keyed"
check "...with mode 0600"                  [ "$(stat -c %a "$CTL_WORK/new.key")" = 600 ]
check_fails "init won't overwrite a key"   "$CTL_BIN" init -k "$CTL_WORK/new.key" "$CTL_WORK/other" 2>/dev/null

MAIN_BACK="$BACK"; MAIN_STORE="$ENCFS_STUB_STORE"
BACK="$CTL_WORK/pass_backing"; export ENCFS_STUB_STORE="$CTL_WORK/pass_cloud"
pmount() {  # mount the passphrase store with $1
    ENCFS_PASSPHRASE="$1" "$FS_BIN" -p -c "$STUB" "$MNT" "$BACK" >>"$LOG" 2>&1 &
    FS_PID=$!
    for _ in $(seq 50); do mountpoint -q "$MNT" && return 0; kill -0 "$FS_PID" 2>/dev/null || return 1; sleep 0.1; done
    return 1
}
check "init --passphrase"                  quiet env ENCFS_PASSPHRASE=first "$CTL_BIN" init -p "$BACK"
check_fails "init refuses an existing store" env ENCFS_PASSPHRASE=x "$CTL_BIN" init -p "$BACK" 2>/dev/null
check_fails "wrong passphrase rejected before any data exists" \
    env ENCFS_PASSPHRASE=typo "$FS_BIN" -p -c "$STUB" "$MNT" "$BACK" 2>/dev/null
pmount first || fail "mount with passphrase"
echo "guarded by a passphrase" > "$MNT/p.txt"
unmount_fs
# Machine B restores the passphrase store before the passphrase changes.
BACK_A="$BACK"; BACK="$CTL_WORK/pass_backing_B"
pmount first || fail "mount B with passphrase"
check "machine B restores the passphrase store" [ "$(cat "$MNT/p.txt")" = "guarded by a passphrase" ]
unmount_fs
BACK="$BACK_A"
check "passwd changes the passphrase" \
    quiet env ENCFS_PASSPHRASE=first ENCFS_NEW_PASSPHRASE=second "$CTL_BIN" passwd -c "$STUB" "$BACK"
check_fails "passwd needs the right current passphrase" \
    env ENCFS_PASSPHRASE=first ENCFS_NEW_PASSPHRASE=third "$CTL_BIN" passwd -c "$STUB" "$BACK" 2>/dev/null
check_fails "old passphrase no longer works" \
    env ENCFS_PASSPHRASE=first "$FS_BIN" -p -c "$STUB" "$MNT" "$BACK" 2>/dev/null
pmount second || fail "mount with new passphrase"
check "files intact under the new passphrase" [ "$(cat "$MNT/p.txt")" = "guarded by a passphrase" ]
unmount_fs
check "cloud got the new encfs.kdf"        cmp -s "$BACK/encfs.kdf" "$ENCFS_STUB_STORE/encfs.kdf"
check "upload clears the pending marker"   [ ! -e "$BACK/encfs.kdf.pending" ]
# B still has the old encfs.kdf: its next mount picks up the change instead
# of reverting it, and from then on only the new passphrase works there.
BACK="$CTL_WORK/pass_backing_B"
pmount first || fail "mount B with its stale encfs.kdf"
unmount_fs
check "B adopted the new encfs.kdf"        grep -q "passphrase was changed on another machine" "$LOG"
check "cloud kept the new encfs.kdf"       cmp -s "$BACK_A/encfs.kdf" "$ENCFS_STUB_STORE/encfs.kdf"
check_fails "B now refuses the old passphrase" \
    env ENCFS_PASSPHRASE=first "$FS_BIN" -p -c "$STUB" "$MNT" "$BACK" 2>/dev/null
pmount second || fail "mount B with the new passphrase"
unmount_fs
BACK="$BACK_A"
check "restore on a new machine with the new passphrase" \
    [ "$(ENCFS_PASSPHRASE=second "$DECRYPT_BIN" -p -c "$STUB" "$CTL_WORK/fresh" p.txt - 2>/dev/null)" = "guarded by a passphrase" ]
STATUS=$(ENCFS_PASSPHRASE=second "$CTL_BIN" status -p "$BACK" 2>&1)
check "status reports files and the KDF"   bash -c "grep -q 'Files: *1 in 0 directories' <<<\"\$0\" && grep -q 'encfs.kdf v2' <<<\"\$0\"" "$STATUS"
BACK="$MAIN_BACK"; export ENCFS_STUB_STORE="$MAIN_STORE"

# ── Large files: segments, incremental sync, padding ──
# Files are stored as 4 MiB segments; an edit re-uploads only the segments
# it touched, and a read downloads only the segments it needs.
MAIN_BACK="$BACK"; MAIN_STORE="$ENCFS_STUB_STORE"
SEG="$WORK/seg"; mkdir -p "$SEG"
BACK="$SEG/backing"; export ENCFS_STUB_STORE="$SEG/cloud"
log_mark() { wc -l < "$LOG"; }
log_since() { tail -n +"$(( $1 + 1 ))" "$LOG"; }
uploads_since() { log_since "$1" | grep '^Uploaded ' | grep -vc -e ' -> index$' -e ' -> encfs.kdf$'; }
deletes_since() { log_since "$1" | grep -c '^Deleted '; }
downloads_since() { log_since "$1" | grep '^Downloaded ' | grep -vc -e '^Downloaded index ' -e '^Downloaded encfs.kdf '; }
local_objects() { find "$BACK" -maxdepth 1 -name '*.enc' ! -name index.enc | wc -l; }

head -c 18000000 /dev/urandom > "$SEG/src"   # 5 segments: 4 × 4 MiB + 1.2 MB
mount_fs || fail "mount (segments)"
cp "$SEG/src" "$MNT/large.bin"
unmount_fs
check "a large file is stored as 5 segment objects" [ "$(cloud_ids | wc -l)" = 5 ]
check "...named <inode>.<segment>.<version>"  [ "$(cloud_ids | grep -cE '^[0-9a-f]{64}\.[0-4]\.[0-9]+$')" = 5 ]

# Change one byte in the middle (segment 2).
printf 'Z' | dd of="$SEG/src" bs=1 seek=9000000 conv=notrunc status=none
MARK=$(log_mark)
mount_fs || fail "mount (one-byte edit)"
printf 'Z' | dd of="$MNT/large.bin" bs=1 seek=9000000 conv=notrunc status=none
unmount_fs
check "a one-byte edit uploads exactly one segment" [ "$(uploads_since "$MARK")" = 1 ]
check "...and deletes only the segment it replaced" [ "$(deletes_since "$MARK")" = 1 ]
check "the cloud still holds 5 segments"           [ "$(cloud_ids | wc -l)" = 5 ]
mount_fs || fail "mount (after edit)"
check "the edited file reads back correctly"        cmp -s "$SEG/src" "$MNT/large.bin"
unmount_fs

# Appending rewrites only the old last segment and adds new ones.
head -c 5000000 /dev/urandom > "$SEG/more"
cat "$SEG/more" >> "$SEG/src"
MARK=$(log_mark)
mount_fs || fail "mount (append)"
cat "$SEG/more" >> "$MNT/large.bin"
unmount_fs
check "appending 5 MB uploads 2 segments, not 6"   [ "$(uploads_since "$MARK")" = 2 ]
mount_fs || fail "mount (after append)"
check "the appended file reads back correctly"     cmp -s "$SEG/src" "$MNT/large.bin"
unmount_fs

# A new machine downloads only what it reads.
BACK="$SEG/backing_B"
MARK=$(log_mark)
mount_fs || fail "mount (fresh machine)"
check "reading the first KiB works"                [ "$(head -c 1024 "$MNT/large.bin" | cmp -s - <(head -c 1024 "$SEG/src") && echo ok)" = ok ]
check "...and downloads only the first segment"    [ "$(downloads_since "$MARK")" = 1 ]
check "...so only one object is cached locally"    [ "$(local_objects)" = 1 ]
check "reading the end fetches the last segment"   cmp -s <(tail -c 1000 "$MNT/large.bin") <(tail -c 1000 "$SEG/src")
check "...two objects downloaded in all"           [ "$(downloads_since "$MARK")" = 2 ]
check "a full read gets every segment"             cmp -s "$SEG/src" "$MNT/large.bin"
check "...each exactly once"                       [ "$(downloads_since "$MARK")" = 6 ]

# Truncating drops the segments past the new end.
truncate -s 5000000 "$MNT/large.bin"
truncate -s 5000000 "$SEG/src"
unmount_fs
check "truncating leaves 2 segments in the cloud"  [ "$(cloud_ids | wc -l)" = 2 ]
check "...and 2 locally"                           [ "$(local_objects)" = 2 ]
BACK="$SEG/backing"
mount_fs || fail "mount (machine A after truncate)"
check "machine A sees the truncated file"          cmp -s "$SEG/src" "$MNT/large.bin"
check "...and dropped its stale segments"          [ "$(local_objects)" -le 2 ]
unmount_fs

# Offline tools understand segmented files.
check "decrypt_by_name restores a segmented file" \
    cmp -s "$SEG/src" <("$DECRYPT_BIN" -k "$KEY" -c "$STUB" "$SEG/backing" large.bin - 2>/dev/null)
check "...from the cloud alone" \
    cmp -s "$SEG/src" <("$DECRYPT_BIN" -k "$KEY" -c "$STUB" "$SEG/fresh" large.bin - 2>/dev/null)
check "--verify passes"                            quiet "$DECRYPT_BIN" -k "$KEY" -c "$STUB" --verify "$SEG/backing"
VICTIM=$(find "$SEG/backing" -maxdepth 1 -name '*.1.*.enc' | head -1)
cp "$VICTIM" "$SEG/victim.bak"
printf 'X' | dd of="$VICTIM" bs=1 seek=200 conv=notrunc status=none
check_fails "--verify catches a tampered segment"  quiet "$DECRYPT_BIN" -k "$KEY" -c "$STUB" --verify "$SEG/backing"
cp "$SEG/victim.bak" "$VICTIM"
SEG0=$(find "$SEG/backing" -maxdepth 1 -name '*.0.*.enc' | head -1)
cp "$VICTIM" "$SEG/victim.bak"; cp "$SEG0" "$VICTIM"
check_fails "--verify catches a segment moved to another position" \
    quiet "$DECRYPT_BIN" -k "$KEY" -c "$STUB" --verify "$SEG/backing"
cp "$SEG/victim.bak" "$VICTIM"
mount_fs || fail "mount (after restoring the segment)"
check "status counts segment objects" \
    bash -c "'$CTL_BIN' status -k '$KEY' '$BACK' | grep -q '2 encrypted object(s) (1 large file(s) split into segments)'"
unmount_fs

# --pad: the cloud learns sizes only to within a power of two.
BACK="$SEG/pad_backing"; export ENCFS_STUB_STORE="$SEG/pad_cloud"
EXTRA_ARGS=(--pad)
mount_fs || fail "mount (--pad)"
head -c 2500 /dev/urandom > "$MNT/a"
head -c 4000 /dev/urandom > "$MNT/b"
head -c 10 /dev/urandom > "$MNT/c"
check "padded files keep their real size"          [ "$(stat -c %s "$MNT/a")" = 2500 ]
unmount_fs
EXTRA_ARGS=()
pad_sizes=$(find "$ENCFS_STUB_STORE" -maxdepth 1 -type f ! -name index ! -name '.*' -printf '%s\n' | sort -n | uniq | tr '\n' ' ')
check "2500 and 4000 bytes look alike in the cloud" \
    [ "$(find "$ENCFS_STUB_STORE" -maxdepth 1 -type f ! -name index ! -name '.*' -printf '%s\n' | sort -n | uniq -c | awk '$1 == 2' | wc -l)" = 1 ]
check "a tiny file is padded to at least 1 KiB"    [ "${pad_sizes%% *}" -gt 1024 ]
mount_fs || fail "mount (read padded)"
check "padded files read back at their real size"  [ "$(wc -c < "$MNT/c") $(wc -c < "$MNT/b")" = "10 4000" ]
unmount_fs
BACK="$MAIN_BACK"; export ENCFS_STUB_STORE="$MAIN_STORE"

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "✓ All end-to-end tests passed"
else
    echo "✗ $FAILURES end-to-end test(s) failed"
    exit 1
fi

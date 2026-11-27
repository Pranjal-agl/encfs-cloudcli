#!/usr/bin/env bash
# End-to-end test: mounts the real filesystem with FUSE and exercises it with
# ordinary shell tools. Needs /dev/fuse and fusermount3.
#
#   tests/e2e/run_e2e.sh <encrypted_cloudfs> <decrypt_by_name> <cloudcli_stub>

set -uo pipefail

FS_BIN=$(realpath "$1")
DECRYPT_BIN=$(realpath "$2")
STUB=$(realpath "$3")

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

mount_fs() {
    "$FS_BIN" -k "$KEY" -c "$STUB" "$MNT" "$BACK" >>"$LOG" 2>&1 &
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
cloud_ids() { find "$ENCFS_STUB_STORE" -maxdepth 1 -type f ! -name '.*' -printf '%f\n' | sort; }

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
check "df works"                df "$MNT" >/dev/null

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

check_fails "nested paths rejected" mkdir "$MNT/dir" 2>/dev/null

# ── Nothing leaks in plaintext ──
check "no plaintext names/data in backing dir" \
    bash -c "! grep -rqa -e moving -e 'c.txt' -e big.bin '$BACK'"

# ── Unmount: pending uploads/deletes must be flushed ──
unmount_fs
check "cloud matches backing dir after unmount" [ "$(blob_ids)" = "$(cloud_ids)" ]
check "cloud holds one blob per file"           [ "$(cloud_ids | wc -l)" = 6 ]
check "no sync journal left behind"             [ ! -e "$BACK/sync.journal" ]

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

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "✓ All end-to-end tests passed"
else
    echo "✗ $FAILURES end-to-end test(s) failed"
    exit 1
fi

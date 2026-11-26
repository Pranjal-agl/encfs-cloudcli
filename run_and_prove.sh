#!/usr/bin/env bash
# =============================================================
# run_and_prove.sh — build, test, and live-demo encfs-cloudcli
#
#   ./run_and_prove.sh                 # build + test + demo
#   ./run_and_prove.sh --install-deps  # apt-get the prerequisites first
#
# Everything runs in a throwaway temp directory: your ~/.encfs/key and any
# existing mounts or backing directories are never touched.
# =============================================================

set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
banner() { echo -e "\n${BOLD}${CYAN}══ $1 ══${NC}"; }
ok()     { echo -e "  ${GREEN}✓ $1${NC}"; }
fail()   { echo -e "  ${RED}✗ $1${NC}"; exit 1; }

cd "$(dirname "$0")"
ROOT=$(pwd)

if [ "${1:-}" = "--install-deps" ]; then
    banner "Installing dependencies"
    sudo apt-get update -qq
    sudo apt-get install -y build-essential cmake libfuse3-dev libssl-dev pkg-config fuse3
fi

for tool in cmake pkg-config fusermount3 openssl; do
    command -v "$tool" >/dev/null || fail "$tool not found (try: $0 --install-deps)"
done

banner "Building"
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENCFS_E2E=ON >/dev/null
cmake --build build -j"$(nproc)"
ok "Build succeeded"

banner "Running tests (unit, integration, FUSE end-to-end)"
ctest --test-dir build --output-on-failure
ok "All tests passed"

banner "Live demo"
DEMO=$(mktemp -d /tmp/encfs_demo.XXXXXX)
MOUNT="$DEMO/mount"; BACKING="$DEMO/backing"; KEY="$DEMO/key"
export ENCFS_STUB_STORE="$DEMO/cloud"
mkdir -p "$MOUNT" "$BACKING"
(umask 077 && openssl rand -hex 32 > "$KEY")

FS_PID=""
cleanup() {
    fusermount3 -u "$MOUNT" 2>/dev/null || true
    if [ -n "$FS_PID" ]; then wait "$FS_PID" 2>/dev/null || true; fi
    rm -rf "$DEMO"
}
trap cleanup EXIT

./build/encrypted_cloudfs -k "$KEY" -c "$ROOT/tools/cloudcli_stub" "$MOUNT" "$BACKING" \
    >"$DEMO/fs.log" 2>&1 &
FS_PID=$!
for _ in $(seq 50); do mountpoint -q "$MOUNT" && break; sleep 0.1; done
mountpoint -q "$MOUNT" || { cat "$DEMO/fs.log"; fail "mount failed"; }
ok "Mounted at $MOUNT"

echo "Top secret quarterly numbers" > "$MOUNT/report.txt"
echo "PS: also secret"              >> "$MOUNT/report.txt"
echo "  Through the mount:"
sed 's/^/    /' "$MOUNT/report.txt"

echo "  In the backing directory (names are HMACs, contents are ciphertext):"
find "$BACKING" -mindepth 1 -printf '    %f\n'
BLOB=$(find "$BACKING" -name '*.enc' ! -name index.enc | head -1)
od -A x -t x1z -N 64 "$BLOB" | sed "s/^/    /"
if grep -rqa -e "secret" -e "report" "$BACKING"; then
    fail "plaintext found in backing directory"
fi
ok "No plaintext names or contents in the backing directory"

fusermount3 -u "$MOUNT"
wait "$FS_PID" || true
FS_PID=""
ok "Unmounted (pending uploads were flushed)"

echo "  Simulated cloud store:"
find "$ENCFS_STUB_STORE" -mindepth 1 -printf '    %f\n'

echo "  Recovering a file without mounting:"
./build/decrypt_by_name -k "$KEY" "$BACKING" report.txt - | sed 's/^/    /'

banner "All done"
echo -e "${GREEN}${BOLD}  encfs-cloudcli built, tested, and demonstrated successfully.${NC}"

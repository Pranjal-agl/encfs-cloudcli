#!/usr/bin/env bash
# Cross-check web/encfs.js against the C++ implementation in both directions.
#   tests/web/run_cross_check.sh <web_fixtures binary>
# Exits 77 (ctest "skipped") if Node.js >= 20 isn't available.

set -euo pipefail

FIXTURES=$(realpath "$1")
HERE=$(cd "$(dirname "$0")" && pwd)

if ! command -v node >/dev/null || [ "$(node -p 'parseInt(process.versions.node)')" -lt 20 ]; then
    echo "Node.js >= 20 not found; skipping"
    exit 77
fi

WORK=$(mktemp -d /tmp/encfs_web.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "C++ → JS"
"$FIXTURES" gen "$WORK"
node "$HERE/cross_check.mjs" "$WORK"
echo "JS → C++"
"$FIXTURES" verify "$WORK"
echo
echo "✓ web/encfs.js and the C++ implementation agree"

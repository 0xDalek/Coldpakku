#!/usr/bin/env bash
#
# Builds all artifacts of a GBA Signer release and drops them under
# releases/ ready to be uploaded to a GitHub release.
#
# Produces (for VERSION=0.1.0):
#   releases/gba-signer-v0.1.0.gba                    (the GBA ROM)
#   releases/gba-signer-pico-bridge-v0.1.0.zip        (Pico bridge bundle)
#   releases/gba-signer-extension-v0.1.0.zip          (browser extension)
#   releases/RELEASE_NOTES_v0.1.0.md                  (release notes copy)
#
# Requirements:
#   - DEVKITPRO and DEVKITARM in env (or auto-detected from .devkitpro/)
#   - node + npm (for the extension)
#   - python3 (used to ZIP folders; no `zip` binary required)
#
# Usage:
#   ./scripts/build_release.sh            # uses VERSION=0.1.0
#   VERSION=0.2.0 ./scripts/build_release.sh
set -euo pipefail

VERSION="${VERSION:-0.1.0}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# --- locate devkitARM (env first, then in-tree fallback at .devkitpro/) -------
if [ -z "${DEVKITPRO:-}" ] && [ -d "$ROOT/.devkitpro/opt/devkitpro" ]; then
    export DEVKITPRO="$ROOT/.devkitpro/opt/devkitpro"
fi
if [ -z "${DEVKITARM:-}" ] && [ -n "${DEVKITPRO:-}" ]; then
    export DEVKITARM="$DEVKITPRO/devkitARM"
fi
: "${DEVKITPRO:?DEVKITPRO not set and no .devkitpro/ found in repo root}"
: "${DEVKITARM:?DEVKITARM not set}"

mkdir -p releases

# Helper: create a deterministic ZIP from a folder using Python (so we
# do not depend on the `zip` system binary).
zipdir() {
    local src="$1"
    local out="$2"
    python3 -c "
import os, sys, zipfile
src = sys.argv[1]
out = sys.argv[2]
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as zf:
    for root, _dirs, files in os.walk(src):
        for f in sorted(files):
            full = os.path.join(root, f)
            arc = os.path.relpath(full, src)
            zf.write(full, arc)
" "$src" "$out"
}

echo
echo "==[ 1/4 ]== Building GBA ROM (gba-signer-v${VERSION}.gba)"
./build.sh
cp gba-signer.gba "releases/gba-signer-v${VERSION}.gba"

echo
echo "==[ 2/4 ]== Bundling Pico bridge files (pico-bridge-v${VERSION}.zip)"
PICO_DIR="releases/_pico-bundle"
rm -rf "$PICO_DIR"
mkdir -p "$PICO_DIR"
cp pico/main.py "$PICO_DIR/main.py"
if [ -f docs/PICO_BRIDGE_QUICKSTART.md ]; then
    cp docs/PICO_BRIDGE_QUICKSTART.md "$PICO_DIR/README.txt"
else
    echo "WARN: docs/PICO_BRIDGE_QUICKSTART.md not found, skipping README.txt"
fi
rm -f "releases/gba-signer-pico-bridge-v${VERSION}.zip"
zipdir "$PICO_DIR" "releases/gba-signer-pico-bridge-v${VERSION}.zip"
rm -rf "$PICO_DIR"

echo
echo "==[ 3/4 ]== Building extension ZIP (gba-signer-extension-v${VERSION}.zip)"
(
    cd extension
    if [ ! -d node_modules ]; then
        npm install
    fi
    rm -rf dist
    npm run build
)
rm -f "releases/gba-signer-extension-v${VERSION}.zip"
zipdir "extension/dist" "releases/gba-signer-extension-v${VERSION}.zip"

echo
echo "==[ 4/4 ]== Copying release notes"
if [ -f RELEASE_NOTES.md ]; then
    cp RELEASE_NOTES.md "releases/RELEASE_NOTES_v${VERSION}.md"
else
    echo "WARN: RELEASE_NOTES.md not found at repo root"
fi

echo
echo "Done. Artifacts:"
ls -lh releases/ | grep -v '^total' | awk '{printf "  %-50s %s\n", $9, $5}'
echo
echo "Upload these files to:"
echo "  https://github.com/<your-user>/gba-signer/releases/new"

#!/usr/bin/env bash
# Build the release tarball: a self-contained tree that builds from
# scratch, named for the version in VERSION.
set -euo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ver="$(cat "$ROOT/VERSION" 2>/dev/null || echo unknown)"
name="wifisting-$ver"
out="${1:-$HOME/$name.tar.gz}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/$name"

# Runtime state is not part of a release, and .git would triple the size.
tar -C "$ROOT" \
    --exclude='.git' --exclude='native/builddir' \
    --exclude='state' --exclude='loot' --exclude='logs' \
    --exclude='captures' --exclude='tmp' \
    --exclude='*.bak.*' --exclude='__pycache__' --exclude='*.pyc' \
    -cf - . | tar -C "$tmp/$name" -xf -

tar -C "$tmp" -czf "$out" "$name"

printf 'built:  %s\n' "$out"
printf 'size:   %s\n' "$(du -h "$out" | cut -f1)"
printf 'root:   %s/ (not the checkout name)\n' "$name"
printf 'modules: %s\n' "$(tar -tzf "$out" | grep -cE "modules/[0-9]+.*\.sh$")"
printf 'version: %s\n' "$(tar -xzOf "$out" "$name/VERSION")"

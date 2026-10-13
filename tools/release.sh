#!/usr/bin/env bash
# =====================================================================
#  release.sh — cut a release
#
#  Bumps VERSION, commits, tags and pushes to both remotes. Still asks
#  you which number, because that is a judgement a script cannot make:
#
#    patch  1.0.1  bug fixes, nothing new
#    minor  1.1.0  new modules or verbs, nothing breaks
#    major  2.0.0  someone's script breaks
#
#  Usage:  tools/release.sh 1.1.0 ["commit message"]
# =====================================================================
set -euo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { printf 'release: %s\n' "$*" >&2; exit 1; }

ver="${1:-}"
[[ -n "$ver" ]] || die "usage: tools/release.sh X.Y.Z [\"message\"]"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be X.Y.Z, got: $ver"

cur="$(cat VERSION 2>/dev/null || echo none)"
[[ "$ver" != "$cur" ]] || die "VERSION is already $ver"

# A release should not carry uncommitted work.
git diff --quiet && git diff --cached --quiet \
    || die "working tree has uncommitted changes — commit or stash first"

branch="$(git rev-parse --abbrev-ref HEAD)"
[[ "$branch" == "main" ]] || die "on $branch, not main"

# Be current with the remotes before tagging, or the tag points at a
# commit they do not have.
for r in origin gitlab; do
    git remote get-url "$r" >/dev/null 2>&1 || continue
    git fetch -q "$r" || true
    if [[ "$(git rev-list --count "HEAD..$r/main" 2>/dev/null || echo 0)" != "0" ]]; then
        printf 'release: pulling from %s first\n' "$r"
        git pull --rebase "$r" main
    fi
done

printf '%s\n' "$ver" > VERSION
git add VERSION module_index.tsv native/src/module_index.c 2>/dev/null || true

msg="${2:-Release $ver}"
git commit -q -m "$msg"
tag="v$ver"
git tag -a "$tag" -m "wifisting $ver"

printf 'release: tagged %s at %s\n' "$tag" "$(git rev-parse --short HEAD)"

git push origin main 2>&1 | tail -1
git push origin --tags 2>&1 | tail -1
git remote get-url gitlab >/dev/null 2>&1 && { git push gitlab main 2>&1 | tail -1; git push gitlab --tags 2>&1 | tail -1; }

printf '\nrelease: %s is out.\n' "$tag"
printf 'Build the artifact with:  tools/mktar.sh\n'

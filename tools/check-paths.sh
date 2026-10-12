#!/usr/bin/env bash
# check-paths.sh — verify the GUI's script paths and module ids resolve on disk.
#
# The GUI reaches modules through two independent tables:
#   * #define <NAME>_SCRIPT PROJECT_DIR "/modules/<file>.sh"  (used by actions)
#   * the modules[] table                                      (used by the UI)
# A stale entry in either one is invisible to the compiler and to the modules'
# own --selftest runs, because nothing executes the path until a user clicks.
# That is exactly how WPA3_ATTACK_SCRIPT sat pointing at 03b_wpa3_attack.sh,
# a file that never existed, while 47_wpa3_attack.sh was the real module.
#
# Usage: tools/check-paths.sh
# Exit:  0 clean, 1 problems found.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/native/src/main1.c"
MODS="$ROOT/modules"

[[ -f "$SRC" ]] || { echo "no such file: $SRC" >&2; exit 1; }

problems=0

# --- 1. every PROJECT_DIR "/modules/..." literal must exist ----------------
while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    if [[ ! -f "$ROOT$rel" ]]; then
        echo "MISSING FILE: $rel is referenced by main1.c but does not exist"
        problems=$((problems + 1))
    elif [[ ! -x "$ROOT$rel" ]]; then
        echo "NOT EXECUTABLE: $rel (the GUI execs it directly)"
        problems=$((problems + 1))
    fi
done < <(grep -oE 'PROJECT_DIR "/modules/[^"]+"' "$SRC" \
         | sed 's/.*"\(.*\)"/\1/' | sort -u)

# --- 2. every modules[] id must have modules/<id>.sh ----------------------
while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    if [[ ! -f "$MODS/$id.sh" ]]; then
        echo "MISSING MODULE: modules[] lists '$id' but modules/$id.sh is absent"
        problems=$((problems + 1))
    fi
done < <(awk '/^static const ModuleDefinition modules\[\]/,/^};/' "$SRC" \
         | grep -oE '\{ "[0-9][A-Za-z0-9_.]*"' | sed 's/{ "//; s/"$//' | sort -u)

# --- 3. module scripts on disk with no modules[] entry --------------------
# 28_live_traffic and 27b_fw_update_audit are tabs/helpers, not modules, so
# they are legitimately absent from the table.
#
# The registered ids are collected once, up front. Running `awk ... | grep -q`
# inside the loop instead would race: grep -q exits at the first match, awk
# takes SIGPIPE, and `set -o pipefail` reports the pipeline as failed even
# though the id was found.
declare -A registered=()
while IFS= read -r id; do
    [[ -n "$id" ]] && registered["$id"]=1
done < <(awk '/^static const ModuleDefinition modules\[\]/,/^};/' "$SRC" \
         | grep -oE '\{ "[0-9][A-Za-z0-9_.]*"' | sed 's/{ "//; s/"$//')

while IFS= read -r f; do
    id="$(basename "$f" .sh)"
    case "$id" in
        27b_fw_update_audit|28_live_traffic) continue ;;
    esac
    if [[ -z "${registered[$id]:-}" ]]; then
        echo "UNREGISTERED: modules/$id.sh exists but is not in modules[]"
        problems=$((problems + 1))
    fi
done < <(ls -1 "$MODS"/*.sh 2>/dev/null)

if (( problems == 0 )); then
    echo "OK: every GUI script path, modules[] entry and module file resolves"
    exit 0
fi

echo "FAIL: $problems problem(s)" >&2
exit 1

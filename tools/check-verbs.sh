#!/usr/bin/env bash
# =====================================================================
#  check-verbs.sh - every documented module verb, exposed in the GUI?
#
#  check-paths.sh walks GUI -> module and proves every path it launches
#  exists. This walks the other way: it takes the verbs each module
#  documents in its own usage text and proves the GUI can actually reach
#  them. A verb that exists but is unreachable from the interface is a
#  feature the operator cannot use, which is exactly the kind of gap that
#  is invisible until someone goes looking for the button.
#
#  Usage:  tools/check-verbs.sh [--verbose] [--module NAME]
#  Exit:   0 = every reachable verb accounted for, 1 = gaps found
#
#  Accuracy: this errs toward FALSE POSITIVES on purpose. A few modules
#  (42_subghz, 43_nfc_rfid, 50/51/52_router_*) parse their option arguments
#  in a case block rather than a getopt loop, so flags like --duration or
#  --yes-write-to-device are reported as unreachable "verbs" when they are
#  really parameters to one. Reporting a flag costs a glance; hiding a verb
#  costs a feature nobody can find, so the bias is deliberate. Treat the
#  count as an upper bound and read the list.
# =====================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# main1.c #includes live_traffic.c, ambient.c and module_index.c, so verbs
# passed from any of them ARE compiled into the GUI. Scanning only main1.c
# reported nine wired Live Traffic verbs as gaps - the tool was wrong, not
# the GUI, and a gap list nobody can trust is worse than none.
GUI_SRC=("$ROOT"/native/src/*.c)

VERBOSE=0
ONLY=""
while (( $# )); do
    case "$1" in
        --verbose|-v) VERBOSE=1; shift ;;
        --module)     ONLY="${2:-}"; shift 2 ;;
        -h|--help)    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

(( ${#GUI_SRC[@]} > 0 )) || {
    printf 'ERR: no GUI sources under %s/native/src\n' "$ROOT" >&2; exit 1; }

# Every "--verb" literal the GUI passes to a subprocess, harvested once.
# Module strings also appear in the generated index, so that counts too.
TMPV=$(mktemp) || exit 1
trap 'rm -f "$TMPV"' EXIT
{ grep -ohE '"--[a-z0-9][a-z0-9-]*"' "${GUI_SRC[@]}" 2>/dev/null || true; } \
    | tr -d '"' | sort -u > "$TMPV"

# Verbs that are internal plumbing rather than operator actions. These are
# reached by the GUI or by other modules but deliberately have no button.
is_internal() {
    case "$1" in
        --selftest|--info|--help) return 0 ;;
        --status-tsv|--start-status|--hop-status-tsv|--stats-tsv) return 0 ;;
        *) return 1 ;;
    esac
}

total=0; missing=0; internal=0
declare -a GAPS=()

for f in "$ROOT"/modules/*.sh; do
    base=$(basename "$f" .sh)
    case "$base" in *.bak*|*~) continue ;; esac
    [[ -n "$ONLY" && "$base" != "$ONLY" ]] && continue

    # Verbs taken from the DISPATCH, i.e. "--verb)" labels in the case block.
    # Scanning the usage text instead pulls in option arguments such as
    # --duration or --gain, which are parameters to a verb rather than
    # commands and correctly have no button of their own.
    # Comments are stripped first: a line like "(never printed by --status)."
    # matches the dispatch pattern and produced a phantom gap that could never
    # be closed, because the verb genuinely does not exist.
    mapfile -t verbs < <(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null \
                         | grep -oE '(^|[[:space:]|(])--[a-z0-9][a-z0-9-]*\)' \
                         | grep -oE -- '--[a-z0-9][a-z0-9-]*' | sort -u)

    # Aliases: a dispatch label of the form "--bssid|--mac)" means either
    # spelling reaches the same code. If the GUI passes one, the capability is
    # reachable and the other must not be reported as a gap. Collected as a
    # map so the alias can be satisfied by its partner.
    declare -A ALIAS_OF=()
    while IFS= read -r group; do
        mapfile -t members < <(printf '%s' "$group" | grep -oE -- '--[a-z0-9][a-z0-9-]*')
        (( ${#members[@]} < 2 )) && continue
        for m in "${members[@]}"; do
            for o in "${members[@]}"; do
                [[ "$m" != "$o" ]] && ALIAS_OF["$m"]+="$o "
            done
        done
    # Match a whole label that contains a pipe, e.g. "--bssid|--mac)": taking
    # only the part after the pipe yields a single member and skips the group.
    done < <(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null \
             | grep -oE -- '--[a-z0-9-]+(\|--[a-z0-9-]+)+\)' | tr -d ')')
    (( ${#verbs[@]} == 0 )) && continue

    mod_missing=0
    for v in "${verbs[@]}"; do
        total=$(( total + 1 ))
        if grep -qxF -- "$v" "$TMPV"; then
            (( VERBOSE )) && printf '  ok       %-24s %s\n' "$base" "$v"
            continue
        fi
        # reachable through an alias the GUI does use?
        alias_hit=""
        for a in ${ALIAS_OF["$v"]:-}; do
            if grep -qxF -- "$a" "$TMPV"; then alias_hit="$a"; break; fi
        done
        if [[ -n "$alias_hit" ]]; then
            (( VERBOSE )) && printf '  alias    %-24s %s (as %s)\n' "$base" "$v" "$alias_hit"
            continue
        fi
        if is_internal "$v"; then
            internal=$(( internal + 1 ))
            (( VERBOSE )) && printf '  internal %-24s %s\n' "$base" "$v"
            continue
        fi
        missing=$(( missing + 1 )); mod_missing=$(( mod_missing + 1 ))
        GAPS+=("$base|$v")
    done
    (( mod_missing > 0 )) && printf '%-26s %d unreachable verb(s)\n' "$base" "$mod_missing"
done

printf '\n'
if (( ${#GAPS[@]} > 0 )); then
    printf 'unreachable from the GUI (%d):\n' "${#GAPS[@]}"
    for g in "${GAPS[@]}"; do
        printf '  %-26s %s\n' "${g%%|*}" "${g##*|}"
    done
fi

printf '\nchecked %d verb(s): %d reachable, %d internal, %d unreachable\n' \
    "$total" "$(( total - internal - missing ))" "$internal" "$missing"

if (( missing > 0 )); then
    printf 'RESULT\tGAPS(%d)\n' "$missing"
    exit 1
fi
printf 'RESULT\tOK\n'
exit 0

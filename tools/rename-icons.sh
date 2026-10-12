#!/usr/bin/env bash
# rename-icons.sh — give module icons the name the GUI actually looks up.
#
# The GUI resolves each module's icon by the literal name in its modules[]
# entry (main1.c), e.g. wifisting-34_pmf_bypass-symbolic. Icons that were
# dropped in by hand carry whatever name the editor gave them
# ("pmf_bypass-removebg-preview.svg") and are therefore never found.
#
# This maps each such file onto the module it depicts and renames it to that
# module's icon name, taken from modules[] so the two cannot drift.
#
# Matching is by normalised name, because the file names are abbreviations:
#   ble_fuzzing-removebg-preview  ->  39_ble_fuzz      (stem contains module)
#   wifi_audit-removebg-preview   ->  46_public_wifi_audit (module contains stem)
# Names that share no substring use the ALIASES table below rather than a
# guess, and anything still unmatched is reported, never renamed.
#
# Default is a dry run. Nothing moves without --apply.
#
# Usage:
#   tools/rename-icons.sh            # show the proposed renames
#   tools/rename-icons.sh --apply    # do them (never overwrites)

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ICONS="$ROOT/native/resources/icons/symbolic"
SRC="$ROOT/native/src/main1.c"

APPLY=0
INSTALL=0
for arg in "$@"; do
    case "$arg" in
        --apply)   APPLY=1 ;;
        --install) INSTALL=1 ;;
        *) echo "usage: $0 [--apply] [--install]" >&2; exit 2 ;;
    esac
done

# GTK loads the icons from the hicolor fallback theme, not from this repo
# directory. Dropping a file into native/resources/icons/symbolic/ therefore
# changes nothing on screen until it is copied here — and hicolor keeps an
# icon-theme.cache, so a newly copied file stays invisible to GTK (which
# reports the name as missing and draws the broken-image icon) until the
# cache is rebuilt. That cache refresh is the step that is easy to miss.
THEME="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
ACTIONS="$THEME/scalable/actions"

[[ -d "$ICONS" ]] || { echo "no icon dir: $ICONS" >&2; exit 2; }
[[ -f "$SRC" ]]   || { echo "no source: $SRC" >&2; exit 2; }

# Files whose name shares no substring with their module. Keep this short and
# obvious: every entry is a claim about which picture belongs to which module.
ALIASES="
sub-gz_rf=42_subghz
geolocation=41_wifi_geolocate
"

# ---- module ids, in the order modules[] declares them ---------------------
mapfile -t IDS < <(awk '/^static const ModuleDefinition modules\[\]/,/^};/' "$SRC" \
    | grep -oE '\{ "[0-9][A-Za-z0-9_.]*"' | sed 's/{ "//; s/"$//')

# normalise: drop the numeric prefix, then everything that is not a letter or
# digit, lowercased. "39_ble_fuzz" -> "blefuzz", "sub-gz_rf" -> "subgzrf"
norm() { printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9'; }
stem_of() {
    # strip the editor's suffixes, then the extension
    printf '%s' "$1" | sed -E 's/\.(svg|png)$//; s/-(removebg-)?preview$//; s/-removebg$//'
}

alias_for() {
    printf '%s\n' "$ALIASES" | awk -F= -v k="$1" '$1==k {print $2; exit}'
}

module_stem() { local id="$1"; norm "${id#[0-9]*_}"; }

declare -A proposed=()      # source file -> target file
declare -A claimed=()       # module id  -> source file (collision guard)

echo "icons dir : $ICONS"
echo "modules   : ${#IDS[@]}"
echo

# ---- pass 1: loose files -> the module they depict ------------------------
shopt -s nullglob
for f in "$ICONS"/*; do
    base="$(basename "$f")"
    [[ "$base" == wifisting-* ]] && continue          # already named
    case "$base" in *.svg) ;; *) echo "SKIP (not svg): $base"; continue ;; esac

    stem="$(stem_of "$base")"
    key="$(norm "$stem")"

    target_id="$(alias_for "$stem")"
    if [[ -z "$target_id" ]]; then
        for id in "${IDS[@]}"; do
            ms="$(module_stem "$id")"
            [[ -z "$ms" ]] && continue
            if [[ "$key" == "$ms" || "$key" == *"$ms"* || "$ms" == *"$key"* ]]; then
                if [[ -n "$target_id" ]]; then
                    echo "AMBIGUOUS: $base matches $target_id and $id - skipped"
                    target_id=""
                    break
                fi
                target_id="$id"
            fi
        done
    fi

    if [[ -z "$target_id" ]]; then
        echo "NO MATCH : $base  (add an ALIASES entry naming its module)"
        continue
    fi
    if [[ -n "${claimed[$target_id]:-}" ]]; then
        echo "COLLISION: $base and ${claimed[$target_id]} both map to $target_id - skipped"
        continue
    fi
    claimed["$target_id"]="$base"
    proposed["$base"]="wifisting-${target_id}-symbolic.svg"
done

# ---- pass 2: wifisting-* files whose name is not the expected one ---------
for f in "$ICONS"/wifisting-*.svg; do
    base="$(basename "$f")"
    id="${base#wifisting-}"; id="${id%.svg}"; id="${id%-symbolic}"
    # only rewrite when that id is a real module and the name differs
    for real in "${IDS[@]}"; do
        if [[ "$real" == "$id" ]]; then
            want="wifisting-${real}-symbolic.svg"
            [[ "$base" != "$want" ]] && proposed["$base"]="$want"
            break
        fi
    done
done

# ---- report / act --------------------------------------------------------
if (( ${#proposed[@]} == 0 )); then
    echo "nothing to rename"
else
    echo "proposed renames (${#proposed[@]}):"
    for src in $(printf '%s\n' "${!proposed[@]}" | sort); do
        printf '  %-40s -> %s\n' "$src" "${proposed[$src]}"
    done
fi

if (( APPLY )); then
    echo
    echo "applying:"
    moved=0
    for src in $(printf '%s\n' "${!proposed[@]}" | sort); do
        dst="${proposed[$src]}"
        if [[ -e "$ICONS/$dst" ]]; then
            echo "  REFUSED $src -> $dst (target exists)"
            continue
        fi
        mv -n "$ICONS/$src" "$ICONS/$dst" && { echo "  $src -> $dst"; moved=$((moved+1)); }
    done
    echo "renamed $moved file(s)"
else
    echo
    echo "dry run - re-run with --apply to perform these renames"
fi

# ---- install into the hicolor theme + rebuild its cache -------------------
if (( INSTALL )); then
    echo
    mkdir -p "$ACTIONS"
    # Keep what we are about to replace: the installed copy may carry a local
    # edit that this repo directory does not have.
    BACKUP="$ACTIONS/.replaced-$(date +%s)"
    copied=0
    for f in "$ICONS"/wifisting-*.svg; do
        base="$(basename "$f")"
        if [[ ! -f "$ACTIONS/$base" ]] || ! cmp -s "$f" "$ACTIONS/$base"; then
            if [[ -f "$ACTIONS/$base" ]]; then
                mkdir -p "$BACKUP"
                cp -p "$ACTIONS/$base" "$BACKUP/$base"
            fi
            cp -f "$f" "$ACTIONS/$base" && { echo "  installed $base"; copied=$((copied+1)); }
        fi
    done
    echo "installed $copied file(s) into $ACTIONS"
    [[ -d "$BACKUP" ]] && echo "  replaced copies saved in $BACKUP"
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -f -t "$THEME" >/dev/null 2>&1 \
            && echo "  hicolor icon cache rebuilt" \
            || echo "  WARNING: icon cache rebuild failed - new icons may not appear"
    else
        echo "  WARNING: gtk-update-icon-cache not found - new icons may not appear"
    fi
fi

# ---- drift between this repo and what GTK actually loads ------------------
if [[ -d "$ACTIONS" ]]; then
    echo
    drift=0
    for f in "$ICONS"/wifisting-*.svg; do
        base="$(basename "$f")"
        if [[ ! -f "$ACTIONS/$base" ]]; then
            echo "not installed: $base  (run with --install)"
            drift=$((drift+1))
        elif ! cmp -s "$f" "$ACTIONS/$base"; then
            echo "out of date : $base  (run with --install)"
            drift=$((drift+1))
        fi
    done
    (( drift == 0 )) && echo "installed theme matches this directory"
fi

# ---- what GTK will actually fail to find --------------------------------
# Checked against the installed theme, not this repo directory: a module icon
# is fine when GTK can resolve its name, and GTK reads $ACTIONS. Reporting on
# the staging directory instead produces false alarms for icons that are
# installed but whose source art is not kept in the repo (00_deps, 04, 07).
echo
missing=0
[[ -d "$ACTIONS" ]] && WHERE="$ACTIONS" || WHERE="$ICONS"
for id in "${IDS[@]}"; do
    icon="$(awk -v id="\"$id\"" '
        /^static const ModuleDefinition modules\[\]/,/^};/ {
            if ($0 ~ id) { getline; if (match($0, /"wifisting-[^"]*"/)) {
                s = substr($0, RSTART+1, RLENGTH-2); print s; exit } }
        }' "$SRC")"
    [[ -z "$icon" ]] && continue
    [[ -f "$WHERE/$icon.svg" ]] && continue
    echo "unresolved: $id expects $icon.svg (not in $WHERE)"
    missing=$((missing+1))
done
(( missing == 0 )) && echo "all ${#IDS[@]} module icon names resolve in $(basename "$(dirname "$WHERE")")"

# Installed art whose source is not kept in this repo, so a fresh checkout
# cannot reproduce the theme.
if [[ -d "$ACTIONS" ]]; then
    for f in "$ACTIONS"/wifisting-*.svg; do
        base="$(basename "$f")"
        [[ -f "$ICONS/$base" ]] || echo "repo has no source for: $base"
    done
fi

# Deliberate exit status: 0 clean, 1 something left unresolved. Without this
# the script exits with whatever the last test happened to return.
if (( missing == 0 )); then exit 0; else exit 1; fi

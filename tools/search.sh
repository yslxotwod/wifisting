#!/usr/bin/env bash
# search.sh — find a value anywhere in the toolkit's collected data.
#
# The tree accumulates scans, databases, captures and module TSVs, but each
# module only knows its own loot. This answers the question that spans them:
# "where have I seen this MAC / SSID / BSSID?" across loot/, state/ and the
# module scratch areas, without touching any module.
#
# Usage:
#   tools/search.sh PATTERN [--type mac|ssid|bssid|any] [--limit N]
#   tools/search.sh --summary            what is searchable, and how much
#
# Output: SOURCE<TAB>KIND<TAB>MATCH<TAB>CONTEXT
# Exit: 0 if anything matched, 1 if nothing did.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPD="${TMP_DIR:-/tmp/wifisting}"

if [[ "${1:-}" == "--summary" ]]; then
    printf 'AREA\tFILES\tBYTES\n'
    for d in "$ROOT/loot" "$ROOT/state" "$ROOT/captures" "$TMPD"; do
        [[ -d "$d" ]] || continue
        n=$(find "$d" -type f 2>/dev/null | wc -l)
        b=$(du -sb "$d" 2>/dev/null | cut -f1)
        printf '%s\t%s\t%s\n' "$(basename "$d")" "$n" "${b:-0}"
    done
    if [[ -f "$ROOT/state/fingerprint.db" ]]; then
        command -v python3 >/dev/null 2>&1 && python3 - "$ROOT/state/fingerprint.db" <<'PY'
import sqlite3, sys
try:
    c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
    tabs = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    tot = 0
    for t in tabs:
        n = c.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
        tot += n
        if n:
            print("db:%s\t%d\trows" % (t, n))
    print("db:total\t%d\trows" % tot)
except Exception as e:
    print("db\terror\t%s" % e)
PY
    fi
    exit 0
fi

pat="${1:-}"
shift 2>/dev/null || true
type="any"; limit=200
while (( $# )); do
    case "$1" in
        --type) type="$2"; shift 2 ;;
        --limit) limit="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -z "$pat" ]]; then
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

# Normalise: MACs and BSSIDs are matched case-insensitively and with any
# separator, because the same address is written four different ways across
# the tree.
norm=$(printf '%s' "$pat" | tr 'A-F' 'a-f' | tr -d ':-')
is_mac=0
[[ "$norm" =~ ^[0-9a-f]{12}$ ]] && is_mac=1

found=0
emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"; found=$((found+1)); }
printf 'SOURCE\tKIND\tMATCH\tCONTEXT\n' >&2

# A MAC is written with colons, dashes, dots or nothing at all depending on
# which module produced the file, so a bare address must match every form.
grep_forms=("$pat")
if (( is_mac )); then
    colon=$(printf '%s' "$norm" | sed 's/../&:/g; s/:$//')
    dash=$(printf '%s' "$norm" | sed 's/../&-/g; s/-$//')
    upper=$(printf '%s' "$colon" | tr 'a-f' 'A-F')
    grep_forms=("$pat" "$norm" "$colon" "$upper" "$dash")
fi

grep_any() {
    local f="$1" form
    for form in "${grep_forms[@]}"; do
        grep -inI -- "$form" "$f" 2>/dev/null | head -3 && return 0
    done
    return 1
}

search_dir() {
    local dir="$1" label="$2"
    [[ -d "$dir" ]] || return 0
    # Text artefacts only; binaries and pcaps need the pcap path below.
    while IFS= read -r f; do
        local hits
        hits=$(grep_any "$f") || true
        [[ -z "$hits" ]] && continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local ln="${line%%:*}" txt="${line#*:}"
            emit "$label/$(basename "$f")" "$(file_kind "$f")" "$ln" \
                 "$(printf '%s' "$txt" | cut -c1-120)"
            (( found >= limit )) && return 0
        done <<< "$hits"
    done < <(find "$dir" -type f \
                \( -name '*.tsv' -o -name '*.csv' -o -name '*.txt' \
                   -o -name '*.json' -o -name '*.log' -o -name '*.md' \) \
                2>/dev/null | head -400)
}

file_kind() {
    case "$1" in
        *.csv)  printf 'scan-csv' ;;
        *.tsv)  printf 'module-tsv' ;;
        *.json) printf 'state-json' ;;
        *.log)  printf 'log' ;;
        *)      printf 'text' ;;
    esac
}

search_dir "$ROOT/loot" "loot"
search_dir "$ROOT/state" "state"
search_dir "$TMPD" "tmp"

# A MAC/BSSID also lives inside the SQLite database and the binary captures,
# where grep cannot reach it.
if (( is_mac )) && [[ -f "$ROOT/state/fingerprint.db" ]]; then
    python3 - "$ROOT/state/fingerprint.db" "$norm" <<'PY' 2>/dev/null | while IFS=$'\t' read -r a b c d; do
import sqlite3, sys
db, want = sys.argv[1], sys.argv[2]
try:
    c = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
except Exception:
    raise SystemExit
# MAC columns across the schema, matched on the normalised form.
for table, col in (("clients","mac"), ("observations","mac"), ("probed","mac"),
                   ("rates","mac"), ("seqnums","mac"), ("ble_clients","mac"),
                   ("cross_domain","wifi_mac"), ("cross_domain","ble_mac")):
    try:
        rows = c.execute(
            'SELECT * FROM "%s" WHERE REPLACE(REPLACE(LOWER(%s),":",""),"-","")=?'
            % (table, col), (want,)).fetchall()
    except Exception:
        continue
    for r in rows[:5]:
        print("state/fingerprint.db\tdb:%s\t%s\t%s" % (table, col, str(r)[:120]))
PY
        emit "$a" "$b" "$c" "$d"
        (( found >= limit )) && break
    done
fi

if (( found == 0 )); then
    printf 'NONE\t%s\t0\tno match in loot, state or scratch\n' "$pat" >&2
    exit 1
fi
exit 0

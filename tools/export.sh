#!/usr/bin/env bash
# export.sh — emit any module's TSV output as JSON.
#
# Rather than teach 47 modules a new output format, this wraps the verbs they
# already have. The convention is therefore: any module verb whose output is
# TSV is exportable, which means diffing, searching and correlating across
# modules need no per-module code.
#
# Usage:
#   tools/export.sh MODULE VERB [ARGS...]     one verb, as JSON
#   tools/export.sh --list                    what can be exported
#   tools/export.sh --all                     every module's summary, as one object
#   tools/export.sh MODULE --status-tsv       capabilities, as JSON
#
# Output shape:
#   { "module": "...", "verb": "...", "ran": "...", "rows": [ {...}, ... ] }
#
# KEY<TAB>VALUE rows become {"KEY": value}; bare multi-column rows become
# objects keyed by the header row when one is present, otherwise an array.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODDIR="$ROOT/modules"

to_json() {
    python3 - "$@"
}

# Verbs whose output is a data table rather than a status line.
list_exportable() {
    python3 - "$ROOT/module_index.tsv" <<'PY'
import sys
try:
    rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1], encoding="utf-8")
            if l.strip() and not l.startswith("MODULE")]
except OSError as e:
    print("ERROR\t%s" % e, file=sys.stderr); raise SystemExit(1)

print("MODULE\tNAME\tDATA_VERBS")
for f in rows:
    if len(f) < 5:
        continue
    verbs = [v for v in f[3].split()
             if any(k in v for k in ("list", "tsv", "status", "report", "show"))]
    if verbs:
        print("%s\t%s\t%s" % (f[0], f[1], " ".join(verbs)))
PY
}

# The TSV -> JSON converter. Values are typed so a diff is meaningful:
# "1"/"0" stay numbers, "true"/"false" become booleans, everything else a string.
convert() {
    # NB: a heredoc on python3 REPLACES stdin, so the piped TSV would be lost
    # and the script itself would be read as the data. Stage it through a file.
    local stage
    stage=$(mktemp) || return 1
    cat > "$stage"
    python3 - "$1" "$2" "$3" "$stage" <<'PY'
import json, sys

module, verb, ran, path = sys.argv[1:5]
with open(path, encoding="utf-8", errors="replace") as fh:
    raw = fh.read()

def typed(v):
    v = v.strip()
    if v == "":
        return None
    if v in ("true", "True"):
        return True
    if v in ("false", "False"):
        return False
    # Only treat as a number when it round-trips, so "007" stays a string
    # and a MAC or version is never silently truncated.
    try:
        if v.lstrip("-").isdigit() and not (v.startswith("0") and len(v) > 1):
            return int(v)
        f = float(v)
        if str(f) == v:
            return f
    except ValueError:
        pass
    return v

out = {"module": module, "verb": verb, "ran": ran, "rows": []}
lines = [l for l in raw.split("\n") if l.strip()]

if not lines:
    out["empty"] = True
else:
    pairs = [l.split("\t") for l in lines]
    kv = all(len(p) == 2 for p in pairs)

    if kv:
        # KEY<TAB>VALUE: one object, later keys winning.
        d = {}
        for p in pairs:
            d[p[0]] = typed(p[1])
        out["rows"] = [d]
        out["shape"] = "key-value"
    else:
        # Table. A leading row whose cells are all non-numeric is a header.
        header = None
        first = pairs[0]
        if all(not c.strip().replace(".", "", 1).lstrip("-").isdigit()
               for c in first if c.strip()):
            header = [c.strip() for c in first]
            pairs = pairs[1:]
        for p in pairs:
            if header and len(header) == len(p):
                out["rows"].append({header[i]: typed(p[i])
                                    for i in range(len(p))})
            else:
                out["rows"].append([typed(c) for c in p])
        out["shape"] = "table"

out["count"] = len(out["rows"])
json.dump(out, sys.stdout, indent=2, sort_keys=False)
sys.stdout.write("\n")
PY
    local rc=$?
    rm -f "$stage"
    return $rc
}

if [[ "${1:-}" == "--list" ]]; then
    list_exportable
    exit 0
fi

if [[ "${1:-}" == "--all" ]]; then
    # Every module's --status-tsv in one document: the cheapest cross-module
    # snapshot, and enough to diff capability changes between sessions.
    python3 - "$ROOT" <<'PY'
import glob, json, os, subprocess, sys
root = sys.argv[1]
mods = sorted(glob.glob(os.path.join(root, "modules", "*.sh")))
out = {}
for m in mods:
    mid = os.path.basename(m)[:-3]
    if "--status-tsv" not in open(m, encoding="utf-8", errors="replace").read():
        continue
    try:
        r = subprocess.run(["bash", m, "--status-tsv"], capture_output=True,
                           text=True, timeout=30, cwd=root)
    except Exception:
        continue
    d = {}
    for line in r.stdout.splitlines():
        p = line.split("\t")
        if len(p) >= 2:
            v = p[1].strip()
            d[p[0]] = (int(v) if v.isdigit() else v)
    if d:
        out[mid] = d
json.dump({"modules": out, "count": len(out)}, sys.stdout, indent=2)
sys.stdout.write("\n")
PY
    exit 0
fi

module="${1:-}"
verb="${2:-}"
shift 2 2>/dev/null || true

if [[ -z "$module" || -z "$verb" ]]; then
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

script="$MODDIR/${module}.sh"
[[ -f "$script" ]] || script="$MODDIR/${module}"
[[ -f "$script" ]] || { echo "ERROR: no such module: $module" >&2; exit 1; }

out=$(cd "$ROOT" && timeout 120 bash "$script" "$verb" "$@" 2>/dev/null)
rc=$?

if (( rc != 0 )) && [[ -z "$out" ]]; then
    { echo "ERROR: $module $verb exited $rc with no output" >&2; exit $rc; }
fi

printf '%s' "$out" | convert "$module" "$verb" "$(date -Is)"

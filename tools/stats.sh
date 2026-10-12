#!/usr/bin/env bash
# stats.sh — real analytics over what the toolkit has actually collected.
#
# The Stats tab used to be directory file counts ("12 files, 3.1 MB"), which
# says nothing about the data. This mines the actual artefacts: the
# fingerprint SQLite database, recon run records, airodump scans, module
# TSVs and the capture/hash tree.
#
# Emits one row per statistic:
#   SECTION<TAB>KEY<TAB>VALUE<TAB>DETAIL
#
# Everything degrades honestly: a missing database or an empty directory
# reports 0 or "n/a" with a reason, never a fabricated number.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$ROOT/state"
LOOT="$ROOT/loot"
CAPS="$ROOT/captures"
TMPD="${TMP_DIR:-/tmp/wifisting}"
DB="$STATE/fingerprint.db"
LOG="${XDG_DATA_HOME:-$HOME/.local/share}/wifisting/wifisting.log"

row() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}"; }

want="${1:---all}"

# ── SQLite-backed statistics ─────────────────────────────────────────────
db_stats() {
    if [[ ! -f "$DB" ]]; then
        row WIFI "database" "absent" "no fingerprint database yet"
        return
    fi
    command -v python3 >/dev/null 2>&1 || { row DB "database" "n/a" "python3 missing"; return; }
    python3 - "$DB" <<'PYEOF'
import sqlite3, sys
try:
    c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
except Exception as e:
    print("DB\tdatabase\terror\t%s" % e); sys.exit(0)

def q(sql, default=0):
    try:
        return c.execute(sql).fetchone()[0]
    except Exception:
        return default

def row(k, v, d="", sec="WIFI"):
    print("%s\t%s\t%s\t%s" % (sec, k, v, d))

row("clients", q("SELECT COUNT(*) FROM clients"))
row("clients_randomised", q("SELECT COUNT(*) FROM clients WHERE randomized=1"))
row("clients_vendors", q("SELECT COUNT(DISTINCT vendor) FROM clients WHERE vendor IS NOT NULL AND vendor<>''"))
row("observations", q("SELECT COUNT(*) FROM observations"))
row("probed_ssids", q("SELECT COUNT(DISTINCT ssid) FROM probed"))
row("probe_events", q("SELECT COUNT(*) FROM probed"))
row("ble_devices", q("SELECT COUNT(*) FROM ble_clients"), "", "BLUETOOTH")
row("ble_companies", q("SELECT COUNT(DISTINCT mfg_company) FROM ble_clients WHERE mfg_company IS NOT NULL AND mfg_company<>''"))
row("cross_domain", q("SELECT COUNT(*) FROM cross_domain"), "wifi<->ble links", "BLUETOOTH")

# The single most interesting one: how much of the client population is
# using MAC randomisation, which decides whether tracking by MAC works.
tot = q("SELECT COUNT(*) FROM clients")
rnd = q("SELECT COUNT(*) FROM clients WHERE randomized=1")
if tot:
    row("randomisation_rate", "%d%%" % round(100.0 * rnd / tot), "%d of %d clients" % (rnd, tot))

top = c.execute("""SELECT ssid, COUNT(*) c FROM probed
                   WHERE ssid IS NOT NULL AND ssid<>''
                   GROUP BY ssid ORDER BY c DESC LIMIT 5""").fetchall()
for ssid, n in top:
    row("top_probe", ssid, "%d probe(s)" % n)
PYEOF
}

# ── scan-derived statistics ──────────────────────────────────────────────
wifi_stats() {
    python3 - "$TMPD" "$LOOT" "$CAPS" <<'PYEOF'
import csv, glob, os, sys, collections, subprocess

tmpd, loot, caps = sys.argv[1:4]
def row(k, v, d=""): print("WIFI\t%s\t%s\t%s" % (k, v, d))

aps = {}
clients = set()
for path in glob.glob(os.path.join(tmpd, "recon", "scan-*.csv")) + \
            glob.glob(os.path.join(loot, "**", "*.csv"), recursive=True):
    try:
        fh = open(path, newline="", encoding="utf-8", errors="replace")
    except OSError:
        continue
    with fh:
        section = None
        for r in csv.reader(fh, skipinitialspace=True):
            if not r:
                continue
            first = (r[0] or "").strip()
            if first == "BSSID":
                section = "ap"; continue
            if first == "Station MAC":
                section = "client"; continue
            if section == "ap" and len(r) >= 14 and first:
                b = first.upper()
                if b not in aps:
                    aps[b] = {"priv": (r[5] or "").strip(),
                              "cipher": (r[6] or "").strip(),
                              "chan": (r[3] or "").strip(),
                              "essid": (r[13] or "").strip()}
            elif section == "client" and len(r) >= 1 and first:
                clients.add(first.upper())

if not aps:
    row("aps", 0, "no scan CSVs found yet")
else:
    row("aps", len(aps))
    row("clients", len(clients))
    sec = collections.Counter()
    for a in aps.values():
        p = a["priv"].upper()
        if not p or p in ("OPN", "OPEN", "NONE"): sec["open"] += 1
        elif "WEP" in p:                          sec["wep"] += 1
        elif "WPA3" in p and "WPA2" in p:          sec["wpa2+wpa3 (transition)"] += 1
        elif "WPA3" in p:                          sec["wpa3"] += 1
        elif "WPA2" in p:                          sec["wpa2"] += 1
        elif "WPA" in p:                           sec["wpa1"] += 1
        else:                                      sec[p or "unknown"] += 1
    for k, v in sec.most_common():
        row("security:" + k, v)
    ch = collections.Counter(a["chan"] for a in aps.values() if a["chan"])
    for c, n in sorted(ch.items(), key=lambda kv: -kv[1])[:6]:
        row("channel " + c, n)
    # 2.4 vs 5 GHz by channel number
    b24 = sum(n for c, n in ch.items() if c.isdigit() and 1 <= int(c) <= 14)
    b5  = sum(n for c, n in ch.items() if c.isdigit() and int(c) > 14)
    if b24 or b5:
        row("band 2.4GHz", b24)
        row("band 5GHz", b5)

# WPS and PMF posture, from the same source the target list uses.
#
# Neither is in a scan CSV: PMF sits in the RSN Capabilities IE and WPS in
# a vendor IE, so both need a capture parsed. The recon verb already does
# that, so this reuses it rather than growing a second tshark pass that
# could drift out of step with the one the GUI shows.
try:
    # ROOT is a shell variable and is NOT passed into this heredoc - only
    # TMPD and LOOT are - so it is undefined here. Derive it from loot,
    # which is ROOT/loot; using the bare name raised NameError, which the
    # except below swallowed so the rows silently never appeared.
    _root = os.path.dirname(loot.rstrip("/"))
    out = subprocess.run([os.path.join(_root, "modules", "02_recon.sh"),
                          "--targets-enriched-tsv"],
                         capture_output=True, text=True, timeout=120).stdout
    wps_on = pmf_yes = pmf_no = pmf_unknown = 0
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 9 or f[0] == "BSSID":
            continue
        if f[7] == "yes":
            wps_on += 1
        if f[6] == "yes":
            pmf_yes += 1
        elif f[6] == "no":
            pmf_no += 1
        else:
            pmf_unknown += 1
    if wps_on or pmf_yes or pmf_no or pmf_unknown:
        row("wps enabled", wps_on, "reachable over WPS")
        row("pmf present", pmf_yes, "forged deauth is ignored")
        row("pmf absent", pmf_no, "deauth disconnects clients")
        if pmf_unknown:
            row("pmf unknown", pmf_unknown, "absent from the last capture")
except Exception:
    pass

  # PMF posture from the dedicated module, if it has run
pmf = os.path.join(loot, "pmf_bypass", "pmf_posture.tsv")
if os.path.exists(pmf):
    v = collections.Counter()
    with open(pmf, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) >= 5 and f[0] != "BSSID":
                v[f[4]] += 1
    for k, n in v.most_common():
        row("pmf:" + k.lower(), n)

# Captures and hash cracking
ncaps = len(glob.glob(os.path.join(caps, "**", "*.cap"), recursive=True)) + \
        len(glob.glob(os.path.join(caps, "**", "*.pcap"), recursive=True))
row("captures", ncaps)
hashes = glob.glob(os.path.join(loot, "**", "*.22000"), recursive=True)
htot = 0
for h in hashes:
    try:
        htot += sum(1 for _ in open(h, encoding="utf-8", errors="replace"))
    except OSError:
        pass
row("hash files", len(hashes))
row("hashes", htot)
cracked = glob.glob(os.path.join(loot, "**", "cracked*.txt"), recursive=True)
ctot = 0
for c in cracked:
    try:
        ctot += sum(1 for _ in open(c, encoding="utf-8", errors="replace"))
    except OSError:
        pass
row("cracked", ctot)
if htot:
    row("crack rate", "%d%%" % round(100.0 * ctot / htot), "%d of %d" % (ctot, htot))
PYEOF
}

# ── findings roll-up (from the audit module) ─────────────────────────────
finding_stats() {
    python3 - "$LOOT" <<'PYEOF'
import collections, subprocess, glob, os, sys
loot = sys.argv[1]
def row(k, v, d=""): print("FINDINGS\t%s\t%s\t%s" % (k, v, d))

paths = glob.glob(os.path.join(loot, "public_wifi_audit", "**", "findings.tsv"), recursive=True)
if not paths:
    row("findings", 0, "run the public Wi-Fi audit to populate this")
    raise SystemExit
sev = collections.Counter(); code = collections.Counter()
for p in paths:
    with open(p, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) >= 6 and f[0] != "BSSID":
                sev[f[4]] += 1; code[f[5]] += 1
for k in ("critical", "high", "medium", "low"):
    if sev[k]:
        row("severity:" + k, sev[k])
for k, n in code.most_common(8):
    row(k, n)
PYEOF
}

# ── activity from recon run records ──────────────────────────────────────
activity_stats() {
    python3 - "$STATE" "$LOG" "$TMPD" <<'PYEOF'
import glob, json, os, sys
state, log, tmpd = sys.argv[1:4]
def row(k, v, d=""): print("ACTIVITY\t%s\t%s\t%s" % (k, v, d))

# recon.json is the only structured run record the tree keeps.
runs = []
for p in [os.path.join(state, "recon.json")] + glob.glob(os.path.join(state, "*.json")):
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            d = json.load(fh)
        if isinstance(d, dict) and "run_id" in d:
            runs.append(d)
    except Exception:
        continue
row("recon runs on record", len(runs))
if runs:
    last = runs[-1]
    row("last run status", last.get("status", "?"))
    row("last run interface", last.get("interface", "?"))
    row("last run label", last.get("label", "?"))
    row("last run started", (last.get("started_at") or "")[:19])

scans = glob.glob(os.path.join(tmpd, "recon", "scan-*.csv"))
row("scan files", len(scans))

# Event log volume is a proxy for session activity.
if os.path.exists(log):
    n = 0
    try:
        with open(log, encoding="utf-8", errors="replace") as fh:
            for _ in fh: n += 1
    except OSError:
        pass
    row("log lines", n)
else:
    row("log lines", "n/a", "no log file")
PYEOF
}

# ── health / footprint ───────────────────────────────────────────────────
health_stats() {
    local mods selfs
    mods=$(cd "$ROOT/modules" && ls -1 *.sh 2>/dev/null | wc -l)
    selfs=$(grep -l -- '--selftest' "$ROOT"/modules/*.sh 2>/dev/null | wc -l)
    row HEALTH "modules" "$mods"
    row HEALTH "modules with selftest" "$selfs" "$(( mods - selfs )) without"
    row HEALTH "scripts parseable" "$(cd "$ROOT/modules" && for f in *.sh; do bash -n "$f" 2>/dev/null || echo bad; done | grep -c bad || true)" "0 = all parse"

    local lc lsz cc
    lc=$(find "$LOOT" -type f 2>/dev/null | wc -l)
    lsz=$(du -sh "$LOOT" 2>/dev/null | cut -f1)
    cc=$(find "$CAPS" -type f 2>/dev/null | wc -l)
    row HEALTH "loot files" "$lc" "${lsz:-0}"
    row HEALTH "capture files" "$cc"

    # Per-module footprint, biggest first
    python3 - "$LOOT" <<'PYEOF'
import os, sys
loot = sys.argv[1]
if not os.path.isdir(loot):
    raise SystemExit
sizes = []
for d in os.listdir(loot):
    p = os.path.join(loot, d)
    if not os.path.isdir(p): continue
    n = 0; b = 0
    for root, _dirs, files in os.walk(p):
        for f in files:
            fp = os.path.join(root, f)
            try: b += os.path.getsize(fp); n += 1
            except OSError: pass
    if n:
        sizes.append((b, n, d))
# Every loot directory, not the top eight. The cap meant a module added
# later stayed invisible here until it outgrew an established one -
# so new modules silently had no coverage at all.
for b, n, d in sorted(sizes, key=lambda t: (-t[1], -t[0], t[2])):
    print("HEALTH\tloot:%s\t%d file(s)\t%.1f KB" % (d, n, b / 1024.0))
PYEOF
}

overview_stats() {
    local mods selfs aps caps
    mods=$(cd "$ROOT/modules" && ls -1 *.sh 2>/dev/null | wc -l)
    selfs=$(grep -l -- '--selftest' "$ROOT"/modules/*.sh 2>/dev/null | wc -l)
    row OVERVIEW "modules" "$mods" "$selfs with a selftest"
    aps=$(python3 - "$TMPD" "$LOOT" <<'PYEOF'
import csv, glob, os, sys
tmpd, loot = sys.argv[1:3]
seen = set()
for path in glob.glob(os.path.join(tmpd, "recon", "scan-*.csv")) + \
            glob.glob(os.path.join(loot, "**", "*.csv"), recursive=True):
    try: fh = open(path, newline="", encoding="utf-8", errors="replace")
    except OSError: continue
    with fh:
        sec = None
        for r in csv.reader(fh, skipinitialspace=True):
            if not r: continue
            f0 = (r[0] or "").strip()
            if f0 == "BSSID": sec = "ap"; continue
            if f0 == "Station MAC": sec = "client"; continue
            if sec == "ap" and len(r) >= 14 and f0: seen.add(f0.upper())
print(len(seen))
PYEOF
)
    row OVERVIEW "access points seen" "$aps"
    caps=$(find "$CAPS" -type f \( -name '*.cap' -o -name '*.pcap' \) 2>/dev/null | wc -l)
    row OVERVIEW "captures" "$caps"
    row OVERVIEW "loot size" "$(du -sh "$LOOT" 2>/dev/null | cut -f1)" "$(find "$LOOT" -type f 2>/dev/null | wc -l) files"
    if [[ -f "$LOG" ]]; then
        row OVERVIEW "log lines" "$(wc -l < "$LOG" 2>/dev/null)"
    fi
}

case "$want" in
    --overview)  overview_stats ;;
    --db)        db_stats ;;
    --wifi)      wifi_stats ;;
    --findings)  finding_stats ;;
    --activity)  activity_stats ;;
    --health)    health_stats ;;
    --all|*)
        overview_stats
        db_stats
        wifi_stats
        finding_stats
        activity_stats
        health_stats
        ;;
esac

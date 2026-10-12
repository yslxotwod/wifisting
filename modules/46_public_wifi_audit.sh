#!/usr/bin/env bash
# 46_public_wifi_audit — Public Wi-Fi Audit
# Grade access points for open, WEP, downgrade and evil-twin risk.
#
# Standalone top-level module (Section B). Self-locating and pkexec-safe:
# the polkit rule matches this script's path, so invoke it directly, never
# through `env`.

set -o pipefail

if [[ -z "${WIFISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    WIFISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export WIFISTING_ROOT
fi
if [[ -n "${WIFISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$WIFISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi

: "${TMP_DIR:=/tmp/wifisting}"
: "${LOOT_DIR:=$WIFISTING_ROOT/loot}"
: "${LOG_DIR:=$WIFISTING_ROOT/logs}"
: "${CAPTURES_DIR:=$WIFISTING_ROOT/captures}"

MOD_TMP="$TMP_DIR/public_wifi_audit"
MOD_LOOT="$LOOT_DIR/public_wifi_audit"
MOD_LOGS="$LOG_DIR/public_wifi_audit"
MOD_CAPS="$CAPTURES_DIR/public_wifi_audit"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

: "${AUDIT_OUT:=$MOD_LOOT/reports}"
mkdir -p "$AUDIT_OUT" 2>/dev/null

audit_status_tsv() {
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'scapy\t%s\n'   "$(python3 -c 'import scapy' 2>/dev/null && echo 1 || echo 0)"
    printf 'iw\t%s\n'      "$(command -v iw >/dev/null 2>&1 && echo 1 || echo 0)"
    local m=0
    local i
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        iw dev "$(basename "$i")" info 2>/dev/null | grep -q 'type managed' && m=1
    done
    printf 'live_scan\t%s\n' "$m"
    # Auditing an existing capture needs no radio at all.
    printf 'offline_audit\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
}

# ── findings model ───────────────────────────────────────────────────────
# Each finding carries a severity so the report can be triaged rather than
# read as a flat list.
audit_rules_tsv() {
    cat <<'EOF'
OPEN	critical	Network is open — all traffic is readable by anyone in range
WEP	critical	WEP is cryptographically broken and crackable in minutes
WPS	high	WPS enabled — PIN brute force can recover the PSK
TKIP	high	TKIP is deprecated and has known weaknesses
WPA1	high	WPA1 (802.1X/PSK without CCMP) is deprecated
EVILTWIN	high	Same SSID advertised by another BSSID with different security
NO_PMF	medium	WPA2 without management frame protection — deauth is possible
DOWNGRADE	medium	Transition mode (WPA2+WPA3) lets a client fall back to WPA2
HIDDEN	low	Hidden SSID — trivial to discover, provides no real protection
DEFAULT_SSID	low	SSID looks like a vendor default
EOF
}

# ── airodump CSV audit ───────────────────────────────────────────────────
# Privacy/Cipher/Authentication columns carry enough to grade a network
# without any radio work.
audit_csv() {
    local csv="$1"
    [[ -z "$csv" || ! -f "$csv" ]] && {
        printf 'ERROR\tusage: --audit AIRODUMP.csv\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    mkdir -p "$AUDIT_OUT"
    python3 - "$csv" "$AUDIT_OUT/findings.tsv" <<'PYEOF'
import csv, sys, collections

src, out = sys.argv[1], sys.argv[2]
aps = []
with open(src, newline="", encoding="utf-8", errors="replace") as fh:
    for row in csv.reader(fh, skipinitialspace=True):
        if not row:
            continue
        first = (row[0] or "").strip()
        if first == "BSSID":
            continue
        if first == "Station MAC":
            break
        if len(row) < 14 or not first:
            continue
        aps.append({
            "bssid": first.upper(),
            "chan": (row[3] or "").strip(),
            "priv": (row[5] or "").strip(),
            "cipher": (row[6] or "").strip(),
            "auth": (row[7] or "").strip(),
            "essid": (row[13] or "").strip(),
            "power": (row[8] or "").strip(),
        })

if not aps:
    print("ERROR\tno access points in that CSV", file=sys.stderr)
    sys.exit(1)

DEFAULT_HINTS = ("linksys", "netgear", "dlink", "d-link", "tp-link", "tplink",
                 "belkin", "asus", "default", "setup", "home-", "dlink-",
                 "livebox-", "bbox-", "sfr_", "freebox-", "orange-")

def looks_default(essid):
    e = essid.lower().strip()
    if not e:
        return False
    if e in ("default", "wireless", "wifi", "internet"):
        return True
    return any(e.startswith(h) or e == h for h in DEFAULT_HINTS)

# Group by SSID to spot the same name offered with different security.
by_ssid = collections.defaultdict(list)
for a in aps:
    if a["essid"]:
        by_ssid[a["essid"]].append(a)

findings = []
for a in aps:
    priv = a["priv"].upper()
    cipher = a["cipher"].upper()
    auth = a["auth"].upper()
    essid = a["essid"]

    if not priv or priv in ("OPN", "OPEN", "NONE"):
        findings.append((a, "OPEN", "critical", "no encryption advertised"))
    if "WEP" in priv:
        findings.append((a, "WEP", "critical", "Privacy=%s" % a["priv"]))
    if "TKIP" in cipher:
        findings.append((a, "TKIP", "high", "Cipher=%s" % a["cipher"]))
    if "WPA" in priv and "WPA2" not in priv and "WPA3" not in priv:
        findings.append((a, "WPA1", "high", "Privacy=%s" % a["priv"]))
    # WPA3 in transition mode still accepts WPA2 clients.
    if "WPA3" in priv and "WPA2" in priv:
        findings.append((a, "DOWNGRADE", "medium",
                         "transition mode WPA2+WPA3"))
    if "WPA2" in priv and "WPA3" not in priv:
        findings.append((a, "NO_PMF", "medium",
                         "WPA2 only; PMF status needs a beacon capture"))
    if not essid:
        findings.append((a, "HIDDEN", "low", "no SSID in beacon"))
    elif looks_default(essid):
        findings.append((a, "DEFAULT_SSID", "low", "SSID=%s" % essid))

# Evil twin: one SSID, several BSSIDs, differing security strings.
for ssid, group in by_ssid.items():
    if len(group) < 2:
        continue
    secs = {(g["priv"], g["cipher"], g["auth"]) for g in group}
    if len(secs) > 1:
        for g in group:
            findings.append((g, "EVILTWIN", "high",
                             "SSID %r offered by %d BSSIDs with %d distinct "
                             "security configurations" % (ssid, len(group), len(secs))))

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
findings.sort(key=lambda f: (SEV_ORDER.get(f[2], 9), f[0]["bssid"]))

with open(out, "w") as fh:
    fh.write("BSSID\tSSID\tCHANNEL\tPRIVACY\tSEVERITY\tFINDING\tDETAIL\n")
    for a, code, sev, detail in findings:
        fh.write("\t".join([a["bssid"], a["essid"], a["chan"], a["priv"],
                            sev, code, detail]) + "\n")

print("APS\t%d" % len(aps))
print("FINDINGS\t%d" % len(findings))
for sev in ("critical", "high", "medium", "low"):
    n = sum(1 for f in findings if f[2] == sev)
    if n:
        print("%s\t%d" % (sev.upper(), n))
open_aps = sum(1 for a in aps
               if not a["priv"] or a["priv"].upper() in ("OPN", "OPEN", "NONE"))
print("OPEN_APS\t%d" % open_aps)
wep = sum(1 for a in aps if "WEP" in a["priv"].upper())
print("WEP_APS\t%d" % wep)
print("REPORT\t%s" % out)
PYEOF
}

audit_show() {
    local f="$AUDIT_OUT/findings.tsv"
    [[ -s "$f" ]] || { printf 'ERROR\tno report yet — run --audit CSV first\n' >&2; return 1; }
    cat "$f"
}

# ── severity roll-up ─────────────────────────────────────────────────────
audit_summary() {
    local f="$AUDIT_OUT/findings.tsv"
    [[ -s "$f" ]] || { printf 'ERROR\tno report yet — run --audit CSV first\n' >&2; return 1; }
    printf 'SEVERITY\tCOUNT\n'
    awk -F'\t' 'NR>1 {c[$5]++} END {
        for (s in c) printf "%s\t%d\n", s, c[s]
    }' "$f" | sort
    printf 'FINDING\tCOUNT\n'
    awk -F'\t' 'NR>1 {c[$6]++} END {
        for (s in c) printf "%s\t%d\n", s, c[s]
    }' "$f" | sort
    # A single number is useful for tracking a site over time, but only if
    # the weighting is stated rather than implied.
    awk -F'\t' 'NR>1 {
        w = ($5 == "critical" ? 10 : $5 == "high" ? 5 : $5 == "medium" ? 2 : 1)
        t += w
    } END { printf "WEIGHTED_SCORE\t%d\n", t }' "$f"
    printf 'NOTE\tweighting: critical=10 high=5 medium=2 low=1\n'
}

# ── live scan ────────────────────────────────────────────────────────────
audit_scan() {
    local iface="${1:-}"
    command -v iw >/dev/null 2>&1 || { printf 'ERROR\tiw not installed\n' >&2; return 1; }
    local n=""
    if [[ -z "$iface" ]]; then
        local i
        for i in /sys/class/net/*/; do
            [[ -e "$i/phy80211" ]] || continue
            local c; c=$(basename "$i")
            if iw dev "$c" info 2>/dev/null | grep -q 'type managed'; then n="$c"; break; fi
        done
    else
        n="$iface"
    fi
    [[ -z "$n" ]] && { printf 'ERROR\tno managed-mode wireless interface\n' >&2; return 1; }

    mkdir -p "$MOD_LOGS"
    local out="$MOD_LOGS/iwscan_$(date +%s).txt"
    if ! iw dev "$n" scan > "$out" 2>/dev/null; then
        printf 'ERROR\tiw scan failed on %s (needs root)\n' "$n" >&2
        rm -f "$out"; return 1
    fi
    local c; c=$(grep -c '^BSS ' "$out" 2>/dev/null) || c=0
    (( c == 0 )) && { printf 'ERROR\tno BSS entries parsed\n' >&2; rm -f "$out"; return 1; }
    printf 'IFACE\t%s\nAPS\t%s\nRAW\t%s\n' "$n" "$c" "$out"
    printf 'NOTE\tlive scan captured; pair it with the PMF module for\n'
    printf 'NOTE\tmanagement-frame-protection detail, which iw reports.\n'
}

audit_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    mkdir -p "$MOD_TMP"
    cat > "$MOD_TMP/t.csv" <<'CSV'
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:AA:AA:AA:AA:01, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 6, 54, OPN, , , -45, 10, 0, 0.0.0.0, 8, "Cafe", 
AA:AA:AA:AA:AA:02, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 6, 54, WEP, WEP, , -50, 10, 9, 0.0.0.0, 3, "Old", 
AA:AA:AA:AA:AA:03, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 1, 54, WPA2, TKIP, PSK, -60, 10, 0, 0.0.0.0, 5, "Hotel", 
AA:AA:AA:AA:AA:04, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 1, 54, WPA2, CCMP, PSK, -55, 10, 0, 0.0.0.0, 5, "Hotel", 
CSV
    local out
    out=$(AUDIT_OUT="$MOD_TMP" bash -c 'true'; true)
    # run the audit with the report redirected into the scratch dir
    local saved="$AUDIT_OUT"
    AUDIT_OUT="$MOD_TMP"
    out=$(audit_csv "$MOD_TMP/t.csv")
    AUDIT_OUT="$saved"

    chk open-detected "$(printf '%s\n' "$out" | awk -F'\t' '$1=="OPEN_APS"{print $2}')" 1
    chk wep-detected  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="WEP_APS"{print $2}')" 1
    chk critical-count "$(printf '%s\n' "$out" | awk -F'\t' '$1=="CRITICAL"{print $2}')" 2
    chk eviltwin-detected "$(awk -F'\t' '$6=="EVILTWIN"{c++} END{print c+0}' "$MOD_TMP/findings.tsv")" 2
    chk tkip-detected "$(awk -F'\t' '$6=="TKIP"{c++} END{print c+0}' "$MOD_TMP/findings.tsv")" 1
    chk open-is-critical "$(awk -F'\t' '$6=="OPEN"{print $5}' "$MOD_TMP/findings.tsv")" critical
    chk wep-is-critical "$(awk -F'\t' '$6=="WEP"{print $5}' "$MOD_TMP/findings.tsv")" critical
    # A CSV with no AP rows must fail rather than report a clean bill of health.
    printf 'BSSID, First time seen\n\n' > "$MOD_TMP/empty.csv"
    if audit_csv "$MOD_TMP/empty.csv" >/dev/null 2>&1; then
        printf 'empty-scan-rejected\tFAIL\n'; bad=$((bad+1))
    else printf 'empty-scan-rejected\tPASS\n'; fi
    rm -f "$MOD_TMP/t.csv" "$MOD_TMP/empty.csv" "$MOD_TMP/findings.tsv"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

audit_info() {
    cat <<'EOF'
Public Wi-Fi security audit

Grades each access point from scan data. Severity is about consequence,
not about how exotic the flaw is:

  critical  open or WEP — traffic is readable, or recoverable in minutes
  high      WPS enabled, TKIP, WPA1, or an evil-twin SSID
  medium    WPA2 without PMF, or WPA2/WPA3 transition mode
  low       hidden SSID, vendor-default name

What this module can and cannot tell you
  It reads the Privacy/Cipher/Authentication columns of an airodump-ng
  CSV, so it knows what a network advertises. It cannot see whether a
  client actually validates certificates, whether the AP is a honeypot,
  or whether WPS is actually enabled — those need beacon IE parsing from
  a capture, which the WPS and evil-twin modules do.

Evil twin detection here is structural: one SSID advertised by several
BSSIDs with differing security strings. That is a prompt to look closer,
not proof of an attack — a legitimate multi-AP rollout can produce it.
EOF
}

audit_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   audit_status_tsv ;;
        --rules-tsv)    audit_rules_tsv ;;
        --audit)        audit_csv "$@" ;;
        --show)         audit_show ;;
        --summary)      audit_summary ;;
        --scan)         audit_scan "$@" ;;
        --selftest)     audit_selftest ;;
        --info)         audit_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --rules-tsv                finding codes and severities
  --audit AIRODUMP.csv       grade the networks in a scan
  --show                     full findings table
  --summary                  severity roll-up and weighted score
  --scan [IFACE]             live capture via iw
  --selftest
  --info
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    audit_cli_main "$@"
fi

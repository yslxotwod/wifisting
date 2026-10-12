#!/usr/bin/env bash
# 02_recon.sh — airodump-ng wrapper with 6 GHz, filters, JSON state

# Self-locate WIFISTING_ROOT from this script's own path so state and
# loot land in the project tree even when launched via pkexec, which
# resets HOME to /root.
if [[ -z "${WIFISTING_ROOT:-}" ]]; then
    _wfs_src="${BASH_SOURCE[0]}"
    while [ -L "$_wfs_src" ]; do
        _wfs_dir="$(cd -P "$(dirname "$_wfs_src")" && pwd)"
        _wfs_tgt="$(readlink "$_wfs_src")"
        [[ "$_wfs_tgt" != /* ]] && _wfs_tgt="$_wfs_dir/$_wfs_tgt"
        _wfs_src="$_wfs_tgt"
    done
    WIFISTING_ROOT="$(cd -P "$(dirname "$_wfs_src")/.." && pwd)"
    export WIFISTING_ROOT
    unset _wfs_src _wfs_dir _wfs_tgt
fi

# Under pkexec, HOME=/root even though we're writing to the invoking
# user's tree. WIFISTING_ROOT is <real_home>/wifisting, so its parent
# is the real home. Reset HOME so downstream $HOME-relative defaults
# (LOOT_DIR, CAPTURES_DIR, LOGS_DIR, XDG_CONFIG_HOME, etc.) resolve
# to the user's paths instead of /root.
if [[ -n "${WIFISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$WIFISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi

: "${TMP_DIR:=/tmp/wifisting}"
: "${LOOT_DIR:=$WIFISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$WIFISTING_ROOT/captures}"
: "${LOGS_DIR:=$WIFISTING_ROOT/logs}"
: "${WIFISTING_HOME:=$WIFISTING_ROOT}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" 2>/dev/null

RECON_DIR="$TMP_DIR/recon"
STATE_DIR="${WIFISTING_STATE:-$WIFISTING_ROOT/state}"
RECON_STATE="$STATE_DIR/recon.json"
RECON_REFRESH_INTERVAL="${RECON_REFRESH_INTERVAL:-1}"

# Per-invocation prefix so concurrent scans don't clobber each other.
# The GUI passes a run-id; otherwise we derive one from $$ + start time.
RECON_RUN_ID="${RECON_RUN_ID:-$$-$(date +%s)}"
RECON_PREFIX="$RECON_DIR/scan-${RECON_RUN_ID}"

mkdir -p "$RECON_DIR" "$STATE_DIR" 2>/dev/null

recon_prepare() {
    mkdir -p "$RECON_DIR" "$STATE_DIR"
    chmod 700 "$STATE_DIR" 2>/dev/null
    # Only clean up OUR prefix (not other concurrent runs)
    rm -f "$RECON_PREFIX"*.csv "$RECON_PREFIX"*.cap \
          "$RECON_PREFIX"*.kismet.csv "$RECON_PREFIX"*.kismet.netxml \
          "$RECON_PREFIX"*.log.csv 2>/dev/null
}

recon_require_mon() {
    if [[ -z "${MON_IFACE:-}" && -f "$TMP_DIR/mon_iface" ]]; then
        MON_IFACE=$(<"$TMP_DIR/mon_iface")
        export MON_IFACE
    fi
    if [[ -z "${MON_IFACE:-}" ]]; then
        MON_IFACE=$(iw dev 2>/dev/null | awk '
            /Interface/ { interface_name = $2 }
            /type monitor/ { print interface_name; exit }')
        [[ -n "$MON_IFACE" ]] && export MON_IFACE
    fi
    [[ -z "${MON_IFACE:-}" ]] && {
        err "monitor interface not set — enable monitor mode in iface menu"
        [[ -z "${WIFISTING_CLI:-}" ]] && read -rp "  press enter " _
        return 1
    }
    iw dev "$MON_IFACE" info >/dev/null 2>&1 || {
        err "monitor interface does not exist: $MON_IFACE"
        return 1
    }
    return 0
}

# ── band to channel-range mapping ──
# airodump accepts: a (5GHz), b (2.4GHz), g (2.4GHz), bg (2.4), abg (both),
# and for 6 GHz you must use the raw frequency list. We synthesize.
recon_band_args() {
    local band="$1"
    case "$band" in
        # Empty band means "all" — GUI passes "" for the All bands
        # dropdown entry, and we want airodump to hop 2.4 + 5 GHz.
        ""|all) printf '%s' "--band abg" ;;
        "2.4")  printf '%s' "--band bg" ;;
        5)      printf '%s' "--band a" ;;
        both)   printf '%s' "--band abg" ;;
        6)     # 6 GHz channels: 1-233, in 20 MHz steps. airodump-ng will
               # reject --band for 6E on older builds; a frequency list
               # is the portable form.
               printf '%s' "--channel 5955,5975,5995,6015,6035,6055,6075,6095,6115,6135,6155,6175,6195,6215,6235,6255,6275,6295,6315,6335,6355,6375,6395,6415,6435,6455,6475,6495,6515,6535,6555,6575,6595,6615,6635,6655,6675,6695,6715,6735,6755,6775,6795,6815,6835,6855,6875,6895,6915,6935,6955,6975,6995,7015,7035,7055,7075,7095,7115" ;;
        *)     printf '%s' "--band bg" ;;
    esac
}

# ── target persistence ──

recon_load_target() {
    [[ -z "${TARGET_BSSID:-}"   && -f "$TMP_DIR/target_bssid"   ]] && TARGET_BSSID=$(<"$TMP_DIR/target_bssid")
    [[ -z "${TARGET_CHANNEL:-}" && -f "$TMP_DIR/target_channel" ]] && TARGET_CHANNEL=$(<"$TMP_DIR/target_channel")
    [[ -z "${TARGET_ESSID:-}"   && -f "$TMP_DIR/target_essid"   ]] && TARGET_ESSID=$(<"$TMP_DIR/target_essid")
    [[ -z "${TARGET_ENC:-}"     && -f "$TMP_DIR/target_enc"     ]] && TARGET_ENC=$(<"$TMP_DIR/target_enc")
    export TARGET_BSSID TARGET_CHANNEL TARGET_ESSID TARGET_ENC
}

recon_save_target() {
    mkdir -p "$TMP_DIR"
    printf '%s\n' "${TARGET_BSSID:-}"   > "$TMP_DIR/target_bssid"
    printf '%s\n' "${TARGET_CHANNEL:-}" > "$TMP_DIR/target_channel"
    printf '%s\n' "${TARGET_ESSID:-}"   > "$TMP_DIR/target_essid"
    printf '%s\n' "${TARGET_ENC:-}"     > "$TMP_DIR/target_enc"
    chmod 600 "$TMP_DIR/target_bssid" "$TMP_DIR/target_channel" \
              "$TMP_DIR/target_essid" "$TMP_DIR/target_enc" 2>/dev/null
}

# ── CSV → TSV (WPA3-aware, BSSID filter) ──

# Returns the newest scan CSV belonging to this run, or falls back to the
# newest overall.
recon_latest_csv() {
    local csv="${RECON_PREFIX}-01.csv"
    if [[ -f "$csv" ]]; then
        printf '%s\n' "$csv"; return 0
    fi
    find "$RECON_DIR" -maxdepth 1 -type f -name 'scan-*.csv' \
        -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2-
}

# Targets straight out of the JSON state, not from a scan CSV.
#
# --list-targets-tsv reads airodump CSV, which only exists while a scan is
# running or freshly finished. The GUI needs the current target list at any
# time, and recon.json holds it persistently - so this reads that instead.
# Parsing stays in python, as everywhere else in this module, so nothing new
# has to be linked into the C side.
# Targets enriched with the fields the target list needs to be scannable:
# PMF capability, WPS, and how many stations are on each AP.
#
# None of these are in recon.json. PMF lives in the RSN Capabilities IE and
# WPS in a vendor IE (WFA type 0x04) - neither is exposed by airodump - so
# both come from a tshark pass over the most recent capture. Station counts
# are derived by grouping the station list by the BSSID each one is on.
recon_cli_targets_enriched_tsv() {
    local jf="${RECON_STATE_FILE:-$WIFISTING_ROOT/state/recon.json}"
    local cap
    [[ -s "$jf" ]] || { printf 'ERROR\tno recon state at %s\n' "$jf" >&2; return 1; }

    cap=$(ls -t "$CAPTURES_DIR"/attack/*.cap "$CAPTURES_DIR"/attack/*.pcapng \
                "$CAPTURES_DIR"/*.cap 2>/dev/null | head -1)

    python3 - "$jf" "${cap:-}" <<'PY'

def _wf_tsv(x):
    """Strip characters that break a TSV row.
    An SSID is attacker-controlled: a network can call itself
    "Foo<TAB>critical<TAB>OPEN" and forge an entire row in any consumer
    that splits on tab. Same class as the payloads this toolkit tests
    for, aimed inward. Tabs and line breaks become spaces so the field
    keeps its shape and the forgery shows up as mangled text.
    """
    return str(x).replace("\t", " ").replace("\r", " ").replace("\n", " ")
import json, subprocess, sys, collections

state, cap = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(state))
except Exception as e:
    sys.stderr.write("ERROR\t%s\n" % e); sys.exit(1)

pmf, wps = {}, set()
if cap:
    try:
        out = subprocess.run(
            ["tshark", "-r", cap, "-Y",
             "wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5",
             "-T", "fields", "-e", "wlan.bssid",
             "-e", "wlan.rsn.capabilities.mfpc",
             "-e", "wlan.rsn.capabilities.mfpr",
             "-e", "wlan.wfa.ie.type"],
            capture_output=True, text=True, timeout=90).stdout
        for line in out.splitlines():
            f = line.split("\t")
            if len(f) < 4 or not f[0]:
                continue
            b = f[0].lower()
            # mfpc = capable, mfpr = required. Required implies capable.
            if f[1].strip().lower() == "true" or f[2].strip().lower() == "true":
                pmf[b] = "yes"
            elif b not in pmf:
                pmf[b] = "no"
            # 0x04 in the WFA vendor IE type list is WPS.
            if "0x04" in f[3].replace(" ", "").split(","):
                wps.add(b)
    except Exception:
        pass

stations = collections.Counter()
for st in (d.get("stations") or []):
    b = (st.get("bssid") or st.get("ap_bssid") or "").lower()
    if b:
        stations[b] += 1

print("BSSID\tSSID\tCHANNEL\tPOWER\tPRIVACY\tCIPHER\tPMF\tWPS\tCLIENTS")
for t in (d.get("targets") or []):
    b = (t.get("bssid") or "").lower()
    def g(k, dflt="-"):
        v = t.get(k)
        return str(v) if v not in (None, "") else dflt
    print("\t".join(_wf_tsv(x) for x in [
        g("bssid"),
        g("essid", "(hidden)"),
        g("channel"),
        g("power"),
        g("privacy"),
        g("cipher"),
        pmf.get(b, "?"),
        "yes" if b in wps else "no",
        str(stations.get(b, 0)),
    ]))
PY
}


recon_cli_targets_json_tsv() {
    local jf="${RECON_STATE_FILE:-$WIFISTING_ROOT/state/recon.json}"
    [[ -s "$jf" ]] || { printf 'ERROR\tno recon state at %s\n' "$jf" >&2; return 1; }
    printf 'BSSID\tSSID\tCHANNEL\tPOWER\tPRIVACY\tCIPHER\n'
    python3 - "$jf" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    sys.stderr.write("ERROR\t%s\n" % e); sys.exit(1)
for t in d.get("targets") or []:
    def g(k, dflt="-"):
        v = t.get(k)
        return str(v) if v not in (None, "") else dflt
    print("\t".join(_wf_tsv(x) for x in [g("bssid"), g("essid", "(hidden)"), g("channel"),
                      g("power"), g("privacy"), g("cipher")]))
PY
}


recon_cli_list_targets_tsv() {
    local csv
    csv=$(recon_latest_csv)
    [[ -z "$csv" || ! -f "$csv" ]] && return 0

    # Optional BSSID filter from an env or arg
    local bssid_filter="${1:-${RECON_FILTER_BSSID:-}}"

    RECON_CSV="$csv" RECON_BSSID_FILTER="$bssid_filter" python3 - <<'PY'
import csv, os
p   = os.environ["RECON_CSV"]
flt = os.environ.get("RECON_BSSID_FILTER", "").strip().lower()

def c(v): return (v or "").strip()

with open(p, encoding="utf-8-sig", errors="replace", newline="") as fh:
    # skipinitialspace must match recon_merge_csv below: airodump separates
    # every field with ", ", so a quoted ESSID arrives as ' "Cafe, Bar"'.
    # Without it csv does not see the quote and splits the ESSID at its comma.
    reader = csv.reader(fh, skipinitialspace=True)
    headers = None
    for raw in reader:
        row = [c(v) for v in raw]
        if not any(row): continue
        if row[0] == "BSSID":
            headers = row; continue
        if row[0] == "Station MAC":
            break
        if not headers: continue
        row += [""] * (len(headers) - len(row))
        rec = dict(zip(headers, row))
        bssid = c(rec.get("BSSID"))
        if not bssid: continue
        if flt and bssid.lower() != flt: continue

        essid = c(rec.get("ESSID")) or "<hidden>"
        privacy = c(rec.get("Privacy"))
        auth    = c(rec.get("Authentication"))

        # WPA3 / SAE detection:
        #   Privacy contains "WPA3" or Authentication contains "SAE"
        #   airodump prints SAE in the Authentication column for WPA3 APs.
        enc = privacy
        if "SAE" in auth or "WPA3" in privacy:
            enc = (privacy + "/WPA3").lstrip("/")
        elif "WPA2" in privacy and "MGT" in auth:
            enc = "WPA2-EAP"

        print("\t".join(_wf_tsv(x) for x in [
            bssid,
            c(rec.get("channel")),
            privacy,
            c(rec.get("Power")),
            essid,
            enc,
        ]))
PY
}

# ── WPA3 / RSN reconstruction from a capture ─────────────────────────────
# airodump-ng's CSV only carries the Privacy string, so the best it can say
# about WPA3 is "WPA2/WPA3". What actually separates the WPA3 variants lives
# in the RSN information element, which the CSV does not carry at all:
#   AKM suite type   2 = PSK (WPA2), 8 = SAE, 24 = SAE-H2E (hash-to-element)
#   RSN Capabilities bit 7 = MFPC, bit 6 = MFPR (WPA3 mandates PMF)
#   group and pairwise cipher suites
# So the beacons/probe responses are parsed straight out of the capture.
#
# Note on the two PMF bits: the numbering above is the house convention, used
# by 03_attack.sh and 34_pmf_bypass.sh --decode-caps so that all three agree.
# IEEE 802.11-2020 Figure 9-321 and Wireshark number them the other way round
# (0x0080 = MFPC, 0x0040 = MFPR). An earlier revision had these transposed;
# where we print 0 1. Both readings agree whenever the bits are equal, which
# includes every WPA3 AP (0x00c0); they differ only for a WPA2 AP that is PMF
# capable but not PMF required. Flipping the two masks in parse_rsn and in the
# selftest synthesizer is the whole change if the tree ever moves to the
# standard numbering.
#
# PcapReader, not rdpcap: rdpcap materialises every packet, and captures in
# this tree run past 140k packets, which is slow enough to look like a hang.

recon_have_scapy() { python3 -c 'import scapy' 2>/dev/null; }

recon_cli_wpa3_recon() {
    local pcap="${1:-}"
    if [[ -z "$pcap" ]]; then
        printf 'ERROR\tusage: --wpa3-recon PCAP\n' >&2
        return 2
    fi
    [[ -f "$pcap" ]] || {
        printf 'ERROR\tnot found: %s\n' "$pcap" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 required for RSN parsing\n' >&2; return 1; }
    recon_have_scapy || {
        printf 'ERROR\tpython3-scapy required (apt install python3-scapy)\n' >&2
        return 1; }

    # Bounded scan: stop after WPA3_MAX_PACKETS frames (default 200000) so a
    # large capture cannot turn into an unbounded read. The table goes to
    # stdout and this verb writes no file at all — no scratch, no loot.
    WPA3_PCAP="$pcap" WPA3_MAX_PACKETS="${WPA3_MAX_PACKETS:-200000}" \
    python3 - <<'PY'
import os, sys
from scapy.all import PcapReader, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt

RS_IE  = 48       # RSN information element
WPA_IE = 221      # WPA1 vendor IE: OUI 00:50:f2, type 1

# IEEE 802.11 AKM suite selectors (the type byte of the 4-byte OUI+type).
AKM_NAMES = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
    5: "802.1X-SHA256", 6: "PSK-SHA256", 7: "TDLS", 8: "SAE",
    9: "FT-SAE", 11: "802.1X-SUITE-B", 12: "802.1X-SUITE-B-192",
    13: "FT-802.1X-SHA384", 14: "FILS-SHA256", 15: "FILS-SHA384",
    16: "FT-FILS-SHA256", 17: "FT-FILS-SHA384", 18: "OWE",
    19: "FT-PSK-SHA384", 20: "PSK-SHA384", 24: "SAE-H2E",
    25: "FT-SAE-H2E",
}
SAE_AKM = frozenset({8, 9, 24, 25})
PSK_AKM = frozenset({2, 4, 6, 19, 20})

def clean(v):
    return str(v).replace("\t", " ").replace("\n", " ").replace("\r", " ")

def parse_rsn(body):
    """Return (akm_types, mfpc, mfpr) from an RSN IE body, or None if cut short.

    Layout: version(2) | group cipher(4) | pairwise count(2) + pairwise(4n)
            | AKM count(2) + AKM(4n) | capabilities(2)
    """
    pos = 6                                   # version + group cipher
    if len(body) < pos + 2:
        return None
    n = int.from_bytes(body[pos:pos + 2], "little"); pos += 2
    pos += 4 * n                              # pairwise cipher list
    if len(body) < pos + 2:
        return None
    n = int.from_bytes(body[pos:pos + 2], "little"); pos += 2
    if len(body) < pos + 4 * n:
        return None
    akms = [body[pos + 4 * i + 3] for i in range(n)]
    pos += 4 * n
    mfpc = mfpr = 0
    if len(body) >= pos + 2:                  # capabilities are optional
        caps = int.from_bytes(body[pos:pos + 2], "little")
        mfpc, mfpr = (caps >> 7) & 1, (caps >> 6) & 1   # 802.11-2020: bit7=MFPC, bit6=MFPR
    return akms, mfpc, mfpr

def mode_of(rec):
    """WPA3 posture from the AKM suites, which is the only place it is real."""
    if not rec["rsn"]:
        # WPA1 rides a vendor IE, not an RSN IE, so an AP carrying one is
        # not open even though it has no RSN element.
        return "WPA(1)-only" if rec["wpa1"] else "OPEN/WEP"
    sae = bool(rec["akm"] & SAE_AKM)
    psk = bool(rec["akm"] & PSK_AKM)
    if sae and psk:
        return "WPA2+WPA3 (transition)"
    if sae:
        return "WPA3-only"
    return "WPA2-only"

limit = int(os.environ.get("WPA3_MAX_PACKETS") or 200000)
aps = {}
try:
    with PcapReader(os.environ["WPA3_PCAP"]) as pr:
        for i, pkt in enumerate(pr):
            if i >= limit:
                break
            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                continue
            bssid = (pkt[Dot11].addr3 or "").upper()
            if not bssid:
                continue
            rec = aps.setdefault(bssid, {"ssid": "", "akm": set(), "mfpc": 0,
                                         "mfpr": 0, "rsn": False, "wpa1": False})
            elt = pkt.getlayer(Dot11Elt)
            while elt is not None:
                info = bytes(elt.info or b"")
                if elt.ID == 0 and not rec["ssid"]:
                    rec["ssid"] = info.decode("utf-8", "replace").strip("\x00")
                elif elt.ID == RS_IE:
                    # Any RSN element at all means this is not an open AP,
                    # even if the element itself is truncated.
                    rec["rsn"] = True
                    parsed = parse_rsn(info)
                    if parsed:
                        akms, mfpc, mfpr = parsed
                        rec["akm"].update(akms)
                        rec["mfpc"] = max(rec["mfpc"], mfpc)
                        rec["mfpr"] = max(rec["mfpr"], mfpr)
                elif (elt.ID == WPA_IE and len(info) > 3
                      and info[:3] == b"\x00\x50\xf2" and info[3] == 1):
                    rec["wpa1"] = True
                nxt = elt.payload
                elt = (nxt.getlayer(Dot11Elt)
                       if (nxt is not None and hasattr(nxt, "getlayer")) else None)
except Exception as e:
    print("ERROR\t%s" % clean(e), file=sys.stderr)
    sys.exit(1)

if not aps:
    print("ERROR\tno beacons or probe responses in %s"
          % clean(os.environ["WPA3_PCAP"]), file=sys.stderr)
    sys.exit(1)

print("BSSID\tSSID\tAKM_SUITES\tPMF_CAPABLE\tPMF_REQUIRED\tMODE")
for bssid in sorted(aps):
    rec = aps[bssid]
    suites = "+".join(AKM_NAMES.get(t, "AKM-%d" % t)
                      for t in sorted(rec["akm"])) or "-"
    print("\t".join(_wf_tsv(x) for x in [bssid,
                     clean(rec["ssid"]) or "<hidden>",
                     suites,
                     str(rec["mfpc"]),
                     str(rec["mfpr"]),
                     mode_of(rec)]))
PY
}

# ── JSON state publisher (unchanged structure; adds running_id) ──

recon_state_publish() {
    local active="${1:-false}" status="${2:-idle}" label="${3:-recon scan}"
    local mode="${4:-all}" band="${5:-}" exit_code="${6:-}" error="${7:-}"
    local csv
    csv=$(recon_latest_csv 2>/dev/null || true)
    [[ -n "$csv" ]] || csv="${RECON_PREFIX}-01.csv"

    mkdir -p "$STATE_DIR" || return 1

    # GUI tells us not to overwrite the target file every second
    if [[ "${RECON_SKIP_TARGET_REFRESH:-0}" != "1" ]]; then
        unset TARGET_BSSID TARGET_CHANNEL TARGET_ESSID TARGET_ENC
        recon_load_target
    fi

    RECON_STATE="$RECON_STATE" RECON_CSV="$csv" \
    RECON_ACTIVE="$active" RECON_STATUS="$status" RECON_LABEL="$label" \
    RECON_MODE="$mode" RECON_BAND="$band" \
    RECON_INTERFACE="${MON_IFACE:-}" \
    RECON_EXIT_CODE="$exit_code" RECON_ERROR="$error" \
    RECON_RUN_ID="$RECON_RUN_ID" \
    TARGET_BSSID="${TARGET_BSSID:-}" TARGET_CHANNEL="${TARGET_CHANNEL:-}" \
    TARGET_ESSID="${TARGET_ESSID:-}" TARGET_ENC="${TARGET_ENC:-}" \
    python3 - <<'PY'
import csv, json, os, tempfile
from datetime import datetime, timezone
from pathlib import Path

def clean(v): return (v or "").strip()
def integer(v):
    try: return int(clean(v))
    except (TypeError, ValueError): return None
def boolean(v): return clean(v).lower() in {"1","true","yes","on"}
def utc_now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")

def load_previous(path):
    try: v = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError): return {}
    return v if isinstance(v, dict) else {}

def atomic_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    prev_uid = prev_gid = -1
    try:
        st = path.stat(); prev_uid = st.st_uid; prev_gid = st.st_gid
    except FileNotFoundError: pass
    fd, tmp = tempfile.mkstemp(prefix=".recon.", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            json.dump(value, h, ensure_ascii=False, indent=2); h.write("\n")
            h.flush(); os.fsync(h.fileno())
        os.chmod(tmp, 0o600)
        if prev_uid >= 0:
            try: os.chown(tmp, prev_uid, prev_gid)
            except (PermissionError, OSError): pass
        os.replace(tmp, path)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def selected_target():
    bssid = clean(os.environ.get("TARGET_BSSID"))
    if not bssid: return None
    return {
        "bssid": bssid,
        "essid": clean(os.environ.get("TARGET_ESSID")) or "<hidden>",
        "channel": integer(os.environ.get("TARGET_CHANNEL")),
        "encryption": clean(os.environ.get("TARGET_ENC")),
    }

def parse_csv(path):
    aps, stations = [], []
    if not path.is_file(): return aps, stations, None
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            # Same airodump ", " separator as recon_cli_list_targets_tsv: a
            # quoted ESSID arrives as ' "Cafe, Bar"', so skipinitialspace is
            # required or csv splits it at the comma and keeps the quote.
            rows = csv.reader(fh, skipinitialspace=True)
            section = None; headers = []
            for raw in rows:
                row = [clean(v) for v in raw]
                if not any(row): continue
                first = row[0]
                if first == "BSSID": section = "ap"; headers = row; continue
                if first == "Station MAC": section = "sta"; headers = row; continue
                if section is None or not headers: continue
                padded = row + [""] * max(0, len(headers) - len(row))
                rec = {headers[i]: padded[i] for i in range(len(headers))}

                if section == "ap":
                    bssid = clean(rec.get("BSSID"))
                    if not bssid: continue
                    privacy = clean(rec.get("Privacy"))
                    cipher  = clean(rec.get("Cipher"))
                    auth    = clean(rec.get("Authentication"))
                    enc = privacy
                    if "SAE" in auth or "WPA3" in privacy:
                        enc = (privacy + "/WPA3").lstrip("/")
                    elif "MGT" in auth and "WPA2" in privacy:
                        enc = "WPA2-EAP"
                    aps.append({
                        "bssid": bssid,
                        "essid": clean(rec.get("ESSID")) or "<hidden>",
                        "channel": integer(rec.get("channel")),
                        "privacy": privacy, "cipher": cipher, "authentication": auth,
                        "encryption": enc,
                        "power": integer(rec.get("Power")),
                        "beacons": integer(rec.get("# beacons")),
                        "data_packets": integer(rec.get("# IV")),
                        "first_seen": clean(rec.get("First time seen")),
                        "last_seen": clean(rec.get("Last time seen")),
                        "lan_ip": clean(rec.get("LAN IP")),
                    })
                else:
                    smac = clean(rec.get("Station MAC"))
                    if not smac: continue
                    abssid = clean(rec.get("BSSID"))
                    if abssid.lower() in {"", "(not associated)", "not associated"}:
                        abssid = None
                    stations.append({
                        "station_mac": smac, "bssid": abssid,
                        "power": integer(rec.get("Power")),
                        "packets": integer(rec.get("# packets")),
                        "first_seen": clean(rec.get("First time seen")),
                        "last_seen": clean(rec.get("Last time seen")),
                    })
    except (OSError, csv.Error) as e:
        return [], [], str(e)

    aps.sort(key=lambda t: (t["power"] is None, -(t["power"] or -999),
                             t["essid"].casefold(), t["bssid"]))
    stations.sort(key=lambda s: (s["power"] is None, -(s["power"] or -999),
                                  s["station_mac"]))
    return aps, stations, None

sp = Path(os.environ["RECON_STATE"])
cp = Path(os.environ["RECON_CSV"])
prev = load_previous(sp)

active = boolean(os.environ.get("RECON_ACTIVE"))
status = clean(os.environ.get("RECON_STATUS")) or "idle"
label  = clean(os.environ.get("RECON_LABEL")) or "recon scan"
mode   = clean(os.environ.get("RECON_MODE")) or "all"
band   = clean(os.environ.get("RECON_BAND"))
iface  = clean(os.environ.get("RECON_INTERFACE"))
reqerr = clean(os.environ.get("RECON_ERROR"))
exit_code = integer(os.environ.get("RECON_EXIT_CODE"))
run_id = clean(os.environ.get("RECON_RUN_ID"))
now = utc_now()

targets, stations, perr = parse_csv(cp)
if active:
    started = prev.get("started_at") if prev.get("status") in {"starting","running","stopping"} else now
else:
    started = prev.get("started_at")

state = {
    "schema_version": 1,
    "run_id": run_id,
    "active": active, "status": status, "label": label,
    "interface": iface or prev.get("interface",""),
    "started_at": started, "updated_at": now,
    "finished_at": None if active else now,
    "exit_code": exit_code,
    "error": reqerr or perr or None,
    "source": str(cp),
    "scan": {"mode": mode, "band": band or None,
              "interface": iface or prev.get("interface",""), "channels": []},
    "selected_target": selected_target(),
    "targets": targets, "stations": stations,
    "summary": {
        "access_points": len(targets),
        "stations": len(stations),
        "associated_stations": sum(s["bssid"] is not None for s in stations),
        "unassociated_stations": sum(s["bssid"] is None for s in stations),
    },
}
atomic_write(sp, state)
PY
}

recon_state_start()  { recon_state_publish true starting "$1" "$2" "$3" "" "" ; }
recon_state_live()   { recon_state_publish true running  "$1" "$2" "$3" "" "" ; }
recon_state_finish() {
    local label="$1" mode="$2" band="$3" exit_code="${4:-0}"
    local status="completed" error=""
    if [[ "$exit_code" -ne 0 && "$exit_code" -ne 130 ]]; then
        status="failed"; error="airodump-ng exited with status $exit_code"
    fi
    recon_state_publish false "$status" "$label" "$mode" "$band" "$exit_code" "$error"
}

recon_state_refresh_target() {
    local active="false" status="idle" label="recon scan" mode="all" band="" exit_code=""
    if [[ -f "$RECON_STATE" ]]; then
        local vals
        vals=$(RECON_STATE="$RECON_STATE" python3 - <<'PY'
import json, os, shlex
from pathlib import Path
p = Path(os.environ["RECON_STATE"])
try: s = json.loads(p.read_text(encoding="utf-8"))
except Exception: s = {}
scan = s.get("scan") or {}
v = [
    str(bool(s.get("active"))).lower(),
    str(s.get("status") or "idle"),
    str(s.get("label") or "recon scan"),
    str(scan.get("mode") or "all"),
    str(scan.get("band") or ""),
    "" if s.get("exit_code") is None else str(s.get("exit_code")),
]
print(" ".join(shlex.quote(x) for x in v))
PY
)
        [[ -n "$vals" ]] && { eval "set -- $vals"
            active="${1:-false}"; status="${2:-idle}"; label="${3:-recon scan}"
            mode="${4:-all}"; band="${5:-}"; exit_code="${6:-}"; }
    fi
    recon_state_publish "$active" "$status" "$label" "$mode" "$band" "$exit_code" ""
}

# ── the airodump runner ──

recon_run_airodump() {
    local label="$1" mode="$2" band="$3"
    shift 3
    local scan_pid="" rc=0 old_int old_term

    old_int=$(trap -p INT || true)
    old_term=$(trap -p TERM || true)

    recon_state_start "$label" "$mode" "$band" || {
        err "could not init state: $RECON_STATE"; return 1
    }

    airodump-ng "$@" --write "$RECON_PREFIX" --output-format csv "$MON_IFACE" &
    scan_pid=$!

    trap 'kill -INT "$scan_pid" 2>/dev/null || true' INT
    trap 'kill -TERM "$scan_pid" 2>/dev/null || true' TERM

    # Bounded run: a watchdog stops airodump after RECON_DURATION seconds.
    local watchdog=""
    if [[ -n "${RECON_DURATION:-}" ]]; then
        ( sleep "$RECON_DURATION"; kill -INT "$scan_pid" 2>/dev/null ) &
        watchdog=$!
    fi

    while kill -0 "$scan_pid" 2>/dev/null; do
        recon_state_live "$label" "$mode" "$band" || true
        sleep "$RECON_REFRESH_INTERVAL" || true
    done

    wait "$scan_pid"; rc=$?
    [[ -n "$watchdog" ]] && kill "$watchdog" 2>/dev/null
    chmod 644 "$RECON_PREFIX"-*.csv 2>/dev/null || true

    [[ -n "$old_int"  ]] && eval "$old_int"  || trap - INT
    [[ -n "$old_term" ]] && eval "$old_term" || trap - TERM

    recon_state_finish "$label" "$mode" "$band" "$rc" || {
        err "could not publish final state"; [[ "$rc" -eq 0 ]] && rc=1
    }
    return "$rc"
}

# ── interactive ──

recon_scan_all() {
    recon_require_mon || return
    recon_prepare
    info "all-band scan on $MON_IFACE (ctrl-c to stop)"
    sleep 1
    recon_run_airodump "all bands" "all" ""
    local rc=$?
    [[ "$rc" -eq 0 || "$rc" -eq 130 ]] && ok "scan stopped" || err "exited $rc"
    read -rp "  press enter " _
    return "$rc"
}

recon_scan_band() {
    recon_require_mon || return
    recon_prepare
    echo "  [1] 2.4GHz  [2] 5GHz  [3] both  [4] 6GHz"
    read -rp "  choice> " b
    local band label
    case "$b" in
        1) band="2.4"; label="2.4 GHz" ;;
        2) band="5";   label="5 GHz" ;;
        3) band="both";label="2.4 + 5 GHz" ;;
        4) band="6";   label="6 GHz (Wi-Fi 6E)" ;;
        *) err "invalid"; return 1 ;;
    esac
    local args
    args=$(recon_band_args "$band")
    info "scanning $label on $MON_IFACE"
    sleep 1
    # shellcheck disable=SC2086
    recon_run_airodump "$label" "band" "$band" $args
    local rc=$?
    [[ "$rc" -eq 0 || "$rc" -eq 130 ]] && ok "scan stopped" || err "exited $rc"
    read -rp "  press enter " _
    return "$rc"
}

recon_cli_start_scan() {
    local mode="${1:-all}" band label args
    # Optional duration bounds the scan from inside the script. The killchain
    # used `pkexec timeout N script`, which makes the program /usr/bin/timeout
    # and so escapes the polkit rule (which only covers /wifisting/modules/).
    if [[ -n "${2:-}" ]]; then
        case "$2" in
            ''|*[!0-9]*) printf 'ERROR\tduration must be seconds\n' >&2; return 2 ;;
            *) export RECON_DURATION="$2" ;;
        esac
    fi
    case "$mode" in
        all)  band="";     label="all bands" ;;
        2.4)  band="2.4";  label="2.4 GHz" ;;
        5)    band="5";    label="5 GHz" ;;
        both) band="both"; label="2.4 + 5 GHz" ;;
        6)    band="6";    label="6 GHz" ;;
        *) printf 'unknown scan mode: %s\n' "$mode" >&2; return 2 ;;
    esac
    recon_require_mon || { printf 'no monitor interface\n' >&2; return 1; }
    recon_prepare
    iface_lock_claim "$MON_IFACE" "02_recon" || return 1
    args=$(recon_band_args "$band")
    # shellcheck disable=SC2086
    recon_run_airodump "$label" "$mode" "$band" $args
}

recon_cli_set_target() {
    local bssid="$1" channel="$2" essid="$3" enc="$4"
    [[ -z "$bssid" ]] && { printf 'missing bssid\n' >&2; return 2; }
    export TARGET_BSSID="$bssid" TARGET_CHANNEL="$channel"
    export TARGET_ESSID="$essid" TARGET_ENC="$enc"
    recon_save_target
    recon_state_refresh_target
}

recon_cli_clear_target() {
    unset TARGET_BSSID TARGET_CHANNEL TARGET_ESSID TARGET_ENC
    rm -f "$TMP_DIR/target_bssid" "$TMP_DIR/target_channel" \
          "$TMP_DIR/target_essid" "$TMP_DIR/target_enc"
    recon_state_refresh_target
}

# If the state file says we're scanning but no airodump-ng process
# exists, the scan died without running its cleanup trap. Rewrite
# the state to idle before returning, so the GUI corrects itself.
recon_check_stale() {
    [[ -f "$RECON_STATE" ]] || return 0

    # Two conditions must both hold before we declare the scan stale:
    #   1. state says active=1
    #   2. updated_at is more than 15s old
    # A live scan rewrites the state every second, so a fresh
    # updated_at is proof of life. If the process died, the file
    # stops advancing and we can safely correct.
    local active age
    read -r active age < <(RECON_STATE="$RECON_STATE" python3 -c "
import json, os, time
try:
    d = json.load(open(os.environ['RECON_STATE']))
except Exception:
    print('0 9999'); raise SystemExit
a = 1 if d.get('active') else 0
up = d.get('updated_at') or ''
age = 9999
try:
    from datetime import datetime, timezone
    t = datetime.fromisoformat(up.replace('Z','+00:00'))
    age = int(time.time() - t.timestamp())
except Exception:
    pass
print(f'{a} {age}')
" 2>/dev/null)

    [[ "$active" == "1" ]] || return 0
    [[ "${age:-9999}" -lt 15 ]] && return 0

    # State is old. If no airodump-ng is alive, flip to idle.
    if ! pgrep -x airodump-ng >/dev/null 2>&1; then
        printf '[info] clearing stale recon state (updated %ss ago, no airodump-ng)\n' \
            "$age" >&2
        recon_state_publish false stale "scan process exited unexpectedly" \
            "all" "" 1 "stale scan state"
    fi
}


recon_cli_status_tsv() {
    recon_check_stale
    if [[ ! -f "$RECON_STATE" ]]; then
        printf 'active\t0\nstatus\tidle\ninterface\t\n'
        printf 'ap_count\t0\nstation_count\t0\n'
        printf 'target_bssid\t\ntarget_essid\t\n'
        printf 'target_channel\t\ntarget_enc\t\n'
        return 0
    fi
    RECON_STATE="$RECON_STATE" python3 - <<'PY'
import json, os
try: s = json.load(open(os.environ["RECON_STATE"]))
except Exception: s = {}
summ = s.get("summary") or {}; tgt = s.get("selected_target") or {}
def esc(v): return str(v).replace("\t"," ").replace("\n"," ")
print("active\t"        + ("1" if s.get("active") else "0"))
print("status\t"        + esc(s.get("status") or "idle"))
print("interface\t"     + esc(s.get("interface") or ""))
print("ap_count\t"      + str(summ.get("access_points") or 0))
print("station_count\t" + str(summ.get("stations") or 0))
print("target_bssid\t"  + esc(tgt.get("bssid") or ""))
print("target_essid\t"  + esc(tgt.get("essid") or ""))
print("target_channel\t"+ (str(tgt["channel"]) if tgt.get("channel") is not None else ""))
print("target_enc\t"    + esc(tgt.get("encryption") or ""))
PY
}

# ── iface arbitration ──
# Monitor-only modules compete for one adapter; 01_iface.sh owns the lock.
IFACE_MODULE="$WIFISTING_ROOT/modules/01_iface.sh"
IFACE_LOCK_IFACE=""
iface_lock_release() {
    [[ -n "$IFACE_LOCK_IFACE" ]] || return 0
    "$IFACE_MODULE" --lock-release "$IFACE_LOCK_IFACE" $$ >/dev/null 2>&1
    IFACE_LOCK_IFACE=""
}
# For BLOCKING commands only (the CLI process lives as long as the capture),
# so $$ is the correct holder. The EXIT trap matters: without it a failure
# path that exits directly leaves a ghost lock and blocks every later module.
iface_lock_claim() {
    [[ -x "$IFACE_MODULE" ]] || return 0
    local out
    if ! out=$("$IFACE_MODULE" --lock-claim "$1" "$2" $$ 2>&1); then
        printf 'ERROR\tinterface busy\n%s\n' "$out" >&2
        return 1
    fi
    IFACE_LOCK_IFACE="$1"
    trap iface_lock_release EXIT
    return 0
}

# Stop a live scan. The GUI must run this under pkexec: the scan was started
# via pkexec, so airodump is root-owned and an unprivileged kill() gets EPERM
# — which is exactly why "Stop scan" appeared to do nothing. We kill airodump
# itself and let the running --start-scan loop notice and publish final state.
recon_cli_stop_scan() {
    local killed=0 seen=0 p
    for p in $(pgrep -x airodump-ng 2>/dev/null); do
        [[ "$p" == "$$" || "$p" == "$PPID" ]] && continue
        # Only ours: the one writing into the recon capture dir.
        tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null \
            | grep -q -- "$RECON_DIR/" || continue
        seen=1
        stop_kill_pid "$p" && killed=1
    done
    if (( killed == 1 )); then
        printf 'STOPPED\n'
        return 0
    fi
    if (( seen == 1 )); then
        # We found it but could not signal it — almost always because the scan
        # is root-owned and we are not. Say so instead of printing STOPPED.
        printf 'ERROR\tairodump is running but could not be signalled (needs pkexec)\n' >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
    return 0
}

# ── verified stop ──
# Escalating signals; returns 0 ONLY once the pid is actually gone. Signals
# the process group first so forked children die with the leader.
stop_kill_pid() {
    local pid="$1" i
    # Liveness via /proc, NOT `kill -0`: for a root-owned process we get EPERM,
    # and treating that as "gone" made stops report success while nothing died.
    [[ -d "/proc/$pid" ]] || return 0
    kill -INT  "-$pid" 2>/dev/null || kill -INT  "$pid" 2>/dev/null
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [[ -d "/proc/$pid" ]] || return 0
        sleep 0.2
    done
    kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for i in 1 2 3 4 5; do
        [[ -d "/proc/$pid" ]] || return 0
        sleep 0.2
    done
    kill -KILL "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
    sleep 0.3
    [[ -d "/proc/$pid" ]] && return 1
    return 0
}

# ── Merge (merged from airodump_merge, submenu: Merge) ───────────────────
# Union of several airodump-ng runs into one AP list and one client list.
# airodump CSV puts ESSIDs in quotes and they routinely contain commas, so
# this is parsed with python's csv module rather than by splitting on ",".

recon_merge_sources_tsv() {
    local d
    for d in "$RECON_DIR" "$LOOT_DIR" "$LOOT_DIR/recon"; do
        [[ -d "$d" ]] || continue
        find "$d" -maxdepth 1 -type f \( -name '*.csv' -o -name '*.cap' \
             -o -name '*.pcap' -o -name '*.pcapng' \) -printf '%T@\t%p\t%s\n' \
             2>/dev/null
    done | sort -rn | awk -F'\t' '{ printf "%s\t%s\n", $2, $3 }'
}

recon_merge_default_out() {
    mkdir -p "$RECON_DIR" 2>/dev/null
    printf '%s\n' "$RECON_DIR/merged-$(date +%s)"
}

recon_merge_csv() {
    local out_prefix="${1:-}"
    shift 2>/dev/null || true
    if [[ -z "$out_prefix" || $# -eq 0 ]]; then
        printf 'ERROR\tusage: --merge-csv OUT_PREFIX FILE...\n' >&2
        return 2
    fi
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 required for CSV merge\n' >&2; return 1
    }
    local f missing=0
    for f in "$@"; do
        [[ -f "$f" ]] || { printf 'ERROR\tnot found: %s\n' "$f" >&2; missing=1; }
    done
    (( missing )) && return 1

    mkdir -p "$(dirname "$out_prefix")" 2>/dev/null
    python3 - "$out_prefix" "$@" <<'PYEOF'
import csv, sys

out_prefix = sys.argv[1]
paths = sys.argv[2:]

def num(s, default=0):
    try:
        return int((s or "").strip())
    except ValueError:
        return default

def txt(s):
    return (s or "").strip()

aps = {}
clients = {}

for path in paths:
    section = None
    try:
        fh = open(path, newline="", encoding="utf-8", errors="replace")
    except OSError as e:
        print("ERROR\t%s" % e, file=sys.stderr)
        sys.exit(1)
    with fh:
        for row in csv.reader(fh, skipinitialspace=True):
            if not row:
                continue
            first = txt(row[0])
            if first == "BSSID":
                section = "ap"; continue
            if first == "Station MAC":
                section = "client"; continue

            if section == "ap" and len(row) >= 15 and first:
                bssid = first.upper()
                new = {
                    "first": txt(row[1]), "last": txt(row[2]),
                    "chan": txt(row[3]), "speed": txt(row[4]),
                    "priv": txt(row[5]), "cipher": txt(row[6]),
                    "auth": txt(row[7]), "power": num(row[8], -1),
                    "beacons": num(row[9]), "iv": num(row[10]),
                    # airodump pads each octet ("  0.  0.  0.  0") for
                    # alignment; collapse the padding back to a real IP.
                    "lan": "".join(txt(row[11]).split()),
                    "idlen": txt(row[12]),
                    "essid": txt(row[13]), "key": txt(row[14]),
                }
                rec = aps.get(bssid)
                if rec is None:
                    aps[bssid] = new
                    continue
                # Union: earliest first-seen, latest last-seen, strongest
                # power, counters summed (these come from disjoint captures).
                if new["first"] and (not rec["first"] or new["first"] < rec["first"]):
                    rec["first"] = new["first"]
                if new["last"] > rec["last"]:
                    rec["last"] = new["last"]
                    for k in ("chan", "speed", "priv", "cipher", "auth",
                              "lan", "idlen", "essid", "key"):
                        if new[k]:
                            rec[k] = new[k]
                if new["power"] > rec["power"]:
                    rec["power"] = new["power"]
                rec["beacons"] += new["beacons"]
                rec["iv"] += new["iv"]
                # Backfill whatever the retained record is missing: a value
                # seen in an older capture still beats a blank, and airodump
                # writes 0.0.0.0 when it never learned the LAN IP.
                for k in ("chan", "speed", "priv", "cipher", "auth",
                          "lan", "idlen", "essid", "key"):
                    cur = rec[k]
                    if new[k] and (not cur or (k == "lan" and cur == "0.0.0.0")):
                        rec[k] = new[k]

            elif section == "client" and len(row) >= 6 and first:
                mac = first.upper()
                new = {
                    "first": txt(row[1]), "last": txt(row[2]),
                    "power": num(row[3], -1), "packets": num(row[4]),
                    "bssid": txt(row[5]).upper(),
                    "probes": [p.strip() for p in
                               (row[6] if len(row) > 6 else "").split(",")
                               if p.strip()],
                }
                rec = clients.get(mac)
                if rec is None:
                    clients[mac] = new
                    continue
                if new["first"] and (not rec["first"] or new["first"] < rec["first"]):
                    rec["first"] = new["first"]
                if new["last"] > rec["last"]:
                    rec["last"] = new["last"]
                    if new["bssid"]:
                        rec["bssid"] = new["bssid"]
                if new["power"] > rec["power"]:
                    rec["power"] = new["power"]
                rec["packets"] += new["packets"]
                for p in new["probes"]:
                    if p not in rec["probes"]:
                        rec["probes"].append(p)

ap_path = out_prefix + ".csv"
cl_path = out_prefix + ".clients.csv"

try:
    with open(ap_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["BSSID", "First time seen", "Last time seen", "channel",
                    "Speed", "Privacy", "Cipher", "Authentication", "Power",
                    "# beacons", "# IV", "LAN IP", "ID-length", "ESSID", "Key"])
        for b in sorted(aps):
            r = aps[b]
            w.writerow([b, r["first"], r["last"], r["chan"], r["speed"],
                        r["priv"], r["cipher"], r["auth"], r["power"],
                        r["beacons"], r["iv"], r["lan"], r["idlen"],
                        r["essid"], r["key"]])
    with open(cl_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Station MAC", "First time seen", "Last time seen",
                    "Power", "# packets", "BSSID", "Probed ESSIDs"])
        for m in sorted(clients):
            r = clients[m]
            w.writerow([m, r["first"], r["last"], r["power"], r["packets"],
                        r["bssid"], ", ".join(r["probes"])])
except OSError as e:
    print("ERROR\t%s" % e, file=sys.stderr)
    sys.exit(1)

print("INPUT\t%d" % len(paths))
print("APS\t%d" % len(aps))
print("CLIENTS\t%d" % len(clients))
print("OUT_CSV\t%s" % ap_path)
print("OUT_CLIENTS\t%s" % cl_path)
PYEOF
}

recon_merge_pcap() {
    local out="${1:-}"
    shift 2>/dev/null || true
    if [[ -z "$out" || $# -eq 0 ]]; then
        printf 'ERROR\tusage: --merge-pcap OUT.pcapng FILE...\n' >&2
        return 2
    fi
    command -v mergecap >/dev/null 2>&1 || {
        printf 'ERROR\tmergecap not installed (apt install wireshark-common)\n' >&2
        return 1
    }
    local f missing=0
    for f in "$@"; do
        [[ -f "$f" ]] || { printf 'ERROR\tnot found: %s\n' "$f" >&2; missing=1; }
    done
    (( missing )) && return 1

    local err rc=0
    err=$(mergecap -w "$out" "$@" 2>&1) || rc=$?
    if (( rc != 0 )); then
        printf 'ERROR\tmergecap failed: %s\n' "$(printf '%s' "$err" | tr '\n' ' ')" >&2
        return 1
    fi
    [[ -s "$out" ]] || { printf 'ERROR\tmergecap produced no output\n' >&2; return 1; }
    printf 'MERGED\t%d\n' "$#"
    printf 'OUT_PCAP\t%s\n' "$out"
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no radio, no root, no network. Every path written to lives
# under a scratch dir inside $RECON_DIR and is removed before returning, so
# loot/, state/ and captures/ are never touched.
recon_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local st="$RECON_DIR/selftest-$$"
    rm -rf "$st"; mkdir -p "$st/recon"
    # Shadow the globals so nothing escapes into the real tree.
    local RECON_DIR="$st" RECON_PREFIX="$st/scan" TMP_DIR="$st"
    local RECON_STATE="$st/state.json" STATE_DIR="$st"

    # ── band -> airodump argument mapping ──
    chk band-all       "$(recon_band_args "")"   "--band abg"
    chk band-2.4       "$(recon_band_args 2.4)"  "--band bg"
    chk band-5         "$(recon_band_args 5)"    "--band a"
    chk band-both      "$(recon_band_args both)" "--band abg"
    chk band-unknown   "$(recon_band_args 900)"  "--band bg"
    # The 6 GHz path is a hardcoded frequency list; it must equal the
    # Wi-Fi 6E 20 MHz channel plan (5955..7115), or airodump hops nowhere.
    chk band-6-plan    "$(recon_band_args 6)" "--channel $(seq -s, 5955 20 7115)"
    chk band-6-count   "$(recon_band_args 6 | awk -F, '{print NF}')" "59"

    # ── airodump CSV -> TSV (WPA3 / EAP / hidden ESSID classification) ──
    local csv="$st/scan-01.csv"
    cat > "$csv" <<'CSV'
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:00:00:01, 2026-01-01 10:00:00, 2026-01-01 10:05:00,  6,  54, WPA2, CCMP, PSK, -45, 100, 5, 0.0.0.0, 12, "Cafe, Bar", 
AA:BB:CC:00:00:02, 2026-01-01 10:00:00, 2026-01-01 10:06:00, 11,  54, WPA2, CCMP, SAE, -60,  50, 0, 0.0.0.0,  8, SecureNet, 
AA:BB:CC:00:00:03, 2026-01-01 10:00:00, 2026-01-01 10:07:00, 36,  54, WPA2, CCMP, MGT, -70,  20, 0, 0.0.0.0,  8, CorpNet, 
AA:BB:CC:00:00:04, 2026-01-01 10:00:00, 2026-01-01 10:08:00,  1,  54, OPN, , , -80,   1, 0, 0.0.0.0,  0, , 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-01-01 10:00:00, 2026-01-01 10:05:00, -40, 100, AA:BB:CC:00:00:01, 
CSV
    local want
    want=$(printf '%s\n' \
        $'AA:BB:CC:00:00:01\t6\tWPA2\t-45\tCafe, Bar\tWPA2' \
        $'AA:BB:CC:00:00:02\t11\tWPA2\t-60\tSecureNet\tWPA2/WPA3' \
        $'AA:BB:CC:00:00:03\t36\tWPA2\t-70\tCorpNet\tWPA2-EAP' \
        $'AA:BB:CC:00:00:04\t1\tOPN\t-80\t<hidden>\tOPN')
    # Row 1 above is the padded-then-quoted form airodump writes (it separates
    # fields with ", "): `, 12, "Cafe, Bar", `. Without skipinitialspace csv
    # does not see the quote and yields `"Cafe`.
    chk list-targets          "$(recon_cli_list_targets_tsv)" "$want"
    chk list-targets-essid-no-quote \
        "$(recon_cli_list_targets_tsv AA:BB:CC:00:00:01 | cut -f5 | grep -c '"')" "0"
    chk list-targets-essid-intact \
        "$(recon_cli_list_targets_tsv AA:BB:CC:00:00:01 | cut -f5)" "Cafe, Bar"
    chk list-targets-fields "$(recon_cli_list_targets_tsv | awk -F'\t' 'NF!=6{c++} END{print c+0}')" "0"
    chk list-targets-filter   "$(recon_cli_list_targets_tsv AA:BB:CC:00:00:02)" \
        $'AA:BB:CC:00:00:02\t11\tWPA2\t-60\tSecureNet\tWPA2/WPA3'
    chk list-targets-filter-lower "$(recon_cli_list_targets_tsv aa:bb:cc:00:00:02)" \
        $'AA:BB:CC:00:00:02\t11\tWPA2\t-60\tSecureNet\tWPA2/WPA3'
    chk list-targets-filter-env "$(RECON_FILTER_BSSID=AA:BB:CC:00:00:03 recon_cli_list_targets_tsv)" \
        $'AA:BB:CC:00:00:03\t36\tWPA2\t-70\tCorpNet\tWPA2-EAP'
    chk list-targets-filter-miss "$(recon_cli_list_targets_tsv AA:BB:CC:00:00:09)" ""

    # ── CSV merge: union of two captures ──
    cat > "$st/a.csv" <<'CSV'
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:00:00:01, 2026-01-01 10:00:00, 2026-01-01 10:05:00,  6,  54, WPA2, CCMP, PSK, -50, 10, 2, 0.0.0.0, 12, Cafe, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-01-01 10:00:00, 2026-01-01 10:05:00, -40, 100, AA:BB:CC:00:00:01, Cafe
CSV
    cat > "$st/b.csv" <<'CSV'
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:00:00:01, 2026-01-01 10:00:00, 2026-01-01 10:09:00, 11,  54, WPA2, CCMP, PSK, -70,  7, 3, 0.0.0.0, 12, , 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-01-01 10:00:00, 2026-01-01 10:06:00, -55,  50, AA:BB:CC:00:00:01, Guest
CSV
    local mout; mout=$(recon_merge_csv "$st/merged" "$st/a.csv" "$st/b.csv")
    chk merge-inputs  "$(printf '%s\n' "$mout" | awk -F'\t' '$1=="INPUT"{print $2}')"   "2"
    chk merge-aps     "$(printf '%s\n' "$mout" | awk -F'\t' '$1=="APS"{print $2}')"     "1"
    chk merge-clients "$(printf '%s\n' "$mout" | awk -F'\t' '$1=="CLIENTS"{print $2}')" "1"
    chk merge-files   "$([[ -s "$st/merged.csv" && -s "$st/merged.clients.csv" ]] && echo yes || echo no)" "yes"
    # newest capture wins the channel, strongest power wins overall,
    # counters sum, and a stale-but-nonempty ESSID is never blanked.
    chk merge-ap-chan     "$(awk -F, 'NR==2{print $4}' "$st/merged.csv")"          "11"
    chk merge-ap-power    "$(awk -F, 'NR==2{print $9}' "$st/merged.csv")"          "-50"
    chk merge-ap-beacons  "$(awk -F, 'NR==2{print $10}' "$st/merged.csv")"         "17"
    chk merge-ap-iv       "$(awk -F, 'NR==2{print $11}' "$st/merged.csv")"         "5"
    chk merge-ap-essid    "$(awk -F, 'NR==2{print $14}' "$st/merged.csv")"         "Cafe"
    chk merge-cl-power    "$(awk -F, 'NR==2{print $4}' "$st/merged.clients.csv")"  "-40"
    chk merge-cl-packets  "$(awk -F, 'NR==2{print $5}' "$st/merged.clients.csv")"  "150"
    chk merge-cl-probes   "$(grep -cF 'Cafe, Guest' "$st/merged.clients.csv")"     "1"
    # Rejections must be non-zero, and must not claim success.
    recon_merge_csv "$st/out2" "$st/does-not-exist.csv" >/dev/null 2>&1
    chk merge-missing-file-rc "$?" "1"
    recon_merge_csv >/dev/null 2>&1
    chk merge-usage-rc "$?" "2"

    # ── state publisher: CSV in, JSON out ──
    recon_state_publish false completed "selftest" all "" 0 "" >/dev/null 2>&1
    local jq="$st/state.json"
    chk state-written  "$([[ -s "$jq" ]] && echo yes || echo no)" "yes"
    chk state-active   "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["active"])' "$jq")" "False"
    chk state-status   "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$jq")" "completed"
    chk state-aps      "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["summary"]["access_points"])' "$jq")" "4"
    chk state-stations "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["summary"]["stations"])' "$jq")" "1"
    chk state-essid    "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["targets"][0]["essid"])' "$jq")" "Cafe, Bar"
    chk state-target   "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["selected_target"])' "$jq")" "None"
    chk state-error    "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["error"])' "$jq")" "None"

    # ── argument validation (never reached the radio) ──
    recon_cli_start_scan all not-a-number >/dev/null 2>&1
    chk start-scan-bad-duration-rc "$?" "2"
    recon_cli_start_scan bogus-mode >/dev/null 2>&1
    chk start-scan-bad-mode-rc "$?" "2"

    # ── WPA3 RSN reconstruction: AKM suites + PMF capabilities ──
    # A missing argument and a missing file must both be non-zero and must
    # not print a table. The parse itself is then run over a pcap synthesized
    # in scratch by scapy when it is installed, so this needs no radio and
    # reads none of the user's captures.
    recon_cli_wpa3_recon >/dev/null 2>&1
    chk wpa3-recon-usage-rc   "$?" "2"
    recon_cli_wpa3_recon "$st/does-not-exist.pcap" >/dev/null 2>&1
    chk wpa3-recon-missing-rc "$?" "1"
    if recon_have_scapy; then
        if WPA3_SYNTH="$st/wpa3-synth.pcap" python3 - >/dev/null 2>&1 <<'PY'
import os
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, wrpcap

def rsn(akms, mfpc=0, mfpr=0, group=4, pairwise=(4,)):
    """RSN IE body: version, group cipher, pairwise, AKM list, capabilities."""
    b  = (1).to_bytes(2, "little") + bytes([0x00, 0x0f, 0xac, group])
    b += len(pairwise).to_bytes(2, "little")
    b += b"".join(bytes([0x00, 0x0f, 0xac, p]) for p in pairwise)
    b += len(akms).to_bytes(2, "little")
    b += b"".join(bytes([0x00, 0x0f, 0xac, a]) for a in akms)
    b += (((mfpr << 7) | (mfpc << 6))).to_bytes(2, "little")
    return b

def wpa1():
    """WPA1 vendor IE body: OUI 00:50:f2, type 1, then a minimal WPA IE."""
    return bytes([0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
                  0x00, 0x50, 0xf2, 0x02])

def beacon(bssid, ssid, ies=()):
    p = (RadioTap()
         / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                 addr2=bssid, addr3=bssid)
         / Dot11Beacon(cap="ESS")
         / Dot11Elt(ID=0, info=ssid.encode()))
    for elem_id, info in ies:
        p = p / Dot11Elt(ID=elem_id, info=info)
    return p

wrpcap(os.environ["WPA3_SYNTH"], [
    beacon("aa:bb:cc:00:00:01", "TransNet", [(48, rsn([2, 8], mfpc=1, mfpr=1))]),
    beacon("aa:bb:cc:00:00:02", "Wpa3Only", [(48, rsn([8], mfpc=1, mfpr=1))]),
    beacon("aa:bb:cc:00:00:03", "Wpa2Only", [(48, rsn([2]))]),
    beacon("aa:bb:cc:00:00:04", "OpenNet",  []),
    beacon("aa:bb:cc:00:00:05", "H2eNet",   [(48, rsn([24], mfpc=1, mfpr=0))]),
    beacon("aa:bb:cc:00:00:06", "",         [(48, rsn([2]))]),
    beacon("aa:bb:cc:00:00:07", "Wpa1Net",  [(221, wpa1())]),
])
PY
        then
            local w3
            w3=$(recon_cli_wpa3_recon "$st/wpa3-synth.pcap" 2>/dev/null)
            chk wpa3-recon-header "$(printf '%s\n' "$w3" | head -n1)" \
                $'BSSID\tSSID\tAKM_SUITES\tPMF_CAPABLE\tPMF_REQUIRED\tMODE'
            chk wpa3-recon-rows \
                "$(printf '%s\n' "$w3" | awk -F'\t' 'NR>1 {
                     printf "%s=%s/%s,%s,%s,%s\n", $1, $2, $3, $4, $5, $6 }' \
                   | paste -sd' ')" \
                "AA:BB:CC:00:00:01=TransNet/PSK+SAE,1,1,WPA2+WPA3 (transition) AA:BB:CC:00:00:02=Wpa3Only/SAE,1,1,WPA3-only AA:BB:CC:00:00:03=Wpa2Only/PSK,0,0,WPA2-only AA:BB:CC:00:00:04=OpenNet/-,0,0,OPEN/WEP AA:BB:CC:00:00:05=H2eNet/SAE-H2E,0,1,WPA3-only AA:BB:CC:00:00:06=<hidden>/PSK,0,0,WPA2-only AA:BB:CC:00:00:07=Wpa1Net/-,0,0,WPA(1)-only"
        fi
    fi

    rm -rf "$st"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

recon_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)       recon_cli_status_tsv ;;
        --list-targets-tsv) recon_cli_list_targets_tsv "$@" ;;
        --targets-json-tsv) recon_cli_targets_json_tsv ;;
        --targets-enriched-tsv) recon_cli_targets_enriched_tsv ;;
        --start-scan)       recon_cli_start_scan "$@" ;;
        --stop-scan)        recon_cli_stop_scan ;;
        --set-target)       recon_cli_set_target "$@" ;;
        --clear-target)     recon_cli_clear_target ;;
        --merge-sources-tsv) recon_merge_sources_tsv ;;
        --merge-default-out) recon_merge_default_out ;;
        --merge-csv)        recon_merge_csv "$@" ;;
        --merge-pcap)       recon_merge_pcap "$@" ;;
        --wpa3-recon)       recon_cli_wpa3_recon "$@" ;;
        --selftest)         recon_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 --status-tsv | --list-targets-tsv [BSSID_FILTER] |
          --start-scan all|2.4|5|both|6 [SECONDS] | --stop-scan |
          --set-target BSSID CH ESSID ENC | --clear-target |
          --merge-sources-tsv | --merge-default-out |
          --merge-csv OUT_PREFIX FILE... |
          --merge-pcap OUT.pcapng FILE... |
          --wpa3-recon PCAP |
          --selftest
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    WIFISTING_CLI=1
    command -v banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    command -v warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    command -v err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    command -v ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    : "${TMP_DIR:=/tmp/wifisting}"
    mkdir -p "$TMP_DIR"
    recon_cli_main "$@"
fi

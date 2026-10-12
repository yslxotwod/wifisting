#!/usr/bin/env bash
# 36_ble_tracker_hunt — BLE Tracker Hunt
# Identify AirTag/SmartTag/Tile advertisements and detect trackers that follow.
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

MOD_TMP="$TMP_DIR/ble_tracker_hunt"
MOD_LOOT="$LOOT_DIR/ble_tracker_hunt"
MOD_LOGS="$LOG_DIR/ble_tracker_hunt"
MOD_CAPS="$CAPTURES_DIR/ble_tracker_hunt"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

TRK_SIGS="$MOD_LOOT/tracker_signatures.tsv"
TRK_SIGHTINGS="$MOD_LOOT/sightings.tsv"

trk_have_hci() {
    local d
    for d in /sys/class/bluetooth/hci*; do
        [[ -e "$d" ]] && { basename "$d"; return 0; }
    done
    return 1
}

trk_status_tsv() {
    local h; h=$(trk_have_hci 2>/dev/null || true)
    printf 'hci\t%s\n'       "${h:-none}"
    printf 'bluetoothctl\t%s\n' "$(command -v bluetoothctl >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'btmon\t%s\n'     "$(command -v btmon >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'hcitool\t%s\n'   "$(command -v hcitool >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'python3\t%s\n'   "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    # Passive decoding of a supplied payload works with no radio at all;
    # only live scanning needs the adapter, so the two are reported apart.
    printf 'decode\t1\n'
    printf 'live_scan\t%s\n' "$([[ -n "$h" ]] && echo 1 || echo 0)"
    local n=0; [[ -f "$TRK_SIGHTINGS" ]] && n=$(grep -c . "$TRK_SIGHTINGS" 2>/dev/null) || n=0
    printf 'cached_sightings\t%s\n' "$n"
}

# ── tracker signature database ───────────────────────────────────────────
# Company IDs are the Bluetooth SIG-assigned values that appear little-endian
# in Manufacturer Specific Data (AD type 0xFF).
trk_signatures() {
    cat <<'EOF'
apple_findmy	0x004C	0x12	Apple	Find My network (AirTag, third-party Find My)	high
apple_airpods	0x004C	0x07	Apple	AirPods / Beats proximity pairing	high
apple_nearby	0x004C	0x10	Apple	Nearby Info (iPhone, iPad, Mac)	high
apple_ibeacon	0x004C	0x02	Apple	iBeacon	high
apple_handoff	0x004C	0x0C	Apple	Handoff / Activity Continuation	medium
samsung_smarttag	0x0075	0x01	Samsung	SmartTag / SmartTag+	medium
samsung_buds	0x0075	0x02	Samsung	Galaxy Buds proximity	medium
tile	0x011D	-	Tile	Tile tracker (company-specific payload)	medium
google_fmdn	0xFE2C	-	Google	Fast Pair / Find My Device network	medium
chipolo	0x021C	-	Chipolo	Chipolo tracker	low
EOF
}

trk_service_signatures() {
    cat <<'EOF'
0xFEED	Tile	Tile tracker service (legacy advertising)	medium
0xFEEC	Tile	Tile tracker service	medium
0xFE9F	Google	Find My Device network accessory	medium
0xFD5A	Samsung	SmartTag service	medium
0x180F	-	Battery Service (not a tracker indicator)	low
0x1809	-	Health Thermometer (not a tracker indicator)	low
EOF
}

# ── advertisement decoding ───────────────────────────────────────────────
# Walks the AD structures in a raw advertising payload:
#   [length][type][data ...] repeated until the payload is consumed.
trk_decode() {
    local hex="$1"
    [[ -z "$hex" ]] && { printf 'ERROR\tusage: --decode AD_HEX\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    python3 - "$hex" <<'PYEOF'
import sys

raw = "".join(sys.argv[1].split()).replace(":", "")
try:
    data = bytes.fromhex(raw)
except ValueError:
    print("ERROR\tnot valid hex", file=sys.stderr); sys.exit(1)

ADT = {0x01:"flags", 0x02:"uuid16_incomplete", 0x03:"uuid16_complete",
       0x06:"uuid128_incomplete", 0x07:"uuid128_complete",
       0x08:"name_short", 0x09:"name_complete", 0x0A:"tx_power",
       0x16:"service_data16", 0x19:"appearance", 0x1A:"tx_power2",
       0x20:"service_data32", 0x21:"service_data128", 0xFF:"manufacturer"}

# company id -> (vendor, product, confidence)
MANUF = {
    0x004C: ("Apple", None, "high"),
    0x0075: ("Samsung", None, "high"),
    0x011D: ("Tile", "Tile tracker", "medium"),
    0xFE2C: ("Google", "Fast Pair / Find My Device", "medium"),
    0x021C: ("Chipolo", "Chipolo tracker", "low"),
    0x00E0: ("Google", "Eddystone/other", "low"),
    0x0157: ("Apple", "Beats", "medium"),
}
APPLE_TYPE = {0x12: ("Find My network", "AirTag or third-party Find My tag", "high"),
              0x07: ("AirPods proximity pairing", "AirPods / Beats", "high"),
              0x10: ("Nearby Info", "iPhone / iPad / Mac", "high"),
              0x02: ("iBeacon", "iBeacon transmitter", "high"),
              0x0C: ("Handoff", "Apple Handoff", "medium"),
              0x0F: ("Nearby Action", "Apple device action", "medium"),
              0x05: ("AirDrop", "Apple AirDrop", "medium")}
SAMSUNG_TYPE = {0x01: ("SmartTag", "Samsung SmartTag / SmartTag+", "medium"),
                0x02: ("Galaxy Buds", "Samsung earbuds", "medium")}

i = 0
n = 0
verdict = None
while i < len(data):
    ln = data[i]; i += 1
    if ln == 0:
        break
    if i + ln > len(data):
        print("WARN\ttruncated AD structure at offset %d" % (i - 1))
        break
    ad = data[i:i+ln]; i += ln
    if not ad:
        continue
    typ = ad[0]
    body = ad[1:]
    name = ADT.get(typ, "type_0x%02x" % typ)
    n += 1

    if typ == 0xFF and len(body) >= 2:
        cid = body[0] | (body[1] << 8)
        extra = body[2:]
        vendor, product, conf = MANUF.get(cid, ("unknown", None, "low"))
        desc = product or vendor
        # Apple nests a second type byte after the company id.
        if cid == 0x004C and extra:
            at = extra[0]
            if at in APPLE_TYPE:
                sub, prod, c2 = APPLE_TYPE[at]
                desc = "%s — %s" % (prod, sub)
                conf = c2
        elif cid == 0x0075 and extra:
            st = extra[0]
            if st in SAMSUNG_TYPE:
                sub, prod, c2 = SAMSUNG_TYPE[st]
                desc = "%s — %s" % (prod, sub)
                conf = c2
        print("AD\t%s\tcompany=0x%04X\tvendor=%s\t%s\tdata=%s" %
              (name, cid, vendor, desc, extra.hex()))
        if conf == "high" and verdict is None:
            verdict = (desc, conf, cid)
        elif conf == "medium" and verdict is None:
            verdict = (desc, conf, cid)
    elif typ == 0x16 and len(body) >= 2:
        uuid = body[0] | (body[1] << 8)
        print("AD\t%s\tuuid=0x%04X\tdata=%s" % (name, uuid, body[2:].hex()))
        if uuid in (0xFEED, 0xFEEC) and verdict is None:
            verdict = ("Tile tracker (service 0x%04X)" % uuid, "medium", None)
        elif uuid == 0xFD5A and verdict is None:
            verdict = ("Samsung SmartTag (service 0xFD5A)", "medium", None)
        elif uuid == 0xFE9F and verdict is None:
            verdict = ("Google Find My Device accessory", "medium", None)
    elif typ in (0x08, 0x09):
        print("AD\t%s\tname=%s" % (name, body.decode("utf-8", "replace")))
    elif typ == 0x01 and body:
        print("AD\t%s\tflags=0x%02x" % (name, body[0]))
    else:
        print("AD\t%s\tdata=%s" % (name, body.hex()))

print("AD_COUNT\t%d" % n)
if verdict:
    print("VERDICT\t%s" % verdict[0])
    print("CONFIDENCE\t%s" % verdict[1])
else:
    print("VERDICT\tnone")
    print("CONFIDENCE\tnone")
    print("NOTE\tno known tracker signature in this payload")
PYEOF
}

# ── following detection ──────────────────────────────────────────────────
# A tracker that is "following" shows up across several separated scan
# windows. Rotating-MAC trackers (AirTag) change address, so the payload
# identity is used when the address is not stable.
trk_follow_check() {
    local log="$1" min_windows="${2:-3}"
    [[ -z "$log" || ! -f "$log" ]] && {
        printf 'ERROR\tusage: --follow-check SIGHTINGS_TSV [MIN_WINDOWS]\n' >&2; return 2; }
    [[ -s "$log" ]] || { printf 'ERROR\tempty sightings file\n' >&2; return 1; }

    # NOTE: iterating `for (id in seen)` over a multi-dimensional array
    # yields the SUBSEP-joined *pair*, not the first index — so identities
    # are tracked separately in `ids`, and windows are counted once each.
    printf 'IDENTITY\tWINDOWS\tSIGHTINGS\tMAX_RSSI\tSIGNATURE\tVERDICT\n'

    awk -F'\t' -v minw="$min_windows" '
        NR == 1 { next }
        $2 == "" { next }
        {
            id = $2; win = $1
            ids[id] = 1
            if (!((id, win) in seen)) { seen[id, win] = 1; wins[id]++ }
            cnt[id]++
            # RSSI is negative, so it must never be compared against the
            # uninitialised 0 (which would make every value look smaller).
            if ($4 != "") { v = $4 + 0; if (!(id in rssi) || v > rssi[id]) rssi[id] = v }
            if ($3 != "") sig[id] = $3
        }
        END {
            for (id in ids)
                printf "%s\t%d\t%d\t%s\t%s\t%s\n", id, wins[id], cnt[id],
                       (id in rssi ? rssi[id] : "-"), sig[id],
                       (wins[id] >= minw ? "FOLLOWING" : "transient")
        }
    ' "$log" | sort -t$'\t' -k2,2nr
}

# ── live scan (radio-gated) ──────────────────────────────────────────────
trk_scan() {
    local dur="${1:-15}"
    local h; h=$(trk_have_hci 2>/dev/null) || {
        printf 'ERROR\tno Bluetooth adapter (hci*) — cannot scan\n' >&2
        printf 'NOTE\tpassive decoding still works: use --decode AD_HEX\n' >&2
        return 1; }
    command -v hcitool >/dev/null 2>&1 || {
        printf 'ERROR\thcitool not installed (apt install bluez)\n' >&2; return 1; }

    mkdir -p "$MOD_LOGS"
    local log="$MOD_LOGS/lescan_$(date +%s).log"
    printf 'HCI\t%s\nDURATION\t%s\nLOG\t%s\n' "$h" "$dur" "$log"
    timeout "$dur" hcitool -i "$h" lescan --duplicates > "$log" 2>&1 || true
    local n; n=$(grep -cE '([0-9A-F]{2}:){5}' "$log" 2>/dev/null) || n=0
    printf 'DEVICES\t%s\n' "$n"
    (( n == 0 )) && printf 'NOTE\tno advertisements captured\n'
}

trk_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    local v out
    # Apple Find My: company 0x004C with type 0x12 -> high confidence.
    v="1eff4c00121900$(printf '00%.0s' {1..24})"
    out=$(trk_decode "$v")
    chk airtag-verdict "$(printf '%s\n' "$out" | awk -F'\t' '$1=="VERDICT"{print $2}')" \
        "AirTag or third-party Find My tag — Find My network"
    chk airtag-confidence "$(printf '%s\n' "$out" | awk -F'\t' '$1=="CONFIDENCE"{print $2}')" high

    # A heart-rate monitor must NOT be reported as a tracker.
    v="02030d18060948524d2d4475616c"
    chk hrm-not-a-tracker "$(trk_decode "$v" | awk -F'\t' '$1=="VERDICT"{print $2}')" none

    # Truncated AD must be reported, not silently accepted.
    trk_decode "1eff4c00" | grep -qi 'truncated' && printf 'truncation-detected\tPASS\n' \
        || { printf 'truncation-detected\tFAIL\n'; bad=$((bad+1)); }

    # Following heuristic: 4 windows >= 3 -> FOLLOWING.
    mkdir -p "$MOD_TMP"
    printf 'WINDOW\tIDENTITY\tSIGNATURE\tRSSI\nw1\tAA:BB\tapple_findmy\t-55\nw2\tAA:BB\tapple_findmy\t-60\nw3\tAA:BB\tapple_findmy\t-52\nw4\tAA:BB\tapple_findmy\t-58\n' > "$MOD_TMP/st.tsv"
    chk follow-3windows "$(trk_follow_check "$MOD_TMP/st.tsv" 3 | awk -F'\t' 'NR>1{print $6}')" FOLLOWING
    chk follow-5windows "$(trk_follow_check "$MOD_TMP/st.tsv" 5 | awk -F'\t' 'NR>1{print $6}')" transient
    # Strongest RSSI must win, not the first seen (all values are negative).
    chk follow-max-rssi "$(trk_follow_check "$MOD_TMP/st.tsv" 3 | awk -F'\t' 'NR>1{print $4}')" -52
    rm -f "$MOD_TMP/st.tsv"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

trk_info() {
    cat <<'EOF'
BLE tracker hunting

Trackers broadcast so the owner's phone (and, for AirTag, any passing
Apple device) can relay their location. Three families matter:

  Apple Find My   Manufacturer Specific Data, company 0x004C, type 0x12.
                  The tag rotates its MAC address, so following it by
                  address alone fails; the payload changes on a schedule
                  tied to the owner's key.
  Samsung SmartTag  company 0x0075, type 0x01.
  Tile            service UUID 0xFEED / 0xFEEC, or company 0x011D.

Following heuristic: a tracker is flagged FOLLOWING when it appears in
at least MIN_WINDOWS separated scan windows. Because AirTags rotate their
address, group sightings by payload when the address is unstable —
address-based grouping under-reports Apple trackers.

This module never claims a device is following you on the strength of one
sighting. Feed it several scans taken minutes apart and compare.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
trk_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)    trk_status_tsv ;;
        --signatures)    trk_signatures ;;
        --service-signatures) trk_service_signatures ;;
        --decode)        trk_decode "$@" ;;
        --follow-check)  trk_follow_check "$@" ;;
        --scan)          trk_scan "$@" ;;
        --selftest)      trk_selftest ;;
        --info)          trk_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --signatures             tracker manufacturer signatures
  --service-signatures     tracker service UUIDs
  --decode AD_HEX           decode a raw advertising payload
  --follow-check TSV [N]    following heuristic over sightings
  --scan [SECONDS]          live BLE scan (needs an hci adapter)
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
    trk_cli_main "$@"
fi

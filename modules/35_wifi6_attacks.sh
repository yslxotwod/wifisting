#!/usr/bin/env bash
# 35_wifi6_attacks — Wi-Fi 6 / 802.11ax Attacks
# HE element inventory, BSS colour collisions, TWT and spatial reuse surface.
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

MOD_TMP="$TMP_DIR/wifi6_attacks"
MOD_LOOT="$LOOT_DIR/wifi6_attacks"
MOD_LOGS="$LOG_DIR/wifi6_attacks"
MOD_CAPS="$CAPTURES_DIR/wifi6_attacks"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

W6_RESULTS="$MOD_LOOT/he_inventory.tsv"

# Split a TAB-separated line into W6_F[], preserving empty fields.
# A tab is IFS *whitespace*, so `IFS=$'\t' read -r bssid ssid ch ...` collapses
# runs of adjacent tabs and shifts every later field left: an AP with a
# hidden SSID is inventoried as "BSSID\t\t6\t25\t...", which reads as
# ssid=6 ch=25, so --plan prints the channel as the SSID and the BSS colour
# as the channel.
w6_split_tab() {
    W6_F=()
    local line="$1"
    while [[ "$line" == *$'\t'* ]]; do
        W6_F+=( "${line%%$'\t'*}" )
        line="${line#*$'\t'}"
    done
    W6_F+=( "$line" )
}

w6_have_scapy() { python3 -c 'import scapy' 2>/dev/null; }

w6_status_tsv() {
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'scapy\t%s\n'   "$(w6_have_scapy && echo 1 || echo 0)"
    local m; m=$(w6_have_mon 2>/dev/null || true)
    printf 'mon_iface\t%s\n' "${m:-none}"
    local n=0
    [[ -f "$W6_RESULTS" ]] && n=$(grep -c . "$W6_RESULTS" 2>/dev/null) || n=0
    printf 'cached_aps\t%s\n' "$n"
    printf 'color_collisions\t%s\n' \
        "$(awk -F'\t' 'NR>1 && $4!="" && $4!="none" {c[$4]++} END{n=0; for(k in c) if(c[k]>1) n++; print n+0}' \
           "$W6_RESULTS" 2>/dev/null || echo 0)"
}

w6_have_mon() {
    local i
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        local n; n=$(basename "$i")
        iw dev "$n" info 2>/dev/null | grep -q 'type monitor' && { printf '%s\n' "$n"; return 0; }
    done
    return 1
}

# ── HE element decoding ──────────────────────────────────────────────────
# HE Operation is extension element 36. Layout (IEEE 802.11ax-2021 9.4.2.249):
#   [0]    Extension ID (36)
#   [1..3] HE Operation Parameters, 24-bit little-endian:
#            B0-B2   Default PE Duration
#            B3-B5   TWT Required
#            B6-B13  TXOP Duration RTS Threshold
#            B14     VHT Operation Information Present
#            B15     Co-Hosted BSS
#            B16     ER SU Disable
#            B17     6 GHz Operation Information Present
#   [4]    BSS Color Information:
#            B0-B5   BSS Color
#            B6      Partial BSS Color
#            B7      BSS Color Disabled
#   [5..6] Basic HE-MCS And NSS Set
w6_decode_he_op() {
    local hex="$1"
    [[ -z "$hex" ]] && { printf 'ERROR\tusage: --decode-he-op HEX\n' >&2; return 2; }
    local clean; clean=$(printf '%s' "$hex" | tr -d ' :\n')
    local n=$(( ${#clean} / 2 ))
    (( n < 5 )) && {
        printf 'ERROR\tHE Operation needs at least 5 bytes, got %d\n' "$n" >&2; return 1; }

    local ext=$(( 16#${clean:0:2} ))
    printf 'EXT_ID\t%s\n' "$ext"
    (( ext != 36 )) && printf 'WARN\tnot an HE Operation element (ext id %s, expected 36)\n' "$ext"

    local b1=$(( 16#${clean:2:2} )) b2=$(( 16#${clean:4:2} )) b3=$(( 16#${clean:6:2} ))
    local params=$(( b1 | (b2 << 8) | (b3 << 16) ))
    printf 'PARAMS_RAW\t0x%06x\n' "$params"
    printf 'PE_DURATION\t%d\n'        $(( params & 0x7 ))
    printf 'TWT_REQUIRED\t%d\n'       $(( (params >> 3) & 0x7 ))
    printf 'TXOP_RTS_THRESH\t%d\n'    $(( (params >> 6) & 0xff ))
    printf 'VHT_OP_PRESENT\t%d\n'     $(( (params >> 14) & 1 ))
    printf 'CO_HOSTED_BSS\t%d\n'      $(( (params >> 15) & 1 ))
    printf 'ER_SU_DISABLE\t%d\n'      $(( (params >> 16) & 1 ))
    printf 'HE_6GHZ_PRESENT\t%d\n'    $(( (params >> 17) & 1 ))

    local ci=$(( 16#${clean:8:2} ))
    printf 'COLOR_INFO_RAW\t0x%02x\n' "$ci"
    printf 'BSS_COLOR\t%d\n'          $(( ci & 0x3f ))
    printf 'PARTIAL_COLOR\t%d\n'      $(( (ci >> 6) & 1 ))
    printf 'COLOR_DISABLED\t%d\n'     $(( (ci >> 7) & 1 ))

    if (( n >= 7 )); then
        printf 'BASIC_HE_MCS_NSS\t0x%04x\n' $(( 16#${clean:10:2} | (16#${clean:12:2} << 8) ))
    fi
}

# ── capture analysis ─────────────────────────────────────────────────────
w6_analyze() {
    local pcap="$1"
    [[ -z "$pcap" || ! -f "$pcap" ]] && {
        printf 'ERROR\tusage: --analyze PCAP\n' >&2; return 2; }
    w6_have_scapy || {
        printf 'ERROR\tpython3-scapy required (apt install python3-scapy)\n' >&2; return 1; }

    mkdir -p "$(dirname "$W6_RESULTS")"
    W6_PCAP="$pcap" W6_OUT="$W6_RESULTS" python3 - <<'PYEOF'
import os, sys
from scapy.all import PcapReader, Dot11, Dot11Beacon, Dot11Elt

EXT = {35: "he_caps", 36: "he_op", 38: "spatial_reuse",
       39: "mu_edca", 55: "eht_op", 59: "he_6ghz", 108: "eht_caps"}
TWT = {216: "twt_individual", 217: "twt_broadcast"}

aps = {}
try:
    with PcapReader(os.environ["W6_PCAP"]) as pr:
        for i, p in enumerate(pr):
            if i > 120000:
                break
            if not p.haslayer(Dot11Beacon):
                continue
            bssid = (p[Dot11].addr3 or "").upper()
            if not bssid:
                continue
            rec = aps.setdefault(bssid, {"ssid": "", "ext": {}, "twt": set(), "ch": ""})
            elt = p.getlayer(Dot11Elt)
            while elt is not None:
                info = bytes(elt.info or b"")
                if elt.ID == 0 and not rec["ssid"]:
                    rec["ssid"] = info.decode("utf-8", "replace").strip("\x00")
                elif elt.ID == 3 and not rec["ch"] and info:
                    rec["ch"] = str(info[0])
                elif elt.ID == 255 and info:
                    name = EXT.get(info[0])
                    if name and name not in rec["ext"]:
                        rec["ext"][name] = info.hex()
                elif elt.ID in TWT:
                    rec["twt"].add(TWT[elt.ID])
                nxt = elt.payload
                elt = (nxt.getlayer(Dot11Elt)
                       if (nxt is not None and hasattr(nxt, "getlayer")) else None)
except Exception as e:
    print("ERROR\t%s" % e, file=sys.stderr)
    sys.exit(1)

if not aps:
    print("EMPTY\t1")
    print("NOTE\tno beacons found in this capture")
    sys.exit(1)

def he_op_fields(hexs):
    """Return (color, disabled, twt_req, six_ghz, er_su) from an HE Operation IE."""
    b = bytes.fromhex(hexs)
    if len(b) < 5 or b[0] != 36:
        return None
    params = b[1] | (b[2] << 8) | (b[3] << 16)
    ci = b[4]
    return (ci & 0x3F, (ci >> 7) & 1, (params >> 3) & 0x7,
            (params >> 17) & 1, (params >> 16) & 1, (ci >> 6) & 1)

with open(os.environ["W6_OUT"], "w") as fh:
    fh.write("BSSID\tSSID\tCHANNEL\tBSS_COLOR\tCOLOR_DISABLED\tPARTIAL_COLOR"
             "\tTWT_REQUIRED\tSIX_GHZ\tER_SU_DISABLE\tHE_ELEMENTS\n")
    for bssid in sorted(aps):
        r = aps[bssid]
        color = disabled = partial = twt_req = six = er = "none"
        if "he_op" in r["ext"]:
            d = he_op_fields(r["ext"]["he_op"])
            if d:
                color, disabled, twt_req, six, er, partial = [str(x) for x in d]
        elems = ",".join(sorted(r["ext"])) or "none"
        if r["twt"]:
            elems += ("+" if elems != "none" else "") + ",".join(sorted(r["twt"]))
        fh.write("\t".join([bssid, r["ssid"], r["ch"], color, disabled, partial,
                            twt_req, six, er, elems]) + "\n")

he_aps = sum(1 for b in aps.values() if "he_op" in b["ext"] or "he_caps" in b["ext"])
print("APPS\t%d" % len(aps))
print("HE_APS\t%d" % he_aps)
print("RESULTS\t%s" % os.environ["W6_OUT"])
PYEOF
    local rc=$?
    (( rc != 0 )) && return $rc
    w6_colors
}

# ── BSS color map + collision detection ──────────────────────────────────
# Two APs sharing a BSS color while on the same channel is a colour
# collision: spatial-reuse logic then treats the other BSS as its own,
# which is the documented 802.11ax failure mode.
w6_colors() {
    [[ -s "$W6_RESULTS" ]] || {
        printf 'ERROR\tno inventory yet — run --analyze PCAP first\n' >&2; return 1; }

    printf 'COLOR\tCOUNT\tCHANNELS\tBSSIDS\n'
    awk -F'\t' 'NR>1 && $4!="none" && $4!="" {
        c[$4]++; if (idx[$4,$3]++ == 0) ch[$4] = (ch[$4] == "" ? $3 : ch[$4] "," $3);
        b[$4] = (b[$4] == "" ? $1 : b[$4] "," $1)
    } END {
        for (k in c) printf "%s\t%d\t%s\t%s\n", k, c[k], ch[k], b[k]
    }' "$W6_RESULTS" | sort -n

    local collisions
    collisions=$(awk -F'\t' 'NR>1 && $4!="none" && $4!="" {c[$4]++} END {
        n=0; for (k in c) if (c[k]>1) n++; print n+0 }' "$W6_RESULTS")
    printf 'COLLISIONS\t%s\n' "$collisions"
    local disabled
    disabled=$(awk -F'\t' 'NR>1 && $5=="1" {c++} END{print c+0}' "$W6_RESULTS")
    printf 'COLOR_DISABLED_APS\t%s\n' "$disabled"
    local six
    six=$(awk -F'\t' 'NR>1 && $8=="1" {c++} END{print c+0}' "$W6_RESULTS")
    printf 'SIX_GHZ_APS\t%s\n' "$six"
}

w6_list_tsv() {
    [[ -s "$W6_RESULTS" ]] || {
        printf 'ERROR\tno inventory yet — run --analyze PCAP first\n' >&2; return 1; }
    cat "$W6_RESULTS"
}

# ── per-AP assessment ────────────────────────────────────────────────────
w6_plan() {
    local want="$1"
    [[ -z "$want" ]] && { printf 'ERROR\tusage: --plan BSSID\n' >&2; return 2; }
    [[ -s "$W6_RESULTS" ]] || {
        printf 'ERROR\tno inventory yet — run --analyze PCAP first\n' >&2; return 1; }
    local want_l; want_l=$(printf '%s' "$want" | tr 'A-F' 'a-f')
    local line
    line=$(awk -F'\t' -v w="$want_l" 'NR>1 && tolower($1)==w {print; exit}' "$W6_RESULTS")
    [[ -z "$line" ]] && { printf 'ERROR\t%s not in the inventory\n' "$want" >&2; return 1; }

    local bssid ssid ch color disabled partial twt six er elems
    # The stored row carries the empty-field hazard too: a hidden-SSID AP is
    # inventoried as "BSSID\t\t6\t25\t...", which a collapsing read shifts.
    w6_split_tab "$line"
    bssid="${W6_F[0]:-}"; ssid="${W6_F[1]:-}"; ch="${W6_F[2]:-}"
    color="${W6_F[3]:-}"; disabled="${W6_F[4]:-}"; partial="${W6_F[5]:-}"
    twt="${W6_F[6]:-}"; six="${W6_F[7]:-}"; er="${W6_F[8]:-}"
    elems="${W6_F[9]:-}"
    printf 'BSSID\t%s\nSSID\t%s\nCHANNEL\t%s\n' "$bssid" "$ssid" "$ch"
    printf 'HE_ELEMENTS\t%s\n' "$elems"
    printf 'BSS_COLOR\t%s\nCOLOR_DISABLED\t%s\nPARTIAL_COLOR\t%s\n' "$color" "$disabled" "$partial"
    printf 'TWT_REQUIRED\t%s\nSIX_GHZ\t%s\nER_SU_DISABLE\t%s\n' "$twt" "$six" "$er"

    if [[ "$elems" == "none" ]]; then
        printf 'VERDICT\tNOT_AX\n'
        printf 'NOTE\tNo HE/EHT elements: this is a pre-802.11ax AP, so the\n'
        printf 'NOTE\tWi-Fi 6 attack surface below does not apply to it.\n'
        return 0
    fi
    printf 'VERDICT\tAX\n'

    printf 'SURFACE\tbss_color_collision\t%s\n' \
        "$([[ "$color" != "none" && "$disabled" != "1" ]] && echo 1 || echo 0)"
    printf 'SURFACE\ttwt_dos\t%s\n'   "$([[ "$twt" != "0" && "$twt" != "none" ]] && echo 1 || echo 0)"
    printf 'SURFACE\tspatial_reuse\t%s\n' \
        "$(printf '%s' "$elems" | grep -q spatial_reuse && echo 1 || echo 0)"

    [[ "$disabled" == "1" ]] && printf 'NOTE\tBSS colour is disabled on this AP, so colour-based\nNOTE\tspatial reuse is inactive and collisions are moot.\n'
    [[ "$partial" == "1" ]] && printf 'NOTE\tPartial BSS colour is set: clients must match only the\nNOTE\tupper colour bits, which widens the collision window.\n'
    [[ "$six" == "1" ]] && printf 'NOTE\tAdvertises 6 GHz operation information (Wi-Fi 6E).\n'
    [[ "$twt" == "0" || "$twt" == "none" ]] && printf 'NOTE\tTWT is not required, so clients may ignore TWT schedules.\n'
    return 0
}

# ── known-answer self-test ───────────────────────────────────────────────
# The vector is an HE Operation element captured from a real 802.11ax AP,
# so this pins the decoder to observed bytes rather than to my reading of
# the spec.
w6_selftest() {
    local vec="2404000119fcff"   # ext=36, params=0x010004, colour info=0x19
    local bad=0

    local out; out=$(w6_decode_he_op "$vec")
    check() {
        local k="$1" want="$2" got
        got=$(printf '%s\n' "$out" | awk -F'\t' -v k="$k" '$1==k{print $2}')
        if [[ "$got" == "$want" ]]; then
            printf '%s\tPASS\n' "$k"
        else
            printf '%s\tFAIL want=%s got=%s\n' "$k" "$want" "$got"; bad=$((bad+1))
        fi
    }
    check EXT_ID 36
    check BSS_COLOR 25
    check PARTIAL_COLOR 0
    check COLOR_DISABLED 0
    check TWT_REQUIRED 0
    check ER_SU_DISABLE 1
    check HE_6GHZ_PRESENT 0
    check PE_DURATION 4

    # A colour-disabled AP must report disabled=1 and colour bits still read.
    local out2; out2=$(w6_decode_he_op "24040001d9fcff")
    local d2; d2=$(printf '%s\n' "$out2" | awk -F'\t' '$1=="COLOR_DISABLED"{print $2}')
    local c2; c2=$(printf '%s\n' "$out2" | awk -F'\t' '$1=="BSS_COLOR"{print $2}')
    if [[ "$d2" == "1" && "$c2" == "25" ]]; then
        printf 'color-disabled-bit\tPASS\n'
    else
        printf 'color-disabled-bit\tFAIL disabled=%s color=%s\n' "$d2" "$c2"; bad=$((bad+1))
    fi

    # A hidden-SSID row must keep its column positions. The empty SSID is the
    # middle field, so the collapsing `IFS=$'\t' read` printed the channel as
    # the SSID, the BSS colour as the channel and the HE element list in the
    # ER_SU_DISABLE column.
    w6_split_tab $'aa:bb:cc:dd:ee:02\t\t6\t25\t0\t0\t0\t0\t1\the_op'
    if [[ "${#W6_F[@]}" == 10 && "${W6_F[1]:-}" == "" \
          && "${W6_F[2]:-}" == "6" && "${W6_F[3]:-}" == "25" \
          && "${W6_F[9]:-}" == "he_op" ]]; then
        printf 'split-hidden-fields\tPASS\n'
    else
        printf 'split-hidden-fields\tFAIL n=%s ssid=[%s] ch=%s color=%s elems=%s\n' \
            "${#W6_F[@]}" "${W6_F[1]:-}" "${W6_F[2]:-}" "${W6_F[3]:-}" "${W6_F[9]:-}"
        bad=$((bad+1))
    fi

    # ... and --plan must read the *stored* hidden-SSID row back the same way.
    # W6_RESULTS is redirected to scratch so the live loot tree is untouched.
    local save_results="$W6_RESULTS" tres
    tres=$(mktemp)
    W6_RESULTS="$tres"
    printf 'BSSID\tSSID\tCHANNEL\tBSS_COLOR\tCOLOR_DISABLED\tPARTIAL_COLOR\tTWT_REQUIRED\tSIX_GHZ\tER_SU_DISABLE\tHE_ELEMENTS\n' > "$W6_RESULTS"
    printf 'AA:BB:CC:DD:EE:02\t\t6\t25\t0\t0\t0\t0\t1\the_op\n' >> "$W6_RESULTS"
    out=$(w6_plan aa:bb:cc:dd:ee:02 2>&1)
    W6_RESULTS="$save_results"
    rm -f "$tres"
    check SSID ""
    check CHANNEL 6
    check HE_ELEMENTS he_op
    check BSS_COLOR 25
    check ER_SU_DISABLE 1
    check SIX_GHZ 0

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

w6_info() {
    cat <<'EOF'
Wi-Fi 6 (802.11ax) attack surface

BSS colour collision
  Each AP picks a 6-bit BSS colour. Spatial-reuse logic lets a device
  ignore a signal it believes belongs to its own BSS. Two APs on the same
  channel using the same colour therefore mis-classify each other, which
  degrades throughput and can be induced deliberately by standing up an
  AP that clones a neighbour's colour. Colour must be enabled (bit 7 of
  BSS Colour Information clear) for this to apply.

TWT (Target Wake Time)
  A TWT-required AP expects clients to honour negotiated wake schedules.
  Forged or malformed TWT setup frames can pin a client to a schedule
  that never wakes, which is a denial-of-service against that client.

Spatial reuse / OBSS-PD
  The Spatial Reuse Parameter Set element advertises SRG and non-SRG
  OBSS-PD thresholds. Loosening these makes an AP more willing to
  transmit over neighbours.

6 GHz (Wi-Fi 6E)
  Signalled by the HE 6 GHz Band Capabilities element and the 6 GHz
  Operation Information field in HE Operation.

Element IDs used here:
  extension 35  HE Capabilities
  extension 36  HE Operation
  extension 38  Spatial Reuse Parameter Set
  extension 39  MU EDCA Parameter Set
  extension 59  HE 6 GHz Band Capabilities
  extension 108 EHT (802.11be) Capabilities
  element   216 Individual TWT
  element   217 Broadcast TWT
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
w6_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     w6_status_tsv ;;
        --analyze)        w6_analyze "$@" ;;
        --list-tsv)       w6_list_tsv ;;
        --colors)         w6_colors ;;
        --plan)           w6_plan "$@" ;;
        --decode-he-op)   w6_decode_he_op "$@" ;;
        --selftest)       w6_selftest ;;
        --info)           w6_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --analyze PCAP          HE/EHT inventory from a capture (scapy)
  --list-tsv              cached per-AP inventory
  --colors                BSS colour map + collision detection
  --plan BSSID            attack surface for one AP
  --decode-he-op HEX      decode a raw HE Operation element
  --selftest              known-answer test against a real ax AP
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
    w6_cli_main "$@"
fi

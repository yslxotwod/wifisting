#!/usr/bin/env bash
# 22_wifi_direct.sh — Wi-Fi Direct / P2P enumeration and research
# ── self-locate WIFISTING_ROOT ──
# When launched via pkexec, HOME is /root and any $HOME-relative path
# would land in the wrong place. Resolve WIFISTING_ROOT from this
# script's own path so state / loot / captures always end up in the
# project tree regardless of who runs us.
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
    unset _sl_src _sl_dir _sl_tgt
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

: "${WIFISTING_HOME:=$WIFISTING_ROOT}"

: "${TMP_DIR:=/tmp/wifisting}"
: "${LOOT_DIR:=$HOME/wifisting/loot}"
: "${LOGS_DIR:=$HOME/wifisting/logs}"
: "${CAPTURES_DIR:=$HOME/wifisting/captures}"
: "${WIFISTING_HOME:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" "$CAPTURES_DIR" 2>/dev/null

P2P_DIR="$TMP_DIR/wifi_direct"
P2P_LOOT="$LOOT_DIR/wifi_direct"
P2P_DEVICES="$P2P_DIR/devices.tsv"
P2P_SERVICES="$P2P_DIR/services.tsv"
P2P_CAPTURE_PID="$P2P_DIR/capture.pid"
P2P_CAPTURE_LOG="$P2P_DIR/capture.log"

mkdir -p "$P2P_DIR" "$P2P_LOOT"
touch "$P2P_DEVICES" "$P2P_SERVICES" 2>/dev/null

p2p_get_mon() {
    if [[ -f "$TMP_DIR/mon_iface" ]]; then
        cat "$TMP_DIR/mon_iface"
        return 0
    fi
    iw dev 2>/dev/null | awk '
        /Interface/ { iface=$2 }
        /type monitor/ { print iface; exit }
    '
}

p2p_get_managed() {
    local name mode
    for name in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
        mode=$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2}')
        [[ "$mode" == "managed" ]] && { echo "$name"; return 0; }
    done
    echo ""
}

# ── FIXED: wpa_cli path autodetection ──
# Modern systemd distros use /run/wpa_supplicant/<iface>. Older use
# /var/run/wpa_supplicant/<iface>. Some setups use neither (D-Bus).
p2p_wpa_cli() {
    local iface="$1"
    shift

    # Try D-Bus first (no -p flag)
    if wpa_cli -i "$iface" "$@" 2>/dev/null | grep -qv '^$'; then
        return 0
    fi

    # Try common socket paths
    for p in /run/wpa_supplicant /var/run/wpa_supplicant /etc/wpa_supplicant; do
        if [[ -S "$p/$iface" ]]; then
            wpa_cli -p "$p" -i "$iface" "$@"
            return $?
        fi
    done

    # Last resort: default behavior
    wpa_cli -i "$iface" "$@"
}

p2p_status_tsv() {
    local mon managed
    mon=$(p2p_get_mon)
    managed=$(p2p_get_managed)

    local wpa_supp="no"
    command -v wpa_cli >/dev/null 2>&1 && wpa_supp="yes"

    local running=0 pid=""
    if [[ -f "$P2P_CAPTURE_PID" ]]; then
        pid=$(cat "$P2P_CAPTURE_PID")
        kill -0 "$pid" 2>/dev/null && running=1
    fi

    local devices=0
    [[ -f "$P2P_DEVICES" ]] && devices=$(wc -l < "$P2P_DEVICES")

    printf 'mon_iface\t%s\n'   "$mon"
    printf 'managed\t%s\n'     "$managed"
    printf 'wpa_cli\t%s\n'     "$wpa_supp"
    printf 'capture\t%s\n'     "$running"
    printf 'capture_pid\t%s\n' "$pid"
    printf 'devices\t%s\n'     "$devices"
    printf 'loot\t%s\n'        "$P2P_LOOT"
    printf 'capture_log\t%s\n' "$P2P_CAPTURE_LOG"
}

# ── passive P2P scan with device name + config method + WPS-PBC flag ──
p2p_scan_passive() {
    local dur="${1:-60}"
    local iface
    iface=$(p2p_get_mon)
    [[ -z "$iface" ]] && { printf 'ERROR\tno monitor interface\n' >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\ttshark required\n' >&2; return 1
    }

    local tmp_pcap="$P2P_DIR/p2p_$(date +%s).pcap"
    info "sniffing P2P frames on $iface for ${dur}s → $tmp_pcap"

    timeout "$dur" tcpdump -i "$iface" -w "$tmp_pcap" \
        'wlan type mgt subtype action or wlan type mgt subtype probe-resp' \
        >/dev/null 2>&1

    [[ ! -s "$tmp_pcap" ]] && {
        printf 'ERROR\tcapture empty (no P2P frames?)\n' >&2
        return 1
    }

    # P2P uses OUI 50:6f:9a (Wi-Fi Alliance). Action frames carry P2P IE.
    # Extract: SA, channel, device name (attr 0x11), primary device type (0x0c),
    # config methods (0x0d), WSC selected registrar flag.
    tshark -r "$tmp_pcap" \
        -Y 'wlan.fc.type_subtype == 0x0d' \
        -T fields \
        -e wlan.sa \
        -e wlan_radio.channel \
        -e wps.device_name \
        -e wps.manufacturer \
        -e wps.model_name \
        -e wps.config_methods \
        2>/dev/null | sort -u | awk -F'\t' 'length($1)==17 { print }' \
        > "$P2P_DEVICES"

    local count
    count=$(wc -l < "$P2P_DEVICES")
    printf 'PCAP\t%s\nDEVICES_FILE\t%s\nCOUNT\t%s\n' \
        "$tmp_pcap" "$P2P_DEVICES" "$count"
}

p2p_list_devices_tsv() {
    [[ -s "$P2P_DEVICES" ]] && cat "$P2P_DEVICES"
    return 0
}

# ── wpa_supplicant P2P_FIND (with path fix) ──
p2p_wpa_p2p_find() {
    local dur="${1:-20}"
    local iface
    iface=$(p2p_get_managed)
    [[ -z "$iface" ]] && { printf 'ERROR\tno managed iface\n' >&2; return 1; }
    command -v wpa_cli >/dev/null 2>&1 || {
        printf 'ERROR\twpa_cli required\n' >&2; return 1
    }

    info "running wpa_cli P2P_FIND on $iface for ${dur}s"
    p2p_wpa_cli "$iface" p2p_find "$dur" 2>&1 | tail -5
    sleep 1

    p2p_wpa_cli "$iface" p2p_peers 2>&1 | while read -r mac; do
        [[ -z "$mac" || "$mac" == "OK" ]] && continue
        [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue

        local info_out name dev
        info_out=$(p2p_wpa_cli "$iface" p2p_peer "$mac" 2>/dev/null)
        name=$(echo "$info_out" | awk -F'=' '/device_name=/{print $2; exit}')
        dev=$(echo "$info_out" | awk -F'=' '/p2p_dev_addr=/{print $2; exit}')

        printf '%s\t%s\t%s\n' "$mac" "${name:-?}" "${dev:-?}"
    done | sort -u | tee -a "$P2P_DEVICES"
}

# ── continuous management-frame pcap ──
p2p_start_capture() {
    local iface
    iface=$(p2p_get_mon)
    [[ -z "$iface" ]] && { printf 'ERROR\tno monitor interface\n' >&2; return 1; }

    if [[ -f "$P2P_CAPTURE_PID" ]] && kill -0 "$(cat "$P2P_CAPTURE_PID")" 2>/dev/null; then
        printf 'ERROR\tcapture already running\n' >&2; return 1
    fi

    local out="$P2P_LOOT/p2p_$(date +%s).pcap"
    ( tcpdump -i "$iface" -w "$out" -U \
        'wlan type mgt' > "$P2P_CAPTURE_LOG" 2>&1 &
      echo $! > "$P2P_CAPTURE_PID" )
    sleep 1

    if kill -0 "$(cat "$P2P_CAPTURE_PID")" 2>/dev/null; then
        printf 'STARTED\t%s\nPCAP\t%s\n' "$(cat "$P2P_CAPTURE_PID")" "$out"
    else
        printf 'ERROR\tcapture failed\n' >&2
        return 1
    fi
}

p2p_stop_capture() {
    local killed=0 pid=""
    [[ -f "$P2P_CAPTURE_PID" ]] && pid=$(cat "$P2P_CAPTURE_PID")

    if [[ -n "$pid" ]]; then
        pkill -P "$pid" 2>/dev/null
        stop_kill_pid "$pid" && killed=1
    fi

    # Sweep any stray capture for this module, and verify that too.
    local sp
    for sp in $(pgrep -f 'tcpdump.*wlan type mgt' 2>/dev/null); do
        [[ "$sp" == "$$" || "$sp" == "$PPID" ]] && continue
        stop_kill_pid "$sp" && killed=1
    done

    if (( killed == 1 )); then
        rm -f "$P2P_CAPTURE_PID"
        printf 'STOPPED\n'
        return 0
    fi
    if [[ -n "$pid" ]]; then
        printf 'ERROR\tcapture pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
    return 0
}

# ── P2P action frame analyzer ──
# Parse a captured pcap and break down by action subtype, count
# GO Negotiation Req/Resp/Conf and Provision Discovery pairs.
p2p_analyze_pcap() {
    local pcap="$1"
    [[ -z "$pcap" || ! -f "$pcap" ]] && {
        pcap=$(ls -t "$P2P_LOOT"/p2p_*.pcap 2>/dev/null | head -1)
    }
    [[ -z "$pcap" || ! -f "$pcap" ]] && {
        printf 'ERROR\tno pcap\n' >&2; return 1
    }

    command -v tshark >/dev/null || { printf 'ERROR\tno tshark\n' >&2; return 1; }

    local report="${pcap%.pcap}_report.txt"
    {
        echo "=== Wi-Fi Direct / P2P action frame report ==="
        echo "pcap: $pcap"
        echo "date: $(date -Is)"
        echo

        echo "── action subtypes present ──"
        # P2P action subtypes: 0=GO Neg Req, 1=GO Neg Resp, 2=GO Neg Conf,
        # 3=Invitation Req, 4=Invitation Resp, 7=Prov Disc Req, 8=Prov Disc Resp
        tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0d' \
            -T fields -e wlan.sa -e wlan.da -e wlan.public_action.subtype \
            2>/dev/null | \
            awk -F'\t' 'NF==3 {subtypes[$3]++; last[$3]=$1" -> "$2}
                        END {
                            for (s in subtypes)
                                printf "  subtype %s: %d frames (last: %s)\n",
                                       s, subtypes[s], last[s]
                        }' | sort
        echo

        echo "── device names seen ──"
        tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0d' \
            -T fields -e wlan.sa -e wps.device_name 2>/dev/null | \
            awk -F'\t' 'length($1)==17 && $2!="" {print "  " $1 "  " $2}' | sort -u
        echo

        echo "── WPS push-button (PBC) capability ──"
        # Config method 0x0080 is PBC. Anything advertising 0x0080 has PBC.
        tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0d' \
            -T fields -e wlan.sa -e wps.config_methods 2>/dev/null | \
            awk -F'\t' 'length($1)==17 && $2!="" {
                if ($2 ~ /0080|0x0080/) print "  " $1 "  PBC advertised"
                else print "  " $1 "  (no PBC)"
            }' | sort -u
        echo

        echo "── channels seen ──"
        tshark -r "$pcap" -T fields -e wlan_radio.channel 2>/dev/null | \
            sort -n | uniq -c | awk '{printf "  ch %s: %s frames\n", $2, $1}'
    } | tee "$report"

    printf 'REPORT\t%s\n' "$report"
}

# ── GO negotiation frame replay (research only) ──
p2p_spoof_go_neg() {
    local iface="$1" target="$2" ssid="${3:-wifisting-p2p}"
    [[ -z "$iface" || -z "$target" ]] && {
        printf 'usage: --spoof-go-neg IFACE TARGET_MAC [SSID]\n' >&2
        return 2
    }

    command -v python3 >/dev/null || { printf 'ERROR\tno python3\n' >&2; return 1; }
    python3 -c 'import scapy' 2>/dev/null || {
        printf 'ERROR\tpython3-scapy required\n' >&2; return 1
    }

    info "spoofing GO Negotiation Request from $target"
    warn "this is research-grade — most modern devices reject unexpected GO Neg frames"

    python3 - "$iface" "$target" "$ssid" <<'PYEOF'
import sys
from scapy.all import (
    RadioTap, Dot11, Dot11Action, Dot11Elt, Raw, sendp, RandMAC
)

iface, target, ssid = sys.argv[1], sys.argv[2], sys.argv[3]

# P2P IE = Vendor Specific IE with OUI 50:6f:9a and type 0x09
# GO Neg Request attribute (0x00) contains config methods.
# This is a minimal frame; real P2P stacks expect the full attribute set.
p2p_ie = bytes.fromhex(
    "dd1a00506f9a09"           # Vendor IE header, P2P OUI, type 0x09
    "0a00506f9a090102"         # Device Info attribute
    "0400"                     # minimal placeholder
)
device_info = bytes.fromhex("0d00506f9a0900" + "00" * 6 + "00" * 8)

# Compose the P2P attribute stream
attrs = device_info + bytes.fromhex("0800506f9a090301")  # GO Intent

# Dot11 action frame: category 0x7f (vendor specific)
dot11 = Dot11(type=0, subtype=13, addr1=target, addr2=str(RandMAC()), addr3=target)
action = Dot11Action(category=0x7f)
frame = RadioTap() / dot11 / action / \
    Dot11Elt(ID=221, info=bytes.fromhex("00506f9a09") + attrs)

print(f"[+] sending 3 GO Neg Request frames to {target}", file=sys.stderr)
sendp(frame, iface=iface, count=3, inter=0.5, verbose=False)
print("SENT\t3", file=sys.stderr)
PYEOF
}

# ── info ──
p2p_info() {
    cat <<'INFO'
Wi-Fi Direct (P2P) module:

  Passive scan:   capture P2P action frames on the monitor interface,
                  extract device names + channels via tshark.
  Active find:    use wpa_supplicant's P2P_FIND on a managed iface.
  Analyzer:       break a pcap into action-subtype counts + WPS-PBC flag.
  GO Neg spoof:   send a forged GO Negotiation Request (research).

Common attack surface on P2P:
  • P2P provision discovery spoofing (send forged PD Req)
  • GO Negotiation Req/Resp replay + MITM
  • WPS push-button replay (many P2P devices advertise PBC in the IEs)
  • Device Name exfiltration via probe responses
  • Persistent group takeover (older Android / IoT firmware)

For active attacks you want:
  • a monitor-capable adapter for injection
  • two adapters if you also want to play the GO role
  • scapy for crafting the P2P action frames

Wpa_supplicant note:
  On systemd distros the control socket lives at
  /run/wpa_supplicant/<iface>. Older setups use /var/run. This module
  probes both paths and falls back to D-Bus.

Socket path missing?
  Check: ls /run/wpa_supplicant/
  Restart: sudo systemctl restart wpa_supplicant
INFO
}

# ── dispatch ──
# ── verified stop ──
# Kill one pid with escalating signals; returns 0 ONLY once it is gone.
# Every stop path below uses this so a failed kill is reported instead of
# printing STOPPED and deleting the pidfile that was the only handle to it.
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

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no radio, no root, no network. tcpdump/tshark/wpa_cli are
# never invoked — the frame-parsing paths need a capture, so they are not
# exercised here; everything that can be checked without one is.
# All file paths are shadowed into a scratch dir under $P2P_DIR.
p2p_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local st="$P2P_DIR/selftest-$$"
    rm -rf "$st"; mkdir -p "$st/loot"
    local P2P_DEVICES="$st/devices.tsv" P2P_SERVICES="$st/services.tsv" \
          P2P_CAPTURE_PID="$st/capture.pid" P2P_CAPTURE_LOG="$st/capture.log" \
          P2P_LOOT="$st/loot"

    # ── GO Negotiation replay: required arguments ──
    p2p_spoof_go_neg "" "AA:BB:CC:DD:EE:FF" >/dev/null 2>&1
    chk spoof-missing-iface-rc "$?" "2"
    p2p_spoof_go_neg "wlan9" "" >/dev/null 2>&1
    chk spoof-missing-target-rc "$?" "2"

    # ── analyzer: no pcap anywhere must fail loudly, not print a report ──
    local out
    out=$(p2p_analyze_pcap "$st/nope.pcap" 2>&1)
    chk analyze-missing-rc "$?" "1"
    chk analyze-missing-msg "$out" $'ERROR\tno pcap'
    out=$(p2p_analyze_pcap "" 2>&1)
    chk analyze-no-arg-rc "$?" "1"

    # ── device list passthrough ──
    printf '%s\n' \
        $'AA:BB:CC:DD:EE:01\t6\tPhone\t?' \
        $'AA:BB:CC:DD:EE:02\t11\tTV\t?' > "$P2P_DEVICES"
    chk list-devices "$(p2p_list_devices_tsv)" \
        "$(printf '%s\n' $'AA:BB:CC:DD:EE:01\t6\tPhone\t?' $'AA:BB:CC:DD:EE:02\t11\tTV\t?')"
    : > "$P2P_DEVICES"
    chk list-devices-empty "$(p2p_list_devices_tsv)" ""
    p2p_list_devices_tsv >/dev/null 2>&1
    chk list-devices-empty-rc "$?" "0"

    # ── status TSV: counts from the files, pid only when the process lives ──
    printf '%s\n' a b c > "$P2P_DEVICES"
    rm -f "$P2P_CAPTURE_PID"
    local stsv; stsv=$(p2p_status_tsv)
    fld() { printf '%s\n' "$stsv" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }
    chk status-devices      "$(fld devices)"      "3"
    chk status-capture-idle "$(fld capture)"      "0"
    chk status-pid-empty    "$(fld capture_pid)"  ""
    chk status-loot         "$(fld loot)"         "$P2P_LOOT"
    chk status-capture-log  "$(fld capture_log)"  "$P2P_CAPTURE_LOG"
    sleep 30 &
    local sp=$!
    echo "$sp" > "$P2P_CAPTURE_PID"
    stsv=$(p2p_status_tsv)
    chk status-capture-live "$(fld capture)"     "1"
    chk status-pid-live     "$(fld capture_pid)" "$sp"
    kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null

    # ── passive scan with no monitor interface must refuse, not capture ──
    # p2p_get_mon is stubbed here on purpose: the real one shells out to iw
    # and this machine does have a monitor iface, which would start a real
    # tcpdump. The stub only simulates "no adapter".
    p2p_get_mon() { :; }
    out=$(p2p_scan_passive 1 2>&1)
    chk scan-passive-no-iface-rc "$?" "1"
    chk scan-passive-no-iface-msg "$out" $'ERROR\tno monitor interface'

    rm -rf "$st"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

p2p_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      p2p_status_tsv ;;
        --passive-scan)    p2p_scan_passive "$@" ;;
        --list-devices-tsv) p2p_list_devices_tsv ;;
        --wpa-find)        p2p_wpa_p2p_find "$@" ;;
        --capture-start)   p2p_start_capture ;;
        --capture-stop)    p2p_stop_capture ;;
        --analyze)         p2p_analyze_pcap "$@" ;;
        --spoof-go-neg)    p2p_spoof_go_neg "$@" ;;
        --info)            p2p_info ;;
        --selftest)        p2p_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --passive-scan [DURATION]
  --list-devices-tsv
  --wpa-find [DURATION]
  --capture-start
  --capture-stop
  --analyze [PCAP]
  --spoof-go-neg IFACE TARGET_MAC [SSID]
  --info
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
    p2p_cli_main "$@"
fi

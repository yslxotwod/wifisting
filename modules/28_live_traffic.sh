#!/usr/bin/env bash
# 28_live_traffic.sh — live 802.11 frame stream
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="${TMP_DIR:-/tmp/wifisting}"
mkdir -p "$TMP_DIR/live_traffic" 2>/dev/null || true

MON_STATE_FILE="$TMP_DIR/mon_iface"
PID_FILE="$TMP_DIR/live_traffic/stream.pid"
FILTER_FILE="$TMP_DIR/live_traffic/filter.txt"
DECRYPT_FILE="$TMP_DIR/live_traffic/psk.txt"

# ── verified stop ──
# Escalating signals; returns 0 ONLY once the pid is actually gone. Signals
# the process group first so forked children die with the leader. Stops that
# print STOPPED and delete the pidfile without this can strand a capture with
# no remaining handle to it, making the stop button useless.
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
# Kill everything matching a pgrep -f pattern, never this shell or its parent.
stop_sweep() {
    local pat="$1" sp rs=0 any=0
    # Exclude this process AND its whole ancestor chain. Excluding only $$ and
    # $PPID is not enough: when invoked via `timeout` or pkexec the caller's
    # shell is further up, and a cmdline substring match would kill it — a
    # pattern like "mitm6" matches the very command line running this stop.
    local -A _skip=()
    sp=$$
    while [[ -n "$sp" && "$sp" != "0" && "$sp" != "1" ]]; do
        _skip[$sp]=1
        sp=$(ps -o ppid= -p "$sp" 2>/dev/null | tr -d ' ')
        [[ -z "$sp" ]] && break
    done
    for sp in $(pgrep -f "$pat" 2>/dev/null); do
        [[ -n "${_skip[$sp]:-}" ]] && continue
        any=1
        stop_kill_pid "$sp" || rs=1
    done
    (( any )) && return $rs
    return 0
}

lt_get_iface() {
    local iface=""
    if [ -s "$MON_STATE_FILE" ]; then
        iface="$(<"$MON_STATE_FILE")"
    fi
    if [ -z "$iface" ]; then
        iface="$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')"
    fi
    printf '%s' "$iface"
}

lt_iface_type() {
    local iface="$1"
    [ -z "$iface" ] && { echo "unknown"; return; }
    local t
    t="$(iw dev "$iface" info 2>/dev/null | awk '/type/{print $2; exit}')"
    [ -z "$t" ] && t="unknown"
    printf '%s' "$t"
}

lt_iface_channel() {
    local iface="$1"
    [ -z "$iface" ] && return
    iw dev "$iface" info 2>/dev/null | awk '/channel/{print $2; exit}'
}

lt_tshark_ok() {
    if command -v tshark >/dev/null 2>&1; then echo yes; else echo no; fi
}

# ── filter support ──
# The filter file stores a single tshark display filter fragment. It's
# prepended to the base filter for the live stream.

lt_set_filter() {
    local filter="${1:-}"
    [[ -z "$filter" ]] && { printf 'ERROR\tno filter\n' >&2; return 2; }
    printf '%s\n' "$filter" > "$FILTER_FILE"
    printf 'FILTER\t%s\n' "$filter"
}

lt_get_filter() {
    [[ -f "$FILTER_FILE" ]] && cat "$FILTER_FILE" || printf ''
}

lt_clear_filter() {
    : > "$FILTER_FILE"
    printf 'CLEARED\n'
}

lt_set_bssid_filter() {
    local bssid="${1:-}"
    [[ -z "$bssid" ]] && { printf 'ERROR\tno bssid\n' >&2; return 2; }
    lt_set_filter "wlan.bssid == $bssid"
}

# ── WPA2 decryption ──
# tshark can decrypt WPA2-PSK if you give it:
#   -o wlan.enable_decryption:TRUE
#   -o wlan.wep_key1:wpa-pwd:<psk>:<ssid>
# We store the psk and ssid, and inject the option when streaming.
lt_set_psk() {
    local psk="${1:-}" ssid="${2:-}"
    [[ -z "$psk" || -z "$ssid" ]] && {
        printf 'ERROR\tusage: --set-psk PSK SSID\n' >&2; return 2; }
    printf '%s\n%s\n' "$psk" "$ssid" > "$DECRYPT_FILE"
    chmod 600 "$DECRYPT_FILE" 2>/dev/null
    printf 'PSK_SET\t%s\n' "$ssid"
}

lt_clear_psk() {
    rm -f "$DECRYPT_FILE"
    printf 'CLEARED\n'
}

lt_has_psk() { [[ -f "$DECRYPT_FILE" ]]; }
lt_psk_info() {
    if lt_has_psk; then
        local ssid
        ssid=$(sed -n 2p "$DECRYPT_FILE")
        printf 'PSK\tconfigured\nSSID\t%s\n' "$ssid"
    else
        printf 'PSK\tnone\n'
    fi
}

# ── status ──

lt_cmd_status() {
    local iface
    iface="$(lt_get_iface)"
    printf 'iface\t%s\n'      "$iface"
    printf 'iface_type\t%s\n' "$(lt_iface_type "$iface")"
    printf 'channel\t%s\n'    "$(lt_iface_channel "$iface")"
    printf 'tshark\t%s\n'     "$(lt_tshark_ok)"
    printf 'filter\t%s\n'     "$(lt_get_filter)"
    if lt_has_psk; then
        printf 'psk\tconfigured\n'
        printf 'psk_ssid\t%s\n' "$(sed -n 2p "$DECRYPT_FILE")"
    else
        printf 'psk\tnone\n'
        printf 'psk_ssid\t\n'
    fi
    # Rotation state
    local rot_dir="$TMP_DIR/live_traffic/rotation"
    if [[ -d "$rot_dir" ]]; then
        printf 'rotation_files\t%s\n' "$(ls "$rot_dir"/*.pcap 2>/dev/null | wc -l)"
    else
        printf 'rotation_files\t0\n'
    fi
}

lt_cmd_list_ifaces() {
    iw dev 2>/dev/null | awk '
        /Interface/ { iface=$2 }
        /type/      { if (iface!="") { print iface "\t" $2; iface="" } }'
}

lt_cmd_lock_channel() {
    local iface="${1:-}" ch="${2:-}"
    [ -z "$iface" ] && { printf 'ERR\tno iface\n'; return 1; }
    [ -z "$ch" ]    && { printf 'ERR\tno channel\n'; return 1; }

    # A missing interface must not masquerade as a channel problem: wlx* names
    # derive from the adapter MAC, so a spoof or replug renames the adapter and
    # the old name stops existing.
    local iwerr
    if iwerr=$(iw dev "$iface" set channel "$ch" 2>&1); then
        printf 'OK\t%s ch %s\n' "$iface" "$ch"
    else
        # Fall through past the printf: a caller (killchain step) must not see
        # success for a channel change that failed.
        case "$iwerr" in
            *"No such device"*|*"no such device"*)
                printf 'ERR\tinterface %s does not exist - adapter renamed or unplugged?\n' "$iface" ;;
            *)
                if [[ -n "$iwerr" ]]; then
                    printf 'ERR\tcould not set %s ch %s: %s\n' \
                        "$iface" "$ch" "$iwerr"
                else
                    printf 'ERR\tcould not set %s ch %s\n' "$iface" "$ch"
                fi ;;
        esac
        return 1
    fi
}

# ── stream ──

lt_cmd_stream() {
    local iface="${1:-}"
    [ -z "$iface" ] && { echo "ERR no iface" >&2; exit 1; }
    ! command -v tshark >/dev/null 2>&1 && {
        echo "ERR tshark missing" >&2; exit 1; }

    mkdir -p "$TMP_DIR/live_traffic" 2>/dev/null || true
    : > "$TMP_DIR/live_traffic/stream.err"
    echo $$ > "$PID_FILE"

    # Base filter
    local base_filter='wlan or eapol'
    if [[ -f "$FILTER_FILE" ]]; then
        local extra
        extra=$(<"$FILTER_FILE")
        [[ -n "$extra" ]] && base_filter="($base_filter) and ($extra)"
    fi

    # Decryption args
    local -a decrypt_args=()
    if lt_has_psk; then
        local psk ssid
        psk=$(sed -n 1p "$DECRYPT_FILE")
        ssid=$(sed -n 2p "$DECRYPT_FILE")
        decrypt_args+=(-o "wlan.enable_decryption:TRUE")
        decrypt_args+=(-o "wlan.wep_key1:wpa-pwd:${psk}:${ssid}")
    fi

    exec stdbuf -oL tshark \
        -i "$iface" -n -q -l \
        "${decrypt_args[@]}" \
        -Y "$base_filter" \
        -T fields \
        -E 'separator=/t' \
        -E 'occurrence=f' \
        -e frame.number \
        -e frame.time_epoch \
        -e wlan.fc.type_subtype \
        -e wlan.sa \
        -e wlan.da \
        -e wlan.bssid \
        -e wlan.ssid \
        -e wlan_radio.channel \
        -e wlan_radio.signal_dbm \
        -e eapol.type \
        2>>"$TMP_DIR/live_traffic/stream.err"
}

lt_cmd_stop() {
    if [ ! -s "$PID_FILE" ]; then
        printf 'ERR\tno pid file\n'; return 1
    fi
    local pid
    pid="$(<"$PID_FILE")"
    if stop_kill_pid "$pid"; then
        rm -f "$PID_FILE"
        printf 'OK\tkilled %s\n' "$pid"
        return 0
    fi
    # Keep the pidfile: it is the only handle left to a surviving capture.
    printf 'ERR\tpid %s survived SIGKILL (pidfile kept)\n' "$pid"
    return 1
}

# ── pcap rotation ──
# Long-running streams produce 100GB+ pcaps. We rotate every N seconds
# into $TMP_DIR/live_traffic/rotation/.

lt_cmd_rotate_start() {
    local iface="${1:-}" interval="${2:-300}" max_files="${3:-20}"
    [ -z "$iface" ] && { printf 'ERR\tno iface\n'; return 1; }

    command -v tshark >/dev/null 2>&1 || {
        printf 'ERR\ttshark missing\n'; return 1; }

    local rot_dir="$TMP_DIR/live_traffic/rotation"
    mkdir -p "$rot_dir"

    local pidfile="$TMP_DIR/live_traffic/rotation.pid"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        printf 'ERR\talready rotating\n'; return 1
    fi

    setsid bash -c '
        dir="'"$rot_dir"'"
        iface="'"$iface"'"
        interval="'"$interval"'"
        max="'"$max_files"'"
        while true; do
            ts=$(date +%Y%m%d_%H%M%S)
            out="$dir/live_$ts.pcap"
            timeout "$interval" tshark -i "$iface" -w "$out" -q 2>/dev/null || true
            # Trim old files
            count=$(ls "$dir"/*.pcap 2>/dev/null | wc -l)
            while (( count > max )); do
                oldest=$(ls -t "$dir"/*.pcap | tail -1)
                rm -f "$oldest"
                count=$((count - 1))
            done
        done
    ' >/dev/null 2>&1 &

    echo $! > "$pidfile"
    printf 'ROTATING\t%s\nINTERVAL\t%s\nMAX\t%s\n' \
        "$(cat "$pidfile")" "$interval" "$max_files"
}

lt_cmd_rotate_stop() {
    local pidfile="$TMP_DIR/live_traffic/rotation.pid"
    local pid=""
    [[ -f "$pidfile" ]] && pid=$(cat "$pidfile")
    if [[ -n "$pid" ]]; then
        if stop_kill_pid "$pid"; then
            rm -f "$pidfile"
            printf 'STOPPED\n'
            return 0
        fi
        printf 'ERROR\trotation pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
}

lt_cmd_rotate_list() {
    local rot_dir="$TMP_DIR/live_traffic/rotation"
    [[ -d "$rot_dir" ]] || return 0
    local f
    for f in "$rot_dir"/*.pcap; do
        [[ -e "$f" ]] || continue
        printf '%s\t%s\t%s\n' "$(basename "$f")" \
            "$(stat -c%s "$f")" "$(stat -c%Y "$f")"
    done
}

lt_cmd_save_pcap() {
    local iface="${1:-}" path="${2:-}"
    [ -z "$iface" ] && { echo "ERR no iface" >&2; exit 1; }
    [ -z "$path" ]  && { echo "ERR no path" >&2;  exit 1; }
    mkdir -p "$(dirname "$path")" 2>/dev/null || true
    echo $$ > "$TMP_DIR/live_traffic/pcap.pid"
    exec tshark -i "$iface" -I -w "$path" -q 2>/dev/null
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline and hardware-free. Every state file (monitor marker, filter, PSK,
# pidfiles, rotation dir) is redirected into scratch space, so a live stream
# or a saved filter on the real box is never read or overwritten.
#
# Steps that call `exit` (--stream/--save-pcap) are only reached through a
# subprocess, and only their argv guards, which return before tshark.
#
# NB: this module runs under `set -u`, so optional reads use :-.
lt_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcount() { printf '%s\n' "$1" | grep -c . ; }

    local MOD_TMP="${TMP_DIR:-/tmp/wifisting}/live_traffic/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/live_traffic"
    local s_tmp="${TMP_DIR:-}" s_mon="$MON_STATE_FILE" s_pid="$PID_FILE"
    local s_filt="$FILTER_FILE" s_psk="$DECRYPT_FILE"
    TMP_DIR="$MOD_TMP"
    MON_STATE_FILE="$MOD_TMP/mon_iface"
    PID_FILE="$MOD_TMP/live_traffic/stream.pid"
    FILTER_FILE="$MOD_TMP/live_traffic/filter.txt"
    DECRYPT_FILE="$MOD_TMP/live_traffic/psk.txt"

    local out rc MOD="${BASH_SOURCE[0]}"

    # 1. iface selection from the monitor marker file
    printf 'wlan9\n' > "$MON_STATE_FILE"
    chk iface-from-marker "$(lt_get_iface)" wlan9
    chk iface-type-unknown "$(lt_iface_type wlan9)" unknown
    chk iface-type-empty   "$(lt_iface_type '')" unknown
    chk tshark-flag "$(lt_tshark_ok)" \
        "$(command -v tshark >/dev/null 2>&1 && echo yes || echo no)"

    # 2. display filter round-trip, including quotes and spaces
    out=$(lt_set_filter 'wlan.fc.type_subtype == 8'); rc=$?
    chk filter-set-rc   "$rc" 0
    chk filter-set-says "$(fld "$out" FILTER)" "wlan.fc.type_subtype == 8"
    chk filter-set-file "$(cat "$FILTER_FILE")" "wlan.fc.type_subtype == 8"
    chk filter-get      "$(lt_get_filter)" "wlan.fc.type_subtype == 8"
    out=$(lt_set_filter 'wlan.ssid == "Cafe Bar" and wlan.bssid == aa:bb:cc:dd:ee:ff')
    chk filter-roundtrip "$(lt_get_filter)" 'wlan.ssid == "Cafe Bar" and wlan.bssid == aa:bb:cc:dd:ee:ff'
    lt_set_filter "" >/dev/null 2>&1; chk filter-empty-rc "$?" 2
    out=$(lt_set_filter "" 2>&1); rc=$?
    chk filter-empty-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" "no filter"
    out=$(lt_clear_filter); rc=$?
    chk filter-clear-rc   "$rc" 0
    chk filter-clear-says "$(printf '%s\n' "$out" | grep -c '^CLEARED')" 1
    chk filter-cleared-empty "$(lt_get_filter)" ""
    rm -f "$FILTER_FILE"
    chk filter-no-file "$(lt_get_filter)" ""

    # 3. BSSID filter builds a valid tshark expression
    out=$(lt_set_bssid_filter AA:BB:CC:DD:EE:FF); rc=$?
    chk bssid-filter-rc  "$rc" 0
    chk bssid-filter-says "$(fld "$out" FILTER)" "wlan.bssid == AA:BB:CC:DD:EE:FF"
    chk bssid-filter-file "$(cat "$FILTER_FILE")" "wlan.bssid == AA:BB:CC:DD:EE:FF"
    lt_set_bssid_filter "" >/dev/null 2>&1; chk bssid-filter-empty-rc "$?" 2
    # Calling these validators with NO argument at all must reach their guard
    # (this module runs under `set -u`), not abort with "unbound variable".
    out=$(lt_set_filter 2>&1); rc=$?
    chk filter-noarg-rc  "$rc" 2
    chk filter-noarg-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" "no filter"
    out=$(lt_set_bssid_filter 2>&1); rc=$?
    chk bssid-filter-noarg-rc  "$rc" 2
    chk bssid-filter-noarg-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" "no bssid"
    out=$(lt_set_psk 2>&1); rc=$?
    chk psk-noarg-rc  "$rc" 2
    chk psk-noarg-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" "usage: --set-psk PSK SSID"
    out=$(lt_cmd_lock_channel 2>&1); rc=$?
    chk lock-noarg-rc  "$rc" 1
    chk lock-noarg-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERR"{print $2}')" "no iface"
    out=$(lt_cmd_rotate_start 2>&1); rc=$?
    chk rotate-noarg-rc  "$rc" 1
    chk rotate-noarg-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERR"{print $2}')" "no iface"

    # 4. PSK handling: two lines, 0600 on disk, info/clear round-trip
    rm -f "$DECRYPT_FILE"
    chk psk-has-before "$(lt_has_psk && echo yes || echo no)" no
    out=$(lt_psk_info)
    chk psk-info-none  "$(fld "$out" PSK)" none
    chk psk-info-rows  "$(rcount "$out")" 1
    out=$(lt_set_psk 'sup3rsecret' 'Cafe Bar'); rc=$?
    chk psk-set-rc   "$rc" 0
    chk psk-set-says "$(fld "$out" PSK_SET)" "Cafe Bar"
    chk psk-line1    "$(sed -n 1p "$DECRYPT_FILE")" sup3rsecret
    chk psk-line2    "$(sed -n 2p "$DECRYPT_FILE")" "Cafe Bar"
    chk psk-mode     "$(stat -c%a "$DECRYPT_FILE")" 600
    chk psk-has-after "$(lt_has_psk && echo yes || echo no)" yes
    out=$(lt_psk_info)
    chk psk-info-configured "$(fld "$out" PSK)" configured
    chk psk-info-ssid       "$(fld "$out" SSID)" "Cafe Bar"
    lt_set_psk onlypsk "" >/dev/null 2>&1;  chk psk-missing-ssid-rc "$?" 2
    lt_set_psk "" "" >/dev/null 2>&1;      chk psk-noargs-rc "$?" 2
    out=$(lt_set_psk x "" 2>&1)
    chk psk-usage-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" "usage: --set-psk PSK SSID"
    out=$(lt_clear_psk); rc=$?
    chk psk-clear-rc   "$rc" 0
    chk psk-clear-says "$(printf '%s\n' "$out" | grep -c '^CLEARED')" 1
    chk psk-clear-file "$([[ -f "$DECRYPT_FILE" ]] && echo present || echo gone)" gone

    # 5. status TSV reflects exactly what is on disk
    printf 'wlan9\n' > "$MON_STATE_FILE"
    printf 'wlan.fc.type_subtype == 8\n' > "$FILTER_FILE"
    printf 'secretpsk\nMyNet\n' > "$DECRYPT_FILE"
    out=$(lt_cmd_status)
    chk status-rows     "$(rcount "$out")" 8
    chk status-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0
    chk status-iface    "$(fld "$out" iface)" wlan9
    chk status-filter   "$(fld "$out" filter)" "wlan.fc.type_subtype == 8"
    chk status-psk      "$(fld "$out" psk)" configured
    chk status-psk-ssid "$(fld "$out" psk_ssid)" MyNet
    chk status-rotation-none "$(fld "$out" rotation_files)" 0
    rm -f "$DECRYPT_FILE"
    out=$(lt_cmd_status)
    chk status-psk-none "$(fld "$out" psk)" none
    chk status-psk-ssid-empty "$(fld "$out" psk_ssid)" ""
    mkdir -p "$MOD_TMP/live_traffic/rotation"
    printf 'x' > "$MOD_TMP/live_traffic/rotation/live_1.pcap"
    printf 'yy' > "$MOD_TMP/live_traffic/rotation/live_2.pcap"
    chk status-rotation-two "$(fld "$(lt_cmd_status)" rotation_files)" 2

    # 6. rotation listing: NAME<TAB>SIZE<TAB>MTIME
    out=$(lt_cmd_rotate_list)
    chk rotate-list-rows   "$(rcount "$out")" 2
    chk rotate-list-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=3 || $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ {c++} END{print c+0}')" 0
    chk rotate-list-size   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="live_2.pcap"{print $2}')" 2
    rm -rf "$MOD_TMP/live_traffic/rotation"
    chk rotate-list-absent "$(lt_cmd_rotate_list | grep -c .)" 0

    # 7. rotation stop is idempotent and clears a stale pidfile
    out=$(lt_cmd_rotate_stop); rc=$?
    chk rotate-stop-nopid-rc   "$rc" 0
    chk rotate-stop-nopid-says "$(fld "$out" STOPPED)" 0
    local dead; dead=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 4194304)
    printf '%s\n' "$dead" > "$MOD_TMP/live_traffic/rotation.pid"
    out=$(lt_cmd_rotate_stop); rc=$?
    chk rotate-stop-stale-rc "$rc" 0
    chk rotate-stop-stale-clears "$([[ -f "$MOD_TMP/live_traffic/rotation.pid" ]] && echo present || echo gone)" gone

    # 8. stream stop: refuses without a pidfile, clears a stale one
    rm -f "$PID_FILE"
    out=$(lt_cmd_stop 2>&1); rc=$?
    chk stop-nopid-rc   "$rc" 1
    chk stop-nopid-msg  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERR"{print $2}')" "no pid file"
    printf '%s\n' "$dead" > "$PID_FILE"
    out=$(lt_cmd_stop 2>&1); rc=$?
    chk stop-stale-rc     "$rc" 0
    chk stop-stale-killed "$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK"{print $2}')" "killed $dead"
    chk stop-stale-clears "$([[ -f "$PID_FILE" ]] && echo present || echo gone)" gone

    # 9. lock-channel argv guard (no radio is touched when args are missing)
    out=$(lt_cmd_lock_channel "" 2>&1); rc=$?
    chk lock-no-iface-rc  "$rc" 1
    chk lock-no-iface-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERR"{print $2}')" "no iface"
    out=$(lt_cmd_lock_channel wlan9 2>&1); rc=$?
    chk lock-no-chan-rc  "$rc" 1
    chk lock-no-chan-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERR"{print $2}')" "no channel"
    # A failing `iw` must make the function return non-zero. It used to fall
    # through to a bare printf and return 0, so a killchain step read a failed
    # channel change as success. Stub `iw` so no radio is touched.
    local wstub="$MOD_TMP/wstub"
    mkdir -p "$wstub"
    printf '#!/bin/sh\nexit 1\n' > "$wstub/iw"
    chmod +x "$wstub/iw"
    local s_wpath="$PATH"
    PATH="$wstub:$PATH"
    out=$(lt_cmd_lock_channel wlan9 6 2>&1); rc=$?
    PATH="$s_wpath"
    chk lock-iw-fail-rc  "$rc" 1
    chk lock-iw-fail-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERR"{print $2}')" "could not set wlan9 ch 6"
    # ...and a succeeding `iw` still reports OK with rc 0
    printf '#!/bin/sh\nexit 0\n' > "$wstub/iw"
    PATH="$wstub:$PATH"
    out=$(lt_cmd_lock_channel wlan9 6 2>&1); rc=$?
    PATH="$s_wpath"
    chk lock-iw-ok-rc   "$rc" 0
    chk lock-iw-ok-msg  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK"{print $2}')" "wlan9 ch 6"

    # 10. CLI dispatch: guards that exit must run in a subprocess. The argv is
    #     genuinely OMITTED here — with the ${1:-} guards in place a missing
    #     argv must reach the guard instead of aborting on `unbound variable`.
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --stream 2>&1); rc=$?
    chk cli-stream-noiface-rc  "$rc" 1
    chk cli-stream-noiface-msg "$(printf '%s\n' "$out" | grep -c 'ERR no iface')" 1
    chk cli-stream-noiface-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --save-pcap 2>&1); rc=$?
    chk cli-savepcp-noargs-rc  "$rc" 1
    chk cli-savepcp-noargs-msg "$(printf '%s\n' "$out" | grep -c 'ERR no iface')" 1
    chk cli-savepcp-noargs-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --save-pcap wlan9 2>&1); rc=$?
    chk cli-savepcp-nopath-rc  "$rc" 1
    chk cli-savepcp-nopath-msg "$(printf '%s\n' "$out" | grep -c 'ERR no path')" 1
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --save-pcap wlan9 2>&1)
    chk cli-savepcp-nopath-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    # The reported repro: `--set-filter` with no argument used to abort with
    # rc 1 and "unbound variable" instead of the intended guard.
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --set-filter 2>&1); rc=$?
    chk cli-setfilter-noarg-rc  "$rc" 2
    chk cli-setfilter-noarg-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" "no filter"
    chk cli-setfilter-noarg-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --set-bssid-filter 2>&1); rc=$?
    chk cli-setbssid-noarg-rc  "$rc" 2
    chk cli-setbssid-noarg-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --set-psk 2>&1); rc=$?
    chk cli-setpsk-noarg-rc  "$rc" 2
    chk cli-setpsk-noarg-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --lock-channel 2>&1); rc=$?
    chk cli-lock-noarg-rc  "$rc" 1
    chk cli-lock-noarg-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --rotate-start 2>&1); rc=$?
    chk cli-rotate-noarg-rc  "$rc" 1
    chk cli-rotate-noarg-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --set-filter 'eapol' 2>&1); rc=$?
    chk cli-setfilter-rc   "$rc" 0
    chk cli-setfilter-says "$(printf '%s\n' "$out" | awk -F'\t' '$1=="FILTER"{print $2}')" eapol
    chk cli-setfilter-file "$(cat "$MOD_TMP/live_traffic/filter.txt")" eapol
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --bogus 2>&1); rc=$?
    chk cli-usage-rc  "$rc" 2
    chk cli-usage-msg "$(printf '%s\n' "$out" | grep -c '^usage:')" 1

    TMP_DIR="$s_tmp"; MON_STATE_FILE="$s_mon"; PID_FILE="$s_pid"
    FILTER_FILE="$s_filt"; DECRYPT_FILE="$s_psk"
    rm -rf "$MOD_TMP"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── dispatch ──

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
case "${1:-}" in
    --selftest)         lt_selftest; exit $? ;;
    --status-tsv)       lt_cmd_status ;;
    --list-ifaces-tsv)  lt_cmd_list_ifaces ;;
    --lock-channel)     shift; lt_cmd_lock_channel "$@" ;;
    --set-filter)       shift; lt_set_filter "$@" ;;
    --set-bssid-filter) shift; lt_set_bssid_filter "$@" ;;
    --clear-filter)     lt_clear_filter ;;
    --get-filter)       lt_get_filter ;;
    --set-psk)          shift; lt_set_psk "$@" ;;
    --clear-psk)        lt_clear_psk ;;
    --psk-info)         lt_psk_info ;;
    --stream)           shift; lt_cmd_stream "$@" ;;
    --stop)             lt_cmd_stop ;;
    --save-pcap)        shift; lt_cmd_save_pcap "$@" ;;
    --rotate-start)     shift; lt_cmd_rotate_start "$@" ;;
    --rotate-stop)      lt_cmd_rotate_stop ;;
    --rotate-list)      lt_cmd_rotate_list ;;
    *)
        echo "usage: $0 --status-tsv | --list-ifaces-tsv | --lock-channel IF CH | --stream IF | --stop | --save-pcap IF PATH | --set-filter FILTER | --set-bssid-filter BSSID | --clear-filter | --set-psk PSK SSID | --clear-psk | --psk-info | --rotate-start IF [INTERVAL] [MAX] | --rotate-stop | --rotate-list | --selftest" >&2
        exit 2
        ;;
esac
fi

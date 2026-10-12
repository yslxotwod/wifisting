#!/usr/bin/env bash
# interface management — list, select, monitor mode, capability probe
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
: "${WIFISTING_HOME:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" 2>/dev/null

IFACE_CAPS_CACHE="$TMP_DIR/iface_caps_cache"
mkdir -p "$IFACE_CAPS_CACHE"

iface_list_wireless() {
    local ifaces=()
    while read -r line; do
        [[ "$line" =~ Interface[[:space:]]+([a-zA-Z0-9]+) ]] && ifaces+=("${BASH_REMATCH[1]}")
    done < <(iw dev 2>/dev/null)
    printf "%s\n" "${ifaces[@]}"
}

iface_show() {
    banner 2>/dev/null || clear
    echo "  === wireless interfaces ==="
    echo ""
    local i=1
    IFACES=()
    while read -r name; do
        [[ -z "$name" ]] && continue
        IFACES+=("$name")
        local type driver
        type=$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2}')
        driver=$(basename "$(readlink /sys/class/net/"$name"/device/driver 2>/dev/null)")
        printf "  [%d]  %s   type:%s   driver:%s\n" "$i" "$name" "${type:-?}" "${driver:-?}"
        i=$((i+1))
    done < <(iface_list_wireless)
    echo ""
    if [[ ${#IFACES[@]} -eq 0 ]]; then
        warn "no wireless interfaces detected"
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  capability probe — runtime, not driver-name heuristic
# ═══════════════════════════════════════════════════════════════════

# Best-effort injection test using aireplay-ng --test. Returns 0 if the
# adapter can inject, 1 otherwise. Runs on a temporary monitor iface
# so we don't disrupt the current one.
iface_probe_injection() {
    local iface="$1"
    command -v aireplay-ng >/dev/null 2>&1 || return 1

    local tmp_out
    tmp_out=$(timeout 8 aireplay-ng --test "$iface" 2>&1 || true)
    if echo "$tmp_out" | grep -qE 'Injection is working|Injection test passed'; then
        return 0
    fi
    return 1
}

iface_probe_ap_mode() {
    local iface="$1"
    command -v iw >/dev/null 2>&1 || return 1
    local info
    info=$(iw phy "$(cat /sys/class/net/"$iface"/phy80211/name 2>/dev/null)" info 2>/dev/null)
    if echo "$info" | grep -qE 'AP.*\{|AP/VLAN'; then
        return 0
    fi
    return 1
}

iface_probe_bands() {
    local iface="$1"
    local phy
    phy=$(cat /sys/class/net/"$iface"/phy80211/name 2>/dev/null)
    [[ -z "$phy" ]] && { echo "unknown"; return; }

    local info
    info=$(iw phy "$phy" info 2>/dev/null)
    local bands=()
    echo "$info" | grep -q "Band 1" && bands+=("2.4")
    echo "$info" | grep -q "Band 2" && bands+=("5")
    echo "$info" | grep -q "Band 4" && bands+=("6")
    if ((${#bands[@]} == 0)); then
        echo "unknown"
    else
        ( IFS=','; echo "${bands[*]}" )
    fi
}

# Full capability report. Cached for 60s so a GUI refresh doesn't
# rerun the injection test every tick.
iface_caps_report() {
    local iface="$1"
    local cache="$IFACE_CAPS_CACHE/$iface.json"

    if [[ -f "$cache" ]]; then
        local age=$(( $(date +%s) - $(stat -c%Y "$cache") ))
        if (( age < 60 )); then
            cat "$cache"
            return
        fi
    fi

    local driver mode bands ap inject
    driver=$(basename "$(readlink /sys/class/net/"$iface"/device/driver 2>/dev/null)")
    mode=$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2}')
    bands=$(iface_probe_bands "$iface")

    iface_probe_ap_mode "$iface" && ap="yes" || ap="no"
    iface_probe_injection "$iface" && inject="yes" || inject="no"

    # If not in monitor mode, injection test is unreliable. Mark unknown.
    if [[ "$mode" != "monitor" ]]; then
        inject="unknown (not monitor)"
    fi

    local out
    out=$(cat <<EOF
{"iface":"$iface","driver":"${driver:-?}","mode":"${mode:-?}","bands":"$bands","ap_mode":"$ap","injection":"$inject"}
EOF
)
    echo "$out" | tee "$cache" >/dev/null
    echo "$out"
}

iface_caps_tsv() {
    local iface="$1"
    [[ -z "$iface" ]] && { printf 'missing iface\n' >&2; return 2; }
    local json
    json=$(iface_caps_report "$iface")
    python3 -c "
import json,sys
try:
    d = json.loads(sys.argv[1])
    for k, v in d.items():
        print(f'{k}\t{v}')
except Exception as e:
    print('error\t' + str(e))
" "$json"
}

iface_kill_conflicts() {
    info "killing NetworkManager + wpa_supplicant"
    airmon-ng check kill >/dev/null 2>&1 || {
        systemctl stop NetworkManager 2>/dev/null
        systemctl stop wpa_supplicant 2>/dev/null
        pkill wpa_supplicant 2>/dev/null
    }
    ok "conflicts killed"
}

# Put an interface into AP mode. The evil twin needs this and had nowhere to
# get it: nothing in the tree set AP mode, so hostapd was left to switch the
# interface itself, which fails whenever the adapter is associated as a
# client - the normal state of a spare adapter.
iface_ap_on() {
    [[ -z "$SELECTED_IFACE" ]] && { err "no interface selected"; return 1; }
    # Tell NetworkManager to leave THIS interface alone rather than killing it
    # system-wide. `airmon-ng check kill` stops NM entirely - which drops every
    # other connection - and NM is then D-Bus-activated back and reclaims the
    # interface, so the AP mode change did not stick. Unmanaging the one
    # device is targeted and survives NM restarting.
    if command -v nmcli >/dev/null 2>&1; then
        # Disconnect first, then unmanage. An adapter that is still ASSOCIATED
        # cannot be put into AP mode at all - and it is commonly associated to
        # the very network you are about to impersonate, because that is the
        # one you were just scanning.
        nmcli device disconnect "$SELECTED_IFACE" 2>/dev/null || true
        nmcli device set "$SELECTED_IFACE" managed no 2>/dev/null || true
    fi
    iface_kill_conflicts
    info "putting $SELECTED_IFACE into AP mode"
    ip link set "$SELECTED_IFACE" down 2>/dev/null
    # __ap is the nl80211 name; some builds accept "ap". Try both.
    iw dev "$SELECTED_IFACE" set type __ap 2>/dev/null || \
        iw dev "$SELECTED_IFACE" set type ap 2>/dev/null || true
    ip link set "$SELECTED_IFACE" up 2>/dev/null

    local type assoc
    type=$(iw dev "$SELECTED_IFACE" info 2>/dev/null | awk '/type/ {print $2}')
    assoc=$(iw dev "$SELECTED_IFACE" info 2>/dev/null | awk '/ssid/ {print $2}')
    # iw prints the type capitalised ("type AP") on some builds and lowercase
    # on others, so comparing exactly reported a SUCCESSFUL mode change as a
    # failure. Compare case-insensitively.
    if [[ "${type,,}" == "ap" || "${type,,}" == "__ap" ]]; then
        ok "AP mode active on $SELECTED_IFACE"
    else
        err "failed to enter AP mode (type=${type:-unknown})"
        [[ -n "$assoc" ]] && \
            err "still associated to $assoc - disconnect it first"
        return 1
    fi
}

# Back to a normal client interface.
iface_ap_off() {
    local iface="${1:-$SELECTED_IFACE}"
    [[ -z "$iface" ]] && { err "no interface selected"; return 1; }
    ip link set "$iface" down 2>/dev/null
    iw dev "$iface" set type managed 2>/dev/null || true
    ip link set "$iface" up 2>/dev/null
    # Hand it back to NetworkManager, or it stays unmanaged and never
    # reconnects on its own.
    if command -v nmcli >/dev/null 2>&1; then
        nmcli device set "$iface" managed yes 2>/dev/null || true
    fi
    ok "$iface back in managed mode"
}


iface_monitor_on() {
    [[ -z "$SELECTED_IFACE" ]] && { err "no interface selected"; return 1; }
    # Release the interface from NetworkManager BEFORE switching it, exactly
    # as --ap-on does. Without this NM is D-Bus-activated straight back after
    # airmon-ng kills it, reclaims the device, and sets it to managed again -
    # so monitor mode was lost MID-ATTACK and the tool holding it failed with
    # "pcap_activate status -5 - No such device exists", which blames a
    # missing adapter rather than the mode change behind it.
    if command -v nmcli >/dev/null 2>&1; then
        nmcli device disconnect "$SELECTED_IFACE" 2>/dev/null || true
        nmcli device set "$SELECTED_IFACE" managed no 2>/dev/null || true
    fi
    iface_kill_conflicts
    info "putting $SELECTED_IFACE into monitor mode"
    ip link set "$SELECTED_IFACE" down
    iw dev "$SELECTED_IFACE" set type monitor 2>/dev/null || airmon-ng start "$SELECTED_IFACE"
    ip link set "$SELECTED_IFACE" up
    local type
    type=$(iw dev "$SELECTED_IFACE" info 2>/dev/null | awk '/type/ {print $2}')
    if [[ "$type" == "monitor" ]]; then
        MON_IFACE="$SELECTED_IFACE"
        printf '%s\n' "$MON_IFACE" > "$TMP_DIR/mon_iface"
        ok "monitor mode active on $MON_IFACE"
    else
        err "failed to enter monitor mode (type=$type)"
    fi
}

iface_monitor_off() {
    local iface="${MON_IFACE:-$SELECTED_IFACE}"
    [[ -z "$iface" ]] && { err "no interface"; return 1; }
    info "restoring $iface to managed mode"
    ip link set "$iface" down
    iw dev "$iface" set type managed 2>/dev/null
    ip link set "$iface" up
    MON_IFACE=""
    rm -f "$TMP_DIR/mon_iface"
    # Hand it back to NetworkManager, or the adapter stays unmanaged and never
    # reconnects on its own - a state with no visible cause from the user's
    # side. Uses $iface, NOT $MON_IFACE: that was cleared three lines above,
    # so the nmcli call silently targeted an empty device name and the
    # re-manage never actually happened.
    if command -v nmcli >/dev/null 2>&1; then
        nmcli device set "$iface" managed yes 2>/dev/null || true
    fi
    ok "restored"
}

iface_restore_net() {
    info "restarting NetworkManager"
    systemctl start NetworkManager 2>/dev/null
    ok "NetworkManager restarted"
}

# ═══════════════════════════════════════════════════════════════════
#  auto-restore watcher — re-asserts monitor mode if the iface flips
# ═══════════════════════════════════════════════════════════════════

# Runs in the background; every 5s checks the tracked monitor iface.
# If it flipped to managed (iwlwifi does this silently), re-assert.
IFACE_WATCH_PID="$TMP_DIR/iface_watch.pid"

iface_watch_start() {
    local iface="$1"
    local interval="${2:-5}"
    [[ -z "$iface" ]] && { printf 'missing iface\n' >&2; return 2; }

    iface_watch_stop  # kill any existing watcher

    setsid bash -c "
        while true; do
            [ -e /sys/class/net/$iface ] || { sleep $interval; continue; }
            mode=\$(iw dev $iface info 2>/dev/null | awk '/type/ {print \$2}')
            if [ \"\$mode\" != \"monitor\" ]; then
                ip link set $iface down 2>/dev/null
                iw dev $iface set type monitor 2>/dev/null
                ip link set $iface up 2>/dev/null
                # Only log if we actually changed something
                newmode=\$(iw dev $iface info 2>/dev/null | awk '/type/ {print \$2}')
                if [ \"\$newmode\" = \"monitor\" ]; then
                    echo \"[\$(date +%H:%M:%S)] re-asserted monitor on $iface\" >> $TMP_DIR/iface_watch.log
                fi
            fi
            sleep $interval
        done
    " >/dev/null 2>&1 &

    echo $! > "$IFACE_WATCH_PID"
    printf 'WATCHING\t%s\nPID\t%s\n' "$iface" "$(cat "$IFACE_WATCH_PID")"
}

iface_watch_stop() {
    local pid=""
    [[ -f "$IFACE_WATCH_PID" ]] && pid=$(cat "$IFACE_WATCH_PID")
    if [[ -n "$pid" ]]; then
        if stop_kill_pid "$pid"; then
            rm -f "$IFACE_WATCH_PID"
            printf 'STOPPED\n'
            return 0
        fi
        printf 'ERROR\twatcher pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
}

iface_watch_status_tsv() {
    if [[ -f "$IFACE_WATCH_PID" ]]; then
        local pid
        pid=$(cat "$IFACE_WATCH_PID")
        if kill -0 "$pid" 2>/dev/null; then
            printf 'running\t1\npid\t%s\n' "$pid"
            return
        fi
    fi
    printf 'running\t0\npid\t\n'
}

# ═══════════════════════════════════════════════════════════════════
#  interactive menu (legacy)
# ═══════════════════════════════════════════════════════════════════

iface_menu() {
    while true; do
        banner 2>/dev/null || clear
        echo "  === interface management ==="
        echo "  selected: ${SELECTED_IFACE:-none}   mon: ${MON_IFACE:-none}"
        cat << 'M'

  [1]  list wireless interfaces
  [2]  select interface
  [3]  kill conflicting processes
  [4]  enable monitor mode
  [5]  disable monitor mode
  [6]  restart NetworkManager
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1) iface_show; read -rp "  press enter " _ ;;
            2) iface_show; read -rp "  select #> " n
               [[ "$n" =~ ^[0-9]+$ ]] && SELECTED_IFACE="${IFACES[$((n-1))]}" ;;
            3) iface_kill_conflicts; read -rp "  press enter " _ ;;
            4) iface_monitor_on; read -rp "  press enter " _ ;;
            5) iface_monitor_off; read -rp "  press enter " _ ;;
            6) iface_restore_net; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════

iface_cli_list_tsv() {
    local name driver type
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        driver=$(basename "$(readlink /sys/class/net/"$name"/device/driver 2>/dev/null)")
        type=$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2}')
        printf '%s\t%s\t%s\n' "$name" "${driver:-?}" "${type:-?}"
    done < <(iface_list_wireless)
}

# ── iface arbitration ──
# Monitor-only modules (attack, fingerprint, IDS, karma, rf spectrum) all
# compete for the same adapter. One lock file turns the resulting
# EBUSY / "device or resource busy" failures into a clear, attributable
# error naming whoever holds it.
IFACE_LOCK="$TMP_DIR/iface.lock"

_iface_lock_read() {
    [[ -s "$IFACE_LOCK" ]] && head -n1 "$IFACE_LOCK"
    return 0
}

# Returns 0 only if a lock exists AND its recorded pid is still alive.
iface_lock_busy() {
    local line iface0 mod0 pid0
    line="$(_iface_lock_read)"
    [[ -z "$line" ]] && return 1
    IFS=$'\t' read -r iface0 mod0 pid0 _ <<<"$line"
    [[ -n "$pid0" ]] && kill -0 "$pid0" 2>/dev/null
}

iface_lock_claim() {
    # PID is the LONG-LIVED holder (the monitor / capture process), not the
    # caller: a CLI invocation exits immediately, so recording its own pid
    # would make the lock look stale the moment it was taken. Callers that
    # are themselves long-lived may omit it.
    local iface="$1" module="$2" holder="${3:-${BASHPID:-$$}}"
    [[ -z "$iface" || -z "$module" ]] && {
        printf 'ERROR\tusage: --lock-claim IFACE MODULE [PID]\n' >&2; return 2; }

    local line iface0 mod0 pid0
    line="$(_iface_lock_read)"
    if [[ -n "$line" ]]; then
        IFS=$'\t' read -r iface0 mod0 pid0 _ <<<"$line"
        if [[ -n "$pid0" ]] && kill -0 "$pid0" 2>/dev/null; then
            if [[ "$iface0" == "$iface" ]]; then
                printf 'BUSY\t%s\t%s\t%s\n' "$iface0" "$mod0" "$pid0"
                return 1
            fi
            # Held on a different iface: allowed, we only arbitrate per-iface.
        else
            rm -f "$IFACE_LOCK"   # holder died — stale lock
        fi
    fi

    # noclobber makes the create atomic, so two racers cannot both win.
    if ! ( set -o noclobber
           printf '%s\t%s\t%s\t%s\n' "$iface" "$module" "$holder" "$(date +%s)" \
               > "$IFACE_LOCK" ) 2>/dev/null; then
        line="$(_iface_lock_read)"
        IFS=$'\t' read -r iface0 mod0 pid0 _ <<<"$line"
        printf 'BUSY\t%s\t%s\t%s\n' "${iface0:-?}" "${mod0:-?}" "${pid0:-0}"
        return 1
    fi
    printf 'OK\t%s\t%s\t%s\n' "$iface" "$module" "$holder"
}

iface_lock_release() {
    # Optional OWNER pid: release only if that pid still holds the lock, so a
    # finishing worker cannot free a lock another module has since taken.
    local iface="${1:-}" owner="${2:-}"
    local line iface0 mod0 pid0
    line="$(_iface_lock_read)"
    [[ -z "$line" ]] && { printf 'OK\tnone\n'; return 0; }
    IFS=$'\t' read -r iface0 mod0 pid0 _ <<<"$line"
    if [[ -n "$iface" && "$iface" != "$iface0" ]]; then
        printf 'ERROR\tlock held on %s, not %s\n' "$iface0" "$iface" >&2
        return 1
    fi
    if [[ -n "$owner" && "$owner" != "$pid0" ]]; then
        printf 'OK\tnot-owner\n'
        return 0
    fi
    rm -f "$IFACE_LOCK"
    printf 'OK\treleased\t%s\t%s\n' "$iface0" "$mod0"
}

iface_lock_status_tsv() {
    local line iface0 mod0 pid0 epoch0
    line="$(_iface_lock_read)"
    if [[ -z "$line" ]]; then
        printf 'LOCKED\t0\nIFACE\t\nMODULE\t\nPID\t0\nAGE\t0\n'
        return 0
    fi
    IFS=$'\t' read -r iface0 mod0 pid0 epoch0 <<<"$line"
    local live=0 age=0
    [[ -n "$pid0" ]] && kill -0 "$pid0" 2>/dev/null && live=1
    [[ -n "$epoch0" ]] && age=$(( $(date +%s) - epoch0 ))
    printf 'LOCKED\t%s\nIFACE\t%s\nMODULE\t%s\nPID\t%s\nAGE\t%s\n' \
        "$live" "$iface0" "$mod0" "${pid0:-0}" "$age"
}

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
# Returns non-zero only if something matched and SURVIVED.
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

# Kill one pid with escalating signals, verifying it is actually gone.
# Lives here because the polkit rule only covers programs under
# /wifisting/modules/ — `pkexec /usr/bin/kill` is NOT authorised, which is why
# the GUI's kill-children button did nothing for root-owned processes.
iface_kill_pid() {
    local pid="$1"
    [[ -z "$pid" || "$pid" == "0" ]] && {
        printf 'ERROR\tusage: --kill-pid PID\n' >&2; return 2; }
    if [[ ! -d "/proc/$pid" ]]; then
        printf 'GONE\t%s\n' "$pid"
        return 0
    fi
    if stop_kill_pid "$pid"; then
        printf 'KILLED\t%s\n' "$pid"
        return 0
    fi
    printf 'ERROR\tpid %s survived SIGKILL (permission denied?)\n' "$pid" >&2
    return 1
}

# Live context for one interface: current mode/channel plus who holds the
# arbitration lock. One call so the GUI can warn about a target whose channel
# differs from where the adapter actually is.
iface_cli_context_tsv() {
    local iface="${1:-}"
    local mode="" chan="" locked=0 lmod="" lpid="0" lage="0"
    local line iface0 mod0 pid0 epoch0

    if [[ -n "$iface" ]] && iw dev "$iface" info >/dev/null 2>&1; then
        mode=$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2}')
        chan=$(iw dev "$iface" info 2>/dev/null | awk '/channel/ {print $2}')
    fi

    line="$(_iface_lock_read)"
    if [[ -n "$line" ]]; then
        IFS=$'\t' read -r iface0 mod0 pid0 epoch0 <<<"$line"
        if [[ -n "$pid0" ]] && [[ -d "/proc/$pid0" ]]; then
            locked=1
            lmod="$mod0"
            lpid="${pid0:-0}"
            [[ -n "$epoch0" ]] && lage=$(( $(date +%s) - epoch0 ))
        elif [[ -n "$iface0" ]]; then
            locked=2   # stale entry, holder is gone
            lmod="$mod0"
            lpid="${pid0:-0}"
        fi
    fi

    printf 'IFACE\t%s\nMODE\t%s\nCHANNEL\t%s\n' "$iface" "$mode" "$chan"
    printf 'LOCK_STATE\t%s\nLOCK_MODULE\t%s\nLOCK_PID\t%s\nLOCK_AGE\t%s\n' \
        "$locked" "$lmod" "$lpid" "$lage"
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline and hardware-free: the arbitration lock and the verified-stop
# paths are ordinary file/pid logic. The live lock and watcher pidfile are
# redirected into scratch space so a running capture is never disturbed.
iface_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local MOD_TMP="$TMP_DIR/iface_selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP"
    local saved_lock="$IFACE_LOCK" saved_watch="$IFACE_WATCH_PID"
    IFACE_LOCK="$MOD_TMP/iface.lock"
    IFACE_WATCH_PID="$MOD_TMP/iface_watch.pid"

    local out rc i1 i2
    i1=$$; i2=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 4194304)

    # 1. empty state
    out=$(iface_lock_status_tsv)
    chk status-nolock-locked "$(fld "$out" LOCKED)" 0
    chk status-nolock-iface  "$(fld "$out" IFACE)"  ""
    chk status-nolock-pid    "$(fld "$out" PID)"    0
    chk status-nolock-age    "$(fld "$out" AGE)"    0

    # 2. claim / status / release round-trip
    out=$(iface_lock_claim wlan0 modA "$i1"); rc=$?
    chk claim-rc     "$rc" 0
    chk claim-iface  "$(fld "$out" OK)"    wlan0
    chk claim-module "$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK"{print $3}')" modA
    chk claim-pid    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="OK"{print $4}')" "$i1"
    chk claim-fields "$(awk -F'\t' 'NF!=4{c++} END{print c+0}' "$IFACE_LOCK")" 0
    chk claim-file-iface "$(cut -f1 "$IFACE_LOCK")" wlan0
    chk claim-file-module "$(cut -f2 "$IFACE_LOCK")" modA
    chk claim-file-pid "$(cut -f3 "$IFACE_LOCK")" "$i1"

    # 3. a second claim is refused while the recorded holder is alive
    out=$(iface_lock_claim wlan0 modB "$i2"); rc=$?
    chk busy-same-iface-rc     "$rc" 1
    chk busy-same-iface-status "$(printf '%s\n' "$out" | cut -f1)" BUSY
    chk busy-same-iface-holder "$(printf '%s\n' "$out" | cut -f3)" modA
    out=$(iface_lock_claim wlan1 modC "$i2"); rc=$?
    chk busy-other-iface-rc "$rc" 1
    chk busy-other-iface-status "$(printf '%s\n' "$out" | cut -f1)" BUSY
    chk busy-still-owner "$(cut -f2 "$IFACE_LOCK")" modA

    # 4. release refuses a caller that does not own the lock
    out=$(iface_lock_release wlan1 2>&1); rc=$?
    chk release-wrong-iface-rc "$rc" 1
    chk release-wrong-iface-keeps-lock "$(cut -f2 "$IFACE_LOCK")" modA
    chk release-wrong-iface-msg "$(printf '%s\n' "$out" | cut -f2)" "lock held on wlan0, not wlan1"

    out=$(iface_lock_release wlan0 "$i2"); rc=$?
    chk release-non-owner-rc   "$rc" 0
    chk release-non-owner-says "$(printf '%s\n' "$out" | cut -f2)" not-owner
    chk release-non-owner-keeps-lock "$(cut -f3 "$IFACE_LOCK")" "$i1"

    # 5. live status + context agree with the lock file
    out=$(iface_lock_status_tsv)
    chk status-live-locked "$(fld "$out" LOCKED)" 1
    chk status-live-iface  "$(fld "$out" IFACE)"  wlan0
    chk status-live-module "$(fld "$out" MODULE)" modA
    chk status-live-pid    "$(fld "$out" PID)"    "$i1"
    out=$(iface_cli_context_tsv "")
    chk context-live-state  "$(fld "$out" LOCK_STATE)"  1
    chk context-live-module "$(fld "$out" LOCK_MODULE)" modA
    chk context-live-pid    "$(fld "$out" LOCK_PID)"    "$i1"
    chk context-no-iface-mode "$(fld "$out" MODE)"      ""

    # 6. release by the owner frees it; releasing nothing is not an error
    out=$(iface_lock_release wlan0 "$i1"); rc=$?
    chk release-owner-rc   "$rc" 0
    chk release-owner-says "$(printf '%s\n' "$out" | cut -f2)" released
    if [[ -e "$IFACE_LOCK" ]]; then
        printf 'release-owner-removes-lock\tFAIL (lock file kept)\n'; bad=$((bad+1))
    else printf 'release-owner-removes-lock\tPASS\n'; fi
    chk status-after-release "$(fld "$(iface_lock_status_tsv)" LOCKED)" 0
    out=$(iface_lock_release); rc=$?
    chk release-idempotent-rc   "$rc" 0
    chk release-idempotent-says "$(printf '%s\n' "$out" | cut -f2)" none

    # 7. a dead holder must not block a new claim, and reads as stale
    printf 'wlan9\tghost\t%s\t%s\n' "$i2" "$(date +%s)" > "$IFACE_LOCK"
    chk context-stale-state "$(fld "$(iface_cli_context_tsv "")" LOCK_STATE)" 2
    out=$(iface_lock_claim wlan2 modD "$i1"); rc=$?
    chk stale-reclaim-rc     "$rc" 0
    chk stale-reclaim-iface  "$(cut -f1 "$IFACE_LOCK")" wlan2
    chk stale-reclaim-module "$(cut -f2 "$IFACE_LOCK")" modD
    iface_lock_release wlan2 "$i1" >/dev/null

    # 8. usage errors
    iface_lock_claim onlyone >/dev/null 2>&1; chk claim-usage-rc "$?" 2

    # 9. --kill-pid: GONE and KILLED are distinct; a survivor must be an error
    iface_kill_pid >/dev/null 2>&1;  chk killpid-usage-rc "$?" 2
    iface_kill_pid 0 >/dev/null 2>&1; chk killpid-zero-rc  "$?" 2
    out=$(iface_kill_pid "$i2"); rc=$?
    chk killpid-gone-rc   "$rc" 0
    chk killpid-gone-says "$(printf '%s\n' "$out" | cut -f1)" GONE

    # Our own process: INT/TERM ignored, so this exercises the escalation to
    # KILL and the /proc-based confirmation that it actually died.
    (
        bash -c 'trap "" INT TERM; while :; do sleep 0.2; done' &
        local p=$!
        sleep 0.3
        local o r
        o=$(iface_kill_pid "$p" 2>/dev/null); r=$?
        printf 'stubborn-rc\t%s\nstubborn-says\t%s\n' "$r" "$(printf '%s\n' "$o" | cut -f1)"
        [[ -d "/proc/$p" ]] && printf 'stubborn-alive\t1\n' || printf 'stubborn-alive\t0\n'
    ) > "$MOD_TMP/kill.out" 2>/dev/null
    chk killpid-stubborn-rc    "$(cut -f2 "$MOD_TMP/kill.out" | head -1)" 0
    chk killpid-stubborn-says  "$(sed -n '2p' "$MOD_TMP/kill.out" | cut -f2)" KILLED
    chk killpid-stubborn-dead  "$(sed -n '3p' "$MOD_TMP/kill.out" | cut -f2)" 0

    # The bug this guards: `kill -0` returns EPERM for a root-owned process,
    # so a liveness test built on it reports a live holder as already dead.
    # (Static guard: an EPERM process is not creatable without root here.)
    local body; body=$(declare -f stop_kill_pid | grep -v '^[[:space:]]*#')
    chk liveness-uses-proc \
        "$(printf '%s\n' "$body" | grep -c -- '-d "/proc/\$pid"' | awk '{print ($1>0)?"yes":"no"}')" yes
    chk liveness-no-kill0  "$(printf '%s\n' "$body" | grep -c -- 'kill -0')" 0

    # 10. watcher stop is idempotent and clears a stale pidfile
    out=$(iface_watch_stop); rc=$?
    chk watch-stop-nopid-rc   "$rc" 0
    chk watch-stop-nopid-says "$(printf '%s\n' "$out" | cut -f1)" STOPPED
    printf '%s\n' "$i2" > "$IFACE_WATCH_PID"
    out=$(iface_watch_stop); rc=$?
    chk watch-stop-stale-rc "$rc" 0
    if [[ -e "$IFACE_WATCH_PID" ]]; then
        printf 'watch-stop-stale-clears\tFAIL (pidfile kept)\n'; bad=$((bad+1))
    else printf 'watch-stop-stale-clears\tPASS\n'; fi

    IFACE_LOCK="$saved_lock"
    IFACE_WATCH_PID="$saved_watch"
    rm -rf "$MOD_TMP"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

iface_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --list-tsv)         iface_cli_list_tsv ;;
        --caps-tsv)         iface_caps_tsv "$@" ;;
        --kill-conflicts)   iface_kill_conflicts ;;
        --monitor-on)       SELECTED_IFACE="$1"; iface_monitor_on ;;
        --ap-on)            SELECTED_IFACE="$1"; iface_ap_on ;;
        --ap-off)           SELECTED_IFACE="$1"; iface_ap_off "$1" ;;
        --monitor-off)      MON_IFACE="$1"; iface_monitor_off ;;
        --restore-network)  iface_restore_net ;;
        --watch-start)      iface_watch_start "$@" ;;
        --watch-stop)       iface_watch_stop ;;
        --watch-status-tsv) iface_watch_status_tsv ;;
        --lock-claim)       iface_lock_claim "$@" ;;
        --lock-release)     iface_lock_release "$@" ;;
        --lock-status-tsv)  iface_lock_status_tsv ;;
        --kill-pid)         iface_kill_pid "$1" ;;
        --context-tsv)      iface_cli_context_tsv "$1" ;;
        --selftest)         iface_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --list-tsv
  --caps-tsv IFACE
  --kill-conflicts
  --ap-on IFACE                 put an interface into AP mode
  --ap-off IFACE                back to managed
  --monitor-on IFACE
  --monitor-off IFACE
  --restore-network
  --watch-start IFACE [INTERVAL]
  --watch-stop
  --watch-status-tsv
  --lock-claim IFACE MODULE [PID]
  --lock-release [IFACE] [OWNER_PID]
  --lock-status-tsv
  --kill-pid PID
  --context-tsv [IFACE]
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
    iface_cli_main "$@"
fi

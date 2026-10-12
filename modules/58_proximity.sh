#!/usr/bin/env bash
# =====================================================================
#  58_proximity.sh — presence watch
#
#  Watch for devices by MAC and act when they arrive or leave.
#
#  This is the one thing in the toolkit that runs for hours rather than
#  seconds. Everything else is a scan or an attack with a beginning and
#  an end; this holds state between polls and fires when that state
#  changes.
#
#  WHY IT IS ITS OWN MODULE
#  It is not identification (30_fingerprint answers "what is this
#  device") and not intrusion detection (14_wifi_ids answers "is someone
#  attacking me"). It answers "tell me when this device appears" - a
#  continuous watch with a trigger. It also spans Wi-Fi and Bluetooth,
#  so filing it under either radio would be wrong.
#
#  WHAT IT IS FOR
#  Knowing when someone arrives. Whether that is a colleague at a desk,
#  a device that should not be in a building, or your own hardware
#  turning up in a place it should not be. It is also the honest half of
#  the tracking story: the same technique that follows a person can tell
#  you that you are being followed.
#
#  DETECTION
#    Wi-Fi      probe requests on a monitor interface. A device announces
#               itself constantly while looking for known networks.
#    Bluetooth  inquiry scan via hcitool, if an adapter is present.
#
#  Authorised use only. Watching for a device is surveillance; do it to
#  your own equipment, or where you have permission to.
# =====================================================================

set -uo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
WIFISTING_ROOT="${WIFISTING_ROOT:-$(cd -P "$(dirname "$SELF")/.." && pwd)}"
export WIFISTING_ROOT

TMP_DIR="${TMP_DIR:-/tmp/wifisting}"
PX_DIR="$TMP_DIR/proximity"
PX_LOOT="${PX_LOOT:-$WIFISTING_ROOT/loot/proximity}"
PX_WATCH="$PX_DIR/watchlist.tsv"
PX_STATE="$PX_DIR/state.tsv"
PX_EVENTS="$PX_LOOT/events.tsv"
PX_PID="$PX_DIR/monitor.pid"
PX_LOG="$PX_LOOT/monitor.log"

mkdir -p "$PX_DIR" "$PX_LOOT" 2>/dev/null
# Create if absent, never truncate. `: > file` at startup wiped the
# watchlist on every invocation, so --watch reported ADDED and the next
# command saw an empty list. The module could not hold state at all,
# which is the one thing it exists to do.
[[ -f "$PX_WATCH" ]] || : > "$PX_WATCH" 2>/dev/null || true
[[ -f "$PX_STATE" ]] || : > "$PX_STATE" 2>/dev/null || true

info() { printf '[info] %s\n' "$*" >&2; }
warn() { printf '[warn] %s\n' "$*" >&2; }

px_mac_ok() { [[ "${1,,}" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; }

# ── watchlist ─────────────────────────────────────────────────────────
px_watch_add() {
    local mac="${1:-}" label="${2:-}"
    px_mac_ok "$mac" || {
        printf 'ERROR\tnot a MAC address: %s\n' "${mac:-<empty>}" >&2
        printf 'ERROR\tuse the form aa:bb:cc:dd:ee:ff\n' >&2
        return 2
    }
    mac="${mac,,}"
    label="${label:-$mac}"

    if grep -qiE "^${mac}\b" "$PX_WATCH" 2>/dev/null; then
        printf 'EXISTS\t%s\n' "$mac"
        return 0
    fi
    printf '%s\t%s\t%s\n' "$mac" "$label" "$(date +%s)" >> "$PX_WATCH"
    printf 'ADDED\t%s\t%s\n' "$mac" "$label"
}

px_watch_remove() {
    local mac="${1,,}"
    px_mac_ok "$mac" || { printf 'ERROR\tnot a MAC: %s\n' "$1" >&2; return 2; }
    local before after
    before=$(wc -l < "$PX_WATCH")
    grep -viE "^${mac}\b" "$PX_WATCH" > "$PX_WATCH.tmp" 2>/dev/null || true
    mv "$PX_WATCH.tmp" "$PX_WATCH"
    after=$(wc -l < "$PX_WATCH")
    printf 'REMOVED\t%s\n' "$(( before - after ))"
}

px_watch_list() {
    printf 'MAC\tLABEL\tADDED\tSTATE\n'
    [[ -s "$PX_WATCH" ]] || return 0
    local mac label added state
    while IFS=$'\t' read -r mac label added; do
        [[ -z "$mac" ]] && continue
        state=$(awk -F'\t' -v m="$mac" '$1 == m { print $2; exit }' "$PX_STATE" 2>/dev/null)
        printf '%s\t%s\t%s\t%s\n' "$mac" "$label" "$added" "${state:-unknown}"
    done < "$PX_WATCH"
}

# ── detection ─────────────────────────────────────────────────────────
#
# Returns one MAC per line, whichever radios are available. Both are
# best-effort: a device that is asleep or not probing is simply absent
# from this poll, which is why absence is only reported after several
# consecutive misses rather than one.
px_iface() {
    local i="${MON_IFACE:-}"
    [[ -z "$i" && -f "$TMP_DIR/mon_iface" ]] && i=$(cat "$TMP_DIR/mon_iface")
    printf '%s' "$i"
}

px_scan_wifi() {
    local iface="$1" secs="${2:-3}"
    [[ -n "$iface" && -e "/sys/class/net/$iface" ]] || return 0
    command -v tshark >/dev/null 2>&1 || return 0

    # Probe requests: subtype 4. The transmitter address is the client.
    timeout "$secs" tshark -i "$iface" -l -q \
        -Y 'wlan.fc.type_subtype == 4' \
        -T fields -e wlan.sa 2>/dev/null \
        | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' \
        | tr 'A-F' 'a-f' | sort -u
}

px_scan_bt() {
    local secs="${1:-4}"
    command -v hcitool >/dev/null 2>&1 || return 0
    hciconfig hci0 up >/dev/null 2>&1 || true
    timeout "$secs" hcitool scan 2>/dev/null \
        | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' \
        | tr 'A-F' 'a-f' | sort -u
}

px_capabilities() {
    local iface bt=no
    iface=$(px_iface)
    command -v hcitool >/dev/null 2>&1 && hciconfig 2>/dev/null | grep -q 'hci0' && bt=yes

    printf 'wifi_iface\t%s\n' "${iface:-none}"
    printf 'wifi_ready\t%s\n' "$( [[ -n "$iface" && -e "/sys/class/net/$iface" ]] && echo yes || echo no)"
    printf 'wifi_reason\t%s\n' \
        "$( [[ -n "$iface" ]] && echo 'monitor interface present' || echo 'no monitor interface - Wi-Fi watching unavailable')"
    printf 'bluetooth_ready\t%s\n' "$bt"
    printf 'bluetooth_reason\t%s\n' \
        "$( [[ "$bt" == yes ]] && echo 'adapter present' || echo 'no Bluetooth adapter')"
    printf 'tshark\t%s\n' "$(command -v tshark >/dev/null 2>&1 && echo yes || echo no)"

    if [[ -z "$iface" && "$bt" == no ]]; then
        printf 'verdict\tneither radio available - nothing can be watched\n'
    else
        printf 'verdict\tready\n'
    fi
}

# ── the monitor loop ──────────────────────────────────────────────────
#
# Absence needs debouncing. A device that stops probing for one poll has
# not necessarily left; it has gone quiet. REQUIRE_MISSES consecutive
# misses before firing a departure, so the events mean something.
PX_REQUIRE_MISSES="${PX_REQUIRE_MISSES:-3}"

px_monitor() {
    local secs="${1:-0}" interval="${2:-5}" on_appear="${3:-}" on_leave="${4:-}"
    local iface; iface=$(px_iface)

    [[ -s "$PX_WATCH" ]] || {
        printf 'ERROR\twatchlist is empty - add one with --watch MAC\n' >&2
        return 1
    }
    (( ${EUID:-$(id -u)} != 0 )) && [[ -z "${PX_UNPRIVILEGED_TEST:-}" ]] && {
        printf 'ERROR\tmonitoring needs root for monitor mode capture\n' >&2
        return 1
    }

    printf 'STARTED\t%s\n' "$$"
    printf 'IFACE\t%s\n' "${iface:-none}"
    printf 'INTERVAL_S\t%s\n' "$interval"
    printf 'WATCHING\t%s device(s)\n' "$(wc -l < "$PX_WATCH")"
    printf 'NOTE\ta departure is only reported after %s quiet polls\n' "$PX_REQUIRE_MISSES"
    : > "$PX_EVENTS"

    local deadline=0
    (( secs > 0 )) && deadline=$(( $(date +%s) + secs ))

    while :; do
        (( deadline > 0 && $(date +%s) >= deadline )) && break

        local seen
        seen=$( { px_scan_wifi "$iface" "$interval"; px_scan_bt 3; } 2>/dev/null | sort -u )

        local mac label now state misses
        now=$(date +%s)
        while IFS=$'\t' read -r mac label _added; do
            [[ -z "$mac" ]] && continue

            if grep -qx "$mac" <<<"$seen"; then
                state=$(awk -F'\t' -v m="$mac" '$1 == m { print $2 }' "$PX_STATE" 2>/dev/null)
                if [[ "$state" != "present" ]]; then
                    printf '%s\t%s\t%s\t%s\n' "$now" "$mac" "appear" "$label" >> "$PX_EVENTS"
                    printf 'EVENT\tappear\t%s\t%s\n' "$mac" "$label"
                    # Fire only on a real transition, never on every poll.
                    [[ -n "$on_appear" ]] && bash -c "$on_appear" "$mac" "$label" >/dev/null 2>&1 &
                fi
                grep -viE "^${mac}\b" "$PX_STATE" > "$PX_STATE.tmp" 2>/dev/null || true
                mv "$PX_STATE.tmp" "$PX_STATE"
                printf '%s\tpresent\t0\t%s\n' "$mac" "$now" >> "$PX_STATE"
            else
                misses=$(awk -F'\t' -v m="$mac" '$1 == m { print $3 }' "$PX_STATE" 2>/dev/null)
                misses=$(( ${misses:-0} + 1 ))
                state=$(awk -F'\t' -v m="$mac" '$1 == m { print $2 }' "$PX_STATE" 2>/dev/null)

                grep -viE "^${mac}\b" "$PX_STATE" > "$PX_STATE.tmp" 2>/dev/null || true
                mv "$PX_STATE.tmp" "$PX_STATE"

                if (( misses >= PX_REQUIRE_MISSES )) && [[ "$state" == "present" ]]; then
                    printf '%s\t%s\t%s\t%s\n' "$now" "$mac" "leave" "$label" >> "$PX_EVENTS"
                    printf 'EVENT\tleave\t%s\t%s\n' "$mac" "$label"
                    [[ -n "$on_leave" ]] && bash -c "$on_leave" "$mac" "$label" >/dev/null 2>&1 &
                    printf '%s\tabsent\t%s\t%s\n' "$mac" "$misses" "$now" >> "$PX_STATE"
                else
                    printf '%s\t%s\t%s\t%s\n' "$mac" "${state:-absent}" "$misses" "$now" >> "$PX_STATE"
                fi
            fi
        done < "$PX_WATCH"

        sleep "$interval"
    done

    printf 'STOPPED\n'
    rm -f "$PX_PID"
}

px_start() {
    local secs="${1:-0}" interval="${2:-5}"
    [[ -f "$PX_PID" ]] && [[ -d "/proc/$(cat "$PX_PID" 2>/dev/null)" ]] && {
        printf 'ERROR\talready monitoring (pid %s) - stop it first\n' "$(cat "$PX_PID")" >&2
        return 1
    }
    local on_appear on_leave
    on_appear=$(cat "$PX_DIR/on-appear.cmd" 2>/dev/null || true)
    on_leave=$(cat "$PX_DIR/on-leave.cmd" 2>/dev/null || true)

    setsid bash -c "
        echo \$\$ > '$PX_PID'
        exec '$SELF' --monitor '$secs' '$interval' '$on_appear' '$on_leave'
    " > "$PX_LOG" 2>&1 &
    sleep 2
    printf 'PID\t%s\n' "$(cat "$PX_PID" 2>/dev/null || echo unknown)"
    printf 'LOG\t%s\n' "$PX_LOG"
}

px_stop() {
    local n=0
    [[ -f "$PX_PID" ]] && {
        kill "$(cat "$PX_PID")" 2>/dev/null && n=$(( n + 1 ))
        rm -f "$PX_PID"
    }
    # Match the spawned monitor specifically; a bare 'proximity' also
    # matches this script's own path.
    pkill -f 'proximity.*--monitor' 2>/dev/null && n=$(( n + 1 ))
    printf 'STOPPED\t%s\n' "$n"
}

px_status() {
    # pid must be initialised: with set -u a bare `local pid` is unbound
    # when the pidfile is absent, and the whole function dies before it
    # prints anything.
    local pid="" running=0
    [[ -f "$PX_PID" ]] && pid=$(cat "$PX_PID" 2>/dev/null)
    [[ -n "$pid" && -d "/proc/$pid" ]] && running=1
    printf 'running\t%s\n' "$running"
    printf 'watching\t%s\n' "$( [[ -s "$PX_WATCH" ]] && wc -l < "$PX_WATCH" || echo 0)"
    printf 'events\t%s\n' "$( [[ -s "$PX_EVENTS" ]] && wc -l < "$PX_EVENTS" || echo 0)"
    px_capabilities
}

px_cli_events() {
    if [[ -s "$PX_EVENTS" ]]; then
        printf 'TIME\tMAC\tEVENT\tLABEL\n'; cat "$PX_EVENTS"
    else
        printf 'INFO\tno events recorded yet\n'
    fi
}

px_set_action() {
    local kind="${1:-}" cmd="${2:-}"
    case "$kind" in
        appear) printf '%s' "$cmd" > "$PX_DIR/on-appear.cmd"; printf 'APPEAR_ACTION\t%s\n' "${cmd:-cleared}" ;;
        leave)  printf '%s' "$cmd" > "$PX_DIR/on-leave.cmd";  printf 'LEAVE_ACTION\t%s\n' "${cmd:-cleared}" ;;
        *) printf 'ERROR\tusage: --on-appear CMD | --on-leave CMD\n' >&2; return 2 ;;
    esac
}

# ── selftest ──────────────────────────────────────────────────────────
px_selftest() {
    local bad=0
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; bad=$(( bad + 1 )); fi
    }

    # Isolate: never touch the real watchlist or event log.
    local save_w="$PX_WATCH" save_s="$PX_STATE" save_e="$PX_EVENTS"
    PX_WATCH="$PX_DIR/st-watch.tsv"; PX_STATE="$PX_DIR/st-state.tsv"; PX_EVENTS="$PX_DIR/st-events.tsv"
    : > "$PX_WATCH"; : > "$PX_STATE"; : > "$PX_EVENTS"

    px_watch_add "AA:BB:CC:00:00:01" "laptop" >/dev/null
    chk add-normalises-case "$(cut -f1 "$PX_WATCH")" "aa:bb:cc:00:00:01"
    chk add-keeps-label "$(cut -f2 "$PX_WATCH")" "laptop"

    # Adding twice must not duplicate.
    px_watch_add "aa:bb:cc:00:00:01" "laptop" >/dev/null
    chk add-idempotent "$(wc -l < "$PX_WATCH")" "1"

    # A bad MAC is a usage error, not a silent accept.
    px_watch_add "not-a-mac" >/dev/null 2>&1
    chk add-rejects-bad-mac "$?" "2"
    px_watch_add "" >/dev/null 2>&1
    chk add-rejects-empty "$?" "2"

    px_watch_add "aa:bb:cc:00:00:02" "phone" >/dev/null
    px_watch_list | tail -n +2 | wc -l | { read -r n; chk list-counts "$n" "2"; }

    px_watch_remove "aa:bb:cc:00:00:02" >/dev/null
    chk remove-works "$(wc -l < "$PX_WATCH")" "1"

    # Capability reporting must answer even with no radio.
    local out
    out=$(px_capabilities 2>&1)
    grep -q '^verdict' <<<"$out" && chk caps-has-verdict ok ok || chk caps-has-verdict no ok
    grep -q '^wifi_ready' <<<"$out" && chk caps-reports-wifi ok ok || chk caps-reports-wifi no ok

    # An empty watchlist must refuse to start rather than monitor nothing.
    # The list still holds one entry from the removal test above, so empty
    # it first - otherwise this asserts against a populated list and the
    # refusal path is never reached.
    : > "$PX_WATCH"
    out=$(PX_UNPRIVILEGED_TEST=1 px_monitor 1 1 "" "" 2>&1)
    grep -q 'watchlist is empty' <<<"$out" && chk empty-watchlist-refused ok ok \
                                          || chk empty-watchlist-refused no ok

    # Actions are stored and readable back.
    px_set_action appear "echo hi" >/dev/null
    chk action-appear-stored "$(cat "$PX_DIR/on-appear.cmd")" "echo hi"
    px_set_action leave "echo bye" >/dev/null
    chk action-leave-stored "$(cat "$PX_DIR/on-leave.cmd")" "echo bye"
    px_set_action bogus x >/dev/null 2>&1
    chk action-rejects-bad-kind "$?" "2"

    # Status answers with no state at all.
    out=$(px_status 2>&1)
    grep -q '^running' <<<"$out" && chk status-answers ok ok || chk status-answers no ok

    PX_WATCH="$save_w"; PX_STATE="$save_s"; PX_EVENTS="$save_e"
    rm -f "$PX_DIR/st-"*.tsv "$PX_DIR/on-appear.cmd" "$PX_DIR/on-leave.cmd"
    printf 'RESULT\t%s\n' "$( (( bad == 0 )) && echo PASS || echo "FAIL($bad)" )"
    return $(( bad > 0 ))
}

case "${1:-}" in
    --watch)      shift; px_watch_add "$@" ;;
    --unwatch)    shift; px_watch_remove "$@" ;;
    --list-tsv)   px_watch_list ;;
    --caps-tsv)   px_capabilities ;;
    --start)      shift; px_start "$@" ;;
    --monitor)    shift; px_monitor "$@" ;;
    --stop)       px_stop ;;
    --status-tsv) px_status ;;
    --events-tsv) px_cli_events ;;
    --on-appear)  shift; px_set_action appear "${1:-}" ;;
    --on-leave)   shift; px_set_action leave "${1:-}" ;;
    --selftest)   px_selftest ;;
    --info)
        printf 'Presence watch: act when a device arrives or leaves.\n'
        printf 'Watches Wi-Fi probe requests and Bluetooth inquiry.\n'
        printf 'Runs for hours and holds state, unlike every other module.\n'
        printf 'Authorised use only - watching for a device is surveillance.\n' ;;
    --help|"")
        printf 'Usage: modules/58_proximity.sh COMMAND\n'
        printf '  --watch MAC [LABEL]     add a device to the watchlist\n'
        printf '  --unwatch MAC           remove one\n'
        printf '  --list-tsv              the watchlist and current state\n'
        printf '  --caps-tsv              which radios are available\n'
        printf '  --start [SECS] [INTERVAL_S]\n'
        printf '  --on-appear CMD / --on-leave CMD\n'
        printf '  --events-tsv / --status-tsv / --stop / --selftest\n' ;;
    *) printf 'ERROR\tunknown command: %s\n' "$1" >&2; exit 2 ;;
esac

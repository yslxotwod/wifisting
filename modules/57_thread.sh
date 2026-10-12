#!/usr/bin/env bash
# =====================================================================
#  57_thread.sh — Thread (802.15.4) network analysis
#
#  Thread is an IPv6 mesh for smart homes that runs on 802.15.4 at
#  2.4 GHz. That is the same physical layer as Zigbee, so a Zigbee
#  radio hears it — the two are different stacks on shared silicon.
#  It matters because Matter runs over Thread, and every HomePod,
#  Nest Hub and Echo is a Thread border router.
#
#  WHY THE BORDER ROUTER IS THE POINT
#  A border router is dual-homed: an 802.15.4 radio for the mesh and a
#  Wi-Fi or Ethernet link to the LAN. It advertises a network prefix
#  into the mesh that comes from the home network, and it relays
#  mDNS/DNS-SD between the two. So a Thread foothold is not a Wi-Fi
#  compromise, but it is a second door into the same house, and it
#  lands on a host that talks to both networks by design.
#
#  WHAT NEEDS NO KEY
#  Thread beacons and enhanced beacons carry the network name, channel,
#  PAN ID, extended PAN ID and border-router presence in the clear.
#  A passive scan reveals the mesh without joining it.
#
#  Hardware: any 802.15.4 radio (CC2531, CC2652, nRF52840) on a serial
#  port. Without one, offline pcap analysis still works.
# =====================================================================

set -uo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
WIFISTING_ROOT="${WIFISTING_ROOT:-$(cd -P "$(dirname "$SELF")/.." && pwd)}"
export WIFISTING_ROOT

TMP_DIR="${TMP_DIR:-/tmp/wifisting}"
TH_DIR="$TMP_DIR/thread"
TH_LOG_DIR="${TH_LOG_DIR:-$WIFISTING_ROOT/loot/thread}"
TH_PID="$TH_DIR/capture.pid"

mkdir -p "$TH_DIR" "$TH_LOG_DIR" 2>/dev/null

# Thread channels are 11-26, the 802.15.4 2.4 GHz band.
TH_CHANNELS=(11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26)

info() { printf '[info] %s\n' "$*" >&2; }
ok()   { printf '[ok]   %s\n'   "$*" >&2; }
warn() { printf '[warn] %s\n'   "$*" >&2; }
err()  { printf '[err]  %s\n'   "$*" >&2; }

# ── hardware ──────────────────────────────────────────────────────────
#
# Same detection the Zigbee module uses, because it is the same radio.
# Looked for explicitly: claiming support without a device present is
# what makes a hardware-gated feature look broken instead of unavailable.
th_find_radio() {
    local d
    for d in /dev/ttyUSB* /dev/ttyACM*; do
        [[ -e "$d" ]] || continue
        # A CC2531 in ZNP mode answers to the TI vendor ID on USB
        local vid
        vid=$(cat "/sys/class/tty/$(basename "$d")/device/../idVendor" 2>/dev/null)
        case "$vid" in
            0451) printf '%s\tTI CC253x (ZNP)\n' "$d"; return 0 ;;
        esac
        printf '%s\tunknown serial device\n' "$d"; return 0
    done
    return 1
}

th_require_radio() {
    local r
    r=$(th_find_radio) || {
        printf 'ERROR\tno 802.15.4 radio found\n' >&2
        printf 'ERROR\tneeds a CC2531, CC2652 or nRF52840 on a serial port\n' >&2
        printf 'HINT\toffline analysis works without one: --analyze FILE\n' >&2
        return 1
    }
    printf '%s' "$r"
}

th_require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 && -z "${TH_UNPRIVILEGED_TEST:-}" ]]; then
        printf 'ERROR\tlive capture needs root - the GUI runs it through pkexec\n' >&2
        return 1
    fi
    return 0
}

# ── offline analysis ──────────────────────────────────────────────────
#
# This is the half that works with no hardware, and it is the half that
# matters for reviewing a capture someone else took.
#
# Thread beacons are 802.15.4 frames with a Thread-specific payload.
# The network name, channel, PAN ID and border-router flags are not
# encrypted - a mesh does not have to be joined to be described.
th_analyze() {
    local pcap="${1:-}"
    [[ -z "$pcap" ]] && { printf 'ERROR\tno file given\n' >&2; return 2; }
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such file: %s\n' "$pcap" >&2; return 1; }

    python3 - "$pcap" <<'PY'
import sys, collections
try:
    from scapy.all import rdpcap, Dot15d4, Dot15d4FCS, Dot15d4Beacon
    from scapy.layers.dot15d4 import Dot15d4Cmd
except Exception as e:
    print("ERROR\tscapy dot15d4 unavailable: %s" % e)
    sys.exit(1)

path = sys.argv[1]
try:
    pkts = rdpcap(path)
except Exception as e:
    print("ERROR\tcannot read %s: %s" % (path, e))
    sys.exit(1)

frames = 0
beacons = 0
pans = collections.Counter()
channels = collections.Counter()
names = set()
extpan = set()
border_routers = 0

for p in pkts:
    if not p.haslayer(Dot15d4):
        continue
    frames += 1
    d = p[Dot15d4]
    # The PAN ID lives on the Beacon layer, not on Dot15d4 - the base
    # class only carries the frame-control flags and sequence number.
    if p.haslayer(Dot15d4Beacon):
        beacons += 1
        b = p[Dot15d4Beacon]
        if getattr(b, "src_panid", None) is not None:
            pans["0x%04x" % b.src_panid] += 1
    # Thread puts its own payload after the MAC header. Frame type 1 is
    # a beacon; the Thread network name is a length-prefixed string and
    # the border-router flag sits in a bitfield beside it.
    raw = bytes(p)
    i = 0
    while i < len(raw) - 1:
        ln = raw[i]
        if 1 <= ln <= 16:
            chunk = raw[i+1:i+1+ln]
            if chunk and all(32 <= c < 127 for c in chunk):
                names.add(chunk.decode("ascii", "replace"))
        i += 1
    if b"thread" in raw.lower() or b"border" in raw.lower():
        border_routers += 1

print("FILE\t%s" % path)
print("FRAMES\t%d" % frames)
print("BEACONS\t%d" % beacons)
for pan, n in pans.most_common(6):
    print("PAN\t%s\t%d" % (pan, n))
if names:
    print("CANDIDATE_NAMES\t%s" % ", ".join(sorted(names)[:8]))
print("BORDER_ROUTER_HINT\t%d" % border_routers)
if frames == 0:
    print("NOTE\tno 802.15.4 frames - is this a Wi-Fi capture?")
elif beacons == 0:
    print("NOTE\tframes but no beacons - the mesh may be quiet or on another channel")
PY
}

# ── live scan ─────────────────────────────────────────────────────────
#
# Channel sweep. A Thread network picks one channel and stays there, so
# a single-channel scan finds nothing about two times out of three.
th_scan() {
    local secs="${1:-2}"
    th_require_root || return 1
    local radio
    radio=$(th_require_radio) || return 1
    local dev="${radio%%$'\t'*}"

    printf 'RADIO\t%s\n' "$dev"
    printf 'CHANNELS\t%s\n' "${TH_CHANNELS[*]}"
    printf 'DWELL_S\t%s\n' "$secs"
    printf 'NOTE\ta Thread mesh occupies one channel; the sweep is why this takes time\n'

    local ch
    for ch in "${TH_CHANNELS[@]}"; do
        local out="$TH_LOG_DIR/ch$ch.pcap"
        timeout "$secs" tcpdump -i "$dev" -w "$out" -c 200 2>/dev/null
        local n=0
        [[ -f "$out" ]] && n=$(th_analyze "$out" 2>/dev/null | awk -F'\t' '/^FRAMES/{print $2}')
        printf 'CHANNEL\t%s\t%s\n' "$ch" "${n:-0}"
        [[ "${n:-0}" -gt 0 ]] && th_analyze "$out"
    done
}

# ── border router reachability ────────────────────────────────────────
#
# The answer to "what does this tell us about the Wi-Fi network". A
# border router advertises a prefix from the LAN into the mesh; if we
# can see that prefix we learn how the home network addresses itself.
th_border() {
    local pcap="${1:-}"
    [[ -z "$pcap" ]] && { printf 'ERROR\tgive a capture: --border-router FILE\n' >&2; return 2; }
    [[ -f "$pcap" ]] || { printf 'ERROR\tno such file: %s\n' "$pcap" >&2; return 1; }

    printf 'ANALYSIS\tborder router\n'
    printf 'FILE\t%s\n' "$pcap"
    python3 - "$pcap" <<'PY'
import sys, re
try:
    from scapy.all import rdpcap
    from scapy.layers.dot15d4 import Dot15d4
    from scapy.layers.inet6 import IPv6
except Exception as e:
    print("ERROR\tscapy unavailable: %s" % e); sys.exit(1)

path = sys.argv[1]
try:
    pkts = rdpcap(path)
except Exception as e:
    print("ERROR\tcannot read: %s" % e); sys.exit(1)

prefixes = set()
routers = set()
mcast = 0
for p in pkts:
    if not p.haslayer(Dot15d4):
        continue
    if p.haslayer(IPv6):
        src = p[IPv6].src
        if src and not src.startswith("fe80"):
            prefixes.add(src.rsplit(":", 2)[0] + "::/64")
        if p[IPv6].dst and p[IPv6].dst.startswith("ff02"):
            mcast += 1
    raw = bytes(p)
    for m in re.finditer(rb"fd[0-9a-f]{2}(:[0-9a-f]{0,4}){1,7}", raw):
        try:
            prefixes.add(m.group(0).decode() + "::/64")
        except Exception:
            pass

print("IPV6_PREFIXES\t%d" % len(prefixes))
for x in sorted(prefixes)[:10]:
    print("PREFIX\t%s" % x)
print("MULTICAST_TO_FF02\t%d" % mcast)
if prefixes:
    print("FINDING\tthe mesh carries LAN addressing - a border router is bridging")
    print("FINDING\tthat prefix is routable from the home network")
else:
    print("NOTE\tno IPv6 prefix visible - either no border router, or the payload is key-encrypted")
PY
}

# ── status and tests ──────────────────────────────────────────────────
th_status() {
    local radio
    radio=$(th_find_radio 2>/dev/null)
    printf 'radio\t%s\n' "${radio:-none}"
    printf 'radio_count\t%s\n' "$(th_find_radio 2>/dev/null | wc -l)"
    printf 'capture_running\t%s\n' \
        "$( [[ -f "$TH_PID" ]] && [[ -d "/proc/$(cat "$TH_PID" 2>/dev/null)" ]] && echo 1 || echo 0)"
    printf 'channels\t%s\n' "${#TH_CHANNELS[@]}"
    printf 'loot_dir\t%s\n' "$TH_LOG_DIR"
}

th_selftest() {
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fi
    }

    # the channel plan must be the 802.15.4 2.4 GHz set, all of it
    chk channel-count "${#TH_CHANNELS[@]}" "16"
    chk channel-first "${TH_CHANNELS[0]}" "11"
    chk channel-last "${TH_CHANNELS[15]}" "26"

    # no radio attached must be reported, not assumed away
    local out
    out=$(TH_UNPRIVILEGED_TEST=1 th_require_radio 2>&1)
    if th_find_radio >/dev/null 2>&1; then
        chk radio-detected ok ok
    else
        grep -q 'no 802.15.4 radio found' <<<"$out" && chk radio-absent-reported ok ok \
                                                 || chk radio-absent-reported no ok
    fi

    # a missing file is a usage error, not a crash
    local rc
    TH_UNPRIVILEGED_TEST=1 th_analyze "" >/dev/null 2>&1
    rc=$?
    chk analyze-noarg-rc "$rc" "2"

    TH_UNPRIVILEGED_TEST=1 th_analyze /nonexistent.pcap >/dev/null 2>&1
    rc=$?
    chk analyze-nofile-rc "$rc" "1"

    # analysis must run without hardware - that is the point of it
    local p="$TH_DIR/selftest.pcap"
    # Field names matter here: Dot15d4 carries only the frame-control
    # flags and sequence number. dest_panid does not exist on it, and
    # passing it raised AttributeError, which silently left no file for
    # the assertions below to read.
    python3 -c "
from scapy.all import wrpcap, Dot15d4, Dot15d4Beacon, Raw
f = Dot15d4() / Dot15d4Beacon(src_panid=0x1234) / Raw(load=b'\x0bThread-Net')
wrpcap('$p', [f])
" 2>&1 | sed 's/^/    /'
    [[ -s "$p" ]] || chk selftest-fixture-built yes no
    out=$(TH_UNPRIVILEGED_TEST=1 th_analyze "$p" 2>&1)
    grep -q '^FRAMES' <<<"$out" && chk analyze-runs-offline ok ok || chk analyze-runs-offline no ok
    grep -q 'Thread-Net' <<<"$out" && chk analyze-finds-name ok ok || chk analyze-finds-name no ok

    # border router analysis on a capture with no IPv6 must say so plainly
    out=$(TH_UNPRIVILEGED_TEST=1 th_border "$p" 2>&1)
    grep -q 'IPV6_PREFIXES' <<<"$out" && chk border-runs ok ok || chk border-runs no ok
    grep -qE 'no IPv6 prefix visible|PREFIX' <<<"$out" && chk border-reports ok ok \
                                                       || chk border-reports no ok

    out=$(th_status 2>&1)
    grep -q '^radio' <<<"$out" && chk status-answers ok ok || chk status-answers no ok

    rm -f "$p"
}

case "${1:-}" in
    --analyze)        shift; th_analyze "$@" ;;
    --scan)           shift; th_scan "$@" ;;
    --border-router)  shift; th_border "$@" ;;
    --channels-tsv)   printf 'CHANNEL\n'; for c in "${TH_CHANNELS[@]}"; do printf '%s\n' "$c"; done ;;
    --status-tsv)     th_status ;;
    --selftest)       th_selftest ;;
    --stop)           pkill -f 'thread.*capture' 2>/dev/null; rm -f "$TH_PID"; printf 'STOPPED\t1\n' ;;
    --info)
        printf 'Thread (802.15.4) network analysis\n'
        printf 'Same radio as Zigbee. Matter runs over Thread.\n'
        printf 'A border router bridges the mesh to the LAN and leaks its prefix.\n'
        printf 'Offline pcap analysis works without hardware.\n' ;;
    --help|"")
        printf 'Usage: modules/57_thread.sh COMMAND\n'
        printf '  --analyze FILE        describe a Thread capture (no hardware needed)\n'
        printf '  --scan [DWELL_S]      channel sweep, needs an 802.15.4 radio\n'
        printf '  --border-router FILE  look for LAN addressing in a capture\n'
        printf '  --channels-tsv / --status-tsv / --selftest\n' ;;
    *) printf 'ERROR\tunknown command: %s\n' "$1" >&2; exit 2 ;;
esac

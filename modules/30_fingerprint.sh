#!/usr/bin/env bash
# 30_fingerprint.sh — client fingerprinting, correlation, sequence tracking
set -u

# Resolve WIFISTING_ROOT from this script's own path so state/loot land
# in the project tree even when launched standalone via pkexec (which
# resets HOME to /root and would otherwise put the DB in the wrong place).
if [[ -z "${WIFISTING_ROOT:-}" ]]; then
    _fp_src="${BASH_SOURCE[0]}"
    while [ -L "$_fp_src" ]; do
        _fp_dir="$(cd -P "$(dirname "$_fp_src")" && pwd)"
        _fp_tgt="$(readlink "$_fp_src")"
        [[ "$_fp_tgt" != /* ]] && _fp_tgt="$_fp_dir/$_fp_tgt"
        _fp_src="$_fp_tgt"
    done
    WIFISTING_ROOT="$(cd -P "$(dirname "$_fp_src")/.." && pwd)"
    export WIFISTING_ROOT
    unset _fp_src _fp_dir _fp_tgt
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

TMP="${TMP_DIR:-/tmp/wifisting}"
FP="$TMP/fingerprint"
STATE="${WIFISTING_ROOT}/state"
LOOT="${WIFISTING_ROOT}/loot/fingerprint"
DB="$STATE/fingerprint.db"
PIDF="$FP/sniff.pid"
# Iface arbitration lives in the interface module; called as a CLI so we
# never need to source shared code (there is no shared lib in modules/).
IFACE_MODULE="$WIFISTING_ROOT/modules/01_iface.sh"
STATUS="$FP/start.status"

mkdir -p "$FP" "$STATE" "$LOOT"

# ── retention: how many days of observation/seqnum history to keep ──
FP_RETENTION_DAYS="${FP_RETENTION_DAYS:-7}"

fp_init_db() {
    local v
    v=$(sqlite3 "$DB" "PRAGMA user_version;" 2>/dev/null || echo 0)
    if [ "$v" -ge 2 ]; then
        return
    fi

    sqlite3 "$DB" <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS clients (
    mac TEXT PRIMARY KEY,
    first_seen INTEGER,
    last_seen INTEGER,
    randomized INTEGER DEFAULT 0,
    vendor TEXT,
    fp_hash TEXT,
    fp_ies TEXT,
    probed_ssids TEXT,
    channels TEXT,
    device_guess TEXT
);
CREATE TABLE IF NOT EXISTS observations (mac TEXT, ts INTEGER, ch INTEGER, rssi INTEGER);
CREATE TABLE IF NOT EXISTS probed (mac TEXT, ssid TEXT, ts INTEGER);
CREATE TABLE IF NOT EXISTS seqnums (mac TEXT, sn INTEGER, ts INTEGER);
CREATE TABLE IF NOT EXISTS rates (mac TEXT, rate REAL, ts INTEGER);

CREATE TABLE IF NOT EXISTS ble_clients (
    mac TEXT PRIMARY KEY,
    first_seen INTEGER,
    last_seen INTEGER,
    addr_type TEXT,
    local_name TEXT,
    appearance INTEGER,
    tx_power INTEGER,
    mfg_company TEXT,
    mfg_data TEXT,
    service_uuids TEXT,
    fp_hash TEXT,
    best_rssi INTEGER
);

CREATE TABLE IF NOT EXISTS cross_domain (
    wifi_mac TEXT,
    ble_mac TEXT,
    confidence INTEGER,
    reason TEXT,
    ts INTEGER,
    PRIMARY KEY (wifi_mac, ble_mac)
);

CREATE INDEX IF NOT EXISTS idx_clients_lastseen ON clients(last_seen);
CREATE INDEX IF NOT EXISTS idx_clients_fp ON clients(fp_hash);
CREATE INDEX IF NOT EXISTS idx_obs_ts ON observations(ts);
CREATE INDEX IF NOT EXISTS idx_seq_ts ON seqnums(ts);
CREATE INDEX IF NOT EXISTS idx_ble_lastseen ON ble_clients(last_seen);
SQL

    # Add new columns idempotently. ALTER errors on duplicate; ignore.
    local col
    for col in \
        "ht_caps TEXT" \
        "vht_caps TEXT" \
        "he_caps TEXT" \
        "ext_caps TEXT" \
        "supp_rates TEXT" \
        "rsn_caps TEXT" \
        "country TEXT" \
        "vendor_ouis TEXT" \
        "first_ie_seen INTEGER" \
    ; do
        sqlite3 "$DB" "ALTER TABLE clients ADD COLUMN $col" 2>/dev/null || true
    done

    sqlite3 "$DB" "PRAGMA user_version=2;"
}

# ── retention/pruning ──
fp_prune() {
    local days="${1:-$FP_RETENTION_DAYS}"
    [ -f "$DB" ] || return 0
    sqlite3 "$DB" <<SQL
PRAGMA journal_mode=WAL;
DELETE FROM observations WHERE ts < strftime('%s','now','-$days days');
DELETE FROM seqnums      WHERE ts < strftime('%s','now','-$days days');
DELETE FROM probed       WHERE ts < strftime('%s','now','-$days days');
DELETE FROM rates        WHERE ts < strftime('%s','now','-$days days');
SQL
}

# ── better device heuristics ──
fp_device_from_ies() {
    local ies="$1" ssids="$2" randomized="$3"

    # IE-based identification (most reliable)
    case "$ies" in
        *0017f2*)                 echo "Apple"; return ;;
        *0050f2*)                 echo "Windows"; return ;;
        *00164c*)                 echo "Android/Chrome"; return ;;
        *00a0c6*)                 echo "Intel WiFi"; return ;;
        *506f9a*)                 echo "Wi-Fi Alliance test"; return ;;
    esac

    # Probed-SSID based
    case "$ssids" in
        *iPhone*|*iPad*|*iCloud*|*AirPort*|*Apple*)   echo "Apple (ssid)"; return ;;
        *Galaxy*|*Android*|*SAMSUNG*|*Pixel*)          echo "Android (ssid)"; return ;;
        *Windows*|*"<hidden>"*)                        echo "Windows (ssid)"; return ;;
        *Kindle*|*Fire*)                               echo "Amazon (ssid)"; return ;;
        *Roku*|*Chromecast*|*"Smart TV"*)              echo "TV (ssid)"; return ;;
    esac

    # Randomized + nothing else to go on
    if [ "$randomized" = "1" ]; then
        echo "Randomized device"
        return
    fi

    echo "Unknown"
}


# ── DHCP fingerprint ────────────────────────────────────────────────────
# Option 55 (parameter request list) is the classic passive OS fingerprint,
# option 60 (vendor class) frequently names the OS and version outright, and
# option 12 is often the device's own name. None of it is encrypted, and
# unlike probe requests it survives MAC randomisation because DHCP happens
# after association.

# ── shared tshark field query ───────────────────────────────────────────
# Surfaces tshark's stderr instead of discarding it. A mistyped field name
# makes tshark print nothing at all, which is otherwise indistinguishable
# from a capture that genuinely contains no matching traffic - that exact
# confusion cost three debugging rounds on the DHCP verb.
fp_tshark() {
    local pcap="$1" filter="$2"; shift 2
    local ef; ef=$(mktemp 2>/dev/null) || ef=/dev/null
    local args=() f out err
    for f in "$@"; do args+=(-e "$f"); done
    out=$(tshark -r "$pcap" -Y "$filter" -T fields -E separator='|' \
          "${args[@]}" 2>"$ef")
    err=$(grep -viE '^Running as user|^Capturing on|packets? captured|^$' \
          "$ef" 2>/dev/null | head -2)
    rm -f "$ef"
    if [[ -n "$err" ]]; then
        # A capture cut short mid-packet is routine for an interrupted run.
        # tshark still emits everything it parsed before the cut, so that is a
        # warning rather than a failure; anything else is fatal.
        if [[ "$err" == *"cut short"* ]]; then
            printf 'WARN\tcapture is truncated - analysing what was readable\n' >&2
        else
            printf 'ERR\ttshark: %s\n' "$err" >&2
            return 1
        fi
    fi
    printf '%s\n' "$out"
}

# ── DHCP option 55 (parameter request list) ─────────────────────────────
# The ordering of this list is the strongest passive OS fingerprint there is,
# and this tshark build exposes no queryable field for it - so it is read out
# of the verbose dissection instead. One row per client, list in wire order.
fp_dhcp_opt55_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --dhcp-opt55-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || { printf 'ERR\ttshark is required\n' >&2; return 1; }

    local out n=0 mac="" list="" line
    out=$(tshark -r "$pcap" -Y 'dhcp.option.dhcp == 1' -V 2>/dev/null)
    [[ -n "$out" ]] || { printf 'DHCP_OPT55\tnone\tno DHCP requests\n'; return 1; }

    while IFS= read -r line; do
        case "$line" in
            *"Client MAC address:"*)
                # flush the previous client
                if [[ -n "$mac" ]]; then
                    printf 'DHCP_OPT55\t%s\t%s\n' "$mac" "${list%,}"
                    n=$((n+1))
                fi
                # tshark renders this as "aa:bb:.. (aa:bb:..)"; keep one copy.
                mac=$(printf '%s' "$line" | sed 's/.*Client MAC address: *//' \
                      | sed 's/ *(.*//' | tr -d ' ')
                list=""
                ;;
            *"Parameter Request List Item:"*)
                # "(15) Domain Name" -> keep the option number only: the
                # numeric sequence is the fingerprint, the names are noise.
                local num
                num=$(printf '%s' "$line" | sed -n 's/.*(\([0-9]\+\)).*/\1/p')
                [[ -n "$num" ]] && list="${list}${num},"
                ;;
        esac
    done <<< "$out"
    if [[ -n "$mac" ]]; then
        printf 'DHCP_OPT55\t%s\t%s\n' "$mac" "${list%,}"
        n=$((n+1))
    fi
    printf 'COUNT\t%d client(s)\n' "$n"
}

# ── mDNS / Bonjour ──────────────────────────────────────────────────────
# Service names give the device class; TXT records frequently carry the exact
# model ("model=AppleTV6,2"). mDNS is DNS on 5353, so the dns.* fields apply.
fp_mdns_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --mdns-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }

    local out rows seen=0
    out=$(fp_tshark "$pcap" 'udp.port == 5353' \
            ip.src dns.qry.name dns.resp.name dns.txt) || return 1
    if [[ -z "$out" ]]; then
        printf 'MDNS\tnone\tno mDNS traffic in %s\n' "$pcap"
        return 1
    fi
    while IFS='|' read -r ip q r txt; do
        [[ -n "$ip$q$r$txt" ]] || continue
        printf 'MDNS\t%s\t%s\t%s\t%s\n' "${ip:--}" "${q:--}" "${r:--}" "${txt:--}"
        seen=$((seen+1))
    done <<< "$out"
    printf 'COUNT\t%d record(s)\n' "$seen"
}

# ── DNS fingerprint ─────────────────────────────────────────────────────
# Where a device phones home at boot identifies it even through encrypted
# traffic, and attributes IoT kit to a vendor without touching the payload.
fp_dns_fp_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --dns-fp-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }

    local out n=0
    out=$(fp_tshark "$pcap" 'dns.flags.response == 0 && udp.port == 53 && ip.src != 0.0.0.0' \
            ip.src dns.qry.name) || return 1
    if [[ -z "$out" ]]; then
        printf 'DNS_FP\tnone\tno outbound DNS queries in %s\n' "$pcap"
        return 1
    fi
    # Collected to a file first: a counter incremented inside a pipeline runs
    # in a subshell and silently stays zero.
    local tmp; tmp=$(mktemp 2>/dev/null) || tmp=/dev/null
    while IFS='|' read -r ip name; do
        [[ -n "$name" ]] || continue
        printf 'DNS_FP\t%s\t%s\n' "${ip:--}" "$name" >> "$tmp"
    done <<< "$out"
    sort -u "$tmp"
    n=$(sort -u "$tmp" | grep -c .)
    [[ "$tmp" != /dev/null ]] && rm -f "$tmp"
    printf 'COUNT\t%d query name(s)\n' "$n"
}

# ── TLS JA3 ─────────────────────────────────────────────────────────────
# A JA3 hash is a stable per-client-stack fingerprint: the same OS and TLS
# library produce the same hash across devices and across sessions.
fp_ja3_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --ja3-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }

    local out n=0
    out=$(fp_tshark "$pcap" 'tls.handshake.type == 1' \
            ip.src tls.handshake.ja3 tls.handshake.extensions_server_name) || return 1
    if [[ -z "$out" ]]; then
        printf 'JA3\tnone\tno TLS ClientHello in %s\n' "$pcap"
        return 1
    fi
    while IFS='|' read -r ip ja3 sni; do
        [[ -n "$ja3" ]] || continue
        printf 'JA3\t%s\t%s\t%s\n' "${ip:--}" "$ja3" "${sni:--}"
        n=$((n+1))
    done <<< "$out"
    printf 'COUNT\t%d ClientHello(s)\n' "$n"
}

# ── HTTP User-Agent ─────────────────────────────────────────────────────
# Captive-portal probes are the giveaway: "CaptiveNetworkSupport" is Apple,
# "Microsoft NCSI" is Windows, and Android announces its version in the UA.
fp_ua_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --ua-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }

    local out n=0
    out=$(fp_tshark "$pcap" 'http.user_agent' \
            ip.src http.host http.user_agent) || return 1
    if [[ -z "$out" ]]; then
        printf 'HTTP_UA\tnone\tno plaintext HTTP User-Agent in %s\n' "$pcap"
        return 1
    fi
    while IFS='|' read -r ip host ua; do
        [[ -n "$ua" ]] || continue
        printf 'HTTP_UA\t%s\t%s\t%s\n' "${ip:--}" "${host:--}" "$ua"
        n=$((n+1))
    done <<< "$out"
    printf 'COUNT\t%d request(s)\n' "$n"
}


# ── WPS information element ─────────────────────────────────────────────
# The richest identity source in any beacon: WPS carries Manufacturer, Model
# Name, Model Number, Device Name and Serial Number as plain attributes. It
# is left enabled on a great many consumer APs because the label-based setup
# depends on it. device_password_id matters too: 0 means the PIN is the
# default one printed on the device, which is the whole Pixie Dust premise.
fp_wps_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --wps-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }

    local out n=0
    out=$(fp_tshark "$pcap" \
            'wps.manufacturer || wps.model_name || wps.device_name || wps.serial_number' \
            wlan.bssid wps.manufacturer wps.model_name wps.model_number \
            wps.device_name wps.serial_number wps.device_password_id) || return 1

    if [[ -z "$out" ]]; then
        printf 'WPS\tnone\tno WPS information elements in %s\n' "$pcap"
        return 1
    fi
    local bssid man mdl num dev ser dpid
    while IFS='|' read -r bssid man mdl num dev ser dpid; do
        [[ -n "$man$mdl$dev$ser" ]] || continue
        printf 'WPS\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${bssid:--}" "${man:--}" "${mdl:--}" "${num:--}" \
            "${dev:--}" "${ser:--}" "${dpid:--}"
        n=$((n+1))
    done <<< "$out"
    printf 'COUNT\t%d WPS IE(s)\n' "$n"
    [[ -n "$out" ]] && printf 'WPS_NOTE\tdevice_password_id 0 = default PIN from the label; that is the Pixie Dust precondition\n'
}

# ── vendor-specific information elements ────────────────────────────────
# IE 221 with a vendor OUI. The OUI set an AP emits is itself a fingerprint:
# Apple silicon, Cisco/Aruba/Ruckus infrastructure, and the Wi-Fi Alliance
# WMM/WPA3 IEs all announce themselves here.
fp_vendor_oui_name() {
    case "$1" in
        00:50:f2)                  printf 'microsoft-or-wfa' ;;
        00:17:f2)                  printf 'apple' ;;
        00:40:96)                  printf 'cisco' ;;
        00:0c:41|00:1a:1e|00:24:6c) printf 'aruba' ;;
        00:13:92|00:1f:e5)         printf 'ruckus' ;;
        50:6f:9a)                  printf 'wi-fi-alliance' ;;
        00:0f:e2|00:e0:fc)         printf 'huawei' ;;
        00:0c:43|00:0e:8e)         printf 'mediatek-ralink' ;;
        00:10:18)                  printf 'broadcom' ;;
        *)                         printf 'unknown' ;;
    esac
}

fp_vendor_ie_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --vendor-ie-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }

    local out
    out=$(fp_tshark "$pcap" 'wlan.tag.number == 221' wlan.bssid wlan.tag.oui) || return 1
    if [[ -z "$out" ]]; then
        printf 'VENDOR_IE\tnone\tno vendor-specific IEs in %s\n' "$pcap"
        return 1
    fi

    # Aggregate: which OUIs each BSSID emits is more useful than raw frames.
    # wlan.tag.oui arrives as a decimal 24-bit integer (20722 = 0x0050F2) and
    # a single frame can carry several, comma-joined. Both had to be handled
    # or every OUI resolves to "unknown".
    oui_hex() {
        local n="$1"
        [[ "$n" =~ ^[0-9]+$ ]] || { printf '%s' "$n"; return; }
        printf '%02x:%02x:%02x' $(( (n >> 16) & 255 )) $(( (n >> 8) & 255 )) $(( n & 255 ))
    }

    local tmp; tmp=$(mktemp 2>/dev/null) || tmp=/dev/null
    local bssid ouis one
    while IFS='|' read -r bssid ouis; do
        [[ -n "$ouis" ]] || continue
        IFS=',' read -ra arr <<< "$ouis"
        for one in "${arr[@]}"; do
            [[ -n "$one" ]] || continue
            printf '%s\t%s\n' "${bssid:--}" "$(oui_hex "$one")" >> "$tmp"
        done
    done <<< "$out"
    local n=0
    while IFS=$'\t' read -r bssid oui cnt; do
        printf 'VENDOR_IE\t%s\t%s\t%s\t%s\n' "$bssid" "$oui" \
            "$(fp_vendor_oui_name "$oui")" "$cnt"
        n=$((n+1))
    done < <(sort "$tmp" | uniq -c | awk '{print $2"\t"$3"\t"$1}')
    [[ "$tmp" != /dev/null ]] && rm -f "$tmp"
    printf 'COUNT\t%d distinct BSSID/OUI pair(s)\n' "$n"
}

# ── association request IEs ─────────────────────────────────────────────
# Probes are sent before association and are often stripped down; the
# association request carries the full capability set. Extended capabilities
# has no queryable field in this build, so 802.11k/r/v are detected by the
# presence of their information elements instead:
#   54  Mobility Domain      (802.11r fast transition)
#   70  RM Enabled Caps      (802.11k radio measurement)
#   127 Extended Capabilities
fp_assoc_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --assoc-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }

    local out
    # wlan.fixed.capabilities.radio_measurement is the actual 802.11k bit in
    # the capability field; IE 70 is only its advertisement. 802.11v has no
    # queryable field in this build, so it stays IE-presence only.
    out=$(fp_tshark "$pcap" 'wlan.fc.type_subtype == 0' \
            wlan.sa wlan.bssid wlan.tag.number \
            wlan.fixed.capabilities.radio_measurement) || return 1
    if [[ -z "$out" ]]; then
        printf 'ASSOC\tnone\tno association requests in %s\n' "$pcap"
        return 1
    fi

    local tmp; tmp=$(mktemp 2>/dev/null) || tmp=/dev/null
    local sa bssid tags rmbit
    while IFS='|' read -r sa bssid tags rmbit; do
        [[ -n "$sa" ]] || continue
        local k='' r='' v='' t
        IFS=',' read -ra arr <<< "$tags"
        for t in "${arr[@]}"; do
            case "$t" in
                54)  r=yes ;;
                70)  k=yes ;;
                # the capability bit is authoritative when present
                *)   [[ "$rmbit" == "1" || "$rmbit" == "True" ]] && k=yes ;;
                127) v=yes ;;
            esac
        done
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$sa" "${bssid:--}" \
            "${k:--}" "${r:--}" "${v:--}" "${tags:--}" >> "$tmp"
    done <<< "$out"
    sort -u "$tmp"
    local n; n=$(sort -u "$tmp" | grep -c .)
    [[ "$tmp" != /dev/null ]] && rm -f "$tmp"
    printf 'COUNT\t%d association request(s)\n' "$n"
    printf 'ASSOC_NOTE\tcolumns: client, bssid, 802.11k, 802.11r, ext-cap-IE, IE numbers in wire order\n'
}


# ── multi-source corroboration ──────────────────────────────────────────
# Every signal above is weak on its own. Joined per device they identify it:
# DHCP says which OS, mDNS says which product, DNS says which vendor cloud it
# trusts, JA3 says which TLS stack, and the User-Agent says which captive
# portal client. Agreement across independent sources is the whole point -
# any one of them alone is a guess.
#
# MAC and IP are joined through ARP, because DHCP keys on the hardware
# address while mDNS/DNS/TLS/HTTP key on the IP.
fp_vendor_guess_from_dns() {
    case "$1" in
        *apple.com|*icloud.com|*mzstatic*)   printf 'apple' ;;
        *gstatic.com|*google.com|*googleapis*) printf 'google' ;;
        *miui.com|*xiaomi*)                  printf 'xiaomi' ;;
        *samsung*)                           printf 'samsung' ;;
        *a2z.com|*amazon*)                   printf 'amazon' ;;
        *msftconnecttest*|*microsoft*)       printf 'microsoft' ;;
        *)                                   printf '-' ;;
    esac
}

fp_guess_from_ua() {
    case "$1" in
        *CaptiveNetworkSupport*|*Darwin*) printf 'apple' ;;
        *Android*)                        printf 'google' ;;
        *NCSI*|*Windows*)                 printf 'microsoft' ;;
        *)                                printf '-' ;;
    esac
}

fp_guess_from_class() {
    case "$1" in
        android*)  printf 'google' ;;
        windows*)  printf 'microsoft' ;;
        ios)       printf 'apple' ;;
        *)         printf '-' ;;
    esac
}

fp_corroborate_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --corroborate-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }

    local tmp; tmp=$(mktemp 2>/dev/null) || { printf 'ERR\tmktemp failed\n' >&2; return 1; }
    local ip2mac="$tmp.ip" ev="$tmp.ev"

    # IP -> MAC from ARP replies and DHCP leases.
    fp_tshark "$pcap" 'arp.opcode == 2' arp.src.proto_ipv4 arp.src.hw_mac \
        2>/dev/null | awk -F'|' 'NF==2 && $1!="" {print $1"\t"$2}' >> "$ip2mac"
    fp_tshark "$pcap" 'dhcp.option.dhcp == 5' bootp.hw.mac_addr dhcp.ip.your \
        2>/dev/null | awk -F'|' 'NF==2 && $1!="" {print $2"\t"$1}' >> "$ip2mac"

    local mac_of
    mac_of() {
        local ip="$1" m
        m=$(awk -F'\t' -v i="$ip" '$1==i{print $2; exit}' "$ip2mac" 2>/dev/null)
        [[ -n "$m" ]] && printf '%s' "${m,,}" || printf '%s' "$ip"
    }

    local mac cls host
    while IFS='|' read -r mac cls host; do
        [[ -n "$mac" ]] || continue
        printf '%s\t%s\tdhcp\t%s\n' "${mac,,}" "$(fp_guess_from_class "$cls")" "class=$cls host=${host:--}" >> "$ev"
    done < <(fp_tshark "$pcap" 'dhcp.option.dhcp == 1' bootp.hw.mac_addr \
                dhcp.option.vendor_class_id dhcp.option.hostname 2>/dev/null)

    local ip name
    while IFS='|' read -r ip name; do
        [[ -n "$ip" && -n "$name" ]] || continue
        printf '%s\t%s\tmdns\t%s\n' "$(mac_of "$ip")" \
            "$(case "$name" in *_googlecast*|*_airplay*|*_raop*) printf 'apple-or-google' ;; *) printf '-' ;; esac)" \
            "$name" >> "$ev"
    done < <(fp_tshark "$pcap" 'udp.port == 5353' ip.src dns.qry.name 2>/dev/null)

    while IFS='|' read -r ip name; do
        [[ -n "$ip" && -n "$name" ]] || continue
        local g; g=$(fp_vendor_guess_from_dns "$name")
        [[ "$g" == "-" ]] && continue
        printf '%s\t%s\tdns\t%s\n' "$(mac_of "$ip")" "$g" "$name" >> "$ev"
    done < <(fp_tshark "$pcap" 'dns.flags.response == 0 && udp.port == 53' ip.src dns.qry.name 2>/dev/null)

    while IFS='|' read -r ip ua; do
        [[ -n "$ip" && -n "$ua" ]] || continue
        local g; g=$(fp_guess_from_ua "$ua")
        [[ "$g" == "-" ]] && continue
        printf '%s\t%s\tua\t%s\n' "$(mac_of "$ip")" "$g" "${ua:0:40}" >> "$ev"
    done < <(fp_tshark "$pcap" 'http.user_agent' ip.src http.user_agent 2>/dev/null)

    while IFS='|' read -r ip ja3; do
        [[ -n "$ip" && -n "$ja3" ]] || continue
        printf '%s\t-\tja3\t%s\n' "$(mac_of "$ip")" "${ja3:0:16}" >> "$ev"
    done < <(fp_tshark "$pcap" 'tls.handshake.type == 1' ip.src tls.handshake.ja3 2>/dev/null)

    if [[ ! -s "$ev" ]]; then
        printf 'CORROBORATE\tnone\tno fingerprintable traffic in %s\n' "$pcap"
        rm -f "$ip2mac" "$ev"; return 1
    fi

    printf 'CORROBORATE\tdevice\tverdict\tsources\tevidence\n'
    local dev
    while IFS= read -r dev; do
        # Which vendors do the sources agree on? The most-named wins, and the
        # count is reported so a single-source guess is visibly weak.
        local top cnt total
        top=$(awk -F'\t' -v d="$dev" '$1==d && $2!="-" && $2!="apple-or-google"{print $2}' "$ev" \
              | sort | uniq -c | sort -rn | awk 'NR==1{print $2}')
        cnt=$(awk -F'\t' -v d="$dev" -v t="$top" '$1==d && $2==t' "$ev" | wc -l)
        total=$(awk -F'\t' -v d="$dev" '$1==d' "$ev" | wc -l)
        [[ -z "$top" ]] && top="-"
        printf 'CORROBORATE\t%s\t%s\t%s/%s\t%s\n' "$dev" "$top" "$cnt" "$total" \
            "$(awk -F'\t' -v d="$dev" '$1==d{printf "%s(%s) ", $3, $4}' "$ev" | cut -c1-90)"
    done < <(cut -f1 "$ev" | sort -u)

    rm -f "$ip2mac" "$ev"
}

fp_dhcp_class() {
    case "$1" in
        MSFT*|*Windows*)   printf 'windows' ;;
        android-dhcp-*)    printf 'android-%s' "${1#android-dhcp-}" ;;
        udhcp*)            printf 'embedded-iot' ;;
        dhcpcd*|dhclient*) printf 'linux' ;;
        *ndroid*)          printf 'android' ;;
        *iPhone*|*iPad*)   printf 'ios' ;;
        "")                printf 'no-vendor-class' ;;
        *)                 printf 'unclassified' ;;
    esac
}

fp_dhcp_fp_tsv() {
    local pcap="${1:-}"
    [[ -n "$pcap" ]] || { printf 'ERR\tusage: --dhcp-fp-tsv CAPTURE\n' >&2; return 2; }
    [[ -s "$pcap" ]] || { printf 'ERR\tno such capture: %s\n' "$pcap" >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || { printf 'ERR\ttshark is required\n' >&2; return 1; }

    local rows n=0
    # bootp.hw.mac_addr, not dhcp.hw.mac_addr: the latter does not exist and
    # asking for it yields no rows at all rather than an error.
    rows=$(fp_tshark "$pcap" 'dhcp.option.dhcp == 1' \
            bootp.hw.mac_addr dhcp.option.vendor_class_id \
            dhcp.option.hostname) || return 1

    if [[ -z "$rows" ]]; then
        printf 'DHCP_FP\tnone\tno DHCP requests in %s\n' "$pcap"
        return 1
    fi

    local mac vc host prl cls
    while IFS='|' read -r mac vc host prl; do
        [[ -n "$mac" ]] || continue
        cls=$(fp_dhcp_class "$vc")
        printf 'DHCP_FP\t%s\t%s\t%s\t%s\n' \
            "$mac" "$cls" "${vc:--}" "${host:--}"
        n=$((n+1))
    done <<< "$rows"
    printf 'COUNT\t%d device(s)\n' "$n"
}

fp_feeder() {
    local buf="" n=0

    # prune once per hour, opportunistically
    local last_prune_file="$FP/.last_prune"
    local now
    now=$(date +%s)
    local last_prune=0
    [ -f "$last_prune_file" ] && last_prune=$(cat "$last_prune_file")
    if (( now - last_prune > 3600 )); then
        fp_prune "$FP_RETENTION_DAYS"
        echo "$now" > "$last_prune_file"
    fi

    while IFS='|' read -r ts mac type sn ssid ch rssi rate caps ies \
                             ht vht he ext sup rsn country vouis; do
        [ -z "${mac:-}" ] && continue
        [ "$mac" = "ff:ff:ff:ff:ff:ff" ] && continue
        [ "$mac" = "00:00:00:00:00:00" ] && continue

        local t=$((type))
        local rat=0
        local first2="${mac:0:2}"
        local nn=$((16#$first2))
        [ $((nn & 2)) -ne 0 ] && rat=1

        local hash=""
        if [ -n "${caps:-}" ] || [ -n "${ies:-}" ]; then
            hash=$(printf '%s|%s' "$caps" "$ies" | md5sum | cut -c1-16)
        fi

        local ts_int="${ts%.*}"
        [ -z "$ts_int" ] && ts_int=$(date +%s)

        local ies_clean="${caps:-}|${ies:-}"
        local ssid_sql="${ssid//\'/\'\'}"
        local ies_sql="${ies_clean//\'/\'\'}"
        local mac_sql="${mac//\'/\'\'}"

        # SQL-escape every new field
        local ht_sql="${ht//\'/\'\'}"
        local vht_sql="${vht//\'/\'\'}"
        local he_sql="${he//\'/\'\'}"
        local ext_sql="${ext//\'/\'\'}"
        local sup_sql="${sup//\'/\'\'}"
        local rsn_sql="${rsn//\'/\'\'}"
        local country_sql="${country//\'/\'\'}"
        local vouis_sql="${vouis//\'/\'\'}"
        local now_int
        now_int=$(date +%s)

        # Extend the fingerprint hash to include structured fields.
        # Two clients whose IE blob hash differs only because a vendor
        # IE was reordered will now hash the same, because we hash
        # ht|vht|he|ext|sup|rsn|caps instead of the raw blob.
        local fp_struct="$ht|$vht|$he|$ext|$sup|$rsn|$caps"
        local fp2
        fp2=$(printf '%s' "$fp_struct" | md5sum | cut -c1-16)

        buf+="INSERT INTO clients (mac, first_seen, last_seen, randomized, fp_hash, fp_ies, channels, ht_caps, vht_caps, he_caps, ext_caps, supp_rates, rsn_caps, country, vendor_ouis, first_ie_seen) VALUES ('$mac_sql', $ts_int, $ts_int, $rat, '$fp2', '$ies_sql', '$ch', '$ht_sql', '$vht_sql', '$he_sql', '$ext_sql', '$sup_sql', '$rsn_sql', '$country_sql', '$vouis_sql', $now_int) ON CONFLICT(mac) DO UPDATE SET last_seen=$ts_int, fp_hash=excluded.fp_hash, channels=excluded.channels, ht_caps=CASE WHEN excluded.ht_caps != '' THEN excluded.ht_caps ELSE ht_caps END, vht_caps=CASE WHEN excluded.vht_caps != '' THEN excluded.vht_caps ELSE vht_caps END, he_caps=CASE WHEN excluded.he_caps != '' THEN excluded.he_caps ELSE he_caps END, ext_caps=CASE WHEN excluded.ext_caps != '' THEN excluded.ext_caps ELSE ext_caps END, supp_rates=CASE WHEN excluded.supp_rates != '' THEN excluded.supp_rates ELSE supp_rates END, rsn_caps=CASE WHEN excluded.rsn_caps != '' THEN excluded.rsn_caps ELSE rsn_caps END, country=CASE WHEN excluded.country != '' THEN excluded.country ELSE country END, vendor_ouis=CASE WHEN excluded.vendor_ouis != '' THEN excluded.vendor_ouis ELSE vendor_ouis END;"

        # Observations cap — only insert one per mac per 60s
        buf+="INSERT INTO observations (mac, ts, ch, rssi) SELECT '$mac_sql', $ts_int, $ch, ${rssi:-0} WHERE NOT EXISTS (SELECT 1 FROM observations WHERE mac='$mac_sql' AND ts > $ts_int - 60);"

        # Sequence numbers: cap at one per mac per 10s to avoid explosion
        if [ -n "${sn:-}" ] && [ "$sn" != "" ]; then
            buf+="INSERT INTO seqnums (mac, sn, ts) SELECT '$mac_sql', $sn, $ts_int WHERE NOT EXISTS (SELECT 1 FROM seqnums WHERE mac='$mac_sql' AND ts > $ts_int - 10);"
        fi
        if [ -n "${rate:-}" ] && [ "$rate" != "" ]; then
            buf+="INSERT INTO rates (mac, rate, ts) VALUES ('$mac_sql', $rate, $ts_int);"
        fi

        if [ "$t" = "4" ] && [ -n "${ssid:-}" ] && [ "$ssid" != "" ]; then
            buf+="INSERT INTO probed (mac, ssid, ts) VALUES ('$mac_sql', '$ssid_sql', $ts_int);"
            buf+="UPDATE clients SET probed_ssids = COALESCE(NULLIF(probed_ssids || ',', ''), '') || '$ssid_sql' WHERE mac='$mac_sql' AND (probed_ssids IS NULL OR probed_ssids NOT LIKE '%$ssid_sql%');"
        fi

        n=$((n+1))
        if [ $n -ge 30 ]; then
            { echo "PRAGMA journal_mode=WAL;"; echo "BEGIN;"; echo "$buf"; echo "COMMIT;"; } | \
                sqlite3 -cmd ".timeout 10000" "$DB" 2>/dev/null
            buf=""; n=0
        fi
    done
    if [ -n "$buf" ]; then
        { echo "PRAGMA journal_mode=WAL;"; echo "BEGIN;"; echo "$buf"; echo "COMMIT;"; } | \
            sqlite3 -cmd ".timeout 10000" "$DB" 2>/dev/null
    fi
}

# ── channel control ──
# The AR9271 (and most single-band adapters) see exactly one channel at
# a time. Locking to a channel with no APs means the sniffer captures
# silence; the DB stays empty even though tshark is running fine. These
# helpers give the GUI a way to pick a channel or auto-hop across 2.4.

fp_get_channel() {
    local iface="$1"
    [ -z "$iface" ] && return 2
    iw dev "$iface" info 2>/dev/null | awk '/channel/ {print $2; exit}'
}

fp_hop_start() {
    local iface="$1" interval="${2:-0.5}"
    local pidfile="$FP/hop.pid"
    [ -z "$iface" ] && { printf 'ERR\tmissing iface\n' >&2; return 2; }

    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        printf 'ERR\thop already running\n'
        return 1
    fi

    # 2.4 GHz channels 1-13. AR9271 is 2.4-only so we don't try 5 GHz.
    setsid bash -c '
        iface="'"$iface"'"
        interval="'"$interval"'"
        while true; do
            for ch in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
                iw dev "$iface" set channel "$ch" 2>/dev/null || true
                sleep "$interval"
            done
        done
    ' >/dev/null 2>&1 &

    echo $! > "$pidfile"
    printf 'HOPPING\t%s\tinterval=%s\n' "$(cat "$pidfile")" "$interval"
}



fp_hop_status_tsv() {
    local pidfile="$FP/hop.pid"
    local running=0 pid=""
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        kill -0 "$pid" 2>/dev/null && running=1
    fi
    printf 'running\t%s\n' "$running"
    printf 'pid\t%s\n'     "$pid"
}

# ── channel control ──
# Most single-band adapters (AR9271, RT5370, etc.) see exactly one
# channel at a time. If we're pinned to a quiet channel the capture is
# silent and the DB stays empty even though tshark is running fine.

fp_set_channel() {
    local iface="$1" ch="$2"
    [ -z "$iface" ] && { printf 'ERR\tmissing iface\n' >&2; return 2; }
    [ -z "$ch"    ] && { printf 'ERR\tmissing channel\n' >&2; return 2; }

    # Diagnosed from iw's own error rather than a sysfs pre-check: wlx* names
    # come from the adapter MAC, so spoofing it or replugging renames the
    # adapter and a name recorded earlier then points at nothing - which used
    # to be reported as a plain channel failure. Interpreting iw keeps the
    # reason authoritative and still works against a stubbed iw in --selftest.
    local iwerr
    if iwerr=$(iw dev "$iface" set channel "$ch" 2>&1); then
        printf '%s\n' "$ch" > "$FP/channel"
        printf 'OK\t%s\t%s\n' "$iface" "$ch"
    else
        case "$iwerr" in
            *"No such device"*|*"no such device"*)
                printf 'ERR\tinterface %s does not exist - adapter renamed or unplugged?\n' "$iface" >&2 ;;
            *)
                if [[ -n "$iwerr" ]]; then
                    printf 'ERR\tcould not set %s to channel %s: %s\n' \
                        "$iface" "$ch" "$iwerr"
                else
                    printf 'ERR\tcould not set %s to channel %s\n' "$iface" "$ch"
                fi ;;
        esac
        return 1
    fi
}

fp_get_channel() {
    local iface="$1"
    [ -z "$iface" ] && return 2
    iw dev "$iface" info 2>/dev/null | awk '/channel/ {print $2; exit}'
}

fp_hop_start() {
    local iface="$1" interval="${2:-0.5}"
    local pidfile="$FP/hop.pid"
    [ -z "$iface" ] && { printf 'ERR\tmissing iface\n' >&2; return 2; }
    if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        printf 'ERR\thop already running\n'
        return 1
    fi
    setsid bash -c '
        iface="'"$iface"'"
        interval="'"$interval"'"
        while true; do
            for ch in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
                iw dev "$iface" set channel "$ch" 2>/dev/null || true
                sleep "$interval"
            done
        done
    ' >/dev/null 2>&1 &
    echo $! > "$pidfile"
    printf 'HOPPING\t%s\tinterval=%s\n' "$(cat "$pidfile")" "$interval"
}

fp_hop_stop() {
    local pidfile="$FP/hop.pid"
    local pid=""
    [ -f "$pidfile" ] && pid=$(cat "$pidfile")
    if [[ -n "$pid" ]]; then
        if stop_kill_pid "$pid"; then
            rm -f "$pidfile"
            printf 'STOPPED\t%s\n' "$pid"
            return 0
        fi
        printf 'ERROR\thopper pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
}

fp_start() {
    local iface="$1"

    : > "$STATUS"

    if [ -z "$iface" ]; then
        echo "ERR no interface specified" | tee "$STATUS" >&2
        exit 1
    fi
    if [ ! -e "/sys/class/net/$iface" ]; then
        echo "ERR interface does not exist: $iface" | tee "$STATUS" >&2
        exit 1
    fi
    command -v tshark  >/dev/null 2>&1 || {
        echo "ERR tshark missing" | tee "$STATUS" >&2; exit 1; }
    command -v sqlite3 >/dev/null 2>&1 || {
        echo "ERR sqlite3 missing" | tee "$STATUS" >&2; exit 1; }

    # Live capture needs raw socket access. Without this check the failure
    # surfaces as "tshark: Couldn't run dumpcap in child process: Permission
    # denied", which reads like a capture or interface fault.
    if [ "$(id -u)" != "0" ]; then
        echo "ERR needs root: live capture requires raw socket access (dumpcap)" \
            | tee "$STATUS" >&2
        echo "HINT run via the GUI, or: pkexec $(readlink -f "$0") --start $iface" >&2
        exit 1
    fi

    # Arbitrate the adapter FIRST — before touching monitor mode or running
    # the pre-flight capture, so a busy iface reports cleanly instead of
    # surfacing as a confusing tshark capture error.
    # $$ is correct here: fp_start IS the long-lived capture process.
    if [[ -x "$IFACE_MODULE" ]]; then
        local lk_out
        if ! lk_out=$("$IFACE_MODULE" --lock-claim "$iface" \
                          "30_fingerprint" $$ 2>&1); then
            echo "ERR interface busy: $lk_out" | tee "$STATUS" >&2
            exit 1
        fi
        FP_LOCK_HELD=1
        FP_LOCK_IFACE="$iface"
        # Release on ANY later exit: pre-flight failures exit directly and
        # would otherwise leave a ghost lock behind.
        trap '"$IFACE_MODULE" --lock-release "$FP_LOCK_IFACE" $$ >/dev/null 2>&1' EXIT
    fi

    local mode
    mode=$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2}')
    if [ -z "$mode" ]; then
        echo "ERR not a wireless interface: $iface" | tee "$STATUS" >&2
        exit 1
    fi

    # Put the iface into monitor mode ourselves if it isn't already.
    # tshark 4.x rejects -I when the iface is already monitor ("That device
    # doesn't support monitor mode"), so we must NOT pass -I to tshark at
    # all when it's already monitor. Doing the switch here makes the state
    # deterministic regardless of what else touches the iface.
    if [ "$mode" != "monitor" ]; then
        ip link set "$iface" down 2>/dev/null
        iw dev "$iface" set type monitor 2>/dev/null
        ip link set "$iface" up 2>/dev/null
        sleep 0.3
        mode=$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2}')
    fi

    case "$mode" in
        monitor) ;;
        *) echo "ERR could not set $iface to monitor mode (still '$mode')" \
               | tee "$STATUS" >&2
           exit 1 ;;
    esac

    fp_init_db

    # Pre-flight: run the REAL capture command line for 1.2s. Any
    # invalid -e field, missing capability, or iface error surfaces
    # before we write OK. We also verify every field exists via
    # `tshark -G fields`, so a renamed field is caught even if it
    # happens to be accepted silently by an older tshark.
    rm -f "$FP/tshark.err" "$FP/fields.checked"

    # Field validation. ONE `tshark -G fields` call for all fields, parsed
    # in a single awk pass. The previous per-field loop issued ten
    # separate -G calls, each dumping ~300k lines, which is why the
    # script appeared to hang on startup.
    local fields="frame.time_epoch wlan.sa wlan.fc.type_subtype wlan.seq wlan.ssid wlan_radio.channel wlan_radio.signal_dbm wlan_radio.data_rate wlan.fixed.capabilities wlan.tagged.all"
    local missing
    missing=$(tshark -G fields 2>/dev/null | awk -F'\t' -v want="$fields" '
        BEGIN { n = split(want, arr, " "); for (i=1; i<=n; i++) need[arr[i]]=1 }
        $3 in need { need[$3]=0 }
        END { for (k in need) if (need[k]) printf "%s ", k }
    ')
    if [ -n "$missing" ]; then
        echo "ERR tshark does not know these fields: $missing" > "$STATUS"
        exit 1
    fi

    timeout 1.2 tshark -i "$iface" -q -c 999999 \
        2>"$FP/tshark.err" >/dev/null
    local pf_rc=$?

    # timeout returns 124 when it had to signal tshark. That is expected
    # and means tshark was happily capturing. Anything else is a real
    # failure.
    if [ "$pf_rc" -ne 0 ] && [ "$pf_rc" -ne 124 ]; then
        local em
        em=$(head -c 400 "$FP/tshark.err" 2>/dev/null | tr '\n' ' ')
        echo "ERR tshark: ${em:-exited rc=$pf_rc}" > "$STATUS"
        exit 1
    fi

    echo "OK iface=$iface mode=$mode" > "$STATUS"
    echo $$ > "$PIDF"

    # Real capture. No -I. Iface is already monitor; tshark just opens it.
    stdbuf -oL tshark -i "$iface" -n -l \
        -Y 'wlan.fc.type_subtype == 0x0004 or wlan.fc.type_subtype == 0x0000 or wlan.fc.type_subtype == 0x0002 or wlan.fc.type == 0x0002' \
        -T fields -E 'separator=|' -E 'occurrence=f' \
        -e frame.time_epoch \
        -e wlan.sa \
        -e wlan.fc.type_subtype \
        -e wlan.seq \
        -e wlan.ssid \
        -e wlan_radio.channel \
        -e wlan_radio.signal_dbm \
        -e wlan_radio.data_rate \
        -e wlan.fixed.capabilities \
        -e wlan.tagged.all \
        -e wlan.ht.capabilities \
        -e wlan.vht.capabilities \
        -e wlan.he.capabilities \
        -e wlan.extcap \
        -e wlan.supported_rates \
        -e wlan.rsn.capabilities \
        -e wlan.country_info \
        -e wlan.tag.vendor.oui \
        2>>"$FP/tshark.err" | awk -F'|' 'BEGIN{OFS="|"} { while (NF < 19) $0 = $0 OFS; print }' | fp_feeder

    rm -f "$PIDF"
    [[ -n "${FP_LOCK_HELD:-}" ]] && \
        "$IFACE_MODULE" --lock-release "$FP_LOCK_IFACE" $$ >/dev/null 2>&1
    exit 0
}

fp_stop() {
    local pid="" killed=0
    [ -s "$PIDF" ] && pid=$(<"$PIDF")

    if [[ -n "$pid" ]]; then
        pkill -TERM -P "$pid" 2>/dev/null
        stop_kill_pid "$pid" && killed=1
        # Release the iface lock with the CAPTURE's pid. Owner-checked, so it
        # is a no-op if another module has since taken the lock. Must NOT be
        # gated on FP_LOCK_HELD: --stop is a separate process where that is
        # unset, which previously leaked the lock on every manual stop.
        [[ -x "$IFACE_MODULE" ]] && \
            "$IFACE_MODULE" --lock-release "" "$pid" >/dev/null 2>&1
    fi

    # Also tear down the BLE feeder if it's running
    [ -f "$FP/ble.pid" ] && fp_ble_stop >/dev/null 2>&1 || true

    if (( killed == 1 )); then
        rm -f "$PIDF"
        echo "STOPPED"
        return 0
    fi
    if [[ -n "$pid" ]]; then
        echo "ERR capture pid $pid survived SIGKILL (pidfile kept)"
        return 1
    fi
    echo "ERR no pid file"
    return 1
}

fp_status() {
    fp_init_db
    sqlite3 "$DB" <<'SQL' 2>/dev/null
SELECT 'clients', COUNT(*) FROM clients
UNION ALL SELECT 'random', COUNT(*) FROM clients WHERE randomized=1
UNION ALL SELECT 'probes', COUNT(*) FROM probed
UNION ALL SELECT 'unique_ssids', COUNT(DISTINCT ssid) FROM probed
UNION ALL SELECT 'observations', COUNT(*) FROM observations
UNION ALL SELECT 'seqnums', COUNT(*) FROM seqnums
UNION ALL SELECT 'ble_clients', COUNT(*) FROM ble_clients
UNION ALL SELECT 'ble_named', COUNT(*) FROM ble_clients WHERE local_name != ''
UNION ALL SELECT 'cross_domain', COUNT(*) FROM cross_domain
UNION ALL SELECT 'correlations', (
    SELECT COUNT(*) FROM (
        SELECT c1.mac, c2.mac FROM clients c1, clients c2
        WHERE c1.mac<c2.mac AND c1.fp_hash=c2.fp_hash AND c1.fp_hash IS NOT NULL
    )
);
SQL
}

fp_list_clients() {
    fp_init_db
    sqlite3 -separator $'\t' "$DB" <<'SQL' 2>/dev/null
SELECT mac,
  datetime(last_seen, 'unixepoch', 'localtime'),
  CASE randomized WHEN 1 THEN 'rand' ELSE 'real' END,
  CASE
    WHEN fp_ies LIKE '%0017f2%' THEN 'Apple'
    WHEN fp_ies LIKE '%0050f2%' THEN 'Windows'
    WHEN fp_ies LIKE '%00164c%' THEN 'Android/Chrome'
    WHEN probed_ssids LIKE '%iPhone%' THEN 'Apple (ssid)'
    WHEN probed_ssids LIKE '%Android%' OR probed_ssids LIKE '%Galaxy%' THEN 'Android (ssid)'
    WHEN randomized=1 THEN 'Unknown randomized'
    ELSE 'Unknown'
  END,
  COALESCE(NULLIF(probed_ssids,''), '-'),
  COALESCE(NULLIF(channels,''), '-')
FROM clients
ORDER BY last_seen DESC
LIMIT 300;
SQL
}

fp_probe_one() {
    local mac="$1"
    [ -z "$mac" ] && { echo "ERR no mac" >&2; exit 1; }
    fp_init_db
    sqlite3 "$DB" <<SQL 2>/dev/null
.mode tabs
SELECT 'mac',           mac FROM clients WHERE mac='$mac';
SELECT 'first_seen',    datetime(first_seen,'unixepoch','localtime') FROM clients WHERE mac='$mac';
SELECT 'last_seen',     datetime(last_seen, 'unixepoch','localtime') FROM clients WHERE mac='$mac';
SELECT 'randomized',    CASE randomized WHEN 1 THEN 'yes (locally administered)' ELSE 'no' END FROM clients WHERE mac='$mac';
SELECT 'fp_hash',       COALESCE(fp_hash,'-') FROM clients WHERE mac='$mac';
SELECT 'channels',      COALESCE(channels,'-') FROM clients WHERE mac='$mac';
SELECT 'probed_ssids',  COALESCE(probed_ssids,'-') FROM clients WHERE mac='$mac';
SELECT 'observations',  COUNT(*) FROM observations WHERE mac='$mac';
SELECT 'seq_range',     printf('%d..%d', MIN(sn), MAX(sn)) FROM seqnums WHERE mac='$mac';
SELECT 'seq_count',     COUNT(*) FROM seqnums WHERE mac='$mac';
SELECT 'max_rate',      COALESCE(MAX(rate), 0) FROM rates WHERE mac='$mac';
SELECT 'ie_blob',       COALESCE(SUBSTR(fp_ies, 1, 300), '-') FROM clients WHERE mac='$mac';
SQL
}

fp_probes() {
    fp_init_db
    sqlite3 -separator $'\t' "$DB" <<'SQL' 2>/dev/null
SELECT ssid, COUNT(DISTINCT mac), COUNT(*)
FROM probed GROUP BY ssid ORDER BY COUNT(*) DESC LIMIT 200;
SQL
}

fp_correlate() {
    fp_init_db
    sqlite3 -separator $'\t' "$DB" <<'SQL' 2>/dev/null
SELECT c1.mac, c2.mac, 'same fingerprint', 95
FROM clients c1 JOIN clients c2 ON c1.mac<c2.mac AND c1.fp_hash=c2.fp_hash
WHERE c1.fp_hash IS NOT NULL AND length(c1.fp_hash)>0

UNION ALL
SELECT c1.mac, c2.mac, 'shared probe set', 80
FROM clients c1 JOIN clients c2 ON c1.mac<c2.mac
  AND c1.probed_ssids=c2.probed_ssids AND c1.probed_ssids IS NOT NULL
  AND length(c1.probed_ssids)>3 AND c1.probed_ssids != c2.probed_ssids

LIMIT 200;
SQL
}

fp_rates() {
    fp_init_db
    sqlite3 -separator $'\t' "$DB" <<'SQL' 2>/dev/null
SELECT c.mac,
  printf('%.1f', COALESCE(MAX(r.rate), 0)),
  CASE c.randomized WHEN 1 THEN 'rand' ELSE 'real' END,
  COUNT(r.ts)
FROM clients c
LEFT JOIN rates r ON r.mac=c.mac
GROUP BY c.mac
HAVING COUNT(r.ts) > 0
ORDER BY MAX(r.rate) DESC
LIMIT 200;
SQL
}

fp_history() {
    fp_init_db
    sqlite3 -separator $'\t' "$DB" <<'SQL' 2>/dev/null
SELECT mac,
  datetime(first_seen,'unixepoch','localtime'),
  datetime(last_seen, 'unixepoch','localtime'),
  CASE randomized WHEN 1 THEN 'rand' ELSE 'real' END,
  COALESCE(NULLIF(probed_ssids,''), '-')
FROM clients ORDER BY last_seen DESC LIMIT 1000;
SQL
}

fp_export_csv() {
    local out="${1:-$LOOT/fingerprint_$(date +%s).csv}"
    mkdir -p "$(dirname "$out")"
    fp_init_db
    sqlite3 -header -csv "$DB" \
      "SELECT * FROM clients ORDER BY last_seen DESC;" > "$out" 2>/dev/null
    sqlite3 -header -csv "$DB" \
      "SELECT * FROM probed;" > "${out%.csv}_probed.csv" 2>/dev/null
    echo "EXPORTED	$out"
}

# ── HTML report ──
fp_export_html() {
    local out="${1:-$LOOT/fingerprint_report_$(date +%s).html}"
    mkdir -p "$(dirname "$out")"
    fp_init_db

    local clients_count random_count correlations_count
    clients_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM clients;" 2>/dev/null)
    random_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM clients WHERE randomized=1;" 2>/dev/null)
    correlations_count=$(sqlite3 "$DB" \
        "SELECT COUNT(*) FROM (SELECT c1.mac, c2.mac FROM clients c1, clients c2 WHERE c1.mac<c2.mac AND c1.fp_hash=c2.fp_hash AND c1.fp_hash IS NOT NULL);" \
        2>/dev/null)

    {
        cat << 'HTMLHEAD'
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>wifisting — fingerprint report</title>
<style>
body{font-family:-apple-system,sans-serif;background:#0a0a0c;color:#e0e0e0;margin:0;padding:20px}
h1{color:#ff3b3b;margin-top:0}
h2{color:#ff8080;border-bottom:1px solid #333;padding-bottom:4px;margin-top:30px}
table{border-collapse:collapse;width:100%;font-family:monospace;font-size:12px}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #222}
th{background:#1a1a1e;color:#ff8080}
tr:hover{background:#1a1010}
.rand{color:#ffd60a}
.real{color:#62e690}
.stat{display:inline-block;background:#1a1a1e;border-left:3px solid #ff3b3b;padding:8px 14px;margin:6px 6px 6px 0;border-radius:4px}
.stat b{color:#ff3b3b;font-size:20px}
</style></head><body>
HTMLHEAD
        echo "<h1>wifisting — fingerprint report</h1>"
        echo "<p>generated: $(date -Is)</p>"
        echo "<div>"
        echo "  <div class=stat><b>$clients_count</b><br>clients</div>"
        echo "  <div class=stat><b>$random_count</b><br>randomized</div>"
        echo "  <div class=stat><b>$correlations_count</b><br>correlations</div>"
        echo "</div>"

        echo "<h2>Clients</h2>"
        echo "<table><tr><th>MAC</th><th>Last seen</th><th>Type</th><th>Guess</th><th>Probed SSIDs</th><th>Channels</th></tr>"
        sqlite3 -separator '|' "$DB" \
          "SELECT mac, datetime(last_seen,'unixepoch','localtime'), CASE randomized WHEN 1 THEN 'rand' ELSE 'real' END, CASE WHEN fp_ies LIKE '%0017f2%' THEN 'Apple' WHEN fp_ies LIKE '%0050f2%' THEN 'Windows' WHEN fp_ies LIKE '%00164c%' THEN 'Android/Chrome' WHEN probed_ssids LIKE '%iPhone%' THEN 'Apple (ssid)' WHEN probed_ssids LIKE '%Android%' THEN 'Android (ssid)' WHEN randomized=1 THEN 'Unknown randomized' ELSE 'Unknown' END, COALESCE(NULLIF(probed_ssids,''),'-'), COALESCE(NULLIF(channels,''),'-') FROM clients ORDER BY last_seen DESC LIMIT 500;" \
          2>/dev/null | while IFS='|' read -r mac when typ guess ssids chans; do
            # escape HTML
            mac=$(printf '%s' "$mac" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            guess=$(printf '%s' "$guess" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            ssids=$(printf '%s' "$ssids" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            printf '<tr><td>%s</td><td>%s</td><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' \
                "$mac" "$when" "$typ" "$typ" "$guess" "$ssids" "$chans"
        done
        echo "</table>"

        echo "<h2>Correlations</h2>"
        echo "<table><tr><th>MAC A</th><th>MAC B</th><th>Reason</th><th>Confidence</th></tr>"
        sqlite3 -separator '|' "$DB" \
          "SELECT c1.mac, c2.mac, 'same fingerprint', 95 FROM clients c1 JOIN clients c2 ON c1.mac<c2.mac AND c1.fp_hash=c2.fp_hash WHERE c1.fp_hash IS NOT NULL UNION ALL SELECT c1.mac, c2.mac, 'shared probe set', 80 FROM clients c1 JOIN clients c2 ON c1.mac<c2.mac AND c1.probed_ssids=c2.probed_ssids AND c1.probed_ssids IS NOT NULL AND length(c1.probed_ssids)>3 LIMIT 200;" \
          2>/dev/null | while IFS='|' read -r a b why conf; do
            printf '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s%%</td></tr>\n' \
                "$a" "$b" "$why" "$conf"
        done
        echo "</table>"

        echo "</body></html>"
    } > "$out"

    echo "REPORT	$out"
}

# ── BLE capture pipeline ──
# Passive BLE advertisement capture via btmon -J. btmon emits one JSON
# object per HCI event, which is far more robust to BlueZ version drift
# than parsing btmon's human text output.
#
# Requires: btmon (bluez), hci0 up (systemctl start bluetooth).

fp_ble_start() {
    local hci="${1:-hci0}"
    : > "$FP/ble.status"

    if ! command -v btmon >/dev/null 2>&1; then
        echo "ERR btmon missing (install bluez)" | tee "$FP/ble.status" >&2
        exit 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "ERR python3 missing" | tee "$FP/ble.status" >&2
        exit 1
    fi
    if [ ! -e "/sys/class/bluetooth/$hci" ]; then
        echo "ERR $hci not present — is the BT adapter up?" \
            | tee "$FP/ble.status" >&2
        exit 1
    fi

    # Bring the adapter up.
    rfkill unblock bluetooth 2>/dev/null || true
    hciconfig "$hci" up 2>/dev/null || true

    fp_init_db

    # Feeder python script. Reads btmon -J JSON, extracts advertising
    # reports, parses AD structures, upserts into ble_clients.
    cat > "$FP/ble_feeder.py" <<'PY_FEEDER'
#!/usr/bin/env python3
"""wifisting BLE advertisement feeder.

Reads btmon's TEXT output (not JSON — btmon has no stdout JSON mode,
the -J flag writes to a file argument and has no stdout equivalent)
and extracts advertising data into the ble_clients table.

btmon text format (BlueZ >= 5.x):

  > HCI Event: LE Meta Event (0x3e) plen 42         #14 [hci0] 8.12
        LE Advertising Report (0x02)
          Num reports: 1
          Event type: Connectable undirected - ADV_IND (0x00)
          Address type: Public (0x00)
          Address: 4C:12:34:56:78:9A (Apple, Inc.)
          Data length: 30
          Flags: 0x1a
          Company: Apple, Inc. (76)
            Data: 10060820d2dcc5
          Name (complete): AirPods Pro
          Tx Power: 12 dBm (0x0c)
          Appearance: 0x0941
          RSSI: -60 dBm (0x44)
"""
import sys, re, sqlite3, hashlib, time

DB = sys.argv[1]

COMPANY = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x0087: "Garmin",
    0x0157: "Xiaomi",
    0x008A: "Logitech",
    0x012D: "Sonos",
    0x0059: "Nordic Semi",
    0x02E5: "Amazon",
}

APP_MAIN = {
    0x01: "phone", 0x02: "computer", 0x03: "watch", 0x04: "clock",
    0x05: "display", 0x06: "remote", 0x07: "glasses", 0x08: "tag",
    0x09: "keyring", 0x0A: "media-player", 0x0B: "barcode",
    0x0C: "thermometer", 0x0D: "heart-rate", 0x0E: "bp",
    0x0F: "hid", 0x10: "glucose", 0x11: "running", 0x12: "cycling",
    0x31: "pulse-ox", 0x32: "weight", 0x33: "outdoor",
}

RE_EVENT     = re.compile(r'^\s+Event type:\s+(.+?)\s+\(0x[0-9a-fA-F]+\)\s*$')
RE_ADDR      = re.compile(r'^\s+Address:\s+([0-9A-Fa-f:]{17})')
RE_ADDR_TYPE = re.compile(r'^\s+Address type:\s+(\S+)')
RE_NAME      = re.compile(r'^\s+Name \((?:complete|short)\):\s+(.*)$')
RE_COMPANY   = re.compile(r'^\s+Company:\s+.*?\((\d+)\)')
RE_DATA      = re.compile(r'^\s+Data:\s+([0-9a-fA-F\s]+)\s*$')
RE_APPEAR    = re.compile(r'^\s+Appearance:\s+0x([0-9a-fA-F]+)')
RE_TXPWR     = re.compile(r'^\s+Tx Power:\s+(-?\d+)\s+dBm')
RE_RSSI      = re.compile(r'^\s+RSSI:\s+(-?\d+)\s+dBm')
RE_SRVDATA   = re.compile(r'^\s+Service Data \((?:UUID )?0x([0-9a-fA-F]+)\)')

def esc(s):
    return (s or "").replace("'", "''")

def addr_type_label(s):
    if not s: return "?"
    s = s.lower()
    if s.startswith("public"): return "public"
    if s.startswith("random"): return "random"
    return s

def flush(con, state):
    if not state or "addr" not in state:
        return
    addr = state["addr"]
    at = addr_type_label(state.get("addr_type"))
    name = state.get("name", "")
    appearance = state.get("appearance")
    tx_power = state.get("tx_power")
    rssi = state.get("rssi")
    cid = state.get("cid")
    mfg_data = state.get("mfg_data", "")
    uuids = state.get("uuids", "")
    ts = int(time.time())

    mfg_company = ""
    if cid is not None:
        mfg_company = COMPANY.get(cid, f"0x{cid:04X}")
        if cid == 0x004C and mfg_data and len(mfg_data) >= 2:
            try:
                sub = int(mfg_data[:2], 16)
                submap = {1: "iBeacon", 2: "AirPods", 7: "AirDrop",
                          9: "AirPlay", 12: "Handoff",
                          16: "NearbyInfo", 18: "FindMy"}
                if sub in submap:
                    mfg_company = "Apple/" + submap[sub]
            except ValueError:
                pass

    fp_src = "|".join([str(appearance or ""), uuids, mfg_company, name[:12]])
    fp = hashlib.md5(fp_src.encode()).hexdigest()[:16]

    sql = (
        "INSERT INTO ble_clients (mac, first_seen, last_seen, addr_type, "
        "local_name, appearance, tx_power, mfg_company, mfg_data, "
        "service_uuids, fp_hash, best_rssi) VALUES ("
        f"'{esc(addr)}', {ts}, {ts}, '{esc(at)}', "
        f"'{esc(name)}', "
        f"{appearance if appearance is not None else 'NULL'}, "
        f"{tx_power if tx_power is not None else 'NULL'}, "
        f"'{esc(mfg_company)}', '{esc(mfg_data)}', "
        f"'{esc(uuids)}', '{fp}', "
        f"{rssi if rssi is not None else 'NULL'}) "
        "ON CONFLICT(mac) DO UPDATE SET "
        f"last_seen={ts}, "
        "local_name=CASE WHEN excluded.local_name != '' THEN excluded.local_name ELSE local_name END, "
        "appearance=COALESCE(excluded.appearance, appearance), "
        "tx_power=COALESCE(excluded.tx_power, tx_power), "
        "mfg_company=CASE WHEN excluded.mfg_company != '' THEN excluded.mfg_company ELSE mfg_company END, "
        "mfg_data=CASE WHEN excluded.mfg_data != '' THEN excluded.mfg_data ELSE mfg_data END, "
        "service_uuids=CASE WHEN excluded.service_uuids != '' THEN excluded.service_uuids ELSE service_uuids END, "
        "best_rssi=MAX(COALESCE(best_rssi, -999), COALESCE(excluded.best_rssi, -999));"
    )
    try:
        con.execute(sql)
    except sqlite3.Error as e:
        sys.stderr.write(f"ble_feeder: {e}\n")

def main():
    con = sqlite3.connect(DB, timeout=10)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")

    state = {}
    last_commit = time.time()
    pending = 0

    for line in sys.stdin:
        # A new advertising report begins with Event type:
        m = RE_EVENT.match(line)
        if m:
            state = {"event_type": m.group(1)}
            continue
        if not state:
            continue
        m = RE_ADDR.match(line)
        if m:
            state["addr"] = m.group(1).upper(); continue
        m = RE_ADDR_TYPE.match(line)
        if m:
            state["addr_type"] = m.group(1); continue
        m = RE_NAME.match(line)
        if m:
            state["name"] = m.group(1).strip(); continue
        m = RE_COMPANY.match(line)
        if m:
            state["cid"] = int(m.group(1)); continue
        m = RE_DATA.match(line)
        if m and "cid" in state:
            state["mfg_data"] = m.group(1).replace(" ", ""); continue
        m = RE_APPEAR.match(line)
        if m:
            state["appearance"] = int(m.group(1), 16); continue
        m = RE_TXPWR.match(line)
        if m:
            state["tx_power"] = int(m.group(1)); continue
        m = RE_SRVDATA.match(line)
        if m:
            prev = state.get("uuids", "")
            state["uuids"] = (prev + "," + m.group(1)) if prev else m.group(1)
            continue
        m = RE_RSSI.match(line)
        if m:
            state["rssi"] = int(m.group(1))
            flush(con, state)
            state = {}
            pending += 1
            if pending >= 20 or time.time() - last_commit > 2:
                try: con.commit()
                except sqlite3.Error: pass
                pending = 0
                last_commit = time.time()
            continue

    try: con.commit()
    except sqlite3.Error: pass
    con.close()

if __name__ == "__main__":
    main()
PY_FEEDER
    chmod +x "$FP/ble_feeder.py"

    # Preflight: run btmon -J for 1s and confirm it stays alive.
    timeout 1.2 btmon >/dev/null 2>"$FP/ble.err"
    local pf_rc=$?
    if [ "$pf_rc" -ne 0 ] && [ "$pf_rc" -ne 124 ]; then
        local em
        em=$(head -c 300 "$FP/ble.err" 2>/dev/null | tr '\n' ' ')
        echo "ERR btmon: ${em:-exited rc=$pf_rc}" > "$FP/ble.status"
        exit 1
    fi

    echo "OK hci=$hci" > "$FP/ble.status"
    echo $$ > "$FP/ble.pid"

    stdbuf -oL btmon 2>>"$FP/ble.err" | python3 "$FP/ble_feeder.py" "$DB"

    rm -f "$FP/ble.pid"
    exit 0
}

fp_ble_stop() {
    local killed=0 pid=""
    [ -f "$FP/ble.pid" ] && pid=$(cat "$FP/ble.pid")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
    fi
    stop_sweep 'btmon' && killed=1
    if (( killed == 1 )); then
        rm -f "$FP/ble.pid"
        printf 'STOPPED\t1\n'
        return 0
    fi
    if [[ -n "$pid" ]]; then
        printf 'ERROR\tBLE pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
}

fp_ble_clients_tsv() {
    fp_init_db
    sqlite3 -separator $'\t' "$DB" <<'SQL' 2>/dev/null
SELECT mac,
  datetime(last_seen, 'unixepoch', 'localtime'),
  COALESCE(addr_type, '?'),
  COALESCE(NULLIF(local_name, ''), '-'),
  CASE
    WHEN appearance IS NULL THEN '-'
    WHEN appearance = 0 THEN 'unknown'
    ELSE printf('0x%04X', appearance)
  END,
  CASE
    WHEN mfg_company != '' THEN mfg_company
    ELSE '-'
  END,
  COALESCE(CAST(best_rssi AS TEXT), '?')
FROM ble_clients
ORDER BY last_seen DESC
LIMIT 300;
SQL
}

# ── Wi-Fi structured IE dump for one client ──
fp_wifi_ies() {
    local mac="$1"
    [ -z "$mac" ] && { echo "ERR no mac" >&2; exit 1; }
    fp_init_db
    sqlite3 "$DB" <<SQL 2>/dev/null
.mode tabs
SELECT 'mac',           mac FROM clients WHERE mac='$mac';
SELECT 'randomized',    CASE randomized WHEN 1 THEN 'yes' ELSE 'no' END FROM clients WHERE mac='$mac';
SELECT 'fp_hash',       COALESCE(fp_hash, '-') FROM clients WHERE mac='$mac';
SELECT 'capabilities',  COALESCE(fp_ies, '-') FROM clients WHERE mac='$mac';
SELECT 'ht_caps',       COALESCE(NULLIF(ht_caps,''), '-') FROM clients WHERE mac='$mac';
SELECT 'vht_caps',      COALESCE(NULLIF(vht_caps,''), '-') FROM clients WHERE mac='$mac';
SELECT 'he_caps',       COALESCE(NULLIF(he_caps,''), '-') FROM clients WHERE mac='$mac';
SELECT 'ext_caps',      COALESCE(NULLIF(ext_caps,''), '-') FROM clients WHERE mac='$mac';
SELECT 'supp_rates',    COALESCE(NULLIF(supp_rates,''), '-') FROM clients WHERE mac='$mac';
SELECT 'rsn_caps',      COALESCE(NULLIF(rsn_caps,''), '-') FROM clients WHERE mac='$mac';
SELECT 'country',       COALESCE(NULLIF(country,''), '-') FROM clients WHERE mac='$mac';
SELECT 'vendor_ouis',   COALESCE(NULLIF(vendor_ouis,''), '-') FROM clients WHERE mac='$mac';
SQL
}

# ── Cross-domain Wi-Fi ↔ BLE correlation ──
# Two MACs correlate if their observation windows overlap AND both
# were observed on the same radio (Wi-Fi client + BLE advertiser that
# turned up in the same 60s bucket). This is coarse but cheap and
# catches phones that rotate Wi-Fi and BLE MACs on the same schedule.
fp_correlate_all() {
    fp_init_db
    sqlite3 "$DB" <<'SQL' 2>/dev/null
DELETE FROM cross_domain WHERE ts < strftime('%s','now','-1 day');
INSERT OR REPLACE INTO cross_domain (wifi_mac, ble_mac, confidence, reason, ts)
SELECT w.mac, b.mac, 70, 'overlap', strftime('%s','now')
FROM clients w
JOIN ble_clients b
  ON w.last_seen  > b.first_seen - 60
 AND w.first_seen < b.last_seen + 60
WHERE w.randomized = 1
  AND b.addr_type LIKE 'random%'
  AND ABS(w.last_seen - b.last_seen) < 300
LIMIT 200;
SQL
    sqlite3 -separator $'	' "$DB" \
        "SELECT wifi_mac, ble_mac, confidence, reason FROM cross_domain ORDER BY ts DESC LIMIT 100;" \
        2>/dev/null
}

# ── verified stop ──
# Kill one pid with escalating signals; returns 0 ONLY once it is gone.
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

# ── MAC-rotation timeline (merged from 45_mac_deanon, submenu: Track) ──
# Given one target MAC, find every other MAC that plausibly belongs to the
# same physical device and emit a timeline. Sources, strongest first:
#   anchor            the target itself
#   IE fingerprint    identical fp_hash -> same radio, new MAC
#   probe-set         shared probed SSIDs
#   channel overlap   same channel set
#   temporal          one disappears as the next appears (rotation)
#   cross-domain      a BLE address correlated to a Wi-Fi address
fp_mac_history() {
    local mac="${1:-}"
    local U

    if [[ -z "$mac" ]]; then
        printf 'ERROR\tusage: --mac-history MAC\n' >&2; return 2
    fi
    # Validate before interpolating into SQL.
    if [[ ! "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        printf 'ERROR\tnot a MAC address: %s\n' "$mac" >&2; return 2
    fi
    U=$(printf '%s' "$mac" | tr 'A-F' 'a-f')

    fp_init_db

    # Anchor must exist, otherwise every join below is pointless.
    local seen
    seen=$(sqlite3 "$DB" "SELECT COUNT(*) FROM clients WHERE lower(mac)='$U';" 2>/dev/null)
    if [[ "${seen:-0}" == "0" ]]; then
        printf 'ERROR\t%s is not in the fingerprint database\n' "$mac" >&2
        return 1
    fi

    {
        # 1) the anchor itself
        sqlite3 -separator $'\t' "$DB" "
            SELECT first_seen, mac, 100, 'anchor (first seen)'
              FROM clients WHERE lower(mac)='$U'
            UNION ALL
            SELECT last_seen, mac, 100, 'anchor (last seen)'
              FROM clients WHERE lower(mac)='$U';" 2>/dev/null

        # 2) identical IE fingerprint
        sqlite3 -separator $'\t' "$DB" "
            SELECT c.last_seen, c.mac, 90, 'IE fingerprint match'
              FROM clients c
              JOIN clients t ON t.fp_hash = c.fp_hash
             WHERE lower(t.mac)='$U'
               AND lower(c.mac)<>'$U'
               AND c.fp_hash IS NOT NULL AND c.fp_hash<>'';" 2>/dev/null

        # 3) probe-set overlap (shared probed SSIDs)
        sqlite3 -separator $'\t' "$DB" "
            SELECT (SELECT MAX(last_seen) FROM clients c2 WHERE c2.mac=p2.mac),
                   p2.mac,
               MIN(50 + 10*n, 88),
                   'probe-set match ('||n||' shared SSID'||CASE n WHEN 1 THEN '' ELSE 's' END||')'
              FROM (SELECT p2.mac AS mac, COUNT(DISTINCT p2.ssid) AS n
                      FROM probed p1 JOIN probed p2 ON p1.ssid = p2.ssid
                     WHERE lower(p1.mac)='$U' AND lower(p2.mac)<>'$U'
                     GROUP BY p2.mac) AS x
              JOIN (SELECT DISTINCT mac FROM probed) AS p2 ON p2.mac = x.mac
             WHERE n >= 2;" 2>/dev/null

        # 4) channel-set overlap
        sqlite3 -separator $'\t' "$DB" "
            SELECT c.last_seen, c.mac, 60, 'channel-set overlap'
              FROM clients c JOIN clients t ON t.channels = c.channels
             WHERE lower(t.mac)='$U' AND lower(c.mac)<>'$U'
               AND c.channels IS NOT NULL AND c.channels<>'';" 2>/dev/null

        # 5) temporal rotation: next device appears as this one goes quiet
        sqlite3 -separator $'\t' "$DB" "
            SELECT c.first_seen, c.mac, 65, 'rotation (appears as target goes quiet)'
              FROM clients c JOIN clients t ON 1=1
             WHERE lower(t.mac)='$U' AND lower(c.mac)<>'$U'
               AND c.first_seen BETWEEN t.last_seen - 30 AND t.last_seen + 120;" 2>/dev/null

        # 6) cross-domain BLE correlation
        sqlite3 -separator $'\t' "$DB" "
            SELECT ts, ble_mac, confidence, 'BLE correlate: '||reason
              FROM cross_domain WHERE lower(wifi_mac)='$U'
            UNION ALL
            SELECT ts, wifi_mac, confidence, 'BLE correlate: '||reason
              FROM cross_domain WHERE lower(ble_mac)='$U';" 2>/dev/null
    } | grep -v '^$' | awk -F'\t' '
        # Collapse duplicate (ts,mac) rows, keeping the HIGHEST confidence.
        # A plain "first wins" dedup was wrong: sort is not stable on equal
        # timestamps, so a weak channel-set match could displace the strong
        # IE-fingerprint match for the same device and instant.
        { k = $1 "\t" $2
          if (!(k in best) || $3+0 > best[k]+0) { best[k] = $3; line[k] = $0 } }
        END { for (k in line) print line[k] }
    ' | sort -n -k1,1
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no adapter, no BLE controller, no root, no live capture.
# Every database this touches is created under $TMP and removed again —
# the real $STATE/fingerprint.db is only ever read (and hashed before and
# after) so the selftest can prove it did not disturb it.
fp_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    hfld() { awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }
    # rows of a fp_mac_history dump for one MAC
    hrows() { awk -F'\t' -v m="$2" '$2==m' <<<"$1"; }
    q() { sqlite3 "$1" "$2" 2>/dev/null; }

    command -v sqlite3 >/dev/null 2>&1 || {
        printf 'selftest-env\tFAIL sqlite3 missing\n'
        printf 'RESULT\tFAIL(1)\n'; return 1; }

    local MOD_TMP="$TMP/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP"

    # The real DB must survive this selftest byte for byte.
    local real_db="$STATE/fingerprint.db" real_before real_after
    chk real-db-exists "$([[ -f "$real_db" ]] && echo yes || echo no)" "yes"
    real_before=$(sha256sum "$real_db" 2>/dev/null | cut -d' ' -f1)

    local save_db="$DB" save_fp="$FP"
    DB="$MOD_TMP/fp.db"
    FP="$MOD_TMP"
    chk real-db-not-used "$([[ "$DB" != "$real_db" ]] && echo yes || echo no)" "yes"

    # ── schema bootstrap ──
    fp_init_db >/dev/null
    chk db-created "$([[ -s "$DB" ]] && echo yes || echo no)" "yes"
    chk db-user-version "$(q "$DB" 'PRAGMA user_version;')" "2"
    chk db-table-clients "$(q "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='clients';")" "1"
    chk db-table-cross-domain "$(q "$DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cross_domain';")" "1"
    chk db-column-randomized "$(q "$DB" "SELECT COUNT(*) FROM pragma_table_info('clients') WHERE name='randomized';")" "1"
    # Idempotent: a second call must not error or duplicate anything.
    fp_init_db >/dev/null
    chk db-init-idempotent "$(q "$DB" 'PRAGMA user_version;')" "2"

    # ── IE/probe-SSID device heuristics ──
    chk dev-ie-apple "$(fp_device_from_ies 'dd0017f2aa' '' 0)" "Apple"
    chk dev-ie-windows "$(fp_device_from_ies 'dd0050f2aa' '' 0)" "Windows"
    chk dev-ie-android "$(fp_device_from_ies 'dd00164caa' '' 0)" "Android/Chrome"
    chk dev-ie-intel "$(fp_device_from_ies 'dd00a0c6aa' '' 0)" "Intel WiFi"
    chk dev-ie-wfa "$(fp_device_from_ies 'dd506f9aaa' '' 0)" "Wi-Fi Alliance test"
    chk dev-ssid-apple "$(fp_device_from_ies '' 'MyiPhone' 1)" "Apple (ssid)"
    chk dev-ssid-android "$(fp_device_from_ies '' 'Galaxy-S21' 1)" "Android (ssid)"
    chk dev-ssid-tv "$(fp_device_from_ies '' 'Chromecast' 0)" "TV (ssid)"
    # IE beats a misleading SSID.
    chk dev-ie-wins "$(fp_device_from_ies 'aa0017f2' 'Galaxy-S21' 0)" "Apple"
    # Randomized with no other evidence is reported as such, not as Unknown.
    chk dev-randomized "$(fp_device_from_ies '' '' 1)" "Randomized device"
    chk dev-unknown "$(fp_device_from_ies '' '' 0)" "Unknown"

    # ── feeder: real ingest path, real SQL escaping, real U/L bit test ──
    # Suppress the opportunistic hourly prune so the fixed 2023 timestamps
    # below are not treated as expired retention data.
    date +%s > "$FP/.last_prune"
    # ts|mac|type|sn|ssid|ch|rssi|rate|caps|ies|ht|vht|he|ext|sup|rsn|country|vouis
    printf '%s\n' \
      "1700000000.5|02:11:22:33:44:55|4|42|O'Reilly-Guest|6|-55|54.0|aabb|ccdd|hh|vv|he|ee|ss|rr|DE|vvvv" \
      "1700000000.6|00:1A:2B:3C:4D:5E|4|43|HomeNet|11|-60|54.0|aabb|eeff|hh|vv|he|ee|ss|rr|DE|vvvv" \
      "1700000005.0|02:11:22:33:44:55|4|44|O'Reilly-Guest|6|-57|54.0|aabb|ccdd|hh|vv|he|ee|ss|rr|DE|vvvv" \
      | fp_feeder >/dev/null

    chk feeder-rows "$(q "$DB" 'SELECT COUNT(*) FROM clients;')" "2"
    # Locally-administered bit (0x02 of the first octet) => randomized.
    chk feeder-rand-local "$(q "$DB" "SELECT randomized FROM clients WHERE mac='02:11:22:33:44:55';")" "1"
    chk feeder-rand-universal "$(q "$DB" "SELECT randomized FROM clients WHERE mac='00:1A:2B:3C:4D:5E';")" "0"
    # An apostrophe in a probed SSID must survive the INSERT.
    chk feeder-sql-escape "$(q "$DB" "SELECT probed_ssids FROM clients WHERE mac='02:11:22:33:44:55';")" \
        "O'Reilly-Guest"
    # The same SSID seen again is not appended twice.
    chk feeder-probed-no-dupe "$(q "$DB" "SELECT probed_ssids FROM clients WHERE mac='02:11:22:33:44:55';" | tr -cd "'" | wc -c)" "1"
    chk feeder-probed-rows "$(q "$DB" 'SELECT COUNT(*) FROM probed;')" "3"
    chk feeder-fp-ies "$(q "$DB" "SELECT fp_ies FROM clients WHERE mac='00:1A:2B:3C:4D:5E';")" "aabb|eeff"
    # fp_hash = md5(ht|vht|he|ext|sup|rsn|caps)[0:16], by construction.
    chk feeder-fp-hash "$(q "$DB" "SELECT fp_hash FROM clients WHERE mac='00:1A:2B:3C:4D:5E';")" \
        "230a57b7a286b4cc"
    # One observation per MAC per 60s and one seqnum per MAC per 10s: the
    # third line (same MAC, 5s later) must not add either.
    chk feeder-obs-capped "$(q "$DB" 'SELECT COUNT(*) FROM observations;')" "2"
    chk feeder-sn-capped "$(q "$DB" 'SELECT COUNT(*) FROM seqnums;')" "2"
    chk feeder-rate-rows "$(q "$DB" 'SELECT COUNT(*) FROM rates;')" "3"
    chk feeder-last-seen "$(q "$DB" "SELECT last_seen FROM clients WHERE mac='02:11:22:33:44:55';")" "1700000005"
    # Broadcast / null MACs must never be stored. The U/L bit is bit 1 of
    # the first octet, not a hardcoded "02:" prefix, so 9E must read as
    # randomised and 2C must not.
    printf '%s\n' \
      "1700000010.0|ff:ff:ff:ff:ff:ff|4|1|x|1|-50|1.0|a|b|c|d|e|f|g|h|i|j" \
      "1700000011.0|00:00:00:00:00:00|4|1|x|1|-50|1.0|a|b|c|d|e|f|g|h|i|j" \
      "1700000012.0|9E:AA:BB:CC:DD:01|4|1|x|1|-50|1.0|a|b|c|d|e|f|g|h|i|j" \
      "1700000013.0|2C:AA:BB:CC:DD:02|4|1|x|1|-50|1.0|a|b|c|d|e|f|g|h|i|j" \
      | fp_feeder >/dev/null
    chk feeder-broadcast-skipped "$(q "$DB" 'SELECT COUNT(*) FROM clients;')" "4"
    chk feeder-rand-9e "$(q "$DB" "SELECT randomized FROM clients WHERE mac='9E:AA:BB:CC:DD:01';")" "1"
    chk feeder-rand-2c "$(q "$DB" "SELECT randomized FROM clients WHERE mac='2C:AA:BB:CC:DD:02';")" "0"

    # ── retention: fp_prune drops only rows past the cutoff ──
    local PDB="$MOD_TMP/prune.db"
    DB="$PDB"; fp_init_db >/dev/null
    sqlite3 "$PDB" "INSERT INTO observations (mac, ts, ch, rssi) VALUES
        ('aa:bb:cc:dd:ee:01', strftime('%s','now') - 90*86400, 1, -90),
        ('aa:bb:cc:dd:ee:01', strftime('%s','now') - 60, 1, -50);"
    chk prune-seed "$(q "$PDB" 'SELECT COUNT(*) FROM observations;')" "2"
    fp_prune 7 >/dev/null
    chk prune-old-dropped "$(q "$PDB" 'SELECT COUNT(*) FROM observations;')" "1"
    chk prune-recent-kept "$(q "$PDB" 'SELECT rssi FROM observations;')" "-50"

    # ── fp_mac_history: 6 signal sources, max-confidence dedup ──
    local HDB="$MOD_TMP/hist.db"
    DB="$HDB"
    fp_init_db >/dev/null
    sqlite3 "$HDB" <<'SQL'
INSERT INTO clients (mac, first_seen, last_seen, randomized, fp_hash, fp_ies, channels) VALUES
 ('aa:bb:cc:dd:ee:01', 1900, 2000, 0, 'H1', 'A|aabb', '1,6'),
 ('aa:bb:cc:dd:ee:02', 1900, 2000, 0, 'H1', 'A|aabb', '1,6'),
 ('aa:bb:cc:dd:ee:03', 2050, 2100, 0, 'H2', 'A|ccdd', '11'),
 ('aa:bb:cc:dd:ee:04', 1500, 1510, 0, 'H3', 'A|eeff', '36');
INSERT INTO probed (mac, ssid, ts) VALUES
 ('aa:bb:cc:dd:ee:01','Net1',1900), ('aa:bb:cc:dd:ee:01','Net2',1900),
 ('aa:bb:cc:dd:ee:03','Net1',2050), ('aa:bb:cc:dd:ee:03','Net2',2050);
INSERT INTO cross_domain (wifi_mac, ble_mac, confidence, reason, ts) VALUES
 ('aa:bb:cc:dd:ee:04','aa:bb:cc:dd:ee:01',95,'co-located',3000);
SQL

    local H
    H=$(fp_mac_history aa:bb:cc:dd:ee:01)
    chk hist-rc "$?" "0"
    chk hist-rows "$(grep -c . <<<"$H")" "6"
    # 02 matches on BOTH the IE fingerprint (90) and the channel set (60) at
    # the same instant: the dedup must keep the strong one, and leave one row.
    chk hist-dedup-one-row "$(hrows "$H" aa:bb:cc:dd:ee:02 | grep -c .)" "1"
    chk hist-dedup-strongest "$(hrows "$H" aa:bb:cc:dd:ee:02 | cut -f3)" "90"
    chk hist-dedup-label "$(hrows "$H" aa:bb:cc:dd:ee:02 | cut -f4)" "IE fingerprint match"
    # Probe-set overlap: 2 shared SSIDs => min(50 + 10*2, 88) = 70.
    chk hist-probeset-conf "$(hrows "$H" aa:bb:cc:dd:ee:03 | awk -F'\t' '$3==70 {print $3}')" "70"
    chk hist-probeset-label "$(hrows "$H" aa:bb:cc:dd:ee:03 | awk -F'\t' '$3==70 {print $4}')" \
        "probe-set match (2 shared SSIDs)"
    chk hist-rotation "$(hrows "$H" aa:bb:cc:dd:ee:03 | awk -F'\t' '$3==65 {print $1}')" "2050"
    chk hist-cross-domain "$(hrows "$H" aa:bb:cc:dd:ee:04 | cut -f3)" "95"
    chk hist-cross-domain-ts "$(hrows "$H" aa:bb:cc:dd:ee:04 | cut -f1)" "3000"
    chk hist-anchor-rows "$(hrows "$H" aa:bb:cc:dd:ee:01 | grep -c .)" "2"
    chk hist-anchor-conf "$(hrows "$H" aa:bb:cc:dd:ee:01 | cut -f3 | sort -u)" "100"
    chk hist-sorted-by-ts "$(cut -f1 <<<"$H" | sort -n | tr '\n' ' ')" \
        "$(cut -f1 <<<"$H" | tr '\n' ' ')"

    # ── rejection: malformed input is refused, absent input is not found ──
    local rc=0
    fp_mac_history 'not-a-mac' >/dev/null 2>&1 || rc=$?
    chk hist-malformed-rc "$rc" "2"
    rc=0; fp_mac_history "" >/dev/null 2>&1 || rc=$?
    chk hist-empty-rc "$rc" "2"
    rc=0; fp_mac_history 'aa:bb:cc:dd:ee:99' >/dev/null 2>&1 || rc=$?
    chk hist-absent-rc "$rc" "1"
    rc=0; fp_cli_main --mac-history 'zz:zz' >/dev/null 2>&1 || rc=$?
    chk hist-cli-malformed-rc "$rc" "2"
    rc=0; fp_cli_main --no-such-flag >/dev/null 2>&1 || rc=$?
    chk unknown-command-rc "$rc" "2"

    DB="$save_db"; FP="$save_fp"
    rm -rf "$MOD_TMP"

    real_after=$(sha256sum "$real_db" 2>/dev/null | cut -d' ' -f1)
    chk real-db-untouched "$real_after" "$real_before"

    # ── Tier 1 fingerprint verbs ────────────────────────────────────────
    # Validation paths always run. Parsing assertions need scapy to build a
    # fixture capture; without it they SKIP loudly rather than pass silently.
    chk fpop-noarg   "$(fp_dhcp_opt55_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpmd-noarg   "$(fp_mdns_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpdns-noarg  "$(fp_dns_fp_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpja3-noarg  "$(fp_ja3_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpua-noarg   "$(fp_ua_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpmd-missing "$(fp_mdns_tsv /nonexistent.pcap >/dev/null 2>&1; echo $?)" 1
    chk fpwps-noarg  "$(fp_wps_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpvie-noarg  "$(fp_vendor_ie_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpas-noarg   "$(fp_assoc_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpwps-missing "$(fp_wps_tsv /nonexistent.pcap >/dev/null 2>&1; echo $?)" 1
    chk fpcorr-noarg "$(fp_corroborate_tsv >/dev/null 2>&1; echo $?)" 2
    chk fpcorr-missing "$(fp_corroborate_tsv /nonexistent.pcap >/dev/null 2>&1; echo $?)" 1
    # OUI naming is a pure function: testable with no capture at all
    chk oui-wfa   "$(fp_vendor_oui_name 00:50:f2)" "microsoft-or-wfa"
    chk oui-apple "$(fp_vendor_oui_name 00:17:f2)" "apple"
    chk oui-unk   "$(fp_vendor_oui_name aa:bb:cc)" "unknown"

    if python3 -c 'import scapy' >/dev/null 2>&1; then
        local fx="$FP/tier1-selftest.pcap" f2="$FP/tier2-selftest.pcap" o
        rm -f "$fx" "$f2"          # never assert against a stale fixture
        python3 - "$fx" "$f2" <<'PYFIX' >/dev/null 2>&1
import struct, sys
from scapy.all import Ether, IP, UDP, TCP, DHCP, BOOTP, DNS, DNSQR, DNSRR, Raw, wrpcap
def dhcp(mac, prl):
    return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
            BOOTP(chaddr=bytes.fromhex(mac.replace(':', '')), xid=1) /
            DHCP(options=[("message-type", "discover"),
                          ("vendor_class_id", "android-dhcp-13"),
                          ("hostname", "Pixel-7"), ("param_req_list", prl), "end"]))
mdns = (Ether() / IP(src="192.168.1.50", dst="224.0.0.251") / UDP(sport=5353, dport=5353) /
        DNS(id=0, rd=0, qd=DNSQR(qname="_airplay._tcp.local"),
            an=DNSRR(rrname="_airplay._tcp.local", type="TXT", ttl=4500,
                     rdata=b"model=AppleTV6,2")))
dnsq = (Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / UDP(sport=40000, dport=53) /
        DNS(id=1, rd=1, qd=DNSQR(qname="connectivitycheck.gstatic.com")))
http = (Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=41000, dport=80, flags="PA") /
        Raw(b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: CaptiveNetworkSupport-1\r\n\r\n"))
name = b"www.example.com"
sniext = struct.pack('!H', len(name) + 3) + b'\x00' + struct.pack('!H', len(name)) + name
ext = struct.pack('!HH', 0, len(sniext)) + sniext
body = b'\x03\x03' + bytes(range(32)) + b'\x00' + struct.pack('!H', 2) + b'\x13\x01' + b'\x01\x00'
body += struct.pack('!H', len(ext)) + ext
hs = b'\x01' + struct.pack('!I', len(body))[1:] + body
tls = (Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=42000, dport=443, flags="PA") /
       Raw(b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs))
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11AssoReq
def beacon():
    return (Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2="aa:bb:cc:00:11:22", addr3="aa:bb:cc:00:11:22") /
            Dot11Beacon(cap=0x0411) / Dot11Elt(ID="SSID", info="TestAP") /
            Dot11Elt(ID=221, info=b'\x00\x17\xf2\x0a\x01\x02') /
            Dot11Elt(ID=221, info=b'\x00\x50\xf2\x02\x00\x01'))
def assoc():
    return (Dot11(type=0, subtype=0, addr1="aa:bb:cc:00:11:22",
                  addr2="de:ad:be:ef:00:01", addr3="aa:bb:cc:00:11:22") /
            Dot11AssoReq(cap=0x1111, listen_interval=10) /
            Dot11Elt(ID="SSID", info="TestAP") /
            Dot11Elt(ID=54, info=b'\x01\x02\x03') /
            Dot11Elt(ID=70, info=b'\x00\x00\x00\x00\x00') /
            Dot11Elt(ID=127, info=b'\x00\x00\x00\x00\x00'))
# Two files, not one: a pcap carries a single linktype, so Ethernet frames
# and 802.11 frames cannot share one. Monitor captures are 802.11; LAN
# captures are Ethernet - mixing them makes tshark read the beacons as
# Ethernet and find nothing.
# An ARP reply joins the MAC (DHCP keys on it) to the IP (mDNS/DNS/TLS/HTTP
# key on that), which is what makes cross-source corroboration possible.
from scapy.all import ARP
arp = (Ether(src="aa:bb:cc:11:22:33") /
       ARP(op=2, psrc="192.168.1.50", hwsrc="aa:bb:cc:11:22:33",
           pdst="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff"))
wrpcap(sys.argv[1], [dhcp("aa:bb:cc:11:22:33", [1,3,6,15,26]), arp,
                     mdns, dnsq, http, tls])
from scapy.all import RadioTap
wrpcap(sys.argv[2], [RadioTap()/beacon(), RadioTap()/assoc()])
PYFIX
        o=$(fp_dhcp_opt55_tsv "$fx" 2>/dev/null)
        chk fp-opt55 "$(printf '%s\n' "$o" | awk -F'\t' '$1=="DHCP_OPT55"{print $3}')" "1,3,6,15,26"
        chk fp-opt55-mac "$(printf '%s\n' "$o" | awk -F'\t' '$1=="DHCP_OPT55"{print $2}')" "aa:bb:cc:11:22:33"
        o=$(fp_mdns_tsv "$fx" 2>/dev/null)
        chk fp-mdns-model "$(printf '%s\n' "$o" | awk -F'\t' '$1=="MDNS"{print $5}')" "model=AppleTV6,2"
        o=$(fp_dns_fp_tsv "$fx" 2>/dev/null)
        # COUNT carries a phrase ("1 query name(s)"); coerce to the number.
        chk fp-dns-count "$(printf '%s\n' "$o" | awk -F'\t' '$1=="COUNT"{print $2+0}')" 1
        o=$(fp_ja3_tsv "$fx" 2>/dev/null)
        chk fp-ja3-len "$(printf '%s\n' "$o" | awk -F'\t' '$1=="JA3"{print length($3)}')" 32
        chk fp-ja3-sni "$(printf '%s\n' "$o" | awk -F'\t' '$1=="JA3"{print $4}')" "www.example.com"
        o=$(fp_ua_tsv "$fx" 2>/dev/null)
        chk fp-ua "$(printf '%s\n' "$o" | grep -c 'CaptiveNetworkSupport')" 1

        # Tier 2
        o=$(fp_vendor_ie_tsv "$f2" 2>/dev/null)
        chk fp2-vendor-apple "$(printf '%s\n' "$o" | awk -F'\t' '$3=="00:17:f2"{print $4}')" "apple"
        # wlan.tag.oui is a decimal 24-bit integer; if that decoding regresses
        # the OUI resolves to the raw number and every name becomes unknown.
        chk fp2-vendor-wfa   "$(printf '%s\n' "$o" | awk -F'\t' '$3=="00:50:f2"{print $4}')" "microsoft-or-wfa"
        o=$(fp_assoc_tsv "$f2" 2>/dev/null)
        chk fp2-assoc-k "$(printf '%s\n' "$o" | awk -F'\t' '$1=="de:ad:be:ef:00:01"{print $3}')" "yes"
        chk fp2-assoc-r "$(printf '%s\n' "$o" | awk -F'\t' '$1=="de:ad:be:ef:00:01"{print $4}')" "yes"
        # this fixture carries no WPS identity, so the verb must say so and
        # exit non-zero rather than report an empty success
        o=$(fp_wps_tsv "$f2" 2>&1); local wrc=$?
        chk fp2-wps-rc "$wrc" 1

        # Corroboration: the row must be keyed by MAC, which only happens if
        # the ARP join worked - otherwise the evidence stays split across the
        # MAC and the IP and no verdict can be reached.
        # A distinct variable: reusing $o here clobbered the WPS result before
        # its own case check ran.
        local oc; oc=$(fp_corroborate_tsv "$fx" 2>/dev/null)
        chk fp3-join    "$(printf '%s\n' "$oc" | awk -F'\t' '$1=="CORROBORATE" && $2=="aa:bb:cc:11:22:33"{print $2}')" "aa:bb:cc:11:22:33"
        chk fp3-verdict "$(printf '%s\n' "$oc" | awk -F'\t' '$1=="CORROBORATE" && $2=="aa:bb:cc:11:22:33"{print $3}')" "google"
        # agreement is reported as a fraction so a lone source is visibly weak
        chk fp3-sources "$(printf '%s\n' "$oc" | awk -F'\t' '$1=="CORROBORATE" && $2=="aa:bb:cc:11:22:33"{print $4}')" "2/5"
        case "$o" in *none*) chk fp2-wps-msg ok ok ;;
                      *) chk fp2-wps-msg "$o" none ;; esac
    else
        printf 'SKIP\ttier1 parsing fixtures - scapy not installed\n'
    fi

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

fp_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --init-db)          fp_init_db ;;
        --start-status)     [[ -f "$STATUS" ]] && cat "$STATUS" || echo "ERR no status file" ;;
        --start)            fp_start "$@" ;;
        --stop)             fp_stop ;;
        --status-tsv)       fp_status ;;
        --list-clients-tsv) fp_list_clients ;;
        --probe-tsv)        fp_probe_one "$@" ;;
        --probes-tsv)       fp_probes ;;
        --correlate-tsv)    fp_correlate ;;
        --rates-tsv)        fp_rates ;;
        --history-tsv)      fp_history ;;
        --export)           fp_export_csv "$@" ;;
        --export-html)      fp_export_html "$@" ;;
        --prune)            fp_prune "$@" ;;
        --start-ble)        fp_ble_start "$@" ;;
        --stop-ble)         fp_ble_stop ;;
        --ble-clients-tsv)  fp_ble_clients_tsv ;;
        --wifi-ies)         fp_wifi_ies "$@" ;;
        --correlate-all-tsv) fp_correlate_all ;;
        --mac-history)        fp_mac_history "$@" ;;
        --selftest)           fp_selftest ;;
        --set-channel)      fp_set_channel "$@" ;;
        --dhcp-fp-tsv)           fp_dhcp_fp_tsv "${1:-}" ;;
        --wps-tsv)          fp_wps_tsv "${1:-}" ;;
        --corroborate-tsv)  fp_corroborate_tsv "${1:-}" ;;
        --vendor-ie-tsv)  fp_vendor_ie_tsv "${1:-}" ;;
        --assoc-tsv)      fp_assoc_tsv "${1:-}" ;;
        --dhcp-opt55-tsv) fp_dhcp_opt55_tsv "${1:-}" ;;
        --mdns-tsv) fp_mdns_tsv "${1:-}" ;;
        --dns-fp-tsv) fp_dns_fp_tsv "${1:-}" ;;
        --ja3-tsv) fp_ja3_tsv "${1:-}" ;;
        --ua-tsv) fp_ua_tsv "${1:-}" ;;
        --get-channel)      fp_get_channel "$@" ;;
        --hop-start)        fp_hop_start "$@" ;;
        --hop-stop)         fp_hop_stop ;;
        --hop-status-tsv)   fp_hop_status_tsv ;;
        --set-channel)      shift; fp_set_channel "$@" ;;
        --get-channel)      shift; fp_get_channel "$@" ;;
        --hop-start)        shift; fp_hop_start "$@" ;;
        --hop-stop)         fp_hop_stop ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --init-db
  --start IFACE
  --stop
  --status-tsv
  --list-clients-tsv
  --probe-tsv MAC
  --probes-tsv
  --correlate-tsv
  --rates-tsv
  --history-tsv
  --export [PATH]
  --export-html [PATH]
  --prune [DAYS]
  --set-channel IFACE CH
  --get-channel IFACE
  --hop-start IFACE [INTERVAL]
  --hop-stop
  --hop-status-tsv
  --mac-history MAC
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
    fp_cli_main "$@"
fi

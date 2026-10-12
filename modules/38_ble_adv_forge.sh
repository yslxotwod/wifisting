#!/usr/bin/env bash
# 38_ble_adv_forge — BLE Adv Forge
# Build and validate iBeacon, Eddystone and Fast Pair advertising payloads.
#
# Standalone top-level module (Section B). Self-locating and pkexec-safe:
# the polkit rule matches this script's path, so invoke it directly, never
# through `env`.

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

MOD_TMP="$TMP_DIR/ble_adv_forge"
MOD_LOOT="$LOOT_DIR/ble_adv_forge"
MOD_LOGS="$LOG_DIR/ble_adv_forge"
MOD_CAPS="$CAPTURES_DIR/ble_adv_forge"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

FRG_OUT="$MOD_LOOT/payloads"
mkdir -p "$FRG_OUT" 2>/dev/null

frg_have_hci() {
    local d
    for d in /sys/class/bluetooth/hci*; do
        [[ -e "$d" ]] && { basename "$d"; return 0; }
    done
    return 1
}

frg_status_tsv() {
    local h; h=$(frg_have_hci 2>/dev/null || true)
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'hci\t%s\n' "${h:-none}"
    printf 'hcitool\t%s\n' "$(command -v hcitool >/dev/null 2>&1 && echo 1 || echo 0)"
    # Building and validating a payload is pure data work. Only putting it
    # on the air needs a controller, so the two are gated separately.
    printf 'build\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'transmit\t%s\n' "$([[ -n "$h" ]] && echo 1 || echo 0)"
}

frg_templates_tsv() {
    cat <<'EOF'
ibeacon	Apple iBeacon	company 0x004C type 0x02, proximity UUID + major/minor	high
eddystone-uid	Eddystone UID	service 0xFEAA frame 0x00, 10-byte namespace + 6-byte instance	high
eddystone-url	Eddystone URL	service 0xFEAA frame 0x10, scheme-compressed URL	high
eddystone-tlm	Eddystone TLM	service 0xFEAA frame 0x20, telemetry	high
findmy	Apple Find My	company 0x004C type 0x12, offline-finding beacon	medium
fastpair	Google Fast Pair	company 0xFE2C, model id + tx power	medium
raw	Raw AD list	verbatim hex, validated for AD structure	high
EOF
}

# ── builders ─────────────────────────────────────────────────────────────
# All builders return a bare lowercase hex string so they compose.

_frg_ad() {  # _frg_ad TYPE HEXBODY -> "len type body"
    local t="$1" body="$2"
    local n=$(( ${#body} / 2 + 1 ))
    printf '%02x%s%s' "$n" "$t" "$body"
}

frg_ibeacon() {
    local uuid="$1" major="$2" minor="$3" tx="${4:--59}"
    [[ -z "$uuid" || -z "$major" || -z "$minor" ]] && {
        printf 'ERROR\tusage: --ibeacon UUID MAJOR MINOR [TX_POWER]\n' >&2; return 2; }
    local u; u=$(printf '%s' "$uuid" | tr -d -- '-:' | tr 'A-F' 'a-f')
    (( ${#u} != 32 )) && {
        printf 'ERROR\tUUID must be 32 hex digits (16 bytes), got %d\n' "${#u}" >&2; return 1; }
    local maj min
    maj=$(printf '%04x' "$((major & 0xffff))")
    min=$(printf '%04x' "$((minor & 0xffff))")
    local txh; txh=$(printf '%02x' "$(( (tx + 256) % 256 ))")
    # company id 4c00, then 02 (beacon type) 15 (length) uuid major minor tx
    _frg_ad ff "4c000215${u}${maj}${min}${txh}"
}

# Scheme prefixes and TLD shorthands are a fixed table in the Eddystone
# spec. Kept as data rather than case statements so the mapping is readable
# and cannot drift between the two directions.
_frg_scheme_table() {
    cat <<'TBL'
http://www.	00
https://www.	01
http://	02
https://	03
TBL
}

_frg_tld_table() {
    cat <<'TBL'
.info/	04
.com/	00
.org/	01
.edu/	02
.net/	03
.biz/	05
.gov/	06
.info	0b
.com	07
.org	08
.edu	09
.net	0a
.biz	0c
.gov	0d
TBL
}

_frg_lookup() {   # _frg_lookup TABLE KEY
    local tbl="$1" key="$2"
    printf '%s\n' "$tbl" | awk -F'\t' -v k="$key" '$1==k {print $2; exit}'
}

frg_eddystone_url() {
    local url="$1"
    [[ -z "$url" ]] && { printf 'ERROR\tusage: --eddystone-url URL\n' >&2; return 2; }

    local scheme="" rest="$url" sh=""
    local s
    for s in "http://www." "https://www." "http://" "https://"; do
        if [[ "$rest" == "$s"* ]]; then
            scheme=$(printf '%s' "$s" | sed 's/\./\\./g')
            sh=$(_frg_lookup "$(_frg_scheme_table)" "$s")
            rest="${rest#"$s"}"
            break
        fi
    done

    local tld="" tl="" t
    for t in ".info/" ".com/" ".org/" ".edu/" ".net/" ".biz/" ".gov/" ".info" ".com" ".org" ".edu" ".net" ".biz" ".gov"; do
        if [[ "$rest" == *"$t" ]]; then
            tl=$(_frg_lookup "$(_frg_tld_table)" "$t")
            tld="$t"
            rest="${rest%"$t"}"
            break
        fi
    done

    local bodyhex
    bodyhex=$(printf '%s' "$rest" | xxd -p | tr -d '\n')
    local payload="${sh}${bodyhex}${tl}"
    local total=$(( ${#payload} / 2 ))
    (( total > 17 )) && {
        printf 'ERROR\tcompressed URL is %d bytes, Eddystone allows 17\n' "$total" >&2
        printf 'NOTE\tshorten the URL or drop the scheme so it can be compressed\n' >&2
        return 1; }

    # service data: 16-bit UUID aa fe (0xFEAA LE), frame type 0x10, then body
    _frg_ad 16 "aafe10${payload}"
}

frg_eddystone_uid() {
    local ns="$1" inst="$2"
    [[ -z "$ns" || -z "$inst" ]] && {
        printf 'ERROR\tusage: --eddystone-uid NAMESPACE(20 hex) INSTANCE(12 hex)\n' >&2; return 2; }
    ns=$(printf '%s' "$ns" | tr -d -- '-:' | tr 'A-F' 'a-f')
    inst=$(printf '%s' "$inst" | tr -d -- '-:' | tr 'A-F' 'a-f')
    (( ${#ns} != 20 )) && { printf 'ERROR\tnamespace must be 20 hex digits\n' >&2; return 1; }
    (( ${#inst} != 12 )) && { printf 'ERROR\tinstance must be 12 hex digits\n' >&2; return 1; }
    _frg_ad 16 "aafe00${ns}${inst}"
}

frg_fastpair() {
    local model="$1" tx="${2:--40}"
    [[ -z "$model" ]] && { printf 'ERROR\tusage: --fastpair MODEL_ID_HEX [TX]\n' >&2; return 2; }
    model=$(printf '%s' "$model" | tr -d -- '-:' | tr 'A-F' 'a-f')
    local m="${model:0:6}"
    (( ${#m} != 6 )) && { printf 'ERROR\tmodel id must be 3 bytes\n' >&2; return 1; }
    local bh; bh=$(printf '%02x' "$(( (tx + 256) % 256 ))")
    local m1="${m:0:2}" m2="${m:2:2}" m3="${m:4:2}"
    # Fast Pair puts the model id in big-endian order in the AD payload
    _frg_ad ff "2cfe${m2}${m1}${m3}${bh}"
}

frg_raw() {
    local hex="$1"
    [[ -z "$hex" ]] && { printf 'ERROR\tusage: --raw AD_HEX\n' >&2; return 2; }
    printf '%s' "$hex" | tr -d ' :\n' | tr 'A-F' 'a-f'
}

# ── AD validation ────────────────────────────────────────────────────────
# Walks the AD structures and reports any malformed length, which is the
# failure that makes a forged advertisement silently undecodable.
frg_validate() {
    local hex="$1"
    [[ -z "$hex" ]] && { printf 'ERROR\tusage: --validate AD_HEX\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    python3 - "$hex" <<'PYEOF'
import sys

raw = "".join(sys.argv[1].split()).replace(":", "")
try:
    data = bytes.fromhex(raw)
except ValueError:
    print("VALID\t0"); print("ERROR\tnot valid hex", file=sys.stderr); sys.exit(1)

NAMES = {0x01:"flags",0x02:"uuid16_inc",0x03:"uuid16",0x06:"uuid128_inc",
         0x07:"uuid128",0x08:"name_short",0x09:"name_full",0x0A:"tx_power",
         0x16:"service_data16",0x19:"appearance",0x20:"service_data32",
         0x21:"service_data128",0xFF:"manufacturer"}

i = 0
n = 0
ok = True
while i < len(data):
    ln = data[i]
    if ln == 0:
        i += 1
        continue
    if i + 1 + ln > len(data):
        print("TRUNCATED\tat offset %d: declared %d bytes, %d remain"
              % (i, ln, len(data) - i - 1))
        ok = False
        break
    ad = data[i+1:i+1+ln]
    typ = ad[0] if ad else 0
    print("AD\t%s\tlen=%d\tdata=%s" % (NAMES.get(typ, "0x%02x" % typ), ln, ad[1:].hex()))
    i += 1 + ln
    n += 1

print("TOTAL_BYTES\t%d" % len(data))
print("AD_COUNT\t%d" % n)
print("VALID\t%d" % (1 if ok and i == len(data) else 0))
sys.exit(0 if (ok and i == len(data)) else 1)
PYEOF
}

# ── transmit (radio-gated) ───────────────────────────────────────────────
frg_transmit() {
    local hex="$1"
    [[ -z "$hex" ]] && { printf 'ERROR\tusage: --transmit AD_HEX\n' >&2; return 2; }
    local h; h=$(frg_have_hci 2>/dev/null) || {
        printf 'ERROR\tno Bluetooth adapter — cannot transmit\n' >&2
        printf 'NOTE\tbuild and validate offline with --build/--validate; a saved\n' >&2
        printf 'NOTE\tpayload can be injected later from a machine with a controller.\n' >&2
        return 1; }
    printf 'HCI\t%s\n' "$h"
    printf 'NOTE\tAdvertising payload injection needs a vendor-specific HCI\n'
    printf 'NOTE\tcommand (LE Set Advertising Data accepts only 31 bytes and\n'
    printf 'NOTE\tmust be followed by LE Set Advertising Enable).\n'
    mkdir -p "$FRG_OUT"
    local f="$FRG_OUT/payload_$(date +%s).hex"
    printf '%s\n' "$hex" > "$f"
    printf 'SAVED\t%s\n' "$f"
}

# ── self-test ────────────────────────────────────────────────────────────
frg_selftest() {
    local bad=0
    chk() {
        local name="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$name"
        else printf '%s\tFAIL want=%s got=%s\n' "$name" "$want" "$got"; bad=$((bad+1)); fi
    }

    # iBeacon: 25-byte payload => AD length byte 0x1a (26), type 0xff
    local ib; ib=$(frg_ibeacon "e2c56db5dffb48d2b060d0f5a71096e0" 1 2 -59)
    chk ibeacon_prefix "${ib:0:12}" "1aff4c000215"
    chk ibeacon_len "${#ib}" "54"

    # Eddystone-URL: https://www.  -> scheme 0x01, .com/ -> 0x00
    local eu; eu=$(frg_eddystone_url "https://www.example.com/")
    chk eddystone_url "${eu}" "0d16aafe10016578616d706c6500"

    # Eddystone-UID: 10-byte namespace + 6-byte instance + 4 header bytes
    local uid; uid=$(frg_eddystone_uid "00112233445566778899" "aabbccddeeff")
    chk eddystone_uid "${uid}" "1416aafe0000112233445566778899aabbccddeeff"

    # Validation must reject a truncated structure.
    if frg_validate "1eff4c00" >/dev/null 2>&1; then
        printf 'truncation-detected\tFAIL (accepted a bad payload)\n'; bad=$((bad+1))
    else
        printf 'truncation-detected\tPASS\n'
    fi

    # And accept a good one.
    if frg_validate "$ib" >/dev/null 2>&1; then
        printf 'valid-payload-accepted\tPASS\n'
    else
        printf 'valid-payload-accepted\tFAIL\n'; bad=$((bad+1))
    fi

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

frg_info() {
    cat <<'EOF'
BLE advertisement forging

An advertising payload is a list of AD structures, each
[length][type][data]. The length counts the type byte, so a 25-byte
iBeacon body is advertised with length 0x1a.

Supported templates
  iBeacon         company 0x004C, beacon type 0x02, length 0x15,
                  then 16-byte UUID + 2-byte major + 2-byte minor +
                  1-byte calibrated TX power (signed).
  Eddystone-UID   service 0xFEAA, frame 0x00, 10-byte namespace,
                  6-byte instance.
  Eddystone-URL   service 0xFEAA, frame 0x10, scheme byte, URL body,
                  TLD byte. Scheme and TLD use the fixed compression
                  table from the Eddystone spec, which is why URLs must
                  be shortened to fit the 17-byte budget.
  Fast Pair       company 0xFE2C, model id, TX power.

Everything here is offline: payloads are built and structurally
validated without a controller. Transmitting requires an adapter and is
refused with a named reason when none is present.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
frg_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      frg_status_tsv ;;
        --templates-tsv)   frg_templates_tsv ;;
        --ibeacon)         frg_ibeacon "$@" ;;
        --eddystone-url)   frg_eddystone_url "$@" ;;
        --eddystone-uid)   frg_eddystone_uid "$@" ;;
        --fastpair)        frg_fastpair "$@" ;;
        --raw)             frg_raw "$@" ;;
        --validate)        frg_validate "$@" ;;
        --transmit)        frg_transmit "$@" ;;
        --selftest)        frg_selftest ;;
        --info)            frg_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --templates-tsv
  --ibeacon UUID MAJOR MINOR [TX_POWER]
  --eddystone-url URL
  --eddystone-uid NAMESPACE INSTANCE
  --fastpair MODEL_ID_HEX [TX]
  --raw AD_HEX
  --validate AD_HEX          structural check of an AD list
  --transmit AD_HEX          needs a Bluetooth adapter
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
    frg_cli_main "$@"
fi

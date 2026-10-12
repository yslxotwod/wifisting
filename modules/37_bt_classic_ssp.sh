#!/usr/bin/env bash
# 37_bt_classic_ssp — Bluetooth Classic SSP
# Secure Simple Pairing association models and HCI log pairing reconstruction.
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

MOD_TMP="$TMP_DIR/bt_classic_ssp"
MOD_LOOT="$LOOT_DIR/bt_classic_ssp"
MOD_LOGS="$LOG_DIR/bt_classic_ssp"
MOD_CAPS="$CAPTURES_DIR/bt_classic_ssp"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

SSP_LOGS="$MOD_LOOT/pairing"
mkdir -p "$SSP_LOGS" 2>/dev/null

ssp_have_hci() {
    local d
    for d in /sys/class/bluetooth/hci*; do
        [[ -e "$d" ]] && { basename "$d"; return 0; }
    done
    return 1
}

ssp_status_tsv() {
    local h; h=$(ssp_have_hci 2>/dev/null || true)
    printf 'hci\t%s\n' "${h:-none}"
    printf 'btmon\t%s\n'  "$(command -v btmon >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    # Parsing an existing btsnoop log and computing the association model are
    # offline operations; only capturing a live pairing needs an adapter.
    printf 'offline_analysis\t1\n'
    printf 'live_capture\t%s\n' "$([[ -n "$h" ]] && echo 1 || echo 0)"
    local n=0
    [[ -d "$SSP_LOGS" ]] && n=$(find "$SSP_LOGS" -maxdepth 1 -type f -name '*.btsnoop' 2>/dev/null | wc -l)
    printf 'cached_logs\t%s\n' "$n"
}

# ── association model ────────────────────────────────────────────────────
# Bluetooth Core Spec Vol 3 Part H, Table 2.8. The association model decides
# whether the pairing is protected against an active man in the middle:
# Numeric Comparison and Passkey Entry are, Just Works is not.
ssp_matrix() {
    cat <<'EOF'
INITIATOR	RESPONDER	MODEL	MITM_PROTECTED
DisplayOnly	DisplayOnly	Just Works	0
DisplayOnly	DisplayYesNo	Just Works	0
DisplayOnly	KeyboardOnly	Passkey Entry	1
DisplayOnly	NoInputNoOutput	Just Works	0
DisplayOnly	KeyboardDisplay	Passkey Entry	1
DisplayYesNo	DisplayOnly	Just Works	0
DisplayYesNo	DisplayYesNo	Numeric Comparison	1
DisplayYesNo	KeyboardOnly	Passkey Entry	1
DisplayYesNo	NoInputNoOutput	Just Works	0
DisplayYesNo	KeyboardDisplay	Numeric Comparison	1
KeyboardOnly	DisplayOnly	Passkey Entry	1
KeyboardOnly	DisplayYesNo	Passkey Entry	1
KeyboardOnly	KeyboardOnly	Passkey Entry	1
KeyboardOnly	NoInputNoOutput	Just Works	0
KeyboardOnly	KeyboardDisplay	Passkey Entry	1
NoInputNoOutput	DisplayOnly	Just Works	0
NoInputNoOutput	DisplayYesNo	Just Works	0
NoInputNoOutput	KeyboardOnly	Just Works	0
NoInputNoOutput	NoInputNoOutput	Just Works	0
NoInputNoOutput	KeyboardDisplay	Just Works	0
KeyboardDisplay	DisplayOnly	Passkey Entry	1
KeyboardDisplay	DisplayYesNo	Numeric Comparison	1
KeyboardDisplay	KeyboardOnly	Passkey Entry	1
KeyboardDisplay	NoInputNoOutput	Just Works	0
KeyboardDisplay	KeyboardDisplay	Numeric Comparison	1
EOF
}

# Accepts the HCI numeric IO-capability values (0-4) or their names.
ssp_io_name() {
    case "$1" in
        0|DisplayOnly)      printf 'DisplayOnly' ;;
        1|DisplayYesNo)     printf 'DisplayYesNo' ;;
        2|KeyboardOnly)     printf 'KeyboardOnly' ;;
        3|NoInputNoOutput)  printf 'NoInputNoOutput' ;;
        4|KeyboardDisplay)  printf 'KeyboardDisplay' ;;
        *)                  printf '' ;;
    esac
}

ssp_model() {
    local init="$1" resp="$2" oob="${3:-}"
    [[ -z "$init" || -z "$resp" ]] && {
        printf 'ERROR\tusage: --model INITIATOR_IO RESPONDER_IO [oob]\n' >&2; return 2; }
    local i r
    i=$(ssp_io_name "$init"); r=$(ssp_io_name "$resp")
    [[ -z "$i" ]] && { printf 'ERROR\tbad initiator IO capability: %s\n' "$init" >&2; return 1; }
    [[ -z "$r" ]] && { printf 'ERROR\tbad responder IO capability: %s\n' "$resp" >&2; return 1; }

    printf 'INITIATOR_IO\t%s\nRESPONDER_IO\t%s\n' "$i" "$r"

    # OOB short-circuits the matrix entirely (Vol 3 Part H 2.2.6).
    if [[ "$oob" == "oob" || "$oob" == "1" ]]; then
        printf 'MODEL\tOut of Band\nMITM_PROTECTED\t1\n'
        printf 'NOTE\tOOB authentication data was exchanged, so the association\n'
        printf 'NOTE\tmodel is Out of Band regardless of IO capabilities.\n'
        return 0
    fi

    local model
    model=$(ssp_matrix | awk -F'\t' -v i="$i" -v r="$r" \
            'NR>1 && $1==i && $2==r {print $3"\t"$4; exit}')
    [[ -z "$model" ]] && { printf 'ERROR\tno matrix entry for %s/%s\n' "$i" "$r" >&2; return 1; }
    printf 'MODEL\t%s\n' "$(printf '%s' "$model" | cut -f1)"
    printf 'MITM_PROTECTED\t%s\n' "$(printf '%s' "$model" | cut -f2)"

    case "$(printf '%s' "$model" | cut -f1)" in
        "Just Works")
            printf 'NOTE\tJust Works performs no user verification, so an active\n'
            printf 'NOTE\tman in the middle can complete pairing with both sides.\n' ;;
        "Numeric Comparison")
            printf 'NOTE\tBoth sides display a 6-digit value; the user must compare\n'
            printf 'NOTE\tthem. Protection depends entirely on the user actually doing so.\n' ;;
        "Passkey Entry")
            printf 'NOTE\tA 6-digit passkey is entered on one side and displayed on\n'
            printf 'NOTE\tthe other, which resists a passive eavesdropper.\n' ;;
    esac
}

# ── btsnoop parsing ──────────────────────────────────────────────────────
# btsnoop is the standard HCI log container (Symbian, reused by BlueZ and
# Android). Header: magic "btsnoop\0", version, datalink type. Each record:
#   original_len(4) included_len(4) flags(4) drops(4) timestamp(8) data...
# all big-endian.
ssp_analyze() {
    local log="$1"
    [[ -z "$log" || ! -f "$log" ]] && {
        printf 'ERROR\tusage: --analyze BTSNOOP\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }

    python3 - "$log" <<'PYEOF'
import struct, sys

path = sys.argv[1]

# HCI event codes that make up a Secure Simple Pairing exchange.
EVENTS = {
    0x2B: "Link Key Request", 0x2C: "Link Key Notification",
    0x2D: "PIN Code Request", 0x2E: "Link Key Request Reply",
    0x2F: "Link Key Request Neg Reply", 0x30: "IO Capability Request",
    0x31: "IO Capability Request Reply", 0x32: "User Confirmation Request",
    0x33: "User Confirmation Request Reply", 0x34: "User Passkey Request",
    0x35: "User Passkey Request Reply", 0x36: "Remote OOB Data Request",
    0x37: "Remote OOB Data Request Reply", 0x38: "Simple Pairing Complete",
    0x3B: "User Passkey Notification", 0x3C: "Keypress Notification",
}
IO = {0: "DisplayOnly", 1: "DisplayYesNo", 2: "KeyboardOnly",
      3: "NoInputNoOutput", 4: "KeyboardDisplay"}

def addr(b):
    return ":".join("%02X" % x for x in reversed(b[:6]))

try:
    fh = open(path, "rb")
except OSError as e:
    print("ERROR\t%s" % e, file=sys.stderr); sys.exit(1)

with fh:
    hdr = fh.read(16)
    if len(hdr) < 16 or not hdr.startswith(b"btsnoop\x00"):
        print("ERROR\tnot a btsnoop file (bad magic)", file=sys.stderr); sys.exit(1)
    version, datalink = struct.unpack(">II", hdr[8:16])
    print("BTSNOOP_VERSION\t%d" % version)
    print("DATALINK\t%d" % datalink)

    # Datalink 1002 (H4) prefixes each record with the HCI packet type byte;
    # 1001 does not, so the type byte has to be inferred.
    type_byte = datalink in (1002, 1003, 1004)

    records = events = 0
    exchange = []
    while True:
        rh = fh.read(24)
        if len(rh) < 24:
            break
        orig, incl, flags, drops, ts = struct.unpack(">IIIIQ", rh)
        data = fh.read(incl)
        if len(data) < incl:
            break
        records += 1

        if type_byte:
            if not data:
                continue
            ptype, payload = data[0], data[1:]
        else:
            ptype, payload = 0x04, data

        if ptype != 0x04 or len(payload) < 2:      # 0x04 = HCI Event
            continue
        code, plen = payload[0], payload[1]
        params = payload[2:2+plen]
        name = EVENTS.get(code)
        if not name:
            continue
        events += 1

        detail = ""
        if code in (0x30,) and len(params) >= 6:
            detail = "bdaddr=%s" % addr(params)
        elif code == 0x31 and len(params) >= 9:
            detail = "bdaddr=%s io=%s(%d) oob=%d auth_req=0x%02x" % (
                addr(params), IO.get(params[6], "?"), params[6], params[7], params[8])
        elif code in (0x32,) and len(params) >= 10:
            val = int.from_bytes(params[6:10], "little")
            detail = "bdaddr=%s numeric=%06d" % (addr(params), val % 1000000)
        elif code in (0x3B,) and len(params) >= 10:
            val = int.from_bytes(params[6:10], "little")
            detail = "bdaddr=%s passkey=%06d" % (addr(params), val % 1000000)
        elif code in (0x38,) and len(params) >= 7:
            detail = "bdaddr=%s status=0x%02x" % (addr(params), params[6])
        elif len(params) >= 6:
            detail = "bdaddr=%s" % addr(params)

        print("EVENT\t0x%02X\t%s\t%s" % (code, name, detail))
        exchange.append((code, name, detail))

    print("RECORDS\t%d" % records)
    print("SSP_EVENTS\t%d" % events)

    if events == 0:
        print("NOTE\tno SSP HCI events in this log — either it holds no\n"
              "NOTE\tpairing, or the adapter did not report them.")
        sys.exit(0)

    # Reconstruct which association model was actually used.
    #
    # Order matters and follows the spec rather than the event order:
    #   1. Either side reporting NoInputNoOutput forces Just Works, whatever
    #      else appears (Vol 3 Part H Table 2.8).
    #   2. A User Confirmation Request means Numeric Comparison.
    #   3. A passkey notification or request means Passkey Entry.
    #   4. Otherwise, if pairing completed at all, it was Just Works - a Just
    #      Works pairing goes straight from the capability exchange to Simple
    #      Pairing Complete and never emits 0x32/0x33/0x3B, so waiting for
    #      one of those would report a completed pairing as "incomplete".
    io_seen = {}
    numeric = False
    passkey = False
    completed = False
    for code, name, detail in exchange:
        if code == 0x31 and "io=" in detail:
            for tok in detail.split():
                if tok.startswith("io="):
                    cap = tok[3:].split("(")[0]
                    io_seen[cap] = io_seen.get(cap, 0) + 1
        if code == 0x32:
            numeric = True
        if code in (0x3B, 0x34):
            passkey = True
        if code == 0x38:
            completed = True

    no_input = "NoInputNoOutput" in io_seen
    print("IO_CAPABILITIES\t%s" % (",".join(sorted(io_seen)) or "unknown"))

    if numeric and not no_input:
        model, mitm = "Numeric Comparison", 1
    elif passkey and not no_input:
        model, mitm = "Passkey Entry", 1
    elif no_input:
        model, mitm = "Just Works", 0
    elif completed:
        model, mitm = "Just Works", 0
    else:
        model, mitm = "incomplete", "unknown"

    print("OBSERVED_MODEL\t%s" % model)
    print("MITM_PROTECTED\t%s" % mitm)
    if model == "Just Works":
        if no_input:
            print("NOTE\ta side reported NoInputNoOutput, which forces Just Works\n"
                  "NOTE\tregardless of the other capabilities: no MITM protection.")
        else:
            print("NOTE\tPairing completed with no numeric comparison and no passkey\n"
                  "NOTE\tnotification, which is the Just Works path: no MITM protection.")
PYEOF
}

# ── live capture (radio-gated) ───────────────────────────────────────────
ssp_capture() {
    local dur="${1:-20}"
    local h; h=$(ssp_have_hci 2>/dev/null) || {
        printf 'ERROR\tno Bluetooth adapter — cannot capture a pairing\n' >&2
        printf 'NOTE\toffline analysis still works: --analyze BTSNOOP\n' >&2
        return 1; }
    command -v btmon >/dev/null 2>&1 || {
        printf 'ERROR\tbtmon not installed (apt install bluez)\n' >&2; return 1; }

    mkdir -p "$SSP_LOGS"
    local out="$SSP_LOGS/pairing_$(date +%s).btsnoop"
    printf 'HCI\t%s\nDURATION\t%s\nOUT\t%s\n' "$h" "$dur" "$out"
    printf 'NOTE\tbtmon writes btsnoop; pair a device while this runs, then\n'
    printf 'NOTE\tanalyse the file with --analyze.\n'
    timeout "$dur" btmon -i "$h" -w "$out" >/dev/null 2>&1 || true
    if [[ -s "$out" ]]; then
        printf 'CAPTURED\t1\n'
    else
        printf 'CAPTURED\t0\n'
        printf 'NOTE\tno data written\n'
        rm -f "$out"; return 1
    fi
}

ssp_list_tsv() {
    local f
    for f in "$SSP_LOGS"/*.btsnoop; do
        [[ -e "$f" ]] || continue
        printf '%s\t%s\n' "$f" "$(stat -c%s "$f" 2>/dev/null || echo 0)"
    done
}

# ── known-answer self-test ───────────────────────────────────────────────
# Builds a synthetic btsnoop containing a Numeric Comparison pairing and
# checks the parser recovers it. Validates the container parsing and the
# event decoding together.
ssp_selftest() {
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    mkdir -p "$MOD_TMP"

    # 1. Association matrix: the four outcomes that matter. A wrong matrix
    #    would silently mislabel an unprotected pairing as protected.
    local out
    out=$(ssp_model DisplayYesNo DisplayYesNo)
    chk model-numeric-comp "$(fld "$out" MODEL)" "Numeric Comparison"
    chk model-numeric-mitm  "$(fld "$out" MITM_PROTECTED)" 1

    out=$(ssp_model NoInputNoOutput DisplayYesNo)
    chk model-just-works "$(fld "$out" MODEL)" "Just Works"
    chk model-just-works-mitm "$(fld "$out" MITM_PROTECTED)" 0

    out=$(ssp_model KeyboardOnly DisplayOnly)
    chk model-passkey "$(fld "$out" MODEL)" "Passkey Entry"
    chk model-passkey-mitm "$(fld "$out" MITM_PROTECTED)" 1

    # OOB must short-circuit the matrix entirely.
    out=$(ssp_model NoInputNoOutput NoInputNoOutput oob)
    chk model-oob-overrides "$(fld "$out" MODEL)" "Out of Band"
    chk model-oob-mitm "$(fld "$out" MITM_PROTECTED)" 1

    # Numeric IO capability values must map to the same rows as the names.
    out=$(ssp_model 1 1)
    chk io-numeric-values "$(fld "$out" MODEL)" "Numeric Comparison"

    ssp_model DisplayYesNo Bogus >/dev/null 2>&1 && { printf 'bad-io-rejected\tFAIL\n'; bad=$((bad+1)); } || printf 'bad-io-rejected\tPASS\n'

    # 2. btsnoop parsing: a synthetic Numeric Comparison pairing must be
    #    reconstructed as protected, and a Just Works pairing as not.
    python3 - "$MOD_TMP/nc.btsnoop" "$MOD_TMP/jw.btsnoop" <<'PYEOF'
import struct, sys

def ev(code, params):
    return bytes([0x04, code, len(params)]) + params

def rec(data, ts):
    return struct.pack(">IIIIQ", len(data), len(data), 0, 0, ts) + data

bd = bytes([0x40, 0x9F, 0xB5, 0x00, 0x5A, 0xD0])
hdr = b"btsnoop\x00" + struct.pack(">II", 1, 1002)

nc = hdr
nc += rec(ev(0x30, bd), 1)
nc += rec(ev(0x31, bd + bytes([1, 0, 0x04])), 2)          # DisplayYesNo
nc += rec(ev(0x32, bd + struct.pack("<I", 123456)), 3)     # numeric comparison
nc += rec(ev(0x38, bd + bytes([0x00])), 4)
open(sys.argv[1], "wb").write(nc)

jw = hdr
jw += rec(ev(0x30, bd), 1)
jw += rec(ev(0x31, bd + bytes([3, 0, 0x00])), 2)          # NoInputNoOutput
jw += rec(ev(0x38, bd + bytes([0x00])), 3)                 # straight to complete
open(sys.argv[2], "wb").write(jw)
PYEOF

    out=$(ssp_analyze "$MOD_TMP/nc.btsnoop")
    chk btsnoop-records "$(fld "$out" RECORDS)" 4
    chk btsnoop-ssp-events "$(fld "$out" SSP_EVENTS)" 4
    chk btsnoop-numeric "$(fld "$out" OBSERVED_MODEL)" "Numeric Comparison"
    chk btsnoop-numeric-mitm "$(fld "$out" MITM_PROTECTED)" 1
    # The 6-digit value must survive the round trip through the log.
    printf '%s\n' "$out" | grep -q 'numeric=123456' \
        && printf 'btsnoop-numeric-value\tPASS\n' \
        || { printf 'btsnoop-numeric-value\tFAIL\n'; bad=$((bad+1)); }

    out=$(ssp_analyze "$MOD_TMP/jw.btsnoop")
    chk btsnoop-justworks-model "$(fld "$out" OBSERVED_MODEL)" "Just Works"
    chk btsnoop-justworks-mitm "$(fld "$out" MITM_PROTECTED)" 0

    # 3. A file that is not btsnoop must be refused, not misparsed.
    printf 'not a btsnoop file at all\n' > "$MOD_TMP/bad.btsnoop"
    ssp_analyze "$MOD_TMP/bad.btsnoop" >/dev/null 2>&1 \
        && { printf 'non-btsnoop-rejected\tFAIL\n'; bad=$((bad+1)); } \
        || printf 'non-btsnoop-rejected\tPASS\n'

    rm -f "$MOD_TMP/nc.btsnoop" "$MOD_TMP/jw.btsnoop" "$MOD_TMP/bad.btsnoop"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

ssp_info() {
    cat <<'EOF'
Bluetooth Classic Secure Simple Pairing

SSP picks an association model from the two devices' IO capabilities
(Vol 3 Part H, Table 2.8). Only two of the four models resist an active
man in the middle:

  Numeric Comparison  both sides display a 6-digit value the user compares
  Passkey Entry       a 6-digit passkey is typed on one side
  Out of Band         authentication data exchanged over another channel
  Just Works          no user verification at all — no MITM protection

Just Works is not a bug, it is the specified outcome whenever either side
reports NoInputNoOutput, which is why headset and car-kit pairing is
routinely unprotected.

Live pairing appears in an HCI log as a fixed sequence of events:
  0x30 IO Capability Request   -> 0x31 IO Capability Request Reply
  0x32 User Confirmation Request (numeric comparison value)
  0x3B User Passkey Notification (passkey on the displaying side)
  0x38 Simple Pairing Complete

--analyze reads a btsnoop log and reconstructs which model was used.
--capture records a new one with btmon and needs a Bluetooth adapter, which
this machine does not have.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
ssp_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  ssp_status_tsv ;;
        --matrix)      ssp_matrix ;;
        --model)       ssp_model "$@" ;;
        --analyze)     ssp_analyze "$@" ;;
        --list-tsv)    ssp_list_tsv ;;
        --capture)     ssp_capture "$@" ;;
        --selftest)    ssp_selftest ;;
        --info)        ssp_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --matrix                  IO capability -> association model table
  --model INITIATOR_IO RESPONDER_IO [oob]
  --analyze BTSNOOP         reconstruct the pairing from an HCI log
  --list-tsv                cached btsnoop logs
  --capture [SECONDS]       record a live pairing (needs an adapter)
  --selftest                parse a synthetic numeric-comparison pairing
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
    ssp_cli_main "$@"
fi

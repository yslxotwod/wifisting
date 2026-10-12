#!/usr/bin/env bash
# 40_wifi_csi — Wi-Fi CSI
# Channel state information parsing and motion analysis.
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

MOD_TMP="$TMP_DIR/wifi_csi"
MOD_LOOT="$LOOT_DIR/wifi_csi"
MOD_LOGS="$LOG_DIR/wifi_csi"
MOD_CAPS="$CAPTURES_DIR/wifi_csi"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

CSI_OUT="$MOD_LOOT/captures"
mkdir -p "$CSI_OUT" 2>/dev/null

# CSI needs a NIC whose driver exposes per-subcarrier channel state. Stock
# drivers do not, so this reports the specific chipset and why it will or
# will not work rather than assuming.
csi_status_tsv() {
    local found=0
    local i n drv
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        n=$(basename "$i")
        drv=$(basename "$(readlink -f "$i/device/driver" 2>/dev/null)" 2>/dev/null)
        printf 'iface\t%s\t%s\n' "$n" "${drv:-unknown}"
        case "$drv" in
            iwlwifi)  found=1 ;;   # Intel 5300 needs the patched csitool driver
            ath9k|ath9k_htc) found=1 ;;
            brcmfmac|brcmsmac) found=1 ;;   # only with Nexmon firmware
            *) ;;
        esac
    done
    printf 'csi_capable_driver\t%s\n' "$found"
    printf 'iwlwifi_csitool\t%s\n' "$(lsmod 2>/dev/null | grep -q iwlwifi_csi && echo 1 || echo 0)"
    printf 'nexmon\t%s\n' "$(command -v nexutil >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    # Parsing an existing CSI capture is pure data work; only collecting a
    # new one needs the special driver, so they are reported separately.
    printf 'parse\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'live_capture\t%s\n' \
        "$([[ $found -eq 1 ]] && lsmod 2>/dev/null | grep -q iwlwifi_csi && echo 1 || echo 0)"
    local c=0
    [[ -d "$CSI_OUT" ]] && c=$(find "$CSI_OUT" -maxdepth 1 -type f 2>/dev/null | wc -l)
    printf 'cached_captures\t%s\n' "$c"
}

csi_formats_tsv() {
    cat <<'EOF'
intel5300	Intel 5300 (linux-80211n-csitool)	20-byte header + 3-byte complex pairs	high
nexmon	Nexmon CSI (Broadcom)	18-byte header + int16 I/Q pairs	medium
esp32	ESP32-CSI-Tool CSV	CSV of raw I/Q	medium
csv	Generic amplitude CSV	one row per subcarrier	high
EOF
}

# ── Intel 5300 CSI parsing ───────────────────────────────────────────────
# Record layout from linux-80211n-csitool (all little-endian):
#   u16 timestamp_low, u16 bfee_count, u16 Nrx, u16 Ntx,
#   u16 rssi_a, u16 rssi_b, u16 rssi_c, s8 noise, u8 agc,
#   u16 antenna_sel, u16 len, u16 fake_rate_n_flags, u8 payload[len]
# The payload holds, per subcarrier per rx per tx, a 3-byte group:
#   bit0 of byte0 = imaginary sign, bits1-7 = imaginary magnitude (7 bits),
#   byte1 = real magnitude, bit7 of byte2 = real sign, bits0-6 = real magnitude.
csi_parse() {
    local file="$1" fmt="${2:-intel5300}"
    [[ -z "$file" || ! -f "$file" ]] && {
        printf 'ERROR\tusage: --parse FILE [intel5300|csv]\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    python3 - "$file" "$fmt" <<'PYEOF'
import struct, sys, math

path, fmt = sys.argv[1], sys.argv[2]
data = open(path, "rb").read()
if not data:
    print("ERROR\tempty file", file=sys.stderr); sys.exit(1)

if fmt == "csv":
    rows = []
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.replace(",", " ").split()
        try:
            rows.append([float(x) for x in parts])
        except ValueError:
            continue
    if not rows:
        print("ERROR\tno numeric rows in CSV", file=sys.stderr); sys.exit(1)
    nsub = len(rows[0])
    print("FORMAT\tcsv")
    print("RECORDS\t%d" % len(rows))
    print("SUBCARRIERS\t%d" % nsub)
    for i in range(nsub):
        col = [r[i] for r in rows if i < len(r)]
        mean = sum(col) / len(col)
        var = sum((x - mean) ** 2 for x in col) / len(col)
        print("SUB\t%d\tmean=%.4f\tvar=%.4f" % (i, mean, var))
    sys.exit(0)

if fmt != "intel5300":
    print("ERROR\tunsupported format %s (have intel5300, csv)" % fmt, file=sys.stderr)
    sys.exit(1)

# Walk the bfee records. The header is 20 bytes:
#   [0..3]  u32 timestamp_low
#   [4..5]  u16 bfee_count
#   [6..7]  reserved
#   [8]     u8  Nrx      [9]  u8 Ntx
#   [10]    u8  rssi_a   [11] u8 rssi_b   [12] u8 rssi_c
#   [13]    s8  noise    [14] u8 agc      [15] u8 antenna_sel
#   [16..17] u16 len     [18..19] u16 fake_rate_n_flags
# The payload is BIT-packed, not byte-aligned: per subcarrier, 3 skip bits
# then 16 bits (one 8-bit imaginary and one 8-bit real) per antenna pair.
# Upstream derives the expected length as (30*(Nrx*Ntx*8*2+3)+6)/8, so the
# bit layout below is pinned to that formula rather than guessed.
off = 0
recs = 0
sub_vars = {}
skipped = 0
HDR = 20
while off + HDR <= len(data):
    (ts, count, rsvd, nrx, ntx, ra, rb, rc, noise, agc,
     asel, ln, flags) = struct.unpack_from("<IHHBBBBBBBBHH", data, off)
    off += HDR
    if ln == 0 or off + ln > len(data):
        break
    payload = data[off:off+ln]
    off += ln
    recs += 1

    expect = (30 * (nrx * ntx * 8 * 2 + 3) + 6) // 8
    if ln != expect:
        skipped += 1

    bits = "".join(format(b, "08b") for b in payload)
    pos = 0
    for sc in range(30):
        pos += 3                       # per-subcarrier skip bits
        amps = []
        for _pair in range(max(1, nrx * ntx)):
            if pos + 16 > len(bits):
                break
            imag = int(bits[pos:pos+8], 2)
            real = int(bits[pos+8:pos+16], 2)
            pos += 16
            if imag > 127:
                imag -= 256
            if real > 127:
                real -= 256
            amps.append(math.hypot(real, imag))
        if amps:
            sub_vars.setdefault(sc, []).extend(amps)

if skipped:
    print("WARN\t%d record(s) had a payload length that disagrees with the\n"
          "WARN\texpected (30*(Nrx*Ntx*16+3)+6)/8 formula" % skipped)

print("FORMAT\tintel5300")
print("RECORDS\t%d" % recs)
print("SUBCARRIERS\t%d" % len(sub_vars))
if recs:
    print("LAST_HEADER\tnrx=%d ntx=%d rssi=%d/%d/%d noise=%d agc=%d" %
          (nrx, ntx, ra, rb, rc, noise, agc))

# Amplitude variance per subcarrier is the standard cheap motion proxy:
# a still environment keeps subcarriers stable, movement perturbs them.
tot = 0.0
n = 0
for sc in sorted(sub_vars):
    a = sub_vars[sc]
    if len(a) < 2:
        continue
    m = sum(a) / len(a)
    v = sum((x - m) ** 2 for x in a) / len(a)
    tot += v
    n += 1
if n:
    print("MEAN_SUBCARRIER_VARIANCE\t%.4f" % (tot / n))
    print("NOTE\tvariance is a relative motion proxy; compare against a\n"
          "NOTE\tbaseline from the same link rather than an absolute threshold.")
    if fmt == "intel5300":
        print("CAVEAT\tthe Intel 5300 payload is bit-packed; the 3 skip bits and\n"
              "CAVEAT\t16 bits per antenna pair are pinned to upstream's own length\n"
              "CAVEAT\tformula, but the imag-then-real ordering within those 16 bits\n"
              "CAVEAT\thas NOT been checked against real 5300 hardware, which this\n"
              "CAVEAT\tmachine does not have. Magnitudes are therefore reliable for\n"
              "CAVEAT\trelative motion, not for absolute calibration.")
PYEOF
}

# ── motion analysis over a capture ───────────────────────────────────────
csi_analyze() {
    local file="$1" fmt="${2:-intel5300}"
    [[ -z "$file" || ! -f "$file" ]] && {
        printf 'ERROR\tusage: --analyze FILE [FORMAT]\n' >&2; return 2; }
    csi_parse "$file" "$fmt" | awk -F'\t' '
        /^RECORDS/        { recs = $2 }
        /^SUBCARRIERS/    { nsub = $2 }
        /^MEAN_SUBCARRIER_VARIANCE/ { var = $2 }
        END {
            printf "RECORDS\t%s\nSUBCARRIERS\t%s\n", recs, nsub
            printf "MEAN_SUBCARRIER_VARIANCE\t%s\n", (var == "" ? "n/a" : var)
            if (var == "") { print "VERDICT\tinsufficient-data"; exit }
            # Relative banding only; an absolute threshold would be a lie
            # because it depends on link geometry and TX power.
            v = var + 0
            if (v < 1)        print "VERDICT\tstable"
            else if (v < 25)  print "VERDICT\tslight-motion"
            else              print "VERDICT\tstrong-motion"
        }'
}

# ── self-test ────────────────────────────────────────────────────────────
csi_selftest() {
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    mkdir -p "$MOD_TMP"
    local bad=0

    # Build a synthetic Intel 5300 record with known amplitudes and check
    # the parser recovers the same subcarrier count and stable variance.
    python3 - "$MOD_TMP/stable.bin" "$MOD_TMP/moving.bin" <<'PYEOF'
import struct, sys

def record(amps, nrx=1, ntx=1):
    # Bit-pack: per subcarrier 3 skip bits then 8-bit imag + 8-bit real.
    bits = ""
    for a in amps:
        bits += "000" + format(0 & 0xFF, "08b") + format(a & 0xFF, "08b")
    bits += "0" * ((8 - len(bits) % 8) % 8)
    payload = bytearray(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    # 20-byte header: u32 ts, u16 count, u16 rsvd, 8 single bytes, u16 len, u16 flags
    hdr = struct.pack("<IHHBBBBBBBBHH", 1, 1, 0, nrx, ntx, 30, 30, 30,
                      0, 0, 1, len(payload), 0)
    assert len(hdr) == 20, len(hdr)
    return hdr + bytes(payload)

# 30 subcarriers, constant across records -> variance 0
stable = b"".join(record([10] * 30) for _ in range(20))
open(sys.argv[1], "wb").write(stable)

# Same layout but amplitude swings hard -> large variance
moving = b"".join(record([(10 if i % 2 else 200)] * 30) for i in range(20))
open(sys.argv[2], "wb").write(moving)
print("wrote %d and %d bytes" % (len(stable), len(moving)))
PYEOF

    local out
    out=$(csi_parse "$MOD_TMP/stable.bin" intel5300)
    local recs subs
    recs=$(printf '%s\n' "$out" | awk -F'\t' '$1=="RECORDS"{print $2}')
    subs=$(printf '%s\n' "$out" | awk -F'\t' '$1=="SUBCARRIERS"{print $2}')
    [[ "$recs" == "20" ]] && printf 'record-count\tPASS\n' || { printf 'record-count\tFAIL got=%s\n' "$recs"; bad=$((bad+1)); }
    [[ "$subs" == "30" ]] && printf 'subcarrier-count\tPASS\n' || { printf 'subcarrier-count\tFAIL got=%s\n' "$subs"; bad=$((bad+1)); }

    local vs vm
    vs=$(csi_analyze "$MOD_TMP/stable.bin" intel5300 | awk -F'\t' '$1=="MEAN_SUBCARRIER_VARIANCE"{print $2}')
    vm=$(csi_analyze "$MOD_TMP/moving.bin" intel5300 | awk -F'\t' '$1=="MEAN_SUBCARRIER_VARIANCE"{print $2}')
    if awk -v a="$vs" -v b="$vm" 'BEGIN{exit !(a+0 < b+0)}'; then
        printf 'motion-discrimination\tPASS (stable=%s moving=%s)\n' "$vs" "$vm"
    else
        printf 'motion-discrimination\tFAIL stable=%s moving=%s\n' "$vs" "$vm"; bad=$((bad+1))
    fi

    local verdict
    verdict=$(csi_analyze "$MOD_TMP/stable.bin" intel5300 | awk -F'\t' '$1=="VERDICT"{print $2}')
    [[ "$verdict" == "stable" ]] && printf 'stable-verdict\tPASS\n' || { printf 'stable-verdict\tFAIL got=%s\n' "$verdict"; bad=$((bad+1)); }
    verdict=$(csi_analyze "$MOD_TMP/moving.bin" intel5300 | awk -F'\t' '$1=="VERDICT"{print $2}')
    [[ "$verdict" == "strong-motion" ]] && printf 'motion-verdict\tPASS\n' || { printf 'motion-verdict\tFAIL got=%s\n' "$verdict"; bad=$((bad+1)); }

    rm -f "$MOD_TMP/stable.bin" "$MOD_TMP/moving.bin"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

csi_info() {
    cat <<'EOF'
Channel State Information

CSI is the per-subcarrier amplitude and phase of a received OFDM frame.
Because it samples the channel rather than the decoded packet, it reacts
to anything that changes the multipath — including people moving in a
room that no device is transmitting from.

Hardware reality
  Stock Wi-Fi drivers do not export CSI. Getting it needs one of:
    Intel 5300   linux-80211n-csitool (patched iwlwifi)
    Atheros      atheros-csi-tool (ath9k)
    Broadcom     Nexmon firmware (nexutil)
    ESP32        ESP32-CSI-Tool
  This machine has none of those, so live capture is unavailable and is
  refused by name. The parsers and the motion analysis below are offline
  and work on captures made elsewhere.

Interpretation
  Per-subcarrier amplitude variance is a relative motion proxy. It is
  reported as a band (stable / slight-motion / strong-motion) rather than
  a threshold, because the absolute value depends on link geometry, TX
  power and gain control, so a fixed cut-off would be meaningless.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
csi_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   csi_status_tsv ;;
        --formats-tsv)  csi_formats_tsv ;;
        --parse)        csi_parse "$@" ;;
        --analyze)      csi_analyze "$@" ;;
        --selftest)     csi_selftest ;;
        --info)         csi_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --formats-tsv
  --parse FILE [intel5300|csv]    amplitude per subcarrier
  --analyze FILE [FORMAT]         motion verdict
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
    csi_cli_main "$@"
fi

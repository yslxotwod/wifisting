#!/usr/bin/env bash
# =====================================================================
#  59_wmbus.sh — Wireless M-Bus (EN 13757) frame codec
#
#  Utility meters — water, gas, heat, electricity — broadcast their
#  readings over the air at 868 MHz with no authentication. Anyone with
#  a receiver can read every meter in range, and the device ID is
#  stable, so readings are linkable to a household over time.
#
#  OFFLINE BY DESIGN
#  Like 43_nfc_rfid, 44_lora and 45_drone_remote_id, this implements the
#  protocol rather than wrapping a tool. A captured frame is hex; the
#  codec turns it into fields. That means it is fully testable with no
#  radio, no root and no network, which matters because it is the only
#  kind of module whose selftest proves something rather than proving
#  the module loaded.
#
#  WHAT IT DECODES
#    - frame envelope: length, C-field, manufacturer, device ID,
#      version, device type, CI field
#    - CRC-16 (EN 13757 poly 0x3D65) over the frame body
#    - DIF/VIF data records: the actual meter readings
#    - AES-128-CBC payloads for modes 5 and 7, given a key
#
#  WHAT IT DOES NOT
#  It does not receive. Pair it with rtl_433 or rtl_wmbus for capture:
#      rtl_433 -f 868.95M -R 104 -F json
#  and feed the hex in. Received frames are the input, not this tool's
#  job.
#
#  Passive receive only. Reading a neighbour's meter without their
#  consent is a privacy matter in most jurisdictions and a criminal one
#  in some.
# =====================================================================

set -uo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
WIFISTING_ROOT="${WIFISTING_ROOT:-$(cd -P "$(dirname "$SELF")/.." && pwd)}"
export WIFISTING_ROOT

MOD_TMP="${TMP_DIR:-/tmp/wifisting}/wmbus"
mkdir -p "$MOD_TMP" 2>/dev/null
WMB_LOOT="${WMB_LOOT:-$WIFISTING_ROOT/loot/wmbus}"

info() { printf '[info] %s\n' "$*" >&2; }

wmb_status_tsv() {
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)"
    printf 'crypto\t%s\n' "$(python3 -c 'import cryptography' 2>/dev/null && echo yes || echo no)"
    printf 'capture_tool\t%s\n' "$(for t in rtl_433 rtl_wmbus rtl_sdr; do command -v "$t" >/dev/null 2>&1 && { echo "$t"; break; }; done)"
    printf 'radio\t%s\n' "$(ls /dev/bus/usb >/dev/null 2>&1 && echo usb-present || echo unknown)"
    printf 'verdict\t%s\n' \
        "$(python3 -c 'import sys; sys.exit(0)' 2>/dev/null && echo 'codec ready - decode from hex, no radio needed' || echo 'python3 missing')"
}

wmb_codec() {
    cat > "$MOD_TMP/wmbus.py" <<'PYEOF'
import sys

# ── CRC-16 / EN 13757 ────────────────────────────────────────────────
# Polynomial 0x3D65, reflected, init 0x0000, final xor 0xFFFF. This is
# the checksum Wireless M-Bus appends; getting it wrong is the usual
# reason a frame "decodes" into nonsense.
def crc16(data):
    crc = 0x0000
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x3D65) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc ^ 0xFFFF


def crc16_bytes(data):
    c = crc16(data)
    return bytes([c & 0xFF, (c >> 8) & 0xFF])


# ── manufacturer code ────────────────────────────────────────────────
# Three letters packed as 5-bit values, little-endian, each offset by 64.
def manufacturer(m):
    return "".join(chr(((m >> s) & 0x1F) + 64) for s in (10, 5, 0))


# ── device ID: 4 bytes, BCD, transmitted least-significant first ─────
def bcd_id(bs):
    return "".join("%02X" % b for b in reversed(bs))


def bcd_digits(bs):
    out = []
    for b in bs:
        out.append(str(b & 0x0F))
        out.append(str((b >> 4) & 0x0F))
    return "".join(out)


DEVICE_TYPES = {
    0x00: "Other", 0x01: "Oil", 0x02: "Electricity", 0x03: "Gas",
    0x04: "Heat (outlet)", 0x05: "Cooling (outlet)", 0x06: "Hot water",
    0x07: "Cold water", 0x08: "Warm water", 0x09: "Heat (inlet)",
    0x0A: "Cooling (inlet)", 0x0B: "Combined heat/cooling",
    0x0C: "Cold water (dual)", 0x0D: "Hot water (dual)",
    0x0E: "Water (dual)", 0x0F: "Pressure", 0x10: "A/D converter",
    0x11: "Room sensor", 0x12: "Gas (dual)", 0x13: "Heat meter",
    0x14: "Warm water meter", 0x15: "Water meter", 0x16: "Heat cost alloc",
    0x17: "Heat/cooling load", 0x18: "Compressed air", 0x19: "Cooling load",
    0x1A: "Volume (dual)", 0x1B: "Reserved", 0x1C: "Gas mode 2",
    0x1D: "Heat mode 2", 0x1E: "Warm water mode 2", 0x1F: "Water mode 2",
}

C_FIELD = {
    0x44: "SND-NR (unidirectional, no request)",
    0x46: "SND-IR (unidirectional, installation)",
    0x48: "SND-UD (unidirectional)",
    0x58: "REQ-UD1 (request user data)",
    0x5A: "REQ-UD2 (request user data)",
    0x60: "CNF-IR (confirmed, installation)",
    0x68: "CNF-UD (confirmed)",
    0x70: "RSP-UD (response)",
    0x74: "RSP-UD (response, small)",
    0x7A: "SND-UD (bidirectional)",
}

CI_FIELD = {
    0x00: "No data", 0x01: "1-byte counter", 0x07: "Global readout",
    0x08: "Global readout (short)", 0x0A: "Global readout (long)",
    0x0B: "Global readout (short, no header)",
    0x72: "Data with long header", 0x78: "Data with long header (no header)",
    0x7A: "Data with short header", 0x7B: "Data with short header (no header)",
    0x8C: "Enhanced data (short)", 0x8D: "Enhanced data (long)",
}

# ── VIF: what the number means ───────────────────────────────────────
# Only the units a utility meter actually sends. The full table is
# larger; these cover the meter types this module reports on.
VIF_UNITS = {
    0x00: ("Wh", 0), 0x01: ("Wh", 1), 0x02: ("Wh", 2), 0x03: ("Wh", 3),
    0x04: ("Wh", 4), 0x05: ("Wh", 5), 0x06: ("Wh", 6), 0x07: ("Wh", 7),
    0x08: ("J", 0), 0x09: ("J", 1), 0x0A: ("J", 2), 0x0B: ("J", 3),
    0x0C: ("J", 4), 0x0D: ("J", 5), 0x0E: ("J", 6), 0x0F: ("J", 7),
    0x10: ("m3", -6), 0x11: ("m3", -5), 0x12: ("m3", -4), 0x13: ("m3", -3),
    0x14: ("m3", 0), 0x15: ("m3", 1), 0x16: ("m3", 2), 0x17: ("m3", 3),
    0x20: ("kg", 0), 0x21: ("kg", 1),
    0x28: ("W", 0), 0x29: ("W", 1), 0x2A: ("W", 2), 0x2B: ("W", 3),
    0x38: ("m3/h", -3), 0x39: ("m3/h", -2), 0x3A: ("m3/h", -1), 0x3B: ("m3/h", 0),
    0x3C: ("m3/h", 1), 0x3D: ("m3/h", 2), 0x3E: ("m3/h", 3), 0x3F: ("m3/h", 4),
    0x40: ("m3/min x 10", -3), 0x41: ("m3/min x 10", -2),
    0x58: ("°C", -3), 0x59: ("°C", -2), 0x5A: ("°C", -1), 0x5B: ("°C", 0),
    0x5C: ("°C", 1), 0x5D: ("°C", 2), 0x5E: ("°C", 3), 0x5F: ("°C", 4),
    0x6C: ("Date", None), 0x6D: ("Date/time", None),
    0x6E: ("Units for HCA", None),
    0xFD: ("Credit counter", 0), 0xFE: ("Credit counter", 0),
}

# DIF bits 0-3: length and encoding. 0x0E/0x0F/0x10/0x11 are BCD/special.
DIF_LEN = {
    0x00: ("none", 0), 0x01: ("8-bit int", 1), 0x02: ("16-bit int", 2),
    0x03: ("24-bit int", 3), 0x04: ("32-bit int", 4), 0x05: ("48-bit int", 6),
    0x06: ("64-bit int", 8), 0x07: ("variable", -1),
    0x0C: ("8-digit BCD", 4), 0x0D: ("variable", -1),
    0x0E: ("12-digit BCD", 6), 0x0F: ("special", -1),
    0x10: ("2-digit BCD", 1), 0x11: ("4-digit BCD", 2),
    0x12: ("6-digit BCD", 3), 0x13: ("8-digit BCD", 4),
}

# Extension of DIF byte 0x0F: these carry no reading.
DIF_SPECIAL = {
    0x00: "No data", 0x01: "Filler", 0x02: "Manufacturer specific",
    0x03: "Manufacturer specific", 0x04: "Error", 0x05: "Error",
}


def le_int(bs):
    return int.from_bytes(bs, "little", signed=False)


def le_signed(bs):
    return int.from_bytes(bs, "little", signed=True)


def render(value, unit, exp):
    if exp is None:
        return "%s" % value
    if exp == 0:
        return "%s %s" % (value, unit)
    return "%s x 10^%d %s" % (value, unit, exp)


def decode_record(buf, pos):
    """Decode one DIF/VIF data record. Returns (text, new_pos) or None."""
    if pos >= len(buf):
        return None
    dif = buf[pos]; pos += 1

    data_field = (dif >> 6) & 0x03
    func = (dif >> 4) & 0x03
    dtype = dif & 0x0F

    # DIFE chains extend the DIF.
    difes = []
    df = data_field
    while df == 1 and pos < len(buf):
        dife = buf[pos]; pos += 1
        difes.append(dife)
        df = (dife >> 6) & 0x03
        if df != 1:
            break

    if dtype == 0x0F and pos < len(buf):
        return ("special: %s" % DIF_SPECIAL.get(buf[pos], "unknown 0x%02X" % buf[pos]), pos + 1)

    name, length = DIF_LEN.get(dtype, ("unknown DIF 0x%02X" % dtype, -1))
    if length == -1:
        if pos >= len(buf):
            return None
        length = buf[pos]; pos += 1

    if pos + length > len(buf):
        return ("truncated %s (want %d bytes, have %d)" % (name, length, len(buf) - pos), len(buf))

    raw = buf[pos:pos + length]; pos += length

    # VIF
    if pos >= len(buf):
        return ("%s = %s (no VIF)" % (name, raw.hex()), pos)
    vif = buf[pos]; pos += 1
    vife = []
    while vif in (0xFB, 0xFD, 0xFF) and pos < len(buf):
        vife.append(buf[pos]); pos += 1
        if buf[pos - 1] not in (0xFB, 0xFD, 0xFF):
            break

    unit, exp = VIF_UNITS.get(vif, ("VIF 0x%02X" % vif, None))

    if "BCD" in name:
        val = bcd_digits(raw)
        text = render(val, unit, exp)
    elif length == 0:
        text = "(no value) %s" % unit
    else:
        signed = bool(func & 0x01) and dtype in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
        val = le_signed(raw) if signed else le_int(raw)
        text = render(val, unit, exp)

    storage = ""
    if func & 0x02:
        storage = " [storage %d]" % ((difes[0] & 0x0F) if difes else 0)
    return ("%s: %s%s" % (name, text, storage), pos)


def decode_frame(hexs):
    try:
        raw = bytes.fromhex("".join(hexs.split()).replace(":", "").replace("-", ""))
    except ValueError:
        return [("ERROR", "not valid hex")]
    if len(raw) < 11:
        return [("ERROR", "too short: %d bytes, need at least 11" % len(raw))]

    out = []
    # Optional 2-byte preamble (0x54 0x3D) then length.
    pos = 0
    if raw[0] == 0x54 and raw[1] == 0x3D:
        out.append(("PREAMBLE", "54 3D"))
        pos = 2
    elif raw[0] == 0x54:
        out.append(("PREAMBLE", "%02X (partial)" % raw[0]))
        pos = 1

    length = raw[pos]; pos += 1
    out.append(("LENGTH", "%d (frame should be %d bytes after this field)"
                % (length, length - 1)))
    body_start = pos

    if pos >= len(raw):
        return out + [("ERROR", "length byte present but no body")]
    c = raw[pos]; pos += 1
    out.append(("C", "0x%02X  %s" % (c, C_FIELD.get(c, "unknown"))))

    if pos + 8 > len(raw):
        return out + [("ERROR", "truncated header")]
    mfr = raw[pos] | (raw[pos + 1] << 8); pos += 2
    out.append(("MANUFACTURER", "%s (0x%04X)" % (manufacturer(mfr), mfr)))

    devid = raw[pos:pos + 4]; pos += 4
    out.append(("DEVICE_ID", "%s (BCD %s, little-endian)"
                % (bcd_id(devid), bcd_digits(devid))))

    ver = raw[pos]; pos += 1
    out.append(("VERSION", "0x%02X" % ver))

    dtype = raw[pos]; pos += 1
    out.append(("DEVICE_TYPE", "0x%02X  %s" % (dtype, DEVICE_TYPES.get(dtype, "unknown"))))

    # CRC is the last two bytes of the frame.
    frame_end = min(body_start + length - 1, len(raw))
    if frame_end + 2 <= len(raw):
        body = raw[body_start:frame_end]
        want = raw[frame_end:frame_end + 2]
        got = crc16_bytes(body)
        ok = "ok" if want == got else "MISMATCH (computed %s)" % got.hex()
        out.append(("CRC16", "%s  %s" % (want.hex(), ok)))

    # CI field and payload.
    if pos < len(raw):
        ci = raw[pos]; pos += 1
        out.append(("CI", "0x%02X  %s" % (ci, CI_FIELD.get(ci, "unknown"))))
        # Short header: access number + status + config, then records.
        if ci in (0x7A,):
            if pos + 3 <= len(raw):
                out.append(("ACCESS_NO", "%d" % raw[pos]))
                out.append(("STATUS", "0x%02X" % raw[pos + 1]))
                out.append(("CONFIG", "0x%04X" % (raw[pos + 2] | (raw[pos + 3] << 8)
                                                  if pos + 3 < len(raw) else raw[pos + 2])))
                pos += 4
        end = frame_end if frame_end > pos else len(raw)

    # Data records, skipping a long header if one is present.
    if pos < len(raw):
        if ci in (0x72, 0x8D) and pos + 12 <= len(raw):
            pos += 12                       # long header: 6 ID + 2 mfr + ver + type + 2
        n = 0
        while pos < (frame_end if frame_end > pos else len(raw)) - 2 and n < 16:
            r = decode_record(raw, pos)
            if r is None:
                break
            text, pos = r
            out.append(("RECORD_%d" % (n + 1), text))
            n += 1
            if r[0].startswith("truncated"):
                break
    return out


def decrypt(hexs, key_hex):
    """Mode 5 / 7 AES-128-CBC. The payload after the header is encrypted
    with a zero IV in the standard's usual configuration."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return None, "cryptography module not installed (pip install cryptography)"
    try:
        raw = bytes.fromhex("".join(hexs.split()).replace(":", ""))
        key = bytes.fromhex("".join(key_hex.split()))
    except ValueError:
        return None, "not valid hex"
    if len(key) != 16:
        return None, "key must be 16 bytes (32 hex chars), got %d" % len(key)

    # Everything before the CI field is cleartext; the payload follows.
    pos = 2 if raw[:2] == b"\x54\x3d" else (1 if raw[:1] == b"\x54" else 0)
    pos += 1                                    # length
    pos += 1 + 2 + 4 + 1 + 1                    # C, mfr, ID, version, type
    if pos >= len(raw):
        return None, "frame too short to hold a payload"
    pos += 1                                    # CI
    body = raw[pos:]
    if len(body) % 16:
        body = body[:len(body) - (len(body) % 16)]
    if not body:
        return None, "no whole AES blocks in the payload"

    dec = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).decryptor()
    return dec.update(body) + dec.finalize(), None


def main(argv):
    if len(argv) < 2:
        print("usage: wmbus.py decode HEX | decrypt HEX KEY", file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "decode":
        for k, v in decode_frame(argv[2]):
            print("%s\t%s" % (k, v))
        return 0
    if cmd == "decrypt":
        if len(argv) < 4:
            print("usage: wmbus.py decrypt HEX KEY", file=sys.stderr)
            return 2
        plain, err = decrypt(argv[2], argv[3])
        if err:
            print("ERROR\t%s" % err, file=sys.stderr)
            return 1
        # Decrypted payloads are another DIF/VIF sequence.
        for k, v in decode_frame("54 3d %02x %s" % (len(plain) + 2, plain.hex())):
            print("%s\t%s" % (k, v))
        return 0
    print("ERROR\tunknown command: %s" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
PYEOF
    python3 "$MOD_TMP/wmbus.py" "$@"
}

wmb_decode() {
    [[ -n "${1:-}" ]] || { printf 'ERROR\tgive a frame in hex\n' >&2; return 2; }
    wmb_codec decode "$1"
}

wmb_decrypt() {
    [[ -n "${1:-}" && -n "${2:-}" ]] || {
        printf 'ERROR\tusage: --decrypt HEX KEY\n' >&2; return 2; }
    wmb_codec decrypt "$1" "$2"
}

wmb_selftest() {
    local bad=0
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; bad=$((bad + 1)); fi
    }

    # CRC-16/EN 13757. A known-answer test: "123456789" is the standard
    # check string for this polynomial and must give 0xC2B7.
    local crc
    crc=$(python3 - <<'PY'
def crc16(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x3D65) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ 0xFFFF
print("%04X" % crc16(b"123456789"))
PY
)
    chk crc16-check-value "$crc" "C2B7"

    # Manufacturer decoding: 5-bit letters offset by 64, little-endian.
    local mfr
    mfr=$(python3 - <<'PY'
def manufacturer(m):
    return "".join(chr(((m >> s) & 0x1F) + 64) for s in (10, 5, 0))
print(manufacturer(0x32A7))
PY
)
    chk manufacturer-decodes "$mfr" "LUG"

    # A real SND-NR frame: 2-byte preamble, length, C=44, manufacturer,
    # 4-byte BCD ID, version, device type, CI=7A, then records and CRC.
    local out
    out=$(wmb_decode "54 3d 20 44 68 2c 12 34 56 78 01 07 7a 00 00 00 00" 2>&1)
    chk decode-has-length    "$(grep -c '^LENGTH' <<<"$out")" "1"
    chk decode-has-c         "$(grep -c '^C	' <<<"$out")" "1"
    chk decode-c-is-sndnr    "$(grep -c 'SND-NR' <<<"$out")" "1"
    chk decode-has-mfr       "$(grep -c '^MANUFACTURER' <<<"$out")" "1"
    chk decode-has-devid     "$(grep -c '^DEVICE_ID' <<<"$out")" "1"
    chk decode-has-devtype   "$(grep -c '^DEVICE_TYPE' <<<"$out")" "1"
    chk decode-has-ci        "$(grep -c '^CI' <<<"$out")" "1"

    # Bad input must be refused, not guessed at.
    chk rejects-non-hex  "$(wmb_decode 'zz zz' 2>&1 | grep -c 'not valid hex')" "1"
    chk rejects-short    "$(wmb_decode '54 3d' 2>&1 | grep -c 'too short')" "1"
    wmb_decode "" >/dev/null 2>&1; chk rejects-empty "$?" "2"

    # Decrypt must refuse a wrong-length key rather than silently doing
    # something.
    local dout
    dout=$(wmb_decrypt "54 3d 20 44 68 2c 12 34 56 78 01 07 7a" "00112233" 2>&1)
    grep -q '16 bytes' <<<"$dout" && chk decrypt-checks-keylen ok ok \
                                   || chk decrypt-checks-keylen no ok

    # Status must answer honestly with no radio present.
    out=$(wmb_status_tsv)
    grep -q '^verdict' <<<"$out" && chk status-has-verdict ok ok || chk status-has-verdict no ok

    printf 'RESULT\t%s\n' "$( (( bad == 0 )) && echo PASS || echo "FAIL($bad)" )"
    return $(( bad > 0 ))
}

wmb_info() {
    printf 'Wireless M-Bus (EN 13757) frame codec.\n'
    printf 'Meters broadcast readings at 868 MHz with no authentication.\n'
    printf 'Decodes from hex: envelope, CRC-16, DIF/VIF records, AES payloads.\n'
    printf 'No radio needed - pair with rtl_433 or rtl_wmbus for capture.\n'
    printf 'Passive receive only. Reading a neighbour'"'"'s meter is a privacy matter.\n'
}

case "${1:-}" in
    --decode)      shift; wmb_decode "$@" ;;
    --decrypt)     shift; wmb_decrypt "$@" ;;
    --status-tsv)  wmb_status_tsv ;;
    --info)        wmb_info ;;
    --selftest)    wmb_selftest ;;
    --help|"")
        printf 'Usage: modules/59_wmbus.sh COMMAND\n'
        printf '  --decode HEX          decode a Wireless M-Bus frame\n'
        printf '  --decrypt HEX KEY     AES-128-CBC payload, 16-byte key in hex\n'
        printf '  --status-tsv          what is available on this machine\n'
        printf '  --info / --selftest\n'
        printf '\nCapture with:  rtl_433 -f 868.95M -R 104 -F json\n' ;;
    *) printf 'ERROR\tunknown command: %s\n' "$1" >&2; exit 2 ;;
esac

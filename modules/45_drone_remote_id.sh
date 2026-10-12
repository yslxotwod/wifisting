#!/usr/bin/env bash
# 45_drone_remote_id — Drone Remote ID
# Decode and build ASTM F3411 Remote ID messages.
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

MOD_TMP="$TMP_DIR/drone_remote_id"
MOD_LOOT="$LOOT_DIR/drone_remote_id"
MOD_LOGS="$LOG_DIR/drone_remote_id"
MOD_CAPS="$CAPTURES_DIR/drone_remote_id"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── Remote ID codec core (Python) ────────────────────────────────────────
# Every ASTM F3411 Remote ID message is EXACTLY 25 bytes. Byte 0 is always
# (message type << 4) | protocol version.
#
# Decode and encode are pure offline arithmetic over hex: no radio, no root,
# no network. Only --receive touches hardware, and it is gated.

drid_py() {
    python3 - "$@" <<'PYEOF'
import math
import re
import sys

MSG_LEN = 25

MSG_TYPE_NAMES = {
    0: "Basic ID",
    1: "Location/Vector",
    2: "Authentication",
    3: "Self-ID",
    4: "System",
    5: "Operator ID",
    15: "Message Pack",
}

MSG_TYPE_NOTES = {
    0: "UAS identity: ID type, UA type, 20-byte UAS ID",
    1: "Position, altitude, speed, accuracy, timestamp",
    2: "Authentication data: header plus opaque 23-byte payload",
    3: "Header plus 23-byte description string",
    4: "Operator location, area, EU category and class, timestamp",
    5: "Header plus 23-byte operator ID string",
    15: "Message pack: byte 1 carries the packed message count",
}

PROTO_VERSION_NAMES = {
    0: "ASTM F3411-19",
    1: "Reserved",
    2: "ASTM F3411-22",
    3: "Reserved",
}

ID_TYPE_NAMES = {
    0: "None",
    1: "Serial Number (ANSI/CTA-2063-A)",
    2: "CAA Registration ID",
    3: "UTM UUID",
    4: "Specific Session ID",
}

UA_TYPE_NAMES = {
    0: "None",
    1: "Aeroplane",
    2: "Helicopter/Multirotor",
    3: "Gyroplane",
    4: "Hybrid Lift",
    5: "Ornithopter",
    6: "Glider",
    7: "Kite",
    8: "Free Balloon",
    9: "Captive Balloon",
    10: "Airship",
    11: "Free Fall Parachute",
    12: "Rocket",
    13: "Tethered Powered Aircraft",
    14: "Ground Obstacle",
    15: "Other",
}

OP_STATUS_NAMES = {
    0: "Undeclared",
    1: "Ground",
    2: "Airborne",
    3: "Emergency",
    4: "Remote ID System Failure",
}

STATUS_ALIASES = {
    "undeclared": 0,
    "ground": 1,
    "airborne": 2,
    "emergency": 3,
    "failure": 4,
    "system_failure": 4,
    "remote_id_system_failure": 4,
}

HEIGHT_TYPE_NAMES = {0: "Above Takeoff", 1: "Above Ground"}
EW_DIRECTION_NAMES = {0: "East", 1: "West"}

ACCURACY_NAMES = {0: "Unknown", 1: "<10m", 2: "<3m", 3: "<1m"}

TS_ACCURACY_NAMES = {
    0: "Unknown",
    1: "<0.1s",
    2: "<0.2s",
    3: "<0.5s",
    4: "<1s",
    5: "<2s",
    6: "<5s",
    7: "<10s",
}

SELFID_DESC_NAMES = {0: "Text", 1: "Emergency", 2: "Extended Status"}

OP_LOCATION_TYPE_NAMES = {
    0: "Take Off",
    1: "Live GNSS",
    2: "Fixed Position",
    3: "Reserved",
}

CLASSIFICATION_TYPE_NAMES = {0: "Undeclared", 1: "EU"}

EU_CATEGORY_NAMES = {
    0: "Undeclared",
    1: "Open",
    2: "Specific",
    3: "Certified",
}

EU_CLASS_NAMES = {
    0: "Undeclared",
    1: "Class 0",
    2: "Class 1",
    3: "Class 2",
    4: "Class 3",
    5: "Class 4",
    6: "Class 5",
    7: "Class 6",
}

RID_LOCATION_NAMES = {0: "Local Broadcast", 1: "Network"}

# Latitude/longitude layout variants.
#
#   astm32  the ASTM F3411 layout: latitude is a 32-bit little-endian two's
#           complement value in degrees x 1e7 at bytes 4-7, longitude at
#           bytes 8-11. This is the DEFAULT.
#   spec24  the literal 24-bit variant: latitude at bytes 4-6, longitude at
#           bytes 7-9, everything after shifted two bytes earlier. A 24-bit
#           degrees x 1e7 field only spans +/-0.8388607 degrees, so this mode
#           is only usable for small coordinates. It exists because the 3-byte
#           two's complement path deserves to be exercised and auditable.
LAYOUTS = {
    "astm32": {
        "lat": (4, 4, 90.0),
        "lon": (8, 4, 180.0),
        "palt": (12, 2),
        "galt": (14, 2),
        "hgt": (16, 2),
        "acc_hv": 18,
        "acc_bs": 19,
        "ts": (20, 4),
        "tsacc": 24,
        "tsacc_shift": 4,
    },
    "spec24": {
        "lat": (4, 3, 0.8388607),
        "lon": (7, 3, 0.8388607),
        "palt": (10, 2),
        "galt": (12, 2),
        "hgt": (14, 2),
        "acc_hv": 16,
        "acc_bs": 17,
        "ts": (18, 4),
        "tsacc": 22,
        "tsacc_shift": 4,
    },
}

VERSION_DEFAULT = 2


# ── small helpers ────────────────────────────────────────────────────────

def emit(*parts):
    """Write one TSV record. emit("KEY", value) or emit("A\tB\tC")."""
    sys.stdout.write("\t".join(str(p) for p in parts) + "\n")


def fail(msg, code=2):
    sys.stderr.write("ERROR\t%s\n" % msg)
    sys.exit(code)


def name_of(table, value, fallback="Reserved"):
    if value in table:
        return table[value]
    return "%s (%d)" % (fallback, value)


def acc_name(value):
    return name_of(ACCURACY_NAMES, value)


def u(raw, off, width):
    return int.from_bytes(raw[off:off + width], "little", signed=False)


def si(raw, off, width):
    return int.from_bytes(raw[off:off + width], "little", signed=True)


def hms(seconds):
    total = seconds
    hh = int(total // 3600)
    mm = int((total - hh * 3600) // 60)
    ss = total - hh * 3600 - mm * 60
    return "%02d:%02d:%04.1f" % (hh, mm, ss)


def parse_hex(text, what="input"):
    t = re.sub(r"[\s:,\-_]", "", str(text))
    t = t.replace("0x", "").replace("0X", "")
    if not t:
        fail("no hex digits in %s" % what)
    bad = sorted(set(re.findall(r"[^0-9A-Fa-f]", t)))
    if bad:
        fail("non-hex character(s) %s in %s" % ("".join(bad), what))
    if len(t) % 2:
        fail("odd number of hex digits (%d) in %s" % (len(t), what))
    return bytes.fromhex(t)


def split_messages(raw, what="input"):
    if len(raw) == 0:
        fail("%s is empty" % what)
    if len(raw) % MSG_LEN:
        fail("%s is %d bytes (%d hex chars); a Remote ID message is exactly 25 bytes, "
             "so the length must be a multiple of 25 (remainder %d) - the input is "
             "truncated, padded or misaligned"
             % (what, len(raw), len(raw) * 2, len(raw) % MSG_LEN))
    return [raw[i:i + MSG_LEN] for i in range(0, len(raw), MSG_LEN)]


def decode_alt(raw, off, width):
    v = u(raw, off, width)
    return v, v * 0.5 - 1000.0


# ── decode ───────────────────────────────────────────────────────────────

def decode_basic(raw):
    b1 = raw[1]
    id_type = (b1 >> 4) & 0x0F
    ua_type = b1 & 0x0F
    field = bytes(raw[2:22])
    text = field.split(b"\x00", 1)[0].decode("ascii", "replace")
    emit("ID_TYPE", id_type)
    emit("ID_TYPE_NAME", name_of(ID_TYPE_NAMES, id_type))
    emit("UA_TYPE", ua_type)
    emit("UA_TYPE_NAME", name_of(UA_TYPE_NAMES, ua_type))
    emit("UAS_ID", text)
    emit("UAS_ID_LEN", len(field.split(b"\x00", 1)[0]))
    emit("UAS_ID_HEX", field.hex().upper())
    emit("RESERVED_BYTES_22_24", bytes(raw[22:25]).hex().upper())


def decode_location(raw, layout):
    L = LAYOUTS[layout]
    b1 = raw[1]
    status = (b1 >> 5) & 0x07
    height_type = (b1 >> 4) & 0x01
    res_b1 = (b1 >> 2) & 0x03
    ew = (b1 >> 1) & 0x01
    mult = b1 & 0x01
    emit("OPERATIONAL_STATUS", status)
    emit("OPERATIONAL_STATUS_NAME", name_of(OP_STATUS_NAMES, status))
    emit("HEIGHT_TYPE", height_type)
    emit("HEIGHT_TYPE_NAME", name_of(HEIGHT_TYPE_NAMES, height_type))
    emit("EW_DIRECTION", ew)
    emit("EW_DIRECTION_NAME", name_of(EW_DIRECTION_NAMES, ew))
    emit("SPEED_MULTIPLIER", mult)
    speed_enc = raw[2] & 0x7F
    emit("SPEED_ENCODED", speed_enc)
    emit("SPEED_MPS", "%.3f" % (speed_enc * (0.75 if mult else 0.25)))

    vs_enc = raw[3] & 0x7F
    vs_signed = vs_enc - 128 if (vs_enc & 0x40) else vs_enc
    emit("VERTICAL_SPEED_ENCODED", vs_signed)
    emit("VERTICAL_SPEED_MPS", "%.3f" % (vs_signed * 0.5))
    if vs_enc == 127:
        emit("VERTICAL_SPEED_OFFSET_FORM_MPS", "unknown")
    else:
        emit("VERTICAL_SPEED_OFFSET_FORM_MPS", "%.3f" % ((vs_enc - 63) * 0.5))

    lat_off, lat_w, lat_max = L["lat"]
    lon_off, lon_w, lon_max = L["lon"]
    lat_raw = si(raw, lat_off, lat_w)
    lon_raw = si(raw, lon_off, lon_w)
    emit("LAT_LON_ENCODING", "int%d little-endian two's complement, degrees x 1e7" % (lat_w * 8))
    emit("LATITUDE_RAW", lat_raw)
    emit("LATITUDE", "%.6f" % (lat_raw / 1e7))
    emit("LONGITUDE_RAW", lon_raw)
    emit("LONGITUDE", "%.6f" % (lon_raw / 1e7))

    for key, off, width in (("PRESSURE_ALTITUDE", L["palt"][0], L["palt"][1]),
                            ("GEODETIC_ALTITUDE", L["galt"][0], L["galt"][1]),
                            ("HEIGHT_ABOVE_TAKEOFF", L["hgt"][0], L["hgt"][1])):
        rawv, metres = decode_alt(raw, off, width)
        emit(key + "_RAW", rawv)
        emit(key + "_M", "%.1f" % metres)

    ah = raw[L["acc_hv"]]
    bs = raw[L["acc_bs"]]
    emit("VERTICAL_ACCURACY", (ah >> 4) & 0x0F)
    emit("VERTICAL_ACCURACY_NAME", acc_name((ah >> 4) & 0x0F))
    emit("HORIZONTAL_ACCURACY", ah & 0x0F)
    emit("HORIZONTAL_ACCURACY_NAME", acc_name(ah & 0x0F))
    emit("BARO_ACCURACY", (bs >> 4) & 0x0F)
    emit("BARO_ACCURACY_NAME", acc_name((bs >> 4) & 0x0F))
    emit("SPEED_ACCURACY", bs & 0x0F)
    emit("SPEED_ACCURACY_NAME", acc_name(bs & 0x0F))

    ts_off, ts_w = L["ts"]
    ts_raw = u(raw, ts_off, ts_w)
    emit("TIMESTAMP_RAW", ts_raw)
    emit("TIMESTAMP_S", "%.1f" % (ts_raw / 10.0))
    emit("TIMESTAMP_HMS", hms(ts_raw / 10.0))
    tsacc = (raw[L["tsacc"]] >> L["tsacc_shift"]) & 0x0F
    emit("TIMESTAMP_ACCURACY", tsacc)
    emit("TIMESTAMP_ACCURACY_NAME", name_of(TS_ACCURACY_NAMES, tsacc))

    emit("RESERVED_BYTE1_BITS_3_2", res_b1)
    emit("RESERVED_BYTE2_BIT_7", (raw[2] >> 7) & 0x01)
    emit("RESERVED_BYTE3_BIT_7", (raw[3] >> 7) & 0x01)
    if layout == "spec24":
        emit("RESERVED_BYTES_23_24", bytes(raw[23:25]).hex().upper())
    else:
        emit("RESERVED_BYTE24_LOW_NIBBLE", raw[24] & 0x0F)


AUTH_TYPE_NAMES = {
    0: "None",
    1: "UAS ID Signature",
    2: "Operator ID Signature",
    3: "Operator ID and UAS ID Signature",
    4: "Message Set Signature",
}


def decode_auth(raw):
    b1 = raw[1]
    payload = bytes(raw[2:25])
    emit("AUTH_TYPE", b1)
    emit("AUTH_TYPE_NAME", name_of(AUTH_TYPE_NAMES, b1))
    emit("PAYLOAD_LEN", len(payload))
    emit("PAYLOAD_HEX", payload.hex().upper())
    emit("PAYLOAD_NOTE", "opaque authentication payload, not parsed")


def decode_selfid(raw):
    b1 = raw[1]
    desc_type = (b1 >> 4) & 0x0F
    field = bytes(raw[2:25])
    text = field.split(b"\x00", 1)[0].decode("ascii", "replace")
    emit("DESC_TYPE", desc_type)
    emit("DESC_TYPE_NAME", name_of(SELFID_DESC_NAMES, desc_type))
    emit("RESERVED_BYTE1_LOW_NIBBLE", b1 & 0x0F)
    emit("DESCRIPTION", text)
    emit("DESCRIPTION_LEN", len(field.split(b"\x00", 1)[0]))
    emit("DESCRIPTION_HEX", field.hex().upper())


def decode_system(raw):
    b1 = raw[1]
    b2 = raw[2]
    loc = (b1 >> 4) & 0x01
    emit("RID_LOCATION", loc)
    emit("RID_LOCATION_NAME", name_of(RID_LOCATION_NAMES, loc))
    emit("RESERVED_BYTE1_BITS", "0x%02X" % (b1 & 0xEF))
    olt = (b2 >> 6) & 0x03
    ctype = (b2 >> 3) & 0x07
    emit("OP_LOCATION_TYPE", olt)
    emit("OP_LOCATION_TYPE_NAME", name_of(OP_LOCATION_TYPE_NAMES, olt))
    emit("CLASSIFICATION_TYPE", ctype)
    emit("CLASSIFICATION_TYPE_NAME", name_of(CLASSIFICATION_TYPE_NAMES, ctype))
    emit("RESERVED_BYTE2_BITS_2_0", b2 & 0x07)
    emit("OP_LATITUDE_RAW", si(raw, 3, 4))
    emit("OP_LATITUDE", "%.6f" % (si(raw, 3, 4) / 1e7))
    emit("OP_LONGITUDE_RAW", si(raw, 7, 4))
    emit("OP_LONGITUDE", "%.6f" % (si(raw, 7, 4) / 1e7))
    emit("AREA_COUNT", u(raw, 11, 2))
    emit("AREA_RADIUS_M", raw[13])
    for key, off in (("AREA_CEILING", 14), ("AREA_FLOOR", 16)):
        rawv = u(raw, off, 2)
        emit(key + "_RAW", rawv)
        if rawv == 0xFFFF:
            emit(key + "_M", "unknown (0xFFFF)")
        else:
            emit(key + "_M", "%.1f" % (rawv * 0.5 - 1000.0))
    emit("UA_CATEGORY_EU", u(raw, 18, 2))
    emit("UA_CATEGORY_EU_NAME", name_of(EU_CATEGORY_NAMES, u(raw, 18, 2)))
    emit("UA_CLASS_EU", u(raw, 20, 2))
    emit("UA_CLASS_EU_NAME", name_of(EU_CLASS_NAMES, u(raw, 20, 2)))
    op_alt_raw = u(raw, 22, 2)
    emit("OPERATOR_ALTITUDE_RAW", op_alt_raw)
    emit("OPERATOR_ALTITUDE_M", "%.1f" % (op_alt_raw * 0.5 - 1000.0))
    emit("TIMESTAMP_RAW", raw[24])
    emit("TIMESTAMP_S", "%.1f" % (raw[24] / 10.0))
    emit("TIMESTAMP_HMS", hms(raw[24] / 10.0))


def decode_header(index, raw, layout):
    mtype = (raw[0] >> 4) & 0x0F
    ver = raw[0] & 0x0F
    emit("MSG_INDEX", index)
    emit("MSG_TYPE", mtype)
    emit("MSG_TYPE_NAME", name_of(MSG_TYPE_NAMES, mtype, "Reserved/Unknown"))
    emit("PROTO_VERSION", ver)
    emit("PROTO_VERSION_NAME", name_of(PROTO_VERSION_NAMES, ver, "Reserved"))
    emit("LAYOUT", layout)
    return mtype


def decode_one(index, raw, layout):
    mtype = decode_header(index, raw, layout)
    if mtype == 0:
        decode_basic(raw)
    elif mtype == 1:
        decode_location(raw, layout)
    elif mtype == 2:
        decode_auth(raw)
    elif mtype == 3:
        decode_selfid(raw)
    elif mtype == 4:
        decode_system(raw)
    elif mtype == 5:
        b1 = raw[1]
        otype = (b1 >> 5) & 0x07
        field = bytes(raw[2:25])
        emit("OPERATOR_ID_TYPE", otype)
        emit("OPERATOR_ID_TYPE_NAME", "Operator ID" if otype == 0 else "Reserved")
        emit("RESERVED_BYTE1_BITS_4_0", b1 & 0x1F)
        emit("OPERATOR_ID", field.split(b"\x00", 1)[0].decode("ascii", "replace"))
        emit("OPERATOR_ID_HEX", field.hex().upper())
        emit("PAYLOAD_LEN", len(field))
    elif mtype == 15:
        emit("PACKED_MESSAGE_COUNT", raw[1])
        emit("PAYLOAD_LEN", 23)
        emit("PAYLOAD_HEX", bytes(raw[2:25]).hex().upper())
        emit("PAYLOAD_NOTE", "message pack header; packed messages follow in the payload")
    else:
        emit("PAYLOAD_LEN", 24)
        emit("PAYLOAD_HEX", bytes(raw[1:25]).hex().upper())
        emit("PAYLOAD_NOTE", "reserved message type, payload not parsed")
    emit("RAW_HEX", bytes(raw).hex().upper())


# ── encode ───────────────────────────────────────────────────────────────

def kv_float(kv, keys, default):
    for k in keys:
        if k in kv:
            try:
                v = float(kv[k])
            except ValueError:
                fail("field %s: not a number: %s" % (k, kv[k]))
            if not math.isfinite(v):
                fail("field %s: not a finite number: %s" % (k, kv[k]))
            return v
    return float(default)


def kv_int(kv, keys, default):
    for k in keys:
        if k in kv:
            try:
                return int(str(kv[k]), 0)
            except ValueError:
                fail("field %s: not an integer: %s" % (k, kv[k]))
    return int(default)


def kv_str(kv, keys, default=""):
    for k in keys:
        if k in kv:
            return kv[k]
    return default


def put_latlon(raw, value, off, width, maxdeg, what):
    if abs(value) > maxdeg:
        fail("%s %s is out of range: a %d-bit degrees x 1e7 field holds "
             "+/-%s degrees" % (what, ("%.7f" % value).rstrip("0").rstrip("."),
                                width * 8, ("%.7f" % maxdeg).rstrip("0").rstrip(".")))
    enc = int(round(value * 1e7))
    lo = -(1 << (width * 8 - 1))
    hi = (1 << (width * 8 - 1)) - 1
    if not (lo <= enc <= hi):
        fail("%s does not fit the %d-byte field" % (what, width))
    raw[off:off + width] = enc.to_bytes(width, "little", signed=True)


def put_alt(raw, value, off, width, what):
    enc = int(round((value + 1000.0) / 0.5))
    if not (0 <= enc <= 0xFFFF):
        fail("%s %.1f m cannot be encoded: the field spans -1000.0 to 31767.5 m" % (what, value))
    raw[off:off + width] = enc.to_bytes(width, "little", signed=False)


def put_u16(raw, value, off, what):
    if not (0 <= value <= 0xFFFF):
        fail("%s %d is out of range 0-65535" % (what, value))
    raw[off:off + 2] = int(value).to_bytes(2, "little", signed=False)


def put_u32(raw, value, off, what):
    if not (0 <= value <= 0xFFFFFFFF):
        fail("%s %d is out of range 0-4294967295" % (what, value))
    raw[off:off + 4] = int(value).to_bytes(4, "little", signed=False)


def ascii_field(value, limit, what):
    try:
        data = value.encode("ascii")
    except UnicodeEncodeError:
        fail("%s must be ASCII; use the *_hex form for arbitrary bytes" % what)
    if len(data) > limit:
        fail("%s is %d bytes; the field holds at most %d" % (what, len(data), limit))
    return data


def parse_status(value):
    s = str(value).strip().lower()
    if s.isdigit():
        n = int(s)
    elif s in STATUS_ALIASES:
        n = STATUS_ALIASES[s]
    else:
        fail("unknown operational status %s (use 0-4 or undeclared/ground/airborne/emergency/failure)"
             % value)
    if not (0 <= n <= 7):
        fail("operational status must be 0-7, got %d" % n)
    return n


def enc_basic(kv, ver):
    raw = bytearray(MSG_LEN)
    raw[0] = (0 << 4) | (ver & 0x0F)
    id_type = kv_int(kv, ("id_type", "idtype"), 1)
    ua_type = kv_int(kv, ("ua_type", "uatype"), 2)
    if not (0 <= id_type <= 15):
        fail("id_type must be 0-15, got %d" % id_type)
    if not (0 <= ua_type <= 15):
        fail("ua_type must be 0-15, got %d" % ua_type)
    raw[1] = ((id_type & 0x0F) << 4) | (ua_type & 0x0F)
    if "uas_id_hex" in kv:
        data = parse_hex(kv["uas_id_hex"], "uas_id_hex")
        if len(data) > 20:
            fail("uas_id_hex is %d bytes; the field holds at most 20" % len(data))
    else:
        data = ascii_field(kv_str(kv, ("uas_id", "uasid", "id"), ""), 20, "uas_id")
    raw[2:22] = data + b"\x00" * (20 - len(data))
    return raw


def enc_location(kv, ver, layout):
    L = LAYOUTS[layout]
    raw = bytearray(MSG_LEN)
    raw[0] = (1 << 4) | (ver & 0x0F)
    status = parse_status(kv.get("status", 0))
    height_type = kv_int(kv, ("height_type", "height_ref"), 0) & 0x01
    ew = kv_int(kv, ("ew_dir", "ew_direction", "ew"), 0) & 0x01
    speed = kv_float(kv, ("speed", "speed_mps", "gspeed"), 0.0)
    if "speed_enc" in kv:
        speed_enc = kv_int(kv, ("speed_enc",), 0)
        mult = kv_int(kv, ("speed_mult", "mult"), 0) & 0x01
        if not (0 <= speed_enc <= 127):
            fail("speed_enc must be 0-127")
    elif "speed_mult" in kv:
        mult = kv_int(kv, ("speed_mult", "mult"), 0) & 0x01
        step = 0.75 if mult else 0.25
        speed_enc = int(round(speed / step))
        if not (0 <= speed_enc <= 127):
            fail("speed %.3f m/s does not fit the encoded speed field with multiplier %d" % (speed, mult))
    else:
        if speed < 0:
            fail("speed must not be negative, got %.3f m/s" % speed)
        if speed <= 31.75:
            mult = 0
            speed_enc = int(round(speed / 0.25))
        elif speed <= 95.25:
            mult = 1
            speed_enc = int(round(speed / 0.75))
        else:
            fail("speed %.3f m/s exceeds the encodable maximum of 95.25 m/s" % speed)
        if speed_enc > 127:
            speed_enc = 127
    raw[1] = ((status & 0x07) << 5) | ((height_type & 0x01) << 4) | ((ew & 0x01) << 1) | (mult & 0x01)
    raw[2] = speed_enc & 0x7F
    if "vspeed_enc" in kv:
        vs_enc = kv_int(kv, ("vspeed_enc",), 0)
        if not (-64 <= vs_enc <= 63):
            fail("vspeed_enc must be -64 to 63 (7-bit two's complement)")
    else:
        vspeed = kv_float(kv, ("vspeed", "vertical_speed"), 0.0)
        vs_enc = int(round(vspeed / 0.5))
        if not (-64 <= vs_enc <= 63):
            fail("vspeed %.3f m/s does not fit the 7-bit two's complement field (-32.0 to 31.5 m/s)"
                 % vspeed)
    raw[3] = vs_enc & 0x7F

    lat = kv_float(kv, ("lat", "latitude"), 0.0)
    lon = kv_float(kv, ("lon", "lng", "longitude"), 0.0)
    lat_off, lat_w, lat_max = L["lat"]
    lon_off, lon_w, lon_max = L["lon"]
    put_latlon(raw, lat, lat_off, lat_w, lat_max, "latitude")
    put_latlon(raw, lon, lon_off, lon_w, lon_max, "longitude")

    alt = kv_float(kv, ("alt", "pressure_alt", "altitude"), 0.0)
    galt = kv_float(kv, ("geodetic_alt", "galt"), alt)
    hgt = kv_float(kv, ("height", "height_above_takeoff", "hta"), alt)
    if "pressure_alt_raw" in kv:
        put_u16(raw, kv_int(kv, ("pressure_alt_raw",), 0), L["palt"][0], "pressure_alt_raw")
    else:
        put_alt(raw, alt, L["palt"][0], L["palt"][1], "altitude")
    if "geodetic_alt_raw" in kv:
        put_u16(raw, kv_int(kv, ("geodetic_alt_raw",), 0), L["galt"][0], "geodetic_alt_raw")
    else:
        put_alt(raw, galt, L["galt"][0], L["galt"][1], "geodetic altitude")
    if "height_raw" in kv:
        put_u16(raw, kv_int(kv, ("height_raw",), 0), L["hgt"][0], "height_raw")
    else:
        put_alt(raw, hgt, L["hgt"][0], L["hgt"][1], "height above takeoff")

    vacc = kv_int(kv, ("vertical_accuracy", "vacc"), 0)
    hacc = kv_int(kv, ("horizontal_accuracy", "hacc"), 0)
    bacc = kv_int(kv, ("baro_accuracy", "bacc"), 0)
    sacc = kv_int(kv, ("speed_accuracy", "sacc"), 0)
    for label, val in (("vertical_accuracy", vacc), ("horizontal_accuracy", hacc),
                       ("baro_accuracy", bacc), ("speed_accuracy", sacc)):
        if not (0 <= val <= 15):
            fail("%s must be 0-15, got %d" % (label, val))
    raw[L["acc_hv"]] = ((vacc & 0x0F) << 4) | (hacc & 0x0F)
    raw[L["acc_bs"]] = ((bacc & 0x0F) << 4) | (sacc & 0x0F)

    ts = kv_float(kv, ("timestamp", "ts", "ts_s"), 0.0)
    if "timestamp_raw" in kv:
        ts_raw = kv_int(kv, ("timestamp_raw",), 0)
    else:
        if ts < 0:
            fail("timestamp must not be negative, got %.1f s" % ts)
        ts_raw = int(round(ts * 10.0))
    ts_off, ts_w = L["ts"]
    put_u32(raw, ts_raw, ts_off, "timestamp (tenths of a second since the hour)")

    tsacc = kv_int(kv, ("timestamp_accuracy", "ts_acc", "tsacc"), 0)
    if not (0 <= tsacc <= 15):
        fail("timestamp_accuracy must be 0-15, got %d" % tsacc)
    raw[L["tsacc"]] = ((tsacc & 0x0F) << L["tsacc_shift"]) & 0xFF
    return raw


def enc_auth(kv, ver):
    raw = bytearray(MSG_LEN)
    raw[0] = (2 << 4) | (ver & 0x0F)
    auth_type = kv_int(kv, ("auth_type", "atype"), 0)
    if not (0 <= auth_type <= 15):
        fail("auth_type must be 0-15, got %d" % auth_type)
    raw[1] = auth_type & 0x0F
    text = kv_str(kv, ("payload", "auth_hex", "auth", "data"), "")
    data = parse_hex(text, "authentication payload") if text.strip() else b""
    if len(data) > 23:
        fail("authentication payload is %d bytes; the field holds at most 23" % len(data))
    raw[2:25] = data + b"\x00" * (23 - len(data))
    return raw


def enc_selfid(kv, ver):
    raw = bytearray(MSG_LEN)
    raw[0] = (3 << 4) | (ver & 0x0F)
    desc_type = kv_int(kv, ("desc_type", "description_type"), 0)
    if not (0 <= desc_type <= 15):
        fail("desc_type must be 0-15, got %d" % desc_type)
    raw[1] = (desc_type & 0x0F) << 4
    if "desc_hex" in kv:
        data = parse_hex(kv["desc_hex"], "desc_hex")
        if len(data) > 23:
            fail("desc_hex is %d bytes; the field holds at most 23" % len(data))
    else:
        data = ascii_field(kv_str(kv, ("desc", "description", "text"), ""), 23, "desc")
    raw[2:25] = data + b"\x00" * (23 - len(data))
    return raw


def enc_system(kv, ver):
    raw = bytearray(MSG_LEN)
    raw[0] = (4 << 4) | (ver & 0x0F)
    loc_text = str(kv_str(kv, ("rid_location", "location", "transport"), "local")).strip().lower()
    if loc_text in ("local", "local_broadcast", "broadcast", "0"):
        loc = 0
    elif loc_text in ("network", "1"):
        loc = 1
    else:
        fail("rid_location must be local or network, got %s" % loc_text)
    raw[1] = (loc & 0x01) << 4
    olt = kv_int(kv, ("op_location_type", "olt"), 0)
    ctype = kv_int(kv, ("classification_type", "ctype"), 0)
    if not (0 <= olt <= 3):
        fail("op_location_type must be 0-3, got %d" % olt)
    if not (0 <= ctype <= 7):
        fail("classification_type must be 0-7, got %d" % ctype)
    raw[2] = ((olt & 0x03) << 6) | ((ctype & 0x07) << 3)
    op_lat = kv_float(kv, ("op_lat", "operator_lat", "lat"), 0.0)
    op_lon = kv_float(kv, ("op_lon", "operator_lon", "lon"), 0.0)
    put_latlon(raw, op_lat, 3, 4, 90.0, "operator latitude")
    put_latlon(raw, op_lon, 7, 4, 180.0, "operator longitude")
    put_u16(raw, kv_int(kv, ("area_count",), 1), 11, "area_count")
    radius = kv_int(kv, ("area_radius", "radius"), 0)
    if not (0 <= radius <= 255):
        fail("area_radius must be 0-255 metres, got %d" % radius)
    raw[13] = radius
    for key, off in (("ceiling", 14), ("floor", 16)):
        if key + "_raw" in kv:
            put_u16(raw, kv_int(kv, (key + "_raw",), 0), off, key + "_raw")
        elif key in kv:
            put_alt(raw, kv_float(kv, (key,), 0.0), off, 2, "area " + key)
        else:
            put_u16(raw, 0, off, key)
    put_u16(raw, kv_int(kv, ("ua_category", "category"), 0), 18, "ua_category")
    put_u16(raw, kv_int(kv, ("ua_class", "klass"), 0), 20, "ua_class")
    op_alt = kv_float(kv, ("op_alt", "operator_altitude"), 0.0)
    if "op_alt_raw" in kv:
        put_u16(raw, kv_int(kv, ("op_alt_raw",), 0), 22, "op_alt_raw")
    else:
        put_alt(raw, op_alt, 22, 2, "operator altitude")
    ts = kv_int(kv, ("timestamp_byte", "ts_byte", "timestamp"), 0)
    if not (0 <= ts <= 255):
        fail("timestamp byte must be 0-255, got %d" % ts)
    raw[24] = ts
    return raw


def enc_opid(kv, ver):
    raw = bytearray(MSG_LEN)
    raw[0] = (5 << 4) | (ver & 0x0F)
    otype = kv_int(kv, ("operator_id_type", "oid_type"), 0)
    if not (0 <= otype <= 7):
        fail("operator_id_type must be 0-7, got %d" % otype)
    raw[1] = (otype & 0x07) << 5
    if "operator_id_hex" in kv:
        data = parse_hex(kv["operator_id_hex"], "operator_id_hex")
        if len(data) > 23:
            fail("operator_id_hex is %d bytes; the field holds at most 23" % len(data))
    else:
        data = ascii_field(kv_str(kv, ("operator_id", "opid", "desc"), ""), 23, "operator_id")
    raw[2:25] = data + b"\x00" * (23 - len(data))
    return raw


def enc_msgpack(kv, ver):
    raw = bytearray(MSG_LEN)
    raw[0] = (15 << 4) | (ver & 0x0F)
    count = kv_int(kv, ("count", "packed", "messages"), 1)
    if not (0 <= count <= 255):
        fail("count must be 0-255, got %d" % count)
    raw[1] = count
    return raw


KIND_ALIASES = {
    "basicid": "basic", "basic_id": "basic", "basic": "basic", "0": "basic",
    "location": "location", "loc": "location", "location_vector": "location", "1": "location",
    "location24": "location24", "loc24": "location24", "location_24": "location24",
    "auth": "auth", "authentication": "auth", "2": "auth",
    "selfid": "selfid", "self_id": "selfid", "3": "selfid",
    "system": "system", "sys": "system", "4": "system",
    "operatorid": "opid", "operator_id": "opid", "opid": "opid", "5": "opid",
    "messagepack": "msgpack", "message_pack": "msgpack", "msgpack": "msgpack", "15": "msgpack",
}


def parse_spec(spec):
    s = str(spec).strip()
    if not s:
        fail("empty encode spec; example: basicid id_type=1 ua_type=2 uas_id=1596F39XK2")
    parts = re.split(r"\s+(?=[A-Za-z_][A-Za-z0-9_]*=)", s)
    kv = {}
    kind = None
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            kv[k.strip().lower()] = v.strip()
        elif kind is None:
            kind = part.strip().lower()
        else:
            fail("cannot parse encode field %s; use key=value" % part)
    if kind is None:
        if "type" in kv:
            kind = kv.pop("type").strip().lower()
        elif "msg" in kv:
            kind = kv.pop("msg").strip().lower()
        else:
            fail("encode spec needs a message type keyword, for example: basicid id_type=1 ua_type=2 uas_id=EXAMPLE")
    if kind not in KIND_ALIASES:
        fail("unknown message type %s; use basicid, location, location24, auth, selfid, system, operatorid or msgpack"
             % kind)
    kind = KIND_ALIASES[kind]
    layout = kv.pop("layout", None)
    if kind == "location24":
        kind = "location"
        layout = "spec24"
    if layout is None:
        layout = "astm32"
    layout = str(layout).strip().lower()
    if layout in ("24", "spec24", "24bit", "24-bit"):
        layout = "spec24"
    elif layout in ("32", "astm32", "astm", "32bit", "32-bit", "f3411"):
        layout = "astm32"
    else:
        fail("unknown layout %s; use 32 (ASTM, default) or 24 (literal 24-bit variant)" % layout)
    ver = kv_int(kv, ("version", "proto", "protocol_version"), VERSION_DEFAULT)
    if not (0 <= ver <= 15):
        fail("protocol version must be 0-15, got %d" % ver)
    return kind, kv, layout, ver


def build(spec):
    kind, kv, layout, ver = parse_spec(spec)
    msg = None
    if kind == "basic":
        msg = enc_basic(kv, ver)
    elif kind == "location":
        msg = enc_location(kv, ver, layout)
    elif kind == "auth":
        msg = enc_auth(kv, ver)
    elif kind == "selfid":
        msg = enc_selfid(kv, ver)
    elif kind == "system":
        msg = enc_system(kv, ver)
    elif kind == "opid":
        msg = enc_opid(kv, ver)
    elif kind == "msgpack":
        msg = enc_msgpack(kv, ver)
    if msg is None:
        fail("unhandled message type %s" % kind)
    if len(msg) != MSG_LEN:
        # Never print a success line for a malformed message.
        fail("internal error: encoder produced %d bytes, expected exactly %d" % (len(msg), MSG_LEN), 3)
    return msg, layout


# ── Bluetooth AD structure wrapper ───────────────────────────────────────

def ad_find_rid(raw):
    """Walk Bluetooth AD structures, return (payload, matches, skipped, leftover)."""
    i = 0
    payloads = []
    matches = []
    skipped = []
    leftover = b""
    while i < len(raw):
        length = raw[i]
        if length == 0:
            i += 1
            continue
        if i + 1 + length > len(raw):
            leftover = bytes(raw[i:])
            break
        ad_type = raw[i + 1]
        data = bytes(raw[i + 2:i + 1 + length])
        if ad_type == 0x16 and len(data) >= 2:
            uuid = int.from_bytes(data[0:2], "little")
            if uuid == 0xFFFA:
                payloads.append(data[2:])
                matches.append((0x16, "0x%04X" % uuid,
                                "Service Data - 16-bit UUID (Remote ID over Bluetooth)"))
            else:
                skipped.append((0x16, "0x%04X" % uuid))
        elif ad_type == 0xFF and len(data) >= 2:
            company = int.from_bytes(data[0:2], "little")
            if company in (0xFFF0, 0xFFFF):
                payloads.append(data[2:])
                matches.append((0xFF, "0x%04X" % company,
                                "Manufacturer Specific Data (Remote ID over Bluetooth)"))
            else:
                skipped.append((0xFF, "0x%04X" % company))
        else:
            skipped.append((ad_type, ""))
        i += 1 + length
    return b"".join(payloads), matches, skipped, leftover


def ad_find_rid_any_offset(raw):
    limit = min(len(raw), 16)
    for off in range(0, limit):
        payload, matches, skipped, leftover = ad_find_rid(raw[off:])
        if matches and payload:
            return payload, matches, skipped, leftover, off
    return b"", [], [], b"", 0


def emit_wrapper(matches, skipped, offset, fallback_note=None):
    if matches:
        emit("AD_WRAPPER", "stripped")
        if offset:
            emit("AD_STRUCTURE_OFFSET", offset)
        for n, (ad_type, ident, label) in enumerate(matches):
            emit("AD_%d_TYPE" % n, "0x%02X" % ad_type)
            if ad_type == 0x16:
                emit("AD_%d_UUID" % n, ident)
            else:
                emit("AD_%d_COMPANY_ID" % n, ident)
            emit("AD_%d_NAME" % n, label)
        emit("AD_MATCHED_ELEMENTS", len(matches))
        if skipped:
            emit("AD_SKIPPED_ELEMENTS", " ".join("0x%02X%s" % (t, (":" + i) if i else "")
                                                 for t, i in skipped))
    else:
        emit("AD_WRAPPER", fallback_note or "none")


def decode_payload(payload, layout):
    if len(payload) % MSG_LEN == 1 and len(payload) > 1:
        emit("PREFIX_BYTE_SKIPPED", "%02X (message pack counter)" % payload[0])
        payload = payload[1:]
    if len(payload) == 0 or len(payload) % MSG_LEN:
        fail("Remote ID payload is %d bytes; expected one or more complete 25-byte messages" % len(payload), 1)
    emit("PAYLOAD_BYTES", len(payload))
    emit("PAYLOAD_HEX", payload.hex().upper())
    emit("MESSAGE_COUNT", len(payload) // MSG_LEN)
    for index, msg in enumerate(split_messages(payload, "Remote ID payload")):
        decode_one(index, msg, layout)


# ── subcommands ──────────────────────────────────────────────────────────

def cmd_decode(args):
    if not args:
        fail("usage: --decode HEX (one or more concatenated 25-byte messages)", 2)
    layout = "astm32"
    rest = []
    for a in args:
        if a == "--layout24":
            layout = "spec24"
        else:
            rest.append(a)
    raw = parse_hex("".join(rest), "decode input")
    for index, msg in enumerate(split_messages(raw, "decode input")):
        decode_one(index, msg, layout)


def cmd_decode24(args):
    if not args:
        fail("usage: --decode24 HEX (literal 24-bit latitude/longitude layout)", 2)
    raw = parse_hex("".join(args), "decode input")
    for index, msg in enumerate(split_messages(raw, "decode input")):
        decode_one(index, msg, "spec24")


def cmd_encode(args):
    if not args:
        fail("usage: --encode SPEC", 2)
    msg, _layout = build(" ".join(args))
    sys.stdout.write(msg.hex().upper() + "\n")


def cmd_encode_tsv(args):
    if not args:
        fail("usage: --encode-tsv SPEC", 2)
    msg, layout = build(" ".join(args))
    mtype = (msg[0] >> 4) & 0x0F
    emit("HEX", msg.hex().upper())
    emit("HEX_CHARS", len(msg.hex()))
    emit("BYTES", len(msg))
    emit("MSG_TYPE", mtype)
    emit("MSG_TYPE_NAME", name_of(MSG_TYPE_NAMES, mtype, "Reserved/Unknown"))
    emit("PROTO_VERSION", msg[0] & 0x0F)
    emit("LAYOUT", layout)


def cmd_roundtrip(args):
    if not args:
        fail("usage: --roundtrip SPEC", 2)
    msg, layout = build(" ".join(args))
    emit("HEX", msg.hex().upper())
    emit("BYTES", len(msg))
    decode_one(0, msg, layout)


def find_aligned_start(raw):
    """First offset where the rest of the buffer is a whole number of messages."""
    for off in range(0, len(raw)):
        if (len(raw) - off) % MSG_LEN:
            continue
        mtype = (raw[off] >> 4) & 0x0F
        ver = raw[off] & 0x0F
        if ver <= 3 and (mtype <= 5 or mtype == 15):
            return off
    return -1


def cmd_bt_payload(args):
    if not args:
        fail("usage: --bt-payload HEX", 2)
    raw = parse_hex("".join(args), "bt-payload input")
    payload, matches, skipped, leftover, offset = ad_find_rid_any_offset(raw)
    if not matches:
        emit_wrapper([], [], 0, "none (input treated as a raw Remote ID payload)")
        payload = raw
    else:
        emit_wrapper(matches, skipped, offset)
    if leftover:
        emit("TRAILING_BYTES", leftover.hex().upper())
    if not payload or len(payload) % MSG_LEN:
        # An AD length field that is short or long by a byte would leave the
        # payload misaligned; fall back to the first 25-byte-aligned header.
        alt = find_aligned_start(raw)
        if alt >= 0 and len(raw[alt:]) and matches:
            payload = raw[alt:]
            emit("AD_ALIGNMENT_FALLBACK", alt)
    decode_payload(payload, "astm32")


def cmd_scan_receive(args):
    """Scan a btmon text log for Remote ID AD structures and decode them."""
    if not args:
        fail("usage: --scan-receive LOGFILE", 2)
    path = args[0]
    try:
        text = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError as exc:
        fail("cannot read %s: %s" % (path, exc), 1)
    found = []
    seen = set()
    for mo in re.finditer(r"(?:[0-9A-Fa-f]{2}[ \t:,-]+){9,}[0-9A-Fa-f]{2}", text):
        blob = re.sub(r"[^0-9A-Fa-f]", "", mo.group(0))
        if len(blob) % 2:
            continue
        try:
            cand = bytes.fromhex(blob)
        except ValueError:
            continue
        payload, matches, _skipped, _leftover, _off = ad_find_rid_any_offset(cand)
        if not matches or not payload:
            continue
        if len(payload) % MSG_LEN == 1:
            payload = payload[1:]
        if not payload or len(payload) % MSG_LEN:
            continue
        for msg in split_messages(payload, "payload"):
            key = msg.hex().upper()
            if key in seen:
                continue
            seen.add(key)
            found.append(msg)
    if not found:
        sys.stderr.write("ERROR\tno Remote ID payload found in %s\n" % path)
        sys.exit(3)
    emit("SOURCE", path)
    emit("MESSAGE_COUNT", len(found))
    for index, msg in enumerate(found):
        decode_one(index, msg, "astm32")


def cmd_message_types(args):
    out = ["TYPE\tNAME\tNOTE"]
    for t in sorted(MSG_TYPE_NOTES):
        out.append("%d\t%s\t%s" % (t, MSG_TYPE_NAMES[t], MSG_TYPE_NOTES[t]))
    for t in range(0, 16):
        if t in MSG_TYPE_NOTES:
            continue
        out.append("%d\tReserved\tReserved by ASTM F3411" % t)
    sys.stdout.write("\n".join(out) + "\n")


def cmd_enums(args):
    out = []
    for label, table in (("ID_TYPE", ID_TYPE_NAMES), ("UA_TYPE", UA_TYPE_NAMES),
                         ("OPERATIONAL_STATUS", OP_STATUS_NAMES),
                         ("ACCURACY", ACCURACY_NAMES),
                         ("TIMESTAMP_ACCURACY", TS_ACCURACY_NAMES),
                         ("SELFID_DESC_TYPE", SELFID_DESC_NAMES),
                         ("HEIGHT_TYPE", HEIGHT_TYPE_NAMES),
                         ("EW_DIRECTION", EW_DIRECTION_NAMES),
                         ("RID_LOCATION", RID_LOCATION_NAMES),
                         ("EU_CATEGORY", EU_CATEGORY_NAMES),
                         ("EU_CLASS", EU_CLASS_NAMES)):
        for value in sorted(table):
            out.append("%s\t%d\t%s" % (label, value, table[value]))
    sys.stdout.write("\n".join(out) + "\n")


def main(argv):
    if not argv:
        fail("no subcommand", 2)
    cmd = argv[0]
    args = argv[1:]
    if cmd == "decode":
        cmd_decode(args)
    elif cmd == "decode24":
        cmd_decode24(args)
    elif cmd == "encode":
        cmd_encode(args)
    elif cmd == "encode-tsv":
        cmd_encode_tsv(args)
    elif cmd == "roundtrip":
        cmd_roundtrip(args)
    elif cmd == "bt-payload":
        cmd_bt_payload(args)
    elif cmd == "scan-receive":
        cmd_scan_receive(args)
    elif cmd == "message-types":
        cmd_message_types(args)
    elif cmd == "enums":
        cmd_enums(args)
    else:
        fail("unknown codec subcommand %s" % cmd, 2)


if __name__ == "__main__":
    main(sys.argv[1:])
PYEOF
}

drid_require_python() {
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required for the Remote ID codec; decode and encode are pure offline arithmetic that runs in python3\n' >&2
        return 1; }
}

# ── capability probes / status ───────────────────────────────────────────

drid_bt_adapters() {
    local d
    for d in /sys/class/bluetooth/hci*; do
        [[ -e "$d" ]] && basename "$d"
    done
}

drid_monitor_ifaces() {
    command -v iw >/dev/null 2>&1 || return 0
    iw dev 2>/dev/null | awk '
        /^[[:space:]]*Interface[[:space:]]/ { iface = $2 }
        $1 == "type" && $2 == "monitor" { if (iface != "") print iface }
    '
}

drid_sdr_radio() {
    # Known USB radio vendor:product pairs (RTL-SDR, HackRF, etc). Presence of a
    # tool is not proof of a radio, so this checks the USB descriptors.
    local f vid pid
    for f in /sys/bus/usb/devices/*/idVendor; do
        [[ -r "$f" ]] || continue
        vid="$(cat "$f" 2>/dev/null)"
        pid="$(cat "${f%idVendor}idProduct" 2>/dev/null)"
        case "$vid:$pid" in
            0bda:2831|0bda:2832|0bda:2838|1d50:604b|1d50:6089|2cf0:5250) return 0 ;;
        esac
    done
    return 1
}

drid_status_tsv() {
    local py=0 bt=0 mon=0 sdr=0
    command -v python3 >/dev/null 2>&1 && py=1
    printf 'python3\t%s\n' "$py"

    local adapters
    adapters="$(drid_bt_adapters | tr '\n' ',' | sed 's/,$//')"
    [[ -n "$adapters" ]] && bt=1
    printf 'bluetooth_adapter\t%s\n' "$bt"
    printf 'bluetooth_adapters\t%s\n' "${adapters:-none}"
    printf 'bluetoothctl\t%s\n' "$(command -v bluetoothctl >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'btmon\t%s\n' "$(command -v btmon >/dev/null 2>&1 && echo 1 || echo 0)"

    printf 'iw\t%s\n' "$(command -v iw >/dev/null 2>&1 && echo 1 || echo 0)"
    local mons
    mons="$(drid_monitor_ifaces | tr '\n' ',' | sed 's/,$//')"
    [[ -n "$mons" ]] && mon=1
    printf 'monitor_iface\t%s\n' "$mon"
    printf 'monitor_ifaces\t%s\n' "${mons:-none}"

    if drid_sdr_radio; then sdr=1; fi
    printf 'sdr_radio\t%s\n' "$sdr"

    # Offline codec: always available when python3 is present. No radio, no
    # root, no network path is involved.
    printf 'decode\t%s\n' "$py"
    printf 'encode\t%s\n' "$py"
    if (( bt == 1 && $(command -v btmon >/dev/null 2>&1 && echo 1 || echo 0) == 1 )); then
        printf 'live_receive\t1\n'
    elif (( sdr == 1 )); then
        printf 'live_receive\t0\n'
        printf 'live_receive_reason\tSDR radio present but the SDR receive path is not implemented; only the Bluetooth transport is implemented\n'
    else
        printf 'live_receive\t0\n'
        printf 'live_receive_reason\tno Bluetooth adapter (/sys/class/bluetooth/hci* absent) and no SDR radio\n'
    fi
    printf 'message_bytes\t25\n'
    printf 'hex_chars_per_message\t50\n'
}

# ── offline codec commands ───────────────────────────────────────────────

drid_decode() {
    [[ $# -ge 1 && -n "${1:-}" ]] || { printf 'ERROR\tusage: --decode HEX (one or more concatenated 25-byte messages)\n' >&2; return 2; }
    drid_require_python || return 1
    drid_py decode "$@"
}

drid_decode24() {
    [[ $# -ge 1 && -n "${1:-}" ]] || { printf 'ERROR\tusage: --decode24 HEX (literal 24-bit latitude/longitude variant)\n' >&2; return 2; }
    drid_require_python || return 1
    drid_py decode24 "$@"
}

drid_encode() {
    [[ $# -ge 1 && -n "${1:-}" ]] || { printf 'ERROR\tusage: --encode SPEC\n' >&2; return 2; }
    drid_require_python || return 1
    drid_py encode "$@"
}

drid_encode_tsv() {
    [[ $# -ge 1 && -n "${1:-}" ]] || { printf 'ERROR\tusage: --encode-tsv SPEC\n' >&2; return 2; }
    drid_require_python || return 1
    drid_py encode-tsv "$@"
}

drid_roundtrip() {
    [[ $# -ge 1 && -n "${1:-}" ]] || { printf 'ERROR\tusage: --roundtrip SPEC\n' >&2; return 2; }
    drid_require_python || return 1
    drid_py roundtrip "$@"
}

drid_bt_payload() {
    [[ $# -ge 1 && -n "${1:-}" ]] || { printf 'ERROR\tusage: --bt-payload HEX\n' >&2; return 2; }
    drid_require_python || return 1
    drid_py bt-payload "$@"
}

drid_message_types_tsv() {
    drid_require_python || return 1
    drid_py message-types
}

# Offline half of --receive: scrape a btmon text log for Remote ID AD
# structures and decode them. No radio needed, so it is testable without one.
drid_scan_log() {
    [[ $# -ge 1 && -n "${1:-}" ]] || { printf 'ERROR\tusage: --scan-log BTMON_LOG\n' >&2; return 2; }
    [[ -f "$1" ]] || { printf 'ERROR\tno such log file: %s\n' "$1" >&2; return 2; }
    drid_require_python || return 1
    drid_py scan-receive "$1"
}

drid_enums_tsv() {
    drid_require_python || return 1
    drid_py enums
}

# ── live reception (GATED) ───────────────────────────────────────────────

drid_receive() {
    local dur="${1:-10}" log out rc
    [[ "$dur" =~ ^[0-9]+$ ]] || {
        printf 'ERROR\tduration must be an integer number of seconds, got %s\n' "$dur" >&2
        return 2; }
    (( dur >= 1 && dur <= 600 )) || {
        printf 'ERROR\tduration must be between 1 and 600 seconds, got %s\n' "$dur" >&2
        return 2; }

    local adapters
    adapters="$(drid_bt_adapters | tr '\n' ' ')"
    if [[ -z "${adapters// /}" ]]; then
        printf 'ERROR\tlive reception unavailable: no Bluetooth adapter found (/sys/class/bluetooth/hci* does not exist)\n' >&2
        if ! drid_sdr_radio; then
            printf 'ERROR\tlive reception unavailable: no SDR radio present either, so the Wi-Fi Beacon/NAN transport cannot be received\n' >&2
        fi
        printf 'HINT\tdecode and encode are fully offline and need no radio: --decode HEX, --encode SPEC, --bt-payload HEX; see --status-tsv\n' >&2
        return 1
    fi
    if ! command -v btmon >/dev/null 2>&1; then
        printf 'ERROR\tlive reception unavailable: btmon (bluez) is not installed, and it is required to read BLE advertising reports from %s\n' "$adapters" >&2
        return 1
    fi
    drid_require_python || return 1

    log="$MOD_CAPS/btmon_$(date +%Y%m%d_%H%M%S).log"
    mkdir -p "$MOD_CAPS" 2>/dev/null
    info "capturing BLE advertising reports for ${dur}s on ${adapters}-> $log"
    timeout "$((dur + 3))" btmon -A >"$log" 2>&1
    rc=$?
    case "$rc" in
        0|124) : ;;
        *) printf 'ERROR\tbtmon exited with status %d before the capture window ended (log: %s)\n' "$rc" "$log" >&2
           return 1 ;;
    esac
    out="$(drid_py scan-receive "$log")"
    rc=$?
    if (( rc != 0 )) || [[ -z "$out" ]]; then
        printf 'ERROR\tno Remote ID payload observed in %ss on %s (log kept at %s)\n' "$dur" "$adapters" "$log" >&2
        return 1
    fi
    printf 'CAPTURE_LOG\t%s\n' "$log"
    printf 'CAPTURE_SECONDS\t%s\n' "$dur"
    printf '%s\n' "$out"
}

# ── selftest ─────────────────────────────────────────────────────────────

drid_field() {
    printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1 == k { print $2; exit }'
}

drid_close() {
    # drid_close A B TOLERANCE -> 0 when |A-B| <= TOLERANCE
    awk -v a="$1" -v b="$2" -v t="$3" 'BEGIN{
        if (a == "" || b == "") exit 1
        d = a - b
        if (d < 0) d = -d
        exit !(d <= t)
    }'
}

drid_selftest() {
    local bad=0 rc hex out err lat lon status speed alt t1 t2 tmp

    err="$MOD_TMP/selftest.err"
    mkdir -p "$MOD_TMP" 2>/dev/null

    if ! command -v python3 >/dev/null 2>&1; then
        printf 'python3-present\tFAIL python3 not found; the codec cannot run at all\n'
        printf 'RESULT\tFAIL(1)\n'
        return 1
    fi
    printf 'python3-present\tPASS\n'

    # ── (f) encoded output is exactly 50 hex characters ──────────────────
    hex="$(drid_py encode 'basicid id_type=1 ua_type=2 uas_id=1596F39XK2' 2>"$err")"
    rc=$?
    if (( rc == 0 )) && [[ ${#hex} -eq 50 && "$hex" =~ ^[0-9A-Fa-f]{50}$ ]]; then
        printf 'encode-exactly-50-hex\tPASS (%s)\n' "$hex"
    else
        printf 'encode-exactly-50-hex\tFAIL rc=%d len=%d value=%s err=%s\n' \
            "$rc" "${#hex}" "$hex" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
        bad=$((bad + 1))
    fi

    # ── (a) Basic ID round trip: UAS ID and both type fields survive ─────
    out="$(drid_py decode "$hex" 2>"$err")"
    rc=$?
    if (( rc != 0 )); then
        printf 'basicid-roundtrip\tFAIL decode rc=%d err=%s\n' "$rc" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
        bad=$((bad + 1))
    else
        t1="$(drid_field "$out" UAS_ID)"
        t2="$(drid_field "$out" ID_TYPE)"
        tmp="$(drid_field "$out" UA_TYPE)"
        if [[ "$t1" == "1596F39XK2" && "$t2" == "1" && "$tmp" == "2" ]]; then
            printf 'basicid-roundtrip\tPASS (uas_id=%s id_type=%s ua_type=%s)\n' "$t1" "$t2" "$tmp"
        else
            printf 'basicid-roundtrip\tFAIL uas_id=%s id_type=%s ua_type=%s\n' "$t1" "$t2" "$tmp"
            bad=$((bad + 1))
        fi
        # the reserved bytes must be printed so the raw structure is auditable
        tmp="$(drid_field "$out" RESERVED_BYTES_22_24)"
        if [[ "$tmp" == "000000" ]]; then
            printf 'basicid-reserved-bytes-printed\tPASS (RESERVED_BYTES_22_24=%s)\n' "$tmp"
        else
            printf 'basicid-reserved-bytes-printed\tFAIL got %s\n' "$tmp"
            bad=$((bad + 1))
        fi
    fi

    # ── (b) Location round trip: lat/lon within 1e-6 ─────────────────────
    hex="$(drid_py encode 'location lat=48.8566 lon=2.3522 alt=120 speed=15 status=2' 2>"$err")"
    rc=$?
    if (( rc != 0 )); then
        printf 'location-roundtrip\tFAIL encode rc=%d err=%s\n' "$rc" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
        bad=$((bad + 1))
    else
        out="$(drid_py decode "$hex" 2>"$err")"
        lat="$(drid_field "$out" LATITUDE)"
        lon="$(drid_field "$out" LONGITUDE)"
        alt="$(drid_field "$out" PRESSURE_ALTITUDE_M)"
        speed="$(drid_field "$out" SPEED_MPS)"
        status="$(drid_field "$out" OPERATIONAL_STATUS)"
        if drid_close "$lat" 48.8566 1e-6 && drid_close "$lon" 2.3522 1e-6; then
            printf 'location-roundtrip\tPASS (lat=%s lon=%s)\n' "$lat" "$lon"
        else
            printf 'location-roundtrip\tFAIL lat=%s lon=%s hex=%s\n' "$lat" "$lon" "$hex"
            bad=$((bad + 1))
        fi
        if drid_close "$alt" 120 0.5 && drid_close "$speed" 15 0.25 && [[ "$status" == "2" ]]; then
            printf 'location-fields-roundtrip\tPASS (alt=%s speed=%s status=%s)\n' "$alt" "$speed" "$status"
        else
            printf 'location-fields-roundtrip\tFAIL alt=%s speed=%s status=%s\n' "$alt" "$speed" "$status"
            bad=$((bad + 1))
        fi
    fi

    # ── (c) NEGATIVE latitude/longitude round trip (two's complement) ────
    hex="$(drid_py encode 'location lat=-33.8688 lon=-151.2093 alt=45.5 speed=7.25 status=1' 2>"$err")"
    rc=$?
    if (( rc != 0 )); then
        printf 'negative-latlon-roundtrip\tFAIL encode rc=%d err=%s\n' "$rc" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
        bad=$((bad + 1))
    else
        out="$(drid_py decode "$hex" 2>"$err")"
        lat="$(drid_field "$out" LATITUDE)"
        lon="$(drid_field "$out" LONGITUDE)"
        if drid_close "$lat" -33.8688 1e-6 && drid_close "$lon" -151.2093 1e-6; then
            printf 'negative-latlon-roundtrip\tPASS (lat=%s lon=%s hex=%s)\n' "$lat" "$lon" "$hex"
        else
            printf 'negative-latlon-roundtrip\tFAIL lat=%s lon=%s hex=%s\n' "$lat" "$lon" "$hex"
            bad=$((bad + 1))
        fi
    fi

    # ── (d) out-of-range latitude is REJECTED, not silently encoded ──────
    out="$(drid_py encode 'location lat=91.0 lon=2.0' 2>"$err")"
    rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'latitude-91-rejected\tPASS (rc=%d, stderr: %s)\n' "$rc" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
    else
        printf 'latitude-91-rejected\tFAIL rc=%d stdout=%s\n' "$rc" "$out"
        bad=$((bad + 1))
    fi
    out="$(drid_py encode 'location lon=181.0 lat=10.0' 2>"$err")"
    rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'longitude-181-rejected\tPASS (rc=%d)\n' "$rc"
    else
        printf 'longitude-181-rejected\tFAIL rc=%d stdout=%s\n' "$rc" "$out"
        bad=$((bad + 1))
    fi
    # ... while the legal extremes still encode and round trip
    for t1 in 90.0 -90.0; do
        hex="$(drid_py encode "location lat=$t1 lon=0.0" 2>"$err")"
        rc=$?
        out="$(drid_py decode "$hex" 2>"$err")"
        lat="$(drid_field "$out" LATITUDE)"
        if (( rc == 0 )) && drid_close "$lat" "$t1" 1e-6; then
            printf 'latitude-boundary-%s-accepted\tPASS (decoded %s)\n' "$t1" "$lat"
        else
            printf 'latitude-boundary-%s-accepted\tFAIL rc=%d decoded=%s\n' "$t1" "$rc" "$lat"
            bad=$((bad + 1))
        fi
    done

    # ── every encoder must emit exactly 25 bytes / 50 hex characters ─────
    for t1 in 'basicid id_type=1 ua_type=2 uas_id=1596F39XK2' \
              'location lat=48.8566 lon=2.3522 alt=120 speed=15 status=2' \
              'location24 lat=0.5 lon=-0.5' \
              'auth auth_type=1 payload=deadbeefcafe' \
              'selfid desc=survey drone' \
              'system op_lat=48.8566 op_lon=2.3522' \
              'operatorid operator_id=FIN87astrdge12k8' \
              'msgpack count=2'; do
        hex="$(drid_py encode "$t1" 2>"$err")"
        rc=$?
        if (( rc == 0 )) && [[ ${#hex} -eq 50 && "$hex" =~ ^[0-9A-Fa-f]{50}$ ]]; then
            printf 'encoder-50-hex[%s]\tPASS\n' "${t1%% *}"
        else
            printf 'encoder-50-hex[%s]\tFAIL rc=%d len=%d hex=%s err=%s\n' \
                "${t1%% *}" "$rc" "${#hex}" "$hex" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
            bad=$((bad + 1))
        fi
    done

    # ── (e) truncated input is rejected with a non-zero exit ─────────────
    hex="$(drid_py encode 'basicid id_type=1 ua_type=2 uas_id=1596F39XK2' 2>/dev/null)"
    out="$(drid_py decode "${hex:0:40}" 2>"$err")"
    rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'truncated-input-rejected\tPASS (40 hex chars = 20 bytes, rc=%d, stderr: %s)\n' \
            "$rc" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
    else
        printf 'truncated-input-rejected\tFAIL rc=%d stdout=%s\n' "$rc" "$out"
        bad=$((bad + 1))
    fi
    out="$(drid_py decode '0212' 2>"$err")"
    rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'short-input-rejected\tPASS (2 bytes, rc=%d)\n' "$rc"
    else
        printf 'short-input-rejected\tFAIL rc=%d stdout=%s\n' "$rc" "$out"
        bad=$((bad + 1))
    fi
    out="$(drid_py decode '' 2>"$err")"
    rc=$?
    if (( rc != 0 )); then
        printf 'empty-input-rejected\tPASS (rc=%d)\n' "$rc"
    else
        printf 'empty-input-rejected\tFAIL rc=%d\n' "$rc"
        bad=$((bad + 1))
    fi
    # one message plus a stray byte must also be refused
    out="$(drid_py decode "${hex}00" 2>"$err")"
    rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'misaligned-input-rejected\tPASS (26 bytes, rc=%d)\n' "$rc"
    else
        printf 'misaligned-input-rejected\tFAIL rc=%d stdout=%s\n' "$rc" "$out"
        bad=$((bad + 1))
    fi

    # ── Self-ID and System round trips ───────────────────────────────────
    hex="$(drid_py encode 'selfid desc=survey drone' 2>"$err")"
    rc=$?
    out="$(drid_py decode "$hex" 2>"$err")"
    t1="$(drid_field "$out" DESCRIPTION)"
    t2="$(drid_field "$out" PAYLOAD_LEN)"
    if (( rc == 0 )) && [[ "$t1" == "survey drone" ]]; then
        printf 'selfid-roundtrip\tPASS (description=%s desc-field-len=%s)\n' "$t1" "${t2:-23}"
    else
        printf 'selfid-roundtrip\tFAIL rc=%d description=%s\n' "$rc" "$t1"
        bad=$((bad + 1))
    fi

    hex="$(drid_py encode 'system op_lat=-22.9068 op_lon=-43.1729 area_count=3' 2>"$err")"
    rc=$?
    out="$(drid_py decode "$hex" 2>"$err")"
    lat="$(drid_field "$out" OP_LATITUDE)"
    lon="$(drid_field "$out" OP_LONGITUDE)"
    if (( rc == 0 )) && drid_close "$lat" -22.9068 1e-6 && drid_close "$lon" -43.1729 1e-6; then
        printf 'system-operator-latlon-roundtrip\tPASS (op_lat=%s op_lon=%s)\n' "$lat" "$lon"
    else
        printf 'system-operator-latlon-roundtrip\tFAIL rc=%d op_lat=%s op_lon=%s\n' "$rc" "$lat" "$lon"
        bad=$((bad + 1))
    fi

    # ── Bluetooth AD wrapper stripping (service data 0xFFFA) ─────────────
    # AD element: flags (02 01 06) then service data with length 0x1C
    # (1 type + 2 UUID + 25 payload = 28).
    hex="$(drid_py encode 'basicid id_type=1 ua_type=2 uas_id=1596F39XK2' 2>/dev/null)"
    out="$(drid_py bt-payload "0201061C16FAFF${hex}" 2>"$err")"
    rc=$?
    t1="$(drid_field "$out" UAS_ID)"
    t2="$(drid_field "$out" AD_WRAPPER)"
    if (( rc == 0 )) && [[ "$t1" == "1596F39XK2" && "$t2" == "stripped" ]]; then
        printf 'bt-payload-service-data-unwrap\tPASS (AD_WRAPPER=%s UAS_ID=%s)\n' "$t2" "$t1"
    else
        printf 'bt-payload-service-data-unwrap\tFAIL rc=%d AD_WRAPPER=%s UAS_ID=%s err=%s\n' \
            "$rc" "$t2" "$t1" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
        bad=$((bad + 1))
    fi
    # manufacturer specific element: length 0x1C, AD type 0xFF, company 0xFFF0
    out="$(drid_py bt-payload "0201061CFFF0FF${hex}" 2>"$err")"
    t1="$(drid_field "$out" UAS_ID)"
    if [[ "$t1" == "1596F39XK2" ]]; then
        printf 'bt-payload-manufacturer-unwrap\tPASS (UAS_ID=%s)\n' "$t1"
    else
        printf 'bt-payload-manufacturer-unwrap\tFAIL UAS_ID=%s\n' "$t1"
        bad=$((bad + 1))
    fi
    out="$(drid_py bt-payload 'zznothex' 2>"$err")"
    rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'bt-payload-garbage-rejected\tPASS (rc=%d)\n' "$rc"
    else
        printf 'bt-payload-garbage-rejected\tFAIL rc=%d stdout=%s\n' "$rc" "$out"
        bad=$((bad + 1))
    fi

    # ── literal 24-bit layout: the 3-byte two's complement path ──────────
    hex="$(drid_py encode 'location24 lat=-0.5 lon=0.25 alt=10 speed=2' 2>"$err")"
    rc=$?
    out="$(drid_py decode24 "$hex" 2>"$err")"
    lat="$(drid_field "$out" LATITUDE)"
    lon="$(drid_field "$out" LONGITUDE)"
    if (( rc == 0 )) && drid_close "$lat" -0.5 1e-6 && drid_close "$lon" 0.25 1e-6; then
        printf 'layout24-negative-roundtrip\tPASS (lat=%s lon=%s hex=%s)\n' "$lat" "$lon" "$hex"
    else
        printf 'layout24-negative-roundtrip\tFAIL rc=%d lat=%s lon=%s\n' "$rc" "$lat" "$lon"
        bad=$((bad + 1))
    fi
    out="$(drid_py encode 'location24 lat=1.0 lon=0.0' 2>"$err")"
    rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'layout24-out-of-range-rejected\tPASS (rc=%d, stderr: %s)\n' "$rc" "$(tr '\n' ' ' <"$err" 2>/dev/null)"
    else
        printf 'layout24-out-of-range-rejected\tFAIL rc=%d stdout=%s\n' "$rc" "$out"
        bad=$((bad + 1))
    fi

    # ── multiple concatenated messages in one input ──────────────────────
    hex="$(drid_py encode 'basicid id_type=1 ua_type=2 uas_id=1596F39XK2' 2>/dev/null)"
    tmp="$(drid_py encode 'location lat=48.8566 lon=2.3522 alt=120 speed=15 status=2' 2>/dev/null)"
    out="$(drid_py decode "${hex}${tmp}" 2>"$err")"
    rc=$?
    t1="$(printf '%s\n' "$out" | awk -F'\t' '$1 == "MSG_INDEX" { n++ } END { print n + 0 }')"
    if (( rc == 0 )) && [[ "$t1" == "2" ]]; then
        printf 'two-concatenated-messages\tPASS (MSG_INDEX rows=%s)\n' "$t1"
    else
        printf 'two-concatenated-messages\tFAIL rc=%d MSG_INDEX rows=%s\n' "$rc" "$t1"
        bad=$((bad + 1))
    fi

    rm -f "$err" "$MOD_TMP/st.err"

    if (( bad == 0 )); then
        printf 'RESULT\tPASS\n'
        return 0
    fi
    printf 'RESULT\tFAIL(%d)\n' "$bad"
    return 1
}

# ── info ─────────────────────────────────────────────────────────────────

drid_info() {
    cat <<'EOF'
ASTM F3411 Remote ID message codec

Every Remote ID message is EXACTLY 25 bytes. Byte 0 is always
(message type << 4) | protocol version, so one hex blob can hold several
concatenated messages: --decode takes 50 hex characters per message.

Message types
  0  Basic ID          ID type, UA type, 20-byte UAS ID
  1  Location/Vector   position, altitude, speed, accuracy, timestamp
  2  Authentication    header plus opaque 23-byte payload
  3  Self-ID           header plus 23-byte description string
  4  System            operator location, area, EU category and class
  5  Operator ID       header plus 23-byte operator ID string
  15 Message Pack      byte 1 is the packed message count

Layout of the Location/Vector message
  byte 1  bits 7-5 operational status, bit 4 height type, bits 3-2 reserved,
          bit 1 E/W direction, bit 0 speed multiplier
  byte 2  bit 7 reserved, bits 6-0 encoded speed
  byte 3  bit 7 reserved, bits 6-0 encoded vertical speed (two's complement)
  bytes 4-7   latitude, bytes 8-11 longitude (see below)
  bytes 12-13 pressure altitude, 14-15 geodetic altitude, 16-17 height
  byte 18 vertical accuracy (high nibble) and horizontal accuracy (low nibble)
  byte 19 baro accuracy (high nibble) and speed accuracy (low nibble)
  bytes 20-23 timestamp, byte 24 timestamp accuracy (high nibble)
  The decoder also prints the reserved bits and bytes and RAW_HEX so the
  structure can be audited byte by byte.

  Speeds are encoded value x 0.25 m/s with speed multiplier 0 and x 0.75 m/s
  with multiplier 1. The encoder picks the multiplier that preserves the
  value and refuses anything above 95.25 m/s. Altitudes are 16-bit unsigned
  as (metres + 1000) / 0.5, spanning -1000.0 to 31767.5 m. Timestamps are
  tenths of a second since the hour.

  Vertical speed: the layout encodes bits 6-0 as a 7-bit two's complement
  value. This module reports VERTICAL_SPEED_ENCODED (signed) and
  VERTICAL_SPEED_MPS (x 0.5 m/s). ASTM F3411 implementations that use the
  offset form (raw - 63) x 0.5 m/s are also covered by the extra
  VERTICAL_SPEED_OFFSET_FORM_MPS row, so neither reading is hidden.

Latitude and longitude
  Degrees x 1e7 in little-endian two's complement, which is what ASTM F3411
  uses for BOTH the Location message (bytes 4-7 and 8-11) and the System
  message (bytes 3-6 and 7-10). This is the default layout.

  INTEROP CAVEAT - read before trusting a built message on the air.
  The layouts are NOT interchangeable: a receiver expecting one misreads
  the other, because every field after the coordinates shifts. The 32-bit
  form is the default because a 24-bit degrees x 1e7 field spans only
  +/-0.8388607 degrees and so cannot express any real coordinate. Neither
  layout has been checked against a real drone broadcast or a certified
  receiver on this machine, so treat the encoder as producing structurally
  valid, self-consistent messages rather than guaranteed-interoperable
  ones. Use --layout spec24 to inspect the 24-bit form explicitly.

  A 24-bit degrees x 1e7 field can only hold +/-0.8388607 degrees, so it
  physically cannot carry a real position such as 48.8566: the module uses
  the 32-bit ASTM fields so that real coordinates round trip. The literal
  24-bit variant is still implemented and reachable with --decode24 and with
  layout=24 or the location24 keyword, where latitude is bytes 4-6, longitude
  is bytes 7-9 and the remaining fields sit two bytes earlier. Out-of-range
  coordinates are REJECTED with a non-zero exit; they are never silently
  truncated or wrapped.

Bluetooth transport
  Remote ID rides in a Bluetooth AD structure: service data AD type 0x16 with
  UUID 0xFFFA, or manufacturer specific data AD type 0xFF with company ID
  0xFFF0 or 0xFFFF. --bt-payload walks the AD elements, strips the wrapper and
  decodes every complete 25-byte message it finds.

Radios and gating
  Decoding and encoding are pure offline arithmetic over hex: no radio, no
  root, no network. --receive is the only gated command. It needs a Bluetooth
  adapter (/sys/class/bluetooth/hci*) plus btmon, and it refuses with a
  non-zero exit naming exactly what is missing when no adapter is present. It
  never reports a capture it did not make: if no Remote ID payload is seen in
  the capture window it exits non-zero.

Examples
  --decode 021231353936463339584B32000000000000000000000000
  --encode basicid id_type=1 ua_type=2 uas_id=1596F39XK2
  --encode location lat=48.8566 lon=2.3522 alt=120 speed=15 status=2
  --encode selfid desc=survey drone
  --encode system op_lat=48.8566 op_lon=2.3522
  --bt-payload 0201061B16FAFF<50 hex chars>
  --selftest
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────

drid_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        drid_status_tsv ;;
        --message-types-tsv) drid_message_types_tsv ;;
        --enums-tsv)         drid_enums_tsv ;;
        --decode)            drid_decode "$@" ;;
        --decode24)          drid_decode24 "$@" ;;
        --encode)            drid_encode "$@" ;;
        --encode-tsv)        drid_encode_tsv "$@" ;;
        --roundtrip)         drid_roundtrip "$@" ;;
        --bt-payload)        drid_bt_payload "$@" ;;
        --scan-log)          drid_scan_log "$@" ;;
        --receive)           drid_receive "$@" ;;
        --selftest)          drid_selftest ;;
        --info)              drid_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv               capabilities; offline codec vs live reception
  --message-types-tsv        reference table of the message types
  --enums-tsv                reference table of the field enums
  --decode HEX [--layout24]  decode one or more concatenated 25-byte messages
  --decode24 HEX             decode with the literal 24-bit lat/lon layout
  --encode SPEC              build one message, prints 50 hex characters
  --encode-tsv SPEC          build one message, KEY/VALUE view
  --roundtrip SPEC           encode then decode in one step
  --bt-payload HEX           strip the Bluetooth AD wrapper, then decode
  --scan-log BTMON_LOG       decode Remote ID payloads found in a btmon log
  --receive [SECONDS]        live reception (GATED: needs a Bluetooth radio)
  --selftest                 round trips, boundaries, error paths
  --info                     format and gating notes

Encode specs
  basicid  id_type=1 ua_type=2 uas_id=1596F39XK2
  location lat=48.8566 lon=2.3522 alt=120 speed=15 status=2
  selfid   desc=survey drone
  system   op_lat=48.8566 op_lon=2.3522
  auth     payload=deadbeef
  operatorid operator_id=FIN87astrdge12k8
  Type keywords accept a trailing 24 (location24) or layout=24 for the
  literal 24-bit latitude/longitude variant.
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    drid_cli_main "$@"
fi

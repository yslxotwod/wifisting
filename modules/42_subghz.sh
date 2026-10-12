#!/usr/bin/env bash
# 42_subghz — Sub-GHz RF
# Decode sub-GHz OOK pulse trains and reference the common bands.
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

MOD_TMP="$TMP_DIR/subghz"
MOD_LOOT="$LOOT_DIR/subghz"
MOD_LOGS="$LOG_DIR/subghz"
MOD_CAPS="$CAPTURES_DIR/subghz"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────
# Sub-GHz OOK work splits in two: everything that reads a pulse train is pure
# arithmetic and always available; everything that touches a radio needs an
# SDR. Only the radio half is gated.

SUBGHZ_RTL_USB="0bda:2838"
SUBGHZ_HACKRF_USB="1d50:6089"

subghz_have() { command -v "$1" >/dev/null 2>&1; }

subghz_usb_has() {
    local id="$1"
    subghz_have lsusb || return 1
    lsusb 2>/dev/null | grep -qi -- "$id"
}

subghz_usb_rtlsdr() { subghz_usb_has "$SUBGHZ_RTL_USB" && echo 1 || echo 0; }
subghz_usb_hackrf() { subghz_usb_has "$SUBGHZ_HACKRF_USB" && echo 1 || echo 0; }

subghz_sdr_present() {
    [[ "$(subghz_usb_rtlsdr)" == 1 || "$(subghz_usb_hackrf)" == 1 ]]
}

subghz_sdr_tools() {
    local t
    for t in rtl_power rtl_fm rtl_test hackrf_sweep hackrf_info; do
        subghz_have "$t" && return 0
    done
    return 1
}

# Which capture tool can actually be used with the hardware that is attached.
subghz_sdr_backend() {
    if [[ "$(subghz_usb_rtlsdr)" == 1 ]] && subghz_have rtl_power; then
        echo rtl_power; return 0
    fi
    if [[ "$(subghz_usb_hackrf)" == 1 ]] && subghz_have hackrf_sweep; then
        echo hackrf_sweep; return 0
    fi
    if subghz_sdr_present && subghz_have rtl_fm; then
        echo rtl_fm; return 0
    fi
    echo none
}

subghz_status_tsv() {
    local py=0 t backend
    subghz_have python3 && py=1
    printf 'python3\t%s\n' "$py"
    for t in rtl_fm rtl_test rtl_power hackrf_info hackrf_sweep rtl_433 lsusb; do
        printf '%s\t%s\n' "$t" "$(subghz_have "$t" && echo 1 || echo 0)"
    done
    printf 'usb_rtlsdr\t%s\n' "$(subghz_usb_rtlsdr)"
    printf 'usb_hackrf\t%s\n' "$(subghz_usb_hackrf)"
    printf 'sdr_tools\t%s\n' "$(subghz_sdr_tools && echo 1 || echo 0)"
    printf 'sdr_present\t%s\n' "$(subghz_sdr_present && echo 1 || echo 0)"
    backend="$(subghz_sdr_backend)"
    printf 'sdr_backend\t%s\n' "$backend"
    # Offline half: pulse decoding and encoding are pure arithmetic over a
    # timing list, so they are available whenever python3 is.
    printf 'decode\t%s\n' "$py"
    printf 'encode\t%s\n' "$py"
    printf 'parse_sweep\t%s\n' "$py"
    printf 'bands\t1\n'
    printf 'live_capture\t%s\n' "$([[ "$backend" != none ]] && echo 1 || echo 0)"
    printf 'rssi_scan\t%s\n' \
        "$([[ "$backend" == rtl_power || "$backend" == hackrf_sweep ]] && echo 1 || echo 0)"
    printf 'loot_dir\t%s\n' "$MOD_LOOT"
}

# ── band reference ───────────────────────────────────────────────────────
subghz_bands_tsv() {
    cat <<'EOF'
FREQ_MHZ	REGION	TYPICAL_USE
303.875	US (FCC Part 15.231)	security sensors, door and window contacts, some remotes
315.0	US / Region 2 (Part 15.231)	garage and gate remotes, doorbells, alarm sensors, TPMS
390.0	US (Part 15.231)	older garage door openers and remote switches
418.0	US (Part 15.231)	garage door openers, home automation remotes
433.05-434.79 (433.92 centre)	EU ISM band 1, also used worldwide	the busiest sub-GHz band: remotes, weather stations, TPMS, CAME and Princeton remotes
868.0-868.6	EU ISM (868 MHz)	EU sensors, alarms, smart meters, some remotes
868.7-869.2	EU ISM (868 MHz wideband)	EU alarms and telemetry
902.0-928.0 (915 centre)	US / Region 2 ISM	US sensors, utility meters, LoRa US, garage remotes
EOF
}

# ── pulse train decoding (offline) ───────────────────────────────────────
# TIMINGS is a list of alternating high/low interval durations in microseconds,
# starting with a high. Works on captured trains, on encoder output, or on
# numbers copied out of a logic analyser capture.
subghz_decode_pulses() {
    local raw="$*"
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required for pulse decoding and is not on PATH\n' >&2
        return 1
    }
    # The interpreter reads its program from stdin, so the timing list has to be
    # drained here rather than inside python.
    if [[ "$raw" == "-" ]]; then
        if [[ -t 0 ]]; then
            printf 'ERROR\t--decode-pulses - wants a timing list on stdin, but stdin is a terminal\n' >&2
            return 2
        fi
        raw="$(cat)"
    fi
    python3 - "$raw" <<'PYEOF'
import sys, math

# Interval classes relative to the estimated base unit t.
S_LO, S_HI = 0.55, 1.62
L_LO, L_HI = 1.72, 5.60
G_MIN = 6.0
MAX_UNITS = 512
SPREAD_MAX = 0.35

# (family, shape, min ratio, max ratio, min sync units, max sync units)
FAMILIES = [
    ("princeton-pt2262", "pwm", 2.40, 3.60, 16.0, 1.0e9),
    ("came-cardin-pwm", "pwm", 1.70, 2.40, 5.0, 14.0),
    ("ook-pwm-generic", "pwm", 1.70, 5.60, 5.0, 48.0),
    ("nexa-like-ppm-manchester", "ppm", 3.50, 6.00, 8.0, 12.0),
    ("ook-ppm-manchester", "ppm", 1.50, 8.00, 2.0, 64.0),
]
NAMED = ("princeton-pt2262", "came-cardin-pwm", "nexa-like-ppm-manchester")


def die(msg, code=3):
    sys.stderr.write("ERROR\t" + msg + "\n")
    sys.exit(code)


def num(v):
    if v is None:
        return "-"
    if abs(v - round(v)) < 0.05:
        return str(int(round(v)))
    return "%.1f" % v


def med(xs):
    xs = sorted(xs)
    n = len(xs)
    if n == 0:
        return 0.0
    h = n // 2
    if n % 2:
        return xs[h]
    return 0.5 * (xs[h - 1] + xs[h])


def spread(xs):
    m = med(xs)
    if m <= 0:
        return 0.0
    return max(abs(v - m) / m for v in xs)


def pclass(v, t):
    r = v / t
    if S_LO <= r <= S_HI:
        return "S"
    if L_LO <= r <= L_HI:
        return "L"
    if r >= G_MIN:
        return "G"
    return "?"


def sync_phrase(lo, hi):
    if hi >= 1.0e8:
        return "sync >= %g units" % lo
    return "sync %g-%g units" % (lo, hi)


def parse_timings(raw):
    toks = raw.replace(",", " ").replace(";", " ").replace("|", " ").split()
    if not toks:
        die("empty pulse list: give a comma or space separated list of microsecond intervals")
    vals = []
    for tk in toks:
        try:
            v = float(tk)
        except ValueError:
            die("not a number in pulse list: " + repr(tk))
        if not math.isfinite(v) or v <= 0:
            die("pulse intervals must be positive finite numbers, got " + repr(tk))
        if v > 1.0e7:
            die("pulse interval out of range (over 10 s): " + repr(tk))
        vals.append(v)
    if len(vals) < 4:
        die("need at least 4 intervals (sync plus one bit pair), got %d" % len(vals))
    return vals


def pick_unit(vals):
    """Smallest base unit under which every interval falls into a clean class."""
    best = None
    for c in sorted(set(round(v, 3) for v in vals)):
        if c <= 0:
            continue
        cc = [pclass(v, c) for v in vals]
        ns = cc.count("S")
        nl = cc.count("L")
        if ns == 0 or nl == 0:
            continue
        score = ns + nl + cc.count("G")
        key = (-score, c)
        if best is None or key < best[0]:
            best = (key, c)
    return best[1] if best else None


def bits_to_hex(bits):
    if not bits:
        return "-"
    pad = (-len(bits)) % 4
    b = ("0" * pad) + "".join(bits)
    return "%0*X" % (len(b) // 4, int(b, 2))


def tristate(bits):
    if len(bits) % 2:
        return "-"
    m = {"00": "0", "11": "1", "01": "F", "10": "?"}
    return "".join(m.get(bits[i] + bits[i + 1], "?") for i in range(0, len(bits), 2))


def main():
    raw = sys.argv[1] if len(sys.argv) > 1 else ""
    vals = parse_timings(raw)
    n = len(vals)
    t = pick_unit(vals)
    if t is None:
        die("cannot separate short and long intervals: no OOK PWM/PPM structure in %d "
            "intervals" % n)
    c = [pclass(v, t) for v in vals]
    shorts = [v for v, k in zip(vals, c) if k == "S"]
    longs = [v for v, k in zip(vals, c) if k == "L"]
    if not shorts or not longs:
        die("only one interval class found; not an OOK pulse train")
    if spread(shorts) > SPREAD_MAX or spread(longs) > SPREAD_MAX:
        die("no consistent interval classes (short spread %.2f, long spread %.2f); this does "
            "not look like an OOK pulse train" % (spread(shorts), spread(longs)))
    short_us = med(shorts)
    long_us = med(longs)
    if short_us <= 0:
        die("zero-length short interval; cannot normalise")
    ratio = long_us / short_us

    # Constant-width pulses with two gap widths is PPM, otherwise PWM pairs.
    hi = vals[0::2]
    lo = vals[1::2]
    hi_all_short = bool(hi) and all(pclass(v, t) == "S" for v in hi)
    lo_mixed = any(pclass(v, t) == "L" for v in lo) and any(pclass(v, t) == "S" for v in lo)
    shape = "ppm" if (hi_all_short and lo_mixed) else "pwm"

    # Phase: index parity that carries the pulses. 0 unless the capture opens
    # inside the inter-frame gap (gap, pulse, gap, ...).
    phase = 0
    if c[0] == "G" and n >= 4 and c[1] == "S" and c[2] == "G":
        phase = 1

    has_sync = False
    sync_hi = None
    sync_lo = None
    start = 0
    gidx = [i for i, k in enumerate(c) if k == "G"]
    if gidx:
        if phase == 1 and gidx[0] == 0:
            sync_hi, sync_lo, start = vals[1], vals[2], 3
            has_sync = True
        else:
            j = gidx[0]
            if (j % 2) != phase:          # sync ends with a long low
                sync_lo = vals[j]
                sync_hi = vals[j - 1] if j >= 1 else None
                start = j + 1
                has_sync = True
            else:                          # sync is a long high (leading-gap family)
                sync_hi = vals[j]
                sync_lo = vals[j + 1] if j + 1 < n else None
                start = j + 2
                has_sync = start <= n

    notes = []
    units = []
    reason = None
    capped = False
    if shape == "pwm":
        i = start if (start % 2 == phase) else start + 1
        while i + 1 < n:
            if len(units) >= MAX_UNITS:
                capped = True
                break
            ka, kb = c[i], c[i + 1]
            if ka == "G" or kb == "G":
                reason = "sync gap at index %d ends the frame" % i
                break
            if ka == "S" and kb == "L":
                units.append("0")
            elif ka == "L" and kb == "S":
                units.append("1")
            else:
                reason = ("interval pair at index %d (%s us high, %s us low) is neither "
                          "short-long nor long-short" % (i, num(vals[i]), num(vals[i + 1])))
                break
            i += 2
        if reason is None and not capped and i < n:
            notes.append("trailing interval at index %d (%s us) has no partner and was not "
                         "decoded" % (i, num(vals[i])))
    else:
        i = start if (start % 2 != phase) else start + 1
        while i < n:
            if len(units) >= MAX_UNITS:
                capped = True
                break
            k = c[i]
            if k == "G":
                reason = "sync gap at index %d ends the frame" % i
                break
            if k == "S":
                units.append("0")
            elif k == "L":
                units.append("1")
            else:
                reason = "gap at index %d (%s us) is neither short nor long" % (i, num(vals[i]))
                break
            i += 2

    bits = []
    if shape == "ppm":
        for p in range(0, len(units) - 1, 2):
            a, b = units[p], units[p + 1]
            if a == "0" and b == "1":
                bits.append("0")
            elif a == "1" and b == "0":
                bits.append("1")
            else:
                reason = ("gap pair %d/%d (%s then %s units) is not a valid Manchester pair"
                          % (p, p + 1, a, b))
                break
        if len(units) % 2:
            notes.append("odd gap count: the last gap (%s units) has no Manchester partner"
                         % units[-1])
    else:
        bits = units
    if capped:
        notes.append("frame truncated at %d symbols" % MAX_UNITS)

    if not bits:
        die("no bits decoded from %d intervals (shape %s, short %s us, long %s us)"
            % (n, shape, num(short_us), num(long_us)))

    sync_units = None
    if has_sync:
        long_side = [v for v in (sync_hi, sync_lo) if v is not None]
        if long_side:
            sync_units = max(long_side) / short_us

    fam = None
    for name, want_shape, r_lo, r_hi, s_lo, s_hi in FAMILIES:
        if shape != want_shape:
            continue
        if not (r_lo <= ratio <= r_hi):
            continue
        if sync_units is None or not (s_lo <= sync_units <= s_hi):
            continue
        fam = name
        break
    if fam is None:
        fam = "unknown-pwm" if shape == "pwm" else "unknown-ppm"

    print("PROTOCOL\t" + fam)
    print("SHAPE\t" + shape)
    print("SYNC_HIGH\t" + num(sync_hi))
    print("SYNC_LOW\t" + num(sync_lo))
    print("SHORT_US\t" + num(short_us))
    print("LONG_US\t" + num(long_us))
    print("SHORT_LONG_RATIO\t%.2f" % ratio)
    print("SYNC_UNITS\t" + ("%.1f" % sync_units if sync_units is not None else "-"))
    print("BITS\t%d" % len(bits))
    print("CODE_HEX\t" + bits_to_hex(bits))
    print("CODE_BIN\t" + "".join(bits))
    print("TRISTATE\t" + tristate(bits))

    if not has_sync:
        notes.append("no sync gap found: the train carries no preamble, so SYNC_HIGH and "
                     "SYNC_LOW are reported as - and the frame was read from the first interval")
    if reason:
        notes.append("frame ended after %d bits: %s" % (len(bits), reason))
    if fam in ("princeton-pt2262", "came-cardin-pwm") and len(bits) != 24:
        notes.append("%s reference frames carry 24 bits; this frame carries %d"
                     % (fam, len(bits)))
    if fam not in NAMED:
        cand = "; ".join("%s needs long/short %.2f-%.2f and %s"
                         % (nm, r_lo, r_hi, sync_phrase(s_lo, s_hi))
                         for nm, sh, r_lo, r_hi, s_lo, s_hi in FAMILIES
                         if sh == shape and not nm.startswith("ook-"))
        meas = ("measured long/short %.2f and sync %s"
                % (ratio, ("%.1f units" % sync_units) if sync_units is not None else "no sync"))
        if fam.startswith("unknown"):
            notes.append("no known protocol family matched: %s; %s. The bits above are a raw "
                         "reading and the protocol is reported as unknown rather than guessed"
                         % (meas, cand))
        else:
            notes.append("the frame decoded cleanly but no named family matched: %s; %s. It is "
                         "reported as a generic %s reading and is not attributed to a vendor"
                         % (meas, cand, shape.upper()))
    if fam == "princeton-pt2262":
        notes.append("PT2262 and compatible SC2262/HS2262: sync high of about 1 unit and sync "
                     "low of about 31 units, then 24 bits, 0 = 1 unit high + 3 units low and "
                     "1 = 3 units high + 1 unit low")
        notes.append("CODE_HEX is the raw 24-bit word with the first transmitted bit as the "
                     "most significant bit")
        notes.append("TRISTATE groups the 24 bits into 12 pairs and reads 00 as 0, 11 as 1 and "
                     "01 as floating (F); 10 pairs are shown as ? because a PT2262-style DIP "
                     "encoder does not produce them, and the pair order differs between "
                     "datasheet variants, so treat TRISTATE as an aid and CODE_HEX as the value")
    if fam == "came-cardin-pwm":
        notes.append("CAME/Cardin style leading-gap PWM: short about 730 us, long about 1400 us, "
                     "sync about 6150 us, 24 bits (rtl_433 cardin.c reference for the Cardin "
                     "S466-TX2); other members of this family use a different sync")
    if shape == "ppm":
        notes.append("constant-width pulses with two gap widths: the code sits in the gap "
                     "positions, so gaps are paired as short-long = 0 and long-short = 1")
    if fam == "nexa-like-ppm-manchester":
        notes.append("the measured widths match the rtl_433 Nexa reference (OOK PPM short "
                     "270 us, long 1300 us, sync 2650 us, 64 or 72 gap symbols that decode to "
                     "32 or 36 bits); rtl_433 inverts this stream for Nexa, so the vendor code "
                     "may be the bitwise inverse of CODE_HEX")
        inv = "".join("1" if b == "0" else "0" for b in bits)
        notes.append("inverted CODE_HEX (rtl_433 Nexa polarity) would be " + bits_to_hex(inv))
    for nt in notes:
        print("NOTE\t" + nt)
    return 0


sys.exit(main())
PYEOF
}

# ── pulse train encoding (offline) ───────────────────────────────────────
# Inverse of --decode-pulses for the 24-bit PWM families. The emitted train is
# re-decoded before the command reports success.
subghz_encode_pulses() {
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required for pulse encoding and is not on PATH\n' >&2
        return 1
    }
    local out code timings back rc
    out="$(python3 - "$@" <<'PYEOF'
import sys, math

PROFILES = {
    "princeton-pt2262": {
        "bits": 24,
        "unit": 350.0,
        "sync_high": 350.0,
        "sync_low": 10850.0,
        "long": 1050.0,
        "unit_override": True,
        "note": ("PT2262 layout: sync high of 1 unit and sync low of about 31 units, then 24 "
                 "bits, 0 = 1 unit high + 3 units low and 1 = 3 units high + 1 unit low; "
                 "SC2262 and HS2262 clones use the same word"),
    },
    "came-cardin-pwm": {
        "bits": 24,
        "unit": 730.0,
        "sync_high": 6150.0,
        "sync_low": 730.0,
        "long": 1400.0,
        "unit_override": False,
        "note": ("CAME/Cardin layout: 6150 us sync pulse, 730 us sync gap, then 24 PWM pairs "
                 "with 0 = 730 us high + 1400 us low and 1 = 1400 us high + 730 us low, from "
                 "the rtl_433 cardin.c reference for the Cardin S466-TX2; leading-gap members "
                 "of this family swap the role of pulse and gap, so check against a capture"),
    },
}

ALIASES = {
    "princeton": "princeton-pt2262",
    "pt2262": "princeton-pt2262",
    "pt2260": "princeton-pt2262",
    "pt2272": "princeton-pt2262",
    "sc2262": "princeton-pt2262",
    "hs2262": "princeton-pt2262",
    "ev1527": "came-cardin-pwm",
    "sc2260": "came-cardin-pwm",
    "came": "came-cardin-pwm",
    "cardin": "came-cardin-pwm",
    "came-cardin": "came-cardin-pwm",
    "came-12bit": "came-cardin-pwm",
}

NEXA_HINT = ("encoding for nexa is not implemented: the rtl_433 reference models Nexa as OOK "
             "PPM with ternary Manchester coding (short 270 us, long 1300 us, sync 2650 us, 64 "
             "or 72 gap symbols), not as a 24-bit PWM word. Use --decode-pulses on a captured "
             "train and see --info")


def die(msg, code=2):
    sys.stderr.write("ERROR\t" + msg + "\n")
    sys.exit(code)


def num(v):
    if abs(v - round(v)) < 0.05:
        return str(int(round(v)))
    return "%.1f" % v


def resolve(proto):
    p = proto.strip().lower()
    if p in PROFILES:
        return p
    if p == "nexa":
        die(NEXA_HINT, 3)
    if p in ALIASES:
        return ALIASES[p]
    die("unknown protocol %r for encoding; supported: princeton, pt2262, sc2262, hs2262, "
        "pt2260, came, cardin, ev1527, sc2260 (nexa is decode-only)" % proto, 2)


def parse_code(tok, nbits):
    s = tok.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.replace("_", "").replace(":", "").replace(" ", "")
    if not s:
        die("empty code: give a hexadecimal code", 2)
    bad = [ch for ch in s if ch not in "0123456789abcdef"]
    if bad:
        die("code is not hexadecimal: %r contains %r" % (tok, bad[0]), 2)
    if len(s) * 4 > nbits:
        die("code %s needs %d bits but this protocol carries %d" % (tok, len(s) * 4, nbits), 2)
    v = int(s, 16)
    return (format(v, "0%dx" % (nbits // 4)).upper(), format(v, "0%db" % nbits), len(s) * 4)


def main(argv):
    raw_only = False
    args = []
    for a in argv:
        if a == "--raw":
            raw_only = True
        else:
            args.append(a)
    if len(args) < 2:
        die("usage: --encode-pulses PROTOCOL CODE_HEX [UNIT_US] [--raw]", 2)
    key = resolve(args[0])
    prof = PROFILES[key]
    code_hex, bits, given_bits = parse_code(args[1], prof["bits"])

    unit = prof["unit"]
    longw = prof["long"]
    sync_high = prof["sync_high"]
    sync_low = prof["sync_low"]
    notes = [prof["note"]]
    if len(args) > 2:
        if not prof["unit_override"]:
            die("this protocol has fixed timings; a unit override is only supported for "
                "princeton", 2)
        try:
            unit = float(args[2])
        except ValueError:
            die("unit must be a number of microseconds, got %r" % args[2], 2)
        if not math.isfinite(unit) or unit <= 0:
            die("unit must be a positive number of microseconds", 2)
        longw = 3.0 * unit
        sync_high = unit
        sync_low = 31.0 * unit
        notes.append("unit overridden to %s us: long %s us, sync %s/%s us"
                     % (num(unit), num(longw), num(sync_high), num(sync_low)))
    if given_bits < prof["bits"]:
        notes.append("code was left-padded from %d to %d bits" % (given_bits, prof["bits"]))

    out = [sync_high, sync_low]
    for b in bits:
        if b == "0":
            out += [unit, longw]
        else:
            out += [longw, unit]

    timings = ",".join(num(v) for v in out)
    print("PROTOCOL\t" + key)
    print("CODE_HEX\t" + code_hex)
    print("BITS\t%d" % prof["bits"])
    print("UNIT_US\t" + num(unit))
    print("SHORT_US\t" + num(unit))
    print("LONG_US\t" + num(longw))
    print("SYNC_HIGH\t" + num(sync_high))
    print("SYNC_LOW\t" + num(sync_low))
    print("PULSES\t%d" % len(out))
    print("FRAME_US\t" + num(sum(out)))
    print("TIMINGS\t" + timings)
    for nt in notes:
        print("NOTE\t" + nt)
    if raw_only:
        print("RAW\t" + timings)
    return 0


sys.exit(main(sys.argv[1:]))
PYEOF
    )" || return $?

    # Never report success without checking: decode the train back.
    timings="$(printf '%s\n' "$out" | awk -F'\t' '$1=="TIMINGS" {print $2; exit}')"
    code="$(printf '%s\n' "$out" | awk -F'\t' '$1=="CODE_HEX" {print $2; exit}')"
    if [[ -z "$timings" || -z "$code" ]]; then
        printf 'ERROR\tencoder produced no timing list\n' >&2
        return 1
    fi
    back="$(subghz_decode_pulses "$timings" | awk -F'\t' '$1=="CODE_HEX" {print $2; exit}')"
    rc=$?
    if (( rc != 0 )) || [[ "$back" != "$code" ]]; then
        printf 'ERROR\tround-trip check failed: %s encoded to a train that decoded as %s\n' \
            "$code" "${back:--}" >&2
        return 1
    fi
    if printf '%s\n' "$out" | awk -F'\t' '$1=="RAW" {found=1} END{exit !found}'; then
        printf '%s\n' "$timings"
    else
        printf '%s\n' "$out"
        printf 'ROUNDTRIP\tOK\t%s\n' "$code"
    fi
    return 0
}

# ── sweep file analysis (offline) ────────────────────────────────────────
# Accepts the CSV written by rtl_power or hackrf_sweep:
#   date, time, hz_low, hz_high, hz_bin_width, samples, dB, dB, ...
subghz_parse_sweep() {
    local file="${1:-}" bands="${2:-}"
    if [[ -z "$file" ]]; then
        printf 'ERROR\tusage: --parse-sweep FILE.csv [BANDS_MHZ]\n' >&2
        return 2
    fi
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 is required for sweep analysis and is not on PATH\n' >&2
        return 1
    }
    python3 - "$file" "$bands" <<'PYEOF'
import sys, math


def die(msg, code=3):
    sys.stderr.write("ERROR\t" + msg + "\n")
    sys.exit(code)


def num(v):
    if abs(v - round(v)) < 0.05:
        return str(int(round(v)))
    return "%.1f" % v


def fnum(v):
    """Frequency label that keeps 433.92 readable instead of rounding to 433.9."""
    s = ("%.3f" % v).rstrip("0").rstrip(".")
    return s if s else "0"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else ""
    band_arg = sys.argv[2] if len(sys.argv) > 2 else ""
    bands = []
    for tok in band_arg.replace(",", " ").split():
        try:
            b = float(tok)
        except ValueError:
            die("bad band value: " + repr(tok), 2)
        if not math.isfinite(b) or b <= 0 or b > 100000:
            die("band out of range in MHz: " + repr(tok), 2)
        bands.append(b)
    if not bands:
        bands = [315.0, 433.92, 868.0, 915.0]
    try:
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        die("cannot read sweep file %s: %s" % (path, exc.strerror or str(exc)))

    samples = []
    rows = 0
    with fh:
        for line in fh:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 7:
                continue
            try:
                hz_low = float(parts[2])
                width = float(parts[4])
            except ValueError:
                continue
            if not math.isfinite(hz_low) or not math.isfinite(width) or width <= 0:
                continue
            dbs = []
            for p in parts[6:]:
                try:
                    dbs.append(float(p))
                except ValueError:
                    continue
            if not dbs:
                continue
            rows += 1
            for i, db in enumerate(dbs):
                samples.append((hz_low + (i + 0.5) * width, db))

    if not samples:
        die("no sweep samples parsed from %s: expected rtl_power or hackrf_sweep CSV rows laid "
            "out as date, time, hz_low, hz_high, hz_bin_width, samples, dB, dB, ..." % path)

    print("SOURCE\t" + path)
    print("ROWS\t%d" % rows)
    print("BINS\t%d" % len(samples))
    print("WINDOW_MHZ\t1.0")
    print("FREQ_MHZ\tPEAK_DB\tBINS")
    matched = 0
    for b in bands:
        lo = b * 1.0e6 - 0.5e6
        hi = b * 1.0e6 + 0.5e6
        sel = [db for c, db in samples if lo <= c <= hi]
        if sel:
            matched += 1
            print("%s\t%.1f\t%d" % (fnum(b), max(sel), len(sel)))
        else:
            print("MISSING\t%s\tno bins within 0.5 MHz in this file" % fnum(b))
    print("NOTE\tPEAK_DB is the strongest bin in a 1 MHz window and is the receiver dB "
          "reading, not calibrated dBm")
    if matched == 0:
        die("none of the requested bands has bins in %s; the file covers a different range"
            % path)
    print("OK\t%d of %d bands found in %s" % (matched, len(bands), path))
    return 0


sys.exit(main())
PYEOF
}

# ── live sweep (gated on an SDR) ─────────────────────────────────────────
subghz_live_refuse() {
    local rtlsdr hackrf
    rtlsdr="$(subghz_usb_rtlsdr)"
    hackrf="$(subghz_usb_hackrf)"
    printf 'ERROR\tno SDR available for a live sweep: RTL-SDR (USB %s) %s, HackRF (USB %s) %s\n' \
        "$SUBGHZ_RTL_USB" "$([[ "$rtlsdr" == 1 ]] && echo present || echo absent)" \
        "$SUBGHZ_HACKRF_USB" "$([[ "$hackrf" == 1 ]] && echo present || echo absent)" >&2
    local t
    for t in rtl_power hackrf_sweep rtl_fm rtl_test hackrf_info; do
        subghz_have "$t" || printf 'MISSING\t%s\tnot on PATH\n' "$t" >&2
    done
    if ! subghz_have lsusb; then
        printf 'MISSING\tlsusb\tcannot enumerate USB devices, so SDR presence cannot be confirmed\n' >&2
    fi
    if [[ "$rtlsdr" == 1 ]] && ! subghz_have rtl_power; then
        printf 'MISSING\trtl_power\tRTL-SDR is attached but rtl_power (rtl-sdr package) is not installed\n' >&2
    fi
    if [[ "$hackrf" == 1 ]] && ! subghz_have hackrf_sweep; then
        printf 'MISSING\thackrf_sweep\tHackRF is attached but hackrf_sweep (hackrf package) is not installed\n' >&2
    fi
    printf 'NOTE\tlive capture needs an SDR; decoding, encoding and sweep-file analysis work offline (--decode-pulses, --encode-pulses, --parse-sweep)\n' >&2
    return 3
}

subghz_rssi_scan() {
    local dur=3 gain=40 bands="" backend csv part lo hi deadline rc=0
    while (($#)); do
        case "$1" in
            --duration) dur="${2:-}"; shift 2 ;;
            --gain)     gain="${2:-}"; shift 2 ;;
            -h|--help)
                cat >&2 <<EOF
Usage: $0 --rssi-scan [--duration SEC] [--gain DB] [FREQ_MHZ ...]
Needs an SDR: RTL-SDR plus rtl_power, or HackRF plus hackrf_sweep.
EOF
                return 0 ;;
            -*) printf 'ERROR\tunknown option for --rssi-scan: %s\n' "$1" >&2; return 2 ;;
            *)  bands="$bands ${1//,/ }"; shift ;;
        esac
    done
    if ! awk -v d="$dur" 'BEGIN{exit !(d > 0 && d <= 120)}'; then
        printf 'ERROR\t--duration must be a number of seconds between 0 and 120, got %s\n' \
            "$dur" >&2
        return 2
    fi
    if ! awk -v g="$gain" 'BEGIN{exit !(g >= 0 && g <= 60)}'; then
        printf 'ERROR\t--gain must be a number between 0 and 60 dB, got %s\n' "$gain" >&2
        return 2
    fi
    [[ -n "$bands" ]] || bands=" 315 433.92 868 915"

    backend="$(subghz_sdr_backend)"
    if [[ "$backend" == none ]]; then
        subghz_live_refuse
        return 3
    fi
    if [[ "$backend" == rtl_fm ]]; then
        printf 'ERROR\tan SDR is attached and rtl_fm is installed, but a sweep needs rtl_power (rtl-sdr package) or hackrf_sweep (hackrf package); install one of those\n' >&2
        return 3
    fi

    mkdir -p "$MOD_TMP" "$MOD_LOGS" 2>/dev/null
    csv="$MOD_TMP/rssi_scan.csv"
    : > "$csv" || {
        printf 'ERROR\tcannot write %s\n' "$csv" >&2
        return 1
    }
    deadline="$(awk -v d="$dur" 'BEGIN{printf "%d", d + 15}')"
    local -a pre=()
    subghz_have timeout && pre=(timeout "$deadline")

    local b
    for b in $bands; do
        awk -v f="$b" 'BEGIN{exit !(f > 0 && f < 6000)}' || {
            printf 'ERROR\tbad frequency for --rssi-scan: %s\n' "$b" >&2
            return 2
        }
        lo="$(awk -v f="$b" 'BEGIN{printf "%.3f", f - 0.5}')"
        hi="$(awk -v f="$b" 'BEGIN{printf "%.3f", f + 0.5}')"
        part="$MOD_TMP/sweep_${b}.csv"
        : > "$part"
        if [[ "$backend" == rtl_power ]]; then
            "${pre[@]}" rtl_power -f "${lo}M:${hi}M:200k" -g "$gain" -i 1 -e "$dur" \
                "$part" >>"$csv" 2>>"$MOD_LOGS/rssi_scan.err" || rc=$?
        else
            "${pre[@]}" hackrf_sweep -f "${lo}:${hi}" -w 200000 -N 1 -g "$gain" \
                >"$part" 2>>"$MOD_LOGS/rssi_scan.err" || rc=$?
        fi
        if (( rc != 0 )); then
            printf 'ERROR\t%s failed for %s MHz with exit %d; see %s\n' \
                "$backend" "$b" "$rc" "$MOD_LOGS/rssi_scan.err" >&2
            return 1
        fi
        cat "$part" >>"$csv" 2>/dev/null
    done

    if [[ ! -s "$csv" ]]; then
        printf 'ERROR\t%s produced no samples: the SDR may be busy, unreadable (udev or permissions), or out of range\n' \
            "$backend" >&2
        return 1
    fi
    printf 'BACKEND\t%s\n' "$backend"
    subghz_parse_sweep "$csv" "$bands"
}

# ── synthetic trains for the self test ───────────────────────────────────
# Independent of the encoder, so an encoder bug cannot make the test pass.
subghz_synth_train() {  # PROFILE CODE [JITTER_PCT] [SYNC_UNITS]
    python3 - "$@" <<'PYEOF'
import random, sys

prof = (sys.argv[1] if len(sys.argv) > 1 else "princeton").lower()
code = sys.argv[2] if len(sys.argv) > 2 else "A1B2C3"
jit = float(sys.argv[3]) / 100.0 if len(sys.argv) > 3 and sys.argv[3] else 0.0
sync_units = float(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None

if prof == "came":
    unit, longw, sh, sl, nbits = 730.0, 1400.0, 6150.0, 730.0, 24
elif prof == "nexa":
    unit, longw, sh, sl, nbits = 270.0, 1300.0, 270.0, 2650.0, len(code) * 4
else:
    unit, longw, sh, sl, nbits = 350.0, 1050.0, 350.0, 10850.0, 24
if sync_units is not None:
    sl = sync_units * unit

bits = bin(int(code, 16))[2:].zfill(nbits)
random.seed(20240517)
if prof == "nexa":
    out = [unit, sl]
    for b in bits:
        for g in ([unit, longw] if b == "0" else [longw, unit]):
            out += [unit, g]
else:
    out = [sh, sl]
    for b in bits:
        out += [unit, longw] if b == "0" else [longw, unit]
if jit:
    out = [v * (1.0 + random.uniform(-jit, jit)) for v in out]
print(",".join(str(int(round(v))) for v in out))
PYEOF
}

subghz_field() {  # KEY  (TSV on stdin)
    awk -F'\t' -v k="$1" '$1 == k {print $2; exit}'
}

subghz_has_pair() {  # KEY VALUE  (TSV on stdin)
    awk -F'\t' -v k="$1" -v v="$2" '$1 == k && $2 == v {found = 1} END {exit !found}'
}

subghz_has_note() {  # SUBSTRING  (TSV on stdin)
    awk -F'\t' -v s="$1" '$1 == "NOTE" && index($0, s) {found = 1} END {exit !found}'
}

# ── self test ────────────────────────────────────────────────────────────
subghz_selftest() {
    local bad=0 out rc train back code

    if subghz_have python3; then
        printf 'python3-present\tPASS\n'
    else
        printf 'python3-present\tFAIL python3 is not on PATH, nothing else can run\n'
        printf 'RESULT\tFAIL(1)\n'
        return 1
    fi

    # 1. Decode a train built independently of the encoder.
    train="$(subghz_synth_train princeton A1B2C3)"
    out="$(subghz_decode_pulses "$train")"
    if (( $? == 0 )) && printf '%s\n' "$out" | subghz_has_pair PROTOCOL princeton-pt2262 \
       && printf '%s\n' "$out" | subghz_has_pair CODE_HEX A1B2C3 \
       && printf '%s\n' "$out" | subghz_has_pair BITS 24; then
        printf 'princeton-synthetic-decode\tPASS\n'
    else
        printf 'princeton-synthetic-decode\tFAIL got %s\n' \
            "$(printf '%s\n' "$out" | subghz_field CODE_HEX)"
        bad=$((bad + 1))
    fi

    # 2. Tri-state and hex width for a 24-bit word.
    local tri
    tri="$(printf '%s\n' "$out" | subghz_field TRISTATE)"
    if [[ ${#tri} -eq 12 ]]; then
        printf 'tristate-24bit\tPASS\n'
    else
        printf 'tristate-24bit\tFAIL length %d, expected 12\n' "${#tri}"
        bad=$((bad + 1))
    fi

    # 3. Encode then decode must reproduce the code.
    code="A1B2C3"
    out="$(subghz_encode_pulses princeton "$code")"
    if (( $? != 0 )); then
        printf 'princeton-roundtrip\tFAIL encoder failed\n'
        bad=$((bad + 1))
    else
        train="$(printf '%s\n' "$out" | subghz_field TIMINGS)"
        back="$(subghz_decode_pulses "$train" | subghz_field CODE_HEX)"
        if [[ "$back" == "$code" ]]; then
            printf 'princeton-roundtrip\tPASS\n'
        else
            printf 'princeton-roundtrip\tFAIL %s came back as %s\n' "$code" "${back:--}"
            bad=$((bad + 1))
        fi
    fi

    # 4. A jittered train still decodes (tolerance, not exact equality).
    train="$(subghz_synth_train princeton 0F1E2D 8)"
    out="$(subghz_decode_pulses "$train")"
    if printf '%s\n' "$out" | subghz_has_pair CODE_HEX 0F1E2D; then
        printf 'princeton-jitter-8pct\tPASS\n'
    else
        printf 'princeton-jitter-8pct\tFAIL got %s\n' \
            "$(printf '%s\n' "$out" | subghz_field CODE_HEX)"
        bad=$((bad + 1))
    fi

    # 5. CAME/Cardin profile round trip.
    code="123456"
    out="$(subghz_encode_pulses came "$code")"
    if (( $? != 0 )); then
        printf 'came-roundtrip\tFAIL encoder failed\n'
        bad=$((bad + 1))
    else
        train="$(printf '%s\n' "$out" | subghz_field TIMINGS)"
        out="$(subghz_decode_pulses "$train")"
        if printf '%s\n' "$out" | subghz_has_pair CODE_HEX "$code" \
           && printf '%s\n' "$out" | subghz_has_pair PROTOCOL came-cardin-pwm; then
            printf 'came-roundtrip\tPASS\n'
        else
            printf 'came-roundtrip\tFAIL got %s %s\n' \
                "$(printf '%s\n' "$out" | subghz_field PROTOCOL)" \
                "$(printf '%s\n' "$out" | subghz_field CODE_HEX)"
            bad=$((bad + 1))
        fi
    fi

    # 6. Nexa shaped PPM train decodes to the same 32-bit word.
    train="$(subghz_synth_train nexa DEADBEEF)"
    out="$(subghz_decode_pulses "$train")"
    if printf '%s\n' "$out" | subghz_has_pair PROTOCOL nexa-like-ppm-manchester \
       && printf '%s\n' "$out" | subghz_has_pair CODE_HEX DEADBEEF; then
        printf 'nexa-ppm-decode\tPASS\n'
    else
        printf 'nexa-ppm-decode\tFAIL got %s %s\n' \
            "$(printf '%s\n' "$out" | subghz_field PROTOCOL)" \
            "$(printf '%s\n' "$out" | subghz_field CODE_HEX)"
        bad=$((bad + 1))
    fi

    # 7. Unmatched timings are named as unmatched, never guessed.
    train="$(subghz_synth_train princeton ABCDEF 0 12)"
    out="$(subghz_decode_pulses "$train")"
    if printf '%s\n' "$out" | subghz_has_pair PROTOCOL ook-pwm-generic \
       && printf '%s\n' "$out" | subghz_has_note 'no named family matched'; then
        printf 'unmatched-not-guessed\tPASS\n'
    else
        printf 'unmatched-not-guessed\tFAIL got %s\n' \
            "$(printf '%s\n' "$out" | subghz_field PROTOCOL)"
        bad=$((bad + 1))
    fi

    # 8. Garbage input is refused, with nothing on stdout.
    out="$(subghz_decode_pulses 'not,a,train' 2>/dev/null)"; rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'garbage-rejected\tPASS\n'
    else
        printf 'garbage-rejected\tFAIL exit %d, stdout %d bytes\n' "$rc" "${#out}"
        bad=$((bad + 1))
    fi

    # 9. An empty timing list is refused.
    out="$(subghz_decode_pulses '' 2>/dev/null)"; rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'empty-rejected\tPASS\n'
    else
        printf 'empty-rejected\tFAIL exit %d\n' "$rc"
        bad=$((bad + 1))
    fi

    # 10. One single pulse width cannot be split into short and long.
    out="$(subghz_decode_pulses '350,350,350,350,350' 2>/dev/null)"; rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'uniform-rejected\tPASS\n'
    else
        printf 'uniform-rejected\tFAIL exit %d\n' "$rc"
        bad=$((bad + 1))
    fi

    # 11. A non hexadecimal code is refused.
    out="$(subghz_encode_pulses princeton ZZZZ 2>/dev/null)"; rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'bad-code-rejected\tPASS\n'
    else
        printf 'bad-code-rejected\tFAIL exit %d\n' "$rc"
        bad=$((bad + 1))
    fi

    # 12. Nexa encoding is advertised as unavailable rather than faked.
    out="$(subghz_encode_pulses nexa DEADBEEF 2>/dev/null)"; rc=$?
    if (( rc != 0 )) && [[ -z "$out" ]]; then
        printf 'nexa-encode-refused\tPASS\n'
    else
        printf 'nexa-encode-refused\tFAIL exit %d\n' "$rc"
        bad=$((bad + 1))
    fi

    # 13. Sweep file parsing, exercised offline on a synthetic rtl_power dump.
    local csv="$MOD_TMP/selftest_sweep.csv"
    {
        printf '2024-01-01, 00:00:00, 314420000, 315420000, 100000.00, 20, -99.0, -98.0, -50.0, -97.0, -96.0, -95.0, -94.0, -93.0\n'
        printf '2024-01-01, 00:00:01, 433420000, 434420000, 100000.00, 20, -95.0, -92.0, -88.0, -80.0, -35.0, -70.0, -91.0, -93.0\n'
    } > "$csv"
    out="$(subghz_parse_sweep "$csv" '315,433.92')"
    if (( $? == 0 )) \
       && printf '%s\n' "$out" | awk -F'\t' '$1 == "315" && $2 == "-50.0" {f = 1} END {exit !f}' \
       && printf '%s\n' "$out" | awk -F'\t' '$1 == "433.92" && $2 == "-35.0" {f = 1} END {exit !f}'; then
        printf 'sweep-file-parse\tPASS\n'
    else
        printf 'sweep-file-parse\tFAIL\n'
        bad=$((bad + 1))
    fi
    rm -f "$csv"

    # 14. The live sweep refuses without hardware, naming what is missing.
    if [[ "$(subghz_sdr_backend)" == none ]]; then
        local errf="$MOD_TMP/selftest_gate.err"
        subghz_rssi_scan >/dev/null 2>"$errf"
        rc=$?
        if (( rc != 0 )) && grep -q 'no SDR available' "$errf" && grep -q 'MISSING' "$errf"; then
            printf 'rssi-scan-gated\tPASS\n'
        else
            printf 'rssi-scan-gated\tFAIL exit %d\n' "$rc"
            bad=$((bad + 1))
        fi
        rm -f "$errf"
    else
        printf 'rssi-scan-gated\tPASS (not applicable: an SDR is attached)\n'
    fi

    if (( bad > 0 )); then
        printf 'ERROR\t%d self test check(s) failed\n' "$bad" >&2
    fi
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── info ─────────────────────────────────────────────────────────────────
subghz_info() {
    cat <<'EOF'
Sub-GHz RF (315 / 433.92 / 868 / 915 MHz) OOK/ASK pulse work.

Offline commands, no radio needed
  --decode-pulses TIMINGS   decode a train given as alternating high/low
                            intervals in microseconds, starting with a high.
                            "-" reads the list from stdin (piped input only).
  --encode-pulses PROTOCOL CODE_HEX [UNIT_US] [--raw]
                            build a timing list for a 24-bit PWM code
  --parse-sweep FILE.csv [BANDS_MHZ]
                            analyse an rtl_power or hackrf_sweep CSV capture
  --bands-tsv               band reference table
  --status-tsv              capability report
  --selftest                offline checks of decoder, encoder and parser

Protocols the decoder recognises
  princeton-pt2262  PT2262 and the SC2262/HS2262 clones. One sync (about 1 unit
                    high, 31 units low, so about 10850 us with 350 us units),
                    then 24 bits. A bit is 1 unit high + 3 units low for 0 and
                    3 units high + 1 unit low for 1. The 24 bits group into 12
                    tri-state pairs: 00 = 0, 11 = 1, 01 = floating, 10 is not
                    produced by a DIP encoder. CODE_HEX is the primary value,
                    TRISTATE is an interpretation aid.
  came-cardin-pwm   CAME/Cardin leading-gap PWM: 730 us and 1400 us pulse
                    widths with a 6150 us sync, 24 bits (rtl_433 cardin.c
                    reference for the Cardin S466-TX2).
  nexa-like-ppm-manchester
                    Nexa is OOK PPM rather than PWM: 270 us pulses with 270 us
                    and 1300 us gaps and a 2650 us sync, and the gap stream is
                    ternary Manchester coded into 32 or 36 bits (rtl_433
                    nexa.c). This module decodes that family; it deliberately
                    does not encode it, because the rtl_433 reference is a
                    subset of a family whose bit polarity varies by device.
  anything else     the frame is still reported as raw bits, with PROTOCOL
                    ook-pwm-generic, ook-ppm-manchester or unknown-pwm plus a
                    NOTE stating that no named family matched. Nothing is
                    guessed silently.

Hardware gating
  Only --rssi-scan touches a radio. It needs an SDR (RTL-SDR USB 0bda:2838 or
  HackRF USB 1d50:6089) together with rtl_power or hackrf_sweep. Without them
  it prints an ERROR naming each missing piece and exits non-zero. Decoding,
  encoding and sweep file analysis never need hardware and never gate.

  This build was validated on a machine with no SDR: the gated path refuses as
  described, and the parsing path is covered by --selftest. The rtl_power and
  hackrf_sweep command lines themselves have not been exercised against a
  physical device.

Legal note: these bands are regulated. Reception is passive, but replaying a
captured code is a transmission, and in most countries that needs a licence and
the permission of the equipment owner.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
subghz_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)    subghz_status_tsv ;;
        --bands-tsv)     subghz_bands_tsv ;;
        --decode-pulses) subghz_decode_pulses "$@" ;;
        --encode-pulses) subghz_encode_pulses "$@" ;;
        --parse-sweep)   subghz_parse_sweep "$@" ;;
        --rssi-scan)     subghz_rssi_scan "$@" ;;
        --selftest)      subghz_selftest ;;
        --info)          subghz_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv                     capability report (python3, SDR, gating)
  --bands-tsv                      sub-GHz band reference table
  --decode-pulses TIMINGS          decode an OOK pulse train (microseconds, or - for stdin)
  --encode-pulses PROTOCOL CODE_HEX [UNIT_US] [--raw]
                                   build a timing list for a 24-bit code
  --parse-sweep FILE.csv [BANDS]   analyse an rtl_power or hackrf_sweep capture
  --rssi-scan [--duration S] [--gain DB] [FREQ ...]
                                   live SDR sweep (needs an SDR, refuses without one)
  --selftest                       offline self test
  --info                           protocol and gating notes
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    subghz_cli_main "$@"
fi

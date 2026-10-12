#!/usr/bin/env bash
# 43_nfc_rfid — NFC / RFID
# NDEF message codec and MIFARE tag structure analysis.
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

MOD_TMP="$TMP_DIR/nfc_rfid"
MOD_LOOT="$LOOT_DIR/nfc_rfid"
MOD_LOGS="$LOG_DIR/nfc_rfid"
MOD_CAPS="$CAPTURES_DIR/nfc_rfid"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────
# The data layer (NDEF codec, tag identification, MIFARE layout) is pure
# computation and always available. Only --read-tag touches hardware.

nfc_have() { command -v "$1" >/dev/null 2>&1; }

nfc_require_python() {
    nfc_have python3 && return 0
    printf 'ERROR\tpython3 is required for the NDEF codec but was not found in PATH\n' >&2
    printf 'MISSING\tpython3 (install: apt install python3)\n' >&2
    return 1
}

# Sets NFC_LSUSB, NFC_TOOL_NFCLIST, NFC_TOOL_MFOC, NFC_TOOL_PCSC,
# NFC_USB_ACR122, NFC_USB_PN532, NFC_USB_PROX and NFC_READER. Prints nothing.
nfc_probe_reader() {
    NFC_TOOL_NFCLIST=0; NFC_TOOL_MFOC=0; NFC_TOOL_PCSC=0
    nfc_have nfc-list  && NFC_TOOL_NFCLIST=1
    nfc_have mfoc      && NFC_TOOL_MFOC=1
    nfc_have pcsc_scan && NFC_TOOL_PCSC=1

    NFC_LSUSB=0; NFC_USB_ACR122=0; NFC_USB_PN532=0; NFC_USB_PROX=0
    if nfc_have lsusb; then
        NFC_LSUSB=1
        local ids
        ids="$(lsusb 2>/dev/null)"
        grep -qi '072f:2200' <<<"$ids" && NFC_USB_ACR122=1
        grep -qi '04cc:2533' <<<"$ids" && NFC_USB_PN532=1
        grep -qi '0483:5740' <<<"$ids" && NFC_USB_PROX=1
    fi

    # A reader can also be reached through pcscd without showing up in a
    # plain lsusb dump, so an installed reader tool counts as a possibility.
    NFC_READER=0
    if (( NFC_TOOL_NFCLIST || NFC_TOOL_MFOC || NFC_TOOL_PCSC \
          || NFC_USB_ACR122 || NFC_USB_PN532 || NFC_USB_PROX )); then
        NFC_READER=1
    fi
    return 0
}

# ── NDEF codec (python3) ─────────────────────────────────────────────────

nfc_py() {
    python3 - "$@" <<'PYEOF'
import re
import sys

# NFC Forum URI record identifier codes (URI RTD, table 3).
URI_PREFIXES = [
    "", "http://www.", "https://www.", "http://", "https://", "tel:",
    "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://",
    "sftp://", "smb://", "nfs://", "ftp://", "dav://", "news:",
    "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:", "sips:",
    "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://",
    "irdaobex://", "file://", "urn:epc:id:", "urn:epc:tag:",
    "urn:epc:pat:", "urn:epc:raw:", "urn:epc:", "urn:nfc:",
]

TNF_NAMES = [
    "Empty", "Well Known", "MIME", "Absolute URI",
    "External", "Unknown", "Unchanged", "Reserved",
]

WK_NAMES = {
    "T": "Text", "U": "URI", "Sp": "Smart Poster", "Si": "Size",
    "Ac": "Action", "Bt": "Bluetooth Carrier Configuration",
    "Wi": "Wi-Fi Carrier Configuration", "Hs": "Handover Select",
    "Hr": "Handover Request", "Sig": "Signature",
}

# Nested NDEF messages carried inside these well known types.
NESTED_WK = {"Sp", "Hs", "Hr"}

ACTION_NAMES = {0: "do the action", 1: "save for later",
                2: "open for editing", 3: "unknown / reserved"}

# ATQA + SAK reference table. ATQA is the 16-bit value as printed by
# nfc-list (two bytes in transmission order, big-endian here). None means
# "any ATQA" and is used for the SAK-only fallback rule.
TAG_TABLE = [
    (0x0004, 0x08, "MIFARE Classic 1K",
     "1 KB, 16 sectors x 4 blocks, Crypto1, default keys FFFFFFFFFFFF"),
    (0x0002, 0x18, "MIFARE Classic 4K",
     "4 KB, 40 sectors (32 x 4 blocks + 8 x 16 blocks), Crypto1"),
    (0x0004, 0x09, "MIFARE Classic Mini",
     "0.3 KB, 5 sectors x 4 blocks, Crypto1"),
    (0x0044, 0x00, "MIFARE Ultralight",
     "64 B, 16 pages, 4-byte UID, no Crypto1, pages 3 and 4 are OTP"),
    (0x0044, 0x00, "NTAG203/213",
     "NTAG203 168 B / NTAG213 144 B, 7-byte UID; ATQA+SAK are identical to Ultralight, the UID length tells them apart"),
    (0x0344, 0x20, "MIFARE DESFire",
     "ISO 14443-4 (ISO-DEP), AES/3DES/DES, SAK bit 6 marks ISO 14443-4 support"),
    (0x0004, 0x20, "ISO 14443-4 / EMV",
     "EMV payment cards and other ISO-DEP tags; ATQA varies, SAK 0x20 means ISO 14443-4"),
    (None,   0x20, "ISO 14443-4 (ISO-DEP)",
     "fallback rule: SAK bit 6 (0x20) is set, so the tag speaks ISO 14443-4; this ATQA is not in the table"),
]

HEX_DIGITS = "0123456789abcdefABCDEF"


class NdefError(Exception):
    pass


def die(msg, code=1):
    sys.stderr.write("ERROR\t%s\n" % msg)
    sys.exit(code)


def hexlify(data):
    return data.hex().upper()


def hexspace(data):
    return " ".join("%02X" % b for b in data)


def tsv(value):
    # Keep one record per line: control characters would break the format.
    return value.replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r")


def disp_bytes(data):
    if not data:
        return "-"
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return hexspace(data)
    if all(0x20 <= ord(c) < 0x7F for c in text):
        return text
    return hexspace(data)


def hexcap(data, limit=128):
    if len(data) <= limit:
        return hexlify(data)
    return hexlify(data[:limit])


def parse_hex(text):
    raw = text.strip()
    if raw[:2].lower() == "0x":
        raw = raw[2:]
    for sep in (" ", ":", "-", "\n", "\t", "_"):
        raw = raw.replace(sep, "")
    if raw == "":
        raise NdefError("empty hex input: an NDEF message needs at least one record (a 1-byte header)")
    bad = sorted(set(c for c in raw if c not in HEX_DIGITS))
    if bad:
        raise NdefError("invalid hex input: unexpected character(s) %s" % " ".join(repr(c) for c in bad))
    if len(raw) % 2:
        raise NdefError("invalid hex input: %d hex digit(s) is an odd count, each byte needs two digits" % len(raw))
    return bytes.fromhex(raw)


# ── decode ───────────────────────────────────────────────────────────────

def decode_message(data, strict=True):
    """Parse a complete NDEF message. Returns a list of record dicts.

    Raises NdefError on anything malformed: truncation, a reserved TNF, a
    chunk that never terminates, an out of range URI identifier code. With
    strict=False the structural checks (MB on the first record, ME on the
    last, zero lengths on an Empty record) become warnings instead.
    """
    def malformed(msg):
        if strict:
            raise NdefError(msg)
        sys.stderr.write("WARN\t%s\n" % msg)

    total = len(data)
    if total == 0:
        raise NdefError("empty NDEF message: 0 bytes, at least one record header is required")

    recs = []
    pending = None
    i = 0
    while i < total:
        start = i
        hdr = data[i]; i += 1
        mb = (hdr >> 7) & 1
        me = (hdr >> 6) & 1
        cf = (hdr >> 5) & 1
        sr = (hdr >> 4) & 1
        il = (hdr >> 3) & 1
        tnf = hdr & 0x07

        if i >= total:
            raise NdefError("truncated record at offset %d: header byte 0x%02X is not followed by TYPE_LENGTH" % (start, hdr))
        tlen = data[i]; i += 1

        if sr:
            if i >= total:
                raise NdefError("truncated record at offset %d: SR is set but the 1-byte PAYLOAD_LENGTH is missing" % start)
            plen = data[i]; i += 1
        else:
            if i + 4 > total:
                raise NdefError("truncated record at offset %d: SR is clear so a 4-byte PAYLOAD_LENGTH is required, only %d byte(s) available" % (start, total - i))
            plen = int.from_bytes(data[i:i + 4], "big"); i += 4

        idlen = 0
        if il:
            if i >= total:
                raise NdefError("truncated record at offset %d: IL is set but ID_LENGTH is missing" % start)
            idlen = data[i]; i += 1

        if i + tlen > total:
            raise NdefError("truncated record at offset %d: TYPE_LENGTH=%d but only %d byte(s) remain" % (start, tlen, total - i))
        rtype = data[i:i + tlen]; i += tlen

        if i + idlen > total:
            raise NdefError("truncated record at offset %d: ID_LENGTH=%d but only %d byte(s) remain" % (start, idlen, total - i))
        rid = data[i:i + idlen]; i += idlen

        if i + plen > total:
            raise NdefError("truncated record at offset %d: PAYLOAD_LENGTH=%d (0x%X) but only %d payload byte(s) remain" % (start, plen, plen, total - i))
        payload = data[i:i + plen]; i += plen

        if tnf == 0x07:
            raise NdefError("record at offset %d declares TNF=0x07 (Reserved), which is not a valid record type" % start)

        if pending is not None:
            if tnf != 0x06:
                raise NdefError("record at offset %d: a chunked record is still open but this record has TNF=0x%02X instead of 0x06 (Unchanged)" % (start, tnf))
            if tlen != 0:
                raise NdefError("record at offset %d: continuation chunk repeats TYPE_LENGTH=%d, the TYPE must appear only in the first chunk" % (start, tlen))
            pending["payload"] += payload
            pending["me"] = me
            if cf:
                continue
            recs.append(finalize(pending, len(recs) + 1, malformed))
            pending = None
            continue

        if tnf == 0x06:
            raise NdefError("record at offset %d has TNF=0x06 (Unchanged) but no chunked record is open" % start)

        if cf and not sr:
            raise NdefError("record at offset %d sets CF with SR clear: chunked records must use the short-record layout" % start)

        if cf:
            pending = {"mb": mb, "me": me, "tnf": tnf, "type": rtype, "id": rid,
                       "payload": payload, "chunked": True, "offset": start}
            continue

        rec = {"mb": mb, "me": me, "tnf": tnf, "type": rtype, "id": rid,
               "payload": payload, "chunked": False, "offset": start}
        recs.append(finalize(rec, len(recs) + 1, malformed))

    if pending is not None:
        raise NdefError("the message ends while a chunked record is still open (CF set on the last chunk)")

    if not recs:
        raise NdefError("no NDEF records were decoded")

    for idx, rec in enumerate(recs):
        if idx == 0 and not rec["mb"]:
            malformed("record 1 does not set MB (message begin); a valid NDEF message starts with MB=1")
        if idx > 0 and rec["mb"]:
            malformed("record %d sets MB but is not the first record" % (idx + 1))
        if idx == len(recs) - 1 and not rec["me"]:
            malformed("the last record does not set ME (message end); the message looks truncated")
        if idx < len(recs) - 1 and rec["me"]:
            malformed("record %d sets ME but %d more record(s) follow" % (idx + 1, len(recs) - idx - 1))

    return recs


def finalize(rec, index, malformed):
    rec["index"] = index
    rec["tnf_name"] = TNF_NAMES[rec["tnf"]]
    rec["type_disp"] = disp_bytes(rec["type"])
    rec["details"] = decode_details(rec, malformed)
    return rec


def decode_details(rec, malformed):
    tnf = rec["tnf"]
    rtype = rec["type"]
    payload = rec["payload"]
    details = []

    if tnf == 0x00:
        if rec["type"] or rec["payload"]:
            malformed("record %d has TNF=0x00 (Empty) but carries a type or a payload; an Empty record must have TYPE_LENGTH=0 and PAYLOAD_LENGTH=0" % rec["index"])
        details.append(("STATUS", "empty record"))
        return details

    if tnf == 0x01:
        if not rtype:
            malformed("record %d has TNF=0x01 (Well Known) with TYPE_LENGTH=0" % rec["index"])
            details.append(("STATUS", "well known record without a type"))
            return details
        name = rtype.decode("ascii", "replace")
        if name in WK_NAMES:
            details.append(("WELL_KNOWN_TYPE", tsv(WK_NAMES[name])))
        return decode_well_known(name, rtype, payload, details, malformed)

    if tnf == 0x02:
        if not rtype:
            malformed("record %d has TNF=0x02 (MIME) with TYPE_LENGTH=0" % rec["index"])
        mime = rtype.decode("ascii", "replace")
        details.append(("MIME", tsv(mime)))
        if mime.lower().startswith("text/"):
            charset = "UTF-8"
            match = re.search(r"charset=([A-Za-z0-9_.:-]+)", mime, re.IGNORECASE)
            if match:
                charset = match.group(1)
            try:
                text = payload.decode(charset, "replace")
            except LookupError:
                text = payload.decode("utf-8", "replace")
                details.append(("NOTE", "unknown charset %s, decoded as UTF-8" % tsv(charset)))
            details.append(("TEXT", tsv(text)))
            details.append(("ENCODING", tsv(charset)))
        else:
            details.append(("PAYLOAD_HEX", hexcap(payload)))
            if len(payload) > 128:
                details.append(("PAYLOAD_HEX_TRUNCATED", "1"))
        return details

    if tnf == 0x03:
        details.append(("URI", tsv(payload.decode("utf-8", "replace"))))
        details.append(("URI_FORM", "absolute URI in the payload, no identifier code"))
        return details

    if tnf == 0x04:
        details.append(("EXTERNAL_TYPE", tsv(rtype.decode("utf-8", "replace"))))
        return decode_opaque(payload, details)

    if tnf == 0x05:
        details.append(("NOTE", "unknown TNF: the type is opaque, only the payload is shown"))
        return decode_opaque(payload, details)

    details.append(("STATUS", "unhandled TNF %d" % tnf))
    return decode_opaque(payload, details)


def decode_opaque(payload, details):
    if payload:
        details.append(("PAYLOAD_HEX", hexcap(payload)))
        if len(payload) > 128:
            details.append(("PAYLOAD_HEX_TRUNCATED", "1"))
        text = payload.decode("utf-8", "replace")
        if all((0x20 <= ord(c) < 0x7F) or c in "\t" for c in text) and text:
            details.append(("TEXT", tsv(text)))
    return details


def decode_well_known(name, rtype, payload, details, malformed):
    if name == "T":
        if not payload:
            raise NdefError("Text record (type T) has an empty payload: the 1-byte status field is missing")
        status = payload[0]
        utf16 = (status & 0x80) == 0
        lang_len = status & 0x3F
        if len(payload) < 1 + lang_len:
            raise NdefError("Text record declares a %d-byte language code but only %d byte(s) follow the status byte" % (lang_len, len(payload) - 1))
        lang = payload[1:1 + lang_len].decode("ascii", "replace")
        body = payload[1 + lang_len:]
        if utf16:
            if len(body) % 2:
                raise NdefError("Text record is UTF-16 but its text part has an odd byte count (%d)" % len(body))
            if body[:2] == b"\xfe\xff":
                text = body[2:].decode("utf-16-be", "replace"); enc = "UTF-16BE"
            elif body[:2] == b"\xff\xfe":
                text = body[2:].decode("utf-16-le", "replace"); enc = "UTF-16LE"
            else:
                text = body.decode("utf-16-be", "replace"); enc = "UTF-16BE (assumed, no BOM)"
        else:
            text = body.decode("utf-8", "replace"); enc = "UTF-8"
        details.append(("TEXT", tsv(text)))
        details.append(("LANG", tsv(lang)))
        details.append(("ENCODING", enc))
        details.append(("TEXT_STATUS", "0x%02X" % status))
        return details

    if name == "U":
        if not payload:
            raise NdefError("URI record (type U) has an empty payload: the 1-byte URI identifier code is missing")
        code = payload[0]
        if code >= len(URI_PREFIXES):
            raise NdefError("URI record has reserved URI identifier code 0x%02X (valid range 0x00-0x%02X)" % (code, len(URI_PREFIXES) - 1))
        prefix = URI_PREFIXES[code]
        suffix = payload[1:].decode("utf-8", "replace")
        details.append(("URI", tsv(prefix + suffix)))
        details.append(("URI_PREFIX_CODE", "0x%02X" % code))
        details.append(("URI_PREFIX", tsv(prefix)))
        details.append(("URI_SUFFIX", tsv(suffix)))
        return details

    if name in NESTED_WK:
        try:
            sub = decode_message(payload, strict=True)
        except NdefError as exc:
            raise NdefError("%s (type %s) carries an invalid nested NDEF message: %s" % (WK_NAMES[name], name, exc))
        details.append(("NESTED_RECORDS", "%d" % len(sub)))
        for srec in sub:
            details.append(("NESTED_RECORD", "%d\tTNF=%s\tTYPE=%s\tPAYLOAD_LEN=%d"
                            % (srec["index"], srec["tnf_name"], srec["type_disp"], len(srec["payload"]))))
            for key, value in srec["details"]:
                details.append(("NESTED_" + key, value))
        return details

    if name == "Si":
        if len(payload) != 4:
            raise NdefError("Size record (type Si) must carry exactly 4 payload bytes, got %d" % len(payload))
        details.append(("SIZE", "%d" % int.from_bytes(payload, "big")))
        return details

    if name == "Ac":
        if len(payload) != 1:
            raise NdefError("Action record (type Ac) must carry exactly 1 payload byte, got %d" % len(payload))
        details.append(("ACTION", ACTION_NAMES.get(payload[0], "reserved (0x%02X)" % payload[0])))
        return details

    details.append(("WK_TYPE", tsv(rtype.decode("ascii", "replace"))))
    if name in ("Bt", "Wi"):
        details.append(("NOTE", "carrier configuration payload shown raw, only the record name is decoded here"))
    else:
        details.append(("NOTE", "well known type recognised by name, payload shown raw"))
    return decode_opaque(payload, details)


def render(recs, nbytes):
    lines = []
    for rec in recs:
        lines.append("RECORD\t%d\tTNF=%s\tTYPE=%s\tPAYLOAD_LEN=%d"
                     % (rec["index"], rec["tnf_name"], rec["type_disp"], len(rec["payload"])))
        if rec["chunked"]:
            lines.append("CHUNKED\t1")
        if rec["id"]:
            lines.append("RECORD_ID\t%s" % tsv(disp_bytes(rec["id"])))
        for key, value in rec["details"]:
            lines.append("%s\t%s" % (key, value))
    lines.append("MESSAGE_RECORDS\t%d" % len(recs))
    lines.append("MESSAGE_BYTES\t%d" % nbytes)
    return lines


# ── encode ───────────────────────────────────────────────────────────────

def uri_encode(uri):
    code = 0
    suffix = uri
    best = -1
    for idx, prefix in enumerate(URI_PREFIXES):
        if idx == 0 or not prefix:
            continue
        if uri.startswith(prefix) and len(prefix) > best:
            best = len(prefix)
            code = idx
            suffix = uri[len(prefix):]
    return code, suffix


def parse_spec(spec):
    if ":" not in spec:
        raise NdefError("cannot parse spec %s: expected PREFIX:... with PREFIX one of T, T16, U, M, A, E, X" % spec)
    kind, rest = spec.split(":", 1)
    kind = kind.strip()

    if kind == "T" or kind == "T16":
        if ":" not in rest:
            raise NdefError("text spec %s needs T:LANG:TEXT (for example T:en:hello)" % spec)
        lang, text = rest.split(":", 1)
        try:
            lang_bytes = lang.encode("ascii")
        except UnicodeEncodeError:
            raise NdefError("language code %s is not ASCII" % lang)
        if len(lang_bytes) > 0x3F:
            raise NdefError("language code %s is longer than 63 bytes" % lang)
        if kind == "T":
            payload = bytes([0x80 | len(lang_bytes)]) + lang_bytes + text.encode("utf-8")
        else:
            payload = bytes([len(lang_bytes)]) + lang_bytes + b"\xfe\xff" + text.encode("utf-16-be")
        return (0x01, b"T", b"", payload)

    if kind == "U":
        if rest == "":
            raise NdefError("URI spec %s needs U:URI (for example U:https://example.com)" % spec)
        code, suffix = uri_encode(rest)
        return (0x01, b"U", b"", bytes([code]) + suffix.encode("utf-8"))

    if kind == "M":
        if ":" not in rest:
            raise NdefError("MIME spec %s needs M:TYPE:PAYLOAD (for example M:text/plain:hello)" % spec)
        mime, body = rest.split(":", 1)
        if mime == "":
            raise NdefError("MIME spec %s has an empty media type" % spec)
        return (0x02, mime.encode("ascii"), b"", body.encode("utf-8"))

    if kind == "A":
        if rest == "":
            raise NdefError("absolute URI spec %s needs A:URI" % spec)
        return (0x03, b"", b"", rest.encode("utf-8"))

    if kind == "E":
        if "=" in rest:
            ext, body = rest.split("=", 1)
        else:
            ext, body = rest, ""
        if ext == "":
            raise NdefError("external spec %s needs E:TYPE=PAYLOAD (for example E:android.com:pkg=com.example)" % spec)
        return (0x04, ext.encode("ascii"), b"", body.encode("utf-8"))

    if kind == "X":
        return (0x05, b"", b"", parse_hex(rest))

    raise NdefError("unknown spec prefix %s in %s: expected T, T16, U, M, A, E or X" % (kind, spec))


def encode_message(records):
    if not records:
        raise NdefError("no records to encode")
    out = bytearray()
    last = len(records) - 1
    for idx, (tnf, rtype, rid, payload) in enumerate(records):
        if len(rtype) > 255:
            raise NdefError("record %d: TYPE is %d bytes, the maximum is 255" % (idx + 1, len(rtype)))
        if len(rid) > 255:
            raise NdefError("record %d: ID is %d bytes, the maximum is 255" % (idx + 1, len(rid)))
        if len(payload) > 0xFFFFFFFF:
            raise NdefError("record %d: payload is too large" % (idx + 1))
        hdr = tnf & 0x07
        if idx == 0:
            hdr |= 0x80
        if idx == last:
            hdr |= 0x40
        short = len(payload) <= 0xFF
        if short:
            hdr |= 0x10
        has_id = len(rid) > 0
        if has_id:
            hdr |= 0x08
        out.append(hdr)
        out.append(len(rtype))
        if short:
            out.append(len(payload))
        else:
            out += len(payload).to_bytes(4, "big")
        if has_id:
            out.append(len(rid))
        out += rtype
        out += rid
        out += payload
    return bytes(out)


# ── tag identification ───────────────────────────────────────────────────

def parse_hex_field(text, what, maxdigits):
    raw = text.strip()
    if raw[:2].lower() == "0x":
        raw = raw[2:]
    for sep in (" ", ":", "_"):
        raw = raw.replace(sep, "")
    if not raw or len(raw) > maxdigits or any(c not in HEX_DIGITS for c in raw):
        raise NdefError("invalid %s value %s: expected 1 to %d hex digits (for example 0x0004)" % (what, text, maxdigits))
    return int(raw, 16)


def identify_tag(atqa, sak):
    """Returns (matches, used_fallback, used_swap, matched_atqa)."""
    swapped = ((atqa & 0xFF) << 8) | ((atqa >> 8) & 0xFF)
    candidates = [atqa] if swapped == atqa else [atqa, swapped]
    for pos, cand in enumerate(candidates):
        hits = [(name, notes) for (ta, ts, name, notes) in TAG_TABLE
                if ta is not None and ta == cand and ts == sak]
        if hits:
            return hits, False, pos == 1, cand
    hits = [(name, notes) for (ta, ts, name, notes) in TAG_TABLE if ta is None and ts == sak]
    return hits, True, False, None


def tag_table_tsv():
    print("ATQA\tSAK\tTYPE\tNOTES")
    for atqa, sak, name, notes in TAG_TABLE:
        atqa_s = "*" if atqa is None else "0x%04X" % atqa
        print("%s\t0x%02X\t%s\t%s" % (atqa_s, sak, name, notes))


def cmd_identify(atqa_s, sak_s):
    try:
        atqa = parse_hex_field(atqa_s, "ATQA", 4)
        sak = parse_hex_field(sak_s, "SAK", 2)
    except NdefError as exc:
        die(str(exc), 2)
    matches, fallback, swapped, matched = identify_tag(atqa, sak)
    print("ATQA\t0x%04X" % atqa)
    print("ATQA_BYTES\t%s" % hexspace(bytes([(atqa >> 8) & 0xFF, atqa & 0xFF])))
    print("SAK\t0x%02X" % sak)
    print("MATCHES\t%d" % len(matches))
    if not matches:
        print("TYPE\tunknown")
        print("NOTE\tno reference row for this ATQA and SAK; SAK alone does not identify a tag")
        sys.stderr.write("NOTE\tATQA 0x%04X with SAK 0x%02X is not in the reference table; run --tag-types-tsv for the known pairs\n" % (atqa, sak))
        return 0
    for name, notes in matches:
        print("TYPE\t%s" % name)
        print("NOTES\t%s" % notes)
    if swapped:
        print("NOTE\tmatched after swapping the ATQA byte order: 0x%04X -> 0x%04X" % (atqa, matched))
    if fallback:
        print("NOTE\tmatch came from the SAK-only fallback rule, the ATQA is not in the table")
    if len(matches) > 1:
        print("NOTE\t%d table rows share this ATQA and SAK; the UID length or a read of the tag is needed to tell them apart" % len(matches))
    return 0


# ── selftest ─────────────────────────────────────────────────────────────

def run_selftest():
    bad = 0

    def check(name, ok, detail=""):
        nonlocal bad
        if ok:
            print("%s\tPASS" % name)
        else:
            print("%s\tFAIL %s" % (name, detail))
            bad += 1

    def decode_hex(text, strict=True):
        return decode_message(parse_hex(text), strict=strict)

    def detail(rec, key):
        for k, v in rec["details"]:
            if k == key:
                return v
        return None

    def rejects(text, strict=True):
        try:
            decode_hex(text, strict=strict)
        except NdefError:
            return True
        return False

    # (a) hand-built URI record: MB|ME|SR|TNF=1, TYPE=U, code 0x04 + example.com
    uri_hex = "D1010C55046578616D706C652E636F6D"
    try:
        recs = decode_hex(uri_hex)
        got = detail(recs[0], "URI") if recs else None
        check("ndef-uri-record-decode",
              len(recs) == 1 and got == "https://example.com" and detail(recs[0], "URI_PREFIX_CODE") == "0x04",
              "decoded URI %r" % got)
    except NdefError as exc:
        check("ndef-uri-record-decode", False, "raised %s" % exc)

    # (b) hand-built Text record: status 0x82 = UTF-8, language length 2, en, hello
    text_hex = "D101085482656E68656C6C6F"
    try:
        recs = decode_hex(text_hex)
        check("ndef-text-record-decode",
              len(recs) == 1 and detail(recs[0], "TEXT") == "hello"
              and detail(recs[0], "LANG") == "en" and detail(recs[0], "ENCODING") == "UTF-8",
              "got TEXT=%r LANG=%r ENC=%r" % (detail(recs[0], "TEXT"), detail(recs[0], "LANG"), detail(recs[0], "ENCODING")))
    except NdefError as exc:
        check("ndef-text-record-decode", False, "raised %s" % exc)

    # UTF-16 text record: status 0x02 = UTF-16, language length 2, en, hi
    # (no BOM here, so the decoder must say it assumed big-endian)
    utf16_hex = "D101075402656E00680069"
    try:
        recs = decode_hex(utf16_hex)
        enc = detail(recs[0], "ENCODING") if recs else None
        check("ndef-text-utf16-decode",
              len(recs) == 1 and detail(recs[0], "TEXT") == "hi"
              and detail(recs[0], "LANG") == "en" and enc is not None and enc.startswith("UTF-16BE"),
              "got TEXT=%r LANG=%r ENC=%r" % (detail(recs[0], "TEXT"), detail(recs[0], "LANG"), enc))
    except NdefError as exc:
        check("ndef-text-utf16-decode", False, "raised %s" % exc)

    # long record (SR clear, 4-byte payload length)
    long_hex = "C1010000000C55046578616D706C652E636F6D"
    try:
        recs = decode_hex(long_hex)
        check("ndef-long-record-decode",
              len(recs) == 1 and detail(recs[0], "URI") == "https://example.com",
              "decoded %r" % (detail(recs[0], "URI") if recs else None))
    except NdefError as exc:
        check("ndef-long-record-decode", False, "raised %s" % exc)

    # record with an ID (IL set)
    id_hex = "D9010C0255002A046578616D706C652E636F6D"
    try:
        recs = decode_hex(id_hex)
        check("ndef-id-length-decode",
              len(recs) == 1 and recs[0]["id"] == b"\x00\x2a" and detail(recs[0], "URI") == "https://example.com",
              "id=%r" % (recs[0]["id"] if recs else None))
    except NdefError as exc:
        check("ndef-id-length-decode", False, "raised %s" % exc)

    # chunked record: CF on the first chunk (payload 04 65 78 = code + "ex"),
    # TNF 0x06 continuation chunk carrying the rest, "ample.com"
    chunk_hex = "B1010355046578560009616D706C652E636F6D"
    try:
        recs = decode_hex(chunk_hex)
        check("ndef-chunked-record-decode",
              len(recs) == 1 and detail(recs[0], "URI") == "https://example.com" and recs[0]["chunked"],
              "decoded %r" % (detail(recs[0], "URI") if recs else None))
    except NdefError as exc:
        check("ndef-chunked-record-decode", False, "raised %s" % exc)

    # (c) encode then decode round trips
    specs = ["T:en:hello", "U:https://example.com", "M:text/plain:hello world",
             "A:https://absolute.example/x", "E:android.com:pkg=com.example.app",
             "T16:de:Hallo Welt", "T::no language"]
    try:
        recs = decode_message(encode_message([parse_spec(s) for s in specs]), strict=True)
        ok = (len(recs) == len(specs)
              and detail(recs[0], "TEXT") == "hello" and detail(recs[0], "LANG") == "en"
              and detail(recs[1], "URI") == "https://example.com"
              and detail(recs[2], "MIME") == "text/plain" and detail(recs[2], "TEXT") == "hello world"
              and detail(recs[3], "URI") == "https://absolute.example/x"
              and detail(recs[4], "EXTERNAL_TYPE") == "android.com:pkg" and detail(recs[4], "TEXT") == "com.example.app"
              and detail(recs[5], "TEXT") == "Hallo Welt" and detail(recs[5], "ENCODING") == "UTF-16BE"
              and detail(recs[6], "TEXT") == "no language" and detail(recs[6], "LANG") == "")
        check("ndef-encode-decode-roundtrip", ok, "record count %d" % len(recs))
    except NdefError as exc:
        check("ndef-encode-decode-roundtrip", False, "raised %s" % exc)

    # long payload: the encoder must switch to the 4-byte length form and
    # the decoder must read it back unchanged
    long_text = "A" * 300
    try:
        msg = encode_message([parse_spec("T:en:" + long_text)])
        recs = decode_message(msg, strict=True)
        check("ndef-long-payload-roundtrip",
              (msg[0] & 0x10) == 0 and int.from_bytes(msg[2:6], "big") == len(recs[0]["payload"])
              and len(recs[0]["payload"]) == len(long_text) + 3
              and detail(recs[0], "TEXT") == long_text,
              "header 0x%02X, length field %s" % (msg[0], hexspace(msg[2:6])))
    except NdefError as exc:
        check("ndef-long-payload-roundtrip", False, "raised %s" % exc)

    # whole URI identifier code table round trips
    ok = True
    problem = ""
    if len(URI_PREFIXES) != 0x24 or URI_PREFIXES[0x23] != "urn:nfc:":
        ok = False
        problem = "prefix table has %d entries" % len(URI_PREFIXES)
    else:
        for idx, prefix in enumerate(URI_PREFIXES):
            uri = prefix + "roundtrip.example/x"
            try:
                recs = decode_message(encode_message([parse_spec("U:" + uri)]), strict=True)
            except NdefError as exc:
                ok = False
                problem = "code 0x%02X raised %s" % (idx, exc)
                break
            if detail(recs[0], "URI") != uri or detail(recs[0], "URI_PREFIX_CODE") != "0x%02X" % idx:
                ok = False
                problem = "code 0x%02X prefix %r came back as %r code %s" % (idx, prefix, detail(recs[0], "URI"), detail(recs[0], "URI_PREFIX_CODE"))
                break
    check("ndef-uri-prefix-table", ok, problem)

    # (d) malformed input must be rejected
    truncations = [
        ("D1010C55046578616D706C65", "payload shorter than PAYLOAD_LENGTH"),
        ("C1010000", "4-byte length field cut short"),
        ("D1", "header without TYPE_LENGTH"),
        ("D1010C", "TYPE missing"),
        ("D1010C55", "payload missing"),
        ("D1010", "odd number of hex digits"),
        ("D1010C5Z", "non hex character"),
        ("", "empty input"),
        ("D1010C5504FFFFFFFF", "payload shorter than PAYLOAD_LENGTH"),
        ("D101015524", "URI identifier code 0x24 out of range"),
    ]
    broken = [note for text, note in truncations if not rejects(text)]
    check("ndef-malformed-rejected", not broken, "accepted: %s" % ", ".join(broken))

    # reserved TNF
    check("ndef-reserved-tnf-rejected", rejects("C70000"), "TNF 0x07 was accepted")

    # an Empty record may not carry data: rejected when strict, warned when lenient
    # D0 = MB|ME|SR, TNF 0 (Empty); TYPE_LENGTH 0, PAYLOAD_LENGTH 1, payload 0x41
    empty_hex = "D0000141"
    strict_ok = rejects(empty_hex, strict=True)
    lenient_ok = False
    try:
        decode_hex(empty_hex, strict=False)
        lenient_ok = True
    except NdefError:
        lenient_ok = False
    check("ndef-empty-record-strict", strict_ok and lenient_ok, "strict=%s lenient=%s" % (strict_ok, lenient_ok))

    # MB and ME checks: rejected when strict, warned when lenient
    mbme_hex = "11010C55046578616D706C652E636F6D"
    strict_ok = rejects(mbme_hex, strict=True)
    lenient_ok = False
    try:
        lenient_ok = detail(decode_hex(mbme_hex, strict=False)[0], "URI") == "https://example.com"
    except NdefError:
        lenient_ok = False
    check("ndef-mb-me-strict", strict_ok and lenient_ok, "strict=%s lenient=%s" % (strict_ok, lenient_ok))

    # (e) tag identification from ATQA and SAK
    classic, fb, sw, _ = identify_tag(0x0004, 0x08)
    check("tag-identify-classic-1k",
          len(classic) == 1 and classic[0][0] == "MIFARE Classic 1K",
          "got %r" % [n for n, _ in classic])

    classic4k, _, _, _ = identify_tag(0x0002, 0x18)
    check("tag-identify-classic-4k",
          any(n == "MIFARE Classic 4K" for n, _ in classic4k),
          "got %r" % [n for n, _ in classic4k])

    ultra, _, _, _ = identify_tag(0x0044, 0x00)
    names = [n for n, _ in ultra]
    check("tag-identify-ultralight-ntag",
          "MIFARE Ultralight" in names and "NTAG203/213" in names,
          "got %r" % names)

    desfire, _, _, _ = identify_tag(0x0344, 0x20)
    check("tag-identify-desfire",
          any(n == "MIFARE DESFire" for n, _ in desfire),
          "got %r" % [n for n, _ in desfire])

    iso4, _, _, _ = identify_tag(0x0004, 0x20)
    check("tag-identify-iso14443-4",
          any(n == "ISO 14443-4 / EMV" for n, _ in iso4),
          "got %r" % [n for n, _ in iso4])

    unknown, _, _, _ = identify_tag(0xFFFF, 0x99)
    check("tag-identify-unknown", len(unknown) == 0, "got %r" % [n for n, _ in unknown])

    fallback_hits, fb, _, _ = identify_tag(0x0044, 0x20)
    check("tag-identify-sak-fallback",
          fb and any(n.startswith("ISO 14443-4") for n, _ in fallback_hits),
          "fallback=%s hits=%r" % (fb, [n for n, _ in fallback_hits]))

    swap_hits, _, sw, _ = identify_tag(0x4400, 0x00)
    check("tag-identify-atqa-byte-order",
          sw and any(n == "MIFARE Ultralight" for n, _ in swap_hits),
          "swapped=%s hits=%r" % (sw, [n for n, _ in swap_hits]))

    required = [(0x0004, 0x08, "MIFARE Classic 1K"), (0x0002, 0x18, "MIFARE Classic 4K"),
                (0x0044, 0x00, "MIFARE Ultralight"), (0x0044, 0x00, "NTAG203/213"),
                (0x0344, 0x20, "MIFARE DESFire"), (0x0004, 0x20, "ISO 14443-4 / EMV")]
    missing = ["%04X/%02X %s" % (a, s, n) for (a, s, n) in required
               if not any(ta == a and ts == s and name == n for (ta, ts, name, _) in TAG_TABLE)]
    check("tag-table-required-rows", not missing, "missing %s" % ", ".join(missing))

    print("CODEC_RESULT\t%s" % ("PASS" if bad == 0 else "FAIL(%d)" % bad))
    return 1 if bad else 0


# ── python entry point ───────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        die("no codec subcommand given", 2)
    cmd = args[0]
    rest = args[1:]
    try:
        if cmd == "decode":
            if len(rest) < 2:
                die("decode needs a mode and a hex string", 2)
            strict = rest[0] != "lenient"
            data = parse_hex(rest[1])
            recs = decode_message(data, strict=strict)
            for line in render(recs, len(data)):
                print(line)
        elif cmd == "encode":
            if not rest:
                die("encode needs at least one record spec", 2)
            print(hexlify(encode_message([parse_spec(s) for s in rest])))
        elif cmd == "tag-table":
            tag_table_tsv()
        elif cmd == "identify":
            if len(rest) < 2:
                die("identify needs ATQA and SAK", 2)
            return cmd_identify(rest[0], rest[1])
        elif cmd == "selftest":
            return run_selftest()
        else:
            die("unknown codec subcommand %s" % cmd, 2)
    except NdefError as exc:
        die(str(exc), 1)
    return 0


sys.exit(main())
PYEOF
}

# ── status ───────────────────────────────────────────────────────────────

nfc_status_tsv() {
    nfc_probe_reader
    local py=0
    nfc_have python3 && py=1
    printf 'python3\t%d\n' "$py"
    printf 'lsusb\t%d\n' "$NFC_LSUSB"
    printf 'nfc-list\t%d\n' "$NFC_TOOL_NFCLIST"
    printf 'mfoc\t%d\n' "$NFC_TOOL_MFOC"
    printf 'pcsc_scan\t%d\n' "$NFC_TOOL_PCSC"
    printf 'usb_acr122\t%d\n' "$NFC_USB_ACR122"
    printf 'usb_pn532\t%d\n' "$NFC_USB_PN532"
    printf 'usb_proxmark\t%d\n' "$NFC_USB_PROX"
    printf 'reader\t%d\n' "$NFC_READER"
    # The codec is a data layer: it ships with the module and needs no radio.
    printf 'codec\t1\n'
    printf 'codec_ready\t%d\n' "$py"
    printf 'tag_types\t1\n'
    printf 'ndef_decode\t1\n'
    printf 'ndef_encode\t1\n'
    printf 'mifare_sectors\t1\n'
    printf 'live_read\t%d\n' "$NFC_READER"
    printf 'tx\t0\n'
    return 0
}

nfc_tag_types_tsv() {
    nfc_require_python || return 1
    nfc_py tag-table
}

nfc_identify() {
    (($# == 2)) || {
        printf 'ERROR\tusage: --identify ATQA SAK   (for example: --identify 0x0004 0x08)\n' >&2
        return 2; }
    nfc_require_python || return 1
    nfc_py identify "$1" "$2"
}

# ── NDEF codec commands ──────────────────────────────────────────────────

nfc_ndef_decode() {
    local hex="" mode="strict"
    while (($#)); do
        case "$1" in
            --lenient) mode="lenient" ;;
            '')        printf 'ERROR\tempty argument to --ndef-decode\n' >&2; return 2 ;;
            --*)       printf 'ERROR\tunknown option for --ndef-decode: %s\n' "$1" >&2; return 2 ;;
            *)
                if [[ -n "$hex" ]]; then
                    printf 'ERROR\t--ndef-decode takes exactly one HEX argument\n' >&2
                    return 2
                fi
                hex="$1" ;;
        esac
        shift
    done
    [[ -n "$hex" ]] || { printf 'ERROR\tusage: --ndef-decode HEX [--lenient]\n' >&2; return 2; }
    nfc_require_python || return 1
    nfc_py decode "$mode" "$hex"
}

nfc_ndef_encode() {
    (($#)) || {
        printf 'ERROR\tusage: --ndef-encode SPEC [SPEC ...]\n' >&2
        printf 'ERROR\texamples: --ndef-encode T:en:hello   --ndef-encode U:https://example.com\n' >&2
        return 2; }
    nfc_require_python || return 1
    nfc_py encode "$@"
}

# ── MIFARE Classic reference layout ──────────────────────────────────────
# Pure reference output: describes where the keys and the sector trailers
# live. It reads no hardware and needs no reader.

nfc_mifare_sectors() {
    local kind="${1:-1K}" spec="" sectors=0 total=0
    case "${kind^^}" in
        1K|S50|CLASSIC1K|MIFARE1K) spec="MIFARE Classic 1K"; sectors=16; total=64 ;;
        4K|S70|CLASSIC4K|MIFARE4K) spec="MIFARE Classic 4K"; sectors=40; total=256 ;;
        *)
            printf 'ERROR\tunknown MIFARE Classic variant %s (expected 1K or 4K)\n' "$kind" >&2
            return 2 ;;
    esac

    printf 'SPEC\t%s\n' "$spec"
    printf 'SOURCE\treference layout, no hardware access\n'
    printf 'SECTORS\t%d\n' "$sectors"
    printf 'BLOCKS\t%d\n' "$total"
    printf 'BLOCK_SIZE\t16 bytes\n'
    if (( total == 64 )); then
        printf 'LAYOUT\t16 sectors x 4 blocks = 3 data blocks + 1 sector trailer\n'
    else
        printf 'LAYOUT\tsectors 0-31: 4 blocks (3 data + 1 trailer); sectors 32-39: 16 blocks (15 data + 1 trailer)\n'
    fi
    printf 'MANUFACTURER_BLOCK\t0\tblock 0 is the manufacturer block: UID, BCC, SAK, ATQA and manufacturer data, written at production and read-only afterwards\n'
    printf 'TRAILER_LAYOUT\tbytes 0-5 Key A, bytes 6-8 access bits, byte 9 general purpose, bytes 10-15 Key B\n'
    printf 'KEY_A\tbytes 0-5 of the sector trailer, write only, never readable back\n'
    printf 'KEY_B\tbytes 10-15 of the sector trailer, readable when the access bits allow it\n'
    printf 'ACCESS_BITS\tbytes 6-8 of the sector trailer, they define read and write access per block\n'
    printf 'DEFAULT_KEY_A\tFFFFFFFFFFFF\n'
    printf 'DEFAULT_KEY_B\tFFFFFFFFFFFF\n'

    local s=0 b=0 first=0 last=0 trailer=0 role=""
    for (( s=0; s<sectors; s++ )); do
        if (( total == 64 )); then
            first=$(( s * 4 ))
        elif (( s < 32 )); then
            first=$(( s * 4 ))
        else
            first=$(( 128 + (s - 32) * 16 ))
        fi
        if (( total == 64 )) || (( s < 32 )); then
            last=$(( first + 3 ))
        else
            last=$(( first + 15 ))
        fi
        trailer=$last
        printf 'SECTOR\t%d\tFIRST_BLOCK=%d\tLAST_BLOCK=%d\tTRAILER_BLOCK=%d\tDATA_BLOCKS=%d-%d\n' \
               "$s" "$first" "$last" "$trailer" "$first" "$(( trailer - 1 ))"
        for (( b=first; b<=last; b++ )); do
            if (( b == 0 )); then
                role="manufacturer"
            elif (( b == trailer )); then
                role="trailer"
            else
                role="data"
            fi
            printf 'BLOCK\t%d\tSECTOR=%d\tROLE=%s\n' "$b" "$s" "$role"
        done
    done
    return 0
}

# ── live read (hardware gated) ───────────────────────────────────────────

nfc_read_tag() {
    nfc_probe_reader
    (($# == 0)) || { printf 'ERROR\t--read-tag takes no arguments\n' >&2; return 2; }

    local missing_tools="" missing_usb=""
    (( NFC_TOOL_NFCLIST )) || missing_tools+="nfc-list "
    (( NFC_TOOL_MFOC ))     || missing_tools+="mfoc "
    (( NFC_TOOL_PCSC ))     || missing_tools+="pcsc_scan "
    (( NFC_USB_ACR122 ))    || missing_usb+="072f:2200 (ACS ACR122U) "
    (( NFC_USB_PN532 ))     || missing_usb+="04cc:2533 (PN532) "
    (( NFC_USB_PROX ))      || missing_usb+="0483:5740 (Proxmark3) "

    if (( ! NFC_READER )); then
        printf 'ERROR\t--read-tag refused: no NFC/RFID reader is present on this machine\n' >&2
        printf 'ERROR\tmissing USB reader: none of %s was found on the USB bus\n' "${missing_usb% }" >&2
        printf 'ERROR\tmissing tool: %s(install nfc-tools, mfoc or pcsc-tools)\n' "$missing_tools" >&2
        (( NFC_LSUSB )) || printf 'ERROR\tlsusb is not installed, so USB detection could not run at all\n' >&2
        printf 'MISSING\thardware: NFC reader plus nfc-list or pcsc_scan\n' >&2
        printf 'NOTE\tthe data layer (--ndef-decode, --ndef-encode, --identify, --tag-types-tsv, --mifare-sectors) needs no hardware and stays available\n' >&2
        return 1
    fi

    if (( ! NFC_TOOL_NFCLIST )) && (( ! NFC_TOOL_PCSC )); then
        printf 'ERROR\t--read-tag refused: a reader may be present but no reader tool is installed\n' >&2
        printf 'ERROR\tmissing tool: %s\n' "${missing_tools% }" >&2
        printf 'MISSING\tnfc-list (package nfc-tools) or pcsc_scan (package pcsc-tools)\n' >&2
        return 1
    fi

    local out="" parsed="" ntags=0 save=""
    if (( NFC_TOOL_NFCLIST )); then
        if nfc_have timeout; then
            out="$(timeout 20 nfc-list -v 2>&1)"
        else
            out="$(nfc-list -v 2>&1)"
        fi
        if (($? != 0)) && [[ -z "$out" ]]; then
            printf 'ERROR\tnfc-list failed and produced no output (is pcscd running? is the reader claimed by another process?)\n' >&2
            return 1
        fi
        parsed="$(printf '%s\n' "$out" | awk -F: '
            /ATQA/ { v=$2; gsub(/[ \t]/, "", v); printf "ATQA\t%s\n", v }
            /SAK/  { v=$2; gsub(/[ \t]/, "", v); printf "SAK\t%s\n", v }
            /UID/  { v=$2; gsub(/[ \t]/, "", v); printf "UID\t%s\n", v }
        ')"
        printf 'SOURCE\tnfc-list\n'
        if [[ -n "$parsed" ]]; then
            printf '%s\n' "$parsed"
        fi
        ntags="$(printf '%s\n' "$parsed" | awk -F'\t' '$1 == "UID" { n++ } END { print n + 0 }')"
        if (( ntags == 0 )); then
            printf 'TAGS\t0\n'
            printf 'ERROR\tnfc-list ran but reported no tag: put a tag on the antenna and retry\n' >&2
            printf 'NOTE\t%s\n' "$(printf '%s\n' "$out" | head -n 3 | tr '\n' ' ')" >&2
            return 1
        fi
        printf 'TAGS\t%d\n' "$ntags"
    else
        if nfc_have timeout; then
            out="$(timeout 8 pcsc_scan 2>&1)"
        else
            out="$(pcsc_scan 2>&1)"
        fi
        parsed="$(printf '%s\n' "$out" | awk '/ATR/ { print "ATR\t" $0 }')"
        printf 'SOURCE\tpcsc_scan\n'
        if [[ -n "$parsed" ]]; then
            printf '%s\n' "$parsed"
            ntags="$(printf '%s\n' "$parsed" | grep -c . || true)"
            printf 'TAGS\t%d\n' "$ntags"
        else
            printf 'TAGS\t0\n'
            printf 'ERROR\tpcsc_scan reported no ATR: no contactless card answered\n' >&2
            return 1
        fi
    fi

    save="$MOD_LOOT/tag_$(date +%Y%m%d_%H%M%S).tsv"
    if { printf 'SOURCE\tlive-read\n'; printf '%s\n' "$parsed"; } >"$save" 2>/dev/null; then
        printf 'SAVED\t%s\n' "$save"
    else
        printf 'WARN\tcould not write %s\n' "$save" >&2
    fi
    return 0
}

# ── selftest ─────────────────────────────────────────────────────────────

nfc_selftest() {
    local bad=0 out="" rc=0 pybad=0 hex="" dec=""

    if nfc_have python3; then
        printf 'python3-present\tPASS\n'
    else
        printf 'python3-present\tFAIL python3 not found; the NDEF codec needs it\n'
        printf 'RESULT\tFAIL(1)\n'
        return 1
    fi

    out="$(nfc_py selftest 2>&1)"; rc=$?
    printf '%s\n' "$out"
    if (( rc == 0 )); then
        printf 'codec-exit-status\tPASS\n'
    else
        printf 'codec-exit-status\tFAIL python codec selftest exited %d\n' "$rc"
        bad=$(( bad + 1 ))
    fi
    pybad=$(printf '%s\n' "$out" | grep -c 'FAIL' || true)
    bad=$(( bad + pybad ))

    # End to end through the shipped command line, not just the codec API.
    hex="$(bash "$0" --ndef-encode 'U:https://example.com' 2>/dev/null)"
    dec="$(bash "$0" --ndef-decode "$hex" 2>/dev/null)"
    if grep -qx $'URI\thttps://example.com' <<<"$dec"; then
        printf 'cli-encode-decode-roundtrip\tPASS\n'
    else
        printf 'cli-encode-decode-roundtrip\tFAIL hex=%s\n' "${hex:-<empty>}"
        bad=$(( bad + 1 ))
    fi

    if bash "$0" --ndef-decode 'D1010C55046578616D706C65' >/dev/null 2>&1; then
        printf 'cli-truncated-rejected\tFAIL a truncated record was accepted\n'
        bad=$(( bad + 1 ))
    else
        printf 'cli-truncated-rejected\tPASS\n'
    fi

    nfc_probe_reader
    if (( NFC_READER )); then
        printf 'reader-gate\tSKIP a reader or NFC tool is present on this machine\n'
    elif bash "$0" --read-tag >/dev/null 2>&1; then
        printf 'reader-gate\tFAIL --read-tag reported success with no reader present\n'
        bad=$(( bad + 1 ))
    else
        printf 'reader-gate\tPASS\n'
    fi

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── documentation ────────────────────────────────────────────────────────

nfc_info() {
    cat <<'EOF'
NFC / RFID data layer: NDEF message codec, tag identification, MIFARE layout.

NDEF (NFC Data Exchange Format)
  A message is a sequence of records, back to back, with no padding.

  Record layout
    header byte     MB ME CF SR IL TNF
                      MB  bit 7  message begin, set on the first record
                      ME  bit 6  message end, set on the last record
                      CF  bit 5  chunk flag, payload continues in the next record
                      SR  bit 4  short record: 1-byte payload length
                      IL  bit 3  an ID field is present
                      TNF bits 0-2  type name format
    TYPE_LENGTH     1 byte
    PAYLOAD_LENGTH  1 byte when SR=1, otherwise 4 bytes big-endian
    ID_LENGTH       1 byte, only when IL=1
    TYPE            TYPE_LENGTH bytes
    ID              ID_LENGTH bytes
    PAYLOAD         PAYLOAD_LENGTH bytes

  TNF values
    0x00 Empty           no type, no id, no payload
    0x01 Well Known      short registered name such as T or U
    0x02 MIME            media type such as text/plain
    0x03 Absolute URI    the payload is the URI itself
    0x04 External        domain qualified type, for example android.com:pkg
    0x05 Unknown         type is opaque, only the payload can be shown
    0x06 Unchanged       continuation chunk of a chunked record
    0x07 Reserved        must never appear

  Well Known records decoded by this module
    T    Text. The first payload byte is the status byte: bit 7 set means
         UTF-8, bit 7 clear means UTF-16, and bits 5-0 are the language
         code length in bytes. The language code follows, then the text.
    U    URI. The first payload byte is a URI identifier code that
         abbreviates a scheme prefix (0x00 none, 0x01 http://www.,
         0x02 https://www., 0x04 https://, 0x05 tel:, 0x06 mailto:,
         0x1D file://, 0x1E-0x23 urn:epc and urn:nfc forms). The rest of
         the payload is the URI suffix. --tag-types-tsv is unrelated; the
         whole table is in the codec and exercised by --selftest.
    Sp   Smart Poster, payload is a nested NDEF message, decoded recursively.
    Hs, Hr  Handover Select and Handover Request, also nested NDEF.
    Si   Size, Ac  Action, Bt and Wi  carrier configuration, Sig  Signature.
         For Bt and Wi only the record name is decoded; the payload is
         printed as hex on purpose rather than guessed at.

  Compact specs for --ndef-encode (several specs make a multi record message)
    T:LANG:TEXT      Text, UTF-8      T:en:hello
    T16:LANG:TEXT    Text, UTF-16BE   T16:de:Hallo
    U:URI            URI, the longest matching prefix code is chosen
    M:TYPE:PAYLOAD   MIME             M:text/plain:hello
    A:URI            Absolute URI record
    E:TYPE=PAYLOAD   External         E:android.com:pkg=com.example
    X:HEX            Unknown TNF with a raw payload
  Output is bare uppercase hex, so it feeds straight back in:
    HEX=$(./43_nfc_rfid.sh --ndef-encode 'U:https://example.com')
    ./43_nfc_rfid.sh --ndef-decode "$HEX"

  Malformed input is rejected with an ERROR on stderr and a non-zero exit:
  truncated records, an odd number of hex digits, a reserved TNF, a chunk
  that never terminates, an out of range URI identifier code, a Text
  record whose payload is too short for its own language code. The
  stricter structural checks (MB on the first record, ME on the last, an
  Empty record that carries data) are also errors; --ndef-decode HEX
  --lenient downgrades exactly those to warnings on stderr.
  --ndef-decode always prints MESSAGE_RECORDS and MESSAGE_BYTES.
  --identify prints TYPE unknown for a pair that is not in the table and
  exits 0 (an honest lookup result); a malformed ATQA or SAK argument is
  an error and exits 2.

Hardware gating
  Everything above is a pure data layer: --ndef-decode, --ndef-encode,
  --identify, --tag-types-tsv and --mifare-sectors read and write no
  hardware, need no reader and always work offline.
  --read-tag is the only live command. It needs a PC/SC or NFC reader
  (ACS ACR122U 072f:2200, PN532 04cc:2533, Proxmark3 0483:5740) plus a
  userland tool (nfc-list from nfc-tools, or pcsc_scan from pcsc-tools).
  With no reader it prints an ERROR naming the missing hardware and
  missing tools, and exits non-zero; it never reports a tag it did not
  read. If a reader is found but no tag answers, it prints TAGS 0 and
  still exits non-zero.
  This module never transmits: it has no RF attack surface at all.

MIFARE Classic reference
  --mifare-sectors 1K|4K prints the sector and block layout: block 0 is
  the manufacturer block, every sector ends in a trailer block that holds
  Key A (bytes 0-5), the access bits (bytes 6-8) and Key B (bytes 10-15).
  1K is 16 sectors x 4 blocks, 4K is 32 sectors x 4 blocks followed by
  8 sectors x 16 blocks.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
nfc_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     nfc_status_tsv ;;
        --tag-types-tsv)  nfc_tag_types_tsv ;;
        --identify)       nfc_identify "$@" ;;
        --ndef-decode)    nfc_ndef_decode "$@" ;;
        --ndef-encode)    nfc_ndef_encode "$@" ;;
        --mifare-sectors) nfc_mifare_sectors "$@" ;;
        --read-tag)       nfc_read_tag "$@" ;;
        --selftest)       nfc_selftest ;;
        --info)           nfc_info ;;
        *) cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv               python3, reader and codec availability
  --tag-types-tsv            ATQA/SAK to tag type reference table
  --identify ATQA SAK        identify one tag from its ATQA and SAK
  --ndef-decode HEX          decode an NDEF message from raw hex
  --ndef-encode SPEC ...     build an NDEF message, prints uppercase hex
  --mifare-sectors [1K|4K]   MIFARE Classic sector and block layout
  --read-tag                 live read (needs a reader, gated)
  --selftest                 run the codec and CLI checks
  --info                     NDEF structure, specs and gating
EOF
           return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    nfc_cli_main "$@"
fi

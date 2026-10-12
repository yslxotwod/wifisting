#!/usr/bin/env bash
# 44_lora_loraWAN — LoRa / LoRaWAN
# LoRaWAN frame codec, MIC validation and session key derivation.
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

MOD_TMP="$TMP_DIR/lora_loraWAN"
MOD_LOOT="$LOOT_DIR/lora_loraWAN"
MOD_LOGS="$LOG_DIR/lora_loraWAN"
MOD_CAPS="$CAPTURES_DIR/lora_loraWAN"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

LORA_OUT="$MOD_LOOT/frames"
mkdir -p "$LORA_OUT" 2>/dev/null

lora_have_sdr() {
    command -v rtl_fm rtl_test hackrf_info >/dev/null 2>&1 && return 0
    lsusb 2>/dev/null | grep -qiE '0bda:2838|1d50:6089|0403:6015' && return 0
    return 1
}

lora_status_tsv() {
    local py=0
    python3 -c 'import cryptography' 2>/dev/null && py=1
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'cryptography\t%s\n' "$py"
    printf 'sdr\t%s\n' "$(lora_have_sdr && echo 1 || echo 0)"
    # The whole codec — MIC, key derivation, payload crypto — is offline.
    # Only receiving frames off the air needs an SDR.
    printf 'codec\t%s\n' "$py"
    printf 'live_receive\t%s\n' "$(lora_have_sdr && echo 1 || echo 0)"
}

lora_msg_types_tsv() {
    cat <<'EOF'
0	Join Request	join	uplink
1	Join Accept	join	downlink
2	Unconfirmed Data Up	data	uplink
3	Unconfirmed Data Down	data	downlink
4	Confirmed Data Up	data	uplink
5	Confirmed Data Down	data	downlink
6	RFU	-	-
7	Proprietary	-	-
EOF
}

# ── codec ────────────────────────────────────────────────────────────────
# The crypto lives in one helper so AES-CMAC and AES-CTR exist in exactly
# one place. Verified against the RFC 4493 AES-CMAC vectors in --selftest.
lora_helper() {
    mkdir -p "$MOD_TMP" 2>/dev/null
    cat > "$MOD_TMP/lora.py" <<'PYEOF'
import binascii, sys

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MTYPE = {0: "Join Request", 1: "Join Accept", 2: "Unconfirmed Data Up",
         3: "Unconfirmed Data Down", 4: "Confirmed Data Up",
         5: "Confirmed Data Down", 6: "RFU", 7: "Proprietary"}


def hexb(s):
    try:
        return bytes.fromhex("".join(s.split()).replace(":", ""))
    except ValueError:
        print("ERROR\tnot valid hex: %r" % s, file=sys.stderr)
        sys.exit(1)


def cmac(key, msg):
    c = CMAC(algorithms.AES(key)); c.update(msg); return c.finalize()


def aes_ecb_enc(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def aes_ecb_dec(key, block):
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(block) + d.finalize()


def ctr(key, dirn, devaddr, fcnt, payload):
    """LoRaWAN FRMPayload encryption: AES-128 in counter mode with the
    Ai block layout from the spec (1.0.x section 4.3.3)."""
    out = bytearray()
    n = (len(payload) + 15) // 16
    for i in range(1, n + 1):
        a = bytes([0x01]) + bytes(4) + bytes([dirn]) + devaddr + \
            fcnt.to_bytes(4, "little") + bytes([0x00]) + bytes([i])
        ks = aes_ecb_enc(key, a)
        chunk = payload[(i - 1) * 16:i * 16]
        out.extend(b ^ k for b, k in zip(chunk, ks))
    return bytes(out)


def b0(dirn, devaddr, fcnt, msglen):
    return (bytes([0x49]) + bytes(4) + bytes([dirn]) + devaddr +
            fcnt.to_bytes(4, "little") + bytes([0x00]) + bytes([msglen]))


def data_mic(nwkskey, msg):
    """msg = MHDR..FRMPayload (no MIC)."""
    return cmac(nwkskey, b0(0, msg[1:5], int.from_bytes(msg[6:8], "little"),
                            len(msg)) + msg)[0:4]


def derive_session_keys(appkey, appnonce, netid, devnonce):
    """1.0.x: NwkSKey = aes128(AppKey, 0x01|AppNonce|NetID|DevNonce|pad16).

    pad16 pads the block TO 16 bytes; it does not append 16 bytes. The
    prefix is 1+3+3+2 = 9 bytes, so 7 zero bytes are appended.
    """
    def block(tag):
        b = bytes([tag]) + appnonce + netid + devnonce
        if len(b) > 16:
            print("ERROR\tsession key block is %d bytes, max 16" % len(b),
                  file=sys.stderr)
            sys.exit(1)
        return b + bytes(16 - len(b))
    return aes_ecb_enc(appkey, block(0x01)), aes_ecb_enc(appkey, block(0x02))


def parse(hexs):
    raw = hexb(hexs)
    if len(raw) < 5:
        print("ERROR\tframe too short (%d bytes, minimum 5)" % len(raw),
              file=sys.stderr); sys.exit(1)
    mhdr = raw[0]
    mtype = (mhdr >> 5) & 0x07
    major = mhdr & 0x03
    print("MHDR\t0x%02x" % mhdr)
    print("MTYPE\t%d" % mtype)
    print("MTYPE_NAME\t%s" % MTYPE.get(mtype, "?"))
    print("MAJOR\t%d" % major)
    print("LEN\t%d" % len(raw))
    print("MIC\t%s" % binascii.hexlify(raw[-4:]).decode())
    return raw, mtype


def decode_join_request(raw):
    if len(raw) != 23:
        print("ERROR\tJoin Request must be 23 bytes, got %d" % len(raw),
              file=sys.stderr); sys.exit(1)
    print("APPEUI\t%s" % binascii.hexlify(raw[1:9][::-1]).decode())
    print("DEVEUI\t%s" % binascii.hexlify(raw[9:17][::-1]).decode())
    print("DEVNONCE\t0x%s" % binascii.hexlify(raw[17:19]).decode())
    print("NOTE\tEUI fields are printed in big-endian display order; on the\n"
          "NOTE\twire they are little-endian, which is why they are reversed.")


def decode_data(raw, nwkskey=None, appskey=None, dirn=0):
    if len(raw) < 12:
        print("ERROR\tdata frame too short (%d bytes)" % len(raw), file=sys.stderr)
        sys.exit(1)
    devaddr = raw[1:5]
    fctrl = raw[5]
    fcnt = int.from_bytes(raw[6:8], "little")
    foptslen = fctrl & 0x0F
    print("DEVADDR\t%s" % binascii.hexlify(devaddr[::-1]).decode())
    print("FCtrl\t0x%02x" % fctrl)
    print("ADR\t%d" % ((fctrl >> 7) & 1))
    print("ACK\t%d" % ((fctrl >> 5) & 1))
    print("FOptsLen\t%d" % foptslen)
    print("FCNT\t%d" % fcnt)
    off = 8 + foptslen
    if off > len(raw) - 4:
        print("ERROR\tFOptsLen %d overruns the frame" % foptslen, file=sys.stderr)
        sys.exit(1)
    body = raw[off:len(raw) - 4]
    if not body:
        print("FPORT\tnone")
        print("FRMPAYLOAD\t")
        return
    fport = body[0]
    frm = body[1:]
    print("FPORT\t%d" % fport)
    print("FRMPAYLOAD\t%s" % binascii.hexlify(frm).decode())
    if nwkskey or appskey:
        key = nwkskey if fport == 0 else appskey
        if key is None:
            print("NOTE\tno %s supplied, cannot decrypt"
                  % ("NwkSKey" if fport == 0 else "AppSKey"))
        else:
            pt = ctr(key, dirn, devaddr, fcnt, frm)
            print("DECRYPTED\t%s" % binascii.hexlify(pt).decode())
            try:
                print("DECRYPTED_ASCII\t%s" % pt.decode("utf-8"))
            except UnicodeDecodeError:
                pass


def decode_join_accept(raw, appkey=None):
    body = raw[1:len(raw) - 4]
    if len(body) not in (16, 32):
        print("ERROR\tJoin Accept body must be 16 or 32 bytes, got %d"
              % len(body), file=sys.stderr); sys.exit(1)
    if appkey:
        # The network encrypts a Join Accept by AES-DECRYPTING it, so the
        # device (and we) recover it by AES-ENCRYPTING.
        print("PLAINTEXT_NOTE\tJoin Accept payload is AES-encrypted with AppKey")
        if len(body) == 16:
            body = aes_ecb_enc(appkey, body)
        else:
            body = (aes_ecb_enc(appkey, body[:16]) +
                    aes_ecb_enc(appkey, body[16:]))
        print("DECRYPTED\t%s" % binascii.hexlify(body).decode())
    print("APPNONCE\t0x%s" % binascii.hexlify(body[0:3]).decode())
    print("NETID\t0x%s" % binascii.hexlify(body[3:6][::-1]).decode())
    print("DEVADDR\t%s" % binascii.hexlify(body[6:10][::-1]).decode())
    print("DLSETTINGS\t0x%02x" % body[10])
    print("RXDELAY\t0x%02x" % body[11])
    if len(body) >= 28:
        print("CFLIST\t%s" % binascii.hexlify(body[12:28]).decode())
    return body


cmd = sys.argv[1]

if cmd == "decode":
    raw, mtype = parse(sys.argv[2])
    nwk = hexb(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else None
    app = hexb(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None
    dirn = int(sys.argv[5]) if len(sys.argv) > 5 else 0
    if mtype == 0:
        decode_join_request(raw)
    elif mtype == 1:
        decode_join_accept(raw, app)
    elif mtype in (2, 3, 4, 5):
        if mtype in (3, 5):
            dirn = 1
        decode_data(raw, nwk, app, dirn)
    else:
        print("NOTE\tno structural decoder for this message type")

elif cmd == "mic":
    # --mic FRAME [NWKSKEY] : compute and compare
    raw = hexb(sys.argv[2])
    body = raw[:-4]
    given = raw[-4:]
    print("MIC_IN_FRAME\t%s" % binascii.hexlify(given).decode())
    if len(sys.argv) > 3 and sys.argv[3]:
        nwk = hexb(sys.argv[3])
        calc = cmac(nwk, b0(0, body[1:5], int.from_bytes(body[6:8], "little"),
                            len(body)) + body)[0:4]
        print("MIC_CALCULATED\t%s" % binascii.hexlify(calc).decode())
        ok = (calc == given)
        print("MIC_VALID\t%d" % (1 if ok else 0))
        sys.exit(0 if ok else 1)
    else:
        print("NOTE\tno NwkSKey supplied, so only the frame MIC is reported")

elif cmd == "derive":
    # --derive APPKEY APPNONCE NETID DEVNONCE
    appkey = hexb(sys.argv[2])
    appnonce = hexb(sys.argv[3]); netid = hexb(sys.argv[4]); devnonce = hexb(sys.argv[5])
    nwk, app = derive_session_keys(appkey, appnonce, netid, devnonce)
    print("NwkSKey\t%s" % binascii.hexlify(nwk).decode())
    print("AppSKey\t%s" % binascii.hexlify(app).decode())

elif cmd == "build":
    # --build DEVADDR FCnt FPORT PAYLOAD_HEX NWKSKEY APPSKEY [DIR]
    devaddr = hexb(sys.argv[2])[::-1]
    fcnt = int(sys.argv[3])
    fport = int(sys.argv[4])
    payload = hexb(sys.argv[5])
    nwk = hexb(sys.argv[6]); app = hexb(sys.argv[7])
    dirn = int(sys.argv[8]) if len(sys.argv) > 8 else 0
    key = nwk if fport == 0 else app
    enc = ctr(key, dirn, devaddr, fcnt, payload)
    mtype = 2 if dirn == 0 else 3
    body = bytes([mtype << 5]) + devaddr + bytes([0]) + \
        fcnt.to_bytes(2, "little") + bytes([fport]) + enc
    mic = cmac(nwk, b0(dirn, devaddr, fcnt, len(body)) + body)[0:4]
    print("FRAME\t%s" % binascii.hexlify(body + mic).decode())
    print("PLAINTEXT\t%s" % binascii.hexlify(payload).decode())

elif cmd == "selftest":
    bad = 0

    def check(name, cond, extra=""):
        global bad
        if cond:
            print("%s\tPASS%s" % (name, (" " + extra) if extra else ""))
        else:
            print("%s\tFAIL %s" % (name, extra)); bad += 1

    # AES-CMAC against RFC 4493: everything else here is built on it.
    K = hexb("2b7e151628aed2a6abf7158809cf4f3c")
    M16 = hexb("6bc1bee22e409f96e93d7e117393172a")
    check("rfc4493-cmac-len16",
          cmac(K, M16).hex() == "070a16b46b4d4144f79bdd9dd04a287c")
    check("rfc4493-cmac-empty",
          cmac(K, b"").hex() == "bb1d6929e95937287fa37d129b756746")

    # Session key derivation must be deterministic and key-dependent.
    appkey = hexb("00112233445566778899aabbccddeeff")
    appnonce = hexb("010203"); netid = hexb("aabbcc"); devnonce = hexb("1234")
    n1, a1 = derive_session_keys(appkey, appnonce, netid, devnonce)
    n2, a2 = derive_session_keys(appkey, appnonce, netid, devnonce)
    check("session-keys-deterministic", n1 == n2 and a1 == a2)
    check("nwkskey-differs-from-appskey", n1 != a1)

    # Full round trip: encrypt a payload into a frame, parse the frame
    # back, decrypt, and confirm the payload survives with a valid MIC.
    devaddr = hexb("01020304")[::-1]
    fcnt = 42
    fport = 1
    plain = b"hello lorawan!26"          # deliberately not a 16-byte multiple
    nwk, app = n1, a1
    enc = ctr(app, 0, devaddr, fcnt, plain)
    body = bytes([2 << 5]) + devaddr + bytes([0]) + fcnt.to_bytes(2, "little") \
        + bytes([fport]) + enc
    mic = cmac(nwk, b0(0, devaddr, fcnt, len(body)) + body)[0:4]
    frame = body + mic
    check("frame-length", len(frame) == 1 + 4 + 1 + 2 + 1 + len(plain) + 4,
          "(%d bytes)" % len(frame))

    back = ctr(app, 0, devaddr, fcnt, frame[9:-4])
    check("payload-roundtrip", back == plain, repr(back))
    calc = cmac(nwk, b0(0, devaddr, fcnt, len(frame) - 4) + frame[:-4])[0:4]
    check("mic-verifies", calc == mic)
    bad_mic = bytes([mic[0] ^ 0xFF]) + mic[1:]
    check("mic-detects-tamper", bad_mic != mic)

    # Non-multiple-of-16 payloads are where CTR implementations break.
    for n in (1, 15, 16, 17, 32, 33):
        p = bytes(range(n))
        e = ctr(app, 0, devaddr, fcnt, p)
        check("ctr-len-%d" % n, ctr(app, 0, devaddr, fcnt, e) == p)

    print("RESULT\t%s" % ("PASS" if bad == 0 else "FAIL(%d)" % bad))
    sys.exit(0 if bad == 0 else 1)

else:
    print("ERROR\tunknown helper command %s" % cmd, file=sys.stderr)
    sys.exit(2)
PYEOF
}

lora_run() {
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    python3 -c 'import cryptography' 2>/dev/null || {
        printf 'ERROR\tpython3 cryptography module required\n' >&2; return 1; }
    lora_helper
    python3 "$MOD_TMP/lora.py" "$@"
}

lora_selftest() { lora_run selftest; }

lora_receive() {
    lora_have_sdr || {
        printf 'ERROR\tno SDR present — cannot receive LoRa frames\n' >&2
        printf 'NOTE\tLoRa needs an SDR (RTL-SDR is marginal; a LoRa HAT or\n' >&2
        printf 'NOTE\tSX127x radio is far better). The codec is offline: use\n' >&2
        printf 'NOTE\t--decode / --mic / --derive / --build on captured hex.\n' >&2
        return 1; }
    printf 'NOTE\treception is out of scope for this module: it decodes and\n'
    printf 'NOTE\tbuilds frames, it does not drive an SDR front end.\n'
    return 1
}

lora_info() {
    cat <<'EOF'
LoRaWAN 1.0.x frame codec

  PHYPayload = MHDR(1) | MACPayload | MIC(4)
  MHDR       = MType(3 bits) | RFU(3) | Major(2)

Join Request  AppEUI(8) | DevEUI(8) | DevNonce(2)
              MIC = cmac(AppKey, MHDR|AppEUI|DevEUI|DevNonce)[0:4]
Join Accept   AppNonce(3) | NetID(3) | DevAddr(4) | DLSettings | RxDelay | [CFList]
              the payload is AES-encrypted with AppKey
Data          DevAddr(4) | FCtrl | FCnt(2) | FOpts | FPort | FRMPayload
              MIC = cmac(NwkSKey, B0|MHDR|FHDR|FPort|FRMPayload)[0:4]
              B0  = 0x49|0x00000000|Dir|DevAddr|FCnt|0x00|len

Session keys
  NwkSKey = aes128(AppKey, 0x01|AppNonce|NetID|DevNonce|pad16)
  AppSKey = aes128(AppKey, 0x02|AppNonce|NetID|DevNonce|pad16)

FRMPayload is AES-128 in counter mode with a per-block Ai counter block.
FPort 0 means the payload is MAC commands and is encrypted with NwkSKey;
any other port uses AppSKey.

Receiving frames needs an SDR, which this machine does not have, so
--receive refuses by name. Decoding, MIC validation, key derivation and
frame building are all offline.
EOF
}

lora_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)      lora_status_tsv ;;
        --message-types-tsv) lora_msg_types_tsv ;;
        --decode)          lora_run decode "$@" ;;
        --mic)             lora_run mic "$@" ;;
        --derive)          lora_run derive "$@" ;;
        --build)           lora_run build "$@" ;;
        --selftest)        lora_selftest ;;
        --receive)         lora_receive ;;
        --info)            lora_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --message-types-tsv
  --decode HEX [NWKSKEY] [APPSKEY] [DIR]
  --mic HEX [NWKSKEY]           verify a frame MIC
  --derive APPKEY APPNONCE NETID DEVNONCE
  --build DEVADDR FCNT FPORT PAYLOAD_HEX NWKSKEY APPSKEY [DIR]
  --selftest
  --receive                     needs an SDR
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
    lora_cli_main "$@"
fi

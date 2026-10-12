#!/usr/bin/env bash
# 24_bt_mesh.sh — BLE Mesh enumeration, sniffing, provisioning capture
# hardware: nRF52840 + btlejack, or nRF Sniffer (Wireshark) capture file
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
: "${LOGS_DIR:=$HOME/wifisting/logs}"
: "${WIFISTING_HOME:=$HOME/wifisting}"
: "${WIFISTING_ROOT:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" 2>/dev/null

MESH_DIR="$TMP_DIR/bt_mesh"
MESH_LOOT="$LOOT_DIR/bt_mesh"
MOD_TMP="$TMP_DIR/bt_mesh"
mkdir -p "$MESH_DIR" "$MESH_LOOT" "$MOD_TMP"

# ── hardware detection ──
mesh_detect_hw() {
    local found="none"
    if command -v lsusb >/dev/null 2>&1; then
        if lsusb 2>/dev/null | grep -qiE '1915:52|1915:82|239a:80'; then
            found="nrf52840"
        elif lsusb 2>/dev/null | grep -qiE '1915:0102|1915:7777'; then
            found="crazyradio"
        fi
    fi
    printf '%s' "$found"
}

mesh_check_deps() {
    local missing=()
    for c in btlejack nrfutil; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    if (( ${#missing[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${missing[*]}")"
        return 1
    fi
    printf 'READY\n'
}

mesh_status_tsv() {
    local deps=0
    mesh_check_deps >/dev/null 2>&1 && deps=1
    local hw
    hw=$(mesh_detect_hw)

    local sessions=0
    [[ -d "$MESH_LOOT" ]] && sessions=$(find "$MESH_LOOT" -maxdepth 1 -type d 2>/dev/null | wc -l)
    (( sessions > 0 )) && sessions=$((sessions - 1))

    printf 'deps_ok\t%s\n'    "$deps"
    printf 'hardware\t%s\n'   "$hw"
    printf 'sessions\t%s\n'   "$sessions"
    printf 'loot\t%s\n'       "$MESH_LOOT"
    printf 'tools\t%s\n'      "$(mesh_tools_available | tr '\n' ',' | sed 's/,$//')"
}

mesh_tools_available() {
    for t in btlejack nrfutil tshark wireshark tshark-dumpcap; do
        command -v "$t" >/dev/null 2>&1 && echo "$t"
    done
}

# ── Mesh beacon parser ──
# BLE Mesh beacons (Network ID, Node Identity, Unprovisioned Device Beacon)
# use specific AD types:
#   0x2B = Mesh Beacon
#   0x2A = Mesh Provisioning Service UUID
#   0x29 = Mesh Proxy Service UUID
# Mesh Beacon payload starts with a byte identifying beacon type:
#   0x00 = Unprovisioned Device Beacon
#   0x01 = Secure Network Beacon
#   0x02 = Mesh Private Beacon (obfuscated)
mesh_parse_beacon() {
    local hex="$1"
    # hex is the AD payload after the type byte, e.g. "01xxxxxxxx..."

    [[ -z "$hex" ]] && return 1

    local type_byte="${hex:0:2}"
    case "$type_byte" in
        00)
            # Unprovisioned Device Beacon: 16-byte UUID + 2-byte OOB + 4-byte URI hash
            local uuid="${hex:2:32}"
            printf 'BEACON_TYPE\tunprovisioned\n'
            printf 'DEVICE_UUID\t%s\n' "$uuid"
            ;;
        01)
            # Secure Network Beacon: Network ID (8) + IV index (4) + flags (1) + auth (8)
            local net_id="${hex:2:16}"
            local iv="${hex:18:8}"
            printf 'BEACON_TYPE\tsecure_network\n'
            printf 'NETWORK_ID\t%s\n' "$net_id"
            printf 'IV_INDEX\t%s\n'   "$iv"
            ;;
        02)
            printf 'BEACON_TYPE\tprivate (obfuscated)\n'
            ;;
        *)
            printf 'BEACON_TYPE\tunknown(%s)\n' "$type_byte"
            ;;
    esac
}

# ── passive Mesh sniff via hcitool + parsing ──
mesh_sniff_beacons() {
    local dur="${1:-30}"
    local iface
    iface=$(hciconfig 2>/dev/null | awk '/^hci[0-9]+:/{print $1}' | tr -d ':' | head -1)
    [[ -z "$iface" ]] && { printf 'ERROR\tno hci iface\n' >&2; return 1; }

    command -v hcitool >/dev/null || { printf 'ERROR\tno hcitool\n' >&2; return 1; }

    local ts out
    ts=$(date +%Y%m%d_%H%M%S)
    out="$MESH_LOOT/sniff_${ts}.log"

    info "passive Mesh beacon sniff on $iface for ${dur}s → $out"

    # lescan --passive gives us raw adv data. Some hcitool builds only
    # print MAC + name; the raw payload needs -d (dump).
    if hcitool --help 2>&1 | grep -q '\-\-duplicates'; then
        timeout "$dur" hcitool -i "$iface" lescan --passive --duplicates 2>&1 | \
            tee "$out" | head -200
    else
        timeout "$dur" hcitool -i "$iface" lescan --passive 2>&1 | \
            tee "$out" | head -200
    fi

    # Count Mesh-looking devices
    local mesh_hits
    mesh_hits=$(grep -c "Mesh\|2b\|0x2b" "$out" 2>/dev/null || echo 0)

    printf 'LOG\t%s\n' "$out"
    printf 'MESH_HITS\t%s\n' "$mesh_hits"
}

# ── btlejack capture (nRF52840 required) ──
mesh_start_capture() {
    local dur="${1:-30}"
    command -v btlejack >/dev/null 2>&1 || {
        printf 'ERROR\tbtlejack not installed\n' >&2
        printf 'HINT\tpip install btlejack\n' >&2
        return 1
    }

    local hw
    hw=$(mesh_detect_hw)
    [[ "$hw" != "nrf52840" ]] && {
        printf 'ERROR\tno nRF52840 detected (found: %s)\n' "$hw" >&2
        printf 'HINT\tplug in nRF52840 with btlejack firmware\n' >&2
        return 1
    }

    local ts session_dir
    ts=$(date +%Y%m%d_%H%M%S)
    session_dir="$MESH_LOOT/$ts"
    mkdir -p "$session_dir"

    info "btlejack capture for ${dur}s → $session_dir"

    # btlejack -c any = sniff all BLE channels
    timeout "$dur" btlejack -c any -o "$session_dir/capture.log" 2>&1 | \
        tee "$session_dir/btlejack.stdout" | tail -40

    if [[ -s "$session_dir/capture.log" ]]; then
        # Parse the capture for Mesh beacons
        mesh_parse_capture_file "$session_dir/capture.log" > "$session_dir/beacons.tsv"
        local beacons
        beacons=$(wc -l < "$session_dir/beacons.tsv")
        printf 'SESSION\t%s\n' "$session_dir"
        printf 'BEACONS\t%s\n' "$beacons"
    else
        printf 'ERROR\tcapture empty\n' >&2
        return 1
    fi
}

# ── parse a btlejack capture for Mesh beacon AD structures ──
mesh_parse_capture_file() {
    local cap="$1"
    [[ ! -f "$cap" ]] && return 1

    printf 'TYPE\tUUID_OR_NETID\tIV_OR_OOB\n'

    # btlejack output includes hex dumps. Look for AD type 0x2b sequences
    # Format varies; this is best-effort.
    grep -oE '2b[0-9a-fA-F]+' "$cap" 2>/dev/null | while read -r hexline; do
        local payload="${hexline:2}"
        [[ ${#payload} -lt 4 ]] && continue

        local type_byte="${payload:0:2}"
        case "$type_byte" in
            00)
                # unprovisioned
                printf 'unprovisioned\t%s\t\n' "${payload:2:32}"
                ;;
            01)
                printf 'secure_network\t%s\t%s\n' \
                    "${payload:2:16}" "${payload:18:8}"
                ;;
            *)
                printf 'unknown_%s\t%s\t\n' "$type_byte" "${payload:2:32}"
                ;;
        esac
    done | sort -u
}

# ── provisioning PDU capture ──
# Mesh provisioning happens over GATT. The Provisioning PDU sequence:
#   Invite → Capabilities → Start → Public Key → Confirmation → Random → Data → Complete
# We need to connect to the unprovisioned device GATT server, subscribe to
# the Provisioning Data In/Out characteristics, and log the PDUs.
mesh_capture_provisioning() {
    local target_mac="$1"
    local dur="${2:-60}"

    [[ -z "$target_mac" ]] && {
        printf 'ERROR\tdevice MAC required (from sniff)\n' >&2; return 1
    }
    command -v gatttool >/dev/null || {
        printf 'ERROR\tgatttool not installed (bluez-deprecated-tools)\n' >&2
        return 1
    }

    local ts out
    ts=$(date +%Y%m%d_%H%M%S)
    out="$MESH_LOOT/prov_${target_mac//:/}_${ts}.log"

    info "connecting to $target_mac GATT — Mesh Provisioning Service 0x1827"
    info "logging all notifications from Provisioning Data OUT char 0x2adb"

    # Provisioning Service UUID 0x1827
    # Data In UUID 0x2adb, Data Out UUID 0x2adc
    # We need to enable notifications on Data Out, then dump raw PDUs.
    {
        echo "== Mesh Provisioning capture =="
        echo "target: $target_mac"
        echo "date:   $(date -Is)"
        echo
        echo "-- primary services --"
        timeout 8 gatttool -b "$target_mac" --primary 2>&1

        echo
        echo "-- provisioning service --"
        timeout 8 gatttool -b "$target_mac" --primary --uuid 00001827-0000-1000-8000-00805f9b34fb 2>&1

        echo
        echo "-- characteristics --"
        timeout 10 gatttool -b "$target_mac" --characteristics 2>&1

        echo
        echo "-- attempting to read Data Out char (2adc) --"
        timeout 5 gatttool -b "$target_mac" --char-read --uuid 00002adc-0000-1000-8000-00805f9b34fb 2>&1
    } | tee "$out"

    # For deep PDU capture you need `btmgmt mesh-*` or BlueZ mesh-cfgclient,
    # which is out of scope for this module. Point the user at the workflow.
    printf 'LOG\t%s\n' "$out"
    printf 'HINT\tfor PDU-level capture use BlueZ mesh-cfgclient or nRF Mesh app\n'
}

# ── Mesh network key extraction from a pcap ──
mesh_extract_keys() {
    local cap="$1"
    [[ -z "$cap" || ! -f "$cap" ]] && { printf 'ERROR\tno pcap\n' >&2; return 1; }

    command -v tshark >/dev/null || { printf 'ERROR\tno tshark\n' >&2; return 1; }

    info "extracting Mesh keys from $cap"

    # Network keys appear in Secure Network Beacons (encrypted) or in the
    # provisioning exchange (Transport Key PDU = 0x04).
    # tshark can parse BLE + Mesh with a Wireshark profile.
    tshark -r "$cap" -Y 'btmesh.provisioning.pdu.type == 0x04' \
        -T fields -e frame.number -e btmesh.provisioning.net_key 2>/dev/null | \
        awk 'NF { print "KEY\t" $0 }'

    # If tshark can't parse it, fall back to strings-like search
    if ! tshark -r "$cap" -Y 'btmesh' 2>/dev/null | grep -q .; then
        printf 'HINT\ttshark cannot parse Mesh here — export via btlejack --json\n'
    fi
}

# ── Mesh network analysis: beacons + IV index tracking ──
mesh_analyze_beacons() {
    local log="$1"
    [[ -z "$log" || ! -f "$log" ]] && { printf 'ERROR\tno log\n' >&2; return 1; }

    info "parsing Mesh beacons from $log"
    local nets=""
    local count=0

    # grep -oE '2b[0-9a-fA-F]+' picks every AD 0x2b byte run
    while read -r hexline; do
        local parsed
        parsed=$(mesh_parse_beacon "${hexline:2}")
        local net_id
        net_id=$(echo "$parsed" | awk -F'\t' '/NETWORK_ID/{print $2}')
        if [[ -n "$net_id" ]]; then
            printf 'NET\t%s\n' "$net_id"
            nets="$nets $net_id"
            count=$((count+1))
        fi
    done < <(grep -oE '2b[0-9a-fA-F]+' "$log" 2>/dev/null)

    printf 'TOTAL_BEACONS\t%s\n' "$count"
    [[ -n "$nets" ]] && printf 'UNIQUE_NETS\t%s\n' \
        "$(echo "$nets" | tr ' ' '\n' | sort -u | wc -l)"
}

# ── sessions ──
mesh_list_sessions_tsv() {
    local d
    for d in "$MESH_LOOT"/*/; do
        [[ -d "$d" ]] || continue
        local name
        name=$(basename "$d")
        local size
        size=$(du -sb "$d" 2>/dev/null | awk '{print $1}')
        printf '%s\t%s\t%s\n' "$name" "${size:-0}" "$d"
    done
}

mesh_info() {
    cat <<'INFO'
BLE Mesh attack surface:
  • Network key extraction from a provisioned node's flash (needs physical)
  • Provisioning PDU capture (public key exchange → ECDH shared secret)
  • Replay of provisioner commands to add a malicious node
  • Friend / Low-Power node hijacking (relay proxy attack)
  • GATT proxy abuse — MitM between node and proxy
  • IV index manipulation — replay old encrypted packets

Provisioning PDU sequence (encrypted after Public Key):
  Invite(0x00) Capabilities(0x01) Start(0x02) PublicKey(0x03)
  Confirmation(0x05) Random(0x06) Data(0x07) Complete(0x08)

If you can capture the full provisioning exchange AND you're within RF
range during the exchange, you can derive the network key without ever
touching the device. Requires precise timing and the right dongle.

Hardware:
  • nRF52840 dongle (pca10059) — btlejack firmware, or nRF Sniffer
  • Two dongles for active MitM

Software:
  • btlejack       — pip install btlejack
  • nRF Sniffer    — Wireshark plugin + Nordic firmware
  • BlueZ mesh-cfgclient — for provisioning capture
  • Wireshark 3.6+ — parses btmesh from nRF Sniffer captures

Setup:
  1. Flash btlejack firmware:
       nrfutil pkg generate --hw-version 52 --sd-req 0x00 \
         --application btlejack.hex --application-version 1 btlejack.zip
       nrfutil dfu usb-serial -pkg btlejack.zip -p /dev/ttyACM0
  2. Plug in. `btlejack -d` should list it.
  3. Or use nRF Sniffer + Wireshark to get a pcap, then load in this module.
INFO
}

# ── dispatch ──
# ── Provision (merged from bt_mesh_provision, submenu: Provision) ────────
# The provisioner side of the Bluetooth Mesh provisioning protocol
# (Mesh Profile 1.0.1 §5.4.2). This is pure protocol crypto: it needs no
# radio until the PDUs are actually put on the air, so the key agreement
# below is fully usable and testable without a mesh-capable dongle.
#
#   s1(M)          = AES-CMAC(0x00 * 16, M)
#   k1(N, SALT, P) = AES-CMAC(AES-CMAC(SALT, N), P)
#
#   ConfirmationSalt = s1(InvitePDU || StartPDU)
#   ConfirmationKey  = k1(ECDHSecret, ConfirmationSalt, "prck")
#   ConfirmValue     = AES-CMAC(ConfirmationKey, Random || AuthValue)
#   ProvisioningSalt = s1(ConfirmationSalt || RandomProv || RandomDev)
#   SessionKey       = k1(ECDHSecret, ProvisioningSalt, "prsk")
#   SessionNonce     = k1(ECDHSecret, ProvisioningSalt, "prsn")
#   DeviceKey        = k1(ECDHSecret, ProvisioningSalt, "prdk")

MESH_PROV_DIR="$MESH_DIR/prov"
MESH_PROV_PY="$MESH_PROV_DIR/prov.py"

# The crypto lives in one python helper rather than being re-inlined into
# every verb, so the primitives exist in exactly one place.
mesh_prov_helper() {
    mkdir -p "$MESH_PROV_DIR" 2>/dev/null
    cat > "$MESH_PROV_PY" <<'PYEOF'
import sys

try:
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    from cryptography.hazmat.primitives.asymmetric import ec
except Exception as e:                                    # pragma: no cover
    print("ERROR\tpython cryptography module missing: %s" % e, file=sys.stderr)
    sys.exit(2)

K0 = b"\x00" * 16

def cmac(key: bytes, msg: bytes) -> bytes:
    c = CMAC(algorithms.AES(key)); c.update(msg); return c.finalize()

def s1(m: bytes) -> bytes:
    return cmac(K0, m)

def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    return cmac(cmac(salt, n), p)

def hexb(s: str) -> bytes:
    """Hex -> bytes, failing with a clean message rather than a traceback."""
    try:
        return bytes.fromhex("".join(s.split()).replace(":", ""))
    except ValueError:
        print("ERROR\tnot valid hex: %r" % s, file=sys.stderr)
        sys.exit(1)

def out(k, v):
    print("%s\t%s" % (k, v))

cmd = sys.argv[1]

if cmd == "keygen":
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.private_numbers().private_value
    pub = priv.public_key().public_numbers()
    out("PRIV", "%064x" % nums)
    out("PUB_X", "%064x" % pub.x)
    out("PUB_Y", "%064x" % pub.y)
    out("PUB", "%064x%064x" % (pub.x, pub.y))

elif cmd == "ecdh":
    priv = int(sys.argv[2], 16)
    peer = hexb(sys.argv[3])
    if len(peer) != 64:
        print("ERROR\tpeer public key must be 64 bytes of X||Y hex", file=sys.stderr)
        sys.exit(1)
    key = ec.derive_private_key(priv, ec.SECP256R1())
    pn = ec.EllipticCurvePublicNumbers(
        int.from_bytes(peer[:32], "big"), int.from_bytes(peer[32:], "big"),
        ec.SECP256R1())
    secret = key.exchange(ec.ECDH(), pn.public_key())
    out("ECDH", secret.hex())

elif cmd == "session":
    # ECDH INVITE START RAND_PROV RAND_DEV AUTH
    ecdh = hexb(sys.argv[2])
    invite = hexb(sys.argv[3])
    start = hexb(sys.argv[4])
    rp = hexb(sys.argv[5])
    rd = hexb(sys.argv[6])
    auth = hexb(sys.argv[7]) if len(sys.argv) > 7 else b""

    csalt = s1(invite + start)
    ckey = k1(ecdh, csalt, b"prck")
    cv_prov = cmac(ckey, rp + auth)
    cv_dev = cmac(ckey, rd + auth)
    psalt = s1(csalt + rp + rd)
    skey = k1(ecdh, psalt, b"prsk")
    snonce = k1(ecdh, psalt, b"prsn")
    dkey = k1(ecdh, psalt, b"prdk")

    out("CONFIRMATION_SALT", csalt.hex())
    out("CONFIRMATION_KEY", ckey.hex())
    out("CONFIRM_VALUE_PROV", cv_prov.hex())
    out("CONFIRM_VALUE_DEV", cv_dev.hex())
    out("PROVISIONING_SALT", psalt.hex())
    out("SESSION_KEY", skey.hex())
    out("SESSION_NONCE", snonce.hex())
    # AES-CCM takes a 13-octet nonce; the spec derives 16 and uses the
    # leading 13. Reported explicitly so the convention is never implicit.
    out("CCM_NONCE", snonce[:13].hex())
    out("DEVICE_KEY", dkey.hex())

elif cmd == "encrypt":
    # SESSION_KEY CCM_NONCE NETKEY KEYIDX FLAGS IVIDX
    skey = hexb(sys.argv[2])
    nonce = hexb(sys.argv[3])
    netkey = hexb(sys.argv[4])
    keyidx = int(sys.argv[5], 0)
    flags = int(sys.argv[6], 0)
    ividx = int(sys.argv[7], 0)
    if len(netkey) != 16:
        print("ERROR\tnetwork key must be 16 bytes", file=sys.stderr); sys.exit(1)
    if len(nonce) != 13:
        print("ERROR\tCCM nonce must be 13 bytes", file=sys.stderr); sys.exit(1)
    plain = (netkey + keyidx.to_bytes(2, "big") + bytes([flags & 0xFF])
             + ividx.to_bytes(4, "big"))
    pdu = AESCCM(skey, tag_length=8).encrypt(nonce, plain, None)
    out("PLAINTEXT", plain.hex())
    out("PROVISIONING_DATA", pdu.hex())
    out("PDU_LEN", str(len(pdu)))

elif cmd == "decrypt":
    skey = hexb(sys.argv[2]); nonce = hexb(sys.argv[3]); pdu = hexb(sys.argv[4])
    try:
        plain = AESCCM(skey, tag_length=8).decrypt(nonce, pdu, None)
    except Exception:
        out("VALID", "0"); sys.exit(1)
    out("VALID", "1")
    out("NETWORK_KEY", plain[0:16].hex())
    out("KEY_INDEX", str(int.from_bytes(plain[16:18], "big")))
    out("FLAGS", str(plain[18]))
    out("IV_INDEX", str(int.from_bytes(plain[19:23], "big")))

elif cmd in ("selftest", "selftest-checks"):
    # RFC 4493 AES-CMAC known-answer vectors — everything else in the mesh
    # KDF is built on this one primitive, so it is pinned first.
    K = hexb("2b7e151628aed2a6abf7158809cf4f3c")
    M16 = hexb("6bc1bee22e409f96e93d7e117393172a")
    M40 = M16 + hexb("ae2d8a571e03ac9c9eb76fac45af8e51" "30c81c46a35ce411")
    M64 = M40 + hexb("e5fbc1191a0a52eff69f2445df4f9b17" "ad2b417be66c3710")
    vecs = [("rfc4493-len0", b"", "bb1d6929e95937287fa37d129b756746"),
            ("rfc4493-len16", M16, "070a16b46b4d4144f79bdd9dd04a287c"),
            ("rfc4493-len40", M40, "dfa66747de9ae63030ca32611497c827"),
            ("rfc4493-len64", M64, "51f0bebf7e3b9d92fc49741779363cfe")]
    bad = 0
    for name, msg, want in vecs:
        got = cmac(K, msg).hex()
        ok = (got == want)
        bad += 0 if ok else 1
        out(name, "PASS" if ok else "FAIL want=%s got=%s" % (want, got))

    # Round-trip: derive a session, seal the provisioning data, open it,
    # and confirm every field survives.
    ecdh = bytes(range(32))
    csalt = s1(hexb("0000") + hexb("00000000010001"))
    psalt = s1(csalt + b"\x11" * 16 + b"\x22" * 16)
    skey = k1(ecdh, psalt, b"prsk")
    nonce = k1(ecdh, psalt, b"prsn")[:13]
    netkey = bytes(range(16, 32))
    plain = netkey + (0x0A).to_bytes(2, "big") + bytes([0]) + (0x01020304).to_bytes(4, "big")
    pdu = AESCCM(skey, tag_length=8).encrypt(nonce, plain, None)
    back = AESCCM(skey, tag_length=8).decrypt(nonce, pdu, None)
    rt = (back == plain)
    bad += 0 if rt else 1
    out("roundtrip-encrypt-decrypt", "PASS" if rt else "FAIL")
    out("pdu_len", "PASS (%d-byte PDU)" % len(pdu))

    # A tampered PDU must fail authentication rather than decrypt to
    # garbage that then gets used as a network key.
    tampered = bytes([pdu[0] ^ 0x01]) + pdu[1:]
    try:
        AESCCM(skey, tag_length=8).decrypt(nonce, tampered, None)
        auth = False
    except Exception:
        auth = True
    bad += 0 if auth else 1
    out("ccm-rejects-tampered-pdu", "PASS" if auth else "FAIL")

    # k1 must depend on all three inputs.
    a = k1(ecdh, psalt, b"prsk"); b = k1(ecdh, psalt, b"prsn")
    d = (a != b)
    bad += 0 if d else 1
    out("k1-input-separation", "PASS" if d else "FAIL")

    # s1/k1 are deterministic and key-dependent; a KDF that ignored its
    # salt or its "P" string would still pass a round trip, so both are
    # pinned separately here.
    det = (s1(b"mesh") == s1(b"mesh") and k1(ecdh, psalt, b"prsk") == a)
    bad += 0 if det else 1
    out("kdf-deterministic", "PASS" if det else "FAIL")
    sep = (s1(b"mesh") != s1(b"mesg") and k1(ecdh, csalt, b"prsk") != a)
    bad += 0 if sep else 1
    out("kdf-input-separation", "PASS" if sep else "FAIL")
    ln = (len(s1(b"mesh")) == 16 and len(k1(ecdh, psalt, b"prsk")) == 16
          and len(k1(ecdh, psalt, b"prsn")[:13]) == 13)
    bad += 0 if ln else 1
    out("kdf-widths", "PASS" if ln else "FAIL")

    if cmd == "selftest":
        out("RESULT", "PASS" if bad == 0 else "FAIL(%d)" % bad)
    sys.exit(0 if bad == 0 else 1)

else:
    print("ERROR\tunknown helper command %s" % cmd, file=sys.stderr)
    sys.exit(2)
PYEOF
}

mesh_prov_run() {
    command -v python3 >/dev/null 2>&1 || {
        printf 'ERROR\tpython3 required\n' >&2; return 1; }
    python3 -c 'import cryptography' 2>/dev/null || {
        printf 'ERROR\tpython3 cryptography module required (apt install python3-cryptography)\n' >&2
        return 1; }
    mesh_prov_helper
    python3 "$MESH_PROV_PY" "$@"
}

mesh_prov_status_tsv() {
    local py=0 radio=0
    python3 -c 'import cryptography' 2>/dev/null && py=1
    lsusb 2>/dev/null | grep -qiE '1915:|0451:' && radio=1
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'cryptography\t%s\n' "$py"
    printf 'mesh_radio\t%s\n' "$radio"
    # The crypto half is always available; only the over-the-air half needs
    # a dongle, and the GUI names that explicitly instead of hiding a button.
    printf 'key_agreement\t%s\n' "$py"
    printf 'over_the_air\t%s\n' "$radio"
}

mesh_prov_keygen() {
    mkdir -p "$MESH_LOOT" 2>/dev/null
    local res
    res=$(mesh_prov_run keygen) || return 1
    printf '%s\n' "$res"
    local priv
    priv=$(printf '%s\n' "$res" | awk -F'\t' '$1 == "PRIV" { print $2 }')
    if [[ -n "$priv" ]]; then
        local f="$MESH_LOOT/prov_key_$(date +%s).txt"
        ( umask 077; printf '%s\n' "$res" > "$f" )
        printf 'SAVED\t%s\n' "$f"
    fi
}

mesh_prov_ecdh() {
    [[ $# -lt 2 ]] && {
        printf 'ERROR\tusage: --prov-ecdh PRIV_HEX PEER_PUB_HEX\n' >&2
        return 2; }
    mesh_prov_run ecdh "$@"
}

mesh_prov_session() {
    [[ $# -lt 5 ]] && {
        printf 'ERROR\tusage: --prov-session ECDH INVITE START RAND_PROV RAND_DEV [AUTH]\n' >&2
        return 2; }
    mesh_prov_run session "$@"
}

mesh_prov_encrypt() {
    [[ $# -lt 6 ]] && {
        printf 'ERROR\tusage: --prov-encrypt SESSION_KEY CCM_NONCE NETKEY KEYIDX FLAGS IVIDX\n' >&2
        return 2; }
    mesh_prov_run encrypt "$@"
}

mesh_prov_decrypt() {
    [[ $# -lt 3 ]] && {
        printf 'ERROR\tusage: --prov-decrypt SESSION_KEY CCM_NONCE PDU\n' >&2
        return 2; }
    mesh_prov_run decrypt "$@"
}

mesh_prov_selftest() {
    mesh_prov_run selftest
}

# ── self-test ────────────────────────────────────────────────────────────
# The beacon parser and the btlejack capture parser are pure text handling,
# so they are checked offline against synthetic input. The provisioning
# crypto (RFC 4493 KAT, CCM round trip, tamper rejection) is delegated to
# the python helper and folded into the same check stream, so this command
# still ends with exactly one RESULT line.
mesh_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld()  { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcof() { "$@" >/dev/null 2>&1; echo $?; }

    local d out rc line nchk
    # Unique per run: a second selftest (runner alongside a manual run)
    # must not share scratch files.
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }

    # 1. Beacon parser: type-byte dispatch and the field offsets inside the
    #    AD payload. A wrong offset silently yields a plausible-looking UUID.
    out=$(mesh_parse_beacon '00aabbccddeeff00112233445566778899')
    chk beacon-unprov-type "$(fld "$out" BEACON_TYPE)" "unprovisioned"
    chk beacon-unprov-uuid "$(fld "$out" DEVICE_UUID)" "aabbccddeeff00112233445566778899"
    out=$(mesh_parse_beacon '01d1e2f3a4b5c6d70000010203')
    chk beacon-secnet-type  "$(fld "$out" BEACON_TYPE)" "secure_network"
    chk beacon-secnet-netid "$(fld "$out" NETWORK_ID)"  "d1e2f3a4b5c6d700"
    chk beacon-secnet-iv    "$(fld "$out" IV_INDEX)"    "00010203"
    out=$(mesh_parse_beacon '02deadbeef')
    chk beacon-private-type "$(fld "$out" BEACON_TYPE)" "private (obfuscated)"
    out=$(mesh_parse_beacon 'ff')
    chk beacon-unknown-type "$(fld "$out" BEACON_TYPE)" "unknown(ff)"
    chk beacon-empty-rc     "$(rcof mesh_parse_beacon '')" "1"

    # The verb goes through mesh_cli_main, which has already shifted the
    # verb off argv: a stray extra `shift` in that arm swallowed the payload
    # and made --parse-beacon always exit 1 with no output.
    out=$(mesh_cli_main --parse-beacon '01d1e2f3a4b5c6d70000010203'); rc=$?
    chk cli-parse-beacon-rc   "$rc" "0"
    chk cli-parse-beacon-type "$(fld "$out" BEACON_TYPE)"  "secure_network"
    chk cli-parse-beacon-netid "$(fld "$out" NETWORK_ID)"  "d1e2f3a4b5c6d700"
    rc=0; mesh_cli_main --parse-beacon >/dev/null 2>&1 || rc=$?
    chk cli-parse-beacon-nopayload-rc "$rc" "1"

    # 2. Capture parser: AD type 0x2b hex runs must be split into
    #    type/network-id/iv, with the unprovisioned OOB field left empty.
    printf '%s\n' 'AD type 2b: 2b0000112233445566778899aabbccddeeff' \
                  'AD type 2b: 2b01d1e2f3a4b5c6d70000010203' > "$d/cap.log"
    mesh_parse_capture_file "$d/cap.log" > "$d/beacons.tsv"
    chk capture-header "$(head -1 "$d/beacons.tsv")" "$(printf 'TYPE\tUUID_OR_NETID\tIV_OR_OOB')"
    chk capture-rows   "$(tail -n +2 "$d/beacons.tsv" | wc -l)" "2"
    chk capture-secnet "$(awk -F'\t' '$1=="secure_network"{print $2"/"$3}' "$d/beacons.tsv")" \
        "d1e2f3a4b5c6d700/00010203"
    chk capture-unprov "$(awk -F'\t' '$1=="unprovisioned"{print $2}' "$d/beacons.tsv")" \
        "00112233445566778899aabbccddeeff"
    chk capture-unprov-oob "$(awk -F'\t' '$1=="unprovisioned"{print $3}' "$d/beacons.tsv")" ""
    chk capture-missing-rc "$(rcof mesh_parse_capture_file "$d/nope.log")" "1"

    # 3. Provisioning crypto: identical checks to --prov-selftest, folded
    #    in here so one command covers the whole module. The helper is
    #    written to this run's scratch dir (not the shared MESH_PROV_PY)
    #    so two concurrent selftests cannot execute a half-written file.
    out=$(MESH_PROV_DIR="$d/prov" MESH_PROV_PY="$d/prov/prov.py" \
        mesh_prov_run selftest-checks 2>&1); rc=$?
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        printf '%s\n' "$line"
        case "$line" in *FAIL*) bad=$((bad+1)) ;; esac
    done <<< "$out"
    if (( rc != 0 )); then
        case "$out" in
            *$'\t'FAIL*) ;;   # already counted above
            *) printf 'prov-crypto-run\tFAIL helper unavailable (rc=%s)\n' "$rc"
               bad=$((bad+1)) ;;
        esac
    fi
    nchk=$(printf '%s\n' "$out" | grep -cE '	(PASS|FAIL)')
    if (( nchk < 8 )); then
        printf 'prov-crypto-checks\tFAIL only %s checks ran\n' "$nchk"; bad=$((bad+1))
    else
        printf 'prov-crypto-checks\tPASS (%s)\n' "$nchk"
    fi

    # 4. The session derivation is a pure function of its inputs: two runs
    #    with the same ECDH secret and nonces must agree, and the 13-octet
    #    CCM nonce must be the leading 13 octets of the 16-octet session
    #    nonce (the spec truncation that --prov-encrypt depends on).
    local s1out s2out
    s1out=$(MESH_PROV_DIR="$d/prov" MESH_PROV_PY="$d/prov/prov.py" mesh_prov_run session \
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        0000 00000000010001 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "")
    s2out=$(MESH_PROV_DIR="$d/prov" MESH_PROV_PY="$d/prov/prov.py" mesh_prov_run session \
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
        0000 00000000010001 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "")
    chk prov-session-deterministic "$([[ -n "$s1out" && "$s1out" == "$s2out" ]] && echo yes || echo no)" "yes"
    chk prov-session-nonce-13of16 "$(printf '%s\n' "$s1out" | awk -F'\t' '$1=="CCM_NONCE"{print $2}')" \
        "$(printf '%s\n' "$s1out" | awk -F'\t' '$1=="SESSION_NONCE"{print substr($2,1,26)}')"
    chk prov-session-nonce-len "$(printf '%s\n' "$s1out" | awk -F'\t' '$1=="CCM_NONCE"{print length($2)}')" "26"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# Full provisioner key agreement for one device, end to end: generate our
# keypair, take the device's public key, derive the session, seal a network
# key into it, and prove it opens again.
mesh_prov_plan() {
    local devpub="$1" netkey="$2" keyidx="${3:-0}" ividx="${4:-0}"
    [[ -z "$devpub" ]] && {
        printf 'ERROR\tusage: --prov-plan DEVICE_PUBKEY_HEX [NETKEY_HEX] [KEYIDX] [IVIDX]\n' >&2
        return 2; }

    local kg
    kg=$(mesh_prov_run keygen) || return 1
    local priv
    priv=$(printf '%s\n' "$kg" | awk -F'\t' '$1 == "PRIV" { print $2 }')

    local ecdh
    ecdh=$(mesh_prov_run ecdh "$priv" "$devpub" | awk -F'\t' '$1 == "ECDH" { print $2 }')
    [[ -z "$ecdh" ]] && { printf 'ERROR\tECDH failed\n' >&2; return 1; }

    # AttentionDuration 0, and the standard "PB-ADV, no OOB, no auth" start.
    local invite="00 00"
    local start="00 00 00 00 00 00"
    local rp rd
    rp=$(head -c 16 /dev/urandom | xxd -p | tr -d '\n')
    rd=$(head -c 16 /dev/urandom | xxd -p | tr -d '\n')

    local sess
    sess=$(mesh_prov_run session "$ecdh" "$invite" "$start" "$rp" "$rd" "") || return 1

    printf 'PRIV\t%s\n' "$priv"
    printf 'ECDH\t%s\n' "$ecdh"
    printf 'RAND_PROV\t%s\n' "$rp"
    printf '%s\n' "$sess"

    [[ -z "$netkey" ]] && netkey=$(head -c 16 /dev/urandom | xxd -p | tr -d '\n')
    local skey nonce
    skey=$(printf '%s\n' "$sess" | awk -F'\t' '$1 == "SESSION_KEY" { print $2 }')
    nonce=$(printf '%s\n' "$sess" | awk -F'\t' '$1 == "CCM_NONCE" { print $2 }')

    mesh_prov_run encrypt "$skey" "$nonce" "$netkey" "$keyidx" 0 "$ividx" || return 1
    printf 'NETWORK_KEY\t%s\n' "$netkey"
}

mesh_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        mesh_status_tsv ;;
        --check-deps)        mesh_check_deps ;;
        --list-sessions-tsv) mesh_list_sessions_tsv ;;
        --start-capture)     mesh_start_capture "$@" ;;
        --sniff-adv)         mesh_sniff_beacons "$@" ;;
        --sniff-beacons)     mesh_sniff_beacons "$@" ;;
        --parse-beacon)      mesh_parse_beacon "$@" ;;
        --analyze-beacons)   mesh_analyze_beacons "$@" ;;
        --capture-prov)      mesh_capture_provisioning "$@" ;;
        --extract-keys)      mesh_extract_keys "$@" ;;
        --info)              mesh_info ;;
        --prov-status-tsv)   mesh_prov_status_tsv ;;
        --prov-keygen)       mesh_prov_keygen ;;
        --prov-ecdh)         mesh_prov_ecdh "$@" ;;
        --prov-session)      mesh_prov_session "$@" ;;
        --prov-encrypt)      mesh_prov_encrypt "$@" ;;
        --prov-decrypt)      mesh_prov_decrypt "$@" ;;
        --prov-plan)         mesh_prov_plan "$@" ;;
        --prov-selftest)     mesh_prov_selftest ;;
        --selftest)          mesh_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --check-deps
  --list-sessions-tsv
  --start-capture [DURATION]            # btlejack (nRF52840)
  --sniff-beacons [DURATION]            # passive adv sniff (any HCI)
  --parse-beacon HEXPAYLOAD
  --analyze-beacons LOGFILE
  --capture-prov MAC [DURATION]         # GATT provisioning service capture
  --extract-keys PCAP
  --selftest                            beacon/capture parsers + prov crypto
  --info

Bluetooth Mesh provisioning (provisioner side, no radio needed):
  --prov-status-tsv
  --prov-selftest                        RFC 4493 KAT + round-trip
  --prov-keygen                          P-256 provisioner keypair
  --prov-ecdh PRIV PEER_PUB              ECDH shared secret
  --prov-session ECDH INVITE START RAND_PROV RAND_DEV [AUTH]
                                         derive Confirmation/Session/DeviceKey
  --prov-encrypt SESSION_KEY CCM_NONCE NETKEY KEYIDX FLAGS IVIDX
  --prov-decrypt SESSION_KEY CCM_NONCE PDU
  --prov-plan DEVICE_PUB [NETKEY] [KEYIDX] [IVIDX]
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
    mesh_cli_main "$@"
fi

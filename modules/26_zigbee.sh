#!/usr/bin/env bash
# Zigbee / 802.15.4 — sniffing, key extraction, replay, energy scan
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

ZB_DIR="$TMP_DIR/zigbee"
ZB_LOOT="$LOOT_DIR/zigbee"
ZB_KEYFILE="$ZB_DIR/keys.tsv"
MOD_TMP="$TMP_DIR/zigbee"
mkdir -p "$ZB_DIR" "$ZB_LOOT" "$MOD_TMP"
touch "$ZB_KEYFILE"

zb_detect_hw() {
    local found="none"
    if command -v lsusb >/dev/null 2>&1; then
        if lsusb 2>/dev/null | grep -qi '0451:16a8\|0451:16ae'; then
            found="cc2531"
        elif lsusb 2>/dev/null | grep -qiE '1915:52|1915:82|239a:80'; then
            found="nrf52840"
        fi
    fi
    if [[ "$found" == "none" ]]; then
        for d in /dev/ttyUSB* /dev/ttyACM*; do
            [[ -e "$d" ]] || continue
            found="serial:$d"
            break
        done
    fi
    printf '%s' "$found"
}

zb_check_tools() {
    local missing=()
    for t in killerbee zbid zbreplay zbstumbler; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if (( ${#missing[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${missing[*]}")"
        return 1
    fi
    printf 'READY\n'
}

zb_status_tsv() {
    local hw
    hw=$(zb_detect_hw)
    local deps=0
    zb_check_tools >/dev/null 2>&1 && deps=1
    local cap=0
    [[ -d "$ZB_LOOT" ]] && cap=$(find "$ZB_LOOT" -maxdepth 1 -type f 2>/dev/null | wc -l)

    local keys=0
    [[ -s "$ZB_KEYFILE" ]] && keys=$(wc -l < "$ZB_KEYFILE")

    printf 'hardware\t%s\n' "$hw"
    printf 'deps_ok\t%s\n'  "$deps"
    printf 'captures\t%s\n' "$cap"
    printf 'keys\t%s\n'     "$keys"
    printf 'loot\t%s\n'     "$ZB_LOOT"
}

zb_list_captures_tsv() {
    local f
    for f in "$ZB_LOOT"/*.pcap "$ZB_LOOT"/*.json "$ZB_LOOT"/*.txt; do
        [[ -e "$f" ]] || continue
        printf '%s\t%s\t%s\n' "$(basename "$f")" "$(stat -c%s "$f")" "$(stat -c%Y "$f")"
    done
}

zb_sniff() {
    local chan="${1:-15}" dur="${2:-30}"
    local hw
    hw=$(zb_detect_hw)
    [[ "$hw" == "none" ]] && {
        printf 'ERROR\tno Zigbee hardware detected\n' >&2
        printf 'HINT\tCC2531, CC2530+CC2591, or nRF52840 with 802.15.4 firmware\n' >&2
        return 1
    }
    command -v zbdump >/dev/null 2>&1 || {
        # KillerBee has had no upstream commit since 2022-08. Name the
        # successor rather than sending people to an abandoned project.
        printf 'ERROR\tzbdump not installed (KillerBee suite, unmaintained since 2022-08)\n' >&2
        printf 'NOTE\tSee ESP32-KillerBee for a live replacement on ~$8 ESP32 hardware:\n' >&2
        printf 'NOTE\thttps://github.com/RockBase-iot/ESP32-KillerBee\n' >&2
        return 1
    }

    local ts out
    ts=$(date +%Y%m%d_%H%M%S)
    out="$ZB_LOOT/sniff_ch${chan}_${ts}.pcap"

    info "zbdump on channel $chan for ${dur}s → $out"
    timeout "$dur" zbdump -i 0 -c "$chan" -w "$out" 2>&1 | tail -10

    if [[ -s "$out" ]]; then
        printf 'CAPTURE\t%s\nSIZE\t%s\n' "$out" "$(stat -c%s "$out")"
    else
        printf 'ERROR\tcapture empty\n' >&2
        return 1
    fi
}

# ── channel scan with energy detection ──
zb_scan_channels() {
    local dur="${1:-3}"
    local hw
    hw=$(zb_detect_hw)
    [[ "$hw" == "none" ]] && { printf 'ERROR\tno hardware\n' >&2; return 1; }

    if command -v zbstumbler >/dev/null 2>&1; then
        info "zbstumbler active scan (${dur}s per channel)"
        for ch in 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26; do
            printf 'CHANNEL\t%s\n' "$ch"
            timeout "$dur" zbstumbler -c "$ch" 2>&1 | \
                grep -iE 'pan|address|channel' | head -5
        done
    else
        # Fallback: energy scan via wpan-tools (802.15.4 stack)
        command -v iz  >/dev/null 2>&1 || {
            printf 'ERROR\tneither zbstumbler nor iz available\n' >&2
            return 1
        }
        info "iz 802.15.4 energy scan"
        for ch in 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26; do
            printf 'CHANNEL\t%s\n' "$ch"
            iz set wpan0 page 0 channel "$ch" 2>/dev/null
            timeout 1 iz wpan0 listen 2>/dev/null | head -3
        done
    fi
}

# ── key extraction from a pcap ──

# Extract transport key commands (NWK cmd 0x05) and any plaintext keys
zb_extract_keys() {
    local cap="$1"
    [[ -z "$cap" || ! -f "$cap" ]] && {
        printf 'ERROR\tno pcap\n' >&2; return 1; }

    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\tno tshark\n' >&2; return 1; }

    info "extracting Zigbee keys from $cap"

    local found=0
    # Transport Key command (NWK cmd 0x05)
    tshark -r "$cap" -Y 'zbee_nwk.cmd.id == 0x05' \
        -T fields -e frame.number -e zbee_sec.key 2>/dev/null | \
    while IFS=$'\t' read -r frame key; do
        [[ -z "$key" ]] && continue
        found=1
        printf 'KEY\t%s\t%s\n' "$frame" "$key"
        # Persist to the key DB
        printf '%s\t%s\t%s\n' "$(date +%s)" "$frame" "$key" >> "$ZB_KEYFILE"
    done

    # Any other place a key might leak (Commissioning, APS Cmd)
    tshark -r "$cap" -Y 'zbee_aps.cmd.id == 0x05' \
        -T fields -e frame.number -e zbee_sec.key 2>/dev/null | \
    while IFS=$'\t' read -r frame key; do
        [[ -z "$key" ]] && continue
        printf 'APS_KEY\t%s\t%s\n' "$frame" "$key"
        printf '%s\t%s\t%s\n' "$(date +%s)" "aps:$frame" "$key" >> "$ZB_KEYFILE"
    done

    # Fall back to a strings-like search for the well-known default key
    if ! grep -q "5a6967426565416c6c69616e63653039" "$cap" 2>/dev/null; then
        # Default Trust Center Link Key (Zigbee Alliance)
        if xxd "$cap" 2>/dev/null | grep -qi "5a6967426565416c6c69616e63653039"; then
            printf 'DEFAULT_KEY\tZigbeeAlliance09\n'
            printf '%s\tdefault\tZigbeeAlliance09\n' "$(date +%s)" >> "$ZB_KEYFILE"
        fi
    else
        printf 'DEFAULT_KEY\tZigbeeAlliance09\n'
    fi
}

# ── key list / verify ──
zb_list_keys_tsv() {
    [[ -s "$ZB_KEYFILE" ]] && cat "$ZB_KEYFILE"
    return 0
}

# Verify a key by attempting to decode an encrypted capture with it
zb_verify_key() {
    local cap="$1" key="$2"
    [[ -z "$cap" || ! -f "$cap" ]] && {
        printf 'ERROR\tno pcap\n' >&2; return 1; }
    [[ -z "$key" ]] && { printf 'ERROR\tno key\n' >&2; return 1; }

    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\tno tshark\n' >&2; return 1; }

    # tshark accepts keys via -o zbee_sec.keyfile:... or by env
    # We write a temp keyfile and pass -o
    local tmpk="$ZB_DIR/verify_key_$$.txt"
    printf '0x%s\n' "$key" > "$tmpk"

    local decrypted
    decrypted=$(tshark -r "$cap" \
        -o "zbee_sec.keyfile:$tmpk" \
        -Y 'zbee_nwk' \
        -T fields -e frame.number 2>/dev/null | wc -l)
    rm -f "$tmpk"

    if (( decrypted > 0 )); then
        printf 'VALID\t%s\t%s\n' "$key" "$decrypted"
        return 0
    else
        printf 'INVALID\t%s\n' "$key"
        return 1
    fi
}

# ── replay ──
# zbreplay sends a captured frame back onto the network. Only works for
# unencrypted frames or if you have the key.
zb_replay() {
    local cap="$1" chan="$2" count="${3:-1}"
    [[ -z "$cap" || ! -f "$cap" ]] && {
        printf 'ERROR\tno pcap\n' >&2; return 1; }
    [[ -z "$chan" ]] && { printf 'ERROR\tno channel\n' >&2; return 2; }

    command -v zbreplay >/dev/null 2>&1 || {
        printf 'ERROR\tzbreplay not installed\n' >&2; return 1; }

    info "replaying $count frame(s) from $cap on channel $chan"
    zbreplay -i 0 -c "$chan" -r "$cap" -n "$count" 2>&1 | tail -10
    printf 'REPLAYED\t%s\n' "$count"
}

# ── OTA downgrade (research) ──
# In a Zigbee OTA session, the client asks for an image from the OTA
# server. Attacker can impersonate the server and serve an older
# firmware. Requires prior key capture.
zb_ota_downgrade() {
    local target="$1" fw_file="$2" chan="${3:-15}"
    [[ -z "$target" ]] && { printf 'ERROR\ttarget PAN/addr required\n' >&2; return 1; }
    [[ -z "$fw_file" || ! -f "$fw_file" ]] && {
        printf 'ERROR\tfirmware file required\n' >&2; return 1; }

    info "OTA downgrade attack: target=$target fw=$fw_file ch=$chan"
    warn "this is research-grade. Real Zigbee OTA stacks verify image signatures"

    # The full OTA hijack requires a rogue OTA server stack (zigbee2mqtt
    # or a custom zbee OTA endpoint). We document the workflow rather
    # than implement a half-working client.
    cat > "$ZB_LOOT/ota_downgrade_plan.txt" <<EOF
OTA downgrade plan for target $target on channel $chan
================================================================

Workflow:
  1. Sniff traffic (this module, --sniff $chan 60)
  2. Extract keys (--extract-keys pcap)
  3. Identify the OTA server's short address from the sniff
     (tshark: -Y 'zbee_aps.cmd.id == 0x02' for Update Device cmd)
  4. Impersonate the OTA server:
       a. Set our short address to match the OTA server
       b. Listen for Image Notify / Query Next Image Request
       c. Reply with the downgraded image
  5. Serve the older firmware:
       fw=${fw_file}
       size=$(stat -c%s "$fw_file")
       hash=$(sha256sum "$fw_file" | cut -c1-16)

Tools you'll want for step 4:
  • killerbee's zbreplay with a crafted zbee packet
  • zbee_packet_craft (a small python module using zigpy)
  • or killerbee's python API directly

Caveats:
  • Most modern Zigbee devices verify the OTA image signature
  • If signature verification is on, this attack fails at the last step
  • Only works on devices with signed-image-verify disabled
EOF
    printf 'PLAN\t%s\n' "$ZB_LOOT/ota_downgrade_plan.txt"
}

zb_info() {
    cat <<'INFO'
Zigbee / 802.15.4 attack surface:

  Passive:
    Network key extraction from Transport Key commands
    PAN ID / channel mapping
    Device inventory

  Active:
    Replay of captured commands (unencrypted or with key)
    Device spoofing (own PAN ID + short address)
    Firmware OTA downgrade (with key + server impersonation)
    Sinkhole / blackhole routing

  Hardware:
    CC2531 USB dongle (flashed with killerbee firmware) — cheap, common
    CC2530 + CC2591 (higher gain, DIY)
    nRF52840 dongle (802.15.4 support with right firmware)

  Software:
    killerbee (zbdump, zbreplay, zbid, zbstumbler)
    Wireshark + Zigbee dissector

  Key verifier:
    tshark with -o zbee_sec.keyfile:/path/to/key.txt
    where the file contains "0x<32-hex-key>"

  Default Trust Center Link Key (Zigbee Alliance):
    5a6967426565416c6c69616e63653039
INFO
}

# ── Thread / Matter (merged from thread_matter, submenu: Thread / Matter) ──
# Only commissioning needs a Thread radio (CC2531 / nRF52840). Discovery,
# TLV handling and attestation-chain validation are network- or data-level
# and work without one, so they are not gated.

THREAD_DIR="$TMP_DIR/thread"
MATTER_DIR="$LOOT_DIR/matter"

# Thread Border Routers advertise _meshcop._udp; Matter devices advertise
# _matter._tcp (and _matterc._udp while commissionable).
thread_discover() {
    local dur="${1:-4}"
    command -v avahi-browse >/dev/null 2>&1 || {
        printf 'ERROR\tavahi-browse not installed (apt install avahi-utils)\n' >&2
        return 1
    }
    mkdir -p "$THREAD_DIR"

    # Browse all three service types concurrently: sequentially this would cost
    # 3x the dwell time for no extra coverage.
    local svc
    for svc in _meshcop._udp _matter._tcp _matterc._udp; do
        # -r resolve, -p parseable. No -t: we want it listening for the whole
        # dwell, and avahi dumps its cache immediately anyway so already-known
        # devices show up at once.
        timeout "$dur" avahi-browse -rp "$svc" > "$THREAD_DIR/${svc#_}.txt" 2>/dev/null &
    done
    wait 2>/dev/null || true

    local found=0 n
    for svc in _meshcop._udp _matter._tcp _matterc._udp; do
        # NB: `grep -c || echo 0` yields "0\n0" — grep already prints 0 on no
        # match and only the exit status is non-zero.
        n=$(grep -c '^=' "$THREAD_DIR/${svc#_}.txt" 2>/dev/null) || n=0
        printf '%s\t%s\n' "$svc" "$n"
        found=$(( found + n ))
    done

    if (( found == 0 )); then
        printf 'NOTE\tno Thread Border Router or Matter device advertised in %ss\n' "$dur"
        printf 'NOTE\t_meshcop._udp = Thread BR, _matter._tcp = operational, _matterc._udp = commissionable\n'
    fi
}

# Thread Border Router details from the last discovery run.
thread_border_routers() {
    local out="$THREAD_DIR/meshcop._udp.txt"
    [[ -s "$out" ]] || { printf 'ERROR\tno discovery results — run --thread-discover first\n' >&2; return 1; }
    # avahi parseable: =;iface;proto;name;type;domain;host;addr;port;txt
    # Names arrive escaped (a space is \032 in parseable mode), so decode the
    # \DDD decimal escapes before displaying them.
    awk -F';' '
        function unesc(s,   out, i, c) {
            out = ""
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (c == "\\" && substr(s, i + 1, 3) ~ /^[0-9][0-9][0-9]$/) {
                    out = out sprintf("%c", substr(s, i + 1, 3) + 0)
                    i += 3
                } else {
                    out = out c
                }
            }
            return out
        }
        /^=/ { printf "%s\t%s\t%s\t%s\n", unesc($4), $8, $9, unesc($10) }
    ' "$out"
}

# Matter TLV decoder. Structure: control byte, then tag, then value.
# tag control (bits 0-2): 0 anon, 1 context(1B), 2 common16, 3 common32,
#                         4 implicit16
# element type (bits 5-7): 0 int, 1 uint, 2 bool, 3 f32, 4 f64, 5 utf8,
#                          6 octets, 7 null, 8 struct, 9 array, 10 list, 11 end
matter_tlv_decode() {
    local hex="$1"
    [[ -z "$hex" ]] && { printf 'ERROR\tusage: --matter-tlv HEX\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }

    # NB: the hex must arrive as argv — a here-doc on python3's stdin would
    # silently replace the pipe and the script would see zero bytes.
    python3 - "$hex" <<'PYEOF'
import sys, binascii, struct

raw = "".join(sys.argv[1].split()).replace(":", "")
try:
    data = binascii.unhexlify(raw)
except Exception as e:
    print(f"ERROR\tbad hex: {e}"); sys.exit(1)

# Matter TLV control byte: bits 0-2 tag control, bits 3-7 element type.
# (Getting these two fields the wrong way round silently mis-parses everything,
# so the widths are pinned here rather than inferred.)
ETYPE = {
    0:("int",1), 1:("int",2), 2:("int",4), 3:("int",8),
    4:("uint",1), 5:("uint",2), 6:("uint",4), 7:("uint",8),
    8:("bool",0), 9:("bool",0),
    10:("f32",4), 11:("f64",8),
    12:("utf8",1), 13:("utf8",2), 14:("utf8",4), 15:("utf8",8),
    16:("octets",1), 17:("octets",2), 18:("octets",4), 19:("octets",8),
    20:("null",0), 21:("struct",0), 22:("array",0), 23:("list",0),
    24:("end",0),
}
LENW = {12:1,13:2,14:4,15:8, 16:1,17:2,18:4,19:8}   # length-prefix width
CONTAINER = ("struct", "array", "list")

i, depth, n = 0, 0, 0
# Malformed input (unknown element type, truncation, container left open)
# must exit non-zero: bad hex already does, and the GUI reads exit 0 as
# success.
malformed = False

class Trunc(Exception):
    pass

# tag control -> width of the tag field
TAGW = {0: 0, 1: 1, 2: 2, 3: 4, 4: 2, 5: 6}

def read_tag(ctrl, i):
    """Return (label, new_i); raise Trunc if the tag runs off the end.

    Every read is bounds-checked: a malformed or captured-mid-stream payload
    is the normal case here, not an exception, and an unchecked
    unpack_from() would abort the whole decode with an IndexError.
    """
    tc = ctrl & 0x07
    w = TAGW.get(tc, 0)
    if i + w > len(data):
        raise Trunc()
    if tc == 0:
        return "-", i
    if tc == 1:
        return str(data[i]), i + 1
    if tc == 2:
        return f"0x{struct.unpack_from('<H', data, i)[0]:04X}", i + 2
    if tc == 3:
        return f"0x{struct.unpack_from('<I', data, i)[0]:08X}", i + 4
    if tc == 4:
        return f"impl:0x{struct.unpack_from('<H', data, i)[0]:04X}", i + 2
    v, p, t = struct.unpack_from("<HHH", data, i)
    return f"vid:0x{v:04X}/pid:0x{p:04X}/0x{t:04X}", i + 6

while i < len(data):
    ctrl = data[i]; i += 1
    etype = (ctrl >> 3) & 0x1F
    if etype not in ETYPE:
        print(f"ERROR\tunknown element type {etype} at byte {i-1}")
        malformed = True
        break
    name, size = ETYPE[etype]
    pad = "  " * depth
    try:
        label, i = read_tag(ctrl, i)
    except Trunc:
        print(f"{pad}[?] TRUNCATED tag at byte {i - 1}")
        malformed = True
        break
    n += 1

    if name in CONTAINER:
        print(f"{pad}[{label}] {name}")
        depth += 1
    elif name == "end":
        depth = max(0, depth - 1)
        print(f"{'  '*depth}[end]")
    elif name == "null":
        print(f"{pad}[{label}] null")
    elif name == "bool":
        print(f"{pad}[{label}] bool = {'true' if etype == 9 else 'false'}")
    elif name in ("int", "uint"):
        if i + size > len(data): print(f"{pad}[{label}] {name} TRUNCATED"); malformed = True; break
        v = int.from_bytes(data[i:i+size], "little", signed=(name == "int")); i += size
        print(f"{pad}[{label}] {name} = {v}")
    elif name in ("f32", "f64"):
        if i + size > len(data): print(f"{pad}[{label}] {name} TRUNCATED"); malformed = True; break
        v = struct.unpack_from("<f" if name == "f32" else "<d", data, i)[0]; i += size
        print(f"{pad}[{label}] {name} = {v}")
    elif name in ("utf8", "octets"):
        lw = LENW[etype]
        if i + lw > len(data): print(f"{pad}[{label}] {name} TRUNCATED"); malformed = True; break
        ln = int.from_bytes(data[i:i+lw], "little"); i += lw
        if i + ln > len(data): print(f"{pad}[{label}] {name} TRUNCATED"); malformed = True; break
        v = data[i:i+ln]; i += ln
        if name == "utf8":
            print(f"{pad}[{label}] utf8 = {v.decode('utf-8','replace')}")
        else:
            print(f"{pad}[{label}] octets = {binascii.hexlify(v).decode()}")

if depth != 0:
    print(f"WARN\t{depth} container(s) left open — truncated or malformed")
    malformed = True
print(f"---\nBYTES\t{len(data)}")
print(f"ELEMENTS\t{n}")
sys.exit(1 if malformed else 0)
PYEOF
}

# Matter device attestation chain: DAC (leaf) <- PAI (intermediate) <- PAA
# (root, usually a well-known vendor root).
matter_verify_chain() {
    local dac="$1" pai="$2" paa="$3"
    if [[ -z "$dac" || -z "$pai" || -z "$paa" ]]; then
        printf 'ERROR\tusage: --matter-verify-chain DAC.pem PAI.pem PAA.pem\n' >&2
        return 2
    fi
    local f
    for f in "$dac" "$pai" "$paa"; do
        [[ -f "$f" ]] || { printf 'ERROR\tnot found: %s\n' "$f" >&2; return 1; }
    done
    command -v openssl >/dev/null 2>&1 || { printf 'ERROR\topenssl required\n' >&2; return 1; }

    mkdir -p "$MATTER_DIR"
    local vf="$MATTER_DIR/paa_bundle_$(date +%s).pem"

    # The DAC must chain to the PAI, and the PAI to the PAA. openssl verify
    # wants the intermediates supplied separately from the trust anchor.
    cat "$pai" > "$vf"

    local rc=0 out
    out=$(openssl verify -CAfile "$paa" -untrusted "$vf" "$dac" 2>&1) || rc=1
    # openssl spreads a failure across several lines and prints the subject
    # first, so flatten it — head -1 alone shows an innocent subject line and
    # loses the real reason ("unable to get local issuer certificate").
    local flat
    flat=$(printf '%s' "$out" | tr '\n' ' ' | tr -s ' ')
    printf 'CHAIN\t%s\n' "$flat"
    printf 'DETAIL\t%s\n' "$(printf '%s' "$flat" | sed 's/.*error [0-9]* at [0-9]* depth lookup: //I')"
    (( rc == 0 )) && printf 'VALID\t1\n' || printf 'VALID\t0\n'
    (( rc != 0 )) && { rm -f "$vf"; return 1; }

    # Matter-specific facts worth surfacing.
    local subj iss
    subj=$(openssl x509 -in "$dac" -noout -subject 2>/dev/null | sed 's/^subject=//')
    iss=$(openssl x509 -in "$dac" -noout -issuer  2>/dev/null | sed 's/^issuer=//')
    printf 'DAC_SUBJECT\t%s\n' "$subj"
    printf 'DAC_ISSUER\t%s\n'  "$iss"
    # VID/PID live in a Matter-defined extension (1.3.6.1.4.1.37244.1.x)
    # openssl's -text rendering replaces the non-printable DER header bytes
    # with literal dots, so VID/PID cannot be read back from it. asn1parse
    # gives the true hex instead.
    openssl asn1parse -in "$dac" -i 2>/dev/null | python3 -c '
import sys, re
oid = None
for line in sys.stdin:
    m = re.search(r"OBJECT\s+:(\S*37244\S*)", line)
    if m:
        oid = m.group(1); continue
    if not oid:
        continue
    m = re.search(r"\[HEX DUMP\]:([0-9A-Fa-f]+)", line)
    if not m:
        continue
    h = m.group(1)
    b = bytes.fromhex(h)
    # Matter stores VID/PID as a DER UTF8String holding the hex digits.
    if b[:1] == b"\x0c" and len(b) >= 2:
        val = b[2:2 + b[1]].decode("utf-8", "replace")
    else:
        val = h
    print("EXT\t%s\t%s" % (oid, val))
    oid = None
'
    rm -f "$vf"
    return 0
}

# Build a TLV blob from a compact spec, e.g.
#   --matter-tlv-build 'struct,1:uint=42,2:octets=6b6f,3:utf8=hi,end'
#   TAG:TYPE=VALUE, or TYPE=VALUE for an anonymous tag.
# Container openers take no tag: struct|array|list|end
matter_tlv_build() {
    local spec="$1"
    [[ -z "$spec" ]] && { printf 'ERROR\tusage: --matter-tlv-build SPEC\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    python3 - "$spec" <<'PYEOF'
import sys, binascii, struct

spec = sys.argv[1]
# element type -> (base id, fixed width or None)
SCALAR = {"int":(0,), "uint":(4,), "bool":(8,), "f32":(10,), "f64":(11,),
          "utf8":(12,), "octets":(16,), "null":(20,)}
CONTAINER = {"struct":21, "array":22, "list":23, "end":24}
WIDTHS = (1, 2, 4, 8)

errors = []
out = bytearray()

def emit(etype, tag, payload=b""):
    """Control byte + optional tag + payload."""
    if tag is None:
        out.append(etype << 3)
    else:
        if not 0 <= tag <= 0xFF:
            errors.append(f"tag {tag} does not fit a context tag (0-255)")
            return
        out.append((etype << 3) | 1)
        out.append(tag)
    out.extend(payload)

for part in [p.strip() for p in spec.split(",") if p.strip()]:
    # Split into tag / type / value before dispatching, so tagged containers
    # (a struct member that is itself a struct) and valueless null work too.
    if "=" in part:
        lhs, val = part.split("=", 1)
    else:
        lhs, val = part, None

    if ":" in lhs:
        tagn, tname = lhs.split(":", 1)
        try:
            tag = int(tagn, 0)
        except ValueError:
            errors.append(f"bad tag {tagn!r}"); continue
    else:
        tname, tag = lhs, None

    if tname in CONTAINER:
        if val is not None:
            errors.append(f"{tname} must not take a value"); continue
        emit(CONTAINER[tname], tag)
        continue

    if tname == "null":
        if val is not None:
            errors.append("null must not take a value"); continue
        emit(20, tag); continue

    if val is None:
        errors.append(f"{tname} needs a value (TYPE=VALUE)"); continue

    if tname in ("int", "uint"):
        try:
            v = int(val, 0)
        except ValueError:
            errors.append(f"bad integer {val!r}"); continue
        signed = (tname == "int")
        for w in WIDTHS:
            try:
                payload = v.to_bytes(w, "little", signed=signed); break
            except OverflowError:
                continue
        else:
            errors.append(f"{val} does not fit an {tname} (1/2/4/8 bytes)"); continue
        emit(SCALAR[tname][0] + WIDTHS.index(w), tag, payload)
        continue

    if tname == "bool":
        emit(9 if val.lower() in ("1", "true", "yes", "on") else 8, tag); continue

    if tname in ("f32", "f64"):
        try:
            payload = struct.pack("<f" if tname == "f32" else "<d", float(val))
        except (ValueError, struct.error) as e:
            errors.append(f"bad float {val!r}: {e}"); continue
        emit(10 if tname == "f32" else 11, tag, payload); continue

    if tname == "utf8":
        b = val.encode()
    elif tname == "octets":
        try:
            b = binascii.unhexlify("".join(val.split()).replace(":", ""))
        except Exception as e:
            errors.append(f"bad hex {val!r}: {e}"); continue
    else:
        errors.append(f"unknown type {tname!r}"); continue

    if len(b) > 255:
        errors.append(f"value too long for a 1-byte length prefix ({len(b)} bytes)")
        continue
    emit(SCALAR[tname][0], tag, bytes([len(b)]) + b)

if errors:
    for e in errors:
        print(f"ERROR\t{e}", file=sys.stderr)
    sys.exit(1)
print(binascii.hexlify(bytes(out)).decode())
PYEOF
}

thread_status_tsv() {
    printf 'avahi\t%s\n'   "$(command -v avahi-browse >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'openssl\t%s\n' "$(command -v openssl >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'radio\t%s\n'   "$(lsusb 2>/dev/null | grep -qiE '0451:|1915:' && echo 1 || echo 0)"
    printf 'cached_br\t%s\n' "$(grep -c '^=' "$THREAD_DIR/meshcop._udp.txt" 2>/dev/null || :)"
    printf 'cached_matter\t%s\n' "$(grep -c '^=' "$THREAD_DIR/matter._tcp.txt" 2>/dev/null || :)"
}

# ── self-test ────────────────────────────────────────────────────────────
# Pure data paths only: the Matter TLV encoder/decoder (control-byte bit
# layout, integer width selection, tag widths, truncation reporting) and the
# avahi/mDNS parseable-record decoder. No radio, no root, no network.
zb_selftest() {
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld()  { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    lnum() { printf '%s\n' "$1" | grep -cxF -- "$2"; }
    lval() { printf '%s\n' "$1" | sed -n 's/^.* = //p' | head -1; }
    rcof() { "$@" >/dev/null 2>&1; echo $?; }

    local d out rc blob v
    # Unique per run: a second selftest (runner alongside a manual run)
    # must not share scratch files.
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }

    # 1. Control byte layout: tag control is bits 0-2, element type is bits
    #    3-7. These are pinned as exact bytes rather than round-tripped,
    #    because swapping the two fields still round-trips through this
    #    encoder and only shows up against a fixed expectation.
    chk build-uint-anon   "$(matter_tlv_build 'uint=42')"     "202a"
    chk build-bool-true   "$(matter_tlv_build '1:bool=true')" "4901"
    chk build-bool-false  "$(matter_tlv_build '2:bool=0')"    "4102"
    chk build-null        "$(matter_tlv_build '3:null')"      "a103"
    chk build-struct-anon "$(matter_tlv_build 'struct')"      "a8"
    chk build-struct-ctx  "$(matter_tlv_build '4:struct')"    "a904"
    chk build-array       "$(matter_tlv_build 'array')"       "b0"
    chk build-list        "$(matter_tlv_build 'list')"        "b8"
    chk build-end         "$(matter_tlv_build 'end')"         "c0"
    chk build-tag255      "$(matter_tlv_build '255:uint=1')"  "21ff01"

    # 2. Integer width selection: 1/2/4/8 bytes, with the element type
    #    advancing with the width (uint 4..7, int 0..3).
    chk build-uint-w1 "$(matter_tlv_build '1:uint=42')"         "21012a"
    chk build-uint-w2 "$(matter_tlv_build '1:uint=300')"        "29012c01"
    chk build-uint-w4 "$(matter_tlv_build '1:uint=70000')"      "310170110100"
    chk build-uint-w8 "$(matter_tlv_build '1:uint=5000000000')" "390100f2052a01000000"
    chk build-int-neg1   "$(matter_tlv_build '1:int=-1')"       "0101ff"
    chk build-int-neg129 "$(matter_tlv_build '1:int=-129')"     "09017fff"

    # 3. Build -> decode round trip across every width and both signs,
    #    including the 8-byte boundaries.
    for v in 0 255 256 65535 65536 4294967295 4294967296 18446744073709551615; do
        out=$(matter_tlv_decode "$(matter_tlv_build "1:uint=$v")")
        chk "tlv-uint-roundtrip-$v" "$(lval "$out")" "$v"
    done
    for v in -1 -128 -129 -32768 -32769 -2147483648 -2147483649 -9223372036854775808; do
        out=$(matter_tlv_decode "$(matter_tlv_build "1:int=$v")")
        chk "tlv-int-roundtrip-$v" "$(lval "$out")" "$v"
    done

    # 4. Struct round trip: one struct of uint + octets + utf8, compared
    #    field by field after decoding the built blob.
    blob=$(matter_tlv_build 'struct,1:uint=42,2:octets=6b6f,3:utf8=hi,end')
    chk tlv-struct-hex "$blob" "a821012a8102026b6f6103026869c0"
    out=$(matter_tlv_decode "$blob")
    chk tlv-struct-bytes    "$(fld "$out" BYTES)"    "15"
    chk tlv-struct-elements "$(fld "$out" ELEMENTS)" "5"
    chk tlv-struct-open     "$(lnum "$out" '[-] struct')"          "1"
    chk tlv-struct-uint     "$(lnum "$out" '  [1] uint = 42')"     "1"
    chk tlv-struct-octets   "$(lnum "$out" '  [2] octets = 6b6f')" "1"
    chk tlv-struct-utf8     "$(lnum "$out" '  [3] utf8 = hi')"     "1"
    chk tlv-struct-close    "$(lnum "$out" '[end]')"               "1"
    chk tlv-struct-balanced "$(printf '%s\n' "$out" | grep -c 'left open')" "0"
    out=$(matter_tlv_decode "$(matter_tlv_build '1:bool=true')")
    chk tlv-bool-true  "$(lnum "$out" '[1] bool = true')"  "1"
    out=$(matter_tlv_decode "$(matter_tlv_build '2:bool=0')")
    chk tlv-bool-false "$(lnum "$out" '[2] bool = false')" "1"
    out=$(matter_tlv_decode "$(matter_tlv_build '3:null')")
    chk tlv-null "$(lnum "$out" '[3] null')" "1"

    # 5. Tag widths, from hand-built control bytes so the decoder tag table
    #    is exercised on its own: anon(0), context(1), common16(2),
    #    common32(4), implicit16(4).
    chk tlv-tag-anon     "$(lnum "$(matter_tlv_decode '202a')"     '[-] uint = 42')"         "1"
    chk tlv-tag-context  "$(lnum "$(matter_tlv_decode '21012a')"   '[1] uint = 42')"         "1"
    chk tlv-tag-common16 "$(lnum "$(matter_tlv_decode '2234122a')" '[0x1234] uint = 42')"    "1"
    chk tlv-tag-common32 "$(lnum "$(matter_tlv_decode '23cdab00002a')" '[0x0000ABCD] uint = 42')" "1"
    chk tlv-tag-implicit "$(lnum "$(matter_tlv_decode '2434122a')" '[impl:0x1234] uint = 42')"   "1"

    # 6. A tagged container nests and closes; depth must return to zero.
    #    NB: an end element prints at the depth it returns to, so both ends
    #    of this blob land in the same column.
    blob=$(matter_tlv_build '1:struct,2:uint=5,end,end')
    chk tlv-nested-hex    "$blob" "a901210205c0c0"
    out=$(matter_tlv_decode "$blob")
    chk tlv-nested-open   "$(lnum "$out" '[1] struct')"     "1"
    chk tlv-nested-member "$(lnum "$out" '  [2] uint = 5')" "1"
    chk tlv-nested-ends   "$(lnum "$out" '[end]')"          "2"
    chk tlv-nested-depth  "$(printf '%s\n' "$out" | grep -c 'left open')" "0"

    # 7. Truncated input is reported at the exact byte, never a traceback —
    #    and it must exit non-zero: the caller (and the GUI) reads exit 0
    #    as a successful decode. Bad hex already exits 1.
    out=$(matter_tlv_decode '20'); rc=$?
    chk tlv-trunc-uint-rc   "$rc" "1"
    chk tlv-trunc-uint-msg  "$(lnum "$out" '[-] uint TRUNCATED')" "1"
    chk tlv-trunc-uint-elem "$(fld "$out" ELEMENTS)" "1"
    out=$(matter_tlv_decode '21'); rc=$?
    chk tlv-trunc-tag-rc    "$rc" "1"
    chk tlv-trunc-tag-msg   "$(lnum "$out" '[?] TRUNCATED tag at byte 0')" "1"
    out=$(matter_tlv_decode '8101'); rc=$?
    chk tlv-trunc-octets-rc "$rc" "1"
    chk tlv-trunc-octets    "$(lnum "$out" '[1] octets TRUNCATED')" "1"
    out=$(matter_tlv_decode 'a8'); rc=$?
    chk tlv-open-container-rc "$rc" "1"
    chk tlv-open-container  "$(printf '%s\n' "$out" | grep -c 'left open')" "1"

    # 8. Malformed input is reported with the offending byte; an unknown
    #    element type decodes nothing rather than inventing an element.
    out=$(matter_tlv_decode 'f8'); rc=$?
    chk tlv-unknown-etype-rc "$rc" "1"
    chk tlv-unknown-etype "$(printf '%s\n' "$out" | grep -c '^ERROR.unknown element type 31 at byte 0')" "1"
    chk tlv-unknown-elems "$(fld "$out" ELEMENTS)" "0"
    chk tlv-badhex-rc     "$(rcof matter_tlv_decode 'zz')" "1"
    out=$(matter_tlv_decode 'zz' 2>&1)
    chk tlv-badhex-msg    "$(printf '%s\n' "$out" | grep -c '^ERROR.bad hex')" "1"
    chk tlv-usage-rc      "$(rcof matter_tlv_decode '')" "2"
    # A well-formed payload still exits 0.
    chk tlv-valid-rc      "$(rcof matter_tlv_decode '202a')" "0"

    # 9. The builder rejects malformed specs instead of emitting a partial
    #    blob that would later decode as something else.
    chk build-badint-rc       "$(rcof matter_tlv_build '1:uint=abc')" "1"
    chk build-neg-uint-rc     "$(rcof matter_tlv_build '1:uint=-1')" "1"
    chk build-uint-overflow   "$(rcof matter_tlv_build '1:uint=18446744073709551616')" "1"
    chk build-int-underflow   "$(rcof matter_tlv_build '1:int=-9223372036854775809')" "1"
    chk build-tag256-rc       "$(rcof matter_tlv_build '256:uint=1')" "1"
    chk build-value-on-struct "$(rcof matter_tlv_build 'struct=1')" "1"
    chk build-value-on-null   "$(rcof matter_tlv_build 'null=1')" "1"
    chk build-unknown-type    "$(rcof matter_tlv_build '1:bogus=1')" "1"
    chk build-usage-rc        "$(rcof matter_tlv_build '')" "2"

    # 10. avahi parseable records: the \DDD decimal escapes in the instance
    #     name must be decoded and non-record lines skipped.
    mkdir -p "$d/thread"
    printf '%s\n' '=;eth0;IPv4;Border\032Router\0321;_meshcop._udp;local;br1.local;192.168.1.5;49191;nn=test' \
        > "$d/thread/meshcop._udp.txt"
    printf '%s\n' '+;eth0;IPv4;Border\032Router\0321;_meshcop._udp;local;br1.local;192.168.1.5;49191;nn=test' \
        >> "$d/thread/meshcop._udp.txt"
    out=$(THREAD_DIR="$d/thread" thread_border_routers)
    chk mdns-rows "$(printf '%s\n' "$out" | grep -c .)" "1"
    chk mdns-name "$(printf '%s\n' "$out" | awk -F'\t' 'NR==1{print $1}')" "Border Router 1"
    chk mdns-addr "$(printf '%s\n' "$out" | awk -F'\t' 'NR==1{print $2}')" "192.168.1.5"
    chk mdns-port "$(printf '%s\n' "$out" | awk -F'\t' 'NR==1{print $3}')" "49191"
    chk mdns-txt  "$(printf '%s\n' "$out" | awk -F'\t' 'NR==1{print $4}')" "nn=test"
    chk mdns-missing-rc "$(THREAD_DIR="$d/none" thread_border_routers >/dev/null 2>&1; echo $?)" "1"

    # 11. Radio-gated verbs validate their arguments before touching a
    #     device, so an empty invocation must fail non-zero.
    chk ota-no-args-rc     "$(rcof zb_ota_downgrade '' '')" "1"
    chk extract-no-pcap-rc "$(rcof zb_extract_keys '')"     "1"
    chk replay-no-pcap-rc  "$(rcof zb_replay '' '')"        "1"
    chk verify-no-pcap-rc  "$(rcof zb_verify_key '' '')"    "1"

    # 12. The killerbee probe must agree with its own exit status.
    out=$(zb_check_tools 2>&1); rc=$?
    case "$out" in
        READY)    chk tools-probe-status "$rc" "0" ;;
        MISSING*) chk tools-probe-status "$rc" "1" ;;
        *)        chk tools-probe-status "$out" "READY-or-MISSING" ;;
    esac

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

zb_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         zb_status_tsv ;;
        --check-tools)        zb_check_tools ;;
        --list-captures-tsv)  zb_list_captures_tsv ;;
        --sniff)              zb_sniff "$@" ;;
        --scan-channels)      zb_scan_channels "$@" ;;
        --extract-keys)       zb_extract_keys "$@" ;;
        --list-keys-tsv)      zb_list_keys_tsv ;;
        --verify-key)         zb_verify_key "$@" ;;
        --replay)             zb_replay "$@" ;;
        --ota-downgrade)      zb_ota_downgrade "$@" ;;
        --selftest)           zb_selftest ;;
        --info)               zb_info ;;
        --thread-discover)  thread_discover "$@" ;;
        --thread-br-tsv)    thread_border_routers ;;
        --matter-tlv)       matter_tlv_decode "$@" ;;
        --matter-verify-chain) matter_verify_chain "$@" ;;
        --matter-tlv-build) matter_tlv_build "$@" ;;
        --thread-status-tsv) thread_status_tsv ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --check-tools
  --list-captures-tsv
  --sniff CHANNEL [DURATION]
  --scan-channels [PER_CHANNEL_SEC]
  --extract-keys PCAP
  --list-keys-tsv
  --verify-key PCAP KEY
  --replay PCAP CHANNEL [COUNT]
  --ota-downgrade TARGET FW_FILE [CHANNEL]
  --selftest                      offline checks of the TLV/mDNS parsers
  --info

Thread / Matter (no Thread radio needed except commissioning):
  --thread-discover [SECS]        mDNS browse for Thread BRs and Matter devices
  --thread-br-tsv                 Border Routers from the last discovery
  --matter-tlv HEX                decode a Matter TLV payload
  --matter-tlv-build SPEC         build one, e.g. 'struct,1:uint=42,end'
  --matter-verify-chain DAC PAI PAA   validate a device attestation chain
  --thread-status-tsv             avahi/openssl/python/radio capability state
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    command -v warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    command -v err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    zb_cli_main "$@"
fi

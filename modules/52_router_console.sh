#!/usr/bin/env bash
# 52_router_console — Physical and bootloader access to a router
# Recovery-mode TFTP, UART/U-Boot console guidance, SPI flash dumping and
# offline parsing of a dumped image.
#
# Standalone top-level module. Self-locating and pkexec-safe: the polkit rule
# matches this script's path, so invoke it directly, never through `env`.

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

MOD_TMP="$TMP_DIR/router_console"
MOD_LOOT="$LOOT_DIR/router_console"
MOD_LOGS="$LOG_DIR/router_console"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" 2>/dev/null

# ─────────────────────────────────────────────────────────────────────────
# 52_router_console — the router when you can reach its bootloader
#
# This module sits on the boundary between "network" and "hands on hardware":
#
#   * TFTP in recovery mode is a network service and is probed for real.
#   * UART and SPI need an adapter on the board, so those verbs emit the exact
#     procedure - pinout, baud, U-Boot commands, clip wiring - and report what
#     hardware is missing rather than pretending to act.
#   * Parsing a dumped flash image is pure offline work and is done properly.
#
# Writing to a device is the one destructive path here, so --tftp-push
# requires --yes-write-to-device. Flashing a router takes it off the air, and
# a half-written image bricks it. The default is read-only.
# ─────────────────────────────────────────────────────────────────────────

RCON_TIMEOUT="${RCON_TIMEOUT:-4}"

# Vendor recovery addresses. Widely documented but not guaranteed: firmware
# revisions move them, so these are probed and reported, never assumed.
RCON_RECOVERY_HOSTS='192.168.1.1 192.168.0.1 192.168.1.20 192.168.2.1 10.0.0.1'

rcon_err()  { printf 'ERR\t%s\n' "$*" >&2; }
rcon_have() { command -v "$1" >/dev/null 2>&1; }

# ── TFTP client ──────────────────────────────────────────────────────────
# bash cannot do UDP, so the client is python3. Implemented rather than
# shelled out to `tftp` because the busybox tftp is not present everywhere
# and its flags differ between implementations.
rcon_tftp_probe() {
    local host="$1"
    python3 - "$host" "$RCON_TIMEOUT" <<'PY'
import socket, struct, sys
host, t = sys.argv[1], float(sys.argv[2])
# An RRQ for a name that will not exist: a TFTP server answers with an ERROR
# packet, which is all we need. No server means a timeout.
pkt = struct.pack('!H', 1) + b'__probe__\x00octet\x00'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(t)
try:
    s.sendto(pkt, (host, 69))
    data, _ = s.recvfrom(516)
    op = struct.unpack('!H', data[:2])[0]
    if op == 5:
        msg = data[4:].split(b'\x00')[0].decode('utf-8', 'replace')
        print("TFTP\t%s\tpresent\t%s" % (host, msg))
    elif op == 3:
        print("TFTP\t%s\tpresent\tdata reply" % host)
    else:
        print("TFTP\t%s\tpresent\topcode=%d" % (host, op))
except socket.timeout:
    sys.exit(1)
except OSError as e:
    print("ERR\ttftp probe %s: %s" % (host, e), file=sys.stderr)
    sys.exit(2)
PY
}

rcon_tftp_probe_all() {
    local h found=0
    for h in $RCON_RECOVERY_HOSTS; do
        if rcon_tftp_probe "$h"; then found=$((found+1)); fi
    done
    (( found > 0 )) || printf 'TFTP\tnone\tno recovery server on the known addresses\n'
    return 0
}

rcon_tftp_read() {
    local host="$1" remote="$2" out="$3"
    [[ -n "$host" && -n "$remote" && -n "$out" ]] || {
        rcon_err "usage: --tftp-pull HOST REMOTE_FILE OUT"; return 2; }
    python3 - "$host" "$remote" "$out" "$RCON_TIMEOUT" <<'PY'
import socket, struct, sys
host, remote, out, t = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(t)
rrq = struct.pack('!H', 1) + remote.encode() + b'\x00octet\x00'
try:
    s.sendto(rrq, (host, 69))
except OSError as e:
    print("ERR\ttftp: %s" % e, file=sys.stderr); sys.exit(2)
buf = bytearray()
try:
    while True:
        data, addr = s.recvfrom(516)
        op = struct.unpack('!H', data[:2])[0]
        if op == 5:
            print("ERR\ttftp error: %s" % data[4:].split(b'\x00')[0].decode('utf-8','replace'),
                  file=sys.stderr)
            sys.exit(1)
        if op != 3:
            continue
        blk = struct.unpack('!H', data[2:4])[0]
        buf += data[4:]
        s.sendto(struct.pack('!HH', 4, blk), addr)
        if len(data) < 516:
            break
except socket.timeout:
    print("ERR\ttftp timed out after %d bytes" % len(buf), file=sys.stderr)
    sys.exit(1)
open(out, 'wb').write(bytes(buf))
print("TFTP\tread\t%s (%d bytes)" % (out, len(buf)))
PY
}

# Deliberately gated: a WRQ replaces the device's firmware or config.
rcon_tftp_write() {
    local host="$1" local_file="$2" remote="$3" ack="$4"
    [[ -n "$host" && -n "$local_file" && -n "$remote" ]] || {
        rcon_err "usage: --tftp-push HOST LOCAL_FILE REMOTE [--yes-write-to-device]"; return 2; }
    if [[ "$ack" != "--yes-write-to-device" ]]; then
        rcon_err "--tftp-push writes to the device and can brick it; re-run with --yes-write-to-device to confirm"
        return 1
    fi
    [[ -s "$local_file" ]] || { rcon_err "no such file: $local_file"; return 1; }
    python3 - "$host" "$local_file" "$remote" "$RCON_TIMEOUT" <<'PY'
import socket, struct, sys, os
host, path, remote, t = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
data = open(path, 'rb').read()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(t)
s.sendto(struct.pack('!H', 2) + remote.encode() + b'\x00octet\x00', (host, 69))
try:
    pkt, addr = s.recvfrom(516)
except socket.timeout:
    print("ERR\ttftp write: no ACK (device may not accept writes)", file=sys.stderr); sys.exit(1)
if struct.unpack('!H', pkt[:2])[0] == 5:
    print("ERR\ttftp refused: %s" % pkt[4:].split(b'\x00')[0].decode('utf-8','replace'),
          file=sys.stderr)
    sys.exit(1)
blk = 1
for off in range(0, len(data), 512):
    chunk = data[off:off+512]
    s.sendto(struct.pack('!HH', 3, blk) + chunk, addr)
    try:
        pkt, _ = s.recvfrom(516)
    except socket.timeout:
        print("ERR\ttftp write stalled at block %d" % blk, file=sys.stderr); sys.exit(1)
    if struct.unpack('!H', pkt[:2])[0] == 5:
        print("ERR\ttftp error: %s" % pkt[4:].split(b'\x00')[0].decode('utf-8','replace'),
              file=sys.stderr)
        sys.exit(1)
    blk = (blk + 1) & 0xffff
print("TFTP\twrote\t%s -> %s:%s (%d bytes)" % (path, host, remote, len(data)))
PY
}

# ── offline flash image parsing ──────────────────────────────────────────
# The payload of every physical route above: a flash dump from U-Boot, the
# SPI clip or a vendor image. Pure offline work, so it is done here properly.
rcon_flash_parse() {
    local img="$1"
    [[ -n "$img" ]] || { rcon_err "usage: --flash-parse IMAGE"; return 2; }
    [[ -s "$img" ]] || { rcon_err "no such file or image is empty: $img"; return 1; }

    local size
    size=$(wc -c < "$img" | tr -d ' ')
    printf 'IMAGE\t%s\t%s bytes\n' "$img" "$size"

    # Filesystem and container signatures worth knowing about in a dump.
    python3 - "$img" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read()
sigs = [
    (b'\x27\x05\x19\x56', 'uImage header'),
    (b'hsqs',             'squashfs (little endian)'),
    (b'sqsh',             'squashfs (big endian)'),
    (b'\x85\x19\x01\x20', 'JFFS2'),
    (b'UBI#',             'UBI volume'),
    (b'cramfs',           'cramfs'),
    (b'\x1f\x8b\x08',     'gzip stream'),
    (b'\xfd7zXZ',         'xz stream'),
    (b'\x5d\x00\x00',     'lzma alone (probable)'),
    (b'\xd0\x0d\xfe\xed', 'device tree blob'),
    (b'\x7fELF',          'ELF executable'),
    (b'#!/bin/sh',        'shell script'),
]
for magic, name in sigs:
    off = data.find(magic)
    if off >= 0:
        print("SIGNATURE\t0x%08x\t%s" % (off, name))
if data.find(b'CFE') >= 0:
    print("SIGNATURE\t-\tCFE bootloader strings")
for tok in (b'U-Boot', b'breed', b'RedBoot'):
    if tok in data:
        print("BOOTLOADER\t%s" % tok.decode())
PY

    # Credential-bearing NVRAM variables. These are the reason to dump a
    # flash in the first place, so they are pulled out explicitly.
    local found=0 line
    while IFS= read -r line; do
        printf 'CRED\t%s\n' "$line"
        found=$((found+1))
    done < <(strings -n 5 "$img" 2>/dev/null \
             | grep -aiE '^(http_passwd|http_username|admin_password|root_password|Login|Password|ppp_username|ppp_passwd|wpa_psk|wl[0-9]_wpa_psk|ssid)=' \
             | sort -u | head -30)
    (( found > 0 )) || printf 'NOTE\tno credential variables matched as plain text; the config may be compressed - look for a squashfs/UBI offset above\n'

    # WiFi PSK shapes that survive as bare strings.
    while IFS= read -r line; do
        printf 'PSK\t%s\n' "$line"
    done < <(strings -n 8 "$img" 2>/dev/null \
             | grep -aoE '\b[0-9A-Fa-f]{64}\b' | sort -u | head -10)
    return 0
}

# ── hardware guidance ────────────────────────────────────────────────────
# These verbs print a procedure. They do not pretend to have performed it,
# and --check-deps says which adapter is missing.

rcon_uart_guide() {
    cat <<'EOF'
UART console — procedure

HARDWARE
  USB-TTL adapter at 3.3 V. Do NOT use a 5 V adapter and do not connect VCC
  until you have identified it: reverse-connecting VCC to a data pad can kill
  the SoC. Most boards expose 4 pads or a 4-pin header (VCC GND TX RX) but
  the order is not standard.

IDENTIFY THE PADS (board unpowered)
  1. Continuity to a ground plane or a large capacitor's negative leg -> GND.
  2. Continuity to the input of the 3.3 V regulator -> VCC (leave it alone;
     the board's own supply is enough).
  3. The two remaining pads are TX and RX. With the board powered, a meter on
     the pad that idles near 3.3 V and twitches at boot is TX (device output).

BAUD
  115200 8N1 first; then 57600, 38400, 9600. Wrong baud gives plausible-looking
  garbage, which is the usual reason people give up early.

CAPTURE
  picocom -b 115200 /dev/ttyUSB0      (or: screen /dev/ttyUSB0 115200)
  Power the board with the terminal already open to catch the boot log.

WHAT YOU ARE LOOKING FOR
  * a U-Boot/Breed/CFE banner and a countdown you can interrupt
  * the kernel command line, which names the flash layout (mtdparts=)
  * a root shell if the vendor left one
EOF
}

rcon_uboot_commands() {
    cat <<'EOF'
U-Boot prompt — what is worth typing

  Interrupt the countdown (usually any key, sometimes Ctrl-C or 'tpl').

  printenv                 everything: bootargs, bootcmd, ipaddr, serverip
  printenv bootdelay       if 0, you must catch it faster or reflash instead

READ
  md 0x9f000000 0x100      memory dump
  sf probe; sf read 0x80000000 0x0 0x100000     SPI flash -> RAM
  nand dump 0x0 0x80000000 0x100000             NAND -> RAM
  md.b 0x80000000 0x10000  then paste out over serial, or use tftpput

RESET THE ADMIN PASSWORD (vendor NVRAM varies)
  printenv | grep -i pass                  find the variable name first
  setenv http_passwd ''                    or admin_password, root_password
  saveenv                                  persists; reboot after

BOOT SINGLE USER (if it is Linux underneath)
  setenv bootargs "$bootargs single init=/bin/sh"
  boot

MOVE AN IMAGE
  setenv serverip <your-ip>; setenv ipaddr <router-ip>
  tftpboot 0x80000000 image.bin
  sf write 0x80000000 0x0 $filesize       DESTRUCTIVE - verify the offset first

IF U-BOOT ASKS FOR A PASSWORD
  options are the bootdelay race, a serial glitch, or reading the flash with
  a clip instead. There is no supported bypass.
EOF
}

rcon_spi_guide() {
    cat <<'EOF'
SPI flash — reading the whole chip

WHEN
  U-Boot is locked, the UART pads are absent, or you want a byte-exact image
  before touching anything.

HARDWARE
  CH341A programmer (or any SPI reader) plus a SOIC-8 clip, or a hot-air
  station if the chip is not clip-friendly. 3.3 V setting.

PROCEDURE
  1. Identify the chip: read the marking, then `flashrom -p ch341a_spi` with
     the clip attached and the board UNPOWERED (or held in reset). Powering
     both the board and the clip is how chips get damaged.
  2. Read twice and compare - a flaky clip contact is common:
       flashrom -p ch341a_spi -r dump1.bin
       flashrom -p ch341a_spi -r dump2.bin
       cmp dump1.bin dump2.bin
  3. Parse offline:  52_router_console.sh --flash-parse dump1.bin
  4. Only then consider writing, and keep dump1.bin as the way back.

NOTE
  Reading is safe. Writing a wrong image to the wrong offset is how a router
  becomes a brick; there is no undo without a known-good dump.
EOF
}

# ── info / deps / selftest ───────────────────────────────────────────────

rcon_info() {
    cat <<'EOF'
52_router_console — bootloader and physical access to a router

  --tftp-probe-tsv           look for a recovery-mode TFTP server
  --tftp-pull HOST REMOTE OUT    read a file from it
  --tftp-push HOST LOCAL REMOTE [--yes-write-to-device]
                             DESTRUCTIVE: replaces firmware or config
  --flash-parse IMAGE        offline: signatures, NVRAM credentials, PSK blobs
  --uart-guide               pinout, baud, capture (prints a procedure)
  --uboot-commands           U-Boot prompt reference
  --spi-guide                clip reading, read-twice discipline
  --check-deps | --info | --selftest

Recovery TFTP is probed for real. UART and SPI need an adapter on the board,
so those verbs print the procedure and name what is missing. Parsing a dump
is offline and is done in full.
EOF
}

rcon_check_deps() {
    local t
    for t in python3 strings flashrom picocom screen; do
        if rcon_have "$t"; then printf 'OK\t%s\t%s\n' "$t" "$(command -v "$t")"
        else printf 'MISSING\t%s\tnone\n' "$t"; fi
    done
    # A USB serial adapter is what unlocks the UART verbs at all.
    if compgen -G '/dev/ttyUSB*' >/dev/null 2>&1 || compgen -G '/dev/ttyACM*' >/dev/null 2>&1; then
        local d
        for d in /dev/ttyUSB* /dev/ttyACM*; do
            [[ -e "$d" ]] && printf 'SERIAL\t%s\n' "$d"
        done
    else
        printf 'NOTE\tno USB serial adapter attached - UART work needs one\n'
    fi
    rcon_have flashrom || printf 'NOTE\tflashrom not installed - SPI read/write needs it\n'
}

rcon_selftest() {
    local pass=0 fail=0
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"; pass=$((pass+1))
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fail=$((fail+1)); fi
    }

    # -- validation -------------------------------------------------------
    rcon_tftp_read "" "" ""      >/dev/null 2>&1; chk pull-noarg-rc  "$?" 2
    rcon_tftp_write "" "" "" ""  >/dev/null 2>&1; chk push-noarg-rc  "$?" 2
    rcon_flash_parse ""          >/dev/null 2>&1; chk parse-noarg-rc "$?" 2
    rcon_flash_parse "/nope"     >/dev/null 2>&1; chk parse-miss-rc  "$?" 1

    # -- the destructive path refuses without the explicit flag -----------
    # This is the assertion that matters most: a regression here writes to
    # someone's router.
    local tmpf="$MOD_TMP/st-fw.bin"
    printf 'IMAGEDATA' > "$tmpf"
    local out rc
    out=$(rcon_tftp_write 192.0.2.1 "$tmpf" fw.bin 2>&1); rc=$?
    chk push-gated-rc "$rc" 1
    case "$out" in
        *--yes-write-to-device*) chk push-gated-msg ok ok ;;
        *) chk push-gated-msg "$out" "--yes-write-to-device" ;;
    esac

    # -- flash parsing against a synthetic dump --------------------------
    # Build an image with a uImage header, an NVRAM variable block and a
    # 64-hex PSK, which is what a real dump yields.
    local img="$MOD_TMP/st-dump.bin"
    python3 - "$img" <<'PY'
import sys
blob = bytearray(b'\xff' * 4096)
blob[0:4] = b'\x27\x05\x19\x56'             # uImage magic
blob[64:64+4] = b'hsqs'                     # squashfs
nv = (b'http_username=admin\x00http_passwd=S3cretAdmin\x00'
      b'ppp_username=isp@example.net\x00'
      b'wl0_wpa_psk=' + b'a1b2c3d4' * 8 + b'\x00')
blob[1024:1024+len(nv)] = nv
open(sys.argv[1], 'wb').write(bytes(blob))
PY
    out=$(rcon_flash_parse "$img" 2>/dev/null)
    chk parse-uimage "$(printf '%s\n' "$out" | grep -c 'uImage header')" 1
    chk parse-squash "$(printf '%s\n' "$out" | grep -c 'squashfs')" 1
    chk parse-passwd "$(printf '%s\n' "$out" | grep -c 'http_passwd=S3cretAdmin')" 1
    chk parse-ppp    "$(printf '%s\n' "$out" | grep -c 'ppp_username=isp@example.net')" 1
    chk parse-psk    "$(printf '%s\n' "$out" | grep -c 'PSK')" 1
    chk parse-shape  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="IMAGE" && NF!=3{bad++} END{print bad+0}')" 0

    # a dump with nothing recognisable must say so, not invent a finding
    head -c 2048 /dev/urandom > "$MOD_TMP/st-noise.bin"
    out=$(rcon_flash_parse "$MOD_TMP/st-noise.bin" 2>/dev/null)
    chk parse-noise-nocred "$(printf '%s\n' "$out" | grep -c '^CRED')" 0

    # -- guidance verbs produce real text --------------------------------
    # Assert each guide emits substantive text. (An earlier version passed
    # only two arguments to a three-argument chk, so it compared a line count
    # against an empty string and could never pass.)
    local v n
    for v in rcon_uart_guide rcon_uboot_commands rcon_spi_guide; do
        n=$("$v" | grep -c .)
        if (( n > 5 )); then chk "guide-$v" ok ok
        else chk "guide-$v" "$n lines" "more than 5 lines"; fi
    done
    rcon_uart_guide | grep -q '3.3 V' && chk uart-voltage ok ok || chk uart-voltage missing ok
    rcon_spi_guide  | grep -qi 'unpowered' && chk spi-unpowered ok ok || chk spi-unpowered missing ok

    # -- no recovery server here: must report none, not success ----------
    out=$(rcon_tftp_probe_all 2>/dev/null)
    chk probe-shape "$(printf '%s\n' "$out" | awk -F'\t' 'NF<2{bad++} END{print bad+0}')" 0

    chk deps-shape "$(rcon_check_deps | awk -F'\t' 'NF<2{bad++} END{print bad+0}')" 0

    printf 'RESULT\t%s\n' "$([[ $fail -eq 0 ]] && echo PASS || echo "FAIL($fail)")"
    printf 'SUMMARY\t%d pass, %d fail\n' "$pass" "$fail"
    [[ $fail -eq 0 ]]
}

# ── dispatch ─────────────────────────────────────────────────────────────
CMD=""; A=(); ACK=""
while (( $# )); do
    case "$1" in
        --info|--check-deps|--selftest|--tftp-probe-tsv|--uart-guide|--uboot-commands|--spi-guide)
            CMD="$1"; shift ;;
        --tftp-pull|--tftp-push|--flash-parse)
            CMD="$1"; shift
            while [[ -n "${1:-}" && "${1:0:2}" != "--" ]]; do A+=("$1"); shift; done ;;
        --yes-write-to-device) ACK="$1"; shift ;;
        -h|--help) rcon_info; exit 0 ;;
        *) rcon_err "unknown argument '$1'"; exit 2 ;;
    esac
done

case "$CMD" in
    --info)            rcon_info ;;
    --check-deps)      rcon_check_deps ;;
    --selftest)        rcon_selftest ;;
    --tftp-probe-tsv)  rcon_tftp_probe_all ;;
    --tftp-pull)       rcon_tftp_read  "${A[0]:-}" "${A[1]:-}" "${A[2]:-}" ;;
    --tftp-push)       rcon_tftp_write "${A[0]:-}" "${A[1]:-}" "${A[2]:-}" "$ACK" ;;
    --flash-parse)     rcon_flash_parse "${A[0]:-}" ;;
    --uart-guide)      rcon_uart_guide ;;
    --uboot-commands)  rcon_uboot_commands ;;
    --spi-guide)       rcon_spi_guide ;;
    "")                rcon_info >&2; exit 2 ;;
esac

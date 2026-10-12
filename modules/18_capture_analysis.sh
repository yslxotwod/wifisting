#!/usr/bin/env bash
# PCAP analysis — merge, filter, extract hashes, hashcat wrapper
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

CAP_DIR="$TMP_DIR/cap_analysis"
CAP_LOOT="$LOOT_DIR/captures"
CAP_HASHES="$CAP_LOOT/hashes"
CAP_POTFILE="$CAP_DIR/hashcat.potfile"
CAP_PID="$CAP_DIR/hashcat.pid"
CAP_OUT="$CAP_DIR/hashcat.out"
CAP_LOG="$CAP_DIR/hashcat.log"
mkdir -p "$CAP_DIR" "$CAP_LOOT" "$CAP_HASHES"

cap_check_tools() {
    local missing=()
    for t in tshark hcxpcapngtool hashcat aircrack-ng; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    # mergecap is part of wireshark-common
    command -v mergecap >/dev/null 2>&1 || missing+=("mergecap")
    if (( ${#missing[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${missing[*]}")"
        return 1
    fi
    printf 'READY\n'
}

cap_list_pcaps_tsv() {
    {
        find "$CAPTURES_DIR" -maxdepth 3 -type f \
            \( -name '*.cap' -o -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null
        find "$LOOT_DIR" -maxdepth 3 -type f \
            \( -name '*.cap' -o -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null
        find "$TMP_DIR" -maxdepth 4 -type f \
            \( -name '*.cap' -o -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null
    } | sort -u | while read -r f; do
        local sz mt
        sz=$(stat -c%s "$f" 2>/dev/null)
        mt=$(stat -c%Y "$f" 2>/dev/null)
        printf '%s\t%s\t%s\n' "$f" "$sz" "$mt"
    done
}

cap_analyze_tsv() {
    local pcap="$1"
    [[ -z "$pcap" || ! -f "$pcap" ]] && { printf 'ERROR\tno pcap\n' >&2; return 1; }
    command -v tshark >/dev/null || { printf 'ERROR\tno tshark\n' >&2; return 1; }

    local aps clients eapol pmkid probes
    aps=$(tshark -r "$pcap" -Y 'wlan.fc.type_subtype==0x08' \
          -T fields -e wlan.bssid 2>/dev/null | sort -u | grep -c .)
    clients=$(tshark -r "$pcap" -Y 'wlan.fc.type==2' \
              -T fields -e wlan.sa 2>/dev/null | sort -u | grep -c .)
    eapol=$(tshark -r "$pcap" -Y 'eapol' \
            -T fields -e frame.number 2>/dev/null | grep -c .)
    pmkid=$(tshark -r "$pcap" -Y 'eapol.type==2 && wlan.rsn.ie.pmkid' \
            -T fields -e frame.number 2>/dev/null | grep -c .)
    probes=$(tshark -r "$pcap" -Y 'wlan.fc.type_subtype==0x04' \
             -T fields -e wlan.ssid 2>/dev/null | sort -u | grep -c .)

    printf 'aps\t%s\n' "$aps"
    printf 'clients\t%s\n' "$clients"
    printf 'eapol\t%s\n' "$eapol"
    printf 'pmkid\t%s\n' "$pmkid"
    printf 'probes\t%s\n' "$probes"
}

cap_list_aps_tsv() {
    local pcap="$1"
    [[ -z "$pcap" || ! -f "$pcap" ]] && return 1
    tshark -r "$pcap" -Y 'wlan.fc.type_subtype==0x08' \
        -T fields -e wlan.bssid -e wlan.ssid -e wlan_radio.channel \
        2>/dev/null | sort -u | awk -F'\t' 'length($1)==17 { print }'
}

# ── merge ──
cap_merge() {
    local out="$1"; shift
    local inputs=("$@")
    [[ -z "$out" ]] && { printf 'ERROR\tno output\n' >&2; return 2; }
    (( ${#inputs[@]} < 2 )) && { printf 'ERROR\tneed 2+ inputs\n' >&2; return 2; }
    command -v mergecap >/dev/null 2>&1 || {
        printf 'ERROR\tmergecap missing (wireshark-common)\n' >&2; return 1; }

    for f in "${inputs[@]}"; do
        [[ -f "$f" ]] || { printf 'ERROR\tmissing input: %s\n' "$f" >&2; return 1; }
    done

    info "merging ${#inputs[@]} files → $out"
    mergecap -w "$out" "${inputs[@]}" 2>&1
    if [[ -s "$out" ]]; then
        printf 'MERGED\t%s\nSIZE\t%s\n' "$out" "$(stat -c%s "$out")"
    else
        printf 'ERROR\tmerge failed\n' >&2
        return 1
    fi
}

# ── filter (extract a subset from a pcap) ──
cap_filter() {
    local pcap="$1" filter="$2" out="$3"
    [[ -z "$pcap" || ! -f "$pcap" ]] && { printf 'ERROR\tno input\n' >&2; return 1; }
    [[ -z "$filter" ]] && { printf 'ERROR\tno filter\n' >&2; return 2; }
    [[ -z "$out" ]] && out="${pcap%.*}_filtered.${pcap##*.}"

    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\tno tshark\n' >&2; return 1; }

    info "filtering $pcap with '$filter' → $out"
    tshark -r "$pcap" -Y "$filter" -w "$out" 2>&1 | tail -3

    if [[ -s "$out" ]]; then
        printf 'FILTERED\t%s\nSIZE\t%s\n' "$out" "$(stat -c%s "$out")"
    else
        printf 'ERROR\tempty result\n' >&2
        return 1
    fi
}

cap_filter_by_bssid() {
    local pcap="$1" bssid="$2" out="$3"
    [[ -z "$bssid" ]] && { printf 'ERROR\tno bssid\n' >&2; return 2; }
    cap_filter "$pcap" "wlan.bssid == $bssid" "$out"
}

cap_filter_by_ssid() {
    local pcap="$1" ssid="$2" out="$3"
    [[ -z "$ssid" ]] && { printf 'ERROR\tno ssid\n' >&2; return 2; }
    # Quote the SSID inside the filter for tshark
    cap_filter "$pcap" "wlan.ssid == \"$ssid\"" "$out"
}

# ── extract hash with per-file count ──
cap_extract_hashes() {
    local pcap="$1" out="$2"
    [[ -z "$pcap" || ! -f "$pcap" ]] && { printf 'ERROR\tno pcap\n' >&2; return 1; }
    [[ -z "$out" ]] && out="$CAP_HASHES/$(basename "${pcap%.*}").22000"
    mkdir -p "$(dirname "$out")"
    command -v hcxpcapngtool >/dev/null || {
        printf 'ERROR\tno hcxpcapngtool\n' >&2; return 1; }

    hcxpcapngtool -o "$out" "$pcap" >/dev/null 2>&1
    if [[ -s "$out" ]]; then
        local n
        n=$(wc -l < "$out")
        printf 'HASHFILE\t%s\nCOUNT\t%s\n' "$out" "$n"
    else
        printf 'NOHASH\n'; return 1
    fi
}

# ── hash listing with per-file hash count ──
cap_list_hashes_tsv() {
    local f
    for f in "$CAP_HASHES"/*.22000; do
        [[ -e "$f" ]] || continue
        local sz count
        sz=$(stat -c%s "$f")
        count=$(grep -c . "$f" 2>/dev/null) || count=0
        printf '%s\t%s\t%s\n' "$f" "$sz" "$count"
    done
}

# ── multi-pcap handshake correlation ──
# Scan every pcap in a directory, extract hashes into one combined file
# per unique BSSID, and report which pcaps contributed.
cap_correlate_handshakes() {
    local dir="${1:-$CAPTURES_DIR}"
    [[ -d "$dir" ]] || { printf 'ERROR\tno dir\n' >&2; return 1; }
    command -v hcxpcapngtool >/dev/null 2>&1 || {
        printf 'ERROR\tno hcxpcapngtool\n' >&2; return 1; }

    local combined="$CAP_HASHES/all_combined.22000"
    local seen_dir="$CAP_DIR/correlation"
    mkdir -p "$seen_dir"
    : > "$combined"

    info "scanning $dir for pcaps…"

    local pcap
    find "$dir" -maxdepth 3 -type f \
        \( -name '*.cap' -o -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null | \
    while read -r pcap; do
        local tmp="$seen_dir/$(basename "${pcap%.*}").22000"
        hcxpcapngtool -o "$tmp" "$pcap" >/dev/null 2>&1 || continue
        if [[ -s "$tmp" ]]; then
            local n
            n=$(wc -l < "$tmp")
            printf 'CONTRIB\t%s\t%s\n' "$pcap" "$n"
            cat "$tmp" >> "$combined"
        fi
    done

    if [[ -s "$combined" ]]; then
        # Dedup by full-line
        sort -u "$combined" -o "$combined"
        local total
        total=$(wc -l < "$combined")
        printf 'COMBINED\t%s\nUNIQUE_HASHES\t%s\n' "$combined" "$total"
    else
        printf 'NOHASHES\n'
        return 1
    fi
}

# ── crack ──
cap_start_crack() {
    local hashfile="$1" mode="$2" wordlist="$3"
    local workload="${4:-}" opt="${5:-}" device="${6:-}"
    local rules="${7:-}"
    [[ -z "$hashfile" || ! -f "$hashfile" ]] && {
        printf 'ERROR\tno hashfile\n' >&2; return 1; }
    [[ -z "$mode" ]] && mode="22000"
    [[ -z "$wordlist" ]] && wordlist="/usr/share/wordlists/rockyou.txt"
    [[ ! -f "$wordlist" ]] && { printf 'ERROR\tno wordlist\n' >&2; return 1; }
    command -v hashcat >/dev/null || { printf 'ERROR\tno hashcat\n' >&2; return 1; }

    if [[ -f "$CAP_PID" ]] && kill -0 "$(cat "$CAP_PID")" 2>/dev/null; then
        printf 'ERROR\tcrack already running\n' >&2; return 1
    fi

    local -a extra=()
    [[ -n "$workload" && "$workload" =~ ^[1-4]$ ]] && extra+=(-w "$workload")
    [[ "$opt" == "1" || "$opt" == "yes" || "$opt" == "on" ]] && extra+=(-O)
    [[ -n "$device" && "$device" =~ ^[0-9,]+$ ]] && extra+=(-d "$device")
    if [[ -n "$rules" && -f "$rules" ]]; then
        extra+=(-r "$rules")
    fi

    ( hashcat -m "$mode" -a 0 "${extra[@]}" "$hashfile" "$wordlist" \
        --potfile-path "$CAP_POTFILE" \
        --outfile "$CAP_OUT" \
        --status --status-timer=5 \
        > "$CAP_LOG" 2>&1 & echo $! > "$CAP_PID" )
    sleep 1
    printf 'STARTED\t%s\nLOG\t%s\nARGS\t%s\n' \
        "$(cat "$CAP_PID")" "$CAP_LOG" "${extra[*]}"
}

# Enumerate rule files hashcat can use. Returns path<TAB>name so the
# GUI can show a friendly label while passing the real path.
cap_list_rules_tsv() {
    local dir f
    for dir in /usr/share/hashcat/rules /usr/share/john/rules; do
        [[ -d "$dir" ]] || continue
        for f in "$dir"/*.rule "$dir"/*.rules; do
            [[ -f "$f" ]] || continue
            printf '%s\t%s\n' "$f" "$(basename "$f")"
        done
    done
}

cap_list_devices() {
    command -v hashcat >/dev/null || { printf 'ERROR\tno hashcat\n' >&2; return 1; }
    hashcat -I 2>/dev/null | awk '
        /Backend Device ID #/ { id=$NF }
        /Type\.\.\.\.\.\.\.\.\.\.\.:/ { type=$2 }
        /Name\.\.\.\.\.\.\.\.\.\.\.:/ {
            sub(/^[^:]+:[[:space:]]*/, "")
            name=$0
            printf "%s\t%s\t%s\n", id, type, name
        }
    '
}

cap_benchmark() {
    local mode="${1:-22000}"
    local workload="${2:-}"
    local -a extra=()
    [[ -n "$workload" && "$workload" =~ ^[1-4]$ ]] && extra+=(-w "$workload")
    hashcat -b -m "$mode" "${extra[@]}" --quiet 2>&1 | tail -20
}

cap_stop_crack() {
    local killed=0 pid=""
    [[ -f "$CAP_PID" ]] && pid=$(cat "$CAP_PID")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
    fi
    stop_sweep 'hashcat -m' && killed=1

    if (( killed == 1 )); then
        rm -f "$CAP_PID"
        printf 'STOPPED\n'
        return 0
    fi
    if [[ -n "$pid" ]]; then
        printf 'ERROR\thashcat pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
}

cap_crack_status() {
    local running=0 cracked=0
    if [[ -f "$CAP_PID" ]] && kill -0 "$(cat "$CAP_PID")" 2>/dev/null; then
        running=1
    fi
    [[ -f "$CAP_OUT" ]] && { cracked=$(grep -c . "$CAP_OUT" 2>/dev/null) || cracked=0; }

    printf 'running\t%s\n' "$running"
    printf 'cracked\t%s\n' "$cracked"
    [[ -f "$CAP_OUT" ]] && tail -5 "$CAP_OUT" 2>/dev/null | \
        sed 's/^/RESULT\t/'
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

# ── Convert (merged from handshake_convert, submenu: Convert) ────────────
# Re-encode a capture or an existing hash file into another cracker's
# format. The backend depends on the input: a pcap/pcapng goes through
# hcxpcapngtool (which parses the frames itself), while an existing
# 22000/hccapx hash file goes through hcxhashtool (which only re-filters).

CAP_CONVERTED="$CAP_LOOT/converted"

# Which tool can read this input at all?
cap_convert_backend() {
    case "${1##*.}" in
        22000|hc22000|hccapx) printf 'hash' ;;
        cap|pcap|pcapng)      printf 'pcap' ;;
        *)                    printf '' ;;
    esac
}

cap_convert_formats_tsv() {
    local hp hh he
    hp=$(command -v hcxpcapngtool >/dev/null 2>&1 && echo 1 || echo 0)
    hh=$(command -v hcxhashtool  >/dev/null 2>&1 && echo 1 || echo 0)
    he=$(command -v editcap      >/dev/null 2>&1 && echo 1 || echo 0)
    # FORMAT  BACKEND  TOOL  AVAILABLE  DESCRIPTION
    printf '22000\tpcap\thcxpcapngtool\t%s\thashcat -m 22000 (PMKID + EAPOL)\n' "$hp"
    printf '22000\thash\thcxhashtool\t%s\thashcat -m 22000, re-filtered\n'      "$hh"
    printf 'hccapx\tpcap\thcxpcapngtool\t%s\thashcat -m 2500 (legacy)\n'        "$hp"
    printf 'hccapx\thash\thcxhashtool\t%s\thashcat -m 2500 (legacy)\n'          "$hh"
    printf 'john\tpcap\thcxpcapngtool\t%s\tJohn the Ripper wpapsk\n'            "$hp"
    printf 'john\thash\thcxhashtool\t%s\tJohn the Ripper wpapsk\n'              "$hh"
    printf 'pmkid\tpcap\thcxpcapngtool\t%s\tdeprecated PMKID list\n'            "$hp"
    printf 'essid\tpcap\thcxpcapngtool\t%s\tESSID wordlist\n'                   "$hp"
    printf 'identity\tpcap\thcxpcapngtool\t%s\tEAP identity list\n'             "$hp"
    printf 'pcapng\tpcap\teditcap\t%s\tnormalise container format\n'            "$he"
}

# Everything the Convert page can take as input, in one list: captures
# (parsed by hcxpcapngtool) and existing hash files (re-filtered by
# hcxhashtool). KIND tells the GUI which backend a row will use.
cap_convert_sources_tsv() {
    local f sz
    while IFS= read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        sz=$(stat -c%s "$f" 2>/dev/null) || sz=0
        case "${f##*.}" in
            22000|hc22000|hccapx) printf '%s\t%s\thash\n' "$f" "$sz" ;;
            *)                    printf '%s\t%s\tpcap\n' "$f" "$sz" ;;
        esac
    done < <(cap_list_pcaps_tsv | cut -f1; cap_list_hashes_tsv | cut -f1)
}

cap_convert() {
    local in="$1" fmt="$2" out="$3"
    [[ -z "$in" || ! -f "$in" ]] && {
        printf 'ERROR\tinput not found: %s\n' "${in:-<none>}" >&2; return 1; }
    [[ -z "$fmt" ]] && { printf 'ERROR\tno target format\n' >&2; return 2; }

    local backend
    backend=$(cap_convert_backend "$in")
    if [[ -z "$backend" ]]; then
        printf 'ERROR\tunsupported input type: %s (want pcap/pcapng/cap/22000/hccapx)\n' \
               "$in" >&2
        return 1
    fi

    mkdir -p "$CAP_CONVERTED"
    if [[ -z "$out" ]]; then
        local stem; stem=$(basename "${in%.*}")
        out="$CAP_CONVERTED/$stem.$fmt"
    fi
    mkdir -p "$(dirname "$out")" 2>/dev/null

    # Remove any previous output first: a stale file left by an earlier run
    # would otherwise be indistinguishable from a successful conversion.
    rm -f "$out"

    local tool="" err="" rc=0
    case "$backend:$fmt" in
        pcap:22000)
            tool=hcxpcapngtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxpcapngtool -o "$out" "$in" 2>&1) || rc=$? ;;
        pcap:hccapx)
            tool=hcxpcapngtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxpcapngtool --hccapx="$out" "$in" 2>&1) || rc=$? ;;
        pcap:john)
            tool=hcxpcapngtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxpcapngtool --john="$out" "$in" 2>&1) || rc=$? ;;
        pcap:pmkid)
            tool=hcxpcapngtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxpcapngtool --pmkid="$out" "$in" 2>&1) || rc=$? ;;
        pcap:essid)
            tool=hcxpcapngtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxpcapngtool -E "$out" "$in" 2>&1) || rc=$? ;;
        pcap:identity)
            tool=hcxpcapngtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxpcapngtool -I "$out" "$in" 2>&1) || rc=$? ;;
        pcap:pcapng)
            tool=editcap
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(editcap -F pcapng "$in" "$out" 2>&1) || rc=$? ;;
        hash:22000)
            tool=hcxhashtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxhashtool -i "$in" -o "$out" 2>&1) || rc=$? ;;
        hash:hccapx)
            tool=hcxhashtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxhashtool -i "$in" --hccapx="$out" 2>&1) || rc=$? ;;
        hash:john)
            tool=hcxhashtool
            command -v "$tool" >/dev/null 2>&1 || { printf 'ERROR\t%s missing\n' "$tool" >&2; return 1; }
            err=$(hcxhashtool -i "$in" --john="$out" 2>&1) || rc=$? ;;
        *)
            printf 'ERROR\tcannot convert %s input to %s\n' "$backend" "$fmt" >&2
            return 1 ;;
    esac

    # Never report success on the strength of an exit status alone: an empty
    # file means the capture simply held no usable handshake material.
    if [[ ! -s "$out" ]]; then
        printf 'EMPTY\t1\n'
        printf 'TOOL\t%s\n' "$tool"
        printf 'NOTE\tno %s material found in %s\n' "$fmt" "$in"
        rm -f "$out"
        return 1
    fi

    printf 'IN\t%s\n'      "$in"
    printf 'BACKEND\t%s\n' "$backend"
    printf 'FORMAT\t%s\n'  "$fmt"
    printf 'TOOL\t%s\n'    "$tool"
    printf 'OUT\t%s\n'     "$out"
    printf 'SIZE\t%s\n'    "$(stat -c%s "$out")"
    printf 'LINES\t%s\n'   "$(wc -l < "$out" 2>/dev/null || echo 0)"
    return 0
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline, no capture and no card: the format matrix and the conversion
# guards are pure logic around the hook tools. Scratch files live under
# $CAP_DIR/selftest so nothing is written into loot/ or captures/.
#
# The trap being guarded: hcxpcapngtool exits 0 on a capture that holds no
# handshake material and simply writes no file. Trusting the exit status
# would report a successful conversion of nothing.
cap_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    local MOD_TMP="$CAP_DIR/selftest" out rc
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP"
    # cap_convert mkdir's $CAP_CONVERTED before it looks at the output path,
    # so point it at scratch too — the selftest must not create anything
    # under loot/.
    local saved_converted="$CAP_CONVERTED"
    CAP_CONVERTED="$MOD_TMP/converted"

    # 1. input-type detection by extension — this picks the backend
    chk backend-22000    "$(cap_convert_backend "a.22000")"   hash
    chk backend-hc22000  "$(cap_convert_backend "a.hc22000")" hash
    chk backend-hccapx   "$(cap_convert_backend "a.hccapx")"  hash
    chk backend-cap      "$(cap_convert_backend "a.cap")"     pcap
    chk backend-pcap     "$(cap_convert_backend "a.pcap")"    pcap
    chk backend-pcapng   "$(cap_convert_backend "a.pcapng")"  pcap
    chk backend-txt      "$(cap_convert_backend "a.txt")"     ""
    chk backend-noext    "$(cap_convert_backend "noext")"     ""
    chk backend-upper    "$(cap_convert_backend "A.PCAP")"    ""

    # 2. rejection paths — malformed input must never look like success
    out=$(cap_convert "$MOD_TMP/absent.pcap" 22000 "$MOD_TMP/absent.22000" 2>&1); rc=$?
    chk missing-input-rc  "$rc" 1
    chk missing-input-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "input not found: $MOD_TMP/absent.pcap"
    if [[ -e "$MOD_TMP/absent.22000" ]]; then
        printf 'missing-input-no-output\tFAIL (created an output for a missing input)\n'; bad=$((bad+1))
    else printf 'missing-input-no-output\tPASS\n'; fi

    printf 'not a capture\n' > "$MOD_TMP/junk.txt"
    out=$(cap_convert "$MOD_TMP/junk.txt" 22000 "$MOD_TMP/junk.22000" 2>&1); rc=$?
    chk unsupported-ext-rc  "$rc" 1
    chk unsupported-ext-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "unsupported input type: $MOD_TMP/junk.txt (want pcap/pcapng/cap/22000/hccapx)"

    out=$(cap_convert "$MOD_TMP/junk.txt" "" "$MOD_TMP/junk.22000" 2>&1); rc=$?
    chk no-format-rc "$rc" 2

    # valid input kind, impossible format pair -> refused, not half-done
    printf 'WPA*01*00000000000000000000000000000000*aabbccddeeff*112233445566*5465737453534944***\n' \
        > "$MOD_TMP/synth.22000"
    out=$(cap_convert "$MOD_TMP/synth.22000" essid "$MOD_TMP/x.essid" 2>&1); rc=$?
    chk bad-combo-rc  "$rc" 1
    chk bad-combo-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}' | head -1)" \
        "cannot convert hash input to essid"

    # 3. a capture with no handshake material: tool exits 0, writes nothing
    if command -v hcxpcapngtool >/dev/null 2>&1; then
        # 24-byte classic pcap global header, zero packets
        printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' \
            > "$MOD_TMP/empty.pcap"
        printf 'STALE PREVIOUS OUTPUT\n' > "$MOD_TMP/empty.22000"
        out=$(cap_convert "$MOD_TMP/empty.pcap" 22000 "$MOD_TMP/empty.22000" 2>&1); rc=$?
        chk empty-rc   "$rc" 1
        chk empty-flag "$(printf '%s\n' "$out" | awk -F'\t' '$1=="EMPTY"{print $2}')" 1
        chk empty-tool "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TOOL"{print $2}')" hcxpcapngtool
        chk empty-no-success "$(printf '%s\n' "$out" | grep -c '^OUT')" 0
        if [[ -e "$MOD_TMP/empty.22000" ]]; then
            printf 'empty-removes-stale\tFAIL (stale output left behind)\n'; bad=$((bad+1))
        else printf 'empty-removes-stale\tPASS\n'; fi
    else
        out=$(cap_convert "$MOD_TMP/empty.pcap" 22000 "$MOD_TMP/empty.22000" 2>&1); rc=$?
        chk no-tool-rc  "$rc" 1
        chk no-tool-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
            "hcxpcapngtool missing"
    fi

    # 4. the success path still works: hash -> hash re-filter round-trip
    if command -v hcxhashtool >/dev/null 2>&1; then
        out=$(cap_convert "$MOD_TMP/synth.22000" 22000 "$MOD_TMP/round.22000" 2>&1); rc=$?
        chk roundtrip-rc      "$rc" 0
        chk roundtrip-backend "$(printf '%s\n' "$out" | awk -F'\t' '$1=="BACKEND"{print $2}')" hash
        chk roundtrip-tool    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TOOL"{print $2}')"    hcxhashtool
        chk roundtrip-lines   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="LINES"{print $2}')"   1
        chk roundtrip-bytes   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="SIZE" && $2>0{c++} END{print c+0}')" 1
        chk roundtrip-content "$(cat "$MOD_TMP/round.22000" 2>/dev/null)" \
            "WPA*01*00000000000000000000000000000000*aabbccddeeff*112233445566*5465737453534944***"
    fi

    # 5. pcap -> pcapng routes to editcap, not hcxpcapngtool
    if command -v editcap >/dev/null 2>&1 && [[ -f "$MOD_TMP/empty.pcap" ]]; then
        out=$(cap_convert "$MOD_TMP/empty.pcap" pcapng "$MOD_TMP/out.pcapng" 2>&1); rc=$?
        chk pcapng-rc   "$rc" 0
        chk pcapng-tool "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TOOL"{print $2}')" editcap
        if [[ -s "$MOD_TMP/out.pcapng" ]]; then printf 'pcapng-written\tPASS\n'
        else printf 'pcapng-written\tFAIL (no output)\n'; bad=$((bad+1)); fi
    fi

    # 6. the advertised format matrix is well formed
    chk formats-rows  "$(cap_convert_formats_tsv | grep -c .)" 10
    chk formats-cols  "$(cap_convert_formats_tsv | awk -F'\t' 'NF!=5{c++} END{print c+0}')" 0
    chk formats-avail "$(cap_convert_formats_tsv | awk -F'\t' '$4!="0" && $4!="1"{c++} END{print c+0}')" 0
    chk formats-kinds "$(cap_convert_formats_tsv | awk -F'\t' '$2!="pcap" && $2!="hash"{c++} END{print c+0}')" 0

    # 7. hash listing: PATH<TAB>SIZE<TAB>non-empty-line-count, *.22000 only
    mkdir -p "$MOD_TMP/hashes"
    printf 'WPA*01*a\n' > "$MOD_TMP/hashes/one.22000"
    printf 'x\ny\n\n'  > "$MOD_TMP/hashes/two.22000"
    printf 'ignored\n' > "$MOD_TMP/hashes/notahash.txt"
    out=$( CAP_HASHES="$MOD_TMP/hashes"; cap_list_hashes_tsv )
    chk list-hashes-rows     "$(printf '%s\n' "$out" | grep -c .)" 2
    chk list-hashes-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=3{c++} END{print c+0}')" 0
    chk list-hashes-size-one "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /one\.22000$/ {print $2}')" 9
    chk list-hashes-count-one "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /one\.22000$/ {print $3}')" 1
    chk list-hashes-count-two "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /two\.22000$/ {print $3}')" 2

    rm -rf "$MOD_TMP"
    CAP_CONVERTED="$saved_converted"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

cap_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --check-tools)     cap_check_tools ;;
        --list-pcaps-tsv)  cap_list_pcaps_tsv ;;
        --analyze-tsv)     cap_analyze_tsv "$@" ;;
        --list-aps-tsv)    cap_list_aps_tsv "$@" ;;
        --merge)           cap_merge "$@" ;;
        --filter)          cap_filter "$@" ;;
        --filter-bssid)    cap_filter_by_bssid "$@" ;;
        --filter-ssid)     cap_filter_by_ssid "$@" ;;
        --extract)         cap_extract_hashes "$@" ;;
        --list-hashes-tsv) cap_list_hashes_tsv ;;
        --correlate)       cap_correlate_handshakes "$@" ;;
        --crack)           cap_start_crack "$@" ;;
        --list-rules-tsv)  cap_list_rules_tsv ;;
        --list-devices)    cap_list_devices ;;
        --benchmark)       cap_benchmark "$@" ;;
        --crack-stop)      cap_stop_crack ;;
        --crack-status)    cap_crack_status ;;
        --convert)         cap_convert "$@" ;;
        --convert-formats-tsv) cap_convert_formats_tsv ;;
        --convert-sources-tsv) cap_convert_sources_tsv ;;
        --selftest)        cap_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --check-tools
  --list-pcaps-tsv
  --analyze-tsv PCAP
  --list-aps-tsv PCAP
  --merge OUT IN1 IN2 [IN3 ...]
  --filter PCAP DISPLAY_FILTER [OUT]
  --filter-bssid PCAP BSSID [OUT]
  --filter-ssid PCAP SSID [OUT]
  --extract PCAP [OUTFILE]
  --list-hashes-tsv
  --correlate [DIR]
  --crack HASHFILE [MODE] [WORDLIST] [WL_LEVEL] [OPT] [DEVICE]
  --list-devices
  --benchmark [MODE] [WORKLOAD]
  --crack-stop
  --crack-status
  --convert INPUT FORMAT [OUT]
      FORMAT: 22000|hccapx|john|pmkid|essid|identity|pcapng
      pcap/pcapng/cap -> hcxpcapngtool, 22000/hccapx -> hcxhashtool
  --convert-formats-tsv
  --convert-sources-tsv
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
    cap_cli_main "$@"
fi

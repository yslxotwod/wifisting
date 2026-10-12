#!/usr/bin/env bash
# Resolve WIFISTING_ROOT from this script's own path so state/loot land in the
# project tree even when launched standalone via pkexec (no wifisting.sh env).
if [[ -z "${WIFISTING_ROOT:-}" ]]; then
    _bfs_src="${BASH_SOURCE[0]}"
    while [ -L "$_bfs_src" ]; do
        _bfs_dir="$(cd -P "$(dirname "$_bfs_src")" && pwd)"
        _bfs_tgt="$(readlink "$_bfs_src")"
        [[ "$_bfs_tgt" != /* ]] && _bfs_tgt="$_bfs_dir/$_bfs_tgt"
        _bfs_src="$_bfs_tgt"
    done
    WIFISTING_ROOT="$(cd -P "$(dirname "$_bfs_src")/.." && pwd)"
    export WIFISTING_ROOT
    unset _bfs_src _bfs_dir _bfs_tgt
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
# Single shared temp root. Other modules write cross-module state here
# (mon_iface, target_bssid, ...); using $WIFISTING_ROOT/tmp silently
# split those reads and made this module unable to see a monitor
# interface or target at all.
: "${TMP_DIR:=/tmp/wifisting}"
: "${LOOT_DIR:=$WIFISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$WIFISTING_ROOT/captures}"
: "${LOGS_DIR:=$WIFISTING_ROOT/logs}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" 2>/dev/null

# bt cve scan — fingerprint nearby bt devices against known CVEs

BT_CVE_DIR="$TMP_DIR/bt_cve"
BT_CVE_TARGETS="$BT_CVE_DIR/targets.txt"
BT_CVE_RESULTS="$BT_CVE_DIR/results.txt"
MOD_TMP="$TMP_DIR/bt_cve"
mkdir -p "$MOD_TMP" 2>/dev/null

btcve_init() {
    mkdir -p "$BT_CVE_DIR"
    : > "$BT_CVE_TARGETS"
    [[ -f "$BT_CVE_RESULTS" ]] || : > "$BT_CVE_RESULTS"
}

btcve_require_iface() {
    BT_HCI_IFACE="${BT_HCI_IFACE:-hci0}"
    hciconfig "$BT_HCI_IFACE" >/dev/null 2>&1 || {
        err "no $BT_HCI_IFACE interface — check it's up in iface manager"
        read -rp "  press enter " _
        return 1
    }
    hciconfig "$BT_HCI_IFACE" up 2>/dev/null
    return 0
}

# --- discovery ---

btcve_scan_classic() {
    info "classic BT inquiry on $BT_HCI_IFACE (~10s)..."
    local out
    out=$(hcitool -i "$BT_HCI_IFACE" scan --length=10 2>/dev/null)
    [[ -z "$out" ]] && { warn "no classic devices found"; return 1; }
    echo "$out" | tail -n +1 | while read -r mac name; do
        [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue
        echo "$mac|$name" >> "$BT_CVE_TARGETS"
    done
    ok "found $(wc -l < "$BT_CVE_TARGETS") classic devices"
    cat "$BT_CVE_TARGETS" | while IFS='|' read -r m n; do
        echo -e "  ${C_CYN}$m${C_RESET}  $n"
    done
}

btcve_scan_ble() {
    command -v hcitool >/dev/null || { err "hcitool missing"; return 1; }
    info "BLE scan (lescan, 15s)..."
    timeout 15 hcitool -i "$BT_HCI_IFACE" lescan 2>/dev/null | \
        grep -E '^([0-9A-Fa-f]{2}:){5}' | sort -u > "$BT_CVE_DIR/ble_raw.txt"
    local n; n=$(wc -l < "$BT_CVE_DIR/ble_raw.txt")
    ok "found $n BLE devices"
    cp "$BT_CVE_DIR/ble_raw.txt" "$BT_CVE_DIR/ble_targets.txt"
}

# --- CVE checks ---

# CVE-2017-1000250/251/252 (BlueBorne) — L2CAP/SDP/BNEP parsing bugs in Linux/Android/Windows stacks.
# Detection: check if device exposes vulnerable profiles. Actual memory-corruption testing needs
# the BlueBorne PoC scripts; we flag exposure and hand off.
btcve_check_blueborne() {
    local mac="$1" name="$2"
    info "blueborne profile check on $mac..."
    local sdp
    sdp=$(sdptool --bdaddr "$mac" browse 2>/dev/null | grep -E "Service Name|Protocol:" | head -20)
    local vuln=0
    # vulnerable stacks expose BNEP (personal ad-hoc) or unfiltered L2CAP
    if echo "$sdp" | grep -qi "BNEP\|PAN"; then
        vuln=1
        echo "[$mac] blueborne: BNEP exposed — potential CVE-2017-1000252" >> "$BT_CVE_RESULTS"
        echo -e "  ${C_RED}[!] $mac — BNEP service exposed (BlueBorne candidate)${C_RESET}"
    fi
    if [[ $vuln -eq 0 ]]; then
        echo "[$mac] blueborne: no BNEP exposure detected" >> "$BT_CVE_RESULTS"
        echo -e "  ${C_GRN}[+] $mac — no obvious BlueBorne exposure${C_RESET}"
    fi
}

# CVE-2019-9506 (KNOB) — encryption key entropy downgrade. Need to sniff the pairing
# exchange; if the negotiated key length < 7 bytes, vulnerable. We check locally-configured
# min entropy as a proxy and flag remote devices we can't confirm.
btcve_check_knob() {
    local mac="$1"
    info "KNOB check on $mac..."
    local min_key
    min_key=$(btmgmt info 2>/dev/null | grep -i "min_enc_key" | head -1)
    echo "[$mac] knob: local min-entropy = ${min_key:-unknown} — remote device needs pairing-capture to confirm" >> "$BT_CVE_RESULTS"
    warn "$mac: KNOB needs a pairing exchange capture (ubertooth/btlejack) — flagged for manual review"
}

# CVE-2020-10135 (BIAS) — legacy pairing auth bypass. Devices supporting legacy pairing
# with no secure simple pairing flag are candidates.
btcve_check_bias() {
    local mac="$1"
    info "BIAS check on $mac..."
    local info_out
    info_out=$(hcitool -i "$BT_HCI_IFACE" info "$mac" 2>/dev/null)
    if echo "$info_out" | grep -q "SSP.*disabled\|Legacy"; then
        echo "[$mac] bias: legacy pairing mode — CVE-2020-10135 candidate" >> "$BT_CVE_RESULTS"
        echo -e "  ${C_YEL}[!] $mac — legacy pairing (BIAS candidate)${C_RESET}"
    else
        echo "[$mac] bias: SSP active — likely patched" >> "$BT_CVE_RESULTS"
        echo -e "  ${C_GRN}[+] $mac — SSP active${C_RESET}"
    fi
}

# CVE-2020-10134 (BLESA) — unauthenticated BLE reconnection. Test: connect, drop, reconnect
# without pairing, see if characteristic reads still work.
btcve_check_blesa() {
    local mac="$1"
    info "BLESA reconnect test on $mac..."
    # attempt unauthenticated read of a characteristic
    local val
    val=$(timeout 8 gatttool -i "$BT_HCI_IFACE" -b "$mac" --char-read 2>&1 | head -5)
    if echo "$val" | grep -qi "value\|handle"; then
        echo "[$mac] blesa: unauthenticated GATT read succeeded — CVE-2020-10134 candidate" >> "$BT_CVE_RESULTS"
        echo -e "  ${C_RED}[!] $mac — GATT readable without auth (BLESA candidate)${C_RESET}"
    else
        echo "[$mac] blesa: GATT read blocked or timed out" >> "$BT_CVE_RESULTS"
        echo -e "  ${C_GRN}[+] $mac — GATT auth enforced or unreachable${C_RESET}"
    fi
}

# CVE-2020-15802 (BLURtooth) — cross-transport key confusion. Both BR/EDR and LE
# must be active on the device for the confusion to apply.
btcve_check_blurtooth() {
    local mac="$1"
    info "BLURtooth dual-stack check on $mac..."
    local has_le has_classic
    has_le=$(hcitool -i "$BT_HCI_IFACE" leinfo "$mac" 2>/dev/null | head -1)
    has_classic=$(hcitool -i "$BT_HCI_IFACE" info "$mac" 2>/dev/null | grep -c "Features")
    if [[ -n "$has_le" && "$has_classic" -gt 0 ]]; then
        echo "[$mac] blurtooth: dual-mode (BR/EDR + LE) — CVE-2020-15802 candidate" >> "$BT_CVE_RESULTS"
        echo -e "  ${C_YEL}[!] $mac — dual-mode device (BLURtooth candidate)${C_RESET}"
    else
        echo "[$mac] blurtooth: single-mode" >> "$BT_CVE_RESULTS"
    fi
}

# CVE-2021-28414 / BrakTooth family — LMP stack overflow in firmware. No remote-safe
# probe; we flag devices with known-vulnerable OUI + firmware combos.
btcve_check_braktooth() {
    local mac="$1"
    local oui; oui=$(echo "$mac" | cut -d: -f1-3)
    # known-affected vendor prefixes (Intel, CSR, Broadcom, TI chips in affected FW revs)
    case "$(echo "$oui" | tr 'a-f' 'A-F')" in
        00:1A:7D|00:02:72|00:0C:10|00:1B:20)
            echo "[$mac] braktooth: vendor OUI $oui matches affected-chip list — manual firmware check needed" >> "$BT_CVE_RESULTS"
            echo -e "  ${C_YEL}[!] $mac — OUI $oui in affected-chip list${C_RESET}"
            ;;
        *)
            echo "[$mac] braktooth: OUI not in known-affected list" >> "$BT_CVE_RESULTS"
            ;;
    esac
}

# --- main scan loop ---

btcve_scan_all() {
    btcve_init
    btcve_require_iface || return 1

    echo -e "\n  ${C_MAG}=== bt cve scan — full sweep ===${C_RESET}\n"
    btcve_scan_classic
    btcve_scan_ble

    [[ -s "$BT_CVE_TARGETS" ]] || { warn "no classic targets"; }
    [[ -s "$BT_CVE_DIR/ble_targets.txt" ]] || { warn "no ble targets"; }

    # classic devices — run blueborne / bias / braktooth
    if [[ -s "$BT_CVE_TARGETS" ]]; then
        while IFS='|' read -r mac name; do
            [[ -z "$mac" ]] && continue
            echo -e "\n  ${C_CYN}--- $mac ($name) ---${C_RESET}"
            btcve_check_blueborne "$mac" "$name"
            btcve_check_bias "$mac"
            btcve_check_blurtooth "$mac"
            btcve_check_braktooth "$mac"
            btcve_check_knob "$mac"
        done < "$BT_CVE_TARGETS"
    fi

    # ble devices — run blesa
    if [[ -s "$BT_CVE_DIR/ble_targets.txt" ]]; then
        while read -r mac; do
            [[ -z "$mac" ]] && continue
            echo -e "\n  ${C_CYN}--- $mac (BLE) ---${C_RESET}"
            btcve_check_blesa "$mac"
        done < "$BT_CVE_DIR/ble_targets.txt"
    fi

    echo -e "\n  ${C_MAG}=== scan complete ===${C_RESET}"
    ok "results saved to $BT_CVE_RESULTS"
    read -rp "  press enter " _
}

btcve_show_results() {
    if [[ ! -s "$BT_CVE_RESULTS" ]]; then
        warn "no results yet — run a scan first"
        read -rp "  press enter " _
        return
    fi
    echo -e "\n  ${C_MAG}=== bt cve results ===${C_RESET}\n"
    cat "$BT_CVE_RESULTS"
    echo ""
    read -rp "  press enter " _
}

btcve_clear_results() {
    : > "$BT_CVE_RESULTS"
    ok "results cleared"
    sleep 1
}

btcve_export_results() {
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local out; out="$LOOT_DIR/bt_cve_results_${ts}.txt"
    [[ -s "$BT_CVE_RESULTS" ]] || { warn "nothing to export"; sleep 1; return; }
    cp "$BT_CVE_RESULTS" "$out"
    ok "exported to $out"
    sleep 1
}

btcve_set_iface() {
    read -rp "  hci iface [default hci0]> " i
    [[ -z "$i" ]] && i="hci0"
    if hciconfig "$i" >/dev/null 2>&1; then
        BT_HCI_IFACE="$i"
        export BT_HCI_IFACE
        ok "set: $BT_HCI_IFACE"
    else
        err "no such iface"
    fi
    sleep 1
}

btcve_scan_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== bt cve scan ===${C_RESET}"
        echo -e "  iface: ${C_GRN}${BT_HCI_IFACE:-hci0}${C_RESET}"
        echo -e "  results: ${C_GRN}$BT_CVE_RESULTS${C_RESET}\n"
        cat << 'M'
  [1]  scan classic + BLE (full CVE sweep)
  [2]  scan classic only
  [3]  scan BLE only
  [4]  show results
  [5]  clear results
  [6]  export results to loot
  [7]  set hci iface
  [0]  back

M
        read -rp "  choice> " c
        case "$c" in
            1) btcve_scan_all ;;
            2) btcve_init; btcve_require_iface && { btcve_scan_classic; read -rp "  press enter " _; } ;;
            3) btcve_init; btcve_require_iface && { btcve_scan_ble; read -rp "  press enter " _; } ;;
            4) btcve_show_results ;;
            5) btcve_clear_results ;;
            6) btcve_export_results ;;
            7) btcve_set_iface ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI / GUI entry points ────────────────────────────────

btcve_cli_status_tsv() {
    local targets=0 results=0
    [[ -f "$BT_CVE_TARGETS" ]] && targets=$(wc -l < "$BT_CVE_TARGETS" 2>/dev/null || echo 0)
    [[ -f "$BT_CVE_RESULTS" ]] && results=$(wc -l < "$BT_CVE_RESULTS" 2>/dev/null || echo 0)
    printf 'hci\t%s\n'      "${BT_HCI_IFACE:-hci0}"
    printf 'targets\t%s\n'  "$targets"
    printf 'results\t%s\n'  "$results"
    printf 'dir\t%s\n'      "$BT_CVE_DIR"
    printf 'results_file\t%s\n' "$BT_CVE_RESULTS"
}

# =====================================================================
# --run-cve <id> — non-interactive per-CVE probe (GUI Run button)
# =====================================================================

btcve_run_handoff() {
    local id="${1:-}" note="${2:-}"
    local slug; slug="$(printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_')"
    local dir="$LOOT_DIR/cves/bt"
    local f="$dir/run_${slug}_$(date +%s).txt"
    mkdir -p "$dir"
    {
        echo "cve: $id"
        echo "status: handoff — no automated one-shot probe in this kit"
        echo "note: $note"
        echo "ts: $(date -Is)"
    } | tee "$f"
    warn "$id → $note"
    info "note: $f"
    return 0
}

btcve_run_resolve_target() {
    local mac="${BT_TARGET:-}"
    [[ -n "$mac" ]] && { printf '%s\n' "$mac"; return 0; }
    if [[ -f "$BT_CVE_TARGETS" && -s "$BT_CVE_TARGETS" ]]; then
        mac="$(head -n1 "$BT_CVE_TARGETS" | cut -d'|' -f1 | tr -d '[:space:]')"
        [[ -n "$mac" ]] && { printf '%s\n' "$mac"; return 0; }
    fi
    if command -v hcitool >/dev/null 2>&1; then
        info "no BT target — running a quick classic scan"
        btcve_scan_classic >/dev/null 2>&1
        if [[ -s "$BT_CVE_TARGETS" ]]; then
            mac="$(head -n1 "$BT_CVE_TARGETS" | cut -d'|' -f1 | tr -d '[:space:]')"
            [[ -n "$mac" ]] && { printf '%s\n' "$mac"; return 0; }
        fi
    fi
    return 1
}

btcve_run() {
    local id="${1:-}"
    if [[ -z "$id" ]]; then
        echo "usage: $0 --run-cve <CVE-ID>" >&2
        return 2
    fi
    # NOTE: no exec </dev/null — it kills the dispatch below.
    BT_HCI_IFACE="${BT_HCI_IFACE:-hci0}"
    export BT_HCI_IFACE
    mkdir -p "$BT_CVE_DIR"
    [[ -f "$BT_CVE_RESULTS" ]] || : > "$BT_CVE_RESULTS"
    info "BT CVE probe start: $id (non-interactive)"
    info "results: $BT_CVE_RESULTS"

    local mac=""
    case "$id" in
        CVE-2017-1000250|CVE-2017-1000251|CVE-2017-1000252|CVE-2019-9506|CVE-2020-10135|CVE-2020-10134|CVE-2020-15802|CVE-2021-28414)
            mac="$(btcve_run_resolve_target)" || {
                warn "no BT target — set BT_TARGET or run a classic scan first"
                return 1
            } ;;
    esac

    case "$id" in
        CVE-2017-1000250|CVE-2017-1000251|CVE-2017-1000252)
            btcve_check_blueborne "$mac" ;;
        CVE-2019-9506)  btcve_check_knob "$mac" ;;
        CVE-2020-10135) btcve_check_bias "$mac" ;;
        CVE-2020-10134) btcve_check_blesa "$mac" ;;
        CVE-2020-15802) btcve_check_blurtooth "$mac" ;;
        CVE-2021-28414) btcve_check_braktooth "$mac" ;;
        CVE-2021-37577)
            btcve_run_handoff "$id" "LE Passkey MITM — needs nRF52840 + btlejack capture harness" ;;
        CVE-2022-25836|CVE-2022-25837)
            btcve_run_handoff "$id" "BR/EDR Secure-Connections key downgrade — needs nRF52840 + BT sniffer" ;;
        CVE-2020-26558)
            btcve_run_handoff "$id" "LE Passkey MITM — needs nRF52840 + btlejack capture harness" ;;
        CVE-2026-0101)
            btcve_run_handoff "$id" "BLE RPA spoofing — needs nRF52840 sniffer" ;;
        CVE-2019-17517|CVE-2019-17518|CVE-2019-17519|CVE-2019-17520)
            btcve_run_handoff "$id" "SweynTooth family — needs nRF52840 + LMP/ATT fuzzer" ;;
        CVE-2020-0022)
            btcve_run_handoff "$id" "BlueFrag Android RCE — needs nRF52840 + crafted L2CAP" ;;
        CVE-2023-45866)
            btcve_run_handoff "$id" "BlueDucky unauthenticated HID — use module 12 HID injection on nRF52840" ;;
        CVE-2024-45431|CVE-2024-45433|CVE-2024-45434)
            btcve_run_handoff "$id" "PerfektBlue family — needs nRF52840 + crafted AVRCP/L2CAP/RFCOMM" ;;
        CVE-2025-27840)
            btcve_run_handoff "$id" "ESP32 hidden HCI backdoor — needs serial access to the ESP32" ;;
        CVE-2025-20700|CVE-2025-20701|CVE-2025-20702)
            btcve_run_handoff "$id" "No-auth profile impersonation — needs nRF52840 + BLE host" ;;
        CVE-2026-15460|CVE-2026-11368|CVE-2026-89569|CVE-2026-16473|CVE-2026-53208)
            btcve_run_handoff "$id" "Zephyr RTOS stack bug — needs nRF52840 running vulnerable Zephyr FW" ;;
        CVE-2024-35964)
            btcve_run_handoff "$id" "Linux BT ISO setsockopt — local kernel test, not a remote probe" ;;
        *)
            err "unknown CVE id: $id"
            return 2 ;;
    esac
}

# ── self-test ────────────────────────────────────────────────────────────
# No radio: every path here is argument routing, target extraction, OUI
# matching and file writing. LOOT_DIR/BT_CVE_* are redirected into
# $MOD_TMP so the real loot tree is never touched.
btcve_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

    local d out rc id ok n
    # Unique per run: a second selftest (runner alongside a manual run)
    # must not share scratch files.
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    mkdir -p "$d/cve" "$d/loot"
    # Redirect every output path into the scratch dir. These are exported
    # so the helper functions (and anything they exec) see them too.
    export LOOT_DIR="$d/loot" BT_CVE_DIR="$d/cve"
    export BT_CVE_TARGETS="$d/cve/targets.txt" BT_CVE_RESULTS="$d/cve/results.txt"

    # 1. Argument validation: a missing or unknown CVE id must be refused,
    #    never silently accepted as "nothing to do".
    chk run-no-id-rc    "$(btcve_run >/dev/null 2>&1; echo $?)" "2"
    out=$(btcve_run CVE-9999-99999 2>&1); rc=$?
    chk run-unknown-rc  "$rc" "2"
    chk run-unknown-msg "$(printf '%s\n' "$out" | grep -c 'unknown CVE id: CVE-9999-99999')" "1"

    # 2. Every id the module documents as a handoff must route to the
    #    handoff path (rc 0 + one plan file each); a bad edit that drops an
    #    id from the case list would otherwise show up as "unknown CVE".
    local handoff=( CVE-2021-37577 CVE-2022-25836 CVE-2022-25837 CVE-2020-26558
                    CVE-2026-0101 CVE-2019-17517 CVE-2019-17518 CVE-2019-17519
                    CVE-2019-17520 CVE-2020-0022 CVE-2023-45866 CVE-2024-45431
                    CVE-2024-45433 CVE-2024-45434 CVE-2025-27840 CVE-2025-20700
                    CVE-2025-20701 CVE-2025-20702 CVE-2026-15460 CVE-2026-11368
                    CVE-2026-89569 CVE-2026-16473 CVE-2026-53208 CVE-2024-35964 )
    ok=1
    for id in "${handoff[@]}"; do
        btcve_run "$id" >/dev/null 2>&1 || ok=0
    done
    chk handoff-list-size "${#handoff[@]}" "24"
    chk handoff-all-rc "$ok" "1"
    chk handoff-files  "$(find "$d/loot/cves/bt" -type f 2>/dev/null | wc -l)" "${#handoff[@]}"

    out=$(btcve_run CVE-2023-45866 2>&1); rc=$?
    chk handoff-rc      "$rc" "0"
    chk handoff-status  "$(printf '%s\n' "$out" | grep -c '^status: handoff')" "1"
    chk handoff-cve     "$(printf '%s\n' "$out" | grep -c '^cve: CVE-2023-45866$')" "1"
    n=$(find "$d/loot/cves/bt" -name 'run_CVE-2023-45866_*.txt' | head -1)
    chk handoff-plan-exists "$([[ -f "$n" ]] && echo yes || echo no)" "yes"
    chk handoff-plan-status "$(grep -c '^status: handoff' "$n")" "1"
    chk handoff-plan-note   "$(grep -c 'BlueDucky unauthenticated HID' "$n")" "1"

    # An id with path separators must not escape the plan directory.
    n=$(find "$d/loot/cves/bt" -type f | wc -l)
    btcve_run_handoff 'weird/id 1' 'note' >/dev/null 2>&1
    chk handoff-slug-count "$(find "$d/loot/cves/bt" -type f | wc -l)" "$((n + 1))"
    chk handoff-slug-name  "$(find "$d/loot/cves/bt" -name 'run_weird_id_1_*.txt' | wc -l)" "1"

    # 3. A probe id must route to its probe, not to the unknown branch:
    #    CVE-2021-28414 is the OUI-only BrakTooth check, so it needs no radio.
    out=$(BT_TARGET="00:1A:7D:11:22:33" btcve_run CVE-2021-28414 2>&1); rc=$?
    chk probe-rc   "$rc" "0"
    chk probe-line "$(grep -c '00:1A:7D:11:22:33. braktooth: vendor OUI 00:1A:7D' "$d/cve/results.txt")" "1"

    # 4. Target extraction: BT_TARGET wins, else the first MAC in the
    #    targets file with the pipe-delimited name column stripped.
    chk target-from-env "$(BT_TARGET=AA:BB:CC:DD:EE:FF BT_CVE_TARGETS="$d/cve/targets.txt" \
        btcve_run_resolve_target)" "AA:BB:CC:DD:EE:FF"
    printf '%s\n' '  11:22:33:44:55:66 |My Phone' > "$d/cve/targets.txt"
    chk target-from-file "$(BT_CVE_TARGETS="$d/cve/targets.txt" btcve_run_resolve_target)" \
        "11:22:33:44:55:66"

    # 5. OUI matching is case-insensitive and must miss what it does not know.
    : > "$d/cve/oui.txt"
    BT_CVE_RESULTS="$d/cve/oui.txt" btcve_check_braktooth "00:1a:7d:11:22:33" >/dev/null 2>&1
    BT_CVE_RESULTS="$d/cve/oui.txt" btcve_check_braktooth "00:0C:10:11:22:33" >/dev/null 2>&1
    BT_CVE_RESULTS="$d/cve/oui.txt" btcve_check_braktooth "DE:AD:BE:11:22:33" >/dev/null 2>&1
    chk oui-lowercase-matched "$(grep -c 'braktooth: vendor OUI 00:1a:7d matches affected-chip list' "$d/cve/oui.txt")" "1"
    chk oui-second-matched    "$(grep -c 'braktooth: vendor OUI 00:0C:10 matches affected-chip list' "$d/cve/oui.txt")" "1"
    chk oui-unknown-not-flagged "$(grep -c 'braktooth: OUI not in known-affected list' "$d/cve/oui.txt")" "1"
    chk oui-rows "$(grep -c . "$d/cve/oui.txt")" "3"

    # 6. Status TSV contract.
    printf '%s\n' 'AA:BB:CC:DD:EE:FF|One' 'AA:BB:CC:DD:EE:01|Two' > "$d/cve/targets.txt"
    printf '%s\n' 'r1' 'r2' 'r3' > "$d/cve/results.txt"
    unset BT_HCI_IFACE
    out=$(btcve_cli_status_tsv)
    chk status-hci     "$(fld "$out" hci)"          "hci0"
    chk status-targets "$(fld "$out" targets)"      "2"
    chk status-results "$(fld "$out" results)"      "3"
    chk status-dir     "$(fld "$out" dir)"          "$d/cve"
    chk status-file    "$(fld "$out" results_file)" "$d/cve/results.txt"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

btcve_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     btcve_cli_status_tsv ;;
        --run-cve)        btcve_run "${1:-}" ;;
        --selftest)       btcve_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 --status-tsv
       $0 --run-cve <CVE-ID>
       $0 --selftest
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    WIFISTING_CLI=1
    : "${TMP_DIR:=/tmp/wifisting}"
    : "${LOOT_DIR:=$HOME/wifisting/loot}"
    : "${LOGS_DIR:=$HOME/wifisting/logs}"
    : "${WIFISTING_HOME:=$HOME/wifisting}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    btcve_cli_main "$@"
fi

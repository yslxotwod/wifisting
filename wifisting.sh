#!/usr/bin/env bash
# wifisting main launcher — v0.5, all 30 modules, category menu
#
# Standalone CLI:   sudo bash wifisting.sh
# Sourced by GUI:   WIFISTING_GUI=1 source wifisting.sh

# ── sourced-vs-executed detection ───────────────────────────
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    WIFISTING_SOURCED=1
else
    WIFISTING_SOURCED=0
fi
export WIFISTING_SOURCED

# ── resolve script location, following symlinks ─────────────
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

export WIFISTING_ROOT="$SCRIPT_DIR"
export MODULES_DIR="$SCRIPT_DIR/modules"
export TMP_DIR="$SCRIPT_DIR/tmp"
export LOOT_DIR="$SCRIPT_DIR/loot"
export LOG_DIR="$SCRIPT_DIR/logs"
export CAPTURES_DIR="$SCRIPT_DIR/captures"
export SESSION_LOG="${SESSION_LOG:-$LOG_DIR/session_$(date +%Y%m%d_%H%M%S)_$$.log}"

# ---------------------------------------------------------------------
#  Install the module icons into the user's hicolor theme on first run.
#
#  The GUI looks icons up by name through GtkIconTheme, so they have to
#  be in a theme directory - they cannot be loaded from the project tree.
#  That install used to be a manual step (tools/rename-icons.sh
#  --install), which meant a fresh machine, a live USB, or anyone who
#  unzipped the tarball got grey placeholder boxes instead of icons and
#  no indication why.
#
#  Cheap to run: it copies only files that are missing, and the cache
#  rebuild is skipped when nothing changed.
# ---------------------------------------------------------------------
ICON_SRC="$SCRIPT_DIR/native/resources/icons/symbolic"
ICON_DST="$HOME/.local/share/icons/hicolor/scalable/actions"

if [ -d "$ICON_SRC" ]; then
    installed=0
    mkdir -p "$ICON_DST" 2>/dev/null

    for src in "$ICON_SRC"/wifisting-*.svg; do
        [ -e "$src" ] || continue
        name=$(basename "$src")

        # A file already there may be newer than the tree - a local edit
        # the user made. Only copy what is absent.
        if [ ! -e "$ICON_DST/$name" ]; then
            cp -f "$src" "$ICON_DST/$name" 2>/dev/null && installed=$((installed + 1))
        fi
    done

    if [ "$installed" -gt 0 ]; then
        echo "  installed $installed module icon(s) into the hicolor theme"
        if command -v gtk-update-icon-cache >/dev/null 2>&1; then
            gtk-update-icon-cache -q -t -f "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
        fi
    fi
fi

for d in "$TMP_DIR" "$LOOT_DIR" "$LOG_DIR" "$CAPTURES_DIR"; do
    if ! mkdir -p "$d"; then
        printf 'wifisting: cannot create %s\n' "$d" >&2
        (( WIFISTING_SOURCED )) && return 1 || exit 1
    fi
done

# ── CLI flags (standalone only) ─────────────────────────────
WIFISTING_LIST=0
if (( ! WIFISTING_SOURCED )); then
    case "${1:-}" in
        -h|--help)
            cat << 'USAGE'
wifisting — wireless security research toolkit

Usage:
  sudo bash wifisting.sh           Interactive module menu (requires root)
  bash wifisting.sh --list         List all modules and availability
  bash wifisting.sh --version      Print version
  bash wifisting.sh --help         This message
USAGE
            exit 0 ;;
        -V|--version)
            echo "wifisting v0.5 — 30 modules"
            exit 0 ;;
        --list)
            WIFISTING_LIST=1 ;;
        "")
            ;;
        *)
            printf 'wifisting: unknown flag: %s\n' "$1" >&2
            exit 2 ;;
    esac
fi

# ── palette ─────────────────────────────────────────────────
C_RED=$'\e[38;5;196m'; C_GRN=$'\e[38;5;46m';   C_YEL=$'\e[38;5;226m'
C_CYN=$'\e[38;5;51m';  C_MAG=$'\e[38;5;203m';  C_BLU=$'\e[38;5;39m'
C_ORG=$'\e[38;5;208m'; C_PUR=$'\e[38;5;160m';  C_DIM=$'\e[38;5;240m'
C_WHT=$'\e[38;5;255m'; C_BOLD=$'\e[1m';        C_RESET=$'\e[0m'
export C_RED C_GRN C_YEL C_CYN C_MAG C_BLU C_ORG C_PUR C_DIM C_WHT C_BOLD C_RESET

# ── logging ─────────────────────────────────────────────────
info() { echo -e "${C_CYN}[${C_BOLD}*${C_RESET}${C_CYN}]${C_RESET} $*" | tee -a "$SESSION_LOG"; }
ok()   { echo -e "${C_GRN}[${C_BOLD}+${C_RESET}${C_GRN}]${C_RESET} $*" | tee -a "$SESSION_LOG"; }
warn() { echo -e "${C_YEL}[${C_BOLD}!${C_RESET}${C_YEL}]${C_RESET} $*" | tee -a "$SESSION_LOG"; }
err()  { echo -e "${C_RED}[${C_BOLD}-${C_RESET}${C_RED}]${C_RESET} $*" | tee -a "$SESSION_LOG"; }

# ── cursor + width ──────────────────────────────────────────
show_cursor() { printf '\e[?25h'; }
hide_cursor() { printf '\e[?25l'; }
term_width() {
    local w
    w=$(tput cols 2>/dev/null) || w=80
    [[ -z "$w" || "$w" -lt 40 ]] && w=80
    echo "$w"
}

if (( ! WIFISTING_SOURCED )); then
    trap 'show_cursor; tput cnorm 2>/dev/null; echo' EXIT INT TERM
fi

# ── module table ────────────────────────────────────────────
# CATEGORY|KEY|LABEL|MENU_FUNCTION
MODULE_TABLE=(
  "SYSTEM|00|Dependencies|script:00_deps.sh"
  "SYSTEM|01|Interface Manager|script:01_iface.sh"

  "WI-FI|02|Wi-Fi Recon|script:02_recon.sh"
  "WI-FI|03|WPA/2 Attack|script:03_attack.sh"
  "WI-FI|04|Evil Twin|script:04_eviltwin.sh"
  "WI-FI|08|Offline PMKID|script:08_pmkid_offline.sh"
  "WI-FI|09|Wardriving|script:09_wardrive.sh"
  "WI-FI|10|Rogue DHCP|script:10_rogue_dhcp.sh"
  "WI-FI|11|KRACK / Kr00k|script:11_krack_kr00k.sh"
  "WI-FI|17|WPS Attack|script:17_wps_attack.sh"
  "WI-FI|20|Karma|script:20_karma.sh"
  "WI-FI|21|Wi-Fi DoS / Flood|script:21_beacon_flood.sh"
  "WI-FI|22|Wi-Fi Direct / P2P|script:22_wifi_direct.sh"
  "WI-FI|23|Portal Builder|script:23_captive_portal_builder.sh"
  "WI-FI|34|PMF Bypass|script:34_pmf_bypass.sh"
  "WI-FI|35|Wi-Fi 6 Attacks|script:35_wifi6_attacks.sh"
  "WI-FI|47|WPA3 / SAE Attack|script:47_wpa3_attack.sh"
  "WI-FI|48|WEP Attacks|script:48_wep_attack.sh"
  "WI-FI|53|Jamming|script:53_jamming.sh"
  "WI-FI|54|Client Isolation|script:54_client_isolation.sh"
  "WI-FI|55|SSID Overflow|script:55_ssid_overflow.sh"

  "NETWORK|07|ARP / MITM|script:07_arp.sh"
  "NETWORK|13|Enterprise Kit|script:13_802.1x_relay.sh"
  "NETWORK|28|Live Traffic|script:28_live_traffic.sh"
  "NETWORK|32|Resolver Poison|script:32_resolver_poison.sh"
  "NETWORK|50|Router LAN Attacks|script:50_router_lan.sh"
  "NETWORK|51|Router Web UI|script:51_router_web.sh"

  "BLUETOOTH|05|Bluetooth Recon|script:05_bt_recon.sh"
  "BLUETOOTH|06|Bluetooth Attack|script:06_bt_attack.sh"
  "BLUETOOTH|24|BLE Mesh|script:24_bt_mesh.sh"
  "BLUETOOTH|36|Tracker Hunt|script:36_ble_tracker_hunt.sh"
  "BLUETOOTH|37|Classic SSP|script:37_bt_classic_ssp.sh"
  "BLUETOOTH|38|Adv Forge|script:38_ble_adv_forge.sh"
  "BLUETOOTH|39|BLE Fuzzing|script:39_ble_fuzz.sh"

  "WIRELESS|57|Thread|script:57_thread.sh"
  "WIRELESS|58|Proximity|script:58_proximity.sh"

  "PHYSICAL|12|HID Injection|script:12_hid_injection.sh"
  "PHYSICAL|40|Wi-Fi CSI|script:40_wifi_csi.sh"
  "PHYSICAL|42|Sub-GHz RF|script:42_subghz.sh"
  "PHYSICAL|43|NFC / RFID|script:43_nfc_rfid.sh"
  "PHYSICAL|44|LoRa / LoRaWAN|script:44_lora_loraWAN.sh"
  "PHYSICAL|45|Drone Remote ID|script:45_drone_remote_id.sh"
  "PHYSICAL|49|USB Ethernet MitM|script:49_usb_mitm.sh"
  "PHYSICAL|52|Router Console|script:52_router_console.sh"

  "SCANNERS|14|Wireless IDS|script:14_wifi_ids.sh"
  "SCANNERS|15|Wi-Fi CVE Kit|script:15_wifi_cve_scan.sh"
  "SCANNERS|16|Bluetooth CVE Kit|script:16_bt_cve_scan.sh"
  "SCANNERS|25|RF Spectrum|script:25_rf_spectrum.sh"
  "SCANNERS|26|Zigbee / 802.15.4|script:26_zigbee.sh"
  "SCANNERS|27|Firmware / IoT|script:27_firmware_iot.sh"

  "ANALYSIS|18|Capture Analysis|script:18_capture_analysis.sh"
  "ANALYSIS|19|Wordlist Manager|script:19_wordlist_manager.sh"
  "ANALYSIS|27b|Fw Update Audit|script:27b_fw_update_audit.sh"
  "ANALYSIS|30|Fingerprint|script:30_fingerprint.sh"
  "ANALYSIS|41|Geolocation|script:41_wifi_geolocate.sh"
  "ANALYSIS|46|Public Wi-Fi Audit|script:46_public_wifi_audit.sh"

  "AUTOMATION|29|Killchain|script:29_killchain.sh"
  "AUTOMATION|31|Remote Node|script:31_remote_node.sh"
)

# ── banner ──────────────────────────────────────────────────
banner() {
    clear
    local w; w=$(term_width)

    printf '%s%s' "$C_MAG" "$C_BOLD"
    cat << 'B'

            ) ) )
           ( ( (
            ) )
             (
            ×
 ██╗    ██╗██╗███████╗██╗███████╗████████╗██╗███╗   ██╗ ██████╗
 ██║    ██║██║██╔════╝██║██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝
 ██║ █╗ ██║██║█████╗  ██║███████╗   ██║   ██║██╔██╗ ██║██║  ███╗
 ██║███╗██║██║██╔══╝  ██║╚════██║   ██║   ██║██║╚██╗██║██║   ██║
 ╚███╔███╔╝██║██║     ██║███████║   ██║   ██║██║ ╚████║╚██████╔╝
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝
B
    printf '%s\n' "$C_RESET"

    printf '%s' "$C_PUR"
    printf '═%.0s' $(seq 1 "$w")
    printf '%s\n' "$C_RESET"

    printf '  %s%s» %swifi · bt · rf offensive toolkit %s// v0.5 %s// ysl%s\n' \
        "$C_CYN" "$C_BOLD" "$C_WHT" "$C_DIM" "$C_MAG" "$C_RESET"

    printf '%s' "$C_PUR"
    printf '─%.0s' $(seq 1 "$w")
    printf '%s\n' "$C_RESET"
}

# ── menu primitives ─────────────────────────────────────────
menu_row() {
    local key="$1" label="$2" state="$3"
    local kcol="$C_ORG" lcol="$C_WHT" tag=""
    case "$state" in
        missing)
            kcol="$C_DIM"; lcol="$C_DIM"; tag=" ${C_YEL}[not loaded]${C_RESET}" ;;
    esac
    printf '   %s│%s %s[%s]%s  %s%s%s%s\n' \
        "$C_DIM" "$C_RESET" \
        "$kcol$C_BOLD" "$key" "$C_RESET" \
        "$lcol" "$label" "$C_RESET" "$tag"
}

section_header() {
    local title="$1"
    printf '\n   %s── %s%s%s %s───────────────────────────────%s\n' \
        "$C_PUR$C_BOLD" "$C_MAG" "$title" "$C_PUR$C_BOLD" "$C_DIM" "$C_RESET"
}

row_state() {
    local ref="$1"

    # script:<file> rows — present when the module exists on disk.
    if [[ "$ref" == script:* ]]; then
        [[ -f "$MODULES_DIR/${ref#script:}" ]] && echo present || echo missing
        return
    fi

    # Legacy function rows.
    declare -F "$ref" >/dev/null 2>&1 && echo present || echo missing
}

fn_for_key() {
    local key="$1" row
    for row in "${MODULE_TABLE[@]}"; do
        IFS='|' read -r _ k _ f <<< "$row"
        [[ "$k" == "$key" ]] && { echo "$f"; return; }
    done
}

# ── root + module dir checks ────────────────────────────────
# Skip the root requirement for the read-only --list flag: it only does
# `declare -F` checks and never touches privileged hardware.
if [[ $EUID -ne 0 && "${WIFISTING_LIST:-0}" != "1" ]]; then
    if [[ "${WIFISTING_GUI:-0}" == "1" ]]; then
        warn "GUI backend is not root; privileged module operations may fail"
    else
        err "must run as root — try: sudo bash $0"
        exit 1
    fi
fi

if [[ ! -d "$MODULES_DIR" ]]; then
    err "modules dir not found: $MODULES_DIR"
    (( WIFISTING_SOURCED )) && return 1 || exit 1
fi

info "loading modules from $MODULES_DIR"
shopt -s nullglob
MODULE_FILES=("$MODULES_DIR"/*.sh)
shopt -u nullglob

if [[ ${#MODULE_FILES[@]} -eq 0 ]]; then
    err "no .sh files in $MODULES_DIR"
    (( WIFISTING_SOURCED )) && return 1 || exit 1
fi

# Syntax-check every module. They are deliberately NOT sourced.
#
# The menu runs each one as its own process, so it needs nothing from
# inside them. Sourcing all 58 executed every module's top-level code at
# startup: that is slow, it trips any module that calls exit or expects
# arguments, and it printed a "failed to load" error on every launch -
# which read as though all the modules were broken.
for mod in "${MODULE_FILES[@]}"; do
    if ! bash -n "$mod" 2>/dev/null; then
        err "syntax error in $(basename "$mod") — skipping"
        continue
    fi

    # Only the modules that define a menu function need sourcing - those
    # are the ones offering an interactive interface here. Everything
    # else is run as its own process, so its top-level code never runs at
    # startup. That is what made the old loop slow and noisy.
    grep -qE '^[a-z0-9_]+_menu\(\)' "$mod" || continue

    # Some call `exit` at top level; shadow it or this shell dies mid-loop.
    _prev_exit_fn=$(declare -f exit 2>/dev/null || true)
    exit() { return "${1:-0}"; }
    source "$mod" 2>>"$SESSION_LOG" || true
    unset -f exit
    if [[ -n "$_prev_exit_fn" ]]; then
        eval "$_prev_exit_fn"
        unset _prev_exit_fn
    fi
done

# ── --list ──────────────────────────────────────────────────
if (( WIFISTING_LIST )) && (( ! WIFISTING_SOURCED )); then
    printf '\nwifisting — installed modules\n\n'
    local_cat=""
    for row in "${MODULE_TABLE[@]}"; do
        IFS='|' read -r cat key label fn <<< "$row"
        if [[ "$cat" != "$local_cat" ]]; then
            printf '  %s%s%s\n' "$C_MAG" "$cat" "$C_RESET"
            local_cat="$cat"
        fi
        # Route through row_state, which knows about script: rows. An
        # inline declare -F here reported every module as missing, because
        # a script reference is not a function name.
        if [[ "$(row_state "$fn")" == present ]]; then
            printf '    [%s] %-28s %s✓%s\n' "$key" "$label" "$C_GRN" "$C_RESET"
        else
            printf '    [%s] %-28s %s✗%s\n' "$key" "$label" "$C_DIM" "$C_RESET"
        fi
    done
    echo
    exit 0
fi

# ── cleanup (standalone only) ──────────────────────────────
cleanup() {
    show_cursor
    info "cleaning up network interfaces..."
    for daemon in airodump-ng hostapd dnsmasq; do
        pkill -f "$daemon" 2>/dev/null
    done
    for iface in $(iw dev 2>/dev/null | awk '/Interface {/ {print $2}' | tr -d ':'); do
        iw dev "$iface" set type managed 2>/dev/null
        ip addr flush dev "$iface" 2>/dev/null
    done
    ok "system restored. goodbye."
}
if (( ! WIFISTING_SOURCED )) && [[ "${WIFISTING_GUI:-0}" != "1" ]]; then
    trap cleanup EXIT TERM
fi

# ── main menu ───────────────────────────────────────────────
launch_gui() {
    if ! pgrep -x wifisting-gui >/dev/null 2>&1; then
        info "launching wifisting-gui..."
        nohup "$WIFISTING_ROOT/native/builddir/wifisting-gui" \
            >/dev/null 2>&1 &
        sleep 1
    else
        info "wifisting-gui is already running"
        sleep 1
    fi
}

# ── generic module menu ──────────────────────────────────────
# Modules that ship their own _menu get that instead. The rest are driven
# from their --help text: the CLI lists the verbs the module advertises and
# asks for any arguments the help shows. A new module is therefore usable
# from the menu the moment its help exists - nothing to write per module,
# and nothing to forget, which is how the old table drifted out of date.
run_module_menu() {
    local script="$1"
    local base; base=$(basename "$script")
    local -a verbs=() args=() descs=()
    local line

    while IFS= read -r line; do
        # Take the verb, then split the remainder on the run of two or
        # more spaces that separates arguments from description. Matching
        # the placeholder by shape instead broke on multi-word argument
        # lists such as "MAC [LABEL]", so only a handful of verbs parsed.
        [[ "$line" =~ ^[[:space:]]+(--[a-z0-9-]+)(.*)$ ]] || continue
        local v="${BASH_REMATCH[1]}" rest="${BASH_REMATCH[2]}" a="" d="$rest"

        if [[ "$rest" =~ ^[[:space:]]+([^[:space:]].*[^[:space:]]|[^[:space:]])[[:space:]]{2,}(.+)$ ]]; then
            a="${BASH_REMATCH[1]}"
            d="${BASH_REMATCH[2]}"
        fi

        verbs+=("$v")
        args+=("$a")
        descs+=("$d")
    done < <(timeout 20 bash "$script" --help 2>/dev/null)

    # Nothing parseable: run it bare rather than showing an empty menu.
    if (( ${#verbs[@]} == 0 )); then
        bash "$script"
        printf '\n   press enter to return\n'; read -r _
        return
    fi

    local pick idx i val want
    while true; do
        clear
        printf '\n   %s%s%s\n\n' "$C_MAG$C_BOLD" "$base" "$C_RESET"
        for i in "${!verbs[@]}"; do
            printf '   %s[%2d]%s %-30s %s%s%s\n' \
                "$C_ORG$C_BOLD" "$((i + 1))" "$C_RESET" \
                "${verbs[$i]}${args[$i]}" "$C_DIM" "${descs[$i]}" "$C_RESET"
        done
        printf '\n   %s[b]%s back to the menu\n' "$C_ORG$C_BOLD" "$C_RESET"
        printf '\n   %sλ%s ' "$C_MAG$C_BOLD" "$C_RESET"

        read -r pick
        case "$pick" in b|B|q|Q|"") return ;; esac
        [[ "$pick" =~ ^[0-9]+$ ]] || continue
        (( pick >= 1 && pick <= ${#verbs[@]} )) || continue
        idx=$((pick - 1))

        # Split the placeholder into words: "IFACE PID" is two prompts.
        local -a argv=("$script" "${verbs[$idx]}")
        if [[ -n "${args[$idx]}" ]]; then
            for want in ${args[$idx]}; do
                printf '   %s%s%s: ' "$C_YEL" "$want" "$C_RESET"
                read -r val
                [[ -n "$val" ]] && argv+=("$val")
            done
        fi

        printf '\n'
        bash "${argv[@]}"
        printf '\n   press enter to return\n'; read -r _
    done
}

main_menu() {
    while true; do
        banner
        echo

        local_cat=""
        for row in "${MODULE_TABLE[@]}"; do
            IFS='|' read -r cat key label fn <<< "$row"
            if [[ "$cat" != "$local_cat" ]]; then
                section_header "$cat"
                local_cat="$cat"
            fi
            menu_row "$key" "$label" "$(row_state "$fn")"
        done

        echo
        printf '   %s│%s\n' "$C_DIM" "$C_RESET"
        printf '   %s│%s  %s[h]%s help   %s[c]%s clear   %s[g]%s gui   %s[q]%s quit\n' \
            "$C_DIM" "$C_RESET" \
            "$C_ORG$C_BOLD" "$C_RESET" \
            "$C_ORG$C_BOLD" "$C_RESET" \
            "$C_ORG$C_BOLD" "$C_RESET" \
            "$C_RED$C_BOLD" "$C_RESET"

        echo
        printf '   %s└─%s▶%s %s · %ssession:%s %s\n' \
            "$C_PUR" "$C_MAG" "$C_RESET" \
            "$(date +%H:%M:%S)" "$C_DIM" "$C_RESET" \
            "$(basename "$SESSION_LOG")"
        echo

        show_cursor
        local choice
        read -rp "   ${C_MAG}${C_BOLD}λ${C_RESET} " choice
        hide_cursor

        local norm="${choice#0}"
        [[ -z "$norm" ]] && norm="$choice"

        case "$choice" in
            q|Q) show_cursor; info "bye"; exit 0 ;;
            h|H)
                clear
                cat << 'HELP'
wifisting CLI — help
────────────────────

  Modules are grouped by category. Type the two-digit key to launch.
  Modules marked [not loaded] are missing or failed to load — check logs/session_*.log.

  Keys:
    [NN]        launch module
    [h]         this help
    [c]         clear screen
    [g]         launch the GUI (builddir/wifisting-gui)
    [q]         quit

  A module opens its own interface; most take --help for their verbs.

  Session log:  logs/session_<date>_<pid>.log
  Project root: ${WIFISTING_ROOT:-$HOME/wifisting}
  Press enter to return.
HELP
                read -r _
                ;;
            c|C) : ;;
            g|G) launch_gui ;;
            *)
                local fn
                fn=$(fn_for_key "$choice")
                [[ -z "$fn" ]] && fn=$(fn_for_key "$norm")

        # script: rows are run as their own process. A module is a
        # standalone script, so the menu needs no wrapper function from
        # it - and declare -F on a script reference always fails, which
        # is what produced "module N failed to load" for every choice.
        if [[ "$fn" == script:* ]]; then
            local script="$MODULES_DIR/${fn#script:}"
            local mfn=""

            if [[ -f "$script" ]]; then
                # If the module ships a menu, use it: that is the richer
                # interface, and running the script bare would only print
                # its usage. Otherwise run the script, which is the whole
                # point of it being standalone.
                mfn=$(grep -oE '^[a-z0-9_]+_menu\(\)' "$script" 2>/dev/null \
                      | head -1 | sed 's/()//')

                if [[ -n "$mfn" ]] && declare -F "$mfn" >/dev/null 2>&1; then
                    "$mfn"
                else
                    run_module_menu "$script"
                fi
            else
                warn "module file missing: ${fn#script:}"
                sleep 1
            fi
        elif [[ -n "$fn" ]] && declare -F "$fn" >/dev/null 2>&1; then
            "$fn"
        elif [[ -n "$fn" ]]; then
            warn "module $choice has no runnable entry — check $SESSION_LOG"
            sleep 1
        else
            warn "invalid selection: $choice"
            sleep 0.5
        fi
                ;;
        esac
    done
}

# ── entry ───────────────────────────────────────────────────
# Don't leave a false conditional as the final sourced command — the
# GUI sources this file then invokes a module function; a status of 1
# here would prevent the caller's `&&` from firing.
if (( ! WIFISTING_SOURCED )) && [[ "${WIFISTING_GUI:-0}" != "1" ]]; then
    main_menu
fi

true

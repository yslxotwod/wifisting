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
C_CYN=$'\e[38;5;51m';  C_MAG=$'\e[38;5;201m';  C_BLU=$'\e[38;5;39m'
C_ORG=$'\e[38;5;208m'; C_PUR=$'\e[38;5;135m';  C_DIM=$'\e[38;5;240m'
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
    "SYSTEM|01|Dependency Manager|deps_menu"
    "SYSTEM|02|Interface Manager|iface_menu"

    "WI-FI|03|Wi-Fi Recon|recon_menu"
    "WI-FI|04|Wardriving|wardrive_menu"
    "WI-FI|05|Wi-Fi Attack|attack_menu"
    "WI-FI|06|Offline PMKID|pmkid_menu"
    "WI-FI|07|WPS Attack|wps_menu"
    "WI-FI|08|KRACK / Kr00k|krack_kr00k_menu"
    "WI-FI|09|Evil Twin|eviltwin_menu"
    "WI-FI|10|Karma|karma_menu"
    "WI-FI|11|Portal Builder|portal_menu"
    "WI-FI|12|Beacon Flood|beacon_flood_menu"
    "WI-FI|13|Wi-Fi Direct / P2P|p2p_menu"
    "WI-FI|14|Rogue DHCP|rogue_dhcp_menu"

    "BLUETOOTH|15|Bluetooth Recon|bt_recon_menu"
    "BLUETOOTH|16|Bluetooth Attack|bt_attack_menu"
    "BLUETOOTH|17|BLE Mesh|mesh_menu"

    "NETWORK|18|ARP / MITM|arp_menu"
    "NETWORK|19|Enterprise Kit|dot1x_menu"

    "PHYSICAL|20|HID Injection|hid_menu"

    "ANALYSIS|21|Capture Analysis|capture_analysis_menu"
    "ANALYSIS|22|Wordlist Manager|wordlist_menu"
    "ANALYSIS|23|Fingerprint|fingerprint_menu"

    "SCANNERS|24|Wi-Fi CVE Kit|wifi_cve_scan_menu"
    "SCANNERS|25|Bluetooth CVE Kit|btcve_scan_menu"
    "SCANNERS|26|Wireless IDS|wifi_ids_menu"
    "SCANNERS|27|RF Spectrum|spectrum_menu"
    "SCANNERS|28|Zigbee|zigbee_menu"
    "SCANNERS|29|Firmware / IoT|firmware_menu"

    "AUTOMATION|30|Killchain|killchain_menu"
)

# ── banner ──────────────────────────────────────────────────
banner() {
    clear
    local w; w=$(term_width)

    printf '%s%s' "$C_MAG" "$C_BOLD"
    cat << 'B'
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
            kcol="$C_DIM"; lcol="$C_DIM"; tag=" ${C_YEL}[offline]${C_RESET}" ;;
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
    declare -F "$1" >/dev/null 2>&1 && echo present || echo missing
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

for mod in "${MODULE_FILES[@]}"; do
    if ! bash -n "$mod" 2>/dev/null; then
        err "syntax error in $(basename "$mod") — skipping"
        continue
    fi

    # Some modules call `exit` at top level. Sourcing such a file would
    # kill this shell mid-loop. Shadow the exit builtin for the duration
    # of the source, then unshadow.
    _prev_exit_fn=$(declare -f exit 2>/dev/null || true)
    exit() { return "${1:-0}"; }

    if source "$mod" 2>>"$SESSION_LOG"; then
        ok "loaded: $(basename "$mod")"
    else
        err "runtime error in $(basename "$mod")"
    fi

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
        if declare -F "$fn" >/dev/null 2>&1; then
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
  Modules marked [offline] failed to load — check logs/session_*.log.

  Keys:
    [01]-[30]   launch module
    [h]         this help
    [c]         clear screen
    [g]         launch the GUI (builddir/wifisting-gui)
    [q]         quit

  Every module has its own menu. Type '0' inside to return here.

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

                if [[ -n "$fn" ]] && declare -F "$fn" >/dev/null 2>&1; then
                    "$fn"
                elif [[ -n "$fn" ]]; then
                    warn "module $choice failed to load — check $SESSION_LOG"
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

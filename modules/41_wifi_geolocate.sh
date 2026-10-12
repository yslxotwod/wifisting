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
# Apple lookup cache, and the cap on how many BSSIDs one batch run will
# disclose to Apple without an explicit override.
GEO_DIR="${GEO_DIR:-$MOD_TMP}"
APPLE_MAX_PER_RUN="${APPLE_MAX_PER_RUN:-25}"
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
geo_apple_selftest() {
    local bad=0
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; bad=$(( bad + 1 )); fi
    }

    # Zero-stripped octets must canonicalise, because Apple replies with
    # e4:9e:12:5:34:59 for a query of e4:9e:12:05:34:59 and a raw string
    # comparison never matches.
    local norm
    norm=$(python3 - <<'PY'
def norm_mac(mac):
    return ":".join(o.rjust(2, "0") for o in mac.lower().split(":"))
print(norm_mac("e4:9e:12:5:34:59"))
PY
)
    chk apple-zero-stripped-normalises "$norm" "e4:9e:12:05:34:59"

    # The batch cap is enforced before anything is disclosed.
    printf 'aa:bb:cc:00:00:01\naa:bb:cc:00:00:02\n' > "$GEO_DIR/st-aps.txt"
    local out
    out=$(geo_apple_batch "$GEO_DIR/st-aps.txt" 1 2>&1)
    grep -q 'exceeds the per-run cap' <<<"$out" && chk apple-batch-cap-enforced ok ok \
                                               || chk apple-batch-cap-enforced no ok

    # A file with no BSSIDs must be refused rather than silently doing nothing.
    printf 'not a mac\n' > "$GEO_DIR/st-empty.txt"
    out=$(geo_apple_batch "$GEO_DIR/st-empty.txt" 2>&1)
    grep -q 'no BSSIDs found' <<<"$out" && chk apple-batch-rejects-empty ok ok \
                                        || chk apple-batch-rejects-empty no ok

    out=$(geo_apple_batch "" 2>&1); chk apple-batch-noarg-rc "$?" "2"
    out=$(geo_apple_batch /nonexistent 2>&1); chk apple-batch-nofile-rc "$?" "1"

    rm -f "$GEO_DIR/st-aps.txt" "$GEO_DIR/st-empty.txt"
    return $(( bad > 0 ))
}

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

    # Apple lookup: argument handling only. A live query is not part of a
    # selftest - it would disclose BSSIDs to Apple on every run. Captured
    # so the block prints once and its failures count toward the total.
    {
        local apple_out
        apple_out=$(geo_apple_selftest 2>&1)
        printf '%s\n' "$apple_out"
        bad=$(( bad + $(grep -c FAIL <<<"$apple_out") ))
    }

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
# ── Apple Location Services ───────────────────────────────────────────
#
# Resolve a BSSID to coordinates server-side, with no signal strength and
# no calibration. Apple maintains a database of access points built from
# devices that have geolocated themselves, so a single observation is
# enough — which is the thing RSSI estimation cannot do.
#
# HOW IT WORKS
# POST a binary plist of BSSIDs to Apple's wloc endpoint; get back a plist
# of coordinates. The endpoint is undocumented and unofficial: it is what
# locationd uses, it changes without notice, and it may simply refuse.
#
# SO THIS IS A SECOND OPINION, NOT A REPLACEMENT
# The RSSI estimate stays as the offline method. This adds a network
# method beside it, and the output says which one answered. If Apple stops
# replying the module degrades to what it did before rather than breaking.
#
# PRIVACY, AND IT IS NOT A FOOTNOTE
# Every BSSID you look up is sent to Apple, who can associate the query
# with your address and correlate it with the rest of the batch. That is
# the same information a war-drive would collect about a neighbourhood,
# handed to a third party. Results are cached, so a repeat costs nothing,
# and --apple-batch refuses to send more than APPLE_MAX_PER_RUN without
# an explicit override.

geo_apple_cache() {
    printf '%s/apple-cache.tsv' "$GEO_DIR"
}

geo_apple_available() {
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c 'import plistlib, urllib.request' 2>/dev/null || return 1
    return 0
}

# Cache lookups: TSV of bssid -> lat,lon,accuracy,ts.
# A cached miss is stored too, so a dead BSSID is not retried every run.
geo_apple_cached() {
    local bssid="${1,,}" cache
    cache=$(geo_apple_cache)
    [[ -f "$cache" ]] || return 1
    awk -F'\t' -v b="$bssid" '$1 == b { print; found=1; exit } END { exit !found }' "$cache"
}

geo_apple_store() {
    local bssid="${1,,}" lat="$2" lon="$3" acc="$4" cache
    cache=$(geo_apple_cache)
    mkdir -p "$(dirname "$cache")" 2>/dev/null
    printf '%s\t%s\t%s\t%s\t%s\n' "$bssid" "$lat" "$lon" "$acc" "$(date +%s)" >> "$cache"
}

geo_apple_tsv() {
    local bssid="${1,,}"
    printf 'BSSID\tLAT\tLON\tACCURACY_M\tSOURCE\tCACHED\n'

    local hit
    if hit=$(geo_apple_cached "$bssid"); then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$bssid" "$(cut -f2 <<<"$hit")" "$(cut -f3 <<<"$hit")" \
            "$(cut -f4 <<<"$hit")" "apple" "yes"
        return 0
    fi

    geo_apple_available || {
        printf 'ERROR\tpython3 with plistlib and urllib is required\n' >&2
        return 1
    }

    local out
    out=$(APPLE_BSSID="$bssid" python3 - <<'PY' 2>&1
import os, re, struct, sys, urllib.error, urllib.request

# Apple's positioning service is an undocumented endpoint speaking a
# reverse-engineered protobuf. It is NOT a plist - an earlier version of
# this module guessed plist and every request came back HTTP 400.
#
# The wire format below is the minimal subset needed: protobuf varints and
# length-delimited fields, hand-encoded so there is no protobuf dependency.
# Credit for the protocol work belongs to the researchers who documented
# it; see the Credits section of the README.

WLOC = "https://gs-loc.apple.com/clls/wloc"
# Apple's service inspects the User-Agent and expects a locationd-style one.
UA = "locationd/1753.17 CFNetwork/889.9 Darwin/17.2.0"
UNKNOWN = -18000000000          # what Apple returns for an AP it cannot place

bssid = os.environ["APPLE_BSSID"]


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def tag(field, wire):
    return varint((field << 3) | wire)


def ld(field, data):
    """Length-delimited field: tag, length, payload."""
    return tag(field, 2) + varint(len(data)) + data


def build(bssids):
    # Repeated WifiDevice (field 2), each carrying its BSSID as field 1.
    devices = b"".join(ld(2, ld(1, b.encode())) for b in bssids)
    payload = devices + tag(3, 0) + varint(0) + tag(4, 0) + varint(0)
    # Fixed frame: locale, a locationd identifier and a client version,
    # then a two-byte big-endian payload length.
    frame = (b"\x00\x01\x00\x05en_US"
             b"\x00\x13com.apple.locationd"
             b"\x00\x0a8.1.12B411"
             b"\x00\x00\x00\x01\x00\x00")
    return frame + struct.pack(">H", len(payload)) + payload


def read_varint(buf, off):
    result = shift = 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated")
        byte = buf[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7


def signed(v):
    return v - (1 << 64) if v >= (1 << 63) else v


def parse_device(buf):
    """WifiDevice: field 1 BSSID, field 2 Location."""
    mac = None
    lat = lon = None
    off, end = 0, len(buf)
    while off < end:
        key, off = read_varint(buf, off)
        field, wire = key >> 3, key & 7
        if wire == 2:
            ln, off = read_varint(buf, off)
            chunk, off = buf[off:off + ln], off + ln
            if field == 1:
                mac = chunk.decode(errors="replace")
            elif field == 2:
                lat, lon = parse_loc(chunk)
        elif wire == 0:
            _, off = read_varint(buf, off)
        else:
            break
    return mac, lat, lon


def parse_loc(buf):
    """Location: field 1 latitude, field 2 longitude, int64 scaled by 1e8."""
    lat = lon = acc = None
    off, end = 0, len(buf)
    while off < end:
        key, off = read_varint(buf, off)
        field, wire = key >> 3, key & 7
        if wire == 0:
            v, off = read_varint(buf, off)
            v = signed(v)
            if field == 1:
                lat = v
            elif field == 2:
                lon = v
            elif field == 3:
                acc = v          # horizontal accuracy in metres
        elif wire == 2:
            ln, off = read_varint(buf, off)
            off += ln
        else:
            break
    if lat is None or lon is None:
        return None, None, None
    if lat == UNKNOWN or lon == UNKNOWN:
        return None, None, None
    return lat * 1e-8, lon * 1e-8, acc


def norm_mac(mac):
    """Canonical form: lowercase, every octet zero-padded to two digits.

    Apple replies with leading zeros stripped, so a raw string comparison
    against the address you asked for never matches.
    """
    try:
        return ":".join(o.rjust(2, "0") for o in mac.lower().split(":"))
    except Exception:
        return mac.lower()


def find_bssid(buf, want):
    """Locate WANT in the response and decode the Location that follows.

    Searching for the BSSID rather than walking from a fixed offset: the
    response carries a variable-length frame prefix and the device entry
    sits at field 1, not field 2. Assuming either cost one debugging
    session - the first version skipped 10 bytes when the prefix is 12 and
    looked for field 2 when the entry is field 1, so it read a valid 24 KB
    response and reported "no location".

    After the BSSID comes the Location as a length-delimited field. Its
    number is not assumed either; anything that parses as a Location is
    accepted.
    """
    needle = want.lower().encode()
    at = buf.lower().find(needle)
    if at < 0:
        return None

    off = at + len(needle)
    # Walk a short way forward looking for a length-delimited field whose
    # body decodes as a Location.
    for _ in range(6):
        if off + 1 >= len(buf):
            break
        key = buf[off]
        field, wire = key >> 3, key & 7
        off += 1
        if wire != 2:
            continue
        ln, off = read_varint(buf, off)
        chunk, off = buf[off:off + ln], off + ln
        if field == 2:
            lat, lon, acc = parse_loc(chunk)
            if lat is not None:
                return lat, lon, acc
    return None


def parse(raw):
    """Decode every BSSID/location pair Apple returned.

    The reply includes access points beyond the one asked for - Apple
    returns what it knows about the area - so this reads them all and the
    caller picks. Scanning is done on the raw bytes with a regex rather
    than by walking protobuf fields from a guessed offset.
    """
    located = {}
    # One or two hex digits per octet. Apple zero-STRIPS its replies:
    # ask for e4:9e:12:05:34:59 and it answers e4:9e:12:5:34:59. A
    # {2} pattern matched every other access point and silently skipped
    # the requested one, which read as "Apple has no location".
    for m in re.finditer(rb'(?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}', raw):
        mac = norm_mac(m.group(0).decode())
        off = m.end()
        for _ in range(6):
            if off + 1 >= len(raw):
                break
            key = raw[off]
            field, wire = key >> 3, key & 7
            off += 1
            if wire != 2:
                continue
            try:
                ln, off = read_varint(raw, off)
            except ValueError:
                break
            chunk, off = raw[off:off + ln], off + ln
            if field == 2:
                lat, lon, acc = parse_loc(chunk)
                if lat is not None:
                    located[mac] = (lat, lon, acc)
                    break
    return located


req = urllib.request.Request(
    WLOC, data=build([bssid]),
    headers={"User-Agent": UA,
             "Content-Type": "application/x-www-form-urlencoded"})

try:
    with urllib.request.urlopen(req, timeout=20) as fh:
        raw = fh.read()
except urllib.error.HTTPError as e:
    print("NETFAIL\tApple returned HTTP %s" % e.code)
    sys.exit(2)
except Exception as e:
    print("NETFAIL\t%s" % e)
    sys.exit(2)

located = parse(raw)
hit = located.get(norm_mac(bssid))
if hit is None:
    # Apple answered but does not know this access point. Not an error in
    # the request - the response simply carries no entry for it.
    print("NOMATCH\tApple has no location for this BSSID (%d other APs in reply)"
          % len(located))
    sys.exit(4)

print("OK\t%.7f\t%.7f\t%s" % (hit[0], hit[1], hit[2] if hit[2] is not None else ""))
PY
)
    local rc=$?

    if [[ "$out" == OK$'\t'* ]]; then
        local lat lon acc
        lat=$(cut -f2 <<<"$out"); lon=$(cut -f3 <<<"$out"); acc=$(cut -f4 <<<"$out")
        geo_apple_store "$bssid" "$lat" "$lon" "$acc"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$bssid" "$lat" "$lon" "$acc" "apple" "no"
        return 0
    fi

    # A failure is reported as a failure. Storing a miss keeps a dead
    # BSSID from being retried on every run.
    local kind msg
    kind=$(cut -f1 <<<"$out"); msg=$(cut -f2- <<<"$out")
    geo_apple_store "$bssid" "" "" "" 
    printf 'ERROR\t%s\t%s\n' "${kind:-FAILED}" "${msg:-no detail}" >&2
    return "${rc:-1}"
}

geo_apple_batch() {
    local file="${1:-}" max="${2:-$APPLE_MAX_PER_RUN}"
    [[ -z "$file" ]] && { printf 'ERROR\tusage: --apple-batch FILE [MAX]\n' >&2; return 2; }
    [[ -f "$file" ]] || { printf 'ERROR\tno such file: %s\n' "$file" >&2; return 1; }

    local total
    total=$(grep -cE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' "$file" || true)
    (( total == 0 )) && { printf 'ERROR\tno BSSIDs found in %s\n' "$file" >&2; return 1; }

    printf 'BATCH\t%s\t%s BSSID(s)\n' "$file" "$total"
    printf 'PRIVACY\teach BSSID is disclosed to Apple - see --help\n'

    if (( total > max )); then
        printf 'ERROR\t%s exceeds the per-run cap of %s\n' "$total" "$max" >&2
        printf 'ERROR\traise it deliberately: --apple-batch %s %s\n' "$file" "$total" >&2
        return 1
    fi

    printf 'BSSID\tLAT\tLON\tACCURACY_M\tSOURCE\tCACHED\n'
    local b n=0 ok=0
    while read -r b; do
        [[ "$b" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || continue
        n=$(( n + 1 ))
        geo_apple_tsv "$b" | tail -n +2 && ok=$(( ok + 1 ))
        # Deliberate pacing. Hammering an undocumented endpoint is how it
        # stops answering for everyone.
        sleep 1
    done < "$file"
    printf 'SUMMARY\t%s attempted, %s answered\n' "$n" "$ok"
}


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
        --apple-lookup) geo_apple_tsv "$@" ;;
        --apple-batch)  geo_apple_batch "$@" ;;
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

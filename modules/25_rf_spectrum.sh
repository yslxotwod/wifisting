#!/usr/bin/env bash
# 25_rf_spectrum.sh — HackRF / RTL-SDR spectrum sweeps, waterfall,
# channel occupancy, raw IQ capture
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
: "${WIFISTING_HOME:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" 2>/dev/null

SPEC_DIR="$TMP_DIR/rf_spectrum"
SPEC_LOOT="$LOOT_DIR/rf_spectrum"
MOD_TMP="$TMP_DIR/rf_spectrum"
mkdir -p "$SPEC_DIR" "$SPEC_LOOT" "$MOD_TMP"

spec_detect_sdr() {
    local found="none"
    if command -v lsusb >/dev/null 2>&1; then
        if lsusb 2>/dev/null | grep -qi '1d50:6089\|1d50:60a1\|1d50:604b'; then
            found="hackrf"
        elif lsusb 2>/dev/null | grep -qi '0bda:2832\|0bda:2838\|0bda:2831'; then
            found="rtlsdr"
        elif lsusb 2>/dev/null | grep -qi '2cf0:5249\|2cf0:5250'; then
            found="nuand"
        fi
    fi
    printf '%s' "$found"
}

spec_check_tools() {
    local missing=()
    for t in hackrf_transfer rtl_sdr rtl_power; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if (( ${#missing[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${missing[*]}")"
        return 1
    fi
    printf 'READY\n'
}

spec_status_tsv() {
    local hw
    hw=$(spec_detect_sdr)
    local hackrf_ok=no rtl_ok=no sox=no
    command -v hackrf_transfer >/dev/null 2>&1 && hackrf_ok=yes
    command -v rtl_power       >/dev/null 2>&1 && rtl_ok=yes
    command -v sox             >/dev/null 2>&1 && sox=yes

    local scans=0
    [[ -d "$SPEC_LOOT" ]] && scans=$(find "$SPEC_LOOT" -maxdepth 1 -type f 2>/dev/null | wc -l)

    printf 'hardware\t%s\n'   "$hw"
    printf 'hackrf\t%s\n'     "$hackrf_ok"
    printf 'rtlsdr\t%s\n'     "$rtl_ok"
    printf 'sox\t%s\n'        "$sox"
    printf 'scans\t%s\n'      "$scans"
    printf 'loot\t%s\n'       "$SPEC_LOOT"
}

spec_list_scans_tsv() {
    local f
    for f in "$SPEC_LOOT"/*.csv "$SPEC_LOOT"/*.png "$SPEC_LOOT"/*.iq \
             "$SPEC_LOOT"/*.wav; do
        [[ -e "$f" ]] || continue
        printf '%s\t%s\t%s\n' "$(basename "$f")" "$(stat -c%s "$f")" "$(stat -c%Y "$f")"
    done
}

# ═══════════════════════════════════════════════════════════════════
#  band sweep (existing)
# ═══════════════════════════════════════════════════════════════════

spec_wifi_band_scan() {
    local band="${1:-2.4}"
    local dur="${2:-30}"
    local hw
    hw=$(spec_detect_sdr)
    [[ "$hw" == "none" ]] && {
        printf 'ERROR\tno SDR detected (need HackRF or RTL-SDR)\n' >&2
        return 1
    }

    local freq_min freq_max
    case "$band" in
        2.4) freq_min="2400000000"; freq_max="2500000000" ;;
        5)   freq_min="5150000000"; freq_max="5850000000" ;;
        6)   freq_min="5925000000"; freq_max="7125000000" ;;
        *)   printf 'ERROR\tunknown band: %s (use 2.4|5|6)\n' "$band" >&2; return 1 ;;
    esac

    local ts out
    ts=$(date +%Y%m%d_%H%M%S)
    out="$SPEC_LOOT/wifi_${band}_${ts}.csv"

    if command -v rtl_power >/dev/null 2>&1; then
        info "rtl_power scan $band GHz (${dur}s) → $out"
        timeout "$dur" rtl_power -f "${freq_min}:${freq_max}:100k" \
            -i 5 -e "$dur" -g 40 -F 9 "$out" 2>&1 | tail -5
    elif command -v hackrf_sweep >/dev/null 2>&1; then
        info "hackrf_sweep $band GHz (${dur}s) → $out"
        timeout "$dur" hackrf_sweep -f "$((freq_min/1000000)):$((freq_max/1000000))" \
            -l 32 -g 32 -w 100000 2>&1 | tee "$out" | tail -5
    else
        printf 'ERROR\tneither rtl_power nor hackrf_sweep available\n' >&2
        return 1
    fi

    if [[ -s "$out" ]]; then
        printf 'SCAN\t%s\n' "$out"
        # Immediately generate a waterfall PNG
        spec_render_waterfall "$out" || true
    else
        printf 'ERROR\tscan produced no data\n' >&2
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  waterfall PNG
# ═══════════════════════════════════════════════════════════════════

# Parse rtl_power / hackrf_sweep CSV and render a heatmap.
# rtl_power format: date,time,freq_low,freq_high,step,n_samples,p0,p1,...
# hackrf_sweep format: date,time,freq_low,freq_high,step,n_samples,p0,p1,...
# (same structure)
spec_render_waterfall() {
    local csv="$1"
    local out="${2:-${csv%.csv}.png}"
    [[ ! -f "$csv" ]] && { printf 'ERROR\tno csv\n' >&2; return 1; }

    python3 - "$csv" "$out" <<'PY'
import sys, csv
try:
    from PIL import Image
except ImportError:
    print("ERROR\tPillow not installed (pip install pillow)", file=sys.stderr)
    sys.exit(1)

src, dst = sys.argv[1], sys.argv[2]

rows = []
with open(src, "r", errors="replace") as fh:
    reader = csv.reader(fh)
    for row in reader:
        if len(row) < 7: continue
        try:
            lo = float(row[2]); hi = float(row[3])
        except ValueError:
            continue
        try:
            powers = [float(x) for x in row[6:] if x.strip()]
        except ValueError:
            continue
        if not powers: continue
        rows.append((lo, hi, powers))

if not rows:
    print("ERROR\tno valid rows in csv", file=sys.stderr)
    sys.exit(1)

n_freq = max(len(r[2]) for r in rows)
n_time = len(rows)

# Find global min/max for scaling
all_p = [p for r in rows for p in r[2]]
pmin = min(all_p); pmax = max(all_p)
span = pmax - pmin if pmax > pmin else 1.0

# Build image (RGB). x = frequency bin, y = time
img = Image.new("RGB", (n_freq, n_time), (0, 0, 0))
px = img.load()

for y, (lo, hi, powers) in enumerate(rows):
    for x in range(n_freq):
        if x < len(powers):
            p = powers[x]
        else:
            p = pmin
        norm = (p - pmin) / span
        # heat map: black -> blue -> red -> yellow -> white
        if norm < 0.25:
            t = norm / 0.25
            r = 0; g = 0; b = int(t * 255)
        elif norm < 0.5:
            t = (norm - 0.25) / 0.25
            r = int(t * 255); g = 0; b = 255 - int(t * 128)
        elif norm < 0.75:
            t = (norm - 0.5) / 0.25
            r = 255; g = int(t * 255); b = 128 - int(t * 128)
        else:
            t = (norm - 0.75) / 0.25
            r = 255; g = 255; b = int(t * 255)
        px[x, y] = (r, g, b)

img.save(dst)
print(f"WATERFALL\t{dst}\t{n_freq}x{n_time}\t{pmin:.1f}..{pmax:.1f}dBm", file=sys.stderr)
PY
    if [[ -s "$out" ]]; then
        printf 'PNG\t%s\n' "$out"
    else
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  peak detection
# ═══════════════════════════════════════════════════════════════════

spec_find_peaks() {
    local csv="$1"
    local threshold="${2:--50}"
    local min_sep_khz="${3:-5000}"
    [[ ! -f "$csv" ]] && { printf 'ERROR\tno csv\n' >&2; return 1; }

    python3 - "$csv" "$threshold" "$min_sep_khz" <<'PY'
import sys, csv
src, thresh, min_sep_khz = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
min_sep_hz = min_sep_khz * 1000.0

# Aggregate the whole sweep into one average spectrum
bins = {}   # freq_hz -> [sum, count]
with open(src, "r", errors="replace") as fh:
    for row in csv.reader(fh):
        if len(row) < 7: continue
        try:
            lo = float(row[2]); hi = float(row[3])
        except ValueError: continue
        try:
            powers = [float(x) for x in row[6:] if x.strip()]
        except ValueError: continue
        if not powers: continue
        step = (hi - lo) / len(powers)
        for i, p in enumerate(powers):
            f = lo + i * step
            b = bins.setdefault(f, [0.0, 0])
            b[0] += p; b[1] += 1

if not bins:
    print("ERROR\tno data")
    sys.exit(1)

spec = sorted((f, s/n) for f, (s, n) in bins.items())

# Peak = local maximum over a 3-bin window, above threshold
peaks = []
for i in range(1, len(spec) - 1):
    f, p = spec[i]
    if p < thresh: continue
    if p >= spec[i-1][1] and p >= spec[i+1][1]:
        # Enforce min separation
        if peaks and (f - peaks[-1][0]) < min_sep_hz:
            if p > peaks[-1][1]:
                peaks[-1] = (f, p)
            continue
        peaks.append((f, p))

peaks.sort(key=lambda x: -x[1])
for f, p in peaks[:30]:
    print(f"PEAK\t{f/1e6:.3f}\t{p:.1f}")
if not peaks:
    print("NOPEAKS")
PY
}

# ═══════════════════════════════════════════════════════════════════
#  gain sweep (weak signal detection)
# ═══════════════════════════════════════════════════════════════════

# Repeat a narrowband scan at increasing LNA/VGA gain to find the
# setting where a weak signal first crosses the noise floor.
spec_gain_sweep() {
    local freq="${1:-2437000000}"
    local dur_per_step="${2:-3}"
    local hw
    hw=$(spec_detect_sdr)
    [[ "$hw" == "none" ]] && { printf 'ERROR\tno SDR\n' >&2; return 1; }

    local ts out
    ts=$(date +%Y%m%d_%H%M%S)
    out="$SPEC_LOOT/gain_${freq}_${ts}.tsv"
    : > "$out"

    local -a gains
    case "$hw" in
        hackrf) gains=(0 8 16 24 32 40) ;;   # LNA steps in dB
        rtlsdr) gains=("auto" 0 8.7 16.6 22.9 28.0 33.8 40.2 49.6) ;;
        *) printf 'ERROR\tunsupported SDR: %s\n' "$hw" >&2; return 1 ;;
    esac

    info "gain sweep on $freq Hz ($hw) — ${#gains[@]} steps × ${dur_per_step}s"

    local g
    for g in "${gains[@]}"; do
        local tmp="$SPEC_DIR/gainsweep_${g}.csv"
        case "$hw" in
            hackrf)
                timeout "$dur_per_step" hackrf_sweep \
                    -f "$((freq/1000000)):$((freq/1000000+20))" \
                    -l "$g" -g 32 -w 100000 > "$tmp" 2>/dev/null || true ;;
            rtlsdr)
                if [[ "$g" == "auto" ]]; then
                    timeout "$dur_per_step" rtl_power \
                        -f "${freq}:$((freq+2000000)):100k" \
                        -i 1 -e "$dur_per_step" "$tmp" 2>/dev/null || true
                else
                    timeout "$dur_per_step" rtl_power \
                        -f "${freq}:$((freq+2000000)):100k" \
                        -i 1 -e "$dur_per_step" -g "$g" "$tmp" 2>/dev/null || true
                fi ;;
        esac

        if [[ -s "$tmp" ]]; then
            local peak
            peak=$(spec_find_peaks "$tmp" -90 500 2>/dev/null | \
                   awk -F'\t' '/^PEAK/{print $3; exit}')
            printf '%s\t%s\n' "$g" "${peak:-?}" >> "$out"
        fi
    done

    printf 'GAIN_SWEEP\t%s\n' "$out"
    cat "$out"
}

# ═══════════════════════════════════════════════════════════════════
#  raw IQ capture (existing, with WAV export)
# ═══════════════════════════════════════════════════════════════════

spec_raw_capture() {
    local freq="${1:-2437000000}"
    local rate="${2:-2000000}"
    local dur="${3:-10}"
    local hw
    hw=$(spec_detect_sdr)
    [[ "$hw" == "none" ]] && { printf 'ERROR\tno SDR\n' >&2; return 1; }

    local ts out
    ts=$(date +%Y%m%d_%H%M%S)

    case "$hw" in
        hackrf)
            command -v hackrf_transfer >/dev/null || {
                printf 'ERROR\tno hackrf_transfer\n' >&2; return 1; }
            out="$SPEC_LOOT/iq_${freq}_${ts}.iq"
            info "hackrf_transfer $freq Hz @ $rate sps for ${dur}s → $out"
            timeout "$dur" hackrf_transfer -r "$out" -f "$freq" -s "$rate" \
                -a 1 -l 32 -g 32 2>&1 | tail -5 ;;
        rtlsdr)
            command -v rtl_sdr >/dev/null || {
                printf 'ERROR\tno rtl_sdr\n' >&2; return 1; }
            out="$SPEC_LOOT/iq_${freq}_${ts}.iq"
            info "rtl_sdr $freq Hz @ $rate sps for ${dur}s → $out"
            timeout "$dur" rtl_sdr -f "$freq" -s "$rate" -g 40 \
                -n "$((dur * rate))" "$out" 2>&1 | tail -5 ;;
        *)
            printf 'ERROR\tunsupported SDR: %s\n' "$hw" >&2; return 1 ;;
    esac

    if [[ -s "$out" ]]; then
        printf 'CAPTURE\t%s\nSIZE\t%s\n' "$out" "$(stat -c%s "$out")"

        # Optional WAV export via sox
        if command -v sox >/dev/null 2>&1; then
            local wav="${out%.iq}.wav"
            info "converting IQ → WAV via sox"
            sox -t raw -e unsigned-integer -b 8 -r "$rate" -c 2 "$out" "$wav" 2>/dev/null && \
                printf 'WAV\t%s\n' "$wav"
        fi
    else
        printf 'ERROR\tcapture empty\n' >&2
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  sox spectrogram
# ═══════════════════════════════════════════════════════════════════

spec_spectrogram() {
    local iq="$1"
    [[ -z "$iq" || ! -f "$iq" ]] && { printf 'ERROR\tno iq file\n' >&2; return 1; }
    command -v sox >/dev/null 2>&1 || { printf 'ERROR\tsox missing\n' >&2; return 1; }

    local png="${iq%.iq}.spectrogram.png"
    info "rendering sox spectrogram → $png"
    # -n spectrogram → normalise, -x 1024 → fft bins, -y 513 → rows
    sox "$iq" -n spectrogram -o "$png" -x 1024 -y 513 2>&1 | tail -3
    [[ -s "$png" ]] && printf 'PNG\t%s\n' "$png"
}

# ═══════════════════════════════════════════════════════════════════
#  channel occupancy (existing)
# ═══════════════════════════════════════════════════════════════════

spec_channel_occupancy() {
    local band="${1:-2.4}"
    local dur="${2:-20}"
    local -a channels
    case "$band" in
        2.4) channels=(1 2 3 4 5 6 7 8 9 10 11 12 13) ;;
        5)   channels=(36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 149 153 157 161 165) ;;
        6)   channels=(1 5 9 13 17 21 25 29 33 37 41 45 49 53 57 61 65 69 73 77 81 85 89 93 97 101 105 109 113 117 121 125 129 133 137 141 145 149 153 157 161 165 169 173 177 181 185 189 193 197 201 205 209 213 217 221 225 229 233) ;;
        *)   printf 'ERROR\tunknown band\n' >&2; return 1 ;;
    esac

    local iface
    iface=$(iw dev 2>/dev/null | awk '
        /Interface/ { i=$2 }
        /type monitor/ { print i; exit }')
    [[ -z "$iface" ]] && { printf 'ERROR\tno monitor interface\n' >&2; return 1; }

    printf 'CHANNEL\tBSS\tSTATIONS\n'
    local ch
    for ch in "${channels[@]}"; do
        iw dev "$iface" set channel "$ch" 2>/dev/null || continue
        sleep 1
        local bss stations
        bss=$(iw dev "$iface" scan 2>/dev/null | grep -c '^BSS') || bss=0
        stations=$(iw dev "$iface" station dump 2>/dev/null | grep -c '^Station') || stations=0
        printf '%s\t%s\t%s\n' "$ch" "$bss" "$stations"
    done
}

spec_info() {
    cat <<'INFO'
RF spectrum analysis:

Supported hardware:
  HackRF One           1 MHz – 6 GHz TX/RX (half-duplex)
  RTL-SDR (RTL2832U)   24 MHz – 1.7 GHz RX only
  Nuand BladeRF        higher-end, not actively tested

New in this build:
  --waterfall CSV       render a heatmap PNG from a sweep
  --peaks CSV           detect local-max peaks above a threshold
  --gain-sweep FREQ     step through gain settings, report peak dBm each
  --spectrogram IQ      render a sox spectrogram PNG from a raw IQ file
  WAV export            sox converts IQ → WAV automatically after capture

Band reference:
  2.4 GHz    2412–2472 MHz, channels 1-14
  5 GHz      5180–5825 MHz, channels 36-165
  6 GHz      5955–7115 MHz, channels 1-233 (Wi-Fi 6E)

Common workflows:
  rtl_power           channel occupancy over time (sweep → CSV)
  hackrf_sweep        fast broadband spectrum scan
  rtl_sdr / hackrf_transfer   raw IQ capture for offline analysis

Downstream tools (not integrated):
  gqrx            interactive waterfall
  sigmf           standard IQ metadata format
  inspectrum      offline IQ viewer
  gnuradio-companion   custom DSP chains
INFO
}

# ── self-test ────────────────────────────────────────────────────────────
# No SDR is touched: the sweep backends (rtl_power/iw/lsusb) are stubbed on
# PATH so the band arithmetic and the channel tables are observable, and
# the peak detector / waterfall renderer run on synthetic CSVs whose
# expected bins are known by construction.
spec_selftest() {
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    rcof() { "$@" >/dev/null 2>&1; echo $?; }

    local d out rc
    # Unique per run: a second selftest (runner alongside a manual run)
    # must not share scratch files.
    d=$(mktemp -d "$MOD_TMP/selftest.XXXXXX") || {
        printf 'ERROR\tmktemp failed under %s\n' "$MOD_TMP" >&2; return 1; }
    mkdir -p "$d/bin" "$d/loot"

    # ── peak detection: exact bin frequencies from a synthetic sweep ──
    # lo=2400 MHz, 10 bins of 1 MHz, so bin i sits at 2400+i MHz.
    printf '%s\n' '2024-01-01,00:00:00,2400000000,2410000000,1000000.0,10,-80,-75,-70,-60,-50,-45,-50,-60,-70,-80' \
        > "$d/one.csv"
    out=$(spec_find_peaks "$d/one.csv")
    chk peak-count  "$(printf '%s\n' "$out" | grep -c '^PEAK')" "1"
    chk peak-mhz    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="PEAK"{print $2}')" "2405.000"
    chk peak-dbm    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="PEAK"{print $3}')" "-45.0"
    chk peak-threshold "$(spec_find_peaks "$d/one.csv" -40)" "NOPEAKS"

    # Two tones 2 MHz apart, both above the -50 dBm threshold: the default
    # 5 MHz separation keeps only the stronger one, a 1 kHz separation
    # keeps both (strongest first).
    printf '%s\n' '2024-01-01,00:00:00,2400000000,2410000000,1000000.0,10,-80,-70,-50,-45,-60,-48,-65,-70,-75,-80' \
        > "$d/two.csv"
    chk peak-minsep-default "$(spec_find_peaks "$d/two.csv" | grep -c '^PEAK')" "1"
    chk peak-minsep-tight   "$(spec_find_peaks "$d/two.csv" -50 1 | grep -c '^PEAK')" "2"
    chk peak-minsep-order   "$(spec_find_peaks "$d/two.csv" -50 1 | awk -F'\t' 'NR==1{print $2"/"$3}')" \
        "2403.000/-45.0"
    chk peaks-missing-rc "$(rcof spec_find_peaks "$d/absent.csv")" "1"
    printf '%s\n' 'too,few,fields' > "$d/bad.csv"
    out=$(spec_find_peaks "$d/bad.csv" 2>&1); rc=$?
    chk peaks-nodata-rc  "$rc" "1"
    chk peaks-nodata-msg "$(printf '%s\n' "$out" | grep -c 'no data')" "1"

    # ── waterfall colour mapping, only if Pillow is present ──
    if python3 -c 'from PIL import Image' 2>/dev/null; then
        # 3 frequency bins x 2 sweeps; pmin -80, pmax -40.
        printf '%s\n' \
            '2024-01-01,00:00:00,2400000000,2403000000,1000000.0,3,-80,-60,-40' \
            '2024-01-01,00:00:01,2400000000,2403000000,1000000.0,3,-80,-50,-60' \
            > "$d/wf.csv"
        out=$(spec_render_waterfall "$d/wf.csv" "$d/wf.png" 2>/dev/null); rc=$?
        chk waterfall-rc  "$rc" "0"
        chk waterfall-png "$(printf '%s\n' "$out" | awk -F'\t' '$1=="PNG"{print $2}')" "$d/wf.png"
        chk waterfall-pixels "$(python3 - "$d/wf.png" <<'PY'
import sys
from PIL import Image
im = Image.open(sys.argv[1])
print("%sx%s %s %s %s" % (im.size[0], im.size[1], im.getpixel((0, 0)),
                          im.getpixel((1, 0)), im.getpixel((2, 0))))
PY
)" "3x2 (0, 0, 0) (255, 0, 128) (255, 255, 255)"
    else
        printf 'waterfall-pixels\tSKIP (Pillow not installed)\n'
    fi

    # ── band mapping: stub lsusb (SDR present) + rtl_power (records argv) ──
    cat > "$d/bin/lsusb" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' 'Bus 001 Device 004: ID 0bda:2832 Realtek Semiconductor Corp. RTL2838 DVB-T'
STUB
    cat > "$d/bin/rtl_power" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG"
out=""
for a in "$@"; do
    case "$a" in -*) ;; *) out="$a" ;; esac
done
[[ -n "$out" ]] && printf '%s\n' \
    '2024-01-01,00:00:00,2400000000,2410000000,1000000.0,3,-70,-60,-50' > "$out"
exit 0
STUB
    chmod +x "$d/bin/lsusb" "$d/bin/rtl_power"

    band_probe() {   # band tag
        (
            export PATH="$d/bin:$PATH" STUB_LOG="$d/args_$2.log" SPEC_LOOT="$d/loot"
            spec_wifi_band_scan "$1" 1 > "$d/band_$2.out" 2>&1
            echo $? > "$d/band_$2.rc"
        )
    }
    band_f() { awk '{for (i = 1; i <= NF; i++) if ($i == "-f") print $(i+1)}' "$d/args_$1.log"; }

    band_probe 2.4 b24; band_probe 5 b5; band_probe 6 b6
    chk band-24-freq "$(band_f b24)" "2400000000:2500000000:100k"
    chk band-5-freq  "$(band_f b5)"  "5150000000:5850000000:100k"
    chk band-6-freq  "$(band_f b6)"  "5925000000:7125000000:100k"
    chk band-24-rc   "$(cat "$d/band_b24.rc")" "0"
    chk band-5-rc    "$(cat "$d/band_b5.rc")" "0"
    chk band-6-rc    "$(cat "$d/band_b6.rc")" "0"
    out=$(PATH="$d/bin:$PATH" SPEC_LOOT="$d/loot" spec_wifi_band_scan 7 1 2>&1); rc=$?
    chk band-unknown-rc  "$rc" "1"
    chk band-unknown-msg "$(printf '%s\n' "$out" | grep -c 'unknown band: 7')" "1"

    # ── channel tables: stub iw + a no-op sleep so the whole sweep is
    #    instant. The row count is the table length for that band.
    cat > "$d/bin/iw" <<'STUB'
#!/usr/bin/env bash
case "$*" in
    "dev")            printf 'phy#0\n\tInterface wlan0\n\t\ttype monitor\n' ;;
    *"station dump"*) printf 'Station aa:bb:cc:dd:ee:ff (on wlan0)\n' ;;
    *scan*)           printf 'BSS aa:bb:cc:dd:ee:ff(on wlan0)\nBSS 11:22:33:44:55:66(on wlan0)\n' ;;
esac
exit 0
STUB
    cat > "$d/bin/sleep" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    chmod +x "$d/bin/iw" "$d/bin/sleep"

    occ_probe() {   # band tag
        (
            export PATH="$d/bin:$PATH"
            spec_channel_occupancy "$1" 1 > "$d/occ_$2.tsv" 2>&1
            echo $? > "$d/occ_$2.rc"
        )
    }
    occ_rows()  { tail -n +2 "$d/occ_$1.tsv" | grep -c .; }
    occ_first() { awk -F'\t' 'NR==2{print $1"/"$2"/"$3}' "$d/occ_$1.tsv"; }
    occ_last()  { awk -F'\t' 'END{print $1"/"$2"/"$3}' "$d/occ_$1.tsv"; }

    occ_probe 2.4 o24; occ_probe 5 o5; occ_probe 6 o6
    chk occ-24-rows  "$(occ_rows o24)" "13"
    chk occ-24-first "$(occ_first o24)" "1/2/1"
    chk occ-24-last  "$(occ_last o24)"  "13/2/1"
    chk occ-5-rows   "$(occ_rows o5)"  "24"
    chk occ-5-first  "$(occ_first o5)" "36/2/1"
    chk occ-5-last   "$(occ_last o5)"  "165/2/1"
    chk occ-6-rows   "$(occ_rows o6)"  "59"
    chk occ-6-first  "$(occ_first o6)" "1/2/1"
    chk occ-6-last   "$(occ_last o6)"  "233/2/1"
    chk occ-bad-rc   "$(PATH="$d/bin:$PATH" spec_channel_occupancy 7 1 >/dev/null 2>&1; echo $?)" "1"

    # ── listing / probing contracts ──
    mkdir -p "$d/loot2"
    printf '%s\n' 'x' > "$d/loot2/scan_a.csv"
    out=$(SPEC_LOOT="$d/loot2" spec_list_scans_tsv)
    chk list-name "$(printf '%s\n' "$out" | awk -F'\t' '{print $1}')" "scan_a.csv"
    chk list-size "$(printf '%s\n' "$out" | awk -F'\t' '{print $2}')" "2"
    chk list-mtime "$(printf '%s\n' "$out" | awk -F'\t' '{print $3}')" "$(stat -c%Y "$d/loot2/scan_a.csv")"
    out=$(spec_check_tools 2>&1); rc=$?
    case "$out" in
        READY)    chk tools-probe-status "$rc" "0" ;;
        MISSING*) chk tools-probe-status "$rc" "1" ;;
        *)        chk tools-probe-status "$out" "READY-or-MISSING" ;;
    esac

    rm -rf "$d"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

spec_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         spec_status_tsv ;;
        --check-tools)        spec_check_tools ;;
        --list-scans-tsv)     spec_list_scans_tsv ;;
        --wifi-scan)          spec_wifi_band_scan "$@" ;;
        --raw-capture)        spec_raw_capture "$@" ;;
        --channel-occupancy)  spec_channel_occupancy "$@" ;;
        --waterfall)          spec_render_waterfall "$@" ;;
        --peaks)              spec_find_peaks "$@" ;;
        --gain-sweep)         spec_gain_sweep "$@" ;;
        --spectrogram)        spec_spectrogram "$@" ;;
        --selftest)           spec_selftest ;;
        --info)               spec_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --check-tools
  --list-scans-tsv
  --wifi-scan BAND(2.4|5|6) [DURATION]
  --raw-capture FREQ_HZ [RATE] [DURATION]
  --channel-occupancy BAND(2.4|5|6) [PER_CHANNEL_SEC]
  --waterfall CSV [OUT_PNG]
  --peaks CSV [THRESH_DBM] [MIN_SEP_KHZ]
  --gain-sweep FREQ_HZ [DUR_PER_STEP]
  --spectrogram IQ_FILE
  --selftest                offline checks of the band/peak/waterfall maths
  --info
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    command -v err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    spec_cli_main "$@"
fi

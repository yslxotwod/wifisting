#!/usr/bin/env bash
# trace-icon.sh — turn a bitmap into a wifisting symbolic icon.
#
# The module icons are single-colour SVGs that GTK recolours through
# fill="currentColor". Turning supplied artwork into one is a three-stage
# pipeline, and getting any stage wrong produces a file that looks plausible
# but renders as a solid block, an inverted silhouette, or a blank icon:
#
#   convert   -> greyscale PGM (mkbitmap only reads pnm/bmp, never png/jpeg)
#   mkbitmap  -> threshold to PBM. -i inverts, which is required whenever the
#                artwork is light-on-dark; -f is the highpass radius that
#                suppresses JPEG ringing around the strokes.
#   potrace   -> SVG, then fill="#000000" is rewritten to currentColor.
#
# Polarity is not guessed: the mean brightness decides, and --invert/--no-invert
# override it. The result is checked by rendering it, so a bad trace is caught
# here rather than on the dashboard.
#
# Usage:
#   tools/trace-icon.sh IMAGE MODULE_ID [--invert|--no-invert]
#
# Example:
#   tools/trace-icon.sh native/resources/icons/symbolic/ble_fuzzing.jpeg 39_ble_fuzz

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_DIR="$ROOT/native/resources/icons/symbolic"

IMG="${1:-}"; MOD="${2:-}"; MODE="${3:-auto}"
if [[ -z "$IMG" || -z "$MOD" ]]; then
    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
[[ -f "$IMG" ]] || { echo "no such image: $IMG" >&2; exit 2; }

for t in convert mkbitmap potrace; do
    command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 2; }
done

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# ---- polarity ------------------------------------------------------------
mean=$(convert "$IMG" -colorspace Gray -format '%[fx:mean*255]' info: 2>/dev/null)
invert=""
case "$MODE" in
    --invert)    invert="-i" ;;
    --no-invert) invert="" ;;
    auto)        # dark frame means the artwork is the light part
                 awk -v m="${mean:-255}" 'BEGIN{exit !(m < 128)}' \
                     && invert="-i" || invert="" ;;
    *) echo "bad mode: $MODE" >&2; exit 2 ;;
esac
printf 'image    : %s (mean brightness %s)\n' "$IMG" "${mean:-?}"

# ---- build the mask ------------------------------------------------------
# A transparent source carries its shape in the alpha channel, not in the
# colours: nfc_rfid.png is black artwork on transparency, so a greyscale
# conversion flattens it to a uniformly black image and the trace comes out
# empty. Alpha is the mask in that case, and alpha-extract is light-on-dark,
# so it always needs inverting.
has_alpha=$(convert "$IMG" -format '%A' info: 2>/dev/null)
if [[ "$has_alpha" == "True" ]]; then
    echo "source   : alpha channel present - tracing that as the mask"
    # Straight to a bitmap, deliberately skipping mkbitmap: its highpass stage
    # is an edge filter, and on an already-clean alpha mask that traces the
    # outline of each stroke rather than its solid body, producing a hollow
    # double-stroked glyph.
    convert "$IMG" -alpha extract -morphology Open Disk:2 -negate \
            -threshold 50% -compress none "$WORK/out.pbm" || exit 1
    HAVE_PBM=1
else
    # A morphological open erases one-pixel whiskers before they are traced:
    # on this artwork that is the difference between a clean glyph and one
    # fringed with JPEG ringing. It is done here rather than by raising the
    # threshold, which at higher values floods the whole canvas instead.
    convert "$IMG" -colorspace Gray -morphology Open Disk:2 "$WORK/in.pgm" || exit 1
fi

# Reported after both the brightness test and the alpha override have had
# their say, so the message reflects what is actually done.
if [[ -n "$invert" ]]; then
    echo "polarity : inverting (artwork is the light part)"
else
    echo "polarity : direct (artwork is the dark part)"
fi

# ---- threshold + trace ---------------------------------------------------
if [[ -z "${HAVE_PBM:-}" ]]; then
    mkbitmap $invert -f 4 -t 0.5 "$WORK/in.pgm" -o "$WORK/out.pbm" || {
        echo "mkbitmap failed" >&2; exit 1; }
fi
[[ -s "$WORK/out.pbm" ]] || { echo "no bitmap produced" >&2; exit 1; }

potrace -s -o "$WORK/out.svg" --turdsize 10 --alphamax 1.0 "$WORK/out.pbm" || exit 1

# GTK recolours a symbolic icon through currentColor. Matching only the exact
# string potrace happens to emit today would, on any other output, leave a
# hard-coded black fill - an icon that renders correctly but never takes the
# theme colour. So rewrite any hex fill, then insist the result really has it.
sed -i -E 's/fill="#[0-9A-Fa-f]{3,8}"/fill="currentColor"/g' "$WORK/out.svg"
if ! grep -q 'fill="currentColor"' "$WORK/out.svg"; then
    echo "FAILED: could not make the SVG use currentColor - GTK would draw it" >&2
    echo "        in a fixed colour instead of the theme colour. Trace kept at:" >&2
    echo "        $WORK/out.svg" >&2
    cp "$WORK/out.svg" "/tmp/trace-failed-$(basename "$IMG").svg" 2>/dev/null || true
    exit 1
fi

OUT="$DEST_DIR/wifisting-${MOD}-symbolic.svg"
cp "$WORK/out.svg" "$OUT"
printf 'written  : %s (%s bytes)\n' "$OUT" "$(stat -c %s "$OUT")"

# ---- verify by rendering -------------------------------------------------
# Corner must be transparent (no background survived) and some ink must remain
# (the artwork was not thresholded away).
if command -v python3 >/dev/null 2>&1 && [[ -x /tmp/svgtest/ink ]]; then
    /tmp/svgtest/ink "$OUT"
fi
echo
echo "simulate GTK's recolour and check it at real size:"
convert -background none "$OUT" -resize 32x32 -fill '#ff3b3b' -colorize 100 \
        -background '#140a0c' -flatten -resize 400% "$WORK/check.png" 2>/dev/null \
    && echo "  wrote $WORK/check.png (lost when this script exits)" || true
echo
echo "next: tools/rename-icons.sh --install   # copy into the theme + rebuild cache"

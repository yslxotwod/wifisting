#!/usr/bin/env bash
# 39_ble_fuzz — BLE Payload Fuzzing
# Deterministic malformed BLE payload corpus generation.
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

MOD_TMP="$TMP_DIR/ble_fuzz"
MOD_LOOT="$LOOT_DIR/ble_fuzz"
MOD_LOGS="$LOG_DIR/ble_fuzz"
MOD_CAPS="$CAPTURES_DIR/ble_fuzz"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" "$MOD_CAPS" 2>/dev/null

# ── capability probes ────────────────────────────────────────────────────

FZ_OUT="$MOD_LOOT/corpus"
mkdir -p "$FZ_OUT" 2>/dev/null

fz_have_hci() {
    local d
    for d in /sys/class/bluetooth/hci*; do
        [[ -e "$d" ]] && { basename "$d"; return 0; }
    done
    return 1
}

fz_status_tsv() {
    local h; h=$(fz_have_hci 2>/dev/null || true)
    printf 'python3\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'hci\t%s\n' "${h:-none}"
    # Corpus generation is offline and deterministic; only replaying a case
    # onto a target needs a controller.
    printf 'generate\t%s\n' "$(command -v python3 >/dev/null 2>&1 && echo 1 || echo 0)"
    printf 'replay\t%s\n' "$([[ -n "$h" ]] && echo 1 || echo 0)"
    local n=0
    [[ -d "$FZ_OUT" ]] && n=$(find "$FZ_OUT" -maxdepth 1 -type f -name '*.hex' 2>/dev/null | wc -l)
    printf 'cached_corpora\t%s\n' "$n"
}

fz_strategies_tsv() {
    cat <<'EOF'
bitflip	Flip exactly one bit, walking the whole payload	deterministic
byteflip	XOR every byte with 0xff	deterministic
truncate	Cut the payload short at every length	deterministic
extend	Append 1..N filler bytes past the end	deterministic
adlen	Corrupt each AD length byte to 0x00/0xff/off-by-one	deterministic
adtype	Replace each AD type byte with edge values	deterministic
repeat	Duplicate AD structures to overflow the 31-byte limit	deterministic
random	Seeded random byte mutation	seeded
all	Every deterministic strategy above	deterministic
EOF
}

# ── mutation engine ──────────────────────────────────────────────────────
# Deterministic by design: the same seed and strategy always produce the
# same corpus, so a crash found by a replay can be reproduced exactly.
fz_mutate() {
    local seed_hex="$1" strategy="${2:-all}" limit="${3:-512}" rngseed="${4:-1}"
    [[ -z "$seed_hex" ]] && {
        printf 'ERROR\tusage: --mutate SEED_HEX [STRATEGY] [LIMIT] [RNG_SEED]\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    python3 - "$seed_hex" "$strategy" "$limit" "$rngseed" <<'PYEOF'
import random, sys

seed_hex, strategy, limit, rngseed = sys.argv[1:5]
limit = int(limit)
# argv is all strings; rngseed is formatted with %d later, so coerce once.
rngseed = int(rngseed)
rng = random.Random(rngseed)

raw = "".join(seed_hex.split()).replace(":", "")
try:
    seed = bytes.fromhex(raw)
except ValueError:
    print("ERROR\tnot valid hex", file=sys.stderr); sys.exit(1)
if not seed:
    print("ERROR\tempty seed payload", file=sys.stderr); sys.exit(1)

cases = []          # (strategy, description, bytes)

def add(s, d, b):
    if len(cases) < limit:
        cases.append((s, d, b))

# Walk the AD structures so structure-aware strategies know the offsets.
def ad_offsets(buf):
    offs = []
    i = 0
    while i < len(buf):
        ln = buf[i]
        if ln == 0 or i + 1 + ln > len(buf):
            break
        offs.append(i)
        i += 1 + ln
    return offs

if strategy in ("bitflip", "all"):
    for byte_i in range(len(seed)):
        for bit in range(8):
            m = bytearray(seed)
            m[byte_i] ^= (1 << bit)
            add("bitflip", "byte %d bit %d" % (byte_i, bit), bytes(m))

if strategy in ("byteflip", "all"):
    for byte_i in range(len(seed)):
        m = bytearray(seed); m[byte_i] ^= 0xFF
        add("byteflip", "byte %d" % byte_i, bytes(m))

if strategy in ("truncate", "all"):
    for cut in range(0, len(seed)):
        add("truncate", "cut to %d of %d" % (cut, len(seed)), seed[:cut])

if strategy in ("extend", "all"):
    for extra in (1, 2, 4, 8, 16, 31, 64, 255):
        for filler in (b"\x00", b"\xff", b"\xaa"):
            add("extend", "+%d x%02x" % (extra, filler[0]), seed + filler * extra)

if strategy in ("adlen", "all"):
    for off in ad_offsets(seed):
        for val in (0x00, 0x01, 0xFF, (seed[off] + 1) & 0xFF,
                    (seed[off] - 1) & 0xFF if seed[off] else 0xFE):
            m = bytearray(seed); m[off] = val
            add("adlen", "offset %d -> 0x%02x" % (off, val), bytes(m))

if strategy in ("adtype", "all"):
    for off in ad_offsets(seed):
        if off + 1 >= len(seed):
            continue
        for val in (0x00, 0x01, 0xFF, 0x7F, 0xFE):
            m = bytearray(seed); m[off + 1] = val
            add("adtype", "offset %d type -> 0x%02x" % (off + 1, val), bytes(m))

if strategy in ("repeat", "all"):
    for times in (2, 3, 8, 64):
        add("repeat", "x%d" % times, seed * times)

if strategy in ("random", "all"):
    n = 64 if strategy == "random" else 32
    for i in range(n):
        m = bytearray(seed)
        for _ in range(rng.randint(1, 4)):
            m[rng.randrange(len(m))] = rng.randrange(256)
        add("random", "seed %d draw %d" % (rngseed, i), bytes(m))

print("SEED_LEN\t%d" % len(seed))
print("STRATEGY\t%s" % strategy)
print("RNG_SEED\t%s" % rngseed)
print("CASES\t%d" % len(cases))
for s, d, b in cases:
    print("CASE\t%s\t%s\t%s" % (s, d, b.hex()))
PYEOF
}

# ── boundary corpus ──────────────────────────────────────────────────────
# Hand-picked payloads that sit exactly on the protocol limits, which is
# where parsers usually break.
fz_boundary() {
    command -v python3 >/dev/null 2>&1 || { printf 'ERROR\tpython3 required\n' >&2; return 1; }
    # Generated rather than hand-written so the advertised length and the
    # real byte count cannot disagree — the whole point of these cases is
    # that they sit exactly on a limit.
    python3 - <<'PYEOF'
def ad(t, body):
    return bytes([len(body) + 1, t]) + body

cases = []
def add(name, desc, b):
    cases.append((name, desc, b))

add("empty", "zero-length payload", b"")
add("zero_len_ad", "AD length 0 with no type byte", b"\x00")
add("ad_padding", "three zero-length AD entries (legal padding)", b"\x00\x00\x00")
add("ad_len_no_body", "declares 5 bytes, supplies none", bytes([0x05, 0xFF]))
add("ad_len_ff", "declares 255 bytes, supplies 1", bytes([0xFF, 0xFF, 0x00]))
add("ad_len_overrun", "declares 32, supplies 3", bytes([0x20, 0x09, 0x65, 0x66, 0x67]))
add("all_ff", "8 bytes of 0xff", b"\xff" * 8)

# A genuine iBeacon: length 0x1a, 26 bytes follow, 27 total.
ib = ad(0xFF, bytes([0x4C, 0x00, 0x02, 0x15]) + bytes(range(16)) +
        bytes([0x00, 0x01, 0x00, 0x02, 0xC5]))
add("ibeacon_valid", "real iBeacon, %d bytes total" % len(ib), ib)

# Exactly at the legacy 31-byte advertising limit.
# 31 total = 1 length byte + 1 type byte + 29 body bytes.
fill = bytes([0x4C, 0x00]) + bytes(range(27))          # 29-byte body
at31 = ad(0xFF, fill)
assert len(at31) == 31, len(at31)
add("at_31_limit", "exactly 31 bytes, the legacy ADV limit", at31)

# One byte past it.
over = ad(0xFF, fill + b"\x00")
add("over_31_limit", "%d bytes, past the legacy ADV limit" % len(over), over)

print("NAME\tDESC\tHEX\tLEN")
for name, desc, b in cases:
    print("%s\t%s\t%s\t%d" % (name, desc, b.hex(), len(b)))
PYEOF
}

fz_emit() {
    local seed_hex="$1" strategy="${2:-all}" out="${3:-}"
    [[ -z "$seed_hex" ]] && {
        printf 'ERROR\tusage: --emit SEED_HEX [STRATEGY] [OUTFILE]\n' >&2; return 2; }
    [[ -z "$out" ]] && out="$FZ_OUT/corpus_$(date +%s).hex"
    mkdir -p "$(dirname "$out")"
    fz_mutate "$seed_hex" "$strategy" 512 1 \
        | awk -F'\t' '$1=="CASE"{print $4}' > "$out" || return 1
    local n; n=$(grep -c . "$out" 2>/dev/null) || n=0
    (( n == 0 )) && { printf 'ERROR\tno cases generated\n' >&2; rm -f "$out"; return 1; }
    printf 'OUT\t%s\nCASES\t%s\nSTRATEGY\t%s\n' "$out" "$n" "$strategy"
}

# ── replay (radio-gated) ─────────────────────────────────────────────────
fz_replay() {
    local corpus="$1"
    [[ -z "$corpus" || ! -f "$corpus" ]] && {
        printf 'ERROR\tusage: --replay CORPUS.hex\n' >&2; return 2; }
    local h; h=$(fz_have_hci 2>/dev/null) || {
        printf 'ERROR\tno Bluetooth adapter — cannot replay a corpus\n' >&2
        printf 'NOTE\tgeneration is offline: use --mutate/--emit/--boundary.\n' >&2
        return 1; }
    local n; n=$(grep -c . "$corpus" 2>/dev/null) || n=0
    printf 'HCI\t%s\nCORPUS\t%s\nCASES\t%s\n' "$h" "$corpus" "$n"
    printf 'NOTE\treplaying %s cases needs a controller and a target; this\n' "$n"
    printf 'NOTE\tmodule generates the corpus but does not blast the air.\n'
}

# ── self-test ────────────────────────────────────────────────────────────
fz_selftest() {
    local bad=0
    local seed="1aff4c000215e2c56db5dffb48d2b060d0f5a71096e000010002c5"

    # Determinism: identical inputs must give byte-identical corpora.
    local a b
    a=$(fz_mutate "$seed" all 512 1 | md5sum | cut -d' ' -f1)
    b=$(fz_mutate "$seed" all 512 1 | md5sum | cut -d' ' -f1)
    if [[ "$a" == "$b" && -n "$a" ]]; then printf 'deterministic\tPASS\n'
    else printf 'deterministic\tFAIL %s vs %s\n' "$a" "$b"; bad=$((bad+1)); fi

    # A different rng seed must change the random strategy.
    local r1 r2
    r1=$(fz_mutate "$seed" random 512 1 | md5sum | cut -d' ' -f1)
    r2=$(fz_mutate "$seed" random 512 7 | md5sum | cut -d' ' -f1)
    if [[ "$r1" != "$r2" ]]; then printf 'rng-seed-matters\tPASS\n'
    else printf 'rng-seed-matters\tFAIL\n'; bad=$((bad+1)); fi

    # bitflip over a 27-byte seed yields exactly len*8 cases.
    local n
    n=$(fz_mutate "$seed" bitflip 100000 1 | awk -F'\t' '$1=="CASES"{print $2}')
    if [[ "$n" == "216" ]]; then printf 'bitflip-count\tPASS (%s)\n' "$n"
    else printf 'bitflip-count\tFAIL want=216 got=%s\n' "$n"; bad=$((bad+1)); fi

    # truncate yields one case per cut position (0..len-1).
    n=$(fz_mutate "$seed" truncate 100000 1 | awk -F'\t' '$1=="CASES"{print $2}')
    if [[ "$n" == "27" ]]; then printf 'truncate-count\tPASS (%s)\n' "$n"
    else printf 'truncate-count\tFAIL want=27 got=%s\n' "$n"; bad=$((bad+1)); fi

    # The limit must actually cap output.
    n=$(fz_mutate "$seed" all 10 1 | awk -F'\t' '$1=="CASES"{print $2}')
    if [[ "$n" == "10" ]]; then printf 'limit-honoured\tPASS\n'
    else printf 'limit-honoured\tFAIL got=%s\n' "$n"; bad=$((bad+1)); fi

    # Every emitted case must be valid hex of a sane length.
    local okall=1
    while read -r hx; do
        [[ "$hx" =~ ^[0-9a-f]*$ ]] || { okall=0; break; }
        (( ${#hx} % 2 == 0 )) || { okall=0; break; }
    done < <(fz_mutate "$seed" all 200 1 | awk -F'\t' '$1=="CASE"{print $4}')
    if (( okall )); then printf 'cases-are-hex\tPASS\n'
    else printf 'cases-are-hex\tFAIL\n'; bad=$((bad+1)); fi

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

fz_info() {
    cat <<'EOF'
BLE payload fuzzing

The corpus is generated offline and is fully deterministic: the same
seed payload, strategy and RNG seed always produce byte-identical cases,
so anything a target does with a case can be reproduced exactly.

Strategies
  bitflip    one bit at a time, covering every position
  byteflip   each byte XOR 0xff
  truncate   every prefix length, including zero
  extend     padding past the declared end, up to 255 bytes
  adlen      each AD length byte set to 0, 1, 0xff, and off-by-one
  adtype     each AD type byte replaced with edge values
  repeat     the payload duplicated to overflow the 31-byte limit
  random     seeded random mutation, reproducible from RNG_SEED

--boundary emits hand-picked payloads sitting exactly on the protocol
limits (zero-length AD, 31 bytes, 32 bytes, length overruns).

Replay onto a target needs a Bluetooth controller, which this machine
does not have; generation, emission and boundary cases all work offline.
EOF
}

# ── dispatch ─────────────────────────────────────────────────────────────
fz_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     fz_status_tsv ;;
        --strategies-tsv) fz_strategies_tsv ;;
        --mutate)         fz_mutate "$@" ;;
        --boundary)       fz_boundary ;;
        --emit)           fz_emit "$@" ;;
        --replay)         fz_replay "$@" ;;
        --selftest)       fz_selftest ;;
        --info)           fz_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --strategies-tsv
  --mutate SEED_HEX [STRATEGY] [LIMIT] [RNG_SEED]
  --boundary                 protocol-limit payloads
  --emit SEED_HEX [STRATEGY] [OUTFILE]
  --replay CORPUS.hex        needs a Bluetooth adapter
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
    fz_cli_main "$@"
fi

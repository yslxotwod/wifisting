#!/usr/bin/env bash
# 27_firmware_iot.sh — firmware analysis: binwalk + unblob, entropy,
# architecture detection, filesystem-specific extraction, CVE correlation.
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

FW_DIR="$TMP_DIR/firmware"
FW_LOOT="$LOOT_DIR/firmware"
FW_SAMPLES="$FW_LOOT/samples"
FW_EXTRACTED="$FW_LOOT/extracted"
FW_RESULTS="$FW_LOOT/results"
mkdir -p "$FW_DIR" "$FW_LOOT" "$FW_SAMPLES" "$FW_EXTRACTED" "$FW_RESULTS"

# ═══════════════════════════════════════════════════════════════════
#  tool detection
# ═══════════════════════════════════════════════════════════════════

fw_check_tools() {
    local missing=()
    for t in binwalk strings file; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if (( ${#missing[@]} )); then
        printf 'MISSING\t%s\n' "$(IFS=,; echo "${missing[*]}")"
        return 1
    fi
    printf 'READY\n'
}

fw_status_tsv() {
    local bw=no ss=no cve=no fw=no unblob=no ent=no r2=no
    command -v binwalk    >/dev/null 2>&1 && bw=yes
    command -v strings    >/dev/null 2>&1 && ss=yes
    command -v cve-bin-tool >/dev/null 2>&1 && cve=yes
    command -v firmwalker >/dev/null 2>&1 && fw=yes
    command -v unblob     >/dev/null 2>&1 && unblob=yes
    command -v ent        >/dev/null 2>&1 && ent=yes
    command -v r2         >/dev/null 2>&1 && r2=yes

    local samples=0 analyses=0
    samples=$(find "$FW_SAMPLES" -maxdepth 1 -type f 2>/dev/null | wc -l)
    analyses=$(find "$FW_RESULTS" -maxdepth 1 -type d 2>/dev/null | wc -l)
    (( analyses > 0 )) && analyses=$((analyses - 1))

    printf 'binwalk\t%s\n'   "$bw"
    printf 'strings\t%s\n'   "$ss"
    printf 'cve_bin_tool\t%s\n' "$cve"
    printf 'firmwalker\t%s\n' "$fw"
    printf 'unblob\t%s\n'    "$unblob"
    printf 'ent\t%s\n'       "$ent"
    printf 'radare2\t%s\n'   "$r2"
    printf 'samples\t%s\n'   "$samples"
    printf 'analyses\t%s\n'  "$analyses"
    printf 'loot\t%s\n'      "$FW_LOOT"
}

fw_list_samples_tsv() {
    local f
    for f in "$FW_SAMPLES"/*; do
        [[ -f "$f" ]] || continue
        local sz
        sz=$(stat -c%s "$f")
        printf '%s\t%s\t%s\n' "$(basename "$f")" "$sz" "$f"
    done
}

fw_list_analyses_tsv() {
    local d
    for d in "$FW_RESULTS"/*/; do
        [[ -d "$d" ]] || continue
        local name
        name=$(basename "$d")
        local meta="$d/meta.txt"
        local summary=""
        [[ -f "$meta" ]] && summary=$(grep -m1 '^SUMMARY=' "$meta" 2>/dev/null | sed 's/^SUMMARY=//')
        printf '%s\t%s\n' "$name" "${summary:--}"
    done
}

fw_import_sample() {
    local src="$1"
    [[ -z "$src" || ! -f "$src" ]] && { printf 'ERROR\tno file\n' >&2; return 1; }
    local name
    name=$(basename "$src")
    local dst="$FW_SAMPLES/$name"
    if [[ "$src" != "$dst" ]]; then
        cp "$src" "$dst" || { printf 'ERROR\tcopy failed\n' >&2; return 1; }
    fi
    printf 'IMPORTED\t%s\n' "$dst"
}

# ═══════════════════════════════════════════════════════════════════
#  entropy analysis
# ═══════════════════════════════════════════════════════════════════

# Entropy heuristic: samples the file in 4 KiB windows, computes Shannon
# entropy per window, and returns a coarse verdict. Uses Python so we
# don't depend on `ent`.
fw_entropy_report() {
    local f="$1"
    [[ ! -f "$f" ]] && return 1

    python3 - "$f" <<'PY'
import sys, math, os
path = sys.argv[1]
size = os.path.getsize(path)
win = 4096
high = 0
low = 0
total = 0
sum_h = 0.0
with open(path, "rb") as fh:
    while True:
        chunk = fh.read(win)
        if not chunk: break
        hist = [0] * 256
        for b in chunk: hist[b] += 1
        n = len(chunk)
        h = 0.0
        for c in hist:
            if c:
                p = c / n
                h -= p * math.log2(p)
        sum_h += h
        total += 1
        if h > 7.5: high += 1
        if h < 3.0: low += 1
avg = sum_h / total if total else 0.0
verdict = "packed/encrypted" if high * 4 > total else \
          "mostly plaintext" if low * 4 > total else "mixed"
print(f"size\t{size}")
print(f"windows\t{total}")
print(f"avg_entropy\t{avg:.3f}")
print(f"high_windows\t{high}")
print(f"low_windows\t{low}")
print(f"verdict\t{verdict}")
PY
}

# ═══════════════════════════════════════════════════════════════════
#  architecture detection
# ═══════════════════════════════════════════════════════════════════

# Looks for ELF magic in the file and reads e_machine. Also does a strings
# pass for common arch identifiers ("MIPS", "ARM", "AArch64", etc.).
fw_arch_detect() {
    local f="$1"
    [[ ! -f "$f" ]] && return 1

    python3 - "$f" <<'PY'
import sys, os, struct

path = sys.argv[1]

ELF_MACHINE = {
    0x03: "x86", 0x3E: "x86_64",
    0x28: "ARM", 0xB7: "AArch64",
    0x08: "MIPS", 0x0A: "MIPS", 0x02: "SPARC",
    0x14: "PPC", 0x15: "PPC64",
    0xF3: "RISC-V", 0x16: "S390", 0x32: "IA-64",
}

found = set()
with open(path, "rb") as fh:
    data = fh.read(min(os.path.getsize(path), 32 * 1024 * 1024))

off = 0
while True:
    off = data.find(b"\x7fELF", off)
    if off < 0 or off + 20 > len(data): break
    ei_class = data[off + 4]
    ei_data  = data[off + 5]
    endian = "<" if ei_data == 1 else ">"
    try:
        e_machine = struct.unpack_from(endian + "H", data, off + 18)[0]
    except struct.error:
        off += 4; continue
    bits = "64" if ei_class == 2 else "32"
    name = ELF_MACHINE.get(e_machine, f"unknown(0x{e_machine:x})")
    found.add(f"{name}/{bits}")
    off += 4

if not found:
    print("arch\tunknown")
else:
    for a in sorted(found):
        print(f"arch\t{a}")
PY
}

# ═══════════════════════════════════════════════════════════════════
#  basic identity
# ═══════════════════════════════════════════════════════════════════

fw_basic_id() {
    local f="$1"
    [[ -z "$f" || ! -f "$f" ]] && { printf 'ERROR\tno file\n' >&2; return 1; }

    printf 'FILE\t%s\n' "$f"
    printf 'SIZE\t%s\n' "$(stat -c%s "$f")"
    printf 'TYPE\t%s\n' "$(file -b "$f" 2>/dev/null)"
    printf 'MD5\t%s\n'  "$(md5sum "$f" 2>/dev/null | awk '{print $1}')"
    printf 'SHA256\t%s\n' "$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"

    # Entropy
    fw_entropy_report "$f" | sed 's/^/entropy_/'

    # Architecture
    fw_arch_detect "$f"

    if command -v binwalk >/dev/null 2>&1; then
        local sigs
        sigs=$(binwalk "$f" 2>/dev/null | tail -n +4 | head -20)
        printf 'SIGNATURES_START\n%s\nSIGNATURES_END\n' "$sigs"
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  extraction — binwalk and/or unblob
# ═══════════════════════════════════════════════════════════════════

fw_extract() {
    local f="$1"
    local engine="${2:-auto}"
    [[ -z "$f" || ! -f "$f" ]] && { printf 'ERROR\tno file\n' >&2; return 1; }

    local name
    name=$(basename "$f")
    local outdir="$FW_EXTRACTED/${name%.*}_$(date +%s)"
    mkdir -p "$outdir"

    # unblob is dramatically better for squashfs, ubifs, jffs2, cramfs
    local used=""
    if [[ "$engine" == "unblob" || "$engine" == "auto" ]] && \
       command -v unblob >/dev/null 2>&1; then
        info "extracting with unblob (handles squashfs/ubifs/jffs2/cramfs)"
        ( cd "$outdir" && unblob --output . "$f" 2>&1 | tail -30 )
        used="unblob"
    fi

    if [[ -z "$used" || "$engine" == "binwalk" ]]; then
        if [[ "$engine" == "binwalk" ]] || ! command -v unblob >/dev/null 2>&1; then
            command -v binwalk >/dev/null 2>&1 || {
                printf 'ERROR\tno binwalk and no unblob\n' >&2; return 1; }
            info "extracting with binwalk"
            ( cd "$outdir" && binwalk --preserve-symlinks -e "$f" 2>&1 | tail -40 )
            used="binwalk"
        fi
    fi

    # Post-pass: try filesystem-specific extractors if binwalk left
    # recognizable image files that it couldn't fully process.
    local extra=0
    for img in "$outdir"/*.squashfs "$outdir"/*.sqsh "$outdir"/*.jffs2 "$outdir"/*.ubifs; do
        [[ -e "$img" ]] || continue
        case "$img" in
            *.squashfs|*.sqsh)
                command -v unsquashfs >/dev/null 2>&1 && {
                    unsquashfs -d "${img%.*}_root" "$img" 2>/dev/null
                    extra=$((extra+1))
                } ;;
            *.jffs2)
                command -v jefferson >/dev/null 2>&1 && {
                    jefferson -d "${img%.*}_root" "$img" 2>/dev/null
                    extra=$((extra+1))
                } ;;
            *.ubifs)
                command -v ubireader_extract_images >/dev/null 2>&1 && {
                    ubireader_extract_images -o "${img%.*}_root" "$img" 2>/dev/null
                    extra=$((extra+1))
                } ;;
        esac
    done

    local count
    count=$(find "$outdir" -maxdepth 2 -type d 2>/dev/null | wc -l)
    printf 'EXTRACTED\t%s\nENGINE\t%s\nDIRS\t%s\nEXTRA_ROOTS\t%s\n' \
        "$outdir" "$used" "$count" "$extra"
}

# ═══════════════════════════════════════════════════════════════════
#  strings and patterns
# ═══════════════════════════════════════════════════════════════════

fw_strings_search() {
    local f="$1"
    local pattern="${2:-}"
    [[ -z "$f" || ! -f "$f" ]] && { printf 'ERROR\tno file\n' >&2; return 1; }

    [[ -z "$pattern" ]] && \
        pattern='password|passwd|secret|api[_-]?key|token|admin|root:|private[_-]?key'

    command -v strings >/dev/null 2>&1 || { printf 'ERROR\tstrings missing\n' >&2; return 1; }

    info "searching strings in $f for: $pattern"
    strings -a -n 6 "$f" | grep -iE "$pattern" | sort -u | head -100
}

fw_pattern_search_files() {
    local dir="$1"
    local pattern="${2:-}"
    [[ -z "$dir" || ! -d "$dir" ]] && { printf 'ERROR\tno dir\n' >&2; return 1; }
    [[ -z "$pattern" ]] && \
        pattern='password|passwd|secret|api[_-]?key|token|admin|private[_-]?key'

    info "grepping extracted tree for: $pattern"
    grep -rIiE "$pattern" "$dir" 2>/dev/null | head -200
}

# ═══════════════════════════════════════════════════════════════════
#  CVE correlation
# ═══════════════════════════════════════════════════════════════════

fw_cve_scan() {
    local dir="$1"
    [[ -z "$dir" || ! -d "$dir" ]] && { printf 'ERROR\tno dir\n' >&2; return 1; }
    command -v cve-bin-tool >/dev/null 2>&1 || {
        printf 'ERROR\tcve-bin-tool missing (pip install cve-bin-tool)\n' >&2
        return 1
    }

    local outcsv="$dir/cve_report_$(date +%s).csv"
    info "running cve-bin-tool (may take a while)"
    cve-bin-tool -q -f csv -o "$outcsv" "$dir" 2>&1 | tail -10

    if [[ -s "$outcsv" ]]; then
        local n
        n=$(tail -n +2 "$outcsv" | wc -l)
        printf 'REPORT\t%s\nFINDINGS\t%s\n' "$outcsv" "$n"
    else
        printf 'ERROR\tcve-bin-tool produced no report\n' >&2
        return 1
    fi
}

# Software-version → CVE heuristic against a small built-in table.
# Complements cve-bin-tool for the cases where the extracted binaries
# don't have version strings that cve-bin-tool can match.
fw_cve_heuristic() {
    local dir="$1"
    [[ -z "$dir" || ! -d "$dir" ]] && { printf 'ERROR\tno dir\n' >&2; return 1; }

    local strings_file="$TMP_DIR/fw_strings_$$"
    find "$dir" -type f -size -10M 2>/dev/null | head -200 | \
        xargs -r strings -a -n 6 2>/dev/null | head -50000 > "$strings_file"

    info "correlating versions against known CVE table"

    # Simple table: version string -> CVE hint
    local -a table=(
        "busybox-1.2[0-9]|CVE-2021-42374..42386 (busybox applet CVEs)"
        "busybox-1.3[0-2]|CVE-2022-28391 etc (busybox)"
        "openssl-1.0.2|CVE-2019-1551 etc (openssl 1.0.2)"
        "openssl-1.1.0|CVE-2020-1971 etc (openssl 1.1.0)"
        "openssl-1.1.1|CVE-2022-0778 (openssl 1.1.1 pre-1.1.1n)"
        "dropbear_20[0-1][0-9]|CVE-2016-7406 etc (dropbear)"
        "lighttpd/1.4.[0-4][0-9]|CVE-2022-22707 (lighttpd)"
        "dnsmasq-2.[0-7][0-9]|CVE-2020-25681..25687 (dnsmasq)"
        "hostapd-2.[0-6]|CVE-2019-9495 etc (hostapd)"
        "wpa_supplicant-2.[0-6]|CVE-2019-9494 etc (wpa_supplicant)"
        "openssh_7.[0-9]|CVE-2018-15473 etc (openssh)"
        "uhttpd|CVE-2019-19945 (uhttpd)"
        "miniupnpd|CVE-2021-3768 etc (miniupnpd)"
    )

    local hits=0
    for entry in "${table[@]}"; do
        local pat="${entry%%|*}"
        local cve="${entry##*|}"
        if grep -qiE "$pat" "$strings_file" 2>/dev/null; then
            printf 'MATCH\t%s\t%s\n' "$pat" "$cve"
            hits=$((hits+1))
        fi
    done
    rm -f "$strings_file"

    if (( hits == 0 )); then
        printf 'NOHITS\n'
    fi
}

fw_firmwalker() {
    local dir="$1"
    [[ -z "$dir" || ! -d "$dir" ]] && { printf 'ERROR\tno dir\n' >&2; return 1; }
    command -v firmwalker >/dev/null 2>&1 || {
        printf 'ERROR\tfirmwalker missing\n' >&2
        printf 'HINT\tgit clone https://github.com/craigz28/firmwalker\n' >&2
        return 1
    }
    local out="$dir/firmwalker_report.txt"
    firmwalker "$dir" "$out" 2>&1 | tail -10
    if [[ -s "$out" ]]; then
        local findings
        findings=$(wc -l < "$out")
        printf 'REPORT\t%s\nLINES\t%s\n' "$out" "$findings"
    else
        printf 'ERROR\tfirmwalker produced no output\n' >&2
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  radare2 handoff
# ═══════════════════════════════════════════════════════════════════

# Locate interesting binaries in an extracted tree and print their
# paths so the user can open them in r2/ghidra.
fw_list_binaries() {
    local dir="$1"
    [[ -z "$dir" || ! -d "$dir" ]] && { printf 'ERROR\tno dir\n' >&2; return 1; }

    find "$dir" -type f \( -perm -111 -o -name '*.so' -o -name '*.ko' \) \
        -size +1k -size -50M 2>/dev/null | while read -r bin; do
        # Verify it's an ELF
        if head -c 4 "$bin" | grep -q $'\x7fELF'; then
            local arch
            arch=$(file -b "$bin" 2>/dev/null | grep -oE 'ELF [0-9]+-bit [A-Za-z0-9_]+' | head -1)
            printf '%s\t%s\n' "$bin" "${arch:-unknown}"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════
#  full analysis pipeline
# ═══════════════════════════════════════════════════════════════════

fw_full_analysis() {
    local f="$1"
    [[ -z "$f" || ! -f "$f" ]] && { printf 'ERROR\tno file\n' >&2; return 1; }
    local name
    name=$(basename "$f")
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    local outdir="$FW_RESULTS/${name%.*}_$ts"
    mkdir -p "$outdir"

    # identity + entropy + arch
    {
        file -b "$f"
        md5sum "$f"
        sha256sum "$f"
    } > "$outdir/identity.txt" 2>&1

    fw_entropy_report "$f" > "$outdir/entropy.txt" 2>&1
    fw_arch_detect "$f"     > "$outdir/arch.txt" 2>&1

    # signatures
    if command -v binwalk >/dev/null 2>&1; then
        binwalk "$f" > "$outdir/binwalk.txt" 2>&1 || true
    fi

    # strings
    if command -v strings >/dev/null 2>&1; then
        strings -a -n 6 "$f" | sort -u > "$outdir/strings.txt"
        grep -iE 'password|passwd|secret|api[_-]?key|token|admin|private[_-]?key' \
            "$outdir/strings.txt" | head -200 > "$outdir/creds_like.txt" || true
    fi

    # extraction (prefer unblob)
    if command -v unblob >/dev/null 2>&1; then
        ( cd "$outdir" && unblob --output . "$f" >/dev/null 2>&1 ) || true
    elif command -v binwalk >/dev/null 2>&1; then
        ( cd "$outdir" && binwalk --preserve-symlinks -e "$f" >/dev/null 2>&1 ) || true
    fi

    # metadata
    local sigs_count=0 strings_count=0 creds_count=0 extracted_count=0
    [[ -f "$outdir/binwalk.txt" ]] && sigs_count=$(tail -n +4 "$outdir/binwalk.txt" | grep -c .)
    [[ -f "$outdir/strings.txt" ]] && strings_count=$(wc -l < "$outdir/strings.txt")
    [[ -f "$outdir/creds_like.txt" ]] && creds_count=$(wc -l < "$outdir/creds_like.txt")
    extracted_count=$(find "$outdir" -maxdepth 1 -type d ! -path "$outdir" | wc -l)

    local entropy verdict arch
    entropy=$(grep '^avg_entropy' "$outdir/entropy.txt" 2>/dev/null | awk '{print $2}')
    verdict=$(grep '^verdict' "$outdir/entropy.txt" 2>/dev/null | awk '{print $2}')
    arch=$(grep -m1 '^arch' "$outdir/arch.txt" 2>/dev/null | awk '{print $2}')

    cat > "$outdir/meta.txt" << EOF
SAMPLE=$name
SIZE=$(stat -c%s "$f")
SHA256=$(sha256sum "$f" | awk '{print $1}')
TIMESTAMP=$ts
SIGNATURES=$sigs_count
STRINGS=$strings_count
CREDS_LIKE=$creds_count
EXTRACTED_DIRS=$extracted_count
ENTROPY=${entropy:-?}
ENTROPY_VERDICT=${verdict:-?}
ARCH=${arch:-?}
SUMMARY=${sigs_count} sigs, ${strings_count} strings, ${creds_count} creds-like, ${extracted_count} dirs, entropy=${entropy:-?} (${verdict:-?}), arch=${arch:-?}
EOF

    printf 'ANALYSIS\t%s\nSIGNATURES\t%s\nSTRINGS\t%s\nCREDS_LIKE\t%s\nEXTRACTED\t%s\nENTROPY\t%s\nENTROPY_VERDICT\t%s\nARCH\t%s\n' \
        "$outdir" "$sigs_count" "$strings_count" "$creds_count" \
        "$extracted_count" "${entropy:-?}" "${verdict:-?}" "${arch:-?}"
}

# ═══════════════════════════════════════════════════════════════════
#  info
# ═══════════════════════════════════════════════════════════════════

fw_info() {
    cat <<'INFO'
Firmware / IoT analysis workflow:

  1. Import a firmware image (--import)
  2. Identify it: hashes, entropy, arch, binwalk signatures
       high entropy → packed or encrypted (may need a deobfuscation step)
       low entropy  → plaintext configuration / HTML
  3. Extract: unblob first (handles squashfs/ubifs/jffs2/cramfs better
     than binwalk in 2026), binwalk as fallback
  4. Strings search + pattern grep for credentials
  5. cve-bin-tool + heuristic version → CVE correlation
  6. firmwalker if installed
  7. List ELF binaries and hand off to r2/ghidra (--list-binaries)

Tool priority:
  unblob         preferred extractor
  binwalk        fallback + signature listing
  strings        literal string harvest
  cve-bin-tool   library version → CVE database
  firmwalker     automated common-issue sweep
  ent (optional) alternate entropy
  radare2        binary analysis (--list-binaries emits paths)

Filesystem-specific extractors (auto-invoked after binwalk):
  unsquashfs     squashfs
  jefferson      jffs2
  ubireader      ubifs

Where to get firmware (for devices you own):
  Vendor support sites
  FCC ID database (internal photos + firmware blobs)
  OpenWrt table of hardware
INFO
}

# ═══════════════════════════════════════════════════════════════════
#  dispatch
# ═══════════════════════════════════════════════════════════════════

# ── self-test ────────────────────────────────────────────────────────────
# Offline, no hardware: entropy maths, ELF architecture detection, hashing,
# sample inventory and the CVE heuristic table are all pure file logic on
# synthetic inputs built here. Every output dir is redirected into scratch
# space so the real loot/firmware tree is never written.
#
# binwalk / unblob / cve-bin-tool / firmwalker are absent here, so their
# error paths are asserted; the branches are written to follow whatever is
# actually installed rather than hardcoding this box.
fw_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcount() { printf '%s\n' "$1" | grep -c . ; }

    # synthetic ELF header: e_ident + e_type + e_machine (honours endianness)
    mkelf() {
        local f="$1" class="$2" edata="$3" machine="$4"
        local lo=$(( machine & 0xff )) hi=$(( (machine >> 8) & 0xff ))
        printf '\x7fELF' > "$f"
        printf "\\x$(printf '%02x' "$class")\\x$(printf '%02x' "$edata")" >> "$f"
        printf '\x01' >> "$f"
        printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00' >> "$f"
        printf '\x02\x00' >> "$f"
        if (( edata == 2 )); then
            printf "\\x$(printf '%02x' "$hi")\\x$(printf '%02x' "$lo")" >> "$f"
        else
            printf "\\x$(printf '%02x' "$lo")\\x$(printf '%02x' "$hi")" >> "$f"
        fi
    }
    mkhirandom() { python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*16)'; }

    local MOD_TMP="${TMP_DIR:-/tmp/wifisting}/firmware/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/samples" "$MOD_TMP/extracted" "$MOD_TMP/results"
    local s_samples="$FW_SAMPLES" s_extracted="$FW_EXTRACTED" s_results="$FW_RESULTS"
    FW_SAMPLES="$MOD_TMP/samples"; FW_EXTRACTED="$MOD_TMP/extracted"; FW_RESULTS="$MOD_TMP/results"

    local out rc

    # 1. entropy maths on crafted inputs
    head -c 4096 /dev/zero > "$MOD_TMP/zeros.bin"
    mkhirandom > "$MOD_TMP/full.bin"
    cat "$MOD_TMP/zeros.bin" "$MOD_TMP/full.bin" > "$MOD_TMP/mixed.bin"
    : > "$MOD_TMP/empty.bin"
    out=$(fw_entropy_report "$MOD_TMP/zeros.bin")
    chk entropy-rows-zero   "$(rcount "$out")" 6
    chk entropy-zero-size   "$(fld "$out" size)" 4096
    chk entropy-zero-windows "$(fld "$out" windows)" 1
    chk entropy-zero-avg    "$(fld "$out" avg_entropy)" 0.000
    chk entropy-zero-high   "$(fld "$out" high_windows)" 0
    chk entropy-zero-low    "$(fld "$out" low_windows)" 1
    chk entropy-zero-verdict "$(fld "$out" verdict)" "mostly plaintext"
    out=$(fw_entropy_report "$MOD_TMP/full.bin")
    chk entropy-full-avg     "$(fld "$out" avg_entropy)" 8.000
    chk entropy-full-high    "$(fld "$out" high_windows)" 1
    chk entropy-full-low     "$(fld "$out" low_windows)" 0
    chk entropy-full-verdict "$(fld "$out" verdict)" "packed/encrypted"
    out=$(fw_entropy_report "$MOD_TMP/mixed.bin")
    chk entropy-mixed-windows "$(fld "$out" windows)" 2
    chk entropy-mixed-avg     "$(fld "$out" avg_entropy)" 4.000
    chk entropy-mixed-high    "$(fld "$out" high_windows)" 1
    chk entropy-mixed-low     "$(fld "$out" low_windows)" 1
    chk entropy-mixed-verdict "$(fld "$out" verdict)" "packed/encrypted"
    out=$(fw_entropy_report "$MOD_TMP/empty.bin")
    chk entropy-empty-windows "$(fld "$out" windows)" 0
    chk entropy-empty-avg     "$(fld "$out" avg_entropy)" 0.000
    chk entropy-empty-verdict "$(fld "$out" verdict)" mixed
    fw_entropy_report "$MOD_TMP/absent.bin" >/dev/null 2>&1
    chk entropy-missing-rc "$?" 1

    # 2. ELF architecture detection by e_machine + endianness
    mkelf "$MOD_TMP/arm32.elf" 1 1 0x28
    mkelf "$MOD_TMP/x86_64.elf" 2 1 0x3E
    mkelf "$MOD_TMP/mips_be.elf" 1 2 0x08
    mkelf "$MOD_TMP/weird.elf" 1 1 0x99
    chk arch-arm    "$(fw_arch_detect "$MOD_TMP/arm32.elf" | cut -f2)" ARM/32
    chk arch-x86_64 "$(fw_arch_detect "$MOD_TMP/x86_64.elf" | cut -f2)" x86_64/64
    chk arch-mips-be "$(fw_arch_detect "$MOD_TMP/mips_be.elf" | cut -f2)" MIPS/32
    chk arch-unknown-machine "$(fw_arch_detect "$MOD_TMP/weird.elf" | cut -f2)" "unknown(0x99)/32"
    cat "$MOD_TMP/arm32.elf" "$MOD_TMP/x86_64.elf" > "$MOD_TMP/multi.elf"
    out=$(fw_arch_detect "$MOD_TMP/multi.elf")
    chk arch-multi-rows "$(rcount "$out")" 2
    chk arch-multi-order "$(printf '%s\n' "$out" | cut -f2 | tr '\n' ' ')" "ARM/32 x86_64/64 "
    chk arch-no-elf  "$(fw_arch_detect "$MOD_TMP/zeros.bin" | cut -f2)" unknown
    head -c 10 "$MOD_TMP/arm32.elf" > "$MOD_TMP/trunc.elf"
    chk arch-truncated "$(fw_arch_detect "$MOD_TMP/trunc.elf" | cut -f2)" unknown
    fw_arch_detect "$MOD_TMP/absent" >/dev/null 2>&1; chk arch-missing-rc "$?" 1

    # 3. basic identity: hashes are of THIS file, entropy/arch are folded in
    printf 'wifisting\n' > "$MOD_TMP/sample.bin"
    out=$(fw_basic_id "$MOD_TMP/sample.bin")
    chk id-missing-sample  "$(fld "$out" FILE)" "$MOD_TMP/sample.bin"
    chk id-size            "$(fld "$out" SIZE)" 10
    chk id-type            "$(fld "$out" TYPE)" "$(file -b "$MOD_TMP/sample.bin")"
    chk id-md5             "$(fld "$out" MD5)" a6541db5c8ddf170e3043687700b021b
    chk id-sha256          "$(fld "$out" SHA256)" 3ac5cfd0152a036d33cbfcf3b891d4a545334f5591a8fd3f0380dd78b9044010
    chk id-entropy-folded  "$(fld "$out" entropy_size)" 10
    chk id-entropy-verdict "$(fld "$out" entropy_verdict)" "mostly plaintext"
    chk id-arch-line       "$(fld "$out" arch)" unknown
    if command -v binwalk >/dev/null 2>&1; then
        chk id-signature-block "$(printf '%s\n' "$out" | grep -c '^SIGNATURES_START$')" 1
    else
        chk id-no-signature-block "$(printf '%s\n' "$out" | grep -c '^SIGNATURES_START$')" 0
    fi
    fw_basic_id "$MOD_TMP/absent" >/dev/null 2>&1; chk id-missing-rc "$?" 1

    # 4. sample inventory and import
    rm -f "$FW_SAMPLES"/*
    out=$(fw_list_samples_tsv); chk samples-empty "$(rcount "$out")" 0
    out=$(fw_import_sample "$MOD_TMP/sample.bin"); rc=$?
    chk import-rc   "$rc" 0
    chk import-says "$(printf '%s\n' "$out" | cut -f2)" "$FW_SAMPLES/sample.bin"
    chk import-copied "$([[ -f "$FW_SAMPLES/sample.bin" ]] && echo 1 || echo 0)" 1
    fw_import_sample "$FW_SAMPLES/sample.bin" >/dev/null 2>&1
    chk import-in-place-rc "$?" 0
    chk import-nodup "$(rcount "$(fw_list_samples_tsv)")" 1
    fw_import_sample "$MOD_TMP/absent" >/dev/null 2>&1; chk import-missing-rc "$?" 1
    printf 'hidden\n' > "$FW_SAMPLES/.hidden"
    out=$(fw_list_samples_tsv)
    chk samples-rows     "$(rcount "$out")" 1
    chk samples-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=3{c++} END{print c+0}')" 0
    chk samples-size     "$(printf '%s\n' "$out" | awk -F'\t' '{print $2}')" 10
    chk samples-skip-dot "$(printf '%s\n' "$out" | grep -c 'hidden')" 0
    rm -f "$FW_SAMPLES/.hidden"

    # 5. analysis inventory reads SUMMARY out of meta.txt
    mkdir -p "$FW_RESULTS/run_one" "$FW_RESULTS/run_two"
    printf 'SAMPLE=x\nSUMMARY=3 sigs, 4 strings\n' > "$FW_RESULTS/run_one/meta.txt"
    printf 'SAMPLE=y\n' > "$FW_RESULTS/run_two/meta.txt"
    out=$(fw_list_analyses_tsv)
    chk analyses-rows "$(rcount "$out")" 2
    chk analyses-summary "$(printf '%s\n' "$out" | awk -F'\t' '$1=="run_one"{print $2}')" \
        "3 sigs, 4 strings"
    chk analyses-nosummary "$(printf '%s\n' "$out" | awk -F'\t' '$1=="run_two"{print $2}')" "-"

    # 6. status rollup matches the tool set and the redirected dirs
    out=$(fw_status_tsv)
    chk status-rows    "$(rcount "$out")" 10
    chk status-binwalk "$(fld "$out" binwalk)" "$(command -v binwalk >/dev/null 2>&1 && echo yes || echo no)"
    chk status-strings "$(fld "$out" strings)" "$(command -v strings >/dev/null 2>&1 && echo yes || echo no)"
    chk status-samples "$(fld "$out" samples)" 1
    chk status-analyses "$(fld "$out" analyses)" 2
    chk status-loot    "$(fld "$out" loot)" "$FW_LOOT"

    # 7. built-in version -> CVE table
    mkdir -p "$MOD_TMP/tree"
    # version tokens in the hyphenated form the built-in table matches on
    printf 'banner: busybox-1.31.1 (2021-04-01)\nlibrary: openssl-1.1.1k\n' > "$MOD_TMP/tree/banner.txt"
    out=$(fw_cve_heuristic "$MOD_TMP/tree")
    chk heuristic-hits     "$(printf '%s\n' "$out" | grep -c '^MATCH')" 2
    chk heuristic-busybox  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="MATCH" && $2 ~ /busybox/{print $3}')" \
        "CVE-2022-28391 etc (busybox)"
    chk heuristic-openssl  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="MATCH" && $2 ~ /openssl-1\.1\.1/{print $3}')" \
        "CVE-2022-0778 (openssl 1.1.1 pre-1.1.1n)"
    mkdir -p "$MOD_TMP/emptytree"
    chk heuristic-nohits "$(fw_cve_heuristic "$MOD_TMP/emptytree")" NOHITS
    fw_cve_heuristic "$MOD_TMP/absent" >/dev/null 2>&1; chk heuristic-missing-rc "$?" 1

    # 8. binary hunting only reports real ELF files
    head -c 2048 /dev/zero > "$MOD_TMP/tree/exe.elf"
    cat "$MOD_TMP/arm32.elf" "$MOD_TMP/zeros.bin" > "$MOD_TMP/tree/bin.elf.tmp"
    cp "$MOD_TMP/tree/bin.elf.tmp" "$MOD_TMP/tree/real_elf"
    chmod +x "$MOD_TMP/tree/real_elf"
    printf '#!/bin/sh\necho hi\n' > "$MOD_TMP/tree/script.sh"
    head -c 2048 /dev/urandom > "$MOD_TMP/tree/notelf.so"
    out=$(fw_list_binaries "$MOD_TMP/tree")
    chk binaries-rows    "$(rcount "$out")" 1
    chk binaries-fields  "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0
    chk binaries-path    "$(printf '%s\n' "$out" | cut -f1)" "$MOD_TMP/tree/real_elf"
    rm -f "$MOD_TMP/tree/bin.elf.tmp"
    fw_list_binaries "$MOD_TMP/absent" >/dev/null 2>&1; chk binaries-missing-rc "$?" 1

    # 9. strings / pattern search
    printf 'password=hunter2\nnothing to see\napi_key=abcdef\n' > "$MOD_TMP/tree/config.txt"
    out=$(fw_strings_search "$MOD_TMP/tree/config.txt" 'password' 2>/dev/null); rc=$?
    chk strings-explicit-rc  "$rc" 0
    chk strings-explicit-hit "$(printf '%s\n' "$out" | grep -c '^password=hunter2$')" 1
    chk strings-default-hit  "$(fw_strings_search "$MOD_TMP/tree/config.txt" 2>/dev/null | grep -c 'api_key=abcdef')" 1
    fw_strings_search "$MOD_TMP/absent" >/dev/null 2>&1; chk strings-missing-rc "$?" 1
    out=$(fw_pattern_search_files "$MOD_TMP/tree" 'api_key' 2>/dev/null); rc=$?
    chk patterns-rc  "$rc" 0
    chk patterns-hit "$(printf '%s\n' "$out" | grep -c 'api_key=abcdef')" 1
    fw_pattern_search_files "$MOD_TMP/absent" >/dev/null 2>&1; chk patterns-missing-rc "$?" 1

    # 10. tool-gated paths name what is missing instead of failing obscurely
    chk check-tools-verdict "$(fw_check_tools >/dev/null 2>&1; echo $?)$(fw_check_tools 2>/dev/null | cut -f1)" \
        "$( if command -v binwalk >/dev/null 2>&1 && command -v strings >/dev/null 2>&1 && command -v file >/dev/null 2>&1; then echo "0READY"; else echo "1MISSING"; fi )"
    if ! command -v binwalk >/dev/null 2>&1 && ! command -v unblob >/dev/null 2>&1; then
        out=$(fw_extract "$MOD_TMP/sample.bin" 2>&1); rc=$?
        chk extract-noengine-rc  "$rc" 1
        chk extract-noengine-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
            "no binwalk and no unblob"
    fi
    fw_extract "$MOD_TMP/absent" >/dev/null 2>&1; chk extract-missing-rc "$?" 1
    fw_cve_scan "$MOD_TMP/absent" >/dev/null 2>&1; chk cvescan-missing-rc "$?" 1
    if ! command -v cve-bin-tool >/dev/null 2>&1; then
        out=$(fw_cve_scan "$MOD_TMP/tree" 2>&1); rc=$?
        chk cvescan-notool-rc  "$rc" 1
        chk cvescan-notool-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
            "cve-bin-tool missing (pip install cve-bin-tool)"
    fi
    if ! command -v firmwalker >/dev/null 2>&1; then
        out=$(fw_firmwalker "$MOD_TMP/tree" 2>&1); rc=$?
        chk firmwalker-notool-rc "$rc" 1
        chk firmwalker-hint     "$(printf '%s\n' "$out" | grep -c '^HINT')" 1
    fi

    FW_SAMPLES="$s_samples"; FW_EXTRACTED="$s_extracted"; FW_RESULTS="$s_results"
    rm -rf "$MOD_TMP"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

fw_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         fw_status_tsv ;;
        --check-tools)        fw_check_tools ;;
        --list-samples-tsv)   fw_list_samples_tsv ;;
        --list-analyses-tsv)  fw_list_analyses_tsv ;;
        --import)             fw_import_sample "$@" ;;
        --identify)           fw_basic_id "$@" ;;
        --entropy)            fw_entropy_report "$@" ;;
        --arch)               fw_arch_detect "$@" ;;
        --extract)            fw_extract "$@" ;;
        --strings)            fw_strings_search "$@" ;;
        --patterns)           fw_pattern_search_files "$@" ;;
        --cve-scan)           fw_cve_scan "$@" ;;
        --cve-heuristic)      fw_cve_heuristic "$@" ;;
        --firmwalker)         fw_firmwalker "$@" ;;
        --list-binaries)      fw_list_binaries "$@" ;;
        --full)               fw_full_analysis "$@" ;;
        --selftest)           fw_selftest ;;
        --info)               fw_info ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --check-tools
  --list-samples-tsv
  --list-analyses-tsv
  --import PATH
  --identify PATH
  --entropy PATH
  --arch PATH
  --extract PATH [auto|binwalk|unblob]
  --strings PATH [PATTERN]
  --patterns DIR [PATTERN]
  --cve-scan DIR             cve-bin-tool
  --cve-heuristic DIR        built-in version→CVE table
  --firmwalker DIR
  --list-binaries DIR
  --full PATH
  --selftest
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
    fw_cli_main "$@"
fi

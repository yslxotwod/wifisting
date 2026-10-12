#!/usr/bin/env bash
# Wordlist manager — inventory, download, compose, SecLists
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
: "${WORDLISTS_DIR:=$HOME/wifisting/wordlists}"
: "${WIFISTING_HOME:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR" "$WORDLISTS_DIR" 2>/dev/null

WL_DIR="$WORDLISTS_DIR"
WL_TMP="$TMP_DIR/wordlist_dl"
WL_META="$WL_DIR/.meta"
mkdir -p "$WL_TMP" "$WL_META"

# ── inventory ──

wl_list_tsv() {
    local f size lines
    for f in "$WL_DIR"/*.txt "$WL_DIR"/*.lst "$WL_DIR"/*.gz \
             /usr/share/wordlists/*.txt /usr/share/wordlists/*.gz \
             /usr/share/seclists/Passwords/*.txt; do
        [[ -e "$f" ]] || continue
        size=$(stat -c%s "$f" 2>/dev/null)
        case "$f" in
            *.gz) lines=$(gzip -cdf "$f" 2>/dev/null | wc -l) ;;
            *)    lines=$(wc -l < "$f" 2>/dev/null) ;;
        esac
        printf '%s\t%s\t%s\n' "$f" "${size:-0}" "${lines:-0}"
    done
}

wl_rules_tsv() {
    local d
    for d in /usr/share/hashcat/rules /usr/share/john/rules; do
        [[ -d "$d" ]] || continue
        local f
        for f in "$d"/*.rule "$d"/*.rules; do
            [[ -e "$f" ]] || continue
            printf '%s\t%s\n' "$f" "$(stat -c%s "$f")"
        done
    done
}

wl_stats() {
    local count=0 total=0
    local f
    for f in "$WL_DIR"/*.txt "$WL_DIR"/*.lst; do
        [[ -e "$f" ]] || continue
        count=$((count + 1))
        total=$((total + $(stat -c%s "$f")))
    done
    printf 'count\t%s\n' "$count"
    printf 'total_bytes\t%s\n' "$total"
    printf 'dir\t%s\n' "$WL_DIR"
}

# ── metadata ──
# Store a small sidecar file per wordlist capturing source + timestamp.
wl_meta_save() {
    local path="$1" source="${2:-}"
    local key
    key=$(printf '%s' "$path" | md5sum | cut -c1-16)
    cat > "$WL_META/$key" <<EOF
path=$path
source=$source
fetched=$(date -Is)
EOF
}

wl_meta_get() {
    local path="$1"
    local key
    key=$(printf '%s' "$path" | md5sum | cut -c1-16)
    [[ -f "$WL_META/$key" ]] && cat "$WL_META/$key"
}

# ── download ──

wl_download() {
    local url="$1" name="$2"
    [[ -z "$url" ]] && { printf 'ERROR\tno url\n' >&2; return 1; }
    [[ -z "$name" ]] && name=$(basename "$url")
    local out="$WL_TMP/$name"

    command -v curl >/dev/null 2>&1 || { printf 'ERROR\tcurl missing\n' >&2; return 1; }

    info "downloading $url"
    if ! curl -L --fail -o "$out" "$url" 2>&1; then
        printf 'ERROR\tcurl failed\n' >&2; return 1
    fi

    case "$out" in
        *.gz)
            gzip -dc "$out" > "${out%.gz}" && out="${out%.gz}"
            ;;
    esac

    if [[ -s "$out" ]]; then
        local size lines
        size=$(stat -c%s "$out")
        lines=$(wc -l < "$out")
        printf 'DOWNLOADED\t%s\nSIZE\t%s\nLINES\t%s\n' "$out" "$size" "$lines"
    else
        printf 'ERROR\tempty file\n' >&2; return 1
    fi
}

wl_install_to_dir() {
    local src="$1" name="$2"
    [[ -z "$src" || ! -f "$src" ]] && { printf 'ERROR\tno file\n' >&2; return 1; }
    [[ -z "$name" ]] && name=$(basename "$src")
    mv "$src" "$WL_DIR/$name"
    wl_meta_save "$WL_DIR/$name" "download:$name"
    printf 'INSTALLED\t%s\n' "$WL_DIR/$name"
}

# ── compose (streaming sort -u) ──
# The old version used `awk '!seen[$0]++'` which loads the entire list
# into RAM. `sort -u` streams. For 10GB inputs this is the difference
# between OOM and done.

wl_compose() {
    local out="$1"; shift
    local inputs=("$@")
    [[ -z "$out" ]] && { printf 'ERROR\tno output\n' >&2; return 1; }
    (( ${#inputs[@]} == 0 )) && { printf 'ERROR\tno inputs\n' >&2; return 1; }

    local expanded=()
    local f
    for f in "${inputs[@]}"; do
        if [[ -f "$f" ]]; then
            expanded+=("$f")
        elif [[ "$f" == *"*"* ]]; then
            for g in $f; do [[ -f "$g" ]] && expanded+=("$g"); done
        fi
    done

    (( ${#expanded[@]} == 0 )) && { printf 'ERROR\tno readable inputs\n' >&2; return 1; }

    info "merging ${#expanded[@]} files → $out (streaming sort -u)"

    # Use LC_ALL=C for speed and predictable byte-order dedup
    LC_ALL=C sort -u --parallel="$(nproc)" "${expanded[@]}" > "$out" 2>/dev/null

    if [[ -s "$out" ]]; then
        local size lines
        size=$(stat -c%s "$out")
        lines=$(wc -l < "$out")
        printf 'COMPOSED\t%s\nLINES\t%s\nSIZE\t%s\n' "$out" "$lines" "$size"
    else
        # sort already created $out; a leftover 0-byte file would later be
        # mistaken for a usable wordlist, so remove it on the failure path.
        rm -f "$out"
        printf 'ERROR\tempty output\n' >&2; return 1
    fi
}

# ── gzip output ──
wl_compose_gz() {
    local out="$1"; shift
    local plain="${out%.gz}"
    [[ "$out" == *.gz ]] || out="${out}.gz"

    local tmp_plain="$WL_TMP/compose_$$.txt"
    wl_compose "$tmp_plain" "$@" >/dev/null || return 1
    gzip -9 -c "$tmp_plain" > "$out"
    rm -f "$tmp_plain"

    if [[ -s "$out" ]]; then
        local size
        size=$(stat -c%s "$out")
        printf 'COMPOSED_GZ\t%s\nSIZE\t%s\n' "$out" "$size"
    else
        printf 'ERROR\tgzip failed\n' >&2; return 1
    fi
}

wl_delete() {
    local f="$1"
    [[ -z "$f" || ! -f "$f" ]] && { printf 'ERROR\tno file\n' >&2; return 1; }
    case "$f" in
        "$WL_DIR"/*)
            rm -f "$f"
            local key
            key=$(printf '%s' "$f" | md5sum | cut -c1-16)
            rm -f "$WL_META/$key"
            printf 'DELETED\t%s\n' "$f"
            ;;
        *)
            printf 'ERROR\trefusing to delete outside %s\n' "$WL_DIR" >&2
            return 1 ;;
    esac
}

# ── SecLists integration ──

SLC_GIT_URL="https://github.com/danielmiessler/SecLists.git"
SLC_TARGET_DIR="${SECLISTS_DIR:-$HOME/wifisting/external/SecLists}"

wl_seclists_status_tsv() {
    if [[ -d "$SLC_TARGET_DIR/.git" ]]; then
        local size count
        size=$(du -sh "$SLC_TARGET_DIR" 2>/dev/null | awk '{print $1}')
        count=$(find "$SLC_TARGET_DIR/Passwords" -type f 2>/dev/null | wc -l)
        printf 'installed\tyes\n'
        printf 'dir\t%s\n' "$SLC_TARGET_DIR"
        printf 'size\t%s\n' "$size"
        printf 'password_files\t%s\n' "$count"
        # Current commit
        local commit
        commit=$(git -C "$SLC_TARGET_DIR" rev-parse --short HEAD 2>/dev/null)
        printf 'commit\t%s\n' "${commit:-?}"
    else
        printf 'installed\tno\n'
        printf 'dir\t%s\n' "$SLC_TARGET_DIR"
        printf 'size\t\n'
        printf 'password_files\t0\n'
        printf 'commit\t\n'
    fi
}

wl_seclists_clone() {
    command -v git >/dev/null 2>&1 || { printf 'ERROR\tgit missing\n' >&2; return 1; }
    if [[ -d "$SLC_TARGET_DIR/.git" ]]; then
        printf 'EXISTS\t%s\n' "$SLC_TARGET_DIR"
        return 0
    fi
    mkdir -p "$(dirname "$SLC_TARGET_DIR")"
    info "cloning SecLists (this is big — 1.4 GB+)"
    git clone --depth 1 "$SLC_GIT_URL" "$SLC_TARGET_DIR" 2>&1 | tail -5
    if [[ -d "$SLC_TARGET_DIR/.git" ]]; then
        printf 'CLONED\t%s\n' "$SLC_TARGET_DIR"
    else
        printf 'ERROR\tclone failed\n' >&2
        return 1
    fi
}

wl_seclists_update() {
    [[ -d "$SLC_TARGET_DIR/.git" ]] || {
        printf 'ERROR\tnot installed\n' >&2; return 1; }
    info "updating SecLists"
    ( cd "$SLC_TARGET_DIR" && git pull --ff-only 2>&1 | tail -5 )
    printf 'UPDATED\t%s\n' "$SLC_TARGET_DIR"
}

# List the WiFi-relevant wordlists inside SecLists
wl_seclists_list_tsv() {
    [[ -d "$SLC_TARGET_DIR" ]] || return 0
    local base="$SLC_TARGET_DIR/Passwords"
    [[ -d "$base" ]] || return 0
    find "$base" -maxdepth 3 -type f \( -name '*.txt' -o -name '*.lst' \) 2>/dev/null | \
        while read -r f; do
            local sz
            sz=$(stat -c%s "$f")
            printf '%s\t%s\n' "$f" "$sz"
        done
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline: no download, no clone. Every path the module writes to (list
# dir, scratch dir, meta sidecars, SecLists target) is redirected into
# scratch space so the real wordlist inventory is never touched.
wl_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rows() { printf '%s\n' "$1" | grep -c . ; }

    local MOD_TMP="$WL_TMP/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/wl" "$MOD_TMP/meta" "$MOD_TMP/slc/Passwords/sub" "$MOD_TMP/fakegit/.git"
    local s_dir="$WL_DIR" s_tmp="$WL_TMP" s_meta="$WL_META" s_slc="$SLC_TARGET_DIR"
    WL_DIR="$MOD_TMP/wl"; WL_TMP="$MOD_TMP"; WL_META="$MOD_TMP/meta"
    SLC_TARGET_DIR="$MOD_TMP/nothere"

    local out rc

    # 1. stats: *.txt + *.lst counted, other extensions ignored, bytes summed
    printf 'apple\nbanana\napple\n' > "$WL_DIR/a.txt"
    printf 'cherry\nbanana\n'       > "$WL_DIR/b.lst"
    printf 'ignored\n'              > "$WL_DIR/c.rule"
    out=$(wl_stats)
    chk stats-count       "$(fld "$out" count)"       2
    chk stats-total-bytes "$(fld "$out" total_bytes)" 33
    chk stats-dir         "$(fld "$out" dir)"         "$WL_DIR"
    chk stats-rows        "$(rows "$out")"            3

    # 2. inventory: PATH<TAB>SIZE<TAB>LINES, .gz counted decompressed
    printf 'x\ny\nz\n' | gzip -c > "$WL_DIR/c.gz"
    out=$(wl_list_tsv | grep "^$WL_DIR/")
    chk list-rows       "$(rows "$out")" 3
    chk list-fields     "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=3{c++} END{print c+0}')" 0
    chk list-txt-lines  "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /a\.txt$/ {print $3}')" 3
    chk list-txt-size   "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /a\.txt$/ {print $2}')" 19
    chk list-lst-lines  "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /b\.lst$/ {print $3}')" 2
    chk list-gz-lines   "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /c\.gz$/ {print $3}')"  3
    chk list-gz-size    "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /c\.gz$/ {print ($2>0)?"yes":"no"}')" yes
    chk list-skips-other "$(printf '%s\n' "$out" | grep -c 'c\.rule')" 0

    # 3. compose: duplicates collapse, byte-order sorted, counted
    out=$(wl_compose "$MOD_TMP/out.txt" "$WL_DIR/a.txt" "$WL_DIR/b.lst" 2>/dev/null); rc=$?
    chk compose-rc     "$rc" 0
    chk compose-lines  "$(fld "$out" LINES)" 3
    chk compose-size   "$(fld "$out" SIZE)"  20
    chk compose-order  "$(tr '\n' ',' < "$MOD_TMP/out.txt")" "apple,banana,cherry,"
    chk compose-dedup  "$(grep -c '^apple$' "$MOD_TMP/out.txt")" 1

    # ... a quoted glob is expanded by the module itself
    out=$(wl_compose "$MOD_TMP/glob.txt" "$WL_DIR/*.txt" 2>/dev/null); rc=$?
    chk compose-glob-rc    "$rc" 0
    chk compose-glob-lines "$(fld "$out" LINES)" 2

    # ... and every malformed invocation is refused, non-zero
    wl_compose >/dev/null 2>&1;                       chk compose-usage-rc     "$?" 1
    wl_compose "" "$WL_DIR/a.txt" >/dev/null 2>&1;    chk compose-no-out-rc    "$?" 1
    wl_compose "$MOD_TMP/o.txt" /nonexistent/x >/dev/null 2>&1; chk compose-bad-input-rc "$?" 1
    : > "$WL_DIR/empty.txt"
    out=$(wl_compose "$MOD_TMP/o.txt" "$WL_DIR/empty.txt" 2>&1); rc=$?
    chk compose-empty-rc "$rc" 1
    chk compose-empty-no-claim "$(printf '%s\n' "$out" | grep -c '^COMPOSED')" 0
    # The 0-byte file sort created must be removed, not left behind where a
    # later step could mistake it for a usable wordlist.
    chk compose-empty-no-file "$([[ -e "$MOD_TMP/o.txt" ]] && echo present || echo gone)" gone
    chk compose-empty-not-success "$([[ -s "$MOD_TMP/o.txt" ]] && echo 1 || echo 0)" 0
    rm -f "$MOD_TMP/o.txt" "$WL_DIR/empty.txt"

    # 4. gzip compose: suffix enforced, content really compressed
    out=$(wl_compose_gz "$MOD_TMP/gzout" "$WL_DIR/a.txt" "$WL_DIR/b.lst" 2>/dev/null); rc=$?
    chk gz-rc      "$rc" 0
    chk gz-suffix  "$(fld "$out" COMPOSED_GZ)" "$MOD_TMP/gzout.gz"
    chk gz-format  "$(gzip -dc "$MOD_TMP/gzout.gz" 2>/dev/null | wc -l)" 3
    chk gz-no-tmp  "$(find "$MOD_TMP" -maxdepth 1 -name 'compose_*.txt' | wc -l)" 0

    # 5. meta sidecar round-trip, keyed by path hash
    wl_meta_save "$WL_DIR/a.txt" "unit-test" >/dev/null
    out=$(wl_meta_get "$WL_DIR/a.txt"); rc=$?
    chk meta-rc      "$rc" 0
    chk meta-path    "$(printf '%s\n' "$out" | awk -F= '$1=="path"{sub(/^[^=]*=/,""); print}')" "$WL_DIR/a.txt"
    chk meta-source  "$(printf '%s\n' "$out" | awk -F= '$1=="source"{sub(/^[^=]*=/,""); print}')" unit-test
    chk meta-fetched "$(printf '%s\n' "$out" | grep -c '^fetched=')" 1
    chk meta-key-name "$(find "$WL_META" -maxdepth 1 -type f -printf '%f\n' | grep -cE '^[0-9a-f]{16}$')" 1
    out=$(wl_meta_get "$MOD_TMP/never-saved"); rc=$?
    chk meta-missing-rc   "$rc" 1
    chk meta-missing-empty "$out" ""

    # 6. delete: only inside the list dir, and the sidecar goes with it
    printf 'tmp\n' > "$MOD_TMP/outside.txt"
    out=$(wl_delete "$MOD_TMP/outside.txt" 2>&1); rc=$?
    chk delete-outside-rc  "$rc" 1
    chk delete-outside-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "refusing to delete outside $WL_DIR"
    chk delete-outside-kept "$([[ -f "$MOD_TMP/outside.txt" ]] && echo 1 || echo 0)" 1
    wl_delete "$MOD_TMP/never" >/dev/null 2>&1; chk delete-missing-rc "$?" 1
    local key_before; key_before=$(find "$WL_META" -maxdepth 1 -type f | wc -l)
    out=$(wl_delete "$WL_DIR/a.txt" 2>/dev/null); rc=$?
    chk delete-inside-rc   "$rc" 0
    chk delete-inside-says "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DELETED"{print $2}')" "$WL_DIR/a.txt"
    chk delete-inside-gone "$([[ -f "$WL_DIR/a.txt" ]] && echo 1 || echo 0)" 0
    chk delete-sidecar-gone "$(find "$WL_META" -maxdepth 1 -type f | wc -l)" "$((key_before - 1))"

    # 7. install moves the file in and records where it came from
    printf 'w1\nw2\n' > "$MOD_TMP/newwl.txt"
    out=$(wl_install_to_dir "$MOD_TMP/newwl.txt" 2>/dev/null); rc=$?
    chk install-rc     "$rc" 0
    chk install-says   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="INSTALLED"{print $2}')" "$WL_DIR/newwl.txt"
    chk install-exists "$([[ -f "$WL_DIR/newwl.txt" ]] && echo 1 || echo 0)" 1
    chk install-moved  "$([[ -f "$MOD_TMP/newwl.txt" ]] && echo 1 || echo 0)" 0
    chk install-meta   "$(wl_meta_get "$WL_DIR/newwl.txt" | grep -c '^source=download:newwl.txt$')" 1
    wl_install_to_dir "$MOD_TMP/never" >/dev/null 2>&1; chk install-missing-rc "$?" 1

    # 8. rule inventory rows are PATH<TAB>SIZE (machine may have none)
    out=$(wl_rules_tsv)
    chk rules-shape "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2 || $2 !~ /^[0-9]+$/ {c++} END{print c+0}')" 0

    # 9. SecLists status: absent vs a bogus .git (no network either way)
    out=$(wl_seclists_status_tsv)
    chk slc-absent-installed "$(fld "$out" installed)" no
    chk slc-absent-dir       "$(fld "$out" dir)" "$SLC_TARGET_DIR"
    chk slc-absent-files     "$(fld "$out" password_files)" 0
    chk slc-absent-rows      "$(rows "$out")" 5
    SLC_TARGET_DIR="$MOD_TMP/fakegit"
    out=$(wl_seclists_status_tsv)
    chk slc-present-installed "$(fld "$out" installed)" yes
    chk slc-present-commit    "$(fld "$out" commit)" "?"
    chk slc-present-size-set  "$([[ -n "$(fld "$out" size)" ]] && echo 1 || echo 0)" 1
    out=$(wl_seclists_clone 2>/dev/null); rc=$?
    chk slc-clone-exists-rc   "$rc" 0
    chk slc-clone-exists-says "$(printf '%s\n' "$out" | awk -F'\t' '$1=="EXISTS"{print $2}')" "$SLC_TARGET_DIR"
    SLC_TARGET_DIR="$MOD_TMP/nothere"
    wl_seclists_update >/dev/null 2>&1; chk slc-update-missing-rc "$?" 1

    # 10. SecLists listing: files under Passwords, path+size, empty when absent
    printf 'aaa\n' > "$MOD_TMP/slc/Passwords/p.txt"
    printf 'bb\n'  > "$MOD_TMP/slc/Passwords/sub/q.lst"
    SLC_TARGET_DIR="$MOD_TMP/slc"
    out=$(wl_seclists_list_tsv)
    chk slc-list-rows   "$(rows "$out")" 2
    chk slc-list-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=2{c++} END{print c+0}')" 0
    chk slc-list-size   "$(printf '%s\n' "$out" | awk -F'\t' '$1 ~ /p\.txt$/ {print $2}')" 4
    SLC_TARGET_DIR="$MOD_TMP/nothere"
    chk slc-list-absent "$(wl_seclists_list_tsv | grep -c .)" 0

    # 11. download refuses without a url (never reaches the network)
    wl_download "" >/dev/null 2>&1; chk download-no-url-rc "$?" 1

    WL_DIR="$s_dir"; WL_TMP="$s_tmp"; WL_META="$s_meta"; SLC_TARGET_DIR="$s_slc"
    rm -rf "$MOD_TMP"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}


# ── ISP default-key patterns ─────────────────────────────────────────────
# The table lives in modules/isp_patterns.tsv as data. Every row carries its
# source and a confidence tag, so a hypothesis is never printed as a fact, and
# rows whose derivation is unknown are reported as unhelpful rather than
# silently skipped.

WL_PATTERNS="$WIFISTING_ROOT/modules/isp_patterns.tsv"

wl_patterns_tsv() {
    local want="${1:-}"
    [[ -f "$WL_PATTERNS" ]] || {
        printf 'ERR\tpattern table missing: %s\n' "$WL_PATTERNS" >&2; return 1; }
    if [[ -z "$want" || "$want" == "--all" ]]; then
        grep -v '^#' "$WL_PATTERNS"
        return 0
    fi
    # header first, then matching rows, so the output is self-describing
    grep -v '^#' "$WL_PATTERNS" | head -1
    grep -v '^#' "$WL_PATTERNS" | awk -F'\t' -v w="$want" \
        'tolower($1)==tolower(w) || tolower($2)==tolower(w)'
}

# Charset -> hashcat custom charset. The charset matters more than the length:
# at eight characters ?h is ~4.3e9 candidates while ?l?d is ~2.8e12, a 650x
# difference, and that is the whole point of knowing the ISP.
wl_mask_charset() {
    case "$1" in
        hex-lower)   printf '?h' ;;
        hex-upper)   printf '?u' ;;
        lower)       printf '?l' ;;
        lower-digit) printf '?l?d' ;;
        alnum)       printf '?l?u?d' ;;
        digits)      printf '?d' ;;
        *)           printf '' ;;
    esac
}

wl_gen_mask_tsv() {
    local want="${1:---all}"
    local isp model class len cs deriv conf src
    local n=0 skipped=0
    while IFS=$'\t' read -r isp model class len cs deriv conf src; do
        [[ -z "$isp" ]] && continue
        if [[ "$want" != "--all" && "$isp" != "$want" && "$model" != "$want" ]]; then
            continue
        fi
        # Cannot build a mask without both a length and a charset, and a row
        # marked unknown has no derivation to exploit.
        if [[ "$class" == "unknown" || "$len" == "-" || -z "$cs" || "$cs" == "-" ]]; then
            printf 'NOT-A-MASK\t%s\t%s\t%s\t%s\n' "$isp" "$model" "$class" "${conf}"
            skipped=$((skipped+1)); continue
        fi
        local set mask i
        set=$(wl_mask_charset "$cs")
        [[ -z "$set" ]] && { skipped=$((skipped+1)); continue; }
        mask=""
        for (( i=0; i<len; i++ )); do mask+="?1"; done
        printf 'MASK\t%s\t%s\t-h -1 %s "%s"\t%s\n' \
            "$isp" "$model" "$set" "$mask" "$conf"
        n=$((n+1))
    done < <(grep -v '^#' "$WL_PATTERNS")
    printf 'COUNT\t%d masks, %d row(s) with no usable derivation\n' "$n" "$skipped"
}

# Candidates for the derivable classes. Anything not derivable is named as
# such: a wordlist that cannot contain the answer is worse than no wordlist,
# because it costs an engagement to discover that.
wl_gen_isp_tsv() {
    local want="$1"; shift
    local ssid="" mac="" serial=""
    while (( $# )); do
        case "$1" in
            --ssid)   ssid="${2:-}";   shift 2 ;;
            --bssid|--mac) mac="${2:-}"; shift 2 ;;
            --serial) serial="${2:-}"; shift 2 ;;
            *) shift ;;
        esac
    done
    [[ -n "$want" ]] || {
        printf 'ERR\tusage: --gen-isp-tsv ISP [--ssid S] [--bssid M] [--serial N]\n' >&2
        return 2; }

    local n=0
    # MAC forms: with and without separators, both cases, full and suffixed.
    if [[ -n "$mac" ]]; then
        local m_lo m_up m_nosep
        m_lo=$(printf '%s' "$mac" | tr 'A-Z' 'a-z')
        m_up=$(printf '%s' "$mac" | tr 'a-z' 'A-Z')
        m_nosep=$(printf '%s' "$m_lo" | tr -d ':-')
        m_upper_nosep=$(printf '%s' "$m_up" | tr -d ':-')
        printf 'CANDIDATE\tmac-full\t%s\n' "$m_lo"
        printf 'CANDIDATE\tmac-full-upper\t%s\n' "$m_up"
        printf 'CANDIDATE\tmac-nosep\t%s\n' "$m_nosep"
        printf 'CANDIDATE\tmac-suffix6\t%s\n' "${m_nosep: -6}"
        printf 'CANDIDATE\tmac-suffix6-upper\t%s\n' "${m_upper_nosep: -6}"

        n=$((n+5))
    fi
    if [[ -n "$serial" ]]; then
        local sl su
        sl=$(printf '%s' "$serial" | tr 'A-Z' 'a-z')
        su=$(printf '%s' "$serial" | tr 'a-z' 'A-Z')
        printf 'CANDIDATE\tserial\t%s\n' "$serial"
        printf 'CANDIDATE\tserial-lower\t%s\n' "$sl"
        printf 'CANDIDATE\tserial-upper\t%s\n' "$su"
        n=$((n+3))
    fi
    if [[ -n "$ssid" ]]; then
        printf 'CANDIDATE\tssid\t%s\n' "$ssid"
        n=$((n+1))
    fi

    printf 'GENERATED\t%d\t%s\n' "$n" "$want"
    # Say precisely what was NOT produced and why.
    local class
    class=$(grep -v '^#' "$WL_PATTERNS" | awk -F'\t' -v w="$want" \
            'tolower($1)==tolower(w){print $3; exit}')
    case "$class" in
        ssid-derived)
            printf 'NOTE\t%s keys are derived from the SSID by a model-specific algorithm; this verb cannot reproduce it - use --patterns-tsv and the cited source\n' "$want" ;;
        label-random)
            printf 'NOTE\t%s keys are random and printed on the device label; no generator can produce them - read the sticker or dump the config\n' "$want" ;;
        unknown|"")
            printf 'NOTE\tno published derivation for %s - any wordlist here would be a guess\n' "$want" ;;
    esac
}


# SHA-1 serial derivation, documented for Thomson SpeedTouch and BT Home Hub
# (VARIoT VAR-200804-0458). The published vector is why this is implemented
# rather than merely described: feed it CP0615313039 and it must produce key
# 742DA831D2, or it is wrong.
#
# Only the hash step is automated. Normalising a real serial ("CP0615JT109
# (53)" -> "CP0615109" -> "CP0615313039") stays with the operator, because the
# published description of that step is ambiguous and guessing it would emit
# confidently wrong keys.
wl_sha1_serial_tsv() {
    local raw="${1:-}"
    [[ -n "$raw" ]] || {
        printf 'ERR\tusage: --gen-sha1-serial-tsv NORMALISED_SERIAL\n' >&2; return 2; }

    local h key ssid3 ssid2
    h=$(printf '%s' "$raw" | sha1sum 2>/dev/null | cut -d' ' -f1)
    [[ ${#h} -eq 40 ]] || { printf 'ERR\tsha1sum unavailable\n' >&2; return 1; }

    key=$(printf '%s' "$h" | cut -c1-10 | tr 'a-z' 'A-Z')
    # A SHA-1 hex digest is 40 chars for 20 bytes, so the last 3 bytes are
    # characters 35-40 and the last 2 are 37-40. Slicing from the front of the
    # tail (31-36) is off by four and yields a plausible-looking wrong SSID.
    ssid3=$(printf '%s' "$h" | cut -c35-40 | tr 'a-z' 'A-Z')
    ssid2=$(printf '%s' "$h" | cut -c37-40 | tr 'a-z' 'A-Z')

    printf 'INPUT\t%s\n' "$raw"
    printf 'SHA1\t%s\n' "$h"
    printf 'KEY\t%s\tfirst 5 bytes, uppercase hex\n' "$key"
    printf 'SSID\tSpeedTouch%s\tThomson: last 3 bytes\n' "$ssid3"
    printf 'SSID\tBTHomeHub-%s\tBT: last 2 bytes\n' "$ssid2"
}


# ── pattern inference from samples ───────────────────────────────────────
# Takes a TSV of samples you legitimately hold - labels on your own or
# permissioned hardware, or public test vectors - and reports what the keys
# have in common, plus which known derivation actually reproduces them.
#
# Columns (header required, extras ignored):
#   isp  model  key  [serial]  [mac]  [ssid]
#
# It infers; it does not guess. A hypothesis is reported as MATCH only when a
# derivation reproduces the key from the identifiers in the same row.
wl_charset_of() {
    local k="$1"
    case "$k" in
        *[!0-9a-fA-F]*) ;;
        *) case "$k" in
               *[A-F]*) printf 'hex-upper' ;;
               *[a-f]*) printf 'hex-lower' ;;
               *)       printf 'hex-nodigit' ;;
           esac; return ;;
    esac
    case "$k" in
        *[!0-9]*) ;;
        *) printf 'digits'; return ;;
    esac
    case "$k" in
        *[!a-z0-9]*) ;;
        *) printf 'lower-digit'; return ;;
    esac
    case "$k" in
        *[!a-z]*) ;;
        *) printf 'lower'; return ;;
    esac
    case "$k" in
        *[!A-Za-z0-9]*) ;;
        *) printf 'alnum'; return ;;
    esac
    printf 'mixed'
}

wl_infer_pattern_tsv() {
    local f="$1"
    [[ -n "$f" ]] || {
        printf 'ERR\tusage: --infer-pattern-tsv SAMPLES.tsv\n' >&2; return 2; }
    [[ -s "$f" ]] || { printf 'ERR\tno such file: %s\n' "$f" >&2; return 1; }

    local header
    header=$(head -1 "$f")
    case "$header" in
        isp*) ;;
        *) printf 'ERR\tfirst line must be a header starting with "isp"\n' >&2; return 2 ;;
    esac

    local isp model key serial mac ssid n=0 matches=0
    local t; t=$(mktemp) || return 1

    while IFS=$'\t' read -r isp model key serial mac ssid; do
        [[ "$isp" == "isp" || -z "$key" ]] && continue
        n=$((n+1))
        local cs; cs=$(wl_charset_of "$key")
        local len=${#key}
        local hyp="-"

        # Does a documented derivation reproduce this key from this row's
        # identifiers? Tested, not assumed.
        if [[ -n "$serial" ]]; then
            local h raw stripped
            raw=$(printf '%s' "$serial" | tr -d ' ' | sha1sum | cut -d' ' -f1)
            stripped=$(printf '%s' "$serial" | tr -cd 'A-Za-z0-9' | sha1sum | cut -d' ' -f1)
            local hl=${key,,}
            if [[ "$raw" == *"$hl"* ]]; then hyp="sha1-serial-raw"
            elif [[ "$stripped" == *"$hl"* ]]; then hyp="sha1-serial-stripped"
            fi
        fi
        if [[ "$hyp" == "-" && -n "$mac" ]]; then
            local m; m=$(printf '%s' "$mac" | tr -d ':-' | tr 'A-Z' 'a-z')
            [[ "$m" == *"${key,,}"* ]] && hyp="mac-substring"
        fi
        if [[ "$hyp" == "-" && -n "$ssid" ]]; then
            [[ "${ssid,,}" == *"${key,,}"* || "${key,,}" == *"${ssid,,}"* ]] && hyp="ssid-related"
        fi
        [[ "$hyp" != "-" ]] && matches=$((matches+1))

        printf 'SAMPLE\t%s\t%s\t%s\t%s\t%s\n' "$isp" "$model" "$len" "$cs" "$hyp"
        printf '%s\t%s\t%s\t%s\n' "$isp" "$model" "$len" "$cs" >> "$t"
    done < "$f"

    # Aggregate: the pattern is what the group shares.
    printf 'GROUP\tisp\tmodel\tsamples\tlengths\tcharsets\n'
    awk -F'\t' '
        { n[$1"/"$2]++; L[$1"/"$2][$3]=1; C[$1"/"$2][$4]=1 }
        END {
            for (g in n) {
                ls=""; for (l in L[g]) ls = ls (ls=="" ? "" : ",") l
                cs=""; for (c in C[g]) cs = cs (cs=="" ? "" : ",") c
                printf "GROUP\t%s\t%d\t%s\t%s\n", g, n[g], ls, cs
            }
        }' "$t" | sort
    rm -f "$t"

    printf 'TOTAL\t%d sample(s), %d matched a known derivation\n' "$n" "$matches"
    if (( n > 0 && matches == 0 )); then
        printf 'NOTE\tno known derivation reproduced any key. Either the scheme is not one this module implements, or the identifiers in the rows are incomplete (a serial is needed for the SHA-1 schemes).\n'
    fi
    return 0
}


# ── on-screen-keyboard friendly PSK generation ───────────────────────────
# Ported from luiscantero's OSK WPA2 Key Generator. This CREATES a key; it is
# not a wordlist source. The output is random, so enumerating it for cracking
# is pointless - what it is good for is producing a strong passphrase that a
# human can type on a TV remote, which is the situation a rogue AP or captive
# portal puts people in.
#
# The design decisions are the original author's and are what make it usable:
#   * five character classes (lower/upper x consonant/vowel, plus digits)
#   * consonant always followed by a vowel, so the result is pronounceable
#   * O and 0 omitted as visually confusable
#   * a switch budget, keeping the typist on one keyboard page as long as it can
wl_osk_key() {
    local len="${1:-20}" maxsw="${2:-3}"
    shift $(( $# >= 2 ? 2 : $# ))

    local count=1 min_digits=0 min_upper=0 use_digits=1 use_symbols=0
    local group=0 allow_amb=0
    while (( $# )); do
        case "$1" in
            --count)           count="${2:-1}"; shift 2 ;;
            --no-digits)       use_digits=0;     shift ;;
            --min-digits)      min_digits="${2:-1}"; shift 2 ;;
            --min-upper)       min_upper="${2:-1}";  shift 2 ;;
            --symbols)         use_symbols=1;    shift ;;
            --group)           group="${2:-4}";  shift 2 ;;
            --allow-ambiguous) allow_amb=1;      shift ;;
            *) shift ;;
        esac
    done

    [[ "$len" =~ ^[0-9]+$ ]] || { printf 'ERR\tlength must be a number\n' >&2; return 2; }
    (( len >= 8 && len <= 63 )) || {
        printf 'ERR\tlength must be 8-63 (the generator supports 64-504 bits)\n' >&2; return 2; }
    [[ "$maxsw" =~ ^[0-9]+$ ]] || { printf 'ERR\tswitches must be a number\n' >&2; return 2; }
    (( maxsw >= 0 && maxsw <= 10 )) || { printf 'ERR\tswitches must be 0-10\n' >&2; return 2; }
    [[ "$count" =~ ^[0-9]+$ ]] || { printf 'ERR\tcount must be a number\n' >&2; return 2; }
    (( count >= 1 && count <= 100 )) || { printf 'ERR\tcount must be 1-100\n' >&2; return 2; }
    [[ "$group" =~ ^[0-9]+$ ]] || { printf 'ERR\tgroup must be a number\n' >&2; return 2; }

    # O and 0 are dropped as confusable unless the operator opts out. The
    # symbol set omits quotes and backslashes: they are miserable to type into
    # a Wi-Fi dialog and worse to pass through a shell.
    local cons_lo vow_lo cons_up vow_up digits syms
    if (( allow_amb )); then
        cons_lo="bcdfghjklmnpqrstvwxyz"; cons_up="BCDFGHJKLMNPQRSTVWXYZ"
        vow_lo="aeiou"; vow_up="AEIOU"; digits="0123456789"
    else
        cons_lo="bcdfghjkmnpqrstvwxyz"; cons_up="BCDFGHJKLMNPQRSTVWXYZ"
        vow_lo="aeiu"; vow_up="AEU"; digits="123456789"
    fi
    syms='!@#%^&*_-+=?'

    local -a sets=( "$cons_lo" "$vow_lo" "$cons_up" "$vow_up" )
    (( use_digits ))  && sets+=( "$digits" )
    (( use_symbols )) && sets+=( "$syms" )
    local n=${#sets[@]}

    local per
    if (( maxsw > 0 )); then per=$(( (len + maxsw - 1) / maxsw )); else per=$(( len + 1 )); fi

    local k out=0 worst=0
    for (( k = 0; k < count; k++ )); do
        local idx=$(( (RANDOM % 2) * 2 ))     # start on a lower/upper consonant set
        local left="$maxsw" key="" set cur guard=0

        while (( ${#key} < len )) && (( guard++ < 800 )); do
            if (( left > 0 && ${#key} > 0 && ${#key} % per == 0 )); then
                # Switch only to a CONSONANT set (0, 2) or to a non-letter set
                # (digits/symbols, index >= 4). The original picks
                # getrand(0,2)*2, i.e. never a vowel set: a key must open each
                # run with a consonant, and landing on a vowel set would both
                # break that and burn a switch without changing keyboard page.
                local -a cand=( 0 2 )
                (( use_digits ))  && cand+=( $(( n - 1 - use_symbols )) )
                (( use_symbols )) && cand+=( $(( n - 1 )) )
                cur="$idx"
                local tries=0 pick
                while (( tries++ < 40 )); do
                    pick="${cand[$((RANDOM % ${#cand[@]}))]}"
                    [[ "$pick" != "$cur" ]] && { idx="$pick"; break; }
                done
                left=$(( left - 1 ))
            fi

            set="${sets[$idx]}"
            key+="${set:$((RANDOM % ${#set})):1}"

            # consonant then vowel, unless that would spend a switch
            if (( ${#key} < len && idx < 4 && idx % 2 == 0 && ${#key} % per != 0 )); then
                set="${sets[$((idx + 1))]}"
                key+="${set:$((RANDOM % ${#set})):1}"
            fi
        done
        key="${key:0:len}"

        # Policy floors, applied by substitution. Deliberately blunt: it
        # satisfies "at least one digit" without pretending the strict
        # consonant-vowel rhythm survives.
        (( min_digits > 0 )) && key=$(wl_osk_force_class "$key" "$min_digits" "$digits")
        (( min_upper  > 0 )) && key=$(wl_osk_force_class "$key" "$min_upper" "$cons_up$vow_up")
        # Enabling the symbol class is not the same as using it: a switch may
        # never land there. Asking for symbols is a policy requirement, so at
        # least one is guaranteed.
        (( use_symbols )) && key=$(wl_osk_force_class "$key" 1 "$syms")

        # Count keyboard-page changes: lower / upper / digits / symbols.
        # Alternating consonant and vowel inside one page is free. An earlier
        # version counted 1->0 as a switch and reported more than the budget.
        local i prev=-1 fam sw=0
        for (( i = 0; i < ${#key}; i++ )); do
            case "${key:i:1}" in
                [a-z]) fam=0 ;;
                [A-Z]) fam=1 ;;
                [0-9]) fam=2 ;;
                *)     fam=3 ;;
            esac
            (( prev >= 0 && fam != prev )) && sw=$(( sw + 1 ))
            prev="$fam"
        done
        (( sw > worst )) && worst="$sw"

        local shown="$key"
        if (( group > 0 )); then
            local out_s="" j
            for (( j = 0; j < ${#key}; j += group )); do
                out_s+="${key:j:group}"
                (( j + group < ${#key} )) && out_s+="-"
            done
            shown="$out_s"
        fi
        printf 'PSK\t%s\n' "$shown"
        out=$(( out + 1 ))
    done

    local pool=$(( ${#cons_lo} + ${#vow_lo} + ${#cons_up} + ${#vow_up} ))
    (( use_digits ))  && pool=$(( pool + ${#digits} ))
    (( use_symbols )) && pool=$(( pool + ${#syms} ))

    printf 'LENGTH\t%d\n' "$len"
    printf 'COUNT\t%d\n' "$out"
    printf 'POOL\t%d\tdistinct characters across the enabled classes\n' "$pool"
    printf 'SWITCHES\t%d\tworst of %d key(s), budget %d\n' "$worst" "$out" "$maxsw"
    printf 'NOTE\tfor creating a key, not for cracking: this is random, so it will not be found by guessing\n'
}

# Replace characters until `want` of them come from `set`. Positions are chosen
# at random, so a short key with a high floor may need several passes; that is
# why this is only used to satisfy policy minimums, not to shape the key.
wl_osk_force_class() {
    local key="$1" want="$2" set="$3"
    local i have=0 c

    for (( i = 0; i < ${#key}; i++ )); do
        c="${key:i:1}"
        [[ "$set" == *"$c"* ]] && have=$(( have + 1 ))
    done

    local need=$(( want - have )) guard=0
    while (( need > 0 )) && (( guard++ < 300 )); do
        local p=$(( RANDOM % ${#key} ))
        c="${key:p:1}"
        [[ "$set" == *"$c"* ]] && continue       # already the right class
        key="${key:0:p}${set:$((RANDOM % ${#set})):1}${key:$((p + 1))}"
        need=$(( need - 1 ))
    done
    printf '%s' "$key"
}

wl_selftest_patterns() {
    local pass=0 fail=0
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"; pass=$((pass+1))
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fail=$((fail+1)); fi
    }

    chk table-exists "$([[ -s "$WL_PATTERNS" ]] && echo yes || echo no)" yes
    # A floor, not an exact count: the table is data and is expected to grow.
    chk patterns-all   "$(wl_patterns_tsv --all | wc -l | tr -d ' ' | awk '{print ($1>=8)}')" 1
    chk patterns-filter "$(wl_patterns_tsv fritzbox | wc -l | tr -d ' ')" 2
    chk patterns-header "$(wl_patterns_tsv fritzbox | head -1 | cut -f1)" isp

    # dispatcher-level: a filter must actually filter. Reading the wrong
    # argument here silently reported every row as if it were the match.
    chk cli-mask-filter "$("$0" --gen-mask-tsv virgin-media | awk -F'\t' '$1=="MASK"' | wc -l | tr -d ' ')" 1
    chk cli-pattern-filter "$("$0" --patterns-tsv fritzbox | wc -l | tr -d ' ')" 2
    chk cli-gen-isp "$("$0" --gen-isp-tsv generic --mac AA:BB:CC:DD:EE:FF | grep -c 'aabbccddeeff')" 1

    # charset -> mask: the keyspace-relevant part
    chk charset-hex   "$(wl_mask_charset hex-lower)" "?h"
    chk charset-lod   "$(wl_mask_charset lower-digit)" "?l?d"
    chk charset-bad   "$(wl_mask_charset nonsense)" ""

    # a row with a length and charset becomes an 8-position mask
    chk mask-vm "$(wl_gen_mask_tsv virgin-media | awk -F'\t' '$1=="MASK"{print $2}')" "virgin-media"
    chk mask-vm-args "$(wl_gen_mask_tsv virgin-media | awk -F'\t' '$1=="MASK"{print $4}')" \
        '-h -1 ?l?d "?1?1?1?1?1?1?1?1"'
    # rows without a derivation are reported, not silently dropped
    chk mask-skip "$(wl_gen_mask_tsv free | grep -c 'NOT-A-MASK')" 1
    chk mask-count "$(wl_gen_mask_tsv --all | awk -F'\t' '$1=="COUNT"{print ($2+0>0)}')" 1

    # candidate generation from identifiers
    local out
    out=$(wl_gen_isp_tsv generic --mac AA:BB:CC:DD:EE:FF --serial SN123 --ssid Net)
    chk gen-mac-nosep "$(printf '%s\n' "$out" | grep -c 'aabbccddeeff')" 1
    chk gen-mac-suffix "$(printf '%s\n' "$out" | awk -F'\t' '$2=="mac-suffix6"' | wc -l | tr -d ' ')" 1
    chk gen-serial "$(printf '%s\n' "$out" | grep -c 'serial-upper')" 1
    chk gen-ssid "$(printf '%s\n' "$out" | grep -c 'Net')" 1
    chk gen-shape "$(printf '%s\n' "$out" | awk -F'\t' '$1=="CANDIDATE" && NF!=3{bad++} END{print bad+0}')" 0

    # and the honest refusals
    chk gen-noarg-rc "$(wl_gen_isp_tsv >/dev/null 2>&1; echo $?)" 2
    chk gen-freebox-note "$(wl_gen_isp_tsv free | grep -c 'no published derivation')" 1
    chk gen-random-note  "$(wl_gen_isp_tsv fritzbox | grep -c 'printed on the device label')" 1

    # The published vector from VAR-200804-0458. If this fails the hash step
    # is wrong and every key it emits is wrong.
    local v
    v=$(wl_sha1_serial_tsv CP0615313039)
    chk sha1-key  "$(printf '%s\n' "$v" | awk -F'\t' '$1=="KEY"{print $2}')" "742DA831D2"
    chk sha1-ssid "$(printf '%s\n' "$v" | awk -F'\t' '$1=="SSID" && $2 ~ /SpeedTouch/{print $2}')" "SpeedTouchF8A3D0"
    chk sha1-bt   "$(printf '%s\n' "$v" | awk -F'\t' '$1=="SSID" && $2 ~ /BTHomeHub/{print $2}')" "BTHomeHub-A3D0"
    chk sha1-noarg "$(wl_sha1_serial_tsv >/dev/null 2>&1; echo $?)" 2

    # Inference against the published vector plus a decoy: the right sample
    # must MATCH and the unrelated one must not, or the verb is just noise.
    local sf="$WL_DIR/st-samples.tsv"
    printf 'isp\tmodel\tkey\tserial\tmac\tssid\n' > "$sf"
    printf 'thomson\tSpeedTouch\t742DA831D2\tCP0615313039\t\t\n' >> "$sf"
    printf 'bt\tHome Hub\t06f48a28eb\tCP064736444D\t\t\n' >> "$sf"
    printf 'orange\tLivebox\tZQ9K2M4T7P\t\t\t\n' >> "$sf"
    local io
    io=$(wl_infer_pattern_tsv "$sf")
    chk infer-count   "$(printf '%s\n' "$io" | awk -F'\t' '$1=="TOTAL"{print $2}' | cut -d' ' -f1)" 3
    chk infer-match   "$(printf '%s\n' "$io" | awk -F'\t' '$1=="SAMPLE" && $2=="thomson"{print $6}')" "sha1-serial-raw"
    chk infer-decoy   "$(printf '%s\n' "$io" | awk -F'\t' '$1=="SAMPLE" && $2=="orange"{print $6}')" "-"
    chk infer-charset "$(printf '%s\n' "$io" | awk -F'\t' '$1=="SAMPLE" && $2=="orange"{print $5}')" "alnum"
    # GROUP rows are: GROUP <isp/model> <count> <lengths> <charsets>
    chk infer-group   "$(printf '%s\n' "$io" | awk -F'\t' '$1=="GROUP" && $2 ~ /thomson/{print $2}')" "thomson/SpeedTouch"
    printf 'foo\tbar\n' > "$WL_DIR/st-bad.tsv"
    chk infer-badheader "$(wl_infer_pattern_tsv "$WL_DIR/st-bad.tsv" >/dev/null 2>&1; echo $?)" 2
    chk infer-missing   "$(wl_infer_pattern_tsv "$WL_DIR/st-none.tsv" >/dev/null 2>&1; echo $?)" 1
    chk infer-noarg   "$(wl_infer_pattern_tsv >/dev/null 2>&1; echo $?)" 2

    # OSK key generation: shape and constraints, deterministic assertions.
    local osk ok
    osk=$(wl_osk_key 20 3)
    ok=$(printf '%s\n' "$osk" | awk -F'\t' '$1=="PSK"{print $2}')
    chk osk-length  "${#ok}" 20
    # It may legitimately start in either case: the source set is chosen as
    # getrand(0,1)*2, i.e. lowercase OR uppercase consonants.
    chk osk-starts-letter "$(printf '%s' "$ok" | grep -cE '^[A-Za-z]')" 1
    # O and 0 are excluded precisely because they are confusable
    chk osk-no-O "$(printf '%s' "$ok" | grep -c '[O0]')" 0
    chk osk-charset "$(printf '%s' "$ok" | grep -cE '^[A-Za-z1-9]+$')" 1
    chk osk-badlen  "$(wl_osk_key 4  >/dev/null 2>&1; echo $?)" 2
    chk osk-badlen2 "$(wl_osk_key 64 >/dev/null 2>&1; echo $?)" 2
    chk osk-badsw   "$(wl_osk_key 20 99 >/dev/null 2>&1; echo $?)" 2
    chk osk-nonnum  "$(wl_osk_key abc >/dev/null 2>&1; echo $?)" 2
    # every length in range must be honoured exactly
    local bad=0 l
    for l in 8 15 20 31 63; do
        [[ "${#l}" -gt 0 ]] || continue
        osk=$(wl_osk_key "$l" 10 | awk -F'\t' '$1=="PSK"{print $2}')
        [[ "${#osk}" == "$l" ]] || bad=$((bad+1))
    done
    chk osk-all-lengths "$bad" 0
    # a zero switch budget must produce an all-lowercase-start key with one class
    osk=$(wl_osk_key 12 0 | awk -F'\t' '$1=="PSK"{print $2}')
    # A zero budget means no class change at all: the key stays in one case
    # family (and contains vowels, because consonant+vowel is the unit).
    # Options must actually take effect. They did not at first: the dispatcher
    # forwarded only two arguments, so --no-digits, --symbols, --group and
    # --count were accepted and silently ignored.
    local g
    g=$(wl_osk_key 16 4 --no-digits | awk -F'\t' '$1=="PSK"{print $2}')
    chk osk-nodigits "$(printf '%s' "$g" | grep -c '[0-9]')" 0
    g=$(wl_osk_key 16 4 --symbols | awk -F'\t' '$1=="PSK"{print $2}')
    # NB: keep '-' last in the class, otherwise it forms a range and never matches
    chk osk-symbols "$(printf '%s' "$g" | grep -cE '[!@#%^&*_+=?-]')" 1
    g=$(wl_osk_key 16 4 --group 4 | awk -F'\t' '$1=="PSK"{print $2}')
    chk osk-group "$(printf '%s' "$g" | grep -c -- '-')" 1
    chk osk-count "$(wl_osk_key 16 4 --count 5 | grep -c '^PSK')" 5
    # These are FLOORS: more than asked for is a pass, not a failure.
    g=$(wl_osk_key 20 4 --min-digits 3 | awk -F'\t' '$1=="PSK"{print $2}')
    local nd; nd=$(printf '%s' "$g" | tr -cd '0-9' | wc -c | tr -d ' ')
    chk osk-mindigits "$([[ $nd -ge 3 ]] && echo ok || echo "only $nd")" ok
    g=$(wl_osk_key 20 4 --min-upper 2 | awk -F'\t' '$1=="PSK"{print $2}')
    local nu; nu=$(printf '%s' "$g" | tr -cd 'A-Z' | wc -c | tr -d ' ')
    chk osk-minupper "$([[ $nu -ge 2 ]] && echo ok || echo "only $nu")" ok
    # the switch budget must never be exceeded, at any setting
    local over=0 sw
    for sw in 0 1 2 3 5 10; do
        g=$(wl_osk_key 24 "$sw" --count 4 | awk -F'\t' '$1=="SWITCHES"{print $2}')
        [[ "$g" -le "$sw" ]] || over=$((over + 1))
    done
    chk osk-budget "$over" 0

    chk osk-zerobudget "$(printf '%s' "$osk" | grep -cE '^([a-z]+|[A-Z]+)$')" 1

    printf 'PATTERNS\t%s\n' "$([[ $fail -eq 0 ]] && echo PASS || echo "FAIL($fail)")"
    printf 'PATTERNS_SUMMARY\t%d pass, %d fail\n' "$pass" "$fail"
    [[ $fail -eq 0 ]]
}

wl_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         wl_stats ;;
        --list-tsv)           wl_list_tsv ;;
        --rules-tsv)          wl_rules_tsv ;;
        --download)           wl_download "$@" ;;
        --install)            wl_install_to_dir "$@" ;;
        --compose)            wl_compose "$@" ;;
        --compose-gz)         wl_compose_gz "$@" ;;
        --delete)             wl_delete "$@" ;;
        --meta)               wl_meta_get "$@" ;;
        --seclists-status)    wl_seclists_status_tsv ;;
        --seclists-clone)     wl_seclists_clone ;;
        --seclists-update)    wl_seclists_update ;;
        --seclists-list)      wl_seclists_list_tsv ;;
        --patterns-tsv)       wl_patterns_tsv "${1:-}" ;;
        --gen-mask-tsv)       wl_gen_mask_tsv "${1:---all}" ;;
        --gen-isp-tsv)        wl_gen_isp_tsv "$@" ;;
        --gen-sha1-serial-tsv) wl_sha1_serial_tsv "${1:-}" ;;
        --infer-pattern-tsv) wl_infer_pattern_tsv "${1:-}" ;;
        --gen-osk-key-tsv)
            # Forward EVERYTHING after the verb: passing only $1 and $2 silently
            # dropped --count/--no-digits/--symbols/--group, so those options
            # appeared to work while having no effect at all.
            if [[ "${1:-}" == --* ]]; then
                wl_osk_key "" "" "$@"          # flags only, defaults apply
            else
                wl_osk_key "${1:-}" "${2:-}" "${@:3}"
            fi ;;
        --selftest)           wl_selftest && wl_selftest_patterns ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --list-tsv
  --rules-tsv
  --download URL [NAME]
  --install TMPPATH [NAME]
  --compose OUTPATH INPUT1 [INPUT2 ...]
  --compose-gz OUTPATH.gz INPUT1 [INPUT2 ...]
  --delete PATH
  --meta PATH
  --seclists-status
  --seclists-clone
  --seclists-update
  --seclists-list
  --patterns-tsv [ISP|--all]
  --gen-mask-tsv [ISP|--all]
  --gen-isp-tsv ISP [--ssid S] [--bssid M] [--serial N]
  --gen-sha1-serial-tsv NORMALISED_SERIAL
  --infer-pattern-tsv SAMPLES.tsv
  --gen-osk-key-tsv [LENGTH] [MAX-SWITCHES] [OPTIONS]
        Create a PSK that is random but typeable on a TV remote. Not a
        wordlist source: the output is random, so it cannot be guessed.
        --count N         emit N keys (1-100)
        --no-digits       letters only
        --min-digits N    guarantee at least N digits
        --min-upper N     guarantee at least N uppercase letters
        --symbols         add a symbol class and guarantee at least one
        --group N         dash-group every N characters for readability
        --allow-ambiguous include O/0/i/1 lookalikes (default: excluded)
  --selftest
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    WIFISTING_CLI=1
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    command -v err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    wl_cli_main "$@"
fi

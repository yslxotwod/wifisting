#!/usr/bin/env bash
# 08_pmkid_offline — PMKID / EAPOL cracking pipeline
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
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$WORDLISTS_DIR" 2>/dev/null

# Crack sessions hold the hashfile, potfile, and cracked.txt — all
# things you want to keep past a reboot. Store them in loot/.
export CRACK_DIR="$LOOT_DIR/pmkid_sessions"
mkdir -p "$CRACK_DIR"

# One-time migration from the old /tmp location.
pmkid_migrate_sessions() {
    local src="$TMP_DIR/crack_sessions"
    [[ -d "$src" ]] || return 0
    [[ "$src" == "$CRACK_DIR" ]] && return 0
    local d base count=0
    shopt -s nullglob
    for d in "$src"/*/; do
        base=$(basename "$d")
        if [[ ! -e "$CRACK_DIR/$base" ]]; then
            mv "$d" "$CRACK_DIR/$base" 2>/dev/null && count=$((count + 1))
        fi
    done
    shopt -u nullglob
    [[ $count -gt 0 ]] && \
        printf '[info] migrated %d session(s) to %s\n' "$count" "$CRACK_DIR" >&2
    return 0
}

# ── deterministic session naming ──
# Old scheme: crack_$(date +%s)_$$ → orphan on resume from another
# invocation because $$ differs. New scheme uses a sha256 of the
# hashfile so the same input always maps to the same session dir.
pmkid_session_id_for_hash() {
    local h="$1"
    local base
    base=$(basename "$h" | sed 's/[^A-Za-z0-9._-]/_/g')
    local digest
    digest=$(sha256sum "$h" 2>/dev/null | cut -c1-12)
    printf 'crack_%s_%s\n' "$digest" "${base%.22000}"
}

pmkid_find_wordlists() {
    local -a candidates=(
        "$WORDLISTS_DIR/rockyou.txt"
        "/usr/share/wordlists/rockyou.txt"
        "/usr/share/wordlists/rockyou.txt.gz"
        "$WORDLISTS_DIR/probable-v2-wpa-top4800000.txt"
        "$WORDLISTS_DIR/probable-v2-top12000.txt"
        "/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800000.txt"
        "$WORDLISTS_DIR/wpa-passwords.txt"
    )
    FOUND_WORDLISTS=()
    for w in "${candidates[@]}"; do
        [[ -f "$w" ]] && FOUND_WORDLISTS+=("$w")
    done
    if [[ ! -f "$WORDLISTS_DIR/rockyou.txt" && -f "/usr/share/wordlists/rockyou.txt.gz" ]]; then
        info "extracting rockyou.txt.gz"
        gunzip -k -c /usr/share/wordlists/rockyou.txt.gz > "$WORDLISTS_DIR/rockyou.txt"
        FOUND_WORDLISTS+=("$WORDLISTS_DIR/rockyou.txt")
    fi
}

pmkid_find_rules() {
    local -a candidates=(
        "/usr/share/hashcat/rules/best64.rule"
        "/usr/share/hashcat/rules/rockyou-30000.rule"
        "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule"
        "/usr/share/hashcat/rules/d3ad0ne.rule"
    )
    FOUND_RULES=()
    for r in "${candidates[@]}"; do
        [[ -f "$r" ]] && FOUND_RULES+=("$r")
    done
}

# ── hashfile quality check ──
# hcxpcapngtool sometimes writes partial hashes that hashcat rejects.
# We test each line with `hashcat --show` (returns per-line validity).
pmkid_hash_quality() {
    local h="$1"
    [[ ! -f "$h" ]] && { printf 'ERROR\tno file\n' >&2; return 1; }
    local total valid invalid
    # Count records with awk, not `wc -l`: wc undercounts a final line that
    # has no trailing newline, which made INVALID negative.
    total=$(awk 'END{print NR+0}' "$h")
    # hashcat needs mode 22000; if the format is wrong, everything fails
    local ok
    ok=$(hashcat -m 22000 --show "$h" 2>&1 | head -1)
    # crude: count lines that parse as 22000. Mode 22000 is '*' separated
    # (WPA*02*PMKID*MAC_AP*MAC_STA*ESSID*NONCE*EAPOL*MESSAGEPAIR), not ':'
    # separated, so a -F: test called every valid hash malformed.
    valid=$(awk -F'*' 'NF>=5' "$h" | wc -l)
    invalid=$((total - valid))
    printf 'TOTAL\t%s\nVALID\t%s\nINVALID\t%s\n' "$total" "$valid" "$invalid"
    (( invalid > 0 )) && printf 'WARN\t%s malformed line(s) — will be ignored by hashcat\n' "$invalid"
    return 0
}

pmkid_convert_capture() {
    local infile="$1" outfile="$2"
    info "converting $infile → $outfile"
    hcxpcapngtool -o "$outfile" "$infile" 2>&1 | tee -a "$CRACK_DIR/convert.log"
    [[ ! -s "$outfile" ]] && {
        err "no PMKID/EAPOL in capture"; return 1; }
    local count
    count=$(wc -l < "$outfile")
    ok "extracted $count hash line(s)"
    return 0
}

# ── session management ──

pmkid_new_session() {
    local hashfile="$1"
    local sid
    sid=$(pmkid_session_id_for_hash "$hashfile")
    local sdir="$CRACK_DIR/$sid"

    # If it exists already, treat as a resume rather than overwrite
    if [[ -d "$sdir" && -f "$sdir/state" ]]; then
        printf 'EXISTING\t%s\n' "$sid"
        echo "$sid"
        return 0
    fi

    mkdir -p "$sdir"
    cp "$hashfile" "$sdir/hashes.hc22000"
    cat > "$sdir/state" <<EOF
SESSION_ID=$sid
HASHFILE=$sdir/hashes.hc22000
STAGE=0
STARTED=$(date +%s)
STATUS=queued
EOF
    echo "$sid"
}

pmkid_list_sessions() {
    echo ""
    printf "  %-45s %-10s %s\n" "SESSION_ID" "STATUS" "STAGE"
    printf "  %-45s %-10s %s\n" "----------" "------" "-----"
    for s in "$CRACK_DIR"/*/state; do
        [[ -f "$s" ]] || continue
        # shellcheck source=/dev/null
        ( . "$s" && printf "  %-45s %-10s %s\n" "$SESSION_ID" "$STATUS" "$STAGE" )
    done
    echo ""
}

pmkid_update_state() {
    local sdir="$1" key="$2" val="$3"
    sed -i "s|^${key}=.*|${key}=${val}|" "$sdir/state"
}

# ── stage runner ──
# 0: rockyou straight
# 1: probable-v2 straight
# 2: rockyou + best64 rules
# 3: rockyou + OneRuleToRuleThemAll (heavy)
# 4: hybrid rockyou + 4-digit mask
# 5: mask attack — common WPA patterns (8 digits, 4+4 letters, etc)
# 6: hybrid rockyou + 2-digit mask (short PIN-style)
pmkid_run_stage() {
    local sdir="$1" stage="$2"
    # shellcheck source=/dev/null
    . "$sdir/state"
    pmkid_find_wordlists
    pmkid_find_rules

    local hc_common=(-m 22000 --session "$SESSION_ID" \
        --status --status-timer=10 \
        --potfile-path "$sdir/potfile" \
        --outfile "$sdir/cracked.txt" \
        --restore-file-path "$sdir/$SESSION_ID.restore")

    case "$stage" in
        0)
            [[ -z "${FOUND_WORDLISTS[0]}" ]] && { warn "no rockyou-tier wordlist"; return 2; }
            info "stage 0: straight ${FOUND_WORDLISTS[0]}"
            hashcat "${hc_common[@]}" -a 0 "$HASHFILE" "${FOUND_WORDLISTS[0]}"
            ;;
        1)
            local pv2=""
            for w in "${FOUND_WORDLISTS[@]}"; do
                [[ "$w" =~ probable ]] && pv2="$w" && break
            done
            [[ -z "$pv2" ]] && { warn "no probable-v2 list"; return 2; }
            info "stage 1: straight $pv2"
            hashcat "${hc_common[@]}" -a 0 "$HASHFILE" "$pv2"
            ;;
        2)
            local best64=""
            for r in "${FOUND_RULES[@]}"; do
                [[ "$r" =~ best64 ]] && best64="$r" && break
            done
            [[ -z "$best64" || -z "${FOUND_WORDLISTS[0]}" ]] && { warn "missing rockyou/best64"; return 2; }
            info "stage 2: rockyou + best64"
            hashcat "${hc_common[@]}" -a 0 -r "$best64" "$HASHFILE" "${FOUND_WORDLISTS[0]}"
            ;;
        3)
            local onerule=""
            for r in "${FOUND_RULES[@]}"; do
                [[ "$r" =~ OneRule ]] && onerule="$r" && break
            done
            [[ -z "$onerule" || -z "${FOUND_WORDLISTS[0]}" ]] && { warn "missing OneRule/rockyou"; return 2; }
            warn "stage 3: rockyou + OneRuleToRuleThemAll (slow, hours+)"
            hashcat "${hc_common[@]}" -a 0 -r "$onerule" "$HASHFILE" "${FOUND_WORDLISTS[0]}"
            ;;
        4)
            info "stage 4: hybrid rockyou + ?d?d?d?d"
            hashcat "${hc_common[@]}" -a 6 "$HASHFILE" "${FOUND_WORDLISTS[0]}" '?d?d?d?d'
            ;;
        5)
            info "stage 5: mask attack — WPA-likely patterns"
            # Common WPA password shapes:
            #   ?d?d?d?d?d?d?d?d          (8 digits — 10^8)
            #   ?l?l?l?l?d?d?d?d          (4 letters + 4 digits)
            #   ?u?l?l?l?l?l?l?d?d        (Camelword + 2 digits)
            #   ?d?d?d?d?l?l?l?l          (4 digits + 4 letters)
            local -a masks=(
                "?d?d?d?d?d?d?d?d"
                "?l?l?l?l?d?d?d?d"
                "?d?d?d?d?l?l?l?l"
                "?u?l?l?l?l?l?l?d?d"
                "?l?l?l?l?l?l?l?l?d?d"
            )
            local m
            for m in "${masks[@]}"; do
                info "  mask: $m"
                hashcat "${hc_common[@]}" -a 3 "$HASHFILE" "$m" && break
                if [[ -s "$sdir/cracked.txt" ]]; then break; fi
            done
            ;;
        6)
            info "stage 6: hybrid rockyou + ?d?d"
            hashcat "${hc_common[@]}" -a 6 "$HASHFILE" "${FOUND_WORDLISTS[0]}" '?d?d'
            ;;
        *)
            err "unknown stage $stage"; return 3 ;;
    esac
    local rc=$?
    pmkid_update_state "$sdir" STAGE "$stage"
    return $rc
}

pmkid_autotune() {
    info "hashcat -w 3 autotune probe (60s)…"
    timeout 60 hashcat -b -m 22000 -w 3 2>&1 | tail -20
}

pmkid_run_full_chain() {
    local sdir="$1"
    pmkid_update_state "$sdir" STATUS "running"
    for stage in 0 1 2 3 4 5 6; do
        info "=== stage $stage ==="
        pmkid_run_stage "$sdir" "$stage"
        if [[ -s "$sdir/cracked.txt" ]]; then
            ok "cracked! results in $sdir/cracked.txt"
            cat "$sdir/cracked.txt"
            pmkid_update_state "$sdir" STATUS "cracked"
            return 0
        fi
    done
    warn "chain exhausted without a crack"
    pmkid_update_state "$sdir" STATUS "exhausted"
    return 1
}

pmkid_resume_session() {
    local sid="$1"; local sdir="$CRACK_DIR/$sid"
    [[ ! -d "$sdir" ]] && { err "no such session"; return 1; }
    # shellcheck source=/dev/null
    . "$sdir/state"
    if [[ -f "$sdir/$SESSION_ID.restore" ]]; then
        info "resuming hashcat session $SESSION_ID"
        hashcat --session "$SESSION_ID" --restore \
            --restore-file-path "$sdir/$SESSION_ID.restore"
    else
        warn "no restore file, continuing chain from stage $STAGE"
        pmkid_run_full_chain "$sdir"
    fi
}

# ── menu ──
pmkid_menu() {
    while true; do
        banner 2>/dev/null || clear
        cat << 'M'
  PMKID / EAPOL offline cracking

  [1] convert capture -> hc22000 and start new session
  [2] list sessions
  [3] resume session
  [4] run single stage on existing session
  [5] autotune probe (hashcat -b)
  [6] show cracked results
  [7] purge session
  [0] back

M
        read -rp "  choice> " c
        case "$c" in
            1)
                echo ""; ls -1 "$CAPTURES_DIR"/*.{pcapng,cap,pcap} 2>/dev/null | nl
                read -rp "  path (or number)> " sel
                if [[ "$sel" =~ ^[0-9]+$ ]]; then
                    sel=$(ls -1 "$CAPTURES_DIR"/*.{pcapng,cap,pcap} 2>/dev/null | sed -n "${sel}p")
                fi
                [[ ! -f "$sel" ]] && { err "not a file"; sleep 1; continue; }
                local tmphash="$TMP_DIR/convert_$$.hc22000"
                pmkid_convert_capture "$sel" "$tmphash" || { read -rp "  press enter" _; continue; }
                local sid; sid=$(pmkid_new_session "$tmphash" | tail -1)
                ok "created session $sid"
                read -rp "  run full chain now? [Y/n] " a
                [[ "$a" =~ ^[Nn]$ ]] || pmkid_run_full_chain "$CRACK_DIR/$sid"
                read -rp "  press enter" _
                ;;
            2) pmkid_list_sessions; read -rp "  press enter" _ ;;
            3)
                pmkid_list_sessions
                read -rp "  session id> " sid
                pmkid_resume_session "$sid"
                read -rp "  press enter" _
                ;;
            4)
                pmkid_list_sessions
                read -rp "  session id> " sid
                read -rp "  stage (0-6)> " st
                pmkid_run_stage "$CRACK_DIR/$sid" "$st"
                read -rp "  press enter" _
                ;;
            5) pmkid_autotune; read -rp "  press enter" _ ;;
            6)
                local found=0
                for f in "$CRACK_DIR"/*/cracked.txt; do
                    [[ -s "$f" ]] || continue
                    found=1; echo "== $f =="; cat "$f"
                done
                (( found == 0 )) && echo "(nothing cracked yet)"
                read -rp "  press enter" _
                ;;
            7)
                pmkid_list_sessions
                read -rp "  session id to purge> " sid
                rm -rf "${CRACK_DIR:?}/$sid"
                ok "purged"; sleep 1
                ;;
            0) return ;;
        esac
    done
}

# ── CLI ──

pmkid_cli_status_tsv() {
    local count=0 running=0 pid="" current=""
    count=$(find "$CRACK_DIR" -maxdepth 2 -name state 2>/dev/null | wc -l)
    if [[ -f "$TMP_DIR/pmkid.pid" ]]; then
        pid=$(cat "$TMP_DIR/pmkid.pid")
        kill -0 "$pid" 2>/dev/null && running=1
    fi
    [[ -f "$TMP_DIR/pmkid.current" ]] && current=$(cat "$TMP_DIR/pmkid.current")

    printf 'sessions\t%s\n' "$count"
    printf 'running\t%s\n'  "$running"
    printf 'pid\t%s\n'      "$pid"
    printf 'current\t%s\n'  "$current"
    printf 'loot_dir\t%s\n' "$CRACK_DIR"
}

pmkid_cli_list_sessions_tsv() {
    for s in "$CRACK_DIR"/*/state; do
        [[ -f "$s" ]] || continue
        local sid stage status started hashfile
        sid=$(awk -F= '/^SESSION_ID=/{print $2}' "$s")
        stage=$(awk -F= '/^STAGE=/{print $2}' "$s")
        status=$(awk -F= '/^STATUS=/{print $2}' "$s")
        started=$(awk -F= '/^STARTED=/{print $2}' "$s")
        hashfile=$(awk -F= '/^HASHFILE=/{print $2}' "$s")
        printf '%s\t%s\t%s\t%s\t%s\n' \
            "$sid" "$status" "$stage" "$started" "$hashfile"
    done
}

pmkid_cli_start_session() {
    local hashfile="$1"
    [[ -z "$hashfile" || ! -s "$hashfile" ]] && {
        printf 'missing or empty hash file\n' >&2; return 2; }

    # Quality check
    printf 'QUALITY\n'
    pmkid_hash_quality "$hashfile"

    local sid
    sid=$(pmkid_new_session "$hashfile" | tail -1)
    printf '%s' "$sid" > "$TMP_DIR/pmkid.current"
    echo $$ > "$TMP_DIR/pmkid.pid"
    trap 'rm -f "$TMP_DIR/pmkid.pid"' EXIT
    printf 'SESSION\t%s\n' "$sid"
    pmkid_run_full_chain "$CRACK_DIR/$sid"
    rm -f "$TMP_DIR/pmkid.pid" "$TMP_DIR/pmkid.current"
}

pmkid_cli_resume_session() {
    local sid="$1"
    [[ -z "$sid" ]] && { printf 'missing session id\n' >&2; return 2; }
    echo $$ > "$TMP_DIR/pmkid.pid"
    trap 'rm -f "$TMP_DIR/pmkid.pid"' EXIT
    pmkid_resume_session "$sid"
    rm -f "$TMP_DIR/pmkid.pid"
}

pmkid_cli_run_stage() {
    local sid="$1" stage="$2"
    [[ -z "$sid" || -z "$stage" ]] && {
        printf 'usage: --run-stage SESSION_ID STAGE(0-6)\n' >&2; return 2; }
    pmkid_run_stage "$CRACK_DIR/$sid" "$stage"
}

pmkid_cli_autotune() { pmkid_autotune; }

pmkid_cli_convert() {
    local infile="$1" outfile="$2"
    [[ -z "$infile" || -z "$outfile" ]] && {
        printf 'usage: --convert INFILE OUTFILE\n' >&2; return 2; }
    pmkid_convert_capture "$infile" "$outfile" || return 1
    printf 'HASHFILE\t%s\n' "$outfile"
}

pmkid_cli_quality() {
    local h="$1"
    [[ -z "$h" ]] && { printf 'usage: --quality HASHFILE\n' >&2; return 2; }
    pmkid_hash_quality "$h"
}

pmkid_cli_show_cracked() {
    local any=0
    for f in "$CRACK_DIR"/*/cracked.txt; do
        [[ -s "$f" ]] || continue
        any=1
        printf '=== %s ===\n' "$f"
        cat "$f"
    done
    (( any == 0 )) && printf 'NONE\n'
}

pmkid_cli_purge_session() {
    local sid="$1"
    [[ -z "$sid" ]] && { printf 'missing session id\n' >&2; return 2; }
    [[ "$sid" =~ ^[a-zA-Z0-9_-]+$ ]] || {
        printf 'invalid session id\n' >&2; return 2; }
    rm -rf "${CRACK_DIR:?}/$sid"
    printf 'PURGED\t%s\n' "$sid"
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: hashcat is never asked to crack anything, no radio, no root.
# CRACK_DIR is redirected to a scratch tree under $TMP_DIR so the real
# loot/pmkid_sessions (and the real capture at loot/captures/hashes) are
# never read or written.
pmkid_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    pfld() { awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }

    local MOD_TMP="$TMP_DIR/pmkid_selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/sessions"
    local save_crack="$CRACK_DIR" save_tmp="$TMP_DIR"
    CRACK_DIR="$MOD_TMP/sessions"

    # ── deterministic session id: same bytes -> same directory ──
    # sha256("WPA*01*0123...4944***\n") starts 0dab6ca84601
    local hf="$MOD_TMP/capture.22000"
    printf '%s\n' 'WPA*01*0123456789abcdef0123456789abcdef*001122334455*aabbccddeeff*5468697349734153534944***' > "$hf"
    local sid1 sid2
    sid1=$(pmkid_session_id_for_hash "$hf")
    sid2=$(pmkid_session_id_for_hash "$hf")
    chk session-id-exact "$sid1" "crack_0dab6ca84601_capture"
    chk session-id-deterministic "$sid1" "$sid2"
    chk session-id-filesystem-safe "$(grep -cE '^[A-Za-z0-9._-]+$' <<<"$sid1")" "1"

    # sha256("x") starts 2d711642b726; the basename is sanitised for the fs.
    local hf2="$MOD_TMP/my capture (1).22000"
    printf 'x' > "$hf2"
    chk session-id-sanitised "$(pmkid_session_id_for_hash "$hf2")" \
        "crack_2d711642b726_my_capture__1_"
    # Different bytes must not collide in the same session.
    chk session-id-content-sensitive \
        "$([[ "$(pmkid_session_id_for_hash "$hf")" != "$(pmkid_session_id_for_hash "$hf2")" ]] && echo differ || echo same)" \
        "differ"

    # ── session creation is a resume, not an overwrite ──
    local created
    created=$(pmkid_new_session "$hf" | tail -1)
    chk session-created "$created" "$sid1"
    local sdir="$CRACK_DIR/$sid1"
    chk session-dir "$([[ -d "$sdir" ]] && echo yes || echo no)" "yes"
    chk session-hashfile-copied "$(cmp -s "$hf" "$sdir/hashes.hc22000" && echo same || echo differ)" "same"
    chk session-state-id "$(awk -F= '$1=="SESSION_ID"{print $2}' "$sdir/state")" "$sid1"
    chk session-state-stage "$(awk -F= '$1=="STAGE"{print $2}' "$sdir/state")" "0"
    chk session-state-status "$(awk -F= '$1=="STATUS"{print $2}' "$sdir/state")" "queued"
    chk session-state-hashfile "$(awk -F= '$1=="HASHFILE"{print $2}' "$sdir/state")" "$sdir/hashes.hc22000"

    local second
    second=$(pmkid_new_session "$hf")
    chk session-resume-signal "$(head -1 <<<"$second")" "$(printf 'EXISTING\t%s' "$sid1")"
    chk session-resume-same-id "$(tail -1 <<<"$second")" "$sid1"

    # ── state updates are visible to the lister (it sources the file) ──
    pmkid_update_state "$sdir" STATUS cracked
    pmkid_update_state "$sdir" STAGE 5
    chk update-state-status "$(awk -F= '$1=="STATUS"{print $2}' "$sdir/state")" "cracked"
    chk update-state-stage "$(awk -F= '$1=="STAGE"{print $2}' "$sdir/state")" "5"
    # The update must rewrite, not append.
    chk update-state-no-duplicate "$(grep -c '^STATUS=' "$sdir/state")" "1"
    local ls
    ls=$(pmkid_list_sessions)
    chk list-sessions-row "$(grep -c "$sid1" <<<"$ls")" "1"
    chk list-sessions-status "$(grep -c 'cracked' <<<"$ls")" "1"

    # ── stage dispatch: an unknown stage is refused, not silently run ──
    local rc=0
    pmkid_run_stage "$sdir" 99 >/dev/null 2>&1 || rc=$?
    chk run-stage-unknown-rc "$rc" "3"
    chk run-stage-unknown-kept-state "$(awk -F= '$1=="STATUS"{print $2}' "$sdir/state")" "cracked"

    # ── hashfile quality accounting ──
    local qf="$MOD_TMP/mixed.22000" q
    # A real-shaped hashcat mode 22000 line: nine '*' separated fields
    # (WPA*02*PMKID*MAC_AP*MAC_STA*ESSID*NONCE*EAPOL*MESSAGEPAIR). Counting
    # valid lines with -F: classified this as malformed.
    local h22000='WPA*02*4d1f4d5e0e1a2b3c4d5e6f708192a3b4*001122334455*aabbccddeeff*486f6d654e6574*11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff*0103007502010a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*02'
    chk quality-real-line-sep "$(printf '%s\n' "$h22000" | awk -F'*' 'END{print NF}')" "9"
    chk quality-real-line-colons "$(printf '%s\n' "$h22000" | awk -F: 'END{print NF}')" "1"
    printf '%s\n' "$h22000" "$h22000" "$h22000" 'malformed' 'not-a-22000-line' > "$qf"
    q=$(pmkid_hash_quality "$qf")
    chk quality-total "$(pfld TOTAL <<<"$q")" "5"
    chk quality-valid "$(pfld VALID <<<"$q")" "3"
    chk quality-invalid "$(pfld INVALID <<<"$q")" "2"
    chk quality-accounting "$(awk -F'\t' '$1=="TOTAL"{t=$2} $1=="VALID"{v=$2} $1=="INVALID"{i=$2}
                                         END{printf "%s", (t==v+i) ? "consistent" : "broken"}' <<<"$q")" \
        "consistent"
    chk quality-warns-on-invalid "$(grep -c '^WARN' <<<"$q")" "1"
    # The real verdict for a genuinely valid 22000 file: all VALID, no WARN.
    printf '%s\n' "$h22000" > "$qf"
    q=$(pmkid_hash_quality "$qf")
    chk quality-real-valid   "$(pfld VALID <<<"$q")"   "1"
    chk quality-real-invalid "$(pfld INVALID <<<"$q")" "0"
    chk quality-real-no-warn "$(grep -c 'WARN' <<<"$q")" "0"
    # A final line with no trailing newline is still a line: `wc -l`
    # undercounted it and INVALID came out negative.
    printf '%s' "$h22000" > "$qf"
    q=$(pmkid_hash_quality "$qf")
    chk quality-nonl-total   "$(pfld TOTAL <<<"$q")"   "1"
    chk quality-nonl-valid   "$(pfld VALID <<<"$q")"   "1"
    chk quality-nonl-invalid "$(pfld INVALID <<<"$q")" "0"
    chk quality-nonl-accounting "$(awk -F'\t' '$1=="TOTAL"{t=$2} $1=="VALID"{v=$2} $1=="INVALID"{i=$2}
                                         END{printf "%s", (t==v+i && i>=0) ? "consistent" : "broken"}' <<<"$q")" \
        "consistent"
    printf '%s\n%s' "$h22000" 'malformed' > "$qf"
    q=$(pmkid_hash_quality "$qf")
    chk quality-nonl-mixed-invalid "$(pfld INVALID <<<"$q")" "1"
    printf '%s\n' "$h22000" "$h22000" > "$qf"
    q=$(pmkid_hash_quality "$qf")
    chk quality-invalid-zero "$(pfld INVALID <<<"$q")" "0"
    chk quality-no-warn "$(grep -c 'WARN' <<<"$q")" "0"
    rc=0; pmkid_hash_quality "$MOD_TMP/nope.22000" >/dev/null 2>&1 || rc=$?
    chk quality-missing-file-rc "$rc" "1"

    # ── wordlist/rule discovery must only return paths that exist ──
    pmkid_find_wordlists
    local w missing=0
    for w in ${FOUND_WORDLISTS[@]+"${FOUND_WORDLISTS[@]}"}; do
        [[ -f "$w" ]] || missing=$((missing+1))
    done
    chk wordlists-exist "$missing" "0"
    pmkid_find_rules
    local r
    missing=0
    for r in ${FOUND_RULES[@]+"${FOUND_RULES[@]}"}; do
        [[ -f "$r" ]] || missing=$((missing+1))
    done
    chk rules-exist "$missing" "0"

    # ── purge guards against path escape ──
    rc=0; pmkid_cli_purge_session '../../etc' >/dev/null 2>&1 || rc=$?
    chk purge-traversal-rc "$rc" "2"
    rc=0; pmkid_cli_purge_session '' >/dev/null 2>&1 || rc=$?
    chk purge-empty-rc "$rc" "2"
    chk purge-traversal-noop "$([[ -d "$sdir" ]] && echo intact || echo destroyed)" "intact"
    chk purge-valid "$(pmkid_cli_purge_session "$sid1")" "$(printf 'PURGED\t%s' "$sid1")"
    chk purge-removed "$([[ -d "$sdir" ]] && echo present || echo gone)" "gone"

    # ── one-time migration out of the old /tmp location ──
    TMP_DIR="$MOD_TMP"
    mkdir -p "$MOD_TMP/crack_sessions/old_session"
    printf 'SESSION_ID=old_session\n' > "$MOD_TMP/crack_sessions/old_session/state"
    pmkid_migrate_sessions >/dev/null 2>&1
    chk migrate-moved "$([[ -f "$CRACK_DIR/old_session/state" ]] && echo yes || echo no)" "yes"
    chk migrate-source-gone "$([[ -d "$MOD_TMP/crack_sessions/old_session" ]] && echo still || echo gone)" "gone"
    TMP_DIR="$save_tmp"

    # ── TSV status contract ──
    local st
    st=$(pmkid_cli_status_tsv)
    chk status-tsv-rows "$(grep -c . <<<"$st")" "5"
    chk status-tsv-loot-dir "$(pfld loot_dir <<<"$st")" "$CRACK_DIR"
    chk status-tsv-sessions "$(pfld sessions <<<"$st")" "1"
    rc=0; pmkid_cli_main --no-such-flag >/dev/null 2>&1 || rc=$?
    chk unknown-command-rc "$rc" "2"

    CRACK_DIR="$save_crack"
    rm -rf "$MOD_TMP"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

pmkid_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)        pmkid_cli_status_tsv ;;
        --list-sessions-tsv) pmkid_cli_list_sessions_tsv ;;
        --start-session)     pmkid_cli_start_session "$@" ;;
        --resume)            pmkid_cli_resume_session "$@" ;;
        --run-stage)         pmkid_cli_run_stage "$@" ;;
        --autotune)          pmkid_cli_autotune ;;
        --convert)           pmkid_cli_convert "$@" ;;
        --quality)           pmkid_cli_quality "$@" ;;
        --show-cracked)      pmkid_cli_show_cracked ;;
        --purge)             pmkid_cli_purge_session "$@" ;;
        --selftest)          pmkid_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --list-sessions-tsv
  --start-session HASHFILE
  --resume SESSION_ID
  --run-stage SESSION_ID STAGE(0-6)
  --autotune
  --convert INFILE OUTFILE
  --quality HASHFILE
  --show-cracked
  --purge SESSION_ID
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
    : "${WORDLISTS_DIR:=$HOME/wifisting/wordlists}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$WORDLISTS_DIR"
    CRACK_DIR="$LOOT_DIR/pmkid_sessions"
    mkdir -p "$CRACK_DIR"
    pmkid_migrate_sessions
    pmkid_cli_main "$@"
fi

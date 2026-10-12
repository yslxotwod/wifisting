#!/usr/bin/env bash
# =====================================================================
#  diag.sh — diagnostic report for bug reports
#
#  Collects what a maintainer needs to debug a failure, with every
#  network identifier removed before anything is written.
#
#  Why redaction is not optional: a tester debugging a detection bug
#  would otherwise have to send BSSIDs and SSIDs of whatever was in
#  range, which is their neighbours' data, not theirs. Asking for that
#  to fix a bug is a bad trade and careful people just do not reply.
#
#  The report reads system state only. It never opens loot/, so it
#  cannot leak a capture even by accident.
#
#  Usage:
#    tools/diag.sh --collect [FILE]        full report
#    tools/diag.sh --redact FILE           scrub an existing log
#    tools/diag.sh --compare MODULE VERB   GUI vs bare-shell divergence
#    tools/diag.sh --selftest
# =====================================================================

set -uo pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ROOT="${WIFISTING_ROOT:-$(cd -P "$(dirname "$SELF")/.." && pwd)}"
export WIFISTING_ROOT="$ROOT"

DIAG_TMP="${TMP_DIR:-/tmp/wifisting}/diag"
mkdir -p "$DIAG_TMP" 2>/dev/null

# ── redaction ─────────────────────────────────────────────────────────
#
# Two rules, and the difference matters:
#
#   Consistent mapping  - the same MAC becomes the same placeholder
#                         everywhere, so a maintainer can still see
#                         "adapter A talked to adapter B" without
#                         knowing who either is.
#   Blanket removal     - secrets get no placeholder at all. There is
#                         no debugging value in a passphrase, and a
#                         consistent map would still be a map.
#
# State files hold the maps so one run is internally consistent.
diag_redact_stream() {
    local macmap="$DIAG_TMP/macs.tsv" ssidmap="$DIAG_TMP/ssids.tsv"
    local py="$DIAG_TMP/redact.py"

    # The filter lives in a file rather than a heredoc. A heredoc IS
    # stdin, so `python3 - <<'PY'` consumed the script and left nothing
    # for the piped data to arrive on - the filter produced no output at
    # all, which the tests below caught.
    if [[ ! -s "$py" ]]; then
        cat > "$py" <<'PYFILTER'
import re, sys

macmap, ssidmap = sys.argv[1], sys.argv[2]
macs, ssids = {}, {}
mac_n = ssid_n = 0

def map_mac(m):
    global mac_n
    key = m.group(0).lower()
    if key not in macs:
        mac_n += 1
        macs[key] = "mac:%02d" % mac_n
    return macs[key]

def map_ssid(m):
    global ssid_n
    key = m.group(3)
    if key.lower() in ("hidden", ""):
        return m.group(0)
    if key not in ssids:
        ssid_n += 1
        ssids[key] = "ssid:%02d" % ssid_n
    return "%s%s%s" % (m.group(1), m.group(2), ssids[key])

MAC  = re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b')
SSID = re.compile(r'(?i)\b(ssid|essid|network[_ ]?name)(\s*[:=]\s*|["\'])([^"\'\s,;]{1,32})')
IP4  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
IP6  = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b')
# A secret gets no placeholder: there is no debugging value in a
# passphrase, and a consistent map would still be a map.
SECRET = re.compile(
    r'(?i)\b(pass(?:word|phrase)?|psk|pin|secret|token|api[_-]?key|'
    r'wpa[_-]?key|netkey|network[_-]?key|credential)\b(\s*[:=]\s*)(\S+)')

for line in sys.stdin:
    line = SECRET.sub(lambda m: "%s%s<redacted>" % (m.group(1), m.group(2)), line)
    line = MAC.sub(map_mac, line)
    line = SSID.sub(map_ssid, line)
    # Private ranges stay: they show topology, not identity.
    line = IP4.sub(lambda m: m.group(0)
                   if m.group(0).startswith(("10.", "192.168.", "127.", "172."))
                   else "ip:<redacted>", line)
    line = IP6.sub(lambda m: m.group(0)
                   if m.group(0).lower().startswith(("fe80", "fd"))
                   else "ip6:<redacted>", line)
    sys.stdout.write(line)

with open(macmap, "w") as fh:
    for k, v in sorted(macs.items(), key=lambda x: x[1]):
        fh.write("%s\t%s\n" % (v, k))
PYFILTER
    fi

    : > "$macmap"; : > "$ssidmap"
    python3 "$py" "$macmap" "$ssidmap"
}

diag_cli_redact() {
    local f="${1:-}"
    [[ -z "$f" ]] && { printf 'ERROR\tno file given\n' >&2; return 2; }
    [[ -f "$f" ]] || { printf 'ERROR\tno such file: %s\n' "$f" >&2; return 1; }
    diag_redact_stream < "$f"
}

# ── system ────────────────────────────────────────────────────────────
diag_system() {
    printf '## system\n\n'
    printf 'generated\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'hostname\t<redacted>\n'

    if [[ -r /etc/os-release ]]; then
        local id name ver
        id=$(awk -F= '/^ID=/{gsub(/"/,"",$2); print $2}' /etc/os-release)
        name=$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2); print $2}' /etc/os-release)
        ver=$(awk -F= '/^VERSION_ID=/{gsub(/"/,"",$2); print $2}' /etc/os-release)
        printf 'distro\t%s\n' "${name:-$id}"
        printf 'distro_id\t%s\n' "${id:-unknown}"
        printf 'distro_version\t%s\n' "${ver:-unknown}"
    else
        printf 'distro\tunknown\n'
    fi

    printf 'kernel\t%s\n' "$(uname -r)"
    printf 'arch\t%s\n' "$(uname -m)"
    printf 'session\t%s\n' "${XDG_SESSION_TYPE:-unknown}"
    printf 'desktop\t%s\n' "${XDG_CURRENT_DESKTOP:-unknown}"

    if command -v pkg-config >/dev/null 2>&1; then
        printf 'gtk4\t%s\n' "$(pkg-config --modversion gtk4 2>/dev/null || echo absent)"
    else
        printf 'gtk4\tpkg-config missing\n'
    fi
    printf 'python3\t%s\n' "$(python3 -V 2>&1 | awk '{print $2}')"
    printf 'scapy\t%s\n' "$(python3 -c 'import scapy; print(scapy.__version__)' 2>/dev/null || echo absent)"
    printf '\n'
}

# ── adapters ──────────────────────────────────────────────────────────
#
# Capability, not just presence. "Does it see my card" is the wrong
# question - the useful one is "can this card inject", because that is
# what decides whether most of the toolkit will do anything.
diag_adapters() {
    printf '## adapters\n\n'
    local found=0
    for i in /sys/class/net/*; do
        local name; name=$(basename "$i")
        [[ "$name" =~ ^(wl|wlan|mon|ath|phy) ]] || continue
        found=1

        local driver bands type mon inj
        driver=$(basename "$(readlink -f "$i/device/driver" 2>/dev/null)" 2>/dev/null)
        type=$(iw dev "$name" info 2>/dev/null | awk '/type/{print $2}')
        mon=$(iw phy "$(iw dev "$name" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')" info 2>/dev/null \
              | grep -c 'monitor' || echo 0)

        # Bands from the phy's channel list. Read-only, safe to run.
        bands=$(iw phy "$(iw dev "$name" info 2>/dev/null | awk '/wiphy/{print "phy"$2}')" info 2>/dev/null \
                | awk '/\[[0-9]+\] MHz/{f=$2+0; if (f<3000) b24=1; else if (f>4900) b5=1}
                       END { s=""; if (b24) s="2.4"; if (b5) s=s (s?"+":"") "5"; print (s?s:"unknown") }')

        # Injection is a property of the driver. Probing it for real
        # means transmitting, which this tool must not do, so this
        # reports the known answer rather than a tested one.
        case "$driver" in
            ath9k_htc|ath9k|carl9170|rt2800usb|mt76*) inj="likely" ;;
            iwlwifi|iwlwifi_*|ath10k*|ath11k*|ath12k*|rtw88*|rtw89*|brcmfmac|mt7921*)
                inj="no (driver does not inject)" ;;
            "")  inj="unknown (no driver bound)" ;;
            *)   inj="unknown" ;;
        esac

        printf 'adapter\t%s\n' "$name"
        printf '  mac\t%s\n' "$(cat "$i/address" 2>/dev/null || echo none)"
        printf '  driver\t%s\n' "${driver:-none}"
        printf '  type\t%s\n' "${type:-unknown}"
        printf '  bands\t%s GHz\n' "$bands"
        printf '  monitor_supported\t%s\n' "$( (( mon > 0 )) && echo yes || echo no)"
        printf '  injection\t%s\n' "$inj"
    done
    (( found == 0 )) && printf 'adapter\tnone found\n'
    printf '\n'
}

# ── dependencies ──────────────────────────────────────────────────────
diag_deps() {
    printf '## dependencies\n\n'
    local tools=(aircrack-ng aireplay-ng airodump-ng airmon-ng mdk4 hcxdumptool
                 hcxpcapngtool hostapd dnsmasq tshark tcpdump iw iwconfig nmcli
                 bully reaver pixiewps wash hashcat john crunch macchanger
                 responder mitm6 ntlmrelayx.py nmap avahi-browse mdns-scan
                 bettercap hcitool bluetoothctl gatttool)
    local have=0 miss=0
    for t in "${tools[@]}"; do
        local p
        p=$(command -v "$t" 2>/dev/null || true)
        if [[ -z "$p" && -x "$HOME/.local/bin/$t" ]]; then p="$HOME/.local/bin/$t"; fi
        if [[ -n "$p" ]]; then
            have=$(( have + 1 ))
            printf 'present\t%s\t%s\n' "$t" "$(basename "$p")"
        else
            miss=$(( miss + 1 ))
            printf 'missing\t%s\n' "$t"
        fi
    done
    printf '\nsummary\t%s present, %s missing\n\n' "$have" "$miss"
}

# ── module selftests ──────────────────────────────────────────────────
#
# The most useful single section: it shows whether each module agrees
# with itself on the tester's machine. A module can fail here with no
# hardware attached, which is exactly what makes it worth running.
diag_modules() {
    printf '## module selftests\n\n'
    local pass=0 fail=0 skip=0 total=0
    local m name out rc line
    for m in "$ROOT"/modules/*.sh; do
        [[ -f "$m" ]] || continue
        name=$(basename "$m" .sh)
        [[ "$name" == *".bak"* ]] && continue
        total=$(( total + 1 ))

        # Bounded: a module that hangs must not stall the report.
        out=$(timeout 25 bash "$m" --selftest 2>&1)
        rc=$?

        if (( rc == 124 )); then
            printf 'timeout\t%s\n' "$name"
            skip=$(( skip + 1 ))
            continue
        fi
        if ! grep -qE '^(PASS|FAIL|RESULT)' <<<"$out"; then
            printf 'noselftest\t%s\n' "$name"
            skip=$(( skip + 1 ))
            continue
        fi

        local np nf
        np=$(grep -c 'PASS' <<<"$out" || true)
        nf=$(grep -c 'FAIL' <<<"$out" || true)
        if (( nf > 0 )); then
            printf 'fail\t%s\t%s passed, %s failed\n' "$name" "$np" "$nf"
            grep 'FAIL' <<<"$out" | head -3 | sed 's/^/    /'
            fail=$(( fail + 1 ))
        else
            printf 'pass\t%s\t%s checks\n' "$name" "$np"
            pass=$(( pass + 1 ))
        fi
    done
    printf '\nsummary\t%s modules: %s pass, %s fail, %s skipped\n\n' \
        "$total" "$pass" "$fail" "$skip"
    printf 'TOTAL\t%d\t%d\t%d\n' "$total" "$fail" "$skip" >> "$DIAG_TMP/counts"
}

# ── GUI vs bare shell ─────────────────────────────────────────────────
#
# The reviewer's suggestion, and the best idea in the thread.
#
# Every module is a standalone script that the GUI also calls, so a
# check failing in both places versus only one localises the bug:
#
#   fails both ways      -> the module
#   fails only via GUI   -> argv construction, or the environment pkexec
#                           hands the module
#
# The environment half is the one that actually bites. pkexec resets
# PATH, so a tool in ~/.local/bin is visible from your shell and
# invisible to the module. That was a real bug in this project.
diag_compare() {
    local module="${1:-}" verb="${2:---status-tsv}"
    [[ -z "$module" ]] && { printf 'ERROR\tusage: --compare MODULE [VERB]\n' >&2; return 2; }

    local script="$ROOT/modules/${module}.sh"
    [[ -f "$script" ]] || { printf 'ERROR\tno such module: %s\n' "$module" >&2; return 1; }

    printf '## divergence: %s %s\n\n' "$module" "$verb"

    local direct sudoenv
    direct=$(cd "$ROOT" && timeout 25 bash "$script" "$verb" 2>&1)
    local drc=$?

    # Simulate what pkexec gives a module: a stripped environment with a
    # system PATH. No password needed, and it reproduces the real cause.
    sudoenv=$(cd "$ROOT" && timeout 25 env -i \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        HOME="${HOME:-/root}" \
        WIFISTING_ROOT="$ROOT" \
        bash "$script" "$verb" 2>&1)
    local src=$?

    printf 'direct_exit\t%s\n' "$drc"
    printf 'stripped_exit\t%s\n' "$src"

    if [[ "$direct" == "$sudoenv" ]]; then
        printf 'verdict\tidentical - no divergence\n'
    else
        printf 'verdict\tDIVERGENT\n'
        # Show the difference, redacted, so it is actionable.
        diff <(printf '%s\n' "$direct") <(printf '%s\n' "$sudoenv") 2>/dev/null \
            | head -20 | diag_redact_stream | sed 's/^/    /'
        printf '\n'
        printf 'likely\tPATH: tools in ~/.local/bin are visible to your shell\n'
        printf 'likely\tand not to a module started by pkexec\n'
    fi
    printf '\n'
}

# ── report ────────────────────────────────────────────────────────────
diag_cli_collect() {
    local out="${1:-}"
    : > "$DIAG_TMP/counts"

    {
        printf '# wifisting diagnostic report\n\n'
        printf 'Paste this into the issue. Network identifiers have been replaced.\n'
        printf 'Nothing from loot/ is included.\n\n'
        diag_system
        diag_adapters
        diag_deps
        diag_modules
        printf '## notes\n\n'
        printf 'injection column\t"likely" is inferred from the driver, not tested.\n'
        printf '\t\t\tTesting it means transmitting, which this tool does not do.\n'
    } | diag_redact_stream > "$DIAG_TMP/report.md"

    if [[ -n "$out" ]]; then
        cp "$DIAG_TMP/report.md" "$out"
        printf 'WROTE\t%s\n' "$out"
    else
        cat "$DIAG_TMP/report.md"
    fi
    printf 'SIZE\t%s\n' "$(wc -l < "$DIAG_TMP/report.md") lines" >&2
}

diag_selftest() {
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fi
    }

    # MACs become consistent placeholders
    local out
    out=$(printf 'aa:bb:cc:dd:ee:ff and aa:bb:cc:dd:ee:ff and 11:22:33:44:55:66\n' | diag_redact_stream 2>/dev/null)
    chk mac-consistent "$(grep -o 'mac:01' <<<"$out" | wc -l)" "2"
    chk mac-second "$(grep -c 'mac:02' <<<"$out")" "1"
    chk mac-gone "$(grep -c 'aa:bb:cc:dd:ee:ff' <<<"$out" || true)" "0"

    # SSIDs get replaced, not passed through
    out=$(printf 'ssid=MyNeighboursNetwork\n' | diag_redact_stream 2>/dev/null)
    chk ssid-replaced "$(grep -c 'MyNeighboursNetwork' <<<"$out" || true)" "0"
    chk ssid-placeholder "$(grep -c 'ssid:' <<<"$out")" "1"

    # secrets vanish entirely - no placeholder, because a passphrase has
    # no debugging value
    out=$(printf 'password=hunter2\npsk=deadbeefcafe\npin=12345678\n' | diag_redact_stream 2>/dev/null)
    chk secret-password "$(grep -c 'hunter2' <<<"$out" || true)" "0"
    chk secret-psk "$(grep -c 'deadbeefcafe' <<<"$out" || true)" "0"
    chk secret-pin "$(grep -c '12345678' <<<"$out" || true)" "0"
    chk secret-redacted "$(grep -c '<redacted>' <<<"$out")" "3"

    # private ranges stay (topology), public addresses go
    out=$(printf 'lan 192.168.1.10 and wan 88.174.22.9\n' | diag_redact_stream 2>/dev/null)
    chk private-kept "$(grep -c '192.168.1.10' <<<"$out")" "1"
    chk public-gone "$(grep -c '88.174.22.9' <<<"$out" || true)" "0"

    # a missing file is a usage error, not a crash
    diag_cli_redact "" >/dev/null 2>&1
    chk redact-noarg-rc "$?" "2"
    diag_cli_redact /nonexistent >/dev/null 2>&1
    chk redact-nofile-rc "$?" "1"

    # compare needs a real module
    diag_compare "" >/dev/null 2>&1
    chk compare-noarg-rc "$?" "2"
    diag_compare no_such_module >/dev/null 2>&1
    chk compare-badmodule-rc "$?" "1"

    # the report must run and produce the expected sections
    local rep="$DIAG_TMP/selftest-report.md"
    timeout 300 bash "$SELF" --collect "$rep" >/dev/null 2>&1
    if [[ -s "$rep" ]]; then
        chk report-produced ok ok
        for sec in '## system' '## adapters' '## dependencies' '## module selftests'; do
            grep -qF "$sec" "$rep" && chk "report-has-${sec##* }" ok ok \
                                  || chk "report-has-${sec##* }" missing ok
        done
        # and it must not have leaked the hostname
        chk report-hides-hostname "$(grep -c "$(hostname)" "$rep" || true)" "0"
    else
        chk report-produced yes no
    fi
    rm -f "$rep"
}

case "${1:-}" in
    --collect)  shift; diag_cli_collect "$@" ;;
    --redact)   shift; diag_cli_redact "$@" ;;
    --compare)  shift; diag_compare "$@" ;;
    --selftest) diag_selftest ;;
    --info)
        printf 'Diagnostic report generator\n'
        printf 'Collects system, adapter, dependency and module-selftest state.\n'
        printf 'Redacts MACs, SSIDs, secrets and public IPs before writing.\n'
        printf 'Never reads loot/.\n' ;;
    --help|"")
        printf 'Usage: tools/diag.sh COMMAND\n'
        printf '  --collect [FILE]         full redacted report\n'
        printf '  --redact FILE            scrub an existing log file\n'
        printf '  --compare MODULE [VERB]  GUI vs stripped-env divergence\n'
        printf '  --selftest\n' ;;
    *) printf 'ERROR\tunknown command: %s\n' "$1" >&2; exit 2 ;;
esac

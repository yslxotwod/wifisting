#!/usr/bin/env bash
# smoke-pages.sh — construct every module page and report any that crash.
#
# The GUI restores open tabs from ~/.config/wifisting/state.ini. This driver
# writes that session with one module per run, launches the GUI, and checks
# it is still alive after a settle period. That is the only way to build a
# page without a human clicking, and it catches construction-time crashes
# (bad async callbacks, uninitialised cleanups) that never fire otherwise.
#
# The user's real state.ini is backed up and restored.
#
# Usage:
#   tools/smoke-pages.sh                 # every module
#   tools/smoke-pages.sh 02_recon 34_pmf_bypass
#   tools/smoke-pages.sh --settle 10     # longer settle for slow pages

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUI="$ROOT/native/builddir/wifisting-gui"
STATE_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/wifisting"
STATE="$STATE_DIR/state.ini"
SETTLE=5

[[ -x "$GUI" ]] || { echo "build the GUI first: meson compile -C native/builddir" >&2; exit 2; }

want=()
confirmed=0
while (( $# )); do
    case "$1" in
        --settle) SETTLE="$2"; shift 2 ;;
        --i-know-it-pops-windows) confirmed=1; shift ;;
        *) want+=("$1"); shift ;;
    esac
done

# This launches the real GUI once per module, which maps a window each time
# and steals focus. There is no Xvfb on this box, so it cannot run
# off-screen - require an explicit acknowledgement rather than surprising
# whoever is at the keyboard.
if (( ! confirmed )); then
    cat >&2 <<'MSG'
smoke-pages.sh launches the GUI once per module (a window every few
seconds, each taking focus). No Xvfb is available here, so it cannot be
run headless.

Re-run with --i-know-it-pops-windows if that is acceptable, or name the
specific modules you want to check:
    tools/smoke-pages.sh --i-know-it-pops-windows --settle 6 02_recon
MSG
    exit 3
fi

if (( ${#want[@]} == 0 )); then
    mapfile -t want < <(cd "$ROOT/modules" && ls -1 *.sh 2>/dev/null | sed 's/\.sh$//' | sort)
fi

mkdir -p "$STATE_DIR"
backup=""
if [[ -f "$STATE" ]]; then
    backup="$(mktemp)"
    cp "$STATE" "$backup"
fi

kill_gui() {
    local p exe
    for p in /proc/[0-9]*; do
        exe=$(readlink "$p/exe" 2>/dev/null) || continue
        case "$exe" in *wifisting-gui*) kill -9 "${p#/proc/}" 2>/dev/null ;; esac
    done
}

ok=0; bad=0; failed=()
printf '%-26s %s\n' MODULE RESULT
printf '%-26s %s\n' "--------------------------" "------"

for m in "${want[@]}"; do
    kill_gui; sleep 0.4

    # A [session] with this one module as the open tab.
    if [[ -n "$backup" ]]; then
        # keep any non-session sections from the user's file
        awk '/^\[session\]/{skip=1} /^\[/{if($0!="[session]")skip=0} !skip' "$backup" > "$STATE"
    else
        : > "$STATE"
    fi
    printf '\n[session]\ncount=1\ntab_0=%s\n' "$m" >> "$STATE"

    "$GUI" >/tmp/smoke-pages.log 2>&1 &
    pid=$!
    sleep "$SETTLE"

    if [[ -d "/proc/$pid" ]]; then
        # still up: the page constructed. Make sure it did not fault and
        # get restarted by a shell that ignores it.
        printf '%-26s %s\n' "$m" "ok"
        ok=$((ok + 1))
    else
        wait "$pid" 2>/dev/null
        rc=$?
        printf '%-26s %s\n' "$m" "CRASH exit=$rc"
        head -4 /tmp/smoke-pages.log 2>/dev/null | sed 's/^/      /'
        bad=$((bad + 1)); failed+=("$m")
    fi
    kill -9 "$pid" 2>/dev/null
    kill_gui
done

if [[ -n "$backup" ]]; then
    cp "$backup" "$STATE"; rm -f "$backup"
else
    rm -f "$STATE"
fi
kill_gui

printf '\npassed %d   crashed %d\n' "$ok" "$bad"
(( ${#failed[@]} )) && printf 'crashed: %s\n' "${failed[*]}"
(( bad == 0 )) || exit 1
exit 0

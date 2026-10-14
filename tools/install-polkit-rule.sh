#!/usr/bin/env bash
# install-polkit-rule.sh — install the polkit rule that stops wifisting asking
# for a password on every privileged module action.
#
#   sudo tools/install-polkit-rule.sh
#
# Installing needs root once; after that the rule serves every user on the
# machine, so a normal `./wifisting.sh` never sees a polkit prompt. Safe to
# re-run: it tells you whether anything actually changed.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/tools/49-wifisting.rules"
DEST_DIR="/etc/polkit-1/rules.d"
DEST="$DEST_DIR/49-wifisting.rules"

if [[ ! -f "$SRC" ]]; then
    echo "missing $SRC" >&2
    exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "needs root: sudo $0" >&2
    exit 1
fi

if [[ ! -d "$DEST_DIR" ]]; then
    echo "no $DEST_DIR — is polkit installed?" >&2
    exit 1
fi

if [[ -f "$DEST" ]] && cmp -s "$SRC" "$DEST"; then
    echo "already installed and up to date: $DEST"
else
    install -m 0644 -o root -g root "$SRC" "$DEST" || exit 1
    echo "installed $DEST"
    # polkitd watches the directory, so this is belt-and-braces. It matters on
    # older polkitd that only reload on a signal, and it avoids the "I
    # installed it and nothing changed" confusion.
    pkill -HUP polkitd 2>/dev/null || true
fi

echo
echo "verify (should print TSV with no password prompt):"
echo "  pkexec $ROOT/modules/02_recon.sh --status-tsv"

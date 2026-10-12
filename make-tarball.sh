#!/usr/bin/env bash
# Build a portable tarball of wifisting — source + launcher + modules,
# no user state, no loot, no build artifacts.
set -euo pipefail

SRC="$HOME/wifisting"
OUT="${1:-/tmp/wifisting-portable.tar.gz}"
STAGE="$(mktemp -d)"

echo "[*] staging into $STAGE"
mkdir -p "$STAGE/wifisting"

rsync -a --quiet \
    --exclude='loot/' \
    --exclude='captures/' \
    --exclude='state/' \
    --exclude='logs/' \
    --exclude='reports/' \
    --exclude='tmp/' \
    --exclude='local/' \
    --exclude='external/' \
    --exclude='tools/' \
    --exclude='wordlists/*.txt' \
    --exclude='wordlists/*.gz' \
    --exclude='wordlists/*.lst' \
    --exclude='wordlists/*.rule' \
    --exclude='native/builddir/' \
    --exclude='native/builddir-*/' \
    --exclude='native/src/*.bak.*' \
    --exclude='native/resources/icons/*.bak.*' \
    --exclude='*.pid' \
    --exclude='*.log' \
    --exclude='.git/' \
    --exclude='__pycache__/' \
    --exclude='*.pyc' \
    --exclude='wifisting.txt' \
    "$SRC/" "$STAGE/wifisting/"

# Empty runtime dirs so first run doesn't create them as root
for d in loot captures state logs tmp wordlists reports; do
    mkdir -p "$STAGE/wifisting/$d"
done

# Drop an INSTALL.md for the recipient
cat > "$STAGE/wifisting/INSTALL.md" << 'README'
# wifisting — install

## 1. Build dependencies

Debian / Ubuntu:
    sudo apt install gtk4 libvte-2.91-gtk4-0 meson ninja-build \
                     gcc pkg-config libglib2.0-dev libgtk-4-dev \
                     libvte-2.91-gtk4-dev

Arch:
    sudo pacman -S gtk4 vte4 meson ninja gcc pkgconf

Fedora:
    sudo dnf install gtk4 vte291-gtk4 meson ninja-build gcc \
                     pkgconf glib2-devel gtk4-devel vte291-gtk4-devel

## 2. Build

    cd ~/wifisting/native
    meson setup builddir
    meson compile -C builddir

## 3. Install launcher + icon (optional, makes a menu entry)

    bash ~/wifisting/install.sh

## 4. Run

    ~/wifisting/native/builddir/wifisting-gui

Or, from the menu: search "wifisting".

## First-run setup

Open **Dependency Manager** → **Install Missing**. It uses pkexec and
will prompt for your password once. This pulls aircrack-ng, hashcat,
bettercap, and the rest of the wireless tool stack.

If pkexec doesn't prompt, install a polkit agent:

    sudo apt install policykit-1-gnome     # GNOME
    sudo apt install lxpolkit              # LXDE / minimal WMs

## CLI

The same toolkit is also available headless:

    sudo bash ~/wifisting/wifisting.sh

Requires root (module scripts call iw, aircrack-ng, hciconfig, etc.).

    bash ~/wifisting/wifisting.sh --list     # list all modules

## Authorized use only

This toolkit performs real wireless attacks (deauth, handshake capture,
rogue AP, etc.). Do not use it against networks you don't own or don't
have explicit written permission to test.
README

# install.sh for the recipient
cat > "$STAGE/wifisting/install.sh" << 'INSTALL_EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -x "$ROOT/native/builddir/wifisting-gui" ]; then
    echo "Build first:" >&2
    echo "  cd $ROOT/native && meson setup builddir && meson compile -C builddir" >&2
    exit 1
fi

# --- Icons ---
SRC="$ROOT/native/resources/splash.png"
[ -f "$SRC" ] || SRC="$ROOT/native/resources/icons/wifisting.ico"

if [ -f "$SRC" ]; then
    echo "[*] installing icons..."
    for size in 48 64 128 256 512; do
        DEST="$HOME/.local/share/icons/hicolor/${size}x${size}/apps"
        mkdir -p "$DEST"
        convert "$SRC" -background none -resize "${size}x${size}" \
            "$DEST/com.wifisting.native.png" 2>/dev/null || true
    done
    gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor/" 2>/dev/null || true
fi

# --- Desktop entry ---
echo "[*] installing launcher..."
mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/com.wifisting.native.desktop" << DESK
[Desktop Entry]
Type=Application
Name=wifisting
GenericName=Wireless Security Toolkit
Comment=Wi-Fi and Bluetooth security research GUI
Exec=$ROOT/native/builddir/wifisting-gui
Icon=com.wifisting.native
Terminal=false
Categories=Network;Security;Utility;
StartupNotify=true
StartupWMClass=com.wifisting.native
DESK

update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

echo
echo "[+] Done. Launch wifisting from your app menu, or:"
echo "    $ROOT/native/builddir/wifisting-gui"
INSTALL_EOF
chmod +x "$STAGE/wifisting/install.sh"

# --- Tarball ---
echo "[*] creating $OUT"
tar czf "$OUT" -C "$STAGE" wifisting
rm -rf "$STAGE"

SIZE=$(du -h "$OUT" | cut -f1)
echo
echo "[+] Done: $OUT  ($SIZE)"
echo
echo "Send that to your friend. They run:"
echo "  tar xzf $(basename "$OUT") -C ~/"
echo "  cd ~/wifisting/native && meson setup builddir && meson compile -C builddir"
echo "  bash ~/wifisting/install.sh"

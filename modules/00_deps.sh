#!/usr/bin/env bash
# Wifisting dependency manager
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
: "${WIFISTING_HOME:=$HOME/wifisting}"
: "${WIFISTING_ROOT:=$HOME/wifisting}"
mkdir -p "$TMP_DIR" 2>/dev/null

# ═══════════════════════════════════════════════════════════════════
#  distro detection
# ═══════════════════════════════════════════════════════════════════

deps_detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

deps_pkg_manager() {
    case "$(deps_detect_distro)" in
        debian|ubuntu|kali|parrot|raspbian) echo "apt" ;;
        fedora|rhel|centos|rocky|alma)     echo "dnf" ;;
        arch|manjaro|endeavouros)          echo "pacman" ;;
        alpine)                            echo "apk" ;;
        *)                                 echo "unknown" ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
#  tool registry
#  name, package-per-distro, group, min-version (optional)
# ═══════════════════════════════════════════════════════════════════

declare -A DEPS_GROUP=(
    [aircrack-ng]=critical [airodump-ng]=critical [aireplay-ng]=critical
    [airmon-ng]=critical [hcxdumptool]=critical [hcxpcapngtool]=critical
    [hostapd]=critical [dnsmasq]=critical [iw]=critical [ip]=critical
    [rfkill]=critical [python3]=critical
    [mdk4]=optional [bettercap]=optional [ettercap]=optional
    [reaver]=optional [bully]=optional [pixiewps]=optional [wash]=optional
    [hashcat]=optional [john]=optional [cowpatty]=optional [asleap]=optional
    [iptables]=optional [ethtool]=optional [xterm]=optional [ccze]=optional
    [tshark]=optional [sqlite3]=optional [arp-scan]=optional [tcpdump]=optional
    [dsniff]=optional [netcat]=optional [stdbuf]=optional [curl]=optional
    [wget]=optional [openssl]=optional [binwalk]=optional [kismet]=optional
    [gpsd]=optional [gpsd-clients]=optional [rtl_sdr]=optional
    [hackrf_transfer]=optional [bluetoothctl]=optional [hciconfig]=optional
    [macchanger]=optional [socat]=optional [lspci]=optional [unzip]=optional
    [git]=optional [make]=optional [gcc]=optional [pip3]=optional
    [unblob]=optional [cve-bin-tool]=optional [firmwalker]=optional
    [mitm6]=optional [responder]=optional [btlejack]=optional
    [hcitool]=optional [gatttool]=optional [killerbee]=optional
)

# Package name per distro for each tool. Missing entries → skip.
declare -A DEPS_APT=(
    [aircrack-ng]=aircrack-ng [airodump-ng]=aircrack-ng [aireplay-ng]=aircrack-ng
    [airmon-ng]=aircrack-ng [hcxdumptool]=hcxdumptool [hcxpcapngtool]=hcxtools
    [hostapd]=hostapd [dnsmasq]=dnsmasq [iw]=iw [ip]=iproute2 [rfkill]=rfkill
    [python3]=python3 [mdk4]=mdk4 [bettercap]=bettercap [ettercap]=ettercap-graphical
    [reaver]=reaver [bully]=bully [pixiewps]=pixiewps [wash]=reaver
    [hashcat]=hashcat [john]=john [cowpatty]=cowpatty [asleap]=asleap
    [iptables]=iptables [ethtool]=ethtool [xterm]=xterm [ccze]=ccze
    [tshark]=tshark [sqlite3]=sqlite3 [arp-scan]=arp-scan [tcpdump]=tcpdump
    [dsniff]=dsniff [netcat]=netcat-openbsd [stdbuf]=coreutils [curl]=curl
    [wget]=wget [openssl]=openssl [binwalk]=binwalk [kismet]=kismet
    [gpsd]=gpsd [gpsd-clients]=gpsd-clients [rtl_sdr]=rtl-sdr
    [hackrf_transfer]=hackrf [bluetoothctl]=bluez [hciconfig]=bluez
    [macchanger]=macchanger [socat]=socat [lspci]=pciutils [unzip]=unzip
    [git]=git [make]=make [gcc]=gcc [pip3]=python3-pip
    [unblob]=unblob [cve-bin-tool]=cve-bin-tool [responder]=responder
    [mitm6]=mitm6 [btlejack]=btlejack [killerbee]=killerbee
    [firmwalker]=firmwalker
)

declare -A DEPS_DNF=(
    [aircrack-ng]=aircrack-ng [hcxdumptool]=hcxdumptool [hcxpcapngtool]=hcxtools
    [hostapd]=hostapd [dnsmasq]=dnsmasq [iw]=iw [ip]=iproute
    [rfkill]=rfkill [python3]=python3 [mdk4]=mdk4
    [bettercap]=bettercap [ettercap]=ettercap [hashcat]=hashcat
    [john]=john [iptables]=iptables [ethtool]=ethtool [xterm]=xterm
    [tshark]=wireshark-cli [sqlite3]=sqlite [arp-scan]=arp-scan
    [tcpdump]=tcpdump [netcat]=nc [curl]=curl [wget]=wget [openssl]=openssl
    [binwalk]=binwalk [bluetoothctl]=bluez [macchanger]=macchanger
    [socat]=socat [lspci]=pciutils [unzip]=unzip [git]=git [make]=make
    [gcc]=gcc [pip3]=python3-pip
)

declare -A DEPS_PACMAN=(
    [aircrack-ng]=aircrack-ng [hcxdumptool]=hcxdumptool [hcxtools]=hcxtools
    [hostapd]=hostapd [dnsmasq]=dnsmasq [iw]=iw [ip]=iproute2
    [rfkill]=rfkill [python3]=python [mdk4]=mdk4 [bettercap]=bettercap
    [ettercap]=ettercap [hashcat]=hashcat [john]=john [iptables]=iptables
    [ethtool]=ethtool [xterm]=xterm [tshark]=wireshark-cli [sqlite3]=sqlite
    [arp-scan]=arp-scan [tcpdump]=tcpdump [netcat]=gnu-netcat [curl]=curl
    [wget]=wget [openssl]=openssl [binwalk]=binwalk [bluetoothctl]=bluez
    [macchanger]=macchanger [socat]=socat [lspci]=pciutils [unzip]=unzip
    [git]=git [make]=make [gcc]=gcc [pip3]=python-pip
)

# Version floor for a few critical tools. `--check-versions` verifies these.
declare -A DEPS_MIN_VERSION=(
    [hcxdumptool]="6.0"
    [hcxpcapngtool]="6.0"
    [bettercap]="2.32"
    [hashcat]="6.0"
    [hostapd]="2.6"
    [tshark]="3.6"
    [unblob]="22.0"
)

deps_pkg_for() {
    local tool="$1"
    local mgr
    mgr=$(deps_pkg_manager)
    case "$mgr" in
        apt)    echo "${DEPS_APT[$tool]:-}" ;;
        dnf)    echo "${DEPS_DNF[$tool]:-}" ;;
        pacman) echo "${DEPS_PACMAN[$tool]:-}" ;;
        *)      echo "" ;;
    esac
}

deps_check_one() { command -v "$1" >/dev/null 2>&1; }

# Extract a version from a tool. Best-effort: many tools report on
# -V / --version / -v. Returns empty if we can't get one.
deps_tool_version() {
    local tool="$1"
    local out=""
    case "$tool" in
        hcxdumptool)  out=$("$tool" --version 2>&1 | head -1) ;;
        hcxpcapngtool) out=$("$tool" --version 2>&1 | head -1) ;;
        bettercap)    out=$("$tool" -version 2>&1 | head -1) ;;
        hashcat)      out=$("$tool" --version 2>&1 | head -1) ;;
        hostapd)      out=$("$tool" -v 2>&1 | head -1) ;;
        tshark)       out=$("$tool" -v 2>&1 | head -1) ;;
        unblob)       out=$("$tool" --version 2>&1 | head -1) ;;
        reaver)       out=$("$tool" --help 2>&1 | grep -m1 -i 'reaver' | head -1) ;;
        *)            out=$("$tool" --version 2>&1 | head -1) ;;
    esac
    printf '%s\n' "$out" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1
}

# Compare two semver-ish strings. Returns 0 if $1 >= $2.
deps_version_ge() {
    local a="$1" b="$2"
    [[ -z "$a" || -z "$b" ]] && return 0
    printf '%s\n%s\n' "$b" "$a" | sort -V -C
    return $?
}

# ═══════════════════════════════════════════════════════════════════
#  status TSV
# ═══════════════════════════════════════════════════════════════════

deps_status_tsv() {
    local tool group pkg state min cur
    # Iterate all tools known
    for tool in $(printf '%s\n' "${!DEPS_GROUP[@]}" | sort); do
        group="${DEPS_GROUP[$tool]}"
        pkg=$(deps_pkg_for "$tool")
        if deps_check_one "$tool"; then
            state="installed"
        else
            state="missing"
        fi
        printf '%s\t%s\t%s\t%s\n' "$tool" "${pkg:-?}" "$group" "$state"
    done
}

deps_check_versions_tsv() {
    local tool min cur ok
    local issues=0
    for tool in "${!DEPS_MIN_VERSION[@]}"; do
        min="${DEPS_MIN_VERSION[$tool]}"
        deps_check_one "$tool" || continue
        cur=$(deps_tool_version "$tool")
        if [[ -z "$cur" ]]; then
            printf 'VERSION_UNKNOWN\t%s\t%s\n' "$tool" "$min"
            continue
        fi
        if deps_version_ge "$cur" "$min"; then
            ok="ok"
        else
            ok="too_old"
            issues=$((issues+1))
        fi
        printf '%s\t%s\t%s\t%s\n' "$ok" "$tool" "$cur" "$min"
    done
    printf 'ISSUES\t%s\n' "$issues"
}

# ═══════════════════════════════════════════════════════════════════
#  install paths
# ═══════════════════════════════════════════════════════════════════

deps_missing_packages() {
    local tool pkg
    for tool in "${!DEPS_GROUP[@]}"; do
        deps_check_one "$tool" && continue
        pkg=$(deps_pkg_for "$tool")
        [[ -n "$pkg" ]] && printf '%s\n' "$pkg"
    done | sort -u
}

# pipx-installable tools that don't have a Debian/Ubuntu package
# (or whose package lags upstream badly).
DEPS_PIPX_TOOLS=(
    "unblob|unblob"
    "cve-bin-tool|cve-bin-tool"
    "btlejack|btlejack"
    "mitm6|mitm6"
)

deps_install_pipx_tools() {
    command -v pipx >/dev/null 2>&1 || {
        command -v apt >/dev/null 2>&1 && apt install -y pipx 2>/dev/null
    }
    command -v pipx >/dev/null 2>&1 || {
        printf 'MISSING\tpipx\n'; return 1
    }
    pipx ensurepath >/dev/null 2>&1 || true

    local entry name cmd
    for entry in "${DEPS_PIPX_TOOLS[@]}"; do
        name="${entry%%|*}"
        cmd="${entry##*|}"
        if command -v "$cmd" >/dev/null 2>&1; then
            printf 'HAVE\t%s\n' "$cmd"
            continue
        fi
        info "pipx install $name"
        pipx install "$name" 2>&1 | tail -5 || \
            printf 'FAILED\t%s\n' "$name"
    done
}

deps_install_git_tools() {
    # responder has no maintained Debian package on modern distros
    local dir="$WIFISTING_ROOT/external/Responder"
    if [[ -d "$dir" ]]; then
        printf 'HAVE\tresponder\n'
        return 0
    fi
    command -v git >/dev/null || { printf 'MISSING\tgit\n'; return 1; }
    mkdir -p "$WIFISTING_ROOT/external"
    info "cloning Responder"
    git clone https://github.com/lgandx/Responder.git "$dir" 2>&1 | tail -3
    if [[ -f "$dir/Responder.py" ]]; then
        ln -sf "$dir/Responder.py" "$HOME/.local/bin/responder" 2>/dev/null || \
            ln -sf "$dir/Responder.py" /usr/local/bin/responder 2>/dev/null || true
        printf 'INSTALLED\t%s\n' "$dir"
    fi
}

# ═══════════════════════════════════════════════════════════════════
#  privilege wrapper
# ═══════════════════════════════════════════════════════════════════

deps_run_privileged() {
    local packages=("$@")
    local mgr script
    ((${#packages[@]} > 0)) || {
        printf 'Everything requested is already installed.\n'
        return 0
    }
    mgr=$(deps_pkg_manager)
    [[ "$mgr" == "unknown" ]] && {
        printf 'Unsupported distro — install manually: %s\n' "${packages[*]}" >&2
        return 1
    }

    if (( EUID == 0 )); then
        deps_privileged_install "${packages[@]}"
        return
    fi

    script=$(readlink -f "${BASH_SOURCE[0]}")
    if command -v pkexec >/dev/null 2>&1; then
        exec pkexec "$script" privileged-install "${packages[@]}"
    fi

    printf 'pkexec is required for package installation.\n' >&2
    return 1
}

deps_privileged_install() {
    local packages=("$@")
    local mgr pkg failed=()
    (( EUID == 0 )) || { printf 'root required\n' >&2; return 1; }
    ((${#packages[@]} > 0)) || return 0

    mgr=$(deps_pkg_manager)
    case "$mgr" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update || return 1
            for pkg in "${packages[@]}"; do
                printf '\nInstalling %s...\n' "$pkg"
                apt-get install -y -- "$pkg" || failed+=("$pkg")
            done ;;
        dnf)
            for pkg in "${packages[@]}"; do
                printf '\nInstalling %s...\n' "$pkg"
                dnf install -y "$pkg" || failed+=("$pkg")
            done ;;
        pacman)
            pacman -Sy --noconfirm || true
            for pkg in "${packages[@]}"; do
                printf '\nInstalling %s...\n' "$pkg"
                pacman -S --noconfirm --needed "$pkg" || failed+=("$pkg")
            done ;;
        *)
            printf 'Unsupported pkg manager\n' >&2; return 1 ;;
    esac

    if ((${#failed[@]} > 0)); then
        printf '\nFailed packages: %s\n' "${failed[*]}" >&2
        return 1
    fi
    printf '\nDependency operation completed.\n'
}

# ═══════════════════════════════════════════════════════════════════
#  entry points
# ═══════════════════════════════════════════════════════════════════

deps_install_packages() {
    local req=("$@") pkg unique=() seen=()
    ((${#req[@]} > 0)) || { printf 'No package specified.\n' >&2; return 2; }
    for pkg in "${req[@]}"; do
        local found=0
        for f in "${unique[@]}"; do [[ "$f" == "$pkg" ]] && { found=1; break; }; done
        (( found == 0 )) && unique+=("$pkg")
    done
    deps_run_privileged "${unique[@]}"
}

deps_install_missing_backend() {
    local packages=()
    mapfile -t packages < <(deps_missing_packages)
    deps_run_privileged "${packages[@]}"
}

deps_install_all_backend() {
    local packages=()
    mapfile -t packages < <(
        for tool in "${!DEPS_GROUP[@]}"; do
            deps_pkg_for "$tool"
        done | sort -u | grep -v '^$'
    )
    deps_run_privileged "${packages[@]}"
}

# ═══════════════════════════════════════════════════════════════════
#  self-test
# ═══════════════════════════════════════════════════════════════════
# Offline and side-effect free: the registry tables, the distro→package
# mapping, version comparison and the TSV shapes are all pure logic. No
# install path is exercised beyond the two guards that return before any
# package manager or pkexec call.
deps_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcount() { printf '%s\n' "$1" | grep -c . ; }

    local out rc

    # 1. distro detection and its package-manager mapping
    local id want
    id=$(deps_detect_distro)
    chk distro-id-shape "$(printf '%s' "$id" | grep -cE '^[a-z0-9._-]+$')" 1
    chk distro-id-matches-os-release "$id" \
        "$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"' | head -1)"
    case "$id" in
        debian|ubuntu|kali|parrot|raspbian) want=apt ;;
        fedora|rhel|centos|rocky|alma)     want=dnf ;;
        arch|manjaro|endeavouros)          want=pacman ;;
        alpine)                            want=apk ;;
        *)                                 want=unknown ;;
    esac
    chk pkg-manager-for-distro "$(deps_pkg_manager)" "$want"
    chk pkg-manager-known "$(deps_pkg_manager | grep -cE '^(apt|dnf|pacman|apk|unknown)$')" 1

    # 2. tool -> package mapping (Debian names are what this box resolves)
    if [[ "$(deps_pkg_manager)" == "apt" ]]; then
        chk pkg-hcxpcapngtool "$(deps_pkg_for hcxpcapngtool)" hcxtools
        chk pkg-ip            "$(deps_pkg_for ip)"            iproute2
        chk pkg-netcat        "$(deps_pkg_for netcat)"        netcat-openbsd
        chk pkg-tshark        "$(deps_pkg_for tshark)"        tshark
        chk pkg-python3       "$(deps_pkg_for python3)"       python3
    fi
    chk pkg-unknown-tool "$(deps_pkg_for definitely-not-a-tool)" ""

    # every critical tool must be installable, or install-missing lies
    local t missing_crit=0
    for t in "${!DEPS_GROUP[@]}"; do
        [[ "${DEPS_GROUP[$t]}" == "critical" ]] || continue
        [[ -n "$(deps_pkg_for "$t")" ]] || { missing_crit=$((missing_crit+1)); printf 'NOTE\tno package mapping for critical tool %s\n' "$t"; }
    done
    chk pkg-all-critical-mapped "$missing_crit" 0
    # version floors only make sense for registered tools
    local orphan=0
    for t in "${!DEPS_MIN_VERSION[@]}"; do
        [[ -n "${DEPS_GROUP[$t]:-}" ]] || orphan=$((orphan+1))
    done
    chk min-version-tools-registered "$orphan" 0
    chk pipx-table-shape "$(printf '%s\n' "${DEPS_PIPX_TOOLS[@]}" | grep -cE '^[^|]+\|[^|]+$')" "${#DEPS_PIPX_TOOLS[@]}"

    # 3. presence probe
    chk check-one-present "$(deps_check_one bash && echo yes || echo no)" yes
    chk check-one-absent  "$(deps_check_one definitely-not-a-tool-xyz && echo yes || echo no)" no

    # 4. version comparison: numeric fields, not string order
    chk vge-equal      "$(deps_version_ge 6.0 6.0; echo $?)" 0
    chk vge-newer      "$(deps_version_ge 6.1 6.0; echo $?)" 0
    chk vge-older      "$(deps_version_ge 5.9 6.0; echo $?)" 1
    chk vge-numeric-10 "$(deps_version_ge 1.10 1.9; echo $?)" 0
    chk vge-numeric-9  "$(deps_version_ge 1.9 1.10; echo $?)" 1
    chk vge-major-10   "$(deps_version_ge 10.0 9.9; echo $?)" 0
    chk vge-shorter    "$(deps_version_ge 3.6 3.6.1; echo $?)" 1
    chk vge-longer     "$(deps_version_ge 3.6.1 3.6; echo $?)" 0
    chk vge-empty-cur  "$(deps_version_ge "" 6.0; echo $?)" 0
    chk vge-empty-min  "$(deps_version_ge 6.0 ""; echo $?)" 0

    # 5. version extraction from a real tool, and empty for a missing one
    if command -v tshark >/dev/null 2>&1; then
        local tsh
        tsh=$(deps_tool_version tshark)
        chk tool-version-shape "$(printf '%s' "$tsh" | grep -cE '^[0-9]+\.[0-9]+(\.[0-9]+)?$')" 1
        chk tool-version-matches "$tsh" \
            "$(tshark -v 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)"
    fi
    chk tool-version-python3 "$(deps_tool_version python3 | grep -cE '^[0-9]+\.[0-9]+')" 1
    chk tool-version-absent  "$(deps_tool_version definitely-not-a-tool-xyz)" ""

    # 6. status TSV: one row per registered tool, 4 fields, sorted, honest state
    out=$(deps_status_tsv)
    chk status-rows     "$(rcount "$out")" "${#DEPS_GROUP[@]}"
    chk status-fields   "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=4 || $2=="" || $3=="" || $4==""{c++} END{print c+0}')" 0
    chk status-groups   "$(printf '%s\n' "$out" | awk -F'\t' '$3!="critical" && $3!="optional"{c++} END{print c+0}')" 0
    chk status-states   "$(printf '%s\n' "$out" | awk -F'\t' '$4!="installed" && $4!="missing"{c++} END{print c+0}')" 0
    chk status-sorted   "$(printf '%s\n' "$out" | cut -f1 | sort -c 2>/dev/null; echo $?)" 0
    local tool
    for tool in python3 unblob git; do
        chk "status-state-$tool" "$(printf '%s\n' "$out" | awk -F'\t' -v t="$tool" '$1==t{print $4}')" \
            "$(command -v "$tool" >/dev/null 2>&1 && echo installed || echo missing)"
    done
    chk status-pkg-column "$(printf '%s\n' "$out" | awk -F'\t' '$1=="hcxpcapngtool"{print $2}')" hcxtools

    # 7. missing-package list is deduplicated and sorted
    out=$(deps_missing_packages)
    chk missing-unique "$(printf '%s\n' "$out" | sort -u | md5sum)" "$(printf '%s\n' "$out" | md5sum)"
    chk missing-nonempty "$(printf '%s\n' "$out" | grep -c '^$')" 0
    if ! command -v unblob >/dev/null 2>&1; then
        chk missing-includes-absent-tool "$(printf '%s\n' "$out" | grep -c '^unblob$')" 1
    fi

    # 8. version check report is internally consistent
    out=$(deps_check_versions_tsv)
    local issues too_old
    issues=$(fld "$out" ISSUES)
    too_old=$(printf '%s\n' "$out" | awk -F'\t' '$1=="too_old"' | grep -c .)
    chk versioncheck-issues "$issues" "$too_old"
    chk versioncheck-last   "$(printf '%s\n' "$out" | tail -1 | cut -f1)" ISSUES
    chk versioncheck-fields "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ok"||$1=="too_old"{if(NF!=4)c++} $1=="VERSION_UNKNOWN"{if(NF!=3)c++} $1!="ok"&&$1!="too_old"&&$1!="VERSION_UNKNOWN"&&$1!="ISSUES"{c++} END{print c+0}')" 0
    chk versioncheck-known-tools "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ok"||$1=="too_old"||$1=="VERSION_UNKNOWN"{print $2}' | while read -r t; do [[ -n "${DEPS_MIN_VERSION[$t]:-}" ]] || echo bad; done | grep -c .)" 0
    chk versioncheck-installed-only "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ok"||$1=="too_old"||$1=="VERSION_UNKNOWN"{print $2}' | while read -r t; do command -v "$t" >/dev/null 2>&1 || echo bad; done | grep -c .)" 0

    # 9. install entry points: only the guards that return before acting
    out=$(deps_install_packages 2>&1); rc=$?
    chk install-noargs-rc  "$rc" 2
    chk install-noargs-msg "$(printf '%s\n' "$out" | grep -c 'No package specified.')" 1
    out=$(deps_run_privileged); rc=$?
    chk privileged-nopkgs-rc   "$rc" 0
    chk privileged-nopkgs-msg  "$(printf '%s\n' "$out" | grep -c 'already installed')" 1

    # 10. git tool path: the already-present short circuit (no clone attempted)
    local s_root="$WIFISTING_ROOT"
    WIFISTING_ROOT="/tmp/wifisting/deps_selftest"
    rm -rf "$WIFISTING_ROOT"; mkdir -p "$WIFISTING_ROOT/external/Responder"
    out=$(deps_install_git_tools); rc=$?
    chk git-tools-have-rc   "$rc" 0
    chk git-tools-have-says "$(printf '%s\n' "$out" | grep -c $'^HAVE\tresponder$')" 1
    chk git-tools-no-clone  "$(find "$WIFISTING_ROOT" -maxdepth 3 -name '.git' | wc -l)" 0
    rm -rf "/tmp/wifisting/deps_selftest" "$WIFISTING_ROOT"
    WIFISTING_ROOT="$s_root"

    # 11. dispatch
    out=$(deps_main --distro-info); rc=$?
    chk main-distroinfo-rc   "$rc" 0
    chk main-distroinfo-rows "$(rcount "$out")" 2
    chk main-distroinfo-keys "$(printf '%s\n' "$out" | cut -f1 | tr '\n' ' ')" "distro pkg_manager "
    deps_main --help >/dev/null 2>&1;      chk main-help-rc "$?" 0
    deps_main definitely-not-a-verb >/dev/null 2>&1; chk main-unknown-rc "$?" 2

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

deps_usage() {
    cat <<EOF
Usage:
  $(basename "$0") status | --status-tsv
  $(basename "$0") --check-versions
  $(basename "$0") install PACKAGE [PACKAGE...]
  $(basename "$0") --install-package PACKAGE [PACKAGE...]
  $(basename "$0") install-missing | --install-missing
  $(basename "$0") install-all | --install-all
  $(basename "$0") --install-pipx     # unblob, cve-bin-tool, btlejack, mitm6
  $(basename "$0") --install-git      # Responder
  $(basename "$0") --distro-info
  $(basename "$0") --selftest
EOF
}

deps_main() {
    local command="${1:-}"
    (($# > 0)) && shift
    case "$command" in
        status|--status|--status-tsv)   deps_status_tsv ;;
        --check-versions)               deps_check_versions_tsv ;;
        install|install-package|--install-package) deps_install_packages "$@" ;;
        install-missing|--install-missing) deps_install_missing_backend ;;
        install-all|--install-all)      deps_install_all_backend ;;
        --install-pipx)                 deps_install_pipx_tools ;;
        --install-git)                  deps_install_git_tools ;;
        --distro-info)                  printf 'distro\t%s\npkg_manager\t%s\n' \
                                            "$(deps_detect_distro)" "$(deps_pkg_manager)" ;;
        --selftest)                     deps_selftest ;;
        privileged-install|--privileged-install) deps_privileged_install "$@" ;;
        help|--help|-h)                 deps_usage ;;
        *) deps_usage >&2; return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    deps_main "$@"
fi

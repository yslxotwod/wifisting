<img width="1774" height="887" alt="image" src="https://github.com/user-attachments/assets/9c8ccd38-0b57-4d18-a03e-ede7850902d8" />


# wifisting

A GTK4 wireless security toolkit for Linux. 57 modules covering Wi-Fi,
Bluetooth, RF, router-side and network MITM work behind one interface.

Every module is a standalone shell script. The GUI is a view over them, not a
container — nothing is locked behind the interface.

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/40c72cfd-b8ae-47ae-9eb7-c4652d68fd9d" />

> **Early development.** Tested thoroughly on one machine with one adapter.
> The section [What actually works](#what-actually-works) is honest about what
> that means, and it is worth reading before you file a bug.

---

## What this actually is

- **A CLI.** `sudo bash wifisting.sh` gives you a numbered menu grouped by
  category. `bash wifisting.sh --list` prints module availability without
  needing root.

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/f9f1c681-3a01-4a6c-86cb-ca5a38a1d571" />


- **A native GUI.** `wifisting-gui` builds on GTK4 + VTE and drives the
  same shell modules through a strict TSV protocol. Roughly 15,000 lines
  of C, no runtime dependency heavier than GTK and VTE.

  <img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/87558c5c-392e-42e0-80e8-cc48079fd5c4" />


- **A module collection.** More than 50 shell scripts, each one self-contained,
  each one self-locating its project root (works under `pkexec`, where
  `HOME` is `/root`), each one with a `--selftest` verb that runs offline
  and touches no hardware.
  
<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/e04137c3-a66d-4a9b-8163-62971a46ebd7" />

The GUI and the CLI are not alternatives — they share the state under
`/tmp/wifisting/`. Select a target in the GUI's Recon tab and the CLI sees
it. Kick off a scan from the CLI and the GUI's status pills update.

---

## Why this exists

Most wireless tooling is deep in one lane. `aircrack-ng` is Wi-Fi. `bettercap`
is network MITM. BlueZ tooling is Bluetooth. An assessment means five tools,
five config formats, and no shared view of the target.

wifisting is wide on purpose — across layers and protocols, in one place. It
also wraps Responder, **mitm6**, ntlmrelayx, mdk4 and hcxdumptool rather than
reimplementing them, so the specialist tools stay underneath where they belong.

The other thing it does differently: **most tools tell you they worked.** This
one is built to tell you when they didn't. A module that reports OK while the
target is untouched is worse than one that fails loudly, so there is a
`--selftest` per module and the hardware-gated ones say what's missing instead
of returning an empty result.

---

## Notable features

**Frame-level jamming**. Not a deauth flood — actual **reactive jamming**, **carrier-sense manipulation** and **FCS corruption**, driven through a **modified Atheros driver**. This needed porting **modwifi** to **kernel 7.0**, which is why almost nobody ships it. You can jam one access point's beacons while leaving the rest of the channel alone.

**SSID overflow** with real **IE-length control**. Beacons whose SSID exceeds the **32-byte limit**, carrying **injection payloads** in the same bytes. The published **ESP32** tools can't do this — WiFi.softAP() truncates at 32, so they all list it as future work. Building the frame by hand means the length byte is independent of the content, which is the case that actually matters.

**Router Advertisement poisoning**. **mitm6** does **DHCPv6** and deliberately skips Router Advertisements, so a network with no **DHCPv6** in play is untouched by it. This does **RA/SLAAC**: one forged packet reconfigures every host's default route and resolver.

**Client isolation bypass**. **Gateway bouncing**, **port stealing**, **broadcast reflection**, plus an **inter-NIC relay** to hold the bypass open. From the **AirSnitch** work (**NDSS'26**).

**USB Ethernet MITM**. **RNDIS**-based, **PoisonTap**-style, over a USB port.

**Router recovery and console**. **Recovery-mode TFTP**, **UART/U-Boot** guidance, **offline flash image parsing**. Unusual to find in a wireless tool.

**Multi-node capture**. Drive a fleet of remote nodes — Pi, VM, laptop — and correlate what they see.

The one I'd argue matters most: it's built to tell you when it failed. Every module has a --selftest. Hardware-gated modules name the hardware they're missing instead of returning an empty result. A module that reports OK while the target is untouched is worse than one that fails loudly, and that's the bug class I'm hunting.

---

## Modules

### System
| Module | Description |
|---|---|
| `00_deps` | Inspect installed tools and install missing packages |
| `01_iface` | Discover wireless interfaces and control monitor mode |

### Wi-Fi
| Module | Description |
|---|---|
| `02_recon` | Live scan, target selection, CSV parsing |
| `03_attack` | Deauth, WPA/WPA2 handshake capture and PMKID |
| `04_eviltwin` | Rogue AP with captive portal and credential capture |
| `08_pmkid_offline` | Offline PMKID extraction and hashcat conversion |
| `09_wardrive` | GPS-tagged scanning for coverage mapping |
| `10_rogue_dhcp` | Malicious DHCP server for interception |
| `11_krack_kr00k` | KRACK and Kr00k key reinstallation |
| `17_wps_attack` | Pixie Dust and WPS PIN |
| `20_karma` | Answer every probe request to ensnare clients |
| `21_beacon_flood` | Beacon and auth floods, WIDS confusion, Michael countermeasures |
| `22_wifi_direct` | P2P devices, services and group owner negotiation |
| `23_captive_portal_builder` | Render captive portal HTML from templates |
| `34_pmf_bypass` | 802.11w management frame protection posture per AP |
| `35_wifi6_attacks` | HE elements, BSS colour collisions, TWT, spatial reuse |
| `47_wpa3_attack` | Transition downgrade, Dragonblood, SAE capture and dictionary |
| `48_wep_attack` | Fake auth, ARP replay, ChopChop, fragmentation, key recovery |
| `53_jamming` | **Frame-level jamming** via the **modwifi** driver |
| `54_client_isolation` | Gateway bounce, **port stealing**, **broadcast reflection**, **inter-NIC relay** |
| `55_ssid_overflow` | Oversized SSID past the **32-byte limit**, with injection in the same bytes |

### MITM and network
| Module | Description |
|---|---|
| `07_arp` | ARP spoofing and MITM capture |
| `13_802.1x_relay` | RADIUS relay for 802.1X |
| `32_resolver_poison` | LLMNR/NBT-NS/mDNS poisoning, NTLM relay, **mitm6**, Router Advertisement |
| `49_usb_mitm` | **USB Ethernet MITM** over **RNDIS** |
| `50_router_lan` | TR-064, HNAP, UPnP/SSDP, SNMP, DNS rebinding, CSRF |
| `51_router_web` | Diagnostic-page injection, rom-0 disclosure, default credentials |
| `52_router_console` | **Recovery-mode TFTP**, **UART/U-Boot** guidance, offline flash parsing |

### Bluetooth
| Module | Description |
|---|---|
| `05_bt_recon` | Device enumeration and fingerprinting |
| `06_bt_attack` | BLE spoofing and Bluetooth attack primitives |
| `12_hid_injection` | Bluetooth HID keystroke injection |
| `24_bt_mesh` | BLE Mesh sniffing and attacks |
| `36_ble_tracker_hunt` | AirTag/SmartTag/Tile detection and following detection |
| `37_bt_classic_ssp` | Secure Simple Pairing models and HCI log reconstruction |
| `38_ble_adv_forge` | iBeacon, Eddystone and Fast Pair payload building |
| `39_ble_fuzz` | Malformed BLE payload corpus generation |

### 802.15.4
| Module | Description |
|---|---|
| `26_zigbee` | Zigbee sniffing and attacks (**CC2531** / **nRF52840**) |
| `57_thread` | Thread mesh analysis and border router discovery |

### RF and physical
| Module | Description |
|---|---|
| `25_rf_spectrum` | **SDR** spectrum sweeps, IQ capture, channel occupancy |
| `40_wifi_csi` | Channel state information parsing and motion analysis |
| `42_subghz` | Sub-GHz OOK pulse train decoding and band reference |
| `43_nfc_rfid` | NDEF codec and MIFARE tag structure analysis |
| `44_lora_loraWAN` | LoRa and LoRaWAN |
| `45_drone_remote_id` | ASTM F3411 Remote ID decode and build |

### Scanners and analysis
| Module | Description |
|---|---|
| `14_wifi_ids` | Passive monitoring and wireless intrusion detection |
| `15_wifi_cve_scan` | Probe networks for known Wi-Fi CVE exposure |
| `16_bt_cve_scan` | Probe Bluetooth devices for known CVE exposure |
| `18_capture_analysis` | pcap browsing, hash extraction, hashcat driving |
| `19_wordlist_manager` | Download, compose and manage wordlists and rules |
| `27_firmware_iot` | Firmware extraction, credential harvesting, CVE scan |
| `27b_fw_update_audit` | Firmware update audit |
| `28_live_traffic` | Live traffic view |
| `30_fingerprint` | Client identification, random MAC detection, correlation |
| `41_wifi_geolocate` | Position estimate from BSSID and RSSI |
| `46_public_wifi_audit` | Grade APs for open, WEP, downgrade and evil-twin risk |

### Automation
| Module | Description |
|---|---|
| `29_killchain` | Chain multi-step attacks into reusable runs |
| `31_remote_node` | Manage a fleet of remote nodes (Pi / VM / PC) |

---

## Hardware

**You need an adapter that can inject.**

Nothing here is needed to build or launch the app. But most of it won't do anything without at least one of these, so it's worth knowing what each piece buys you.

**Essential** — a Wi-Fi adapter that **can inject**. **Atheros AR9271** is what I built and tested against: **TP-Link WN722N v1**, **Alfa AWUS036NHA**, **Technoethical N150**.

**Intel adapters** will not work for anything involving injection. The app detects **iwlwifi** and tells you so instead of failing quietly, but it will refuse. **Monitor mode** alone isn't enough. Without one of these, you can browse the interface and read captures, and that's about it.

**A second Wi-Fi adapter** — for client isolation testing. That module needs two interfaces associated at the same time, one acting as the victim and one as the attacker. Any managed-capable card works as the second; it doesn't need to inject.

**Bluetooth adapter** — for the eight Bluetooth modules. Classic and BLE recon, SSP, advertising forgery, fuzzing, mesh, tracker hunting, HID injection. A recent adapter is preferable; some of the older CSR dongles won't pass BLE advertising data through.

**802.15.4 radio** — for Zigbee and Thread. A **CC2531**, **CC2652** or **nRF52840** dongle, flashed with sniffing firmware. One radio covers both, because Thread and Zigbee share the same physical layer — they're different stacks on the same silicon. This is also the hardware that gets you toward **Matter**.

**SDR** — for RF spectrum, sub-GHz, LoRa and drone Remote ID. An **RTL-SDR** is the cheap entry point and covers sub-GHz receive. A **HackRF** adds 2.4 GHz coverage and transmit, which you need for anything that isn't passive. Note that sub-GHz transmission — replay attacks and the like — needs **TX-capable hardware**; an **RTL-SDR** can only listen.

NFC reader/writer — for the NFC/RFID module. A PN532 or ACR122U handles NDEF and MIFARE work. A Proxmark3 if you're going past the tag structure analysis into proper card research.

USB-to-UART adapter — for router console access. CP2102, CH340 or FTDI. This is what gets you a U-Boot prompt on a router's serial header when recovery mode won't hand it to you. Worth having a set of dupont leads and, for board-level work, SOIC clips.

GPS receiver — for wardriving. The wardriving module drives Kismet with gpsd, so any receiver gpsd supports works. USB or Bluetooth both fine.

---

## How to run it

After extracting the archive, in your terminal:

```bash
cd native
meson setup builddir && meson compile -C builddir
```

That builds the GUI. Then, from the project root:

```bash
./wifisting.sh
```

The app asks for your password when a module needs root — that is `pkexec`,
and it prompts per action rather than once at startup.

Or launch the built binary directly:

```bash
./native/builddir/wifisting-gui
```

### Dependencies

**Operating system:** Linux. Developed on Arch-family and Ubuntu derivatives.
It will not run natively on Windows — see [Windows](#windows) below.

**Required:** GTK4 (4.14+), meson, ninja, a C compiler, python3 with scapy.

```bash
# Debian / Ubuntu
sudo apt install build-essential meson ninja-build cmake libgtk-4-dev libvte-2.91-gtk4-dev python3-scapy

# Arch
sudo pacman -S base-devel meson ninja cmake gtk4 vte4 python-scapy
```

If the build fails, the error names the missing dependency. Install it and
re-run `meson compile -C builddir`.

### First run

**1 — Check dependencies.** Open **Dependencies** and run the check. It lists
what is installed, what is missing, and offers to install the missing packages.
Do this first: half of all confusing failures later are a missing tool.

<img width="1366" height="710" alt="image (3)" src="https://github.com/user-attachments/assets/21645256-3468-424d-9518-1fd974d543fa" />

**2 — Set up your adapter.** Open **Interface Manager**. It lists your wireless
interfaces and their capabilities. Put your injection-capable adapter into
**monitor mode** here and confirm it reports `injection yes`. If it says `no`,
retrying will not help.

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/ff855e33-d930-4ad5-8567-0e4fe7a26505" />

**3 — Scan something.** Open **Wi-Fi Recon** and start a scan. If you see
nothing, the adapter is in the wrong mode or on a band it does not support.

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/ae3a344d-332a-456d-bda0-7317422aa74d" />

---

## What actually works

Tested against real hardware:

- Wi-Fi recon, deauth, handshake and PMKID capture
- WPS including Pixie Dust
- WPA3, Dragonblood, SAE
- WEP including ChopChop and fragmentation
- Enterprise 802.1X, PEAP, TEAP, GTC downgrade
- PMF bypass, KRACK, Kr00k, FragAttacks
- Evil twin, Karma, captive portal, beacon and auth floods
- ARP MITM, rogue DHCP, Responder, **mitm6**, NTLM relay, Router Advertisement
- Client isolation testing
- Router-side: TR-064, HNAP, UPnP, SNMP, web UI, console and TFTP
- Analysis: capture analysis, statistics, fingerprinting, wordlists

**Written but NOT tested against real hardware:**

- **All Bluetooth modules.** No adapter was available. Classic and BLE recon,
  SSP, advertising forgery, fuzzing, mesh, tracker hunting, HID injection.
- **Sub-GHz, LoRa, Zigbee, NFC, drone Remote ID, RF spectrum.** No **SDR** or radio.
- **Thread.** Offline capture analysis works; live scanning needs an **802.15.4 radio**.
- **Jamming.** Needs a modified driver and firmware that is not included. It will
  report that it cannot find the driver. That is correct behaviour, not a bug.

The code is written and reviewed. "Written" and "works" are not the same claim.

---

## How it is put together

The GUI is a view over 57 standalone shell scripts in `modules/`. Nothing is
locked behind the interface:

```bash
./modules/02_recon.sh --help
./modules/57_thread.sh --analyze capture.pcap
```

Every module has a `--selftest`. If something misbehaves, run that first — it
often identifies the problem without any hardware attached.

Useful tools in `tools/`:

```bash
./tools/check-paths.sh    # every script path and module entry resolves
./tools/check-verbs.sh    # find verbs no GUI control can reach
```

---

## Directories

On first run it creates `tmp/`, `loot/`, `logs/` and `captures/` automatically.
Nothing needs to pre-exist.

**`loot/` is where results land** — one subdirectory per module. Everything in
it came off the air or off a target device and **is not redacted**. It contains
real network names and captured credentials.

Treat a copy of `loot/` the way you would treat the equipment it came from.
Do not commit it, sync it, or email it.

---

## Troubleshooting

**"The module says OK but nothing happened."**
The failure worth reporting. Tell us which module, what you expected, and what
the target actually did.

**"It says no adapter, or injection no."**
Your adapter cannot inject. See [Hardware](#hardware).

**"A module refuses to run."**
It is usually telling you exactly why. Read the error rather than retrying —
the hardware-gated modules refuse on purpose.

**"The GUI will not start."**
Check GTK4 is installed and at least 4.14.

---

## Windows

It does not run natively on Windows, and no wrapper changes that: **Windows does
not expose raw 802.11 frames to userspace**, so monitor mode and injection are
not available to any tool.

The working path is **WSL2**, which runs a real Linux kernel and passes the USB
adapter through:

```powershell
wsl --install
winget install usbipd
usbipd list
usbipd bind --busid <your-AR9271>
usbipd attach --wsl --busid <your-AR9271>
```

The adapter then appears inside WSL with the real `ath9k_htc` driver, and the
GUI runs through WSLg on Windows 11.

---

## Contributing

Adding a module:

1. Write `modules/NN_name.sh`. It must self-locate `WIFISTING_ROOT`, print TSV
   as `KEY\tVALUE`, send errors to stderr, and exit non-zero on failure.
2. Add a `--selftest` that passes with no hardware attached.
3. Register it in `native/src/main1.c` — an entry in the `modules[]` table, a
   GUI page, and a `module_registry_register` call.
4. Run the checks:

```bash
./tools/gen-module-index.sh
./tools/check-paths.sh
./tools/check-verbs.sh
```

`check-verbs.sh` fails if a verb exists in a module but no GUI control can
reach it. That is deliberate — a feature nobody can click is a feature nobody
has.

Run `./tools/diag.sh --collect` to see how your machine reports itself — it is
also the report testers are asked to send with a bug.

---

## Credits

Built on the work of others. The specialist tools stay underneath:

- **aircrack-ng** suite — capture and cracking
- **mdk4** — frame injection and floods
- **hcxdumptool / hcxtools** — PMKID and handshake capture
- **Responder**, **impacket**, **mitm6** — credential capture and relay
- **hostapd / dnsmasq** — rogue AP and DHCP
- **modwifi** (Mathy Vanhoef) — frame-level jamming driver capabilities
- **AirSnitch** (Vanhoef et al., **NDSS'26**) — client isolation bypass research
- **scapy** — frame construction throughout

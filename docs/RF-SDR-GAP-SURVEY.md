# RF / non-IP wireless security tooling — gap survey for the Wi-Fi toolkit

**Date of verification: 2026-10-13.** Every maintenance claim below was checked by me that day against the live GitHub API or the repo's `commits.atom` feed (dates = last commit on the default branch), or against the project's own documentation. Cost figures are rough 2026 street prices in USD. Legal ratings are my assessment, with the statute/regulator cited; they are not legal advice.

*Note: written to `/home/ysl/wifisting/` because the session workspace root (`/home/ysl/wifisting/wifisting`) is root-owned and not writable by uid 1000.*

**Not reported as gaps** (already in the toolkit): spectrum sweeps/waterfall, sub-GHz OOK/ASK pulse work, LoRa/LoRaWAN 1.0.x codec, ASTM F3411 Remote ID, NFC/RFID data layer, firmware analysis, GPS wardriving, router bootloader/flash work, USB RNDIS MitM. Wi-Fi itself is assumed fully covered.

**Headline findings**
1. **Universal Radio Hacker is archived** (read-only since 2025-12-19). Do not plan an integration against it — vendor it, or move protocol-RE work to GNU Radio + inspectrum + SDRangel.
2. The parent's **Zigbee/802.15.4 module is built on KillerBee, which is dead (last commit 2022-08-19)**. Two live replacements exist, one of them on an $8 ESP32.
3. **ADS-B, AIS, BLE, pagers, digital voice, TPMS, wM-Bus/smart meters, Meshtastic, DECT, TETRA, UWB, key-fob rolling codes and satellite are all absent** from the toolkit. Most of the cheap ones are *passive, offline-decodable and CI-testable*.
4. The scariest legal exposure is not where people expect: **DECT and TETRA voice interception** (wiretap statutes) and **anything that keys a transmitter** (jamming/spoofing/relay).

---

## Priority table

| # | Capability gap | Tool(s) | Hardware | Cost | Offline/CI | Maint. (last commit) | Legal |
|---|---|---|---|---|---|---|---|
| 1 | ADS-B / Mode-S aircraft | [readsb](https://github.com/wiedehopf/readsb), [pyModeS](https://github.com/junzis/pyModeS), [tar1090](https://github.com/wiedehopf/tar1090), [dump1090-fa](https://github.com/flightaware/dump1090) | RTL-SDR | $30 | **Yes** (`--ifile`, `modes decode --file`) | 2026-10-10 / 09-24 / 09-29 / 07-01 | Low (RX) |
| 2 | AIS marine VHF | [AIS-catcher](https://github.com/jvde-github/AIS-catcher) | RTL-SDR | $30 | **Yes** (`-r`, `-r txt`) | 2026-10-09 | Low (RX) |
| 3 | BLE / Bluetooth LE | [Sniffle](https://github.com/nccgroup/Sniffle), [Ubertooth](https://github.com/greatscottgadgets/ubertooth) | TI CC26xx ($50) / Ubertooth One ($120) | $50–120 | PCAP → tshark offline | 2025-09-25 / 2026-03-19 | Med (relay/TX = high) |
| 4 | Smart meters + utility telemetry | [wmbusmeters](https://github.com/wmbusmeters/wmbusmeters), [rtlamr](https://github.com/bemasher/rtlamr) | RTL-SDR or wM-Bus dongle | $30–60 | **Yes** (wmbus: hex stdin; rtlamr: needs shim) | 2026-10-13 / 2026-07-25 | Low–med (privacy) |
| 5 | Meshtastic / LoRa mesh | [meshtastic/python](https://github.com/meshtastic/python), [firmware](https://github.com/meshtastic/firmware), [MeshCore](https://github.com/ripplebiz/MeshCore), [Reticulum](https://github.com/markqvist/Reticulum) | LoRa node | $30–60 | Protobuf layer yes | 2026-10-03 / 10-13 / 09-30 / 09-30 | Low |
| 6 | ~250 ISM device protocols (weather stations, TPMS, remotes, sensors) | [rtl_433](https://github.com/merbanan/rtl_433) | RTL-SDR; CC1101+ESP32 for TX | $5–30 | **Yes** (`-r file.cu8`) | 2026-10-11 | Low (RX); TX = high |
| 7 | Zigbee/802.15.4 (replace dead KillerBee) | [ESP32-KillerBee](https://github.com/RockBase-iot/ESP32-KillerBee), [nRF Sniffer 802.15.4](https://www.nordicsemi.com/Products/Development-tools/nrf-sniffer-for-802154), [zigbee2mqtt](https://github.com/Koenkk/zigbee2mqtt) | ESP32 / nRF52840 dongle | $8–15 | PCAP offline | 2026-04-24 / vendor / 2026-10-02 | Low (RX) |
| 8 | Z-Wave | [zwave-js Zniffer](https://github.com/zwave-js/node-zwave-js) | Zniffer stick (UZB-7 class) | $25–80 | **Yes** (`.zlf` load) | 2026-10-13 | Low |
| 9 | Pagers (POCSAG/FLEX/ERMES) | [multimon-ng](https://github.com/EliasOenal/multimon-ng) | RTL-SDR + rtl_fm | $30 | **Yes** (wav/raw/flac/stdin) | 2026-10-11 | Med (content interception) |
| 10 | Digital voice: DMR/P25/NXDN/D-STAR/M17 | [dsd-fme](https://github.com/lwvmobile/dsd-fme), [SDRTrunk](https://github.com/DSheirer/sdrtrunk), [trunk-recorder](https://github.com/robotastic/trunk-recorder), [op25](https://github.com/boatbod/op25) | RTL-SDR (audio) | $30 | **Yes** (`-i file.wav`) | 2026-09-26 / 10-12 / 09-27 / 08-23 | **High** (wiretap) |
| 11 | Key fobs / rolling codes / RKE | [Proxmark3](https://github.com/RfidResearchGroup/proxmark3), [rfcat](https://github.com/atlas0fd00m/rfcat), [Flipper Zero fw](https://github.com/flipperdevices/flipperzero-firmware) | Proxmark3 Easy / Yard Stick One / Flipper | $40–200 | Partial (mfkey tools) | 2026-10-13 / 08-16 / 10-09 | **Severe** (theft) |
| 12 | TPMS privacy + spoofing | rtl_433 + [IMDEA research](https://www.securityweek.com/researchers-uncover-method-to-track-cars-via-tire-sensors/) | RTL-SDR (~$100/receiver in study) | $30+ | **Yes** (rtl_433) | research 2026-03 | Low (RX); spoof = severe |
| 13 | DECT voice | [DeDECTive](https://github.com/SarahRoseLives/DeDECTive) | **HackRF/SDRplay/Pluto — not RTL-SDR** | $120–350 | **No** (live only) | 2026-10-07 | **High** (ECPA/wiretap) |
| 14 | TETRA | [telive](https://github.com/sq5bpf/telive) | RTL-SDR (needs ~4 MHz BW) | $30+ | Partial (`--playback`) | 2026-01-24 | **Severe** (emergency services) |
| 15 | Satellite non-IP | [iridium-toolkit](https://github.com/muccc/iridium-toolkit), [gr-iridium](https://github.com/muccc/gr-iridium), [SatDump](https://github.com/SatDump/SatDump) | RTL-SDR + LNA/antenna; better with Airspy | $30–300 | **Yes** (.bits parse) | 2026-09-16 / 2025-03-29 / 2026-09-30 | Med (RX); TX severe |
| 16 | GNSS interference *detection* | [gpsjam.org](https://gpsjam.org/) method, [gnss-sdr](https://github.com/gnss-sdr/gnss-sdr), [RTKLIB-EX](https://github.com/rtklibexplorer/RTKLIB) | RTL-SDR | $30 | Yes (IQ) | live map / 2026-10-04 / 2026-10-13 | Low (detect); TX = **severe** |
| 17 | Cellular base-station detection (defensive) | [EFF Rayhunter](https://github.com/EFForg/rayhunter) | Orbic RC400L hotspot | ~$30 | Logs offline | 2026-10-10 | Low (defensive) |
| 18 | UWB ranging / distance-reduction | [SEEMOO uwb-sniffer](https://github.com/seemoo-lab/uwb-sniffer) + [Ghost Peak](https://www.usenix.org/conference/usenixsecurity22/presentation/leu) | DW3000-class boards | $30–100 | Research-grade | 2022-03-02 (stale) | Med–high |
| 19 | Protocol RE platform | [SDRangel](https://github.com/f4exb/sdrangel), [inspectrum](https://github.com/miek/inspectrum), [GNU Radio](https://github.com/gnuradio/gnuradio), [SigMF](https://github.com/sigmf/sigmf) | any SDR | — | Yes (IQ files) | 2026-10-13 / 2025-12-01 / 2026-10-08 / 2026-01-13 | Low; **rpitx TX = severe** |
| 20 | NFC relay (delta vs. your data layer) | [NFCGate](https://github.com/nfcgate/nfcgate) | 2 Android phones | $0 | No (live) | 2026-07-20 | **High** (payment/access fraud) |

---

## P0 — cheap, passive, offline-decodable, low legal risk (do these first)

### 1. ADS-B / Mode-S + aircraft datalinks — **biggest single capability jump**
- **readsb** (wiedehopf) — github.com/wiedehopf/readsb — last commit **2026-10-10**, very healthy. High-performance Mode-S/ADS-B/MLAT decoder; writes `aircraft.json` + trace history + API. **Offline: `--device-type ifile --ifile=<path>` (or `-` for stdin), `--write-json=<dir>`, `--db-file aircraft.csv.gz`; also `--net-only --net-connector host,30005,beast_in` to replay recorded Beast streams.** Hardware: RTL-SDR ~$30. Legal: receive-only, low.
- **pyModeS v3** (junzis, TU Delft) — github.com/junzis/pyModeS — **2026-09-24**, GPL-3.0, pure Python, mypy-strict, has a golden-file regression oracle upstream. `modes decode --file captures/flight.log` (hex or `timestamp,hex` CSV), `--file -` for stdin, `--compact | jq`, `--reference lat lon`, `decode()` / `PipeDecoder` API. This is the single best "no hardware in CI" module on this list.
- **tar1090** — github.com/wiedehopf/tar1090 — 2026-09-29. Web UI over readsb JSON (browser-only, not CI).
- **dump1090-fa** — github.com/flightaware/dump1090 — 2026-07-01, still maintained.
- **ACARS/VDL2** (aircraft VHF datalink, often overlooked): [acarsdec](https://github.com/TLeconte/acarsdec) (2025-07-31), [dumpvdl2](https://github.com/szpajder/dumpvdl2) (2026-08-01). Both RTL-SDR, both text/JSON output.
- **Transmit side (flag, do not ship casually)**: [gr-adsb](https://github.com/mhostetter/gr-adsb) (2026-04-09) is a GNU Radio ADS-B **transmitter**; [gr-air-modes](https://github.com/bistromath/gr-air-modes) is dead (2020-05-06). Injecting false aircraft is a safety-of-life offence and prosecuted in the US/EU — **severe**.

### 2. AIS marine — **second-biggest jump**
- **AIS-catcher** — github.com/jvde-github/AIS-catcher — **2026-10-09**, GPL-3.0, v0.36. Dual-channel AIS receiver (Class A/B, base stations, AtoN, SAR) → NMEA 0183, web viewer, filters, station sharing.
- **Offline is first-class**: `AIS-catcher -r <wav>`; raw IQ too (`-r CU8 file.raw -s 1536K`, `-r CS16 .`); `-r .`/`-r stdin` for stdin; **`-r txt nmea-file` replays a plain NMEA text file** (ideal fixture format). Python binding `aiscat` on PyPI. Docs: jvde-github.github.io/AIS-catcher-docs/configuration/input/file/
- Hardware: RTL-SDR ~$30 (also Airspy/HackRF/SDRplay). Legal: RX low; the project itself warns reception rules vary locally. **Transmitting AIS** ([gr-ais](https://github.com/bistromath/gr-ais), 2026-09-06) requires a licensed station and spoofing is **severe** (SOLAS/safety-of-life).

### 3. BLE — completely absent from the toolkit
- **Sniffle** (NCC Group) — github.com/nccgroup/Sniffle — **2025-09-25**. BLE 5 sniffer/scanner, Wireshark extcap, PCAP output, connection following, PHY modes. Hardware: TI LAUNCHXL-CC26X2R1 ~$50 / CC1352P-2 ~$60 (**RTL-SDR cannot do BLE**). Offline: no IQ input, but PCAP output means `tshark -r` dissectors are the CI-testable layer. **It also ships TX: link-layer fuzzing and a full BLE link-layer relay (`relay_master.py`/`relay_slave.py`), plus an `airtag_spoofer` firmware image** — relay/TX on third-party devices is **high risk**.
- **Ubertooth One** — github.com/greatscottgadgets/ubertooth — 2026-03-19, ~$120. Classic BLE sniffing; keep as legacy/alternative.
- **BTLEjack** is dead (2023-10-04); the nRF Sniffer is vendor tooling (nRF52840 dongle ~$10–15).
- **Live research worth encoding as detections**: **WhisperPair / CVE-2025-36911** (Jan 2026, KU Leuven) — Fast Pair accessories accept pairing without being in pairing mode; ~68% of tested models hijackable within ~14 m, enabling microphone eavesdropping and Find-My-based tracking. Sources: SecurityWeek, [Xcitium ThreatLabs writeup](https://threatlabsnews.xcitium.com/blog/whisperpair-bluetooth-flaw-lets-attackers-hijack-and-track-wireless-headphones/), and the IEEE paper *One Tap to Hijack Them All: A Security Analysis of the Google Fast Pair Protocol*. *(Secondary-source confidence; the CVE and vendor list are consistent across two independent outlets but I did not read the primary paper.)*

### 4. Smart meters and utility telemetry
- **wmbusmeters** — github.com/wmbusmeters/wmbusmeters — **2026-10-13**, very healthy. Wireless M-Bus (EN 13757, 868 MHz) + wired M-Bus for water/gas/heat/electric meters, with per-meter driver library and key decryption. **Offline: excellent** — `wmbusmeters myfile.txt:hex`, `echo <hex> | wmbusmeters --format=json stdin:hex MyMeter auto <id> NOKEY`, `stdin:rtlwmbus` (accepts rtl_433/rtl_wmbus output), `--analyze <hex>` for driver development, simulation files. Hardware: RTL-SDR ~$30 (`rtl_sdr | rtl_wmbus | wmbusmeters`) or a dedicated dongle (IM871A/IU891A/AMB8465/CUL, ~$30–60). Legal: passive, low; meter data is personal data under GDPR.
- **rtlamr** — github.com/bemasher/rtlamr — 2026-07-25, **AGPL-3.0** (network copyleft — matters if you host it). Decodes Itron ERT/SCM/SCM+/IDM/netIDM and Neptune R900 at ~900 MHz. **Offline: no native file input** (architecture is `rtl_tcp` → TCP; README documents only `-server`). Budget a small rtl_tcp-protocol replay shim, or call the Go decode package directly. Hardware: RTL-SDR ~$30.
- Missing here: **no maintained open-source attack tooling** for meter replay/spoofing. That is a genuine hole, but the privacy literature (load-tracing/occupancy inference) is substantial — cite it, don't claim a tool exists.

### 5. Meshtastic / LoRa mesh — new protocol family, documented weaknesses
- **meshtastic/python** (github.com/meshtastic/python, 2026-10-03) and **firmware** (2026-10-13). The CLI needs a device (serial/BLE/TCP) or MQTT, **but the pip package ships generated protobufs** (`meshtastic/protobuf/mesh_pb2.py`), so offline `MeshPacket` decode from JSON/serial logs is pure-Python and CI-testable. Hardware: a LoRa node $30–60 (Heltec V3, RAK4631, T-Beam) or MQTT.
- **Attack surface, straight from the project's own docs** (meshtastic.org/docs/about/overview/encryption/limitations/): AES-CTR with **no authentication** → keystream reuse means a known plaintext plus NodeNum/PacketID reuse lets an attacker send spoofed messages **without the PSK**; **TOFU** public-key model with a **120-entry NodeDB that evicts older nodes** → fake-node flooding causes legitimate nodes to roll off and enables impersonation with a new key; broadcasts too large for a 66-byte signature are sent **unsigned**; STM32WL nodes neither sign nor verify; **ham "licensed mode" disables encryption entirely** (regulatory). This is a ready-made, defensible module spec (packet replayer, keystream-reuse detector, node-eviction DoS, signature-policy audit).
- Adjacent ecosystems: [MeshCore](https://github.com/ripplebiz/MeshCore) (2026-09-30), [Reticulum](https://github.com/markqvist/Reticulum) (2026-09-30), [meshmonitor](https://github.com/Yeraze/meshmonitor) (2026-10-13, ships a low-entropy-key security doc).
- **Gap with no good tooling:** promiscuous over-the-air capture of Meshtastic/LoRa mesh requires custom SX1262 firmware; the official CLI cannot sniff raw OTA traffic. Flag as build-it-yourself.

### 6. rtl_433 as a protocol library, not just a receiver
- github.com/merbanan/rtl_433 — **2026-10-11**, 7.9k★, GPL-2.0. ~250 decoders: **wireless weather stations** (Fine Offset/AcuRite/Ecowitt), **TPMS**, remotes/key fobs, door/window sensors, thermostats, meters.
- **Offline: `-r <file>` reads IQ files (params auto-detected from filename/extension), stdin supported, `-S all` saves detected signals as `.cu8` fixtures, `-F json|csv|kv|mqtt|influx|http`.** The `-X "<custom decoder>"` flag defines brand-new OOK/FSK protocols at runtime without recompiling — the best extension hook available for your existing sub-GHz work.
- **Weather-station spoofing** (fake freeze/heat alarms into home automation) is feasible today with a $5 CC1101 + ESP32 ([SmartRC-CC1101-Driver-Lib](https://github.com/LSatan/SmartRC-CC1101-Driver-Lib), 2026-05-18; [rc-switch](https://github.com/sui77/rc-switch) is stale, 2022-05-18). Frame TX, not RF brute force, is the differentiator.

### 7. TPMS — privacy/tracking is the story, not the decoder
- Decoder: rtl_433 (above). Research: **"Can't Hide Your Stride: Inferring Car Movement…"** (IMDEA Networks + Spanish/Swiss/Luxembourg academics, March 2026). Five ~$100 receivers, 10 weeks, >6 M TPMS messages from ~20,000 vehicles; IDs are **static for the life of the tyre**, transmitted in cleartext → presence, weight and driving-pattern inference. The authors also describe **active spoofing** (fake flat-tyre alerts to stop trucks for cargo theft). Summary: securityweek.com/researchers-uncover-method-to-track-cars-via-tire-sensors/ · paper PDF: dspace.networks.imdea.org/bitstream/handle/20.500.12761/2011/
- Legal: passive reception low; **spoofing is illegal transmission plus potential endangerment — severe**. GDPR applies to the tracking use case.

### 8. Zigbee/802.15.4 — replace the dead base
- **KillerBee is dead (2022-08-19)** — your current Zigbee module rests on an abandoned toolkit.
- **ESP32-KillerBee** — github.com/RockBase-iot/ESP32-KillerBee — **2026-04-24**, "ESP32-based IEEE 802.15.4/Zigbee security research toolkit". Hardware: plain ESP32 ~$8. Best value replacement.
- **nRF Sniffer for 802.15.4** (Nordic, nRF52840 dongle ~$10–15, Wireshark extcap) — vendor tooling, well supported; covers Thread too. URL returned HTTP 403 to my fetch (bot block), so treat the link as unverified by me: nordicsemi.com/Products/Development-tools/nrf-sniffer-for-802154
- **Zigator** (github.com/akestoridis/zigator) — the academic Zigbee/Thread security analyser (ACM WiSec 2020) — is **stale (2022-05-19)**; still useful as a reference implementation of Zigbee attack taxonomy.
- [zigbee2mqtt](https://github.com/Koenkk/zigbee2mqtt) (2026-10-02) is the active ecosystem for device behaviour reference, not a security tool.

### 9. Z-Wave — offline frame parsing for free
- **zwave-js Zniffer** — github.com/zwave-js/node-zwave-js — **2026-10-13**. `loadCaptureFromFile("/path/file.zlf")` and `loadCaptureFromBuffer` parse saved captures, **explicitly including captures created by Silicon Labs' official Zniffer applications**; `saveCaptureToFile` / `getCaptureAsZLFBuffer` round-trip. So you can ship `.zlf` fixtures and unit-test an entire Z-Wave frame parser with **zero hardware**; only producing new captures needs a stick (UZB-7-class ~$25–40; there is **no RTL-SDR path**).
- Legal: passive, low. zwave-js is a controller, not a sniffer-transmitter — jamming/replay would need different hardware and is illegal.

### 10. Pagers
- **multimon-ng** — github.com/EliasOenal/multimon-ng — **2026-10-11**. POCSAG 512/1200/2400, FLEX/FLEX_NEXT, ERMES, AFSK1200/AX.25, FMSFSK, EAS, DTMF. **Offline: `-t raw|wav|flac`, stdin via `-`/`/dev/stdin`, test WAVs in `demo/`.** Hardware: RTL-SDR ~$30 via `rtl_fm`. Legal: **moderate** — pager content is often medical/private; interception statutes (US 18 U.S.C. §2511) and HIPAA-adjacent rules apply. Paging is still operationally live (hospitals, utilities, some emergency services).
- [pagermon](https://github.com/pagermon/pagermon) (aggregation/UI) is **stale (2024-04-21)** — don't build on it.

### 11. Digital voice: DMR/P25/NXDN/D-STAR (+ M17)
- **dsd-fme** — github.com/lwvmobile/dsd-fme — **2026-09-26**, permissive (ISC-style). P25 Ph1/Ph2, DMR, NXDN, D-STAR, YSF, M17, EDACS, ProVoice; trunking, LRRP/GPS mapping, per-call WAV. **Offline: `dsd-fme -i file.wav` (48 k) and `dsd-fme -i file.wav -s 96000` for DSDPlus raw**; input is demodulated audio, not IQ; `-o udp:host:port` for audio plumbing.
- Ecosystem: [SDRTrunk](https://github.com/DSheirer/sdrtrunk) (2026-10-12), [trunk-recorder](https://github.com/robotastic/trunk-recorder) (2026-09-27), [GopherTrunk](https://github.com/MattCheramie/GopherTrunk) (2026-10-13), [op25](https://github.com/boatbod/op25) (2026-08-23), [M17](https://github.com/M17-Project/M17_Implementations) (2026-10-03, open ham standard), [MMDVM](https://github.com/g4klx/MMDVM) (2026-08-16, **transmits** — ham licence required).
- Legal: **high**. Passive decoding of third-party voice traffic is interception in most jurisdictions; decoding *encrypted* traffic with recovered keys is worse. Treat as lab-only with loud warnings.

---

## P1 — high value, more hardware or more caution

### 12. Key fobs, rolling codes, keyless entry
- **Proxmark3 (RRG/Iceman)** — github.com/RfidResearchGroup/proxmark3 — **2026-10-13**, very healthy, ~$40–80 (Easy) / ~$300+ (RDV4). Delta vs. your NFC/RFID data layer: **MIFARE Classic crypto (darkside/nested/hardnested), emulation, sniffing**, plus **offline, hardware-free key recovery**: the repo ships `tools/mfc/card_reader/mfkey32v2.c` and `mfkey64.c` (verified present) which recover keys from captured nonces in CI-able fashion; dump formats (.eml/.json/.bin) are parseable.
- **rfcat** — github.com/atlas0fd00m/rfcat — **2026-08-16**. Python API for Yard Stick One (~$100–150, availability patchy) giving arbitrary sub-GHz **RX and TX**. Docs are Python-2 era — verify py3 before integrating. **Transmits: severe legal exposure if misused.**
- **Flipper Zero firmware** — github.com/flipperdevices/flipperzero-firmware — 2026-10-09, ~$170–200. Sub-GHz capture/replay, rolling-code *capture* (not bypass), NFC/RFID, BadUSB. Convenient field companion.
- Concepts to encode: **RollJam** (Samy Kamkar, samy.pl/rolljam/) — jam-and-capture two rolling codes then replay, defeating fixed-code and many rolling-code systems; **KeeLoq cryptanalysis** (academic); **keyless relay** — ADAC's continuing tests report only ~10% of tested keyless models resist relay attacks (secondary sources: sicurauto.it, vau-max.de claimed ~350 models broken; the ADAC page I tried returned 404, so treat the exact figures as secondary).
- Legal: relay/replay of vehicle access = **severe** (theft offences).

### 13. DECT
- **DeDECTive** — github.com/SarahRoseLives/DeDECTive — **2026-10-07**. DECT 6.0 wideband scanner + G.721 ADPCM voice decode, call following, US/EU bands, CLI + ImGui GUI. **Hardware: HackRF One ~$350 (18.432 Msps full-band pass), SDRplay RSP ~$100–250, or PlutoSDR ~$200 — an RTL-SDR is not sufficient.** **No file/IQ input today** (live SDR only) — but the code is split into a reusable `dedective_core` static library with an `IqSource` abstraction, so adding an offline file source is realistic engineering.
- Offline alternative: GNU Radio + gr-dect2 blocks (file_source → decoder). Originals: [bkerler/gr-dect2](https://github.com/bkerler/gr-dect2) (2022-10-21), and Pavel Yazev's gr-dect2 which DeDECTive's pipeline was ported from.
- **DECT-2020 NR / NR+** (new non-cellular 5G standard, 1.9 GHz): [lauri-piikivi/dect-nr-samples](https://github.com/lauri-piikivi/dect-nr-samples) — **2026-04-28** — sniffer application using the nRF9161 PHY API (DK ~$100–150). Very fresh area, little security research.
- Legal: **high** — DeDECTive's own README opens with a warning citing 18 U.S.C. §2511 (ECPA); cordless-voice interception is a wiretap offence in most jurisdictions.

### 14. TETRA
- **telive** — github.com/sq5bpf/telive — **2026-01-24** (an earlier 404 was a wrong org; this is the live one). TETRA live monitor, with `osmo-tetra-sq5bpf` (2023-08-05) as the decoder. Hardware: RTL-SDR works (needs ~4 MHz of bandwidth around 380–400 MHz); a second dongle improves voice following.
- Research to pair with it: **"All cops are broadcasting: TETRA under scrutiny"** (Meijer, Bokslag, Wetzels — Midnight Blue), USENIX Security 2023: usenix.org/conference/usenixsecurity23/presentation/meijer — five vulnerabilities, two critical, including deliberate weakening in TEA1; the paper publishes the previously secret primitives (CVE-2022-24401/24402/24403). A useful, citable, *defensive* framing for any TETRA module.
- Legal: **severe** — TETRA carries police/emergency/military traffic; interception is a serious criminal offence in essentially every jurisdiction (US 18 U.S.C. §2511; UK Wireless Telegraphy Act 2006 s.48), and the "research" framing does not protect you. Ship documentation/awareness, not an interception workflow.

### 15. Satellite (non-IP)
- **iridium-toolkit** — github.com/muccc/iridium-toolkit — **2026-09-16**, BSD-2-Clause. Parses raw Iridium frames produced by gr-iridium's `iridium-extractor` and reassembles higher layers (ACARS, IDA, pager, voice). **Offline: `python3 iridium-parser.py -p output.bits`, then `reassembler.py -m idapp|acars ...`** — a clean, CI-testable file→text pipeline.
- **gr-iridium** (front-end, GNU Radio OOT) — github.com/muccc/gr-iridium — 2025-03-29, semi-dormant but usable. Hardware: RTL-SDR can hear Iridium bursts with a good 1620 MHz antenna + LNA/bias-tee (~$70–120 total, marginal); Airspy/USRP are far better ($100–1,300).
- Weather/EO satellites: **SatDump** (github.com/SatDump/SatDump, 2026-09-30, very active) supersedes **noaa-apt** (2023-11-30, stale). **JAERO** (Inmarsat Aero, github.com/jontio/JAERO) is **stale (2023-11-21)** — flag as a gap in maintenance, not capability.
- Legal: downlink reception is generally lawful for these services, but **any uplink/transmit is severe** and some jurisdictions restrict decoding commercial satellite traffic. iridium-toolkit's README does *not* carry a legal warning — don't infer safety from that.

### 16. GNSS: detection is the defensible capability
- Parent already has GPS-tagged wardriving; the missing pieces are **interference detection** and an honest treatment of spoofing.
- **gpsjam.org** (John Wiseman) — ADS-B-derived global GPS interference map; the method (aircraft reporting degraded navigation integrity → interference) is a *detection technique* you can replicate locally. Passive, legal, URL live (HTTP 200).
- Local SDR detection: **gnss-sdr** (github.com/gnss-sdr/gnss-sdr, 2026-10-04) for C/N0 and multi-constellation quality metrics; **RTKLIB-EX** (github.com/rtklibexplorer/RTKLIB, 2026-10-13) for positioning-quality analysis. RTL-SDR ~$30 is enough for coarse jamming detection (AGC/C/N0 collapse), not for precision.
- Spoofing tools exist ([gps-sdr-sim](https://github.com/osqzss/gps-sdr-sim), 2025-01-07, dormant) but **transmitting GNSS is severely illegal and safety-of-life** — FCC: 47 U.S.C. §301/§333, 47 CFR §15.3, and the FCC's own notice "Jamming Cell Phones and GPS Equipment is Against the Law" (docs.fcc.gov/public/attachments/DOC-304575A2.pdf). Treat as documentation-only.

### 17. Cellular — the only cheap, legal, novel item is *defensive*
- **EFF Rayhunter** — github.com/EFForg/rayhunter — **2026-10-10**, very active. Detects 4G/5G cell-site simulators (IMSI catchers) using a **~$30 Orbic RC400L hotspot**; produces logs you can analyse offline. This is a legitimate, low-risk capability addition.
- Heavy/legal-risk option: **srsRAN** ([5G](https://github.com/srsran/srsRAN_Project/) 2026-06-01, [4G](https://github.com/srsran/srsRAN_4G) 2026-09-10) + **OsmocomBB** (github.com/osmocom/osmocom-bb, 2026-10-07) for lab base stations; requires USRP-class hardware ($1,300+) for anything real. **gr-gsm is dead (2021-05-05).** Mobile Sentinel (RUB-SysSec, baseband fuzzing) is stale (2020-08-14); SnoopSnitch needs an old rooted Qualcomm device (I could not resolve an authoritative maintained repo — one 2016 fork exists at github.com/pk-development/snoopsnitch).
- Legal: **severe** for anything that impersonates or intercepts a network (US 18 U.S.C. §2511, §1029; FCC). Prefer Rayhunter-style detection.

---

## P2 — RF attack classes: coverage map

| Attack class | Missing capability in the toolkit | Best available tooling | Legal |
|---|---|---|---|
| **Replay** | Protocol-aware replay (not raw pulse repeat): weather stations, TPMS, remotes, Meshtastic packets, meter telegrams | rtl_433 `-X` custom decoders + CC1101/ESP32 TX; Meshtastic protobuf replay; Flipper/rfcat | High (TX) |
| **Jamming (non-Wi-Fi)** | Sub-GHz/GPS/DECT *jamming detection*, not jamming itself | AGC/C/N0 collapse monitoring (gnss-sdr, RTKLIB-EX); gpsjam.org method; rtl_433 noise-floor stats; FCC jamming notice as legal anchor | Jamming = **severe**; detection = low |
| **Signal spoofing** | ADS-B/AIS/TPMS/weather-station/message-level spoofing | gr-adsb, gr-ais, rtl_433 TX, TPMS research PoC | **Severe** (safety-of-life, theft) |
| **Relay** | Keyless-entry relay, BLE link-layer relay, NFC/EMV relay | Sniffle `relay_master.py`/`relay_slave.py`; [NFCGate](https://github.com/nfcgate/nfcgate) (2026-07-20); car relay kits are not a software capability | **Severe** (theft/fraud) |
| **Rolling-code bypass** | Jam-capture-replay (RollJam) and KeeLoq-class analysis | Proxmark3, rfcat, Flipper; concepts from samy.pl/rolljam | **Severe** |
| **RF fingerprinting** | Transmitter identification / same-model device discrimination | [SMoRFFI](https://arxiv.org/abs/2511.07770) (2.4 GHz Wi-Fi dataset + reproducible framework, 2025/2026, also in Computer Networks); INRIA I/Q dataset (Zenodo 2026); many IEEE papers | Low–moderate (passive) |

**Honest gap statement:** for *jamming detection* and *RF fingerprinting*, open-source tooling is thin — there are datasets and papers, but no maintained turnkey tool. That is a genuine open field where your toolkit could contribute rather than integrate.

---

## P3 — protocol reverse-engineering tooling (the URH problem)

- **Universal Radio Hacker (URH)** — github.com/jopohl/urh — **ARCHIVED / read-only, last push 2025-12-19** (confirmed: GitHub API `archived: true` and the repo page shows "Public archive"; 12.6k★). Still the best protocol-RE GUI, but you cannot upstream to it. Plan: vendor a pinned fork, or replace with the stack below.
- **SDRangel** — github.com/f4exb/sdrangel — **2026-10-13**, extremely active, 4.1k★. RX/TX across most SDRs, many demodulators/decoders (including digital voice), headless-capable. The best-maintained URH *replacement* for demodulation work; GUI-heavy though.
- **inspectrum** — github.com/miek/inspectrum — **2025-12-01**, semi-dormant but stable. The canonical offline IQ/waterfall symbol analyser for stored captures — ideal for CI fixture inspection workflows (GUI).
- **GNU Radio** — github.com/gnuradio/gnuradio — 2026-10-08. The glue for everything else; gr-dect2, gr-iridium, gr-adsb, gr-ais are all OOT modules, and GNU Radio's `file_source`/`file_sink` blocks give you offline pipelines for free.
- **SigMF** — github.com/sigmf/sigmf — 2026-01-13. Standard IQ metadata format; adopt it as your capture interchange format so fixtures are self-describing.
- **IQEngine** — github.com/IQEngine/IQEngine — 2025-12-20 (slowing). Web-based IQ dataset/spectrogram platform; useful for hosting a corpus.
- **rpitx** — github.com/F5OEO/rpitx — **2024-09-30 (dormant)**, ~$35 Raspberry Pi. Transmits from a GPIO pin (FM/RDS/POCSAG/FT8/SSTV/…) — a cheap TX path for POCSAG/pager testing, but **transmitting on most of what it can reach is illegal without a licence**; also see the modernised fork "RPITX-UI" covered by RTL-SDR.com. Wrap with hard authorization gates or leave out.

---

## Cheap-hardware shopping list (rough 2026 USD)

| Item | Price | Unlocks |
|---|---|---|
| RTL-SDR Blog V4 dongle | $30–40 | ADS-B, AIS, pagers, DMR voice, meters, rtl_433, satellite, GNSS detection |
| TCXO + HF upconverter / bias-tee + LNA | +$20–50 | HF, Iridium, weak-signal work |
| CC1101 module + ESP32 | $5–12 | Sub-GHz TX for replay/spoofing of ISM devices, weather stations, TPMS |
| nRF52840 dongle | $10–15 | 802.15.4/Thread/Zigbee + BLE sniffing (Wireshark extcap) |
| ESP32 (plain) | $8 | ESP32-KillerBee Zigbee/802.15.4 work |
| wM-Bus USB dongle (IM871A/IU891A) | $30–60 | Reliable 868 MHz meter reading |
| Zniffer-capable stick (UZB-7 class) | $25–40 | Z-Wave Zniffer captures (.zlf) |
| Orbic RC400L hotspot | ~$30 | EFF Rayhunter cellular-base-station detection |
| TI LAUNCHXL-CC26X2R1 / CC1352P-2 | $50–60 | Sniffle BLE 5 sniffing + relay |
| Proxmark3 Easy | $40–80 | NFC/RFID crypto, emulation, sniffing |
| Yard Stick One (used, patchy) | $100–150 | rfcat scripted sub-GHz TX/RX |
| SDRplay RSP1B / Airspy Mini | $100–150 | Better SNR: DECT, TETRA, Iridium, AIS range |
| Flipper Zero | $170–200 | Field sub-GHz/NFC/RFID companion |
| ADALM-Pluto | $200–250 | DeDECTive, TX-capable lab SDR |
| HackRF One (+ PortaPack H2 ~$100–150) | $150–350 | 18.432 Msps DECT band, TX, [Mayhem firmware](https://github.com/portapack-mayhem/mayhem-firmware) (2026-10-12) |
| USRP B210 / LimeSDR | $400–1,300+ | srsRAN/5G lab, wideband satellite |

## Legal anchor list (cite these in the toolkit's warnings)

- **US jamming/interference**: 47 U.S.C. §301, §333; 47 CFR §15.3; FCC notice *"Jamming Cell Phones and GPS Equipment is Against the Law"* — docs.fcc.gov/public/attachments/DOC-304575A2.pdf
- **US interception**: 18 U.S.C. §2511 — govinfo.gov/content/pkg/USCODE-2023-title18/html/USCODE-2023-title18-partI-chap119-sec2511.htm
- **UK**: Wireless Telegraphy Act 2006 s.48 (interception and disclosure of messages) — legislation.gov.uk/ukpga/2006/36/section/48 (and the Act generally for unlicensed transmission)
- **Privacy**: TPMS/meter/wearable tracking and any collection of identifiers engages GDPR/UK GDPR; vehicle relay/replay is prosecuted as theft.
- Practical rule for the toolkit: mark every module as **RX-only / TX-capable / TX-and-attack**, and refuse to run TX modules without an explicit authorization token.

---

## Do not build on (verified dead or archived)

| Project | Last commit | Note |
|---|---|---|
| jopohl/urh (Universal Radio Hacker) | 2025-12-19 | **Archived, read-only** |
| riverloopsec/killerbee | 2022-08-19 | Dead — your current Zigbee base |
| ptrkrysik/gr-gsm | 2021-05-05 | Dead (cellular) |
| bistromath/gr-air-modes | 2020-05-06 | Dead (ADS-B) |
| virtualabs/btlejack | 2023-10-04 | Stale (BLE) |
| akestoridis/zigator | 2022-05-19 | Stale (Zigbee analysis) |
| pagermon/pagermon | 2024-04-21 | Stale (pager UI) |
| jontio/JAERO | 2023-11-21 | Stale (Inmarsat) |
| martinber/noaa-apt | 2023-11-30 | Stale (superseded by SatDump) |
| sui77/rc-switch | 2022-05-18 | Stale (use SmartRC-CC1101) |
| BastilleResearch/mousejack | 2016-08-07 | Research artefact, keep as reference only |
| RUB-SysSec/Mobile_sentinel | 2020-08-14 | Stale (baseband) |
| F5OEO/rpitx | 2024-09-30 | Dormant (still works) |

## Explicit uncertainties

1. **rtlamr offline mode** — inferred from README + `main.go` (only `flag.Parse` appears there); I did not exhaustively audit its flag definitions. Verify before promising offline CI.
2. **DeDECTive file input** — no `-f/--file` documented in its README; I did not read all CLI parsing code. The `IqSource`/`dedective_core` split makes it feasible, not present.
3. **rfcat Python 3 support** — docs are Python-2 era; repo is active. Unverified.
4. **WhisperPair / CVE-2025-36911** — details from two secondary outlets (SecurityWeek + Xcitium); primary paper not read.
5. **ADAC keyless figures** (~10% protected / ~350 models) — from secondary news coverage; the ADAC page I tried returned 404.
6. **Nordic nRF Sniffer URL** — returned 403 to my fetcher (bot block); link unverified though it is the vendor's official product page.
7. **SnoopSnitch** — no authoritative maintained repository resolved; do not cite as current.
8. **Sigfox** — I found **no maintained open-source decoder**; only academic SDR work (e.g. a VUT Brno thesis on SDR for Sigfox) and vendor payload decoders. Treat "Sigfox support" as research-grade/DIY, not an integration.
9. **UWB** — the only open sniffer I could verify (SEEMOO, 2022-03-02) is stale and research-grade; Ghost Peak (USENIX Security 2022, arXiv 2111.05313) and the Troopers 2023 UWB smartphone analysis are the key literature. No maintained tooling → genuine gap.
10. **Jamming detection and RF fingerprinting** — datasets/papers (SMoRFFI arXiv 2511.07770; INRIA Zenodo dataset 2026) but no turnkey tool; my claim that no maintained tool exists is a negative finding and could be wrong.
11. **Web-Spectrum** (RTL-SDR-based GPS signal analyser, seen on RTL-SDR.com) — headline only, contents unverified; possibly useful for GNSS quality monitoring.

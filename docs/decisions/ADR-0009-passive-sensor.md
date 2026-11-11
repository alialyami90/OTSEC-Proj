# ADR-0009: The passive sensor: which engine, and where it runs

- Status: **accepted, 2026-11-11 (D4-85): the owner chose option (b)**, a separate Linux sensor at each site that feeds the node, on D1's recommendation and P4-4-S1's evidence. This supersedes D4-78's choice of option (a). **The engine is not yet approved:** Zeek is the provisional engine, and D1 approves it after E-D4-03 (brief P4-4-S2), as "Decision" says. HR-20 closes with this decision, and reopens if (a) or (c) is ever reopened. History: proposed from 2026-11-07. The owner chose (a) on 2026-11-10 (D4-78), with the engine and the Npcap licence left open (D4-83).
- Date: 2026-11-07; decided 2026-11-11
- Deciders: D1, with D4 (author), D5 (the process and the node's side) and D3 (the boundary). D2 reviews protocol interpretation, D6 testability. The owner decides the two questions in "What decides it".
- Related: R6.1 to R6.7, V-M6, C-09, C-11, H-06; ADR-0002 item 2 (b), ADR-0007; `docs/phase0/A4-telemetry-feasibility.md` §3 and §4 (E-A4-01); threat model TB6, AP-30 to AP-36, SC-19, HR-20 (#523); D4-66, D4-67, D4-78; brief P4-4-A4 in `docs/agent-handoffs.md`, and brief P4-4-S1 (D4-83, #614)

Every claim below carries its evidence class: `desk` (read from a cited document), `simulated (Linux)` or `simulated (Windows Server)` (a run on recorded or synthetic traffic), or `unknown`. Nothing in this ADR has been run on the owner's hardware or a site network, and nothing captures a real network (D4-66).

## Context

ADR-0002 item 2 (b) reserves a separate process for Zeek or Suricata "when R6 work starts", and asks a later ADR to name the boundary that process enforces. That work has started (D4-66). Every engine and decoder evaluated so far ran on Linux (E-A4-01). The site node, though, is a dedicated Windows 10/11 machine (ADR-0007). A packet capture on Windows needs a kernel-mode capture driver, and that driver's licence and privilege are part of the choice (AP-31, HR-20).

C13 (`otsec.netobs/0.1`), the network baseline note and D5's node note all depend on where the sensor runs. That is why this ADR comes first (brief, "Order").

## Options considered

- **(a) Zeek or Suricata on the Windows site node, with a capture driver.** The engine runs as its own service under its own account (AP-30), and reads a monitoring NIC on the node.
- **(b) A separate Linux sensor at the site that feeds the node.** The engine runs on its own small machine with the monitoring NIC, and sends C13 records to the node over the network.
- **(c) The project's own Go decoders in a separate process on the node.** These are memory-safe decoders for the first protocol set, running in their own process and account. Capture is still needed, through a driver or the OS.

One variant applies to (a) and (c) and is recorded on its own: **(a′/c′) capture by the OS's built-in Packet Monitor (`pktmon`) into rotating capture files, which the engine or decoder reads.** This would avoid shipping a third-party driver. Whether `pktmon` sees enough on a SPAN or TAP port is `unknown` (below).

## Evidence

### Upstream sources read for this draft (2026-11-07, `desk`)

These were read from `raw.githubusercontent.com`, the only upstream host this environment reaches (D1 tested it on 2026-11-07). The project's site, `npcap.com`, `docs.zeek.org` and `suricata.io` are refused here. A cell that needs one of them is `unknown` until the owner allows the host or another source is found.

| Source | What it says | SHA-256 of the file read |
| --- | --- | --- |
| `nmap/npcap` `master/LICENSE` | Npcap "is not open source software and may not be redistributed or used in other software without special permission from the Nmap Project". The free edition "is usually limited to installation on five systems". Products need the sold "Npcap OEM Redistribution License". Organisations above five systems need the "Npcap OEM Internal-Use License". The silent installer is an OEM feature. | `0543f4f93939013f80852d33469b1b5a2623676b387994ffb7a01e34e443ac83` |
| `zeek/zeek` `master/COPYING` | BSD-style licence (The Regents of the University of California). | `1f984adb6b5cd93d5035c2a87c2df5f38922649fbea90c7bd79ff321d17333aa` |
| `zeek/zeek` `master/NEWS` (master is `9.1.0-dev.539`) | Zeek 6.0 added "experimental support … on Microsoft Windows", with btest not running on Windows and Spicy unsupported there. The Zeek 8.2.0 section says "Windows support has been greatly improved … The btest suite now runs on CI builds. The great majority of btests pass." How Zeek captures live on Windows is not stated in NEWS. | `8f72f184d8542b9b45e2eb63c7ffaa71428a943cc08149052940007e9ec463f0` |
| `OISF/suricata` `master/LICENSE` | GNU GPL version 2. | `8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643` |
| `OISF/suricata` `master/doc/userguide/install/windows.rst` | "Npcap is required for live capture on Windows." WinDivert is "required for IPS mode", which a passive sensor never uses. For end users it recommends "the Windows installer available on the Suricata download page". | `ca1dc37d836147cc3a382fee8fad496deb0dd1fe9cb959ff6a96b874df76a67f` |
| `cisagov/icsnpp-dnp3` and `cisagov/icsnpp-modbus` `main/LICENSE.txt` and `README.md` | BSD 3-Clause (Battelle Energy Alliance). Installed with `zkg`. Windows is not mentioned. | not kept here. D7 hashed both `LICENSE.txt` files on 2026-11-11 (byte-identical, `4c66ca6036dae3010138952138e8df3a7d037cf05a9643a108f20f05c794e98d`, `docs/release.md` §4). |

### Sources read on 2026-11-11 (P4-4-S1, `desk`)

From D4's CLI session, `npcap.com`, `zeek.org`, `docs.zeek.org` and `openinfosecfoundation.org` were reachable with a direct fetch. `suricata.io` returned 403 to a direct fetch and was read through WebFetch, which returns a summary, not the text. Each fact, its URL and the SHA-256 of the file read are in [`docs/phase4/D4-sensor-engine-eval.md`](../phase4/D4-sensor-engine-eval.md) §3 and §5. The files are kept in `reference/carried/d4-sensor-engine-eval-2026-11-11/`, which is not committed. In short:

- **Npcap** (`npcap.com/`, `/oem/`, `/oem/internal.html`, `/oem/redist.html`, the user's guide; the `LICENSE` is unchanged from 2026-11-07). The free edition: up to 5 systems, where a virtual machine counts as one, no redistribution, and no silent installer. OEM Internal-Use: from US$4,980 for 100 installs to $59,980 for unlimited installs, perpetual, with optional maintenance. OEM Redistribution: $39,980, $59,980 or $79,980 perpetual by company size, or $6,980 to $11,980 a quarter. `/admin_only`, off by default, restricts the capture and injection devices to SYSTEM and built-in Administrators, with UAC elevation for each process. The installer also creates an `npcapwatchdog` startup task that runs batch files from the install folder, and WinPcap-compatible mode, on by default, puts its DLLs in the system folder. 802.1Q VLAN support is "currently unsupported". The 1.90 installer names Windows 10 and 11 among its systems.
- **Suricata** (suricata.io/download through WebFetch; the directory `openinfosecfoundation.org/download/windows/`). The stable release is 8.0.8, and its one Windows link is `Suricata-8.0.8-1-64bit.msi`. No checksum or signature file is published for Windows installers, so the workflow's pin is a first-use pin. The MSI is Authenticode-signed by the Open Information Security Foundation.
- **Zeek** (`zeek.org/get-zeek/`, `docs.zeek.org/en/master/install.html`, GitHub releases to v9.0.1, `v9.0.1/NEWS` and `vcpkg.json`). No official Windows binary or package: downloads are "Source Code | Linux Binaries", and releases carry only source. The Windows build is from source with Visual Studio, CMake and vcpkg's `libpcap`.

### The comparison

| Row the brief asks for | (a) Zeek or Suricata on the Windows node | (b) Linux sensor at the site | (c) own Go decoders on the node |
| --- | --- | --- | --- |
| **Runs on Windows** (`windows-latest` run; offline decoding kept apart from live capture) | Zeek: Windows support "experimental" since 6.0 and "greatly improved" in 8.2 (`desk`, NEWS). Suricata: OISF's signed Windows build 8.0.8 installs unattended but **does not start without Npcap, not even to read a file**: `suricata.exe` imports `wpcap.dll` and exits `0xC0000135` (`simulated (Windows Server)`, [run 43017246251](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43017246251)). So its offline decoding on Windows is still `unknown`. Zeek: **no official Windows binary or package exists** (`desk`, 2026-11-11); Zeek on Windows would be a project build from source, not tried. Live capture on Windows Server: `unknown`, because no run installs Npcap (licence row). The 10/11 LTSC floor is `unknown` for every option. | Not applicable on the node. The sensor runs Linux, where E-A4-01 ran (`simulated (Linux)`). | Go cross-compiles for `windows/amd64` (ADR-0003, the node's own build). The decoders do not exist yet. Live capture needs a driver or `pktmon`. `pktmon` on Windows Server captures and converts the runner's own traffic as administrator, and in one run saw no loopback traffic, which is not a confidentiality property (E-D4-01, `simulated (Windows Server)`). |
| **Capture driver and its licence** for a product that ships it | Npcap. It can't be redistributed in a product without the sold OEM Redistribution licence. The free edition is limited to five systems, so even "the customer installs it" does not cover a fleet (`desk`, LICENSE above). Prices (`desk`, npcap.com, 2026-11-11): OEM Internal-Use from US$4,980 (100 installs) to $59,980 (unlimited); OEM Redistribution $39,980 to $79,980 perpetual by company size, or $6,980 to $11,980 a quarter. Which one applies depends on whether the owner's organization installs it on its own nodes or OTSEC ships it to others. Variant (a′) uses `pktmon` instead, with no third-party licence, but **with Suricata's official build it saves no licence**, because that build needs Npcap installed even to read files (E-D4-01 part 2). Its fitness is otherwise `unknown`. | None on Windows. Linux `AF_PACKET` is in the kernel and needs `CAP_NET_RAW` (`desk`, AP-31). | The same as (a): Npcap with its licence, or `pktmon` (c′). |
| **The engine's own licence** | Zeek: `COPYING` is BSD-3-Clause, and `COPYING-3rdparty` adds other licences (see "Decision", the engine's licences, and `docs/release.md` §4). ICSNPP BSD-3 (`desk`). Suricata GPLv2 (`desk`): a separate process is not linking, but shipping its binary brings the GPL's distribution duties (source offer, licence text). | The same engines and licences, shipped on the sensor's image, or the customer installs them. Who ships the Linux image is an open question. | The project's own code. Any decoder library taken in must not be GPL (brief exclusion: no libiec61850 or lib60870 linked). |
| **Protocols decoded**, shown on the public captures | E-A4-01 (`simulated (Linux)`): Zeek 8.0.4 decoded all 6 DNP3 captures, including midstream, and Modbus on 2 of 3. Suricata 7.0.3 decoded 4 of 6 DNP3 captures by default (2 more with midstream), and Modbus on 1 of 3 by default (2 of 3 with midstream). Neither decodes IEC 61850 MMS, GOOSE, SV or IEC 104. **Telnet, FTP, HTTP and SNMP decoding is not shown on any capture:** E-A4-01's table has no rows for them, and no engine document on them has been read for this ADR (D2 on #618). On Windows: still `unknown`, because Suricata's official build does not start without Npcap, and Zeek has no Windows binary (E-D4-01 part 2). | As E-A4-01, on the same OS it ran on. | None yet. DNP3 and Modbus/TCP framing are small, documented formats. IEC 61850 and IEC 104 need their own decoders under every option, because no stock engine has them (A4 Q4). |
| **Midstream handling** | Zeek: yes (`simulated (Linux)`). Suricata: only with `stream.midstream=true`, whose false-positive cost has not been measured (A4 §3). | The same. | A design choice. The decoder must start on any frame (A4 §4), and that is testable on the two handshake-less captures. |
| **PRP duplicate handling** (two copies with the same RCT sequence number, LAN A and LAN B). Pass: each flow and service is recorded once, with counts equal to those from the LAN-A-only capture (D6). | **Fails as stock engines** (E-D4-02, `simulated (Linux)`, offline). Suricata 7.0.3 and Zeek 8.0.4 each record every flow once, with the same service, but count both LAN copies: on `-ab` every packet total is exactly twice the `-a` total, in all 18 rows. So neither discards PRP duplicates by RCT. **Requirement:** a PRP duplicate-discard stage before the engine, keyed on (source MAC, RCT sequence number) (D1). It applies only if the site's station network is PRP, which is still asked of the owner. | The same as (a): the same engines, and the same requirement. | A design choice. Discard by (source MAC, RCT sequence number) before decoding, as A4 §4 and R-A4-4 already require. |
| **Process and privilege** | D5 (#525, `docs/phase4/D5-sensor-node.md`): the sensor is its own SCM service (`NT SERVICE\otsec-sensor`, its own service SID, SCM restart), not a child of the node. A child would run under the node's account, so a decoder exploit would reach the store and keys. W-2 also denies the node the privilege to start a child under another account (ADR-0002 items 2 and 5 agree). It never runs as LocalSystem or in Administrators. **Npcap's install mode is an open choice, and neither setting is safe yet** (D3 on #618; `desk`, Npcap user's guide, 2026-11-11). `/admin_only` is off by default ("Unless otherwise noted, the default for these options is no"). Without it, accounts other than the sensor's may open the driver's "capture and injection" devices on every bound adapter, including the collector's device-facing one, which is the opposite of AP-31 (2) and a C-11 risk. With it, the devices allow only SYSTEM and built-in Administrators, with UAC elevation for each process, so the engine starts as an administrator. AP-31 (2) then needs it to open the adapter and drop privilege before decoding. Four things stay `unknown` until a lab machine shows them: which accounts can open and send without the option; whether the driver can be bound to the monitoring adapter only, and stays so; whether the devices' access list can name the sensor's SID; and whether Suricata can open the adapter and then drop privilege. | A whole host whose only job is the sensor. The engine runs with `CAP_NET_RAW` only, dropped after the socket opens (AP-31). The node supervises nothing; D5's note covers the link's health instead. | As (a): its own SCM service and service SID. The decoder process needs no capture privilege if it reads capture files written by `pktmon` (c′). Something must start `pktmon` and keep it running. If that needs Administrators, it is a third privileged process, best kept as a small SCM service that runs only `pktmon` and parses no packets (D5). Its account is `unknown`. E-D4-01 ran as the runner's administrator, so it cannot show it; a run under a less-privileged account, or a lab run, must. |
| **Live interface fed by a timed replay** (R6.4 latency, the C-11 test) | On Windows Server: `unknown`. There is no network namespace or veth on Windows. A loopback adapter or Npcap's send path would be needed, and the sensor itself must never use that path (AP-32). Loopback looks closed for (a′): `pktmon` captured none of 106 payload segments replayed over 127.0.0.1, at the NICs or at every component (E-D4-01 part 2). That is one run, as administrator, on Windows Server 2025, and it must never be cited as a confidentiality property. | Expected, but not yet shown: a veth pair across network namespaces with a timed replayer, the rig in D6's plan §6 (#527). No project workflow uses veth or a replayer yet. V-M8's paired runs use `unshare -n` with loopback only (`ci.yml`), so they are not a precedent for this (D6). | As (a) on the node. Or the decoder is tested on Linux with the same veth replay, which proves the decoder but not the Windows capture. |
| **Channel to the node and how it is authenticated** | A named pipe on the collector's pattern: each end checks the other's service SID, and only the node writes the store (D5, #525; AP-34). | A network link with enrollment and a revocable credential like a node's (SC-11), peer binding, replay protection, acknowledgement of the committed sequence number and resume after a break (C-04, E-01), set in the link's contract. The new device's own management interface and update path count as attack surface (D3). The node opens the link, so the node gains no inbound port. The sensor host's listener is bound to its management interface only and firewalled to the node's address, and never listens on the station LAN (D5, agreeing with AP-34). | As (a). |
| **What C-11 relies on** | A TAP is receive-only by construction. A SPAN port with a host NIC relies on host settings (D5, #525; AP-32): every binding removed from the NIC except the capture filter, a deny-all firewall rule on the sensor's service SID, and the monitoring NIC never ETH1 while Intel AMT is on (ADR-0007 item 8). None of these blocks a send made through the driver itself, so the zero-frames test is the evidence, not the settings. Zeek and Suricata link libpcap, which can send, and Suricata transmits by design in `reject` and IPS modes. So for an engine, C-11 also rests on IDS mode and a rule set that is refused at load if it holds any `reject*` or `drop` action (AP-31, AP-32 as amended on #523). The zero-frames test needs its negative control, a deliberately misconfigured interface that must show frames. | The same choice on Linux: the interface up with no address, ARP off, IPv6 disabled, and no discovery daemons. Whether an nftables `netdev` egress drop catches every `AF_PACKET` send is `unknown` until tested (D5). It can be tested in CI in a namespace. | As (a). Because the decoder is the project's own code, a link check can show that it has no send or inject call (AP-31). |
| **Hostile input reaches** | C and C++ decoders (Zeek, Suricata, ICSNPP) on the machine that holds the node's store, keys and the collector's route. The process and account boundary is the only wall (AP-30). | C and C++ decoders on a separate host. A decoder exploit holds the sensor, not the node. It can still lie to the node (AP-34). | Memory-safe Go, fuzzed (SC-14), on the node, inside its own process and account. Exploitation is much less likely, but the decoder can still lie or crash. |
| **Cost to the owner** | The Npcap OEM licence: from US$4,980 (Internal-Use, 100 installs) to $79,980 and maintenance (Enterprise Redistribution) (`desk`, 2026-11-11). With Suricata's official build, (a′) does not avoid it. Only a project-built engine that needs no `wpcap.dll` could, and none has been tried. | A second machine at each site, and its patching. ADR-0007 gives the platform "its own dedicated machine" per site, so a second box is the owner's call. | Decoder build and maintenance for every protocol, which the brief's "evaluate existing engines first" rule asks us to justify. For IEC 61850 and IEC 104 that work is needed under every option anyway. |

### Protocol points (D2 on #526)

D2 raised six points at 216b111. Each one is answered here, or recorded as `unknown`, or carried to D2's note `docs/phase4/D2-sel-network-services.md`.

1. **Other protocols SEL devices may speak.** These are C37.118 synchrophasors, EtherNet/IP, PTP, SEL Fast Operate inside a Telnet stream, OPC UA and OpenFlow. ICSNPP packages exist for C37.118 (`icsnpp-synchrophasor`), EtherNet/IP (`icsnpp-enip`) and OPC UA binary (`icsnpp-opcua-binary`); their READMEs were read on 2026-11-07, and none has been run here. Suricata's EtherNet/IP parser was enabled in E-A4-01, but no EtherNet/IP capture was in the set. No ICSNPP package for PTP was found under that name. Fast Operate inside Telnet has no engine decoder known to this draft. OpenFlow on the SEL-2731 and SEL-2741 is OpenFlow 1.3 over TLS on TCP 6653 (D2 on #618), so under any engine only its TLS metadata is visible. Decoding of every protocol in this item is `unknown` under every option until a GT-PCAP capture holds it. Which of these SEL families actually offer is D2's note's job. None of them is in the first protocol set (#522), so each is a stated visibility limit (R6.1) until it is added.
2. **Detection by content, not only by registered port.** A service on a non-standard port is missed by a port-only decoder. Whether each engine finds DNP3 and Modbus by content on another port is `unknown`. GT-PCAP now holds one of each (#623): DNP3 on a moved outstation port, synthesized, and Modbus/TCP with its server port moved, derived from a public capture, beside DNP3 over UDP (D6 and D2 on #618). Under (c), the decoder detects by content on any port as a design rule.
3. **DNP3 Secure Authentication (group 120).** Tshark shows group 120 objects, which is GT-PCAP's label source. Whether Zeek, ICSNPP-DNP3 or Suricata expose group 120 per session, which the "DNP3 without SA" flag needs, is `unknown`. Under (c) it is a design rule. A passive sensor can see that SA objects are exchanged, but cannot check their MACs (D6's plan §2B).
4. **SNMPv3 header fields.** These are the message version, the engine ID, the user name, the flags, and the boots and time, which are in clear (D6's plan §2B). Which of them each engine logs is `unknown`. The engine ID and user name are identity evidence for R6.7, so C13 carries them where the sensor reads them.
5. **HSR beside PRP.** HSR frames carry an HSR tag and circulate in both directions (A4 §4). No engine here is documented to strip HSR tags or discard duplicates, so that is `unknown`. No GT-PCAP capture holds HSR. For the first sensor, HSR is a stated limit (R6.6): an HSR segment is not covered until a decoder and a capture exist.
6. **Non-IP frames and 802.1Q tags in the capture** (first written for `pktmon`). GOOSE, SV, PRP trailers, LLDP and VLAN tags all need the capture to keep the whole layer-2 frame. E-D4-01 captures only the runner's own IP traffic, so it cannot show whether `pktmon` keeps non-IP frames, PRP trailers or 802.1Q tags. That stayed `unknown` for (a′) and (c′). **Under (b), the chosen option, the question is Linux `AF_PACKET`'s:** whether the sensor's capture keeps non-IP frames, PRP trailers and 802.1Q tags as the engine sees them. That is `unknown` until a lab run on a SPAN or TAP port shows it.

### E-D4-01 (run on 2026-11-07)

The experiment is `modules/telemetry/experiments/sensor-windows/`, run by the dispatch-only `.github/workflows/d4-sensor-eval.yml` on `windows-2025`. D4 dispatched it after #526 merged (run 42404069667). Every result below is `simulated (Windows Server)`.

| Question | Result |
| --- | --- |
| Edition and build | Windows Server 2025 Datacenter, version 24H2, build 26100. |
| Npcap on the image | Not present. |
| `pktmon` present | Yes, with no third-party driver installed. |
| `pktmon` captures and converts to pcapng | Yes. With no packet filter, it captured 82 packets of the runner's traffic while the runner downloaded `dnp3-read.pcap`, so the count is not only the download. On stop, `pktmon` reported "No events lost", which is the line that speaks to capture loss. `pktmon etl2pcap` then converted all 82 to pcapng, with a packet drop count of 0 in the conversion. The capture itself was not uploaded, only the counts. |
| Suricata's Windows build decoding offline | Not run on 2026-11-07: the `suricata` job needed the installer's URL and SHA-256, and none was given at dispatch. Run on 2026-11-11: it does not start without Npcap (part 2, below). |

What E-D4-01 does not show:

- **The account `pktmon` needs.** The job ran as the runner's administrator, so whether a service account with less privilege can capture is `unknown`. This matters for D5's privilege drop under (a′) and (c′).
- **Promiscuous capture on a SPAN or TAP port.** The runner has no such port.
- **Non-IP frames, PRP trailers and 802.1Q tags** (protocol point 6). Only IP traffic was captured.
- **Live capture with Npcap.** There is no licence to install it unattended.
- **Any client edition, including ADR-0007's Windows 10/11 IoT Enterprise LTSC floor.**

All of these stay `unknown` until a lab machine runs them (H-06's hardware run, or a new H-row D6 proposes).

### E-D4-01 part 2 (run on 2026-11-11, P4-4-S1)

[Run 43017246251](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43017246251), `d4-sensor-eval` at `e65a9f52`, `windows-2025`. Every result is `simulated (Windows Server)`. The tables, the counts and the pin are in [`docs/phase4/D4-sensor-engine-eval.md`](../phase4/D4-sensor-engine-eval.md) §1, §2 and §4. Npcap was not installed.

| Question | Result |
| --- | --- |
| The installer | Suricata 8.0.8, `Suricata-8.0.8-1-64bit.msi`, with the first-use SHA-256 pin `7c6b302e…dd084` (OISF publishes none for Windows) and a valid Authenticode signature by the Open Information Security Foundation. Both are checked before `msiexec` runs. `msiexec /qn` exits 0, so it installs unattended, and it installs no Npcap. |
| Does it start and read a capture file with no Npcap? | **No.** `suricata.exe -V` exits `0xC0000135` and prints nothing. It imports `wpcap.dll`, which is not on the image. The MSI's own exit text says Npcap must be installed "with winpcap compatability mode in order to run Suricata". |
| Protocols decoded on the public captures and GT-PCAP | `unknown`. All 58 captures (21 public, 18 PRP, 19 DNP3) matched their pinned SHA-256, and none ran. |
| (a′) end to end: `pktmon`, `etl2pcap`, the engine | Capture and conversion work at the NICs: 184 frames, "No events lost", 184 formatted. **`pktmon` saw none of the 106 segments replayed over loopback**, at the NICs or at every component. The engine stage is `unknown`, because no engine starts. |

**What it changes.** Under (a), Suricata needs Npcap whatever the capture path, so (a′) saves no driver licence with Suricata's official build. Zeek has no Windows binary. Loopback did not feed a timed replay for (a′) on this image. That rests on one administrator run on Windows Server 2025, and it is never to be cited as a confidentiality property.

**E-D4-01 does not choose an option.** It shows only that unfiltered capture works on Windows Server 2025 as administrator, simulated in CI, with no third-party driver. That keeps the `pktmon` variant possible; it does not show the variant is good enough for a site, and it says nothing for or against (a), (b) or (c).

### E-D4-02 results

E-D4-02 answers the PRP row. `modules/telemetry/experiments/prp-engines/` works in five steps:

1. It rebuilds GT-PCAP's 9 PRP pairs with D6's `prp.py` and checks them against `prp-derived.sha256`.
2. It labels them with D6's `prp_check.py`, which runs tshark, pinned at 4.2.2. The run stops if another version is installed.
3. It runs Suricata, from Ubuntu's package and **with `stream.midstream=true`**, and Zeek 8.0.4 in Docker, as in E-A4-01. Each engine runs on each `-ab` capture, which holds both LAN copies, and on each `-a` capture, which holds LAN A only. The pulled Zeek image's digest is written into `versions.txt`, so the result names exactly what ran (D3).
4. It checks the row's pass condition for each capture and engine. Each flow must have as many records on `-ab` as on `-a`, with the same packet total and the same service (Zeek's `service`, Suricata's `app_proto`). Every labelled flow must be in the `-a` output with its labelled packet count, so a flow that both runs drop does not pass (D6).
5. A capture whose logs are missing reads `not run`, and the job fails unless every row passes. A `not run` row is `unknown`, never a pass (D6).

**The run.** Run 42407918524, job `prp-engines`, on `main` at `7716087`, `ubuntu-24.04`, on 2026-11-07 (`simulated (Linux)`, offline files, not live capture). Versions: Suricata 7.0.3, Zeek 8.0.4 (`zeek/zeek@sha256:753a694a1fc3a3447f3be02d5a0b80ac77f70b47d298de736e855e6d9799a3fa`), and tshark 4.2.2. Every PRP pair's trailers checked out, and every capture ran. The job exits 1 because rows fail, as designed.

| Capture | Labelled flows | Flows `-a` / `-ab` | Packets `-a` / `-ab` | Once | Packets equal | Services equal | Labels met |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dnp3-digitalbond-part1 | 8 | 8 / 8 | 181 / 362 | yes | no | yes | 8 of 8 |
| dnp3-digitalbond-part2 | 1 | 1 / 1 | 33 / 66 | yes | no | yes | 1 of 1 |
| dnp3-malformed | 198 | 198 / 198 | 198 / 396 | yes | no | yes | 198 of 198 |
| dnp3-read | 1 | 1 / 1 | 8 / 16 | yes | no | yes | 1 of 1 |
| dnp3-select-operate | 1 | 1 / 1 | 12 / 24 | yes | no | yes | 1 of 1 |
| dnp3-write | 1 | 1 / 1 | 8 / 16 | yes | no | yes | 1 of 1 |
| modbus | 1 | 1 / 1 | 102 / 204 | yes | no | yes | 1 of 1 |
| modbus-digitalbond-part1 | 6 | 6 / 6 | 118 / 236 | yes | no | yes | 6 of 6 |
| modbus-digitalbond-part2 | 1 | 1 / 1 | 350 / 700 | yes | no | yes | 1 of 1 |

The two engines gave identical rows, so each row stands for both.

**What it shows.**
- **The doubling is the only failure** (the `-ab` and `-a` columns, as D6 asked). Neither engine splits a flow or changes its service when both LAN copies are present. But both count every copy, so each packet total doubles.
- **There is no R6.1 gap.** Every flow tshark labels is in both engines' `-a` output with its labelled packet count.
- **The requirement on (a) and (b)** (D1): a PRP duplicate-discard stage, keyed on (source MAC, RCT sequence number), runs before the engine. Under (c) the project's own decoder does the same discard (A4 §4, R-A4-4). Whichever option runs, the sensor reports it in C13's `prp.duplicates_discarded`. A sensor that sees both LANs and does not discard is a coverage mismatch at the node, not data (C13 §4.4). The requirement applies only where the station network is PRP, which the owner has yet to say.

**What it doesn't show.**
- Live capture on either LAN, or behaviour on Windows.
- HSR (protocol point 5).
- Whether a pre-filter in front of an engine keeps up at line rate.
- What the engines' own alert rules do with doubled packets. The run read flow and service records only.

## What decides it

**Answered on 2026-11-11 (D4-85).** The owner allowed a second machine at each site by choosing (b) (question 1). So no Npcap licence is bought, and question 2 is answered by the choice. The record of what was asked is kept below.

The options split on two questions only the owner can answer, and on two experiment results.

1. **Owner: may a site have a second machine for the sensor?** If yes, (b) is the only option where the engine is already shown decoding the first protocols (E-A4-01, on Linux), with no Windows driver licence, and with hostile parsing off the machine that holds the store and the collector's route. Its costs are a second box to enrol, patch and protect (D3's row), and the owner's hardware budget.
2. **Owner: is an Npcap OEM licence acceptable?** The prices are now known (`desk`, 2026-11-11): Internal-Use from US$4,980 for 100 installs, Redistribution from $39,980. If it is not acceptable, and (b) is not allowed, (a) has no shown path: Suricata's official build needs Npcap even to read files, and Zeek has no Windows binary. (c) then depends on `pktmon` (variant ′) being good enough, which is `unknown`.
3. **E-D4-01:** `pktmon` captures and converts to pcapng with no third-party driver on Windows Server 2025 (runs on 2026-11-07 and 2026-11-11). In one administrator run it saw no loopback traffic, which is not a confidentiality property. Whether it captures under a service account with less privilege, on a SPAN port, with layer-2 frames intact, and on a client edition is still `unknown`. Suricata's official Windows build does not start without Npcap (2026-11-11).
4. **E-D4-02, on D6's PRP captures:** neither engine discards RCT duplicates (run on 2026-11-07). If the station network is PRP, (a) and (b) need a duplicate-discard stage before the engine, and (c) builds it into its decoder. This doesn't separate the options, but it adds a component to (a) and (b).

## Decision

**Option (b): a separate Linux sensor at each site, which feeds the node** (the owner, 2026-11-11, D4-85, on D1's recommendation). The engine and the capture privilege are below, with what (b) commits the project to and what is left to later briefs.

### Why (b), from this ADR's evidence

- **(b) is the only option where an engine is shown decoding two protocols of the first set**: with stock Zeek 8.0.4, DNP3 on 6 of 6 public captures and Modbus/TCP on 2 of 3 (E-A4-01), and once per flow on GT-PCAP's PRP pairs (E-D4-02). Both are `simulated (Linux)`, on the OS the sensor would run. The rest of the first set is not shown (see "What the engine choice does not claim").
- **(a) had no shown path on Windows** (E-D4-01 part 2, P4-4-S1):
  - Suricata's official Windows build does not start without Npcap. It imports `wpcap.dll` and exits `0xC0000135`, even to read a file. So nothing was decoded on Windows.
  - There is no official Zeek binary or package for Windows (`desk`).
  - Npcap needs an OEM licence for a fleet: from US$4,980 (Internal-Use, 100 installs) to $79,980 and maintenance (Redistribution). Its free edition has no silent install (`desk`, npcap.com).
  - Npcap's install mode was undecided, and D3 made it a condition on (a): without `/admin_only` other accounts may capture and send on every bound adapter, including the collector's device-facing one, and with it the engine starts as an administrator (AP-31 (2)).
  - Npcap's guide says 802.1Q VLAN support is "currently unsupported" (`desk`).
- **(c′) rested on `pktmon`**, whose fitness on a SPAN or TAP port, under a less-privileged account and with layer-2 frames intact is `unknown`. It would also have brought forward decoder work for DNP3 and Modbus that stock engines already do.
- **Under (b), hostile input is parsed off the machine that holds the node's store, its keys and the collector's route** (AP-30). A decoder exploit holds the sensor, not the node. It can still lie to the node (AP-34, AP-36).

### The engine under (b): provisional

**Zeek is the provisional engine, with the ICSNPP-DNP3 and ICSNPP-Modbus packages as candidates. D1 approves it after an offline Linux run, E-D4-03, under brief P4-4-S2,** which D1 issues next and which is not built here (D1's ruling on #618). E-D4-03 runs Zeek with and without the two ICSNPP packages over three sets of captures:
- GT-PCAP's DNP3 cases, including group 120, DNP3 on a moved outstation port and DNP3 over UDP (its ports by inference, settled by H-23; D2), which GT-PCAP holds since #623, and the derived Modbus/TCP case on a moved port (D6 and D2 on #618);
- GT-PCAP's PRP pairs;
- the public captures.

**What would turn the choice.** If Zeek, with or without ICSNPP, cannot show DNP3 group 120 per session, V-M6's "DNP3 without SA" row fails on Zeek. The same holds if it cannot find DNP3 or Modbus on a moved port, or cannot read DNP3 over UDP where the sites use it. D1 decides on E-D4-03's result and records it here.

D4's reasons for Zeek:

1. **Decoding on two protocols of the first set** (E-A4-01, `simulated (Linux)`, stock engines, no ICSNPP):
   - Zeek 8.0.4 decoded all 6 DNP3 captures, including the 2 without a TCP handshake, with no setting, and Modbus as a service on 2 of 3.
   - Suricata 7.0.3 decoded 4 of 6 DNP3 and 1 of 3 Modbus by default, and needs `stream.midstream=true` to reach 6 of 6 and 2 of 3. Polling sessions start long before a sensor does, so midstream matters, and the false-positive cost of Suricata's setting was never measured.
   - On PRP duplicates the two engines behave identically (E-D4-02): one record per flow, every packet counted twice.
2. **Zeek's logs are the baseline's input.** Its connection and protocol logs record who talks to whom with which function codes, which is what the network baseline note learns. Each row is citable evidence. Suricata is alert-centric, with flow and protocol events beside its alerts (A4 §3).
3. **Licences.**
   - Zeek's `COPYING` is BSD-3-Clause, and ICSNPP is BSD-3-Clause. Zeek's `COPYING-3rdparty` adds MIT, BSD, Boost-1.0, Apache-2.0, MPL-2.0, LGPL-3.0-or-later with its author's BSD permission, public domain, and the JSON licence, whose "shall be used for Good, not Evil" term D7 calls unusual (`docs/release.md` §4). Which of these reach the build the project ships is for D7 to settle against that build. Shipping Zeek means carrying `COPYING`, the applicable notices and the MPL-2.0 file's source.
   - Suricata is GPLv2: its binary would carry the licence text and the source, or a written offer of it valid for at least three years (`docs/release.md` §4; D7 on #618).
   - The engine is a separate program, so it does not put the node's binaries under its licence. But the project's own sensor code (the PRP discard stage, the redaction and the link to the node) shares the sensor host with the engine. So a separate process settles only part of the GPLv2 question for Suricata, and D7 settles the rest if Suricata is ever chosen (D7 on #618).
4. **Who installs and patches it.** Zeek publishes Linux binaries (through the openSUSE Build Service) and container images (`desk`, zeek.org, 2026-11-11; E-A4-01 and E-D4-02 ran `zeek/zeek`). Ubuntu's archive carries Suricata (E-D4-02 installed it with `apt`). Whether the project ships the sensor's Linux image with the engine in it, or the owner's organization installs both, is open (below). Either way, AP-31 (1) and `docs/release.md` §4 require the engine and its packages at a pinned version, never fetched at run time. That includes ICSNPP, which `zkg` would otherwise download. AP-31 is proposed, and was first written for the node (D7 on #618). As it now reads (D3, P4-4-L1, #624), it covers the sensor host: the engine, each engine package and the project's sensor programs pinned, carried by the platform's signed release, listed in the SBOM, and never fetched at install time or at run time, with the engine's own fetchers, `zkg` among them, absent or off. If the site installs the engine itself, this rests on the site's procedure (HR-21).

**Suricata stays a possible later addition** for signature rules, as A4 §3 proposed, and the fallback if E-D4-03 turns the choice. It is not part of this decision.

**ICSNPP is not shown.** No experiment in this repository installs ICSNPP: there is no `zkg` or `icsnpp` under `modules/telemetry/experiments/`. What ICSNPP-DNP3 and ICSNPP-Modbus decode, and whether they work with the Zeek version the project pins, are `unknown` until E-D4-03 (D6 and D2 on #618).

**What the engine choice does not claim** (D2 on #618):
- Zeek's built-in analyzers are shown for DNP3/TCP and Modbus/TCP only (E-A4-01).
- Telnet, FTP, HTTP, SNMP, NTP and DNP3 over UDP are not shown on any capture.
- SEL ASCII and the SEL Fast protocols inside Telnet, IEC 61850 MMS, GOOSE and SV, IEC 60870-5-104 and PTP need the project's own decoder under every option.

**Still `unknown` for the engine under (b):**
- ICSNPP itself, as above.
- Whether Zeek and ICSNPP expose DNP3 group 120 per session (protocol point 3) and SNMPv3's header fields (point 4).
- Whether Zeek finds DNP3 and Modbus by content on a non-standard port (point 2).
- DNP3 over UDP.
- What Zeek decodes of any protocol the sites turn out to use beyond the two shown.
- Whether Zeek can run with `CAP_NET_RAW` only and drop it after its socket opens (AP-31 (4)).
- Zeek's own send paths. It links libpcap, which can send (AP-31 (3)), and Zeek has a NetControl framework for acting on the network (from Zeek's design; its documentation was not read for this ADR). Which send paths a sensor build can reach is `unknown`, and C-11's zero-frames test is the check (AP-32).
- Which Zeek and ICSNPP versions are pinned.
- The engine's supply chain (D7 on #618): artifact hashes and the upstream signature check (Zeek publishes `.asc` files beside its releases); who watches the engine's advisories, since `govulncheck` covers Go modules only; the licences of the Linux distribution's own packages on the sensor host; and an SBOM for the sensor.

### What (b) commits the project to (from this ADR's rows)

- **A second device class at each site,** with its own enrollment and a revocable credential like a node's (SC-11) (D5 and D3).
- **The sensor host's management network is attack surface** (D3 on #618):
  - Who may log in to the sensor host, and how, and its physical custody, are owed. They are not decided here.
  - The link carries no command and no configuration to the sensor, only C13 records from it and the node's acknowledgements.
  - **The update path is owed:** it must refuse a tampered package, a package below the anti-rollback floor, and an unsigned package (AP-10). No signed release exists yet.
  - A threat-model entry for the sensor host, HR-21 (image and patching, management access, custody, TAP or SPAN), is owed by D3. It is not written here.
- **The link: the node opens it, and gains no inbound port.** The sensor host's listener is bound to its management interface only, firewalled to the node's address, and never listens on the station LAN (D5, AP-34).
- **The sensor must never affect collection.** Its records go to the node's network database and its own store classes (C5 0.9; D4-68), so that a sensor failure, or a flood from it, must never affect SER or Syslog collection (D5 on #618). That is a requirement, not yet shown: no flood over a network link has run, and the test is owed (D3 on #618; P4-4-L3 item 8).
- **Capture through Linux `AF_PACKET`, with `CAP_NET_RAW` only, dropped after the socket opens** (AP-31 (4)). The engine runs in IDS mode only. Its send paths are listed in the unknowns above; for Suricata, a rule set holding any `reject*` or `drop` action would be refused at load (AP-32).
- **A PRP duplicate-discard stage before the engine where the station network is PRP,** keyed on (source MAC, RCT sequence number) (E-D4-02). It is reported in C13's `prp.duplicates_discarded`. Whether the station network is PRP is still asked of the owner.
- **C-11's zero-frames evidence on Linux, with its negative control** (AP-32; D6's plan §6). The monitoring interface is up with no address, with ARP off, IPv6 disabled and no discovery daemons. Whether an nftables `netdev` egress drop on the monitoring interface catches every `AF_PACKET` send is `unknown` until tested, and can be tested in CI in a namespace (D5). **These measures are software.** Against a compromised sensor host, only a TAP, or a switch that refuses ingress on the mirror port, holds (AP-32 (1); D3 on #618).
- **A clock for the sensor host.** The tie between the node's own sessions and the observations (AP-35) now compares the collector host's clock with the sensor host's capture clock, on two machines. So the sensor's brief needs a time source for the sensor host and a check of the skew against `tie_grace_s` (D2 on #618).
- **A timed replay over a veth pair across network namespaces in CI, for R6.4's latency** (D6's plan §6). No project workflow does this yet.
- **The redaction by position, with fail-closed,** before anything is stored (D4-67; D4-68 ruling 13).
- **The open question of who ships the sensor's Linux image,** and who patches it.

### Not decided here

- The engine, which D1 approves after E-D4-03 (above).
- The sensor's implementation brief, which D1 writes.
- The link's contract: C13's channel on the network, with its enrollment, credential, peer binding, replay protection, acknowledgement of the committed sequence number, resume after a break, and a bound on late records.
- The sensor host's hardware and its Linux distribution and version.

Each follows in D1's briefs.

### Superseded: D4's provisional view under option (a)

Kept as the record of what was weighed. D4-85 superseded it on 2026-11-11.

**D4's provisional view under option (a), for review only** (2026-11-11, P4-4-S1; the owner chose (a) in D4-78). The reasons and costs in full are in [`docs/phase4/D4-sensor-engine-eval.md`](../phase4/D4-sensor-engine-eval.md) §7.

- **Engine: Suricata, from OISF's signed Windows build.** It is the only engine with a vendor-built, signed Windows binary, and it installs unattended. Zeek on Windows would be the project's own build of an upstream port that its NEWS has called experimental, and its third-party licences go beyond BSD (D7's inventory, #615). On Linux, with `stream.midstream=true`, Suricata decoded 6 of 6 DNP3 captures and 2 of 3 Modbus, as Zeek did (E-A4-01). Midstream is required, and its false-positive cost is unmeasured.
- **Capture: Npcap, live, under an OEM licence, on the condition that a safe install mode is found.** The official build needs Npcap installed even to read files, so `pktmon` (a′) saves no licence. It would only add a third privileged process and the file-rotation latency. **Npcap's install mode is undecided, and it is a condition on option (a), not a detail of it.** Without `/admin_only` (the default), other accounts may capture and send on every bound adapter. With it, the engine starts as an administrator. Neither meets AP-31 (2) as shown so far. The four lab checks in the process and privilege row decide it.
- **Carried to the sensor brief:** a capture stage that discards PRP duplicates must sit in front of the engine if the station network is PRP, so the engine likely reads files rather than the NIC; the redaction by position (D4-67); IDS mode only, with `reject` and `drop` rules refused at load (C-11); and GPLv2's distribution duties for D7.
- **Not shown on Windows:** what Suricata decodes, Npcap on a SPAN or TAP port, which accounts can capture, and the LTSC floor. Each needs a lab machine with Npcap installed by an operator (the note's §6), which needs the owner's authorization.
- **If the owner refuses an Npcap licence,** (a) has no shown path, because both ways around Npcap need the project to build an engine itself. D4's view is then that D1 should reopen (b) or (c′).

Under every option the project writes its own IEC 61850 and IEC 104 decoders later.

### The supervised process and its boundary (ADR-0002 item 2)

Under (b), the sensor runs on its own host, as one process under its own account. It has no access to the node's store, its keys or the collector's credential store, which are on another machine. Its only output is C13 records over the authenticated link (AP-34). The node decodes those records strictly, under their own quota (C5 stream class, D5). D3's boundary rows and D5's link rows are reviewed with this decision.

## Consequences

### Under (b), the chosen option

- **Enrollment, the credential and the update path of a second device class are new work for D5 and D3.** The sensor host's management access, its custody and its update path are new attack surface. They are owed as listed in "What (b) commits the project to", and the threat model gains them in HR-21.
- **R6.4's latency and C-11's zero frames are measured on Linux,** on the same OS the sensor runs: latency over a timed veth replay in CI, and C-11 on a virtual interface in a namespace of its own, with its negative control (D6's plan §6). H-06's hardware run is still owed for the 24 h run and a real SPAN or TAP port.
- **The link is a network link,** not a named pipe, and its contract carries what the pipe's peer checks gave for free: peer binding, replay protection, acknowledgement and resume (above).
- **Whether the sensor reads the NIC directly or files from a capture stage** depends on the PRP discard stage, which is for the sensor's brief.
- **GT-PCAP labels come from tshark** (D6's plan §1). Tshark is not the engine.
- **C13's records and the baseline note do not change with the decision,** and C13's citation of packets as a capture ID and frame numbers holds under (b). **C13's channel is revised in the link's contract** (D3 and D5 on #618), with:
  - peer binding;
  - replay protection;
  - acknowledgement of the committed sequence number, and resume after a break (the lesson of C-04 and E-01);
  - a bound on late records.
- Tying the node's own session to one connection (AP-35) uses the collector's `local_addr` and `connected_at`, which C2 0.9 carries (D4-69, #547). The window tie, the collector's IP to the device's IP and port within the session's time window, and its residual when two sessions to one endpoint overlap, apply to C2 0.8 results only (D2 on #618). Under (b) the tie also spans two hosts' clocks (above).
- **A sensor that heartbeats but is blind** shows as flat packet counters, which `sensor-unreachable` cannot see (D4-74). Today only `own-session-unseen` catches it, when a scheduled session goes unobserved. A `sensor-blind` alarm on flat counters is owed (D5 on #618).
- The sensor's coverage is self-reported (AP-36), so it gets an independent check (D1 on #525 §3, from D3). Each of the node's own scheduled sessions, taken from the session record, must appear as an observation within its window. A missing one raises a coverage alarm. D4's baseline note specifies the check.
- The coverage statement names the engine and its version, its decoded protocols, and SPAN or TAP. A protocol it cannot decode is a stated visibility limit (R6.1, R6.6), not a silent gap. **Except R6.7's insecure list:** a miss there fails V-M6, and is never recorded as a visibility limit (D6 on #618).

### Under (a) and (c), not chosen

Kept because they explain why these options were not chosen.

- **Where a Windows timed replay stays `unknown`,** under (a) and (c), R6.4's CI latency would be measured on Linux, as a Linux number for the decoder, not for the Windows capture path. C-11's zero-frames evidence on Windows would rest on H-06's hardware run alone, with the installer check in CI (D6's plan §6).
- **Under (a′) and (c′), latency is bounded below by `pktmon`'s file rotation interval,** because the decoder reads only closed files. R6.4 would report that interval with the latency figures (D6). If (a′) or (c′) had been chosen, the rotating capture files would themselves have been the citable capture IDs.
- If (a) or (c) had been chosen, the Windows capture path and its privilege drop would have been the main risk (E-D4-01 part 2; D3 on #618).

## Open objections

None open. Option (b)'s link direction is settled: the node opens the link, and there is no listener on the node (D5 withdrew the inbound listener, which agrees with D3's AP-34). The contradiction D3 and D5 raised on #618 is answered: C13's records stand, and its channel is revised in the link's contract ("Consequences").

Reviewers of the decision: D5 (process and link rows), D3 (boundary rows, HR-20), D6 (testability), D7 (licence rows) and D2 (protocol rows). D1 arranges them.

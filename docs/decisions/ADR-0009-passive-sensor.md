# ADR-0009: The passive sensor: which engine, and where it runs

- Status: proposed (draft for review; no option chosen yet)
- Date: 2026-11-07
- Deciders: D1, with D4 (author), D5 (the process and the node's side) and D3 (the boundary). D2 reviews protocol interpretation, D6 testability. The owner decides the two questions in "What decides it".
- Related: R6.1 to R6.7, V-M6, C-09, C-11, H-06; ADR-0002 item 2 (b), ADR-0007; `docs/phase0/A4-telemetry-feasibility.md` §3 and §4 (E-A4-01); threat model TB6, AP-30 to AP-36, SC-19, HR-20 (#523); D4-66, D4-67; brief P4-4-A4 in `docs/agent-handoffs.md`

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
| `cisagov/icsnpp-dnp3` and `cisagov/icsnpp-modbus` `main/LICENSE.txt` and `README.md` | BSD 3-Clause (Battelle Energy Alliance). Installed with `zkg`. Windows is not mentioned. | not kept: licence only |

### The comparison

| Row the brief asks for | (a) Zeek or Suricata on the Windows node | (b) Linux sensor at the site | (c) own Go decoders on the node |
| --- | --- | --- | --- |
| **Runs on Windows** (`windows-latest` run; offline decoding kept apart from live capture) | Zeek: Windows support "experimental" since 6.0 and "greatly improved" in 8.2 (`desk`, NEWS). Suricata: a Windows build exists and needs Npcap for live capture (`desk`). Offline decoding on Windows Server: `unknown` until E-D4-01's Suricata job runs. No official Zeek Windows binary was found from the sources reachable here, so Zeek on Windows is `unknown`. Live capture on Windows Server: `unknown`, because E-D4-01 installs no driver (licence row). The 10/11 LTSC floor is `unknown` for every option. | Not applicable on the node. The sensor runs Linux, where E-A4-01 ran (`simulated (Linux)`). | Go cross-compiles for `windows/amd64` (ADR-0003, the node's own build). The decoders do not exist yet. Live capture needs a driver or `pktmon`. `pktmon` on Windows Server: `unknown` until E-D4-01's `builtin` job runs. |
| **Capture driver and its licence** for a product that ships it | Npcap. It can't be redistributed in a product without the sold OEM Redistribution licence. The free edition is limited to five systems, so even "the customer installs it" does not cover a fleet (`desk`, LICENSE above). Price and terms beyond the LICENSE text: `unknown` (npcap.com refused). Variant (a′) uses `pktmon` instead: built into Windows, with no third-party licence, but its fitness is `unknown`. | None on Windows. Linux `AF_PACKET` is in the kernel and needs `CAP_NET_RAW` (`desk`, AP-31). | The same as (a): Npcap with its licence, or `pktmon` (c′). |
| **The engine's own licence** | Zeek BSD, ICSNPP BSD-3 (`desk`). Suricata GPLv2 (`desk`): a separate process is not linking, but shipping its binary brings the GPL's distribution duties (source offer, licence text). | The same engines and licences, shipped on the sensor's image, or the customer installs them. Who ships the Linux image is an open question. | The project's own code. Any decoder library taken in must not be GPL (brief exclusion: no libiec61850 or lib60870 linked). |
| **Protocols decoded**, shown on the public captures | E-A4-01 (`simulated (Linux)`): Zeek 8.0.4 decoded all 6 DNP3 captures, including midstream, and Modbus on 2 of 3. Suricata 7.0.3 decoded 4 of 6 DNP3 captures by default (2 more with midstream), and Modbus on 1 of 3 by default (2 of 3 with midstream). Neither decodes IEC 61850 MMS, GOOSE, SV or IEC 104. On Windows: `unknown`. Telnet, FTP, HTTP and SNMP are decoded by both (`desk`, E-A4-01 table, "built in"). | As E-A4-01, on the same OS it ran on. | None yet. DNP3 and Modbus/TCP framing are small, documented formats. IEC 61850 and IEC 104 need their own decoders under every option, because no stock engine has them (A4 Q4). |
| **Midstream handling** | Zeek: yes (`simulated (Linux)`). Suricata: only with `stream.midstream=true`, whose false-positive cost has not been measured (A4 §3). | The same. | A design choice. The decoder must start on any frame (A4 §4), and that is testable on the two handshake-less captures. |
| **PRP duplicate handling** (two copies with the same RCT sequence number, LAN A and LAN B) | Neither engine is documented here as discarding PRP duplicates by RCT. `unknown` until D6's PRP case runs. If they don't, either a pre-filter strips RCT duplicates before the engine, or every count is doubled. | The same as (a). | A design choice. Discard by (source MAC, RCT sequence number) before decoding, as A4 §4 and R-A4-4 already require. |
| **Process and privilege** | D5 (#525, `docs/phase4/D5-sensor-node.md`): the sensor is its own SCM service (`NT SERVICE\otsec-sensor`, its own service SID, SCM restart), not a child of the node. A child would run under the node's account, so a decoder exploit would reach the store and keys. W-2 also denies the node the privilege to start a child under another account (ADR-0002 items 2 and 5 agree). It never runs as LocalSystem or in Administrators. Whether Npcap's "restrict to administrators" install option would force that is `unknown` (npcap.com refused). If it would, Npcap is installed without the option, and capture access is limited by other means, which is still to be designed. | A whole host whose only job is the sensor. The engine runs with `CAP_NET_RAW` only, dropped after the socket opens (AP-31). The node supervises nothing; D5's note covers the link's health instead. | As (a): its own SCM service and service SID. The decoder process needs no capture privilege if it reads capture files written by `pktmon` (c′). Which account `pktmon` itself needs is `unknown`. |
| **Live interface fed by a timed replay** (R6.4 latency, the C-11 test) | On Windows Server: `unknown`. There is no network namespace or veth on Windows. A loopback adapter or Npcap's send path would be needed, and the sensor itself must never use that path (AP-32). | Yes, in principle: a veth pair in its own network namespace with `tcpreplay`, as V-M8's paired runs already do (`desk`, the CI workflow). Not yet run for a sensor. | As (a) on the node. Or the decoder is tested on Linux with the same veth replay, which proves the decoder but not the Windows capture. |
| **Channel to the node and how it is authenticated** | A named pipe on the collector's pattern: each end checks the other's service SID, and only the node writes the store (D5, #525; AP-34). | A network link with enrollment and a revocable credential like a node's (SC-11). The new device's own management interface and update path count as attack surface (D3). D5 proposes an inbound mTLS listener on the node's LAN interface. AP-34 says "never a listener open to the station LAN". Which end initiates is open (below). | As (a). |
| **What C-11 relies on** | A TAP is receive-only by construction. A SPAN port with a host NIC relies on host settings (D5, #525; AP-32): every binding removed from the NIC except the capture filter, a deny-all firewall rule on the sensor's service SID, and the monitoring NIC never ETH1 while Intel AMT is on (ADR-0007 item 8). None of these blocks a send made through the driver itself, so the zero-frames test is the evidence, not the settings. Zeek and Suricata link libpcap, which can send, and Suricata transmits by design in `reject` and IPS modes. So for an engine, C-11 also rests on IDS mode and a rule set that is refused at load if it holds any `reject*` or `drop` action (AP-31, AP-32 as amended on #523). The zero-frames test needs its negative control, a deliberately misconfigured interface that must show frames. | The same choice on Linux: the interface up with no address, ARP off, IPv6 disabled, and no discovery daemons. Whether an nftables `netdev` egress drop catches every `AF_PACKET` send is `unknown` until tested (D5). It can be tested in CI in a namespace. | As (a). Because the decoder is the project's own code, a link check can show that it has no send or inject call (AP-31). |
| **Hostile input reaches** | C and C++ decoders (Zeek, Suricata, ICSNPP) on the machine that holds the node's store, keys and the collector's route. The process and account boundary is the only wall (AP-30). | C and C++ decoders on a separate host. A decoder exploit holds the sensor, not the node. It can still lie to the node (AP-34). | Memory-safe Go, fuzzed (SC-14), on the node, inside its own process and account. Exploitation is much less likely, but the decoder can still lie or crash. |
| **Cost to the owner** | The Npcap OEM licence (price `unknown`), unless (a′) proves out. | A second machine at each site, and its patching. ADR-0007 gives the platform "its own dedicated machine" per site, so a second box is the owner's call. | Decoder build and maintenance for every protocol, which the brief's "evaluate existing engines first" rule asks us to justify. For IEC 61850 and IEC 104 that work is needed under every option anyway. |

### E-D4-01 (to run)

The experiment is `modules/telemetry/experiments/sensor-windows/`, run by the dispatch-only `.github/workflows/d4-sensor-eval.yml` on `windows-2025` (`simulated (Windows Server)`). The `builtin` job reports the edition and build, whether Npcap is on the image, and whether `pktmon` captures and converts the runner's own download to pcapng. The `suricata` job runs only when the dispatcher gives the installer's URL and SHA-256 from the vendor's page. It decodes the 9 public DNP3 and Modbus captures offline, with and without midstream, so they can be compared with E-A4-01's Linux table. GitHub registers a dispatch-only workflow only once its file is on `main`, so E-D4-01 runs after this PR merges, and its results are added here in a follow-up.

What E-D4-01 cannot show: live capture with Npcap (no licence to install it unattended), `pktmon` on a SPAN or TAP port in promiscuous mode, and any client edition. Those stay `unknown` until a lab machine runs them (H-06's hardware run, or a new H-row D6 proposes).

## What decides it

The options split on two questions only the owner can answer, and on two results E-D4-01 and D6's PRP case will give.

1. **Owner: may a site have a second machine for the sensor?** If yes, (b) is the only option where the engine is already shown decoding the first protocols (E-A4-01, on Linux), with no Windows driver licence, and with hostile parsing off the machine that holds the store and the collector's route. Its costs are a second box to enrol, patch and protect (D3's row), and the owner's hardware budget.
2. **Owner: is an Npcap OEM licence acceptable?** If it is not, and (b) is not allowed, (a) and (c) depend on `pktmon` (variant ′) being good enough. Today that is `unknown`.
3. **E-D4-01:** whether `pktmon` captures and converts to pcapng with no third-party driver, and whether Suricata's Windows build decodes offline as on Linux.
4. **D6's PRP case:** whether the engines discard RCT duplicates. If not, a pre-filter is needed under (a) and (b).

## Decision

None yet. This is a draft for review.

**D4's provisional view, for review only.** If the owner allows a second machine, choose (b) with Zeek and the ICSNPP packages. Zeek has the strongest decoding evidence (E-A4-01), is BSD, and handles midstream without a setting. If not, choose (c′), the project's own memory-safe decoders reading `pktmon` capture files on the node, provided E-D4-01 shows `pktmon` works and a lab run shows it sees a SPAN port. Fall back to (a) with an Npcap OEM licence only if both of those fail.

Under every option the project writes its own IEC 61850 and IEC 104 decoders later, so (c) adds no new class of work. It only brings DNP3 and Modbus forward. D1 records the choice here after review and the owner's answers.

**The supervised process and its boundary (ADR-0002 item 2).** Whatever is chosen, the sensor is one process under its own account. It has no access to the node's store, keys or the collector's credential store. Its only output is C13 records over the authenticated channel in AP-34. The node decodes those records strictly, under their own quota (C5 stream class, D5). D3's boundary rows and D5's supervision rows complete this before the ADR is accepted.

## Consequences

- C13 and the baseline note wait for the decision (brief, "Order"). One part doesn't depend on it, because every option produces the same records: C13's citation of packets as a capture ID and frame numbers. If (a′) or (c′) is chosen, the rotating capture files are themselves the citable capture IDs.
- If (b) is chosen, enrollment, the credential and the update path of a second device class become new work for D5 and D3. If (a) or (c) is chosen, the Windows capture path and its privilege drop are the main risk.
- Whichever option is chosen, the sensor's coverage is self-reported (AP-36), so it gets an independent check (D1 on #525 §3, from D3). Each of the node's own scheduled sessions, taken from the session record, must appear as an observation within its window. A missing one raises a coverage alarm. D4's baseline note specifies the check.
- Whichever option is chosen, the coverage statement names the engine and its version, its decoded protocols, and SPAN or TAP. A protocol it cannot decode is a stated visibility limit (R6.1, R6.6), not a silent gap.

## Open objections

- **Option (b): which end opens the link.** D5 proposes an inbound mTLS listener on the node's LAN interface. D3's AP-34 says "never a listener open to the station LAN". These agree only if the node's listening interface is not on the station LAN. That has to be settled before (b) can be chosen. Raised by D4 from D3's and D5's rows. It does not block the other options.

Reviewers: D5 (process rows), D3 (boundary rows, HR-20), D6 (testability), D2 (protocol rows).

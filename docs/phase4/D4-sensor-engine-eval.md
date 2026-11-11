# The engine and the capture path under ADR-0009 option (a): what ran, and what it showed

Author: D4. Date: 2026-11-11. Brief P4-4-S1 (to be recorded as D4-83), on `main` at `b383a242`. It builds no sensor and records no decision. D1 and D4 choose the engine, and the owner answers the Npcap question (D4-78).

Evidence classes: `desk` (read from a cited source on the date given) and `simulated (Windows Server)` (a GitHub-hosted `windows-2025` runner, recorded or synthesized traffic only). Nothing here ran on the owner's PC, on a client edition of Windows, or on any site network. Npcap was not installed anywhere.

## 1. What ran

[Run 43017246251](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43017246251), `d4-sensor-eval`, dispatched on `agent/telemetry-sensor-engine-eval` at `e65a9f52`, 2026-11-11 at about 12:05Z. Three jobs:

| Job | Result | Why |
| --- | --- | --- |
| `builtin` (E-D4-01 part 1, unchanged) | success | As on 2026-11-07. |
| `suricata` (E-D4-01 part 2) | failure | The Suricata step exits 1 because `suricata.exe` does not start (section 2). The step wrote its whole result file first, and the pipeline step after it ran. The failure is the finding, not a script fault. |
| `prp-engines` (E-D4-02, unchanged) | failure | By design: the PRP rows fail (ADR-0009, "E-D4-02 results"). Not part of this brief. |

The two result files are the run's artifact `d4-sensor-eval-suricata` (`suricata.json`, `pipeline.json`). They hold versions, hashes, counts and decode tables only. No binary or installer is committed or uploaded. `pktmon` captured only the runner's own traffic, and its capture files were deleted on the runner; only their packet counts are reported.

**Limits of the run itself** (D3 on #618):

- **One input cannot be pinned.** `pipeline.ps1`'s engine stage (`suricata.exe -r` on the `pktmon` pcapng) would feed the engine the runner's live traffic, the downloads and the image's background traffic. Unlike the 58 captures, that input cannot be pinned by hash. In this run the stage did not execute, because Suricata does not start.
- **Not pinned by hash:** the workflow's Actions (`actions/checkout@v4`, `actions/setup-python@v5`, `actions/upload-artifact@v4`) are pinned by tag; Python is pinned as `3.12`, resolved to 3.12.10 on this run; and the unchanged Linux job `prp-engines` takes Suricata and tshark from apt, and `zeek/zeek:8.0.4` by tag. That job writes the pulled image's digest into `versions.txt`, but does not pin it in advance.

**The download.** Suricata 8.0.8's official installer, `https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.8-1-64bit.msi`, the one link that suricata.io/download gives for Windows. OISF publishes no SHA-256, MD5 or signature file for its Windows installers: its download page links only the source tarball's `.sig` (read through WebFetch on 2026-11-11, which returned a summary, not the page text; a direct fetch of suricata.io returned 403), and the directory `openinfosecfoundation.org/download/windows/` holds only `.msi` and `.zip` files. So the pin is **a first-use pin, not a vendor-published one**: the SHA-256 of D4's first download from that URL on 2026-11-11, `7c6b302e51a166c5b87b383ff2550406bc72faba9d690bd3a0532869a95dd084`, pinned in the workflow from then on. The vendor's own assurance is its Authenticode signature: valid, signer `CN=Open Information Security Foundation Inc., O=Open Information Security Foundation Inc., L=Boston, C=US`, issued by Certum Code Signing 2021 CA, thumbprint `1CC0A04E667EB4C1C23AABD304F1F7D54A017D38`. The job checks the hash and then the signer before `msiexec` runs, and stops on either mismatch. The runner computed the same hash.

**The captures.** All 58 matched their pinned SHA-256 on the runner: the 21 public captures in `MANIFEST.tsv` that E-A4-01 used, GT-PCAP's 18 PRP captures rebuilt by `prp.py`, and its 19 DNP3 captures rebuilt by `dnp3_cases.py`. So GT-PCAP's generators reproduce their captures byte for byte under Windows Python 3.12.10, a side result.

## 2. Suricata's official Windows build, with no Npcap

**It does not start.** `suricata.exe -V` exits `0xC0000135` (`-1073741515`, the NT status for a DLL not found), prints nothing, and leaves no Application Popup event (System log, event 26) in the job's window. The binary imports `wpcap.dll` (`dumpbin /dependents`), and `wpcap.dll` is not on the image: not in the install folder, `System32`, `SysWOW64` or the `PATH`. Every other DLL it imports resolves. `wpcap.dll` is what Npcap installs.

| Question | Result (`simulated (Windows Server)`, run 43017246251) |
| --- | --- |
| Npcap before, after the install and at the end | Absent each time: no `System32\Npcap`, no `npcap` service, no `wpcap.dll`. The MSI did not install it. |
| `msiexec /i … /qn /norestart` | Exit 0. The MSI has no launch condition on Npcap, so it installs silently and unattended. Its exit-dialog text, from the install log: "YOU MUST HAVE Npcap installed with winpcap compatability mode in order to run Suricata IDS/IPS. If you do not have it , you can get it from here - https://npcap.com/dist/" (verbatim). |
| Does it start and read a capture file? | **No.** Exit `0xC0000135` before `main`, because `wpcap.dll` is missing. |
| Protocols decoded per capture, by default and with `stream.midstream=true` | `unknown` for all 58 captures: none ran. |

**What it means for option (a).** The official build needs Npcap installed even to read a file. So under (a), Suricata needs Npcap whatever the capture path, and variant (a′) (`pktmon` capture) saves no driver licence with this build. Suricata's own build guide says Npcap "can be skipped" if "only PCAP processing is desired" (`doc/userguide/install/windows.rst` at `suricata-8.0.8`, SHA-256 `02051051…94fcb`), but that is a build from source in MSYS2, which this brief excludes. Whether such a build would need no `wpcap.dll` at run time is `unknown`.

The E-A4-01 table for Windows stays empty: what Suricata decodes on Windows is `unknown` until a machine with Npcap runs it (section 6).

## 3. Zeek on Windows

**No official Windows binary or package exists** (`desk`, 2026-11-11):

| Source | What it says | SHA-256 of the file read |
| --- | --- | --- |
| `zeek.org/get-zeek/` | Downloads for 8.0.11 and the current release are "Source Code \| Linux Binaries". Packages come from Linux distributions, FreeBSD, MacPorts and Homebrew, and the openSUSE Build Service for Linux. No Windows item. | `24fd5b59…82f71` |
| GitHub releases `zeek/zeek`, v9.0.1 and v8.0.11 (2026-10-26) back to v8.2.1 | Each release's assets are the source tarball and its `.asc` only. | `gh api`, not kept |
| `docs.zeek.org/en/master/install.html` | No Windows section. The only match for "windows" is a script name, `windows-version-detection.zeek`. | `11a94c5b…bf75` |
| `zeek/zeek` `v9.0.1/NEWS` | 6.0: "Experimental support added for building and running Zeek on Microsoft Windows … not considered production-ready", and Spicy "currently unsupported" there. 8.2.0: "Windows support has been greatly improved … The great majority of btests pass". | `ba78c1c1…3803a` |
| `zeek/zeek` `v9.0.1/vcpkg.json` and `ci/windows/` | The Windows build is from source, with Visual Studio Build Tools, CMake and vcpkg, and takes `libpcap` from vcpkg. | `624fd561…41bdf` |

So Zeek on Windows means the project building and shipping its own Zeek binary from an upstream port that its own NEWS last called experimental. Whether that build reads files or captures live without Npcap, and whether Spicy and the ICSNPP packages work on it, are `unknown`. Nothing was built.

## 4. The (a′) pipeline on the runner

`pktmon` captured while the runner downloaded two public captures (each checked against its pinned SHA-256) and replayed their TCP payloads between two sockets on 127.0.0.1 (`replay.py`). Then `pktmon etl2pcap` converted, and the engine was to read the pcapng. Two passes: `--comp nics` (network adapters only) and `--comp all` (pktmon's default).

| Stage | `--comp nics` | `--comp all` |
| --- | --- | --- |
| 1. Sent over loopback: `dnp3-select-operate.pcap` on TCP 20000 | 4 segments (2 requests of 35 octets, 2 responses of 1 octet, as recorded) | the same |
| 1. Sent over loopback: `modbus.pcap` on TCP 502 | 102 segments (51 each way, 1,173 octets) | the same |
| 2. `pktmon stop` | "No events lost" | "No events lost" |
| 2. `etl2pcap`: packets total, formatted | 184, 184 | 156, 156 |
| 2. `etl2pcap`: "Packet drop count" | 0 | 8 |
| 3. pcapng: frames, link type | 184, all Ethernet | 156, all Ethernet |
| 3. pcapng: TCP frames on port 20000 or 502 | **0** | **0** |
| 4. The engine reads the pcapng | `unknown`: no engine starts on the image | `unknown` |

What it shows (`simulated (Windows Server)`):

- **`pktmon` did not see loopback traffic** in this one run, as administrator, on Windows Server 2025, at either component setting: 106 replayed segments, 0 frames. So loopback replay cannot feed a timed replay for R6.4 under (a′) on this image, and the ADR's row "Live interface fed by a timed replay" stays `unknown` with one route closed. It is one observation on one image. It must never be cited as a confidentiality property, for example that loopback traffic between the node and the collector cannot be captured on the node (D3).
- **Capture and conversion work at the NICs**, with no event lost and every packet formatted. The frames are the runner's own traffic (the downloads and the image's background traffic), which is why the two passes differ in count. Nothing here shows duplicate copies across components.
- **"Packet drop count" is not explained by a source read here.** It was 0, 8 and 3 (the `builtin` job, all components) in this run, and 0 on 2026-11-07. It is not the capture-loss line, which is "No events lost". What it counts is `unknown`.
- **Stage 4 did not run.** The (a′) pipeline is not shown end to end, because no engine starts without Npcap.

## 5. Npcap's terms, from the vendor's pages

Read on 2026-11-11 with a direct fetch (the full page, not a summary). The saved files and their SHA-256s are in `reference/carried/d4-sensor-engine-eval-2026-11-11/SHA256SUMS`, which is not committed. Every fact is `desk`.

| Fact | Source (SHA-256 of the file read) |
| --- | --- |
| **Free edition.** "may be used (but not externally redistributed) on up to 5 systems". Unlimited systems where used only with Nmap, Wireshark or Microsoft Defender for Identity. | `npcap.com/` (`20c29ff9…b4227`) |
| **Free licence text.** Five copies, five computers, five users. "computer" and "machine" include "virtual machines and Docker containers". Exceeding the limits, redistribution or a silent installer needs a commercial licence. Unchanged since 2025-02-18; the same file the ADR read on 2026-11-07. `npcap.com/license` redirects to it. | `nmap/npcap` `master/LICENSE` (`0543f4f9…3ac83`) |
| **Silent install is OEM only.** "/S (Silent install, Npcap OEM only)". The free edition "does not include a silent installer". | user's guide (`90a89e5a…d5fe`); `npcap.com/oem/` (`b4e108de…7734`) |
| **OEM Internal-Use**, perpetual, for use inside one organization with no redistribution: 100 installs US$4,980 (maintenance $980 a year); 250 installs $8,980 ($1,980); 500 installs $14,980 ($2,980); 1,000 installs $24,980 ($4,980); 5,000 installs $39,980 ($7,980); unlimited $59,980 ($12,980). Maintenance (updates and support) is optional, with 10 % off for 3 years and 20 % off for 5. "An install would be on an individual computer or virtual machine or docker container or cloud server or similar." | `npcap.com/oem/internal.html` (`e87dcdd5…2c27`) |
| **OEM Redistribution**, for a company that ships Npcap in its products, priced by the whole company's size, with no per-install fee. Small/startup (50 or fewer employees, at most US$10 M revenue): $39,980 perpetual plus optional $11,980 a year, or $6,980 a quarter as a term licence. Mid-sized (500 or fewer employees, under $200 M revenue, under $1 B market capitalization if listed): $59,980 plus $14,980 a year, or $8,980 a quarter. Enterprise: $79,980 per product line plus $19,980 a year, or $11,980 a quarter. Perpetual licences carry a six-month full-refund period. | `npcap.com/oem/redist.html` (`c28d293d…b3b4`) |
| **Restricting capture to administrators is an install option, `/admin_only`, and it is off by default.** It is one of the "Graphical installer options", of which the guide says: "Unless otherwise noted, the default for these options is no." Its own entry notes no other default. With it, "the devices created by the Npcap driver for capture and injection on each network adapter will be created with a restrictive ACL that only allows access to the device by the SYSTEM and built-in Administrators", and `NpcapHelper.exe` requests UAC elevation "for each process that opens a capture handle". The guide does not give the devices' ACL without the option. (Corrected after D3's review: the first version of this note said the default was unstated.) | user's guide (`90a89e5a…d5fe`), "Graphical installer options" and `/admin_only` |
| **A startup task that runs batch files from the install folder.** "the Npcap installer creates a scheduled task named npcapwatchdog that runs once at each system startup. The script executes the CheckStatus.bat script from the Npcap installation directory … If it finds a problem, it runs the adjacent FixInstall.bat script to reinstall the Npcap driver." The guide does not name the account the task runs under, so it is `unknown` (D3 on #618). | user's guide, "The npcapwatchdog scheduled task" |
| **WinPcap-compatible mode puts DLLs in the system folder, and is on by default.** "/winpcap_mode … The default for this option is yes in Npcap 0.9985 and later. … This option also installs the DLLs to the system directory, replacing WinPcap. Any existing WinPcap installation will be removed." Also: "The driver and DLLs will always be installed into the appropriate directories below %SYSTEMROOT%\System32\". Suricata's MSI asks for this mode (section 2). | user's guide, `/winpcap_mode` and `/D` |
| **802.1Q tags.** "/vlan_support (deprecated, ignored) Support 802.1Q VLAN tag when capturing and sending data (currently unsupported). This feature was disabled in 2016 to prevent a crash and has not been re-enabled." | user's guide |
| **Supported systems for 1.90**, the installer offered on 2026-11-11: "Windows 7/2008R2, 8/2012, 8.1/2012R2, 10/2016, 2019, 11 (x86, x64, and ARM64)". Server 2022 and 2025 are not named. | `npcap.com/` |
| **The driver sends as well as captures:** "packet capture (and sending) library". | `npcap.com/`, `npcap.com/oem/redist.html` |

Which licence applies depends on who installs Npcap at the sites. If the owner's own organization installs the sensor on its own nodes, it is the Internal-Use licence, sized by the number of nodes. If OTSEC is shipped to anyone outside that organization with Npcap inside, it is the Redistribution licence. That is the owner's answer to give. The free edition covers neither a fleet nor an unattended install.

**Why Npcap was not installed on the runner.** The brief forbids it. The licence's terms agree: each hosted runner is a new virtual machine, which counts as a computer, and the free edition has no silent installer.

## 6. What stays `unknown`, and where it can be settled

| Unknown | Needs | Why not on a hosted runner |
| --- | --- | --- |
| What Suricata's Windows build decodes (the E-A4-01 table, GT-PCAP), by default and with midstream | A machine with Npcap installed, by an operator, under the free licence's five systems or an OEM licence | Npcap install forbidden; no silent install in the free edition |
| Npcap live capture on a SPAN or TAP port: promiscuous mode, non-IP frames, PRP trailers, 802.1Q tags | A lab machine on a SPAN or TAP port with recorded traffic replayed into it | No such port; the guide says VLAN support is "currently unsupported" |
| Without `/admin_only`: which accounts can open a capture handle, and which can send through it | A lab machine with the sensor's, the node's and the collector's accounts | The guide doesn't give the devices' ACL without the option |
| Whether the Npcap driver can be bound to the monitoring adapter only, and stays so across updates, reboots and `npcapwatchdog` reinstalls | A lab machine with a monitoring adapter and the collector's device-facing adapter | One adapter on the runner; no Npcap |
| Whether the capture devices' access list can name the sensor's service SID alone | A lab machine | No Npcap; the guide offers only the two settings |
| With `/admin_only`: whether Suricata can open the adapter and then drop privilege before it decodes (AP-31 (2)), and how `NpcapHelper.exe`'s UAC request behaves for a service | A lab machine, Suricata as an SCM service | No Npcap |
| C-11 zero frames with Npcap installed, and its negative control | H-06's hardware run | The driver can send by design |
| Everything above on ADR-0007's Windows 10/11 IoT Enterprise LTSC floor | A client-edition lab machine | Hosted runners are Windows Server |
| A timed replay on Windows for R6.4 | A second host or adapter feeding the monitoring NIC | `pktmon` saw no loopback traffic in one run (section 4); no second interface |
| `pktmon` on a SPAN or TAP port, under a less-privileged account, with layer-2 frames intact (from E-D4-01) | A lab machine | As 2026-11-07 |
| What `etl2pcap`'s "Packet drop count" counts | A primary source, or a lab run with a known drop | — |
| A project-built Suricata or Zeek for Windows that needs no `wpcap.dll` | A build brief, which this brief excludes | — |

The first eight rows need a lab machine with the owner's authorization. D6 can propose them as one H-row: one Windows 10/11 LTSC machine with Npcap installed by an operator, with a monitoring adapter on a SPAN or TAP port and a second, device-facing adapter, fed recorded traffic from a second host, with the sensor, the node and the collector each under its own service account.

## 7. D4's recommendation under option (a)

**Engine: Suricata, from OISF's signed Windows build. Capture: Npcap, live, on the condition that a safe install mode for Npcap is found.** Npcap's install mode is undecided. It is a condition on option (a), not a detail of it (see "Privilege" below). The reasons:

1. **Suricata is the only engine with a vendor-built, signed Windows binary** that installs unattended (section 2). Zeek on Windows would be the project's own build of a port whose upstream has called it experimental (section 3). Shipping and patching that build would be D7's and D5's work for as long as the sensor lives.
2. **That build needs Npcap installed in any case**, even to read files. So capturing with `pktmon` saves no licence, adds a third privileged process to start and keep `pktmon` running, and adds the file-rotation interval to R6.4's latency. Npcap captures directly into the engine.
3. **Decoding is close enough to Zeek on the first protocol set**, on Linux, with `stream.midstream=true`: 6 of 6 DNP3 captures and 2 of 3 Modbus, against Zeek's 6 of 6 and 2 of 3 as a service (E-A4-01, `simulated (Linux)`). Midstream is required, and its false-positive cost is still unmeasured. On Windows it is `unknown` (section 6, first row).

**What this choice costs, stated plainly:**

- **An Npcap OEM licence**, from US$4,980 (100 internal installs) to $79,980 and upward (enterprise redistribution), by who installs it (section 5).
- **GPLv2 duties for shipping Suricata's binary** (ADR-0009, the engine's licence row). D7's to check. Zeek is not licence-free either: D7's inventory (#615) read Zeek's `COPYING-3rdparty`, which includes MPL-2.0, LGPL-3.0 with a BSD permission, Apache-2.0, Boost and the JSON licence, whose "shall be used for Good, not Evil" clause is a use restriction for D7 and the owner to weigh. So Zeek's BSD top-level licence is not the whole of what a project-built Zeek binary would ship. This weighs slightly against Zeek on Windows, beside reason 1.
- **No PRP discard before the engine on a live Npcap feed.** Suricata reading the NIC directly leaves no stage between capture and engine. If the station network is PRP (still asked of the owner), the sensor needs its own capture stage that discards duplicates and hands the engine files or a stream, and Suricata's `-r` on a directory (`--pcap-file-continuous`) is the likely way in. That design is for the sensor brief, and it is `unknown` here.
- **Privilege: an open choice, and neither setting is safe to carry as a recommendation** (D3 on #618).
  - **Without `/admin_only`, the default:** accounts other than the sensor's may be able to open the driver's capture and injection devices on every bound adapter. That includes the collector's device-facing adapter, where device passwords cross in plaintext (HR-1, HR-2, HR-8). A decoder exploit could then reach past AP-30 (2) to those passwords, and could send on any adapter (C-11). This is the opposite of AP-31 (2), "Capture rights limited to the sensor's account".
  - **With `/admin_only`:** capture is limited to SYSTEM and built-in Administrators, so the engine starts as an administrator. AP-31 (2) then requires it to open the adapter and drop privilege before it decodes anything. Whether Suricata can do that on Windows, and how `NpcapHelper.exe`'s per-process UAC request works for a service, are `unknown`.
  - Either way it stays `unknown` until a lab machine shows four things (section 6): which accounts can open and send without the option; whether the driver can be bound to the monitoring adapter only, and stays so; whether the devices' access list can name the sensor's SID; and whether Suricata can open the adapter and then drop privilege. If none of these holds, option (a) with Npcap does not meet AP-31 (2), and D1 should treat that as a reason to reopen the option.
- **C and C++ decoders on the node**, behind the process and account boundary only (AP-30), as the ADR says for every (a).

**If the owner refuses an Npcap licence**, option (a) has no proven path. Both Windows paths that avoid Npcap need the project to build an engine itself (Suricata in MSYS2 without Npcap, or Zeek), feeding it from `pktmon` files, and neither has been tried. In that case D4's view is that (b) or (c′) should be reopened with D1. Choosing between them is not this note's job.

The IEC 61850 and IEC 104 decoders are the project's own under every option, as before.

## 8. What this evidence decided

On 2026-11-11 D1 put three choices to the owner with this note's findings: stay with (a) and buy an Npcap licence, switch to (b), or (c′). D1 recommended (b), and the owner chose it (D4-85). That choice supersedes D4-78's choice of (a), and section 7's recommendation is kept as the record of what was weighed. No Npcap licence is bought. ADR-0009 is accepted for (b), and its Decision section gives the engine D4 recommends under (b), Zeek with ICSNPP, for D1's approval.

**No longer owed under (b):** the Npcap lab checks of section 6. These are which accounts can open and send without `/admin_only`, binding to one adapter, a device access list naming the sensor's SID, opening and then dropping privilege, and the `npcapwatchdog` task's account. Suricata's decoding on Windows, the LTSC floor for a sensor, and `pktmon`'s fitness are no longer owed either.

**Still `unknown` under (b),** for D6's H-row and the sensor's brief:
- The sensor host's NIC on a SPAN or TAP port: promiscuous capture, non-IP frames and loss.
- PRP live on both LANs, and HSR, which no engine here handles.
- Whether Linux capture keeps 802.1Q tags as the engine sees them.
- The engine's decoding of each protocol the sites use (the owner has yet to say which). This includes DNP3 group 120, SNMPv3's header fields, and DNP3 or Modbus on a non-standard port.
- Whether the engine runs with `CAP_NET_RAW` only and drops it after its socket opens.
- Whether an nftables `netdev` egress drop catches every `AF_PACKET` send.

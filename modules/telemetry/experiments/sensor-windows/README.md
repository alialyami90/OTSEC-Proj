# E-D4-01: what a Windows site node offers a passive sensor (ADR-0009)

D4's experiment for [ADR-0009](../../../../docs/decisions/ADR-0009-passive-sensor.md) (P4-4-A4, D4-66). It is throwaway: nothing here is product code or a toolchain choice.

It runs only from the dispatch-only workflow `.github/workflows/d4-sensor-eval.yml` on a GitHub-hosted Windows Server 2025 VM. Every result is `simulated (Windows Server)`: it is not evidence for ADR-0007's Windows 10/11 IoT Enterprise LTSC floor, which stays `unknown` until a client edition runs it.

| Script | Question | Needs |
| --- | --- | --- |
| `probe.ps1` | Which edition and build is the runner? Is a third-party capture driver (Npcap) already on the image? Can the built-in Packet Monitor (`pktmon`) capture the runner's own traffic and convert it to pcapng with no third-party driver? | nothing installed; Python for `count.py` |
| `suricata.ps1` | Does Suricata's Windows build decode the public DNP3 and Modbus captures offline (`-r`, no capture driver), with and without `stream.midstream=true`, as E-A4-01 found on Linux? | the installer URL and its SHA-256, given as workflow inputs by the person who dispatches it, read from the vendor's download page; the public captures (`fetch_captures.sh`) |
| `count.py` | Counts packets in a pcapng file and app-layer events in a Suricata `eve.json`, with the standard library only. | Python 3, run with `-I` |

What it does not do: it contacts no device, it sends nothing to any host other than the downloads it names, and it does not upload any capture of the runner's own traffic (only the counts). It installs no capture driver: Npcap's licence does not allow an unattended install outside its paid OEM edition (ADR-0009, Evidence).

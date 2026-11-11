# E-D4-01: what a Windows site node offers a passive sensor (ADR-0009)

D4's experiment for [ADR-0009](../../../../docs/decisions/ADR-0009-passive-sensor.md) (P4-4-A4, D4-66). It is throwaway: nothing here is product code or a toolchain choice.

It runs only from the dispatch-only workflow `.github/workflows/d4-sensor-eval.yml` on a GitHub-hosted Windows Server 2025 VM. Every result is `simulated (Windows Server)`: it is not evidence for ADR-0007's Windows 10/11 IoT Enterprise LTSC floor, which stays `unknown` until a client edition runs it.

| Script | Question | Needs |
| --- | --- | --- |
| `probe.ps1` | Which edition and build is the runner? Is a third-party capture driver (Npcap) already on the image? Can the built-in Packet Monitor (`pktmon`) capture the runner's own traffic and convert it to pcapng with no third-party driver? | nothing installed; Python for `count.py` |
| `suricata.ps1` | Part 2 (P4-4-S1). Does Suricata's official Windows build start with no Npcap, and if not, exactly why (exit code, the loader's event, the DLLs it imports)? If it starts, what does it decode offline (`-r`), with and without `stream.midstream=true`, on every public capture E-A4-01 used and on GT-PCAP's PRP pairs and DNP3 cases? | the installer, pinned in the workflow by URL and SHA-256 and checked for its Authenticode signer before it runs; the captures, each checked against its pinned SHA-256 |
| `pipeline.ps1` | Part 2. The (a′) pipeline end to end: `pktmon` captures while the runner downloads a public capture and replays two recorded sessions over loopback, `pktmon etl2pcap` converts, and the engine reads the pcapng, with packets counted at each stage. Once at the NICs only and once at every component. | `suricata.json` from the step before |
| `replay.py` | Replays one recorded TCP session's payloads between two sockets on 127.0.0.1, so that `pktmon` has known traffic to see. | Python 3, run with `-I` |
| `count.py` | Counts packets in a pcapng file (in total, and TCP frames to or from one port) and app-layer events in a Suricata `eve.json`, with the standard library only. | Python 3, run with `-I` |

A row that did not run reads `unknown`, never a pass. Only `suricata.json` and `pipeline.json` are uploaded.

What it does not do: it contacts no device, it sends nothing to any host other than the downloads it names and its own loopback, and it does not upload any capture of the runner's own traffic (only the counts). It installs no capture driver: Npcap's licence does not allow an unattended install outside its paid OEM edition (ADR-0009, Evidence).

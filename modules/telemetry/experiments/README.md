# A4 Phase 0 experiments

Throwaway experiments for task P0-A4. Nothing here is product code or a toolchain choice; scripts are Python 3 and POSIX sh because those were in the container. Findings are written up in `docs/phase0/A4-telemetry-feasibility.md` and `docs/phase0/A4-event-schema-draft.md`.

| Directory | Question | Run | Needs |
| --- | --- | --- | --- |
| `ids-coverage/` | Which OT protocols do Zeek and Suricata decode on public captures? Do simple deterministic GOOSE checks separate labeled attacks? | `sh fetch_captures.sh <cache>` then `sh run_all.sh <cache> <work>` | suricata 7, tshark, docker with `zeek/zeek:8.0.4`, network access to the URLs in the manifest |
| `syslog-framing/` | Can hostile device text forge messages at a stock Syslog receiver, with newline framing and with the draft profile? Does the profile hold over every standard transport and in RFC 3164 form? | `python3 -I run_test.py <work> results/framing.md`; `python3 -I run_transports.py <work> results/transports.md` | rsyslog with imtcp, imudp, imrelp, gtls; openssl |
| `relp-ack/` | Does a RELP acknowledgement mean the receiver kept the message when it crashes? | `python3 -I relp_ack_test.py <work> results/relp-ack-trialN.md` | rsyslog with imrelp and omprog |
| `schema-mapping/` | Does the draft schema hold four native timestamp encodings losslessly? Does snapshot alignment handle the C-13 cases? | `python3 -I map_examples.py <cache> results/examples.json`; `python3 test_align.py`; `python3 test_sel_ser.py` | tshark, the capture cache from `ids-coverage/` |
| `sensor-windows/` | E-D4-01 for ADR-0009 (D4, 2026-11-07): does a Windows Server VM capture with its built-in `pktmon`, and does Suricata's Windows build decode the public DNP3 and Modbus captures offline? | the dispatch-only workflow `d4-sensor-eval.yml` | a GitHub-hosted `windows-2025` runner; the Suricata installer URL and SHA-256 as inputs |
| `prp-engines/` | E-D4-02 for ADR-0009 (D4, 2026-11-07): do Zeek and Suricata record each flow once on GT-PCAP's PRP doubled captures, with the packets and service of the LAN-A-only capture and every flow tshark labels? Exits 1 unless every row passes. | the `prp-engines` job of `d4-sensor-eval.yml`, or `sh run.sh <cache> <work>` | suricata 7, tshark 4.2.2, docker with `zeek/zeek:8.0.4`, python3, the capture cache from `ids-coverage/` |

All results are `simulated`: public recorded or synthesized traffic and stock software on localhost, never project equipment.

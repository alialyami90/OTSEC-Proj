# A4 Phase 0 experiments

Throwaway experiments for task P0-A4. Nothing here is product code or a toolchain choice; scripts are Python 3 and POSIX sh because those were in the container. Findings are written up in `docs/phase0/A4-telemetry-feasibility.md` and `docs/phase0/A4-event-schema-draft.md`.

| Directory | Question | Run | Needs |
| --- | --- | --- | --- |
| `ids-coverage/` | Which OT protocols do Zeek and Suricata decode on public captures? Do simple deterministic GOOSE checks separate labeled attacks? | `sh fetch_captures.sh <cache>` then `sh run_all.sh <cache> <work>` | suricata 7, tshark, docker with `zeek/zeek:8.0.4`, network access to the URLs in the manifest |
| `syslog-framing/` | Can hostile device text forge messages at a stock Syslog receiver, with newline framing and with the draft profile? | `python3 -I run_test.py <work> results/framing.md` | rsyslog with imtcp |
| `relp-ack/` | Does a RELP acknowledgement mean the receiver kept the message when it crashes? | `python3 -I relp_ack_test.py <work> results/relp-ack-trialN.md` | rsyslog with imrelp and omprog |
| `schema-mapping/` | Does the draft schema hold four native timestamp encodings losslessly? Does snapshot alignment handle the C-13 cases? | `python3 -I map_examples.py <cache> results/examples.json`; `python3 test_align.py`; `python3 test_sel_ser.py` | tshark, the capture cache from `ids-coverage/` |

All results are `simulated`: public recorded or synthesized traffic and stock software on localhost, never project equipment.

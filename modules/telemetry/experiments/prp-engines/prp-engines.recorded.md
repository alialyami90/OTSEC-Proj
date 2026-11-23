# prp-engines: the recorded result

Recorded from run 45081194524 (`d4-sensor-eval`, `workflow_dispatch` on `main` at `9242c214`, job `prp-engines` 137389519378, 2026-11-22): its artifact `d4-sensor-eval-prp-engines`'s `prp-engines.md`, byte for byte below, and `run.sh`'s exit code. `prp_recorded.py` compares a run's table, closing line and exit code with these. Versions in that run: Suricata 7.0.3, Zeek 8.0.4, tshark 4.2.2 (its `versions.txt`, which is not compared).

| capture | engine | labelled flows | flows -a | flows -ab | packets -a | packets -ab | once | packets equal | services equal | labels met | pass |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| dnp3-digitalbond-part1 | zeek | 8 | 8 | 8 | 181 | 362 | yes | no | yes | 8 of 8 | no |
| dnp3-digitalbond-part1 | suricata | 8 | 8 | 8 | 181 | 362 | yes | no | yes | 8 of 8 | no |
| dnp3-digitalbond-part2 | zeek | 1 | 1 | 1 | 33 | 66 | yes | no | yes | 1 of 1 | no |
| dnp3-digitalbond-part2 | suricata | 1 | 1 | 1 | 33 | 66 | yes | no | yes | 1 of 1 | no |
| dnp3-malformed | zeek | 198 | 198 | 198 | 198 | 396 | yes | no | yes | 198 of 198 | no |
| dnp3-malformed | suricata | 198 | 198 | 198 | 198 | 396 | yes | no | yes | 198 of 198 | no |
| dnp3-read | zeek | 1 | 1 | 1 | 8 | 16 | yes | no | yes | 1 of 1 | no |
| dnp3-read | suricata | 1 | 1 | 1 | 8 | 16 | yes | no | yes | 1 of 1 | no |
| dnp3-select-operate | zeek | 1 | 1 | 1 | 12 | 24 | yes | no | yes | 1 of 1 | no |
| dnp3-select-operate | suricata | 1 | 1 | 1 | 12 | 24 | yes | no | yes | 1 of 1 | no |
| dnp3-write | zeek | 1 | 1 | 1 | 8 | 16 | yes | no | yes | 1 of 1 | no |
| dnp3-write | suricata | 1 | 1 | 1 | 8 | 16 | yes | no | yes | 1 of 1 | no |
| modbus | zeek | 1 | 1 | 1 | 102 | 204 | yes | no | yes | 1 of 1 | no |
| modbus | suricata | 1 | 1 | 1 | 102 | 204 | yes | no | yes | 1 of 1 | no |
| modbus-digitalbond-part1 | zeek | 6 | 6 | 6 | 118 | 236 | yes | no | yes | 6 of 6 | no |
| modbus-digitalbond-part1 | suricata | 6 | 6 | 6 | 118 | 236 | yes | no | yes | 6 of 6 | no |
| modbus-digitalbond-part2 | zeek | 1 | 1 | 1 | 350 | 700 | yes | no | yes | 1 of 1 | no |
| modbus-digitalbond-part2 | suricata | 1 | 1 | 1 | 350 | 700 | yes | no | yes | 1 of 1 | no |

18 row(s) not run or failed.

run.sh exit code: 1

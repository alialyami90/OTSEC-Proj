# D4: E-D4-03, the engine on Linux over GT-PCAP (P4-4-S2)

D4, 2026-11-11. Brief P4-4-S2 in `docs/agent-handoffs.md` ("Phase 4 item 4, second part", D4-86). ADR-0009 names Zeek as the provisional engine under option (b), and D1 approves it or turns the choice on this run.

**Status: run.** The counted run is [run 43092601088](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43092601088), from `main` at `8f23629d` (`CI-Linux`). Its results, against ADR-0009's three turning conditions, D4's recommendation and D1's ruling on #637 are in section 5: the engine is Zeek 9.0.1 with the project's script, and Modbus/TCP on a moved port is a recorded high risk, not closed (HR-22, which D3 writes under P4-4-L6, D4-90). ADR-0009 carries them. **Section 10 is brief P4-4-E2** (D4-90): the Modbus/TCP content signature as an experiment, its corpus, the harness's PRP statement and the notes carried from #637. It has run in rehearsals only, and nothing in it is counted or adopted. Sections 1 to 4 describe the experiment, its pins, and what D4 read in the engines' own sources beforehand (`desk`, each with its file's SHA-256). **Any dispatch from a ref other than `main`, or with a conditions file other than the pinned one, is a rehearsal,** and is recorded here as one: its tables are not the counted result (D1 on #625). Each table's header says which it is (section 1).

**This is evidence for the engine choice, not V-M6 evidence.** V-M6 runs on the real sensor, over the real link, with the checker of P4-4-R1 (brief, acceptance).

## 1. What the experiment runs

`modules/telemetry/experiments/engine-linux/`, started only by the dispatch-only workflow `.github/workflows/d4-engine-linux-eval.yml` on `ubuntu-24.04`. Every engine runs in a container pinned by digest, started with `--network none`, so no engine has a network; the runner keeps its own, which fetches the images, ICSNPP and the captures. The engines read capture files, and in the pipe case (section 1a) a pipe. Nothing captures a network, and no device or lab machine is contacted.

**Five configurations,** each judged alone:

| Configuration | What runs |
| --- | --- |
| `zeek` | Zeek 9.0.1, stock: `zeek -C -r <file> LogAscii::use_json=T` |
| `zeek-probe`, labelled "Zeek with the project's script" in every table | The same, with `probe.zeek`, the project's own script. It handles Zeek's documented DNP3 and SNMP events and writes `otsec_probe.log`, one row per event with the event's name in `ev`. DNP3: `dnp3_header_block` (the link source and destination addresses), the application request and response headers, and `dnp3_object_header`. SNMP: get, get-next, get-bulk, response, set, trap, trapV2, inform, report, unknown PDU, unknown scoped PDU, encrypted PDU, and `snmp_unknown_header_version` (which carries only the version number Zeek read); for SNMPv3 the auth, priv and reportable flags, the security model, the USM engine boots and time, and the lengths of the engine IDs, the user name and the raw USM parameters, never their bytes. It changes no analyzer, registers no port, and names no port, address or capture. **Not read by `table.py`:** the DNP3 link addresses (logged only, so they are in the run's logs for a later reading where one connection carries several outstations; the defaults are outstation 0 and master 1, S22 Table D.7). |
| `zeek-icsnpp` | The same as `zeek`, with ICSNPP-DNP3 and ICSNPP-Modbus loaded from their `scripts` folders |
| `suricata` | Suricata 8.0.8, its image's own `suricata.yaml` with only the `dnp3` and `modbus` eve types added (the stock file comments out `dnp3` and lists no `modbus`), the DNP3 and Modbus parsers switched on, `--disable-detection`, `-k none` |
| `suricata-midstream` | The same, with `stream.midstream=true` |
| `zeek-modbus-sig` (P4-4-E2, section 10; not in E-D4-03's counted run) | `zeek-probe` with `modbus-sig.zeek`, the project's Modbus/TCP content signature, an experiment that is not adopted |

Why the probe is a configuration of its own: Zeek's default `dnp3.log` records the request and reply function names and the IIN, and no object (section 3). Whether Zeek can show group 120 per message at all is then a question of what its events carry, and a sensor under option (b) is project code around the engine in any case. The probe answers that question without touching the stock and ICSNPP rows.

**D1's ruling on #625:** `zeek-probe` is a configuration of its own and is labelled "Zeek with the project's script" in every table. It counts for the engine decision, because a sensor would ship that script and the project writes the capture stage and the mapping to C13 anyway. It does **not** count as "the engine's own log files" under D6's rule 1. So each pass condition is reported three ways for Zeek: stock, with ICSNPP, and with the project's script. D6 owns the pass conditions and may tighten this in review; if it does, D6's reading wins.

**Three capture sets:**

1. **GT-PCAP's cases** (`run.sh dnp3 WORK CACHE`). D6's `dnp3_cases.py` rebuilds every capture named in `tests/fixtures/network/gt-pcap/dnp3/dnp3.sha256`, and the run fails unless each matches its hash: 21 captures since #623 (`96c35ef8`), 19 labelled cases with `dnp3-moved-port` and `dnp3-udp`, and the two R6.2 series. **The derived `modbus-moved-port`** (D6's note, section 3) is rebuilt by D6's `movedport.py` from the cache's `modbus.pcap`, after that file is checked against `MANIFEST.tsv`, and the result is checked against `gt-pcap/modbus/modbus-moved-port.sha256`. **Its control, `modbus.pcap` on port 502, runs beside it** under every configuration. If either check fails, both are left out and their rows read `unknown (not run)`. `table.py` finds the cases from every `*.sha256` under `gt-pcap/*/`, takes each case's protocol from its label file, and reads Modbus requests from Zeek's `modbus.log` and Suricata's `modbus` events.
2. **GT-PCAP's 9 PRP pairs** (`run.sh prp`), rebuilt by `prp.py`, checked against `prp-derived.sha256`, labelled by tshark 4.2.2 through `prp_check.py`, and checked by E-D4-02's own `compare.py` for each configuration. `compare.py` gained an optional list of configurations, and with none it behaves as before.
3. **The public captures** (`run.sh public`): the 21 in `MANIFEST.tsv`, and two Wireshark sample captures in `extra-captures.tsv` for what neither set holds: Telnet (`telnet-raw.pcap`) and HTTP (`http_gzip.cap`). **FTP and SNMPv3 are not shown.** The FTP sample tried, `FTPv6-1.cap`, is in Microsoft Network Monitor format, which libpcap does not read; the page lists its other FTP samples in the same format. The one SNMPv3 sample, `snmp_usm.pcap`, is a big-endian BSD-loopback capture (link type 0) whose address-family word both pinned engines read as little-endian, so each drops every packet with no error (D6 on #630, from Zeek 9.0.1's `packet_analysis/protocol/null/Null.cc` and Suricata 8.0.8's `src/decode-null.c`). So what the engines log of SNMPv3's header fields (P4-4-S2, deliverable 2; ADR-0009's point 4) stays `unknown`, and `probe.zeek`'s SNMP handlers have no capture. In `public.md`, a configuration that exits 0 and logs no flow at all reads `no flow record: capture not decoded`, never `-`, so an undecoded capture cannot read as a negative result. In the rehearsal no other capture had no flow under every configuration. They carry no GT-PCAP label, so no pass condition reads them (D6's note, section 6).

**What the tables say.** `table.py` reads each configuration's logs into flow records and DNP3 messages, with no judgement, and prints:

- **a header on every table** (`dnp3.md`, `public.md`, `prp.md`): the commit, the ref, the SHA-256 of `engine-pass-conditions.tsv` (or `absent`) and whether it equals the pin in `pins.env` (`38e6c081…acc80e`, the file merged with #623, LF endings), and `counted` only when the ref is `refs/heads/main` and the file equals the pin, else `rehearsal: not the counted result` (D6 and D1 on #625);
- per GT-PCAP case and configuration, counts against the labels: flows named as labelled, services, request functions, objects, every group 120 message as `code:variation from sender`, request codes that no label holds, and parser notes (Zeek `weird.log` and `analyzer.log`, Suricata `anomaly`). **Each labelled function row needs a distinct logged request** (a maximum matching), so an engine that logs one of two operates on `dnp3-reused-seq` passes one row, not two (D6 on #625);
- **if D6's `tests/integration/gt_pcap/engine-pass-conditions.tsv` is in the checkout,** each of D6's rows as `pass`, `fail` with its reason, or `unknown`, with the `file:line` it rests on, and each column as n of m. Without the file, the verdict reads `pending D6's pass conditions`. The rows are D6's, and `table.py` holds no condition of its own. **How it reads D6's note is D4's reading, of the note as merged with #623 (`96c35ef8`),** and D6 reviews it. Each result is `pass`, `fail` or `unknown`, never conditional, and each column counts pass, fail and unknown apart. A parser note (`weird.log`, `analyzer.log` or an `anomaly` event) on a group 120 row's flow is appended to the observed reason, with its own text, and its reading as a filler body refused is marked as D4's inference. The engine logs themselves are not uploaded, so nobody reads them by hand.

  **Which function in `table.py` applies which of D6's rules:**

  | D6's rule or condition | Function |
  | --- | --- |
  | Protocol: one record, named as the row's `protocol`; the originator is `src` where `direction` is `client-server`, either orientation, stated, where it is `none` or `midstream`; two records fail | `judge_flow` |
  | Service, and rule 6: the protocol at the server end the row names, and a service at another end of a labelled flow fails as `fail (service also at …)` | `judge_flow` (its `flow_rows` are the capture's Protocol rows; an end that a labelled flow names as its server is never counted as another end, D6 on #625) |
  | Which ICSNPP logs are read: `dnp3.log` for requests, as stock; `dnp3_objects.log` for object headers (READ requests and RESPONSE replies only); and `dnp3_control.log`, whose `block_type` names a control relay output block (group 12 variation 1, Zeek's `dnp3_crob`) or a pattern control block (group 12 variation 2, `dnp3_pcb`). The rows of one ICSNPP message share its connection, direction, arrival time and code. An ICSNPP request joins a `dnp3.log` row when it is on the same connection, with the same code, and is the latest such request after that connection's previous `dnp3.log` row and not after this one: Zeek writes a `dnp3.log` row for the last request before its reply, stamped with the reply's time when it is answered (`base/protocols/dnp3/main.zeek` at `v9.0.1`). So one request is one message, citing both logs, and rule 9 cannot count it twice. A self-check stops the table if any ICSNPP request row is in no request message or in more than one (D6 on #630) | `zeek` |
  | A function row whose engine event has no flow record: `fail (event has no flow record)`, with the event cited | `judge_capture` |
  | Rule 2: a record tied to its flow; for Suricata, a dnp3 or modbus event's sender is taken from its flow record by `flow_id`, the originator for a request and the responder for a response, never from the event's own source fields (D6 on #625) | `suricata` |
  | Rule 9: rows that share a capture, a flow and a code are matched one to one with logged requests, for Function and again for Objects | `assign`, used by `match_functions`, called from `judge_capture` |
  | Rule 7: a name counts only if it maps to one code | `one`, over Zeek's and ICSNPP's own `function_codes` tables |
  | Group 120: each named message as a message of its own; the "no group 120" row passes only if the configuration passes the capture's other group 120 rows and shows no group 120 object between the request and its response, fails on one, and is otherwise `unknown`; a `failed` exchange's challenge and error are separate rows | `judge_g120`, with `judge_capture` judging the named rows first |
  | Which record a row cites when several satisfy it (a Service row's flow, rule 6's wrong server, a Protocol row's several records, a group 120 message, and the order rule 9's matching takes requests in): the first in an order taken from the records' own content (a flow by start time, transport, ends, then the engine's own id; a message by time, protocol, transport, ends, request before response, sender, code and objects), never from its line in a log, whose order the engine does not fix. The file run and the pipe run then cite the same record whenever both hold it (D1 on #630) | `Logs.in_content_order` |
  | Rule 3: what did not run is `unknown` | `ran`, and `evaluate` |
  | Section 3: the Modbus control, and `fail (also fails on port 502)` | `evaluate` with `to_control` |
  | Rule 8: the probe names no port, address or capture | `probe.zeek` itself; the table says so in section 2's preamble |
  | Moved port and UDP columns | the column count in `dnp3`, by capture name |
- **in section 2's preamble,** which setting gives content detection: no configuration names a port, an address or a capture (`run.sh`, `in-container.sh` and `probe.zeek` hold none, D6's rule 8), so detection off a port comes only from Zeek's stock DPD signatures and Suricata's stock `detection-ports` with the two parsers switched on; and **which function codes are critical**: none is treated as critical by the table. S22 Table D.2 lists write, select, operate, direct operate and direct operate with no reply (codes 2 to 6); IEEE 1815's list is not held, so any further code is `unknown`. D6's pass conditions are the authority (D2 on #625).

The engine logs are never uploaded, because they hold capture content. So the tables are computed in the job, and each verdict cites its log line there. The artifact holds `dnp3.md`, `public.md`, `prp.md` and `versions.txt` only.

## 1a. The pipe case, and which stage of the sensor each part stands for

**Why** (D4-87; D7 on #625). AP-31 and D3's note cite E-D4-03 for an engine that reads a pipe in an empty network namespace, and the first harness read files. Since D4-87 and D1's brief to D3 under P4-4-L4, **the sensor's shape, as a design to be shown,** is: a capture process that holds the packet socket, parses nothing and only copies frames to a pipe; a separate stage with no socket that redacts, reassembles and discards PRP duplicates; and the engine, which reads that stage's output through a pipe. A measurement in #626 had shown a process that dropped every capability still sending on its open packet socket.

**What runs.** `run.sh dnp3` runs each Zeek configuration (stock, with the project's script, with ICSNPP) a second time over the same captures (GT-PCAP's 21 DNP3 captures, `modbus-moved-port` and its control), each read from stdin through a pipe: `cat FILE | zeek -r -`. **Each pipe-case container runs with `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges` and the runner's own user, which is not root** (D3 on #630), into an output directory of its own; `versions.txt` records the options. If an engine fails under them, that is a finding and its row stays; the options are not relaxed. The file runs keep Docker's defaults, as E-D4-03 first ran. Zeek's `-r` (`--readfile`) opens its argument with libpcap's offline reader, which D4 expects to take `-` as stdin (`desk`, from libpcap's documented behaviour, not read for this note). The run records the pinned image's own `zeek --help` line for `-r` in `versions.txt`, and that line and the exit codes are the evidence. Still `--network none`. The same functions judge the logs, and section 3 of `dnp3.md` gives a row per configuration: **reads a pipe** is `yes` only when every capture exits 0 with at least one flow record and every one of D6's rows equals the file run's; `no` when no capture does; otherwise `partly`. An exit 0 with no flow record never counts. A pipe row equals its file row when the result, with its citations taken out, is the same and the citations name the same records (a flow by its transport and ends, a message by its flow, sender, code, time and objects), whatever their line numbers, because the order in which Zeek writes records is not fixed. Rows that cite the same records at other line numbers are listed as a note, not as a difference; every differing row is printed with both citations (D6 on #630). **Suricata** reads a FIFO that `cat` writes (`suricata -r FIFO`, its pcap file mode; its own `--help` line for `-r` is recorded), with the same container options, as a note with its exit and flow-record count per capture, and no condition. The engine has 60 s and the writer 30 s per capture, every later capture is skipped after the first time-out, and the note is written after the judged tables, so a hang there cannot cost them (D6 on #630).

**Which stage each part stands for:**

| Part of the experiment | Stage of the sensor | What it does not show |
| --- | --- | --- |
| `cat FILE` writing the pipe | The redacting stage's output (with the capture process behind it) | Any of that stage's work: no redaction, no reassembly, no PRP discard runs here. The capture process and its packet socket are not here at all. |
| `zeek -r -` in a container with `--network none`, `--cap-drop ALL`, no new privileges and a user that is not root | The engine reading the stage's output through a pipe, with no network, no capability and no root | That it runs under the sensor's own account for the engine; that it cannot read the link key; the namespace and the user are Docker's, not the sensor's own. |
| The judge over the logs | The link agent's reading of the engine's logs, roughly | The mapping to C13 records, and the link. |
| `--network none` | The engine's empty network namespace | No name lookup or connection was attempted and refused, only none possible. |

**What a pipe of a finished capture does not show:** a live stream that never ends (log rotation, memory over hours), back-pressure (a slow engine with a full pipe, and what the stage drops or counts then), a writer that stalls or dies (whether the engine waits, ends or reports), **a malformed record on the pipe** (a bad length or a cut record must end the engine visibly, never hang it or be skipped in silence), and **the engine's own file writes and state directory** (here it writes its logs to a mounted host directory; SL-T15's search needs every place it writes) (D3 on #630). Each is for the sensor's own tests under the third part's briefs, D6's rig, or an H-row. It also does not show live capture on a SPAN or TAP port.

**Not to be copied into a sensor** (D3 on #630): the file runs' shell pipeline as root in a container, where one shell holds both ends (a sensor's service manager makes the pipe and hands each end to one process under its own account, with no shell between); the named FIFO in a shared directory, which any process with access could open to read the frames or write its own (a sensor passes an unnamed pipe by descriptor); a container with Docker's default capabilities and user, as the file runs have; and a writable host directory for the engine's logs (a sensor keeps them in bounded, memory-backed storage, SL-22).

**Group 120 and the project's script** (D6's question on #630, D1's ruling). Stock Zeek's `dnp3.log` holds no object, and ICSNPP's `dnp3_objects.log` is written only for READ requests and RESPONSE replies, which function 131 is not, so neither can hold the group 120 messages by construction of its logs. Only "Zeek with the project's script" can pass that column. D1's ruling on #625 stands: that configuration counts for the engine decision, because a sensor would ship the script. **Its log, `otsec_probe.log`, is the project's, not the engine's own** (D6's rule 1), and what passes only with it is sensor code the project must write, test and keep. D1 decides the engine on the counted run.

## 2. The pins

Every pin below is a **first-use pin**: D4 read the digest or hash on 2026-11-11 from the source named, and checked nothing against a signature, because none is published for these artifacts. The workflow checks each pin before what it fetched runs.

| What | Pin | Source of the pin | Checked how | Upstream signature |
| --- | --- | --- | --- | --- |
| Zeek 9.0.1 | `zeek/zeek@sha256:71c1d6b61cdcc25d306c091d32b3da15583485c0c9dfc45cdff48b088cdfdc92` (linux/amd64; the `lts` and `9.0.1` tags point to its index, `sha256:524cb0ce…49dd0`) | Docker Hub's tag listing for `zeek/zeek`. That it is Zeek's own: Zeek's install page, "We provide official Docker images on Docker Hub at hub.docker.com/u/zeek" (`docs.zeek.org/en/master/install.html`, read 2026-11-11, saved file SHA-256 `11a94c5b2e59b3d0b7f543be5c1734fa4caaa82f9bca08e326b8204ba118bf75`, in `reference/carried/d4-sensor-engine-eval-2026-11-11/`) | Docker pulls by digest and checks the content against it; the run then requires `zeek --version` to print `zeek version 9.0.1` | None for the image: no signature tag in the repository. Zeek signs its source tarball (`zeek-9.0.1.tar.gz.asc` on the GitHub release), which the image does not carry. |
| Suricata 8.0.8 | `jasonish/suricata@sha256:a8277a84662969927de6bf6fd1848f64f353e47dd498d1b7d11f75b89096be1f` (linux/amd64) | Docker Hub's tag listing for `jasonish/suricata`, whose page points to `github.com/jasonish/docker-suricata` | By digest, then `suricata -V` must name 8.0.8 | None found. **A first-use pin of an image that OISF does not publish:** it is a personal account's, not an OISF organisation one. **It would not be acceptable in a sensor.** It is accepted for this comparison only, pinned by digest, run with `--network none` on a hosted runner, with tables only uploaded (D1 on #625). It was chosen because it keeps `apt-get` out of the `dnp3-public` job (section 6). **Suricata is the comparison, not the choice.** |
| ICSNPP-DNP3 | commit `b31dbadeceb1cbcda16aef89c650559cd177dd7e` (2026-08-05; the repository has no tag) | GitHub's API for `cisagov/icsnpp-dnp3` | Six files fetched from that commit, each checked against `icsnpp.sha256` before Zeek loads them. `LICENSE.txt` hashes to `4c66ca60…e98d`, the hash D7 recorded (`docs/release.md` §4). | None: no signed tag or release |
| ICSNPP-Modbus | commit `6dd3dab173169e454a73925d0426d3c019104852` (2026-10-17; its last tag, `v2.0.0`, is older) | GitHub's API for `cisagov/icsnpp-modbus` | As above, six files | None |
| Two extra captures | SHA-256 per file in `extra-captures.tsv` | D4's own download from the Wireshark wiki | `sha256sum`; a mismatch removes the file, and its rows read `not run` | None |
| The MANIFEST captures | Their committed SHA-256s (E-A4-01) | `MANIFEST.tsv` | `run.sh public` checks each file against `MANIFEST.tsv` itself, whatever `fetch_captures.sh` left in the cache, and drops one that fails, whose rows then read `not run` (D7 on #625). A `.gz` is checked before it is unpacked. | None |
| tshark 4.2.2 (`prp` job only) | The version, not a hash: `prp_check.py` refuses any other | Ubuntu 24.04's archive | `apt` checks the archive's signature and each package's hash | Ubuntu's archive key |
| `actions/checkout`, `actions/upload-artifact` | Commit SHAs of `v4.4.0` and `v4.6.2` | GitHub's API | GitHub resolves the action by SHA | — |

**Zeek 9.0.1, not 8.0.4.** E-A4-01 and E-D4-02 ran 8.0.4. 9.0.1 is the current LTS release (Docker Hub's `lts` tag on 2026-11-11), so it is the version a sensor would pin. That makes this run the first on 9.0.1: a difference from E-D4-02's PRP rows would be a version difference, and the `prp` table shows whether there is one.

**How ICSNPP gets into the run.** `zkg` is not used, although the brief allowed it. `run.sh` fetches six files per package with `curl` from `raw.githubusercontent.com` at the pinned commit, checks them with `sha256sum -c` against `icsnpp.sha256`, and only then does Zeek load the `scripts` folder. The files are not in the repository: only their hashes are. Neither package needs a build (both are scripts only).

**What a digest pins, and what is not pinned.** A digest pins the image's bytes, not what they were built from: each image's base layers and packages are unverified here. Not pinned at all: the hosted runner's image (`ubuntu-24.04`, as GitHub updates it), its Docker, and its system `python3`, which runs `dnp3_cases.py`, `prp.py`, `prp_check.py`, `compare.py` and `table.py`. Each run's versions are what `versions.txt` records.

**A sensor may not fetch at run time.** The experiment fetches ICSNPP from GitHub and the images from Docker Hub, checked against these pins. A sensor may not: AP-31 (1) and `docs/release.md` §4 require the engine and its packages at a pinned version, carried in the sensor's image or package, never fetched at run time. AP-31 is proposed, and since #624 (D3, P4-4-L1) it covers the sensor host; if the site installs the engine itself, that rests on the site's procedure (HR-21).

**Owed before a sensor can ship** (D7 on #625; ADR-0009's open list, "the engine's supply chain (D7 on #618)"): Zeek built from its signed source tarball, with the `.asc` checked, rather than a registry image whose build is unverified; a reviewed ICSNPP commit (ICSNPP-DNP3 has no tag, and ICSNPP-Modbus is pinned past its last tag, `v2.0.0`); an SBOM for the sensor; and who watches the engines' advisories, since `govulncheck` covers Go modules only. None of these is done here.

**Licences** (D7 on #625). Only tables and versions are uploaded, so the run redistributes nothing: no engine, no package, no capture. Running GPL (Suricata) or BSD (Zeek, ICSNPP) software is not distribution. The Wireshark sample captures state no terms (`extra-captures.tsv`'s header); whether they may be used this way is not decided here, and they are not vendored.

## 3. What the engines' own sources say (`desk`, 2026-11-11)

Read from `raw.githubusercontent.com` at the tags and commits pinned above. These are expectations for the run to confirm or refute. None is a result.

| Source (tag or commit) | SHA-256 | What it says |
| --- | --- | --- |
| `zeek/zeek` `v9.0.1` `src/analyzer/protocol/dnp3/dnp3-objects.pac` | `0ba3df0cab28933f6729d6cab06d9b5c0d88bb9554c9b4a89caeb5b6b24dc493` | Zeek's DNP3 parser has a case for group 120, variations 1 to 15 (`0x7801` to `0x780F`). |
| `v9.0.1` `src/analyzer/protocol/dnp3/events.bif` | `c3c3107870fb0347e0aaa7f3e004d35fb369b9e7908e88862889b970e2de7100` | `dnp3_object_header` is raised for every object header, with the object type (group and variation), the qualifier and the range. |
| `v9.0.1` `scripts/base/protocols/dnp3/main.zeek` | `37f51eab720db2d744ef229c0a10b0fbcd90a131b859f5500f4665a51258d2cd` | `dnp3.log` records `fc_request`, `fc_reply` and `iin`, one row per request and reply. No object. The stream analyzer, `DNP3_TCP`, is registered on 20000/tcp and 20000/udp; `DNP3_UDP` is registered on no port (D2's finding A on #637, from `DNP3.h` and this file). |
| `v9.0.1` `scripts/base/protocols/dnp3/dpd.sig` | `b2067b53fca4dff949c837928e94af647318cc4937d8a37fac3be5d62488a402` | Two content signatures: a TCP payload from the responder that starts `0x05 0x64` enables the TCP analyzer, and a UDP payload that starts `0x05 0x64` enables the UDP analyzer, on any port. **So Zeek may find DNP3 on a moved port and over UDP by content,** which is D6's moved-port condition (no port named). |
| `v9.0.1` `scripts/base/protocols/modbus/main.zeek` and `__load__.zeek` | `c6719dd1a7153be2230cded7343fc60f9ec6fd8ac762bd059e9858cf805b79a1`, `dc51855c1ee8fd1b5ccdfab74249c8f2d064fbb85f6068b329208da2dcca1456` | Modbus is registered on 502/tcp only, and its loader loads no signature file. **So stock Zeek is not expected to find Modbus on a moved port.** |
| `v9.0.1` `scripts/base/init-bare.zeek` | `05e960679cdc6832276c35f8dc2623bce3fa786555cbf80a4a4f19cd9cc4c675` | SNMPv3: the header carries the flags, the security model, the raw USM parameters, the scoped PDU's context engine ID and name, and, new in 9.0 and marked experimental, the parsed USM fields: authoritative engine ID, boots, time and user name. |
| `v9.0.1` `scripts/base/protocols/snmp/main.zeek` | `5a11f2cb5a4959ee210152c344c677570ad7209404ad9b6917806ed667432def` | `snmp.log` puts an SNMPv3 user name in its `community` field. The engine ID, boots and time are not logged. |
| `cisagov/icsnpp-dnp3` `b31dbade` `scripts/main.zeek`, `scripts/consts.zeek` | `62d9892d…c04d`, `0a699332…1025` (`icsnpp.sha256`) | ICSNPP-DNP3 logs `dnp3_control.log` (CROB and PCB) and `dnp3_objects.log`. It logs object headers **only for READ requests and RESPONSE replies,** and drops any object type its table does not name. **Its table names no group 120 object.** So ICSNPP is not expected to add group 120 visibility. |
| `cisagov/icsnpp-modbus` `6dd3dab1` `scripts/main.zeek` | `111ef525…7178` | ICSNPP-Modbus adds detailed logs and an `additional_tcp_ports` option, which registers ports that an operator lists. That is configured ports, not detection by content. |
| `OISF/suricata` `suricata-8.0.8` `suricata.yaml.in` | `6894b0618b7f948c93fbd99a403bc92eb1cf88facec5ace6a45181d5655353b6` | The DNP3 and Modbus parsers are off by default, with detection ports 20000 and 502. The `dnp3` eve type is commented out and `modbus` is not listed. |

**Zeek's DNP3 parse direction** (D2's question on #625; `zeek/zeek` `v9.0.1`, `src/analyzer/protocol/dnp3/dnp3-protocol.pac`, SHA-256 `497eeac4504d8d925d4b35ec9e5c8950b7d3309d2b7a96b644e1c500312279b1`, and `src/analyzer/protocol/dnp3/DNP3.cc`, SHA-256 `8a6fb005cc7b52cbd7a3846a733a3be017ee248af3966d12eae366c1c28c7e6e`). **Yes: Zeek chooses the parse direction from `is_orig`.** `DNP3_PDU(is_orig)` parses the originator's data as `DNP3_Request` and the responder's as `DNP3_Response` (`dnp3-protocol.pac` lines 5 to 8). `DNP3.cc` lines 177 to 182 compare the link header's direction bit with `is_orig` and, on a mismatch, raise the weird `dnp3_unexpected_flow_direction` and go on with `is_orig`. So a UDP flow that the outstation starts, for example with an unsolicited response, is expected to be parsed backwards, with that weird. GT-PCAP's `dnp3-udp` starts from the master, so it does not test this; the two UDP variants D2 named on #625 are owed to D6 as cases.

**The two extra captures are not SEL traffic** (D2 on #625). They show only whether an analyzer fires on Telnet and HTTP. FTP and SNMPv3 are not shown at all (section 1). Missing, and not shown by this run: the SEL login dialogue, SEL ASCII and the Fast protocols inside Telnet; `CFG.TXT` and `SER.TXT` over FTP; any FTP, and FTP's active data on port 20 over IPv4 in particular; and SNMPv3 `authPriv` without DES, as the SEL-2731 requires.

**What D4 expects, before the run.** Group 120 per message can come only from a script on `dnp3_object_header`, not from stock logs or ICSNPP, if Zeek's parser accepts the filler bodies of GT-PCAP's group 120 objects (D6's note: a refused filler body is neither a pass nor evidence about real SA traffic). DNP3 on a moved port and over UDP may be found by the content signatures. Modbus on a moved port is not expected without a configured port. The run decides each of these. **These are expectations read from source, at the files and commits above. They stay in this section and never appear in a results table.**

## 4. What it cannot pin or check, and why

- **No upstream signature for either image.** Neither `zeek/zeek` nor `jasonish/suricata` carries a signature in the registry. Zeek signs only its source tarball. Building Zeek from the signed source would replace the image pin with a signature check, at the cost of a long build in each run. D4 did not do it here. For the sensor's own image it is D7's question.
- **The Suricata image is a personal account's.** No image under an OISF organisation account was found (`oisf/suricata` does not exist on Docker Hub). Ubuntu's signed `suricata` package, which E-D4-02 used, needs `apt-get`. So the comparison rests on a first-use digest from a personal account.
- **ICSNPP has no signed release.** The pin is a commit and the hash of each file loaded.
- **tshark's version is checked, not its hash,** because `apt` resolves it. `apt` checks the archive's signature.
- **Offline decoding of files is not live capture** on a SPAN or TAP port, and a hosted runner is not the sensor host. Both stay `unknown` (brief, risk).
- **Modbus on a moved port is one derived capture** (D6's note, section 3): one midstream conversation, one function code, one unit, from a public capture of unknown origin. It shows whether Modbus/TCP is found by content off port 502, and little else.
- **What the rehearsal showed about the harness** (run 43080066361, at `45daf8d7` from a branch, labelled `rehearsal`; its numbers are not results and are not written here). Both jobs ran to the end, and every table carried its header. Three faults were the harness's, and this follow-up fixes them. The FTP sample tried, `FTPv6-1.cap`, is in Microsoft Network Monitor format, which libpcap does not read (Zeek exited 1, "unknown file format"; Suricata exited 0 with no output), so it is removed. An engine's warnings reached the job log only when it failed, so `in-container.sh` now prints the first warning lines of every run. **D4's own reading of the rehearsal missed the third, which D6 found:** every configuration exited 0 on `snmp_usm.pcap` and logged nothing, because neither engine decodes its link layer, and the table would have shown that as `-`, reading as "no analyzer fires". It is removed, and `public.md` now prints `no flow record: capture not decoded` for any such run. No other capture had no flow under every configuration. No container pulled anything beyond the two pinned images, and no step took more than a minute. **A second rehearsal** (run 43084842333, at `c4e3b541`, labelled `rehearsal`) ran the pipe case and the locked container options (`--network none --cap-drop ALL --security-opt no-new-privileges` and a user that is not root) for the first time, to the end. It showed two faults in the judge, fixed since: the ICSNPP join matched on time, which an answered `dnp3.log` row does not share with its request, and the pipe comparison compared line numbers, whose order Zeek does not fix.
- **`table.py`, `run.sh` and `in-container.sh` were parse-checked only before they ran on the runner,** in four rehearsals and the counted run (section 5). Nothing ran on the owner's PC (no test and no install there). The faults the rehearsals found were fixed in commits, not re-run away.

## 5. Results

**The counted run:** [run 43092601088](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43092601088). D1 dispatched it from `main` at `8f23629d` on 2026-11-11, and both jobs succeeded. Every table opens "Run: counted" and "Ref: refs/heads/main", and the conditions file's SHA-256 equals its pin (`38e6c081…acc80e`). Evidence class `CI-Linux`, `simulated`: offline files on a hosted `ubuntu-24.04` runner.

Versions, from the run's `versions.txt`: Zeek 9.0.1 (`zeek/zeek@sha256:71c1d6b6…dfdc92`), Suricata 8.0.8 (`jasonish/suricata@sha256:a8277a84…be1f`), ICSNPP-DNP3 `b31dbade` and ICSNPP-Modbus `6dd3dab1` (every file checked), and tshark 4.2.2 for the PRP labels. The four rehearsals before it (runs 43080066361, 43084842333, 43086346339 and 43087200195) are not results. Its section 2 tallies equal the second, third and fourth rehearsals'.

### 5.1 D6's 110 rows, per configuration

Each cell counts D6's rows (`tests/integration/gt_pcap/engine-pass-conditions.tsv`) as pass / fail / unknown, judged as `docs/phase4/D6-engine-run-pass-conditions.md` says. **Moved port** counts 7 rows: 4 on `dnp3-moved-port` and 3 on `modbus-moved-port`, read apart below. Objects, Moved port and UDP re-read rows of the other four columns, so the columns sum to 165, not 110 (D6 on #637). "Zeek with the project's script" is its own configuration. Its `otsec_probe.log` is the project's, not the engine's own log (D6's rule 8; D1 on #625).

| Configuration | Protocol (26) | Service (22) | Function (51) | Objects (44) | Moved port (7) | Group 120 (11) | UDP (4) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Zeek, stock | 25 / 1 / 0 | 21 / 1 / 0 | 49 / 2 / 0 | 0 / 44 / 0 | 4 / 3 / 0 | 0 / 10 / 1 | 4 / 0 / 0 |
| Zeek with the project's script | 25 / 1 / 0 | 21 / 1 / 0 | 50 / 1 / 0 | 44 / 0 / 0 | 4 / 3 / 0 | 11 / 0 / 0 | 4 / 0 / 0 |
| Zeek with ICSNPP | 25 / 1 / 0 | 21 / 1 / 0 | 50 / 1 / 0 | 26 / 18 / 0 | 4 / 3 / 0 | 0 / 10 / 1 | 4 / 0 / 0 |
| Suricata (comparison) | 23 / 3 / 0 | 19 / 3 / 0 | 46 / 5 / 0 | 40 / 4 / 0 | 0 / 7 / 0 | 11 / 0 / 0 | 0 / 4 / 0 |
| Suricata, midstream (comparison) | 23 / 3 / 0 | 19 / 3 / 0 | 46 / 5 / 0 | 40 / 4 / 0 | 0 / 7 / 0 | 11 / 0 / 0 | 0 / 4 / 0 |

**The rows that did not pass,** by configuration:

- **Every Zeek configuration** fails `modbus-moved-port`'s Protocol, Service and Function rows. It names nothing on port 15020 (`not named modbus`), and its control, `modbus.pcap` on port 502, passes all three. So each fails because of the port.
- **Stock Zeek also fails:**
  - one of `dnp3-reused-seq`'s two Function rows, because `dnp3.log` keeps one of the two operates;
  - every Objects row, because `dnp3.log` holds no object;
  - every named group 120 row, `fail (no object logged)`. The read's "no group 120" row is `unknown`, because a configuration that logs no object has not shown the absence.
- **Zeek with ICSNPP:**
  - It passes both `dnp3-reused-seq` operates, through `dnp3_control.log`.
  - It fails 18 Objects rows. Its object log covers only READ requests and RESPONSE replies, and its control log only group 12.
  - It passes no group 120 row. Eight read plain `fail`, two read `fail (message shown, no group 120 object)` (`5:g120v3` and `33:g120v7`, requests ICSNPP logs without their group 120 object), and the read's row is `unknown`.
  - Of its 26 Objects passes, 12 cite `dnp3_objects.log` (the function 1 rows) and 14 cite `dnp3_control.log` (the group 12 rows).
- **Zeek with the project's script** fails only the three `modbus-moved-port` rows.
- **Suricata, both ways,** fails:
  - all four rows of `dnp3-moved-port` (`not named dnp3` on 20001);
  - all four of `dnp3-udp` (`not named dnp3` over UDP);
  - the three of `modbus-moved-port`. Without midstream it also fails its control on 502 (`fail (also fails on port 502)`: the capture has no handshake). With midstream the control passes, so it fails because of the port.
  - The four Objects failures are the four function rows of those two DNP3 captures.

### 5.2 ADR-0009's three turning conditions

| Configuration | DNP3 group 120 per message (11 rows) | DNP3 on a moved port (4 rows) | Modbus on a moved port (3 rows) | DNP3 over UDP (4 rows) | All three |
| --- | --- | --- | --- | --- | --- |
| Zeek, stock | **fails**: 0 pass, 10 fail, 1 unknown | meets: 4 of 4 | **fails**: 0 of 3; control passes | meets: 4 of 4 | no |
| Zeek with the project's script | meets: 11 of 11 | meets: 4 of 4 | **fails**: 0 of 3; control passes | meets: 4 of 4 | no |
| Zeek with ICSNPP | **fails**: 0 pass, 10 fail, 1 unknown | meets: 4 of 4 | **fails**: 0 of 3; control passes | meets: 4 of 4 | no |
| Suricata | meets: 11 of 11 | **fails**: 0 of 4 | **fails**: 0 of 3; control fails too | **fails**: 0 of 4 | no |
| Suricata, midstream | meets: 11 of 11 | **fails**: 0 of 4 | **fails**: 0 of 3; control passes | **fails**: 0 of 4 | no |

**No configuration meets all three,** reading the moved-port condition per protocol, DNP3 and Modbus each, as V-M6 does: it lists unauthenticated Modbus/TCP, and a miss there fails. Read as "DNP3 or Modbus", Zeek with the project's script would meet all three (D6 on #637). The nearest is Zeek with the project's script. It meets group 120 and UDP, and meets the moved-port condition for DNP3 and not for Modbus. Every configuration fails Modbus on a moved port.

### 5.3 The pipe case

All three Zeek configurations read a pipe: `yes`, 23 of 23 captures with exit 0 and a flow record, and 110 of 110 rows equal to the file run in result and in the records cited. No row differed, and none cited the same records at other line numbers. The containers ran with `--network none --cap-drop ALL --security-opt no-new-privileges --user 1001:1001`. The run's `versions.txt` records these options, and Zeek's own `--help` line for `-r`: "pass '-' as the filename to read from stdin". **Suricata through a FIFO** (a note, not a condition) exited 0 on all 23 captures, with the same flow-record count as its file run on each.

In D3's words on #630, adapted: the run shows that the engine reads a finished capture from a pipe on its standard input, in a network namespace with only loopback, with no capability and as a user that is not root, and that it gives the same judged rows as from the file. It does not show the engine under the sensor's own account, a stream that does not end, or the stage that writes the pipe (section 1a).

### 5.4 The PRP pairs

**0 of 45 rows pass** (`prp.md`: "pass: no" on every row, "45 row(s) not run or failed", `compare.py` exit code 1). All 45 rows (9 pairs, 5 configurations) record each flow once, with its service and its labelled packets on the LAN A capture. Each counts every packet of both LAN copies, so the totals on `-ab` are exactly twice those on `-a`. That is E-D4-02's result, now on Zeek 9.0.1 and Suricata 8.0.8, and with ICSNPP and the project's script. The PRP duplicate-discard stage stays required.

### 5.5 The public captures

No pass condition reads this table (D6's note, section 6). Each line below is what the engines logged.

- **Telnet** (`telnet-raw.pcap`): Zeek, in every configuration, names no service and writes one `weird.log` row. Suricata names `telnet`.
- **HTTP** (`http_gzip.cap`): every configuration names `http` and logs the file.
- **IEC 104** (`iec104`, `iec104-sq`) and **MMS** (`mms`): no configuration names either. Zeek names no service, and Suricata `failed` or `none`.
- **GOOSE** (the nine `goose-*` captures): no configuration logs GOOSE. Zeek records their DHCP and DNS, and Suricata their DHCP and mDNS.
- **The public DNP3 captures:** every Zeek configuration names `dnp3_tcp` on all six. Without midstream, Suricata names no protocol on `dnp3-digitalbond-part2` or `dnp3-malformed`. With midstream it names both, and writes 133 `anomaly` events on `dnp3-malformed`. That is E-A4-01's 4 of 6 and 6 of 6 again.
- **The public Modbus captures:**
  - On `modbus.pcap` and `modbus-digitalbond-part1`, every Zeek configuration names `modbus`.
  - **On `modbus-digitalbond-part2`, only Zeek with ICSNPP names a Modbus service:** `-=1, modbus=1`, with 281 `modbus.log` and 254 `modbus_detailed.log` rows. Stock Zeek and the project's script show `-=2`, with 45 `modbus.log` rows and one `analyzer.log` row (D6 on #637). D4's reading of the source, `desk` and not shown by the run: ICSNPP-Modbus adds `Analyzer::ANALYZER_MODBUS` to `DPD::ignore_violations` (`scripts/main.zeek` l.134 at `6dd3dab1`), so the analyzer stays on after a parse violation that stops stock Zeek's.
  - Without midstream, Suricata names no protocol on `modbus.pcap`. With midstream it names `modbus` but writes 51 `anomaly` events.
- **FTP and SNMPv3 are on no capture**, so what any engine logs of them is not shown. The FTP sample is in Network Monitor format, and the SNMPv3 sample's link layer is read by neither engine (section 1).
- No capture is `no flow record: capture not decoded` under any configuration.

### 5.6 D4's recommendation, and D1's ruling on #637

**D4's recommendation** (`c794efb3`) was Zeek with the project's script, with the Modbus moved-port gap to be closed first by a per-site port list. D1 approved the engine and ruled that a port list does not close the gap (item 3 below; D6's B1 and D2's note 3 on #637).

**D1's ruling** (the PR's review record, on D4's recommendation):

1. **The engine is Zeek 9.0.1 with the project's script.** It is the only configuration that passes every DNP3 group 120 row (11 of 11), every DNP3 moved-port row (4 of 4) and every DNP3-over-UDP row (4 of 4). Suricata is the comparison only, and its image is never used in a sensor.
2. **One of ADR-0009's turning conditions is met, and the choice does not turn.** No configuration identifies Modbus/TCP on a moved port, Zeek included. It does not turn the choice, because no engine tested meets it and Suricata fails more. **The gap is not closed.**
3. **A per-site Modbus port list does not close the gap.** Under D6's pinned conditions, a service found because the engine was told the port fails the row (`fail (told the port)`), as C13 §11 fails a `service` with `basis: port` on a moved port. The list also misses exactly the server that matters, one the asset table does not know. It may be offered later as an aid for known servers, not as the closure.
4. **The gap is a recorded high risk** (D3 writes it in the threat model as HR-22, under P4-4-L6, D4-90). Two things are owed before item 4's gate:
   - **a tested signal for a flow the engine names nothing for** (`undecoded`), together with `unknown-pair`, so that an unidentified server on a moved port is at least visible, with D6's legs and controls;
   - **a Modbus/TCP content signature in the project's script, as a measured experiment:** its detection on `modbus-moved-port`, and its false-positive rate on a corpus with more non-Modbus binary traffic. It is adopted only on that measurement.
5. **ICSNPP-DNP3 is dropped; ICSNPP-Modbus is not dropped yet** (below).
6. **Owed in GT-PCAP:** DNP3 over UDP on a moved port. GT-PCAP's UDP case is on the registered port 20000 (D2 on #637); by Zeek's source the pass most likely came from content (section 5.7, D2's finding A).

**What ICSNPP adds, corrected** (D6 on #637):
- **ICSNPP-DNP3.** On D6's rows it adds two things over stock Zeek:
  - objects: 12 Objects passes from `dnp3_objects.log` (function 1) and 14 from `dnp3_control.log` (group 12), 26 of 44 in all;
  - one of the two operates of `dnp3-reused-seq`: stock Zeek fails one of its two identical Function rows, and the run does not show which (D6's note 7 on #637).

  It adds no group 120. The project's script passes 44 of 44 Objects and 11 of 11 group 120 rows. So dropping ICSNPP-DNP3 is supported by the run, against project code, which the sensor must keep (D6's rule 8).
- **ICSNPP-Modbus.** D6's rows cannot separate it from stock Zeek: every Zeek configuration fails the moved port and passes the control. The one observation that favours it is the public `modbus-digitalbond-part2` line (§5.5), which no pass condition reads. So it stays under evaluation. Its licence duties stay in D7's record until it is decided. ICSNPP-Modbus is scripts only, so that advantage runs on Zeek's own Modbus analyzer, and D2 reads it as most likely the one `DPD::ignore_violations` line, which the project's script could set without carrying ICSNPP (`inference`: the run does not show the line alone; D2's finding C on #637). That line also removes the check a content signature relies on, a parse violation removing the analyzer, so the two are measured together if both are ever set. P4-4-E2's signature does not set it (section 10).

**Suricata.**
- It fails DNP3 on a moved port: its stock DNP3 detection port is 20000.
- It fails DNP3 over UDP on a capture that *is* on port 20000, so the ports do not explain that failure. **Suricata's DNP3 parser is registered for TCP only:** `documented` by D2 from Suricata's source, `src/app-layer-dnp3.c` at `suricata-8.0.8` (SHA-256 `3dc3186f…` as D2 gave it), where `RegisterDNP3Parsers` registers detection and every parser function for `IPPROTO_TCP` and never for `IPPROTO_UDP` (D2's finding B on #637). So no port setting gives Suricata DNP3 over UDP. The run shows the failure, and the source its cause.
- Without midstream it also fails the Modbus control, because the capture has no handshake.

**The per-site port list, if it is ever offered as an aid** (not as a closure; D2 and D6 on #637). None of this is built.
- **The mechanism.** Zeek registers the Modbus analyzer by a port set in `base/protocols/modbus/main.zeek` (`const ports = { 502/tcp } &redef;`, then `register_for_ports`; §3's source). The `&redef` is what would let a site list extend that set (D2's finding H on #637). ICSNPP-Modbus's `additional_tcp_ports` is the same idea, but it would carry ICSNPP-Modbus, with its pin, review and notices (D7's N4 on #637).
- **How the list would reach the sensor.** Not over the link: no command and no configuration reaches the sensor that way (`docs/phase4/D3-sensor-link.md`), and no asset contract has a field for a device's service ports. So it would be a file placed by the sensor host's management path, and it can drift from the asset table.
- **The ports to list.** A SEL-751 has two Modbus/TCP ports, `MODNUM1` and `MODNUM2`, each 1 to 65534, 502 by default, with `EMOD` off by default (S22 Table 4.104, p. 4.250). The SEL-787-4 is the same, and the SEL-400G and the RTAC also serve Modbus/TCP (D2's note).
- **What it misses** (D2):
  - a Modbus server nobody entered, which includes an unauthorized or rogue server, exactly what an IDS is meant to find;
  - an RTAC's project-defined servers;
  - non-SEL devices, which have only operator-entered data;
  - a server behind NAT, where the port on the wire differs from the setting;
  - Modbus RTU framing in a raw-TCP serial tunnel, which has no MBAP header.
- **Port collisions.** Zeek registers an analyzer by port, not by address, so a listed port is parsed as Modbus on every host at the site. Keying the list on (address, port) in the script would avoid that (D2's `inference`).
- **Its own test row, under its own name** (D6's B1):
  - with 15020 listed, the sensor reports a `service` with `basis: port`;
  - with an empty list, an `undecoded` observation and, after acknowledgement, `unknown-pair`, never silence.

  **D6's three `modbus-moved-port` rows keep failing** for any configuration that names the port.
- **Configuration monitoring of `MODNUM1` and `MODNUM2`** on SEL relays whose settings are collected would cover a known relay's port change, and nothing else (D6).

**The Modbus content signature, as an experiment** (D1's item 4; D2 and D6 on #637). Built as an experiment under P4-4-E2 (section 10), and not adopted.
- **A strict check** (D2) on the client's first segment: protocol ID 0, a length that the bytes fill exactly, allowing a whole number of ADUs in one segment (D2's finding G on #637), and a public function code; and the server's reply echoes the transaction ID and the function code, or the code plus 0x80.
- **Its measurement:**
  - detection on `modbus-moved-port`, and on held-out Modbus moved off 502, writes included;
  - its false-positive rate on a non-Modbus TCP corpus of stated size, with more binary traffic than GT-PCAP and the public captures hold (IEC 104, MMS and EtherNet/IP captures among it), saying what the corpus does not hold;
  - nothing learned from GT-PCAP (D6's rule 8).

  A measured rate is only as good as the traffic it was measured on.

### 5.7 Limits of this result

- **Offline files, not live capture** on a SPAN or TAP port, on a hosted runner and not on the sensor host. The DNP3 captures are synthesized, the Modbus moved-port capture is derived from a public capture of unknown origin, and nothing is a real relay's traffic.
- **The pipe case is a finished capture through a pipe** (section 1a; D3 on #630). It does not show:
  - a stream that never ends;
  - back-pressure;
  - a writer that stalls or dies;
  - a malformed record on the pipe;
  - the engine's own file writes and state directory;
  - the engine under the sensor's own account.

  The namespace and the user are Docker's.
- **Stock Zeek's and ICSNPP's group 120 failures are by construction of their logs.** `dnp3.log` holds no object. ICSNPP's object log is written only for READ requests and RESPONSE replies, which function 131 is not. So they do not show that Zeek's parser misses group 120: the project's script, on the same parser, passes all 11 rows.
- **The group 120 bodies are filler** (D6's note). The pass shows header-level parsing on function 5's exchanges, not decoding of a real challenge, reply or error.
- **DNP3 over UDP is one arrangement, on the registered port:** the master starts, and both ends are on 20000, with the ports by inference until H-23. **By Zeek's source, the UDP pass most likely came from content, not from the port** (D2's finding A on #637; a reading, `desk`, and not a result). Zeek registers its stream analyzer, `DNP3_TCP`, for both 20000/tcp and 20000/udp; it reads streams only, so on a UDP flow it would read no datagram. `DNP3_UDP`, which reads datagrams, is registered for no port and is enabled only by `dpd.sig`'s UDP signature, a payload starting `05 64` on any port in either direction. So the owed case of DNP3 over UDP on a moved port is expected to pass if its first datagram starts `05 64`. It stays owed in GT-PCAP until it runs (D2 on #637; D1's ruling; P4-D6-GT2). An outstation that starts a UDP flow is expected to be parsed backwards by Zeek (section 3), and is not tested.
- **The Modbus moved-port case is one midstream conversation,** one function code and one unit. Modbus/TCP on a moved port is a recorded high risk (§5.6; HR-22, owed by D3), not closed.
- **No rate, drop or latency is measured.** R6.4's latency is the timed-replay rig's.
- **What the captures do not represent** (D2's table in `docs/phase4/D6-engine-run-pass-conditions.md` §7): unsolicited responses, application confirms, link keep-alives, link-layer confirms, fragmentation, real response contents, a refused master, other UDP port arrangements, and Modbus beyond one read.
- **FTP and SNMPv3 are not shown** on any capture. Telnet, HTTP, IEC 104, MMS and GOOSE are reported with no pass condition.
- **This is evidence for the engine choice, not V-M6 evidence.**

**D2's reading of unsolicited reporting, beside the cases owed** (D2 on #625 and #623; S22 Table D.7 p. D.11, behaviour p. D.9).
- On a SEL-751, unsolicited reporting is off by default (`UNSOLn := N`, `PUNSOLn := N`), a per-session setting.
- With `UNSOLn := Y`, D2's `inference` is that the relay sends function 130 with UNS and CON set, and the master confirms with function 0. No GT-PCAP capture holds it.
- Zeek parses DNP3 by `is_orig` (section 3). So a UDP flow that the relay starts, with an unsolicited response or a reply sent to port 20000 while the master sent from another port, is expected to be parsed backwards.
- The ports of GT-PCAP's `dnp3-udp` (both ends on 20000) are by inference, settled by H-23 (D2 on #623).
- **Cases owed to D6** (D1 passed them on):
  - a master that sends from a temporary UDP port while the relay replies to `DNPUDPn` 20000, so the reply is a second 5-tuple;
  - `DNPUDPn := REQ`;
  - an unsolicited response that starts a flow.

  This run shows none of them.

## 6. What waits

Nothing now. The record of what waited:

1. **Done:** D6's cases and pass conditions are on `main` (#623 as `96c35ef8`), and this branch has merged `main`.
2. **The workflow on `main`.** GitHub finds a `workflow_dispatch` workflow only on the default branch, so `gh workflow run d4-engine-linux-eval.yml --ref agent/telemetry-engine-linux-eval` cannot start it before this PR's workflow file is on `main`. It has no `pull_request` or `push` trigger, by the brief. This PR merges on its reviews and green checks; then D1 dispatches the counted run from `main`, or tells D4 to.
3. **The hosted runners.** From 13:53Z on 2026-11-11, `apt-get` on the hosted Linux runners could not resolve Ubuntu's package archive (D4-84, D4-85). The `dnp3-public` job installs no package: Docker and Python come with the image, and the engines come as pinned images, so that fault does not reach it. The `prp` job installs tshark with `apt-get`, for the labeller `prp_check.py` pins, so it fails in set-up while the fault lasts. A set-up failure is D1's to re-run (D4-85).

## 7. D1's rulings on D4's four questions (on #625, 2026-11-11)

1. **The first dispatch:** #625 merges, then D1 dispatches the counted run from `main`, or tells D4 to. D1's first order put #625 before #623; #623 merged first (`96c35ef8`), and this branch merged `main`. A dispatch from another ref is a rehearsal (status line, section 6).
2. **The probe configuration:** a configuration of its own, labelled in every table. It counts for the engine decision and is not "the engine's own log files". D6 may tighten this (section 1).
3. **Modbus on a moved port:** `unknown` is not good enough if a case can be made honestly. D1 has asked D6 for a derived case, and the table takes it (section 1). Without it, D1 reads the row as not shown.
4. **The Suricata image:** acceptable for this comparison only, never in a sensor, and `apt-get` stays out of the `dnp3-public` job (section 2).

## 8. ADR-0009

#618 merged as `c9222b35`. This branch applies the three notes its reviewers gave for D4's next change to the ADR (D1's record on #618, 15:53Z), and nothing else:

1. "The sensor never affects collection" now reads "must never", with the test owed (D3; P4-4-L3 item 8).
2. AP-31 as it now reads (D3, P4-4-L1, #624) covers the sensor host; GPLv2's source offer is valid for "at least" three years (D7).
3. GT-PCAP now holds DNP3 on a moved outstation port and over UDP (#623), and the derived Modbus moved-port case (D6 and D2).

With the counted run (brief P4-4-S2, deliverable 4), ADR-0009's evidence gains "E-D4-03 results", from section 5. Its engine line now reads as D1 ruled on #637: Zeek 9.0.1 with the project's script, approved on E-D4-03, with the met turning condition, the high risk, ICSNPP-Modbus under evaluation and the owed UDP case.

## 9. Files

- `modules/telemetry/experiments/engine-linux/`: `run.sh`, `in-container.sh`, `table.py`, `probe.zeek`, `pins.env`, `icsnpp.sha256`, `extra-captures.tsv`
- `modules/telemetry/experiments/prp-engines/compare.py`: an optional list of configurations
- The follow-up under D4-87 (`agent/telemetry-engine-linux-eval-2`): the pipe case in `in-container.sh`, `run.sh` and `table.py`; the Suricata sender from the flow record and rule 6's labelled servers in `table.py`; this note; ADR-0009's UDP ports and AP-31 (1)'s site-install sentence; the workflow's header
- `modules/telemetry/experiments/README.md`: one row
- `.github/workflows/d4-engine-linux-eval.yml` (new, dispatch-only)
- `docs/decisions/ADR-0009-passive-sensor.md`: the three notes in section 8, the engine's line and results under #637, and under P4-4-E2 the notes carried from #637 (section 10.5)
- P4-4-E2 (`agent/telemetry-e2-signature`): `modbus-sig.zeek` and `modbus-sig.sig` (new, then amended), `flows.py`, `corpus_label.py`, `synth_corpus.py`, `ports.zeek` and `test_sig_judge.py` (new), `run.sh`, `table.py` and `pins.env` in `engine-linux/`; `tests/fixtures/network/modbus-sig-corpus/corpus.tsv` and `labels.tsv` (new); the experiments README's row; this note; ADR-0009. The workflow is unchanged.

## 10. P4-4-E2: the Modbus/TCP content signature, as an experiment (D4-90)

Brief P4-4-E2 in `docs/agent-handoffs.md` ("After D4-90"). D1's ruling on #637 adopts a Modbus/TCP content signature in the project's script only on a measurement. **D6's pass conditions for it are merged and pinned** (`tests/integration/gt_pcap/modbus-signature-conditions.tsv`, SHA-256 `7b242b85…4418`, #642; the note `docs/phase4/D6-modbus-signature-conditions.md`, #647), with D1's threshold (comments 6838101998 on #642 and 6840362704 on #647). This section is the signature as amended under D1's rulings 6837866171 and 6839544756 on #643 and 6839544318 and 6839966277 on #642, its corpus, the harness that judges every row of D6's file, and the rehearsals. **The counted run is dispatched from `main` after #643 merges, by D1, and D1 adopts the signature or does not on it.** Nothing here is counted, and nothing calls the signature adopted.

### 10.1 What the signature matches, as amended

`modbus-sig.zeek` loads `modbus-sig.sig`, and runs with `probe.zeek` as `zeek-modbus-sig`: S0 in D6's conditions, beside S1, `zeek-probe`, the approved configuration. It names no port, no address and no capture (D6's rule 8), registers no port, and sets no option of Zeek's: no `DPD::ignore_violations`, so S2 does not arise. The amendment is `25e1286b`, committed before any capture added to the corpus under it was read.

- **Two orientations, both sides needed.** Forward: the originator's first chunk reads as requests, and the responder's as replies whose first carries the first request's transaction ID and its code, or that code plus 80h (D2's strict check). Reversed, for a flow whose first frame is the server's with no SYN, which Zeek keeps with the server as originator off a likely server port (D2's B1 on #642): the originator's first chunk reads as replies and the responder's as requests, with no ID or code compared, as the first reply answers a request the capture does not hold (D1's ruling 6839544318: roles are lost, not the protocol). Only the second signature of each pair enables Zeek's Modbus analyzer.
- **The framing, from the specifications only** (D1's ruling 6839966277: no narrower than the specification allows for a code; each check cites its clause for D2; neither document is in `reference/`, so each citation is `inference` until D2 labels it): [T1] the MBAP header, protocol ID 0 (Messaging on TCP/IP Implementation Guide V1.0b, §3.1.3); [A1] a length of 2 to 254 (Application Protocol Specification V1.1b3, §4.1); [A2] a request with code 1 to 6 has length 6 (§6.1 to §6.6); [A3] a normal reply to code 1 to 4 has length 3 plus its byte count (§6.1 to §6.4), never applied to an exception reply (§7; D6's `review-text` (e)). Every other code is accepted with any length from 2 to 254. No transaction ID, unit or length learned from a capture, and no value of another protocol: the BER rule D1 first suggested is withdrawn, and `30 84` appears nowhere.
- **The codes:** every code of `fc-classes/1` (1 to 6, 8, 15, 16, 22, 23, 43, 60h, 61h, 62h, 7Dh, 7Eh) and the other "Standard defined" codes of Zeek's `Modbus::function_codes`, without 5Bh (`review-text` (b)).
- **What an eval function is given** (Zeek v9.0.1 `src/RuleMatcher.cc`, SHA-256 `1be73e06…d545`, read for this change): conditions are evaluated only when a pattern newly matches (l.830), on the whole chunk of the reassembled stream in which the anchored pattern completes (l.886 to l.890), and again on that stored chunk when a `requires-reverse-signature` is met later (l.983 to l.989, l.1010 and l.1011). So a chunk with several ADUs is read ADU by ADU; a chunk cut partway through an ADU after its sixth octet, or holding a header without its code, is accepted on what it shows. **A first segment of 1 to 5 octets is refused** (D6's reading of `review-text` (c) on `3ef15100`, from `RuleMatcher.cc` l.823, l.881, l.886 and l.1012): the matcher's state carries across chunks, but the eval function gets only the chunk in which the anchored pattern completes, so the second chunk is read from its own first octet and refused unless it happens to read as an ADU. D6 reads (c) as failing on this; it is a limit, and the signature is not changed for it before the counted run (D1's ruling on the rehearsal). No capture here shows it.
- **What it does not do:** read past the first chunk of each side; match a capture of one direction; accept a code outside the set, function code 0 included; match Modbus RTU or ASCII framing in raw TCP, which this measurement classes `not-modbus`. The limits for HR-22 and the gate report are in 10.7.

### 10.2 The corpus

`tests/fixtures/network/modbus-sig-corpus/corpus.tsv` is the manifest of every member, each with its URL or writer, its SHA-256, its source and terms, its protocol, its Modbus label by source, the port its source names for the server, and the earlier runs of S0 over it (`seen`). Its header lists the terms of each source and what the corpus does not hold (`corpus-not-held`). Nothing is committed: every public capture is fetched in the run at its pin, and every synthesized one is written in the run by its writer and checked.

- **Members** (`corpus-members`): GT-PCAP's 21 DNP3 cases; MANIFEST.tsv's 21 captures, which bring IEC 104 and MMS (D7's N2 on `bebd8243`: no stated terms is not a bar when fetched and never committed); extra-captures.tsv's 2; the 58 captures rehearsed at `3436c8dc`; **13 public Zeek v9.0.1 traces not run under S0 before the amendment** (FTP, HTTP, SSH, SMTP, IRC, SMB3, TLS; no POP3, as Zeek's Traces README names a third-party origin for it); and **3 synthesized captures** written by `synth_corpus.py` with D6's GT-PCAP writer: four Modbus RTU read flows in raw TCP (codes 1 to 4 at address 0, quantity 2, as D1 ruled; D6's example `01 03 00 00 00 02 C4 0B` among them), one server-first Modbus/TCP flow on 15020, and five Modbus/TCP flows opened with SEL's codes 60h to 7Eh, answered with an exception.
- **Labels** (`label-flow`): `labels.tsv`, one row per TCP and UDP flow, 952 rows, written by `corpus_label.py` from the manifest and the pinned tshark 4.2.2, never from an engine, in rehearsal 43344298828 and committed as written (SHA-256 `b16e911e…1199`). `flows.py` gives each flow's packets and payload per end, which end sent the SYN and the first frame, and the first 8 octets of each end's reassembled stream for `near_miss`; the labels hold no payload byte.
- **Five labels corrected** (D6's B2 on `3ef15100`): `corpus_label.py` classed a flow `not-modbus` on its two tshark checks alone, without `label-not-modbus`'s first half (the source names the flow's protocol, or the capture's, as not Modbus). It now classes `not-modbus` only where the manifest's `modbus` is `none` or `rtu`. That moves five flows to `disputed`: `zeek-modbus-small`'s three UDP flows on port 53, and `zeek-modbus-big`'s two TCP flows on 102, whose `protocol` was `iso-tsap`, a name its source does not give; it is now `-`. - **GT-PCAP's three DNP3-over-UDP cases from #648** (`dnp3-udp-moved-port`, `-req-port`, `-temp-port`) are members: `corpus-members` names every capture of `gt-pcap/dnp3/dnp3.sha256`, and rehearsal 6 showed that without them the 13 rows #648 added to D6's 123 read `not run` under S0 and S1 in the measurement. The manifest now holds 121 members (SHA-256 `6aeaa447…5c9d`; `918cef08…e3b2` since two moved hashes were re-pinned after #649, rehearsal 9 in 10.4).
- **The labels as committed** are the file rehearsal 7 (43355514690) wrote with the pinned tshark, committed as written (SHA-256 `36adf462…a67a`): 956 rows, **33 `modbus`, 911 `not-modbus` and 12 `disputed`**. Against rehearsal 43344298828's file, the pinned labeller's output differs in exactly the five rows of B2 and the `-` for `iso-tsap`, and adds four UDP rows for the three new cases. Rehearsal 8 regenerated them equal, row for row.
- **Licences** (D7's N1 on `bebd8243`): `zeek-modbus-eit` and `zeek-modbus-4sics-min` now read "Zeek's `COPYING`; Traces/README names Netresec's 4SICS set as the source; its own terms not read".

### 10.3 The harness

- **P4-4-E2's measurement runs in the `prp` job,** the one job with the pinned tshark that `corpus_label.py` and D6's `modbus_label.py` need, and its table is appended to `prp.md` and the job's summary. The workflow file is unchanged. The `public` mode no longer runs a corpus.
- **Every row of D6's file is judged or marked as read, not measured.** The det-, ctl- and reg- rows come from D6's 110 rows under S0 and S1 in the same run. `held-502` flows are moved to 15020 by `movedport.py`, checked against their pins, labelled there by `modbus_label.py`, and judged per flow on their protocol, service and function rows with their control on 502; `held-other` flows on their protocol and service rows; a flow with no client SYN whose first frame is the server's on its protocol row only, never counted. `held-count` counts public flows only (D1's 6840362704) and states the count with synthesized flows beside it. `fp-control` counts again on a copy of the labels with `modbus.pcap`'s flow on 502 relabelled.
- **`judge-counted`:** the header checks D6's two condition files, the manifest and the labels against `pins.env` (`MODBUS_SIGNATURE_CONDITIONS_SHA256`, D6's name, `CONDITIONS_SHA256`, `MODBUS_SIG_CORPUS_SHA256`, `MODBUS_SIG_LABELS_SHA256`) and the ref. The labels are also regenerated in the run and compared with the committed file, which decides. **`CONDITIONS_SHA256` now pins #648's file** (`4a99d030…c455`, 123 rows, LF endings; `main` `79b43c93`), merged into this branch, as D1 set.
- **The held-out rows, after D6's review of `3ef15100`:** a row that fails under S0 while its control on 502 did not run reads `unknown`, never a pass (B1); a flow none of whose rows was judged, because every row also fails on 502, is listed and is not tallied as a pass, and `held-502` and `held-other` read "n pass, n fail, n unknown, n listed, of m" (N3); a `det-` row whose control fails reads `fail (also fails on port 502)`, and one whose control did not run reads `unknown` (N2); with `held-count` under 5, both held- rows read `unknown` whatever they read before (N2). Each is a function of `table.py` (`judge_held`, `held_tally`, `det_verdict`, `held_count_gate`), tested on made-up rows in `test_sig_judge.py`, which the `pytest` job runs.
- **Public and synthesized** (D6's N1): a member is synthesized when its source says so, GT-PCAP's `GT-PCAP (D6), synthesized` included. Before, GT-PCAP's 24 DNP3 flows were reported as public.
- **`judge-seen`** (D6's N4): the harness lists every earlier run of S0 by ID, with its head and the signature's hashes, and says the signature is unchanged since `25e1286b`. **`corpus-protocols`** (D6's N6) says it counts names by capture: `protocol` is one name per capture, so sslh's SSH flows read `tls` and `goose` names flows that are UDP or carry no payload.
- **Rule 6 takes the servers from the Service rows** (`7bfa398a`; D1 to D4 from #648): a Protocol row's `dst` can be a master on a temporary port (`dnp3-udp-temp-port`), and a service named there must fail.
- **`likely_server_ports`** is printed under S0 and S1 after every `zeek_init` handler (priority −1000) and at `zeek_done` (`ports.zeek`; D2's N2 on #647), and the table says whether the four prints agree and checks each held-out client port with no client SYN against S1's set.
- **The PRP statement** (D4-88's bullet) is unchanged from rehearsals 1 and 2: the summary says the comparison failed and why the job is green, and the job fails if a row did not run. A P4-4-E2 measurement that does not finish also fails the job.

### 10.4 Rehearsals

Every run below was dispatched from `agent/telemetry-e2-signature` and is labelled `rehearsal` in its tables, for E-D4-03's conditions and for P4-4-E2's. Its numbers are not results: they show that the harness runs, and what the counted run will be asked to measure.

**Rehearsal 1**, [run 43314221626](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43314221626) at `21ffb801` (`CI-Linux`, simulated). Both jobs green.
- **The harness ran to the end.** All 58 corpus captures matched their pins, all 5 moved captures matched theirs, and no capture read `not run`. The P4-4-E2 header line read "rehearsal … (D6's P4-4-E2 conditions are not pinned in pins.env)" in every table.
- **The PRP statement** was written into `prp.md` and the job's summary, and the run carries the warning annotation (read through GitHub's check-run API; the rendered summary page has no API and was not read). 54 rows, 9 pairs under 6 configurations, all `no`, none `not run`. A desk check of the block with a stubbed checker (four outcomes: rows failed, a row not run, all passed, checker crashed) gave green with the statement, a failed job, the "passed" statement, and a failed job.
- **D6's 110 rows** (`dnp3.md`): the five E-D4-03 configurations gave the counted run's column counts. `zeek-modbus-sig` passed 110 of 110, its three `modbus-moved-port` rows among them, with the control on 502 passing.
- **The corpus** (`public.md`): with the signature, 21 of the 22 held-out Modbus flows on 15020 were named, and 22 of 22 controls on 502; `zeek-probe` named none on 15020 and all 22 on 502. One non-Modbus flow had a Modbus record under the signature and none under `zeek-probe`: `zeek-ldap-invalid-credentials` (`conn.log` names `modbus`, and `modbus.log` has a row). Of the totals, the negatives read 140 because the table counted `zeek-modbus-big`'s two port-102 flows in both its moved run and its control; `table.py` now counts them once (138), a fix to the table and not to the signature.
- **Why the LDAP flow matched** (D4's reading of the capture's bytes, `desk`). Both ends of this flow encode each LDAP message with a four-octet BER length: the client's first payload is `30 84 00 00 00 4a 02 01 41 …`. Read as MBAP, that is transaction ID `0x3084`, protocol ID 0, a length of 74 that fills the 80-octet payload exactly, unit `0x02` and function code `0x01` (READ_COILS, a public code; it is the BER length of the message ID). The reply starts `30 84 00 00 00 f6 02 01`, the same transaction ID and code, so the echo check passes too. Any LDAP message in this encoding under 255 octets has that shape. The other three LDAP captures did not match: in `zeek-ldap-aduser1` only the server uses `30 84`, and the client's first payload (`30 82 05 80`) fails; `zeek-ldap-sasl-ntlm` uses short lengths both ways; `zeek-ldap-missing-ldap-logs` uses `30 84`, but its first request is 350 octets, over the 254 bound. The servers that use `30 84` in these captures are domain controllers by their content, so D4 reads the encoding as Windows' (`inference`). D2 did not list BER in its reading on #637, so this is a collision the strict check does not rule out. **On a station LAN with Windows machines in a domain, LDAP to a domain controller is ordinary traffic,** and a flow named Modbus there could raise the insecure-protocol flag and `unknown-pair` (D4's inference).
- **Why the `zeek-modbus-big` flow was not named** (the capture's bytes, `desk`). The capture starts midstream with the server's reply (`c2 4a 00 00 00 04 ff 01 01 01`, from port 502), so Zeek takes the server as the originator. The originator's first payload is then a reply, and the other side's first payload is the next request, with transaction ID `0xc24b`, not `0xc24a`, so the echo check fails. On 502 Zeek turns the flow round by its port, which is why the control passes. This is the limit written in 10.1 before the run. It matters for a sensor that starts while a long-lived polling connection is open: whether that connection is found depends on which side's segment the sensor sees first, and a connection missed this way stays missed until it reconnects (D4's inference).
- **Rehearsal 2**, [run 43315465228](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43315465228) at `51540b17` (`CI-Linux`, simulated), after the totals fix. Both jobs green. D6's 110 rows: every configuration's column counts equal rehearsal 1's. PRP: 54 rows, all `no`, none `not run`, with the statement. Corpus totals: 138 / 11 / 7 non-Modbus flows (equal to D4's `desk` reading), one with a Modbus record under the signature (the same LDAP flow) and none under `zeek-probe`; held-out 21 of 22 named on 15020; controls 22 of 22 under both.
- **The signature was not changed.** Changing it now to fit the LDAP capture would make the corpus's false-positive count a measurement of traffic the signature was fitted to. **Two questions go to D1, with D2 and D6, before the counted run:** (1) whether the counted run measures the signature as committed (`3436c8dc`), or an amendment that refuses a first payload starting `30 84`, a BER SEQUENCE with a four-octet length (which would also refuse a Modbus flow whose first transaction ID is `0x3084`, one in 65,536), measured then on negative traffic it was not shaped on, BER-encoded LDAP among it; (2) whether the midstream limit is accepted as stated, since Zeek's own Modbus analyzer reads the originator's side as requests and a signature alone cannot turn a flow round. **D1 ruled on both** (6837866171 on #643, narrowed by 6839544318 and 6839966277 on #642): the signature as committed is not adopted; it may be amended with framing from the Modbus specification only; and a server-first flow loses its roles, not its protocol. The amendment is 10.1.

**Rehearsal 3**, [run 43344298828](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43344298828) at `4011e49e`, the amended signature over the grown corpus (`CI-Linux`, simulated). Both jobs green. It wrote `labels.tsv` with the pinned tshark into its artifact, and that file is committed as written. Three harness faults, fixed in `4da1f1c8` and none in the signature: an empty manifest field shifted the next one (`read` collapses tabs), so every capture was treated as held-out and refused for moving; `ports.zeek` used the keyword `when` and printed nothing; and `held-other` was judged on function rows the condition does not ask for.

**Rehearsal 4**, [run 43345170729](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43345170729) at `4da1f1c8` (`CI-Linux`, simulated), with every pin equal and the labels regenerated equal to the committed file. Both jobs green. Rows as the run judges them (a rehearsal, not the result):

- **Pass:** `det-protocol`, `det-service`, `det-function`, `ctl-502`, `ctl-baseline` (S1 fails all three on 15020), `reg-rows` (S1 107 of 110, S0 110 of 110, none lost), `held-other` (6 of 6, synthesized: the server-first flow on its protocol row, and the five SEL-code flows), `held-count` (23 public flows that count, from 4 captures other than `modbus.pcap`), `fp-flows` (**0 false positives**), `fp-floor` (532), `fp-near` (24: MySQL 15, PostgreSQL 3, LDAP 1, MQTT 1, RTU 4 synthesized), `fp-control` (+1), `corpus-protocols` (31; DNP3 the largest at 245 of 532), `label-disputed` (6 of 571).
- **Fail: `held-502`, 22 of 27 pass.** Two public flows fail where their control on 502 passes, both from `modbus-digitalbond-part1/2` (MANIFEST.tsv, Digital Bond's IDS test data): `10.0.0.57:2579` sends two requests and the server sends nothing, so the signature, which needs both sides, cannot name it; `192.168.66.235:2582` opens with function code 0, which the specification does not define, so the first chunk is refused and the signature reads no later chunk. Both are limits written in 10.1 before the run. **So by D1's threshold the signature as amended would not be adopted on this corpus**, and the counted run will most likely say the same.
- **Listed and in no count:** `modbus_label.py` refused two moved captures because tshark's TCP checksum verdict differs between source and moved form (`icsnpp-modbus-example`, every frame; `zeek-modbus-big`, frame 10931). The moved files equal their pins, so this is `movedport.py`'s checksum adjustment on these two captures, a finding for D6. `zeek-modbus-big`'s server-first flow is therefore not judged; the synthesized server-first flow is, and S0 names it.
- **`likely_server_ports`** printed the same set four times (S0 and S1, at `zeek_init` priority −1000 and at `zeek_done`): TCP 502 and 20000 are in it; 15020, 4001 and every held-out client port with no client SYN (2074, 37699, 54297, 54298, 1987, 49226, 49300) are not. So the mirror case of D2's N3 does not arise in this corpus (D6's option (b)), and the server-first flows exercise D1's ruling.
- **LDAP:** the four LDAP flows whose BER framing reads as MBAP are `disputed` by D6's labelling rule (tshark, told port 389, reads requests answered with the same ID and code), so they are in no count; S0 names none of them.
- **Seen:** 148 of fp-floor's flows come from captures not run under S0 before the amendment; none is a false positive. The earlier runs of S0 over the corpus are 43314221626 and 43315465228 (the signature at `3436c8dc`), and this PR's 43344298828, 43345170729 and 43346878016 (the amendment).

**Rehearsal 5**, [run 43346878016](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43346878016) at `7bfa398a`, after rule 6 took its servers from the Service rows (`CI-Linux`, simulated). Both jobs green. Every P4-4-E2 row reads as in rehearsal 4, and every configuration's column counts over D6's 110 rows in `dnp3.md` equal rehearsal 4's, so the change moves no row at the current pin; the row it is for, `dnp3-udp-temp-port`, arrives with #648.

**Rehearsal 6**, [run 43354762583](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43354762583) at `ccfc4091`, with `CONDITIONS_SHA256` at #648's file and the fixes of 10.3 (`CI-Linux`, simulated). Both jobs green; every pin equal; the labels regenerated equal. `reg-rows` read "S1 passes 107 of 123, S0 110 of 123, none lost": the 13 rows of #648's three UDP cases did not run in the measurement, because those captures were not corpus members (the `dnp3-public` job ran them, and its `dnp3.md` has them). They were added (10.2).

**Rehearsal 7**, [run 43355514690](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43355514690) at `4c4ad119`, with no `labels.tsv` committed so that the run wrote it (`CI-Linux`, simulated). Both jobs green. Its labels are committed as written.

**Rehearsal 8**, [run 43356139186](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43356139186) at `9beba8d6`, with every pin equal (`CONDITIONS_SHA256` `4a99d030…c455`, the manifest `6aeaa447…5c9d`, the labels `36adf462…a67a`) and the labels regenerated equal to the committed file, row for row (`CI-Linux`, simulated). Both jobs green. Rows as the run judges them (a rehearsal, not the result):

- **Pass:** `det-protocol`, `det-service`, `det-function`, `ctl-502`, `ctl-baseline` (S1 fails all three on 15020), `reg-rows` (S1 119 of 123, S0 122 of 123, none lost), `held-other` (6 pass of 6), `held-count` (23 public flows from 4 captures; 28 with the synthesized), `fp-flows` (0 false positives), `fp-floor` (530: 502 public, 28 synthesized), `fp-near` (24, 20 public, from 5 protocols), `fp-control` (+1), `corpus-protocols` (30 names by capture; DNP3 245 of 530), `label-disputed` (8 of 571).
- **Fail: `held-502`**, 22 pass, 2 fail, 0 unknown, 3 listed, of 27: `10.0.0.57:2579` and `192.168.66.235:2582`, as in rehearsals 4 and 5. `adopt-when`: not met (`held-502`, `review-text`).
- The rehearsal reads as the counted run is expected to: **not adopted**. Rehearsal 8 is not in `SEEN` (its head adds runs 6 and 7); the counted result names it.

**Rehearsal 9**, [run 43361080550](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43361080550) at `d980815f`, after `main` (`24c28052`, D6's `movedport.py` fix, #649) was merged into this branch and the two moved captures re-pinned: `icsnpp-modbus-example`'s `moved_sha256` `ac0ea1a5…cc72` and `zeek-modbus-big`'s `66847c41…df48` (D4's review of #649), the manifest re-pinned to `918cef08…e3b2` (`CI-Linux`, simulated). Both jobs green. Every pin equal; the labels regenerated equal to the committed file, row for row, so `MODBUS_SIG_LABELS_SHA256` stays `36adf462…a67a`. `SEEN` holds runs 1 to 8; rehearsal 8 was added at this head. Rows as the run judges them (a rehearsal, not the result):

- **The pinned tshark now reads both re-derived captures:** `modbus_label.py` refused neither, and no held-out flow is listed.
- **Pass:** `det-protocol`, `det-service`, `det-function`, `ctl-502`, `ctl-baseline` (S1 fails all three on 15020), `reg-rows` (S1 119 of 123, S0 122 of 123, none lost), `held-other` (6 pass of 6), `held-count` (**25** public flows from **5** captures other than `modbus.pcap`; 30 from 6 with the synthesized), `fp-flows` (0 false positives), `fp-floor` (530), `fp-near` (24, 20 public, from 5 protocols), `fp-control` (+1), `corpus-protocols` (30 names by capture; DNP3 245 of 530), `label-disputed` (8 of 571).
- **Fail: `held-502`**, **25 pass**, 2 fail, 0 unknown, **0 listed**, of 27: `10.0.0.57:2579` and `192.168.66.235:2582`, as in rehearsals 4 to 8. `adopt-when`: not met (`held-502`, `review-text`).
- **What moved against rehearsal 8:** the three listed flows are judged. `icsnpp-modbus-example`'s two (`127.0.0.1:47785`, 22 function rows; `192.168.1.6:37699`, function 3) pass every row, each with its control on 502 passing, and count, which takes `held-count` from 23 to 25 and from 4 captures to 5. `zeek-modbus-big`'s server-first flow (`10.235.149.240:49226`) is judged on its protocol row only and does not count: S0 names it Modbus with the server, `10.235.149.243`, as originator, where the control on 502 has the client; the roles are lost and the protocol is not, as D1 ruled. Every other row reads as in rehearsal 8.
- The rehearsal reads as the counted run is expected to: **not adopted**. The head after it adds rehearsal 9 to `SEEN`, with this note and nothing else.

### 10.5 The notes carried from #637

D1's integration review of `ccea278c` carried these to D4's next change. Each is answered here, in ADR-0009 or in `pins.env`.

| Note | Answer | Where |
| --- | --- | --- |
| D7's N1: "which the sensor ships" | "which a sensor would ship" | ADR-0009, D1's ruling on #637 |
| D7's N2: 9.0.1 under the engine line, and "which versions are pinned" still `unknown` | "Which build of Zeek 9.0.1 a sensor pins, and how … 9.0.1 is the version tested and approved, not a release pin" | ADR-0009, "Still `unknown`" |
| D7's N4: "would bring ICSNPP back" | "would carry ICSNPP-Modbus, with its pin, review and notices" | ADR-0009; section 5.6 |
| D7's N5: the "fallback" comment in `pins.env` | "Suricata is the comparison, not the choice" | `pins.env` |
| D2's A: the UDP pass most likely came from content | Stated as D2's reading, `desk`, not a result; the owed case is expected to pass if the first datagram starts `05 64` | ADR-0009, "Owed in GT-PCAP"; sections 3 and 5.7 |
| D2's B: Suricata's DNP3 is TCP only, from source | Now `documented`, from D2's reading of `app-layer-dnp3.c` | Section 5.6 |
| D2's C: ICSNPP-Modbus's advantage is most likely one `ignore_violations` line | Stated as D2's `inference`; the signature does not set the line | Section 5.6; 10.1 |
| D2's D: "DNP3 is found" | DNP3 over TCP is found on 20001 when the outstation's reply starts `05 64`; a capture of the master's side alone is not shown. Points 2 and 3 point to E-D4-03 | ADR-0009, "Still `unknown`"; protocol points 2 and 3 |
| D2's E: "shown for DNP3/TCP and Modbus/TCP only", and Telnet | DNP3 over UDP on one arrangement added; Zeek names no Telnet service, Suricata does | ADR-0009, "What the engine choice does not claim" |
| D2's F | D2's list on `53554116` has no F (A to E, G, H) | — |
| D2's G: a whole number of ADUs | The strict check allows it, and the signature implements it | Section 5.6; 10.1; `modbus-sig.zeek` |
| D2's H: `&redef` left out of the quote | Quoted in full, with what `&redef` allows | Section 5.6 |
| D6's 1: "which the sensor ships" | As D7's N1 | ADR-0009 |
| D6's 2: the pinned-versions line | As D7's N2, in D6's suggested words | ADR-0009 |
| D6's 3: protocol points 2 and 3 still `unknown` | Each now points to E-D4-03's answer | ADR-0009, protocol points |
| D6's 4: what D4 recommended, and what D1 ruled differently | One sentence each | ADR-0009, "What the run decided"; section 5.6 |
| D6's 5: Suricata "a possible later addition" | "by a later decision only" | ADR-0009 |
| D6's 6: no HR number yet | Cites HR-22, which D3 writes under P4-4-L6 (D4-90), and D4-90 beside "D1 on #637" | ADR-0009 status, ruling, "Still `unknown`"; this note's status, 5.6, 5.7 |
| D6's 7: "the second operate" | "one of the two operates", and the run does not show which | Section 5.6 |
| D6's 8: section 9 lists only the three notes of section 8 | Section 9 lists what each change touched | Section 9 |
| D1: "Each follows in D1's briefs" covers the sensor host, which is the owner's choice | The first two follow in D1's briefs; the host's hardware and system are the owner's choice, with D1's recommendation (D4-86) | ADR-0009, "Not decided here" |
| ADR-0009's "may come from its port registration" (D4-90) | Brought in line with D2's finding A, as a reading | ADR-0009 and section 5.7 |

### 10.6 D7's notes on `bebd8243`

| Note | Answer | Where |
| --- | --- | --- |
| N1: the licence of the two 4SICS captures | "Zeek's `COPYING`; Traces/README names Netresec's 4SICS set as the source; its own terms not read" | `corpus.tsv`, both rows and its header |
| N2: no stated terms is not a bar for a fetched capture | MANIFEST.tsv's and extra-captures.tsv's captures are corpus members, IEC 104 and MMS among them, fetched at their pins and never committed | `corpus.tsv`'s header; 10.2 |
| N3: test traces installed with Zeek | D7's own record; nothing for D4 | — |
| Section 3: the corpus and labels pins, and the pin's name | `MODBUS_SIGNATURE_CONDITIONS_SHA256` (D6's name), `MODBUS_SIG_CORPUS_SHA256` and `MODBUS_SIG_LABELS_SHA256` in `pins.env`; the header checks all four files and the ref | `pins.env`; `run.sh`'s `header`; 10.3 |

### 10.7 Limits for HR-22 and the gate report

Each is a limit of the signature as committed (`25e1286b`), stated before the counted run. None is fixed before it (D1's ruling on the rehearsal: the conditions and threshold stand).

- **Both public misses are reconnaissance** (D2's N3 on `3ef15100`). `modbus-digitalbond-part1`'s `10.0.0.57:2579` is an unanswered Read Device Identification (2Bh, MEI 0Eh): a one-sided identification probe, which the signature cannot name because it needs both sides. `modbus-digitalbond-part2`'s `192.168.66.235:2582` is a function-code sweep that opens with the invalid code 0: the first chunk is refused and no later chunk is read. On a moved port these are what an IDS most wants named. The gate report says the signature misses a sweep that opens with an invalid code and a one-sided identification probe, not only "a session that opens with an undefined code".
- **The codes the set refuses** (D2's N5): code 0; the user-defined ranges 41h to 48h and 64h to 6Eh (Application Protocol Specification §5), which the specification allows; the reserved codes 09h, 0Ah, 0Dh, 0Eh, 29h, 2Ah, 5Bh and 7Fh (Annex A, D2's `inference`); and the unassigned public codes. The set is wider than `fc-classes/1` (it adds Zeek's "Standard defined" codes) but not the specification's whole range. A session that opens with any refused code is not named.
- **A first segment of 1 to 5 octets is refused** (10.1; D6's `review-text` (c)). It is also an evasion path: a client that sends its first request in segments under 6 octets is not named.
- **Pipelined requests answered out of order** (D2's N4): the forward orientation needs the first reply to carry the first request's transaction ID and code, so a server that answers pipelined requests out of order is refused there. Whether the Messaging Guide allows that is D2's `inference`; no corpus flow shows it. Beside "first chunk only".
- **The reversed pair runs on every flow** (D2's N1, D6 on `review-text`): `otsec_modbus_server_first` and `otsec_modbus_client_second` are not limited to flows whose originator sent no SYN, so they are a second gate, without pairing and with framing only for codes 5 and up, on all traffic. The false-positive measurement covers S0 with the pair in place, so nothing is understated; limiting the pair to flows with no SYN is for a later brief.
- **A connection whose first segment the sensor saw from the server** loses its roles (10.4, `zeek-modbus-big`), and one where the echo check then fails is missed until it reconnects.

### 10.8 The reviews of `3ef15100`

| Note | Answer | Where |
| --- | --- | --- |
| D6's B1: a fail with its control not run tallied as a pass | `unknown`, tested | `table.py` `judge_held`; `test_sig_judge.py`; 10.3 |
| D6's B2: five labels break `label-not-modbus` | The rule's first half is checked; five flows `disputed`; `iso-tsap` is `-`; pins moved | `corpus_label.py`; `corpus.tsv`; `labels.tsv`; `pins.env`; 10.2 |
| D6's N1: GT-PCAP reported as public | `synthesized()`; fp-floor's 530 flows are 502 public and 28 synthesized (24 DNP3, 4 RTU) | `table.py`; 10.3 |
| D6's N2: det- rows and held-count | `det_verdict`, `held_count_gate`, tested | `table.py`; 10.3 |
| D6's N3: listed flows in the pass count | `listed`, named apart, tested | `table.py`; 10.3 |
| D6's N4: every S0 run by ID | `SEEN` in the harness's output | `table.py`; 10.3 |
| D6's N5: rehearse at #648's pin | Rehearsals 6 to 8; rehearsal 6 found #648's three cases outside the corpus, so their 13 rows had not run | 10.2; 10.4 |
| D6's N6: names by capture | Said in the row | `table.py`; 10.3 |
| D6's `review-text` (c) | A limit, for HR-22 and the gate report | 10.1; 10.7 |
| D2's N1, N3, N4, N5 | Limits | 10.7 |
| D2's N2: part2's wording | 2582's protocol and service rows also fail on 502 and are not counted against S0; its `held-502` failure is on function rows 1 to 4 with their controls passing | the PR body |
| D7's N1: the two contributors | Named in the header, as Traces/README gives them | `corpus.tsv` |
| D7's N2: "Every pin" | "Every image and package pin" | `pins.env` |
| D7's N3: two forms of the licence | One: `BSD-3-Clause (COPYING)`, which the header says is Zeek's | `corpus.tsv` |
| `CONDITIONS_SHA256` | `4a99d030…c455`, #648's file, D1's word | `pins.env`; 10.3 |
| `movedport.py`'s checksums (D6, another branch) | If its fix changes the moved bytes, the five `moved_sha256` values and the manifest's pin move after it merges, and `held-502` gains the refused flows | — |

# D4: E-D4-03, the engine on Linux over GT-PCAP (P4-4-S2)

D4, 2026-11-11. Brief P4-4-S2 in `docs/agent-handoffs.md` ("Phase 4 item 4, second part", D4-86). ADR-0009 names Zeek as the provisional engine under option (b), and D1 approves it or turns the choice on this run.

**Status: run.** The counted run is [run 43092601088](https://github.com/alialyami90/OTSEC-Proj/actions/runs/43092601088), from `main` at `8f23629d` (`CI-Linux`). Its results, against ADR-0009's three turning conditions, and D4's recommendation are in section 5; ADR-0009's evidence carries them. Sections 1 to 4 describe the experiment, its pins, and what D4 read in the engines' own sources beforehand (`desk`, each with its file's SHA-256). **Any dispatch from a ref other than `main`, or with a conditions file other than the pinned one, is a rehearsal,** and is recorded here as one: its tables are not the counted result (D1 on #625). Each table's header says which it is (section 1).

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
| Suricata 8.0.8 | `jasonish/suricata@sha256:a8277a84662969927de6bf6fd1848f64f353e47dd498d1b7d11f75b89096be1f` (linux/amd64) | Docker Hub's tag listing for `jasonish/suricata`, whose page points to `github.com/jasonish/docker-suricata` | By digest, then `suricata -V` must name 8.0.8 | None found. **A first-use pin of an image that OISF does not publish:** it is a personal account's, not an OISF organisation one. **It would not be acceptable in a sensor.** It is accepted for this comparison only, pinned by digest, run with `--network none` on a hosted runner, with tables only uploaded (D1 on #625). It was chosen because it keeps `apt-get` out of the `dnp3-public` job (section 6). **Suricata is the fallback, not the choice.** |
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
| `v9.0.1` `scripts/base/protocols/dnp3/main.zeek` | `37f51eab720db2d744ef229c0a10b0fbcd90a131b859f5500f4665a51258d2cd` | `dnp3.log` records `fc_request`, `fc_reply` and `iin`, one row per request and reply. No object. The analyzer is registered on 20000/tcp and 20000/udp. |
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

Versions, from the run's `versions.txt`: Zeek 9.0.1 (`zeek/zeek@sha256:71c1d6b6…dfdc92`), Suricata 8.0.8 (`jasonish/suricata@sha256:a8277a84…be1f`), ICSNPP-DNP3 `b31dbade` and ICSNPP-Modbus `6dd3dab1` (every file checked), and tshark 4.2.2 for the PRP labels. The four rehearsals before it are not results. Its section 2 tallies equal the second, third and fourth rehearsals'.

### 5.1 D6's 110 rows, per configuration

Each cell counts D6's rows (`tests/integration/gt_pcap/engine-pass-conditions.tsv`) as pass / fail / unknown, judged as `docs/phase4/D6-engine-run-pass-conditions.md` says. **Moved port** counts 7 rows: 4 on `dnp3-moved-port` and 3 on `modbus-moved-port`, read apart below. "Zeek with the project's script" is its own configuration. Its `otsec_probe.log` is the project's, not the engine's own log (D6's rule 8; D1 on #625).

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
  - It passes no group 120 row. Eight fail with no group 120 message shown, two fail as `message shown, no group 120 object` (`5:g120v3` and `33:g120v7`, requests ICSNPP logs without their group 120 object), and the read's row is `unknown`.
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

**No configuration meets all three.** The nearest is Zeek with the project's script. It meets group 120 and UDP, and meets the moved-port condition for DNP3 and not for Modbus. Every configuration fails Modbus on a moved port.

### 5.3 The pipe case

All three Zeek configurations read a pipe: `yes`, 23 of 23 captures with exit 0 and a flow record, and 110 of 110 rows equal to the file run in result and in the records cited. No row differed, and none cited the same records at other line numbers. The containers ran with `--network none --cap-drop ALL --security-opt no-new-privileges --user 1001:1001`. The run's `versions.txt` records these options, and Zeek's own `--help` line for `-r`: "pass '-' as the filename to read from stdin". **Suricata through a FIFO** (a note, not a condition) exited 0 on all 23 captures, with the same flow-record count as its file run on each.

In D3's words on #630, adapted: the run shows that the engine reads a finished capture from a pipe on its standard input, in a network namespace with only loopback, with no capability and as a user that is not root, and that it gives the same judged rows as from the file. It does not show the engine under the sensor's own account, a stream that does not end, or the stage that writes the pipe (section 1a).

### 5.4 The PRP pairs

All 45 rows (9 pairs, 5 configurations) record each flow once, with its service and its labelled packets on the LAN A capture. Each counts every packet of both LAN copies, so the totals on `-ab` are exactly twice those on `-a`. That is E-D4-02's result, now on Zeek 9.0.1 and Suricata 8.0.8, and with ICSNPP and the project's script. The PRP duplicate-discard stage stays required.

### 5.5 The public captures

No pass condition reads this table (D6's note, section 6). Each line below is what the engines logged.

- **Telnet** (`telnet-raw.pcap`): Zeek, in every configuration, names no service and writes one `weird.log` row. Suricata names `telnet`.
- **HTTP** (`http_gzip.cap`): every configuration names `http` and logs the file.
- **IEC 104** (`iec104`, `iec104-sq`) and **MMS** (`mms`): no configuration names either. Zeek names no service, and Suricata `failed` or `none`.
- **GOOSE** (the nine `goose-*` captures): no configuration logs GOOSE. Zeek records their DHCP and DNS, and Suricata their DHCP and mDNS.
- **The public DNP3 and Modbus captures:**
  - Zeek names `dnp3_tcp` and `modbus` as E-A4-01 found.
  - Without midstream, Suricata names no protocol on `modbus.pcap`.
  - With midstream, Suricata names it but writes 51 `anomaly` events.
- **FTP and SNMPv3 are on no capture**, so what any engine logs of them is not shown. The FTP sample is in Network Monitor format, and the SNMPv3 sample's link layer is read by neither engine (section 1).
- No capture is `no flow record: capture not decoded` under any configuration.

### 5.6 D4's recommendation (D4's, not a decision; D1 approves in review)

**The engine: Zeek 9.0.1, with the project's own script on Zeek's documented DNP3 events, as the sensor's engine.**

- It is the only configuration that meets the group 120 condition and the UDP condition, and DNP3 on a moved port.
- It reads a pipe with no capability.
- Its objects are complete on these captures (44 of 44).

**ICSNPP is not recommended for the sensor on this evidence.** It adds no group 120 visibility and fewer objects than the project's script. It would be one more package to pin, review and carry. Its control log is the one thing it adds over stock Zeek here.

**Suricata stays the comparison.** It fails DNP3 on a moved port and DNP3 over UDP with its stock detection ports.

The script is sensor code that the project must write, test and keep (D6's rule 8). Zeek's own stock logs do not meet the group 120 condition, by construction.

**What closes the Modbus moved-port gap: two ways, neither built.**

1. **A list of Modbus server ports per site, from the asset table, in the sensor's site configuration** (Zeek's `Modbus::ports`, or ICSNPP-Modbus's `additional_tcp_ports`). A SEL relay's Modbus/TCP port is a setting (`MODNUM1`, D6's note, section 3), so the asset table can carry it, as GT-PCAP's own labeller is told the port. D6's rule 8 forbids naming a port in the experiment's configuration. A sensor's site configuration could carry one, as a stated dependency: a Modbus server on a port nobody listed is a stated visibility limit (R6.1), never a silent gap.
   - **The test that would show it:** `modbus-moved-port` run with a site list naming 15020 passes its three rows; the same run with an empty list fails them and reports the limit; and no other capture's flow is named Modbus.
2. **A Modbus/TCP content signature in the project's script.** Zeek has none (section 3), so this would be the project's. Modbus/TCP's header is weak content: a transaction ID, a protocol ID of zero and a length. So a signature risks naming other traffic as Modbus. It is worth adding only with its false-positive rate measured.
   - **The test:** the same three rows pass with no port named, and no flow in GT-PCAP's DNP3 captures, the public captures or the PRP pairs is named Modbus by it.

D4 recommends the site port list first, because it is deterministic and follows the asset table. The signature should be considered only as an addition, after its false-positive measurement. Either way the rows are owed again by a run.

**Not changed:** ADR-0009's engine line. D1 decides on this run.

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
- **DNP3 over UDP is one arrangement:** the master starts, and both ends are on 20000, with the ports by inference until H-23. An outstation that starts a UDP flow is expected to be parsed backwards by Zeek (section 3), and is not tested.
- **The Modbus moved-port case is one midstream conversation,** one function code and one unit.
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

With the counted run (brief P4-4-S2, deliverable 4), ADR-0009's evidence gains "E-D4-03 results", from section 5: the run, the results against the three turning conditions, and D4's recommendation as D4's. The ADR's engine line changes only on D1's approval.

## 9. Files

- `modules/telemetry/experiments/engine-linux/`: `run.sh`, `in-container.sh`, `table.py`, `probe.zeek`, `pins.env`, `icsnpp.sha256`, `extra-captures.tsv`
- `modules/telemetry/experiments/prp-engines/compare.py`: an optional list of configurations
- The follow-up under D4-87 (`agent/telemetry-engine-linux-eval-2`): the pipe case in `in-container.sh`, `run.sh` and `table.py`; the Suricata sender from the flow record and rule 6's labelled servers in `table.py`; this note; ADR-0009's UDP ports and AP-31 (1)'s site-install sentence; the workflow's header
- `modules/telemetry/experiments/README.md`: one row
- `.github/workflows/d4-engine-linux-eval.yml` (new, dispatch-only)
- `docs/decisions/ADR-0009-passive-sensor.md`: the three notes in section 8

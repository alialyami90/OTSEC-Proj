# D4: E-D4-03, the engine on Linux over GT-PCAP (P4-4-S2)

D4, 2026-11-11. Brief P4-4-S2 in `docs/agent-handoffs.md` ("Phase 4 item 4, second part", D4-86). ADR-0009 names Zeek as the provisional engine under option (b), and D1 approves it or turns the choice on this run.

**Status: built, not run.** No engine has run under this experiment yet, so this note holds no `CI-Linux` result. What it holds is the experiment, its pins, and what D4 read in the engines' own sources (`desk`, each with its file's SHA-256). Three things wait, in section 6. When the counted run is done, its run URL and tables go into section 5, and ADR-0009's evidence follows. **Any dispatch before #623 is on `main` is a rehearsal,** and is recorded here as one: its tables are not the counted result (D1 on #625). Each table's header says which it is (section 1).

**This is evidence for the engine choice, not V-M6 evidence.** V-M6 runs on the real sensor, over the real link, with the checker of P4-4-R1 (brief, acceptance).

## 1. What the experiment runs

`modules/telemetry/experiments/engine-linux/`, started only by the dispatch-only workflow `.github/workflows/d4-engine-linux-eval.yml` on `ubuntu-24.04`. Every engine runs in a container pinned by digest, started with `--network none`, over capture files. Nothing captures a network, and no device or lab machine is contacted.

**Five configurations,** each judged alone:

| Configuration | What runs |
| --- | --- |
| `zeek` | Zeek 9.0.1, stock: `zeek -C -r <file> LogAscii::use_json=T` |
| `zeek-probe`, labelled "Zeek with the project's script" in every table | The same, with `probe.zeek`, the project's own script. It handles Zeek's documented DNP3 and SNMP events and writes `otsec_probe.log`, one row per event with the event's name in `ev`. DNP3: `dnp3_header_block` (the link source and destination addresses), the application request and response headers, and `dnp3_object_header`. SNMP: get, get-next, get-bulk, response, set, trap, trapV2, inform, report, unknown PDU, unknown scoped PDU and encrypted PDU; for SNMPv3 the auth, priv and reportable flags, the security model, the USM engine boots and time, and the lengths of the engine IDs, the user name and the raw USM parameters, never their bytes. It changes no analyzer, registers no port, and names no port, address or capture. **Not read by `table.py`:** the DNP3 link addresses (logged only, so they are in the run's logs for a later reading where one connection carries several outstations; the defaults are outstation 0 and master 1, S22 Table D.7). |
| `zeek-icsnpp` | The same as `zeek`, with ICSNPP-DNP3 and ICSNPP-Modbus loaded from their `scripts` folders |
| `suricata` | Suricata 8.0.8, its image's own `suricata.yaml` with only the `dnp3` and `modbus` eve types added (the stock file comments out `dnp3` and lists no `modbus`), the DNP3 and Modbus parsers switched on, `--disable-detection`, `-k none` |
| `suricata-midstream` | The same, with `stream.midstream=true` |

Why the probe is a configuration of its own: Zeek's default `dnp3.log` records the request and reply function names and the IIN, and no object (section 3). Whether Zeek can show group 120 per message at all is then a question of what its events carry, and a sensor under option (b) is project code around the engine in any case. The probe answers that question without touching the stock and ICSNPP rows.

**D1's ruling on #625:** `zeek-probe` is a configuration of its own and is labelled "Zeek with the project's script" in every table. It counts for the engine decision, because a sensor would ship that script and the project writes the capture stage and the mapping to C13 anyway. It does **not** count as "the engine's own log files" under D6's rule 1. So each pass condition is reported three ways for Zeek: stock, with ICSNPP, and with the project's script. D6 owns the pass conditions and may tighten this in review; if it does, D6's reading wins.

**Three capture sets:**

1. **GT-PCAP's DNP3 captures** (`run.sh dnp3`). D6's `dnp3_cases.py` rebuilds every capture named in `tests/fixtures/network/gt-pcap/dnp3/dnp3.sha256`, and the run fails unless each matches its hash. Today that is 19 captures: 17 labelled cases and the two R6.2 series. **D6's two new cases drop in with no change here**: `dnp3-moved-port` and `dnp3-udp` are in #623, and once they are on `main` they are in `dnp3.sha256` and have their label files.

   **A derived Modbus case on a moved port** (D1 has asked D6 for one, if it can be labelled honestly) drops in the same way if D6 lists it in `dnp3.sha256` with its label file beside the others. `table.py` takes each case's protocol from its label file's `flow` rows, so protocol and service rows are read for Modbus as for DNP3, and a `moved port` column counts every capture whose name holds `moved-port`. Function rows are read for DNP3 only: a Modbus function row reads `unknown (this table reads DNP3 functions only)`. If D6 builds the case another way, for example from a fetched capture outside `dnp3_cases.py`, `run.sh` needs one line to build it, in a commit that names it. If D6 cannot make it, the row stays `unknown`, and D1 reads it as not shown.
2. **GT-PCAP's 9 PRP pairs** (`run.sh prp`), rebuilt by `prp.py`, checked against `prp-derived.sha256`, labelled by tshark 4.2.2 through `prp_check.py`, and checked by E-D4-02's own `compare.py` for each configuration. `compare.py` gained an optional list of configurations, and with none it behaves as before.
3. **The public captures** (`run.sh public`): the 21 in `MANIFEST.tsv`, and four Wireshark sample captures in `extra-captures.tsv` for what neither set holds: SNMPv3 with USM (`snmp_usm.pcap`), Telnet (`telnet-raw.pcap`), FTP over IPv6 (`FTPv6-1.cap`) and HTTP (`http_gzip.cap`). They carry no GT-PCAP label, so no pass condition reads them (D6's note, section 6).

**What the tables say.** `table.py` reads each configuration's logs into flow records and DNP3 messages, with no judgement, and prints:

- **a header on every table** (`dnp3.md`, `public.md`, `prp.md`): the commit, the ref, the SHA-256 of `engine-pass-conditions.tsv` (or `absent`), and `counted` only when the ref is `refs/heads/main` and that file is present, else `rehearsal: not the counted result` (D6 and D1 on #625);
- per GT-PCAP case and configuration, counts against the labels: flows named as labelled, services, request functions, objects, every group 120 message as `code:variation from sender`, request codes that no label holds, and parser notes (Zeek `weird.log` and `analyzer.log`, Suricata `anomaly`). **Each labelled function row needs a distinct logged request** (a maximum matching), so an engine that logs one of two operates on `dnp3-reused-seq` passes one row, not two (D6 on #625);
- **if D6's `tests/integration/gt_pcap/engine-pass-conditions.tsv` is in the checkout,** each of D6's rows as `pass`, `fail` with its reason, or `unknown`, with the `file:line` it rests on, and each column as n of m. Without the file, the verdict reads `pending D6's pass conditions`. The rows are D6's, and `table.py` holds no condition of its own. **How it reads D6's note is D4's reading, written against #623 at `2d322c36`,** and D6 reviews it. Where the note leaves room, the reading is stated in the table's own text, for example that "no group 120 object between the request and its response" passes only where the configuration also shows the capture's other group 120 messages. Each result is `pass`, `fail` or `unknown`, never conditional, and each column counts pass, fail and unknown apart. `fail (filler body refused)` is inferred, not read: the configuration shows no such group 120 object and wrote a parser note (`weird.log`, `analyzer.log` or an `anomaly` event) on the same flow, and the note's own text is printed beside the result so that D6 can judge it from the table. The engine logs themselves are not uploaded, so nobody reads them by hand.
- **in section 2's preamble,** which setting gives content detection: no configuration names a port, an address or a capture (`run.sh`, `in-container.sh` and `probe.zeek` hold none, D6's rule 8), so detection off a port comes only from Zeek's stock DPD signatures and Suricata's stock `detection-ports` with the two parsers switched on; and **which function codes are critical**: none is treated as critical by the table. S22 Table D.2 lists write, select, operate, direct operate and direct operate with no reply (codes 2 to 6); IEEE 1815's list is not held, so any further code is `unknown`. D6's pass conditions are the authority (D2 on #625).

The engine logs are never uploaded, because they hold capture content. So the tables are computed in the job, and each verdict cites its log line there. The artifact holds `dnp3.md`, `public.md`, `prp.md` and `versions.txt` only.

## 2. The pins

Every pin below is a **first-use pin**: D4 read the digest or hash on 2026-11-11 from the source named, and checked nothing against a signature, because none is published for these artifacts. The workflow checks each pin before what it fetched runs.

| What | Pin | Source of the pin | Checked how | Upstream signature |
| --- | --- | --- | --- | --- |
| Zeek 9.0.1 | `zeek/zeek@sha256:71c1d6b61cdcc25d306c091d32b3da15583485c0c9dfc45cdff48b088cdfdc92` (linux/amd64; the `lts` and `9.0.1` tags point to its index, `sha256:524cb0ce…49dd0`) | Docker Hub's tag listing for `zeek/zeek`. That it is Zeek's own: Zeek's install page, "We provide official Docker images on Docker Hub at hub.docker.com/u/zeek" (`docs.zeek.org/en/master/install.html`, read 2026-11-11, saved file SHA-256 `11a94c5b2e59b3d0b7f543be5c1734fa4caaa82f9bca08e326b8204ba118bf75`, in `reference/carried/d4-sensor-engine-eval-2026-11-11/`) | Docker pulls by digest and checks the content against it; the run then requires `zeek --version` to print `zeek version 9.0.1` | None for the image: no signature tag in the repository. Zeek signs its source tarball (`zeek-9.0.1.tar.gz.asc` on the GitHub release), which the image does not carry. |
| Suricata 8.0.8 | `jasonish/suricata@sha256:a8277a84662969927de6bf6fd1848f64f353e47dd498d1b7d11f75b89096be1f` (linux/amd64) | Docker Hub's tag listing for `jasonish/suricata`, whose page points to `github.com/jasonish/docker-suricata` | By digest, then `suricata -V` must name 8.0.8 | None found. **A first-use pin of an image that OISF does not publish:** it is a personal account's, not an OISF organisation one. **It would not be acceptable in a sensor.** It is accepted for this comparison only, pinned by digest, run with `--network none` on a hosted runner, with tables only uploaded (D1 on #625). It was chosen because it keeps `apt-get` out of the `dnp3-public` job (section 6). **Suricata is the fallback, not the choice.** |
| ICSNPP-DNP3 | commit `b31dbadeceb1cbcda16aef89c650559cd177dd7e` (2026-08-05; the repository has no tag) | GitHub's API for `cisagov/icsnpp-dnp3` | Six files fetched from that commit, each checked against `icsnpp.sha256` before Zeek loads them. `LICENSE.txt` hashes to `4c66ca60…e98d`, the hash D7 recorded (`docs/release.md` §4). | None: no signed tag or release |
| ICSNPP-Modbus | commit `6dd3dab173169e454a73925d0426d3c019104852` (2026-10-17; its last tag, `v2.0.0`, is older) | GitHub's API for `cisagov/icsnpp-modbus` | As above, six files | None |
| Four extra captures | SHA-256 per file in `extra-captures.tsv` | D4's own download from the Wireshark wiki | `sha256sum`; a mismatch removes the file, and its rows read `not run` | None |
| The MANIFEST captures | Their committed SHA-256s (E-A4-01) | `MANIFEST.tsv` | `run.sh public` checks each file against `MANIFEST.tsv` itself, whatever `fetch_captures.sh` left in the cache, and drops one that fails, whose rows then read `not run` (D7 on #625). A `.gz` is checked before it is unpacked. | None |
| tshark 4.2.2 (`prp` job only) | The version, not a hash: `prp_check.py` refuses any other | Ubuntu 24.04's archive | `apt` checks the archive's signature and each package's hash | Ubuntu's archive key |
| `actions/checkout`, `actions/upload-artifact` | Commit SHAs of `v4.4.0` and `v4.6.2` | GitHub's API | GitHub resolves the action by SHA | — |

**Zeek 9.0.1, not 8.0.4.** E-A4-01 and E-D4-02 ran 8.0.4. 9.0.1 is the current LTS release (Docker Hub's `lts` tag on 2026-11-11), so it is the version a sensor would pin. That makes this run the first on 9.0.1: a difference from E-D4-02's PRP rows would be a version difference, and the `prp` table shows whether there is one.

**How ICSNPP gets into the run.** `zkg` is not used, although the brief allowed it. `run.sh` fetches six files per package with `curl` from `raw.githubusercontent.com` at the pinned commit, checks them with `sha256sum -c` against `icsnpp.sha256`, and only then does Zeek load the `scripts` folder. The files are not in the repository: only their hashes are. Neither package needs a build (both are scripts only).

**What a digest pins, and what is not pinned.** A digest pins the image's bytes, not what they were built from: each image's base layers and packages are unverified here. Not pinned at all: the hosted runner's image (`ubuntu-24.04`, as GitHub updates it), its Docker, and its system `python3`, which runs `dnp3_cases.py`, `prp.py`, `prp_check.py`, `compare.py` and `table.py`. Each run's versions are what `versions.txt` records.

**A sensor may not fetch at run time.** The experiment fetches ICSNPP from GitHub and the images from Docker Hub, checked against these pins. A sensor may not: AP-31 (1) and `docs/release.md` §4 require the engine and its packages at a pinned version, carried in the sensor's image or package, never fetched at run time. Whether AP-31, which is proposed and was written for the node, covers the sensor host is D3's question under P4-4-L1.

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

**The four extra captures are not SEL traffic** (D2 on #625). They show only whether an analyzer fires on SNMPv3, Telnet, FTP and HTTP. Missing, and not shown by this run: the SEL login dialogue, SEL ASCII and the Fast protocols inside Telnet; `CFG.TXT` and `SER.TXT` over FTP; FTP's active data on port 20 over IPv4 (`FTPv6-1.cap` is IPv6); and SNMPv3 `authPriv` without DES, as the SEL-2731 requires.

**What D4 expects, before the run.** Group 120 per message can come only from a script on `dnp3_object_header`, not from stock logs or ICSNPP, if Zeek's parser accepts the filler bodies of GT-PCAP's group 120 objects (D6's note: a refused filler body is neither a pass nor evidence about real SA traffic). DNP3 on a moved port and over UDP may be found by the content signatures. Modbus on a moved port is not expected without a configured port. The run decides each of these. **These are expectations read from source, at the files and commits above. They stay in this section and never appear in a results table.**

## 4. What it cannot pin or check, and why

- **No upstream signature for either image.** Neither `zeek/zeek` nor `jasonish/suricata` carries a signature in the registry. Zeek signs only its source tarball. Building Zeek from the signed source would replace the image pin with a signature check, at the cost of a long build in each run. D4 did not do it here. For the sensor's own image it is D7's question.
- **The Suricata image is a personal account's.** No image under an OISF organisation account was found (`oisf/suricata` does not exist on Docker Hub). Ubuntu's signed `suricata` package, which E-D4-02 used, needs `apt-get`. So the comparison rests on a first-use digest from a personal account.
- **ICSNPP has no signed release.** The pin is a commit and the hash of each file loaded.
- **tshark's version is checked, not its hash,** because `apt` resolves it. `apt` checks the archive's signature.
- **Offline decoding of files is not live capture** on a SPAN or TAP port, and a hosted runner is not the sensor host. Both stay `unknown` (brief, risk).
- **No Modbus capture on a moved port exists yet** (D6's note, section 3), so that row is `unknown` until D6 adds the derived case (section 1).
- **`table.py`, `run.sh` and `in-container.sh` are parse-checked only.** Nothing here has been run, on the runner or on the owner's PC (no test and no install on the PC). They run for the first time at dispatch. If one fails there for its own reason, that is a defect in the experiment and is fixed in a commit, not re-run.

## 5. Results

None yet. The counted run's URL, the tables and the versions go here, each `CI-Linux`.

## 6. What waits

1. **D6's two cases and pass conditions on `main`** (#623, P4-4-R1 deliverable 0). The counted run needs both. Until then, the run counts 19 captures and its verdict column reads `pending D6's pass conditions`.
2. **The workflow on `main`.** GitHub finds a `workflow_dispatch` workflow only on the default branch, so `gh workflow run d4-engine-linux-eval.yml --ref agent/telemetry-engine-linux-eval` cannot start it before this PR's workflow file is on `main`. It has no `pull_request` or `push` trigger, by the brief. D1's order (on #625): this PR merges first, on its reviews and green checks; then #623; then D1 dispatches the counted run, or tells D4 to.
3. **The hosted runners.** From 13:53Z on 2026-11-11, `apt-get` on the hosted Linux runners could not resolve Ubuntu's package archive (D4-84, D4-85). The `dnp3-public` job installs no package: Docker and Python come with the image, and the engines come as pinned images, so that fault does not reach it. The `prp` job installs tshark with `apt-get`, for the labeller `prp_check.py` pins, so it fails in set-up while the fault lasts. A set-up failure is D1's to re-run (D4-85).

## 7. D1's rulings on D4's four questions (on #625, 2026-11-11)

1. **The first dispatch:** #625 merges first, then #623, then the counted run. A dispatch before #623 is on `main` is a rehearsal (status line, section 6).
2. **The probe configuration:** a configuration of its own, labelled in every table. It counts for the engine decision and is not "the engine's own log files". D6 may tighten this (section 1).
3. **Modbus on a moved port:** `unknown` is not good enough if a case can be made honestly. D1 has asked D6 for a derived case, and the table takes it (section 1). Without it, D1 reads the row as not shown.
4. **The Suricata image:** acceptable for this comparison only, never in a sensor, and `apt-get` stays out of the `dnp3-public` job (section 2).

## 8. Carried to ADR-0009 after #618 merges

ADR-0009 is changed by #618, which is not merged, so this branch does not touch it (brief, by D1's message). After #618 merges and `main` is merged in, D4 applies, with the run's evidence:

- D3's note on #618: the sensor "must never affect collection", with the test owed (P4-4-L3 item 8);
- D7's notes on #618: AP-31 is proposed and was written for the node; GPLv2's source offer is valid for at least three years;
- the engine's evidence from section 5, and D4's recommendation. The ADR's engine line changes only on D1's approval.

## 9. Files

- `modules/telemetry/experiments/engine-linux/`: `run.sh`, `in-container.sh`, `table.py`, `probe.zeek`, `pins.env`, `icsnpp.sha256`, `extra-captures.tsv`
- `modules/telemetry/experiments/prp-engines/compare.py`: an optional list of configurations
- `modules/telemetry/experiments/README.md`: one row
- `.github/workflows/d4-engine-linux-eval.yml` (new, dispatch-only)

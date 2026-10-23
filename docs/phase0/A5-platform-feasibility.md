# A5 Phase 0 findings: runtime shape, toolchain, persistence, site-to-central

- Task: P0-A5 (A1 brief, 2026-10-23). Answers Q6.
- Author: A5. Reviewers per CLAUDE.md 5.6: A6 (reliability), A3 (trust boundaries).
- Status: **proposal.** Nothing here is a decision or a contract. A1 turns sections 2, 3, 5, and 6 into ADRs; outbox semantics become a Phase 1 contract after A4 and A6 review.
- Evidence labels used below: **[E-A5-n]** an experiment in `platform/experiments/phase0/` (all `simulated`: container, local files, loopback); **[doc]** published documentation or module metadata, not exercised; **[inferred]** reasoning, no direct evidence; **[A3]**, **[A6]** positions from those agents' Phase 0 work; **[open]** needs an owner answer.

## 1. Summary

1. **Runtime shape:** one Go codebase built into one binary that runs as `site`, `central`, or `all-in-one`. Modules are packages behind interfaces, enabled per node by configuration. Out-of-process only where isolation earns it: Zeek or Suricata (already separate programs), and a privilege-separated collector process that alone holds IED credentials (A3 to confirm). No broker, no orchestration platform.
2. **Q6:** yes, if the site node is always the only thing that collects and talks to IEDs, and central is always a consumer of data that sites replicate to it over a site-initiated connection. Single-server is then the two roles in one process.
3. **Toolchain:** Go (pinned toolchain), `go test` with native fuzzing for parsers, `go vet` + `staticcheck` + `govulncheck`, `CGO_ENABLED=0` static builds. Python 3.13 allowed for verification tooling and offline fixture work, never in the shipped runtime.
4. **UI stack:** server-rendered HTML from the same binary (Go `html/template`), assets embedded, no Node build chain and no CDN, vanilla JS only for progressive enhancement, strict CSP.
5. **Persistence:** SQLite in WAL mode, one writer per database, `synchronous=FULL` for native evidence and audit, bounded WAL, incremental auto-vacuum, an emergency reserve file, separate quotas per stream class, incremental pruning, and recovery from exhaustion as a startup step. PostgreSQL deferred until central scale demands it.
6. **Delivery semantics:** commit locally before any acknowledgement or cursor move; per-stream sequence numbers; at-least-once to central with idempotent upsert by `(node_id, stream, seq)`; plain RFC 5425 syslog cannot confirm delivery, so it gets a replay window and an event id for downstream dedup, and an acked transport (RELP or equivalent) is evaluated in Phase 1.
7. **Site-to-central:** site-initiated HTTPS with mutual TLS 1.3; central's instruction surface is a short allowlist of signed, typed messages, with no exec channel and no path to IED credentials.

## 2. Runtime shape (R7, R8)

### Options

| Option | What it is | For | Against |
| --- | --- | --- | --- |
| A. Modular monolith plus edge role | One codebase, one binary; modules as packages with interfaces; the same binary runs as site node, central, or both | One artifact to sign, test, upgrade, and roll back; one tested combination of module versions; fewest network surfaces at a substation; works offline with no infrastructure | Modules cannot be deployed at different versions on one node; a crash in one module takes the process down unless isolated |
| B. Service per module | Each module a separate service, joined by a broker or RPC | Independent deploy and scaling per module | Every service is another listener, credential, and upgrade path at the site (Q7); needs a broker and service discovery at every substation; many more partial-failure modes; no evidence of a scaling need that justifies it (P8) |
| C. Hybrid | A, plus selected components out of process | Fault and privilege isolation exactly where needed | Some local IPC to secure and test |

### Recommendation: A, with the narrow hybrid in C

- Single binary, roles by configuration. Modules are Go packages exposing interfaces defined in `contracts/`. A module is enabled or disabled per node in configuration; a disabled module's code is present but never started (R7.1 enable/disable).
- Modules integrate through durable streams in the node's local store, not in-memory channels, for anything that must survive a crash (collector writes, forwarder reads). The store is the inter-module boundary for telemetry; typed interfaces are the boundary for synchronous calls.
- Out of process, supervised by the node:
  - Zeek or Suricata, if A4 selects them. They are separate programs anyway; the node consumes their logs (EVE JSON, Zeek logs) as a stream. [doc]
  - The IED collector, as a separate OS user and process that alone can read device credentials and alone has a route to the IED network. The monitoring UI and API process then has no credential access and no IED route even if compromised. This is defense in depth for A3's concern that read-only enforcement in the adapter is "one bug away from a write". [inferred; A3 to accept or reject]
- No message broker, no container orchestrator. systemd supervises processes on the node (section 7).

**Deviation to flag for A1:** R7.1 says modules are independently "upgraded". Under A they are independently developed, tested, enabled, and disabled, but shipped together in one versioned artifact. I recommend accepting this: an OT site running an untested mix of module versions is a reliability and verification risk, and A6 can only verify combinations that ship. If A1 reads R7.1 literally, option B or plugin loading is required and the cost above applies.

### Deployment modes from one foundation (answers Q6)

| Mode | Site role | Central role | Notes |
| --- | --- | --- | --- |
| R8.1 single server | in the same process | in the same process | The replication link is an in-process call over the same contract, so the R8.2 code path is exercised in R8.1 tests |
| R8.2 central plus collectors | collection, local store, forwarding; local UI off | aggregation, UI, policy | Collector keeps a local store sized for WAN outages |
| R8.3 distributed site-local | collection, local store, forwarding, local UI and API on the site management interface | optional aggregation | Site keeps operating with central gone (R8.4) |

Invariants that make Q6 "yes" [inferred, consistent with A3's draft]:

1. Only a site node connects to IEDs. Central never does, in any mode.
2. Sites are the system of record for what they collected. Central holds replicas.
3. Every connection between site and central is opened by the site.
4. Losing central never stops local collection, local storage, or upstream syslog forwarding configured at the site.

What could make the answer "no": if the owner requires central to reach IEDs directly (for example engineering access brokered from central), the site-initiated invariant breaks. That belongs to A3's Q1 work.

## 3. Toolchain (language, build, test, lint)

### Criteria from the brief

Deployability on site hardware (x86-64 and ARM industrial PCs, possibly Windows [open]); SSH, Telnet, and serial client libraries with prompt and pagination handling (R5.5); parser testability with hostile input (R5.6, A6 C-08); memory safety; TLS, X.509, and crypto in a maintained standard library (R8.5); small supply chain; readability for a team that rotates (P9).

### Comparison

| | Go | Rust | Python | Java/JVM | TypeScript/Node |
| --- | --- | --- | --- | --- | --- |
| Memory safe | yes (GC) | yes | yes | yes | yes |
| Ship artifact | one static binary; linux amd64/arm64/arm and windows built with no C toolchain, about 7 MiB each [E-A5-5] | one static binary; cross builds usually need a C linker per target [inferred] | interpreter plus packages; native wheels per platform | JVM plus jars, larger footprint | Node runtime plus `node_modules` |
| TLS / X.509 | standard library | rustls (third party, mature) [doc] | OpenSSL bindings | JSSE | OpenSSL bindings |
| SSH client | `golang.org/x/crypto/ssh`, maintained by the Go project, v0.58.0 of 2026-10-09 [doc: module proxy] | `russh` (third party) [doc] | `asyncssh`, `paramiko` (mature) [doc] | Apache MINA SSHD, JSch [doc] | `ssh2` [doc] |
| Prompt and pagination handling | `scrapligo` v1.4.3 of 2026-10-21, a port of scrapli with SSH and Telnet transports [doc, not exercised] | little | `scrapli`, `pexpect` (strongest ecosystem) [doc] | `expect4j` [doc] | little |
| Telnet | no mature standalone library; `scrapligo` transport or a small RFC 854 client | none mature | `telnetlib` was removed from the standard library in 3.13 (PEP 594); `telnetlib3` third party [doc] | Apache Commons Net [doc] | small libraries |
| Serial | `go.bug.st/serial` v1.8.0 [doc] | `serialport` [doc] | `pyserial` (mature) [doc] | jSerialComm [doc] | `serialport` |
| Parser fuzzing | built into `go test -fuzz` | `cargo-fuzz` | `hypothesis`, `atheris` | jazzer | limited |
| Embedded SQL store | `modernc.org/sqlite`, pure Go, no cgo [E-A5-5] | `rusqlite` (bundles C) | `sqlite3` stdlib | JDBC SQLite (native) | `better-sqlite3` (native) |
| Team supportability | simple language, one formatter, one build tool | steep learning curve, slow builds | easiest to write; runtime type errors; packaging and dependency drift on long-lived sites | verbose; heavy | very large dependency trees |

### Recommendation: Go

- Go 1.26 or later, pinned in `go.mod` (`go` and `toolchain` directives) so every agent and CI builds with the same compiler. The current `modernc.org/sqlite` release (v1.61.0) requires Go 1.26; the container's Go 1.24.7 fetched 1.26.0 automatically through `GOTOOLCHAIN=auto`, checksum-verified by the Go module system [E-A5-5]. Release builds should use a pre-installed pinned toolchain, not an automatic download.
- Build: `CGO_ENABLED=0 go build -trimpath`. Static binaries for linux/amd64 and linux/arm64 at minimum; windows/amd64 only if the owner confirms Windows site hosts [open].
- Test: `go test ./...` with `-race` in CI. Parsers get golden-file tests from fixtures plus `go test -fuzz` targets, because device output is untrusted input (A6 C-08).
- Lint and supply chain: `gofmt` (enforced), `go vet`, `staticcheck`, `govulncheck`. Dependencies vendored or verified through `go.sum`; each new third-party module needs a line in the ADR or a later one saying why.
- Python 3.13 is acceptable for verification tooling (A6's asyncssh oracle, B-06) and offline fixture sanitization, which supports A6's independence argument. It is not part of the shipped runtime.

A2 found no hard requirement for Python or C [A2, section 12 of `docs/phase0/A2-device-feasibility.md`]. The primary family's SEL ASCII protocol is a plain line protocol over Telnet or serial with prompt detection and simple checksums, so it needs a Telnet client and a serial port, not a vendor library. For the IEC 61850 contrast family a pure-Go MMS client exists (`github.com/otfabric/go-iec61850` v1.0.2, MIT); it also exposes control and file-delete services, so it may only be used behind a read-only facade that does not compile those calls into the collector. [A2; doc]

Why not Python, given it has the best prompt-handling ecosystem: the runtime ships to sites that stay in service for years with intermittent WAN, and an interpreter plus a native-wheel dependency tree is the hardest thing on this list to upgrade, roll back, and verify as one artifact (R8.7). `scrapligo` narrows the library gap. If A2 finds a device collection path that only a Python or C library can do, the hybrid shape allows that one adapter to run as a separate process behind the same adapter contract; it does not need to decide the whole runtime.

Why not Rust: it would be a defensible choice for memory safety without GC, but the brief's targets (event rates of a substation, not packet-rate processing, which Zeek or Suricata do) do not need it, and its learning curve costs P9.

Risks of the choice:

- `modernc.org/sqlite` is SQLite's C source machine-translated to Go. It is widely used, but it is a large dependency that tracks upstream SQLite with some lag. The alternative `mattn/go-sqlite3` needs cgo and loses toolchain-free static cross builds. [doc; inferred]
- Old relay SSH stacks may offer only legacy algorithms (for example `ssh-rsa` host keys or SHA-1 key exchange) that `x/crypto/ssh` leaves disabled by default. Enabling one must be an explicit per-device setting that marks the downstream link insecure (R2.3). [inferred; A2 to confirm against device documentation]

### UI stack (delegated to A5 by `PRODUCT.md`)

Recommendation: **server-rendered HTML from the platform binary.** Go `html/template` (contextual auto-escaping), static assets embedded with `embed`, no CDN, vanilla JavaScript only where a page cannot work without it, and a strict Content-Security-Policy with no inline script.

| Option offered | Verdict | Reason |
| --- | --- | --- |
| Plain static HTML/CSS/JS | chosen, served by the binary | Brief limits the UI to verifying workflows; no build chain; works on an offline site; every page is served by code A3 already reviews |
| React with Vite | not now | Adds a Node toolchain and hundreds of transitive npm packages to a security product's release path, for a UI that does not yet need client-side state |
| SvelteKit | not now | Same supply-chain cost, plus a Node server runtime at the site unless statically adapted |

Revisit when a workflow genuinely needs rich client state (for example live session views for engineering access). The first real surface still goes through the `impeccable` new-work flow in Phase 2, which writes `DESIGN.md`. `PRODUCT.md` "Stack" needs updating through `/impeccable init` once A1 accepts the ADR; I have not edited it.

## 4. Experiments and what they show

All `simulated`. Raw output is committed in `platform/experiments/phase0/results/`. Reproduce with `sh platform/experiments/phase0/run.sh`.

**E-A5-1, crash durability.** A writer commits events in SQLite WAL mode and prints each committed sequence (the acknowledgement). A harness SIGKILLs it at a random time between 50 ms and 2 s, reopens the database, and checks integrity, that every acknowledged event is present, and that sequences have no gaps. 100 kills in each of four modes (`NORMAL`/`FULL`, 1 or 100 events per transaction): 400 runs, 0 failures. Committed-but-unacknowledged events never exceeded one transaction, which is the expected at-least-once window. Only the two `FULL` modes are durability evidence. A6 traced the writer with strace (A6 E-02, R-A5-1): at `NORMAL`, 1,011 of 1,016 acknowledgements had no fsync since the previous one, with up to 454 acknowledgements between syncs; at `FULL`, 0 of 680. The `NORMAL` runs pass only because the OS page cache survives SIGKILL, so they must not be cited for R8.7. The `FULL` runs are evidence for the R8.7 crash target and V-S6's device-to-store leg, for process crash only. **None of this says anything about power loss** (A6 hardware test H-11).

**E-A5-2, throughput.** On this container's disk: per-event commit at `FULL` about 4,200 events/s, `NORMAL` about 22,000; batches of 100 at `FULL` about 83,000. Absolute numbers are disk-specific; the point is that `FULL` with small batches leaves wide headroom for SER-scale rates, so there is no reason to accept the weaker mode for evidence. [E-A5-2; substation event rates are inferred, A2 and A4 to supply real ones]

**E-A5-3, storage limits.** Four findings, each changing the design:

1. In every case, at quota or at a genuinely full filesystem, SQLite refused the write with `SQLITE_FULL`, lost no acknowledged event, and passed `integrity_check`. Failure is safe and observable.
2. With default WAL settings on a full 4 MiB filesystem, the store **wedged**: after freeing a 512 KiB reserve, the prune succeeded but the checkpoint could not run, and the store accepted zero further events. Nearly all data sat in a 3.6 MiB WAL that needs the same space again to checkpoint. `PRAGMA max_page_count` does not bound the WAL either (WAL reached 4 MiB under a 1 MiB quota).
3. With a bounded WAL (`wal_autocheckpoint=64`, `journal_size_limit=256 KiB`) the same filesystem held 3.8 times as many events (8,320 vs 2,190). Recovery then worked only with **both** a reserve and incremental pruning: a single large DELETE consumed the freed reserve and failed, while 50-event transactions with a checkpoint between each pruned 4,160 events and the store accepted 5,440 more.
4. **Recovery must run at startup, and freed space must go back to the filesystem.** A6 showed (E-03, R-A5-2) that a writer killed at `SQLITE_FULL` leaves a store that reopens and reads fine but cannot delete anything while the disk is still full. Case 3 now runs the recovery as a startup step: a writer process dies at `SQLITE_FULL`, and a fresh start releases the reserve, prunes in 50-event transactions, checkpoints, and re-creates the reserve; this repeats for three exhaustions. With `auto_vacuum=NONE` (SQLite's default) every step succeeded, but the store took back only 100 events after each recovery, against 4,160 and 2,130 pruned: pages freed inside the database cannot hold WAL frames, and the filesystem stayed at 236 KiB free. With `auto_vacuum=INCREMENTAL` and `incremental_vacuum` run 32 pages at a time with a checkpoint between steps (a single `incremental_vacuum` call itself failed with `SQLITE_FULL`), each recovery returned about 1.9 MiB to the filesystem and the next run wrote 4,090 events, three times in a row. A6 also measured about 9 KB of WAL per event at default settings (A6 E-03), one more reason never to ship them.

**E-A5-4, syslog forwarding.** Plain TCP syslog with RFC 6587 octet counting, collector process SIGKILLed mid-stream; an event counts as "sent" when the socket write returned no error, which is all an RFC 5425 sender can know. Lost with no error, over 10 runs per scenario: paced at 1 event/ms, exactly 1 per run; burst to a fast collector, 62 to 12,891; burst to a collector that spends 1 ms per event, 40,267 to 41,901, nearly everything the socket buffers held. Every one of the 30 runs lost events. With an application-level acknowledgement after the collector records each event (RELP-like), 20,000 events across three collector kills plus one crash between recording and acking: 0 missing, 1 duplicate (the event recorded but never acked). A6's independent E-01 over TLS reached the same conclusion (100 of 150 frames lost without a write error). [E-A5-4; A6 E-01]

**E-A5-5, cross-build.** The experiment binary, including the SQLite driver, builds with `CGO_ENABLED=0` as a statically linked executable for linux/amd64, linux/arm64, linux/arm, and windows/amd64, about 7 MiB each, with 26 modules in the dependency graph (`go list -m all`).

## 5. Persistence and store-and-forward (draft semantics for the Phase 1 contract)

### Store choice

| Option | Verdict |
| --- | --- |
| SQLite, WAL mode | **recommended** for site nodes, all-in-one, and central in slice 1. One file per node, no administrator, crash-safe [E-A5-1], fails safe when full [E-A5-3] |
| PostgreSQL | deferred. Reasonable for a large central later; a database server at every substation is unjustified administration and attack surface (P8). Module-owned repository interfaces keep the switch possible for central only |
| Embedded key-value (bbolt, Badger) | rejected; we would rebuild indexing and querying ourselves |
| Custom append-only segment log | rejected; we would own crash recovery, which E-A5-1 shows SQLite already gets right |
| Broker (NATS JetStream, Kafka, MQTT) | rejected for slice 1; adds a service to every site, and MQTT QoS does not give end-to-end durability from device to central anyway [inferred] |

### Store layout

- One database per data-owning module (for example `telemetry.db`, `audit.db`, `platform.db`), each with exactly one writer. This is persistent data ownership in practice: no module writes another module's database (R7.1). Raw evidence lives in the row as a byte-exact BLOB for SER and Syslog sizes; large artifacts such as PCAPs go to files named by SHA-256 with the hash in the row. [inferred]
- `journal_mode=WAL`; `synchronous=FULL` for every stream whose acknowledgement moves a device cursor or confirms delivery, which is native evidence and audit at minimum (`NORMAL` acknowledges before fsync [A6 E-02]); bounded WAL (`wal_autocheckpoint`, `journal_size_limit`); `auto_vacuum=INCREMENTAL` set at database creation; `quick_check` at start and a scheduled `integrity_check`.
- Startup sequence: if the store is at its quota or the filesystem is short of the reserve size, release the reserve, prune confirmed events in small transactions, run `incremental_vacuum` in small steps with a checkpoint between, re-create the reserve, and only then start collectors. If the reserve cannot be re-created, collectors do not start and the node raises an alarm [E-A5-3 case 3, A6 R-A5-2]. Two further rules from A6's E-04 (Python re-implementation, five exhaustions, SIGKILL with the connection held): (1) the prune boundary must come from durable state, the consumer cursors plus retention, never from "half of what is there" as the experiment does; A6 killed a recovery after its prune committed and the rerun pruned another half, losing 75% of the store (R-A5-5). A repeated recovery must prune nothing new, and Phase 2 must kill recovery at each step. (2) Startup refuses a store whose `auto_vacuum` is not `INCREMENTAL`, because the setting can only be applied before the first table exists and such a store cannot be repaired while the disk is full.
- The store lives on a dedicated filesystem (or a fixed-size volume), and its processes run as non-root users: root can consume ext4's reserved blocks, which hides exhaustion from the quota logic [A6].

### Delivery semantics

1. **Commit before acknowledgement.** A collector advances its device-side cursor (for example the last SER record retrieved) only after the local commit returns. The native record is stored byte-exact in the same transaction as its normalized form.
2. **Sequence and idempotency key.** The node assigns each event a monotonic `seq` per stream at commit. The transport idempotency key is `(node_id, stream, seq)`. This is separate from A4's content-level duplicate key, which handles a device re-sending SER history; the two must not be conflated. Each event also carries an `event_id` for downstream systems that cannot see sequences (SIEM dedup over syslog).
3. **Ordering.** Order is guaranteed within a stream by `seq`. There is no global order across streams or nodes; consumers order by device timestamp and its quality, as A4's schema defines.
4. **To central: at-least-once, effectively once at rest.** The site uploads batches by sequence range. Central upserts by the idempotency key and answers with the highest contiguous `seq` it has durably committed. The site advances its confirmed cursor only on that answer and resends from it after any reconnect.
5. **To upstream syslog.** Each forwarding target has a sent cursor and a confirmed cursor. Over RFC 5425 the confirmed cursor can never advance (E-A5-4), so the site keeps a replay window by time and replays it on reconnect, accepting duplicates downstream, deduplicated by `event_id` in structured data. An acknowledged transport such as RELP is a Phase 1 evaluation for A4. Whether "forwarded" can ever mean "confirmed" for an RFC 5425 target is a contract decision for A1 and A4, and it determines what V-S9 can promise.
6. **Required consumers.** Each consumer (central, each forwarding target) carries a `required` flag in node policy. Only required consumers hold back pruning. A consumer that cannot confirm, such as an RFC 5425 target, is never required; it gets a time-bounded replay window instead. Without this rule an RFC 5425 target would make nothing prunable, and the store would fill until SER polling stopped permanently [A6 R-A5-3, carried by A1 under B-03]. Making a consumer required is a policy change and is audited.
7. **Alignment with A4** (`/mnt/project-files/phase0/A4-notes-for-agents.md`, A4's PR #4 schema draft). `event_id` is a UUIDv7 assigned at the first durable write; A4's `stream_seq`, monotonic per (node, stream), is the same number as this section's `seq` and is the outbox position; each destination has its own cursor; delivery is at-least-once and receivers deduplicate by `event_id`. A4's E-A4-03 found that rsyslog `imrelp` with default queues lost about 98% of already-acknowledged messages on a crash, and none with Direct queues and `confirmMessages`; so an acked transport is only as good as the receiver's queue configuration, which becomes part of the contract for any relay we operate. A4 prefers this proposal's acknowledged site-to-central channel over syslog for that hop.
8. **Raw evidence and normalized events are pruned together (A4 EP-6).** A normalized event never outlives its shed raw evidence: any eviction, including a quota-driven one, removes or marks both in the same transaction.

### Storage-full policy

| Stream class | Separate quota | At the alarm threshold | At the quota |
| --- | --- | --- | --- |
| Native SER (polled) | yes | alarm with fill level and time to full at current rate | stop polling and alarm with the time polling stopped and, where A2 documents the device buffer depth, an estimate of when the device starts overwriting [A3] |
| Device syslog over UDP | yes | alarm | drop and count; the counters are persisted, survive restart, and are forwarded so loss is visible centrally [A3] |
| Device syslog over TCP | yes | alarm | stop reading, which pushes back to the device. How each device behaves under that (buffer, drop, block) is unknown and must not risk a device function [open, A2] |
| Audit | yes | alarm | privileged operations fail closed: no audit record, no privileged operation (P5) |
| Platform health | yes, small | alarm | oldest health samples evicted; the eviction is counted |

Separate quotas stop a syslog flood from filling the store and halting SER collection, which would otherwise be a cheap way to blind the platform (ATT&CK for ICS Block Reporting Message class) [A3]. Eviction never removes an event that a required consumer has not confirmed (item 6 above); only confirmed events are pruned, in small transactions, oldest first [E-A5-3, A6 V-S9]. A reserve file of at least twice the WAL bound is kept on the data filesystem and released only for emergency pruning [E-A5-3]. Alarm thresholds of 70, 85, and 95 percent are a starting proposal, not derived from evidence.

### Response to A6's numbers

- R8.7 crash target: I confirm A6's 100 randomized kills as a minimum per durability configuration actually shipped, with the pass condition "zero acknowledged events lost, zero gaps, integrity ok". E-A5-1 meets it for the two `FULL` configurations; the `NORMAL` runs are not evidence [A6 E-02]. Phase 2 must add kills during checkpoint-heavy load, during schema migration, and a power-loss test on real hardware.
- R8.3 72-hour WAN outage: accept as the acceptance floor, and make outage tolerance a per-site sizing parameter. At about 500 bytes per stored event, 72 hours at a sustained 10 events/s is about 1.3 GB, and at 100 events/s about 13 GB. That is small for SER rates; the sizing risk is syslog floods, which the separate quota bounds. How long real WAN outages last at the owner's sites is unknown [open].

## 6. Site-to-central transport and enrollment

Aligned with A3's draft (A3 accepted the anti-rollback, listener-binding, and storage-full points).

### Transport

- The site opens HTTPS with mutual TLS 1.3 to central. Central never opens a connection into a site; the node has no listener reachable from the WAN. The local UI and API (R8.3) binds only to the site management interface, never to the IED-facing interface.
- Upload: idempotent batch posts by sequence range, answered with the confirmed sequence (section 5). Instructions: the site long-polls central for signed messages. HTTP/2 and JSON on the Go standard library, versioned path (`/v1/`).
- Why not gRPC, MQTT, or NATS: HTTPS passes the proxies and firewalls utilities already run, needs no broker, and uses only the standard library. gRPC adds a code-generation toolchain for little gain at these rates. [inferred]
- Version compatibility: central accepts the current and previous protocol major from nodes; a node rejects instructions with an unknown major. [inferred]

### What central may and may not instruct

| Central may | Central may not |
| --- | --- |
| Deliver a signed, versioned policy bundle: enabled modules, collection schedules that reference operation IDs from the approved command register, forwarding targets, retention within bounds the node enforces | Run any command, shell, or free-form request on the node |
| Request replay of a sequence range still in the node's store (reads the local store only, never touches a device) | Request re-collection from a device; that would be a register operation, out of scope for slice 1 |
| Announce an available release signed by the offline release key | Install anything not signed by that key, or lower the anti-rollback floor in the signed release metadata |
| Revoke or rotate the node certificate | Read, receive, or set IED credentials in usable form; central sees credential references only [A3] |
| | Enable a state-changing operation, add an operation absent from the node's local register, disable audit, or set quotas below the node's safety minimum |

The node validates every bundle against its own local register and limits, so a compromised central cannot widen what a node does to an IED [A3]. Central's command surface is a Q7 attack path and stays this narrow by contract.

### Enrollment and certificates

- One-time enrollment token plus out-of-band fingerprint confirmation [A3]. The node generates its key pair locally and the private key never leaves it (TPM-backed where the hardware has one [open]). Central's enrollment CA signs the node's request.
- **Certificate lifetime versus WAN outages.** A short-lived node certificate that expires during an outage locks the site out when the WAN returns. Proposal: lifetime well beyond the longest tolerated outage (for example 90 days), renewal over the existing mTLS session at one third of lifetime, and an expired node re-enrolls with operator approval. Revocation works by central refusing the certificate on the next connect. [inferred; A3 to decide]
- **Clocks.** mTLS validation needs a sane node clock. Substations usually have a good time source, but a node with a wrong clock fails every TLS handshake; that failure must be reported locally, not just as "central unreachable". [inferred]

## 7. Node runtime, upgrades, observability

- **Supervision:** systemd units, one per process, each a dedicated user with `NoNewPrivileges`, `ProtectSystem=strict`, and write access only to its own data directory. Restart with backoff, because a crash loop that reconnects to an IED each time could exhaust the device's session slots; adapters must also close device sessions cleanly on shutdown [inferred; A2 to give session limits].
- **Upgrade and rollback (R8.7):** two binary slots and a symlink switch; schema migrations follow expand-then-contract so the previous binary still reads the database after a rollback; snapshot with `VACUUM INTO` before a migration when space allows; rollback never below the signed anti-rollback floor.
- **Observability (P5):** node health (store fill per quota, cursor lag per stream and target, last successful poll per device, drop counters, certificate expiry, clock offset) is itself a platform stream forwarded like any other, plus a local health endpoint on the management interface. Central raises an alarm when a node's heartbeat stops.
- **Containers:** optional packaging, not required. No orchestration platform (P8).

## 8. R7 and R8 coverage

| Req | How this proposal addresses it | State |
| --- | --- | --- |
| R7.1 | Modules as packages, enabled per node; one database per owning module | Satisfied by design, except independent upgrade (deviation flagged in section 2) |
| R7.2 | Interfaces live in `contracts/`; telemetry modules integrate through stored streams | Partly: inter-module messaging and persistence ownership are proposed here; the rest are other owners' contracts |
| R8.1 | All-in-one role | By design; not built |
| R8.2 | Site and central roles, site-initiated replication | By design; not built |
| R8.3 | Site role with local UI on management interface | By design; not built |
| R8.4 | Site autonomous; outage tolerance as a sizing parameter, 72 h floor | By design; the store behavior is evidenced [E-A5-1, E-A5-3] |
| R8.5 | mTLS, enrollment, certificate lifetime and rotation | Outline only; details with A3 |
| R8.6 | Local store, sequence-based at-least-once, idempotent central upsert | Semantics drafted; crash safety evidenced for process crash [E-A5-1] |
| R8.7 | systemd restarts, crash-safe store, A/B slots, expand-contract migrations | Crash recovery evidenced for process crash; upgrade and rollback deferred to Phase 2 |
| R8.8 | Per-class quotas, reserve, bounded WAL, incremental pruning and vacuum, startup recovery, alarms | Mechanism evidenced across three repeated exhaustions [E-A5-3]; alarm thresholds unproven; ext4 and real disks untested |

## 9. Risks

1. **Upstream syslog delivery cannot be confirmed over RFC 5425** [E-A5-4, A6 E-01]. Without an acked transport, "never silently discard" (R4) holds only up to the socket, and V-S9 cannot promise more. Owner: A4 with A1.
2. **Store wedging when full** [E-A5-3]. Default SQLite settings can leave a full node unable to recover without operator action. The design that fixes this in the experiment has four parts that only work together: a bounded WAL, a reserve, incremental pruning and vacuum, and recovery as a startup step [E-A5-3 cases 2 and 3]. It must become a tested requirement, not a configuration hope; A6's second-exhaustion test belongs in the Phase 2 suite.
3. **Power-loss durability is untested.** Everything here is process-crash evidence. Owner: A6, on real site storage.
4. **TCP syslog backpressure on devices** is unknown and could, in principle, affect a device. Owner: A2.
5. **Restart loops versus IED session limits.** A crashing collector could hold or exhaust IED sessions. A2 has now documented the limits (documented-untested, `docs/phase0/A2-sel-portfolio.md` section 8): per Ethernet port the SEL-751 allows 2 Telnet sessions, the SEL-787-4 2, the SEL-400 series 3, and the SEL-311L 1; a session that is not quit stays held until the relay's `TIDLE` timeout, 15 minutes by default. Two unclean collector restarts can therefore lock everyone, including protection engineers, out of Telnet on a 751 for up to 15 minutes, and a single one does so on a 311L. Proposed node rules for the Phase 1 contract: (a) at most one platform session per device and transport, enforced by the collector process, never by configuration alone; (b) the collector sends the device's quit command on every orderly shutdown and on adapter timeout; (c) after an unclean exit, a refused or failed connect is retried no sooner than the device's configured `TIDLE`, with an alarm, rather than on systemd's normal restart backoff; (d) on devices with a single session (SEL-311L), polling is scheduled and short, and the platform yields to engineering access. Owner: A2 for adapter behaviour, A5 for supervision, A6 to test (two forced restarts must never leave the platform holding more than one session).
6. **Certificate expiry during WAN outages** could lock out a site that did nothing wrong. Owner: A3 with A5.
7. **Single SQLite driver dependency** (`modernc.org/sqlite`) is large and translated code. Mitigated by its wide use and our crash tests; revisit if a defect appears.

## 10. Proposed ADR inputs for A1

- **Runtime shape:** option A with the narrow hybrid; deviation on R7.1 independent upgrade for A1's decision.
- **Toolchain and UI:** Go with the build, test, and lint set in section 3; Python for verification tooling only; server-rendered UI from the binary. Includes the `PRODUCT.md` Stack update.
- **Persistence:** SQLite WAL with the settings, quotas, and pruning rules in section 5, evidence E-A5-1 to E-A5-3.
- **Site-to-central:** section 6, with A3 as co-decider.
- **Phase 1 contract items from this work:** outbox semantics (section 5, with A4); site-to-central message set (section 6, with A3); storage-full policy table (with A3, A4, A6).

## 11. Open questions for the owner

1. What hardware and operating system will site nodes run on? If it is the SEL-3355-2, section 12 covers most of this; the remaining question is which OS you would install.
2. How long do WAN outages at your sites last in practice? (72 h is the current acceptance floor.)
3. Do any sites require central to reach IEDs directly? (The design assumes never.)

## 12. Owner-supplied SEL documentation (added 2026-10-23)

The owner added SEL manuals and data sheets on their device. Everything below is `documented-untested`: read from those PDFs by text extraction, nothing exercised. Sources: SEL-3355-2 data sheet (date code 20260521), SEL-2488 instruction manual (20260918), SEL-311L-0-6 instruction manual (20260129), SEL-751 (20260910) and SEL-451 400-series (20260730) instruction manuals, ACSELERATOR RTAC SEL-5033 programming reference (20260925).

### SEL-3355-2 as a candidate site node

If the owner intends the SEL-3355-2 automation controller as site hardware, it answers most of open question 1:

| Data sheet says | Effect on this proposal |
| --- | --- |
| x86-64 (Intel Xeon E3-1505L or E3-1505M, quad core), 4 to 64 GB DDR4 ECC | linux/amd64 is the primary build target; ample headroom for the runtime |
| Supported OS: Windows 8, 10, 11 IoT LTSC, Windows Server 2012 to 2025; RHEL 6 to 9, AlmaLinux 8 to 10, Ubuntu LTS 16.04 to 26.04, SUSE 15 and 16, CentOS 6 and 7 | Linux recommended (systemd hardening in section 7); keep the windows/amd64 build [E-A5-5] as an option only if the owner runs Windows |
| Infineon SLM 9670AQ TPM 2.0 | The node's enrollment key can be generated in and bound to the TPM (section 6, A3's B-04) |
| Industrial SSD options (SLC 30 to 250 GB, pSLC 120 to 480 GB, 3D TLC 240 to 7680 GB), hot-swap, RAID 0, 1, 5, 10; SEL publishes an application note on SSD lifetimes | The store goes on a dedicated, mirrored (RAID 1) volume. `synchronous=FULL` plus WAL traffic consumes SSD write endurance, so bytes written per event must be measured against the drive's rating in Phase 2 (A6 measured about 9 KB of WAL per event at default settings) |
| Real-time clock drift 200 ppm (about 17 s/day free running); IRIG-B input through an SEL-3390S8 card | The node must be time-synchronized (IRIG-B, or NTP or PTP from a station clock) and alarm when it is not; an unsynchronized node will drift into mTLS failures and wrong receive times (section 6) |
| Alarm contact and watchdog under SEL SysMon; the OS table footnote gives Linux "limited support for system Alarm, Watchdog, and AUX LEDs" | Driving the hardware alarm contact from node health is attractive but unproven on Linux; verify before relying on it |
| Intel AMT v11, accessible through ETH1 | An out-of-band management path below the OS. It must be disabled, or ETH1 kept off every WAN and IED-facing network. Flag for A3 (Q7) |

### Syslog sources in the SEL documentation

- SEL-2488 satellite clock: remote syslog follows RFC 3164 with a UTC offset added to the timestamp, to up to three destinations; "the port number is fixed to the default port for the Syslog Protocol (514) and cannot be changed". The node therefore needs an RFC 3164 listener on port 514, which is a privileged port: grant the listener `CAP_NET_BIND_SERVICE` through systemd rather than running it as root. The transport is not stated beyond the port. A4's survey of the same documents lists the device syslog sources as the SEL-2488, the RTAC, the SEL-5056, and switches in RSTP mode, and requires the listener to accept UDP, TCP, and TLS [A4]; the TCP backpressure question (risk 4) therefore applies to those sources. A4 also found that the RTAC holds 10,000 syslog messages and the SEL-2488 60,000 log entries, so both can be backfilled after an outage over a channel other than syslog.
- SEL-311L: "The SEL-311L does not support Syslog functionality."
- SEL-751 and SEL-451 manuals: the word "syslog" does not occur in the extracted text, while "Sequential Events" occurs over 40 times in each. This is an absence in documentation, not proof; A2 to confirm. If it holds, these relays reach the platform through SER polling only, and risk 4 (TCP syslog backpressure on devices) does not apply to them.
- RTAC (SEL-5033): has a `SyslogCollector` library that receives syslog into the RTAC logic engine. An RTAC can therefore sit between devices and the platform as a syslog source or aggregator; its outbound transport was not checked.

## Handoff P0-A5 — A5 — 2026-10-23

**Completed:** runtime shape comparison and recommendation (section 2, answers Q6); toolchain and UI stack recommendation (section 3); persistence, outbox semantics, and storage-full policy (section 5); site-to-central transport, instruction allowlist, and enrollment outline (section 6); node runtime, upgrade, and observability outline (section 7); five experiments.

**Evidence:** E-A5-1 to E-A5-5 in `platform/experiments/phase0/`, reproducible with `run.sh`, raw output in `results/`. All `simulated` (container, local files, loopback). Library and version claims are `[doc]` from module metadata or published documentation and were not exercised against devices. A6's E-01 independently corroborates E-A5-4.

**Interfaces:** none introduced. Drafts for Phase 1: outbox delivery semantics and idempotency key `(node_id, stream, seq)` (with A4), site-to-central message set and central instruction allowlist (with A3), storage-full policy per stream class (with A3, A4, A6).

**Limitations:** no power-loss test; no real disk, collector, or site hardware; throughput numbers are container-specific; substation event rates are inferred; upgrade and rollback not exercised; Windows support unconfirmed.

**Risks:** section 9. Highest: upstream RFC 5425 delivery cannot be confirmed; default SQLite settings can wedge a full store; power-loss durability untested.

**Dependencies:** A1: ADRs per section 10 and a decision on the R7.1 independent-upgrade deviation. A3: accept or reject the privilege-separated collector process; certificate lifetime versus outages. A4: acked transport evaluation (RELP or equivalent); content-level duplicate key separate from the transport key; whether "forwarded" can mean "confirmed" for RFC 5425 targets. A2: device behavior under TCP syslog backpressure; IED session limits; SER buffer depth for the storage-full alarm. A6: power-loss test on site storage; review of E-A5-1 and E-A5-3 methods. Owner: the three questions in section 11.

**Files changed:** `docs/phase0/A5-platform-feasibility.md`; `platform/experiments/phase0/` (`*.go`, `go.mod`, `go.sum`, `run.sh`, `README.md`, `results/*.txt`).

**Reviewer(s) and outcome:** A6 accepted for Phase 0 (`docs/phase0/A6-cross-review.md`, branch claude/project-thread-u7odvk, commit 827fffc) with R-A5-1 to R-A5-3. All three are addressed in this document and in E-A5-3 case 3: `NORMAL` is withdrawn as durability evidence, recovery is a startup step with a second-exhaustion test, and required consumers have their own rule. A1 independently reproduced E-A5-1, E-A5-3, and E-A5-4. A3 accepted for Phase 0 (`docs/phase0/A3-review-A5.md`, branch claude/project-thread-qj1j9d) with conditions C-A5-1 to C-A5-9 for the Phase 1 contract, chiefly: the out-of-process collector is mandatory and the OS restricts the IED route to the collector's user; the policy signing key is not usable by central's online services alone; forwarding targets come from a site-local allowlist, since central-set targets would be an exfiltration path. A3 reviewed the storage-full policy and site-to-central points in thread and their three additions are incorporated in sections 5 and 6; that is input, not a completed review.

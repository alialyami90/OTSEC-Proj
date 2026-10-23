# A6 cross-review of P0-A2 and P0-A3 (CLAUDE.md 5.6)

Reviewer: A6. Date: 2026-10-23. Reviewed:

- A3: `docs/threat-model.md`, `docs/phase0/A3-security-feasibility.md`, `modules/access/experiments/e1-ssh-forward-controls/` at `f08abf9` on `claude/project-thread-qj1j9d` (PR #1).
- A2: `docs/phase0/A2-device-feasibility.md`, `docs/phase0/A2-command-register-draft.json`, `docs/device-capabilities.md` at the head of `claude/project-thread-8k8qrr` (PR #2) on 2026-10-23.

Method: try to disprove each claim with tests where possible, otherwise by checking it against the cited source or against the other agent's draft. Outcome per item: **holds**, **holds with limits**, **disproved**, or **open**. Nothing here is hardware evidence.

## Outcome summary

| Draft | Outcome | Blocking for Phase 1? |
| --- | --- | --- |
| A3 threat model v0 | Accepted as the Phase 0 threat model with six findings. One claim disproved (L1–L7 are not seven independent layers for the slice). One scoping error (T8 shows termination, not revocation). | No. R-A3-1 and R-A3-3 must be resolved in the Phase 1 read-only enforcement ADR. |
| A3 experiment E1 | Reproduced 3 of 3 runs, 9 of 9 checks. Three extra A6 probes pass 3 of 3. | No. |
| A2 register draft | Accepted for Phase 0. The four allowed lines (`ACC`, `QUI`, `ID`, `SER`) are exact and pass A6's 61-line deny corpus with zero read-only classifications. | No, but Phase 2 cannot start without B-07 (manual text). |
| A2 feasibility findings | Accepted with four findings. SSH-not-native and Level-1-is-not-read-only are significant and change A6 criteria (V-S7, V-S13, V-S14). | No. |

## A3 findings

### R-A3-1 — L1–L7 are not seven independent layers for the slice (disproved as stated)

Claim (A3 §4.3, AP-5): read-only is enforced by seven independent layers. Tested against the slice's real path, a CLI write sent over the approved collection session:

- **L2, L3, L4, and the L7 test oracle all derive from the same register.** A too-broad allowed pattern (for example a future `SER( .*)?` to admit row ranges) passes all four at once. They are independent against adapter bugs, not against register errors.
- **L5 does not hold for the primary family.** A2 reports that SEL Level 1, the level needed for `SER`, also permits `TRI` (creates an event report), elevation attempts (`2AC`, `BAC`), and on SEL-400 series transparent port connections. The device cannot enforce read-only for us (this was HR-2 as a risk; A2's evidence makes it a fact at `documented-untested`).
- **L6 adds nothing against this path.** A write over the same Telnet session uses the same port as the read.
- **L7 in deployment (IDS) is protocol-dependent.** Over Telnet it can see command lines; over SSH (if a gateway is used) it cannot (A6 C-03).
- **L1** stops humans, not the collector identity, which is the only identity that does device I/O in slice 1.

Effective independent prevention for the slice: L1 for humans, and L3 and L4 against adapter bugs, which are common-mode with the register. Against register errors the only checks not derived from the register are A2/A6 review and A6's independent corpus ([tests/safety/register_review/](../../tests/safety/register_review/)). **Requested change:** restate AP-5 and §4.3 with this common-mode analysis. Make "A6 deny corpus passes" a gate for every register change, and require L4 to be a separate component that checks the final bytes written to the socket, after encoding, line terminator, and Telnet escaping. A check on the command string before those steps does not see what the device receives.

### R-A3-2 — E1 T8 shows termination, not revocation (scope error)

E1 T8 reports "new use fails" after killing the session process. A6 probe T9 shows why: the held connection was closed, but the same key immediately re-established a working tunnel (`REPLY OK DATA`, 3 of 3 runs). The "new use fails" in T8 is the user's local `ssh -L` listener dying, not the gateway refusing. Revocation requires removing the authorization (key, certificate, or grant) and then killing the sessions; E1 shows only the second half. **Requested change:** reword AP-6 and the Q1 table's revocation row; A6 will require R2.5 tests to show re-authentication denied after revocation, not only session teardown.

Other E1 checks hold: A6 T10 (`ssh -W` stdio forward to an unapproved device: refused, 0 connections at that device) and T11 (sftp subsystem: refused) pass 3 of 3. Evidence: [tests/security/reviews/A3-E1/](../../tests/security/reviews/A3-E1/) (patch and three result files; `simulated`, OpenSSH 9.6p1 loopback).

### R-A3-3 — Credential injection "below the recorder" does not fit in-band authentication

AP-2 and §4.2 assume the secret is resolved by the transport at connect time, below the transcript recorder and the egress check. On SEL relays the password is an in-band line: `ACC`, then a `Password:` prompt, then the secret as the next line of the same session (A2 §10 and §11). The egress check must therefore pass one line that is not in the register. That exception is a bypass path:

- If the device does not show `Password:` (for example passwords disabled on the relay, which A6 recalls is possible by jumper on some SEL models; unverified), the secret line is executed as a command.
- Whatever the credential store holds is sent unchecked in that slot. An administrator, or anyone who can write the credential store, can place a command there.

**Requested change:** the egress check permits the credential slot only when the documented password prompt has just been received, and never otherwise. The credential value is validated at write time: printable ASCII, bounded length, and not matching any register or deny-corpus entry. The recording simulator now records this exchange as an auth event and flags any line or password sent before the prompt (`before-prompt` verdict).

### R-A3-4 — Forwarding "accepts nothing back" conflicts with acknowledged delivery

TB5 and AP-9 say the forwarder accepts nothing from the collector beyond the TLS handshake. A6 E-01 shows delivery needs an application-level acknowledgement (B-03). An acknowledging transport such as RELP means parsing responses from a less-trusted collector. **Requested change:** A3 and A4 agree on one of two options. Either accept a minimal, strictly parsed acknowledgement channel, with AP-9's test changed to "anything other than a well-formed ack is ignored and alarmed". Or keep TB5 one-way and accept a documented unconfirmed window. A1 decides; this is an input to B-03.

### R-A3-5 — AP-17 detection window equals the WAN outage

AP-17 claims central detects an edited or deleted audit record "within one sync interval". A root attacker on a node can rewrite every record not yet forwarded, including the hash chain, and central cannot tell. With R8.3's 72 h *(proposed)* outage, the undetectable window is 72 h. **Requested change:** state the window, and consider a local anchor the node's root cannot rewrite (TPM monotonic counter or write-once media) or periodic anchoring to a site-local second device.

### R-A3-6 — Standards and ATT&CK citations

Spot-checked the ATT&CK for ICS IDs against attack.mitre.org on 2026-10-23: T1694.001/.002, T1692.001/.002, T1691.002, T0859, T0886, T0866, T0832, T0811, T0882 match A3's table. The IEC 62443-3-3 SR titles used match A6's recollection of the SR list; A6 has not read the normative text either. **Holds.**

### A3 items that hold

The Q7 answer (yes, the platform is an attack path by construction) and the 20-path table are sound. Each row has a falsifiable test, and the tests map onto V-S5, V-S7, V-S11, V-S14, and V-S15 without conflict. The slice rule that no human role can trigger device I/O (AP-15) removes the hardest privilege-separation case and is endorsed. The T0 precondition pattern is adopted: every A6 denial test includes a positive control showing the path works when it should.

## A2 findings

### R-A2-1 — Register: allowed set is tight; deny entries are labels only

A6 ran the draft register through `check.py` with an independent corpus of 60 lines (case, whitespace, abbreviation, argument, separator, binary-prefix, and escape variants; [tests/safety/register_review/sel-deny-corpus.txt](../../tests/safety/register_review/sel-deny-corpus.txt)). Zero deny-corpus lines classify read-only, and all four allow-corpus lines do. Evidence: [tests/safety/register_review/results/A2-draft-2026-10-23.txt](../../tests/safety/register_review/results/A2-draft-2026-10-23.txt) (`desk`). Because classification is deny-by-default, the safety of the register rests entirely on the four allowed patterns. The deny entries only improve violation labels. **Holds.** Every future widening of an allowed pattern (for example `SER` row ranges) must pass the corpus.

### R-A2-2 — `ACC` is classified read-only but has device side effects

`ACC` changes session state and starts a password exchange whose failures close the ALARM contact after three attempts (A2 D2, SEL-300G). Its classification is defensible, but V-S13 must bound it. A6 criterion: at most one failed in-band authentication per session, and no further `ACC` after a failure. **Requested change:** add a `side_effects` field to register entries so that this kind of constraint is machine-checkable.

### R-A2-3 — SER duplicate key will merge legitimate repeats

A2 §7 says row numbers are positional and identical rows (same element, state, and millisecond) are possible, while proposing a duplicate key of device, timestamp, element, and state. With `SER` returning the whole buffer on every poll, a per-row key cannot tell "same row seen again" from "a new identical row". It will silently drop the second, which violates R4.4. **Requested change (A4 with A2):** de-duplicate by aligning consecutive buffer snapshots, matching the longest overlapping suffix and prefix of ordered rows, instead of by a per-row key. Treat an ambiguous alignment as a gap event. A6 adds this case to V-S4 (C-13).

### R-A2-4 — Transport is Telnet: V-S14 does not apply, and credentials cross the LAN in clear

With no documented SSH on SEL relays, the slice transport is Telnet. Device identity cannot be authenticated (V-S14 is not applicable to this family), and the shared Level 1 password is visible to anyone on the station LAN (A3 AP-12, HR-1). A6 updates V-S14 to apply only to transports with server authentication. For Telnet families, the residual risk is recorded per device and identity drift is detectable only from `ID` output, which is spoofable. On the positive side, V-S7 gains a fourth independent source: a lab packet capture can read the command lines.

### Simulator and checker changes made in response

A2's and A1's review of A6's tooling was correct on both points. `check.py` now flags any byte outside 0x20–0x7E itself, without relying on the register or on latin-1 decoding. The simulator has a raw TCP transport with Telnet option refusal and IAC removal, CR NUL line endings, and in-band authentication recorded as an auth event with the secret never stored. It also has a `before-prompt` check for lines sent before the device answered. Self-test: 13 of 13 pass, 3 runs ([results](../../tests/safety/recording_simulator/results/selftest-2026-10-23.txt)).

### Blocker raised from this review

**B-07:** the SEL manual bodies (command tables, example outputs) cannot be read from this environment. The network policy denies `selinc.com` (A6 confirmed: proxy `CONNECT` 403), and A2 could read only front matter from mirrors. The documented-behaviour layer of the simulator, the `documented-example` fixtures, and every register entry still marked "located, not read" are blocked until the owner uploads the SEL-751 instruction manual (and the SEL-300G and SEL-421 sections A2 cites) or allows `selinc.com` in the environment's network policy.

## A5 findings (PR #3, `claude/project-thread-xni3ff` at `26c08cb`, and `A5-platform-feasibility.md`)

Requested by A1 with focus on the methods of E-A5-1 and E-A5-3. A6 built A5's experiment binary from `26c08cb` and ran two independent experiments against it and against the same SQLite engine. Overall outcome: **accepted for Phase 0.** The persistence recommendation holds and A6 evidence supports `synchronous=FULL`, but three claims need narrower wording and one contract contradiction must be settled.

### R-A5-1 — E-A5-1 cannot distinguish `NORMAL` from `FULL`; E-02 can (holds with limits)

E-A5-1 reports 0 failures in all four modes. SIGKILL leaves the page cache intact, so a commit that never reached the disk still survives. A5 states this limit. A6 experiment E-02 checks the precondition for power-loss safety directly by running A5's own writer under strace ([script](../../tests/integration/experiments/fsync_before_ack.py), [results](../../tests/integration/experiments/results/E-02-2026-10-23.json)):

- At `NORMAL`, 1,011 of 1,016 acknowledgements had no fsync since the previous one, with up to 454 acknowledgements between syncs.
- At `FULL`, every acknowledgement (0 of 680 unsynced) followed an fsync.

So `NORMAL`'s "PASS" in E-A5-1 is not evidence of durability, and acknowledged events at `NORMAL` can be lost on power failure. This supports A5's choice of `FULL` for evidence and audit. **Requested change:** §4 and §8 should not cite E-A5-1 as meeting R8.7 for `NORMAL`. Any stream run at `NORMAL` must be declared non-durable on power loss. A6 adds hardware test H-11 (power cut on site storage).

### R-A5-2 — Restart while the disk is full: reads survive, pruning does not (extends E-A5-3)

E-A5-3 recovers a full store with the writer still running. A6 experiment E-03 kills the writer at `SQLITE_FULL` and opens the store in a new process with the disk still full ([script](../../tests/integration/experiments/store_restart_while_full.py), [results](../../tests/integration/experiments/results/E-03-2026-10-23.json); 3 trials per configuration, Python's sqlite3 binding over SQLite 3.45). In both default and bounded-WAL configurations, the restarted process opened the store, read every acknowledged event, passed `integrity_check`, and ran a forwarder-style range read. Deleting 50 rows failed with `SQLITE_FULL` every time. So a forwarder can still drain after a crash at full disk, but nothing can be pruned until space is freed. **Requested change:** the reserve release must be a startup step, not only a runtime reaction, and the reserve must be re-created after recovery. Phase 2 must test a second exhaustion after a recovery that consumed the reserve. V-S9 gains a restart-while-full case.

### R-A5-3 — Pruning only confirmed events contradicts a target that can never confirm (contract contradiction)

§5 says eviction never removes an event a required consumer has not confirmed, and that over RFC 5425 the confirmed cursor can never advance. If an RFC 5425 syslog target is a required consumer, nothing is ever prunable, the SER quota fills, and polling stops permanently. Today that is the default deployment. **Requested change:** the Phase 1 contract must state per target whether it is a required consumer, and what retires an event for a target that cannot confirm (for example age beyond the replay window, recorded as "delivered unconfirmed"). This is part of B-03 and needs A1, A4, and A5 together.

### R-A5-4 — Smaller items

- E-A5-3 ran on tmpfs, which has no root-reserved blocks. On ext4, a writer running as root consumes the reserved blocks and fills the disk for the whole node. Requested: the store lives on a dedicated filesystem and the writer runs as non-root, both asserted at startup.
- With per-event commits, E-03 measured about 9 KB of WAL per 368-byte event before a checkpoint (about 450 events filled 4 MiB at default settings). This is fine with the bounded WAL A5 recommends. It is one more reason the default settings must never ship.
- E-A5-4 agrees with A6 E-01 and adds the acknowledged-transport result: 0 missing and 1 duplicate across 3 collector kills. **Holds.**
- The R8.3 sizing arithmetic (about 1.3 GB for 72 h at 10 events/s) is consistent with E-03's main-database growth of about 410 bytes per event. **Holds.**

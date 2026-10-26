# ADR-0008: Monitoring goals and the collection-method order (owner clarification)

- Status: accepted
- Date: 2026-10-26
- Deciders: project owner (goals and order), A1 (architectural consequences)
- Related: R1.8, R3.6, R3.7, R4.8, R4.9, R6.7, R9; ADR-0005, ADR-0006; `docs/phase-2-exit.md` "Next coordinated tasks"

## Context

At the Phase 2 gate (2026-10-26) the owner stated what "security monitoring, configuration monitoring and baseline" must mean for the product, and the order in which collection methods are to be chosen per device. Six points:

1. **Configuration monitoring:** a device's configuration must stay unchanged unless a change was approved in advance. A change the platform does not know about is raised as an alarm.
2. **Event-behaviour baseline:** Syslog and SER events are compared with a per-device baseline learnt over an observation period; repeated alarms, events that should not occur, and other departures raise an alarm.
3. **IDS:** a network baseline with anomaly and vulnerability detection, as the brief already has it.
4. **Vulnerability applicability:** from everything read about a device (identity by SNMPv3, SSH, Telnet, Syslog or any other read path), the platform lists the vulnerabilities that apply to it.
5. **Collection-method order, per device:** for events, device-generated Syslog first; then a file fetch (the Syslog archive, the SER, settings or CID files) over a secure transfer (SFTP or SCP), with FTP only where nothing better exists; then command-line parsing (Telnet, SSH or serial) when no file path exists. The same order applies to configuration retrieval.
6. **Asset monitoring and management is a separate module**, mainly through SNMPv3, with other read paths where SNMP is not available.

The brief's sections 1.1, 1.3, 1.4 and 1.6 contain points 1, 2 (in part), 3 and 6 in general words. Points 1 (prior approval), 2 (an observation period and event-behaviour alarms), 4 (vulnerability applicability) and 5 (the method order) were not written down anywhere, and point 6's module boundary was not either.

## Options considered

1. **Fold the points into the existing requirements as new rows and re-rank Phase 3 and Phase 4 around them.** Keeps requirement IDs stable and the verification trace intact.
2. **Write a second requirements document for "monitoring goals".** Rejected: it would split the trace between two documents for no gain.
3. **Treat the method order as guidance only.** Rejected: the owner stated it as a rule, and a rule can be tested per family in the capability matrix.

For the SEL-751 specifically, the method order forces a choice the team made differently in Phase 2:

- a. **FTP file fetch of `/REPORTS` and the settings files, ahead of Telnet** (the owner's rung 2 before rung 3).
- b. **Telnet SER and `SHO`, as built** (ADR-0005), with FTP excluded by finding D8.

## Evidence

- `docs/device-capabilities.md` (A2, from S22 Table 7.5): the SEL-751 offers no Syslog emission, no SSH, no TLS and no SNMP agent. FTP exists, with the SER readable from `/REPORTS` and settings files in the FTP virtual file system (`docs/phase0/A2-device-feasibility.md`, p. 10.40, Table 7.80). `CFG.TXT` over FTP carries RELAYTYPE, FID, BFID and PARTNO (Figure 7.46).
- Finding D8 (A2, A3): FTP logins use the access-level credentials, `FTPACC` defaults to 2, and FTP transfers settings "to and from the relay", so a Level 2 FTP login is a write path. Whether a Level 1 FTP login (`FTPACC := 1`) is read-only is `documented-untested`.
- Finding D7: Telnet and FTP both carry the password in clear. FTP is therefore no worse than the Telnet path the slice already uses on that point, and no better.
- SEL switches (2730M), the RTAC, the SEL-2488 and the SEL-3620 emit Syslog and offer SNMPv3 (`docs/architecture.md`, device coverage table; A2's classification of the 2730M in PR #8).
- The Phase 2 slice (`docs/phase-2-exit.md`): Telnet SER collection, normalization, evidence and RELP forwarding work end to end on the simulator. Syslog receive is designed (C1 listener endpoints, C4 `origin: syslog`, C5 `syslog-stream` and `syslog-datagram`) and not built.

Nothing here is hardware-verified.

## Decision

1. **Requirements.** `docs/requirements.md` gains R1.8 (asset module, SNMPv3 first), R3.6 (prior approval), R3.7 (configuration method order), R4.8 (event-behaviour baseline), R4.9 (event method order), R6.7 (exposure as input to applicability) and a new section R9 (vulnerability applicability). The rows are traced to acceptance criteria by A6 in Phase 3.
2. **Module boundary.** Asset monitoring and management is `modules/asset/`, owned by A2 for the device-facing reads (an SNMPv3 adapter under the same register, approval and read-only rules as every adapter) and the inventory logic; persistence and the operator interface stay with A5 through C1 and C5. The module is separately enabled and disabled (R7.1).
3. **The method order is a rule, recorded per family.** The capability matrix gains, for each SEL family, the rung reached for events, configuration and identity, with its evidence class. An adapter for a lower rung is built only when the matrix shows the higher rungs absent or unsafe for that family.
4. **SEL-751.** Rung 1 (Syslog) is absent. Rung 2 (FTP) is eligible only if A2 shows, from the manual and later on hardware, that `FTPACC := 1` yields a read-only login and that `/REPORTS` and the settings files are readable at that level; A3 must accept the credential exposure, which equals the Telnet path's. Until then rung 3 (the Telnet adapter from Phase 2) stays the SEL-751 path, and the Phase 2 result is not invalidated: it is the rung the rule itself falls back to. The FTP assessment is A2's Phase 3 work; the decision between (a) and (b) is taken in the Phase 4 configuration-monitoring brief on that evidence.
5. **Phasing.** Phase 3 keeps its hardening tasks (they gate any device contact) and adds Syslog receive (A4, rung 1 for every family that emits it) and the capability-matrix rungs (A2). Phase 4 is re-ranked: (1) configuration retrieval, baseline and prior approval; (2) the event-behaviour baseline; (3) vulnerability applicability with the asset module's SNMPv3 identity; (4) IDS; (5) secure engineering access; (6) the central role. The owner may reorder again.

## Consequences

- Easier: the method order gives A2 a deterministic way to choose an adapter per family, and the capability matrix becomes the place where "supported" is decided (ADR-0006).
- Harder: three new capabilities (prior approval, event baseline, vulnerability applicability) need design before code. Each gets a brief with contracts first (CLAUDE.md §5.4): an approval record in C8, a baseline model in C4 or a new contract, and an advisory-set format with a signed offline update path.
- The event-behaviour baseline must stay explainable: deterministic rules and statistical baselines whose parameters are shown with every alarm; no machine learning until a measured benefit exists (brief, section 1.6 constraint, applied to events).
- Vulnerability applicability must never become active scanning (P1), and must never state exploitability without evidence (P10). Every advisory entry cites its source; the advisory set is versioned and updated offline.
- Unverified: which SEL families reach which rung is `documented-untested` until the hardware items run.

## Open objections

- A3's objection to FTP (D8 write path, D7 cleartext credentials) stands and is the condition in decision 4. It is tracked in the Phase 3 brief for A2 and in the Phase 4 configuration-monitoring brief.
- SNMPv1 and v2c are unauthenticated. The asset module uses them only as read-only fallbacks with the owner's per-device approval (R1.8).

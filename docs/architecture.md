# Architecture

Owner: A1. Status: **Phase 0 exit gate passed with conditions (2026-10-23).** Decisions are recorded in ADR-0002 to ADR-0005 under [decisions/](decisions/). Phase 0 evidence lives on the agent branches listed in [agent-handoffs.md](agent-handoffs.md); every result in Phase 0 is `documented-untested` or `simulated`.

## System boundary

Zone names follow IEC 62443-3-2 zone and conduit terminology (alignment, not certification).

### Where the platform sits

```text
 Enterprise / control-centre zone          ┌───────────────────────────┐
   upstream Syslog / SIEM  ◄── TLS ─────── │ Central server (optional) │ ◄── operators, admins (upstream authn)
                                           └─────────────▲─────────────┘
 ─────────────── WAN (intermittent) ─────────────────────┼─────────────────────── conduit C1 (mTLS, site-initiated)
 Substation security-services zone         ┌─────────────┴─────────────┐
                                           │ Site node                 │
                                           │  collector + store/forward│
                                           │  adapter executor (creds) │
                                           │  passive sensor (later)   │
                                           └───┬───────────────────▲───┘
 ──────────────────────────────────────────────┼───────────────────┼────────── conduit C2: approved read-only
 Station bus / substation LAN                  │ C2 (read-only     │ C3 (receive-only   device interfaces only
   IEDs, RTU/gateway, HMI, eng. workstation ◄──┘  adapter traffic) │  SPAN/TAP, later)  conduit C3: no transmit
 Process bus (SV/GOOSE): out of scope for the first slice; visibility documented by A4.
```

In single-server deployment the central and site roles run on one host; the conduits stay logically the same.

### What the platform observes

- Device-generated Syslog sent to the site node (R4.1).
- SER and identification data retrieved by approved read-only adapter commands over C2 (R4.2, R1.2, R5).
- Later milestones: mirrored traffic on C3 (R6), configuration files (R3), engineering session traffic (R2).

### What the platform may touch

- Only commands in the approved command register (`docs/device-capabilities.md`) classified `read-only`, invoked through the collector process, on devices the owner has listed for collection. Default for every device is "not collected". For the first slice the sendable lines are exactly `ACC`, `QUI`, `ID`, `SER` (ADR-0005).
- In the first slice no human role can trigger device I/O; collection runs under a non-human collector identity from site-local schedules (A3 §4.1).

### What the platform must never do

- Issue control operations (for example DNP3 operate, IEC 61850 control, GOOSE publication), settings writes, firmware uploads, or buffer-clearing commands, through any monitoring path.
- Perform active discovery or scanning on production networks without explicit, per-scan owner authorization.
- Transmit on a passive sensor interface.
- Let the central server or WAN reach a device directly. Central may change a site node's policy only through signed bundles within limits the site enforces locally (ADR-0002, A5 §6).
- Sit in the protection or control path. If every platform component stops, protection, control, and SCADA continue unchanged (R8 constraint).

### Evidence ceiling for the first slice

Owner decision, 2026-10-23: no lab IED and no real device outputs are available. The first slice is built and verified against OEM documentation and a device simulator only. No capability in this milestone can be classified above `documented-untested` or `simulated`. A6 builds the simulator independently from A2's cited documents, not from A2's code, so a misreading is not shared by parser and simulator.

## Device coverage and vendor strategy

Owner scope change, 2026-10-23 ([ADR-0006](decisions/ADR-0006-device-coverage-and-vendor-strategy.md)): every OT device class is in scope, and vendor-specific support is built for SEL first, family by family. The architecture already separates class- and vendor-neutral parts (collector process, register, adapter envelope, store, forwarder) from per-family parts (session driver, parser, capability profile), so the change adds profiles and adapters, not new runtime components.

| Device class | SEL families (source) | Vendor-neutral coverage from the start | SEL-specific read path (to be classified by A2) |
| --- | --- | --- | --- |
| Protective relays, IEDs | SEL-751, SEL-787-2/-3/-4, SEL-311L, SEL-400 series (400G, 411L, 451) — instruction manuals supplied by owner | Passive observation; no Syslog on these relays (SEL-751 IM: no SSH, Syslog, or TLS) | SEL ASCII over Telnet or serial: `ID` (Access Level 0), `SER` (Level 1) — SEL-751 IM Tables 7.43, 7.63 |
| RTUs, automation controllers | SEL RTAC: SEL-3350 (replaces the discontinued SEL-3530, owner 2026-10-23), SEL-3555-2, SEL-3505, SEL-3530 (installed base); hardware IMs and acSELerator RTAC SEL-5033 IM supplied | Syslog | SSH, Syslog, SNMP, HTTPS, LDAP, REST API appear in SEL-5033 IM, Programming Reference, and SEL-3555-2 IM; classification pending (A2) |
| Ethernet switches | SEL-2731, -2741, -2743, -2744 (2731 and 2741 manuals supplied); RSTP-managed or OT SDN-managed | Syslog (RSTP User's Guide, SDN User's Guide) | RSTP-managed: SNMP, HTTPS; SDN-managed: via SEL-5056 flow controller (IM supplied) |
| Routers, security gateways, firewalls | SEL-3620/-3622 (IM 20241010, shared with SEL-3610, supplied) | Syslog (documented in IM) | SSH, SNMP, HTTPS appear in IM; classification pending (A2, A3) |
| Time servers and clocks | SEL-2488 (IM and data sheet supplied); SEL-2401, SEL-2404, SEL-2407 satellite clocks (IMs supplied) | SEL-2488: Syslog (RFC 3164, fixed port 514, A5/A4); passive PTP/NTP observation. SEL-2401/2404/2407: A1 grep of the IMs finds no Syslog, SSH, Telnet, SNMP, or NTP, so operator-entered data and passive observation only (A2 to confirm) | SEL-2488: SNMP, HTTPS, LDAP/RADIUS in IM; classification pending |
| Servers and computers | SEL-3355-2 (IM and data sheet supplied), Windows 10/11 IoT LTSC (owner 2026-10-23); also the platform's site node (ADR-0007) | Windows events by host push (owner decision, ADR-0006); passive observation | Hardware management (SNMP/HTTPS in SEL-3355-2 IM); classification pending |
| Engineering workstations, HMIs | Windows hosts (SEL-3355-2) running COPA-DATA zenon HMI Energy Edition (owner 2026-10-23; non-SEL software) | As servers | As servers; zenon-specific logs wait for a later vendor phase |
| Historians | Windows hosts; historian product as named by the owner (zenon, 2026-10-23) | Passive observation; Windows events by host push | Windows event collection only, until a later vendor phase for the historian product |
| SDN flow controller | SEL-5056 (IM supplied) | Syslog | SNMP, HTTPS, REST appear in IM; classification pending |
| Meters | SEL-735 (IM 20250711 supplied) | Passive observation; A1 grep finds no Syslog or SSH in the IM | Telnet and SER appear in IM (SEL ASCII family, like the relays); classification pending (A2) |
| Port servers, serial equipment | SEL-3610 (IM shared with SEL-3620/3622, supplied); SEL-ICON (no manual) | Syslog (documented in shared IM) | SSH, SNMP, HTTPS in shared IM; classification pending (A2) |

"Supported" (owner clarification, 2026-10-23): an SEL family is in scope for support to the extent its native capabilities can meet the project requirements; where a family lacks a capability (for example SEL-751 has no Syslog or SSH), the requirement is met by another path or recorded as a limitation for that family.

Every active read path in the last column is an adapter: registered operations, read-only classification with citations, per-device approval, and the same enforcement layers as the relay adapter. A device class is "supported" only per SEL family and only at the evidence class `docs/verification.md` requires.

## Runtime shape

Decided in [ADR-0002](decisions/ADR-0002-runtime-shape.md): one Go binary (ADR-0003) running as `site`, `central`, or `all-in-one`; modules as packages behind `contracts/`; separate OS processes only for the IED collector (sole holder of device credentials and of the route to the IED network) and, later, Zeek. No broker, no orchestrator. Persistence and delivery in [ADR-0004](decisions/ADR-0004-local-persistence-and-delivery.md): SQLite WAL per data-owning module, commit before acknowledgement, at-least-once with `(node_id, stream, seq)`, required vs best-effort forwarding targets.

```text
 site node (one host; all-in-one for the slice)
 ┌───────────────────────────────────────────────────────────────┐
 │ main process (user otsec)                                     │
 │  telemetry: normalize → telemetry.db ──► forwarder ──► RELP/TLS or RFC 5425 ──► upstream receiver
 │  assets, audit (audit.db), policy, local UI on mgmt interface │
 │        ▲ adapter results (raw transcript + records)           │
 │        │ local IPC contract (C7)                              │
 │ collector process (user otsec-collector)                      │
 │  register lookup → render → egress check → Telnet driver ─────┼──► SEL relay (station LAN, plaintext, ADR-0005)
 │  credential store (only reader)                               │
 └───────────────────────────────────────────────────────────────┘
```

## Phase 0 answers to the architecture-critical questions

| ID | Question | Answer (evidence class) | Source |
| --- | --- | --- | --- |
| Q1 | Can arbitrary engineering applications be proxied? | **No.** TCP forwarding pins destination but cannot constrain operations or attribute users at the device (E1, `simulated`); multi-channel vendor tools likely break. Proposed for Phase 4: protocol-aware gateway for CLI devices, controlled remote workstations for vendor GUIs, pinned TCP forwarding only as a labelled last resort. Unsettled until experiments X1–X4 (need licences and a lab IED). | A3 §3 |
| Q2 | Can all desired configuration be safely retrieved? | **No, not all, and not by one mechanism.** SEL Level 1 shows settings as text; native settings files sit behind FTP, which also writes; passwords need Level 2 and are never retrieved. R3 needs per-family rows stating what is retrievable, how, and at what level. (`documented-untested`) | A2 §8 |
| Q3 | Can vendors' SER records be accurately normalized? | **Structurally yes, semantically no.** One schema held four native time encodings losslessly when it keeps native time verbatim, separates resolution from accuracy, allows offset "unknown", and scopes time quality. Meaning needs per-device mapping tables. (`simulated` for protocol encodings, `documented-untested` for SEL) | A4 §2 |
| Q4 | Can passive monitoring see enough for IDS? | **Only per site, with stated placement.** Zeek 8.0.4 and Suricata 7.0.3 decode DNP3 and Modbus but not IEC 61850 MMS, GOOSE, or IEC 104. PRP, SPAN loss, encryption, and serial links further limit visibility. Zeek plus own decoders proposed for Phase 4. (`simulated`) | A4 §3, §4 |
| Q5 | Can one adapter framework cover vendor behaviour? | **Plausibly yes,** if the shared part is the invocation/result envelope plus enforcement, and session drivers stay per family. Test in Phase 1: implement the SEL relay profile against the envelope, write a second SEL class (RTAC, per ADR-0006: Syslog push, named users and roles, two timestamps, no monitoring shell) on paper, count special cases. (inferred) | A2 §9 |
| Q6 | Can centralized and distributed share a foundation? | **Yes,** under four invariants: only sites talk to IEDs; sites are system of record; site-initiated connections; loss of central never stops a site. (`simulated` store evidence; design otherwise) | A5 §2, ADR-0002 |
| Q7 | Could the platform become an attack path into OT? | **Yes, by construction.** 21 attack paths with mitigations and falsifiable tests; most consequential: device access levels that do not separate read from write, the node credential store, central as a fleet command path. None implemented. | A3 threat model |

## Five architecture-critical risks

Consolidated from proposals by A2, A3, A4, A5, A6.

| # | Risk | Evidence | Mitigation in the architecture | What still needs hardware or owner input |
| --- | --- | --- | --- | --- |
| 1 | **"Read-only" collection is not guaranteed by the device.** SEL Access Level 1 permits `TRI`, elevation attempts, and clearing the SER buffer (`SER C` or `SER R` are Level 1 on SEL-751, IM Table 7.63); binary Fast Operate (breaker control) shares the ASCII port; three bad passwords pulse the ALARM contact; some models allow a single Telnet session. | A2 D1–D9 and data-sheet follow-up; A6 C-01, C-02, C-12; A3 HR-2 | Exact-line register with deny-by-default; independent A6 deny corpus gates every register change; egress check on final socket bytes (printable ASCII + CR/LF only); credential ceiling Level 1; one auth attempt then suspend; one short session per device closed with `QUI`. | H-02 to H-05, H-08, H-09 on a lab relay. |
| 2 | **The platform is a path into IEDs.** Node credential store; central as a fleet command path; slice credentials cross the station LAN in cleartext and the relay cannot be cryptographically authenticated. | A3 HR-1, AP-7, HR-8; ADR-0005 | Separate collector process as sole credential reader; site-initiated mTLS with signed bundles under a site ceiling; no human-triggered device I/O; plaintext label plus per-device acknowledgement; owner accepted residual Telnet risks for the simulated slice only. | Owner authorization before any real device; production path (serial or gateway) undecided. |
| 3 | **No primary device evidence.** No lab IED, no captures; SEL manual bodies are unreadable here; parser and simulator both derive from the same documents, so a documentation error passes every simulated test. | A6 B-01, B-07; A2 §1 | Every result labelled `simulated`; A2 and A6 transcribe documents independently; no family called "supported" until H-01, H-07, H-08, H-09 pass. | SEL-751 instruction manual; later a lab relay. |
| 4 | **Delivery guarantees are weaker than the requirements assume.** RFC 5425 cannot confirm delivery; RELP confirms only with a specific receiver queue configuration; "prune only confirmed" plus an unconfirmable target would stop SER polling. | A6 E-01, A5 E-A5-4, A4 E-A4-03, A6 C-18 (all reproduced by A1 except C-18, which is analytical) | ADR-0004: commit before ack, at-least-once with stable `event_id`, required vs best-effort targets, mode A (RELP/TLS, tested receiver config) preferred, mode B (RFC 5425, replay window) best-effort only. | Owner's real upstream collector and its configuration. |
| 5 | **Event fidelity across vendors and over time.** Offsets absent or mislabelled by tools; rendered digits overstate precision; SER ring buffers wrap and can be cleared with no sequence counter, so some gaps are undetectable. | A4 §2; A2 D10; A6 C-05, C-06, C-13 | Schema keeps native time verbatim with resolution, accuracy, offset "unknown", scoped quality; snapshot alignment instead of per-row keys; gaps reported as telemetry health, and undetectable-gap limits documented per family. | H-07, H-10 on a lab relay. |

Also tracked, outside the first slice: stock IDS engines are blind to IEC 61850 and IEC 104 (A4 risk 1); engineering access cannot give per-operation control for arbitrary tools (A3 HR-4).

## First implementation scenario

Selected in [ADR-0005](decisions/ADR-0005-first-slice-scenario-and-transport.md): an all-in-one site node collects `ID` and `SER` at Level 1 over Telnet from A6's simulated SEL-751, stores native bytes and normalized events, and forwards them to an independent upstream receiver. Evidence ceiling: `simulated`.

## Contracts required for Phase 1

Only what the first slice needs. Each contract carries a version identifier and states its compatibility rule (API versioning). Owner writes the draft; A1 approves after the listed reviewers.

| ID | Contract | Draft source | Owner | Reviewers |
| --- | --- | --- | --- | --- |
| C1 | Asset identity and device capability profile, including device class and vendor/product family (ADR-0006), evidence source and confidence per attribute, `downstream_security`, and transport identity binding where the transport has one | A2 §9, A3 §4.5, A6 C-07 | A2 | A3, A6, A4 |
| C2 | Adapter invocation and result envelope, limits, closed error taxonomy, transcript with byte spans and redaction markers | A2 §9, A3 HR-3 ruling, A4 EP-1..EP-9 | A2 | A3, A4, A6 |
| C3 | Approved command register format (machine-readable, exact lines, citation, classification) | A2 register JSON, A6 checker | A1 (format), A2 (content) | A6 (deny corpus gate), A3 |
| C4 | Event and timestamp schema `otsec.event/0.1` and evidence-preservation rules EP-1..EP-9 | A4 schema draft | A4 | A2, A6, A5 |
| C5 | Local store, outbox, and delivery semantics (ADR-0004), including per-module data ownership | A5 §5 | A5 | A4, A6, A3 |
| C6 | Syslog forwarding profile `otsec-syslog/0.1`, modes A and B, TB5 ack-only grammar | A4 schema draft §5 | A4 | A3, A6 |
| C7 | Authorization and credentials: role and operation matrix, `CredentialRef`, collector IPC (what the main process may ask the collector to do) | A3 §4.1, §4.2 | A3 | A5, A2, A6 |
| C8 | Audit event format, sharing the timestamp model of C4 | A3 §4.4 | A3 | A4, A6 |

Deferred until after the slice: site-to-central message set and central instruction allowlist (A5 §6, A3), configuration-monitoring contracts, IDS sensor contracts, engineering-access contracts.

## Unsupported assumptions (marked)

| Assumption | Status | What settles it |
| --- | --- | --- |
| The brief's example "SSH to an IED" | Not supported for SEL relays (A2; SEL-751 data sheet 20260910 lists no SSH) | Revisit per family |
| SEL-751 Telnet session limit, SER row layout details, password echo | Manual now supplied (SEL-751 IM 20260910); A2 to read and cite. Already read by A1: `ID` is Level 0, `SER` and `SER C/R` are Level 1, Telnet idle timeout `TIDLE` 1–30 min (default 15) | A2 transcription, A6 independent transcription |
| SEL Level 1 behaviour, ALARM pulse, session limits on SEL-751 specifically | Documented for SEL-300G or SEL-311L only | Manual, then H-02 to H-04 |
| Relay CPU and communications load from polling | `unknown` | H-05 |
| Power-loss durability of the store | Untested; process-crash only at `synchronous=FULL` | H-11 |
| Substation event rates and real WAN outage durations | Owner 2026-10-23: WAN outage is not tolerated and sites have N-1 redundancy, so an outage is a fault, not normal operation. Store-and-forward stays (R8); the 72 h buffer floor is kept as a fault allowance, not a sizing target. Event rates still inferred | H-tests on real site traffic |
| Site node hardware and OS | **Settled by owner 2026-10-23:** SEL-3355-2 with Windows 10/11 IoT LTSC. Consequences in ADR-0007 (proposed); Linux evidence for durability does not transfer | ADR-0007 experiments on Windows |
| Central never needs direct IED access | **Confirmed by owner 2026-10-23:** the central HMI server may reach relays, central cybersecurity servers may not. The platform's central role never connects to devices; all device sessions originate at site nodes. The HMI server's relay traffic is an existing authorized path the IDS must model | Settled |
| Upstream collector supports RELP with the tested queue configuration | Owner 2026-10-23: assume any standards-compliant Syslog collector and support all types. The forwarder offers RELP/TLS (only mode allowed as `required`), RFC 5425 TLS, RFC 6587 TCP, and RFC 5426 UDP (all `best-effort`; UDP and plain TCP labelled insecure) per ADR-0004 | A6 interoperability tests per transport |
| IEC 62351-8 role names; IEC 62443-3-3 requirement mapping | Mapped at title level from secondary knowledge | Normative texts |
| Contrast family (SIPROTEC 5 or Relion 615) identity and SOE access | Superseded by ADR-0006 (SEL RTAC is the contrast) | — |

## Phase 0 exit gate

Decision by A1, 2026-10-23: **passed with conditions.** Phase 1 (contracts) may start. Phase 2 implementation may not start until the conditions below are met.

- [x] Five architecture-critical risks identified (above).
- [x] A plausible initial architecture established (ADR-0002 to ADR-0004, accepted at this gate).
- [x] Initial implementation scenario selected (ADR-0005; transport decided by the owner).
- [x] Required contracts defined (C1 to C8 above, with owners and reviewers).
- [x] Objective acceptance criteria established: V-S1 to V-S15 and the R/P matrix in [verification.md](verification.md) (A6 branch), approved as the Phase 0 baseline; thresholds marked *(proposed)* are confirmed by owning agents in Phase 1.
- [x] Unsupported assumptions marked (above).

Conditions before Phase 2 code:

1. B-02: the approved register (C3) is approved with citations read from the SEL-751 manual, not only located (needs the manual, B-07).
2. B-04: C7 credential storage accepted by A3 and reviewed by A6.
3. B-03: C5 and C6 approved, including the required/best-effort rule and the mode A receiver configuration.
4. The five agent branches are merged to `main` so contracts are written against one tree.

# A3 Phase 0 findings: security and engineering access feasibility

Owner: A3. Task: P0-A3 (brief in `docs/agent-handoffs.md`, issued by A1 2026-10-23). Date: 2026-10-23. Branch: `claude/project-thread-qj1j9d` (the environment fixes the branch name; the `agent/security-*` convention could not be used).

The threat model v0 itself is in [../threat-model.md](../threat-model.md). This file holds the supporting analysis, the drafts A1 asked for, and proposals for A1-owned documents.

Evidence labels: `[doc]` read in an OEM document or standard; `[exp-sim]` shown by experiment E1 against loopback mocks; `[inferred]` reasoning only; `[peer]` agreed with another agent's draft, not an ADR. **Nothing here is hardware-verified.**

## 1. Summary

1. **Q7 (new attack path): yes.** The platform holds device credentials and sits on the IED network, so it is an attack path by construction. The threat model lists 21 paths, each with a mitigation, an enforcement point, and a falsifiable test. None is implemented or verified.
2. **Q1 (arbitrary engineering apps via proxy): no, not arbitrary ones.** A TCP-level proxy can pin *which device and port* a session reaches (E1 `[exp-sim]`) but cannot constrain *what operations* are sent over it (E1 T6), and the device then sees only the gateway's address (E1 T7). Vendor tools that use multi-channel protocols (ABB PCM600 needs FTP 20/21 plus MMS 102 `[doc]`) or discovery broadcasts are also likely to break under simple forwarding `[inferred]`. Recommended direction for Phase 4: a protocol-aware terminal gateway for CLI devices, controlled remote engineering workstations for vendor GUI tools, and destination-pinned TCP forwarding only as a labelled last resort. Settling it needs licensed vendor software and a lab IED (section 3.4).
3. **Read-only must be enforced in seven independent layers**, not in the adapter alone (section 4.3). The weakest link is device-native: if the access level that reads SER can also change settings, the device gives us no protection (HR-2, A6 C-12).
4. **In slice 1, no human role can trigger device I/O at all.** Collection runs under a non-human collector identity from site-local schedules. This removes the largest privilege-separation risk from the first milestone instead of mitigating it.
5. **Credentials stay at the site.** Central stores references only; secrets travel admin→node encrypted to the node's key; only the transport layer resolves a secret, at connect time, below the transcript recorder (section 4.2).
6. **Central cannot command nodes** beyond signed policy bundles bounded by a site-local ceiling; nodes initiate the connection; replay reads only the node's local store `[peer A5]`.
7. **Downstream insecurity is labelled, not hidden.** Every device carries `encrypted-authenticated`, `encrypted-weak`, or `plaintext-unauthenticated`; plaintext requires a per-device admin acknowledgement (section 4.5).
8. **A1 rulings received 2026-10-23:** R8.5 rotation covers platform-owned credentials only, and IED rotation is a device write outside slice 1 (HR-5). Transcripts keep every byte received from the device; bytes the platform sends during authentication are replaced by a redaction marker (HR-3). Slice 1 is provisionally `encrypted-authenticated` only, with out-of-band pinned host keys; if A2's family cannot do that, A1 takes it to the owner as a security-policy decision.
9. **A2's primary family (SEL, Telnet) cannot meet the provisional encrypted-only rule for slice 1** (HR-8). A3 recommends Telnet with lab-only credentials for the simulator-based slice, with production use left to an explicit owner decision and serial as the preferred production path (section 8.2). SEL Level 1 is not read-only, so the egress check (exact lines plus a printable-ASCII byte filter) is the decisive control (section 8.1).

## 2. Evidence examined

| Source | What it shows | Class | Used for |
| --- | --- | --- | --- |
| ABB, *615 series Cyber Security Deployment Guideline*, 1MRS758280 rev C (2018-12-20), §3.2–3.5, §4.1–4.2, §5.1 | Ports: FTP/FTPS 20/21 and IEC 61850 102 open and required for configuration (cannot be disabled); HTTP/HTTPS closed by default. Roles VIEWER, OPERATOR, ENGINEER, ADMINISTRATOR with default passwords. Secure Communication gives HTTPS and FTPS with a relay-generated self-signed 1024-bit RSA certificate, TLS 1.0–1.2. Audit trail of 2048 events readable by administrator only. No Syslog or central account management mentioned. | `[doc]` | AS-2, HR-7, Q1, SC-7 |
| Siemens ProductCERT SSA-899560 (SIPROTEC 5 and DIGSI 5) | Engineering-related vulnerabilities on 443/TCP; vendor mitigations include blocking 443/TCP, enabling device RBAC (firmware ≥ V7.80), the DIGSI 5 connection password, and DIGSI 5 client authorization (≥ V7.90). | `[doc]` | Q1 (engineering protocol is a high-value surface), SC-6 |
| SEL, *SEL-3620 Ethernet Security Gateway* product page and data sheet (date code 20221003) | A commercial gateway does exactly the CLI-proxy model: users log in to the gateway, which holds every protected IED's passwords, can rotate them on a schedule, logs every command, and emits Syslog for session start and end. | `[doc]` | Q1 feasibility of terminal gateways; HR-5; AP-1 (a gateway that knows all IED passwords is the prime target) |
| IEC TS 62351-8 ed1.0 public preview | Confirms the standard defines pre-defined roles, rights, and role-to-right mapping (Tables 1–7). The preview does **not** contain the role names or table contents. | `[doc]` (titles only) | SC-2 alignment; role names below are from secondary knowledge, not verified |
| MITRE ATT&CK for ICS technique list, attack.mitre.org/techniques/ics, retrieved 2026-10-23 | Current technique IDs, including the renumbered T1691/T1692/T1694 families. T0886 mitigations M0801, M0800, M0937, M0804, M0807, M0930, M0927, M0813, M0918. | `[doc]` | ATT&CK column in the threat model |
| Experiment E1, `modules/access/experiments/e1-ssh-forward-controls/` | See section 5. | `[exp-sim]` | AP-6, HR-4, Q1, R2.5 |
| A5 findings (branch `claude/project-thread-xni3ff`, `docs/phase0/A5-platform-feasibility.md`) and A5 messages | Site-initiated mTLS, no central re-collect, anti-rollback floor, local listener on management interface only, storage-full policy. | `[peer]` | TB2, AP-7, AP-10, AP-16, AP-19 |
| A6 verification draft (branch `claude/project-thread-u7odvk`) | Blockers B-04 (site credential storage), B-05 (device identity trust); concerns C-08 (log injection upstream), C-12 (device access level); tests V-S11, V-S14, V-S15. | `[peer]` | AP-1, AP-4, AP-12, AP-20 |

Not obtained: full normative texts of IEC 62443-3-3, IEC 62351-3/-8/-9/-14, and NIST SP 800-82r3 section numbering. Standards columns are alignment at the level of requirement titles only.

## 3. Q1: can arbitrary engineering applications be proxied?

### 3.1 Options

- **P — Protocol-level proxying.** The platform forwards or terminates the engineering protocol between the engineer's own workstation and the IED. Two sub-variants: **P-tcp** (destination-pinned TCP forwarding, protocol-agnostic) and **P-aware** (the gateway understands the protocol, e.g. terminal CLI, and can record and filter commands).
- **W — Controlled remote engineering workstation.** Vendor tools run on hardened workstations inside the OT side. The engineer reaches the workstation through a brokered, recorded remote-desktop session; the workstation's own network reach is restricted to the session's approved devices.
- **G — Per-application gateways.** A purpose-built gateway per vendor protocol (e.g. SEL-3620 style for SEL CLI devices `[doc]`), possibly vendor-supplied.

### 3.2 Comparison

| Criterion | P-tcp | P-aware (CLI) | W (remote workstation) | G (per-app gateway) |
| --- | --- | --- | --- | --- |
| Works with arbitrary vendor tools | Only single-channel TCP tools. Likely breaks on FTP active data channel, UDP discovery, broadcasts, dynamic ports, serial/USB front ports `[inferred]`; ABB PCM600 needs FTP 20/21 plus MMS 102 `[doc]`. | CLI devices only. | Yes, if the tool runs on the workstation and reaches the device from there `[inferred]`. | Only the protocols the gateway implements. |
| Destination control | Yes, per device:port (E1 T2, T3 `[exp-sim]`). | Yes. | Yes, via per-session firewall rules on the workstation's segment `[inferred]`. | Yes. |
| Per-operation control (R2.4) | **No.** Any byte stream passes (E1 T6 `[exp-sim]`). | Possible for line-oriented CLIs (command allowlist). | No at protocol level; relies on device-native levels and on what the tool exposes. | Possible, if the gateway parses the protocol. |
| Session recording | Byte stream only; unreadable for binary or TLS protocols. | Full transcript. | Screen recording; human-reviewable but not machine-checkable. | Protocol-level log. |
| Attribution at device | Device sees gateway address only (E1 T7). | Same, unless per-user device accounts are injected. | Device sees workstation; attribution only in platform audit. | Same as P-aware. |
| Credential exposure | Engineer typically holds device credentials. | Gateway can inject; engineer never sees them. | Can be injected on workstation, or engineer holds them. | Gateway holds all (SEL-3620 model `[doc]`): concentrates risk (AP-1). |
| Endpoint risk | Engineer's own laptop talks to IEDs (bad). | Engineer's laptop only sees a terminal. | Engineer's laptop only sees pixels; workstation is a new high-value asset to harden and patch. | Low on client side. |
| Revocation | Kill session process is *termination* only: E1 T8 closed a held connection in 0.013–0.014 s, but T9 shows the same key reconnects at once. Revocation needs the authorization removed first; T9r (key removed, then sessions killed) denies re-authentication `[exp-sim]`. | Same. | Broker disconnect plus authorization and firewall rule removal; untested. | Vendor dependent. |
| Insecure downstream visible | Must be labelled separately. | Yes, gateway knows the transport. | Must be labelled separately. | Yes. |
| Build effort for us | Low. | Medium. | Medium: broker, recording, workstation hardening, licences. | High per vendor, or buy. |

### 3.3 Recommendation (proposal for an ADR in Phase 4, not now)

Do not promise transparent proxying of arbitrary engineering software. Use **P-aware** for CLI devices (SSH/Telnet terminal sessions terminated at the gateway, credentials injected, transcript recorded, optional command allowlist), **W** for vendor GUI tools, and **P-tcp** only as a last resort that is destination-pinned, time-limited, and labelled in the UI as "no operation-level control". Evaluate buying **G** where a vendor gateway already exists rather than building one.

### 3.4 Evidence that would settle Q1

All of these need the owner's authorization because they need vendor software licences and a lab IED or vendor simulator. None touches production.

| ID | Experiment | Distinguishes |
| --- | --- | --- |
| X1 | Run PCM600, DIGSI 5, and QuickSet (or whichever tools match A2's families) against a lab IED (a) through a pinned P-tcp forward and (b) from a W workstation. Record which functions work: connect, read settings, write settings, retrieve events, firmware. Capture PCAP to enumerate ports, UDP, and broadcasts. | Whether P-tcp is viable at all per tool. |
| X2 | Same as X1 with the IED's FTP restricted to passive mode, if configurable. | Whether the FTP data channel is the only blocker for PCM600-style tools. |
| X3 | Measure revocation latency and completeness for W: broker disconnect, then attempt continued device traffic from the workstation. | Whether W meets R2.5 as well as P does. |
| X4 | For P-aware on a CLI IED: verify credential injection never echoes the secret into the transcript (AP-2) and that a non-allowlisted command is blocked before reaching the device. | Feasibility of per-operation control for CLI devices. |

## 4. Minimum safe behaviour for the first slice (drafts for Phase 1 contracts)

Slice 1: collect native SER from a lab IED, forward to Syslog, with asset identification and evidence preservation.

### 4.1 Authorization boundary (draft)

Roles (alignment with IEC 62351-8 role concepts; the 62351-8 role names VIEWER, OPERATOR, ENGINEER, INSTALLER, SECADM, SECAUD, RBACMNT are from secondary knowledge and not verified against the standard text):

| Role | Human? | Nearest IEC 62351-8 concept |
| --- | --- | --- |
| `monitor` | yes | VIEWER |
| `engineer` | yes | ENGINEER (Phase 4 only) |
| `admin` | yes | RBACMNT / INSTALLER (platform, not device) |
| `security-auditor` | yes | SECAUD |
| `collector` | **no**: per-node system identity | none |

Operation classes and who may invoke them in slice 1:

| Operation class | Examples | monitor | engineer | admin | security-auditor | collector |
| --- | --- | --- | --- | --- | --- | --- |
| `observe` | read assets, events, alarms | ✓ | ✓ | ✓ | ✓ | — |
| `device-read` | run a register read-only operation against a device | — | — | — | — | ✓ (site-local schedule only) |
| `device-write` | any state-changing device operation | **not implemented in slice 1** | | | | |
| `policy-admin` | schedules, register versions within the site ceiling | — | — | ✓ (second approver for widening) | — | — |
| `credential-write` | create or replace a device credential (never read) | — | — | ✓ | — | — |
| `role-admin` | grant roles | — | — | ✓ (second approver for engineer/admin/auditor) | — | — |
| `audit-read` | read and export audit | — | — | — | ✓ | — |

Rules: an `admin` cannot also hold `engineer` or `security-auditor` (AP-14). No API in slice 1 turns a human request into device I/O; "collect now" buttons are out of scope (AP-15).

### 4.2 Credential reference model (draft)

```
CredentialRef (stored centrally and at the node; contains no secret)
  id               opaque, stable
  asset_id         device this credential is for (one device per ref)
  node_id          the only node that can resolve it
  transport        ssh | telnet | ftp | serial | ...
  purpose          collect-readonly            (slice 1 allows no other value)
  access_level     device-native level name, e.g. "ACC" or "VIEWER" (from A2's register)
  version          increments on replace
  created_by, created_at, replaced_at
```

- **Write path:** the admin UI encrypts the secret to the target node's public key in the browser or API edge; central stores and relays ciphertext only; the node decrypts into its local store, encrypted at rest under a node-bound key (TPM-sealed where the hardware has one; otherwise a root-only key file, which is weaker and must be recorded as such).
- **Read path:** only the transport layer may resolve a ref, in-process, at connect time. For in-band authentication (SEL), the secret is sent only through a credential slot that the egress check opens immediately after the documented `Password:` prompt, and never otherwise (A6 R-A3-3).
- **Write-time validation:** a credential value must be printable ASCII (0x20–0x7E), within a bounded length, and must not match any register or deny-corpus entry, so the credential store cannot be used to smuggle a command into the slot.
- Adapters receive a connected session, not a secret. The secret never appears in adapter results, logs, audit records, errors, transcripts, environment variables, command lines, or crash dumps.
- **No read-back:** no role, including admin, can retrieve a stored secret.
- **Ceiling:** the node refuses to store a credential whose `access_level` exceeds the register's maximum for that device family (AP-4).
- **Rotation of IED credentials is out of slice 1** (HR-5).

Interfaces affected: A2's adapter invocation contract takes a `CredentialRef` id and receives a session; A5's node store owns the encrypted store; A6's V-S11 canary test checks the "never appears" list.

### 4.3 Where read-only is enforced (defense in depth)

| Layer | Enforcement | Catches | Owner | Test |
| --- | --- | --- | --- | --- |
| L1 | Authorization: only `collector` may invoke `device-read`; `device-write` does not exist in slice 1. | Human misuse, AP-15. | A3 | Enumerate API with each role's token. |
| L2 | Signed command register: every operation classified, reviewed by A2 (source) and A6 (safety). | Wrong classification reaching code. | A2, A6 review | Register signature check; review record. |
| L3 | Adapter renders bytes only from register templates and typed parameters. | Injection, free-form commands (AP-3). | A2 | Parameter fuzzing. |
| L4 | Transport egress check, a separate component that checks the **final bytes written to the socket** (after encoding, line terminator, and Telnet escaping) against the register, phase-aware (auth, operate, close), with a credential slot opened only by the documented password prompt; fails closed. | L3 bugs, elevation commands (AP-4), binary frames (D5). | A3 (shared with A2) | Mutation test with L3 disabled. |
| L5 | Device-native least privilege: the stored credential is for the lowest level that can read SER. | Everything above, *if* the device separates read from write at that level. | A2 facts; A3 policy | Lab IED only (hardware). Unknown until A2 reports (HR-2). |
| L6 | Site firewall: node may reach each IED only on the port its register operations need. | Use of other device services (e.g. FTP or MMS write paths). | A5 deploy | Connection attempts to other ports fail. |
| L7 | Independent observation: recording device simulator in tests (A6); IDS rule for write-class commands from the node in deployment (A4). | Anything that got through. | A6, A4 | V-S7. |

**Independence (A6 R-A3-1, accepted).** These layers are not seven independent barriers for slice 1. L2, L3, L4 and the L7 test oracle all derive from the register, so an over-broad register pattern passes all of them together. L5 fails for SEL (Level 1 is not read-only, A2 D1). L6 is the same port as the read. L1 constrains humans, not the collector. What is independent: against adapter bugs, L3 and L4 (separate components); against register errors, only the A2/A6 review and A6's deny corpus (`tests/safety/register_review/` on A6's branch). A3 therefore proposes that **passing A6's deny corpus is a release gate for every register change**, and that L7 in deployment be counted only for transports an IDS can read (Telnet yes, SSH no; A6 C-03).

### 4.4 Audit event minimum fields (draft, for A1 to merge with A4's event schema)

Audit records are a separate stream from device events but use the same timestamp conventions as A4's schema.

| Field | Notes |
| --- | --- |
| `audit_id` | Globally unique. |
| `node_id`, `seq` | Per-node monotonic sequence; gaps are detectable (AP-17). |
| `prev_hash` | Hash of the previous record on this node (chain). |
| `time` | Same shape as A4's `received` field: `utc`, `resolution_ns`, `clock.sync`, `clock.source` (A4 draft schema, PR #4; A4 sees no conflict with this table). |
| `actor` | `{type: human\|collector\|node\|system, id, role, auth_method, session_id}`. |
| `action` | Enum, e.g. `auth.login`, `auth.fail`, `role.grant`, `policy.apply`, `credential.replace`, `device.session.open`, `device.op`, `device.session.close`, `enroll.*`, `forward.config`, `audit.export`, `clock.change`, `storage.alarm`, `service.start`, `service.stop`. |
| `target` | `{asset_id, address, transport, downstream_security}` for device actions. |
| `operation_id`, `register_version` | For `device.op`. |
| `params_digest`, `bytes_sent_digest` | Hashes, not values: lets A6 reconcile against the recording simulator without storing sensitive parameters. |
| `outcome` | `allowed`, `denied`, `failed`, `succeeded`, with `reason_code`. |
| `policy_version` | Policy bundle in force. |
| `correlation_id` | Links to the collection job and resulting events. |

Never present: secrets, full configurations, raw device output (that belongs to the evidence store, not audit).

### 4.5 Insecure downstream transports

- Every asset carries `downstream_security`: `encrypted-authenticated` (e.g. SSH with pinned host key), `encrypted-weak` (e.g. TLS with 1024-bit RSA self-signed certificate, as documented for ABB 615 `[doc]`), or `plaintext-unauthenticated` (Telnet, FTP, serial, serial-over-IP).
- **Slice 1 (A1 ruling 2026-10-23): `encrypted-authenticated` devices only, with host keys pinned out of band.** The rest of this section applies from Phase 4, or earlier only if the owner decides otherwise.
- Plaintext is allowed only with a per-device admin acknowledgement that records the reason; the label is shown wherever the device appears and in every `device.*` audit record.
- Plaintext never crosses the WAN: the node is collocated with the IEDs it collects from. Credentials sent in plaintext on the station LAN are exposed to anyone there (AC-10); this residual risk is recorded per device, and unique per-device credentials limit its spread.
- Server identity: SSH host keys and TLS certificates are pinned at commissioning with out-of-band verification; on mismatch the node sends nothing, stops collection for that device, and alarms (A6 V-S14). The asset record binds the device-reported identity to the pinned key; a change of either without an approved re-commissioning record has the same effect (A6 C-07). Plaintext transports cannot authenticate the device at all; that is part of the label.

### 4.6 Failure behaviour

- Policy bundle unverifiable, credential store locked, register signature invalid, or egress check failed → no device I/O, alarm (fail closed, SC-18).
- Device authentication failure → one attempt only, no retry with the same credential, alarm (AP-13).
- Collection stopped for any reason → observable as an alarm with the time it stopped (P5).

## 5. Experiment E1: SSH gateway controls (`[exp-sim]`)

Location: `modules/access/experiments/e1-ssh-forward-controls/` (README, `run.sh`, mocks, recorded output `results-2026-10-23.txt`). OpenSSH 9.6p1 on loopback; mock line-oriented "IEDs" log every byte received. Run three times after A1's and A6's reviews (real `/bin/bash` login shell, T4b, A6's probes T9–T11, and T9r); 14/14 checks passed on each run.

| Check | Result |
| --- | --- |
| T0 key authenticates (precondition so refusals are policy, not auth failures) | pass |
| T1 approved device:port reachable through the tunnel | pass |
| T2 different device refused; 0 connections reached it; sshd logged the denial | pass |
| T3 different port on the approved device refused; 0 connections | pass |
| T4 remote command refused after successful authentication, with a real bash login shell (refusal comes from the key's forced command) | pass |
| T4b interactive shell with forced TTY refused (PTY allocation denied) | pass |
| T5 reverse forward refused; nothing listening on the gateway | pass |
| T6 **limitation:** a `WRITE` line passes through the approved tunnel and reaches the device | confirmed |
| T7 **limitation:** the device sees only the gateway's address | confirmed |
| T8 termination: killing the session process closed a held application connection in 0.013–0.014 s | pass |
| T9 (A6) **limitation:** after the kill, the same key re-establishes access at once, so T8 is termination, not revocation | confirmed |
| T9r revocation: key removed from authorized keys, then sessions killed → re-authentication denied | pass |
| T10 (A6) `ssh -W` stdio forward to an unapproved device refused, 0 connections | pass |
| T11 (A6) sftp subsystem refused | pass |

What E1 does not show: behaviour with real IEDs or real engineering tools; anything about Telnet, FTP, or serial; revocation in a production gateway (we killed processes by name); session expiry (OpenSSH has no native session lifetime, so expiry must be an external timer using the same kill path). An early run produced false "passes" for T4 and T5 because authentication was failing; the T0 precondition was added to prevent that and is worth copying into A6's harness. A1's review found that the first version's T4 refusal came from the account's `nologin` shell rather than an sshd or key restriction; the account now has a real shell and T4b was added. A production gateway must still be tested the same way (ForceCommand or forced key command, `PermitTTY no`, with a real shell).

## 6. Coordination record

- **A5** `[peer]`: agreed six site-to-central rules (site-initiated mTLS, no exec channel, signed bundles under a site ceiling, credentials at site, offline-signed updates, independent site operation). A3 accepted A5's three amendments: anti-rollback floor, local listener on management interface only, storage-full policy. A3 review of the storage-full policy sent to A5: alarm must carry stop time and device-buffer overwrite estimate; separate quotas for syslog and SER (AP-19); drop counters persisted and forwarded. A5 leans to Go; acceptable from a security standpoint (memory safety, `x/crypto/ssh`).
- **A2**: answered all five questions (A2 findings §11). Enforcement-point decisions for D1, D2, D4–D10 are in §8.
- **A6** `[peer]`: incorporated B-04, B-05, C-08, C-12 and mapped AP-1, AP-4, AP-12, AP-20 to V-S11, C-12, V-S14, V-S15. Cross-review requested.
- **A6 items routed by A1** (from `A6-handoff.md`): B-04 credential storage on site nodes → section 4.2 and AP-1, SC-5; B-05/C-07 device identity trust, no unconfirmed TOFU, bind reported identity to host key, fail closed on change → section 4.5 and AP-12, SC-8; C-08 device output as untrusted input reaching the SIEM → AP-11, AP-20, SC-14, SC-16; C-12 collector credential may permit more than monitoring → AP-4, HR-2, layer L5, `CredentialRef.access_level` ceiling. For plaintext transports (Telnet, FTP) B-05 cannot be met by the transport at all: identity can only be checked *after* credentials are sent. A3 proposes that A1 treat this as a residual risk to accept per device, or exclude plaintext-only devices from slice 1.
- **A4** `[peer]`: replied 2026-10-23 (A4 findings §5, PR #4). Forwarding mode A is RELP over TLS with a bounded response grammar and a parser whose only output is acknowledged txnrs (TB5, AP-9 updated). AP-20 is implemented in A4's profile: octet counting, device text only in escaped SD, base64 for non-printable bytes, origin set by the collector; 0 forged messages in 10 hostile cases against stock rsyslog, versus 2 of 10 with newline framing (`[exp-sim]`, A4's experiment). HR-3 accepted with two conditions (marker carries no derivative of the secret; echoed password characters redacted too). Audit `time` reuses A4's `received` shape. Original requests were: AP-20 forwarding rules (octet-counted RFC 5425 framing, escaping), "no secrets or configurations forwarded", and agreement on HR-3 (login phase not byte-exact evidence) and on sharing the timestamp model with audit records.

## 7. Proposals for A1-owned documents

1. **`docs/architecture.md` Q-table:** Q1 → "partially answered: transparent proxying of arbitrary tools rejected; hybrid P-aware/W/P-tcp proposed; needs X1–X4 with lab and licences". Q7 → "answered yes; 21 paths with mitigations and tests in threat-model.md; none implemented".
2. **Architecture-critical risks (exit gate)** from A3: (a) device access levels may not separate read from write (HR-2); (b) plaintext shared-password IEDs make the site node's credential store a single point of compromise (HR-1); (c) central server as a fleet-wide command path (AP-7); (d) engineering access cannot give per-operation control for arbitrary tools (HR-4); (e) device output as an injection vector into parsers and the SIEM (AP-11, AP-20).
3. **Clarify R8.5:** "credential rotation" means platform credentials and certificates; IED credential rotation is a state-changing engineering operation outside slice 1 (HR-5).
4. **ADR candidates:** (a) *Read-only enforcement in depth* (L1–L7), for Phase 1; (b) *Site-to-central trust and command surface* jointly with A5, for Phase 1; (c) *Engineering access approach*, Phase 4, after X1–X4.
5. **Contract inputs for Phase 1:** `CredentialRef` (4.2), operation classes and role matrix (4.1), audit minimum fields (4.4), `downstream_security` asset attribute (4.5).
6. **Ruling needed on HR-3:** the login phase of a device session is recorded as a marker, not bytes, in preserved evidence.

## 8. Enforcement-point decisions for A2's device risks (added 2026-10-23)

Input: A2 findings `docs/phase0/A2-device-feasibility.md` §5, §6, §11 (branch `claude/project-thread-8k8qrr`, PR #2). Primary family: SEL relays speaking SEL ASCII, SEL-751 reference. All A2 facts are `documented-untested`.

### 8.1 Decisions

| A2 risk | Decision | Enforcement point (layer) | Verification |
| --- | --- | --- | --- |
| D1 Level 1 is not read-only (`TRI`, `2AC`, `BAC`) | Only exact complete lines from the register allow list may be sent. `TRI` and every elevation command are denied. `ACC` is sent only by the transport's authentication phase, never by an adapter. | Register (L2), adapter rendering (L3), transport egress exact-line check (L4). | A6 recording simulator: every deny-list line attempted through the adapter API reaches the simulator zero times. |
| D2 Three bad passwords close the ALARM contact | One authentication attempt per invocation. On failure the `CredentialRef` becomes `suspended`, persisted at the node so it survives restart, and is cleared only by an admin replacing the credential (audited). The scheduler never retries a suspended credential, and no code path guesses or tries default passwords (D13). Note that a refused elevation prompt also counts toward the three; this is a further reason elevation is never sent. | Transport authentication phase; credential store state. | Simulator with a wrong password: exactly one attempt across a 24-hour simulated schedule and a node restart. |
| D4 Control and settings at Levels B and 2 on the same session | The collection-plane credential store refuses to hold any SEL credential above Level 1 (`access_level` ceiling `ACC`). Level B and 2 passwords never exist on a collection node. | Credential store (SC-5, SC-6). | Attempt to store a Level 2 credential → rejected and audited. |
| D5 Binary Fast Operate frames (`0xA5 …`) may be accepted on the ASCII port | Agree with A2's byte filter, placed in the transport egress check (L4) on the application payload *before* Telnet encoding: only 0x20–0x7E plus CR and LF; anything else aborts the session before any byte is written. The Telnet layer itself may emit only a fixed set of option-refusal responses (`IAC WONT`, `IAC DONT`) and never `IAC` data from the payload. | Transport egress (L4); Telnet layer. | A6: inject every non-printable byte value, including `0xA5 0xE0`, `0xA5 0xE3`, `0xFF`, through each adapter parameter; the simulator receives none, and the session aborts with an audit record. |
| D6 SEL-400 Level 1 transparent connections | SEL-400 series out of slice 1. Transparent-connection and port commands are not in the allow list. Tracked as AP-21. | Register (L2), egress (L4). | AP-21 test. |
| D7 Cleartext Telnet, shared per-level passwords | Node collocated in the relay's zone; never across the WAN. Platform audit carries the attribution (the device cannot). Asset labelled `plaintext-unauthenticated`. Unique Level 1 password per relay is recommended to the asset owner, though the platform cannot enforce it. Conflicts with A1's provisional slice-1 ruling; see 9.2. | Deploy (A5), asset record, audit. | Residual risk; recorded as HR-1 and HR-8. |
| D8 FTP uses access-level credentials and writes settings | FTP is out of slice 1. Site firewall permits the node to reach each relay only on its Telnet port, not FTP (21), HTTP, MMS (102), DNP3, or Modbus. | Site firewall (L6, A5 deploy). | Connection attempts from the node to the other ports fail. |
| D9, D10 Session contention, SER ring overwrite | Accept A2's controls: one short session per device, always `QUI`, minimum interval; overlap detection and gap reporting. These are availability controls; A3 adds that a gap must be an alarm, not only a metric (P5). | Scheduler (A5), adapter (A2), telemetry (A4). | A6 V-S4, V-S6. |

### 8.2 The slice-1 downstream transport conflict (HR-8)

A1 ruled slice 1 provisionally `encrypted-authenticated` only. A2 found no native SSH on the primary family. The options, for A1 to put to the owner:

| Option | Downstream security | What it costs | A3 view |
| --- | --- | --- | --- |
| a. Telnet from a collocated node | `plaintext-unauthenticated`. B-05 cannot be met: the node sends the Level 1 password before it can know it is talking to the real relay. | Accepting HR-1 and AP-12 as residual risk. | Acceptable **only** for simulator and lab work with lab-only credentials. Not acceptable for production without an explicit owner decision. |
| b. Serial (EIA-232) from the node | Physically point-to-point; no LAN exposure of the password; no impersonation over the network. | Needs a serial port per relay or a local serial server (which reintroduces a network hop if it is networked). Needs hardware to test. | Best security posture for the SEL family if the site has serial access. |
| c. SSH to an SEL-3620 or RTAC that talks Telnet or serial to the relay | Node→gateway `encrypted-authenticated` with pinned keys; gateway→relay as the gateway does it. | The gateway holds every relay password (SEL-3620 data sheet `[doc]`), becomes the high-value target, and adds a dependency on a product we do not control. | Valid production path where the gateway already exists; out of slice 1 scope. |
| d. Switch the slice-1 primary to A2's contrast family (IEC 61850 MMS log query) | Depends on the device's MMS/TLS support (IEC 62351-4), not yet read. | Delays slice 1; less like the brief's scenario. | Only if the owner rejects (a) for lab work. |

**A3 recommendation:** for slice 1, which runs against a simulator and recorded fixtures only, use (a) and label everything `plaintext-unauthenticated` with lab-only credentials. Make production use of Telnet collection conditional on the owner's explicit decision, with (b) as the recommended production path for this family. This keeps slice 1 moving without the team accepting a production security risk on its own authority.

### 8.3 SEL transport phases (A2 cross-review, part 1, 2026-10-23)

A2 reviewed §8.1 for IED compatibility and found it compatible with these adjustments, which A3 accepts. Sequence per A2 (SEL-300G quick start, SEL-421 Table 4.3, open-source client; `documented-untested`): CR, expect `=`; `ACC`, expect `Password:`; password line, expect `=>`.

- **Phase-aware egress check (L4).** The transport has three phases: *auth*, *operate*, *close*. `ACC` is accepted only in auth and `QUI` only in close; either one from an adapter is a violation (abort, audit). Adapters in slice 1 can therefore send only `ID` and `SER` lines.
- **Password line.** Exempt from the line allowlist only through the prompt-gated credential slot (§4.2); if the `Password:` prompt does not arrive, the secret is never sent and the session aborts (A6 R-A3-3: on a relay with passwords disabled the secret would otherwise execute as a command). Still subject to the 0x20–0x7E byte filter, and must contain no CR or LF. Its bytes are replaced by the redaction marker in the transcript (HR-3 ruling).
- **Auth outcome by prompt.** `=>` is success. A bare `=` or a second `Password:` is failure: the credential is suspended and nothing more is sent (D2). `=>>` or a prompt with a level letter is an unexpected level: send `QUI`, close, alarm. `ACC` that goes straight to `=>` (the level's password is disabled; A2's unverified recollection) is treated as success but raised as a security finding on that asset.
- **Mid-operation level drop.** If the prompt falls back to `=` during operate (idle timeout), the invocation fails; `ACC` is never re-sent in the same invocation.
- **`ID` runs after auth**, since whether it works at Level 0 is unknown.

- **Telnet options (A2 cross-review, part 2).** No SEL document read covers option negotiation; the open-source SEL client refuses every option (WONT to DO, DONT to WILL), which matches this design. Whether the SEL-751 works this way is unknown and is a hardware test. Expect the relay to echo the command line even with options refused (unverified).
- **Inbound bytes are preserved exactly.** The byte filter is outbound only. Inbound, the Telnet layer strips only IAC sequences; NUL (0x00), XON (0x11) and every other byte the relay sends are kept in the transcript, as the SEL client's code notes they matter. Parsers treat them as hostile input (AP-11).
- **HR-8:** A2 agrees with option (a) for simulator and lab only, and (b) serial as the production recommendation.

These become acceptance tests for A6's recording simulator: one test per prompt outcome above, plus `ACC` or `QUI` injected through an adapter.

### 8.4 SEL-751 instruction manual evidence (owner-supplied, 2026-10-23)

Source: *SEL-751 Relay Instruction Manual*, date code 20260910, copy supplied by the project owner (not committed to the repository). All items are `documented-untested`. Section, table, and setting names are given so they can be re-checked; page numbers were not extracted reliably.

| Finding | Where in the manual | Effect on A3 decisions |
| --- | --- | --- |
| No SSH and no Syslog anywhere in the manual. Telnet, FTP, and HTTP are described as plain text, and SEL "strongly recommends" a security gateway that provides encrypted communications, plus SEL SDN. | Whole-text search; Appendix B, firmware upgrade note. | Confirms A2 and HR-8. SEL's own guidance supports option (c) in §8.2 for production. |
| Ethernet Port 1 has a per-port access ceiling `MAXACC` (1, 2, C; default 2) and `FTPACC` for FTP (default 2). The manual frames `MAXACC` as least privilege per port. | Port 1 settings table (`ETELNET`, `MAXACC`, `TPORT`, `TIDLE`, `FASTOP`, `EFTPSERV`, `FTPACC`); "Authorization" in the security section. | Gives a **device-native ceiling** that stops elevation to Level 2 or C on the Telnet port if the owner sets `MAXACC := 1`. That partly restores L5 for elevation, though not for `TRI`. Trade-off: engineers could then not change settings over Ethernet on that port. This is the owner's setting to choose; the platform never changes it. |
| Binary Fast Operate on Telnet is governed by `FASTOP`, default `N` ("block binary Fast Operate messages"). | Port 1 settings; port settings description. | Resolves A2 D5's open question at documentation level: blocked by default. The printable-ASCII egress filter stays, because the setting can be changed. |
| Hardware jumpers: A = password bypass (Levels 1, 2, C reachable without passwords, up to `MAXACC`); B = breaker control enable (when off, `OPE`, `CLO`, `PUL` and Fast Operate breaker control are refused: "Command Aborted: No Breaker Jumper"). | Table 2.24 *Jumper Functions and Default Positions*; `OPE`/`CLO` command descriptions. | Jumper A confirms A6 R-A3-3: with passwords bypassed, `ACC` goes straight to `=>` with no `Password:` prompt, so the prompt-gated credential slot is required. Jumper B is a device-native barrier against breaker control by command, but not against settings changes. |
| Wrong password: the relay re-prompts (`Password: ?`) up to three times, then pulses the `SALARM` Relay Word bit for one second and stays at Level 0. `SALARM` is also pulsed after a *successful* Level 2 or C access. In the example settings, `OUT101 := HALARM OR SALARM` (alarm output contact) and `SER4 := SALARM` (the event is written to the SER log). | "Access Level Attempt" examples in Communications (SEL ASCII); self-test ALARM output description; example SELOGIC and SER settings. | Supports the one-attempt rule (D2) and never elevating. It also means the relay's own SER log can record access-level events. This is a partial device-side audit trail that A4's normalization should keep, and a cross-check that the platform never elevated. |
| Password with Level 1 disabled: `ACC` goes directly to Level 1 with no prompt. | "Access Level Attempt (Password Not Required)". | Same handling as jumper A. Raise a security finding on the asset (§8.3). |
| Passwords: up to 12 characters, case-sensitive, from the printable set in Table 7.54 (letters, digits, and listed specials; space is not listed). | Table 7.54 *Valid Password Characters*. | Write-time credential validation for this family: 1–12 characters from Table 7.54 only (sharper than the generic printable-ASCII rule). |
| Without `QUIT`, the relay "remains at an elevated access level until `TIDLE` expires" (default 15 minutes). | Telnet section note. | Confirms `QUI` in the close phase is mandatory. A dropped connection must be treated as possibly leaving the device at Level 1 until `TIDLE`. |
| Firmware can be upgraded over Ethernet by FTP, HTTP, or Telnet; each attempt pulses `SALARM` and writes an SER entry. | Appendix B, Ethernet firmware upgrades. | Firmware load is reachable over the same services the node uses. The commands are not in the allow list, and FTP and HTTP are blocked at L6. Recorded under AP-5 and D4. |

**Possible commissioning posture check (proposal for A2's register).** A read-only check that the device's port settings match what the threat model assumes: `FASTOP = N` on the Telnet port, and `MAXACC` as the owner has set it. It would run at commissioning and periodically. A2 must first confirm which `SHO` form reads port settings at Level 1, and that it does not reveal passwords.

**Owner-side hardening recommendations** (device settings, which the platform never changes): unique Level 1 password per relay; `FASTOP := N` on the Ethernet port; `EFTPSERV := N` or `FTPACC := 1` if FTP is not used for engineering; and considering `MAXACC := 1` on the port the collector uses, if engineering does not need that port.

## 9. Handoff

### Handoff P0-A3 — A3 — 2026-10-23
**Completed:** Threat model v0 (scope, assumptions, assets, 10 trust boundaries for T1 and T2, 11 actors, 21 Q7 attack paths each with mitigation, enforcement point, falsifiable test, and ATT&CK for ICS IDs; 18 controls with IEC 62443-3-3 and IEC 62351 alignment; 7 open high-risk concerns). Q1 comparison of P-tcp, P-aware, W, and G with recommendation and settling experiments X1–X4. Drafts: authorization boundary, credential reference model, read-only enforcement layers L1–L7, audit minimum fields, insecure-downstream policy, failure behaviour. Experiment E1.
**Evidence:** SEL-751 Instruction Manual date code 20260910 (owner-supplied, §8.4); ABB 1MRS758280 rev C; Siemens SSA-899560; SEL-3620 product page and data sheet; IEC TS 62351-8 preview (titles only); ATT&CK for ICS list retrieved 2026-10-23; E1 scripts and `results-2026-10-23.txt` (`simulated`, loopback mocks, three runs, 14/14 after A1's and A6's reviews).
**Interfaces:** none approved. Drafts for Phase 1: `CredentialRef`, operation classes, role matrix, audit fields, `downstream_security`.
**Limitations:** no hardware; no vendor engineering software exercised; standards mapped at requirement-title level only; IEC 62351-8 role names unverified; A2 device facts not yet received.
**Risks:** HR-1 to HR-7 in the threat model; the most consequential are HR-2 (device access levels) and AP-7 (central as fleet-wide command path).
**Dependencies:** A2: facts received; enforcement points decided in §8. A1: take HR-8 (slice-1 downstream transport) to the owner. A4: AP-20 forwarding rules, HR-3. A5: write the agreed site-to-central rules into the runtime proposal. A6: cross-review of this file and the threat model; adopt E1's T0 precondition pattern. A1: rulings on R8.5 and HR-3; transfer section 7 proposals.
**Files changed:** `docs/threat-model.md`, `docs/phase0/A3-security-feasibility.md`, `modules/access/experiments/e1-ssh-forward-controls/` (README.md, run.sh, mock_ied.py, probe.py, results-2026-10-23.txt).
**Reviewer(s) and outcome:** A1 accepted P0-A3 on 2026-10-23 after re-running E1; review note on T4 fixed (real login shell, T4b added). A2 (IED compatibility): compatible with adjustments, applied in §8.3; agrees with the HR-8 recommendation. A6 (independent security review): accepted for Phase 0 with changes R-A3-1 to R-A3-5, applied (layer independence restated, revocation vs termination with E1 T9/T9r/T10/T11, prompt-gated credential slot, TB5 acknowledgement open with A4, AP-17 window stated).

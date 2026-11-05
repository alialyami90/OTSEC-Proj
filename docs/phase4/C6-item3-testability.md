# Phase 4 item 3: are V-M1, V-M7 and V-M8 testable as written? (C6, P4-3-A6)

Date: 2026-11-05. Owner: C6. Brief: P4-3-A6, third deliverable (`docs/agent-handoffs.md`, "Phase 4 item 3: Stage A briefs").

This note checks each pass condition of V-M1, V-M7 and V-M8 (`docs/verification.md`, #144) against what a test can observe on the real binaries. The thresholds are not changed. Where a condition can be read more than one way, or cannot be observed until a contract says something it does not say yet, the condition is listed as a question for C1. Each question gives the reading C6 proposes, so the contracts can be approved with an answer. Evidence class: `desk`. No device was contacted.

**Summary.** The three criteria have 16 pass conditions.
- 8 are testable as written, given the contracts the briefs ask for.
- 6 need an answer first.
  - Five of those need it before the contracts are approved: V-M1 (c), (d) and (e), and two of V-M7's, through Q1 to Q7.
  - The sixth is V-M8's paired captures, through Q12. That is a test-method question, not a contract question.
- 2 need a line of contract text: Q10 and Q11.
- Q8 and Q9 record how C6 reads two conditions that are already testable.
- One finding changes what item 3 can show on the SEL-751: F1, at the end of this note.

## V-M1 (R1.8): the asset module and SNMPv3

| Condition | Testable as written? | How C6 tests it |
| --- | --- | --- |
| (a) With `modules/asset/` disabled, every other module's tests pass, and GT-MIB receives zero PDUs. | Yes, read as in Q8. | The real-binary suite runs with the module disabled in the node configuration. One more run uses a configuration that names an SNMPv3 asset but disables the module. GT-MIB's PDU log must stay empty in both. |
| (b) Every PDU GT-MIB receives is `GetRequest`, `GetNextRequest` or `GetBulkRequest`, never `SetRequest`, across the whole suite, including under fault injection. | Yes. | GT-MIB logs every PDU it decodes, including ones it cannot authenticate, and the check runs over all logs of the suite. Fault injection covers timeouts, `authorizationError` and malformed responses, plus a report PDU in place of a response. Discovery's empty `GetRequest` counts as a `GetRequest`. |
| (c) SNMPv3 runs only at `authPriv`. An agent offering `noAuthNoPriv` or `authNoPriv`, a wrong user, wrong keys or a wrong engine ID gets no fallback, and the failure shows in health. | Only in part: Q1 and Q2. | GT-MIB profiles each refuse in one way (`usmStatsUnsupportedSecLevels`, `usmStatsUnknownUserNames`, `usmStatsWrongDigests`, `usmStatsDecryptionErrors`, and an unexpected engine ID). The log must show that no later PDU uses a lower level, another user, or v1 or v2c. The health code named in the contract must appear. |
| (d) v1 or v2c only for a device with an owner approval record in the audit chain, and refused without one. | The refusal half, yes. The other half depends on Q3. | A configuration naming v1 or v2c with no approval is refused, with GT-MIB receiving zero PDUs. |
| (e) Every identity attribute read equals the GT-MIB value field by field, and carries its source. | Yes, once Q4 fixes one vocabulary. | Each stored attribute is compared with GT-MIB's served value, raw bytes first and then the parsed field, under the parse the plan states. |
| (f) A family with no SNMP agent (the SEL-751) gets its identity from its registered path, labelled, and no SNMP packet is sent to it. | Yes. | The SEL-751 identity carries `device-read` with the path `sel.id`. A capture on the simulator's address shows no UDP to port 161 or 162. |

**Q1. Is the engine ID pinned?** A "wrong engine ID" is testable only if the client expects a particular authoritative engine ID for each device. Two ways would give that: it holds keys localized to that engine ID, or the node configuration or C1 record names it. If the client stores the passphrase and localizes it to whatever engine ID it discovers, a wrong engine ID simply succeeds, and the condition cannot fail.
- *Proposed reading:* the engine ID is part of the device's SNMPv3 credential and is pinned. A discovered engine ID that differs is refused, with its own health code. C2 and C3 put this into C3 0.4 and the key register row.

**Q2. Does an algorithm count as a level?** USM `authPriv` can run on MD5 or SHA-1 with DES, which is authenticated and encrypted in name only. The SEL-2731 and 2741 in RSTP mode refuse DES (S29 p. 43). The SEL-2730M's algorithms are not yet in our matrix.
- *Proposed reading:* the client uses only the algorithms configured for the device and never falls back to another. That is tested like a level fallback: GT-MIB offers a weaker algorithm, and the log must show that none is used. Which algorithms may be configured at all (no DES, no MD5) is C3's threat-model call. Whatever C3 rules, GT-MIB then offers the refused ones as negative cases.

**Q3. Is there a v1 or v2c path in item 3?** The C2 brief excludes one in this stage. If none is built in item 3, the half of (d) that says "used only with an approval" is vacuous, as V-M3's lower rung was (D4-40 point 3). The refusal half still holds. *Proposed reading:* item 3 tests the refusal only, and the gate states that (d) is shown for the refusal alone.

**Q4. One vocabulary for the source.** V-M1 (e) names the sources `snmpv3`, "another registered path", `passive` and `operator`. "R9 classes and what `confirmed` needs" names `device-read`, `passive` and `operator`, with the read path beside `device-read`.
- *Proposed reading:* C1 0.3 stores a kind (`device-read`, `passive` or `operator`) and, for `device-read`, a path such as `snmpv3` or `sel.id`, plus an evidence ID. V-M1 (e) is then checked on the path, and V-M7 on the kind.

## V-M7 (R9.1, R9.2): applicability classes over GT-ADV

| Condition | Testable as written? |
| --- | --- |
| The class equals GT-ADV's, per cell. | Yes, once Q5 and Q6 fix the class for two input states that the rules do not cover. |
| Every finding lists the evidence IDs that made it so. | Yes. GT-ADV states which evidence each cell needs: the identity read, a settings read, and a control record. |
| An operator-entered or passively inferred identity never yields `confirmed`. | Yes. GT-ADV has these rows. |
| An unread precondition leaves the finding `applicable-by-version`, with that precondition named. | Yes. |
| A later contradicting device read reclassifies the finding at the next evaluation and records the change. | Only once Q7 defines "next evaluation". |
| No finding states that a device is exploitable. | Yes, read as Q9. |

**Q5. A precondition that was read and does not hold.** The rules cover a precondition that holds (`confirmed`, if the rest hold) and one that was not read (`applicable-by-version`). They do not say what a precondition read as false gives. An example is an advisory that needs the web server enabled, on a relay that reads `EHTTP := N`. That case is exactly the SEL-751's R400 to R402 condition. Three readings are possible:
- `not-applicable`, citing the settings read;
- `mitigated`, when the advisory or the vendor names turning the service off as a mitigation;
- `applicable-by-version`, with the precondition shown as read and false.

*Proposed reading:* `not-applicable`, citing the settings read, when the identity is device-read. It is `mitigated` only when the advisory itself names that setting as a mitigation. With an operator or passive identity, the version itself is not device-read, so the finding stays `applicable-by-version`, with the precondition shown as evidenced false. GT-ADV has cells for each of these.

**Q6. Precedence, staleness and a passive identity out of range.**
- (i) When every precondition holds and a mitigation is also evidenced, *proposed:* `mitigated`.
- (ii) A `confirmed` finding whose evidence stopped being current, through a later contradicting read or a configuration change retrieved since. *Proposed:* it falls to `applicable-by-version`, and the finding names the stale evidence. It does not fall to `not-applicable`, because the version is still in range until a new read says otherwise.
- (iii) A passively inferred identity outside the affected range. The rules give `not-applicable` for a device-read identity and `not-applicable (operator)` for an operator-entered one, and say nothing about a passive one. *Proposed:* treat it like an operator identity, with its own label `not-applicable (passive)`. This needs C12 to allow that label. The alternative is to fold it into `not-applicable (operator)`, but then the source is misnamed.
- (iv) An advisory with no preconditions, on a device-read identity in range. Read literally, it is `confirmed` on the version read alone. Under condition 3, any configuration change retrieved after the identity read makes it stale until the next identity read. *Proposed:* yes to both. A configuration change makes every `confirmed` finding on the asset stale, whatever the advisory reads, because the rule does not say which changes matter.

**Q7. When is "the next evaluation"?** A test needs a bound on when reclassification must have happened.
- *Proposed reading:* evaluation runs after each commit of an identity record, a settings read or a configuration record for the asset, and after each set replacement. The finding's change is in the store before the next scheduled read of that asset starts.
- The test steps the test clock past the contradicting read and checks the finding before the next read's time, the way V-M4 checks its acknowledgement.

## V-M8 (R9.3, R9.4): the advisory set, and no probing

| Condition | Testable as written? |
| --- | --- |
| An unsigned, wrongly signed, truncated or older-version set is refused, the set in use stays in use, and the refusal is in health and the audit chain. | Yes, once Q10 settles a set of the same version. |
| An entry with no published source is refused. | Yes, once Q11 says whether the entry or the set is refused. |
| Every report carries the set's version and date. | Yes. C12 has both fields. |
| During a full applicability run, the node opens no outbound connection and sends no packet to a device beyond the collection schedule. | Yes, read as Q12. The paired-capture method is in the criterion. |

**Q12, the paired captures.** Three points need settling before the method can be applied as written.
- **"No outbound connection."** In every slice run, the node opens outbound connections it always opens, such as the RELP forwarder to the upstream receiver. *Proposed reading:* the operative test is the one the criterion gives, that the R9 run has no flow the R9-disabled run lacks, over every destination and not only devices. That also catches an internet fetch.
- **Ports.** The harness picks free ports for each run, so the paired runs must fix every listening port, or the flows must be compared by role. *Proposed:* fix the ports for the two runs.
- **Packet counts per collection session.** TCP's packet count can differ between identical runs: delayed ACKs, coalescing and retransmits depend on timing. Before relying on it, C6 runs two R9-disabled runs (A/A). If the A/A counts differ, the criterion is not testable as written. C6 then brings C1 the measured difference and a proposal to compare the application bytes per direction per session instead. Until then nothing is changed.
- **Capture scope (C3 on #436).** The capture covers every interface on the Linux runner, not only loopback (`tcpdump -i any` under `sudo`), because a DNS lookup or an internet fetch would leave through the runner's real interface. It includes the collector's device sessions. The flow comparison covers TCP, UDP and ICMP, so a lookup or a ping counts as a flow the R9-disabled run lacks.

## Smaller points (answerable in the contract text)

- **Q8, on V-M1 (a).** "Every other module's tests pass" is read at the binary level: the real-binary suite with the module disabled. Go unit tests do not depend on node configuration, so they pass whether the module is on or off.
- **Q9, on V-M7.** "No finding states that a device is exploitable" is tested in two ways. First, C12 has no field for exploitability, risk or severity of attack. Second, if C12 has any free text, the test scans every stored finding for a fixed word list (`exploitable`, `exploit`, `vulnerable to attack`, `attackable`). C4 can avoid free text altogether, and then only the schema check remains. A finding names its C11 entry by ID and never copies the entry's title or text (C3 on #436), so advisory wording cannot reach a finding.
- **Q10, on V-M8.** A set with the same version as the one in use. *Proposed:* refused unless it is byte-identical to the set in use, and a byte-identical one is a no-op. Either way the set in use stays in use, and only a refusal is audited.
- **Q11, on V-M8.** An entry with no published source. *Proposed:* the whole set is refused, as for a truncated one. Refusing only the entry would make the set in use differ from the signed set.

## F1: on the SEL-751, a device-read identity exists only on allowlisted firmware

The collector reads `ID` at Level 0 only for an asset whose declared FID is on register revision 5's allowlist. A declared FID on R302 or older is refused before any session, with `refused.firmware_not_allowlisted` (`modules/ied/sel751/run.go`; ADR-0005). For those relays, the only identity the platform holds is the declared FID, which is `operator`-entered. So on the SEL-751:
- For R400 to R501, the identity can be `device-read`, and R400 to R402 also read `EHTTP` by `SHO P 1`. Every V-M7 class can be reached on these branches.
- For R302 and older, the identity is `operator` only. Those relays can get `applicable-by-version` or `not-applicable (operator)`, never `confirmed`. Yet these are the firmware lines that Appendix A shows lack the most fixes.

This follows the rules. It is not a defect. But the brief's line "R9 on the SEL-751 … V-M7 can reach every class" holds only for allowlisted FIDs. GT-ADV includes denied-branch rows with operator identity to pin this.

Whether a Level 0 `ID`-only session should be allowed on a denied branch is a safety question for C1, C2 and C3: F5's restart defect is in communications-port access. It is not a test question, and C6 does not propose it.

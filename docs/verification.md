# Verification

Owner: A6 (independent verification and OT safety). A6 writes this document independently of the implementing agents and actively attempts to disprove their claims. Status: **no verification performed. No acceptance criteria approved yet.**

## Rules

- A test result is reported only with reproducible output committed under `tests/`.
- Every result states whether it ran against hardware, a simulator, or recorded fixtures.
- A critical unresolved safety or security failure blocks milestone acceptance regardless of other progress.
- Claims by implementing agents are inputs to verification, not evidence.

## Verification matrix

Maps each requirement in [requirements.md](requirements.md) to how it will be verified. Column "Needs hardware" marks tests that cannot be completed on fixtures or simulators alone.

| Requirement | Acceptance criterion (measurable) | Test location | Needs hardware | Status |
| --- | --- | --- | --- | --- |
| R1.x | to be defined | | | not defined |
| R2.x | to be defined | | | not defined |
| R3.x | to be defined | | | not defined |
| R4.x | to be defined | | | not defined |
| R5.x | to be defined | | | not defined |
| R6.x | to be defined | | | not defined |
| R7.x | to be defined | | | not defined |
| R8.x | to be defined | | | not defined |

## First vertical slice acceptance criteria

Target (brief, Phase 2): collect native SER records from a representative lab IED and securely forward them to an upstream Syslog collector, with local asset identification and evidence preservation.

Criteria to be made measurable before Phase 2 begins:

| ID | Claim to verify | Independent test | Status |
| --- | --- | --- | --- |
| V-S1 | Asset identity is correct against OEM documentation and actual device information. | | not defined |
| V-S2 | Normalized events match native events (fields, values, order). | | not defined |
| V-S3 | Timestamp precision is preserved end to end. | | not defined |
| V-S4 | Duplicate and missing events are detected and handled per contract. | | not defined |
| V-S5 | Monitoring permissions cannot invoke state-changing operations. | | not defined |
| V-S6 | Network interruption and reconnection do not lose or duplicate events beyond contract limits. | | not defined |
| V-S7 | No unauthorized IED write operations are issued (observed on the wire or device log). | | not defined |
| V-S8 | Raw device evidence is preserved alongside normalized output. | | not defined |

## Independent validation methods (from the brief, section 7)

- Asset identification: compare collected attributes against OEM documentation and actual device information.
- Configuration monitoring: apply a known change in a controlled environment and verify the expected meaningful difference.
- SER collection: reconcile original device events with collected and forwarded events (timestamps, order, duplicates, missing data).
- Secure access: demonstrate permitted operation, unauthorized access denial, session expiration, and revocation.
- IDS: labeled benign and malicious traffic; measure false positives, detection effectiveness, and latency.
- Distributed operation: simulate site disconnection, process termination, delayed events, and reconnection.
- OT safety: verify passive functions generate no control/write commands and approved reads stay within tested limits.

## Safety and security blockers

| ID | Blocker | Affects | Raised | Status |
| --- | --- | --- | --- | --- |
| (none yet) | | | | |

## Findings log

Independent findings, newest first. Each entry: date, what was tested, how, result, evidence path, and whether it disproves a claim.

(none yet)

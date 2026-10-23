# Device Capabilities

Owner: A2. Reviewed by A6 (device safety and correctness) and A3 (security-sensitive behaviour). Status: **no devices evaluated yet.**

Every capability claim in this document carries an evidence classification. A claim without a classification is invalid.

## Evidence classification

| Class | Meaning |
| --- | --- |
| `hardware-verified` | Demonstrated on physical equipment, with the firmware version, date, and reproducible procedure recorded. |
| `documented-untested` | Stated in OEM documentation but not exercised on hardware by this project. |
| `simulated` | Implemented and tested only against a simulator, emulator, or recorded fixture. |
| `unsupported` | Known not to work, or deliberately excluded. |
| `unknown` | Not yet investigated. |

A `simulated` result is never promoted to `hardware-verified` without a recorded hardware test.

## Candidate IED families

To be proposed in Phase 0 by A2. Selection criteria: availability of a lab unit or sanitized real outputs, representativeness, availability of primary documentation, and OT safety of the read-only collection mechanism.

| Family | Vendor | Candidate firmware | Lab availability | Rationale |
| --- | --- | --- | --- | --- |
| (none yet) | | | | |

## Capability matrix template

One section per supported IED family and firmware line. Copy the template below.

### `<Vendor> <Model>` — firmware `<version range>`

| Capability | Mechanism | Transport / auth | Classification | Evidence | Limitations |
| --- | --- | --- | --- | --- | --- |
| Asset identification | | | `unknown` | | |
| Configuration retrieval | | | `unknown` | | |
| Event / SER retrieval | | | `unknown` | | |
| Syslog emission | | | `unknown` | | |
| Available CLI commands (approved, read-only) | | | `unknown` | | |
| Remote engineering compatibility | | | `unknown` | | |
| Known firmware differences | | | `unknown` | | |
| Operational limitations and safety notes | | | `unknown` | | |

Evidence column points to primary material: fixture files under `tests/fixtures/ied/`, OEM document name and section, or a dated hardware test log.

## Approved command register

Every command an adapter may issue is listed here before it is implemented. Commands are classified `read-only` or `state-changing`; `state-changing` commands are never reachable through monitoring permissions (R5.3, R5.7).

| Device family | Command | Parameters (validated) | Classification | Timeout / rate limit | Pagination / prompt handling | Classification evidence |
| --- | --- | --- | --- | --- | --- | --- |
| (none yet) | | | | | | |

## Fixture inventory

Sanitized real device outputs live under `tests/fixtures/ied/<vendor>/<model>/`. Each fixture records its source device, firmware, capture date, and what was redacted.

| Fixture path | Device | Firmware | Source | Redactions |
| --- | --- | --- | --- | --- |
| (none yet) | | | | |

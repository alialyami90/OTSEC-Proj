# Architecture

Owner: A1. Status: **Phase 0 not started. No architecture has been selected.** Nothing in this document is decided until it is recorded in an ADR under [decisions/](decisions/).

## System boundary

To be defined in Phase 0. The boundary must state:

- What the platform observes (network segments, device interfaces, log sources).
- What the platform may touch (approved read-only operations only, by default).
- What the platform must never do (control or write operations on protection and control functions without separate, explicit authorization).
- Where the platform sits relative to substation LAN, station bus, process bus, engineering network, and enterprise/WAN.

## Alternatives under evaluation

Candidates to be compared with evidence, not preference. Each comparison ends in an ADR.

| Topic | Alternatives | Owner of investigation |
| --- | --- | --- |
| Runtime shape | Modular monolith with deployable edge components; service-per-module; hybrid | A5, reviewed by A1 and A3 |
| Engineering access | Protocol-level proxying; controlled remote engineering workstations; per-application gateways | A3, reviewed by A2 |
| IDS engine | Zeek; Suricata; protocol libraries plus custom rules; combination | A4, reviewed by A2 |
| Event transport and buffering | To be enumerated against R4.7 and R8.6 | A5, reviewed by A4 |
| Persistence | To be enumerated against R8 and storage-exhaustion behavior | A5, reviewed by A6 |

## Architecture-critical questions

From the brief, section 3. Each must be answered with evidence before it is treated as resolved.

| ID | Question | Owner | Status |
| --- | --- | --- | --- |
| Q1 | Can arbitrary engineering applications actually be proxied? | A3 | open |
| Q2 | Can all desired IED configuration data be safely retrieved? | A2 | open |
| Q3 | Can different vendors' SER records be accurately normalized? | A4 with A2 | open |
| Q4 | Can passive monitoring observe sufficient network traffic for reliable IDS? | A4 | open |
| Q5 | Can a common adapter framework represent vendor-specific behavior without excessive complexity? | A2 | open |
| Q6 | Can centralized and distributed operation share a maintainable foundation? | A5 | open |
| Q7 | Could the application create a new attack path into OT assets? | A3 with A6 | open |

## Module boundaries

The directory layout in the repository README reflects the initial ownership from the brief. Module interfaces are defined in `contracts/` and must not be invented independently by module owners.

Contracts required for the first vertical slice (to be approved in Phase 1):

- Asset identity model.
- Device capability model.
- Event and timestamp schema.
- Adapter invocation and result contract.
- Error and timeout semantics.
- Authentication and authorization boundaries.
- Inter-module communication.
- Persistent data ownership.
- Audit event format.
- API versioning and compatibility expectations.

## Critical dependencies

To be filled in Phase 0. Expected shape: which module depends on which contract, and which investigations block which contracts.

## Phase 0 exit gate

The team does not advance to major implementation until all of the following are recorded here or in ADRs:

- [ ] Five architecture-critical risks identified.
- [ ] A plausible initial architecture established.
- [ ] The initial implementation scenario selected (brief default: collect native SER records from a representative lab IED and forward securely to an upstream Syslog collector, with local asset identification and evidence preservation).
- [ ] Required contracts defined.
- [ ] Objective acceptance criteria established in [verification.md](verification.md).
- [ ] Unsupported assumptions marked.

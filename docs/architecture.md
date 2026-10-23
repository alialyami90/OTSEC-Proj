# Architecture

Owner: A1. Status: **Phase 0 in progress (2026-10-23). Provisional architecture drafted by A1; no architecture is selected until recorded in an ADR under [decisions/](decisions/).** Sections marked *provisional* are A1's working position, to be confirmed or overturned by the Phase 0 findings of A2–A6.

## System boundary

*Provisional, A1, 2026-10-23.* Zone names follow IEC 62443-3-2 zone and conduit terminology (alignment, not certification).

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

- Only commands in the approved command register (`docs/device-capabilities.md`) classified `read-only`, invoked through the adapter executor, on devices the owner has listed for collection. Default for every device is "not collected".

### What the platform must never do

- Issue control operations (for example DNP3 operate, IEC 61850 control, GOOSE publication), settings writes, firmware uploads, or buffer-clearing commands, through any monitoring path.
- Perform active discovery or scanning on production networks without explicit, per-scan owner authorization.
- Transmit on a passive sensor interface.
- Let the central server or WAN reach a device directly. Central may change a site node's policy only within limits the site enforces locally (A3/A5 to define the allowed instruction set).
- Sit in the protection or control path. If every platform component stops, protection, control, and SCADA continue unchanged (R8 constraint).

### Evidence ceiling for the first slice

Owner decision, 2026-10-23: no lab IED and no real device outputs are available. The first slice is built and verified against OEM documentation and a device simulator only. No capability in this milestone can be classified above `documented-untested` or `simulated`. A6 builds the simulator independently from A2's cited documents, not from A2's code, so a misreading is not shared by parser and simulator.

## Provisional runtime shape

*Provisional, A1, pending P0-A5 (runtime) and P0-A3 (trust boundaries).*

| Option | Summary | A1 assessment before evidence |
| --- | --- | --- |
| A. Modular monolith | One codebase and one process per node; modules are in-process packages behind contract interfaces; the same build runs in `site`, `central`, or `single` role with modules enabled per role. | Simplest to build, test, and upgrade (P8, P9). Weakness: device credentials and device-facing code share a process with everything else. |
| B. Service per module | Each module is its own deployable service with network APIs and a broker. | Adds network, broker, and version-skew failure modes at every site with no requirement that needs them yet. Not justified by R7 alone (R7 asks for modularity, not distribution). |
| C. Monolith plus isolated executors | Option A, plus a small number of separate OS processes where a security boundary is needed: the adapter executor (holds device credentials, speaks to IEDs, accepts only register-listed command IDs) and, later, the packet sensor (Zeek or Suricata run as external processes anyway). | A1's working position. The split is justified by privilege separation (Q7, P4), not scale. Each extra process must name the boundary it enforces. |

## Critical dependencies for the first slice

| Deliverable | Depends on | Blocks |
| --- | --- | --- |
| Toolchain and runtime ADR (A5 → A1) | P0-A5 | All Phase 2 code |
| Primary IED family, SER format, command register (A2) | Owner input on hardware or real outputs; OEM docs | Event schema, adapter contract, device simulator |
| Event and timestamp schema (A4) | A2 SER format plus a second vendor's format | Outbox idempotency key (A5), forwarding profile, V-S2/V-S3 |
| Credential reference and read-only enforcement points (A3) | A2 transports and access levels; A5 process model | Adapter contract, V-S5/V-S7 |
| Outbox and delivery semantics (A5) | A4 event identity | V-S4/V-S6 |
| Device simulator and write-detection method (A6) | A2 command register and SER examples | Independent verification of the whole slice |

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

## Phase 0 exit gate

The team does not advance to major implementation until all of the following are recorded here or in ADRs:

- [ ] Five architecture-critical risks identified.
- [ ] A plausible initial architecture established.
- [ ] The initial implementation scenario selected (brief default: collect native SER records from a representative lab IED and forward securely to an upstream Syslog collector, with local asset identification and evidence preservation).
- [ ] Required contracts defined.
- [ ] Objective acceptance criteria established in [verification.md](verification.md).
- [ ] Unsupported assumptions marked.

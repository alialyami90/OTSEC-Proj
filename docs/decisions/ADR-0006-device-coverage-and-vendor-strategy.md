# ADR-0006: Device coverage scope and vendor strategy (SEL first)

- Status: accepted
- Date: 2026-10-23
- Deciders: project owner (scope), A1 (architectural consequences)
- Related: R1, R5, P7; ADR-0002, ADR-0005; `docs/requirements.md` "Device and vendor scope"

## Context

The brief centred on IEDs. On 2026-10-23 the project owner widened the scope: the platform must cover all OT device classes found in substations and control networks (for example servers, workstations, historians, switches, routers, time servers, RTUs), and support is to be built vendor by vendor, starting with complete coverage of SEL devices; other vendors follow once the product is complete for SEL.

## Options considered

1. Breadth first: shallow, vendor-neutral coverage of every class from the start.
2. SEL first, depth per SEL product family, with vendor-neutral mechanisms only where they need no vendor-specific code.
3. Keep the original IED-only scope.

Option 3 contradicts the owner's instruction. Option 1 conflicts with P7 (interoperability must be proven) and would spread verification thin. The owner chose option 2.

## Evidence

Owner instruction (project thread, 2026-10-23). SEL product facts below are A1 recollection unless cited, and A2 must confirm each against SEL documentation before it enters `docs/device-capabilities.md`.

## Decision

1. **Device classes in scope** for inventory (R1) and, where a safe read-only mechanism exists, for monitoring, events, and configuration baselines: protective relays and other IEDs; RTUs, automation controllers, and communications processors; Ethernet switches; routers, security gateways, and firewalls; time servers and satellite clocks; servers and computers; engineering workstations and HMIs; historians; meters; port servers and serial communications equipment.
2. **Vendor strategy.** SEL is the only vendor with vendor-specific adapters, parsers, and capability profiles until the owner declares the SEL product complete. Each SEL product family is supported only when its capability matrix rows reach the evidence class required by `docs/verification.md` (P7). "All SEL devices covered" is a goal tracked per family, never a blanket claim.
3. **Vendor-neutral mechanisms** that need no vendor-specific code apply to every device from the start: passive network observation (R6, later phase), receipt of device-sent Syslog (R4.1), and recording of operator-entered asset data with its evidence source. Active vendor-neutral queries (for example SNMP reads, Windows event collection, SSH to network equipment) are adapters like any other: registered operations, read-only classification, explicit per-device approval, and the same enforcement layers.
4. **Non-SEL products in SEL-centric classes** (for example a third-party historian or general-purpose servers) are covered by the vendor-neutral mechanisms only, with their limits recorded, until a later vendor phase.
5. **Architecture impact.** None to ADR-0002 to ADR-0004: the collector process, register, adapter envelope, and store are vendor- and class-neutral by design. The asset model (contract C1) must carry a device class and a vendor/product family, and the capability profile must allow profiles for non-IED classes. The first slice (ADR-0005, SEL-751) is unchanged.
6. **Q5 contrast family.** The paper exercise that tests the adapter envelope uses a second SEL product class instead of a second vendor: an SEL automation controller (RTAC) is the default candidate, because it differs in transport (SSH), operating model, and logging from an SEL ASCII relay. A2 to confirm.

## Consequences

- R1 gains device-class and vendor-scope requirements (R1.6, R1.7) without renumbering existing IDs.
- A2's candidate list and capability matrix are organized by SEL product family and device class.
- A3's threat model gains new credential types and attack paths (network-device credentials, Windows hosts, possible agents on hosts); any host agent is a new trust boundary needing its own ADR.
- A4's schema must accept non-SER native records (Syslog from switches and gateways, Windows events, clock status) without loss.
- A6's verification matrix states support per SEL family and per device class.
- The SIPROTEC 5 / Relion 615 contrast family from Phase 0 is dropped from Phase 1.

## Open objections

None. Owner to confirm the class list and whether any non-SEL device must be deeply supported before the SEL product is complete.

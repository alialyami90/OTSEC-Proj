# ADR-0002: Runtime shape — modular monolith with isolated collector and sensor processes

- Status: accepted (A1, Phase 0 exit gate, 2026-10-23)
- Date: 2026-10-23
- Deciders: A1, with A5 (proposer) and A3 (trust boundaries)
- Related: R7, R8, Q6, Q7; `docs/phase0/A5-platform-feasibility.md` §2, §6, §7; `docs/phase0/A3-security-feasibility.md` §4; ADR-0003, ADR-0004

## Context

R7 asks for modules that can be developed, tested, enabled, disabled, and upgraded independently; R8 asks for single-server, central-plus-collector, and distributed deployments with independent site operation. The brief forbids defaulting to microservices without justification (P8). Q6 asks whether centralized and distributed operation can share one foundation; Q7 asks whether the platform creates a new attack path.

## Options considered

A. Modular monolith: one codebase and one binary, roles `site`, `central`, `all-in-one` by configuration, modules as packages behind contract interfaces.
B. Service per module joined by a broker or RPC.
C. A, plus separate OS processes only where a security or fault boundary is needed.

## Evidence

- A5 comparison (§2) and experiments E-A5-1 to E-A5-5 (`simulated`). A1 re-ran E-A5-1 (25 kills × 4 modes, 0 failures), E-A5-3 (wedge at default WAL settings; recovery only with bounded WAL + reserve + incremental pruning), and E-A5-4 (loss in 3/3 runs per scenario without acknowledgement; 0 missing with acknowledgement) on 2026-10-23; all reproduce.
- A3 E1 and threat model: device credentials and IED reachability are the platform's main attack path (Q7 "yes, by construction"); A3 L1–L7 layering.
- No requirement or measurement shows a scaling need for B (inferred; substation SER and Syslog rates are low, A5 §4 E-A5-2).

## Decision

Option C, narrowly:

1. One Go binary (ADR-0003) runs as `site`, `central`, or `all-in-one`. Modules are packages behind interfaces in `contracts/`; a disabled module is present but never started.
2. Separate processes only for: (a) the **IED collector**, which runs as its own OS user, alone can resolve device credentials, and alone has a route to the IED network; (b) **Zeek or Suricata** when R6 work starts. Each additional process must name the boundary it enforces in a later ADR.
3. Invariants that make Q6 "yes": only site nodes talk to IEDs; sites are the system of record; every site–central connection is opened by the site; loss of central never stops local collection, storage, or site-configured forwarding.
4. Central's instruction surface is the allowlist in A5 §6 and A3 §1.6: signed, typed policy bundles bounded by a site-local ceiling; no exec channel; no path to IED credentials; no request that touches a device.
5. No broker and no orchestrator; systemd supervision. *(Site node: Windows Service Control Manager instead, ADR-0007.)*

**R7.1 interpretation.** Modules are independently developed, tested, enabled, and disabled, and are *released together* as one signed, versioned artifact. A6 can only verify combinations that ship, and an untested mix of module versions at an OT site is a reliability risk. If the owner requires independent per-module upgrades on a node, this ADR is superseded and option B or plugin loading must be costed.

## Consequences

- One artifact to sign, verify, upgrade, and roll back (R8.7).
- The R8.2 replication path is exercised in R8.1 tests because all-in-one uses the same contract in-process.
- Local IPC between the main process and the collector becomes a contract to secure and test (Phase 1).
- A crash in a non-isolated module takes down the main process; mitigated by systemd restart with backoff, which must respect IED session limits (A5 §7, A2 D9).

## Review record

A6 reliability review of P0-A5 accepted it for Phase 0 (`docs/phase0/A6-cross-review.md`, commit 827fffc); A3 contributed and accepted the site-to-central rules (A3 §6). A1 reproduced E-A5-1, E-A5-3, E-A5-4.

## Open objections

None recorded. Owner questions outstanding: site hardware and OS; real WAN outage durations; whether central ever needs direct IED access (would break invariant 3).

# ADR-0001: Repository structure and module ownership

- Status: accepted
- Date: 2026-10-23
- Deciders: A1
- Related: CLAUDE.md sections 4, 5.3, and 8

## Context

The repository was empty. The brief prescribes a suggested layout and initial per-agent ownership. A layout had to exist before any investigation or implementation could be assigned without agents inventing conflicting locations.

## Options considered

1. Adopt the brief's suggested layout as-is, with placeholders for empty directories.
2. Defer the layout until the runtime shape (modular monolith versus services) is decided.
3. Adopt a language-specific layout now.

Option 2 would block Phase 0 task assignment on a decision that Phase 0 is meant to inform. Option 3 would pre-empt the technology evaluation assigned to A5 and is not justified by evidence.

## Evidence

None beyond the brief itself. This is an organizational decision, not a technical one.

## Decision

Adopt option 1. The layout and ownership table are recorded in the repository README. Directories hold `.gitkeep` placeholders until their owners add content. Language- or build-specific structure inside each directory is left to the owning agent, subject to the toolchain decision (a future ADR).

## Consequences

- Phase 0 tasks can be assigned to owned paths immediately.
- If the runtime decision favours a different structure, a superseding ADR will move directories; the ownership mapping is what matters and is expected to survive.
- The brief notes the structure should be adapted to the selected architecture, so this ADR is expected to be revisited after Phase 0.

## Open objections

None.

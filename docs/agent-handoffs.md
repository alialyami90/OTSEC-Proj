# Agent Handoffs

Maintained by A1. Each agent appends a handoff when it completes an assigned task. Keep entries actionable; this is not a progress diary.

## Task brief template

A1 issues a brief before assigning significant work.

```
### Task <ID>: <short title>
- Objective and rationale:
- Owner agent:
- Required inputs and dependencies:
- Files or modules the agent may modify:
- Expected interfaces:
- Deliverable:
- Acceptance tests:
- Explicit exclusions:
- Uncertainty or safety risks:
```

## Handoff template

```
### Handoff <Task ID> — <agent> — <date>
**Completed:** what was implemented or investigated.
**Evidence:** tests, source material, or experiments supporting the result. Include paths.
**Interfaces:** contracts introduced, used, or modified.
**Limitations:** what is unsupported or not yet validated.
**Risks:** what might fail, including security and OT safety concerns.
**Dependencies:** what another agent must do next.
**Files changed:** source, tests, documentation.
**Reviewer(s) and outcome:** per the cross-review table in CLAUDE.md section 5.6.
```

## Cross-review assignments

| Implementation | Primary reviewer |
| --- | --- |
| A2 — IED integration | A6 (device safety, correctness); A3 (security-sensitive behaviour) |
| A3 — Secure access | A6 (independent security tests); A2 (IED compatibility) |
| A4 — Telemetry and IDS | A6 (detection accuracy); A2 (protocol interpretation) |
| A5 — Platform | A6 (reliability); A3 (trust boundaries) |
| Shared contracts | A1 and all affected agent owners |
| Integrated release | A6 independent verification and A1 integration review |

## Open task briefs

(none yet)

## Handoffs

(none yet)

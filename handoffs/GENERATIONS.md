# Agent generations

One row per generation. The last row is the generation working now, so its letter is the current X of the checkpoint instruction. At each reset the outgoing lead (role 1) fills in that row's end, SHA and reason, and appends a row for the next letter. Before rewriting `HANDOFF-SUMMARY.md`, it pins the last row's summary link to the commit that holds the outgoing summary, as row A's is. Each generation keeps the same six roles; only the names change (see the role-number rule in [HANDOFF-SUMMARY.md](HANDOFF-SUMMARY.md)).

| Letter | Started | Ended | `main` SHA at handoff | Phase | Reason | Summary |
| --- | --- | --- | --- | --- | --- | --- |
| A | 2026-10-23 | 2026-10-27 | `80e7161` (#217, the handoff; its summary describes the code at `d4afc63`) | Phases 0 to 3 | The owner replaced A1 to A6 with B1 to B6, roles unchanged (D3-12) | [A-team to B-team](https://github.com/alialyami90/OTSEC-Proj/blob/80e71613a2b88503dc039cd140acdb66c8518c59/handoffs/HANDOFF-SUMMARY.md) (as merged; later revised under B) |
| B | 2026-10-27 | 2026-10-28 | `26d8e78` (the last role checkpoint PR, #354, before B1's #337) | Phase 4, before the first exit gate | The owner paused all agents and asked for a restart-safe checkpoint (D4-28) | [B-team to C-team](HANDOFF-SUMMARY.md) |
| C | 2026-10-28 | (working) | | Phase 4 | | |

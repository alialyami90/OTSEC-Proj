# A1 decisions during Phase 1

Owner: A1. One entry per decision made while the contracts are reviewed. Each entry names the question, the decision, the reason, and who must act. Decisions that change architecture also go into an ADR.

## D1-1. Who holds NodeID: a leaf package (2026-10-24)

- **Question (A4, C1-A4 change 1):** C4 imports `contracts/asset` for the asset ID, and C1 needs C4's NodeID, which creates an import cycle. There were two options: a leaf package, or two copies of the pattern kept in step by an A6 test.
- **Decision:** a leaf package `contracts/node`, owned by A1 like `contracts/version`. It holds NodeID and the event stream token, with their validation and tests. C1 and C4 both import it, and neither keeps a copy.
- **Reason:** one definition per concept (contracts/README.md). A test that keeps two copies in step catches drift only after it has happened.
- **Action:**
  - A4 adds `contracts/node` in #29, which merges first, and adds its row to the contracts/README.md table.
  - A2 switches C1 to import it once #29 merges.

## D1-2. Syslog endpoint semantics in C1 (2026-10-24)

- **Decision:** A4's change C1-A4-2 stands as written: host is the expected source address, port is never the device's ephemeral source port, and there is one asset per (transport, host) per node.
- **Status:** A2 reports it applied at b627e50.

## D1-3. Collecting node under N-1 redundancy (2026-10-24)

- **Question (A2):** which node collects from an asset when a site has more than one node.
- **Decision for 0.x:** exactly one collecting node per asset (D9), as C1 states. Moving collection to another node is an explicit operator action, recorded by C8. Other nodes may still receive the asset's Syslog. Automatic collector failover is out of scope until Phase 4, distributed operation.
- **Reason:**
  - Two nodes collecting from one relay double the session load on a device with few Telnet sessions (V-S13).
  - They also produce two event streams for the same SER rows.
  - Failover needs leader election, which the first slice does not need.
- **Action:**
  - A5 records the rule in A5-node-posture.md.
  - A6 adds a negative test: a second node's collection request for an assigned asset is refused.

## D1-4. Storage exhaustion states in C5 (2026-10-24)

- **Question:** what the node does when no reserve is left (ADR-0004 item 8, F-013, F-014). A5 proposed a two-tier reserve and a blocked startup. A6 proposed an explicit "full" state.
- **Decision:** both proposals, under two named states.
  - **blocked:** there is no open headroom. The store is not opened and the lock is held.
  - **drain-only:** the store opened after a degraded recovery. The node forwards and prunes, and accepts no new events.
- **Common rules:**
  - Both states are reported on the node health surface and in a C8 audit record.
  - In both states the collector stops pulling SER, so events stay on the relay. If the relay's buffer wraps meanwhile, the next collection records a gap marker.
  - C5 defines the exit condition for each state.
  - A failed reserve release stops startup.
- **Action:**
  - A5 writes this into C5 (#33).
  - A6 tests blocked, drain-only and failed release under V-S9.

## D1-5. Prune boundary and replay windows (2026-10-24)

- **Question (A4, C5-A4, blocking):** the best-effort prune boundary uses max(cursor, aged), so it can prune a mode B replay window before the replay happens.
- **Decision:** the boundary may not pass any open replay window (R-A5-5: nothing a consumer still needs is pruned). If storage pressure forces a prune past it, that is an explicit loss, recorded with a gap marker and an audit record. It is never silent.
- **Action:** A5 changes C5. A4 re-checks.

## D1-6. Register format changes from A2's C3 review (2026-10-24)

- **C3-A2 change 1:** operations may list phases (operate, probe). sel.id runs in both. `Matcher.Permit(phase, line)` is the egress check.
- **C3-A2 change 2:** posture warnings are in the package (MAXACC, FTPACC and HTTPACC above 1).
- **C3-A2 note 5:** a probe operation must be literal and need access level 0 (`ProbeAccessLevel`).
- **Content:** the corrected package is A2's `contracts/register/testdata/sel-751.json`, after #27 merges. `sel-751-phase0.json` stays as the lossless Phase 0 conversion record.
- **FID count:** A6 confirmed 78 unique FIDs and withdrew the count of 84.

## D1-7. A read after an empty read is not a gap (2026-10-24)

- **Question (A6, C4-A6 Q4):** C4 reports a read that follows an empty read as a gap, so clearing a relay's SER buffer raises `ser.gap` twice. The first gap, the clear itself, is real. The second is not, because nothing can have been dropped from an empty read.
- **Decision:** A6's recommendation is accepted. When the previous read is empty but not nil, `Align` returns `ok` and adds every record. C4's doc.go states the case that cannot be detected: if the buffer wraps completely between two reads, records are lost without trace, and that is true after any read, not only after an empty one.
- **Action:** A4 changes `Align` and adds the case to `align_test.go`. A6's V-S4 case expects exactly one gap per clear.

## D1-8. An authentication line is sent in auth only (2026-10-24)

- **Question (A6, C3 re-check at 6a776bc):** the format allowed a session line such as `ACC` to be listed for probe as well.
- **Decision:** `Validate` refuses a session line that lists auth together with any other phase. The format cannot tell which line elevates a session, so a package that puts `ACC` in probe alone is caught by A2's and A3's content review and by C7's signature, not by `Validate`.

## D1-9. C4 decoding is strict (2026-10-24)

- **Question (A6, C4-A6 optional 6):** `encoding/json` matches keys to fields without regard to case, lets a duplicate key overwrite the first, and ignores unknown fields. A6 showed that the result of decoding an event depended on key order.
- **Decision:** C4 gets a strict `Decode`, the same rules as C3. Stored events are evidence, so every reader must read them the same way. Checking only at the C7 IPC boundary would leave stored and forwarded copies unchecked.
- **Action:** A4 adds `Decode` in #29. A shared helper may move into a leaf package later, but only once a third contract needs it.

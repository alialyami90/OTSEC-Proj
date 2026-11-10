# GT-MIB: the SNMPv3 ground truth's case table (C6, P4-3-C6)

`cases.json` gives what the collector must do for each GT-MIB case. It covers the SEL-2731M and SEL-2741M in RSTP mode (D4-51). It was written by hand before any agent code, as P4-3-C6 deliverable 1 requires. The plan it follows is `docs/phase4/C6-gt-mib-plan.md`, and its section numbers are the plan's.

**Nothing here has touched a switch.** The FIDs are real (S29 p. 62). Every other served value is labelled SYNTHESIZED in the plan, including the engine ID's MAC part, `sysName` and the table's other cells. Every result over GT-MIB will be `simulated`.

**The agent is in `agent/`** (D6, 2026-11-06). It is built from the RFC texts in `reference/rfc/` (D4-58), imports only the Go standard library, and listens on loopback only. `agent/cmd/gtmib` runs one case: `-case <ID>`, with the USM password from `GTMIB_PASSWORD`, never from argv. Every layout in the table that comes from an RFC is listed under `confirmed`, with its RFC, section and lines. Checking them against the texts changed two things: W4 is 720 varbinds (RFC 6933 §4 has 18 accessible columns, not 17), and H12 is a positive case, because RFC 3417 §8 (1) permits a long-form length with more octets than needed.

`go test ./tests/integration/gt_mib/agent` checks the agent on its own: the served list against S29, the RFC 3414 A.3.2 key vector, one loopback round as a manager sees it, the report rule of RFC 3412 §7.1 step 3b, each case's behaviour, and each hostile entry decoded by a strict reader. The V-M1 runner, `tests/integration/slice/test_slice_vm1_e2e.py` (#496), runs the real binaries against one agent per case, in CI's `integration-long` vm1 leg. W11 and W12 need a GetNext walk, which no signed register holds while D4-60's bar stands, so `tests/integration/gt_mib/client` runs them, and W10 beside its binary run, with C2's SNMPv3 session over a UDP socket against the case's agent (C2 0.9's test 3).

## What the table holds

- `cases`: the plan's sections 2.1 to 2.5 and 2.8, one entry per case. Each gives:
  - the expected C2 code (0.7, or 0.8 for U19a and U19b; `null` where the configuration or the credential is refused before any run);
  - the counts where the plan fixes them: datagrams the agent received, authenticated requests, and requests of the operation;
  - the attributes with their read paths, and the attributes that must be absent;
  - the health lines, and any further checks.
  The counts depend on whether the agent answers the client's first authPriv request with the authenticated time-window Report, as a real agent does, so each such case says so in `time_window_first` and in its setup (C2 on #457). A whole-run count of authPriv requests is given only for runs that end before the walk; an ok run gives the requests of one operation (`requests_of`).
  The plan's U4 and F5 each hold two behaviours, so the table splits them into U4a and U4b, and F5a and F5b.
- `every_run`: what the agent's own decoded log and the transcript must show in every case, as V-M1 (b) requires.
- `hostile`: section 2.6's malformed messages, at the outer layer, which is parsed before authentication, and at the scoped layer, which is parsed after decryption. `positive` holds H12, which the client must accept at both layers.
- `egress`: section 2.7's deny corpus, by the rule each message must be refused under. The test that feeds it to C3's check is `egress/deny_test.go`, which came in with #449.

## Codes from C2 0.8

C1 ruled on three cases (D4-54), and C2 0.8 adds the two codes:

- **U19a and U19b** expect `failed.snmp_unexpected_report`: a Report out of order, at any stage after connecting.
- **A ScopedPDU that does not decode after authentication** (2.6, scoped layer) expects `failed.snmp_scoped_pdu_unreadable`, at the auth stage.

Both codes are SNMP-only, suspend nothing, and keep the bytes. C2 0.8 is on main since #453, and `test_codes_are_c2_codes_for_snmp` checks both against it.

## How the table is checked

`test_gt_mib_cases.py` checks the table itself, not the product:

- every case in the plan is in the table, and nothing else is;
- every expected code is one `contracts/adapter` defines, and none is for line sessions only;
- every SNMP code is expected by at least one case or by the hostile corpus;
- each FID matches the family's grammar and is one the agent serves;
- the model and firmware version are the FID's parts;
- each OID is one the operation names, or lies inside its subtree;
- the engine ID is cited by its header;
- `failed.snmp_fid_unreadable` reports nothing cut from a FID;
- each egress rule is one `snmpegress` returns, and all thirteen near misses are present;
- every RFC-derived item is listed under `confirmed` with its RFC, section and lines;
- H12 is positive, and W4 counts RFC 6933's 18 columns.

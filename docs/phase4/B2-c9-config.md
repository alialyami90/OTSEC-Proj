# C9 `otsec.config/0.1`: configuration snapshot and difference (P4-A2, B2)

Date: 2026-10-27.

**Evidence class.** Everything here is `desk`, or `simulated` where it says so: contract code and constructed examples on a CI runner. No relay was read. The `SHO` layouts are `documented-untested`.

**Where things are.**
- The contract is `contracts/config/`: `doc.go` states the rule, `config.go` and `diff.go` hold the types, and `check.go` enforces the rule.
- The schemas are in `schema/` and the goldens in `testdata/`.

**Reviewers.** B5 (storage and size), B3 (the digest that C7 0.6 and C8 0.5 name), and B6 (contract tests and the rule's mutations). B1 approves C9 together with C10, C7 0.6 and C8 0.5 (P4-A2, D4-8).

## What C9 defines

**A snapshot** is one `config.read` of one asset:
- One section per settings class that the family's rule lists, in the rule's order. So a snapshot is complete by construction.
- Each section has the exact register line that read it, its state (`present` or `absent`), the rule's sensitive mark, its span in the session's C2 transcript, the SHA-256 of those bytes, and its settings.
- Each setting is a name and a value, exactly as printed.
- The transcript is named by its C5 evidence ref, `sha256:<hex>`. The bytes are kept only there (D4-8).

**A difference** compares two snapshots of one asset under one rule and one target:
- Each setting changed, added or removed, with both values.
- Each class that appeared or disappeared.
- An empty `changes` list means no change.
- Two snapshots that differ in asset, rule or target are refused with `ErrNotComparable`. That is never reported as an empty difference.

**The digest** of either document is `Digest`: `sha256:` plus the SHA-256 of the stored bytes, exactly as written. This is the C10 rule (D4-4 item 5).
- C7 0.6 names the acknowledged snapshot's digest as `baseline_digest`.
- C8 0.5 names `snapshot_digest` and `difference_digest`.
- These names were agreed with B3. B4 uses the same hash rule for C10.

**The rule** `sel-751-sho/1` decides what is a setting. It has three parts:
- **Its classes.** These are the 24 `SHO` forms of S22 Table 7.67, p. 7.77 (#231). None takes the trailing `s` parameter. Ports and maps are always given explicitly.
- **Its tokenization**, stated line by line in `doc.go`.
- **`CheckAgainst`**, which re-reads every section from the transcript by that rule and requires the snapshot to match exactly.

The node runs `CheckAgainst` on every snapshot, as it runs C2's `CheckLines` on every result. The adapter's own parser and the contract's tokenizer are separate implementations, and this check makes them agree.

## Decisions

1. **A snapshot holds every class of its rule.** A read that cannot fill one class fails, and C2 keeps its bytes. P4-A2 requires that a partial snapshot is never presented as complete, and this makes that structural: no "incomplete" snapshot exists.
2. **Sections point and hash; settings do not carry spans** (D4-8; B5).
   - The section span and its SHA-256 are the evidence.
   - Per-setting spans would add nothing, because `CheckAgainst` re-derives every setting from the section bytes. Dropping them keeps the snapshot about the size of the transcript, which B5's per-snapshot cap needs.
   - A section's bytes are the reply's message text: after the echoed command line and before the prompt, without the STX and ETX frame.
3. **The continuation rule for wrapped values.**
   - A line counts as a continuation of the last setting on the line before when it has no `:=`, is not blank, is not a header, and follows a setting line or another continuation directly.
   - Its trimmed text is joined to the value with one space. So a value rewrapped at another column gives the same value.
   - The rule separates a continuation from a heading by the blank line that precedes every heading S22 prints: Figure 7.43, Figure D.3 and the p. G.29 examples.
   - S22 prints no wrapped `SHO` reply. The settings sheet's wrapped `FAULT` (Table 4.84) and `ER` (Table 4.125) are table layout. So this rule is an assumption until a capture exists. B6's widened H-13 (D4-8) is that capture.
4. **The command-response header is never a setting and never a continuation.** It matches `Date: … Time: …` or `Time Source: …` (S22 p. 7.31), wherever it falls, so a header printed again mid-reply changes nothing. This is how a page break or a new time gives an empty difference.
5. **What is not semantic:** headings, headers, blank lines, columns, wrapping, the order of settings within a class, and the frame. So the difference compares settings by name, and never compares hashes.
6. **Absent classes** (#231).
   - Ports 2 to 4, Modbus, IEC 60870-5-103, EtherNet/IP maps 1 to 3 and DNP maps 1 to 3 may be absent. A relay answers `Invalid Command` to a command that is not available (S22 p. 7.31).
   - Groups, logic, Global, Port F, Port 1, Report and Front Panel may not be absent. Port 1 is in that list because the Telnet session reaches the relay through it, and it reads `SHO P 1` for `LANG`.
   - An absent class keeps its reply bytes and has no settings.
   - A class that changes between absent and present is a change, and its settings are listed as added or removed.
   - Whether an absent port or protocol answers exactly `Invalid Command` is `documented-untested`.
7. **Some replies fail the read:**
   - a layout the rule cannot place;
   - a present reply with no setting;
   - an empty value;
   - a value holding `:=`, or a byte that is not printable ASCII;
   - a continuation holding two spaces together;
   - a name printed twice in one class.

   Each fails closed. The adapter reports a C2 failure with the bytes kept, never a snapshot.
8. **Sensitivity.** Every port class is marked sensitive in the rule, the snapshot and each change, because they hold addresses, the router and `FTPUSER` (Table 4.104). No class prints a password, because passwords are set with `PAS` (Table 7.52). B5's views print digests and setting names from port sections, never their values. C9 itself masks nothing.
9. **An unknown rule ID is refused.** A new family, or a changed rule, gets a new rule ID in a later minor. `sel-751-sho/1` is never edited.
10. **The C2 operation ID** for the read will be `sel.config.read_all`, one operation for the whole read, as `sel.ser.read_all` is. Register revision 5 fixes it.

## Storage, agreed with B5 for C5 0.4

- A `config.read` session's transcript is one C5 capture. The snapshot is the record's event, and the transcript is its capture.
- The two commit together and are pruned together. Pinning a snapshot (the active baseline, or one with an unacknowledged difference) pins its capture.
- The per-snapshot cap (transcript plus snapshot) is a parameter, with a provisional default of 512 KiB.
- The store volume's recovery reserve follows from the cap: at least 2 × (WAL bound + 1.25 × the largest record cap), about 2.3 MiB at 512 KiB (B5, #246). B5 measured the WAL at 1.05 to 1.13 times the record bytes.
- A read over the cap fails into quarantine with its bytes kept.
- **Size estimate, not yet a count.** A full 24-form read holds an estimated 5,000 to 8,000 printed settings, about 150 to 250 KB of transcript, and a snapshot of about the same size.
  - Register revision 5 will state a counted byte cap for each `SHO` line, taken from S22's settings sheets. The cap and the reserve then follow from that sum.

## Against P4-A2's acceptance tests

| P4-A2 test | Where it is checked |
| --- | --- |
| The same configuration read twice, with a different time and page break, gives an empty difference | `TestSameConfigurationOtherBytesIsNoChange`. Reads 1 and 2 differ in header time, a mid-reply header, columns, order and wrapping. |
| A single injected change names exactly that setting | The contract half is `TestCompareGoldens` (read 3). The end-to-end half is B6's GT-INJ series against the simulator, written independently. |
| An unparseable reply is kept and fails the read | Decisions 1 and 7. `TestTokenizeRule`'s failing cases and `TestCheckAgainstCatches`. The adapter half comes with C2 0.6. |
| Mutation of the non-semantic rule is caught | `TestTokenizeRule` pins each clause. `TestCheckAgainstCatches` covers a dropped, misread, swapped or cut setting, and a heading read as a continuation. B6's independent contract tests go in `tests/contract/`. |
| V-S7 with the new lines | Comes with register revision 5. |

Each golden is generated by `testdata/generate.py`. It has its own Python reading of the rule and of `Compare`, and the Go tests check the two against each other. `FuzzTokenize` found that a control byte could pass as a value. That is fixed, and the input is kept in `testdata/fuzz`.

## Limitations and risks

- **The layouts are `documented-untested`.** The adapter and B6's simulator both come from S22, so agreement between them is not hardware evidence. The H-13 widening (D4-8) is the capture that settles it.
- **Free text breaks the read.** A free-text value with two spaces together, such as Event Messenger text (`MPTX01` to `MPTX32` in Global) or a `TID`, would end at those two spaces, and the rest of the line would not tokenize. The read then fails closed, which is an availability risk at a site that uses such text. How the relay prints a free-text value with two spaces is unknown: it may quote it or not allow it.
- **An empty value fails the read.** Whether a relay prints `NAME :=` with nothing after it is unknown; the settings sheets leave SELOGIC blanks for the engineer to fill in.
- **The difference has no meaning attached.** It names settings and values as printed. It does not rank how dangerous a change is.
- **Session load.** A 24-form read holds Level 1 longer than a SER read. The read's total time and the poll interval go in register revision 5, checked against `TIDLE` and the two-session limit with P4-A5's quiet interval.

## Next (B2)

These wait until C9 is approved:

1. **Register revision 5.** The 24 exact forms at Level 1, each with a timeout and a counted byte cap, and the read's total time. The deny corpus, updated by B6, covers every `s` form and every bare `SHO P`.
2. **C2 0.6 `config.read`** in `sel751`. It follows the `ser.read` session rules, with a parser and a fuzz target per class, and goldens from S22's figures and tables. B6's simulator forms are not read until those goldens are fixed.

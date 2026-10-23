# A3 security review of A2's Phase 0 findings

Reviewer: A3. Under the cross-review table (CLAUDE.md 5.6), A3 reviews A2's work for security-sensitive behaviour. Date: 2026-10-23. Reviewed on `main` at 2cb5da2:

- `docs/phase0/A2-device-feasibility.md`: risks D1–D27, sections 5–9 and 15.
- `docs/phase0/A2-command-register-draft.json`: 6 allow entries and 38 deny entries.
- `docs/phase0/A2-sel751-firmware-allowlist.json`: 12 branches.

Not reviewed: parser correctness and device safety beyond security. A6 owns those.

**Verdict: accepted for Phase 0, with three changes (C-A2-1 to C-A2-3).** None of them blocks Phase 0 close-out, because all three apply when the register becomes a Phase 1 contract. Nothing in Phase 1 is drafted here.

All A2 facts used here are `documented-untested` (S22, SEL-751 manual, date code 20260910), except where marked `inferred`.

## What holds

### Register classification

- Entries classify complete command lines, not verbs (A6 C-01).
- The allow list is six exact canonical lines: `ACC`, `QUI`, `ID`, `SER`, `SHO G`, `SHO P 1`.
- The deny list is case-insensitive and tolerates abbreviations. That matters because the relay accepts any command shortened to three letters (S22 p. 7.31).
- The state-changing Level 1 commands are all denied: `SER C/R`, `HIS C`, `TAR R`, `SUM C`, `MET R*`, `COM C`, `DATE`/`TIME` with arguments, `IRIG`, `TRI`, `PING` and `FIL`. This confirms the threat model's point that the relay's Level 1 is not a read-only boundary and the L4 exact-line check is.
- The `SHO G` and `SHO P 1` outputs carry no secrets. A2 searched every settings sheet in S22 for password-bearing settings and found none. Passwords are set with `PAS` and are not settings. `SHO P 1` shows IP addresses and `FTPUSER`, which is a user name, not a password. Both outputs are marked as sensitive configuration evidence. This closes the condition A3 set in its feasibility findings (section 8.4).

### Deny-by-default posture

- A line that matches no entry is a violation, and the deny list exists only so tests can probe known-dangerous lines. This is the posture threat model SC-2 requires.
- The register is English-only. Before any `SER`, the adapter reads `LANG` with `SHO P 1` and fails closed unless the port is English (ADR-0005). The Level 0 `QUI` probe catches a Spanish-mode port before elevation. Both close the D16 trap, where Spanish `SER D` clears the SER.
- Agreed exclusions:
  - FTP, HTTP, MMS, DNP3, Fast SER and Fast Operate are out of slice 1 (D8, D14, D17, section 7.1).
  - MMS with authentication enabled requires the Level 2 password, so it is incompatible with the Level 1 credential ceiling (D17).
  - `CSE` and `CAS` stay denied until their formats are documented.

### Firmware allowlist (AP-27, D27)

- Collection is limited to FIDs at or after every communications-restart fix on their branch. The FID must match the full string, and anything not in Appendix A fails closed. The `EHTTP := N` condition on R400–R402 is checked with `SHO P 1`.
- The inheritance assumption is classed `inferred (owner-accepted)` and never `documented` (ADR-0005). Threat model AP-27 records this.
- Limitation: the FID is reported by the device itself. The allowlist keeps platform traffic away from known-bad firmware on a genuine relay. It does not defend against a device impersonating a relay; that is AP-12, covered by the downstream-security labelling and HR-8.

### D-items A3 relies on

| D-item | What A3 relies on | Where A3 enforces it |
| --- | --- | --- |
| D1, D3 | Level 1 is not read-only | Register (L2), rendering (L3), egress exact-line check (L4) |
| D2, D19 | Three wrong passwords pulse `SALARM`. After a wrong password, the next line is consumed as a password. | One attempt, then disconnect without sending `QUI`. Credential suspended (C-19). |
| D4, D17 | Control and settings commands, and MMS authentication, need Level 2 | Credential store ceiling: `ACC` level only |
| D5 | Fast Operate shares the ASCII port. `FASTOP` defaults to `N`. | Egress byte filter, 0x20–0x7E plus CR/LF (L4) |
| D7 | Cleartext Telnet with shared per-level passwords | `plaintext-unauthenticated` label. HR-1, HR-8. |
| D13 | Default passwords ship with the relay | No code path guesses or tries default passwords |
| D15 | Failed logins create SER rows | A4 correlates and tags them as self-generated, never suppresses them |
| D16 | Spanish `SER D` clears the SER | `LANG` check that fails closed, plus the `QUI` probe |
| D18 | An unquit session stays elevated until `TIDLE` | Read the first prompt before sending. `QUI` on every close. |
| D26 | With the password disabled, the password would run as a command | Prompt-gated credential slot |
| D27 | Communications traffic has restarted some firmware | FID allowlist, checked before `ACC` |

## Changes

| ID | Finding | Change | Test |
| --- | --- | --- | --- |
| C-A2-1 | `ACC` and `QUI` are classified `read-only` in the register. Under A3 section 8.3 and ADR-0005, they are sent only by the transport's probe, auth and close phases, never by an adapter. If the register labels them `read-only`, a Phase 1 implementation that offers every `read-only` entry as an invocable `operation_id` would let an adapter send them. | Give them a distinct classification, such as `session-control`, that is not invocable as an operation. The L4 phase check then accepts `ACC` only in auth and `QUI` only in probe and close. | Invoking `sel.session.acc` or `sel.session.qui` through the adapter API is refused before connect. `ACC` or `QUI` injected in the operate phase aborts the session. |
| C-A2-2 | The firmware allowlist is a separate JSON file. If it is loaded from configuration rather than shipped with the register, a compromised central server or a local administrator could widen it (AP-7). | Ship the allowlist in the same signed register package, under the same release key and anti-rollback floor. The FID check runs in the transport before `ACC`, and it fails closed when the allowlist is missing, unsigned or unparseable. | A node given an unsigned or modified allowlist refuses to collect from every SEL-751 and raises an alarm. A FID one version below a branch minimum ends the session at Level 0. |
| C-A2-3 | S22 does not document whether Telnet echoes password characters. Its example (p. 7.33) shows only `Password: ? <Enter>`, which suggests no echo but does not prove it. Under the HR-3 ruling, all received bytes are kept. | Echo redaction (HR-3, A4's condition) stays mandatory until a hardware capture shows no echo. The transport is the only component that holds the secret, so it scans the bytes received during the auth phase for the secret and replaces any match with the marker before the transcript leaves the collector. | Simulator in echo mode: the stored transcript contains the marker and no secret bytes, and the event `redaction.echo` is recorded. In no-echo mode, only the sent-side marker appears. |

## Open items, no change to A2 documents required

- **Failed-attempt counting across connections** is not documented. Under the one-attempt rule, the platform can cause at most one failure each time an operator clears a suspended credential. A3 asks the clear-suspension UI to say so. Whether the relay's count of three survives a disconnect is a hardware test, which A6 should list.
- **`MAXACC` above 1 is warned, not refused** (ADR-0005). A3's position is unchanged: a refusal would be safer, and the owner's decision is still open.
- **Order of steps in the A3 transport sequence.** A3's findings section 8.3 said "`ID` runs after auth", because the Level 0 behaviour of `ID` was unknown at the time. S22 Table 7.43 settles it as Level 0, and D27 moves the FID check before `ACC`. That is safer, because no credential is sent to an unlisted firmware. Section 8.3 is updated in the same change as this review.

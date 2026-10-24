# A2 Phase 1 notes: C1 and C2

- Task: P1-A2 (`docs/agent-handoffs.md`). Author: A2. Started 2026-10-24.
- Contracts: C1 `otsec.asset/0.1` in `contracts/asset/`; C2 `otsec.adapter/0.1` in `contracts/adapter/` (next PR).
- No device was contacted. Every device value in the examples is from the SEL-751 instruction manual (S22, date code 20260910) or invented and marked as such.

## C1 decisions

| Decision | Why |
| --- | --- |
| The asset ID is an assigned UUID, never derived from device content. | A device's claims change (firmware upgrade) or are forged (C-07). An example derived from the FID is in `testdata/invalid/`. |
| Every fact is an attribute with observations. Each observation has an evidence class and a source (method, ref, time, and a transcript span when it came from a session). | R1.5 and EP-2. It also lets the declared and observed FID sit side by side, which is what B-05 needs. |
| Confidence is derived by fixed rules (`single-source`, `corroborated`, `conflicting`), not asserted. | So it can be checked. Two device claims (for example `ID` and the SER header) are one evidence class and do not corroborate each other. |
| A conflicting attribute keeps the operator-declared value. | A device claim never overwrites the records. |
| Evidence class `simulated` goes only with method `simulator-session`, and the reverse. | A simulator run can never be shown as a device observation (C-10). |
| `downstream_security` is per endpoint. Telnet and plain Syslog are always `plaintext-unauthenticated`. Anything below `encrypted-authenticated` needs an acknowledgement (by, at, reason). | A3 §4.5 and ADR-0005. An RTAC has a plaintext Syslog endpoint next to an SSH one, so a single per-asset value would be wrong; `WeakestDownstreamSecurity` gives the asset-level label. |
| Serial is always `plaintext-unauthenticated`, like Telnet. `encrypted-authenticated` requires a `pinned-key` binding; SSH or TLS without one is `encrypted-weak`. Every acknowledgement carries a `scope`, and 0.1 has only `lab-only`. | A3 review C1-A3-1 to C1-A3-3. The collector refuses a run whose credential `plaintext_scope` (C7) differs from the endpoint's acknowledgement scope. A production scope needs an owner decision. |
| C1 keeps its own copy of the node ID pattern (identical to C4's). Syslog endpoints name the expected sender address; the port, when set, is the node's listening port. `CheckSenders` rejects one sender on two assets of one node. `node_id` is the node that runs adapter sessions; other nodes may receive the asset's Syslog. A replaced unit gets a new asset ID; the same unit keeps its ID. | A4 review C1-A4-1 to C1-A4-4. C4 imports C1, so C1 cannot import C4. Collector failover under N-1 redundancy is open for A5 and A1. |
| Unknown values from a later minor are read as the enum's least trusted value (`plaintext-unauthenticated`, `spoofable`, `unknown`). | contracts/README.md compatibility rule, with a fallback that is never more trusted. |
| Vendor and product family are lowercase tokens (`sel`, `sel-751`). | C3 names a register package's family with the same token (`family` in PR #27). Display names belong in the UI. |
| Vendor-specific attributes use a vendor prefix (`sel.cid`). Unprefixed names come from a fixed list. | Profiles can add attributes without a contract change, while the common names stay stable. |
| The site platform node is an asset of class `server` with `platform_node.posture`. | P1-A5 posture labels. `os-out-of-support` needs its standing condition. TODO(A5): `docs/phase1/A5-node-posture.md` will define when each label applies. |
| Capability profiles are C1 types (`profile.go`), and ship in the signed register package. | Architecture table: C1 covers the capability profile. Shipping it with the register means a profile cannot widen what the collector may send (C-A2-2). |

## B-05: what the identity binding proves

The text is in `contracts/asset/doc.go`. In short:

- **Proves:** the device at this address reports the same FID (and, after authentication, the same serial number) as the commissioning records. This catches a replaced relay, a wrong address and an unrecorded firmware upgrade. The FID check runs at Level 0, before any credential is sent (AP-27).
- **Does not prove:** that the device is genuine. Anything on the station LAN can print the expected FID and serial number. The binding is labelled `spoofable`, and the password still goes in clear text to whatever answers (owner-accepted, ADR-0005).
- **On mismatch:** the collector sends nothing more except the close sequence that is safe at that point. The invocation ends with `identity_mismatch` (C2), and the asset is suspended until an operator re-commissions it. The observed value never replaces the declared one.

## Findings from this work

1. **The serial number is not in the SEL-751 `ID` response.** Figure 7.38 (p. 7.64) lists FID, BFID, CID, DEVID, DEVCODE, PARTNO, CONFIG, SPECIAL and the two display packages, and no serial number. The serial number appears in the SER report header (`Serial No`, Figure 10.16) and in the `STA` report (`Serial Num`, Figure 1.5). Both are Level 1, so the serial can only be compared after the password has been sent. It detects a substitution but cannot protect the credential. The P1-A2 brief says "FID and serial from `ID`". C1 binds both, but only the FID is a pre-authentication check.
2. **The manual does document a `QUIT` reply.** Figure 1.4 (p. 1.12, "Response Header") shows `=>QUIT`, then the two header lines without milliseconds (`Feeder xyz  Date: 03/10/2011  Time: 10:31:43` and `Station 1  Time Source: Internal`), then `=`. ADR-0005 says the manual documents no QUIT reply. This one is from Level 1, not Level 0, and its time has no milliseconds, while Table 7.16 shows `hh:mm:ss.sss`. The C2 language-probe grammar accepts both forms. It is still to be confirmed on hardware (H-12).
3. **RID and TID are bounded** (Table 4.1, p. 4.5): up to 16 characters from letters, digits, periods, dashes and spaces. The probe grammar uses that bound for the header lines.

## Open items for reviewers

- A3: `Acknowledgement.By` and operator refs are TODO(C7) principal IDs.
- A6: `testdata/generate.py` writes the examples. They are built from my own transcription, so A6's independent tests should not reuse them as ground truth (risk 3).

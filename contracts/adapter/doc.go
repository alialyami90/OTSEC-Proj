// Package adapter is contract C2, otsec.adapter/0.4: how the collector is
// asked to do one approved thing to one device, and how it reports exactly
// what happened.
//
// # What it covers
//
//   - Invocation: asset and endpoint (C1), one register operation ID (C3)
//     with validated parameters, a credential reference (C7), the identity
//     the device must report (C1 declared values), and limits on time, size,
//     retries and rate. Invocations are strict: an unknown field rejects the
//     whole message (contracts/README.md; AP-7, HR-1). The collector builds
//     the invocation itself from an accepted C7 run, the C1 asset (endpoint,
//     binding and its pre_credential attributes) and the profile; it is never
//     received from the main process. A C7 refusal means no invocation
//     exists. A refused.* result means the run was accepted and the collector
//     then declined it. Invocation.ValidateWith checks the operation against
//     the register (RegisterLookup over a verified C3 package), and
//     CheckAgainst checks the invocation against the C1 asset and profile:
//     its endpoint, the binding's declared values as expected identity, a
//     credential only where asset.CredentialAllowed permits one, and limits
//     no looser than the profile's session_limits (D1-18). An address-only
//     binding compares nothing, so no C2 session runs on it.
//   - Result: status and one error code from a closed taxonomy; the whole
//     session transcript as bytes, cut into send and receive segments that
//     cover every byte exactly once, each with its transport phase and time;
//     redaction markers for the password and any echo of it; what the
//     session established (language probe, password prompt, access level,
//     QUI); the identity check; posture warnings; identity observations and
//     parsed records, each pointing at its bytes.
//   - The language-probe reply grammar (probe.go), so the transport and A6's
//     tests use one definition (ADR-0005, A6 F-007).
//   - SEL framing. The SEL-751 sends every message as <STX>, the lines with
//     CRLF, then <ETX> (S22 p. 7.28). The transcript keeps both bytes. Prompt
//     detection and the probe grammar ignore them, as they ignore XON, XOFF
//     and NUL; no span of an observation, warning or record may include
//     them. That the prompt follows ETX is assumed: no capture exists (A6
//     H-13).
//
// # Rules the types enforce
//
// Result.Validate checks these against the transcript bytes, not against the
// session facts, which must agree with the bytes (dialogue.go; A3 and A6 C2
// reviews). Result.CheckLines checks every sent line against the register
// package and the invocation, and is the oracle for "no unauthorized write".
//
//   - A refusal before connecting has an empty transcript: nothing was sent.
//   - Every line follows a prompt, and a prompt counts only at the start of a
//     line: first in the received bytes, or after CR, LF, STX or ETX. Probe
//     lines and ACC follow "=", operate lines "=>", and the close-phase QUI
//     any level prompt. The Phase 2 transport acts on a prompt only after a
//     short quiet interval with no byte received.
//   - One exception: after failed.timeout or failed.response_too_large, QUI
//     may be sent with no prompt before it, because a session at Level 1
//     must end with QUI (D18, V-S13) and the step ended without one. It
//     needs Level 1 confirmed by a prompt first, so it is never the first
//     send after the password and never follows an unanswered ACC.
//   - If the device prints nothing on connect, one bare line end may wake
//     it: first, once, and only into silence. A session that ended without
//     QUI can leave the relay elevated or inside "Password: ?" until TIDLE
//     expires (S22 p. 7.16, p. 7.33), so the wake is allowed only after the
//     failed-auth floor (C7). A first prompt of "=>" or "=>>" ends the
//     session with nothing more sent (refused.session_elevated), and a first
//     "Password: ?" with nothing sent at all (refused.session_pending_password).
//   - The auth phase is ACC once, after "=", after an accepted language probe
//     and after a matching identity item read in the probe phase (AP-27).
//   - A probe reply that ends in a prompt is accepted or rejected by the
//     grammar, and a rejected one is refused.language_probe_rejected, which
//     suspends the asset. From 0.4, a probe with no prompt after it, because
//     the step timed out or the connection closed, is unanswered: the code
//     is failed.timeout or failed.transport_closed, which suspend nothing,
//     and the QUI probe is still the last line sent (D16; A6, V-S12). Up to
//     0.3 a timeout could only be reported as a rejected probe (A6 C2
//     review note).
//   - An ID reply that cannot be read (no frame, no FID line or an empty
//     FID) compares nothing: failed.identity_unreadable, from 0.3, with
//     identity not-checked and ID the last line sent. It suspends nothing.
//     refused.identity_mismatch is kept for a FID that was read and differs
//     (A6 on #118).
//   - The credential slot: the password prompt received after ACC, then one
//     segment that is exactly the redaction marker and one line end
//     (HR-3, C-17). password_prompt says whether the prompt was received.
//   - Nothing is sent after the password until a level prompt confirms it:
//     "=>", or "=>>" for failed.unexpected_access_level. A rejected password
//     is answered by a second "Password: ?" (S22 p. 7.33), and after it, or
//     after no answer, nothing more is sent, not even QUI, which would be the
//     second attempt (C-19, D1-20).
//   - The password is in the transcript only as the redaction marker. An
//     echo of it is redacted wherever it is received after the password,
//     and an echo scan is recorded whenever one was sent (C-A2-3; mandatory
//     until a capture shows the SEL-751 does not echo).
//   - access_level is the highest level the received prompts showed.
//   - The credential is suspended (C7) only for codes where the password was
//     sent: Code.SuspendsCredential. The asset is suspended (C1) by
//     Code.Suspends.
//   - A session that reached Level 1 ends with QUI in the close phase (V-S13,
//     D18), and the close phase sends nothing else. The exceptions are a
//     closed connection, a level that already dropped, a port that is not
//     English (D16), a session found elevated, and, from 0.2 (D2-14), a
//     rejected probe whose reply showed a level prompt (D16) and a
//     "Password: ?" at Level 1 (failed.unexpected_password_prompt), where
//     QUI would be a password attempt (C-19).
//   - A session-control or unknown operation can never be invoked (C-A2-1),
//     and a level 0 operation never carries a credential (C7-A2-5).
//   - Records and observations point into received bytes only, never into a
//     redaction.
//   - error.detail is the collector's own words: at most 256 bytes of
//     printable ASCII, never device text.
//   - An unknown error code reads as failed.unknown, a failure. A code
//     carries the minor that added it (Code.Since), and a result of an
//     earlier minor cannot carry it.
//
// # Versions
//
//   - 0.1 (#51): the first contract.
//   - 0.2 (D2-14): failed.unexpected_password_prompt, and the QUI exemption
//     for refused.language_probe_rejected. Results of 0.1 read unchanged.
//   - 0.3 (A6 on #118): failed.identity_unreadable. Results of 0.1 and 0.2
//     read unchanged; a 0.2 adapter reports an unreadable ID reply as
//     refused.identity_mismatch.
//   - 0.4 (A6, V-S12): the unanswered language probe. Earlier results read
//     unchanged; a 0.3 adapter reports an unanswered probe as
//     refused.language_probe_rejected.
//
// # For the consumers of a result
//
//   - Records: RecordFields names the fields of each kind. A record was
//     received at Transcript.ReceivedAt(record.Span).
//   - Clock: C2 0.1 carries times only. The producer takes C4 received
//     resolution_ns and clock.sync from the node's clock status at ended_at
//     (A4 C2 review change 4).
//   - Audit: the C8 record written at the end of the device session carries
//     transcript_sha256, the transcript's sha256, so a stored transcript can
//     be checked against the audit chain (A3 change 10, D1-25; the field is
//     C8's). The sha256 here detects corruption; the chain detects
//     tampering.
//
// # What it leaves out
//
//   - The Telnet driver, prompt detection, parsers and the egress check
//     (Phase 2). Record types here are envelopes: kind, span and verbatim
//     fields.
//   - Operation and parameter definitions (C3), principals and credential
//     storage (C7), event schema (C4), audit records (C8). C2 uses C3's
//     matcher, C7's principal ID syntax and a copy of its credential
//     reference ID syntax (kept equal by a test).
//   - Session limits per family. They are on the C1 capability profile
//     (session_limits, D1-18); C2 holds only the ceilings they must sit in.
//
// # Serves
//
// R5.1 to R5.7, R4.2, R4.4, P1, P2, P5; A3 §8.3, HR-3, AP-23, AP-27;
// A4 EP-1 to EP-4; A6 C-17, C-19, V-S7, V-S8, V-S10, V-S13; C-A2-1, C-A2-3.
package adapter

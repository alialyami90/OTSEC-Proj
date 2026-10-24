// Package adapter is contract C2, otsec.adapter/0.1: how the collector is
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
//     H-12, H-13).
//
// # Rules the types enforce
//
//   - A refusal before connecting has an empty transcript: nothing was sent.
//   - No line is sent before a prompt. If the device prints nothing on
//     connect, one bare line end may wake it, once, before any prompt. A
//     session that ended without QUI can leave the relay elevated or inside
//     "Password: ?" until TIDLE expires (S22 p. 7.16, p. 7.33), so the wake is
//     allowed only after the failed-auth floor (C7). A first prompt of "=>" or
//     "=>>" ends the session with nothing sent (refused.session_elevated).
//   - A refusal before authentication has no auth phase: no credential left
//     the node. This covers the language probe and the FID check (AP-27).
//   - A credential is sent only after a password prompt, appears in the
//     transcript only as the redaction marker, and an echo scan is recorded
//     whenever one was sent (C-A2-3; mandatory until a capture shows the
//     SEL-751 does not echo).
//   - A rejected password is answered by a second "Password: ?" (S22 p.
//     7.33). After it nothing more is sent, not even QUI, which would be the
//     second attempt (C-19).
//   - The credential is suspended (C7) only for codes where the password was
//     sent: Code.SuspendsCredential. The asset is suspended (C1) by
//     Code.Suspends.
//   - A successful session ends with QUI in the close phase (V-S13, D18).
//   - A session-control or unknown operation can never be invoked (C-A2-1).
//   - Records and observations point into received bytes only, never into a
//     redaction.
//   - An unknown error code reads as failed.unknown, a failure.
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

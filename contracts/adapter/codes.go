package adapter

import (
	"strings"

	"otsec.local/otsec/contracts/asset"
)

// Status is the outcome class of an invocation. Closed; an unknown value
// reads as failed.
type Status string

const (
	StatusOK      Status = "ok"      // every step done, QUI sent
	StatusPartial Status = "partial" // collected, but some or all records were not parsed; raw bytes kept
	StatusRefused Status = "refused" // the collector declined, by rule
	StatusFailed  Status = "failed"  // something went wrong
)

// Code is the closed error taxonomy. The prefix is the status. A reader that
// meets a code it does not know reads it as FailedUnknown.
type Code string

// Stage says how far a session may have got for a code, which fixes what
// its transcript may contain.
type Stage string

const (
	// StageBeforeConnect: nothing was sent. The transcript is empty.
	StageBeforeConnect Stage = "before-connect"
	// StageBeforeAuth: connected at Level 0; no auth phase, no credential.
	StageBeforeAuth Stage = "before-auth"
	// StageAuth: the auth phase was entered.
	StageAuth Stage = "auth"
	// StageAfterAuth: authenticated; the credential was accepted.
	StageAfterAuth Stage = "after-auth"
	// StageAny: can happen at any point after connecting.
	StageAny Stage = "any"
)

const (
	// Before connecting. The collector checks these with no traffic.
	RefusedNotInvocable          Code = "refused.operation_not_invocable"    // unknown, session-control, or denied operation (C-A2-1)
	RefusedInvalidParams         Code = "refused.invalid_parameters"         // parameters do not fit the operation's grammar
	RefusedLimits                Code = "refused.limits_out_of_range"        // malformed invocation, limits above the ceilings, or a credential a level 0 operation does not need
	RefusedInvocationMismatch    Code = "refused.invocation_mismatch"        // not the invocation the collector builds for this asset and profile (CheckAgainst)
	RefusedRegisterUnverified    Code = "refused.register_unverified"        // register package missing, unsigned or unparseable (C-A2-2)
	RefusedFirmwareUndeclared    Code = "refused.firmware_undeclared"        // no declared FID on the asset (ADR-0005 (b), C-23)
	RefusedFirmwareNotAllowed    Code = "refused.firmware_not_allowlisted"   // declared FID not allowed (AP-27)
	RefusedAssetSuspended        Code = "refused.asset_suspended"            // asset suspended (C1)
	RefusedCredentialUnavailable Code = "refused.credential_unavailable"     // missing, suspended, revoked or out of scope (C7)
	RefusedPlaintextNotAcked     Code = "refused.plaintext_not_acknowledged" // insecure endpoint without a matching acknowledgement (C1)
	RefusedSessionBusy           Code = "refused.session_busy"               // another session to the device is open (D9)
	RefusedRateLimited           Code = "refused.rate_limited"               // min_interval_ms not yet elapsed
	FailedConnect                Code = "failed.connect"                     // TCP or serial open failed after the allowed retries
	// RefusedEndpointPath (0.5): the C1 endpoint's path is not direct, so
	// no session is opened (asset.Endpoint.CheckPath). No path (a C1 0.1
	// record), a port server, and a path the reader does not know are
	// refused alike: a port server's timeouts in front of the device have
	// no evidence yet (D2-16, H-13). Nothing is sent, so it suspends
	// nothing; an administrator setting the path clears it.
	RefusedEndpointPath Code = "refused.endpoint_path"

	// Connected, before authentication.
	RefusedSessionElevated Code = "refused.session_elevated" // first prompt already "=>" or "=>>": a session left open (S22 p. 7.16, D18); nothing sent
	// RefusedSessionPendingPassword: the first thing received is "Password: ?",
	// a session left inside the prompt (S22 p. 7.33). Nothing is sent, not
	// even the wake, which would be a password attempt (A3 change 7).
	RefusedSessionPendingPassword Code = "refused.session_pending_password"
	RefusedLanguageProbe          Code = "refused.language_probe_rejected" // QUI reply did not match the probe grammar (ADR-0005)
	RefusedIdentityMismatch       Code = "refused.identity_mismatch"       // ID at Level 0 differs from the declared identity (AP-27, B-05)
	// FailedIdentityUnreadable (0.3): the ID reply could not be read, so
	// nothing was compared: no STX and ETX frame, no FID line, or an empty
	// FID. A reply the adapter cannot read is not evidence of another
	// device, so the asset is not suspended. ACC is not sent (AP-27), and a
	// repeat sends the same Level 0 lines and no password (A6 on #118).
	FailedIdentityUnreadable Code = "failed.identity_unreadable"

	// The auth phase.
	RefusedPasswordPromptAbsent Code = "refused.password_prompt_absent" // ACC reached Level 1 with no prompt: credential not sent (AP-23)
	FailedAuthRejected          Code = "failed.auth_rejected"           // a second "Password: ?" (S22 p. 7.33): nothing more sent, no QUI (C-19)
	FailedUnexpectedLevel       Code = "failed.unexpected_access_level" // a prompt other than the expected one, e.g. "=>>"

	// After authentication.
	RefusedLanguageNotEnglish  Code = "refused.language_not_english"       // SHO P 1 did not show LANG := ENGLISH
	RefusedFirmwareCondition   Code = "refused.firmware_condition_not_met" // a branch condition failed, e.g. EHTTP := N on R400-R402
	FailedIdentityMismatchLate Code = "failed.identity_mismatch"           // identity differs in Level 1 output (SER header serial)
	FailedAccessLevelDropped   Code = "failed.access_level_dropped"        // prompt fell back to "=" mid-session (TIDLE)
	FailedDeviceError          Code = "failed.device_error"                // "Invalid Command", "Invalid Access Level" or similar
	// FailedUnexpectedPasswordPrompt (0.2): a reply at Level 1 ended in
	// "Password: ?". Anything sent now is a password attempt, so nothing more
	// is sent, not even QUI (C-19, D2-14). Repeating the invocation would
	// send ACC and the password again into the same state, so the asset is
	// suspended; the password was accepted, so the credential is not.
	FailedUnexpectedPasswordPrompt Code = "failed.unexpected_password_prompt"

	// Any time after connecting.
	FailedTimeout          Code = "failed.timeout"            // a step or the deadline expired
	FailedTransportClosed  Code = "failed.transport_closed"   // the device or network closed the connection
	FailedResponseTooLarge Code = "failed.response_too_large" // max_response_bytes reached
	FailedEgressViolation  Code = "failed.egress_violation"   // the egress check refused a line (L4): session aborted
	FailedInternal         Code = "failed.internal"           // a collector fault
	FailedUnknown          Code = "failed.unknown"            // fallback for codes this reader does not know

	// FailedConfigUnparsable (0.6): a reply in a configuration run is not a
	// settings section the rule can read (a name printed twice, a line that
	// does not tokenize, no framed message). The run fails as a whole: QUI is
	// sent, the bytes are kept, no record is reported and no snapshot is
	// made (D4-13). A single read keeps partial.parse_errors.
	FailedConfigUnparsable Code = "failed.config_unparsable"

	// The SNMPv3 codes (0.7, C3 0.4, D4-53; docs/phase4/C2-c1-0.3-c3-0.4.md
	// §2.3 and §2.4). Each is distinct so health shows which failure it
	// was. None is retried at a lower security level, as another user or
	// over another SNMP version (#437 §4 rule 1). None suspends the asset or
	// the credential, because the message that causes it may not
	// authenticate: a Report for an unknown user, a wrong digest or a
	// decryption error cannot, and a forged one could otherwise suspend an
	// asset at will (D4-53). Repeats show in health.

	// RefusedEngineIDMismatch: discovery's msgAuthoritativeEngineID differs
	// from the pinned snmp_engine_id. Nothing authenticated was sent, and the
	// keys are never localized to the new value (D4-49 Q1).
	RefusedEngineIDMismatch Code = "refused.engine_id_mismatch"
	// The four failure Reports end the run with their code even when they do
	// not authenticate (§2.3 step 3).
	FailedUSMUnsupportedSecLevel Code = "failed.usm_unsupported_sec_level" // a usmStatsUnsupportedSecLevels Report
	FailedUSMUnknownUser         Code = "failed.usm_unknown_user"          // a usmStatsUnknownUserNames Report
	FailedUSMWrongDigest         Code = "failed.usm_wrong_digest"          // a usmStatsWrongDigests Report
	FailedUSMDecryptionError     Code = "failed.usm_decryption_error"      // a usmStatsDecryptionErrors Report
	// FailedUSMNotInTimeWindow: a second usmStatsNotInTimeWindows Report in
	// one session, or one that does not authenticate.
	FailedUSMNotInTimeWindow Code = "failed.usm_not_in_time_window"
	// FailedSNMPErrorStatus: an authenticated Response with a non-zero
	// error-status, for example authorizationError. The bytes are kept.
	FailedSNMPErrorStatus Code = "failed.snmp_error_status"
	// FailedSNMPWalkNotIncreasing: a walk returned an OID not greater than
	// the one before it (RFC 3416's order). The bytes are kept.
	FailedSNMPWalkNotIncreasing Code = "failed.snmp_walk_not_increasing"

	PartialParseErrors Code = "partial.parse_errors" // some records failed to parse; all bytes kept (EP-1)
	// PartialReadRowsExceeded: the read has more rows than the profile's
	// max_read_rows (D1-12). The bytes are kept and nothing from the read is
	// parsed into a record, so nothing is aligned or stored as events.
	PartialReadRowsExceeded Code = "partial.read_rows_exceeded"
)

type codeInfo struct {
	stage Stage
	// since is the minor that added the code. A result of an earlier minor
	// cannot carry it.
	since int
	// suspends is the C1 suspension reason the code sets on the asset, if any.
	suspends asset.SuspensionReason
	// credential is the C7 suspension reason the code sets on the credential,
	// if any. C7 uses C1's names. Only codes where the password was sent set
	// one (C7 design section 7).
	credential asset.SuspensionReason
	// session is the kind of session the code can end (0.7): a line session
	// (SEL ASCII), an SNMPv3 session, or either ("").
	session sessionKind
}

// sessionKind says which sessions a code applies to (0.7). A line-only code
// needs a prompt or a SEL line; an SNMP-only code needs USM or a PDU.
type sessionKind string

const (
	lineOnly sessionKind = "line"
	snmpOnly sessionKind = "snmp"
)

var codes = map[Code]codeInfo{
	RefusedNotInvocable:            {StageBeforeConnect, 1, "", "", ""},
	RefusedInvalidParams:           {StageBeforeConnect, 1, "", "", ""},
	RefusedLimits:                  {StageBeforeConnect, 1, "", "", ""},
	RefusedRegisterUnverified:      {StageBeforeConnect, 1, "", "", ""},
	RefusedFirmwareUndeclared:      {StageBeforeConnect, 1, "", "", ""},
	RefusedFirmwareNotAllowed:      {StageBeforeConnect, 1, "", "", ""},
	RefusedAssetSuspended:          {StageBeforeConnect, 1, "", "", ""},
	RefusedCredentialUnavailable:   {StageBeforeConnect, 1, "", "", ""},
	RefusedPlaintextNotAcked:       {StageBeforeConnect, 1, "", "", ""},
	RefusedSessionBusy:             {StageBeforeConnect, 1, "", "", ""},
	RefusedRateLimited:             {StageBeforeConnect, 1, "", "", ""},
	FailedConnect:                  {StageBeforeConnect, 1, "", "", ""},
	RefusedEndpointPath:            {StageBeforeConnect, 5, "", "", ""},
	RefusedSessionElevated:         {StageBeforeAuth, 1, "", "", lineOnly}, // TIDLE clears it; retried no sooner than TIDLE
	RefusedSessionPendingPassword:  {StageBeforeAuth, 1, "", "", lineOnly}, // as elevated: TIDLE clears it
	RefusedInvocationMismatch:      {StageBeforeConnect, 1, "", "", ""},
	RefusedLanguageProbe:           {StageBeforeAuth, 1, asset.SuspendLanguageNotEnglish, "", lineOnly},
	RefusedIdentityMismatch:        {StageBeforeAuth, 1, asset.SuspendIdentityMismatch, "", lineOnly},
	FailedIdentityUnreadable:       {StageBeforeAuth, 3, "", "", lineOnly},
	RefusedPasswordPromptAbsent:    {StageAuth, 1, asset.SuspendPasswordPromptAbsent, "", lineOnly}, // no password sent (C7-A2 change 3)
	FailedAuthRejected:             {StageAuth, 1, asset.SuspendAuthFailed, asset.SuspendAuthFailed, lineOnly},
	FailedUnexpectedLevel:          {StageAuth, 1, asset.SuspendUnexpectedLevel, asset.SuspendUnexpectedLevel, lineOnly},
	RefusedLanguageNotEnglish:      {StageAfterAuth, 1, asset.SuspendLanguageNotEnglish, "", lineOnly},
	RefusedFirmwareCondition:       {StageAfterAuth, 1, asset.SuspendFirmwareNotAllowed, "", lineOnly},
	FailedIdentityMismatchLate:     {StageAfterAuth, 1, asset.SuspendIdentityMismatch, asset.SuspendIdentityMismatch, ""},
	FailedAccessLevelDropped:       {StageAfterAuth, 1, "", "", lineOnly},
	FailedDeviceError:              {StageAfterAuth, 1, "", "", lineOnly},
	FailedConfigUnparsable:         {StageAfterAuth, 6, "", "", lineOnly},
	FailedUnexpectedPasswordPrompt: {StageAfterAuth, 2, asset.SuspendUnexpectedLevel, "", lineOnly},
	FailedTimeout:                  {StageAny, 1, "", "", ""},
	FailedTransportClosed:          {StageAny, 1, "", "", ""},
	FailedResponseTooLarge:         {StageAny, 1, "", "", ""},
	FailedEgressViolation:          {StageAny, 1, "", "", ""},
	FailedInternal:                 {StageAny, 1, "", "", ""},
	FailedUnknown:                  {StageAny, 1, "", "", ""},
	PartialParseErrors:             {StageAfterAuth, 1, "", "", ""},
	PartialReadRowsExceeded:        {StageAfterAuth, 1, "", "", ""},
	RefusedEngineIDMismatch:        {StageBeforeAuth, 7, "", "", snmpOnly},
	FailedUSMUnsupportedSecLevel:   {StageAuth, 7, "", "", snmpOnly},
	FailedUSMUnknownUser:           {StageAuth, 7, "", "", snmpOnly},
	FailedUSMWrongDigest:           {StageAuth, 7, "", "", snmpOnly},
	FailedUSMDecryptionError:       {StageAuth, 7, "", "", snmpOnly},
	FailedUSMNotInTimeWindow:       {StageAuth, 7, "", "", snmpOnly},
	FailedSNMPErrorStatus:          {StageAfterAuth, 7, "", "", snmpOnly},
	FailedSNMPWalkNotIncreasing:    {StageAfterAuth, 7, "", "", snmpOnly},
}

// Codes lists every code in the taxonomy of this package's minor.
func Codes() []Code {
	out := make([]Code, 0, len(codes))
	for c := range codes {
		out = append(out, c)
	}
	return out
}

// Known reports whether c is in the taxonomy of this package's minor.
func (c Code) Known() bool { _, ok := codes[c]; return ok }

// Effective is the code a reader acts on: c itself, or FailedUnknown.
func (c Code) Effective() Code {
	if c.Known() {
		return c
	}
	return FailedUnknown
}

// Status is the status a code implies, from its prefix.
func (c Code) Status() Status {
	switch c := c.Effective(); {
	case strings.HasPrefix(string(c), "refused."):
		return StatusRefused
	case strings.HasPrefix(string(c), "partial."):
		return StatusPartial
	}
	return StatusFailed
}

// Since is the minor that added the code: 1 for the 0.1 codes.
func (c Code) Since() int { return codes[c.Effective()].since }

// Stage is how far a session may have got for this code.
func (c Code) Stage() Stage { return codes[c.Effective()].stage }

// Suspends is the C1 suspension reason the collector sets on the asset for
// this code, or "" when the code suspends nothing. Codes after a connection
// suspend when repeating the invocation would send the device the same
// traffic, or the same password, again for the same outcome. Refusals before
// connecting send nothing and repeat harmlessly. An unreadable ID reply
// (failed.identity_unreadable) does not suspend: a repeat sends only the
// Level 0 wake, QUI and ID, never ACC, and each run is reported as a
// failure. Credential suspension is C7's (A3 C1-A3-5).
func (c Code) Suspends() asset.SuspensionReason { return codes[c.Effective()].suspends }

// SuspendsCredential is the C7 suspension reason the collector sets on the
// credential for this code in a line session, or "". A collector reads it
// through Result.SuspendsCredential, which also knows the session (0.7). It
// is set only for codes where the password was sent, so the credential may be exposed or wrong: a rejected
// password, a wrong level after a password, and an identity mismatch after
// authentication (C1-A3-5).
//
// A timeout or a closed connection after ACC or the password, before any
// level prompt, suspends nothing. The relay may still be in "Password: ?" or
// may have counted a failure (H-15, H-04). The C7 failed-auth floor covers it:
// the floor starts when ACC is sent and clears only when "=>" is received
// (D1-20 as amended), so the next session waits it out (A6 C2 review changes 8
// and 14).
func (c Code) SuspendsCredential() asset.SuspensionReason { return codes[c.Effective()].credential }

// SuspendsCredential is the C7 suspension reason the collector sets on the
// credential for this result: the code's, except on an SNMPv3 result, which
// suspends no credential (0.7, C1 on #445). Under USM the keys never cross
// the wire: a response that authenticates against the pinned engine ID came
// from an agent that already holds them, so suspending them protects
// nothing. An authenticated FID mismatch still suspends the asset
// (Code.Suspends) until an operator reviews it.
func (r Result) SuspendsCredential() asset.SuspensionReason {
	if r.Error == nil || r.Session.SNMP != nil {
		return ""
	}
	return r.Error.Code.SuspendsCredential()
}

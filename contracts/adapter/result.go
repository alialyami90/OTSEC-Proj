package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/version"
)

// Result is what the collector reports for one invocation. It is written
// once, at the end of the invocation, and never edited.
type Result struct {
	Schema       string `json:"schema"`
	InvocationID string `json:"invocation_id"`
	// OperationID is the invocation's operation, so that a result can be
	// reconciled on its own (V-S8; C4 collection.operation_id).
	OperationID string     `json:"operation_id"`
	Adapter     AdapterRef `json:"adapter"`
	// RegisterVersion is the verified register package that permitted every
	// line in the transcript (the C7 run's register_version, EP-4). 0 only
	// with refused.register_unverified.
	RegisterVersion uint64 `json:"register_version"`
	// Target says whether the far end was a device or a simulator. It is
	// set from the endpoint's configuration, never from what the far end
	// says, and fixes the C1 evidence class of every observation below.
	Target    asset.EvidenceClass `json:"target"` // device-observed or simulated
	Status    Status              `json:"status"`
	Error     *Error              `json:"error,omitempty"`
	StartedAt string              `json:"started_at"` // RFC 3339 UTC with Z
	EndedAt   string              `json:"ended_at"`
	// Transcript holds every byte sent and received, in order. A refusal
	// before connecting has an empty transcript.
	Transcript Transcript    `json:"transcript"`
	Session    SessionFacts  `json:"session"`
	Identity   IdentityCheck `json:"identity"`
	// Observations are identity facts read in this session, for C1. Each
	// points at its bytes.
	Observations []Observation `json:"observations,omitempty"`
	Warnings     []Warning     `json:"warnings,omitempty"`
	Records      []Record      `json:"records,omitempty"`
}

// AdapterRef names the adapter build and its parser (A4 EP-4).
type AdapterRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Error is the outcome code plus optional free text. The text never
// replaces the code and never contains a secret.
type Error struct {
	Code   Code   `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// Transcript is the session's raw evidence (R4.4, V-S8, EP-1). Data is
// base64 in JSON. Segments cut it into sends and receives that cover every
// byte exactly once, in order. Data is the transcript as stored: credential
// bytes, and any echo of them, are already replaced by RedactionMarker, so
// offsets index stored bytes, not wire bytes (C4 change 1).
type Transcript struct {
	Data       []byte      `json:"data"`
	SHA256     string      `json:"sha256"` // lowercase hex of SHA-256(Data)
	Segments   []Segment   `json:"segments"`
	Redactions []Redaction `json:"redactions"`
}

// Segment is one send or one received chunk.
type Segment struct {
	Offset int64     `json:"offset"`
	Length int64     `json:"length"`
	Dir    Direction `json:"dir"`
	Phase  Phase     `json:"phase"`
	At     string    `json:"at"` // when the chunk was sent or received, RFC 3339 UTC
}

// ReceivedAt is when the bytes of sp were received: the At of the receive
// segment that holds its last byte. C4 uses it as received.utc for an
// adapter-poll event. It is "" for an empty span or one that ends in sent
// bytes.
func (t Transcript) ReceivedAt(sp Span) string {
	if sp.Length <= 0 {
		return ""
	}
	last := sp.Offset + sp.Length - 1
	for _, sg := range t.Segments {
		if last >= sg.Offset && last < sg.Offset+sg.Length {
			if sg.Dir != Received {
				return ""
			}
			return sg.At
		}
	}
	return ""
}

// Direction of a segment. Closed.
type Direction string

const (
	Sent     Direction = "tx"
	Received Direction = "rx"
)

// Phase is the transport phase (A3 §8.3). Phases only move forward. Closed.
type Phase string

const (
	PhaseProbe   Phase = "probe"   // Level 0: QUI language probe, ID for the FID check
	PhaseAuth    Phase = "auth"    // ACC, prompt, credential slot
	PhaseOperate Phase = "operate" // register operations
	PhaseClose   Phase = "close"   // QUI, then TCP close
)

var phaseOrder = map[Phase]int{PhaseProbe: 0, PhaseAuth: 1, PhaseOperate: 2, PhaseClose: 3}

// Redaction marks bytes that replaced a secret (A3 HR-3, A4 EP-3). The
// marker is fixed, so it reveals neither the secret nor its length, and no
// hash of the secret is ever stored.
type Redaction struct {
	Offset    int64           `json:"offset"`
	Length    int64           `json:"length"`
	Reason    RedactionReason `json:"reason"`
	Component string          `json:"component"` // "transport": the only component that holds the secret
}

// RedactionReason is closed.
type RedactionReason string

const (
	// RedactCredential: the password sent in the credential slot.
	RedactCredential RedactionReason = "credential"
	// RedactEcho: the device echoing the password back (C-A2-3).
	RedactEcho RedactionReason = "echo"
)

// RedactionMarker replaces a secret in the stored transcript.
const RedactionMarker = "[REDACTED]"

// SessionFacts are what the transport established, by phase.
type SessionFacts struct {
	Connected bool `json:"connected"`
	// WakeSent: the transport sent one bare line end to get the first
	// prompt, because the device printed nothing on connect. It may do so
	// only when the failed-auth floor has passed since the last session to
	// the endpoint that ended without QUI: a session left inside "Password: ?"
	// would take the line end as a password attempt (S22 p. 7.33, p. 7.16;
	// C7-A2 change 1).
	WakeSent bool `json:"wake_sent"`
	// LanguageProbe is the outcome of the QUI probe: accepted, rejected or
	// not-run (no connection, or a profile without a probe).
	LanguageProbe ProbeOutcome `json:"language_probe"`
	// PasswordPrompt: the bytes received after ACC end with the password
	// prompt.
	PasswordPrompt bool `json:"password_prompt"`
	// CredentialSent: the credential left the node, once, in the slot that
	// only the prompt opens.
	CredentialSent bool `json:"credential_sent"`
	// EchoScan: the transport scanned every byte received after the password
	// for the secret, to the end of the session. "performed" whenever a
	// credential was sent (C-A2-3).
	EchoScan EchoScan `json:"echo_scan"`
	// AccessLevel is the highest level the received prompts showed: "0",
	// "1" or "2" for SEL; "0" when connected and no higher prompt was seen,
	// "" when not connected.
	AccessLevel string `json:"access_level"`
	// QuitSent: QUI was sent in the close phase.
	QuitSent bool `json:"quit_sent"`
}

// ProbeOutcome is closed.
type ProbeOutcome string

const (
	ProbeAccepted ProbeOutcome = "accepted"
	ProbeRejected ProbeOutcome = "rejected"
	ProbeNotRun   ProbeOutcome = "not-run"
)

// EchoScan is closed.
type EchoScan string

const (
	EchoScanPerformed     EchoScan = "performed"
	EchoScanNotApplicable EchoScan = "not-applicable"
)

// IdentityCheck compares the declared identity with what the device printed.
type IdentityCheck struct {
	Result IdentityResult `json:"result"`
	Items  []IdentityItem `json:"items,omitempty"`
}

// IdentityResult is closed.
type IdentityResult string

const (
	IdentityMatch      IdentityResult = "match"
	IdentityMismatch   IdentityResult = "mismatch"
	IdentityNotChecked IdentityResult = "not-checked"
)

// IdentityItem is one compared attribute.
type IdentityItem struct {
	Name     string `json:"name"` // C1 attribute name
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Span     Span   `json:"span"` // where Observed is in the transcript
}

// Observation is one identity fact for C1: an attribute value and its bytes.
type Observation struct {
	Name  string `json:"name"` // C1 attribute name
	Value string `json:"value"`
	Span  Span   `json:"span"`
}

// Warning is a posture warning: a setting read from the device that does
// not stop collection but must be shown (ADR-0005 MAXACC ruling).
type Warning struct {
	// Code is the C3 register's PostureWarning ID, e.g. "warn.maxacc_above_1".
	Code    string `json:"code"`
	Setting string `json:"setting"`
	// Observed is the value as printed. It is empty when Missing is set.
	Observed string `json:"observed,omitempty"`
	// Missing: the setting was not in the output. A missing setting raises
	// the warning; it is never skipped (A3, C3 re-check).
	Missing bool `json:"missing,omitempty"`
	// Span is the setting's bytes, or the whole response when Missing.
	Span Span `json:"span"`
}

// Record is one parsed record: its kind, its bytes, and its fields as the
// device printed them. Parsers are Phase 2; this is only the envelope.
//
// A record was received at Transcript.ReceivedAt(Span): the time of the
// receive segment that holds its last byte.
type Record struct {
	Kind   string  `json:"kind"` // a RecordFields kind, e.g. "sel.ser.row"
	Span   Span    `json:"span"`
	Fields []Field `json:"fields,omitempty"`
	// ContextSpan is the report header that applies to the record (C4
	// native.context_span, EP-2).
	ContextSpan *Span `json:"context_span,omitempty"`
	// ParseOK is false for a record the parser could not read; its bytes are
	// still referenced (EP-1).
	ParseOK bool `json:"parse_ok"`
}

// RecordFields names the fields of each record kind 0.1 defines, in order.
// Values are verbatim device text. For sel.ser.row (S22 Figure 10.16): row
// is the relay's row number, and row 1 is the newest; date is in the
// relay's DATE_F order (S22 p. 7.31) and time is as printed; element and
// state are the Relay Word bit and its printed state. A parsed record of
// one of these kinds carries exactly these fields. Kinds not listed are a
// later minor's.
var RecordFields = map[string][]string{
	"sel.ser.row": {"row", "date", "time", "element", "state"},
}

// Field is one native field, verbatim.
type Field struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Span is a byte range in the transcript.
type Span struct {
	Offset int64 `json:"offset"`
	Length int64 `json:"length"`
}

var (
	Statuses         = []Status{StatusOK, StatusPartial, StatusRefused, StatusFailed}
	Directions       = []Direction{Sent, Received}
	Phases           = []Phase{PhaseProbe, PhaseAuth, PhaseOperate, PhaseClose}
	RedactionReasons = []RedactionReason{RedactCredential, RedactEcho}
	ProbeOutcomes    = []ProbeOutcome{ProbeAccepted, ProbeRejected, ProbeNotRun}
	EchoScans        = []EchoScan{EchoScanPerformed, EchoScanNotApplicable}
	IdentityResults  = []IdentityResult{IdentityMatch, IdentityMismatch, IdentityNotChecked}
)

var (
	hexSHA256     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	recordKind    = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`)
	warningCode   = regexp.MustCompile(`^warn\.[a-z0-9_]+$`)
	settingName   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,15}$`)
	adapterIDText = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// DecodeResult parses and validates a result. Decoding is strict except for
// forward compatibility (strictjson.Forward, D1-10): case-variant and
// duplicate keys are rejected, unknown exact-case fields are ignored.
//
// A result of this package's own minor or earlier is decoded with
// strictjson.Decode as well, so a writer bug in 0.1 is caught (A6 C2 review
// change 9; the same rule as C1 and C4).
func DecodeResult(b []byte) (Result, error) {
	var r Result
	if err := strictjson.Forward(b, &r); err != nil {
		return Result{}, fmt.Errorf("adapter: result: %w", err)
	}
	if id, err := version.Parse(r.Schema); err == nil && id.Name == self.Name && id.Major == self.Major && id.Minor <= self.Minor {
		var own Result
		if err := strictjson.Decode(b, &own); err != nil {
			return Result{}, fmt.Errorf("adapter: result: %w", err)
		}
	}
	return r, r.Validate()
}

// Validate checks every rule that can be checked from the result alone.
func (r Result) Validate() error {
	id, err := version.Parse(r.Schema)
	if err != nil || !self.Accepts(id) {
		return fmt.Errorf("adapter: result: schema %q is not readable as %s", r.Schema, Contract)
	}
	c := &check{later: id.Minor > self.Minor}
	if !uuidPattern.MatchString(r.InvocationID) {
		c.fail("invocation_id %q is not a lowercase UUID", r.InvocationID)
	}
	if !operationIDPattern.MatchString(r.OperationID) {
		c.fail("operation_id %q is not an operation ID", r.OperationID)
	}
	if !adapterIDText.MatchString(r.Adapter.ID) || r.Adapter.Version == "" {
		c.fail("adapter id and version are required (EP-4)")
	}
	if r.Target != asset.DeviceObserved && r.Target != asset.Simulated {
		c.fail("target must be %q or %q", asset.DeviceObserved, asset.Simulated)
	}
	if !asset.ValidTime(r.StartedAt) || !asset.ValidTime(r.EndedAt) {
		c.fail("started_at and ended_at must be RFC 3339 UTC times")
	}
	code := c.status(r)
	if r.RegisterVersion == 0 && code != RefusedRegisterUnverified {
		c.fail("register_version is required: the register package that permitted the lines (EP-4)")
	}
	t := r.Transcript
	if !c.transcript(t) {
		// The bytes cannot be cut into segments, so no rule about them
		// can be checked.
		return c.err()
	}
	c.session(r, code)
	c.identity(r, code)
	for i, o := range r.Observations {
		if !asset.ValidAttributeName(o.Name) || o.Value == "" {
			c.fail("observations[%d]: needs a C1 attribute name and a value", i)
		}
		c.rxSpan(fmt.Sprintf("observations[%d].span", i), o.Span, t)
	}
	for i, w := range r.Warnings {
		if !warningCode.MatchString(w.Code) || !settingName.MatchString(w.Setting) || (w.Observed == "") != w.Missing {
			c.fail("warnings[%d]: needs a register warning code, a setting name, and either the observed value or missing", i)
		}
		c.rxSpan(fmt.Sprintf("warnings[%d].span", i), w.Span, t)
	}
	for i, rec := range r.Records {
		if !recordKind.MatchString(rec.Kind) {
			c.fail("records[%d].kind %q is not a record kind", i, rec.Kind)
		}
		c.rxSpan(fmt.Sprintf("records[%d].span", i), rec.Span, t)
		if rec.ContextSpan != nil {
			c.rxSpan(fmt.Sprintf("records[%d].context_span", i), *rec.ContextSpan, t)
		}
		for j, f := range rec.Fields {
			if f.Name == "" {
				c.fail("records[%d].fields[%d].name is empty", i, j)
			}
		}
		if want, ok := RecordFields[rec.Kind]; ok && rec.ParseOK {
			names := make([]string, len(rec.Fields))
			for j, f := range rec.Fields {
				names[j] = f.Name
			}
			if !slices.Equal(names, want) {
				c.fail("records[%d]: a %s carries the fields %v, not %v", i, rec.Kind, want, names)
			}
		}
	}
	if code == PartialParseErrors {
		bad := false
		for _, rec := range r.Records {
			bad = bad || !rec.ParseOK
		}
		if !bad {
			c.fail("partial.parse_errors needs at least one record with parse_ok false")
		}
	}
	if code == PartialReadRowsExceeded {
		for i, rec := range r.Records {
			if rec.ParseOK {
				c.fail("records[%d]: partial.read_rows_exceeded keeps the bytes but parses no record (D1-12)", i)
			}
		}
		if r.Error.Detail == "" {
			c.fail("partial.read_rows_exceeded needs a detail giving the row count and the limit")
		}
	}
	if r.Status == StatusOK {
		for i, rec := range r.Records {
			if !rec.ParseOK {
				c.fail("records[%d]: status ok with a record that did not parse; use partial.parse_errors", i)
			}
		}
	}
	return c.err()
}

// status checks Status against Error and returns the effective code ("" for ok).
func (c *check) status(r Result) Code {
	if !contains(Statuses, r.Status) {
		if !c.later {
			c.fail("status %q is not one of the 0.1 values", r.Status)
		}
	}
	if r.Status == StatusOK {
		if r.Error != nil {
			c.fail("status ok carries no error")
		}
		return ""
	}
	if r.Error == nil {
		c.fail("status %q needs an error code", r.Status)
		return FailedUnknown
	}
	// The detail is the collector's own words: bounded printable ASCII, never
	// device text, which belongs in spans (A3 change 9; C8 refuses CR and LF).
	if d := r.Error.Detail; len(d) > MaxDetailLen || !printable(d) {
		c.fail("error.detail must be at most %d bytes of printable ASCII", MaxDetailLen)
	}
	code := r.Error.Code
	if !code.Known() {
		if !c.later {
			c.fail("error code %q is not in the 0.1 taxonomy", code)
		}
		code = FailedUnknown
	}
	if code.Status() != r.Status && code != FailedUnknown {
		c.fail("error code %q implies status %q, not %q", code, code.Status(), r.Status)
	}
	return code
}

// transcript checks the bytes, the hash, the exact cover and the redactions.
// It reports whether the segments cover the bytes exactly.
func (c *check) transcript(t Transcript) bool {
	sum := sha256.Sum256(t.Data)
	if !hexSHA256.MatchString(t.SHA256) || hex.EncodeToString(sum[:]) != t.SHA256 {
		c.fail("transcript.sha256 does not match the data")
	}
	var next int64
	last := -1
	for i, s := range t.Segments {
		p := fmt.Sprintf("transcript.segments[%d]", i)
		if s.Offset != next || s.Length <= 0 {
			c.fail("%s: segments must cover the transcript exactly, in order, with no gap or overlap (offset %d, expected %d)", p, s.Offset, next)
		}
		next = s.Offset + s.Length
		if !contains(Directions, s.Dir) {
			c.fail("%s.dir %q is not tx or rx", p, s.Dir)
		}
		o, ok := phaseOrder[s.Phase]
		if !ok {
			c.fail("%s.phase %q is not a phase", p, s.Phase)
		} else if o < last {
			c.fail("%s: phase %s after %s; phases only move forward", p, s.Phase, Phases[last])
		} else {
			last = o
		}
		if !asset.ValidTime(s.At) {
			c.fail("%s.at is not an RFC 3339 UTC time", p)
		}
	}
	covered := next == int64(len(t.Data))
	for _, s := range t.Segments {
		covered = covered && s.Offset >= 0 && s.Length > 0 && s.Offset+s.Length <= int64(len(t.Data))
	}
	if next != int64(len(t.Data)) {
		c.fail("transcript.segments cover %d bytes but the data has %d; spans must cover the bytes exactly", next, len(t.Data))
	}
	if !covered {
		return false
	}
	var credAt int64 = -1
	for _, rd := range t.Redactions {
		if rd.Reason == RedactCredential {
			credAt = rd.Offset
		}
	}
	for i, rd := range t.Redactions {
		p := fmt.Sprintf("transcript.redactions[%d]", i)
		seg, ok := segmentAt(t, rd.Offset, rd.Length)
		if !ok {
			c.fail("%s: a redaction must lie inside one segment", p)
			continue
		}
		if string(t.Data[rd.Offset:rd.Offset+rd.Length]) != RedactionMarker {
			c.fail("%s: the bytes there are not the redaction marker", p)
		}
		if rd.Component != "transport" {
			c.fail("%s.component must be \"transport\"", p)
		}
		switch rd.Reason {
		case RedactCredential:
			if seg.Dir != Sent || seg.Phase != PhaseAuth {
				c.fail("%s: a credential redaction lies in a sent auth-phase segment", p)
			}
		case RedactEcho:
			// Anywhere the device may print the password back after it
			// was sent, to the end of the session (A3 change 8).
			if seg.Dir != Received || credAt < 0 || rd.Offset < credAt {
				c.fail("%s: an echo redaction lies in a received segment after the credential", p)
			}
		default:
			c.fail("%s.reason %q is not credential or echo", p, rd.Reason)
		}
		for j := 0; j < i; j++ {
			q := t.Redactions[j]
			if rd.Offset < q.Offset+q.Length && q.Offset < rd.Offset+rd.Length {
				c.fail("%s overlaps redactions[%d]", p, j)
			}
		}
	}
	return true
}

// session checks the session facts against the transcript and the code.
func (c *check) session(r Result, code Code) {
	t, s := r.Transcript, r.Session
	if !contains(ProbeOutcomes, s.LanguageProbe) {
		c.fail("session.language_probe %q is not a probe outcome", s.LanguageProbe)
	}
	if !contains(EchoScans, s.EchoScan) {
		c.fail("session.echo_scan %q is not an echo-scan value", s.EchoScan)
	}
	has := func(ph Phase, d Direction) bool {
		for _, sg := range t.Segments {
			if sg.Phase == ph && sg.Dir == d {
				return true
			}
		}
		return false
	}
	credentials := 0
	for _, rd := range t.Redactions {
		if rd.Reason == RedactCredential {
			credentials++
		}
	}

	if !s.Connected {
		if len(t.Data) != 0 || s.LanguageProbe != ProbeNotRun || s.AccessLevel != "" || s.QuitSent {
			c.fail("session: not connected, so the transcript is empty, the probe not-run and no level reached")
		}
	}
	// The credential slot opens only after the prompt (A3 §4.2, C-17).
	if s.CredentialSent && !s.PasswordPrompt {
		c.fail("session: a credential was sent without a password prompt")
	}
	if s.CredentialSent != (credentials == 1) || credentials > 1 {
		c.fail("session: credential_sent needs exactly one credential redaction, and none otherwise (found %d)", credentials)
	}
	// Echo redaction is mandatory until a capture shows no echo (C-A2-3).
	if s.CredentialSent && s.EchoScan != EchoScanPerformed {
		c.fail("session: a credential was sent, so echo_scan must be performed")
	}
	if !s.CredentialSent && s.EchoScan != EchoScanNotApplicable {
		c.fail("session: echo_scan is not-applicable when no credential was sent")
	}
	if (s.CredentialSent || s.PasswordPrompt) && !has(PhaseAuth, Sent) {
		c.fail("session: a prompt or credential needs a sent auth-phase segment")
	}
	if s.LanguageProbe == ProbeRejected && code != RefusedLanguageProbe {
		c.fail("session: a rejected probe ends with %s", RefusedLanguageProbe)
	}
	c.dialogue(r, code)

	switch code.Stage() {
	case StageBeforeConnect:
		if code != "" && s.Connected {
			c.fail("error %s is decided before connecting, so the session is not connected", code)
		}
	case StageBeforeAuth:
		if !s.Connected || has(PhaseAuth, Sent) || s.CredentialSent {
			c.fail("error %s is decided before authentication: connected, with no auth phase and no credential", code)
		}
	}

	switch code {
	case "":
		if !s.Connected || !s.QuitSent || s.LanguageProbe == ProbeRejected {
			c.fail("status ok needs a connected session that ended with QUI (V-S13)")
		}
	case PartialParseErrors, PartialReadRowsExceeded:
		if !s.QuitSent {
			c.fail("a partial result still ends with QUI (V-S13)")
		}
	case RefusedSessionElevated:
		// Nothing but the wake may be sent to a session left elevated.
		for _, sg := range t.Segments {
			if sg.Dir == Sent && !isWake(t.Data[sg.Offset:sg.Offset+sg.Length]) {
				c.fail("%s: nothing but the wake is sent to a session left elevated", code)
				break
			}
		}
		if s.AccessLevel == "0" || s.AccessLevel == "" {
			c.fail("%s needs the elevated level seen", code)
		}
	case RefusedLanguageProbe:
		if s.LanguageProbe != ProbeRejected {
			c.fail("%s needs language_probe rejected", code)
		}
	case RefusedPasswordPromptAbsent:
		// ACC went straight to Level 1. The relay is not in a password
		// prompt, so QUI is safe and drops it back to Level 0 (D18).
		if s.PasswordPrompt || s.CredentialSent || !s.QuitSent || !has(PhaseAuth, Sent) {
			c.fail("%s: ACC sent, no prompt, no credential, then QUI", code)
		}
	case FailedAuthRejected:
		if !s.CredentialSent || s.QuitSent {
			c.fail("%s: the credential was sent and QUI was not (C-19)", code)
		}
	case FailedUnexpectedLevel:
		if !s.QuitSent {
			c.fail("%s: send QUI, then close (A3 §8.3)", code)
		}
	}
	if code.Stage() == StageAfterAuth && code != "" {
		if !s.CredentialSent && s.AccessLevel != "1" {
			c.fail("error %s happens after authentication", code)
		}
		// QUI drops Level 1 to Level 0 (D18). Two exceptions: the level has
		// already dropped, or the port turned out not to be English, where
		// QUI is not a known command and nothing more may be sent (D16).
		switch code {
		case FailedAccessLevelDropped:
		case RefusedLanguageNotEnglish:
			if s.QuitSent {
				c.fail("%s: the port is not English, so QUI is not sent; close the connection (D16)", code)
			}
		default:
			if !s.QuitSent {
				c.fail("error %s happens at Level 1, so the session ends with QUI (D18)", code)
			}
		}
	}
}

// identity checks the identity result against the code.
func (c *check) identity(r Result, code Code) {
	id := r.Identity
	if !contains(IdentityResults, id.Result) {
		c.fail("identity.result %q is not match, mismatch or not-checked", id.Result)
		return
	}
	differs := false
	for i, it := range id.Items {
		if !asset.ValidAttributeName(it.Name) || it.Expected == "" {
			c.fail("identity.items[%d]: needs a C1 attribute name and the expected value", i)
		}
		c.rxSpan(fmt.Sprintf("identity.items[%d].span", i), it.Span, r.Transcript)
		differs = differs || it.Expected != it.Observed
	}
	switch id.Result {
	case IdentityMatch:
		if len(id.Items) == 0 || differs {
			c.fail("identity match needs items, all equal")
		}
	case IdentityMismatch:
		if !differs {
			c.fail("identity mismatch needs an item that differs")
		}
		if code != RefusedIdentityMismatch && code != FailedIdentityMismatchLate {
			c.fail("an identity mismatch ends the invocation with an identity_mismatch code")
		}
	case IdentityNotChecked:
		if len(id.Items) != 0 {
			c.fail("identity not-checked has no items")
		}
		if r.Session.CredentialSent {
			c.fail("a credential was sent without an identity check (AP-27)")
		}
	}
	// AP-27: the password goes only to the device we meant, so a match read
	// at Level 0, before the auth phase, must precede it. Items read later,
	// such as the SER header serial, are checked as well.
	if r.Session.CredentialSent {
		var firstAuth int64 = -1
		for _, sg := range r.Transcript.Segments {
			if sg.Phase == PhaseAuth && sg.Dir == Sent {
				firstAuth = sg.Offset
				break
			}
		}
		pre := false
		for _, it := range id.Items {
			sg, ok := segmentAt(r.Transcript, it.Span.Offset, it.Span.Length)
			pre = pre || (it.Expected == it.Observed && ok && sg.Phase == PhaseProbe && sg.Dir == Received &&
				(firstAuth < 0 || it.Span.Offset < firstAuth))
		}
		if !pre {
			c.fail("a credential was sent, so a matching identity item read in the probe phase must precede it (AP-27)")
		}
	}
	if (code == RefusedIdentityMismatch || code == FailedIdentityMismatchLate) && id.Result != IdentityMismatch {
		c.fail("%s needs identity.result mismatch", code)
	}
	if r.Status == StatusOK && id.Result != IdentityMatch {
		c.fail("status ok needs a matching identity")
	}
}

// rxSpan checks that a span lies in received bytes, touches no redaction
// and holds no framing byte.
func (c *check) rxSpan(path string, sp Span, t Transcript) {
	if sp.Offset < 0 || sp.Length <= 0 || sp.Offset+sp.Length > int64(len(t.Data)) {
		c.fail("%s lies outside the transcript", path)
		return
	}
	for _, sg := range t.Segments {
		if sp.Offset < sg.Offset+sg.Length && sg.Offset < sp.Offset+sp.Length && sg.Dir != Received {
			c.fail("%s covers sent bytes; records and observations point into received bytes only", path)
			return
		}
	}
	for _, rd := range t.Redactions {
		if sp.Offset < rd.Offset+rd.Length && rd.Offset < sp.Offset+sp.Length {
			c.fail("%s overlaps a redaction", path)
			return
		}
	}
	// A record is text: the STX and ETX that frame a relay message are not
	// part of it (S22 p. 7.28; A4's record bytes and C6 dtext depend on it).
	if bytes.ContainsAny(t.Data[sp.Offset:sp.Offset+sp.Length], "\x02\x03") {
		c.fail("%s includes an STX or ETX framing byte", path)
	}
}

// MaxDetailLen bounds error.detail.
const MaxDetailLen = 256

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func segmentAt(t Transcript, off, n int64) (Segment, bool) {
	for _, sg := range t.Segments {
		if off >= sg.Offset && off+n <= sg.Offset+sg.Length && n > 0 {
			return sg, true
		}
	}
	return Segment{}, false
}

type check struct {
	later bool
	errs  []error
}

func (c *check) fail(f string, a ...any) { c.errs = append(c.errs, fmt.Errorf(f, a...)) }

func (c *check) err() error {
	if len(c.errs) == 0 {
		return nil
	}
	return fmt.Errorf("adapter: result: %w", errors.Join(c.errs...))
}

func contains[T comparable](xs []T, x T) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

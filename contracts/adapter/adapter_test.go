package adapter

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
)

// resultWant is the error each invalid result must produce. Every file in
// testdata/results/invalid must be listed, so a new example cannot pass by
// failing for an unrelated reason.
var resultWant = map[string]string{
	"segments-gap":                                     "no gap or overlap",
	"segments-short":                                   "spans must cover the bytes exactly",
	"bytes-beyond-segments":                            "spans must cover the bytes exactly",
	"sha256-mismatch":                                  "sha256 does not match",
	"phase-backwards":                                  "phases only move forward",
	"credential-not-redacted":                          "not the redaction marker",
	"credential-without-prompt":                        "without a password prompt",
	"credential-without-echo-scan":                     "echo_scan must be performed",
	"credential-without-redaction":                     "exactly one credential redaction",
	"credential-redaction-labelled-echo":               "an echo redaction lies in a received",
	"ok-without-quit":                                  "ended with QUI",
	"ok-with-error-code":                               "status ok carries no error",
	"status-disagrees-with-code":                       `implies status "refused", not "failed"`,
	"unknown-code-at-0.1":                              "is not in the otsec.adapter/0.2 taxonomy",
	"probe-rejected-at-level1-at-0.1":                  "so the session ends with QUI",
	"unexpected-password-prompt-at-0.1":                "is new in 0.2, so a 0.1 result cannot carry it",
	"unexpected-password-prompt-then-quit":             "is a password attempt",
	"unexpected-password-prompt-for-rejected-password": "Level 1 was reached, an operate line was the last sent",
	"span-in-sent-bytes":                               "covers sent bytes",
	"span-on-echo-redaction":                           "overlaps a redaction",
	"ok-with-unparsed-record":                          "use partial.parse_errors",
	"identity-mismatch-reported-ok":                    "ends the invocation with an identity_mismatch code",
	"warning-without-value":                            "either the observed value or missing",
	"simulator-reported-as-device":                     "target must be",
	"other-major":                                      "not readable as otsec.adapter/0.2",
	"span-includes-stx":                                "includes an STX or ETX framing byte",
	"read-rows-exceeded-with-parsed-record":            "parses no record (D1-12)",
	"read-rows-exceeded-without-detail":                "needs a detail giving the row count",
	"ser-row-field-renamed":                            "a sel.ser.row carries the fields",
	"ser-row-field-names-lowercase":                    "a sel.ser.row carries the fields",
	"no-operation-id":                                  "operation_id \"\" is not an operation ID",
	"wake-into-password-prompt":                        "only when nothing was received",
	"quit-after-unconfirmed-password":                  "no level prompt confirmed (C-19, D1-20)",
	"quit-after-unanswered-acc":                        `"QUI" sent before a prompt`,
	"quit-after-rejected-probe":                        "the QUI probe is the last line sent (D16)",
	"credential-and-quit-in-one-segment":               "exactly the redaction marker and one line end",
	"credential-without-password-prompt":               "without a received password prompt",
	"auth-line-not-acc":                                "the auth phase sends ACC once",
	"acc-without-language-probe":                       "ACC sent without an accepted language probe",
	"operate-line-without-prompt":                      `"SER" sent before the "=>" prompt`,
	"setting-read-as-prompt":                           `"SER" sent before the "=>" prompt`,
	"close-line-not-quit":                              "the close phase sends QUI only",
	"timeout-at-level1-without-quit":                   "so the session ends with QUI (D18, V-S13)",
	"elevated-with-level0-prompt":                      "not an elevated one",
	"access-level-without-prompt":                      "the highest prompt received shows",
	"identity-only-after-password":                     "must precede it (AP-27)",
	"detail-with-device-text":                          "error.detail must be at most",
	"unknown-field-in-own-minor":                       "is not a field name",
	"auth-rejected-then-quit":                          "QUI was not (C-19)",
	"before-connect-code-but-connected":                "decided before connecting",
	"identity-mismatch-code-with-match":                "needs identity.result mismatch",
	"prompt-absent-without-quit":                       "no prompt, no credential, then QUI",
	"probe-rejected-wrong-code":                        "a rejected probe ends with refused.language_probe_rejected",
	"partial-without-unparsed-record":                  "at least one record with parse_ok false",
	"language-not-english-then-quit":                   "QUI is not sent",
	"probe-before-prompt":                              `sent before the "=" prompt`,
	"probe-accepted-but-reply-off-grammar":             "does not match the probe grammar",
	"no-register-version":                              "register_version is required",
	"session-elevated-then-quit":                       "nothing but the wake is sent",
	"wake-after-prompt":                                "sent once, first, and only when nothing was received",
}

var invocationWant = map[string]string{
	"unknown-field":         `key "command" is not a field name`,
	"case-variant-key":      `key "OPERATION_ID" is not a field name`,
	"duplicate-key":         `duplicate key "operation_id"`,
	"limits-above-ceiling":  "max_response_bytes 1073741824 is outside",
	"deadline-below-step":   "deadline_ms 1000 is outside",
	"no-expected-identity":  "expected_identity is required",
	"params-with-free-text": "is not a parameter name and value",
	"other-major":           "not readable as otsec.adapter/0.2",
	"credential-ref-not-c7": "not a C7 credential reference ID",
	"principal-ref-not-c7":  "not a C7 principal ID",
}

func files(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join("testdata", dir, "*.json"))
	if err != nil || len(m) == 0 {
		t.Fatalf("no examples in testdata/%s", dir)
	}
	sort.Strings(m)
	return m
}

func name(f string) string { return strings.TrimSuffix(filepath.Base(f), ".json") }

func loadResult(t *testing.T, n string) Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "results", "valid", n+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResult(b)
	if err != nil {
		t.Fatalf("%s: %v", n, err)
	}
	return r
}

func TestValidResults(t *testing.T) {
	for _, f := range files(t, "results/valid") {
		b, _ := os.ReadFile(f)
		if _, err := DecodeResult(b); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestValidInvocations(t *testing.T) {
	for _, f := range files(t, "invocations/valid") {
		b, _ := os.ReadFile(f)
		if _, err := DecodeInvocation(b); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func checkInvalid(t *testing.T, dir string, want map[string]string, decode func([]byte) error) {
	seen := map[string]bool{}
	for _, f := range files(t, dir) {
		n := name(f)
		seen[n] = true
		w, ok := want[n]
		if !ok {
			t.Errorf("%s: not listed", f)
			continue
		}
		b, _ := os.ReadFile(f)
		if err := decode(b); err == nil {
			t.Errorf("%s: accepted", f)
		} else if !strings.Contains(err.Error(), w) {
			t.Errorf("%s: error does not mention %q:\n%v", f, w, err)
		}
	}
	for n := range want {
		if !seen[n] {
			t.Errorf("%s lists %s but there is no such file", dir, n)
		}
	}
}

func TestInvalidResults(t *testing.T) {
	checkInvalid(t, "results/invalid", resultWant, func(b []byte) error { _, err := DecodeResult(b); return err })
}

func TestInvalidInvocations(t *testing.T) {
	checkInvalid(t, "invocations/invalid", invocationWant, func(b []byte) error { _, err := DecodeInvocation(b); return err })
}

// Every code in the taxonomy has a valid example result that carries it,
// built with the transcript its stage allows (C2 acceptance test 1).
func TestEveryCodeHasAnExample(t *testing.T) {
	for _, c := range Codes() {
		r := loadResult(t, string(c))
		if r.Error == nil {
			t.Errorf("%s: example carries no error", c)
			continue
		}
		if got := r.Error.Code.Effective(); got != c {
			t.Errorf("%s: example reads as %s", c, got)
		}
		if r.Status != c.Status() {
			t.Errorf("%s: status %s, want %s", c, r.Status, c.Status())
		}
	}
	if r := loadResult(t, "ok"); r.Status != StatusOK || r.Error != nil {
		t.Errorf("ok example: status %s, error %v", r.Status, r.Error)
	}
}

func TestUnknownCodeReadsAsFailedUnknown(t *testing.T) {
	r := loadResult(t, "failed.unknown")
	if r.Error.Code.Known() || r.Error.Code.Effective() != FailedUnknown || r.Error.Code.Status() != StatusFailed {
		t.Fatalf("code %q: known %v, effective %s", r.Error.Code, r.Error.Code.Known(), r.Error.Code.Effective())
	}
}

func TestCodeTable(t *testing.T) {
	for _, c := range Codes() {
		prefix, _, _ := strings.Cut(string(c), ".")
		if Status(prefix) != c.Status() {
			t.Errorf("%s: status %s does not match its prefix", c, c.Status())
		}
		// A refusal before connecting sends nothing, so repeating it is
		// harmless and it suspends nothing.
		if c.Stage() == StageBeforeConnect && c.Suspends() != "" {
			t.Errorf("%s: suspends %s before connecting", c, c.Suspends())
		}
		if s := c.Suspends(); s != "" && !contains(asset.SuspensionReasons, s) {
			t.Errorf("%s: suspension %q is not a C1 reason", c, s)
		}
	}
	for c, want := range map[Code]asset.SuspensionReason{
		RefusedLanguageProbe:           asset.SuspendLanguageNotEnglish,
		RefusedIdentityMismatch:        asset.SuspendIdentityMismatch,
		FailedIdentityMismatchLate:     asset.SuspendIdentityMismatch,
		FailedAuthRejected:             asset.SuspendAuthFailed,
		RefusedPasswordPromptAbsent:    asset.SuspendPasswordPromptAbsent,
		FailedUnexpectedPasswordPrompt: asset.SuspendUnexpectedLevel,
		FailedTimeout:                  "",
	} {
		if got := c.Suspends(); got != want {
			t.Errorf("%s suspends %q, want %q", c, got, want)
		}
	}
}

// The QUI probe reply grammar (ADR-0005). The accepted forms follow S22
// Figure 1.4 (header lines without milliseconds, then "=") and Table 7.16
// (time with milliseconds). The echo and the "Level 0" line are not
// documented (H-13); the grammar tolerates them. Every text here is
// constructed, not captured.
// The credential is suspended only where the password was sent (C7 design
// section 7, C7-A2 changes 2 and 3).
func TestSuspendsCredential(t *testing.T) {
	want := map[Code]asset.SuspensionReason{
		FailedAuthRejected:         asset.SuspendAuthFailed,
		FailedUnexpectedLevel:      asset.SuspendUnexpectedLevel,
		FailedIdentityMismatchLate: asset.SuspendIdentityMismatch,
	}
	for _, c := range Codes() {
		if got := c.SuspendsCredential(); got != want[c] {
			t.Errorf("%s suspends the credential with %q, want %q", c, got, want[c])
		}
		if c.SuspendsCredential() != "" && c.Stage() != StageAuth && c.Stage() != StageAfterAuth {
			t.Errorf("%s suspends the credential before authentication", c)
		}
	}
	for _, c := range []Code{RefusedIdentityMismatch, RefusedPasswordPromptAbsent, RefusedSessionElevated, RefusedLanguageProbe} {
		if c.SuspendsCredential() != "" {
			t.Errorf("%s: no password was sent, so the credential is not suspended", c)
		}
	}
	if RefusedSessionElevated.Suspends() != "" {
		t.Error("an elevated first prompt clears with TIDLE; the asset is not suspended")
	}
}

// The spans in the C1 golden asset point into this package's example
// transcript of the same invocation, and select the values they claim (A6
// C1 review change 4).
func TestC1SpansSelectTheirValues(t *testing.T) {
	r := loadResult(t, "ok")
	b, err := os.ReadFile(filepath.Join("..", "asset", "testdata", "valid", "sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, at := range a.Attributes {
		for _, ob := range at.Observations {
			sp := ob.Source.Span
			if sp == nil || ob.Source.Ref != r.InvocationID {
				continue
			}
			n++
			if got := string(r.Transcript.Data[sp.Offset : sp.Offset+sp.Length]); got != ob.Value {
				t.Errorf("%s: span selects %q, want %q", at.Name, got, ob.Value)
			}
		}
	}
	if n == 0 {
		t.Fatal("no C1 span refers to this invocation")
	}
}

func TestProbeGrammar(t *testing.T) {
	header := "SEL-751          Date: 10/24/2026  Time: 09:15:00\r\nFEEDER 1         Time Source: Internal\r\n"
	accept := map[string]string{
		"figure 1.4 form":    "\r\n" + header + "\r\n=",
		"milliseconds":       "\r\nSEL-751   Date: 2026/10/24  Time: 09:15:00.123\r\nFEEDER 1  Time Source: EXTERNAL\r\n=",
		"echo":               "QUI\r\n\r\n" + header + "\r\n=",
		"echo QUIT":          "QUIT\r\n" + header + "=",
		"level 0 line":       "\r\n" + header + "\r\nLevel 0\r\n=",
		"prompt only":        "\r\n=",
		"flow control bytes": "\x13\x11\r\n" + header + "\x00\r\n=",
		"bare LF line ends":  "\n" + strings.ReplaceAll(header, "\r\n", "\n") + "=",
		"empty RID and TID":  " Date: 10/24/2026 Time: 09:15:00\r\n Time Source: internal\r\n=",
		"16-character RID":   "ABCDEFGHIJKLMNOP Date: 10/24/2026 Time: 09:15:00\r\nFEEDER 1 Time Source: Internal\r\n=",
		// S22 p. 7.28: every message is <STX> lines <CRLF> <ETX>. The prompt
		// after ETX is assumed (no capture), as in A6's simulator.
		"STX and ETX":          "QUI\r\n\x02\r\n" + header + "\r\n\x03=",
		"STX and ETX, no echo": "\x02\r\n" + header + "\x03\r\n=",
	}
	reject := map[string]string{
		"empty":                "",
		"level 1 prompt":       "\r\n" + header + "\r\n=>",
		"level 2 prompt":       "\r\n" + header + "\r\n=>>",
		"text after prompt":    "\r\n" + header + "\r\n= ",
		"invalid command":      "QUI\r\nInvalid Command\r\n=",
		"spanish":              "QUI\r\nComando no valido\r\n=",
		"password prompt":      "\r\nPassword: ? ",
		"non-ascii":            "\r\nSEL-751 Date: 10/24/2026 Time: 09:15:00\r\nFEEDER \xc3\xa9 Time Source: Internal\r\n=",
		"escape byte":          "\x1b[2J\r\n=",
		"17-character RID":     "ABCDEFGHIJKLMNOPQ Date: 10/24/2026 Time: 09:15:00\r\nFEEDER 1 Time Source: Internal\r\n=",
		"one header line only": "\r\nSEL-751 Date: 10/24/2026 Time: 09:15:00\r\n=",
		"bad time source":      "\r\nSEL-751 Date: 10/24/2026 Time: 09:15:00\r\nFEEDER 1 Time Source: GPS\r\n=",
		"no prompt":            "\r\n" + header,
	}
	for n, s := range accept {
		if !ProbeReplyAccepted([]byte(s)) {
			t.Errorf("%s: rejected: %q", n, s)
		}
	}
	for n, s := range reject {
		if ProbeReplyAccepted([]byte(s)) {
			t.Errorf("%s: accepted: %q", n, s)
		}
	}
}

// sel751 is A2's SEL-751 register content (C3).
func sel751(t *testing.T) RegisterLookup {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	m, err := register.NewMatcher(p)
	if err != nil {
		t.Fatal(err)
	}
	return RegisterLookup{M: m}
}

func validInvocation(t *testing.T) Invocation {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "invocations", "valid", "sel-ser-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := DecodeInvocation(b)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func codeOf(err error) Code {
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// RegisterLookup answers from the register: operations are invocable at
// their access level, and session-control lines, deny rules and unknown IDs
// are not (C-A2-1).
func TestRegisterLookup(t *testing.T) {
	reg := sel751(t)
	for op, want := range map[string]string{
		"sel.id": "0", "sel.ser.read_all": "1", "sel.settings.show_global": "1", "sel.settings.show_port1": "1",
	} {
		if got, err := reg.Invocable(op, nil); err != nil || got != want {
			t.Errorf("%s: level %q, %v; want %q", op, got, err, want)
		}
	}
	for _, op := range []string{"sel.session.acc", "sel.session.qui", "sel.ser.clear", "sel.ser.other_args",
		"sel.access.elevate", "sel.breaker.ope", "sel.unknown_read", ""} {
		var nf *NotInvocableError
		if _, err := reg.Invocable(op, nil); !errors.As(err, &nf) {
			t.Errorf("%s: %v, want NotInvocableError", op, err)
		}
	}
	if _, err := reg.Invocable("sel.ser.read_all", map[string]string{"rows": "10"}); err == nil {
		t.Error("parameters on a literal operation accepted")
	}
}

// An invocation naming a session-control line or an unknown operation is
// refused before connecting (C2 acceptance test 3).
func TestValidateWith(t *testing.T) {
	reg := sel751(t)
	inv := validInvocation(t)
	if err := inv.ValidateWith(reg); err != nil {
		t.Fatalf("valid invocation refused: %v", err)
	}
	for op, want := range map[string]Code{
		"sel.session.acc":  RefusedNotInvocable, // session control: never an operation
		"sel.session.qui":  RefusedNotInvocable,
		"sel.ser.clear":    RefusedNotInvocable, // a deny rule
		"sel.unknown_read": RefusedNotInvocable,
	} {
		i := inv
		i.OperationID = op
		if got := codeOf(i.ValidateWith(reg)); got != want {
			t.Errorf("%s: code %q, want %q", op, got, want)
		}
	}
	i := inv
	i.Params = map[string]string{"rows": "10"}
	if got := codeOf(i.ValidateWith(reg)); got != RefusedInvalidParams {
		t.Errorf("params on a literal operation: code %q", got)
	}
	i = inv
	i.CredentialRef = ""
	if got := codeOf(i.ValidateWith(reg)); got != RefusedCredentialUnavailable {
		t.Errorf("Level 1 operation with no credential: code %q", got)
	}
	i.OperationID = "sel.id"
	if err := i.ValidateWith(reg); err != nil {
		t.Errorf("Level 0 operation with no credential refused: %v", err)
	}
	// A password a Level 0 operation does not need is not sent (C7-A2-5).
	i = inv
	i.OperationID = "sel.id"
	if got := codeOf(i.ValidateWith(reg)); got != RefusedLimits {
		t.Errorf("Level 0 operation with a credential: code %q, want %q", got, RefusedLimits)
	}
	i = inv
	i.Limits.ConnectRetries = 3
	if got := codeOf(i.ValidateWith(reg)); got != RefusedLimits {
		t.Errorf("retries above the ceiling: code %q", got)
	}
}

func c1Example(t *testing.T) (asset.Asset, asset.CapabilityProfile) {
	t.Helper()
	dir := filepath.Join("..", "asset", "testdata", "valid")
	b, err := os.ReadFile(filepath.Join(dir, "sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(dir, "profile-sel-751-ascii.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := asset.DecodeProfile(b)
	if err != nil {
		t.Fatal(err)
	}
	return a, p
}

// The example invocation is the one the collector builds for the C1 relay
// example, and each way of departing from that asset or its profile is
// refused with the code the collector reports.
func TestCheckAgainst(t *testing.T) {
	a, p := c1Example(t)
	inv := validInvocation(t)
	if err := inv.CheckAgainst(a, p); err != nil {
		t.Fatalf("C1 relay example refused: %v", err)
	}
	cases := []struct {
		name string
		f    func(*Invocation, *asset.Asset, *asset.CapabilityProfile)
		want Code
	}{
		{"suspended asset", func(_ *Invocation, a *asset.Asset, _ *asset.CapabilityProfile) {
			a.Suspension = &asset.Suspension{Reason: "identity-mismatch"}
		}, RefusedAssetSuspended},
		{"address-only binding", func(_ *Invocation, a *asset.Asset, _ *asset.CapabilityProfile) {
			a.IdentityBinding = asset.IdentityBinding{Method: asset.AddressOnly}
		}, RefusedInvocationMismatch},
		{"credential on a binding 0.1 reads as address-only", func(_ *Invocation, a *asset.Asset, _ *asset.CapabilityProfile) {
			a.IdentityBinding.Method = "tpm-attested" // compares attributes, but C1 sends no credential on it (R-1)
		}, RefusedCredentialUnavailable},
		{"operation the profile does not name", func(i *Invocation, _ *asset.Asset, _ *asset.CapabilityProfile) {
			i.OperationID = "sel.unknown_read"
		}, RefusedNotInvocable},
		{"profile with no password attempt", func(_ *Invocation, _ *asset.Asset, p *asset.CapabilityProfile) {
			l := *p.SessionLimits
			l.PasswordAttempts = 0
			p.SessionLimits = &l
		}, RefusedLimits},
		{"other asset, also suspended", func(i *Invocation, a *asset.Asset, _ *asset.CapabilityProfile) {
			i.AssetID = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b14"
			a.Suspension = &asset.Suspension{Reason: "identity-mismatch"}
		}, RefusedInvocationMismatch},
		{"other asset", func(i *Invocation, _ *asset.Asset, _ *asset.CapabilityProfile) {
			i.AssetID = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b14"
		}, RefusedInvocationMismatch},
		{"endpoint not on the asset", func(i *Invocation, _ *asset.Asset, _ *asset.CapabilityProfile) {
			i.EndpointID = "port2-telnet"
		}, RefusedInvocationMismatch},
		{"other profile", func(i *Invocation, _ *asset.Asset, _ *asset.CapabilityProfile) {
			i.ProfileID = "sel-rtac-syslog"
		}, RefusedInvocationMismatch},
		{"expected FID not the declared one", func(i *Invocation, _ *asset.Asset, _ *asset.CapabilityProfile) {
			i.Expected = []Expected{{"firmware_id", "SEL-751-R500-V1-Z103101-D20260910"}, i.Expected[1]}
		}, RefusedInvocationMismatch},
		{"expected identity missing an attribute", func(i *Invocation, _ *asset.Asset, _ *asset.CapabilityProfile) {
			i.Expected = i.Expected[:1]
		}, RefusedInvocationMismatch},
		{"min interval below the profile's", func(i *Invocation, _ *asset.Asset, _ *asset.CapabilityProfile) {
			i.Limits.MinIntervalMS = 59_999
		}, RefusedLimits},
		{"profile without session limits", func(_ *Invocation, _ *asset.Asset, p *asset.CapabilityProfile) {
			p.SessionLimits = nil
		}, RefusedLimits},
		{"profile allowing two sessions", func(_ *Invocation, _ *asset.Asset, p *asset.CapabilityProfile) {
			l := *p.SessionLimits
			l.MaxConcurrentSessions = 2
			p.SessionLimits = &l
		}, RefusedLimits},
	}
	for _, c := range cases {
		i, a2, p2 := inv, a, p
		i.Expected = slices.Clone(inv.Expected)
		c.f(&i, &a2, &p2)
		if got := codeOf(i.CheckAgainst(a2, p2)); got != c.want {
			t.Errorf("%s: code %q, want %q", c.name, got, c.want)
		}
	}
	// An address-only binding compares nothing, so no C2 session runs on it,
	// not even a Level 0 read: every session checks identity (AP-27).
	i, a2 := inv, a
	i.OperationID, i.CredentialRef = "sel.id", ""
	a2.IdentityBinding = asset.IdentityBinding{Method: asset.AddressOnly, Strength: asset.Spoofable}
	if got := codeOf(i.CheckAgainst(a2, p)); got != RefusedInvocationMismatch {
		t.Errorf("Level 0 read on an address-only binding: code %q, want %q", got, RefusedInvocationMismatch)
	}
}

// C2 checks C7's credential reference ID syntax with a copy of its pattern,
// and principal IDs with C7 itself.
func TestCredentialRefMatchesC7(t *testing.T) {
	ref := authz.CredentialRef{
		AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", NodeID: "site-a-node1", EndpointID: "port1-telnet",
		Transport: authz.TransportTelnet, Purpose: authz.PurposeCollectReadOnly, AccessLevel: "1",
		DownstreamSecurity: authz.DownstreamPlaintext, PlaintextScope: authz.PlaintextLabOnly, Version: 1,
		CreatedBy: authz.Principal{Type: authz.PrincipalHuman, ID: "admin:lab-admin"}, CreatedAt: "2026-10-24T09:00:00Z",
	}
	for _, id := range []string{"cred_lab751feeder1", "cred_abcdefgh", "cred_abcdefg", "cred_" + strings.Repeat("a", 40),
		"cred_" + strings.Repeat("a", 41), "cred_ABCDEFGH", "cred:site-a:acc", "cred_abcd-efgh", ""} {
		ref.ID = id
		if c7, c2 := ref.Validate() == nil, credentialRefPattern.MatchString(id); c7 != c2 {
			t.Errorf("%q: C2 %v, C7 %v", id, c2, c7)
		}
	}
}

func TestDecodeInvocationRejectsTrailingData(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("testdata", "invocations", "valid", "sel-ser-read.json"))
	if _, err := DecodeInvocation(append(b, []byte(`{"schema":"otsec.adapter/0.1"}`)...)); err == nil {
		t.Fatal("trailing object accepted")
	}
}

// Results read every 0.x minor: unknown fields are ignored.
func TestResultIgnoresUnknownFields(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("testdata", "results", "valid", "ok.json"))
	b = []byte(strings.Replace(string(b), `"schema": "otsec.adapter/0.1"`, `"added_in_0_3": {"x": 1}, "schema": "otsec.adapter/0.3"`, 1))
	if _, err := DecodeResult(b); err != nil {
		t.Fatalf("unknown field rejected: %v", err)
	}
}

// A redaction marker reveals nothing about the secret: the stored bytes are
// the same whatever the password was.
func TestRedactionIsFixed(t *testing.T) {
	r := loadResult(t, "ok-with-echo")
	for _, rd := range r.Transcript.Redactions {
		if got := string(r.Transcript.Data[rd.Offset : rd.Offset+rd.Length]); got != RedactionMarker {
			t.Errorf("redaction holds %q", got)
		}
	}
	if len(r.Transcript.Redactions) != 2 {
		t.Fatalf("echo example has %d redactions, want credential and echo", len(r.Transcript.Redactions))
	}
}

func TestExamplesHaveNotes(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("testdata", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"results/valid", "results/invalid", "invocations/valid", "invocations/invalid"} {
		for _, f := range files(t, dir) {
			rel := dir + "/" + filepath.Base(f)
			if !strings.Contains(string(readme), "`"+rel+"`") {
				t.Errorf("testdata/README.md has no note for %s", rel)
			}
		}
	}
}

package contract

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
)

// C7 otsec.authz/0.1: A6's negative cases (C7-A6 review and re-checks).
// Expected values come from the contract's doc.go prose and from the merged
// C3 SEL-751 register, not from A3's testdata or helpers. Ground truth:
// GT-HAND (contract prose), same-source (manual) for the SEL-751 limits.

func sel751Package(t *testing.T) *register.Package {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "register", "testdata", "sel-751-phase0.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func refusalCode(err error) authz.RefusalCode {
	var r *authz.Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// A request A6 wrote from the contract's field list; the variants below
// change one thing each.
const c7Run = `{
  "contract": "otsec.authz/0.1",
  "kind": "run",
  "request_id": "req-a6-0001",
  "on_behalf_of": {"type": "schedule", "id": "sch-a6"},
  "policy_version": 3,
  "run": {
    "asset_id": "0b6c2f4e-1d3a-4c5b-8e7f-9a0b1c2d3e4f",
    "operation_id": "sel.ser.read_all",
    "params": {},
    "credential_ref": "cred_a6a6a6a6",
    "register_version": 1
  }
}`

func TestC7RequestDecode(t *testing.T) {
	if _, err := authz.DecodeRequest([]byte(c7Run)); err != nil {
		t.Fatalf("A6's request: %v", err)
	}
	for _, c := range []struct {
		name, req string
		want      authz.RefusalCode
	}{
		{"case-variant key", strings.Replace(c7Run, `"run": {`, `"Run": {`, 1), authz.RefuseUnknownField},
		{"Kelvin sign in key", strings.Replace(c7Run, `"kind"`, "\"Kind\"", 1), authz.RefuseUnknownField},
		{"duplicate key", strings.Replace(c7Run, `"params": {}`, `"params": {}, "params": {}`, 1), authz.RefuseMalformed},
		{"byte-order mark", "\xef\xbb\xbf" + c7Run, authz.RefuseMalformed},
		{"over 8192 bytes", c7Run + strings.Repeat(" ", 8193-len(c7Run)), authz.RefuseOversize},
		{"negative policy version", strings.Replace(c7Run, `"policy_version": 3`, `"policy_version": -1`, 1), authz.RefuseMalformed},
		{"policy version 2^64", strings.Replace(c7Run, `"policy_version": 3`, `"policy_version": 18446744073709551616`, 1), authz.RefuseMalformed},
		{"run for a human", strings.Replace(c7Run, `"type": "schedule"`, `"type": "human"`, 1), authz.RefusePrincipal},
	} {
		_, err := authz.DecodeRequest([]byte(c.req))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		// Malformed numbers may be reported as malformed or invalid; both refuse.
		if got := refusalCode(err); got != c.want && !(c.want == authz.RefuseMalformed && got == authz.RefuseInvalid) {
			t.Errorf("%s: got %q (%v), want %q", c.name, got, err, c.want)
		}
	}
	if _, err := authz.DecodeRequest([]byte(c7Run + strings.Repeat(" ", 8192-len(c7Run)))); err != nil {
		t.Errorf("exactly 8192 bytes refused: %v", err)
	}
}

func TestC7AccessLevel(t *testing.T) {
	pkg := sel751Package(t)
	if err := authz.CheckAccessLevel(pkg, "1"); err != nil {
		t.Fatalf("level 1: %v", err)
	}
	// C7-A6-1: the device-native name, Level 2 in any spelling, and anything
	// that is not exactly the register's token are refused.
	for _, lv := range []string{"0", "2", "2AC", "ACC", "any", "", "01", " 1", "1 ", "１"} {
		if got := refusalCode(authz.CheckAccessLevel(pkg, lv)); got != authz.RefuseCredentialMismatch {
			t.Errorf("level %q: got %q", lv, got)
		}
	}
	if got := refusalCode(authz.CheckAccessLevel(nil, "1")); got != authz.RefuseRegisterUnverified {
		t.Errorf("nil package: got %q", got)
	}
}

func TestC7SecretNotACommand(t *testing.T) {
	pkg := sel751Package(t)
	p, ok := authz.SecretPolicies["sel-751"]
	if !ok {
		t.Fatal("no SEL-751 secret policy")
	}
	// Every command word the SEL-751 register names, transcribed by A6 from
	// the register's operations, session lines and deny rules. The relay reads
	// the first three characters (S22 p. 7.31), so each is tried as the start
	// of a secret in three case forms.
	words := []string{"2AC", "BAC", "PAC", "AAC", "OAC", "CAL", "SER", "HIS", "TRI", "MET", "PRO", "TAR", "STA",
		"OPE", "CLO", "PUL", "CON", "SET", "PAS", "COP", "GRO", "R_S", "L_D", "FIL", "LDP", "DAT", "TIM", "IRI",
		"LOO", "ANA", "POR", "SUM", "COM", "GOO", "FGS", "PIN", "BRE", "THE", "89C", "89O", "AFT", "HSR", "INI",
		"PAR", "TES", "CSE", "CAS", "ID", "SHO", "ACC", "QUI"}
	for _, w := range words {
		for _, s := range []string{w, strings.ToLower(w) + "9x", strings.ToLower(w[:1]) + w[1:] + "!"} {
			err := authz.ValidateSecret([]byte(s), p, pkg)
			if !errors.Is(err, authz.ErrSecretRejected) {
				t.Errorf("%q: got %v", s, err)
			} else if strings.Contains(err.Error(), s) {
				t.Errorf("%q: the error contains the secret", s)
			}
		}
	}
	for _, s := range []string{"Otter#2026", "xQUI", "9SER"} {
		if err := authz.ValidateSecret([]byte(s), p, pkg); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	for _, s := range []string{"Otter #26", "Thirteen#2026", "a\tb"} {
		if err := authz.ValidateSecret([]byte(s), p, pkg); !errors.Is(err, authz.ErrSecretRejected) {
			t.Errorf("%q: got %v", s, err)
		}
	}
	// A policy the caller builds itself must say how the device reads words.
	if err := authz.ValidateSecret([]byte("Otter#2026"), authz.SecretPolicy{}, pkg); err == nil {
		t.Error("zero policy accepted")
	}
	if err := authz.ValidateSecret([]byte("Otter#2026"), p, nil); err == nil {
		t.Error("no register package accepted")
	}
}

// D1-20 and C7-A5-3 at contract level: the floor runs from the last
// unconfirmed authentication, which the collector records before the
// password is sent. A crash between sending the password and seeing "=>"
// therefore leaves a recorded time, and the next request inside the floor
// is refused. The collector half (flush before send) is a Phase 2 test.
func TestC7FailureFloor(t *testing.T) {
	for _, c := range []struct {
		tidle, want time.Duration
	}{
		{0, 31 * time.Minute}, // unknown
		{-time.Minute, 31 * time.Minute},
		{5 * time.Minute, 6 * time.Minute},
		{30 * time.Minute, 31 * time.Minute},
		{31 * time.Minute, 31 * time.Minute}, // out of range
	} {
		if got := authz.FailureFloor(c.tidle); got != c.want {
			t.Errorf("FailureFloor(%v) = %v, want %v", c.tidle, got, c.want)
		}
	}
	sent := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) // password sent, then the collector crashed
	floor := authz.FailureFloor(5 * time.Minute)
	for _, c := range []struct {
		name   string
		last   time.Time
		now    time.Time
		inside bool
	}{
		{"nothing recorded", time.Time{}, sent, false},
		{"restart 1 s after the crash", sent, sent.Add(time.Second), true},
		{"just inside the floor", sent, sent.Add(floor - time.Nanosecond), true},
		{"floor elapsed", sent, sent.Add(floor), false},
		{"clock stepped back below the record", sent, sent.Add(-time.Hour), true},
	} {
		if got := authz.InsideFailureFloor(c.last, c.now, floor); got != c.inside {
			t.Errorf("%s: inside = %v, want %v", c.name, got, c.inside)
		}
	}
}

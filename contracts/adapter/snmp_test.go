package adapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
)

// The SNMPv3 results of 0.7. The goldens are in testdata/snmp and are written
// by testdata/generate_snmp.py.

// snmpWant is the error each invalid SNMP example must produce. Every file in
// testdata/snmp/results/invalid must be listed.
var snmpWant = map[string]string{
	"snmp-at-0.6":                                "session.snmp is new in 0.7",
	"line-code-on-snmp":                          `"failed.device_error" ends only a line session`,
	"snmp-code-on-line-session":                  `"refused.engine_id_mismatch" ends only an SNMP session`,
	"ok-not-authenticated":                       "status ok needs an authenticated SNMP session",
	"snmp-with-quit":                             "an SNMP session has no wake",
	"engine-mismatch-after-auth":                 "is decided at discovery",
	"usm-failure-at-discovery":                   "so an auth or operate message was sent",
	"after-auth-not-authenticated":               "happens after authentication, so the session authenticated",
	"authenticated-before-auth-sent":             "authenticated needs a discovered engine ID and an auth or operate message sent",
	"no-engine-check-before-auth":                "must precede it (AP-27)",
	"engine-id-item-not-first":                   "an SNMP identity starts with snmp_engine_id",
	"engine-id-item-not-session":                 "equals session.snmp.engine_id",
	"engine-id-not-hex":                          "is not 5 to 32 octets in lowercase hex",
	"observation-without-read":                   "observations[1].read is required from 0.7",
	"observation-read-oid-and-header":            "names exactly one of oid and header",
	"engine-id-observation-from-oid":             "is read from the msgAuthoritativeEngineID header",
	"observation-value-not-span":                 "observations[1]: the span does not select the value",
	"observation-read-header-other-field":        `header "msgUserName" is not msgAuthoritativeEngineID`,
	"credential-redaction-on-snmp":               "an SNMP result's only redaction is usm-digest",
	"sent-digest-20-octets":                      "a sent digest is 24 or 48 octets, not 20",
	"digest-not-zeroed":                          "a usm-digest redaction is zero octets",
	"snmp-close-phase":                           "an SNMP session has no close phase",
	"not-connected-with-engine-id":               "not connected, so the transcript is empty",
	"keyed-send-without-digest-redaction":        "an authenticated message sent holds exactly one usm-digest redaction, not 0",
	"value-from-message-without-digest":          "observations[0]: snmp_engine_id is read only from a received operate message that carried a digest",
	"authenticated-without-authenticated-answer": "authenticated needs a received auth or operate message that carried a digest",
	"fid-unreadable-with-fid-item":               "failed.snmp_fid_unreadable: the identity holds only the matching snmp_engine_id item",
	"fid-unreadable-with-fid-observation":        "failed.snmp_fid_unreadable reports no firmware_id",
}

func snmpFixtures(t *testing.T) (*register.Package, Invocation) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "snmp", "register.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join("testdata", "snmp", "invocation.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := DecodeInvocation(b)
	if err != nil {
		t.Fatal(err)
	}
	return p, inv
}

func snmpResult(t *testing.T, n string) Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "snmp", "results", "valid", n+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResult(b)
	if err != nil {
		t.Fatalf("%s: %v", n, err)
	}
	return r
}

// Every valid SNMP example passes Validate and CheckSNMP, and CheckLines
// refuses it: an SNMP result has no lines.
func TestSNMPValidResults(t *testing.T) {
	p, inv := snmpFixtures(t)
	for _, f := range files(t, "snmp/results/valid") {
		r := snmpResult(t, name(f))
		if r.Session.SNMP == nil {
			t.Errorf("%s: not an SNMP result", name(f))
			continue
		}
		if err := r.CheckSNMP(p, inv); err != nil {
			t.Errorf("%s: %v", name(f), err)
		}
		if err := r.CheckLines(p, inv); err == nil || !strings.Contains(err.Error(), "check it with CheckSNMP") {
			t.Errorf("%s: CheckLines: %v", name(f), err)
		}
	}
}

func TestSNMPInvalidResults(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range files(t, "snmp/results/invalid") {
		n := name(f)
		seen[n] = true
		want, ok := snmpWant[n]
		if !ok {
			t.Errorf("%s: not listed in snmpWant", n)
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeResult(b)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error does not mention %q:\n%v", n, want, err)
		}
	}
	for n := range snmpWant {
		if !seen[n] {
			t.Errorf("snmpWant lists %s but testdata/snmp/results/invalid has no such file", n)
		}
	}
}

// Every SNMP example has a one-line note in testdata/snmp/README.md.
func TestSNMPExamplesHaveNotes(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("testdata", "snmp", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"results/valid", "results/invalid"} {
		for _, f := range files(t, "snmp/"+dir) {
			if rel := dir + "/" + filepath.Base(f); !strings.Contains(string(readme), "`"+rel+"`") {
				t.Errorf("testdata/snmp/README.md has no note for %s", rel)
			}
		}
	}
}

// CheckSNMP ties each read to the register: an operation the invocation
// runs, and an OID that operation reads (C3's review of #445).
func TestCheckSNMP(t *testing.T) {
	p, inv := snmpFixtures(t)
	edit := func(f func(r *Result)) error {
		r := snmpResult(t, "ok")
		f(&r)
		return r.CheckSNMP(p, inv)
	}
	for n, c := range map[string]struct {
		f    func(r *Result)
		want string
	}{
		"an OID the get does not name": {func(r *Result) { r.Observations[1].Read.OID = "1.3.6.1.2.1.1.6.0" },
			"sel27x1.snmp.system does not read 1.3.6.1.2.1.1.6.0"},
		"the walk's subtree itself": {func(r *Result) { r.Observations[2].Read.OID = "1.3.6.1.2.1.47.1.1.1" },
			"sel27x1.snmp.entity does not read 1.3.6.1.2.1.47.1.1.1"},
		"an OID past the subtree": {func(r *Result) { r.Observations[2].Read.OID = "1.3.6.1.2.1.47.1.1.10.1" },
			"does not read 1.3.6.1.2.1.47.1.1.10.1"},
		"an operation the run does not hold": {func(r *Result) { r.Observations[1].Read.Operation = "sel27x1.snmp.other" },
			"sel27x1.snmp.other is not an SNMP operation this invocation runs"},
		"another register revision": {func(r *Result) { r.RegisterVersion = 2 }, "register_version 2"},
		"another invocation":        {func(r *Result) { r.OperationID = "sel27x1.snmp.system" }, "not 6f1c2b9e"},
	} {
		if err := edit(c.f); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", n, err)
		}
	}
	// An invocation of one SNMP operation, not a run, holds that operation.
	one := inv
	one.OperationID = "sel27x1.snmp.system"
	r := snmpResult(t, "ok")
	r.OperationID = one.OperationID
	r.Observations = r.Observations[:2]
	if err := r.CheckSNMP(p, one); err != nil {
		t.Errorf("one operation: %v", err)
	}
	r.Observations = snmpResult(t, "ok").Observations
	if err := r.CheckSNMP(p, one); err == nil || !strings.Contains(err.Error(), "sel27x1.snmp.entity is not an SNMP operation this invocation runs") {
		t.Errorf("a read of a step the invocation did not run: %v", err)
	}
	// A line result is not checked here.
	if err := loadResult(t, "ok").CheckSNMP(p, inv); err == nil || !strings.Contains(err.Error(), "check it with CheckLines") {
		t.Errorf("a line result: %v", err)
	}
}

// The SEL-only and SNMP-only codes are the proposal's lists (§2.1), and every
// SNMP code is new in 0.7.
func TestSNMPCodes(t *testing.T) {
	for c, info := range codes {
		snmp := strings.Contains(string(c), "usm_") || strings.Contains(string(c), "snmp_") || c == RefusedEngineIDMismatch
		if snmp != (info.session == snmpOnly) {
			t.Errorf("%s: session kind %q", c, info.session)
		}
		if snmp && info.since != 7 {
			t.Errorf("%s: since 0.%d", c, info.since)
		}
		if snmp && (info.suspends != "" || info.credential != "") {
			t.Errorf("%s suspends something (D4-53)", c)
		}
	}
	line := []Code{RefusedSessionElevated, RefusedSessionPendingPassword, RefusedLanguageProbe, RefusedIdentityMismatch,
		FailedIdentityUnreadable, RefusedPasswordPromptAbsent, FailedAuthRejected, FailedUnexpectedLevel,
		RefusedLanguageNotEnglish, RefusedFirmwareCondition, FailedAccessLevelDropped, FailedDeviceError,
		FailedConfigUnparsable, FailedUnexpectedPasswordPrompt}
	n := 0
	for c, info := range codes {
		if info.session == lineOnly {
			n++
			if !contains(line, c) {
				t.Errorf("%s is line-only, but not on the proposal's list", c)
			}
		}
	}
	if n != len(line) {
		t.Errorf("%d line-only codes, want %d", n, len(line))
	}
}

// An authenticated FID mismatch on SNMPv3 suspends the asset and not the
// credential (C1 on #445). The same code on a line session suspends both.
func TestSNMPSuspendsNoCredential(t *testing.T) {
	r := snmpResult(t, "failed.identity_mismatch")
	if r.Error.Code.Suspends() != asset.SuspendIdentityMismatch || r.SuspendsCredential() != "" {
		t.Errorf("SNMP: asset %q, credential %q", r.Error.Code.Suspends(), r.SuspendsCredential())
	}
	sel := loadResult(t, "failed.identity_mismatch")
	if sel.SuspendsCredential() != asset.SuspendIdentityMismatch {
		t.Errorf("line: credential %q", sel.SuspendsCredential())
	}
	if (Result{}).SuspendsCredential() != "" {
		t.Error("an ok result suspends a credential")
	}
}

// A read is new in 0.7, and a line result's read names no OID or header.
// CheckLines ties it to the reply that holds the observation.
func TestLineReads(t *testing.T) {
	p, _ := rev5(t)
	b, err := os.ReadFile(filepath.Join("testdata", "results", "valid", "ok.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	inv := Invocation{InvocationID: r.InvocationID, OperationID: r.OperationID}
	r.RegisterVersion = p.Revision
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	// At 0.6 a read cannot be carried, and at 0.7 it must be.
	r.Observations[0].Read = &Read{Operation: "sel.id"}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "is new in 0.7") {
		t.Errorf("a read at 0.1: %v", err)
	}
	r.Schema = Contract
	r.Observations[0].Read = nil
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "observations[0].read is required from 0.7") {
		t.Errorf("no read at 0.7: %v", err)
	}
	for i, o := range r.Observations {
		op := "sel.id"
		if o.Name == asset.AttrSerialNumber {
			op = "sel.ser.read_all"
		}
		r.Observations[i].Read = &Read{Operation: op}
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("0.7 with reads: %v", err)
	}
	if err := r.CheckLines(p, inv); err != nil {
		t.Fatalf("0.7 with reads: %v", err)
	}
	r.Observations[0].Read.OID = "1.3.6.1.2.1.1.1.0"
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "a line result's read names no oid or header") {
		t.Errorf("an OID on a line read: %v", err)
	}
	r.Observations[0].Read.OID = ""
	r.Observations[0].Read.Operation = "sel.ser.read_all"
	if err := r.CheckLines(p, inv); err == nil || !strings.Contains(err.Error(), "is not in the reply to a line of sel.ser.read_all") {
		t.Errorf("a read of the wrong operation: %v", err)
	}
}

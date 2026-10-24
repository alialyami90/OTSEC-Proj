package asset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// invalidWant is the error each invalid example must produce. Every file in
// testdata/invalid must be listed, so a new example cannot pass by failing
// for an unrelated reason.
var invalidWant = map[string]string{
	"observation-without-evidence-class":   "evidence_class is required",
	"attribute-without-observations":       "at least one observation with an evidence class",
	"corroborated-by-one-class":            "at least two evidence classes",
	"conflicting-value-not-declared":       "keeps the operator-declared value",
	"telnet-labelled-encrypted":            "telnet is plaintext-unauthenticated",
	"plaintext-without-acknowledgement":    "needs an acknowledgement",
	"device-reported-claims-cryptographic": `strength must be "spoofable"`,
	"pinned-key-on-plaintext":              "cannot carry a pinned key",
	"binding-attribute-not-declared":       `"sel.cid" has no operator-declared value`,
	"platform-node-on-relay":               "platform_node is allowed only",
	"os-out-of-support-without-condition":  "needs the standing condition",
	"unknown-device-class-at-0.1":          "is not one of the 0.1 values",
	"unprefixed-unknown-attribute":         `name "cid" is neither`,
	"simulator-value-labelled-device":      "go together",
	"session-observation-without-span":     "needs the transcript span",
	"missing-vendor":                       `required attribute "vendor"`,
	"other-major":                          "not readable as otsec.asset/0.1",
	"asset-id-from-device-content":         "is not a lowercase UUID",
	"profile-adapter-without-allowlist":    "needs a firmware allowlist",
	"profile-claim-without-citation":       "needs a citation",
}

func decodeAny(b []byte) error {
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	if probe.Kind == ProfileKind {
		_, err := DecodeProfile(b)
		return err
	}
	_, err := Decode(b)
	return err
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

func TestValidExamples(t *testing.T) {
	for _, f := range files(t, "valid") {
		b, _ := os.ReadFile(f)
		if err := decodeAny(b); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestInvalidExamples(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range files(t, "invalid") {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		seen[name] = true
		want, ok := invalidWant[name]
		if !ok {
			t.Errorf("%s: not listed in invalidWant", f)
			continue
		}
		b, _ := os.ReadFile(f)
		err := decodeAny(b)
		if err == nil {
			t.Errorf("%s: accepted", f)
		} else if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error does not mention %q:\n%v", f, want, err)
		}
	}
	for name := range invalidWant {
		if !seen[name] {
			t.Errorf("invalidWant lists %s but testdata/invalid has no such file", name)
		}
	}
}

// Every example has a one-line note in testdata/README.md.
func TestExamplesHaveNotes(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("testdata", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"valid", "invalid"} {
		for _, f := range files(t, dir) {
			rel := dir + "/" + filepath.Base(f)
			if !strings.Contains(string(readme), "`"+rel+"`") {
				t.Errorf("testdata/README.md has no note for %s", rel)
			}
		}
	}
}

func load(t *testing.T, name string) Asset {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	a, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDeclaredIsTheBindingReference(t *testing.T) {
	a := load(t, "sel-751-identity-mismatch.json")
	got, ok := a.Declared(AttrFirmwareID)
	if !ok || got != "SEL-751-R501-V0-Z104101-D20260910" {
		t.Fatalf("Declared(firmware_id) = %q, %v", got, ok)
	}
	if a.Suspension == nil || a.Suspension.Reason != SuspendIdentityMismatch {
		t.Fatalf("mismatch example is not suspended")
	}
}

func TestWeakestDownstreamSecurity(t *testing.T) {
	a := load(t, "sel-751-simulated.json")
	a.Endpoints = append(a.Endpoints, Endpoint{ID: "future-ssh", Transport: SSH, Host: "192.0.2.21", Port: 22,
		DownstreamSecurity: DownstreamSecurity{Level: EncryptedAuthenticated}})
	if l, ok := a.WeakestDownstreamSecurity(); !ok || l != PlaintextUnauthenticated || !l.Insecure() {
		t.Fatalf("weakest = %q, %v", l, ok)
	}
	a.Endpoints[0].DownstreamSecurity.Level = "something-from-a-later-minor"
	if l, _ := a.WeakestDownstreamSecurity(); l != FallbackSecurityLevel {
		t.Fatalf("unknown level read as %q, want the fallback", l)
	}
	if _, ok := (Asset{}).WeakestDownstreamSecurity(); ok {
		t.Fatal("asset with no endpoints reported a level")
	}
}

func TestLaterMinorReadsUnknownClassAsFallback(t *testing.T) {
	a := load(t, "later-minor.json")
	at, _ := a.Attribute(AttrDeviceClass)
	if contains(DeviceClasses, at.Value) {
		t.Fatalf("example should carry a class 0.1 does not know, got %q", at.Value)
	}
}

func TestStrengthOf(t *testing.T) {
	for m, want := range map[BindingMethod]BindingStrength{
		DeviceReported: Spoofable, AddressOnly: Spoofable, PinnedKey: Cryptographic, "": Spoofable, "new": Spoofable,
	} {
		if got := StrengthOf(m); got != want {
			t.Errorf("StrengthOf(%q) = %q, want %q", m, got, want)
		}
	}
}

func TestAttributeNames(t *testing.T) {
	for _, ok := range []string{"firmware_id", "sel.cid", "sel.devcode", "vendor"} {
		if !ValidAttributeName(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "cid", "FIRMWARE_ID", "sel.", ".cid", "sel.cid.x", "s.cid", "firmware-id"} {
		if ValidAttributeName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValueRejectsControlBytes(t *testing.T) {
	a := load(t, "sel-751-simulated.json")
	for _, v := range []string{"SEL\x00", "SEL\x11", "SEL\r\n", "\x7f", strings.Repeat("A", MaxValueBytes+1), "\xff"} {
		b := a
		b.Attributes = append([]Attribute(nil), a.Attributes...)
		b.Attributes[1] = Attribute{Name: AttrVendor, Value: v, Confidence: SingleSource,
			Observations: []Observation{{Value: v, EvidenceClass: OperatorDeclared,
				Source: Source{Method: OperatorEntry, Ref: "operator:x", ObservedAt: "2026-10-24T09:00:00Z"}}}}
		if err := b.Validate(); err == nil {
			t.Errorf("value %q accepted", v)
		}
	}
}

func TestTimes(t *testing.T) {
	for _, ok := range []string{"2026-10-24T09:00:00Z", "2026-10-24T09:00:00.123456Z"} {
		if !ValidTime(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"2026-10-24T09:00:00+02:00", "2026-10-24 09:00:00Z", "2026-10-24", ""} {
		if ValidTime(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

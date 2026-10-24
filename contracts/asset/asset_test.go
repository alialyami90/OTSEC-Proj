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
	"observation-without-evidence-class":          "evidence_class is required",
	"attribute-without-observations":              "at least one observation with an evidence class",
	"corroborated-by-one-class":                   "at least two evidence classes",
	"conflicting-value-not-declared":              "keeps the operator-declared value",
	"telnet-labelled-encrypted":                   "telnet is plaintext-unauthenticated",
	"plaintext-without-acknowledgement":           "needs an acknowledgement",
	"device-reported-claims-cryptographic":        `strength must be "spoofable"`,
	"pinned-key-on-plaintext":                     "cannot carry a pinned key",
	"binding-attribute-not-declared":              `"sel.cid" has no operator-declared value`,
	"platform-node-on-relay":                      "platform_node is allowed only",
	"os-out-of-support-without-condition":         "needs the standing condition",
	"unknown-device-class-at-0.1":                 "is not one of the 0.1 values",
	"unprefixed-unknown-attribute":                `name "cid" is neither`,
	"simulator-value-labelled-device":             "go together",
	"session-observation-without-span":            "needs the transcript span",
	"missing-vendor":                              `required attribute "vendor"`,
	"other-major":                                 "not readable as otsec.asset/0.1",
	"asset-id-from-device-content":                "is not a lowercase UUID",
	"serial-labelled-encrypted":                   "serial is plaintext-unauthenticated",
	"ssh-authenticated-without-pinned-key":        "only pinned-key authenticates the device",
	"syslog-tls-authenticated-without-pinned-key": "only pinned-key authenticates the device",
	"acknowledgement-without-scope":               "acknowledgement.scope is required",
	"profile-adapter-without-allowlist":           "needs a firmware allowlist",
	"profile-claim-without-citation":              "needs a citation",
	"binding-without-pre-credential":              "needs a pre_credential attribute",
	"device-reported-on-ip-address":               `cannot compare "ip_address"`,
	"pre-credential-not-in-attributes":            `"firmware_id" is not in attributes`,
	"address-only-with-pre-credential":            "pre_credential is empty",
	"profile-pre-credential-operator-only":        `"ip_address" is not an attribute a device reports`,
	"case-variant-key":                            `IDENTITY_BINDING`,
	"duplicate-key":                               `duplicate key "identity_binding"`,
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

func TestCheckSenders(t *testing.T) {
	r := load(t, "sel-rtac-syslog.json")
	if err := CheckSenders([]Asset{r, load(t, "sel-751-simulated.json")}); err != nil {
		t.Fatalf("distinct senders rejected: %v", err)
	}
	other := r
	other.AssetID = "5d0b7c3e-2a41-4f86-9c1d-8e7f6a5b4c32"
	other.Endpoints = []Endpoint{r.Endpoints[0]}
	other.Endpoints[0].Host = "::ffff:192.0.2.40" // the same IPv4 sender, written mapped
	if err := CheckSenders([]Asset{r, other}); err == nil {
		t.Fatal("one sender on two assets of one node accepted")
	}
	other.NodeID = "site-a-node2"
	if err := CheckSenders([]Asset{r, other}); err != nil {
		t.Fatalf("same sender heard by two nodes rejected: %v", err)
	}
}

func TestInboundPortIsOptional(t *testing.T) {
	r := load(t, "sel-rtac-syslog.json")
	r.Endpoints[0].Port = 0
	if err := r.Validate(); err != nil {
		t.Fatalf("Syslog endpoint without a listening port rejected: %v", err)
	}
	a := load(t, "sel-751-simulated.json")
	a.Endpoints[0].Port = 0
	if err := a.Validate(); err == nil {
		t.Fatal("Telnet endpoint without a port accepted")
	}
}

// A later minor's values are read down wherever they carry trust (A6 C1
// review change 2).
func TestLaterMinorReadsDown(t *testing.T) {
	fid := func(a Asset) Attribute { at, _ := a.Attribute(AttrFirmwareID); return at }
	a := load(t, "later-minor-unknown-binding-method.json")
	if a.IdentityBinding.Strength != Spoofable {
		t.Errorf("unknown binding method read as %q, want spoofable", a.IdentityBinding.Strength)
	}
	a = load(t, "later-minor-unknown-source-method.json")
	if c := fid(a).Observations[1].EvidenceClass; c != FallbackEvidenceClass {
		t.Errorf("device-observed value from an unknown method read as %q", c)
	}
	a = load(t, "later-minor-unknown-confidence.json")
	if c := fid(a).Confidence; c != Corroborated {
		t.Errorf("unknown confidence recomputed as %q, want corroborated", c)
	}
	a = load(t, "later-minor-unknown-evidence-class.json")
	if at, _ := a.Attribute("sel.cid"); at.Observations[0].EvidenceClass != FallbackEvidenceClass {
		t.Errorf("unknown evidence class read as %q", at.Observations[0].EvidenceClass)
	}
	if a := load(t, "later-minor.json"); a.DeviceClass() != FallbackDeviceClass {
		t.Errorf("unknown device class read as %q", a.DeviceClass())
	}
	// A valid 0.1 record reads unchanged.
	b, _ := os.ReadFile(filepath.Join("testdata", "valid", "sel-751-simulated.json"))
	var raw Asset
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(load(t, "sel-751-simulated.json"))
	want, _ := json.Marshal(raw)
	if string(got) != string(want) {
		t.Error("Decode changed a valid 0.1 record")
	}
}

// Two device claims of one class are single-source, never corroborated.
func TestSingleSourceAcrossMethods(t *testing.T) {
	a := load(t, "sel-751-simulated.json")
	a.Attributes = append([]Attribute(nil), a.Attributes...)
	for i, at := range a.Attributes {
		if at.Name == "sel.cid" {
			at.Observations = append(at.Observations, Observation{Value: "E754", EvidenceClass: Simulated,
				Source: Source{Method: SimulatorRun, Ref: "other-run", ObservedAt: "2026-10-24T09:20:00Z",
					Span: &Span{Offset: 221, Length: 4}}})
			a.Attributes[i] = at
		}
	}
	if err := a.Validate(); err == nil || !strings.Contains(err.Error(), "keep only the latest") {
		t.Fatalf("two observations of one class and method: %v", err)
	}
	if got := DeriveConfidence("E754", []Observation{{Value: "E754", EvidenceClass: DeviceObserved},
		{Value: "E754", EvidenceClass: DeviceObserved}}); got != SingleSource {
		t.Errorf("two device claims derive %q", got)
	}
}

func TestCheckProfile(t *testing.T) {
	a := load(t, "sel-751-simulated.json")
	b, _ := os.ReadFile(filepath.Join("testdata", "valid", "profile-sel-751-ascii.json"))
	p, err := DecodeProfile(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.CheckProfile(p); err != nil {
		t.Fatalf("golden asset against its profile: %v", err)
	}
	a.IdentityBinding.PreCredential = []string{"serial_number"} // printed only after authentication
	if err := a.CheckProfile(p); err == nil {
		t.Fatal("serial_number accepted as a pre-credential attribute of the SEL-751")
	}
	p.ProfileID = "other"
	if err := a.CheckProfile(p); err == nil {
		t.Fatal("a profile the asset does not name accepted")
	}
}

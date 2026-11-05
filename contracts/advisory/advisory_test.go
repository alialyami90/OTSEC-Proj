package advisory_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/config"
)

// validSet is a small test set: one SEL-751 entry with a per-branch range, a
// setting precondition, a setting mitigation and a control mitigation.
func validSet() advisory.Set {
	return advisory.Set{
		Contract:  advisory.Identifier,
		SetID:     "otsec-sel",
		Version:   7,
		IssuedAt:  "2026-11-05T00:00:00Z",
		Purpose:   advisory.PurposeTest,
		Publisher: "C3 tests",
		Entries: []advisory.Entry{{
			ID:       "gt-adv-0001",
			TestOnly: true,
			Title:    "test entry",
			Sources: []advisory.Source{{
				Kind: advisory.SourceOther, Ref: "GT-ADV D1", Published: "2026-11-05",
				URL: "https://example.invalid/gt-adv", Retrieved: "2026-11-05",
				SHA256: strings.Repeat("ab", 32),
			}},
			Affected: []advisory.Affected{{
				Vendor: "SEL", Product: "SEL-751", Scheme: advisory.SchemeSELFID,
				Ranges:   []advisory.Range{{Introduced: "R300-V0", Fixed: "R300-V3"}, {Fixed: "R400-V1"}, {Introduced: "R500-V2"}},
				Versions: []string{"SEL-751-R301-V2-Z009005-D20220607"},
			}},
			Preconditions: []advisory.Item{{Name: "telnet-enabled", Kind: advisory.KindSetting, Key: "ETELNET", Op: advisory.OpIn, Values: []string{"Y"}}},
			Mitigations: []advisory.Item{
				{Name: "telnet-disabled", Kind: advisory.KindSetting, Key: "ETELNET", Op: advisory.OpIn, Values: []string{"N"}},
				{Name: "web-blocked", Kind: advisory.KindControl, Key: "tcp/80", Op: advisory.OpPresent},
			},
		}},
	}
}

// mitigations returns n distinct, valid control mitigations.
func mitigations(n int) []advisory.Item {
	var m []advisory.Item
	for i := range n {
		m = append(m, advisory.Item{Name: fmt.Sprintf("blocked-%d", i), Kind: advisory.KindControl, Key: fmt.Sprintf("tcp/%d", 1000+i), Op: advisory.OpPresent})
	}
	return m
}

func payloadOf(t *testing.T, s advisory.Set) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func anchors() []advisory.Anchor { return []advisory.Anchor{advisorytest.Anchor(0)} }

func TestValidSetInstalls(t *testing.T) {
	file := advisorytest.Sign(advisorytest.Key(0), payloadOf(t, validSet()))
	v, r := advisory.Verify(file, anchors())
	if r != nil {
		t.Fatalf("Verify: %v", r)
	}
	out, next, r := advisory.Admit(v, advisory.Floor{}, true)
	if r != nil || out != advisory.Install {
		t.Fatalf("Admit = %v, %v", out, r)
	}
	if next.SetID != "otsec-sel" || next.Version != 7 || next.PayloadSHA256 != v.PayloadSHA256 {
		t.Fatalf("floor %+v", next)
	}
}

// TestLoadRule is V-M8's set cases and every other 1.5 code, each with the
// code it must give.
func TestLoadRule(t *testing.T) {
	good := payloadOf(t, validSet())
	sum := sha256.Sum256(good)
	held := advisory.Floor{SetID: "otsec-sel", Version: 7, PayloadSHA256: sum}

	_, other, err := ed25519.GenerateKey(nil) // not an anchor; signs only to be refused
	if err != nil {
		t.Fatal(err)
	}
	revoked := advisorytest.Anchor(1)
	revoked.Status = advisory.KeyRevoked

	mutate := func(f func(*advisory.Set)) []byte {
		s := validSet()
		f(&s)
		return payloadOf(t, s)
	}
	envelope := func(f func(*advisory.Envelope)) []byte {
		var env advisory.Envelope
		if err := json.Unmarshal(advisorytest.Sign(advisorytest.Key(0), good), &env); err != nil {
			t.Fatal(err)
		}
		f(&env)
		b, _ := json.Marshal(env)
		return b
	}

	cases := []struct {
		name    string
		file    []byte
		anchors []advisory.Anchor
		floor   advisory.Floor
		test    bool
		code    advisory.Code
		detail  string
	}{
		{name: "unsigned", file: envelope(func(e *advisory.Envelope) { e.Signature = nil }), code: advisory.Malformed, detail: advisory.DetailNoSignature},
		{name: "signature removed from the JSON", file: []byte(strings.Replace(string(envelope(func(e *advisory.Envelope) { e.Signature = nil })), `,"signature":null`, "", 1)), code: advisory.Malformed, detail: advisory.DetailNoSignature},
		{name: "wrongly signed", file: envelope(func(e *advisory.Envelope) { e.Signature = ed25519.Sign(other, advisory.SigningInput(good)) }), code: advisory.BadSignature},
		{name: "payload altered after signing", file: envelope(func(e *advisory.Envelope) { e.Payload = mutate(func(s *advisory.Set) { s.Version = 8 }) }), code: advisory.BadSignature},
		{name: "truncated", file: advisorytest.Sign(advisorytest.Key(0), good)[:200], code: advisory.Malformed},
		{name: "older version", file: advisorytest.Sign(advisorytest.Key(0), mutate(func(s *advisory.Set) { s.Version = 6 })), floor: held, test: true, code: advisory.OlderVersion},
		{name: "same version, other bytes", file: advisorytest.Sign(advisorytest.Key(0), mutate(func(s *advisory.Set) { s.Publisher = "other" })), floor: held, test: true, code: advisory.SameVersionDiffers},
		{name: "entry with no source", file: advisorytest.Sign(advisorytest.Key(0), mutate(func(s *advisory.Set) { s.Entries[0].Sources = nil })), code: advisory.Invalid, detail: "entry gt-adv-0001: no published source"},
		{name: "release set holding a test_only entry", file: advisorytest.Sign(advisorytest.Key(0), mutate(func(s *advisory.Set) { s.Purpose = advisory.PurposeRelease })), test: true, code: advisory.Invalid, detail: "entry gt-adv-0001: test_only in a release set"},
		{name: "test set in a release build", file: advisorytest.Sign(advisorytest.Key(0), good), code: advisory.TestSet},
		{name: "unknown key", file: advisorytest.Sign(advisorytest.Key(2), good), code: advisory.UnknownKey},
		{name: "revoked key", file: advisorytest.Sign(advisorytest.Key(1), good), anchors: []advisory.Anchor{revoked}, code: advisory.RevokedKey},
		{name: "wrong set", file: advisorytest.Sign(advisorytest.Key(0), mutate(func(s *advisory.Set) { s.SetID = "otsec-other"; s.Version = 9 })), floor: held, test: true, code: advisory.WrongSet},
		{name: "over MaxEnvelopeBytes", file: make([]byte, advisory.MaxEnvelopeBytes+1), code: advisory.Malformed},
		{name: "envelope with an unknown field", file: []byte(strings.Replace(string(advisorytest.Sign(advisorytest.Key(0), good)), `{`, `{"extra":1,`, 1)), code: advisory.Malformed},
		{name: "envelope with a duplicate key", file: []byte(strings.Replace(string(advisorytest.Sign(advisorytest.Key(0), good)), `{`, `{"algorithm":"ed25519",`, 1)), code: advisory.Malformed},
		{name: "trailing data", file: append(advisorytest.Sign(advisorytest.Key(0), good), []byte(" {}")...), code: advisory.Malformed},
		{name: "another algorithm", file: envelope(func(e *advisory.Envelope) { e.Algorithm = "rsa" }), code: advisory.Malformed},
		{name: "another contract", file: envelope(func(e *advisory.Envelope) { e.Contract = "otsec.register/0.3" }), code: advisory.Malformed},
		{name: "a later minor names its own payload", file: envelope(func(e *advisory.Envelope) { e.Contract = "otsec.advisory/0.2" }), code: advisory.Invalid},
		{name: "signature over the register's domain", file: envelope(func(e *advisory.Envelope) {
			e.Signature = ed25519.Sign(advisorytest.Key(0), authz.RegisterSigningInput(good))
		}), code: advisory.BadSignature},
		{name: "payload with an unknown field, signed", file: advisorytest.Sign(advisorytest.Key(0), []byte(strings.Replace(string(good), `{`, `{"severity":"high",`, 1))), code: advisory.Invalid},
		{name: "payload that is not JSON, unsigned by an anchor", file: envelope(func(e *advisory.Envelope) { e.Payload = []byte("not json") }), code: advisory.BadSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := c.anchors
			if a == nil {
				a = anchors()
			}
			v, r := advisory.Verify(c.file, a)
			if r == nil {
				var out advisory.Outcome
				out, _, r = advisory.Admit(v, c.floor, c.test)
				if r == nil {
					t.Fatalf("accepted (%v), want %s", out, c.code)
				}
			}
			if r.Code != c.code {
				t.Fatalf("code %s (%s), want %s", r.Code, r.Detail, c.code)
			}
			if c.detail != "" && r.Detail != c.detail {
				t.Fatalf("detail %q, want %q", r.Detail, c.detail)
			}
			if r.FileSHA256 != sha256.Sum256(c.file) {
				t.Fatal("refusal does not carry the file's SHA-256")
			}
		})
	}
}

func TestSameSetIsInUse(t *testing.T) {
	good := payloadOf(t, validSet())
	held := advisory.Floor{SetID: "otsec-sel", Version: 7, PayloadSHA256: sha256.Sum256(good)}
	v, r := advisory.Verify(advisorytest.Sign(advisorytest.Key(0), good), anchors())
	if r != nil {
		t.Fatal(r)
	}
	out, next, r := advisory.Admit(v, held, true)
	if r != nil || out != advisory.InUse || next != held {
		t.Fatalf("Admit = %v, %+v, %v; want InUse and the same floor", out, next, r)
	}
}

// TestRefusalCarriesOnlyCheckedFields: a refusal's key ID, set ID and version
// come from the file only once they have been checked, so an audit record
// built from them carries no unchecked bytes.
func TestRefusalCarriesOnlyCheckedFields(t *testing.T) {
	good := payloadOf(t, validSet())
	var env advisory.Envelope
	_ = json.Unmarshal(advisorytest.Sign(advisorytest.Key(0), good), &env)
	env.KeyID = "ed25519-<script>"
	b, _ := json.Marshal(env)
	if _, r := advisory.Verify(b, anchors()); r == nil || r.KeyID != "" {
		t.Fatalf("refusal %+v carries a key ID that is not in its form", r)
	}
	s := validSet()
	s.Entries[0].Sources = nil
	_, r := advisory.Verify(advisorytest.Sign(advisorytest.Key(0), payloadOf(t, s)), anchors())
	if r == nil || r.SetID != "" || r.Version != 0 || r.KeyID == "" {
		t.Fatalf("invalid refusal %+v: want the key ID only", r)
	}
	s = validSet()
	s.Version = 3
	v, r := advisory.Verify(advisorytest.Sign(advisorytest.Key(0), payloadOf(t, s)), anchors())
	if r != nil {
		t.Fatal(r)
	}
	_, _, r = advisory.Admit(v, advisory.Floor{SetID: "otsec-sel", Version: 7}, true)
	if r == nil || r.SetID != "otsec-sel" || r.Version != 3 {
		t.Fatalf("older_version refusal %+v: want the set ID and version", r)
	}
}

// TestDetailNamesOnlyTheEntry: step 4's detail names the entry by id and
// nothing else from the file.
func TestDetailNamesOnlyTheEntry(t *testing.T) {
	const marker = "MARKER-FROM-THE-FILE"
	s := validSet()
	s.Entries[0].Title = marker + strings.Repeat("x", advisory.MaxTitleBytes)
	s.Entries[0].Sources[0].Ref = marker
	_, r := advisory.Verify(advisorytest.Sign(advisorytest.Key(0), payloadOf(t, s)), anchors())
	if r == nil || r.Code != advisory.Invalid {
		t.Fatalf("got %v, want invalid", r)
	}
	if strings.Contains(r.Detail, marker) || !strings.Contains(r.Detail, "gt-adv-0001") {
		t.Fatalf("detail %q", r.Detail)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		f    func(*advisory.Set)
		ok   bool
	}{
		{"valid", func(*advisory.Set) {}, true},
		{"empty set", func(s *advisory.Set) { s.Entries = nil }, true},
		{"release set with no test_only entry", func(s *advisory.Set) { s.Purpose = advisory.PurposeRelease; s.Entries[0].TestOnly = false }, true},
		{"range with no endpoint covers every version", func(s *advisory.Set) { s.Entries[0].Affected[0].Ranges = []advisory.Range{{}} }, true},
		{"exact versions only", func(s *advisory.Set) {
			s.Entries[0].Affected[0] = advisory.Affected{Vendor: "SEL", Product: "SEL-751", Scheme: advisory.SchemeExact, Versions: []string{"anything"}}
		}, true},
		{"absent op with no values", func(s *advisory.Set) {
			s.Entries[0].Preconditions[0] = advisory.Item{Name: "no-ftp", Kind: advisory.KindService, Key: "ftp", Op: advisory.OpAbsent}
		}, true},

		{"bad contract", func(s *advisory.Set) { s.Contract = "otsec.advisory/0.2" }, false},
		{"bad set_id", func(s *advisory.Set) { s.SetID = "Otsec" }, false},
		{"version 0", func(s *advisory.Set) { s.Version = 0 }, false},
		{"issued_at not UTC", func(s *advisory.Set) { s.IssuedAt = "2026-11-05T00:00:00+03:00" }, false},
		{"issued_at lower-case z", func(s *advisory.Set) { s.IssuedAt = "2026-11-05T00:00:00z" }, false},
		{"bad purpose", func(s *advisory.Set) { s.Purpose = "lab" }, false},
		{"publisher too long", func(s *advisory.Set) { s.Publisher = strings.Repeat("p", advisory.MaxPublisherBytes+1) }, false},
		{"bad entry id", func(s *advisory.Set) { s.Entries[0].ID = "-x" }, false},
		{"duplicate entry id", func(s *advisory.Set) { s.Entries = append(s.Entries, s.Entries[0]) }, false},
		{"title too long", func(s *advisory.Set) { s.Entries[0].Title = strings.Repeat("t", advisory.MaxTitleBytes+1) }, false},
		{"too many sources", func(s *advisory.Set) {
			for len(s.Entries[0].Sources) <= advisory.MaxSources {
				s.Entries[0].Sources = append(s.Entries[0].Sources, s.Entries[0].Sources[0])
			}
		}, false},
		{"bad source kind", func(s *advisory.Set) { s.Entries[0].Sources[0].Kind = "blog" }, false},
		{"no ref", func(s *advisory.Set) { s.Entries[0].Sources[0].Ref = "" }, false},
		{"http url", func(s *advisory.Set) { s.Entries[0].Sources[0].URL = "http://example.invalid" }, false},
		{"no published date", func(s *advisory.Set) { s.Entries[0].Sources[0].Published = "" }, false},
		{"bad retrieved date", func(s *advisory.Set) { s.Entries[0].Sources[0].Retrieved = "2026-13-01" }, false},
		{"upper-case sha256", func(s *advisory.Set) { s.Entries[0].Sources[0].SHA256 = strings.Repeat("AB", 32) }, false},
		{"no affected", func(s *advisory.Set) { s.Entries[0].Affected = nil }, false},
		{"no product", func(s *advisory.Set) { s.Entries[0].Affected[0].Product = "" }, false},
		{"unknown scheme", func(s *advisory.Set) { s.Entries[0].Affected[0].Scheme = "semver" }, false},
		{"no range and no version", func(s *advisory.Set) {
			s.Entries[0].Affected[0].Ranges = nil
			s.Entries[0].Affected[0].Versions = nil
		}, false},
		{"sel-fid endpoint is a full FID", func(s *advisory.Set) {
			s.Entries[0].Affected[0].Ranges = []advisory.Range{{Fixed: "SEL-751-R301-V2-Z009005-D20220607"}}
		}, false},
		{"sel-fid range across branches", func(s *advisory.Set) {
			s.Entries[0].Affected[0].Ranges = []advisory.Range{{Introduced: "R300-V0", Fixed: "R400-V1"}}
		}, false},
		{"sel-fid introduced not below fixed", func(s *advisory.Set) {
			s.Entries[0].Affected[0].Ranges = []advisory.Range{{Introduced: "R300-V3", Fixed: "R300-V3"}}
		}, false},
		{"sel-fid version is not a full FID", func(s *advisory.Set) { s.Entries[0].Affected[0].Versions = []string{"R301-V2"} }, false},
		{"exact range with an endpoint", func(s *advisory.Set) {
			s.Entries[0].Affected[0] = advisory.Affected{Vendor: "SEL", Product: "X", Scheme: advisory.SchemeExact, Ranges: []advisory.Range{{Fixed: "2"}}}
		}, false},
		{"bad item name", func(s *advisory.Set) { s.Entries[0].Preconditions[0].Name = "Telnet" }, false},
		{"reserved name", func(s *advisory.Set) { s.Entries[0].Preconditions[0].Name = advisory.ReservedFirmwareVersion }, false},
		{"name in a precondition and a mitigation", func(s *advisory.Set) { s.Entries[0].Mitigations[0].Name = "telnet-enabled" }, false},
		{"mitigations at the limit", func(s *advisory.Set) { s.Entries[0].Mitigations = mitigations(advisory.MaxMitigations) }, true},
		{"one mitigation past the limit", func(s *advisory.Set) { s.Entries[0].Mitigations = mitigations(advisory.MaxMitigations + 1) }, false},
		{"unknown kind", func(s *advisory.Set) { s.Entries[0].Preconditions[0].Kind = "register" }, false},
		{"unknown op", func(s *advisory.Set) { s.Entries[0].Preconditions[0].Op = "eq" }, false},
		{"in with no values", func(s *advisory.Set) { s.Entries[0].Preconditions[0].Values = nil }, false},
		{"present with values", func(s *advisory.Set) { s.Entries[0].Preconditions[0].Op = advisory.OpPresent }, false},
		{"value too long", func(s *advisory.Set) {
			s.Entries[0].Preconditions[0].Values = []string{strings.Repeat("v", advisory.MaxRefBytes+1)}
		}, false},
		{"no key", func(s *advisory.Set) { s.Entries[0].Preconditions[0].Key = "" }, false},
		{"attribute on BFID", func(s *advisory.Set) {
			s.Entries[0].Preconditions[0] = advisory.Item{Name: "bfid", Kind: advisory.KindAttribute, Key: "BFID", Op: advisory.OpPresent}
		}, false},
		{"attribute on configVersion", func(s *advisory.Set) {
			s.Entries[0].Preconditions[0] = advisory.Item{Name: "cv", Kind: advisory.KindAttribute, Key: "configVersion", Op: advisory.OpPresent}
		}, false},
		{"control as a precondition", func(s *advisory.Set) {
			s.Entries[0].Preconditions[0] = advisory.Item{Name: "web-blocked", Kind: advisory.KindControl, Key: "tcp/80", Op: advisory.OpPresent}
		}, false},
		{"control with op absent", func(s *advisory.Set) { s.Entries[0].Mitigations[1].Op = advisory.OpAbsent }, false},
		{"control with values", func(s *advisory.Set) {
			s.Entries[0].Mitigations[1].Op = advisory.OpIn
			s.Entries[0].Mitigations[1].Values = []string{"x"}
		}, false},
		{"control on another protocol", func(s *advisory.Set) { s.Entries[0].Mitigations[1].Key = "sctp/80" }, false},
		{"control on port 0", func(s *advisory.Set) { s.Entries[0].Mitigations[1].Key = "tcp/0" }, false},
		{"control on port 65536", func(s *advisory.Set) { s.Entries[0].Mitigations[1].Key = "udp/65536" }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := validSet()
			c.f(&s)
			err := s.Validate()
			if c.ok && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if !c.ok && !errors.Is(err, advisory.ErrInvalid) {
				t.Fatalf("Validate = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestDecodeIsStrict(t *testing.T) {
	good := payloadOf(t, validSet())
	if _, err := advisory.Decode(good); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]string{
		"unknown field":      strings.Replace(string(good), `"set_id"`, `"cvss":9.8,"set_id"`, 1),
		"duplicate key":      strings.Replace(string(good), `"set_id"`, `"version":1,"set_id"`, 1),
		"case-variant key":   strings.Replace(string(good), `"set_id"`, `"Set_ID"`, 1),
		"trailing data":      string(good) + "{}",
		"severity in entry":  strings.Replace(string(good), `"test_only"`, `"severity":"high","test_only"`, 1),
		"over MaxSetPayload": string(good) + strings.Repeat(" ", advisory.MaxSetPayload),
	} {
		if _, err := advisory.Decode([]byte(b)); !errors.Is(err, advisory.ErrInvalid) {
			t.Errorf("%s: Decode = %v, want ErrInvalid", name, err)
		}
	}
}

// TestEnvelopeFitsOneRecord pins 1.4: MaxEnvelopeBytes is the base64 of
// MaxSetPayload plus 1,024 bytes, under the node's record cap less the
// headroom, and an envelope around a payload of MaxSetPayload bytes fits it.
func TestEnvelopeFitsOneRecord(t *testing.T) {
	if advisory.MaxSetPayload != 1<<20 || advisory.MaxEnvelopeBytes != 1_399_128 {
		t.Fatalf("MaxSetPayload %d, MaxEnvelopeBytes %d", advisory.MaxSetPayload, advisory.MaxEnvelopeBytes)
	}
	if base64.StdEncoding.EncodedLen(advisory.MaxSetPayload)+1024 != advisory.MaxEnvelopeBytes {
		t.Fatal("MaxEnvelopeBytes is not the base64 of MaxSetPayload plus 1,024")
	}
	if advisory.MaxEnvelopeBytes > config.RecordCap-config.RecordHeadroom {
		t.Fatalf("MaxEnvelopeBytes %d is over the record cap less headroom, %d", advisory.MaxEnvelopeBytes, config.RecordCap-config.RecordHeadroom)
	}
	env, err := json.MarshalIndent(advisory.Envelope{
		Contract: advisory.Identifier, Algorithm: "ed25519", KeyID: "ed25519-0123456789abcdef",
		Payload: make([]byte, advisory.MaxSetPayload), Signature: make([]byte, ed25519.SignatureSize),
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(env) > advisory.MaxEnvelopeBytes {
		t.Fatalf("an envelope at MaxSetPayload is %d bytes, over MaxEnvelopeBytes", len(env))
	}
}

func TestValidateAnchors(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	real := advisory.Anchor{KeyID: advisory.KeyID(pub), PublicKey: pub, Status: advisory.KeyActive}
	if err := advisory.ValidateAnchors([]advisory.Anchor{real}, false); err != nil {
		t.Fatalf("a non-test anchor in a release build: %v", err)
	}
	for i := range advisorytest.Seeds {
		test := advisorytest.Anchor(i)
		if err := advisory.ValidateAnchors([]advisory.Anchor{real, test}, false); err == nil {
			t.Errorf("test key %d accepted as an anchor in a release build", i)
		}
		if err := advisory.ValidateAnchors([]advisory.Anchor{real, test}, true); err != nil {
			t.Errorf("test key %d in a test build: %v", i, err)
		}
	}
	wrongID := real
	wrongID.KeyID = "ed25519-0000000000000000"
	short := real
	short.PublicKey = pub[:31]
	badStatus := real
	badStatus.Status = "suspended"
	for name, a := range map[string][]advisory.Anchor{
		"key ID not the key's": {wrongID},
		"short key":            {short},
		"bad status":           {badStatus},
		"duplicate":            {real, real},
	} {
		if err := advisory.ValidateAnchors(a, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeyIDIsTheAdminRule(t *testing.T) {
	pub := advisorytest.Key(0).Public().(ed25519.PublicKey)
	if advisory.KeyID(pub) != authz.AdminKeyID(pub) {
		t.Fatal("advisory key IDs differ from the admin key rule")
	}
}

func TestCodesAreTheApprovedList(t *testing.T) {
	want := []string{"malformed", "unknown_key", "revoked_key", "bad_signature", "invalid", "wrong_set", "same_version_differs", "older_version", "test_set"}
	if len(advisory.Codes) != len(want) {
		t.Fatalf("%d codes", len(advisory.Codes))
	}
	for i, c := range advisory.Codes {
		if string(c) != want[i] {
			t.Fatalf("code %d is %q, want %q", i, c, want[i])
		}
	}
}

// TestSchemaBounds holds the schema's bounds to the package's limits.
func TestSchemaBounds(t *testing.T) {
	data, err := os.ReadFile("schema/advisory.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	type prop struct{ MaxItems, MaxLength int }
	var s struct {
		Defs map[string]struct {
			Properties map[string]prop
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		def, prop string
		got, want int
	}{
		{"envelope", "payload", s.Defs["envelope"].Properties["payload"].MaxLength, base64.StdEncoding.EncodedLen(advisory.MaxSetPayload)},
		{"set", "entries", s.Defs["set"].Properties["entries"].MaxItems, advisory.MaxEntries},
		{"set", "publisher", s.Defs["set"].Properties["publisher"].MaxLength, advisory.MaxPublisherBytes},
		{"entry", "title", s.Defs["entry"].Properties["title"].MaxLength, advisory.MaxTitleBytes},
		{"entry", "sources", s.Defs["entry"].Properties["sources"].MaxItems, advisory.MaxSources},
		{"entry", "affected", s.Defs["entry"].Properties["affected"].MaxItems, advisory.MaxProducts},
		{"entry", "preconditions", s.Defs["entry"].Properties["preconditions"].MaxItems, advisory.MaxPreconditions},
		{"entry", "mitigations", s.Defs["entry"].Properties["mitigations"].MaxItems, advisory.MaxMitigations},
		{"source", "ref", s.Defs["source"].Properties["ref"].MaxLength, advisory.MaxRefBytes},
		{"source", "url", s.Defs["source"].Properties["url"].MaxLength, advisory.MaxURLBytes},
		{"affected", "ranges", s.Defs["affected"].Properties["ranges"].MaxItems, advisory.MaxRanges},
		{"affected", "versions", s.Defs["affected"].Properties["versions"].MaxItems, advisory.MaxVersions},
		{"item", "key", s.Defs["item"].Properties["key"].MaxLength, advisory.MaxRefBytes},
		{"item", "values", s.Defs["item"].Properties["values"].MaxItems, advisory.MaxValues},
	} {
		if c.got != c.want {
			t.Errorf("schema %s.%s is %d, want %d", c.def, c.prop, c.got, c.want)
		}
	}
}

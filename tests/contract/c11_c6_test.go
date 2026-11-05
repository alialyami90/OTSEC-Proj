package contract

// C11 0.1 (otsec.advisory/0.1, docs/phase4/C3-c11-advisory.md 1.1 to 1.6,
// D4-53) and C8 0.11's advisory records: C6's own cases. Expected outcomes
// come from the rule text. Every set is a test set signed with an
// advisorytest key; no real advisory is used. Ground truth: GT-HAND.
//
// What is checked here that a per-package test cannot see: the load rule's
// steps run in the order 1.5 gives, a refusal never carries a field from a
// step it did not pass, and every refusal or install C11 produces is a
// record C8 0.11 accepts.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
)

func c11Set(version uint64, purpose advisory.Purpose) advisory.Set {
	return advisory.Set{
		Contract: advisory.Identifier, SetID: "c6-test", Version: version,
		IssuedAt: "2026-11-05T00:00:00Z", Purpose: purpose, Publisher: "C6 contract tests",
		Entries: []advisory.Entry{{
			ID: "TEST-ADV-01", TestOnly: purpose == advisory.PurposeTest, Title: "invented",
			Sources: []advisory.Source{{Kind: advisory.SourceOther, Ref: "GT-ADV", Published: "2026-11-05"}},
			Affected: []advisory.Affected{{Vendor: "SEL", Product: "SEL-751", Scheme: advisory.SchemeSELFID,
				Ranges: []advisory.Range{{Introduced: "R501-V0", Fixed: "R501-V2"}}}},
		}},
	}
}

func c11Payload(t *testing.T, s advisory.Set) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// c11Envelope signs input (not SigningInput(payload)) with key n, so a test
// can sign the wrong bytes on purpose.
func c11Envelope(t *testing.T, contract string, n int, payload, input []byte) []byte {
	t.Helper()
	priv := advisorytest.Key(n)
	b, err := json.Marshal(advisory.Envelope{Contract: contract, Algorithm: "ed25519",
		KeyID: advisory.KeyID(priv.Public().(ed25519.PublicKey)), Payload: payload, Signature: ed25519.Sign(priv, input)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var c11Time = audit.Time{UTC: "2026-11-05T05:00:00.000000Z", ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized, Source: "ntp"}}

func c11Load(file []byte, anchors []advisory.Anchor, floor advisory.Floor, testBuild bool) (advisory.Outcome, advisory.Floor, *advisory.Refusal) {
	v, r := advisory.Verify(file, anchors)
	if r != nil {
		return 0, advisory.Floor{}, r
	}
	return advisory.Admit(v, floor, testBuild)
}

func TestC11LoadRuleOrder(t *testing.T) {
	a0 := []advisory.Anchor{advisorytest.Anchor(0)}
	revoked := advisorytest.Anchor(0)
	revoked.Status = advisory.KeyRevoked

	test7 := c11Payload(t, c11Set(7, advisory.PurposeTest))
	file7 := advisorytest.Sign(advisorytest.Key(0), test7)
	_, floor7, r := c11Load(file7, a0, advisory.Floor{}, true)
	if r != nil {
		t.Fatalf("the test set refused in a test build: %v", r)
	}
	other := c11Set(8, advisory.PurposeTest)
	other.SetID = "c6-other"
	bad := c11Set(8, advisory.PurposeTest)
	bad.Entries[0].Sources = nil // invalid: no published source
	invalid := c11Payload(t, bad)

	for _, c := range []struct {
		name      string
		file      []byte
		anchors   []advisory.Anchor
		floor     advisory.Floor
		testBuild bool
		want      advisory.Code // "" is installed
	}{
		{"first test set, test build", file7, a0, advisory.Floor{}, true, ""},
		{"first test set, release build", file7, a0, advisory.Floor{}, false, advisory.TestSet},

		// 1.1: the signature is over the domain and the payload. A signature
		// over the payload alone, or under another artifact's domain, is not one.
		{"signed without the domain", c11Envelope(t, advisory.Identifier, 0, test7, test7), a0, advisory.Floor{}, true, advisory.BadSignature},
		{"signed under the register's domain", c11Envelope(t, advisory.Identifier, 0, test7, append([]byte("otsec.register/0 package\n"), test7...)), a0, advisory.Floor{}, true, advisory.BadSignature},
		{"signed by an unpinned test key", advisorytest.Sign(advisorytest.Key(1), test7), a0, advisory.Floor{}, true, advisory.UnknownKey},

		// 1.5's order: key before signature, signature before payload, set
		// before order, order before purpose.
		{"revoked key and a bad signature", c11Envelope(t, advisory.Identifier, 0, test7, []byte("x")), []advisory.Anchor{revoked}, advisory.Floor{}, true, advisory.RevokedKey},
		{"bad signature over an invalid payload", c11Envelope(t, advisory.Identifier, 0, invalid, []byte("x")), a0, advisory.Floor{}, true, advisory.BadSignature},
		{"invalid payload, signed", advisorytest.Sign(advisorytest.Key(0), invalid), a0, advisory.Floor{}, true, advisory.Invalid},
		{"another set, older", advisorytest.Sign(advisorytest.Key(0), c11Payload(t, func() advisory.Set { s := other; s.Version = 1; return s }())), a0, floor7, true, advisory.WrongSet},
		{"older test set, release build", advisorytest.Sign(advisorytest.Key(0), c11Payload(t, c11Set(6, advisory.PurposeTest))), a0, floor7, false, advisory.OlderVersion},
		{"same version, other bytes", advisorytest.Sign(advisorytest.Key(0), c11Payload(t, func() advisory.Set { s := c11Set(7, advisory.PurposeTest); s.Publisher = "C6"; return s }())), a0, floor7, true, advisory.SameVersionDiffers},
		{"newer test set, test build", advisorytest.Sign(advisorytest.Key(0), c11Payload(t, c11Set(8, advisory.PurposeTest))), a0, floor7, true, ""},

		// Envelope versions: any 0.x envelope is read, but the payload must
		// name the same contract, and only 0.1 is a payload this reader decodes.
		{"envelope 0.2 over a 0.1 payload", c11Envelope(t, "otsec.advisory/0.2", 0, test7, advisory.SigningInput(test7)), a0, advisory.Floor{}, true, advisory.Invalid},
		{"envelope 1.0", c11Envelope(t, "otsec.advisory/1.0", 0, test7, advisory.SigningInput(test7)), a0, advisory.Floor{}, true, advisory.Malformed},

		// D4-53: the set in use is verified again at start and on an anchor
		// change, so revoking its key stops it.
		{"set in use, key since revoked", file7, []advisory.Anchor{revoked}, floor7, true, advisory.RevokedKey},
		{"set in use, key since unpinned", file7, nil, floor7, true, advisory.UnknownKey},
	} {
		out, next, r := c11Load(c.file, c.anchors, c.floor, c.testBuild)
		switch {
		case c.want == "" && r != nil:
			t.Errorf("%s: refused %v", c.name, r)
			continue
		case c.want == "" && out != advisory.Install:
			t.Errorf("%s: outcome %v, want install", c.name, out)
			continue
		case c.want != "" && r == nil:
			t.Errorf("%s: outcome %v, want %s", c.name, out, c.want)
			continue
		case c.want != "" && r.Code != c.want:
			t.Errorf("%s: refused %s, want %s (%v)", c.name, r.Code, c.want, r)
			continue
		}
		if r != nil {
			c11CheckRefusal(t, c.name, r)
		} else {
			c11CheckInstall(t, c.name, c.floor, next, c.file)
		}
	}
}

// c11CheckRefusal: the fields a refusal carries come only from steps it
// passed (C8 0.11), and the record C8 builds from them is valid.
func c11CheckRefusal(t *testing.T, name string, r *advisory.Refusal) {
	t.Helper()
	afterStep4 := r.Code == advisory.WrongSet || r.Code == advisory.SameVersionDiffers || r.Code == advisory.OlderVersion || r.Code == advisory.TestSet
	if afterStep4 != (r.SetID != "") || afterStep4 != (r.Version != 0) {
		t.Errorf("%s: %s refusal carries set_id %q and version %d", name, r.Code, r.SetID, r.Version)
	}
	rec := &audit.Record{Contract: audit.ContractID, NodeID: "site-a-node-1", Seq: 30, PrevHash: strings.Repeat("6", 64),
		Time: c11Time, Actor: audit.Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"},
		Action: audit.ActionAdvisorySetRefused, Outcome: audit.OutcomeDenied, ReasonCode: string(r.Code),
		Advisory: &audit.Advisory{SetID: r.SetID, Version: r.Version, KeyID: r.KeyID, FileSHA256: hex.EncodeToString(r.FileSHA256[:])}}
	if err := rec.Validate(); err != nil {
		t.Errorf("%s: C8 refuses the record of a C11 refusal: %v", name, err)
	}
}

func c11CheckInstall(t *testing.T, name string, prev, next advisory.Floor, file []byte) {
	t.Helper()
	var env advisory.Envelope
	if err := json.Unmarshal(file, &env); err != nil {
		t.Fatal(err)
	}
	set, err := advisory.Decode(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	rec := &audit.Record{Contract: audit.ContractID, NodeID: "site-a-node-1", Seq: 30, PrevHash: strings.Repeat("6", 64),
		Time: c11Time, Actor: audit.Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"},
		Action: audit.ActionAdvisorySetInstalled, Outcome: audit.OutcomeSucceeded,
		Advisory: &audit.Advisory{SetID: next.SetID, Version: next.Version, IssuedAt: set.IssuedAt,
			PayloadSHA256: hex.EncodeToString(next.PayloadSHA256[:]), KeyID: env.KeyID, PreviousVersion: prev.Version}}
	if err := rec.Validate(); err != nil {
		t.Errorf("%s: C8 refuses the record of a C11 install: %v", name, err)
	}
}

// 1.5 step 1: the size bound is on the file. A file of exactly
// MaxEnvelopeBytes is read; one byte more is malformed before it is parsed.
func TestC11EnvelopeSizeBound(t *testing.T) {
	a0 := []advisory.Anchor{advisorytest.Anchor(0)}
	file := advisorytest.Sign(advisorytest.Key(0), c11Payload(t, c11Set(7, advisory.PurposeTest)))
	pad := func(n int) []byte {
		out := append([]byte(nil), file[:len(file)-1]...)
		out = append(out, bytes.Repeat([]byte(" "), n-len(file))...)
		return append(out, '}')
	}
	if _, r := advisory.Verify(pad(advisory.MaxEnvelopeBytes), a0); r != nil {
		t.Errorf("a file of exactly MaxEnvelopeBytes refused: %v", r)
	}
	r := func() *advisory.Refusal { _, r := advisory.Verify(pad(advisory.MaxEnvelopeBytes+1), a0); return r }()
	if r == nil || r.Code != advisory.Malformed || r.KeyID != "" {
		t.Errorf("a file of MaxEnvelopeBytes+1: %v", r)
	}
}

// 1.3 and 1.4, as written: sel-fid ranges are per branch, ordered on V as a
// number; exact has no order.
func TestC11Ranges(t *testing.T) {
	for _, c := range []struct {
		name string
		r    []advisory.Range
		ok   bool
	}{
		{"V7 to V10 is ordered as numbers", []advisory.Range{{Introduced: "R501-V7", Fixed: "R501-V10"}}, true},
		{"V10 to V7", []advisory.Range{{Introduced: "R501-V10", Fixed: "R501-V7"}}, false},
		{"an empty range", []advisory.Range{{Introduced: "R501-V3", Fixed: "R501-V3"}}, false},
		{"across branches", []advisory.Range{{Introduced: "R400-V0", Fixed: "R501-V1"}}, false},
		{"no endpoint", []advisory.Range{{}}, true},
		{"fixed only", []advisory.Range{{Fixed: "R302-V9"}}, true},
		{"a two-digit branch", []advisory.Range{{Introduced: "R50-V1"}}, false},
		{"an X branch", []advisory.Range{{Introduced: "X397-V0"}}, false},
		{"lower-case r", []advisory.Range{{Introduced: "r501-V0"}}, false},
		{"a date in place of V", []advisory.Range{{Fixed: "R501-D20260101"}}, false},
	} {
		s := c11Set(7, advisory.PurposeTest)
		s.Entries[0].Affected[0].Ranges = c.r
		_, err := advisory.Decode(c11Payload(t, s))
		if c.ok != (err == nil) {
			t.Errorf("%s: %v, want ok %v", c.name, err, c.ok)
		}
	}
}

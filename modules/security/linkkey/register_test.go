package linkkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/modules/security/nodekey"
)

// The link key and the node key register reach each other in neither
// direction (NK-1, NK-6): nodekey does not change, and its register keeps
// its two kinds.

// TestLinkKeyNotInRegister (NK-1): LoadCertificate given the link key's
// reference finds no entry; a register holding an entry of kind link-key
// is refused whole, as any unknown kind is; and neither reader takes the
// other's file. Control: the link-key kind added to the register's
// validate, which then parses the register.
func TestLinkKeyNotInRegister(t *testing.T) {
	ca := newCA(t)
	f := newFixture(t)
	reg := installed(t, ca, f.keys)
	if _, err := f.load(t, encode(t, f.file), FromRegister(reg)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reg.LoadCertificate(linkRef, f.keys); err == nil {
		t.Error("LoadCertificate resolved the link key's reference")
	}
	if _, _, err := reg.LoadTrustAnchors(linkRef); err == nil {
		t.Error("LoadTrustAnchors resolved the link key's reference")
	}

	// The register with the link key's entry put into it, in the
	// register's entry form.
	regJSON, err := reg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(regJSON, &doc); err != nil {
		t.Fatal(err)
	}
	var link map[string]any
	lb, err := json.Marshal(f.file.Entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lb, &link); err != nil {
		t.Fatal(err)
	}
	doc["entries"] = append(doc["entries"].([]any), link)
	withLink, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := nodekey.Parse(withLink, testNode); got != nil || err == nil {
		t.Errorf("a register with a link-key entry was parsed: %v", err)
	} else if !strings.Contains(err.Error(), `kind "link-key"`) {
		t.Errorf("the register was refused for another reason: %v", err)
	}
	if _, err := nodekey.Parse(regJSON, testNode); err != nil {
		t.Fatalf("the register without it: %v", err)
	}

	linkJSON, err := f.file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodekey.Parse(linkJSON, testNode); err == nil {
		t.Error("the register's reader took the link key file")
	}
	if _, err := parse(regJSON, testNode); !errors.Is(err, ErrMalformed) {
		t.Errorf("the link key's reader took the register: %v", err)
	}
}

var update = flag.Bool("update", false, "rewrite testdata/register-0.1.golden.json")

// TestRegisterSchemaUnchanged (NK-6): the link key work leaves the node
// key register as it is, so a node rolled back to a build without the
// link key reads its register as before. Its format, its fields and its
// encoding are pinned by a golden written from a key derived from a fixed
// test value (no key file), and it refuses the link-key kind. Control: a
// link-key kind added to the register's validate.
func TestRegisterSchemaUnchanged(t *testing.T) {
	if nodekey.RegisterFormat != "otsec.nodekey-register/0.1" {
		t.Errorf("register format %q", nodekey.RegisterFormat)
	}
	tags := func(v any) []string {
		var out []string
		rt := reflect.TypeOf(v)
		for i := range rt.NumField() {
			out = append(out, rt.Field(i).Tag.Get("json"))
		}
		return out
	}
	if got, want := tags(nodekey.Register{}), []string{"format", "node_id", "entries"}; !slices.Equal(got, want) {
		t.Errorf("Register fields %q, want %q", got, want)
	}
	if got, want := tags(nodekey.Entry{}), []string{"ref", "kind", "version", "state", "provider,omitempty",
		"public_key,omitempty", "certificates,omitempty", "fingerprint", "installed_by", "installed_at"}; !slices.Equal(got, want) {
		t.Errorf("Entry fields %q, want %q", got, want)
	}

	seed := sha256.Sum256([]byte("otsec nodekey register golden, test only"))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), seed[:])
	if err != nil {
		t.Fatal(err)
	}
	spki := spkiOf(t, k.Public())
	r := nodekey.NewRegister(testNode)
	r.Entries = append(r.Entries, nodekey.Entry{Ref: clientRef, Kind: nodekey.KindTLSKey, Version: 1,
		State: nodekey.StatePending, Provider: nodekey.ProviderCNGSoftware, PublicKey: spki,
		Fingerprint: fingerprint(spki), InstalledBy: admin, InstalledAt: "2026-11-13T12:00:00Z"})
	b, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "register-0.1.golden.json")
	if *update {
		if err := os.WriteFile(golden, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))) {
		t.Errorf("the register's encoding changed:\n%s\nwant:\n%s", b, want)
	}
	if _, err := nodekey.Parse(want, testNode); err != nil {
		t.Errorf("the golden register: %v", err)
	}

	r.Entries[0].Kind = KindLinkKey
	if _, err := r.Marshal(); err == nil {
		t.Error("the register takes an entry of kind link-key")
	}
}

package asset_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
)

// C1 keeps a copy of C4's ceiling so the two packages need not import each
// other (D1-1); an external test package can import both.
func TestMaxReadRowsCeilingIsC4s(t *testing.T) {
	if asset.MaxReadRowsCeiling != event.MaxAlignRows {
		t.Errorf("asset.MaxReadRowsCeiling %d, event.MaxAlignRows %d", asset.MaxReadRowsCeiling, event.MaxAlignRows)
	}
}

// C1 carries the family secret policy (D1-19) and C7 applies it; until C7
// reads it from the profile, the two copies must agree.
func TestSecretPolicyMatchesC7(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "valid", "profile-sel-751-ascii.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := asset.DecodeProfile(b)
	if err != nil {
		t.Fatal(err)
	}
	c7, ok := authz.SecretPolicies["sel-751"]
	sp := p.SecretPolicy
	switch {
	case !ok || sp == nil:
		t.Fatal("sel-751 secret policy missing from C1 or C7")
	case sp.MinLen != c7.MinLen || sp.MaxLen != c7.MaxLen || sp.MnemonicLen != c7.MnemonicLen ||
		sp.WholeWord != c7.WholeWord || c7.Allowed == nil || sp.Allowed != c7.Allowed.String():
		t.Errorf("C1 %+v and C7 %+v disagree", *sp, c7)
	}
	if asset.MaxSecretLen != authz.MaxSecretLen {
		t.Errorf("asset.MaxSecretLen %d, authz.MaxSecretLen %d", asset.MaxSecretLen, authz.MaxSecretLen)
	}
}

// C1 checks C7's principal ID syntax with a copy of its pattern.
func TestPrincipalIDMatchesC7(t *testing.T) {
	for _, id := range []string{"admin:lab-admin", "operator:commissioning-sheet-07", "a", "x@y.z",
		"", ":lead", "has space", "tab\t", "é", strings.Repeat("a", 128), strings.Repeat("a", 129)} {
		c7 := authz.Principal{Type: authz.PrincipalHuman, ID: id}.Validate() == nil
		if got := asset.ValidPrincipalID(id); got != c7 {
			t.Errorf("%q: C1 %v, C7 %v", id, got, c7)
		}
	}
}

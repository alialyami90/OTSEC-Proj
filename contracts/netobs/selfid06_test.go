package netobs

import (
	"testing"

	"otsec.local/otsec/contracts/version"
)

// C4 0.6 §1 and §2.1: SelfIdentifier is the reader's own C13 identifier,
// self, which the netobs detail of detector.observation-refused carries.
// It is not Identifier, the 0.1 channel's identifier, which does not track
// self. Control: SelfIdentifier returning Identifier fails here.
func TestSelfIdentifier(t *testing.T) {
	got := SelfIdentifier()
	v, err := version.Parse(got)
	if err != nil || v != self || v.Name != "netobs" {
		t.Fatalf("SelfIdentifier %q is not self %s: %v", got, self, err)
	}
	// C13 is at 0.3 (D4-102), and SelfIdentifier follows it.
	if got != Identifier03 {
		t.Fatalf("SelfIdentifier %q, want %s", got, Identifier03)
	}
	if got == Identifier {
		t.Fatalf("SelfIdentifier is the 0.1 channel's identifier %s", Identifier)
	}
}

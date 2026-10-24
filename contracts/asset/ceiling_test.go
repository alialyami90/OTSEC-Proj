package asset_test

import (
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
)

// C1 keeps a copy of C4's ceiling so the two packages need not import each
// other (D1-1); an external test package can import both.
func TestMaxReadRowsCeilingIsC4s(t *testing.T) {
	if asset.MaxReadRowsCeiling != event.MaxAlignRows {
		t.Errorf("asset.MaxReadRowsCeiling %d, event.MaxAlignRows %d", asset.MaxReadRowsCeiling, event.MaxAlignRows)
	}
}

package baseline

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

// TestSizeCap: a baseline is stored compact and is at most MaxBytes, or the
// node's lower cap, and a learner that stops at the byte cap may hold fewer
// than max_types types.
func TestSizeCap(t *testing.T) {
	b := valid()
	out, err := Encode(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, out); err != nil || !bytes.Equal(compact.Bytes(), out) {
		t.Errorf("not compact: %.80s", out)
	}
	got, err := Decode(out)
	if err != nil || len(got.Types) != len(b.Types) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := Encode(b, len(out)); err != nil {
		t.Errorf("at the cap: %v", err)
	}
	if _, err := Encode(b, len(out)-1); !slices.Contains(Codes(err), CodeRange) {
		t.Errorf("a byte over the node's cap: %v", err)
	}
	if _, err := Encode(b, MaxBytes*2); err != nil {
		t.Errorf("a cap above MaxBytes is MaxBytes: %v", err)
	}
	// Over MaxBytes is refused before it is read, whatever it holds.
	big := append(bytes.Repeat([]byte(" "), MaxBytes+1-len(out)), out...)
	if _, err := Decode(big); !slices.Contains(Codes(err), CodeRange) {
		t.Errorf("%d bytes: %v", len(big), err)
	}
	if _, err := Decode(big[1:]); slices.Contains(Codes(err), CodeRange) {
		t.Errorf("%d bytes refused as too large: %v", len(big)-1, err)
	}
	// An invalid baseline is not encoded.
	bad := valid()
	bad.Schema = ""
	if _, err := Encode(bad, 0); err == nil {
		t.Error("an invalid baseline was encoded")
	}

	// Overflow below max_types (the byte cap bound first) is valid; overflow
	// with nothing kept is not.
	o := valid()
	o.Counts.TypesOverflow = 3
	if int64(len(o.Types)) >= o.Params.MaxTypes {
		t.Fatal("fixture: types should be below max_types")
	}
	if err := o.Validate(); err != nil {
		t.Errorf("overflow below max_types: %v", err)
	}
	o.Types = []Type{}
	if !slices.Contains(Codes(o.Validate()), CodeConflict) {
		t.Error("overflow with no type kept accepted")
	}
}

package store

import (
	"context"
	"testing"
)

// C5 0.6 (D4-18): the hold code of a change whose alarm an acknowledgement
// ended. The closed set is three codes, each naming a C8 record, and a
// configuration record can be committed with a hold of the new code.
func TestHoldAcknowledgedDifference(t *testing.T) {
	if HoldAcknowledgedDifference != "acknowledged-difference" {
		t.Fatalf("code %q", HoldAcknowledgedDifference)
	}
	r := HoldReason{Code: HoldAcknowledgedDifference, Ref: auditRef}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (HoldReason{Code: HoldAcknowledgedDifference}).Validate(); !isCode(err, CodeInvalid) {
		t.Errorf("no C8 record: %v", err)
	}
	for _, c := range []HoldCode{HoldBaseline, HoldUnapprovedDifference, HoldAcknowledgedDifference} {
		if err := (HoldReason{Code: c, Ref: auditRef}).Validate(); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	if err := (HoldReason{Code: "acknowledged", Ref: auditRef}).Validate(); !isCode(err, CodeInvalid) {
		t.Errorf("a code outside the set: %v", err)
	}
	f := newFake()
	l, err := NewLogFor(f, f.node, configDB(512<<10), DefaultGroup, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(context.Background(), configRec(100, Hold{Reason: r})); err != nil {
		t.Fatalf("a record held as acknowledged-difference: %v", err)
	}
}

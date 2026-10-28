package contract

import (
	"context"
	"testing"
	"time"

	"otsec.local/otsec/contracts/store"
)

// C5 otsec.store/0.6 (#308, B5): the hold codes acknowledged-difference
// (D4-18) and restored-difference (D4-19), from the rulings and the 0.6
// note, not from B5's v06_test.go. Each code holds a configuration record
// on a C8 reference; near-misses of the four codes stay outside the closed
// set; and neither code makes an adapter-evidence record holdable. The
// cross-version case (a store holding a code this code does not know) is
// tests/integration/storeholds/crossversion_b6_test.go. Evidence class:
// desk.

var c5v6Codes = []store.HoldCode{store.HoldBaseline, store.HoldUnapprovedDifference, "acknowledged-difference", "restored-difference"}

func TestC5v06Identifier(t *testing.T) {
	if store.Identifier != "otsec.store/0.6" {
		t.Errorf("identifier %q", store.Identifier)
	}
	if store.HoldAcknowledgedDifference != "acknowledged-difference" || store.HoldRestoredDifference != "restored-difference" {
		t.Errorf("codes %q %q: D4-18 and D4-19 name them acknowledged-difference and restored-difference",
			store.HoldAcknowledgedDifference, store.HoldRestoredDifference)
	}
}

func TestC5v06HoldCodes(t *testing.T) {
	ref := c5vRef().Ref
	for _, code := range c5v6Codes {
		if err := (store.HoldReason{Code: code, Ref: ref}).Validate(); err != nil {
			t.Errorf("%s: %v", code, err)
		}
		if err := (store.HoldReason{Code: code, Ref: store.Key{NodeID: c5vNode, Stream: c5vAudit}}).Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("%s with no C8 record: %v", code, err)
		}
	}
	for _, code := range []store.HoldCode{"", "acknowledged", "restored", "acknowledged_difference", "restored_difference",
		"Acknowledged-difference", "RESTORED-DIFFERENCE", " restored-difference", "restored-difference ", "acknowledged-difference\x00",
		"restored-differences", "unapproved-difference-restored", "approved-difference", "released"} {
		if err := (store.HoldReason{Code: code, Ref: ref}).Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("code %q: %v", code, err)
		}
	}
}

// Each new code commits with its configuration record, through the Log, and
// none makes an adapter-evidence record holdable.
func TestC5v06HoldsReachTheStore(t *testing.T) {
	ctx := context.Background()
	opt := store.GroupOptions{MaxEvents: 8, MaxWait: time.Millisecond}
	for _, code := range []store.HoldCode{store.HoldAcknowledgedDifference, store.HoldRestoredDifference} {
		reason := store.HoldReason{Code: code, Ref: c5vRef().Ref}
		cl, cc := c5vLog(t, c5vDB("config", c5vConfig, store.ClassConfiguration, 8<<20, 512<<10), opt)
		rec := store.Record{Stream: c5vConfig, Class: store.ClassConfiguration, Event: []byte("{}"), Holds: []store.Hold{{Reason: reason}}}
		if _, err := cl.Append(ctx, rec); err != nil {
			t.Fatalf("%s on a configuration record: %v", code, err)
		}
		if g := cc.all(); len(g) != 1 || len(g[0][0].Holds) != 1 || g[0][0].Holds[0].Reason != reason {
			t.Errorf("%s: the hold did not reach the store as written: %+v", code, g)
		}
		el, ec := c5vLog(t, c5vDB("evidence", c5vEvid, store.ClassAdapterEvidence, 64<<20, 0), opt)
		ev := store.Record{Stream: c5vEvid, Class: store.ClassAdapterEvidence, Event: []byte("e"), Holds: []store.Hold{{Reason: reason}}}
		if _, err := el.Append(ctx, ev); !c5vIs(err, store.CodeNotHoldable) {
			t.Errorf("%s on an adapter-evidence record: %v", code, err)
		}
		if n := len(ec.all()); n != 0 {
			t.Errorf("%s: %d commits for a refused hold", code, n)
		}
	}
}

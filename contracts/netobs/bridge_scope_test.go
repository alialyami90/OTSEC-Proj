package netobs

import (
	"testing"
)

// earlier00 is a minor below this reader's: never a later one.
const earlier00 = "otsec.netobs/0.0"

// TestBridgeChannelStaysStrict pins that the later-minor reading reaches
// only the stored readers (D3's N1, D6's N2 on #682): a channel observation
// and a heartbeat at a later minor are refused at schema, through their
// Validate and through DecodeChannel, and a detector checkpoint whose
// coverage carries an unknown degraded value is refused.
func TestBridgeChannelStaysStrict(t *testing.T) {
	hb := fxHeartbeat()
	hb.Schema, hb.Coverage.Degraded = later02, []string{"prp-late"}
	if err := hb.Validate(); !refusedAt(err, CodeSchema, "schema") {
		t.Errorf("heartbeat at 0.2, Validate: got %v, want schema", err)
	}
	if _, err := DecodeChannel(mustJSON(t, hb)); !refusedAt(err, CodeSchema, "schema") {
		t.Errorf("heartbeat at 0.2, DecodeChannel: got %v, want schema", err)
	}

	o := fxFunction()
	o.Schema, o.Coverage.Degraded = later02, []string{"prp-late"}
	if err := o.Validate(); !refusedAt(err, CodeSchema, "schema") {
		t.Errorf("observation at 0.2, Validate: got %v, want schema", err)
	}
	if _, err := DecodeChannel(mustJSON(t, o)); !refusedAt(err, CodeSchema, "schema") {
		t.Errorf("observation at 0.2, DecodeChannel: got %v, want schema", err)
	}

	k := fxDetectorCheckpoint()
	cv := fxCoverage()
	cv.Degraded = []string{"prp-late"}
	k.Coverage = &cv
	if err := k.Validate(); !refusedAt(err, CodeForm, "coverage.degraded[0]") {
		t.Errorf("detector checkpoint with prp-late: got %v, want form at coverage.degraded[0]", err)
	}
}

// TestBridgeEarlierMinor pins the earlier side of "later" (D6's N1 on
// #682): at 0.0 the aggregate keys and an unknown degraded value are
// refused, as at 0.1.
func TestBridgeEarlierMinor(t *testing.T) {
	a := fxUnseen()
	a.Schema, a.AssetID = earlier00, "clock-skew"
	if err := a.Validate(); !refusedAt(err, CodeForm, "asset_id") {
		t.Errorf("clock-skew at 0.0: got %v, want form at asset_id", err)
	}

	degraded := []string{"drops-driver", "prp-late"}
	s := fxStored()
	s.Schema, s.Coverage.Degraded = earlier00, degraded
	if _, err := DecodeStored(mustJSON(t, s)); !refusedAt(err, CodeForm, "coverage.degraded[1]") {
		t.Errorf("stored observation at 0.0: got %v, want form at coverage.degraded[1]", err)
	}

	al := fxAlert()
	al.Schema, al.Coverage.Degraded = earlier00, degraded
	if err := al.Validate(); !refusedAt(err, CodeForm, "coverage.degraded[1]") {
		t.Errorf("alert at 0.0: got %v, want form at coverage.degraded[1]", err)
	}
}

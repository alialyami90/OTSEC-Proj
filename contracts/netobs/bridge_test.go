package netobs

import (
	"slices"
	"strings"
	"testing"
)

// later02 is C13 0.2, now this reader's own minor: a later minor on the 0.1
// channel. later03 is the next minor, a later one for the stored readers;
// the bridge's degraded leg moved to it with the minor (P4-4-CC).
const (
	later02 = Identifier02
	later03 = "otsec.netobs/0.3"
)

// refusedAt reports whether err refuses field with code.
func refusedAt(err error, code Code, field string) bool {
	return slices.Contains(Codes(err), code) && strings.Contains(err.Error(), field)
}

// TestBridgeAggregateKeys is CH-35 item 3, now 0.2's own (CH-47): a stored
// alert of 0.2, or of a later minor, whose asset_id is one of the three
// aggregate keys is read; at 0.1 the same alert is still refused.
func TestBridgeAggregateKeys(t *testing.T) {
	for _, key := range AggregateKeys {
		for _, schema := range []string{later02, later03} {
			a := fxUnseen()
			a.Schema, a.AssetID, a.Assets, a.AssetsTotal = schema, key, []string{fxAsset}, 1
			h, err := a.Health()
			if err != nil {
				t.Fatalf("%s at %s: %v", key, schema, err)
			}
			back, err := AlertFromHealth(h)
			if err != nil {
				t.Errorf("%s at %s, read from its health body: %v", key, schema, err)
			} else if back.AssetID != key || !slices.Equal(back.Assets, a.Assets) || back.AssetsTotal != 1 {
				t.Errorf("%s at %s read back as %q %q %d", key, schema, back.AssetID, back.Assets, back.AssetsTotal)
			}
		}
		a := fxUnseen()
		a.AssetID = key
		h, err := a.Health()
		if err == nil {
			t.Errorf("%s at 0.1: encoded", key)
		}
		a.Schema = later02
		a.Assets, a.AssetsTotal = []string{fxAsset}, 1
		h, _ = a.Health()

		a.Schema, a.Assets, a.AssetsTotal = Identifier, nil, 0
		if err := a.Validate(); !refusedAt(err, CodeForm, "asset_id") {
			t.Errorf("%s at 0.1: got %v, want a form refusal of asset_id", key, err)
		}
		h.Details["schema"] = Identifier
		delete(h.Details, "assets")
		delete(h.Details, "assets_total")
		if _, err := AlertFromHealth(h); !refusedAt(err, CodeForm, "asset_id") {
			t.Errorf("%s at 0.1, read from its health body: got %v", key, err)
		}
	}
	// Only the three keys: another word is still refused at a later minor.
	a := fxUnseen()
	a.Schema, a.AssetID = later02, "clock-skewed"
	if err := a.Validate(); !refusedAt(err, CodeForm, "asset_id") {
		t.Errorf("an unknown asset_id at 0.2: got %v", err)
	}
}

// TestBridgeUnknownDegraded is CH-35 item 4: an unknown coverage.degraded
// value of a later minor is kept and read as degraded, in a stored
// observation and in an alert; at 0.1, and on the channel, it is refused.
func TestBridgeUnknownDegraded(t *testing.T) {
	const added = "prp-late"
	degraded := []string{"drops-driver", added}

	o := fxStored()
	o.Schema, o.Coverage.Degraded = later03, degraded
	got, err := DecodeStored(mustJSON(t, o))
	if err != nil {
		t.Fatalf("stored observation at 0.3: %v", err)
	}
	if !slices.Equal(got.Coverage.Degraded, degraded) {
		t.Errorf("stored observation at 0.3 read degraded as %q, want %q", got.Coverage.Degraded, degraded)
	}

	for _, schema := range []string{Identifier, later02} {
		o.Schema = schema
		if _, err := DecodeStored(mustJSON(t, o)); !refusedAt(err, CodeForm, "coverage.degraded[1]") {
			t.Errorf("stored observation at %s: got %v", schema, err)
		}
	}

	a := fxAlert()
	a.Schema, a.Coverage.Degraded = later03, degraded
	h, err := a.Health()
	if err != nil {
		t.Fatalf("alert at 0.3: %v", err)
	}
	back, err := AlertFromHealth(h)
	if err != nil {
		t.Errorf("alert at 0.3, read from its health body: %v", err)
	} else if !slices.Equal(back.Coverage.Degraded, degraded) {
		t.Errorf("alert at 0.3 read degraded as %q", back.Coverage.Degraded)
	}
	h.Details["schema"] = Identifier
	if _, err := AlertFromHealth(h); !refusedAt(err, CodeForm, "coverage.degraded[1]") {
		t.Errorf("alert at 0.1: got %v", err)
	}

	// The channel is strict: a channel record is 0.1 only.
	f := fxFunction()
	f.Coverage.Degraded = degraded
	if err := f.Validate(); !refusedAt(err, CodeForm, "coverage.degraded[1]") {
		t.Errorf("channel observation: got %v", err)
	}
	hb := fxHeartbeat()
	hb.Coverage.Degraded = degraded
	if err := hb.Validate(); !refusedAt(err, CodeForm, "coverage.degraded[1]") {
		t.Errorf("heartbeat: got %v", err)
	}

	// At a later minor the value must still be a token, and not repeated.
	for _, tc := range []struct {
		name     string
		degraded []string
		code     Code
		field    string
	}{
		{"not a token", []string{"prp late"}, CodeForm, "coverage.degraded[0]"},
		{"empty", []string{""}, CodeForm, "coverage.degraded[0]"},
		{"repeated", []string{added, added}, CodeOrder, "coverage.degraded"},
	} {
		o := fxStored()
		o.Schema, o.Coverage.Degraded = later03, tc.degraded
		if _, err := DecodeStored(mustJSON(t, o)); !refusedAt(err, tc.code, tc.field) {
			t.Errorf("%s at 0.3: got %v, want %s at %s", tc.name, err, tc.code, tc.field)
		}
	}
}

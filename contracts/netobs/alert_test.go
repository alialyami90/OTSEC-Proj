package netobs

import (
	"reflect"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/event"
)

func fxAlert() *Alert {
	return &Alert{
		Schema: Identifier, Rule: RuleUnauthorizedWrite, AssetID: fxAsset,
		Baseline: "sha256:" + hash([]byte("baseline")), BaselineVersion: 2,
		KeyText: "unauthorized-write to " + fxAsset, BaselineValue: "authorized writers for control: none",
		Observation: `wrote to the device: DNP3 5 from "192.0.2.10"`, Clock: ClockCapture,
		AtUTC: "2026-11-07T10:04:00.000001Z", WindowStartUTC: "2026-11-07T10:00:00.000001Z",
		Hits: 3, Sources: 2,
		Related:      []event.EventID{{NodeID: "site-a-node1", Stream: event.Stream("network-observation/" + fxSensor), Seq: 7}, {NodeID: "site-a-node1", Stream: event.Stream("network-observation/" + fxSensor), Seq: 9}, {NodeID: "site-a-node1", Stream: event.Stream("network-observation/" + fxSensor), Seq: 12}},
		RelatedTotal: 3,
		Cites: []Cite{{CaptureID: "ring:" + fxRun + ":3", Frames: []CiteFrame{{N: 17, SHA256: hash([]byte{1})}, {N: 19, SHA256: hash([]byte{2})}}},
			{CaptureID: "file:" + hash([]byte("pcap")), Frames: []CiteFrame{{N: 4, SHA256: hash([]byte{3})}}}},
		Capture:  hash([]byte("alert capture")),
		Coverage: fxCoverage(),
	}
}

func fxUnseen() *Alert {
	return &Alert{
		Schema: Identifier, Rule: RuleOwnSessionUnseen, AssetID: fxAsset,
		KeyText: "own-session-unseen for " + fxAsset, Params: []Param{{Name: "tie_grace_s", Value: "30"}},
		BaselineValue: "not yet seen: before acknowledgement, the draft covers this asset",
		Observation:   "session " + fxRun + " [2026-11-07T10:00:00Z, 2026-11-07T10:00:05Z] not observed",
		Clock:         ClockCapture, AtUTC: "2026-11-07T10:00:35Z", WindowStartUTC: "2026-11-07T10:00:35Z",
		Hits: 1, Coverage: fxCoverage(),
	}
}

// fxMissing is fxAlert with every cited frame's bytes gone: its capture is
// the header-only pcap, and the alert still cites all three frames.
func fxMissing() *Alert {
	a := fxAlert()
	a.FramesMissing = 3
	return a
}

func TestAlertRoundTrip(t *testing.T) {
	for _, a := range []*Alert{fxAlert(), fxUnseen(), fxMissing()} {
		h, err := a.Health()
		if err != nil {
			t.Fatalf("%s: %v", a.Rule, err)
		}
		back, err := AlertFromEvent(&event.Event{Kind: event.KindHealth, Health: &h})
		if err != nil {
			t.Fatalf("%s: %v", a.Rule, err)
		}
		norm := func(x *Alert) {
			if len(x.Coverage.PRP.LANsSeen) == 0 {
				x.Coverage.PRP.LANsSeen = nil
			}
			if len(x.Coverage.Degraded) == 0 {
				x.Coverage.Degraded = nil
			}
			if len(x.Related) == 0 {
				x.Related = nil
			}
		}
		norm(a)
		norm(back)
		if !reflect.DeepEqual(a, back) {
			t.Errorf("%s: round trip\n got %+v\nwant %+v", a.Rule, back, a)
		}
		for k := range h.Details {
			if !detailKey(k) {
				t.Errorf("detail key %q is not a C4 detail key", k)
			}
		}
	}
}

// detailKey is C4's detail key form.
func detailKey(k string) bool {
	if len(k) == 0 || len(k) > 64 || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	for _, ch := range k {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '.' || ch == '-') {
			return false
		}
	}
	return true
}

func TestAlertRules(t *testing.T) {
	cases := []struct {
		name string
		code Code
		base func() *Alert
		mut  func(a *Alert)
	}{
		{"unknown rule", CodeForm, fxAlert, func(a *Alert) { a.Rule = "rate" }},
		{"no baseline for a baseline rule", CodeMissing, fxAlert, func(a *Alert) { a.Baseline, a.BaselineVersion = "", 0 }},
		{"version without baseline", CodeConflict, fxUnseen, func(a *Alert) { a.BaselineVersion = 1 }},
		{"baseline not a hash", CodeForm, fxAlert, func(a *Alert) { a.Baseline = "v2" }},
		{"param missing", CodeConflict, fxUnseen, func(a *Alert) { a.Params = nil }},
		{"param on a rule with none", CodeConflict, fxAlert, func(a *Alert) { a.Params = []Param{{Name: "tie_grace_s", Value: "30"}} }},
		{"device clock", CodeForm, fxAlert, func(a *Alert) { a.Clock = "device" }},
		{"at before window", CodeOrder, fxAlert, func(a *Alert) { a.AtUTC = "2026-11-07T09:00:00Z" }},
		{"related_total not hits", CodeConflict, fxAlert, func(a *Alert) { a.Hits = 4 }},
		{"sources above hits", CodeRange, fxAlert, func(a *Alert) { a.Sources = 4 }},
		{"no cite", CodeRange, fxAlert, func(a *Alert) { a.Cites = nil }},
		{"five flows", CodeRange, fxAlert, func(a *Alert) { a.Cites = append(a.Cites, a.Cites[0], a.Cites[0], a.Cites[0]) }},
		{"three frames in a flow", CodeRange, fxAlert, func(a *Alert) {
			a.Cites[0].Frames = append(a.Cites[0].Frames, CiteFrame{N: 20, SHA256: hash(nil)})
		}},
		{"no capture", CodeForm, fxAlert, func(a *Alert) { a.Capture = "" }},
		{"unseen cites", CodeConflict, fxUnseen, func(a *Alert) { a.Cites, a.Capture = fxAlert().Cites, fxAlert().Capture }},
		{"unseen related", CodeConflict, fxUnseen, func(a *Alert) { a.Related, a.RelatedTotal = fxAlert().Related[:1], 1 }},
		{"text over ExplainMax", CodeRange, fxAlert, func(a *Alert) { a.Observation = string(make([]byte, ExplainMax+1)) }},
		{"asset", CodeForm, fxAlert, func(a *Alert) { a.AssetID = "relay-1" }},
		{"coverage", CodeRange, fxAlert, func(a *Alert) { a.Coverage.Settings.MaxPendingDNP3 = 1 }},
		{"frames_missing above the cited frames", CodeRange, fxAlert, func(a *Alert) { a.FramesMissing = 4 }},
		{"frames_missing negative", CodeRange, fxAlert, func(a *Alert) { a.FramesMissing = -1 }},
		{"unseen frames_missing", CodeRange, fxUnseen, func(a *Alert) { a.FramesMissing = 1 }},
	}
	for _, tc := range cases {
		a := tc.base()
		tc.mut(a)
		if got := Codes(a.Validate()); !slices.Contains(got, tc.code) {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.code)
		}
	}
	// The four baseline-free rules run before acknowledgement.
	for _, r := range BaselineFree {
		a := fxAlert()
		a.Rule, a.Baseline, a.BaselineVersion = r, "", 0
		a.Params = nil
		for _, p := range RuleParams(r) {
			a.Params = append(a.Params, Param{Name: p, Value: "30"})
		}
		if r == RuleOwnSessionUnseen {
			a = fxUnseen()
		}
		if err := a.Validate(); err != nil {
			t.Errorf("%s with no baseline: %v", r, err)
		}
	}
}

func TestAlertFromHealthStrict(t *testing.T) {
	h, err := fxAlert().Health()
	if err != nil {
		t.Fatal(err)
	}
	h.Details["extra"] = "x"
	if _, err := AlertFromHealth(h); !slices.Contains(Codes(err), CodeConflict) {
		t.Errorf("unknown detail: %v", err)
	}
	h.Details["schema"] = "otsec.netobs/0.7"
	if _, err := AlertFromHealth(h); err != nil {
		t.Errorf("a later minor may add details: %v", err)
	}
	delete(h.Details, "extra")
	delete(h.Details, "coverage.hsr")
	if _, err := AlertFromHealth(h); !slices.Contains(Codes(err), CodeMissing) {
		t.Errorf("coverage detail missing: %v", err)
	}
	if h, _ := fxAlert().Health(); h.Details["frames_missing"] != "" {
		t.Errorf("frames_missing written when 0: %q", h.Details["frames_missing"])
	}
	h3, _ := fxMissing().Health()
	if h3.Details["frames_missing"] != "3" {
		t.Errorf("frames_missing: %q", h3.Details["frames_missing"])
	}
	for _, v := range []string{"0", "03", "x"} {
		h3.Details["frames_missing"] = v
		if _, err := AlertFromHealth(h3); err == nil {
			t.Errorf("frames_missing %q read", v)
		}
	}
	h2, _ := fxAlert().Health()
	h2.Type = "baseline.departure"
	if _, err := AlertFromHealth(h2); !slices.Contains(Codes(err), CodeType) {
		t.Errorf("another health type: %v", err)
	}
}

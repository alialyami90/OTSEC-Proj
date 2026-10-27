package baseline

import (
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

func id(seq uint64) event.EventID {
	return event.EventID{NodeID: "site-a", Stream: "sel751/feeder-1/ser", Seq: seq}
}

func validAlarm() *Alarm {
	return &Alarm{
		Schema: Identifier, AssetID: assetA,
		Baseline: "sha256:" + strings.Repeat("b", 64), BaselineVersion: 1,
		Rule: RuleRepeats, Key: Key{Source: SourceSER, Element: "51P1P", State: "Asserted"}, KeyText: "51P1P Asserted",
		Params:        []Param{{Name: "repeats_n", Value: "5"}, {Name: "repeats_window_s", Value: "600"}},
		BaselineValue: "max_per_window 2", Observation: "6 in the 600 s to 2026-11-20T14:05:00Z",
		Clock: ClockReceived, AtUTC: "2026-11-20T14:05:00Z",
		Events: []event.EventID{id(1), id(2), id(3), id(4), id(5), id(6)}, EventsTotal: 6,
		NotCounted: []event.EventID{id(7)}, NotCountedTotal: 1,
	}
}

func TestValidAlarm(t *testing.T) {
	if err := validAlarm().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAlarmRules(t *testing.T) {
	many := make([]event.EventID, MaxEventIDs+1)
	for i := range many {
		many[i] = id(uint64(i + 1))
	}
	cases := []struct {
		name string
		edit func(*Alarm)
		want Code
	}{
		{"unknown rule", func(a *Alarm) { a.Rule = "storm" }, CodeForm},
		{"params are the rule's", func(a *Alarm) { a.Params = a.Params[:1] }, CodeConflict},
		{"params in order", func(a *Alarm) { a.Params[0], a.Params[1] = a.Params[1], a.Params[0] }, CodeConflict},
		{"param decimal", func(a *Alarm) { a.Params[0].Value = "five" }, CodeForm},
		{"device clock only for time", func(a *Alarm) { a.Clock = ClockDevice }, CodeConflict},
		{"explains itself", func(a *Alarm) { a.Observation = "" }, CodeMissing},
		{"names the events", func(a *Alarm) { a.Events, a.EventsTotal = nil, 0 }, CodeMissing},
		{"at most MaxEventIDs", func(a *Alarm) { a.Events, a.EventsTotal = many, int64(len(many)) }, CodeRange},
		{"total counts the list", func(a *Alarm) { a.EventsTotal = 5 }, CodeConflict},
		{"short list is the whole", func(a *Alarm) { a.EventsTotal = 9 }, CodeConflict},
		{"not counted total", func(a *Alarm) { a.NotCountedTotal = 0 }, CodeConflict},
		{"bad event id", func(a *Alarm) { a.Events[0].Seq = 0 }, CodeForm},
		{"baseline hash", func(a *Alarm) { a.Baseline = "abc" }, CodeForm},
		{"at utc", func(a *Alarm) { a.AtUTC = "" }, CodeMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAlarm()
			tc.edit(a)
			if got := Codes(a.Validate()); !slices.Contains(got, tc.want) {
				t.Errorf("codes %v, want %s", got, tc.want)
			}
		})
	}
	// A full list may stand for a larger total; the time rule may use device
	// time; absence may name no event.
	full := validAlarm()
	full.Events, full.EventsTotal = many[:MaxEventIDs], 100
	tm := validAlarm()
	tm.Rule, tm.Params, tm.Clock = RuleTime, nil, ClockDevice
	ab := validAlarm()
	ab.Rule, ab.Params, ab.Events, ab.EventsTotal = RuleAbsence, []Param{{"interval_s", "5040"}, {"tolerance_s", "504"}}, nil, 0
	for name, a := range map[string]*Alarm{"full list": full, "time on device": tm, "absence": ab} {
		if err := a.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAlarmTravelsAsC4Health(t *testing.T) {
	a := validAlarm()
	h, err := a.Health()
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != HealthDeparture || !slices.Equal(h.Related, a.Events) {
		t.Fatalf("health %+v", h)
	}
	// The health body is a valid C4 platform event.
	e := event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: "site-a", Stream: "platform/health", Seq: 1},
		Origin: event.OriginPlatform, Kind: event.KindHealth,
		Source:   event.Source{OriginAuth: event.AuthPlatform},
		Received: event.Received{UTC: "2026-11-20T14:05:01Z", ResolutionNS: 1_000_000_000, Clock: event.Clock{Sync: event.SyncSynchronized}},
		Health:   &h}
	if err := e.Validate(); err != nil {
		t.Fatalf("not a valid C4 event: %v", err)
	}
	back, err := AlarmFromHealth(h)
	if err != nil {
		t.Fatal(err)
	}
	if back.Key != a.Key || !slices.Equal(back.Params, a.Params) || !slices.Equal(back.NotCounted, a.NotCounted) ||
		back.EventsTotal != a.EventsTotal || back.BaselineVersion != 1 || back.Observation != a.Observation {
		t.Errorf("round trip lost a field: %+v", back)
	}
	h.Details["extra"] = "1"
	if _, err := AlarmFromHealth(h); !slices.Contains(Codes(err), CodeConflict) {
		t.Errorf("an unknown detail at this minor: %v", err)
	}
	h.Details["schema"] = "otsec.baseline/0.2"
	if _, err := AlarmFromHealth(h); err != nil {
		t.Errorf("a later minor may add details: %v", err)
	}
	if _, err := validAlarm().Health(); err != nil {
		t.Fatal(err)
	}
	bad := validAlarm()
	bad.Rule = "storm"
	if _, err := bad.Health(); err == nil {
		t.Error("an invalid alarm is not encoded")
	}
}

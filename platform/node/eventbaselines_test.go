package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/baseline"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// ebConfig is a node with one SEL-751 collected for SER, its configuration
// quota, and mod applied.
func ebConfig(t *testing.T, mod func(*nodeconfigtest.Config)) []byte {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300)
	nc.Store.Quotas["configuration"] = 16 << 20
	if mod != nil {
		mod(nc)
	}
	return nc.Bytes()
}

// event_baselines loads with a whole parameter object per asset, gives the
// asset a configuration stream, and counts toward the configuration quota
// floor only for an asset whose configuration is not also read.
func TestEventBaselinesLoad(t *testing.T) {
	c, err := ParseConfig(ebConfig(t, func(nc *nodeconfigtest.Config) { nc.AddEventBaseline(relayID) }))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := c.EventBaselineFor(relayID)
	if !ok || e.Params.MinEvents != 10 || e.Params.TimeClock != baseline.ClockReceived {
		t.Fatalf("event baseline %+v, %v", e, ok)
	}
	if _, ok := c.EventBaselineFor("nobody"); ok {
		t.Fatal("a baseline for an asset that has none")
	}
	if got, want := c.EventBaselineQuotaFloor(), int64(EventBaselineQuotaRecords)*int64(baseline.MaxBytes); got != want {
		t.Fatalf("floor %d, want %d", got, want)
	}
	l, err := c.Layout()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range l.Databases {
		for _, s := range d.Streams {
			found = found || (d.ID == ConfigDB && s.ID == ConfigStream(relayID) && s.Class == c5.ClassConfiguration)
		}
	}
	if !found {
		t.Fatalf("no configuration stream for the asset in %+v", l.Databases)
	}

	// An asset whose configuration is read is covered by its own floor.
	c, err = ParseConfig(ebConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddEventBaseline(relayID)
		nc.Store.Quotas["configuration"] = 32 << 20
		nc.Schedule = append(nc.Schedule, nodeconfigtest.Collection{ID: "sch-cfg", AssetID: relayID, Endpoint: "port1-telnet",
			Operation: "sel.config.read_all", CredentialRef: nodeconfigtest.TestCredentialRef, EverySeconds: 3600})
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.EventBaselineQuotaFloor(); got != 0 {
		t.Fatalf("floor %d for an asset whose configuration is read", got)
	}
}

func TestEventBaselinesRefused(t *testing.T) {
	const other = "3c8e5f21-9d40-4b6c-8f32-8d5a1e7b9c24"
	for name, tc := range map[string]struct {
		mod  func(*nodeconfigtest.Config)
		want string
	}{
		"unknown asset": {func(nc *nodeconfigtest.Config) { nc.AddEventBaseline(other) }, "is not in assets"},
		"listed twice":  {func(nc *nodeconfigtest.Config) { nc.AddEventBaseline(relayID).AddEventBaseline(relayID) }, "listed twice"},
		"no configuration quota": {func(nc *nodeconfigtest.Config) {
			nc.AddEventBaseline(relayID)
			delete(nc.Store.Quotas, "configuration")
		}, "store.quotas.configuration"},
		"quota below the floor": {func(nc *nodeconfigtest.Config) {
			nc.AddEventBaseline(relayID)
			nc.Store.Quotas["configuration"] = EventBaselineQuotaRecords*int64(baseline.MaxBytes) - 1
		}, "below the floor for event baselines"},
		"no events to observe": {func(nc *nodeconfigtest.Config) {
			nc.Schedule = nil
			nc.AddEventBaseline(relayID)
		}, "no events to observe"},
		"only a configuration read": {func(nc *nodeconfigtest.Config) {
			nc.Schedule = []nodeconfigtest.Collection{{ID: "sch-cfg", AssetID: relayID, Endpoint: "port1-telnet",
				Operation: "sel.config.read_all", CredentialRef: nodeconfigtest.TestCredentialRef, EverySeconds: 3600}}
			nc.AddEventBaseline(relayID)
		}, "no events to observe"},
		"a parameter missing": {func(nc *nodeconfigtest.Config) {
			nc.AddEventBaseline(relayID)
			delete(nc.EventBaselines[0].Params, "repeats_n")
		}, "repeats_n 0 is below 1"},
		"device clock": {func(nc *nodeconfigtest.Config) {
			nc.AddEventBaseline(relayID)
			nc.EventBaselines[0].Params["time_clock"] = "device"
		}, "received clock only"},
		"an unknown parameter": {func(nc *nodeconfigtest.Config) {
			nc.AddEventBaseline(relayID)
			nc.EventBaselines[0].Params["learn_faster"] = true
		}, "learn_faster"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig(ebConfig(t, tc.mod))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

// A syslog-only asset has events to observe too.
func TestEventBaselineForASyslogSender(t *testing.T) {
	nc, _ := listenConfig(t, func(nc *nodeconfigtest.Config) {
		nc.Schedule = nil
		nc.Store.Quotas["configuration"] = 16 << 20
		nc.AddEventBaseline(relayID)
	})
	if _, err := ParseConfig(nc.Bytes()); err != nil {
		t.Fatal(err)
	}
}

// The node repeats C10's range check on the parameters, because C10 states
// it on a whole baseline. Each single-field break of C10's valid baseline is
// refused by both; the baseline's own parameters pass both.
func TestEventBaselineParamsMatchC10(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "baseline", "testdata", "valid", "baseline-synthetic.json"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := baseline.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkEventBaselineParams(base.Params); err != nil {
		t.Fatalf("the valid baseline's own parameters: %v", err)
	}
	for name, mut := range map[string]func(*baseline.Params){
		"min_duration_s":          func(p *baseline.Params) { p.MinDurationS = 0 },
		"min_events":              func(p *baseline.Params) { p.MinEvents = 0 },
		"repeats_n":               func(p *baseline.Params) { p.RepeatsN = 0 },
		"repeats_window_s":        func(p *baseline.Params) { p.RepeatsWindowS = 0 },
		"rate_bucket_s":           func(p *baseline.Params) { p.RateBucketS = 0 },
		"rate_min":                func(p *baseline.Params) { p.RateMin = 0 },
		"max_types zero":          func(p *baseline.Params) { p.MaxTypes = 0 },
		"max_types ceiling":       func(p *baseline.Params) { p.MaxTypes = baseline.MaxTypesCeiling + 1 },
		"alarm_hold_s zero":       func(p *baseline.Params) { p.AlarmHoldS = 0 },
		"alarm_hold_s short":      func(p *baseline.Params) { p.AlarmHoldS = baseline.MinAlarmHoldS - 1 },
		"max_alarms zero":         func(p *baseline.Params) { p.MaxAlarmsPerHold = 0 },
		"max_alarms ceiling":      func(p *baseline.Params) { p.MaxAlarmsPerHold = baseline.MaxAlarmsPerHoldCeiling + 1 },
		"rate_factor_pct":         func(p *baseline.Params) { p.RateFactorPct = 99 },
		"periodic_min":            func(p *baseline.Params) { p.PeriodicMinOccurrences = 2 },
		"periodic_spread_pct low": func(p *baseline.Params) { p.PeriodicSpreadPct = -1 },
		"periodic_spread_pct":     func(p *baseline.Params) { p.PeriodicSpreadPct = 101 },
		"absence_tolerance low":   func(p *baseline.Params) { p.AbsenceTolerancePct = -1 },
		"absence_tolerance":       func(p *baseline.Params) { p.AbsenceTolerancePct = 101 },
	} {
		t.Run(name, func(t *testing.T) {
			v := *base
			mut(&v.Params)
			if v.Validate() == nil {
				t.Fatal("C10 accepts it: the test breaks nothing")
			}
			if checkEventBaselineParams(v.Params) == nil {
				t.Fatal("the node accepts what C10 refuses")
			}
		})
	}
}

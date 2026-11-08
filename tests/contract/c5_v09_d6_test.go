package contract

import (
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/store"
)

// C5 0.9 (D4-68; docs/phase4/D5-c5-0.9.md sections 1 and 8), D6's contract
// tests, written from the approved text before the package change. Ground
// truth: independent of D5's tests and goldens (the note's tables). Evidence
// class: desk.

// c5v9Pairs is the closed table, written here from the approved text: the
// nine 0.8 pairs and the three 0.9 pairs.
var c5v9Pairs = map[[2]string]bool{
	{"evidence", "config.snapshot"}:               true,
	{"evidence", "config.difference"}:             true,
	{"evidence", "baseline.event"}:                true,
	{"working-state", "eventcheckpoint.learner"}:  true,
	{"working-state", "eventcheckpoint.detector"}: true,
	{"evidence", "identity"}:                      true,
	{"evidence", "finding"}:                       true,
	{"evidence", "advisory.set"}:                  true,
	{"working-state", "identity.read"}:            true,
	{"evidence", "baseline.network"}:              true,
	{"working-state", "netcheckpoint.learner"}:    true,
	{"working-state", "netcheckpoint.detector"}:   true,
}

const (
	c5v9Obs   store.StreamID = "network-observation/sensor1"
	c5v9Alert store.StreamID = "network-alert/sensor1"
	c5v9Base  store.StreamID = "netbaseline/sensor1"
)

func TestC5v09Identifier(t *testing.T) {
	if store.Identifier != "otsec.store/0.9" {
		t.Errorf("identifier %q", store.Identifier)
	}
}

// The two classes exist with their exact names, are both in Classes, and
// Classes holds nothing else new.
func TestC5v09Classes(t *testing.T) {
	if store.ClassNetworkObservation != "network-observation" || store.ClassNetworkAlert != "network-alert" {
		t.Fatalf("class names %q %q", store.ClassNetworkObservation, store.ClassNetworkAlert)
	}
	want := []store.StreamClass{
		"adapter-evidence", "syslog-stream", "syslog-datagram", "audit", "platform", "configuration", "syslog-unknown",
		"network-observation", "network-alert",
	}
	if !slices.Equal(slices.Sorted(slices.Values(store.Classes)), slices.Sorted(slices.Values(want))) {
		t.Errorf("Classes %v, want %v", store.Classes, want)
	}
}

// Both network classes drop and count at their quota and raise
// network-full, reported as store.network-full; every older class keeps its
// 0.8 action and alarm, so the new case can't become a default.
func TestC5v09ActionAndAlarm(t *testing.T) {
	if store.AlarmNetworkFull != "network-full" || store.AlarmNetworkFull.HealthType() != "store.network-full" {
		t.Errorf("alarm %q reported as %q", store.AlarmNetworkFull, store.AlarmNetworkFull.HealthType())
	}
	for _, c := range []store.StreamClass{store.ClassNetworkObservation, store.ClassNetworkAlert} {
		if a, err := store.ActionFor(c); err != nil || a != store.DropAndCount {
			t.Errorf("%s at quota: %v %v, want drop-and-count", c, a, err)
		}
		if got := store.FullAlarm(c); got != store.AlarmNetworkFull {
			t.Errorf("%s full alarm %q, want network-full", c, got)
		}
	}
	old := map[store.StreamClass][2]string{
		store.ClassAdapterEvidence: {"stop-collecting", "store-quota-reached"},
		store.ClassSyslogStream:    {"refuse-new", "store-quota-reached"},
		store.ClassSyslogDatagram:  {"drop-and-count", "store-quota-reached"},
		store.ClassAudit:           {"fail-closed", "audit-store-full"},
		store.ClassPlatform:        {"refuse-new", "store-quota-reached"},
		store.ClassConfiguration:   {"stop-collecting", "store-quota-reached"},
		store.ClassSyslogUnknown:   {"drop-and-count", "syslog-unknown-full"},
	}
	for c, w := range old {
		a, err := store.ActionFor(c)
		if err != nil || string(a) != w[0] || string(store.FullAlarm(c)) != w[1] {
			t.Errorf("%s: %v %v %q, want %v", c, a, err, store.FullAlarm(c), w)
		}
	}
	if _, err := store.ActionFor("network"); !c5vIs(err, store.CodeInvalid) {
		t.Errorf("near-miss class %q: %v", "network", err)
	}
}

// Each network class needs a record cap, inside the same bounds as any cap.
func TestC5v09QuotaNeedsRecordCap(t *testing.T) {
	for _, c := range []store.StreamClass{store.ClassNetworkObservation, store.ClassNetworkAlert} {
		q := store.Quota{Class: c, Bytes: 8 << 20, WarnFraction: 0.8}
		if err := q.Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("%s with no record cap: %v", c, err)
		}
		q.MaxRecordBytes = store.MinRecordBytes
		if err := q.Validate(); err != nil {
			t.Errorf("%s with cap MinRecordBytes: %v", c, err)
		}
		q.MaxRecordBytes = store.MinRecordBytes - 1
		if err := q.Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("%s with cap one byte under MinRecordBytes: %v", c, err)
		}
		q.MaxRecordBytes = q.Bytes + 1
		if err := q.Validate(); !c5vIs(err, store.CodeInvalid) {
			t.Errorf("%s with cap over its quota: %v", c, err)
		}
	}
	// The older classes that took no cap still take none.
	if err := (store.Quota{Class: store.ClassSyslogUnknown, Bytes: 8 << 20, WarnFraction: 0.8}).Validate(); err != nil {
		t.Errorf("syslog-unknown with no cap: %v", err)
	}
}

func c5v9Net(classes ...store.StreamClass) store.Database {
	d := store.Database{ID: "network", Writer: "node"}
	ids := map[store.StreamClass]store.StreamID{
		store.ClassNetworkObservation: c5v9Obs, store.ClassNetworkAlert: c5v9Alert,
		store.ClassAdapterEvidence: c5vEvid, store.ClassSyslogUnknown: c5vUnk,
		store.ClassPlatform: "platform/health", store.ClassSyslogDatagram: "syslog/udp",
	}
	for _, c := range classes {
		d.Streams = append(d.Streams, store.StreamSpec{ID: ids[c], Class: c})
		d.Classes = append(d.Classes, c)
		d.Quotas = append(d.Quotas, store.Quota{Class: c, Bytes: 8 << 20, WarnFraction: 0.8, MaxRecordBytes: 64 << 10})
	}
	return d
}

// A database holding a network class holds no class but the two network
// classes. The two may share one database, or each have one alone.
func TestC5v09LayoutKeepsNetworkApart(t *testing.T) {
	audit := c5vDB("audit", c5vAudit, store.ClassAudit, 8<<20, 0)
	for name, dbs := range map[string][]store.Database{
		"both together":     {audit, c5v9Net(store.ClassNetworkObservation, store.ClassNetworkAlert)},
		"observation alone": {audit, c5v9Net(store.ClassNetworkObservation)},
		"alert alone":       {audit, c5v9Net(store.ClassNetworkAlert)},
	} {
		if err := (store.Layout{Databases: dbs}).Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, other := range []store.StreamClass{store.ClassAdapterEvidence, store.ClassSyslogUnknown, store.ClassPlatform, store.ClassSyslogDatagram} {
		for _, net := range [][]store.StreamClass{
			{store.ClassNetworkObservation, other},
			{store.ClassNetworkAlert, other},
			{store.ClassNetworkObservation, store.ClassNetworkAlert, other},
		} {
			err := (store.Layout{Databases: []store.Database{audit, c5v9Net(net...)}}).Validate()
			if !c5vIs(err, store.CodeInvalid) {
				t.Errorf("%v in one database: %v", net, err)
			}
		}
	}
	// The older rules still hold beside the new one.
	err := (store.Layout{Databases: []store.Database{c5v9Net(store.ClassNetworkAlert), c5vDB("audit", c5vAudit, store.ClassAudit, 8<<20, 0)}}).Validate()
	if err != nil {
		t.Errorf("audit alone beside network: %v", err)
	}
}

// Every kind against every series, known and near-miss: exactly the twelve
// pairs pass, so neither checkpoint is evidence and the baseline is never
// working state.
func TestC5v09KindSeriesProduct(t *testing.T) {
	kinds := []string{"evidence", "working-state", "", "Evidence", "working_state"}
	series := []string{
		"config.snapshot", "config.difference", "baseline.event", "eventcheckpoint.learner", "eventcheckpoint.detector",
		"identity", "finding", "advisory.set", "identity.read",
		"baseline.network", "netcheckpoint.learner", "netcheckpoint.detector",
		"", "baseline.Network", "baseline.networks", "netcheckpoint", "netcheckpoint.", "netcheckpoint.learners",
		"netcheckpoint.Detector", "network.baseline", "netbaseline", "eventcheckpoint.network",
	}
	passed := 0
	for _, k := range kinds {
		for _, s := range series {
			err := store.DocumentInfo{Kind: store.DocumentKind(k), Series: s}.Validate()
			want := c5v9Pairs[[2]string{k, s}]
			if (err == nil) != want {
				t.Errorf("(%q, %q): %v, want pass %v", k, s, err, want)
			}
			if err == nil {
				passed++
			}
		}
	}
	if passed != len(c5v9Pairs) {
		t.Errorf("%d pairs pass, want %d", passed, len(c5v9Pairs))
	}
}

// RemovableSeries is exactly the six; both network checkpoints are
// removable and the network baseline never is.
func TestC5v09RemovableSeries(t *testing.T) {
	got := store.RemovableSeries()
	want := []string{"config.snapshot", "eventcheckpoint.learner", "eventcheckpoint.detector", "identity.read",
		"netcheckpoint.learner", "netcheckpoint.detector"}
	if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		t.Fatalf("RemovableSeries %v, want %v", got, want)
	}
	for _, s := range []string{"netcheckpoint.learner", "netcheckpoint.detector"} {
		if err := store.CheckRemoveConfig(c5v9Base, s, []store.Seq{1}); err != nil {
			t.Errorf("CheckRemoveConfig(%s): %v", s, err)
		}
	}
	for _, s := range []string{"baseline.network", "baseline.event", "netcheckpoint"} {
		if err := store.CheckRemoveConfig(c5v9Base, s, []store.Seq{1}); err == nil {
			t.Errorf("CheckRemoveConfig(%s) passed", s)
		}
	}
	if slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, "baseline.") }) {
		t.Errorf("a baseline series is removable: %v", got)
	}
}

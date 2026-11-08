package store

import (
	"slices"
	"testing"
)

// C5 0.9 (D4-68; docs/phase4/D5-c5-0.9.md sections 1, 6 and 8). Evidence
// class: desk.

func TestIdentifierV09(t *testing.T) {
	if Identifier != "otsec.store/0.9" {
		t.Errorf("identifier %q", Identifier)
	}
}

func TestNetworkClassesV09(t *testing.T) {
	if len(Classes) != 9 {
		t.Errorf("%d classes, want 9", len(Classes))
	}
	for c, name := range map[StreamClass]string{ClassNetworkObservation: "network-observation", ClassNetworkAlert: "network-alert"} {
		if string(c) != name {
			t.Errorf("class %q, want %q", c, name)
		}
		if !slices.Contains(Classes, c) {
			t.Errorf("%s not in Classes", c)
		}
		if a, err := ActionFor(c); err != nil || a != DropAndCount {
			t.Errorf("ActionFor(%s) = %s, %v", c, a, err)
		}
		if FullAlarm(c) != AlarmNetworkFull {
			t.Errorf("FullAlarm(%s) = %s", c, FullAlarm(c))
		}
	}
	if AlarmNetworkFull != "network-full" || AlarmNetworkFull.HealthType() != "store.network-full" {
		t.Errorf("alarm %q reported as %q", AlarmNetworkFull, AlarmNetworkFull.HealthType())
	}
}

// Both network classes need a record cap in [MinRecordBytes, Bytes].
func TestNetworkQuotaV09(t *testing.T) {
	for _, c := range []StreamClass{ClassNetworkObservation, ClassNetworkAlert} {
		q := Quota{Class: c, Bytes: 1 << 20, WarnFraction: 0.8}
		if err := q.Validate(); !isCode(err, CodeInvalid) {
			t.Errorf("%s with no cap: %v, want CodeInvalid", c, err)
		}
		for _, bad := range []int64{MinRecordBytes - 1, q.Bytes + 1} {
			q.MaxRecordBytes = bad
			if err := q.Validate(); !isCode(err, CodeInvalid) {
				t.Errorf("%s with cap %d: %v, want CodeInvalid", c, bad, err)
			}
		}
		for _, ok := range []int64{MinRecordBytes, q.Bytes} {
			q.MaxRecordBytes = ok
			if err := q.Validate(); err != nil {
				t.Errorf("%s with cap %d: %v", c, ok, err)
			}
		}
	}
}

// A database holding a network class holds only network classes; the two
// may share one.
func TestNetworkLayoutV09(t *testing.T) {
	q := func(c StreamClass) Quota {
		return Quota{Class: c, Bytes: 1 << 20, WarnFraction: 0.8, MaxRecordBytes: MinRecordBytes}
	}
	audit := Database{ID: "audit", Writer: "security", Streams: []StreamSpec{{"audit", ClassAudit}}, Classes: []StreamClass{ClassAudit}, Quotas: []Quota{q(ClassAudit)}}
	network := Database{ID: "network", Writer: "node",
		Streams: []StreamSpec{{"network-observation/s1", ClassNetworkObservation}, {"network-alert/s1", ClassNetworkAlert}},
		Classes: []StreamClass{ClassNetworkObservation, ClassNetworkAlert},
		Quotas:  []Quota{q(ClassNetworkObservation), q(ClassNetworkAlert)}}
	if err := (Layout{Databases: []Database{audit, network}}).Validate(); err != nil {
		t.Fatalf("both network classes in one database: %v", err)
	}
	for _, other := range []StreamClass{ClassAdapterEvidence, ClassSyslogStream, ClassSyslogDatagram, ClassPlatform, ClassSyslogUnknown} {
		for _, net := range []StreamClass{ClassNetworkObservation, ClassNetworkAlert} {
			d := Database{ID: "mixed", Writer: "node",
				Streams: []StreamSpec{{"n", net}, {"o", other}},
				Classes: []StreamClass{net, other},
				Quotas:  []Quota{q(net), q(other)}}
			if err := (Layout{Databases: []Database{audit, d}}).Validate(); !isCode(err, CodeInvalid) {
				t.Errorf("%s with %s: %v, want CodeInvalid", net, other, err)
			}
		}
	}
}

// Thirteen kind and series pairs pass; the four 0.9 series pair with their
// one kind only (netcheckpoint.intake from D4-72).
func TestSeriesV09(t *testing.T) {
	for got, want := range map[string]string{
		SeriesBaselineNetwork: "baseline.network", SeriesNetCheckpointLearner: "netcheckpoint.learner", SeriesNetCheckpointDetector: "netcheckpoint.detector",
		SeriesNetCheckpointIntake: "netcheckpoint.intake",
	} {
		if got != want {
			t.Errorf("series %q, want %q", got, want)
		}
	}
	series := []string{SeriesConfigSnapshot, SeriesConfigDifference, SeriesBaselineEvent, SeriesCheckpointLearner, SeriesCheckpointDetector,
		SeriesIdentity, SeriesFinding, SeriesAdvisorySet, SeriesIdentityRead,
		SeriesBaselineNetwork, SeriesNetCheckpointLearner, SeriesNetCheckpointDetector, SeriesNetCheckpointIntake}
	passed := 0
	for _, k := range []DocumentKind{DocumentEvidence, DocumentWorkingState} {
		for _, s := range series {
			if (DocumentInfo{Kind: k, Series: s}).Validate() == nil {
				passed++
			}
		}
	}
	if passed != 13 {
		t.Errorf("%d pairs pass, want 13", passed)
	}
	for _, bad := range []DocumentInfo{
		{DocumentWorkingState, SeriesBaselineNetwork},
		{DocumentEvidence, SeriesNetCheckpointLearner},
		{DocumentEvidence, SeriesNetCheckpointDetector},
		{DocumentEvidence, SeriesNetCheckpointIntake},
	} {
		if err := bad.Validate(); !isCode(err, CodeInvalid) {
			t.Errorf("%+v: %v, want CodeInvalid", bad, err)
		}
	}
}

// The network checkpoints and the intake hold are removable;
// baseline.network never is.
func TestCheckRemoveConfigV09(t *testing.T) {
	const s StreamID = "netbaseline/s1"
	for _, series := range []string{SeriesNetCheckpointLearner, SeriesNetCheckpointDetector, SeriesNetCheckpointIntake} {
		if err := CheckRemoveConfig(s, series, []Seq{3}); err != nil {
			t.Errorf("%s: %v", series, err)
		}
	}
	if err := CheckRemoveConfig(s, SeriesBaselineNetwork, []Seq{3}); !isCode(err, CodeInvalid) {
		t.Errorf("baseline.network: %v, want CodeInvalid", err)
	}
	if got := RemovableSeries(); len(got) != 7 {
		t.Errorf("RemovableSeries %v, want seven", got)
	}
}

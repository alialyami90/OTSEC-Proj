package node

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/version"
	"otsec.local/otsec/platform/sensorlink"
)

// C4 0.6 step 3 (brief P4-4-C4-06-S3; D1's plan on #780): the node's half
// of the later-minor refusals at judging, docs/phase4/D4-c4-0.6-proposal.md
// section 3.1 and rows E6-13 to E6-15 (D5's T1, the order of runSessionOf
// and the link leg). Later minors are computed from this build's own
// (self-check item 11). Desk only: every record is this build's own,
// stored by hand and its text then edited, as a build of another minor
// would have left it; no sensor wrote them and no device was contacted.

// laterID is id one minor above, and majorID one major and one minor
// above, each computed from the identifier this build reads.
func laterID(t *testing.T, id string) string {
	t.Helper()
	v, err := version.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	v.Minor++
	return v.String()
}

func majorID(t *testing.T, id string) string {
	t.Helper()
	v, err := version.Parse(id)
	if err != nil {
		t.Fatal(err)
	}
	v.Major, v.Minor = v.Major+1, v.Minor+1
	return v.String()
}

// stamp is the JSON member that carries id as a schema.
func stamp(id string) string { return `"schema":"` + id + `"` }

// sessionRefusedAlarms are the details of the network-session-refused
// alarms.
func sessionRefusedAlarms(st *Status) (out []string) {
	for _, a := range st.Snapshot("n").Alarms {
		if a.Code == AlarmSessionRefused {
			out = append(out, a.Detail)
		}
	}
	return out
}

// T1 and E6-13: a stored observation refused at judging, by its stamp.
// Legs 1 to 3 (T1): a body one C13 minor above this build's, an envelope
// one C4 minor above, and that envelope with an unknown binding.method,
// which Validate refuses inside event.Decode. Each is counted under
// later-minor, its alarm names the stamp by the Field of the error
// ErrLaterMinor matched, network-observation-refused is raised once, its
// counts event is written, and its count is exact after a clean restart.
// Legs 4 and 5 (E6-13): an envelope one major and one minor above, whose
// Validate error is returned, and a body one major and one minor above,
// whose CodeSchema refusal carries no ErrLaterMinor: each counted as
// malformed. Controls: the valid record stored beside each leg is judged
// and not counted; the third leg's edit at event.Identifier is malformed.
// Mutants: the alarm removed (legs 1 to 3); the later-minor branch
// removed, which counts legs 1 to 3 as malformed; observationOf's check
// on the Validate path removed, which counts leg 3 as malformed; the node
// classifying any CodeSchema as later-minor, killed by leg 5; and a
// CheckEventMinor that compares the minor only, killed by leg 4.
func TestObservationRefusedLaterMinor(t *testing.T) {
	// The body is stamped at the fixture's own C13 minor, read from the
	// base record; each later stamp is computed from this build's self.
	c4 := stamp(event.Identifier)
	const asC4, asC13 = "a C4 minor above this build's " + event.Identifier, "a C13 minor above this build's "
	for _, tc := range []struct {
		name    string
		edits   func(c13, method string) [][2]string
		reason  string
		named   string // the stamp the alarm names, for later-minor
		restart bool
	}{
		{"later C13", func(c13, _ string) [][2]string { return [][2]string{{c13, stamp(laterID(t, netobs.SelfIdentifier()))}} }, RefusedLaterMinor, asC13 + netobs.SelfIdentifier(), true},
		{"later C4", func(_, _ string) [][2]string { return [][2]string{{c4, stamp(laterID(t, event.Identifier))}} }, RefusedLaterMinor, asC4, true},
		{"later C4 with an unknown binding.method", func(_, m string) [][2]string {
			return [][2]string{{c4, stamp(laterID(t, event.Identifier))}, {`"method":"` + m + `"`, `"method":"added-later"`}}
		}, RefusedLaterMinor, asC4, true},
		{"control: an unknown binding.method at event.Identifier", func(_, m string) [][2]string {
			return [][2]string{{`"method":"` + m + `"`, `"method":"added-later"`}}
		}, RefusedMalformed, "", false},
		{"envelope a major above", func(_, _ string) [][2]string { return [][2]string{{c4, stamp(majorID(t, event.Identifier))}} }, RefusedMalformed, "", false},
		{"body a major above", func(c13, _ string) [][2]string { return [][2]string{{c13, stamp(majorID(t, netobs.SelfIdentifier()))}} }, RefusedMalformed, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var edits [][2]string
			r, st, _, c, dir := storeAfterCheckpoint(t, func(_ *Runtime, base []byte) [][]byte {
				var e event.Event
				var head struct{ Schema string }
				if json.Unmarshal(base, &e) != nil || e.Source.Asset == nil || json.Unmarshal(e.Netobs, &head) != nil || !strings.Contains(string(base), c4) {
					t.Fatalf("the base record: %s", base)
				}
				edits = tc.edits(stamp(head.Schema), string(e.Source.Asset.Binding.Method))
				return [][]byte{base, base}
			}, func(c *Config, seqs []c5.Seq) {
				for _, ed := range edits {
					corruptEvent(t, c, NetObservationStream(sensorID), seqs[0], ed[0], ed[1])
				}
			})
			defer func() { r.Close() }()
			rec := storedObservation(t, r, 2)
			for _, ed := range edits {
				if !strings.Contains(string(rec.Event), ed[1]) {
					t.Fatalf("positive control: the edit %q is not in the stored record", ed[1])
				}
			}
			_, oerr := observationOf(rec)
			if errors.Is(oerr, netobs.ErrLaterMinor) != (tc.reason == RefusedLaterMinor) || oerr == nil {
				t.Fatalf("observationOf: %v", oerr)
			}
			d := detectorStatus(t, st)
			got := refusedAlarms(st)
			if d.Through != 3 || d.Refused != 1 || d.RefusedBy[tc.reason] != 1 || len(got) != 1 || !strings.Contains(got[0], "First at seq 2.") {
				t.Fatalf("status %+v, alarms %q", d, got)
			}
			if tc.reason == RefusedMalformed {
				if !strings.Contains(got[0], "did not decode") {
					t.Fatalf("alarm %q", got[0])
				}
				return
			}
			if !strings.Contains(got[0], "("+tc.named+")") || !strings.Contains(got[0], "Remedy: move this node forward") {
				t.Fatalf("alarm %q does not name %q", got[0], tc.named)
			}
			if ev := newest(t, r); ev["reason."+RefusedLaterMinor] != "1" || ev["first_seq."+RefusedLaterMinor] != "2" || ev["count"] != "1" {
				t.Fatalf("counts event %v", ev)
			}
			r.Close()
			r, st, _ = start(t, c, dir)
			tick(t, r)
			if d := detectorStatus(t, st); d.Refused != 1 || d.RefusedBy[RefusedLaterMinor] != 1 || !d.RefusedExact || len(refusedAlarms(st)) != 0 {
				t.Fatalf("after a clean restart: %+v", d)
			}
		})
	}
}

// storeRuns runs the node once, builds a collection.run for each entry of
// edits, of the relay's schedule and connected with after_seq 0, stops the
// node and stores them on the health stream past this build's checks,
// replaces each entry's old texts by the new ones in its stored record,
// then starts the node again and ticks once. It returns the runs' seqs.
// The caller closes the node.
func storeRuns(t *testing.T, edits [][][2]string) (*Runtime, *Status, []c5.Seq) {
	t.Helper()
	c, dir := holdConfig(t)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, &fakeCollector{})
	var recs []c5.Record
	for i := range edits {
		inv := testInvocation(i + 1)
		d := map[string]string{"endpoint": "127.0.0.1:2323", "l4": "tcp", "started_at": "2026-10-24T09:15:00Z", "ended_at": "2026-10-24T09:15:01Z",
			"connected": "true", "open_flow": "false", "after_seq": "0"}
		rec, err := s.runRecord(HealthStream, HealthCollectionRun, c.Schedule[0], "r-"+inv, inv, d)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec)
	}
	r.Close()
	seqs := appendStoredAll(t, c, recs, c5.DocumentInfo{}, nil)
	for i, eds := range edits {
		for _, ed := range eds {
			corruptEvent(t, c, HealthStream, seqs[i], ed[0], ed[1])
		}
	}
	r, st, _ := start(t, c, dir)
	hs, err := r.Store(HealthStream).Read(bg, HealthStream, seqs[0]-1, len(seqs))
	if err != nil || len(hs) != len(seqs) {
		t.Fatalf("%d runs: %v", len(hs), err)
	}
	for i, eds := range edits {
		for _, ed := range eds {
			if !strings.Contains(string(hs[i].Event), ed[1]) {
				t.Fatalf("positive control: the edit %q is not in run %d", ed[1], seqs[i])
			}
		}
	}
	tick(t, r)
	return r, st, seqs
}

// E6-14 (1): a later-C4 sensor.counters that decodes and carries the bytes
// "collection.run" as an unknown detail's value, which a later minor
// accepts, so newSessions passes it to runSessionOf: no session, and not
// bad. Positive control, first: it decodes with no error. Mutant: the
// stamp check before the type check on the no-error path, which refuses
// it.
func TestRunSessionOfLaterOtherType(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(readFile(t, "../../contracts/event/testdata/valid/health-sensor-counters.json"), &m); err != nil {
		t.Fatal(err)
	}
	m["schema"] = laterID(t, event.Identifier)
	m["health"].(map[string]any)["details"].(map[string]any)["added_later"] = HealthCollectionRun
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := event.Decode(b); err != nil || !strings.Contains(string(b), `"`+HealthCollectionRun+`"`) {
		t.Fatalf("positive control: %v", err)
	}
	if s, ok, err := runSessionOf(c5.Stored{Key: c5.Key{Seq: 7}, Event: b}); ok || err != nil {
		t.Fatalf("runSessionOf: %+v, %v, %v; want no session and no error", s, ok, err)
	}
}

// E6-14 (2) to (5) and its control: runSessionOf's order (C4 0.6 section
// 3.1; D1's 7053867485 ruling 2), each run on its own fresh runtime, so
// (5)'s alarm is not one an earlier leg raised (D6's N19). (2) Two
// later-C4 collection.run with no after_seq: each bad and counted in
// runs_session_missing, network-session-refused raised once, naming the
// first's health-stream seq, and no own-session-unseen. (3) A later-C4
// collection.run whose health is renamed, which fails Validate and still
// holds "collection.run": bad, with no alarm. (4) A collection.run at
// event.Identifier with an unknown binding.method: bad, with no alarm. (5)
// A later-C4 collection.run with an unknown binding.method: bad, and
// network-session-refused raised. Control: the run of (2) at
// event.Identifier with after_seq is handed over. Mutants: after_seq
// before the stamp check, which makes (2) no session (not bad); the alarm
// raised per entry, which raises two in (2); a "type first" short cut on
// the error path, which makes (3) no session; the Validate error dropped
// after the stamp check, which makes (4) a session; the stamp check on the
// no-error path only, which leaves (5) bad with no alarm.
func TestRunSessionOfOrder(t *testing.T) {
	c4, later := stamp(event.Identifier), stamp(laterID(t, event.Identifier))
	noAfter := [2]string{`"after_seq":"0",`, ""}
	binding := [2]string{`"source":{"origin_auth":"platform"}`,
		`"source":{"asset":{"id":"` + relayID + `","binding":{"method":"added-later","confidence":"configured"}},"origin_auth":"platform"}`}
	for _, tc := range []struct {
		name    string
		edits   [][][2]string
		missing int64
		alarm   bool
	}{
		{"control: at event.Identifier with after_seq", [][][2]string{{}}, 0, false},
		{"(2) later C4, no after_seq, twice", [][][2]string{{{c4, later}, noAfter}, {{c4, later}, noAfter}}, 2, true},
		{"(3) later C4, health renamed", [][][2]string{{{c4, later}, {`"health":{`, `"health_later":{`}}}, 1, false},
		{"(4) event.Identifier, unknown binding.method", [][][2]string{{binding}}, 1, false},
		{"(5) later C4, unknown binding.method", [][][2]string{{{c4, later}, binding}}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, st, seqs := storeRuns(t, tc.edits)
			defer r.Close()
			d := detectorStatus(t, st)
			got := sessionRefusedAlarms(st)
			if d.NotJudged["session-missing"] != tc.missing || len(got) != map[bool]int{true: 1}[tc.alarm] || unseenAlerts(t, r) != 0 {
				t.Fatalf("status %+v, alarms %q", d, got)
			}
			if tc.alarm && !strings.Contains(got[0], "First at health-stream seq "+strconv.FormatUint(uint64(seqs[0]), 10)+".") {
				t.Fatalf("alarm %q", got[0])
			}
			if tc.missing == 0 && r.detector.d.SessionThrough() != uint64(seqs[0]) {
				t.Fatalf("control: session through %d, run at %d", r.detector.d.SessionThrough(), seqs[0])
			}
		})
	}
}

// E6-14, the alarm once per process run across drives (D6's N1 on #780): a
// later-C4 collection.run refused in a first drive raises
// network-session-refused; the detector's health position is then moved
// back, so a second drive of the same process reads the refused run again.
// Positive control: the second drive read it, counted again in
// runs_session_missing. Then still one alarm. Mutant: nd.sessionRefused
// reset at the start of each drive, which raises a second alarm.
func TestRunSessionRefusedSecondDrive(t *testing.T) {
	c4, later := stamp(event.Identifier), stamp(laterID(t, event.Identifier))
	r, st, _ := storeRuns(t, [][][2]string{{{c4, later}}})
	defer r.Close()
	if d, got := detectorStatus(t, st), sessionRefusedAlarms(st); d.NotJudged["session-missing"] != 1 || len(got) != 1 {
		t.Fatalf("first drive: status %+v, alarms %q", d, got)
	}
	r.detector.health = 0
	tick(t, r)
	d, got := detectorStatus(t, st), sessionRefusedAlarms(st)
	if d.NotJudged["session-missing"] != 2 {
		t.Fatalf("positive control: the second drive did not read the run again: status %+v", d)
	}
	if len(got) != 1 {
		t.Fatalf("second drive: %d network-session-refused alarms, want 1: %q", len(got), got)
	}
}

// E6-15, the link leg: a held record of a later C13 minor, left in the
// hold's releasing record by a build of that minor, is committed by this
// build's RecoverHold as held, stamped event.Identifier, and refused at
// judging under later-minor, naming the C13 stamp. Control: the same held
// record at the fixture's own C13 minor is committed, stamped
// event.Identifier, and judged. Mutant: the link's commit refusing the
// later body, which commits nothing.
func TestHeldRecordLaterMinor(t *testing.T) {
	for _, later := range []bool{false, true} {
		t.Run(map[bool]string{false: "control: at self", true: "later C13"}[later], func(t *testing.T) {
			c, dir := holdConfig(t)
			r, _, _ := start(t, c, dir)
			s := newScheduler(t, r, &fakeCollector{})
			if s.dispatchHold(bg, c.Schedule[0], s.newID()) == nil {
				t.Fatal("the hold doesn't watch the run")
			}
			if err := r.ServeSensor(bg, sensorChannel(t, ownFlow(1))); err != nil {
				t.Fatal(err)
			}
			_, docs := intakeDocs(t, r)
			held := docs[len(docs)-1]
			if held.State != sensorlink.HoldHolding || len(held.Flows) != 1 || len(held.Flows[0].Records) != 1 {
				t.Fatalf("holding record: %+v", held)
			}
			hr := held.Flows[0].Records[0]
			var head struct{ Schema string }
			if err := json.Unmarshal(hr.Observation, &head); err != nil {
				t.Fatal(err)
			}
			want := head.Schema // the fixture's own C13 minor
			if later {
				want = laterID(t, netobs.SelfIdentifier())
				hr.Observation = laterMinor(t, hr.Observation, want, nil)
			}
			held.State, held.Releasing, held.Head = sensorlink.HoldReleasing, []sensorlink.Release{{Record: hr}}, 0
			held.Flows = []sensorlink.HeldFlow{}
			b, err := json.Marshal(held)
			if err != nil {
				t.Fatal(err)
			}
			stream := r.intakeStream()
			if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassConfiguration, Event: b}); err != nil {
				t.Fatal(err)
			}
			r.Close()

			r, st, _ := start(t, c, dir)
			defer r.Close()
			tick(t, r)
			obs := NetObservationStream(sensorID)
			got, err := r.Store(obs).Read(bg, obs, 0, 10)
			if err != nil || len(got) != 1 || !strings.HasPrefix(string(got[0].Event), "{"+stamp(event.Identifier)) {
				t.Fatalf("%d observations committed: %v", len(got), err)
			}
			if !strings.Contains(string(got[0].Event), stamp(want)) {
				t.Fatalf("the committed body is not at %s: %s", want, got[0].Event)
			}
			d := detectorStatus(t, st)
			alarms := refusedAlarms(st)
			if !later {
				if d.Through != 1 || d.Refused != 0 || len(alarms) != 0 {
					t.Fatalf("control: status %+v, alarms %q", d, alarms)
				}
				return
			}
			if d.Through != 1 || d.Refused != 1 || d.RefusedBy[RefusedLaterMinor] != 1 || len(alarms) != 1 ||
				!strings.Contains(alarms[0], "(a C13 minor above this build's "+netobs.SelfIdentifier()+")") {
				t.Fatalf("status %+v, alarms %q", d, alarms)
			}
		})
	}
}

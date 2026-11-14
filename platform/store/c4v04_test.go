package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
)

// E4-7's store leg (C4 0.4 section 3 and section 5; P4-4-CC deliverable 2).
// The events are D6's #683 fixtures, written from C4 0.4's text, in
// tests/contract/testdata/cc-d0, with their id made pending for this
// store's node. Desk only: no device or sensor wrote them.
var e47Fixtures = []struct {
	file  string
	class c5.StreamClass
}{
	{"event-0.4-ser.json", c5.ClassAdapterEvidence},
	{"event-0.4-syslog.json", c5.ClassSyslogStream},
	{"event-0.4-health-node.json", c5.ClassPlatform},
	{"event-0.4-sensor-counters.json", c5.ClassPlatform},
	{"event-0.4-network-observation.json", c5.ClassNetworkObservation},
	{"event-0.4-network-observation-skewed.json", c5.ClassNetworkObservation},
	{"event-0.4-netobs-alert.json", c5.ClassNetworkAlert},
}

// e47Pending reads a fixture and makes it a pending event of this store's
// node on its own stream, every other member as the fixture has it.
func e47Pending(t *testing.T, file string) (c5.StreamID, []byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "contract", "testdata", "cc-d0", file))
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	var id event.EventID
	if err := json.Unmarshal(top["id"], &id); err != nil {
		t.Fatal(err)
	}
	id.NodeID, id.Seq = event.NodeID(testNode), 0
	if top["id"], err = json.Marshal(id); err != nil {
		t.Fatal(err)
	}
	if b, err = json.Marshal(top); err != nil {
		t.Fatal(err)
	}
	return c5.StreamID(id.Stream), b
}

// TestEvent04Commits: with this code, whose event.Identifier is
// otsec.event/0.4, a pending event of each type stamped 0.4 commits and
// is stored at 0.4, and a pending event stamped otsec.event/0.5 is refused
// as invalid, with nothing written. The controls: a store whose
// eventVersion stays at 0.3 refuses every 0.4 event; a store that accepts
// any minor commits the 0.5 event.
func TestEvent04Commits(t *testing.T) {
	if event.Identifier != "otsec.event/0.4" {
		t.Fatalf("event.Identifier is %s", event.Identifier)
	}
	// The network classes have a database of their own (C5 0.9).
	network := []c5.StreamClass{c5.ClassNetworkObservation, c5.ClassNetworkAlert}
	n := 0
	var (
		health    *DB
		healthLog *c5.Log
		pending04 []byte
	)
	for _, net := range []bool{false, true} {
		d := c5.Database{ID: "e47", Writer: "node"}
		var recs []c5.Record
		for _, f := range e47Fixtures {
			if slices.Contains(network, f.class) != net {
				continue
			}
			s, b := e47Pending(t, f.file)
			if !slices.ContainsFunc(d.Streams, func(x c5.StreamSpec) bool { return x.ID == s }) {
				d.Streams = append(d.Streams, c5.StreamSpec{ID: s, Class: f.class})
			}
			if !slices.Contains(d.Classes, f.class) {
				d.Classes = append(d.Classes, f.class)
				d.Quotas = append(d.Quotas, c5.Quota{Class: f.class, Bytes: 8 << 20, WarnFraction: 0.8, MaxRecordBytes: c5.MinRecordBytes})
			}
			recs = append(recs, c5.Record{Stream: s, Class: f.class, Event: b})
		}
		db := open1(t, storeDir(t), d, nil)
		l := testLog(t, db)
		for _, rec := range recs {
			r, err := l.Append(bg, rec)
			if err != nil {
				t.Fatalf("%s: %v", rec.Stream, err)
			}
			got, err := db.Read(bg, rec.Stream, r.Key().Seq-1, 1)
			if err != nil || len(got) != 1 {
				t.Fatalf("%s stored: %d, %v", rec.Stream, len(got), err)
			}
			if e, err := event.Decode(got[0].Event); err != nil || e.Schema != "otsec.event/0.4" {
				t.Fatalf("%s read back: %v", rec.Stream, err)
			}
			n++
			if rec.Stream == "platform/health" && pending04 == nil {
				health, healthLog, pending04 = db, l, rec.Event
			}
		}
	}
	if n != len(e47Fixtures) {
		t.Fatalf("%d committed, want %d", n, len(e47Fixtures))
	}

	s := c5.StreamID("platform/health")
	before, err := health.LastCommitted(bg, s)
	if err != nil {
		t.Fatal(err)
	}
	later := bytes.Replace(pending04, []byte(`"otsec.event/0.4"`), []byte(`"otsec.event/0.5"`), 1)
	if bytes.Equal(later, pending04) {
		t.Fatal("no schema to restamp")
	}
	if _, err := healthLog.Append(bg, c5.Record{Stream: s, Class: c5.ClassPlatform, Event: later}); !isCode(err, c5.CodeInvalid) {
		t.Fatalf("a pending 0.5 event: %v, want %s", err, c5.CodeInvalid)
	}
	if after, err := health.LastCommitted(bg, s); err != nil || after != before {
		t.Fatalf("after the refusal: last %d, was %d: %v", after, before, err)
	}
}

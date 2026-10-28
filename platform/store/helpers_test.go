package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	c5 "otsec.local/otsec/contracts/store"
)

const testNode c5.NodeID = "site-a-node1"

var (
	evidenceDB = c5.Database{
		ID:     "evidence",
		Writer: "ied",
		Streams: []c5.StreamSpec{
			{ID: "relay1/ser", Class: c5.ClassAdapterEvidence},
			{ID: "syslog/relay1", Class: c5.ClassSyslogStream},
			{ID: "platform/health", Class: c5.ClassPlatform},
		},
		Classes: []c5.StreamClass{c5.ClassAdapterEvidence, c5.ClassSyslogStream, c5.ClassPlatform},
		Quotas: []c5.Quota{
			{Class: c5.ClassAdapterEvidence, Bytes: 8 << 20, WarnFraction: 0.8},
			{Class: c5.ClassSyslogStream, Bytes: 8 << 20, WarnFraction: 0.8},
			{Class: c5.ClassPlatform, Bytes: 8 << 20, WarnFraction: 0.8},
		},
	}
	auditDB = c5.Database{
		ID:      "audit",
		Writer:  "security",
		Streams: []c5.StreamSpec{{ID: "audit", Class: c5.ClassAudit}},
		Classes: []c5.StreamClass{c5.ClassAudit},
		Quotas:  []c5.Quota{{Class: c5.ClassAudit, Bytes: 8 << 20, WarnFraction: 0.8}},
	}
)

func withQuota(d c5.Database, class c5.StreamClass, bytes int64) c5.Database {
	d.Quotas = append([]c5.Quota{}, d.Quotas...)
	for i := range d.Quotas {
		if d.Quotas[i].Class == class {
			d.Quotas[i].Bytes = bytes
		}
	}
	return d
}

func policy(d c5.Database, consumers ...c5.Consumer) c5.StartupPolicy {
	return c5.StartupPolicy{
		Streams:                d.Streams,
		Consumers:              consumers,
		RecoveryReserveBytes:   2 * WALBoundBytes,
		LastResortReserveBytes: WALBoundBytes + c5.MinOpenHeadroom,
		OpenHeadroomBytes:      WALBoundBytes + c5.MinOpenHeadroom,
		PruneStepEvents:        50,
		CompactStepPages:       32,
		PruneTarget:            0.8,
	}
}

type alarms struct{ got []c5.Alarm }

func (a *alarms) sink(x c5.Alarm) { a.got = append(a.got, x) }

func (a *alarms) has(code c5.AlarmCode) bool {
	for _, x := range a.got {
		if x.Code == code {
			return true
		}
	}
	return false
}

// testStore runs C5 startup on dir and returns the open database and its
// report. It fails the test unless the mode is want.
func testStore(t *testing.T, opt Options, p c5.StartupPolicy, want c5.Mode) (*DB, c5.Report) {
	t.Helper()
	env, err := NewEnv(opt)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	r := c5.RunStartup(ctx, env, p)
	if r.Mode != want {
		t.Fatalf("startup mode %s, want %s: %v %v", r.Mode, want, r.Err, r.Steps)
	}
	if r.Unlock != nil {
		t.Cleanup(r.Unlock)
	}
	if r.Store == nil {
		return nil, r
	}
	db, ok := AsDB(r.Store)
	if !ok {
		t.Fatalf("store is %T", r.Store)
	}
	t.Cleanup(func() { db.Close() })
	return db, r
}

func open1(t *testing.T, dir string, d c5.Database, a *alarms) *DB {
	t.Helper()
	opt := Options{Dir: dir, Node: testNode, Database: d}
	if a != nil {
		opt.Alarms = a.sink
	}
	db, _ := testStore(t, opt, policy(d), c5.ModeCollecting)
	return db
}

// testLog is a Log over db with the start positions read from it.
func testLog(t *testing.T, db *DB) *c5.Log {
	t.Helper()
	last := map[c5.StreamID]c5.Seq{}
	for s := range db.Streams() {
		n, err := db.LastCommitted(context.Background(), s)
		if err != nil {
			t.Fatal(err)
		}
		last[s] = n
	}
	l, err := c5.NewLog(db, testNode, db.Streams(), c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond, MaxCommitRecords: 1000}, last)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// pending is a pending C4 platform health event for stream, seq 0.
func pending(stream c5.StreamID, n int) []byte {
	return fmt.Appendf(nil, `{"schema":"otsec.event/0.1","id":{"node_id":"site-a-node1","stream":%q,"seq":0},`+
		`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},`+
		`"received":{"utc":"2026-10-24T12:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
		`"health":{"type":"store.test","details":{"n":"%d"}}}`, stream, n)
}

func rec(stream c5.StreamID, class c5.StreamClass, n int) c5.Record {
	return c5.Record{Stream: stream, Class: class, Event: pending(stream, n)}
}

func recs(stream c5.StreamID, class c5.StreamClass, from, n int) []c5.Record {
	out := make([]c5.Record, n)
	for i := range out {
		out[i] = rec(stream, class, from+i)
	}
	return out
}

// pendingAudit is a pending C8 record for the test node.
func pendingAudit(action, extra string) []byte {
	return fmt.Appendf(nil, `{"contract":"otsec.audit/0.1","node_id":"site-a-node1",`+
		`"time":{"utc":"2026-10-24T12:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
		`"actor":{"type":"system","id":"node"},"action":%q,"outcome":"info"%s}`, action, extra)
}

func auditRec(action, extra string) c5.Record {
	return c5.Record{Stream: "audit", Class: c5.ClassAudit, Event: pendingAudit(action, extra)}
}

func modeChange(i int) c5.Record {
	return auditRec("store.mode_change", fmt.Sprintf(`,"reason_code":"collecting","detail":"op-%d"`, i))
}

func isCode(err error, code c5.Code) bool { return errors.Is(err, &c5.Error{Code: code}) }

// storeDir is a new store directory as CreateDir makes it: mode 0700 on
// Linux, a protected DACL for this account, SYSTEM and Administrators on
// Windows.
func storeDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	if err := CreateDir(dir, ""); err != nil {
		t.Fatal(err)
	}
	return dir
}

func unlock(r c5.Report) {
	if r.Unlock != nil {
		r.Unlock()
	}
}

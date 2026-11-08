package node

import (
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// The retention consumer in the runtime, on the test's wall and monotonic
// clocks: Start creates it and records created; a Tick past the retention
// moves it, the move's record stamped 0.12 in a chain that otherwise holds
// 0.11 records, and the passed alerts become prunable; a
// restart resumes from the record; status shows both cutoffs. Desk only.
func TestNetRetentionRuntime(t *testing.T) {
	c, _ := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection() // 30 days, no target
	})
	var mu sync.Mutex
	wall, mono := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Minute
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return wall }
	monoNow := func() time.Duration { mu.Lock(); defer mu.Unlock(); return mono }
	advance := func(d time.Duration) { mu.Lock(); wall, mono = wall.Add(d), mono+d; mu.Unlock() }
	start := func() (*Runtime, *Status) {
		st := NewStatus("", nil, now)
		r, err := Start(bg, c, RuntimeOptions{Status: st, Now: now, Mono: monoNow, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
		if err != nil {
			t.Fatal(err)
		}
		return r, st
	}
	moves := func(r *Runtime) (out []*audit.Record) {
		for _, rec := range auditRecords(t, r) { // verifies the chain
			if rec.Action == audit.ActionStoreRetentionMoved {
				out = append(out, rec)
			}
		}
		return out
	}

	r, st := start()
	stream := NetAlertStream(sensorID)
	alert := func() {
		t.Helper()
		ev := []byte(`{"schema":"otsec.event/0.1","id":{"node_id":"site-a-node1","stream":"` + string(stream) + `","seq":0},` +
			`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},` +
			`"received":{"utc":"2026-11-01T00:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},` +
			`"health":{"type":"store.test","details":{}}}`)
		if _, err := r.Log(stream).Append(bg, c5.Record{Stream: stream, Class: c5.ClassNetworkAlert, Event: ev}); err != nil {
			t.Fatal(err)
		}
	}
	m := moves(r)
	if len(m) != 1 || m[0].Retention.Bound != audit.BoundCreated || m[0].Contract != RetentionContract ||
		m[0].Actor.ID != "site-a-node1" || m[0].Target.SensorID != sensorID {
		t.Fatalf("at start: %+v", m)
	}
	if s := st.Snapshot("x").NetRetention; s == nil || !s.Running || s.Stream != string(stream) {
		t.Fatalf("status %+v", s)
	}

	alert()
	alert()
	advance(time.Hour)
	alert()
	advance(30*24*time.Hour - time.Hour + time.Minute) // the first two are past the retention
	r.Tick(bg)
	m = moves(r)
	if len(m) != 2 || m[1].Retention.Bound != audit.BoundWall || m[1].Retention.FromSeq != 0 || m[1].Retention.ToSeq != 2 {
		t.Fatalf("after the retention: %+v", m[len(m)-1].Retention)
	}
	// The passed alerts are prunable: the boundary over the node's
	// consumers is the move's to_seq. (Prune removes them once the class
	// is over its target, as for every class.)
	consumers, err := c.Consumers()
	if err != nil {
		t.Fatal(err)
	}
	db := r.Store(stream)
	if b, err := c5.ComputeBoundary(bg, db, db, consumers, stream, c5.ClassNetworkAlert, now()); err != nil || b.Through() != 2 {
		t.Fatalf("boundary %v, %v; want through 2", b, err)
	}
	// The chain mixes minors: every other node record keeps the 0.11
	// stamp, and the chain verifies (auditRecords runs VerifyChain).
	all := auditRecords(t, r)
	var older int
	for _, rec := range all {
		if rec.Contract == audit.ContractID {
			older++
		}
	}
	if older == 0 || audit.ContractID == RetentionContract {
		t.Fatalf("no %s record beside the %s ones", audit.ContractID, RetentionContract)
	}
	if err := audit.VerifyConfigFrom(all, 1); err != nil {
		t.Fatal(err)
	}
	// The same move stamped with the node's other minor is refused (D1 in
	// D4-70).
	old := *m[1]
	old.Contract = audit.ContractID
	if err := old.Validate(); err == nil {
		t.Fatalf("store.retention_moved stamped %s accepted", audit.ContractID)
	}
	s := st.Snapshot("x").NetRetention
	if s.Cursor != 2 || !s.CursorSaved || s.Cutoff.IsZero() || !s.WallCutoff.Equal(now().Add(-30*24*time.Hour)) {
		t.Fatalf("status %+v", s)
	}
	r.Close()

	// A restart resumes from the record: no new created record, and the
	// first move after it is bounded by the start allowance.
	mu.Lock()
	mono = time.Minute
	mu.Unlock()
	r, _ = start()
	defer r.Close()
	advance(2 * time.Hour)
	r.Tick(bg)
	m = moves(r)
	if len(m) != 3 || m[2].Retention.Bound != audit.BoundWall || m[2].Retention.FromSeq != 2 || m[2].Retention.ToSeq != 3 {
		t.Fatalf("after a restart: %+v", m[len(m)-1].Retention)
	}
}

// With a forwarding target there is no retention consumer: nothing is
// recorded and status has no section.
func TestNetRetentionOffWithTarget(t *testing.T) {
	c, _ := schedConfig(t, func(nc *nodeconfigtest.Config) {
		sensorQuotas(nc)
		nc.NetworkSensor = sensorSection()
		delete(nc.NetworkSensor, "alert_retention_days")
		nc.AddRELPTarget("central", "127.0.0.1", 6514, "test-ca", "test-client", "test/durable-ack", true)
	})
	st := NewStatus("", nil, nil)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.Tick(bg)
	for _, rec := range auditRecords(t, r) {
		if rec.Action == audit.ActionStoreRetentionMoved {
			t.Fatalf("a retention record with a target: %+v", rec)
		}
	}
	if st.Snapshot("x").NetRetention != nil {
		t.Fatal("a retention status with a target")
	}
}

// Package sensortest holds the in-process tests of the sensor store set
// and its manager (docs/phase4/D5-sensor-node.md section 1.9 item 8; brief
// P4-4-F27). It holds _test.go files only. It reaches the manager through
// node.RuntimeOptions.SensorSeams, exported test hooks that no product code
// sets (TestSensorSeamsUnsetInProduct). Every test is desk only: no sensor
// and no device; the stores are on the local disk.
package sensortest

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

var bg = context.Background()

// The rig's IDs: a relay with a scheduled SER read, a UDP listener, and a
// sensor. None names a real device.
const (
	relayID  = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	sensorID = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"
	listener = "lab-udp"
)

// rig is a node with a network_sensor section, on clocks the test moves.
type rig struct {
	t   *testing.T
	c   *node.Config
	dir string

	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300).AddListener(listener, "syslog-udp", "127.0.0.1:0")
	nc.Store.Quotas["configuration"] = 16 << 20
	nc.Store.Quotas["network-observation"] = 64 << 20
	nc.Store.Quotas["network-alert"] = 16 << 20
	nc.NetworkSensor = map[string]any{"sensor_id": sensorID, "evidence_class": "simulated", "outage_hours": 72, "alert_retention_days": 30,
		"node_addresses": []any{"192.0.2.10"}, "node_macs": []any{"02:00:5e:00:00:0a"}, "node_vlans": []any{10, "untagged"}}
	if err := nc.WriteInstallKey("ik_sensortest"); err != nil {
		t.Fatal(err)
	}
	c, err := node.ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, c: c, dir: dir, wall: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC), mono: time.Minute}
}

func (g *rig) now() time.Time         { g.mu.Lock(); defer g.mu.Unlock(); return g.wall }
func (g *rig) monoNow() time.Duration { g.mu.Lock(); defer g.mu.Unlock(); return g.mono }
func (g *rig) advance(d time.Duration) {
	g.mu.Lock()
	g.wall, g.mono = g.wall.Add(d), g.mono+d
	g.mu.Unlock()
}

// advanceWall and advanceMono move one clock only.
func (g *rig) advanceWall(d time.Duration) { g.mu.Lock(); g.wall = g.wall.Add(d); g.mu.Unlock() }
func (g *rig) advanceMono(d time.Duration) { g.mu.Lock(); g.mono += d; g.mu.Unlock() }

func (g *rig) options(s node.SensorSeams) node.RuntimeOptions {
	return node.RuntimeOptions{Status: node.NewStatus("", nil, g.now), Now: g.now, Mono: g.monoNow, SensorSeams: s,
		Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}}
}

// start starts the node with seams s and waits for the sensor manager's
// first step, which runs after Start returns.
func (g *rig) start(s node.SensorSeams) (*node.Runtime, *node.Status) {
	g.t.Helper()
	r, st := g.startNoWait(s)
	select {
	case <-r.SensorFirstStep():
	case <-time.After(30 * time.Second):
		g.t.Fatal("the sensor manager's first step did not end within 30 s")
	}
	return r, st
}

// startNoWait starts the node with seams s and returns when Start does.
func (g *rig) startNoWait(s node.SensorSeams) (*node.Runtime, *node.Status) {
	g.t.Helper()
	opt := g.options(s)
	r, err := node.Start(bg, g.c, opt)
	if err != nil {
		g.t.Fatal(err)
	}
	return r, opt.Status
}

// record is a minimal C4 event for stream, as the platform and the Syslog
// intake append them.
func record(stream c5.StreamID, class c5.StreamClass, n int) c5.Record {
	ev := fmt.Sprintf(`{"schema":"otsec.event/0.1","id":{"node_id":"site-a-node1","stream":%q,"seq":0},`+
		`"origin":"platform","kind":"telemetry-health","source":{"origin_auth":"platform"},`+
		`"received":{"utc":"2026-11-13T10:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
		`"health":{"type":"sensortest.append","details":{"n":"%d"}}}`, string(stream), n)
	return c5.Record{Stream: stream, Class: class, Event: []byte(ev)}
}

// within runs f and fails the test if it has not returned after d. It
// returns at once on a failure, leaving f to finish on its own.
func within(t *testing.T, d time.Duration, what string, f func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}

// eventually waits up to 10 s for cond, which the manager's goroutine
// makes true; it never waits a fixed time.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within 10 s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// alarms counts status's alarms of code.
func alarms(st *node.Status, code string) (n int) {
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == code {
			n++
		}
	}
	return n
}

// collecting appends one record to each of the streams the scheduler's
// run path and the Syslog intake append to: the health stream, the audit
// stream and the listener's stream. Each must commit within 2 s.
func collecting(t *testing.T, r *node.Runtime, n int) {
	t.Helper()
	within(t, 2*time.Second, "an append to platform/health", func() error {
		_, err := r.Log(node.HealthStream).Append(bg, record(node.HealthStream, c5.ClassPlatform, n))
		return err
	})
	within(t, 2*time.Second, "an append to the listener's stream", func() error {
		_, err := r.Log(node.ListenerStream(listener)).Append(bg, record(node.ListenerStream(listener), c5.ClassSyslogDatagram, n))
		return err
	})
	within(t, 2*time.Second, "an audit append", func() error {
		rec, err := r.AuditRecord(audit.ActionServiceStart, audit.OutcomeInfo, "", "sensortest")
		if err == nil {
			_, err = r.Log(node.AuditStream).Append(bg, rec)
		}
		return err
	})
	within(t, 2*time.Second, "the evidence database's mode", func() error {
		if m := r.Mode(node.EvidenceDB); m != c5.ModeCollecting {
			return fmt.Errorf("mode %s", m)
		}
		return nil
	})
}

// drainOnly is a Startup seam: C5 startup, with the report taken as
// drain-only, as a volume short of headroom leaves it.
func drainOnly(ctx context.Context, env c5.StartupEnv, p c5.StartupPolicy) c5.Report {
	rep := c5.RunStartup(ctx, env, p)
	if rep.Mode == c5.ModeCollecting {
		rep.Mode = c5.ModeDrainOnly
	}
	return rep
}

// modeChanges are the store.mode_change audit records and mode_changed
// health events of database db.
func modeChanges(t *testing.T, r *node.Runtime, db c5.DatabaseID) (records []*audit.Record, events []map[string]string) {
	t.Helper()
	got, err := r.Store(node.AuditStream).Read(bg, node.AuditStream, 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		rec, err := audit.ParseRecord(s.Event)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Action == audit.ActionStoreModeChange && len(rec.Detail) > len("database "+string(db)+":") && rec.Detail[:len("database "+string(db)+":")] == "database "+string(db)+":" {
			records = append(records, rec)
		}
	}
	hs, err := r.Store(node.HealthStream).Read(bg, node.HealthStream, 0, 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range hs {
		var e struct {
			Health *struct {
				Type    string            `json:"type"`
				Details map[string]string `json:"details"`
			} `json:"health"`
		}
		if json.Unmarshal(s.Event, &e) == nil && e.Health != nil && e.Health.Type == c5.HealthModeChanged && e.Health.Details["database"] == string(db) {
			events = append(events, e.Health.Details)
		}
	}
	return records, events
}

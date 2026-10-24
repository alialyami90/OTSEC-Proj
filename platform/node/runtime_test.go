package node

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

var bg = context.Background()

func runtimeConfig(t *testing.T) (*Config, string) {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := os.Mkdir(storeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(nodeconfigtest.New("site-a-node1", storeDir).
		AddSEL751(relayID, "127.0.0.1", 2323, 300).
		AddRELPTarget("central", "127.0.0.1", 2514, "test-ca", "test-client", "test/durable-ack", true).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func start(t *testing.T, c *Config, dir string) (*Runtime, *Status, *[]string) {
	t.Helper()
	var logged []string
	st := NewStatus(filepath.Join(dir, "status.json"), func(s string) { logged = append(logged, s) }, nil)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	return r, st, &logged
}

func auditActions(t *testing.T, r *Runtime) []audit.Action {
	t.Helper()
	db := r.Store(AuditStream)
	got, err := db.Read(bg, AuditStream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	stored := make([][]byte, len(got))
	var out []audit.Action
	for i, s := range got {
		stored[i] = s.Event
		rec, err := audit.ParseRecord(s.Event)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rec.Action)
	}
	anchor, _ := db.ChainAnchor(bg, AuditStream)
	if err := audit.VerifyChain(string(r.cfg.NodeID), stored, &anchor, nil); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
	return out
}

func healthTypes(t *testing.T, r *Runtime) []string {
	t.Helper()
	got, err := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range got {
		e, err := event.Decode(s.Event)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e.Health.Type)
	}
	return out
}

func count[T comparable](xs []T, x T) int {
	n := 0
	for _, y := range xs {
		if y == x {
			n++
		}
	}
	return n
}

// A new node starts every database collecting, starts its audit chain once,
// records each database's mode as audit and health, and writes status.
func TestStartNewNodeAndRestart(t *testing.T) {
	c, dir := runtimeConfig(t)
	r, st, _ := start(t, c, dir)
	if !r.Collecting() {
		t.Fatalf("not collecting: %+v", st.Snapshot("x"))
	}
	acts := auditActions(t, r)
	if acts[0] != audit.ActionAuditChainStart || count(acts, audit.ActionStoreModeChange) != 2 || acts[len(acts)-1] != audit.ActionServiceStart {
		t.Fatalf("audit %v", acts)
	}
	if count(healthTypes(t, r), c5.HealthModeChanged) != 2 {
		t.Fatalf("health %v", healthTypes(t, r))
	}
	b, err := os.ReadFile(filepath.Join(dir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sf StatusFile
	if err := json.Unmarshal(b, &sf); err != nil || !sf.Collecting || sf.Modes[EvidenceDB] != c5.ModeCollecting {
		t.Fatalf("status %s %v", b, err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	r, _, _ = start(t, c, dir)
	defer r.Close()
	acts = auditActions(t, r)
	if count(acts, audit.ActionAuditChainStart) != 1 || count(acts, audit.ActionServiceStop) != 1 || count(acts, audit.ActionServiceStart) != 2 {
		t.Fatalf("after restart: %v", acts)
	}
}

// A database that fails startup stops collection, and its alarms reach
// status and the OS log although that database cannot store them
// (C5-A3-5). The other databases still record what they can.
func TestFailedAuditDatabaseIsObservable(t *testing.T) {
	c, dir := runtimeConfig(t)
	r, _, _ := start(t, c, dir)
	r.Close()
	// The audit database's recovery reserve cannot be released.
	reserve := filepath.Join(c.Store.Dir, "audit.reserve-recovery")
	os.Remove(reserve)
	if err := os.MkdirAll(filepath.Join(reserve, "held"), 0o700); err != nil {
		t.Fatal(err)
	}
	r, st, logged := start(t, c, dir)
	defer r.Close()
	if r.Mode(AuditDB) != c5.ModeFailed || r.Collecting() {
		t.Fatalf("audit mode %s, collecting %v", r.Mode(AuditDB), r.Collecting())
	}
	snap := st.Snapshot("x")
	found := false
	for _, a := range snap.Alarms {
		if a.Database == AuditDB && a.Code == c5.AlarmReserveReleaseFailed {
			found = true
		}
	}
	if !found || !strings.Contains(strings.Join(*logged, "\n"), "reserve-release-failed") {
		t.Fatalf("alarm not observable: %+v %v", snap.Alarms, *logged)
	}
	if snap.Collecting {
		t.Fatal("status says collecting")
	}
	// The evidence database still records its own mode as health.
	if count(healthTypes(t, r), c5.HealthModeChanged) < 3 {
		t.Fatalf("health %v", healthTypes(t, r))
	}
}

// Store alarms raised while running become health events at the next Tick.
func TestRunningAlarmBecomesHealthEvent(t *testing.T) {
	c, dir := runtimeConfig(t)
	c.Store.Quotas["adapter-evidence"] = 4000
	r, st, _ := start(t, c, dir)
	defer r.Close()
	l := r.Log(SERStream(relayID))
	var err error
	for i := 0; i < 50 && err == nil; i++ {
		e := event.Event{Schema: event.Identifier, ID: event.EventID{NodeID: c.NodeID, Stream: SERStream(relayID)},
			Origin: event.OriginPlatform, Kind: event.KindHealth, Source: event.Source{OriginAuth: event.AuthPlatform},
			Received: r.received(), Health: &event.Health{Type: "test.filler"}}
		b, _ := json.Marshal(e)
		_, err = l.Append(bg, c5.Record{Stream: SERStream(relayID), Class: c5.ClassAdapterEvidence, Event: b})
	}
	if err == nil {
		t.Fatal("quota never reached")
	}
	r.Tick(bg)
	types := healthTypes(t, r)
	if count(types, c5.AlarmQuotaReached.HealthType()) != 1 || count(types, c5.AlarmQuotaWarning.HealthType()) != 1 {
		t.Fatalf("health %v, status %+v", types, st.Snapshot("x").Alarms)
	}
}

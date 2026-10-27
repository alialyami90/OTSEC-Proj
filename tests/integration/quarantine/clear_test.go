// Package quarantine checks the quarantine clear (A5, #163; P3-A5,
// docs/phase3/A5-quarantine-export.md; C8 0.3) from outside the node
// package, through its exported API only (A6).
//
// Ground truth is the store itself, read by A6's own SQLite connection,
// never the node's status or its own reads: which (stream, seq) rows exist
// and their bytes. The rules checked, from the design and C8 0.3:
//   - a clear is refused, and nothing is removed, when the stream no longer
//     matches the recorded manifest, in either direction (a listed record
//     changed or gone, or a stored record in the range not listed);
//   - a manifest copy that does not match the stream both ways is never
//     recorded, so it cannot be cleared;
//   - a clear removes exactly the recorded range of the named asset's
//     quarantine stream: records after the range, another asset's
//     quarantine stream and every other stream keep their bytes.
//
// Evidence class: simulated (a fake collector whose every run is
// quarantined; the store is the real one).
package quarantine

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

const (
	assetA     = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	assetB     = "7e9a1c44-5b2d-4f60-8a13-c2d4e6f80b19"
	invocation = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30"
)

var bg = context.Background()

// quarantining answers every run with an accepted reply and a quarantined
// outcome (a result that does not decode).
type quarantining struct{ seq uint64 }

func (q *quarantining) Do(ctx context.Context, req *authz.CollectorRequest) (collectorclient.Response, error) {
	q.seq++
	frame := []byte(`{"wire":"otsec.collectorwire/0.1","invocation_id":"` + invocation + `","result":{},"audit":[]}`)
	reply := authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, InvocationID: invocation, CollectorSeq: q.seq}
	reason := "result: does not decode"
	return collectorclient.Response{Reply: reply, Quarantine: &collectorclient.Quarantine{Raw: frame, Reason: reason}},
		fmt.Errorf("%w: %w: %s", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined, reason)
}

type rig struct {
	t   *testing.T
	nc  *nodeconfigtest.Config
	c   *node.Config
	dir string
	r   *node.Runtime
	st  *node.Status
	s   *node.Scheduler
	col *quarantining
}

func newRig(t *testing.T) *rig {
	t.Helper()
	g := &rig{t: t, dir: t.TempDir(), col: &quarantining{}}
	storeDir := filepath.Join(g.dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	g.nc = nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(assetA, "", 2323, 300).AddSEL751(assetB, "", 2324, 300)
	g.nc.AdminDir = g.nc.TLSDir
	if err := g.nc.WriteInstallKey("ik_a6_first"); err != nil {
		t.Fatal(err)
	}
	c, err := node.ParseConfig(g.nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	g.c = c
	if err := store.CreateDir(g.nc.TLSDir, ""); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	g.lock()
	t.Cleanup(func() { g.nc.UnlockTLS() })
	g.start()
	return g
}

func (g *rig) lock() {
	g.t.Helper()
	if err := g.nc.LockTLS(); errors.Is(err, nodeconfigtest.ErrNeedsElevation) {
		if os.Getenv("GITHUB_ACTIONS") == "true" || os.Getenv("OTSEC_REQUIRE_ELEVATED") == "1" {
			g.t.Fatal(err)
		}
		g.t.Skip(err)
	} else if err != nil {
		g.t.Fatal(err)
	}
}

func (g *rig) start() {
	g.t.Helper()
	g.st = node.NewStatus(filepath.Join(g.dir, "status.json"), func(string) {}, nil)
	r, err := node.Start(bg, g.c, node.RuntimeOptions{Status: g.st, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond}})
	if err != nil {
		g.t.Fatal(err)
	}
	g.r = r
	g.t.Cleanup(func() { r.Close() })
	s, err := node.NewScheduler(bg, r, g.col)
	if err != nil {
		g.t.Fatal(err)
	}
	g.s = s
}

func (g *rig) stop() { g.r.Close() }

// runs makes n quarantined runs of asset (index into the schedule).
func (g *rig) runs(i, n int) {
	g.t.Helper()
	for k := 0; k < n; k++ {
		if rep := g.s.RunOnce(bg, i); rep.Outcome != "quarantined" {
			g.t.Fatalf("run %d of schedule %d: %+v", k, i, rep)
		}
	}
}

func (g *rig) export(asset string) {
	g.t.Helper()
	g.nc.UnlockTLS()
	defer g.lock()
	if _, err := node.ExportQuarantine(bg, g.c, asset, filepath.Join(g.t.TempDir(), "export"), time.Now()); err != nil {
		g.t.Fatal(err)
	}
}

func (g *rig) adminRead(name string) []byte {
	g.t.Helper()
	b, err := os.ReadFile(filepath.Join(g.nc.AdminDir, name))
	if err != nil {
		g.t.Fatal(err)
	}
	return b
}

func (g *rig) adminWrite(name string, b []byte) {
	g.t.Helper()
	g.nc.UnlockTLS()
	p := filepath.Join(g.nc.AdminDir, name)
	os.Remove(p)
	if err := os.WriteFile(p, b, 0o440); err != nil {
		g.t.Fatal(err)
	}
	g.lock()
}

func (g *rig) clear(asset, manifest string) {
	g.adminWrite(node.ClearQuarantineFileName, []byte(`{"schema":"`+node.ClearQuarantineSchema+`","asset_id":"`+asset+`","manifest_sha256":"`+manifest+`","principal":"admin@site-a"}`))
}

func (g *rig) ticks(n int) {
	for i := 0; i < n; i++ {
		g.s.QuarantineTick(bg)
	}
}

func hexSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// rows is every (stream, seq) row of every store database, with the
// SHA-256 of its event and of its capture, read by A6's own connection.
func (g *rig) rows() map[string]string {
	g.t.Helper()
	out := map[string]string{}
	paths, _ := filepath.Glob(filepath.Join(g.c.Store.Dir, "*.db"))
	if len(paths) == 0 {
		g.t.Fatal("no store databases")
	}
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: p}).EscapedPath()+"?mode=ro&_pragma=busy_timeout(5000)")
		if err != nil {
			g.t.Fatal(err)
		}
		q, err := db.Query(`SELECT e.stream, e.seq, e.event, COALESCE(c.bytes, x'') FROM events e LEFT JOIN captures c ON c.sha256 = e.capture`)
		if err != nil {
			g.t.Fatal(err)
		}
		for q.Next() {
			var stream string
			var seq int64
			var ev, capt []byte
			if err := q.Scan(&stream, &seq, &ev, &capt); err != nil {
				g.t.Fatal(err)
			}
			out[fmt.Sprintf("%s/%s#%d", filepath.Base(p), stream, seq)] = hexSum(ev) + "/" + hexSum(capt)
		}
		q.Close()
		db.Close()
	}
	return out
}

// quarSeqs are the seqs of asset's quarantine stream, from rows.
func quarSeqs(rows map[string]string, asset string) []int {
	var out []int
	for k := range rows {
		if i := strings.Index(k, "/"+string(node.QuarantineStream(asset))+"#"); i >= 0 {
			var n int
			fmt.Sscan(k[i+len(node.QuarantineStream(asset))+2:], &n)
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// exec runs SQL on the database holding asset's quarantine stream, with the
// node stopped, as damage done outside the product.
func (g *rig) exec(asset, query string, args ...any) {
	g.t.Helper()
	paths, _ := filepath.Glob(filepath.Join(g.c.Store.Dir, "*.db"))
	for _, p := range paths {
		db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: p}).EscapedPath())
		if err != nil {
			g.t.Fatal(err)
		}
		var n int
		db.QueryRow(`SELECT count(*) FROM events WHERE stream = ?`, string(node.QuarantineStream(asset))).Scan(&n)
		if n > 0 {
			res, err := db.Exec(query, args...)
			db.Close()
			if err != nil {
				g.t.Fatal(err)
			}
			if k, _ := res.RowsAffected(); k != 1 {
				g.t.Fatalf("%s changed %d rows", query, k)
			}
			return
		}
		db.Close()
	}
	g.t.Fatal("no database holds the quarantine stream")
}

func (g *rig) audit(action audit.Action) []*audit.Record {
	g.t.Helper()
	got, err := g.r.Store(node.AuditStream).Read(bg, node.AuditStream, 0, 5000)
	if err != nil {
		g.t.Fatal(err)
	}
	var out []*audit.Record
	for _, s := range got {
		rec, err := audit.ParseRecord(s.Event)
		if err != nil {
			g.t.Fatal(err)
		}
		if rec.Action == action {
			out = append(out, rec)
		}
	}
	return out
}

func (g *rig) alarm(code, part string) bool {
	return slices.ContainsFunc(g.st.Snapshot("x").Alarms, func(a node.StatusAlarm) bool { return a.Code == code && strings.Contains(a.Detail, part) })
}

func manifestName(asset string) string { return node.QuarantineExportFileName(asset) }

// recorded exports asset's stream, has the node record it, and returns the
// manifest copy's hash.
func (g *rig) recorded(asset string) string {
	g.t.Helper()
	g.export(asset)
	g.ticks(1)
	h := hexSum(g.adminRead(manifestName(asset)))
	for _, r := range g.audit(audit.ActionQuarantineExported) {
		if r.Quarantine.ManifestSHA256 == h {
			return h
		}
	}
	g.t.Fatalf("export of %s not recorded", asset)
	return ""
}

// A clear removes exactly the recorded range: the seqs of the named
// asset's stream that the manifest listed. Every other row of every
// database keeps its bytes, including records committed after the export
// and the other asset's quarantine stream.
func TestClearRemovesOnlyTheRange(t *testing.T) {
	g := newRig(t)
	g.runs(0, 12) // asset A
	g.runs(1, 3)  // asset B
	h := g.recorded(assetA)
	g.runs(0, 2) // after the export
	before := g.rows()
	listed := quarSeqs(before, assetA)
	ex := g.audit(audit.ActionQuarantineExported)[0].Quarantine
	t.Logf("asset A stores %v; recorded range %d to %d (%d items)", listed, ex.FirstSeq, ex.LastSeq, ex.Items)
	if int(ex.Items) >= len(listed) {
		t.Fatalf("no record after the range: %d items of %v", ex.Items, listed)
	}
	g.clear(assetA, h)
	g.ticks(10)
	after := g.rows()
	for k, v := range before {
		var seq int
		inRange := false
		if i := strings.Index(k, "/"+string(node.QuarantineStream(assetA))+"#"); i >= 0 {
			fmt.Sscan(k[strings.LastIndex(k, "#")+1:], &seq)
			inRange = uint64(seq) >= ex.FirstSeq && uint64(seq) <= ex.LastSeq
		}
		got, ok := after[k]
		switch {
		case inRange && ok:
			t.Errorf("%s is in the cleared range and still stored", k)
		case !inRange && strings.Contains(k, "/quarantine/") && !ok:
			t.Errorf("%s is outside the cleared range and was removed", k)
		case !inRange && ok && got != v && strings.Contains(k, "/quarantine/"):
			t.Errorf("%s changed: %s, was %s", k, got, v)
		}
	}
	for k, v := range before {
		if !strings.Contains(k, "/quarantine/") && after[k] != v {
			t.Errorf("%s, outside every quarantine stream, changed or went: %q, was %q", k, after[k], v)
		}
	}
	if len(quarSeqs(after, assetB)) != len(quarSeqs(before, assetB)) || len(quarSeqs(after, assetB)) == 0 {
		t.Errorf("asset B's quarantine: %v, was %v", quarSeqs(after, assetB), quarSeqs(before, assetB))
	}
	cl := g.audit(audit.ActionQuarantineCleared)
	if len(cl) != 1 || cl[0].Outcome != audit.OutcomeSucceeded || cl[0].Target.AssetID != assetA {
		t.Fatalf("cleared records: %+v", cl)
	}
	t.Logf("asset A after: %v; asset B kept %v", quarSeqs(after, assetA), quarSeqs(after, assetB))
}

// A clear is refused, with nothing removed, when the stream no longer
// matches the recorded manifest: each kind of damage done with the node
// stopped, between the export record and the clear.
func TestClearRefusedWhenTheStreamChanged(t *testing.T) {
	q := string(node.QuarantineStream(assetA))
	for _, tc := range []struct {
		name   string
		break_ func(g *rig, seqs []int)
	}{
		{"a listed event's bytes changed", func(g *rig, s []int) {
			g.exec(assetA, `UPDATE events SET event = CAST(event || ' ' AS BLOB) WHERE stream = ? AND seq = ?`, q, s[3])
		}},
		{"a listed record gone (stored fewer than listed)", func(g *rig, s []int) {
			g.exec(assetA, `DELETE FROM events WHERE stream = ? AND seq = ?`, q, s[4])
		}},
		{"a listed capture's bytes changed", func(g *rig, s []int) {
			g.exec(assetA, `UPDATE captures SET bytes = CAST(bytes || 'x' AS BLOB) WHERE sha256 = (SELECT capture FROM events WHERE stream = ? AND seq = ?)`, q, s[2])
		}},
		{"a listed record's capture dropped", func(g *rig, s []int) {
			g.exec(assetA, `UPDATE events SET capture = NULL WHERE stream = ? AND seq = ?`, q, s[1])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t)
			g.runs(0, 4)
			h := g.recorded(assetA)
			seqs := quarSeqs(g.rows(), assetA)
			g.stop()
			tc.break_(g, seqs)
			g.start()
			before := g.rows()
			g.clear(assetA, h)
			g.ticks(4)
			if after := g.rows(); !mapsEqual(before, after) {
				t.Errorf("rows changed after a refused clear: %v, was %v", quarSeqs(after, assetA), quarSeqs(before, assetA))
			}
			for _, r := range g.audit(audit.ActionQuarantineCleared) {
				t.Errorf("a quarantine.cleared was recorded: %s %+v", r.Outcome, r.Quarantine)
			}
			if !g.alarm(node.AlarmQuarantineClearRefused, "nothing removed") {
				t.Errorf("no quarantine-clear-refused alarm: %+v", g.st.Snapshot("x").Alarms)
			}
		})
	}
}

// The manifest copy is checked against the stream both ways before it is
// recorded; one that is not recorded cannot be cleared, and nothing is
// removed by trying.
func TestManifestCheckedBothWays(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(m *node.QuarantineManifest)
	}{
		{"a stored record in the range not listed", func(m *node.QuarantineManifest) { m.Items = slices.Delete(m.Items, 2, 3) }},
		{"a listed seq not stored", func(m *node.QuarantineManifest) {
			last := m.Items[len(m.Items)-1]
			last.Seq += 5
			m.Items = append(m.Items, last)
		}},
		{"the first record left out", func(m *node.QuarantineManifest) {
			m.Items = m.Items[1:]
			m.Items[0].EventSHA256 = strings.Repeat("0", 64)
		}},
		{"an event hash changed", func(m *node.QuarantineManifest) { m.Items[1].EventSHA256 = strings.Repeat("a", 64) }},
		{"a capture hash changed", func(m *node.QuarantineManifest) { m.Items[1].CaptureSHA256 = strings.Repeat("b", 64) }},
		{"a capture left out", func(m *node.QuarantineManifest) { m.Items[2].CaptureSHA256 = "" }},
		{"another asset's stream", func(m *node.QuarantineManifest) {
			m.AssetID, m.Stream = assetB, string(node.QuarantineStream(assetB))
		}},
		{"another node", func(m *node.QuarantineManifest) { m.NodeID = "site-b-node1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newRig(t)
			g.runs(0, 3)
			g.runs(1, 3)
			g.export(assetA)
			var m node.QuarantineManifest
			if err := json.Unmarshal(g.adminRead(manifestName(assetA)), &m); err != nil {
				t.Fatal(err)
			}
			tc.edit(&m)
			b, _ := json.MarshalIndent(m, "", "  ")
			g.adminWrite(manifestName(assetA), append(b, '\n'))
			h := hexSum(append(b, '\n'))
			before := g.rows()
			g.ticks(2)
			if ex := g.audit(audit.ActionQuarantineExported); len(ex) != 0 {
				t.Fatalf("an edited manifest was recorded: %+v", ex[0].Quarantine)
			}
			if !g.alarm(node.AlarmQuarantineExportRefused, "does not match") {
				t.Errorf("no quarantine-export-refused alarm: %+v", g.st.Snapshot("x").Alarms)
			}
			g.clear(assetA, h)
			g.ticks(3)
			if after := g.rows(); !mapsEqual(before, after) {
				t.Errorf("rows changed: %v, was %v", quarSeqs(after, assetA), quarSeqs(before, assetA))
			}
			if cl := g.audit(audit.ActionQuarantineCleared); len(cl) != 0 {
				t.Errorf("a clear of an unrecorded manifest was recorded: %+v", cl[0])
			}
		})
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

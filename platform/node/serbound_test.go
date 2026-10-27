package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/platform/store"
)

// The tests here hold SERCommitBytes to its derivation (D4-9, B1's ruling on
// #246): an SER read is one atomic batch, so the evidence database's commit
// cap must be at least the largest read the node can build. All of it is
// constructed data, normalized by the real normalizer (simulated, not a
// device capture).

const c2Results = "../../contracts/adapter/testdata/results/valid/"

func serFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serRow is one SER table line of a constructed read, and whether the
// constructed adapter parsed it.
type serRow struct {
	line   string
	parsed bool
}

// serReadOf returns the C2 SER example result with its table replaced by
// rows, spans, segments, records and the transcript hash rebuilt so it is
// still valid C2 (the same construction as the normalizer's own tests).
func serReadOf(t testing.TB, rows []serRow) adapter.Result {
	t.Helper()
	tpl, err := adapter.DecodeResult(serFile(t, c2Results+"ok.json"))
	if err != nil {
		t.Fatal(err)
	}
	first, last := tpl.Records[0], tpl.Records[len(tpl.Records)-1]
	start := first.Span.Offset
	end := last.Span.Offset + last.Span.Length
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.line
	}
	table := strings.Join(lines, "\r\n")
	old := tpl.Transcript.Data
	data := append(append(append([]byte{}, old[:start]...), table...), old[end:]...)
	delta := int64(len(data) - len(old))
	segs := append([]adapter.Segment{}, tpl.Transcript.Segments...)
	for i := range segs {
		switch {
		case segs[i].Offset > start:
			segs[i].Offset += delta
		case segs[i].Offset+segs[i].Length >= end:
			segs[i].Length += delta
		}
	}
	res := tpl
	res.Transcript.Data = data
	res.Transcript.Segments = segs
	sum := sha256.Sum256(data)
	res.Transcript.SHA256 = hex.EncodeToString(sum[:])
	res.Records = nil
	off := start
	for _, r := range rows {
		rec := adapter.Record{Kind: "sel.ser.row", Span: adapter.Span{Offset: off, Length: int64(len(r.line))}, ContextSpan: first.ContextSpan, ParseOK: r.parsed}
		if r.parsed {
			f := strings.Fields(r.line)
			if len(f) != 5 {
				t.Fatalf("constructed row does not split into 5 fields: %q", r.line)
			}
			for i, name := range adapter.RecordFields["sel.ser.row"] {
				rec.Fields = append(rec.Fields, adapter.Field{Name: name, Value: f[i]})
			}
		}
		res.Records = append(res.Records, rec)
		off += int64(len(r.line)) + 2
	}
	res.Status, res.Error = adapter.StatusOK, nil
	for _, r := range rows {
		if !r.parsed {
			res.Status, res.Error = adapter.StatusPartial, &adapter.Error{Code: adapter.PartialParseErrors}
		}
	}
	if err := res.Validate(); err != nil {
		t.Fatalf("constructed result is not valid C2: %v", err)
	}
	return res
}

// serMeasure is one constructed read's size as the Log counts it.
type serMeasure struct {
	rows, rowBytes int
	events, health int // JSON bytes of the SER and the health events
	capture        int
	maxEvent       int
}

// commit is what the SER batch counts: events plus its capture once.
func (m serMeasure) commit() int { return m.events + m.capture }

func serNormalize(t testing.TB, rows []serRow, prev []string) serMeasure {
	t.Helper()
	inv, err := adapter.DecodeInvocation(serFile(t, "../../contracts/adapter/testdata/invocations/valid/sel-ser-read.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(serFile(t, "../../contracts/asset/testdata/valid/sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	res := serReadOf(t, rows)
	// The longest node ID, the node's own stream names, and the finest
	// clock step (nine fractional digits in received.utc).
	node := event.NodeID(strings.Repeat("a", 63))
	out, err := normalize.Normalize(res, inv, a, normalize.Input{Node: node, Stream: event.Stream(SERStream(a.AssetID)),
		HealthStream: event.Stream(HealthStream), ClockResolutionNS: 1, Clock: event.Clock{Sync: event.SyncUnknown}, Prev: prev})
	if err != nil {
		t.Fatal(err)
	}
	ser, hl, err := out.Records(event.Stream(SERStream(a.AssetID)), event.Stream(HealthStream))
	if err != nil {
		t.Fatal(err)
	}
	m := serMeasure{rows: len(rows), capture: len(out.Capture.Bytes)}
	for _, r := range rows {
		m.rowBytes += len(r.line)
	}
	for _, r := range ser {
		m.events += len(r.Event)
		m.maxEvent = max(m.maxEvent, len(r.Event))
	}
	for _, r := range hl {
		m.health += len(r.Event)
	}
	return m
}

// serTable is n parsed rows in the layout the relay prints, numbered
// downward, each with an element of elem characters ([A-Za-z0-9_], the
// adapter's grammar) and distinct times.
func serTable(n, elem int) []serRow {
	rows := make([]serRow, n)
	for i := range rows {
		el := fmt.Sprintf("E%d", i)
		if elem > len(el) {
			el += strings.Repeat("A", elem-len(el))
		}
		state := "Asserted"
		if i%2 == 1 {
			state = "Deasserted"
		}
		rows[i] = serRow{line: fmt.Sprintf("%-5d10/24/2026 09:%02d:%02d.%03d   %-17s %s", n-i, i/60000%60, i/1000%60, i%1000, el, state), parsed: true}
	}
	return rows
}

// The bound's two constants are measured, not assumed: k and F come from a
// fit through two single-row reads of different lengths, then F is raised
// by what a worst-case event adds that the fixture does not have.
func TestSERBoundConstants(t *testing.T) {
	small := serNormalize(t, serTable(1, 4), nil)
	big := serNormalize(t, serTable(1, 100000), nil)
	k := float64(big.maxEvent-small.maxEvent) / float64(big.rowBytes-small.rowBytes)
	f := float64(small.maxEvent) - k*float64(small.rowBytes)
	t.Logf("k = %.3f encoded bytes per row byte, F = %.0f bytes (simulated)", k, f)
	if k*100 > SERBytesPerRowByteX100 {
		t.Fatalf("k %.3f is over SERBytesPerRowByteX100/100", k)
	}
	const (
		seqDigits      = 20                                        // the store writes the assigned seq into id (uint64)
		classPad       = len("device-observed") - len("simulated") // the fixture's far end is a simulator
		alignmentPad   = len("possible-duplicate") - len("first-read")
		flagPad        = len(`,"flags":["possible-duplicate"]`)
		operationPad   = MaxOperationBytes - len("sel.ser.read_all")
		nodeResolution = 0 // measured with the node ID at 63 bytes and nine digits
	)
	worst := f + float64(seqDigits+classPad+alignmentPad+flagPad+operationPad+nodeResolution)
	t.Logf("F with the worst-case additions: %.0f of SERFixedEventBytes %d", worst, SERFixedEventBytes)
	if worst > SERFixedEventBytes {
		t.Fatalf("F %.0f is over SERFixedEventBytes %d", worst, SERFixedEventBytes)
	}
}

// The cap is the bound rounded up to a MiB, and no larger: a bound that
// rises past the cap fails here, and a cap that outgrows its bound by a
// MiB or more is loose, which would size the reserve for nothing.
func TestSERCommitCapHoldsTheBound(t *testing.T) {
	if SERReadBound > SERCommitBytes {
		t.Fatalf("an SER read can reach %d bytes, over SERCommitBytes %d", int64(SERReadBound), SERCommitBytes)
	}
	if SERCommitBytes-SERReadBound >= 1<<20 {
		t.Fatalf("SERCommitBytes %d is a MiB or more over the bound %d", SERCommitBytes, int64(SERReadBound))
	}
	// The other commits of the evidence database fit it too: a
	// quarantine is a whole outcome frame, its reason and two events.
	if QuarantineRoom > SERCommitBytes {
		t.Fatalf("a quarantine can take %d bytes, over SERCommitBytes %d", QuarantineRoom, SERCommitBytes)
	}
}

// Reads built to be as large as the node's limits and the adapter's grammar
// allow, normalized by the real normalizer, all fall under the bound.
// B2's two measurements on #246 (6.06 MB and 4.03 MB) are the first two.
func TestSERReadsFallUnderTheBound(t *testing.T) {
	cases := []struct {
		name string
		rows []serRow
	}{
		{"1024 parsed rows, long elements", serTable(1024, 940)},
		{"one unparsed line, 900 KB", []serRow{{line: strings.Repeat("A", 900<<10)}}},
		{"2048 parsed rows, 500-byte elements", serTable(2048, 440)},
		{"2048 shortest parsed rows", serTable(2048, 1)},
		{"one parsed row, 900 KB element", serTable(1, 900<<10)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := serNormalize(t, c.rows, nil)
			t.Logf("%d rows, %d row bytes: events %d, capture %d, commit %d of %d (bound %d), simulated",
				m.rows, m.rowBytes, m.events, m.capture, m.commit(), SERCommitBytes, int64(SERReadBound))
			if int64(m.commit()) > SERReadBound {
				t.Fatalf("commit %d is over the bound %d", m.commit(), int64(SERReadBound))
			}
			if m.health > SERHealthBytes {
				t.Fatalf("health events %d are over %d", m.health, SERHealthBytes)
			}
			if m.capture > adapter.MaxResponseBytes {
				t.Fatalf("capture %d is over MaxResponseBytes", m.capture)
			}
		})
	}
}

// startCapped starts the node with the evidence database's commit cap at
// cap bytes, and a collector that answers every run with a read of rows
// parsed rows.
func startCapped(t *testing.T, cap int64, rows int) (*Runtime, *Status, *Scheduler) {
	t.Helper()
	c, dir := schedConfig(t, nil)
	st := NewStatus(filepath.Join(dir, "status.json"), func(string) {}, nil)
	r, err := Start(bg, c, RuntimeOptions{Status: st, Group: c5.GroupOptions{MaxEvents: 10, MaxWait: 5 * time.Millisecond, MaxCommitBytes: cap}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	res := serReadOf(t, serTable(rows, 40))
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 1),
			Outcome: &collectorclient.Outcome{InvocationID: okInvocation, ResultJSON: raw, Result: res}}, nil
	}}
	return r, st, newScheduler(t, r, f)
}

// A read over the evidence database's commit cap is refused whole (D4-9): no
// SER event is stored, the bytes go to quarantine, one health event says the
// outcome is unknown, and the alarm is raised. The same read under the
// node's cap is stored, so it is the cap that refused it.
func TestReadOverTheCommitCapIsQuarantined(t *testing.T) {
	const rows = 150
	r, st, s := startCapped(t, 256<<10, rows)
	rep := s.RunOnce(bg, 0)
	if rep.Outcome != "quarantined" || rep.Alarm != AlarmResultRefused || rep.Events != 0 {
		t.Fatalf("over the cap: %+v", rep)
	}
	if n, _ := r.Store(SERStream(relayID)).LastCommitted(bg, SERStream(relayID)); n != 0 {
		t.Fatalf("%d SER events stored from a refused read", n)
	}
	if n, _ := r.Store(QuarantineStream(relayID)).LastCommitted(bg, QuarantineStream(relayID)); n != 2 {
		t.Fatalf("%d quarantine records, want the frame and its reason", n)
	}
	if countAlarms(st, AlarmResultRefused) != 1 || s.Halted(relayID) != "" {
		t.Fatalf("alarms %d, halted %q", countAlarms(st, AlarmResultRefused), s.Halted(relayID))
	}
	// The Log kept running: the next small commit is accepted.
	if rep2 := s.RunOnce(bg, 0); rep2.Outcome != "quarantined" {
		t.Fatalf("second run: %+v", rep2)
	}

	r2, _, s2 := startCapped(t, 0, rows)
	if rep := s2.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Events != rows {
		t.Fatalf("under the node's cap: %+v", rep)
	}
	if n, _ := r2.Store(SERStream(relayID)).LastCommitted(bg, SERStream(relayID)); n != rows {
		t.Fatalf("%d SER events stored", n)
	}
}

// Each database's recovery reserve covers its largest commit: the evidence
// database's cap is the SER bound, the others keep 1 MiB (C5 0.4, D4-9).
func TestStartupPolicyReserveFollowsTheCommitCap(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	type commit struct{ bytes, rows int64 }
	want := map[c5.DatabaseID]commit{
		EvidenceDB: {SERCommitBytes, EvidenceBatchRecords},
		SyslogDB:   {c5.DefaultMaxCommitBytes, SyslogBatchRecords},
		AuditDB:    {c5.DefaultMaxCommitBytes, AuditBatchRecords},
	}
	for _, d := range r.dbs {
		largest, ok := want[d.spec.ID]
		if !ok {
			continue
		}
		p := d.policy
		if p.LargestCommitBytes != largest.bytes || p.LargestCommitRecords != largest.rows || p.WALBoundBytes != store.WALBoundBytes ||
			p.RecoveryReserveBytes != c5.RecoveryReserveFor(store.WALBoundBytes, largest.bytes, largest.rows) {
			t.Errorf("%s: largest commit %d bytes in %d rows, WAL bound %d, reserve %d", d.spec.ID, p.LargestCommitBytes, p.LargestCommitRecords, p.WALBoundBytes, p.RecoveryReserveBytes)
		}
		t.Logf("%s: reserve %d bytes (%.2f MiB), simulated", d.spec.ID, p.RecoveryReserveBytes, float64(p.RecoveryReserveBytes)/(1<<20))
		if err := p.Validate(); err != nil {
			t.Errorf("%s: %v", d.spec.ID, err)
		}
	}
}

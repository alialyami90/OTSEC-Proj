package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// The C2 example result the scheduler tests collect: a synthetic simulated
// SEL-751 SER read (evidence class simulated; nothing in it is device
// output).
const (
	okResult     = "../../contracts/adapter/testdata/results/valid/ok.json"
	okInvocation = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30"
	okTranscript = "058846bcaceb20ef8553ddb4c4b6663fc2bbab1ce31e7201b5a0e992a7bbff20"
)

func schedConfig(t *testing.T, mod func(*nodeconfigtest.Config)) (*Config, string) {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300)
	if mod != nil {
		mod(nc)
	}
	if err := nc.WriteInstallKey(testInstallKey); err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(nc.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

// testInstallKey is the collector install key ID schedConfig publishes.
const testInstallKey = "ik_test_first"

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sessionRecords are the pending C8 records the collector reports for one
// session of the ok.json run, numbered from first.
func sessionRecords(t *testing.T, first uint64) []json.RawMessage {
	return sessionRecordsFor(t, first, okTranscript)
}

func sessionRecordsFor(t *testing.T, first uint64, transcript string) []json.RawMessage {
	t.Helper()
	var out []json.RawMessage
	for i, action := range []audit.Action{audit.ActionDeviceSessionOpen, audit.ActionCredentialUse, audit.ActionDeviceOp, audit.ActionDeviceSessionClose} {
		r := audit.Record{
			Contract: audit.ContractID, NodeID: "site-a-node1",
			Time:   audit.Time{UTC: "2026-10-24T09:15:00.123456Z", ResolutionNS: 1000, Clock: audit.Clock{Sync: "synchronized", Source: "ntp"}},
			Actor:  audit.Actor{Type: authz.PrincipalSchedule, ID: "sch-ser-2b7d4e10", Role: authz.RoleCollector},
			Action: action, Outcome: audit.OutcomeSucceeded,
			Target: &audit.Target{AssetID: relayID, Transport: "telnet", DownstreamSecurity: "plaintext-unauthenticated",
				CredentialRef: nodeconfigtest.TestCredentialRef, CredentialVersion: 1, Family: "sel-751"},
			CorrelationID: okInvocation, CollectorSeq: first + uint64(i),
		}
		switch action {
		case audit.ActionDeviceSessionClose:
			r.TranscriptSHA256 = transcript
		case audit.ActionDeviceOp:
			r.OperationID = "sel.ser.read_all"
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := audit.ValidatePending(b); err != nil {
			t.Fatalf("fixture record: %v", err)
		}
		out = append(out, b)
	}
	return out
}

// figureOrder is ok.json with its two SER rows printed oldest first, row 2
// then row 1, as the SEL-751 prints them (S22 Figure 10.16; A4's normalizer
// requires that order), with spans, records and the transcript digest
// rebuilt. Constructed test data, after A4's withRows.
func figureOrder(t *testing.T) (result []byte, transcript string) {
	t.Helper()
	res, err := adapter.DecodeResult(readFile(t, okResult))
	if err != nil {
		t.Fatal(err)
	}
	first, last := res.Records[0], res.Records[len(res.Records)-1]
	start, end := first.Span.Offset, last.Span.Offset+last.Span.Length
	rows := []string{
		"2    10/24/2026 09:10:01.004   IN101             Asserted",
		"1    10/24/2026 09:10:01.251   IN101             Deasserted",
	}
	table := strings.Join(rows, "\r\n")
	old := res.Transcript.Data
	data := append(append(append([]byte{}, old[:start]...), table...), old[end:]...)
	delta := int64(len(data) - len(old))
	for i := range res.Transcript.Segments {
		sg := &res.Transcript.Segments[i]
		switch {
		case sg.Offset > start:
			sg.Offset += delta
		case sg.Offset+sg.Length >= end:
			sg.Length += delta
		}
	}
	res.Transcript.Data = data
	sum := sha256.Sum256(data)
	res.Transcript.SHA256 = hex.EncodeToString(sum[:])
	res.Records = nil
	off := start
	for _, row := range rows {
		rec := adapter.Record{Kind: normalize.SERKind, Span: adapter.Span{Offset: off, Length: int64(len(row))}, ContextSpan: first.ContextSpan, ParseOK: true}
		for i, v := range strings.Fields(row) {
			rec.Fields = append(rec.Fields, adapter.Field{Name: adapter.RecordFields[normalize.SERKind][i], Value: v})
		}
		res.Records = append(res.Records, rec)
		off += int64(len(row)) + 2
	}
	if err := res.Validate(); err != nil {
		t.Fatalf("constructed result is not valid C2: %v", err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return b, res.Transcript.SHA256
}

// wireCollector answers each request over an in-memory pipe through the
// real collectorclient, so every C7, C2 and C8 check of the client runs.
// Before replying it calls onRequest, which the tests use to look at the
// store while the request is in flight.
func wireCollector(t *testing.T, onRequest func(req *authz.CollectorRequest), seq *uint64) *collectorclient.Client {
	t.Helper()
	result, transcript := figureOrder(t)
	return collectorclient.NewWithDialer(func(ctx context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			s.SetDeadline(time.Now().Add(5 * time.Second))
			b, err := collectorwire.ReadFrame(s, authz.MaxRequestBytes)
			if err != nil {
				return
			}
			req, err := authz.DecodeRequest(b)
			if err != nil {
				return
			}
			onRequest(req)
			*seq++
			reply, _ := json.Marshal(authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID,
				Status: authz.ReplyAccepted, InvocationID: okInvocation, CollectorSeq: *seq})
			recs := sessionRecordsFor(t, *seq+1, transcript)
			*seq += uint64(len(recs))
			out, err := collectorwire.EncodeOutcome(collectorwire.RunOutcome{InvocationID: okInvocation, Result: result, Audit: recs})
			if err != nil {
				return
			}
			collectorwire.WriteFrame(s, reply, collectorwire.MaxReplyBytes)
			collectorwire.WriteFrame(s, out, collectorwire.MaxOutcomeBytes)
			io := make([]byte, 1)
			s.Read(io) // wait for the client to close
		}()
		return c, nil
	})
}

// fakeCollector returns what answer says and counts the requests.
// fakeCollector answers each request with answer. calls counts the runs
// and clears the asset clears (assetclear.go). With clear set, clears are
// answered by it instead.
type fakeCollector struct {
	mu     sync.Mutex
	calls  int
	clears int
	answer func(req *authz.CollectorRequest) (collectorclient.Response, error)
	clear  func(req *authz.CollectorRequest) (collectorclient.Response, error)
}

func (f *fakeCollector) Do(ctx context.Context, req *authz.CollectorRequest) (collectorclient.Response, error) {
	f.mu.Lock()
	clear := req.Kind == authz.KindAssetClearSusp
	if clear {
		f.clears++
	} else {
		f.calls++
	}
	answer := f.answer
	if clear && f.clear != nil {
		answer = f.clear
	}
	f.mu.Unlock()
	return answer(req)
}

func (f *fakeCollector) n() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

// nClears is the number of asset clears sent.
func (f *fakeCollector) nClears() int { f.mu.Lock(); defer f.mu.Unlock(); return f.clears }

func accepted(req *authz.CollectorRequest, seq uint64) authz.CollectorReply {
	return authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyAccepted, InvocationID: okInvocation, CollectorSeq: seq}
}

func auditRecords(t *testing.T, r *Runtime) []*audit.Record {
	t.Helper()
	auditActions(t, r) // verifies the chain
	got, err := r.Store(AuditStream).Read(bg, AuditStream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []*audit.Record
	for _, s := range got {
		rec, err := audit.ParseRecord(s.Event)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func requestRecords(recs []*audit.Record, requestID string) []*audit.Record {
	var out []*audit.Record
	for _, r := range recs {
		if r.Action == audit.ActionCollectorRequest && r.CorrelationID == requestID {
			out = append(out, r)
		}
	}
	return out
}

func newScheduler(t *testing.T, r *Runtime, c Collector) *Scheduler {
	t.Helper()
	s, err := NewScheduler(bg, r, c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A run through the real client: the collector.request record holds a
// receipt before the request reaches the collector (D1-11); the decision
// and the session records are committed with their collector_seq; the SER
// rows are committed with their capture and alignment state; and a second
// read of the same rows adds no event but still keeps its transcript.
func TestRunCommitsThroughTheClient(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()

	_, transcript := figureOrder(t)
	var inFlight []string
	var seq uint64
	client := wireCollector(t, func(req *authz.CollectorRequest) {
		// The request is at the collector: its record must already be
		// committed, as the newest audit record.
		recs := auditRecords(t, r)
		last := recs[len(recs)-1]
		if last.Action != audit.ActionCollectorRequest || last.Outcome != audit.OutcomeInfo || last.CorrelationID != req.RequestID {
			t.Errorf("request %s reached the collector before its audit record: newest is %s %s", req.RequestID, last.Action, last.Outcome)
		}
		inFlight = append(inFlight, req.RequestID)
	}, &seq)
	s := newScheduler(t, r, client)

	rep := s.RunOnce(bg, 0)
	if !rep.Sent || rep.Decision != authz.ReplyAccepted || rep.Outcome != "ok" || rep.Events == 0 || rep.Alarm != "" {
		t.Fatalf("first run: %+v", rep)
	}
	if len(inFlight) != 1 || inFlight[0] != rep.RequestID {
		t.Fatalf("requests seen by the collector: %v", inFlight)
	}
	recs := auditRecords(t, r)
	rr := requestRecords(recs, rep.RequestID)
	if len(rr) != 2 || rr[0].Outcome != audit.OutcomeInfo || rr[1].Outcome != audit.OutcomeAllowed || rr[1].CollectorSeq != 1 {
		t.Fatalf("collector.request records: %+v", rr)
	}
	if err := audit.VerifyCollectorSeq(recs, 0, seq); err != nil {
		t.Fatalf("collector_seq: %v", err)
	}
	ser, err := r.Store(SERStream(relayID)).Read(bg, SERStream(relayID), 0, 1000)
	if err != nil || len(ser) != rep.Events {
		t.Fatalf("SER stream: %d events, %v; report says %d", len(ser), err, rep.Events)
	}
	for _, st := range ser {
		e, err := event.Decode(st.Event)
		if err != nil {
			t.Fatal(err)
		}
		if st.EvidenceRef != c5.EvidenceRef(transcript) || e.Collection == nil || e.Collection.InvocationID != okInvocation {
			t.Fatalf("event %d: evidence %q, collection %+v", st.Key.Seq, st.EvidenceRef, e.Collection)
		}
	}
	if cur, _ := r.Store(SERStream(relayID)).SourceCursor(bg, SERStream(relayID)); cur == nil {
		t.Fatal("no alignment state after the first read")
	}

	rep2 := s.RunOnce(bg, 0)
	if rep2.Outcome != "ok" || rep2.Events != 0 {
		t.Fatalf("second read of the same rows: %+v", rep2)
	}
	hs, _ := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
	var runs []c5.Stored
	for _, st := range hs {
		if e, _ := event.Decode(st.Event); e.Health.Type == HealthCollectionRun {
			runs = append(runs, st)
		}
	}
	if len(runs) != 2 || runs[0].EvidenceRef != "" || runs[1].EvidenceRef != c5.EvidenceRef(transcript) {
		t.Fatalf("collection.run events: %+v", runs)
	}
	capture, err := r.Store(HealthStream).ReadCapture(bg, runs[1].EvidenceRef)
	if err != nil || capture.SHA256 != transcript {
		t.Fatalf("transcript of the read that added nothing: %v", err)
	}
}

// D1-11 against the scheduler: with the audit quota full, no request
// leaves the node, the alarm is raised, and received Syslog is unaffected
// (the store tests cover that half).
func TestAuditFullSendsNothing(t *testing.T) {
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) { nc.Store.Quotas["audit"] = 600 })
	r, st, _ := start(t, c, dir)
	defer r.Close()
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 1)}, nil
	}}
	s := newScheduler(t, r, f)
	for i := 0; i < 3; i++ {
		if rep := s.RunOnce(bg, 0); rep.Sent || rep.Alarm != AlarmAuditUnavailable {
			t.Fatalf("run %d: %+v", i, rep)
		}
	}
	if f.n() != 0 {
		t.Fatalf("%d requests sent with no audit receipt", f.n())
	}
	// The first record the node cannot write is collector.install_key,
	// before the first request; its hold is raised once, not per run.
	if n := countAlarms(st, AlarmAuditUnavailable); n != 1 {
		t.Fatalf("%d audit-unavailable alarms", n)
	}
}

func countAlarms(st *Status, code string) int {
	n := 0
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == code {
			n++
		}
	}
	return n
}

// A refusal is audited as denied with the collector's number and code; a
// missing decision leaves only the info record, so a decision the
// collector made shows as a gap.
func TestRefusalAndNoDecision(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	refuse := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: authz.RefuseRateLimited, Detail: "inside the floor"}, CollectorSeq: 4}}, nil
	}}
	rep := newScheduler(t, r, refuse).RunOnce(bg, 0)
	if !rep.Sent || rep.Decision != authz.ReplyRefused || rep.Alarm != AlarmCollectorRefused {
		t.Fatalf("refused: %+v", rep)
	}
	rr := requestRecords(auditRecords(t, r), rep.RequestID)
	if len(rr) != 2 || rr[1].Outcome != audit.OutcomeDenied || rr[1].ReasonCode != string(authz.RefuseRateLimited) || rr[1].CollectorSeq != 4 {
		t.Fatalf("records: %+v", rr)
	}

	lost := &fakeCollector{answer: func(*authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{}, fmt.Errorf("%w: status %q", collectorclient.ErrProtocol, "maybe")
	}}
	rep = newScheduler(t, r, lost).RunOnce(bg, 0)
	if !rep.Sent || rep.Decision != "" || rep.Alarm != AlarmNoDecision {
		t.Fatalf("no decision: %+v", rep)
	}
	if rr := requestRecords(auditRecords(t, r), rep.RequestID); len(rr) != 1 || rr[0].Outcome != audit.OutcomeInfo {
		t.Fatalf("records: %+v", rr)
	}
	for _, a := range st.Snapshot("x").Alarms {
		if strings.Contains(a.Detail, "maybe") {
			t.Fatalf("status quotes the collector's reply: %q", a.Detail)
		}
	}
	if ht := healthTypes(t, r); count(ht, HealthCollectionRefused) != 1 || count(ht, HealthCollectionNoDecision) != 1 {
		t.Fatalf("health: %v", ht)
	}
}

// An accepted run whose outcome never arrived is audited as allowed and
// recorded as outcome unknown; nothing is normalized.
func TestOutcomeLost(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 9)}, fmt.Errorf("%w: connection closed", collectorclient.ErrOutcomeUnknown)
	}}
	rep := newScheduler(t, r, f).RunOnce(bg, 0)
	if rep.Outcome != "unknown" || rep.Alarm != AlarmOutcomeUnknown || rep.Events != 0 {
		t.Fatalf("%+v", rep)
	}
	if rr := requestRecords(auditRecords(t, r), rep.RequestID); len(rr) != 2 || rr[1].Outcome != audit.OutcomeAllowed || rr[1].CollectorSeq != 9 {
		t.Fatalf("records: %+v", rr)
	}
	if ht := healthTypes(t, r); count(ht, HealthCollectionOutcomeUnknown) != 1 {
		t.Fatalf("health: %v", ht)
	}
}

// The safety case (A3 #82): an outcome with an unauthorized line is kept
// byte for byte on a stream nothing forwards, its session records reach
// the chain, the alarm is raised without quoting the line, and collection
// from the asset stops, across a restart (A6).
func TestUnauthorizedLineQuarantinedAndHaltedDurably(t *testing.T) {
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) {
		nc.AddRELPTarget("central", "127.0.0.1", 2514, "test-ca", "test-client", "test/durable-ack", true)
	})
	r, st, logged := start(t, c, dir)
	frame := []byte(`{"wire":"otsec.collectorwire/0.1","invocation_id":"` + okInvocation + `","result":{"x":"FORBIDDEN-LINE-TEXT"},"audit":[]}`)
	reason := "result: line 7 \"FORBIDDEN-LINE-TEXT\" is not permitted for sel.ser.read_all"
	var recs []collectorclient.PendingRecord
	for _, raw := range sessionRecords(t, 2) {
		rec, _ := audit.ValidatePending(raw)
		recs = append(recs, collectorclient.PendingRecord{Raw: raw, Record: rec})
	}
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 1), Quarantine: &collectorclient.Quarantine{Raw: frame, Reason: reason, UnauthorizedLine: true, Audit: recs}},
			fmt.Errorf("%w: %w: %w: %s", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined, collectorclient.ErrUnauthorizedLine, reason)
	}}
	s := newScheduler(t, r, f)
	rep := s.RunOnce(bg, 0)
	if rep.Outcome != "quarantined" || rep.Alarm != AlarmUnauthorizedLine || rep.Events != 0 {
		t.Fatalf("%+v", rep)
	}
	q, err := r.Store(QuarantineStream(relayID)).Read(bg, QuarantineStream(relayID), 0, 10)
	if err != nil || len(q) != 2 {
		t.Fatalf("quarantine stream: %d records, %v", len(q), err)
	}
	got, err := r.Store(QuarantineStream(relayID)).ReadCapture(bg, q[0].EvidenceRef)
	if err != nil || !bytes.Equal(got.Bytes, frame) {
		t.Fatalf("frame not kept byte for byte: %v", err)
	}
	why, err := r.Store(QuarantineStream(relayID)).ReadCapture(bg, q[1].EvidenceRef)
	if err != nil || string(why.Bytes) != reason {
		t.Fatalf("reason not kept: %v %q", err, why.Bytes)
	}
	cs, _ := c.Consumers()
	for _, x := range cs {
		if x.Stream == QuarantineStream(relayID) {
			t.Fatalf("a target consumes the quarantine: %+v", x)
		}
	}
	var closes int
	for _, a := range auditRecords(t, r) {
		if a.Action == audit.ActionDeviceSessionClose && a.TranscriptSHA256 == okTranscript {
			closes++
		}
	}
	if closes != 1 {
		t.Fatalf("%d session close records in the chain", closes)
	}
	if n, _ := r.Store(SERStream(relayID)).LastCommitted(bg, SERStream(relayID)); n != 0 {
		t.Fatalf("quarantined outcome normalized: %d SER events", n)
	}
	sf, _ := os.ReadFile(filepath.Join(dir, "status.json"))
	if !strings.Contains(string(sf), AlarmUnauthorizedLine) {
		t.Fatalf("status file has no safety alarm:\n%s", sf)
	}
	for _, text := range append([]string{string(sf)}, *logged...) {
		if strings.Contains(text, "FORBIDDEN-LINE-TEXT") {
			t.Fatalf("status or OS log quotes the refused line: %s", text)
		}
	}
	if s.Halted(relayID) == "" || countAlarms(st, AlarmUnauthorizedLine) != 1 {
		t.Fatal("asset not halted")
	}
	if rep := s.RunOnce(bg, 0); rep.Sent || rep.Alarm != AlarmCollectionDisabled || f.n() != 1 {
		t.Fatalf("run after the halt: %+v, %d requests", rep, f.n())
	}

	// Restart: the halt comes back from the quarantine stream.
	r.Close()
	r2, _, _ := start(t, c, dir)
	defer r2.Close()
	s2 := newScheduler(t, r2, f)
	if s2.Halted(relayID) == "" {
		t.Fatal("halt lost across a restart")
	}
	if rep := s2.RunOnce(bg, 0); rep.Sent || f.n() != 1 {
		t.Fatalf("run after restart: %+v, %d requests", rep, f.n())
	}
}

// A quarantine that fails a check other than the lines is kept, recorded as
// outcome unknown, and does not halt the asset.
func TestQuarantineWithoutUnauthorizedLine(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 1), Quarantine: &collectorclient.Quarantine{Raw: []byte("not json"), Reason: "outcome: invalid character"}},
			fmt.Errorf("%w: %w: bad", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined)
	}}
	s := newScheduler(t, r, f)
	if rep := s.RunOnce(bg, 0); rep.Outcome != "quarantined" || rep.Alarm != AlarmOutcomeUnknown {
		t.Fatalf("%+v", rep)
	}
	if s.Halted(relayID) != "" {
		t.Fatal("halted without an unauthorized line")
	}
	if rep := s.RunOnce(bg, 0); !rep.Sent {
		t.Fatalf("second run not sent: %+v", rep)
	}
}

// A result A4's normalizer refuses is quarantined and, like every run,
// ends with exactly one collection health event (A6 #92 nit 4).
func TestNormalizerRefusalEndsWithOneHealthEvent(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 1),
			Outcome: &collectorclient.Outcome{InvocationID: "inv-refused", ResultJSON: []byte(`{}`)}}, nil
	}}
	s := newScheduler(t, r, f)
	if rep := s.RunOnce(bg, 0); rep.Outcome != "quarantined" || rep.Alarm != AlarmResultRefused {
		t.Fatalf("%+v", rep)
	}
	if n, _ := r.Store(QuarantineStream(relayID)).LastCommitted(bg, QuarantineStream(relayID)); n != 2 {
		t.Fatalf("%d quarantine records", n)
	}
	hs, _ := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
	var got []string
	for _, st := range hs {
		if e, _ := event.Decode(st.Event); e.Health != nil && strings.HasPrefix(e.Health.Type, "collection.") {
			got = append(got, e.Health.Type)
		}
	}
	if len(got) != 1 || got[0] != HealthCollectionOutcomeUnknown {
		t.Fatalf("collection health events %v", got)
	}
}

// With less than QuarantineRoom left in adapter-evidence, no run is sent,
// and the alarm is raised once for the condition, not once per run (A6).
func TestNoQuarantineRoomSendsNothing(t *testing.T) {
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) { nc.Store.Quotas["adapter-evidence"] = QuarantineRoom - 1 })
	r, st, _ := start(t, c, dir)
	defer r.Close()
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 1)}, nil
	}}
	s := newScheduler(t, r, f)
	for i := 0; i < 3; i++ {
		if rep := s.RunOnce(bg, 0); rep.Sent || rep.Alarm != AlarmNoQuarantineRoom {
			t.Fatalf("run %d: %+v", i, rep)
		}
	}
	if f.n() != 0 || countAlarms(st, AlarmNoQuarantineRoom) != 1 {
		t.Fatalf("%d requests, %d alarms", f.n(), countAlarms(st, AlarmNoQuarantineRoom))
	}
}

// A quarantine the store refuses stops every run on the node, level 0 included.
func TestQuarantineNotStoredStopsTheNode(t *testing.T) {
	c, dir := schedConfig(t, func(nc *nodeconfigtest.Config) { nc.Store.Quotas["adapter-evidence"] = QuarantineRoom + 1024 })
	r, st, _ := start(t, c, dir)
	defer r.Close()
	big := bytes.Repeat([]byte{'x'}, QuarantineRoom+2048) // larger than any real frame, so the commit is refused
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{Reply: accepted(req, 1), Quarantine: &collectorclient.Quarantine{Raw: big, Reason: "r", UnauthorizedLine: true}},
			fmt.Errorf("%w: %w: %w", collectorclient.ErrOutcomeUnknown, collectorclient.ErrOutcomeQuarantined, collectorclient.ErrUnauthorizedLine)
	}}
	s := newScheduler(t, r, f)
	s.RunOnce(bg, 0)
	if countAlarms(st, AlarmQuarantineNotStored) != 1 || s.Halted(relayID) != AlarmQuarantineNotStored {
		t.Fatalf("node not stopped: %q", s.Halted(relayID))
	}
	if rep := s.RunOnce(bg, 0); rep.Sent || f.n() != 1 {
		t.Fatalf("run after a lost quarantine: %+v", rep)
	}
	var stopped bool
	for _, a := range auditRecords(t, r) {
		stopped = stopped || a.ReasonCode == "quarantine_not_stored"
	}
	if !stopped {
		t.Fatal("no audit record of the stop")
	}
}

// Run waits MinIntervalSeconds before the first run and stops with ctx.
func TestRunWaitsBeforeTheFirstRun(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	f := &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		return collectorclient.Response{}, errors.New("unused")
	}}
	s := newScheduler(t, r, f)
	ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if f.n() != 0 {
		t.Fatalf("%d requests in the first 200 ms after start", f.n())
	}
}

// Tick and the scheduler share the runtime (run under -race).
func TestTickAlongsideRuns(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			r.Tick(bg)
		}
	}()
	for i := 0; i < 3; i++ {
		if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" {
			t.Fatalf("run %d: %+v", i, rep)
		}
	}
	<-done
}

// Two entries for one asset, and a run longer than its interval, still
// leave the device MinIntervalSeconds between sessions; another asset is
// not held back by it (A6 review of #92).
func TestPlanSpacesSessionsPerAsset(t *testing.T) {
	const a, b = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", "7f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f"
	sched := []Collection{
		{ID: "x1", AssetID: a, EverySeconds: 60},
		{ID: "x2", AssetID: a, EverySeconds: 60},
		{ID: "y", AssetID: b, EverySeconds: 60},
	}
	t0 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	p := newPlan(sched, t0)
	min := MinIntervalSeconds * time.Second

	i, at := p.due()
	if i != 0 || !at.Equal(t0.Add(min)) {
		t.Fatalf("first: entry %d at %v", i, at)
	}
	// x1 runs for 90 s, longer than its interval.
	p.done(0, at, at.Add(90*time.Second))
	end := at.Add(90 * time.Second)

	// y, on another asset, is due at once; x2 waits for asset a's quiet time.
	if i, at := p.due(); i != 2 || !at.Equal(t0.Add(min)) {
		t.Fatalf("second: entry %d at %v", i, at)
	}
	p.done(2, end, end.Add(time.Second))
	i, at = p.due()
	if p.sched[i].AssetID != a || at.Before(end.Add(min)) {
		t.Fatalf("asset a polled %v after its last session ended (entry %d)", at.Sub(end), i)
	}
	// Whichever entry of asset a runs, the other waits a full minimum after it.
	p.done(i, at, at.Add(5*time.Second))
	end = at.Add(5 * time.Second)
	for k := 0; k < 3; k++ {
		j, next := p.due()
		if p.sched[j].AssetID == a && next.Before(end.Add(min)) {
			t.Fatalf("entry %d of asset a due %v after the session ended", j, next.Sub(end))
		}
		p.done(j, next, next.Add(time.Second))
		if p.sched[j].AssetID == a {
			end = next.Add(time.Second)
		}
	}
}

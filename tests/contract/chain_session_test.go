package contract

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/syslog"
)

// The C2 to C8 links of the chain. One simulated session, ID then SER, is
// built by A6 from A6's transcription of Figures 7.38 and 10.16, with one
// substitution: both figures print a FID on a branch the register denies
// (R301, R100), so the session's FID is allowedFID, its line checksum
// recomputed. Every other device byte is the transcription's. The session
// is synthetic (evidence class simulated); nothing here is device output.
//
// The links then carry it through the contracts as a Phase 2 node would:
// C2 invocation and result, C4 events, C5 commit, C6 rendering and C8 audit,
// each checked against gtID and gtSER, never against the previous link.

const (
	chainNode       = "site-a6-node-1"
	chainInvocation = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30"
	chainEndpoint   = "port1-telnet"
	chainCred       = "cred_a6a6a6a6"
	chainSerial     = "2007XXXXXXXXXXX" // Figure 10.16 header, as printed
	chainStream     = store.StreamID("a6-chain/ser")
	chainAuditS     = store.StreamID("node/audit")
)

// chainSeg is one send or receive of the session.
type chainSeg struct {
	dir   adapter.Direction
	phase adapter.Phase
	b     string
}

type chainRun struct {
	pkg     *register.Package
	prof    asset.CapabilityProfile
	asset   asset.Asset
	inv     adapter.Invocation
	res     adapter.Result
	idOut   string   // the ID response lines, as sent in the session
	serOut  string   // the SER response lines, as sent in the session
	serRows []string // the 8 row lines, in device order
}

var (
	chainOnce sync.Once
	chainVal  *chainRun
	chainErr  error
)

// chainSession builds the session once for all links.
func chainSession(t *testing.T) *chainRun {
	t.Helper()
	chainOnce.Do(func() { chainVal, chainErr = buildChainSession(t) })
	if chainErr != nil {
		t.Fatal(chainErr)
	}
	return chainVal
}

func buildChainSession(t *testing.T) (*chainRun, error) {
	r := &chainRun{pkg: sel751Package(t)}
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "asset", "testdata", "valid", "profile-sel-751-ascii.json"))
	if err != nil {
		return nil, err
	}
	if r.prof, err = asset.DecodeProfile(b); err != nil {
		return nil, err
	}

	id := readLines(t, "id-fig-7-38.txt")
	fidLine := fmt.Sprintf(`"FID=%s",`, allowedFID)
	id[0] = fidLine + `"` + idChecksum(fidLine+`"0000"`) + `"`
	r.idOut = strings.Join(id, "\r\n")
	ser := readLines(t, "ser-fig-10-16.txt")
	for i, l := range ser {
		ser[i] = strings.Replace(l, "FID = "+gtSERHeader.FID, "FID = "+allowedFID, 1)
		if f := strings.Fields(l); len(f) == 5 && f[0] != "#" && strings.Count(f[1], "/") == 2 {
			r.serRows = append(r.serRows, l)
		}
	}
	r.serOut = strings.Join(ser, "\r\n")
	hdr := ser[0] + "\r\n" + ser[1] + "\r\n"

	segs := []chainSeg{
		{adapter.Received, adapter.PhaseProbe, "\r\n="},
		{adapter.Sent, adapter.PhaseProbe, "QUI\r\n"},
		{adapter.Received, adapter.PhaseProbe, "QUI\r\n\x02" + hdr + "\x03="},
		{adapter.Sent, adapter.PhaseProbe, "ID\r\n"},
		{adapter.Received, adapter.PhaseProbe, "ID\r\n\x02" + r.idOut + "\r\n\x03="},
		{adapter.Sent, adapter.PhaseAuth, "ACC\r\n"},
		{adapter.Received, adapter.PhaseAuth, "ACC\r\nPassword: ?"},
		{adapter.Sent, adapter.PhaseAuth, adapter.RedactionMarker + "\r\n"},
		{adapter.Received, adapter.PhaseAuth, "\r\n\x02" + hdr + "\r\nLevel 1\r\n\x03=>"},
		{adapter.Sent, adapter.PhaseOperate, "SER\r\n"},
		{adapter.Received, adapter.PhaseOperate, "SER\r\n\x02" + r.serOut + "\r\n\x03=>"},
		{adapter.Sent, adapter.PhaseClose, "QUI\r\n"},
	}
	var tr adapter.Transcript
	var data []byte
	for i, s := range segs {
		off := int64(len(data))
		data = append(data, s.b...)
		tr.Segments = append(tr.Segments, adapter.Segment{Offset: off, Length: int64(len(s.b)), Dir: s.dir, Phase: s.phase,
			At: fmt.Sprintf("2026-10-24T12:00:%02d.%03dZ", i/4, 100*(i%4)+5)})
		if s.b == adapter.RedactionMarker+"\r\n" {
			tr.Redactions = append(tr.Redactions, adapter.Redaction{Offset: off, Length: int64(len(adapter.RedactionMarker)),
				Reason: adapter.RedactCredential, Component: "transport"})
		}
	}
	sum := sha256.Sum256(data)
	tr.Data, tr.SHA256 = data, hex.EncodeToString(sum[:])
	at := func(sub string, from int) adapter.Span {
		i := strings.Index(string(data[from:]), sub)
		if i < 0 {
			t.Fatalf("%q not in the transcript", sub)
		}
		return adapter.Span{Offset: int64(from + i), Length: int64(len(sub))}
	}
	serStart := int(tr.Segments[10].Offset)
	ctxStart := at(ser[0], serStart).Offset
	colHdr := at("#        DATE", serStart)
	ctx := adapter.Span{Offset: ctxStart, Length: colHdr.Offset + int64(len(ser[6])) - ctxStart}

	r.res = adapter.Result{
		Schema: "otsec.adapter/0.1", InvocationID: chainInvocation, OperationID: "sel.ser.read_all",
		Adapter:         adapter.AdapterRef{ID: "a6-chain", Version: "0.1.0-a6"},
		RegisterVersion: r.pkg.Revision, Target: asset.Simulated, Status: adapter.StatusOK,
		StartedAt: "2026-10-24T12:00:00.000Z", EndedAt: "2026-10-24T12:00:03.000Z",
		Transcript: tr,
		Session: adapter.SessionFacts{Connected: true, LanguageProbe: adapter.ProbeAccepted, PasswordPrompt: true,
			CredentialSent: true, EchoScan: adapter.EchoScanPerformed, AccessLevel: "1", QuitSent: true},
		Identity: adapter.IdentityCheck{Result: adapter.IdentityMatch, Items: []adapter.IdentityItem{
			{Name: "firmware_id", Expected: allowedFID, Observed: allowedFID, Span: at(allowedFID, int(tr.Segments[4].Offset))},
			{Name: "serial_number", Expected: chainSerial, Observed: chainSerial, Span: at(chainSerial, serStart)},
		}},
	}
	for _, row := range r.serRows {
		f := strings.Fields(row)
		r.res.Records = append(r.res.Records, adapter.Record{Kind: "sel.ser.row", Span: at(row, serStart), ContextSpan: &ctx, ParseOK: true,
			Fields: []adapter.Field{{Name: "#", Value: f[0]}, {Name: "DATE", Value: f[1]}, {Name: "TIME", Value: f[2]},
				{Name: "ELEMENT", Value: f[3]}, {Name: "STATE", Value: f[4]}}})
	}

	declared := func(name, value string) asset.Attribute {
		return asset.Attribute{Name: name, Value: value, Confidence: asset.Confidence("single-source"),
			Observations: []asset.Observation{{Value: value, EvidenceClass: asset.EvidenceClass("operator-declared"),
				Source: asset.Source{Method: asset.SourceMethod("operator-entry"), Ref: "operator:a6-chain", ObservedAt: "2026-10-24T11:00:00Z"}}}}
	}
	r.asset = asset.Asset{
		Schema: "otsec.asset/0.1", AssetID: chainAsset, NodeID: chainNode,
		Attributes: []asset.Attribute{
			declared("device_class", "protective-relay"), declared("vendor", "sel"), declared("product_family", "sel-751"),
			declared("firmware_id", allowedFID), declared("serial_number", chainSerial), declared("ip_address", "192.0.2.61"),
		},
		Endpoints: []asset.Endpoint{{ID: chainEndpoint, Transport: asset.Transport("telnet"), Host: "192.0.2.61", Port: 23, Target: asset.Simulated,
			DownstreamSecurity: asset.DownstreamSecurity{Level: asset.SecurityLevel("plaintext-unauthenticated"),
				Acknowledgement: &asset.Acknowledgement{By: "admin:a6", At: "2026-10-24T11:00:00Z", Reason: "A6 chain test, simulated, lab only", Scope: asset.AckScope("lab-only")}}}},
		IdentityBinding: asset.IdentityBinding{Method: asset.BindingMethod("device-reported"), Strength: asset.BindingStrength("spoofable"),
			Attributes: []string{"firmware_id", "serial_number"}, PreCredential: []string{"firmware_id"}},
		Profile: &asset.ProfileRef{ID: r.prof.ProfileID, Version: r.prof.Version},
	}
	inv := fmt.Sprintf(`{"schema":"otsec.adapter/0.1","invocation_id":%q,"requested_at":"2026-10-24T11:59:59Z",
"principal_ref":"sch-a6","asset_id":%q,"endpoint_id":%q,"profile_id":%q,"operation_id":"sel.ser.read_all",
"credential_ref":%q,"expected_identity":[{"name":"firmware_id","value":%q},{"name":"serial_number","value":%q}],
"limits":{"connect_timeout_ms":5000,"step_timeout_ms":10000,"deadline_ms":60000,"max_response_bytes":131072,"connect_retries":0,"min_interval_ms":60000}}`,
		chainInvocation, chainAsset, chainEndpoint, r.prof.ProfileID, chainCred, allowedFID, chainSerial)
	if r.inv, err = adapter.DecodeInvocation([]byte(inv)); err != nil {
		return nil, fmt.Errorf("chain invocation: %w", err)
	}
	return r, nil
}

func chainC2Invocation(t *testing.T) {
	r := chainSession(t)
	m, err := register.NewMatcher(r.pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.asset.Validate(); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if err := r.inv.ValidateWith(adapter.RegisterLookup{M: m}); err != nil {
		t.Errorf("invocation against the register: %v", err)
	}
	if err := r.inv.CheckAgainst(r.asset, r.prof); err != nil {
		t.Errorf("invocation against the asset and profile: %v", err)
	}
	if _, err := r.pkg.Firmware.Decide(r.inv.Expected[0].Value); err != nil {
		t.Errorf("declared FID: %v", err)
	}
	if r.inv.OperationID != "sel.ser.read_all" || r.inv.AssetID != chainAsset || r.inv.Limits.MinIntervalMS < r.prof.SessionLimits.MinIntervalMS {
		t.Errorf("invocation shape: %+v", r.inv)
	}
	// The C7 request that authorizes it names the same asset and operation.
	if !strings.Contains(c7Run, `"asset_id": "`+r.inv.AssetID+`"`) || !strings.Contains(c7Run, `"operation_id": "`+r.inv.OperationID+`"`) ||
		!strings.Contains(c7Run, `"credential_ref": "`+r.inv.CredentialRef+`"`) {
		t.Error("the invocation is not the one the C7 run asks for")
	}
}

func chainC2Result(t *testing.T) {
	r := chainSession(t)
	b, err := json.Marshal(r.res)
	if err != nil {
		t.Fatal(err)
	}
	got, err := adapter.DecodeResult(b)
	if err != nil {
		t.Fatalf("result: %v", err)
	}
	if err := got.CheckLines(r.pkg, r.inv); err != nil {
		t.Errorf("lines against the register: %v", err)
	}
	// D1-24: the result's target is the endpoint's; a simulator session
	// reported as a device read is refused.
	if err := got.CheckAgainst(r.inv, r.asset); err != nil {
		t.Errorf("result against the invocation and asset: %v", err)
	}
	claimed := got
	claimed.Target = asset.DeviceObserved
	if claimed.CheckAgainst(r.inv, r.asset) == nil {
		t.Error("a simulated session reported as device-observed passed CheckAgainst")
	}
	if string(got.Transcript.Data) != string(r.res.Transcript.Data) {
		t.Fatal("transcript bytes changed through JSON")
	}
	d := string(got.Transcript.Data)
	// Every ground-truth ID field and SER row is in the received bytes, and
	// each record's span is exactly its row.
	for _, f := range gtID[1:] {
		if !strings.Contains(d, fmt.Sprintf(`"%s=%s","%s"`, f.Field, f.Value, f.Checksum)) {
			t.Errorf("ID field %s not in the transcript as transcribed", f.Field)
		}
	}
	if len(got.Records) != len(gtSER) {
		t.Fatalf("%d records, want %d", len(got.Records), len(gtSER))
	}
	for i, want := range gtSER {
		rec := got.Records[i]
		row := d[rec.Span.Offset : rec.Span.Offset+rec.Span.Length]
		if f := strings.Fields(row); len(f) != 5 || f[0] != want.Row || f[1] != want.Date || f[2] != want.Time || f[3] != want.Element || f[4] != want.State {
			t.Errorf("record %d spans %q, want row %+v", i, row, want)
		}
		for j, name := range adapter.RecordFields[rec.Kind] {
			if rec.Fields[j].Name != name {
				t.Errorf("record %d field %d is %q, want %q", i, j, rec.Fields[j].Name, name)
			}
		}
	}
}

// chainEvents builds the C4 events of the SER read, pending (seq 0), in
// device order. Only the contracts' rules are used: C2 ReceivedAt for
// received.utc, C4 Align for alignment, C4's alignment_key definition.
func chainEvents(t *testing.T, r *chainRun) [][]byte {
	t.Helper()
	d := r.res.Transcript.Data
	keys := make([]string, len(r.res.Records))
	for i, rec := range r.res.Records {
		row := string(d[rec.Span.Offset : rec.Span.Offset+rec.Span.Length])
		k := sha256.Sum256([]byte(row[strings.Index(row, rec.Fields[1].Value):]))
		keys[i] = "sha256:" + hex.EncodeToString(k[:])
	}
	al, err := event.Align(nil, keys)
	if err != nil || al.Status != event.AlignStatusFirstRead || len(al.Added) != len(keys) {
		t.Fatalf("align: %+v %v", al, err)
	}
	var out [][]byte
	for _, i := range al.Added {
		rec := r.res.Records[i]
		row := d[rec.Span.Offset : rec.Span.Offset+rec.Span.Length]
		rs := sha256.Sum256(row)
		date := strings.Index(string(row), rec.Fields[1].Value)
		tm := strings.Index(string(row), rec.Fields[2].Value) + len(rec.Fields[2].Value)
		native := string(row[date:tm])
		dt := rec.Fields[1].Value
		wall := fmt.Sprintf("%s-%s-%sT%s", dt[6:10], dt[0:2], dt[3:5], rec.Fields[2].Value)
		e := map[string]any{
			"schema": "otsec.event/0.1",
			"id":     map[string]any{"node_id": chainNode, "stream": string(chainStream), "seq": 0},
			"origin": "device", "kind": "ser",
			"source": map[string]any{
				"asset":          map[string]any{"id": chainAsset, "binding": map[string]any{"method": "adapter-target", "confidence": "configured"}},
				"origin_auth":    "session",
				"evidence_class": string(r.res.Target),
			},
			"collection": map[string]any{"method": "adapter-poll", "invocation_id": r.res.InvocationID, "operation_id": r.res.OperationID,
				"parser": map[string]any{"name": "a6-chain-ser", "version": "0.1"}, "native_position": rec.Fields[0].Value,
				"alignment": "first-read", "parse_status": "ok"},
			"received": map[string]any{"utc": r.res.Transcript.ReceivedAt(rec.Span), "resolution_ns": 1000000,
				"clock": map[string]any{"sync": "synchronized", "source": "ntp"}},
			"device_time": map[string]any{"native": native, "native_encoding": "text", "format": "sel-ascii-ser-row",
				"wall_clock": wall, "offset": "unknown", "offset_basis": "none", "resolution_ns": 1000000,
				"quality": map[string]any{"time_source": gtSERHeader.TimeSource, "sync": "unknown", "accuracy_relative_ns": 1000000, "scope": "report"},
				"flags":   []string{"date-format-assumed:MDY"}},
			"native": map[string]any{"bytes": row, "record_sha256": hex.EncodeToString(rs[:]), "record_length": len(row),
				"evidence":      map[string]any{"sha256": r.res.Transcript.SHA256, "length": len(d), "ref": store.EvidenceRef(r.res.Transcript.SHA256)},
				"span":          map[string]any{"offset": rec.Span.Offset, "length": rec.Span.Length},
				"context_span":  map[string]any{"offset": rec.ContextSpan.Offset, "length": rec.ContextSpan.Length},
				"alignment_key": keys[i], "fields": rec.Fields},
			"normalized": map[string]any{"subject": rec.Fields[3].Value, "subject_type": "ser-element", "value": rec.Fields[4].Value, "category": "unmapped"},
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

func chainC4(t *testing.T) {
	r := chainSession(t)
	evs := chainEvents(t, r)
	if len(evs) != len(gtSER) {
		t.Fatalf("%d events, want %d", len(evs), len(gtSER))
	}
	for i, b := range evs {
		var e event.Event
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		if err := e.ValidatePending(); err != nil {
			t.Errorf("event %d: %v", i, err)
			continue
		}
		want := gtSER[i]
		if e.Collection.NativePosition != want.Row || e.Normalized.Subject != want.Element || e.Normalized.Value != want.State {
			t.Errorf("event %d: row %s %s %s, want %+v", i, e.Collection.NativePosition, e.Normalized.Subject, e.Normalized.Value, want)
		}
		if !strings.HasPrefix(e.DeviceTime.Native, want.Date) || !strings.HasSuffix(e.DeviceTime.Native, want.Time) {
			t.Errorf("event %d: native time %q, want %s … %s", i, e.DeviceTime.Native, want.Date, want.Time)
		}
		if !strings.HasSuffix(e.DeviceTime.WallClock, want.Time) || e.DeviceTime.ResolutionNS != 1000000 || e.DeviceTime.Offset != "unknown" {
			t.Errorf("event %d: device time %+v", i, e.DeviceTime)
		}
		if !e.Source.Simulated() {
			t.Errorf("event %d does not say it is simulated", i)
		}
		// D1-25: native.fields are named as the device prints its columns.
		var names []string
		for _, f := range e.Native.Fields {
			names = append(names, f.Name)
		}
		if !slices.Equal(names, gtSERColumns) {
			t.Errorf("event %d: native.fields %q, Figure 10.16 heading %q", i, names, gtSERColumns)
		}
	}
}

// chainCommitter is A6's in-memory Committer: it assigns seqs, writes the
// seq into each event (C5 Record.Event), seals audit records with SealAudit
// and keeps the stored bytes. It records each commit before returning.
type chainCommitter struct {
	mu     sync.Mutex
	next   map[store.StreamID]store.Seq
	stored map[store.StreamID][][]byte
	head   store.ChainLink
}

func (c *chainCommitter) CommitBatch(_ context.Context, s store.StreamID, recs []store.Record) (store.Commit, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next[s] == 0 {
		c.next[s] = 1
	}
	first := c.next[s]
	if recs[0].Class == store.ClassAudit {
		sealed, head, err := store.SealAudit(c.head, recs)
		if err != nil {
			return store.Commit{}, err
		}
		c.stored[s], c.head = append(c.stored[s], sealed...), head
	} else {
		for i, rec := range recs {
			var e event.Event
			if err := json.Unmarshal(rec.Event, &e); err != nil {
				return store.Commit{}, &store.Error{Code: store.CodeInvalid, Err: err}
			}
			e.ID.Seq = uint64(first) + uint64(i)
			b, err := json.Marshal(e)
			if err != nil {
				return store.Commit{}, &store.Error{Code: store.CodeInvalid, Err: err}
			}
			c.stored[s] = append(c.stored[s], b)
		}
	}
	c.next[s] += store.Seq(len(recs))
	return store.Commit{Node: chainNode, Stream: s, FirstSeq: first, Count: len(recs), Sync: store.SyncFull, At: time.Now()}, nil
}

var (
	chainStoreOnce sync.Once
	chainStore     *chainCommitter
	chainReceipts  []store.Receipt
	chainStoreErr  error
)

// chainCommit appends the audit records and the events through one Log.
func chainCommit(t *testing.T) (*chainCommitter, []store.Receipt) {
	t.Helper()
	r := chainSession(t)
	chainStoreOnce.Do(func() {
		c := &chainCommitter{next: map[store.StreamID]store.Seq{}, stored: map[store.StreamID][][]byte{}, head: store.GenesisLink(chainNode)}
		l, err := store.NewLog(c, chainNode, map[store.StreamID]store.StreamClass{chainStream: store.ClassAdapterEvidence, chainAuditS: store.ClassAudit},
			store.GroupOptions{MaxEvents: 8, MaxWait: 5 * time.Millisecond}, nil)
		if err != nil {
			chainStoreErr = err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		audit := func(rec []byte) error {
			_, err := l.Append(ctx, store.Record{Stream: chainAuditS, Class: store.ClassAudit, Event: rec})
			return err
		}
		recs := chainAuditRecords(r)
		for _, a := range recs[:4] {
			if chainStoreErr = audit(a); chainStoreErr != nil {
				return
			}
		}
		// The read is committed, then the session's last records.
		var batch []store.Record
		for _, e := range chainEvents(t, r) {
			batch = append(batch, store.Record{Stream: chainStream, Class: store.ClassAdapterEvidence, Event: e})
		}
		if chainReceipts, chainStoreErr = l.AppendBatch(ctx, batch); chainStoreErr != nil {
			return
		}
		for _, a := range recs[4:] {
			if chainStoreErr = audit(a); chainStoreErr != nil {
				return
			}
		}
		chainStore = c
	})
	if chainStoreErr != nil {
		t.Fatal(chainStoreErr)
	}
	return chainStore, chainReceipts
}

func chainC5(t *testing.T) {
	c, rs := chainCommit(t)
	stored := c.stored[chainStream]
	if len(rs) != len(gtSER) || len(stored) != len(gtSER) {
		t.Fatalf("%d receipts, %d stored, want %d", len(rs), len(stored), len(gtSER))
	}
	for i, rc := range rs {
		if rc.Key().Stream != chainStream || uint64(rc.Key().Seq) != uint64(i+1) {
			t.Errorf("receipt %d: %+v", i, rc.Key())
		}
		e, err := event.Decode(stored[i])
		if err != nil {
			t.Errorf("stored event %d: %v", i, err)
			continue
		}
		if e.ID.Seq != uint64(i+1) || e.ID.NodeID != chainNode || e.Collection.NativePosition != gtSER[i].Row {
			t.Errorf("stored event %d: id %+v row %s", i, e.ID, e.Collection.NativePosition)
		}
	}
}

const chainTarget = `{
  "schema": "otsec.syslog/0.1", "name": "a6-chain", "host": "collector.a6.example", "port": 2514,
  "transport": "relp-tls", "format": "rfc5424", "framing": "relp", "class": "required",
  "max_message_octets": 8192, "facility": 13,
  "tls": {"server_name": "collector.a6.example", "trust_anchor_ref": "a6-ca", "client_credential_ref": "a6-node-forwarder"},
  "relp_window": 64,
  "durable_ack": {"verified_utc": "2026-10-24T10:00:00Z", "evidence_ref": "commissioning/a6-chain/kill-test", "peer_check": "name", "permitted_peer": "a6-node", "ack_after": "durable-write"}
}`

func chainC6(t *testing.T) {
	c, _ := chainCommit(t)
	tg, err := syslog.ParseTarget([]byte(chainTarget))
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range c.stored[chainStream] {
		e, err := event.Decode(b)
		if err != nil {
			t.Fatal(err)
		}
		msg, _, err := syslog.Render(e, tg)
		if err != nil {
			t.Errorf("event %d: %v", i, err)
			continue
		}
		if err := syslog.CheckMessage(msg, tg); err != nil {
			t.Errorf("event %d: rendered message fails its own check: %v", i, err)
		}
		m, err := syslog.ParseMessage(msg)
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		want := gtSER[i]
		for name, v := range map[string]string{"eid": e.ID.String(), "pos": want.Row, "inv": chainInvocation, "op": "sel.ser.read_all",
			"evc": "simulated", "dt": e.DeviceTime.Native, "subj": want.Element, "val": want.State} {
			if got, ok := m.Get(name); !ok || got != v {
				t.Errorf("event %d: %s=%q, want %q", i, name, got, v)
			}
		}
		if txt, ok := m.DeviceText(); !ok || !strings.Contains(string(txt), want.Date) || !strings.Contains(string(txt), want.Time) || !strings.Contains(string(txt), want.Element) {
			t.Errorf("event %d: device text %q does not carry row %s", i, txt, want.Row)
		}
	}
}

// chainAuditRecords are the pending C8 records of the session, in order:
// four before the read (chain start, the C7 request, session open,
// credential use) and two after it (the operation and session close, which
// carries the transcript digest, D1-25).
func chainAuditRecords(r *chainRun) [][]byte {
	sent := sha256.Sum256(sentBytes(r.res.Transcript))
	common := func(i int, action, outcome, extra string) []byte {
		return []byte(fmt.Sprintf(`{"contract":"otsec.audit/0.1","node_id":%q,`+
			`"time":{"utc":"2026-10-24T12:00:0%d.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},`+
			`"actor":{"type":"schedule","id":"sch-a6"},"action":%q,"outcome":%q%s}`, chainNode, i, action, outcome, extra))
	}
	target := fmt.Sprintf(`,"target":{"asset_id":%q,"transport":"telnet","downstream_security":"plaintext-unauthenticated","credential_ref":%q,"credential_version":1,"family":"sel-751"}`, chainAsset, chainCred)
	inv := fmt.Sprintf(`,"operation_id":"sel.ser.read_all","register_revision":%d,"correlation_id":%q`, r.pkg.Revision, chainInvocation)
	return [][]byte{
		[]byte(fmt.Sprintf(`{"contract":"otsec.audit/0.1","node_id":%q,"time":{"utc":"2026-10-24T11:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},"actor":{"type":"system","id":"node"},"action":"audit.chain.start","outcome":"info"}`, chainNode)),
		common(0, "collector.request", "allowed", target+`,"operation_id":"sel.ser.read_all","correlation_id":"req-a6-0001","collector_seq":1`),
		common(0, "device.session.open", "succeeded", target+inv+`,"collector_seq":2`),
		common(1, "credential.use", "succeeded", target+inv+`,"collector_seq":3`),
		common(2, "device.op", "succeeded", target+inv+fmt.Sprintf(`,"bytes_sent_digest":"sha256:%s","collector_seq":4`, hex.EncodeToString(sent[:]))),
		// The close carries the stored transcript's digest (D1-25).
		common(3, "device.session.close", "succeeded", target+inv+fmt.Sprintf(`,"transcript_sha256":%q,"collector_seq":5`, r.res.Transcript.SHA256)),
	}
}

func sentBytes(t adapter.Transcript) []byte {
	var b []byte
	for _, s := range t.Segments {
		if s.Dir == adapter.Sent {
			b = append(b, t.Data[s.Offset:s.Offset+s.Length]...)
		}
	}
	return b
}

func chainC8(t *testing.T) {
	r := chainSession(t)
	c, _ := chainCommit(t)
	stored := c.stored[chainAuditS]
	head := &audit.Checkpoint{NodeID: chainNode, Seq: c.head.Seq, Hash: c.head.Hash}
	if err := audit.VerifyChain(chainNode, stored, nil, head); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
	var recs []*audit.Record
	inInvocation := 0
	for i, b := range stored {
		rec, err := audit.ParseRecord(b)
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		recs = append(recs, rec)
		if rec.CorrelationID == chainInvocation {
			inInvocation++
			if rec.Target == nil || rec.Target.AssetID != chainAsset || rec.OperationID != "sel.ser.read_all" || rec.Actor.ID != "sch-a6" {
				t.Errorf("record %d (%s) does not name the principal, operation and asset", i, rec.Action)
			}
		}
		// No secret and no raw device output: the transcript's text does
		// not appear in any audit record.
		for _, s := range []string{adapter.RedactionMarker, allowedFID, gtSER[0].Element + " ", "Password"} {
			if strings.Contains(string(b), s) {
				t.Errorf("record %d carries %q", i, s)
			}
		}
		// C8 time is C4's Received type.
		var _ event.Received = rec.Time
	}
	// D1-25: the session close carries the digest of the stored
	// transcript. A6 hashes the transcript bytes itself, not the C2 field.
	stx := sha256.Sum256(r.res.Transcript.Data)
	closes := 0
	for i, rec := range recs {
		if rec.Action != audit.ActionDeviceSessionClose {
			if rec.TranscriptSHA256 != "" {
				t.Errorf("record %d (%s) carries transcript_sha256", i, rec.Action)
			}
			continue
		}
		closes++
		if rec.TranscriptSHA256 != hex.EncodeToString(stx[:]) {
			t.Errorf("session close transcript_sha256 %s, A6 hash of the stored transcript %x", rec.TranscriptSHA256, stx)
		}
		// The chain covers the digest: a changed digest breaks it.
		forged := append([][]byte(nil), stored...)
		forged[i] = []byte(strings.Replace(string(stored[i]), rec.TranscriptSHA256, strings.Repeat("0", 64), 1))
		if audit.VerifyChain(chainNode, forged, nil, head) == nil {
			t.Error("a session close with a replaced transcript_sha256 still verifies")
		}
	}
	if closes != 1 {
		t.Errorf("%d session-close records, want 1", closes)
	}
	if inInvocation != 4 {
		t.Errorf("%d records correlate with invocation %s, want 4 (open, credential, op, close)", inInvocation, chainInvocation)
	}
	if err := audit.VerifyCollectorSeq(recs, 0, 5); err != nil {
		t.Errorf("collector seq: %v", err)
	}
}

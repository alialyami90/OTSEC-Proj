package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/config"
	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// Invocation IDs of the identity tests' runs.
const (
	invA = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a3a"
	invB = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a3b"
	invC = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a3c"
	invD = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a3d"
)

// identityConfig is schedConfig's node with asset on and room in the
// configuration class.
func identityConfig(t *testing.T, mod func(*nodeconfigtest.Config)) (*Config, string) {
	return schedConfig(t, func(nc *nodeconfigtest.Config) {
		nc.Asset = &struct{}{}
		nc.Store.Quotas["configuration"] = 8 << 20
		if mod != nil {
			mod(nc)
		}
	})
}

// okRun is figureOrder's result as run inv, with change applied to it.
func okRun(t *testing.T, inv string, change func(*adapter.Result)) *collectorclient.Outcome {
	t.Helper()
	b, _ := figureOrder(t)
	res, err := adapter.DecodeResult(b)
	if err != nil {
		t.Fatal(err)
	}
	res.InvocationID = inv
	if change != nil {
		change(&res)
		sum := sha256.Sum256(res.Transcript.Data)
		res.Transcript.SHA256 = hex.EncodeToString(sum[:])
	}
	b, err = json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	return &collectorclient.Outcome{InvocationID: inv, Result: res, ResultJSON: b}
}

// answering is a collector that answers each run with the next outcome.
func answering(outs ...*collectorclient.Outcome) *fakeCollector {
	n := uint64(0)
	return &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		o := outs[0]
		if len(outs) > 1 {
			outs = outs[1:]
		}
		n++
		reply := accepted(req, n)
		reply.InvocationID = o.InvocationID
		return collectorclient.Response{Reply: reply, Outcome: o}, nil
	}}
}

// identityRecords are the identity documents and the identity.read
// documents in the asset's configuration stream, in order.
func identityRecords(t *testing.T, r *Runtime, assetID string) (ids []c5.Stored, reads []identityReadDoc) {
	t.Helper()
	db := r.Store(ConfigStream(assetID))
	if db == nil {
		return nil, nil // no configuration database
	}
	got, err := db.Read(bg, ConfigStream(assetID), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range got {
		switch {
		case bytes.HasPrefix(st.Event, []byte(`{"schema":"`+IdentitySchema)):
			ids = append(ids, st)
		case bytes.HasPrefix(st.Event, []byte(`{"schema":"`+IdentityReadSchema)):
			d, err := decodeIdentityRead(st.Event)
			if err != nil {
				t.Fatal(err)
			}
			reads = append(reads, d)
		}
	}
	return ids, reads
}

func storedIdentity(t *testing.T, r *Runtime, st c5.Stored) identityDoc {
	t.Helper()
	var capture *c5.Capture
	if st.EvidenceRef != "" {
		c, err := r.Store(ConfigStream(relayID)).ReadCapture(bg, st.EvidenceRef)
		if err != nil {
			t.Fatal(err)
		}
		capture = &c
	}
	d, err := decodeIdentity(st.Event, capture)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// changeCID gives the run another sel.cid, in its transcript too.
func changeCID(res *adapter.Result) {
	for i, o := range res.Observations {
		if o.Name == "sel.cid" {
			res.Observations[i].Value = "E755"
			data := bytes.Clone(res.Transcript.Data)
			copy(data[o.Span.Offset:], "E755")
			res.Transcript.Data = data
		}
	}
}

// An identity record is stored at the first read and on a change only; a
// run that reads the same identity stores only an identity.read, and the
// older ones are removed. A change keeps each unchanged value's first read
// and its bytes, names the previous record, and raises identity-changed. A
// restart reads the records back into status.
func TestIdentityStoredOnChangeOnly(t *testing.T) {
	c, dir := identityConfig(t, nil)
	r, st, _ := start(t, c, dir)
	s := newScheduler(t, r, answering(okRun(t, invA, nil), okRun(t, invB, nil), okRun(t, invC, changeCID)))

	if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Alarm != "" {
		t.Fatalf("first run: %+v", rep)
	}
	ids, reads := identityRecords(t, r, relayID)
	if len(ids) != 1 || len(reads) != 1 || reads[0].InvocationID != invA {
		t.Fatalf("after the first run: %d identity records, reads %+v", len(ids), reads)
	}
	first := storedIdentity(t, r, ids[0])
	if first.InvocationID != invA || first.Previous != "" {
		t.Fatalf("first record: %+v", first)
	}
	if m, ok := first.Asset.Attribute(c1.AttrModel); !ok || m.Value != "SEL-751" || m.Observations[0].Source.Kind != c1.DeviceRead {
		t.Fatalf("model: %+v", m)
	}

	s.RunOnce(bg, 0)
	ids, reads = identityRecords(t, r, relayID)
	if len(ids) != 1 || len(reads) != 1 || reads[0].InvocationID != invB {
		t.Fatalf("after the same identity again: %d identity records, reads %+v", len(ids), reads)
	}
	is := st.Snapshot("x").Identity[relayID]
	if is.EvidenceID != invA || is.LastRead == nil || is.LastRead.InvocationID != invB || is.ReadsRemoved != 1 {
		t.Fatalf("status: %+v", is)
	}
	if countAlarms(st, AlarmIdentityChanged) != 0 {
		t.Fatal("identity-changed raised for the same identity")
	}

	s.RunOnce(bg, 0)
	ids, reads = identityRecords(t, r, relayID)
	if len(ids) != 2 || len(reads) != 1 || reads[0].InvocationID != invC {
		t.Fatalf("after a change: %d identity records, reads %+v", len(ids), reads)
	}
	second := storedIdentity(t, r, ids[1])
	if second.InvocationID != invC || second.Previous != digest(ids[0].Event) {
		t.Fatalf("second record: invocation %s previous %s", second.InvocationID, second.Previous)
	}
	cid, _ := second.Asset.Attribute("sel.cid")
	fid, _ := second.Asset.Attribute(c1.AttrFirmwareID)
	if cid.Observations[0].Source.Ref != invC || fid.Observations[len(fid.Observations)-1].Source.Ref != invA {
		t.Fatalf("refs: cid %+v fid %+v", cid.Observations, fid.Observations)
	}
	if countAlarms(st, AlarmIdentityChanged) != 1 {
		t.Fatalf("%d identity-changed alarms", countAlarms(st, AlarmIdentityChanged))
	}
	var changed int
	for _, typ := range healthTypes(t, r) {
		if typ == HealthIdentityChanged {
			changed++
		}
	}
	if changed != 1 {
		t.Fatalf("%d identity.changed events", changed)
	}
	r.Close()

	r, st, _ = start(t, c, dir)
	defer r.Close()
	newScheduler(t, r, answering(okRun(t, invD, nil)))
	is = st.Snapshot("x").Identity[relayID]
	if is.EvidenceID != invC || is.LastRead == nil || is.LastRead.InvocationID != invC || len(is.Attributes) == 0 {
		t.Fatalf("status after a restart: %+v", is)
	}
}

// With asset off, no identity record is written and status has no identity
// lines; a run that did not collect stores none either.
func TestIdentityNotStored(t *testing.T) {
	t.Run("asset off", func(t *testing.T) {
		c, dir := schedConfig(t, nil)
		r, st, _ := start(t, c, dir)
		defer r.Close()
		s := newScheduler(t, r, answering(okRun(t, invA, nil)))
		if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" {
			t.Fatalf("%+v", rep)
		}
		if ids, reads := identityRecords(t, r, relayID); len(ids)+len(reads) != 0 {
			t.Fatalf("%d identity records, %d reads", len(ids), len(reads))
		}
		if f := st.Snapshot("x"); f.Identity != nil {
			t.Fatalf("identity in status: %+v", f.Identity)
		}
	})
	t.Run("failed run", func(t *testing.T) {
		c, dir := identityConfig(t, nil)
		r, _, _ := start(t, c, dir)
		defer r.Close()
		o := okRun(t, invA, func(res *adapter.Result) {
			res.Status, res.Error, res.Records = adapter.StatusFailed, &adapter.Error{Code: adapter.FailedTimeout, Detail: "read timed out"}, nil
		})
		s := newScheduler(t, r, answering(o))
		if rep := s.RunOnce(bg, 0); rep.Code != adapter.FailedTimeout {
			t.Fatalf("%+v", rep)
		}
		if ids, reads := identityRecords(t, r, relayID); len(ids)+len(reads) != 0 {
			t.Fatalf("%d identity records, %d reads", len(ids), len(reads))
		}
	})
}

// ConfigDocuments takes the two documents into their series and refuses
// what C5 0.8 section 7 lists.
func TestIdentityDocuments(t *testing.T) {
	c, dir := identityConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	newScheduler(t, r, answering(okRun(t, invA, nil))).RunOnce(bg, 0)
	ids, _ := identityRecords(t, r, relayID)
	doc := ids[0].Event
	capture, err := r.Store(ConfigStream(relayID)).ReadCapture(bg, ids[0].EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := ConfigDocuments(doc, &capture); err != nil || info.Kind != c5.DocumentEvidence || info.Series != c5.SeriesIdentity {
		t.Fatalf("identity record: %+v %v", info, err)
	}
	rd, _ := json.Marshal(identityReadDoc{Schema: IdentityReadSchema, AssetID: relayID, InvocationID: invA, ReadAt: "2026-10-24T09:15:01.8Z"})
	if info, err := ConfigDocuments(rd, nil); err != nil || info.Kind != c5.DocumentWorkingState || info.Series != c5.SeriesIdentityRead {
		t.Fatalf("identity read: %+v %v", info, err)
	}
	short := capture.Bytes[:len(capture.Bytes)-1]
	var d identityDoc
	json.Unmarshal(doc, &d)
	d.Pieces[len(d.Pieces)-1].Length--
	uncovered, _ := json.Marshal(d)
	big := bytes.Repeat([]byte("x"), int(MaxIdentityRecordBytes))
	for _, tc := range []struct {
		name    string
		doc     []byte
		capture *c5.Capture
		want    string
	}{
		{"over 64 KiB", doc, &c5.Capture{SHA256: digest(big), Bytes: big}, "over"},
		{"no capture", doc, nil, "not the"},
		{"capture short of its pieces", doc, &c5.Capture{SHA256: digest(short), Bytes: short}, "not the"},
		{"a span in no piece", uncovered, &c5.Capture{SHA256: digest(short), Bytes: short}, "in no piece"},
		{"not the encoder's bytes", append(bytes.Clone(doc[:len(doc)-1]), ' ', '}'), &capture, "encoder"},
		{"a read with a capture", rd, &capture, "no capture"},
		{"a read not the encoder's bytes", bytes.Replace(rd, []byte(`","`), []byte(`", "`), 1), nil, "encoder"},
		{"a read without its time", bytes.Replace(rd, []byte("2026-10-24T09:15:01.8Z"), []byte("yesterday"), 1), nil, "read_at"},
	} {
		if _, err := ConfigDocuments(tc.doc, tc.capture); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// An SNMPv3 schedule entry is the asset module's: it is refused at load
// with asset off. With asset on, an SNMP poll commits its run with its
// transcript and no SER row, and stores the identity it read.
func TestSNMPEntry(t *testing.T) {
	snmp := func(nc *nodeconfigtest.Config) {
		var a map[string]any
		if err := json.Unmarshal(readFile(t, "../../contracts/asset/testdata/valid/sel-2731m-snmpv3.json"), &a); err != nil {
			t.Fatal(err)
		}
		a["endpoints"].([]any)[0].(map[string]any)["host"] = "127.0.0.1"
		nc.Assets = append(nc.Assets, a)
		nc.Schedule = append(nc.Schedule, nodeconfigtest.Collection{ID: "sch-snmp-5d2e8f14", AssetID: a["asset_id"].(string),
			Endpoint: "mgmt-snmpv3", Operation: "sel27x1.snmp.identity", CredentialRef: nodeconfigtest.TestCredentialRef, EverySeconds: 300})
	}
	if _, err := item3Config(t, snmp); err == nil || !strings.Contains(err.Error(), "SNMP reads are the asset module's") {
		t.Fatalf("snmpv3 entry with asset off: %v", err)
	}

	c, dir := identityConfig(t, snmp)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	res, err := adapter.DecodeResult(readFile(t, "../../contracts/adapter/testdata/snmp/results/valid/ok.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	s := newScheduler(t, r, answering(&collectorclient.Outcome{InvocationID: res.InvocationID, Result: res, ResultJSON: b}))
	if rep := s.RunOnce(bg, 1); rep.Outcome != "ok" || rep.Alarm != "" || rep.Events != 0 {
		t.Fatalf("%+v", rep)
	}
	id := c.Schedule[1].AssetID
	hs, _ := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
	var runs []c5.Stored
	for _, rec := range hs {
		if e, _ := event.Decode(rec.Event); e.Health != nil && e.Health.Type == HealthCollectionRun {
			runs = append(runs, rec)
		}
	}
	if len(runs) != 1 || runs[0].EvidenceRef != c5.EvidenceRef(res.Transcript.SHA256) {
		t.Fatalf("collection.run events %+v", runs)
	}
	if n, _ := r.Store(SERStream(id)).LastCommitted(bg, SERStream(id)); n != 0 {
		t.Fatalf("%d SER rows from an SNMP poll", n)
	}
	got, _ := r.Store(ConfigStream(id)).Read(bg, ConfigStream(id), 0, 100)
	var stored *identityDoc
	for _, rec := range got {
		if bytes.HasPrefix(rec.Event, []byte(`{"schema":"`+IdentitySchema)) {
			c, _ := r.Store(ConfigStream(id)).ReadCapture(bg, rec.EvidenceRef)
			d, err := decodeIdentity(rec.Event, &c)
			if err != nil {
				t.Fatal(err)
			}
			stored = &d
		}
	}
	if stored == nil {
		t.Fatalf("no identity record from the SNMP poll: %+v", st.Snapshot("x").Alarms)
	}
	if h, ok := stored.Asset.Attribute(c1.AttrHostname); !ok || h.Value != "sw-bay-1" {
		t.Fatalf("hostname %+v", h)
	}
}

// At the item 3 ceiling a changed identity is not stored, and neither is
// its identity.read, which would say an identity the store does not hold
// was confirmed. asset-store-full is raised and the refusal is counted; no
// identity-not-stored is raised for it.
func TestIdentityAtTheCeiling(t *testing.T) {
	quota := int64(64 << 20)
	mod := func(nc *nodeconfigtest.Config) {
		withConfigRead(t, nil)(nc)
		nc.Store.Quotas["configuration"] = quota
	}
	c, _ := identityConfig(t, mod)
	quota = c.configModuleFloor() + c.item3Floor()
	c, dir := identityConfig(t, mod)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, answering(okRun(t, invA, nil), okRun(t, invC, changeCID)))
	s.RunOnce(bg, 0)
	ids, _ := identityRecords(t, r, relayID)
	if len(ids) != 1 {
		t.Fatalf("%d identity records", len(ids))
	}
	stream := ConfigStream(relayID)
	db := r.Store(stream)
	capture, err := db.ReadCapture(bg, ids[0].EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}
	// Fill the class to just under the ceiling with copies of the record.
	for {
		used, err := db.ClassBytes(bg, c5.ClassConfiguration)
		if err != nil {
			t.Fatal(err)
		}
		if used+int64(len(ids[0].Event))+int64(len(capture.Bytes)) > c.Item3Ceiling() {
			break
		}
		if _, err := r.Log(stream).AppendBatch(bg, []c5.Record{{Stream: stream, Class: c5.ClassConfiguration, Event: ids[0].Event, Capture: &capture}}); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := identityRecords(t, r, relayID)
	s.RunOnce(bg, 0)
	after, reads := identityRecords(t, r, relayID)
	if len(after) != len(before) || len(reads) != 1 || reads[0].InvocationID != invA {
		t.Fatalf("at the ceiling: %d identity records (was %d), reads %+v", len(after), len(before), reads)
	}
	f := st.Snapshot("x")
	if countAlarms(st, AlarmAssetStoreFull) != 1 || countAlarms(st, AlarmIdentityNotStored) != 0 ||
		f.AssetStore == nil || f.AssetStore.Refused[c5.SeriesIdentity] != 1 {
		t.Fatalf("alarms %+v, asset store %+v", f.Alarms, f.AssetStore)
	}
}

// Today's readers of config/<asset> pass over the identity records (C5 0.8
// section 6): storedBaselines and checkpoints skip them by schema prefix,
// and locate matches by digest only.
func TestReadersPassOverIdentityRecords(t *testing.T) {
	c, dir := identityConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, answering(okRun(t, invA, nil), okRun(t, invC, changeCID)))
	s.RunOnce(bg, 0)
	s.RunOnce(bg, 0)
	ids, reads := identityRecords(t, r, relayID)
	if len(ids) != 2 || len(reads) != 1 {
		t.Fatalf("%d identity records, %d reads", len(ids), len(reads))
	}
	if b, err := (&eventLife{rt: r}).storedBaselines(bg, relayID); err != nil || len(b) != 0 {
		t.Fatalf("storedBaselines: %d, %v", len(b), err)
	}
	if cps, err := (&eventRun{rt: r}).checkpoints(bg, relayID); err != nil || len(cps) != 0 {
		t.Fatalf("checkpoints: %d, %v", len(cps), err)
	}
	stream := ConfigStream(relayID)
	want := map[string]bool{config.Digest(ids[1].Event): true, strings.Repeat("0", 64): true}
	got, err := locateAll(bg, r.Store(stream), stream, want)
	if err != nil || len(got) != 1 || len(got[config.Digest(ids[1].Event)]) != 1 || got[config.Digest(ids[1].Event)][0] != ids[1].Key.Seq {
		t.Fatalf("locateAll: %v, %v", got, err)
	}
}

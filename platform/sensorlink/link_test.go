package sensorlink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	c5 "otsec.local/otsec/contracts/store"
)

var bg = context.Background()

// The resolver counts inbound endpoints and the outbound endpoints whose
// CheckPath passes, compares hosts unmapped and without a zone, and names
// neither of two assets on one address (C13 section 5, section 14 item 9).
func TestResolver(t *testing.T) {
	const third = "9a8b7c6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d"
	assets := append(testAssets(),
		asset.Asset{AssetID: third, NodeID: testNode, Endpoints: []asset.Endpoint{
			ep("ps", asset.SSH, "192.0.2.30", asset.PortServer),   // not counted: the host is the port server
			ep("nopath", asset.Telnet, "192.0.2.31", ""),          // not counted: no path (D2-16)
			ep("later", "modbus-tcp", "192.0.2.32", asset.Direct), // not counted: a later C1 transport
			ep("shared", asset.SyslogTCP, "192.0.2.20", ""),       // the relay's address: ambiguous
			ep("v6", asset.SSH, "fe80::1%eth0", asset.Direct),
		}},
		asset.Asset{AssetID: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", NodeID: "site-b-node1",
			Endpoints: []asset.Endpoint{ep("other", asset.SSH, "192.0.2.40", asset.Direct)}},
	)
	r := NewResolver(testNode, assets)
	for addr, want := range map[string]struct {
		id    string
		known bool
	}{
		"192.0.2.10":        {master, true}, // inbound Syslog sender
		"::ffff:192.0.2.10": {master, true}, // the mapped form
		"192.0.2.20":        {"", true},     // two assets: ambiguous
		"192.0.2.30":        {"", false},
		"192.0.2.31":        {"", false},
		"192.0.2.32":        {"", false},
		"192.0.2.40":        {"", false}, // another node's asset
		"fe80::1":           {third, true},
		"fe80::1%eth1":      {third, true}, // the zone is dropped
		"198.51.100.1":      {"", false},
	} {
		id, known := r.Resolve(netip.MustParseAddr(addr))
		if id != want.id || known != want.known {
			t.Errorf("%s: (%q, %v), want (%q, %v)", addr, id, known, want.id, want.known)
		}
	}
}

// A first sight is stored with the node object, its frames stripped and
// stored as a pcap capture whose SHA-256 is stored_capture, and its C4
// event names the destination asset.
func TestFirstSightStored(t *testing.T) {
	s := openNet(t, 64<<20)
	l := newLink(t, s, &clock{}, 64<<20)
	o := firstSight(1, "192.0.2.10", "192.0.2.20", netobs.SAChallenged)
	assets := []asset.Asset{testAssets()[0], testAssets()[1]}
	l.resolver = NewResolver(testNode, assets)
	if err := l.Serve(bg, stream(t, o)); err != nil {
		t.Fatal(err)
	}
	got := stored(t, s)
	if len(got) != 1 {
		t.Fatalf("%d stored, stats %+v", len(got), l.Stats())
	}
	var e event.Event
	if err := json.Unmarshal(got[0].Event, &e); err != nil {
		t.Fatal(err)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("C4: %v", err)
	}
	so, err := netobs.ObservationFromEvent(&e)
	if err != nil {
		t.Fatalf("C13 stored: %v", err)
	}
	n := so.Node
	if n.SrcAsset != master || n.DstAsset != relay || n.ResolvedBy != "ip" || n.EvidenceClass != "simulated" ||
		n.FunctionClass != netobs.ClassControl || n.FunctionTable != netobs.FunctionTable || n.DNP3NoSA != nil || len(so.Frames) != 0 {
		t.Fatalf("node %+v, frames %d", n, len(so.Frames))
	}
	c, err := s.db.ReadCapture(bg, got[0].EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}
	if c.SHA256 != n.StoredCapture || hashOf(c.Bytes) != n.StoredCapture {
		t.Fatalf("stored_capture %s, capture %s", n.StoredCapture, c.SHA256)
	}
	// The pcap: header, then each cited frame in order with its time,
	// captured length and wire length.
	le := binary.LittleEndian
	b := c.Bytes
	if le.Uint32(b) != pcapMagicNS || le.Uint32(b[16:]) != netobs.MaxFrameBytes || le.Uint32(b[20:]) != 1 {
		t.Fatalf("pcap header % x", b[:24])
	}
	b = b[24:]
	for i, f := range o.Frames {
		ts, _ := time.Parse(time.RFC3339Nano, f.TS)
		incl := int(le.Uint32(b[8:]))
		if le.Uint32(b) != uint32(ts.Unix()) || le.Uint32(b[4:]) != uint32(ts.Nanosecond()) ||
			incl != o.Citation.Frames[i].CapturedLen || int(le.Uint32(b[12:])) != o.Citation.Frames[i].WireLen ||
			hashOf(b[16:16+incl]) != o.Citation.Frames[i].SHA256 {
			t.Fatalf("pcap record %d", i)
		}
		b = b[16+incl:]
	}
	if len(b) != 0 {
		t.Fatalf("%d bytes after the last record", len(b))
	}
	if st := l.Stats(); st.Committed != 1 || st.LastCommittedSeq != 1 || st.RunID != testRun {
		t.Fatalf("stats %+v", st)
	}
}

// dnp3_no_sa is set exactly on a DNP3 write, control or session-setup with
// sa none: never when sa is absent, failed or challenged, and never on a read.
func TestDNP3NoSA(t *testing.T) {
	l := newLink(t, openNet(t, 64<<20), &clock{}, 64<<20)
	read := firstSight(1, "192.0.2.10", "192.0.2.20", netobs.SANone)
	read.Function.Code, read.Function.Objects = 1, []string{"g60v1"}
	for name, tc := range map[string]struct {
		o    *netobs.Observation
		want bool
	}{
		"operate, sa none":    {firstSight(1, "192.0.2.10", "192.0.2.20", netobs.SANone), true},
		"operate, sa absent":  {firstSight(1, "192.0.2.10", "192.0.2.20", ""), false},
		"operate, sa failed":  {firstSight(1, "192.0.2.10", "192.0.2.20", netobs.SAFailed), false},
		"operate, challenged": {firstSight(1, "192.0.2.10", "192.0.2.20", netobs.SAChallenged), false},
		"read, sa none":       {read, false},
	} {
		nd, _ := l.nodeObject(tc.o)
		if (nd.DNP3NoSA != nil) != tc.want || (nd.DNP3NoSA != nil && !*nd.DNP3NoSA) {
			t.Errorf("%s: dnp3_no_sa %v", name, nd.DNP3NoSA)
		}
	}
	// Modbus too short for its sub: D1's most restrictive rows.
	mb := firstSight(1, "192.0.2.10", "192.0.2.20", "")
	mb.Protocol, mb.Function = "modbus", &netobs.Function{Code: 8, Objects: []string{}, Unit: ptr(1)}
	if nd, _ := l.nodeObject(mb); nd.FunctionClass != netobs.ClassControl {
		t.Errorf("short Modbus 8: %s", nd.FunctionClass)
	}
	mb.Function.Code = 43
	if nd, _ := l.nodeObject(mb); nd.FunctionClass != netobs.ClassWrite {
		t.Errorf("short Modbus 43: %s", nd.FunctionClass)
	}
}

// Ambiguity: an end on an address two assets share stays unresolved, as
// ip-ambiguous, and the other end keeps its asset. Only an observation
// with neither end named draws on the budget (D3 on #553, D1's ruling (a)).
func TestAmbiguousEnd(t *testing.T) {
	l := newLink(t, openNet(t, 64<<20), &clock{}, 64<<20)
	dup := func(id, host string) asset.Asset {
		return asset.Asset{AssetID: id, NodeID: testNode, Endpoints: []asset.Endpoint{ep("dup", asset.SyslogTCP, host, "")}}
	}
	// .20, the relay's address, and .30 are each shared by two assets.
	l.resolver = NewResolver(testNode, append(testAssets(), dup("9a8b7c6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d", "192.0.2.20"),
		asset.Asset{AssetID: "4e5f6a7b-8c9d-4e0f-a1b2-c3d4e5f6a7b8", NodeID: testNode, Endpoints: []asset.Endpoint{ep("a", asset.SyslogUDP, "192.0.2.30", "")}},
		dup("5f6a7b8c-9d0e-4f1a-b2c3-d4e5f6a7b8c9", "192.0.2.30")))
	for _, tc := range []struct {
		name, src, dst, by, srcAsset, dstAsset string
		budgeted                               bool
	}{
		{"ambiguous dst", "192.0.2.10", "192.0.2.20", "ip-ambiguous", master, netobs.AssetUnresolved, false},
		{"ambiguous src to a resolved dst", "192.0.2.30", "192.0.2.10", "ip-ambiguous", netobs.AssetUnresolved, master, false},
		{"both ends ambiguous", "192.0.2.30", "192.0.2.20", "ip-ambiguous", netobs.AssetUnresolved, netobs.AssetUnresolved, true},
		{"neither end known", "198.51.100.1", "198.51.100.2", "none", netobs.AssetUnresolved, netobs.AssetUnresolved, true},
		{"resolved dst", "198.51.100.1", "192.0.2.10", "ip", netobs.AssetUnresolved, master, false},
		{"resolved src", "192.0.2.10", "198.51.100.2", "ip", master, netobs.AssetUnresolved, false},
	} {
		nd, budgeted := l.nodeObject(flow(1, tc.src, tc.dst))
		if nd.ResolvedBy != tc.by || nd.SrcAsset != tc.srcAsset || nd.DstAsset != tc.dstAsset || budgeted != tc.budgeted {
			t.Errorf("%s: node %+v, budgeted %v", tc.name, nd, budgeted)
		}
	}
}

// End to end, the stored records carry what the node resolved and read back
// under C13: an ambiguous end beside a resolved one, and a TCP flow end with
// its syn_only.
func TestStoredResolution(t *testing.T) {
	s := openNet(t, 64<<20)
	l := newLink(t, s, &clock{}, 64<<20)
	l.resolver = NewResolver(testNode, append(testAssets(),
		asset.Asset{AssetID: "9a8b7c6d-5e4f-4a3b-9c2d-1e0f2a3b4c5d", NodeID: testNode, Endpoints: []asset.Endpoint{ep("dup", asset.SyslogTCP, "192.0.2.20", "")}}))
	end := flow(2, "192.0.2.10", "192.0.2.20")
	syn := true
	end.Flow = &netobs.Flow{Phase: "end", End: "rst", Packets: 2, Bytes: 120, SynOnly: &syn}
	if err := l.Serve(bg, stream(t, flow(1, "192.0.2.10", "192.0.2.20"), end)); err != nil {
		t.Fatal(err)
	}
	got := stored(t, s)
	if len(got) != 2 {
		t.Fatalf("stats %+v", l.Stats())
	}
	var obs []*netobs.Observation
	for i, st := range got {
		var e event.Event
		if err := json.Unmarshal(st.Event, &e); err != nil {
			t.Fatal(err)
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("record %d C4: %v", i, err)
		}
		o, err := netobs.ObservationFromEvent(&e)
		if err != nil {
			t.Fatalf("record %d C13 stored: %v", i, err)
		}
		if o.Node.ResolvedBy != "ip-ambiguous" || o.Node.SrcAsset != master || o.Node.DstAsset != netobs.AssetUnresolved {
			t.Fatalf("record %d node %+v", i, o.Node)
		}
		obs = append(obs, o)
	}
	if f := obs[1].Flow; f.Phase != "end" || f.SynOnly == nil || !*f.SynOnly {
		t.Fatalf("flow %+v", f)
	}
}

// Hostile records are refused and counted, and the channel stays up; only
// an oversized frame closes it.
func TestRefusals(t *testing.T) {
	s := openNet(t, 64<<20)
	l := newLink(t, s, &clock{}, 64<<20)
	alert := []byte(`{"schema":"otsec.netobs/0.1","type":"alert","sensor_id":"` + testSensor + `"}`)
	other := flow(2, "192.0.2.10", "192.0.2.20")
	other.SensorID = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	withNode := flow(3, "192.0.2.10", "192.0.2.20")
	withNode.Node = &netobs.Node{}
	badHash := firstSight(4, "192.0.2.10", "192.0.2.20", "")
	badHash.Citation.Frames[0].SHA256 = hashOf([]byte("x"))
	repeat := flow(4, "192.0.2.10", "192.0.2.20") // seq 4 again
	in := stream(t,
		flow(1, "192.0.2.10", "192.0.2.20"),
		[]byte(`{not json`),
		alert,
		other,
		withNode,
		badHash,
		repeat,
		flow(7, "192.0.2.10", "192.0.2.20"), // 5 and 6 never sent
		heartbeat(8, 100),
		heartbeat(9, 99), // a counter decrease
		heartbeat(10, 200),
	)
	if err := l.Serve(bg, in); err != nil {
		t.Fatal(err)
	}
	st := l.Stats()
	want := map[string]uint64{"decode": 1, "type": 1, RefusedSensorID: 1, "conflict": 1, "hash": 1, RefusedSeq: 1, RefusedCounterDecrease: 1}
	for k, v := range want {
		if st.Refused[k] != v {
			t.Errorf("refused %s: %d, want %d (all %v)", k, st.Refused[k], v, st.Refused)
		}
	}
	if len(st.Refused) != len(want) {
		t.Errorf("refused %v", st.Refused)
	}
	// Seq 2 came from another sensor, so this sensor's 2 is missing too: the
	// gaps are 2, 5 and 6.
	if st.Committed != 2 || st.SeqGaps != 3 || st.LastSeq != 10 || st.LastCommittedSeq != 7 || st.Heartbeat.Counters.Packets != 200 {
		t.Fatalf("stats %+v", st)
	}
	if n := len(stored(t, s)); n != 2 {
		t.Fatalf("%d stored", n)
	}

	// A frame above MaxChannelFrame closes the channel and is counted.
	big := make([]byte, 4)
	binary.BigEndian.PutUint32(big, netobs.MaxChannelFrame+1)
	if err := l.Serve(bg, bytes.NewReader(big)); !errors.Is(err, netobs.ErrFrameTooLarge) {
		t.Fatalf("oversized frame: %v", err)
	}
	if l.Stats().FramesTooLarge != 1 {
		t.Fatal("not counted")
	}

	// A new run starts its seq afresh.
	o := flow(1, "192.0.2.10", "192.0.2.20")
	o.RunID = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f"
	o.Citation.CaptureID = "ring:" + o.RunID + ":1"
	if err := l.Serve(bg, stream(t, o)); err != nil {
		t.Fatal(err)
	}
	if st := l.Stats(); st.RunID != o.RunID || st.LastSeq != 1 || st.LastCommittedSeq != 1 || st.Heartbeat != nil || st.SeqGaps != 3 {
		t.Fatalf("new run: %+v", st)
	}
}

// The unresolved budget on the test clock (D6, D5-c5-0.9 section 4): it
// starts empty, holds B = Q/4 after H, refills n*B/H in n seconds, and a
// restart empties it. Resolved observations commit throughout.
func TestUnresolvedBudget(t *testing.T) {
	// r is one unresolved flow record's bytes: every flow below has a
	// three-digit seq, so all are the same size.
	probe := openNet(t, 64<<20)
	pc := &clock{now: time.Hour}
	pl := newLink(t, probe, &clock{}, 64<<20)
	pl.opt.Monotonic = pc.mono
	if err := pl.Serve(bg, stream(t, flow(100, "198.51.100.1", "198.51.100.2"))); err != nil {
		t.Fatal(err)
	}
	got := stored(t, probe)
	if len(got) != 1 {
		t.Fatalf("probe: %+v", pl.Stats())
	}
	r := int64(len(got[0].Event))

	const k = 5
	q := 4 * k * r // B = k records
	s := openNet(t, 64<<20)
	c := &clock{}
	l := newLink(t, s, c, q)
	seq := 100
	send := func(src, dst string) {
		t.Helper()
		seq++
		if err := l.Serve(bg, stream(t, flow(seq, src, dst))); err != nil {
			t.Fatal(err)
		}
	}
	unresolved := func() { send("198.51.100.1", "198.51.100.2") }
	committed := func() uint64 { return l.Stats().Committed }

	unresolved() // the bucket starts empty
	if committed() != 0 || l.Stats().Dropped[DropUnresolvedBudget] != 1 {
		t.Fatalf("at start: %+v", l.Stats())
	}
	send("192.0.2.10", "192.0.2.20") // resolved: never budgeted
	// A resolved source to an unresolved destination isn't budgeted either,
	// and its C4 event carries the flag, as source.asset is the destination
	// (D6 on #553).
	send("192.0.2.10", "198.51.100.2")
	if committed() != 2 {
		t.Fatalf("a resolved source was budgeted: %+v", l.Stats())
	}
	var e event.Event
	if err := json.Unmarshal(stored(t, s)[1].Event, &e); err != nil {
		t.Fatal(err)
	}
	if e.Source.Asset != nil || !slices.Equal(e.Flags, []string{"asset-unresolved"}) {
		t.Fatalf("source %+v, flags %v", e.Source, e.Flags)
	}
	// A resolved destination is bound observed-address, inferred: a label
	// from the wire, never sender-address or configured (D4-71, D3's B1 on
	// #557).
	var re event.Event
	if err := json.Unmarshal(stored(t, s)[0].Event, &re); err != nil {
		t.Fatal(err)
	}
	if a := re.Source.Asset; a == nil || a.ID != relay || a.Binding != (event.Binding{Method: event.BindObservedAddress, Confidence: event.ConfidenceInferred}) {
		t.Fatalf("resolved destination: source %+v", re.Source)
	}
	c.now += time.Hour
	for range k + 1 {
		unresolved()
	}
	if got := committed(); got != 2+k {
		t.Fatalf("after H: %d committed, want %d", got, 2+k)
	}
	// H/k seconds earn exactly one record; a nanosecond less earns none.
	c.now += time.Hour/k - 1
	unresolved()
	if committed() != 2+k {
		t.Fatal("a record committed before its bytes were earned")
	}
	c.now++
	unresolved()
	unresolved()
	if got := committed(); got != 3+k {
		t.Fatalf("after H/k: %d committed, want %d", got, 3+k)
	}
	send("192.0.2.10", "192.0.2.20")
	if committed() != 4+k {
		t.Fatal("a resolved record was budgeted")
	}
	if d := l.Stats().Dropped; d[DropUnresolvedBudget] != 4 || len(d) != 1 {
		t.Fatalf("dropped %v", d)
	}
	// A restart empties the bucket.
	l = newLink(t, s, c, q)
	unresolved()
	if l.Stats().Committed != 0 {
		t.Fatal("the bucket survived a restart")
	}
}

// At the class quota an observation is dropped as class-full, counted once,
// and nothing else is counted. (record-cap can't be reached from a valid
// record: C4's MaxNetobsBytes and C13's MaxCaptureBytes keep one far under
// the 64 KiB cap, which contracts/netobs pins.)
func TestStoreDrops(t *testing.T) {
	s := openNet(t, 256<<10)
	c := &clock{}
	l := newLink(t, s, c, 256<<10)
	seq := 0
	for l.Stats().Dropped[DropClassFull] == 0 && seq < 10000 {
		seq++
		if err := l.Serve(bg, stream(t, firstSightFlow(seq))); err != nil {
			t.Fatal(err)
		}
	}
	st := l.Stats()
	if st.Dropped[DropClassFull] != 1 || len(st.Dropped) != 1 || st.Committed != uint64(seq-1) {
		t.Fatalf("stats %+v after %d", st, seq)
	}
}

// firstSightFlow is a resolved first sight, so each stores its capture.
func firstSightFlow(seq int) *netobs.Observation {
	o := firstSight(seq, "192.0.2.10", "192.0.2.20", netobs.SAChallenged)
	// A new capture each time, so each is charged.
	o.Frames[0].TS = time.Date(2026, 11, 7, 10, 0, 0, seq*1000, time.UTC).Format("2006-01-02T15:04:05.000000Z")
	return o
}

// coverage.settings outside their bounds refuse the record (C13 section 10),
// on an observation and on a heartbeat.
func TestSettingsBounds(t *testing.T) {
	l := newLink(t, openNet(t, 64<<20), &clock{}, 64<<20)
	o := flow(1, "192.0.2.10", "192.0.2.20")
	o.Coverage.Settings.SAReplyTimeoutMS = netobs.MinSAReplyTimeoutMS - 1
	h := heartbeat(2, 1)
	h.Coverage.Settings.MaxPendingDNP3 = netobs.MaxMaxPendingDNP3 + 1
	idle := flow(3, "192.0.2.10", "192.0.2.20")
	idle.Coverage.Settings.FlowIdleS = netobs.MaxFlowIdleS + 1
	ok := flow(4, "192.0.2.10", "192.0.2.20")
	ok.Coverage.Settings.SAReplyTimeoutMS = netobs.MaxSAReplyTimeoutMS
	ok.Coverage.Settings.FlowIdleS = netobs.MinFlowIdleS
	if err := l.Serve(bg, stream(t, o, h, idle, ok)); err != nil {
		t.Fatal(err)
	}
	if st := l.Stats(); st.Refused["range"] != 3 || st.Committed != 1 || st.Heartbeat != nil {
		t.Fatalf("stats %+v", st)
	}
}

// refusing is a store that refuses its first n appends as class-full.
type refusing struct {
	n   int
	log Appender
}

func (r *refusing) Append(ctx context.Context, rec c5.Record) (c5.Receipt, error) {
	if r.n > 0 {
		r.n--
		return nil, &c5.Error{Code: c5.CodeQuotaReached}
	}
	return r.log.Append(ctx, rec)
}

// Bytes the store refuses go back to the bucket, so the earned records
// still commit once the class has room (D6 on #553); and from empty, H/2
// earns exactly half the bucket.
func TestBudgetGiveBack(t *testing.T) {
	s := openNet(t, 64<<20)
	c := &clock{}
	r := unresolvedBytes(t)
	const k = 4
	l := newLink(t, s, c, 4*k*r)
	ref := &refusing{n: 3, log: s.log}
	l.opt.Store = ref
	seq := 100
	send := func(n int) {
		t.Helper()
		for range n {
			seq++
			if err := l.Serve(bg, stream(t, flow(seq, "198.51.100.1", "198.51.100.2"))); err != nil {
				t.Fatal(err)
			}
		}
	}
	c.now += time.Hour // the bucket holds k records
	send(3)            // refused by the store
	send(k + 1)
	st := l.Stats()
	if st.Committed != k || st.Dropped[DropClassFull] != 3 || st.Dropped[DropUnresolvedBudget] != 1 {
		t.Fatalf("stats %+v", st)
	}

	// From empty, H/2 earns floor((B/2)/r) records: 2 of k = 4.
	l = newLink(t, s, c, 4*k*r)
	c.now += time.Hour / 2
	send(k)
	if st := l.Stats(); st.Committed != k/2 || st.Dropped[DropUnresolvedBudget] != k/2 {
		t.Fatalf("after H/2: %+v", st)
	}
}

// unresolvedBytes is one unresolved flow record's bytes, for a three-digit
// seq.
func unresolvedBytes(t *testing.T) int64 {
	t.Helper()
	s := openNet(t, 64<<20)
	l := newLink(t, s, &clock{}, 64<<20)
	l.opt.Monotonic = (&clock{now: time.Hour}).mono
	if err := l.Serve(bg, stream(t, flow(100, "198.51.100.1", "198.51.100.2"))); err != nil {
		t.Fatal(err)
	}
	got := stored(t, s)
	if len(got) != 1 {
		t.Fatalf("probe: %+v", l.Stats())
	}
	return int64(len(got[0].Event))
}

// A frame cut at 2,048 bytes keeps its wire length as the record's
// orig_len (D6 on #553).
func TestCaptureWireLen(t *testing.T) {
	s := openNet(t, 64<<20)
	l := newLink(t, s, &clock{}, 64<<20)
	o := firstSight(1, "192.0.2.10", "192.0.2.20", netobs.SAChallenged)
	f2 := frameBytes(netobs.MaxFrameBytes, 60, 8)
	cf := &o.Citation.Frames[1]
	cf.CapturedLen, cf.WireLen, cf.SHA256 = len(f2), 3000, hashOf(f2)
	o.Frames[1].Data = base64.StdEncoding.EncodeToString(f2)
	if err := l.Serve(bg, stream(t, o)); err != nil {
		t.Fatal(err)
	}
	got := stored(t, s)
	if len(got) != 1 {
		t.Fatalf("stats %+v", l.Stats())
	}
	c, err := s.db.ReadCapture(bg, got[0].EvidenceRef)
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	rec2 := c.Bytes[24+16+len(frameBytes(74, 0, 0)):]
	if incl, orig := le.Uint32(rec2[8:]), le.Uint32(rec2[12:]); incl != netobs.MaxFrameBytes || orig != 3000 {
		t.Fatalf("incl_len %d, orig_len %d", incl, orig)
	}
}

// A change of run is counted, the first run read not included (D3 on #553).
func TestRunChanges(t *testing.T) {
	l := newLink(t, openNet(t, 64<<20), &clock{}, 64<<20)
	other := "1c2d3e4f-5a6b-4c7d-8e9f-a0b1c2d3e4f5"
	h := heartbeat(1, 1)
	f := flow(1, "192.0.2.10", "192.0.2.20")
	f.RunID = other
	f.Citation.CaptureID = "ring:" + other + ":3"
	if err := l.Serve(bg, stream(t, heartbeat(2, 1), f, h)); err != nil {
		t.Fatal(err)
	}
	if st := l.Stats(); st.RunChanges != 2 || st.RunID != testRun {
		t.Fatalf("stats %+v", st)
	}
}

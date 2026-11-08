package netdetect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

// Constructed fixtures, desk only: no sensor produced them and no device
// was contacted. Addresses are TEST-NET-1 (192.0.2.0/24) and TEST-NET-2.
const (
	lxSensor = "5f0c2a7e-3b1d-4c8e-9a2f-6d4e8b1c7a90"
	lxRun    = "0b9e4c6d-1a2f-4e3b-8c7d-5f6a7b8c9d0e"
	lxRelay  = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	lxMaster = "7c1e5a20-4d3b-4f6a-8b2c-9e0d1f2a3b4c"
	lxStart  = "2026-11-01T00:00:00Z"
)

func ptr[T any](v T) *T { return &v }

func lxConfig() LearnerConfig {
	return LearnerConfig{SensorID: lxSensor, Version: 1, StartUTC: lxStart,
		Params: netobs.BaselineParams{TieGraceS: netobs.DefaultTieGraceS, CoalesceWindowS: netobs.DefaultCoalesceWindowS}}
}

// lxObs is a stored observation of kind k from src to dst on TCP port
// dport. An address in 192.0.2.10 or .20 resolves to the master or the
// relay; any other is unresolved. Each is checked against C13's stored
// rules, so the learner is fed only what the node can store.
func lxObs(t testing.TB, k netobs.Kind, src, dst string, dport int) *netobs.Observation {
	t.Helper()
	o := &netobs.Observation{
		Schema: netobs.Identifier, Type: netobs.TypeObservation, SensorID: lxSensor, RunID: lxRun, Seq: "7",
		Kind: k, FirstUTC: "2026-11-01T10:00:00.000001Z", LastUTC: "2026-11-01T10:00:00.120001Z", ResolutionNS: 1000,
		L2:        netobs.L2{SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02", VLAN: ptr(10), EtherType: "0x0800"},
		IP:        &netobs.IP{Src: src, Dst: dst, L4: "tcp", Sport: ptr(51234), Dport: ptr(dport)},
		Direction: netobs.DirectionClientServer, Protocol: "dnp3",
		Citation: netobs.Citation{CaptureID: "ring:" + lxRun + ":3", FramesTotal: 1, Frames: []netobs.CitedFrame{{N: 17, CapturedLen: 74, WireLen: 74, SHA256: fmt.Sprintf("%064x", 1)}}},
		Coverage: netobs.Coverage{SensorVersion: "0.1.0", Engine: netobs.Engine{Name: "test-engine", Version: "1"},
			Interfaces: []netobs.Interface{{Name: "eth1", Attachment: "span", LAN: "single"}},
			PRP:        netobs.PRP{LANsSeen: []string{}}, HSR: netobs.HSRNotDecoded, VLANsSeen: []int{10}, UntaggedSeen: true,
			Decodes: []string{"dnp3", "modbus"}, Degraded: []string{},
			Settings: netobs.Settings{SAReplyTimeoutMS: netobs.DefaultSAReplyTimeoutMS, MaxPendingDNP3: netobs.DefaultMaxPendingDNP3, FlowIdleS: netobs.DefaultFlowIdleS},
			SinceUTC: "2026-11-01T00:00:00.000000Z"},
	}
	resolve := func(ip string) string {
		switch ip {
		case "192.0.2.10":
			return lxMaster
		case "192.0.2.20":
			return lxRelay
		}
		return netobs.AssetUnresolved
	}
	nd := &netobs.Node{SrcAsset: resolve(src), DstAsset: resolve(dst), ResolvedBy: "none", EvidenceClass: "simulated"}
	if nd.SrcAsset != netobs.AssetUnresolved || nd.DstAsset != netobs.AssetUnresolved {
		nd.ResolvedBy = "ip"
	}
	o.Node = nd
	switch k {
	case netobs.KindFlow:
		o.Flow = &netobs.Flow{Phase: "start", Packets: 3, Bytes: 222}
	case netobs.KindService:
		o.Service = &netobs.Service{Basis: "content"}
	case netobs.KindFunction:
		o.Function = &netobs.Function{Code: 5, Objects: []string{"g12v1"}, SA: netobs.SANone}
		row := Classify("dnp3", 5, nil, o.Function.Objects)
		nd.FunctionClass, nd.FunctionTable = row.Class, Table
		nd.DNP3NoSA = ptr(true)
	}
	if err := o.ValidateStored(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return o
}

// The parts of §2.1, one observation each.
func TestLearnerFolds(t *testing.T) {
	l, err := NewLearner(lxConfig())
	if err != nil {
		t.Fatal(err)
	}
	seq := uint64(0)
	feed := func(o *netobs.Observation) {
		t.Helper()
		seq++
		if err := l.Observe(seq, o); err != nil {
			t.Fatal(err)
		}
	}
	feed(lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000))     // a pair
	feed(lxObs(t, netobs.KindService, "192.0.2.10", "192.0.2.20", 20000))  // a service
	feed(lxObs(t, netobs.KindFunction, "192.0.2.10", "192.0.2.20", 20000)) // a function
	feed(lxObs(t, netobs.KindFlow, "198.51.100.7", "192.0.2.20", 502))     // an unresolved client
	mid := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20001)    // midstream: no pair
	mid.Direction = netobs.DirectionMidstream
	feed(mid)
	end := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20002) // an end: no pair
	end.Flow = &netobs.Flow{Phase: "end", End: "fin", Packets: 9, Bytes: 900, SynOnly: ptr(false)}
	feed(end)
	own := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 22) // the node's own session
	own.Node.PlatformSession = &netobs.PlatformSession{InvocationID: "inv-1", Tie: "connection"}
	feed(own)
	deg := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 23) // degraded coverage
	deg.Coverage.Degraded = []string{"drops"}
	feed(deg)
	lan := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000) // seen untagged on LAN b
	lan.L2.VLAN = nil
	lan.Citation.Frames[0].LAN = "b"
	feed(lan)

	got, err := l.Freeze("2026-11-08T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := netobs.DecodeBaseline(got); err != nil {
		t.Fatal(err)
	}
	want := &netobs.Baseline{Schema: netobs.BaselineIdentifier, SensorID: lxSensor, Version: 1, FunctionTable: Table,
		Period: netobs.Period{StartUTC: lxStart, EndUTC: "2026-11-08T00:00:00Z",
			Observations: netobs.Counts{Flow: 5, Service: 1, Function: 1}, Degraded: 1, PlatformSession: 1},
		Params: lxConfig().Params,
		Pairs: []netobs.Pair{
			{Client: lxMaster, Server: lxRelay, L4: "tcp", Port: 20000, Protocol: "dnp3"},
			{Client: "addr:198.51.100.7", Server: lxRelay, L4: "tcp", Port: 502, Protocol: "dnp3"},
		},
		Services:  []netobs.BaselineService{{Server: lxRelay, L4: "tcp", Port: 20000, Protocol: "dnp3", Basis: "content"}},
		Functions: []netobs.BaselineFunction{{Pair: netobs.Pair{Client: lxMaster, Server: lxRelay, L4: "tcp", Port: 20000, Protocol: "dnp3"}, Code: 5, Objects: []string{"g12v1"}}},
		Addresses: []netobs.Address{
			{IP: "192.0.2.10", Endpoint: lxMaster, VLANs: []int{0, 10}, LANs: []string{"b"}},
			{IP: "192.0.2.20", Endpoint: lxRelay, VLANs: []int{0, 10}, LANs: []string{"b"}},
			{IP: "198.51.100.7", Endpoint: "addr:198.51.100.7", VLANs: []int{10}, LANs: []string{}},
		},
		AuthorizedWriters: []netobs.Writer{},
	}
	netobs.SortBaseline(want)
	wb, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, wb) {
		t.Fatalf("draft\n%s\nwant\n%s", got, wb)
	}
	if l.Through() != seq {
		t.Fatalf("through %d, want %d", l.Through(), seq)
	}
}

// lxStream is a deterministic stream of n observations over a few
// addresses, ports and kinds, with excluded ones mixed in.
func lxStream(t testing.TB, n int) []*netobs.Observation {
	t.Helper()
	srcs := []string{"192.0.2.10", "198.51.100.7", "198.51.100.8"}
	dsts := []string{"192.0.2.20", "198.51.100.9"}
	kinds := []netobs.Kind{netobs.KindFlow, netobs.KindService, netobs.KindFunction, netobs.KindFlow}
	var out []*netobs.Observation
	for i := range n {
		o := lxObs(t, kinds[i%len(kinds)], srcs[i%len(srcs)], dsts[(i/3)%len(dsts)], 20000+i%5)
		switch {
		case i%11 == 0:
			o.Node.PlatformSession = &netobs.PlatformSession{InvocationID: "inv-1", Tie: "window"}
		case i%13 == 0:
			o.Coverage.Degraded = []string{"drops"}
		case i%7 == 0:
			o.L2.VLAN = ptr(20)
		}
		out = append(out, o)
	}
	return out
}

func checkpoint(t testing.TB, l *Learner) []byte {
	t.Helper()
	b, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Acceptance: determinism across fold-batch splits, and restore equals an
// uninterrupted run. A run cut at every observation, checkpointed,
// restored and fed again from an earlier seq, as a node re-reads after a
// crash, gives the same draft bytes and the same checkpoints.
func TestLearnerRestoreAtEveryCut(t *testing.T) {
	obs := lxStream(t, 60)
	whole, err := NewLearner(lxConfig())
	if err != nil {
		t.Fatal(err)
	}
	var marks [][]byte
	for i, o := range obs {
		if err := whole.Observe(uint64(i+1), o); err != nil {
			t.Fatal(err)
		}
		marks = append(marks, checkpoint(t, whole))
	}
	want, err := whole.Freeze("2026-11-08T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut <= len(obs); cut++ {
		l, err := RestoreLearner(lxConfig(), marks[cut-1])
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		// Re-read from a few seqs back: those are passed over.
		for i := max(0, cut-3); i < len(obs); i++ {
			if err := l.Observe(uint64(i+1), obs[i]); err != nil {
				t.Fatal(err)
			}
			if i >= cut && !bytes.Equal(checkpoint(t, l), marks[i]) {
				t.Fatalf("cut %d: checkpoint at %d differs", cut, i+1)
			}
		}
		got, err := l.Freeze("2026-11-08T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("cut %d: draft differs", cut)
		}
	}
	// A restored frozen learner gives the same draft and folds nothing.
	l, err := RestoreLearner(lxConfig(), checkpoint(t, whole))
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := l.Draft(); !l.Frozen() || !bytes.Equal(d, want) {
		t.Fatal("frozen restore")
	}
	if err := l.Observe(1000, obs[0]); !errors.Is(err, ErrFrozen) {
		t.Fatalf("observe after freeze: %v", err)
	}
}

// The order the node's map iteration or batching happens to take never
// shows: two learners fed the same stream give the same bytes, whatever
// was checkpointed between.
func TestLearnerDeterministic(t *testing.T) {
	obs := lxStream(t, 40)
	run := func(every int) []byte {
		l, _ := NewLearner(lxConfig())
		for i, o := range obs {
			if err := l.Observe(uint64(i+1), o); err != nil {
				t.Fatal(err)
			}
			if every > 0 && (i+1)%every == 0 {
				var err error
				if l, err = RestoreLearner(lxConfig(), checkpoint(t, l)); err != nil {
					t.Fatal(err)
				}
			}
		}
		b, err := l.Freeze("2026-11-08T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	want := run(0)
	for _, every := range []int{1, 2, 3, 7, 256} {
		if !bytes.Equal(run(every), want) {
			t.Fatalf("fold batch %d differs", every)
		}
	}
}

// fill feeds new pairs, on new ports, until one doesn't fit, and returns
// the learner just before that observation and the observation itself.
func fill(t *testing.T) (*Learner, uint64, *netobs.Observation) {
	t.Helper()
	l, err := NewLearner(lxConfig())
	if err != nil {
		t.Fatal(err)
	}
	o := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 1)
	near := 0
	for port := 1; port <= 65535; port++ {
		o.IP.Dport = ptr(port)
		var before []byte
		if l.size() > netobs.MaxBaselineBytes-1<<10 { // near the bound: keep the state before each fold
			if near++; near > 100 {
				t.Fatal("the draft is full and nothing overflowed")
			}
			before = checkpoint(t, l)
		}
		if err := l.Observe(uint64(port), o); err != nil {
			t.Fatal(err)
		}
		if l.period.Overflow == 1 {
			if before == nil {
				t.Fatal("overflow far from the bound")
			}
			full, err := RestoreLearner(lxConfig(), before)
			if err != nil {
				t.Fatal(err)
			}
			return full, uint64(port), o
		}
	}
	t.Fatal("the draft never filled")
	return nil, 0, nil
}

// D4-71 condition 2: a draft at the bound plus one observation with a new
// entry gives overflow 1, with every list unchanged and the draft within
// MaxBaselineBytes. A repeat of the refused entry counts again: overflow
// counts observations, not entries.
func TestLearnerOverflow(t *testing.T) {
	l, seq, o := fill(t)
	lists := func() []byte {
		b, err := netobs.DecodeBaseline(must(l.Draft()))
		if err != nil {
			t.Fatal(err)
		}
		j, _ := json.Marshal([]any{b.Pairs, b.Services, b.Functions, b.Addresses})
		return j
	}
	before := lists()
	if err := l.Observe(seq, o); err != nil {
		t.Fatal(err)
	}
	if l.period.Overflow != 1 || !bytes.Equal(lists(), before) {
		t.Fatalf("overflow %d, lists changed %v", l.period.Overflow, !bytes.Equal(lists(), before))
	}
	refused := netobs.Pair{Client: lxMaster, Server: lxRelay, L4: "tcp", Port: *o.IP.Dport, Protocol: "dnp3"}
	if l.pairs[refused] {
		t.Fatal("the refused pair is in the draft")
	}
	// Known entries still fold: a repeat of a held pair adds nothing and
	// does not count.
	held := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 1)
	if err := l.Observe(seq+1, held); err != nil || l.period.Overflow != 1 {
		t.Fatalf("held pair: %v, overflow %d", err, l.period.Overflow)
	}
	if err := l.Observe(seq+2, o); err != nil || l.period.Overflow != 2 {
		t.Fatalf("repeat: %v, overflow %d", err, l.period.Overflow)
	}
	// A new VLAN on a held address is growth: it folds while it fits, and
	// once it doesn't, it is refused the same way and the entry is left
	// as it was.
	next := seq + 3
	for v := 4094; ; v-- {
		vl := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 1)
		vl.L2.VLAN = ptr(v)
		over := l.period.Overflow
		if err := l.Observe(next, vl); err != nil {
			t.Fatal(err)
		}
		next++
		if l.period.Overflow != over {
			// The source's entry may still have grown; the refused one
			// is left as it was, without the VLAN.
			src := l.addresses[addrKey{"192.0.2.10", lxMaster}].VLANs
			dst := l.addresses[addrKey{"192.0.2.20", lxRelay}].VLANs
			if l.period.Overflow != 3 || (slices.Contains(src, v) && slices.Contains(dst, v)) {
				t.Fatalf("vlan growth refused: overflow %d, src %v, dst %v", l.period.Overflow, src, dst)
			}
			break
		}
		// Not counted: both entries took the VLAN.
		src := l.addresses[addrKey{"192.0.2.10", lxMaster}].VLANs
		dst := l.addresses[addrKey{"192.0.2.20", lxRelay}].VLANs
		if !slices.Contains(src, v) || !slices.Contains(dst, v) {
			t.Fatalf("vlan %d refused and not counted: src %v, dst %v", v, src, dst)
		}
	}
	// With the draft now within a few bytes of the bound, a new source
	// address alone, on an observation that learns no pair and whose
	// destination is held as it is, is refused and counted too.
	was := lists()
	end := lxObs(t, netobs.KindFlow, "198.51.100.200", "192.0.2.20", 1)
	end.Flow = &netobs.Flow{Phase: "end", End: "fin", Packets: 9, Bytes: 900, SynOnly: ptr(false)}
	if err := l.Observe(next, end); err != nil || l.period.Overflow != 4 || !bytes.Equal(lists(), was) {
		t.Fatalf("new source address: %v, overflow %d", err, l.period.Overflow)
	}
	// So are a new service and a new function between held addresses.
	for i, k := range []netobs.Kind{netobs.KindService, netobs.KindFunction} {
		if err := l.Observe(next+1+uint64(i), lxObs(t, k, "192.0.2.10", "192.0.2.20", 1)); err != nil || l.period.Overflow != int64(5+i) || !bytes.Equal(lists(), was) {
			t.Fatalf("new %s: %v, overflow %d", k, err, l.period.Overflow)
		}
	}
	d, err := l.Freeze("9999-12-31T23:59:59.999999999Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(d) > netobs.MaxBaselineBytes {
		t.Fatalf("draft %d bytes", len(d))
	}
}

// D4-71: overflow saturates at MaxOverflow and never wraps.
func TestLearnerOverflowSaturates(t *testing.T) {
	l, seq, o := fill(t)
	var k netobs.LearnerCheckpoint
	if err := json.Unmarshal(checkpoint(t, l), &k); err != nil {
		t.Fatal(err)
	}
	b, err := netobs.DecodeBaseline(k.Draft)
	if err != nil {
		t.Fatal(err)
	}
	b.Period.Overflow = netobs.MaxOverflow
	if k.Draft, err = b.Encode(); err != nil {
		t.Fatal(err)
	}
	cp, err := k.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if l, err = RestoreLearner(lxConfig(), cp); err != nil {
		t.Fatal(err)
	}
	if err := l.Observe(seq, o); err != nil {
		t.Fatal(err)
	}
	if l.period.Overflow != netobs.MaxOverflow {
		t.Fatalf("overflow %d, want %d", l.period.Overflow, netobs.MaxOverflow)
	}
	if _, err := l.Draft(); err != nil {
		t.Fatal(err)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// A checkpoint restores only into its own run, and only whole.
func TestRestoreRefuses(t *testing.T) {
	l, _ := NewLearner(lxConfig())
	if err := l.Observe(1, lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000)); err != nil {
		t.Fatal(err)
	}
	cp := checkpoint(t, l)
	for name, cfg := range map[string]func(*LearnerConfig){
		"version": func(c *LearnerConfig) { c.Version = 2 },
		"start":   func(c *LearnerConfig) { c.StartUTC = "2026-11-02T00:00:00Z" },
		"params":  func(c *LearnerConfig) { c.Params.TieGraceS++ },
		"sensor":  func(c *LearnerConfig) { c.SensorID = lxRelay },
	} {
		c := lxConfig()
		cfg(&c)
		if _, err := RestoreLearner(c, cp); err == nil {
			t.Errorf("%s: restored into another run", name)
		}
	}
	for name, edit := range map[string]func([]byte) []byte{
		"truncated":   func(b []byte) []byte { return b[:len(b)-1] },
		"whitespace":  func(b []byte) []byte { return bytes.Replace(b, []byte(`"pairs":[`), []byte(`"pairs": [`), 1) },
		"other table": func(b []byte) []byte { return bytes.Replace(b, []byte(Table), []byte("fc-classes/9"), 1) },
		"unfrozen end": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"end_utc":"`+lxStart), []byte(`"end_utc":"2026-11-03T00:00:00Z`), 1)
		},
	} {
		if _, err := RestoreLearner(lxConfig(), edit(slices.Clone(cp))); err == nil {
			t.Errorf("%s: restored", name)
		}
	}
	if _, err := RestoreLearner(lxConfig(), cp); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestLearnerRefuses(t *testing.T) {
	if _, err := NewLearner(LearnerConfig{SensorID: lxSensor, Version: 0, StartUTC: lxStart, Params: lxConfig().Params}); err == nil {
		t.Error("version 0 accepted")
	}
	l, _ := NewLearner(lxConfig())
	other := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000)
	other.SensorID = lxRelay
	// A refused observation is reported and folds nothing, but takes its
	// seq, so the node's cursor moves past it (D5-S1 on #561); fed again,
	// it is passed over.
	empty := must(l.Draft())
	if err := l.Observe(1, other); err == nil || l.Through() != 1 {
		t.Errorf("another sensor's observation: %v, through %d", err, l.Through())
	}
	if err := l.Observe(1, other); err != nil {
		t.Errorf("a refused seq fed again: %v", err)
	}
	bare := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000)
	bare.Node = nil
	if err := l.Observe(2, bare); err == nil || l.Through() != 2 {
		t.Errorf("an observation without its node object: %v, through %d", err, l.Through())
	}
	if !bytes.Equal(must(l.Draft()), empty) {
		t.Error("a refused observation folded")
	}
	if _, err := l.Freeze("2026-10-01T00:00:00Z"); err == nil || l.Frozen() {
		t.Error("frozen before its start")
	}
	a, err := l.Freeze("2026-11-08T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := l.Freeze("2026-11-08T00:00:00Z"); err != nil || !bytes.Equal(a, b) {
		t.Errorf("freeze again: %v", err)
	}
	if _, err := l.Freeze("2026-11-09T00:00:00Z"); err == nil {
		t.Error("frozen twice at different times")
	}
}

// D3's S1 on #561: with room for a service but not for the new address it
// was seen at, the observation learns nothing and counts in overflow, so
// every entry's ends keep their address in the draft. A service is the
// entry that can be smaller than an address; a pair or a function, larger
// than any address, never fits where its address doesn't.
func TestLearnerNoEntryWithoutItsAddress(t *testing.T) {
	const v6 = "2001:db8:ffff:ffff:ffff:ffff:ffff:fff1"
	l, err := NewLearner(lxConfig())
	if err != nil {
		t.Fatal(err)
	}
	o := lxObs(t, netobs.KindService, "192.0.2.10", "192.0.2.20", 502)
	o.IP.Dst = v6 // the relay, seen at a second address
	svc := encodedLen(netobs.BaselineService{Server: lxRelay, L4: "tcp", Port: 502, Protocol: "dnp3", Basis: "content"})
	src := addressLen(&netobs.Address{IP: "192.0.2.10", Endpoint: lxMaster, VLANs: []int{10}, LANs: []string{}})
	dst := addressLen(&netobs.Address{IP: v6, Endpoint: lxRelay, VLANs: []int{10}, LANs: []string{}})
	pair := netobs.Pair{Client: lxMaster, Server: lxRelay, L4: "tcp", Port: 502, Protocol: "dnp3"}
	if svc >= dst || encodedLen(pair)+1 <= dst {
		t.Fatalf("sizes: service %d, address %d, pair %d", svc, dst, encodedLen(pair))
	}
	// Room for the source address and the service, not for the
	// destination address.
	l.lists[listPairs].bytes = netobs.MaxBaselineBytes - l.size() - (src + svc)
	l.lists[listPairs].n = 1
	if err := l.Observe(1, o); err != nil {
		t.Fatal(err)
	}
	_, held := l.addresses[addrKey{v6, lxRelay}]
	if held || len(l.services) != 0 || l.period.Overflow != 1 {
		t.Errorf("address held %v, services %d, overflow %d", held, len(l.services), l.period.Overflow)
	}
}

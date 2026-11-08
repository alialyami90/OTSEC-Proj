package netdetect

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"otsec.local/otsec/contracts/netobs"
)

// The own-session tests (baseline note §5, D1 in D4-72, D6's 2b rows).
// Constructed fixtures on the test clock, desk only.

var (
	owT0     = time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC)
	owMaster = Destination{"192.0.2.10", "tcp", 23}
	owRelay  = Destination{"192.0.2.20", "tcp", 23}
)

func owCfg(base []byte) DetectorConfig {
	return DetectorConfig{SensorID: lxSensor, NodeID: dxNode, Stream: dxStreamName, Baseline: base,
		Params:        netobs.BaselineParams{TieGraceS: netobs.DefaultTieGraceS, CoalesceWindowS: 60},
		NodeAddresses: dxNodeAddrs, NodeMACs: dxNodeMACs, NodeVLANs: dxNodeVLANs,
		Endpoints: []Endpoint{{lxMaster, owMaster}, {lxRelay, owRelay}}}
}

func owInv(n int) string { return fmt.Sprintf("0b9a6e2c-5d4f-4e3a-9b1c-%012x", n) }

// owSession is a session to dst, connected or not, over [from, to] seconds
// after owT0, handed over at health seq.
func owSession(seq uint64, n int, asset string, dst Destination, connected bool, from, to int) Session {
	at := func(s int) string { return owT0.Add(time.Duration(s) * time.Second).Format(time.RFC3339Nano) }
	return Session{Seq: seq, InvocationID: owInv(n), AssetID: asset, Endpoint: dst, Connected: connected, StartedUTC: at(from), EndedUTC: at(to)}
}

// owTied is the node's own flow to dst, tied to session n.
func owTied(t testing.TB, n int, dst Destination) *netobs.Observation {
	o := nodeFlow(dst.Addr, dst.Port, dxNodeMACs[0], ptr(10), false)(t)
	o.Node.PlatformSession = &netobs.PlatformSession{InvocationID: owInv(n), Tie: "connection"}
	return o
}

// owQuiet is traffic that raises nothing with or without the baseline: the
// master's known poll of the relay, which also records both addresses on
// VLAN 10.
func owQuiet(t testing.TB) *netobs.Observation {
	return lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000)
}

type owRun struct {
	t      *testing.T
	d      *Detector
	seq    uint64
	alerts []netobs.Alert
}

func newOwRun(t *testing.T, base []byte) *owRun {
	d, err := NewDetector(owCfg(base))
	if err != nil {
		t.Fatal(err)
	}
	return &owRun{t: t, d: d}
}

// obs takes o at s seconds after owT0.
func (r *owRun) obs(o *netobs.Observation, s int) {
	r.t.Helper()
	r.seq++
	out, err := r.d.Observe(dxID(r.seq), dxAt(r.t, o, owT0.Add(time.Duration(s)*time.Second)))
	if err != nil {
		r.t.Fatal(err)
	}
	r.alerts = append(r.alerts, out...)
}

func (r *owRun) session(s Session) error {
	r.t.Helper()
	out, err := r.d.Session(s, r.seq)
	r.alerts = append(r.alerts, out...)
	return err
}

func (r *owRun) unseen() []string {
	var out []string
	for _, a := range r.alerts {
		if a.Rule == netobs.RuleOwnSessionUnseen {
			if err := a.Validate(); err != nil {
				r.t.Errorf("unseen alert: %v", err)
			}
			out = append(out, a.AssetID)
		}
	}
	return out
}

// The canary's cases, before and after acknowledgement: it fires only for a
// connected session whose flow no observation was tied to, once the
// capture clock passes its end plus tie_grace_s, while the coverage covers
// the endpoint.
func TestOwnSessionUnseen(t *testing.T) {
	for _, base := range [][]byte{nil, accept(t, dxBaseline(t))} {
		name := "before acknowledgement"
		if base != nil {
			name = "with a baseline"
		}
		cases := []struct {
			name string
			run  func(r *owRun)
			want []string
		}{
			{"connected, no flow seen", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
				r.obs(owQuiet(t), 49)
				if len(r.unseen()) != 0 {
					t.Error("judged before the end plus tie_grace_s")
				}
				r.obs(owQuiet(t), 50)
			}, []string{lxRelay}},
			{"connected, the flow tied before the handover", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				r.obs(owTied(t, 1, owRelay), 11)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
				r.obs(owQuiet(t), 100)
			}, nil},
			{"connected, the flow tied after the handover", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
				r.obs(owTied(t, 1, owRelay), 21)
				r.obs(owQuiet(t), 100)
			}, nil},
			{"another session's flow tied", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				r.obs(owTied(t, 2, owRelay), 11)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
				r.obs(owQuiet(t), 100)
			}, []string{lxRelay}},
			{"another session's flow tied after the handover", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
				r.obs(owTied(t, 2, owRelay), 21)
				r.obs(owQuiet(t), 100)
			}, []string{lxRelay}},
			{"not connected", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, false, 10, 20)))
				r.obs(owQuiet(t), 100)
			}, nil},
			{"the sensor degraded in the window", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				o := owQuiet(t)
				o.Coverage.Degraded = []string{"drops-driver"}
				r.obs(o, 15)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
				r.obs(owQuiet(t), 100)
			}, nil},
			{"the sensor degraded before the window less tie_grace_s", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				o := owQuiet(t)
				o.Coverage.Degraded = []string{"drops-driver"}
				r.obs(o, 1)
				r.obs(owQuiet(t), 2)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 40, 50)))
				r.obs(owQuiet(t), 100)
			}, []string{lxRelay}},
			{"the endpoint's VLAN no longer seen", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
				o := lxObs(t, netobs.KindFlow, "192.0.2.10", "198.51.100.7", 502)
				o.L2.VLAN, o.Coverage.VLANsSeen = ptr(20), []int{20}
				r.obs(o, 100)
			}, nil},
			{"two sessions after one observation, judged in the order handed over", func(r *owRun) {
				r.obs(owQuiet(t), 0)
				must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
				must0(t, r.session(owSession(2, 2, lxMaster, owMaster, true, 10, 20)))
				r.obs(owQuiet(t), 100)
			}, []string{lxRelay, lxMaster}},
		}
		for _, c := range cases {
			r := newOwRun(t, base)
			c.run(r)
			if got := r.unseen(); !slices.Equal(got, c.want) {
				t.Errorf("%s, %s: unseen %v, want %v", name, c.name, got, c.want)
			}
		}
	}
}

func must0(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Before acknowledgement, an enrolled endpoint the detector has never seen
// untied raises no alert and is listed as not yet seen (D6, D4-68); its own
// tied flow doesn't count as seen.
func TestOwnSessionNotYetSeen(t *testing.T) {
	r := newOwRun(t, nil)
	if got := r.d.NotYetSeen(); len(got) != 2 {
		t.Fatalf("not yet seen %v, want both endpoints", got)
	}
	r.obs(owTied(t, 9, owRelay), 0)
	if got := r.d.NotYetSeen(); len(got) != 2 {
		t.Fatalf("not yet seen %v after a tied flow, want both endpoints", got)
	}
	r.obs(lxObs(t, netobs.KindFlow, "198.51.100.7", "192.0.2.20", 502), 1)
	if got := r.d.NotYetSeen(); !slices.Equal(got, []Endpoint{{lxMaster, owMaster}}) {
		t.Fatalf("not yet seen %v, want the master's", got)
	}
	must0(t, r.session(owSession(1, 1, lxMaster, owMaster, true, 10, 20)))
	must0(t, r.session(owSession(2, 2, lxRelay, owRelay, true, 10, 20)))
	r.obs(lxObs(t, netobs.KindFlow, "198.51.100.7", "192.0.2.20", 502), 100)
	if got := r.unseen(); !slices.Equal(got, []string{lxRelay}) {
		t.Fatalf("unseen %v, want the relay's only", got)
	}
}

// Past MaxDetectorEndpoints enrolled addresses, the rest are never
// recorded: before acknowledgement their sessions stay unjudged, and both
// NotYetSeen and EndpointsNotTracked show it (D1's C1 on #575).
func TestOwnSessionEndpointsPastTheCap(t *testing.T) {
	cfg := owCfg(nil)
	cfg.Endpoints = nil
	for i := range netobs.MaxDetectorEndpoints + 1 {
		cfg.Endpoints = append(cfg.Endpoints, Endpoint{lxRelay, Destination{fmt.Sprintf("2001:db8::%x", 0x1000+i), "tcp", 23}})
	}
	last := cfg.Endpoints[netobs.MaxDetectorEndpoints] // 2001:db8::1100 sorts last
	d, err := NewDetector(cfg)
	must0(t, err)
	if d.EndpointsNotTracked() != 1 || len(d.NotYetSeen()) != netobs.MaxDetectorEndpoints+1 {
		t.Fatalf("not tracked %d, not yet seen %d", d.EndpointsNotTracked(), len(d.NotYetSeen()))
	}
	r := &owRun{t: t, d: d}
	for _, e := range cfg.Endpoints {
		o := lxObs(t, netobs.KindFlow, "192.0.2.10", "192.0.2.20", 20000)
		o.IP.Dst = e.Addr
		r.obs(o, 0)
	}
	if got := d.NotYetSeen(); !slices.Equal(got, []Endpoint{last}) || d.EndpointsNotTracked() != 1 {
		t.Fatalf("not yet seen %v, want only the untracked %v", got, last)
	}
	must0(t, r.session(owSession(1, 1, lxRelay, last.Destination, true, 10, 20)))
	must0(t, r.session(owSession(2, 2, lxRelay, cfg.Endpoints[0].Destination, true, 10, 20)))
	r.obs(owQuiet(t), 100)
	if got := r.unseen(); len(got) != 1 {
		t.Fatalf("unseen %v: want the tracked endpoint's only", got)
	}
	must(d.Checkpoint(0))
}

// A session is judged only once the detector has taken after_seq: the
// observations up to it may still tie its flow (D1 in D4-72).
func TestOwnSessionWaitsForAfterSeq(t *testing.T) {
	r := newOwRun(t, nil)
	r.obs(owQuiet(t), 0)
	r.obs(owQuiet(t), 100)
	if out, err := r.d.Session(owSession(1, 1, lxRelay, owRelay, true, 10, 20), 3); err != nil || len(out) != 0 {
		t.Fatalf("handed over ahead: %v, %v", out, err)
	}
	r.obs(owQuiet(t), 101) // seq 3, after_seq not yet passed? it is taken now
	if len(r.unseen()) != 1 {
		t.Fatalf("unseen %v once after_seq is taken", r.unseen())
	}
	r = newOwRun(t, nil)
	r.obs(owQuiet(t), 0)
	r.obs(owQuiet(t), 100)
	must0(t, func() error { _, err := r.d.Session(owSession(1, 1, lxRelay, owRelay, true, 10, 20), 3); return err }())
	r.obs(owTied(t, 1, owRelay), 101) // seq 3 ties it
	r.obs(owQuiet(t), 102)
	if len(r.unseen()) != 0 {
		t.Fatalf("unseen %v, but seq 3 tied the flow", r.unseen())
	}
}

// An after_seq below through is the node's ordering fault: refused,
// counted, and nothing else changes. after_seq equal to through is the
// ordinary case. A session seq already taken is a replay and raises
// nothing.
func TestOwnSessionOrdering(t *testing.T) {
	r := newOwRun(t, nil)
	r.obs(owQuiet(t), 0)
	r.obs(owQuiet(t), 1)
	before := must(r.d.Checkpoint(0))
	if out, err := r.d.Session(owSession(1, 1, lxRelay, owRelay, true, 10, 20), 1); !errors.Is(err, ErrOrdering) || out != nil {
		t.Fatalf("after_seq below through: %v, %v", out, err)
	}
	if r.d.OrderingFaults() != 1 || !bytes.Equal(must(r.d.Checkpoint(0)), before) {
		t.Fatalf("faults %d; the state changed", r.d.OrderingFaults())
	}
	must0(t, r.session(owSession(1, 1, lxRelay, owRelay, true, 10, 20)))
	taken := must(r.d.Checkpoint(0))
	if out, err := r.d.Session(owSession(1, 1, lxRelay, owRelay, true, 10, 20), 2); err != nil || out != nil || !bytes.Equal(must(r.d.Checkpoint(0)), taken) {
		t.Fatalf("a replayed session: %v, %v", out, err)
	}
	if r.d.OrderingFaults() != 1 {
		t.Fatal("a replay counted as a fault")
	}
}

// The bounds fail loud: past MaxPendingSessions a session isn't judged,
// and past MaxTiedSessions the oldest tied ID is dropped; each is counted.
// Past MaxDegradedIntervals the oldest interval is dropped, never merged.
func TestOwnSessionBounds(t *testing.T) {
	r := newOwRun(t, nil)
	r.obs(owQuiet(t), 0)
	for i := range netobs.MaxPendingSessions {
		must0(t, r.session(owSession(uint64(i+1), i+1, lxRelay, owRelay, true, 10, 3600)))
	}
	if err := r.session(owSession(1000, 1000, lxRelay, owRelay, true, 10, 3600)); !errors.Is(err, ErrNotJudged) || r.d.NotJudged() != 1 {
		t.Fatalf("past the cap: %v, %d", err, r.d.NotJudged())
	}
	must(r.d.Checkpoint(0))

	r = newOwRun(t, nil)
	for i := range netobs.MaxTiedSessions + 1 {
		r.obs(owTied(t, i+1, owRelay), i)
	}
	if r.d.NotJudged() != 1 || len(r.d.tied) != netobs.MaxTiedSessions || r.d.tied[0].InvocationID != owInv(2) {
		t.Fatalf("tied past the cap: %d not judged, %d held", r.d.NotJudged(), len(r.d.tied))
	}
	must(r.d.Checkpoint(0))

	r = newOwRun(t, nil)
	for i := range netobs.MaxDegradedIntervals + 1 {
		o := owQuiet(t)
		o.Coverage.Degraded = []string{"drops-driver"}
		r.obs(o, 2*i)
		r.obs(owQuiet(t), 2*i+1)
	}
	if r.d.DegradedDropped() != 1 || len(r.d.degraded) != netobs.MaxDegradedIntervals || r.d.degraded[0].StartUTC != owT0.Add(2*time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("degraded past the cap: %d dropped, %d held", r.d.DegradedDropped(), len(r.d.degraded))
	}
	must(r.d.Checkpoint(0))
}

// A tied ID whose session never comes is dropped quietly after
// tiedHorizon on the capture clock.
func TestOwnSessionTiedHorizon(t *testing.T) {
	r := newOwRun(t, nil)
	r.obs(owTied(t, 1, owRelay), 0)
	r.obs(owQuiet(t), int(tiedHorizon/time.Second))
	if len(r.d.tied) != 1 {
		t.Fatal("dropped at the horizon")
	}
	r.obs(owQuiet(t), int(tiedHorizon/time.Second)+1)
	if len(r.d.tied) != 0 || r.d.NotJudged() != 0 {
		t.Fatalf("%d held, %d not judged past the horizon", len(r.d.tied), r.d.NotJudged())
	}
}

// The install configuration's node identity is refused when it is out of
// bounds, and addresses compare as parsed values (C13 §14 item 9).
func TestOwnConfig(t *testing.T) {
	bad := map[string]func(c *DetectorConfig){
		"no address":       func(c *DetectorConfig) { c.NodeAddresses = nil },
		"nine addresses":   func(c *DetectorConfig) { c.NodeAddresses = slices.Repeat([]string{"192.0.2.250"}, 9) },
		"a host name":      func(c *DetectorConfig) { c.NodeAddresses = []string{"node.example"} },
		"no MAC":           func(c *DetectorConfig) { c.NodeMACs = nil },
		"an uppercase MAC": func(c *DetectorConfig) { c.NodeMACs = []string{"02:00:00:00:00:FA"} },
		"nine MACs":        func(c *DetectorConfig) { c.NodeMACs = slices.Repeat(dxNodeMACs, 9) },
		"VLAN 0":           func(c *DetectorConfig) { c.NodeVLANs = []int{0} },
		"VLAN 4095":        func(c *DetectorConfig) { c.NodeVLANs = []int{4095} },
		"no segment":       func(c *DetectorConfig) { c.NodeVLANs = nil },
		"a named target":   func(c *DetectorConfig) { c.Exclusions = []Destination{{"collector.example", "tcp", 6514}} },
		"a target port 0":  func(c *DetectorConfig) { c.Exclusions = []Destination{{"192.0.2.9", "tcp", 0}} },
		"an endpoint asset": func(c *DetectorConfig) {
			c.Endpoints = []Endpoint{{"relay", owRelay}}
		},
	}
	for name, f := range bad {
		c := owCfg(nil)
		f(&c)
		if _, err := NewDetector(c); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	c := owCfg(nil)
	c.NodeAddresses, c.NodeVLANs, c.NodeUntagged = []string{"::ffff:192.0.2.250"}, nil, true
	d, err := NewDetector(c)
	if err != nil {
		t.Fatal(err)
	}
	o := nodeFlow("192.0.2.20", 23, "02:00:00:00:00:01", nil, true)(t)
	if out, err := d.Observe(dxID(1), o); err != nil || len(out) != 1 || out[0].Rule != netobs.RuleNodeAddressSpoofed {
		t.Fatalf("a mapped node address, untagged: %v, %v", out, err)
	}
}

// owStream is dxStream with the node's own sessions handed over in it: two
// unseen to the relay after one observation (a first alert and a
// summary), one tied before its handover, one not connected, one to the
// master and one to the relay after one observation (two first alerts, in
// handover order), one tied after its handover, and one in a degraded
// window.
func owStream(t testing.TB) ([]*netobs.Observation, []handoff) {
	obs := dxStream(t, 60)
	at := func(i int) time.Time { return mustTime(obs[i].FirstUTC) }
	obs[12] = dxAt(t, owTied(t, 3, owRelay), at(12))
	obs[31] = dxAt(t, owTied(t, 7, owRelay), at(31))
	obs[41].Coverage.Degraded = []string{"drops-driver"}
	return obs, []handoff{
		{6, owSession(1, 1, lxRelay, owRelay, true, 10, 20)},
		{6, owSession(2, 2, lxRelay, owRelay, true, 12, 20)},
		{14, owSession(3, 3, lxRelay, owRelay, true, 55, 65)},
		{14, owSession(4, 4, lxRelay, owRelay, false, 55, 65)},
		{24, owSession(5, 5, lxMaster, owMaster, true, 110, 120)},
		{24, owSession(6, 6, lxRelay, owRelay, true, 110, 120)},
		{30, owSession(7, 7, lxRelay, owRelay, true, 140, 150)},
		{44, owSession(8, 8, lxRelay, owRelay, true, 200, 210)},
	}
}

// D6's 2b row: restore at every cut with session handovers equals the
// uninterrupted run, with the checkpoint taken before the handovers after
// an observation (so a restore hands them over again and takes them) and
// after them (so the replay is a seq already taken), with and without a
// backward clock step.
func TestOwnSessionRestoreAtEveryCut(t *testing.T) {
	base := accept(t, dxBaseline(t))
	obs, hs := owStream(t)
	r := newOwRun(t, base)
	for i, o := range obs {
		r.seq++
		out, err := r.d.Observe(dxID(r.seq), o)
		must0(t, err)
		r.alerts = append(r.alerts, out...)
		for _, h := range hs {
			if h.after == uint64(i+1) {
				must0(t, r.session(h.s))
			}
		}
	}
	var summaries int
	for _, a := range r.alerts {
		if a.Rule == netobs.RuleOwnSessionUnseen && a.Hits > 1 {
			summaries++
		}
	}
	if got := r.unseen(); !slices.Equal(got, []string{lxRelay, lxRelay, lxMaster, lxRelay}) || summaries != 1 {
		t.Fatalf("unseen %v with %d summaries, want relay, its summary, master, relay", got, summaries)
	}
	for _, after := range []bool{false, true} {
		restoreAtEveryCut(t, owCfg(base), obs, hs, after, 4, 4, true)
	}
}

// D6's 2b negatives: a restore whose handovers depart from the run's gives
// a mismatch, never the same records silently. The checkpoint is after
// observation 24, before its two handovers, and the crashed run committed
// every alert to observation 32, both sessions' first alerts among them.
func TestOwnSessionRestoreNegatives(t *testing.T) {
	base := accept(t, dxBaseline(t))
	obs, hs := owStream(t)
	run := func(d *Detector, from int, hs []handoff, upTo int, cp *[]byte) []netobs.Alert {
		var out []netobs.Alert
		for _, h := range hs {
			if h.after == uint64(from) {
				as, _ := d.Session(h.s, h.after)
				out = append(out, as...)
			}
		}
		for i := from; i < upTo; i++ {
			as, err := d.Observe(dxID(uint64(i+1)), obs[i])
			must0(t, err)
			out = append(out, as...)
			if i+1 == 24 && cp != nil {
				*cp = must(d.Checkpoint(uint64(len(out))))
			}
			for _, h := range hs {
				if h.after == uint64(i+1) {
					as, _ := d.Session(h.s, h.after)
					out = append(out, as...)
				}
			}
		}
		return out
	}
	d, err := NewDetector(owCfg(base))
	must0(t, err)
	var cp []byte
	whole := run(d, 0, hs, 32, &cp)
	k := mustV(netobs.DecodeDetectorCheckpoint(cp))
	var committed []Committed
	for i := int(k.LastAlertSeq); i < len(whole); i++ {
		a := whole[i]
		if a.Rule != netobs.RuleOwnSessionUnseen {
			a.Capture = fmt.Sprintf("%064x", 9) // the node's
		}
		committed = append(committed, Committed{Seq: uint64(i + 1), Alert: a})
	}
	if !slices.ContainsFunc(committed, func(c Committed) bool { return c.Alert.Rule == netobs.RuleOwnSessionUnseen }) {
		t.Fatal("no unseen alert after the checkpoint: the negatives test nothing")
	}
	swapped := slices.Clone(hs)
	swapped[4], swapped[5] = swapped[5], swapped[4]
	swapped[4].s.Seq, swapped[5].s.Seq = 5, 6
	dropped := slices.Delete(slices.Clone(hs), 5, 6)
	low := slices.Clone(hs)
	low[4].after = 23
	for name, replay := range map[string][]handoff{"as run": hs, "swapped": swapped, "a handover dropped": dropped, "after_seq one low": low} {
		r, err := RestoreDetector(owCfg(base), cp, committed, 32)
		must0(t, err)
		run(r, 24, replay, 32, nil)
		if (r.Mismatches() == 0) != (name == "as run") {
			t.Errorf("%s: %d mismatches", name, r.Mismatches())
		}
	}
}

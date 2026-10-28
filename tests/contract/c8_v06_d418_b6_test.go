package contract

// C8 0.6 (#309, B3; contracts/audit/config.go): B6's own cases for D4-18,
// written from the ruling and not from B3's tests. A succeeded
// configuration-kind config.baseline_acknowledged ends every open alarm of
// its asset raised before it, whatever baseline it was against; an alarm
// raised after the latest acknowledgement still blocks a later approval; an
// event-kind or a denied or failed acknowledgement ends nothing and moves
// no baseline; another asset's alarm stays open. The 0.5 chains of
// c8_v05_config_b6_test.go run unchanged; the ones below add the 0.5 rules
// D4-18 must leave as they were.
//
// Ground truth: independent (D4-18 as B1 ruled it, D4-9). Evidence class:
// desk; digests are SHA-256 of fixed texts, the times invented.

import (
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
)

var (
	v6BaseC  = vm2Digest("b6 baseline C")
	v6EventA = vm2Digest("b6 event baseline A")
	v6EventB = vm2Digest("b6 event baseline B")
)

// v6 builds a chain on vm2Chain, numbering collector decisions itself and
// naming, in each detection, the asset's last run before its read.
type v6 struct {
	c    *vm2Chain
	next uint64
	last map[string]struct {
		seq uint64
		at  string
	}
	n int
}

func (b *v6) decision() uint64 { b.next++; return b.next }

func (b *v6) payload(what string) string { b.n++; return what + " " + strconv.Itoa(b.n) }

func (b *v6) read(asset, at string) uint64 {
	s := b.decision()
	b.c.read(s, asset, at)
	return s
}

// detect reads asset at at and records what it found against baseline:
// unapproved when approval is 0.
func (b *v6) detect(asset, baseline, at string, approval uint64) {
	prev := b.last[asset]
	s := b.read(asset, at)
	b.c.detect(s, asset, baseline, at, prev.seq, prev.at, approval)
	b.mark(asset, s, at)
}

// unchanged is a read that found the baseline: recorded only as the run.
func (b *v6) unchanged(asset, at string) { b.mark(asset, b.read(asset, at), at) }

func (b *v6) mark(asset string, seq uint64, at string) {
	b.last[asset] = struct {
		seq uint64
		at  string
	}{seq, at}
}

func (b *v6) restore(asset, baseline, at string) {
	s := b.read(asset, at)
	b.c.add(&audit.Record{Action: audit.ActionConfigBaselineRestored, Outcome: audit.OutcomeInfo,
		Time: audit.Time{UTC: at}, Actor: audit.Actor{Type: authz.PrincipalNode, ID: vm2Node},
		Target: &audit.Target{AssetID: asset}, CorrelationID: "restore-" + at,
		Config: &audit.Config{BaselineDigest: baseline, SnapshotDigest: baseline, ReadSeq: s}})
	b.mark(asset, s, at)
}

// ack is an accepted acknowledgement of kind for asset, recorded with
// outcome; prev is the baseline it names as replaced ("" for the first).
func (b *v6) ack(asset string, kind authz.BaselineKind, digest, prev string, outcome audit.Outcome) {
	s := b.decision()
	p := b.payload("ack " + string(kind))
	b.c.accept(s, vm2Person, p, authz.KindNodeBaselineAck)
	r := &audit.Record{Action: audit.ActionConfigBaselineAcknowledge, Outcome: outcome,
		Actor: audit.Actor{Type: authz.PrincipalHuman, ID: vm2Person}, Target: &audit.Target{AssetID: asset},
		CorrelationID: "ack-" + p,
		Config: &audit.Config{DecisionSeq: s, PayloadSHA256: vm2Hex(p), Kind: kind,
			BaselineDigest: digest, PreviousDigest: prev}}
	if outcome != audit.OutcomeSucceeded {
		r.ReasonCode = "b6_refused"
	}
	b.c.add(r)
}

func (b *v6) cfgAck(asset, digest, prev string) {
	b.ack(asset, authz.BaselineConfiguration, digest, prev, audit.OutcomeSucceeded)
}

// approve is an accepted approval against baseline, its window wide
// enough to cover every detection here.
func (b *v6) approve(asset, baseline string) uint64 {
	s := b.decision()
	p := b.payload("approve")
	b.c.accept(s, vm2Person, p, authz.KindNodeChangeApproval)
	b.c.approve(s, vm2Person, p, asset, baseline, "2026-11-02T08:00:00Z", "2026-11-02T12:00:00Z")
	return s
}

// v6Base: both assets read at R0, baseline A acknowledged for each, both
// read unchanged at Rm.
func v6Base() *v6 {
	b := &v6{c: &vm2Chain{}, last: map[string]struct {
		seq uint64
		at  string
	}{}}
	for _, a := range []string{vm2Asset, vm2Other} {
		b.unchanged(a, vm2R0)
		b.cfgAck(a, vm2BaseA, "")
	}
	for _, a := range []string{vm2Asset, vm2Other} {
		b.unchanged(a, vm2Rm)
	}
	return b
}

// v6At is a read time after R1, minute m past 09:00.
func v6At(m int) string { return "2026-11-02T" + strconv.Itoa(9+m/60) + ":" + v6Pad(m%60) + ":00Z" }

func v6Pad(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func TestC8V06B6D418(t *testing.T) {
	ev := authz.BaselineEvent
	cases := []struct {
		name  string
		build func(b *v6)
		want  string // "" accepts; otherwise the refusal names it
	}{
		// An acknowledgement ends the alarms raised before it.
		{"A to B to A after an alarm: an approved change from A verifies", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.cfgAck(vm2Asset, vm2BaseA, vm2BaseB)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, ""},
		{"A to B after an alarm: an approved change from B verifies", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			ap := b.approve(vm2Asset, vm2BaseB)
			b.detect(vm2Asset, vm2BaseB, v6At(10), ap)
		}, ""},
		{"A acknowledged again after an alarm on A: an approved change verifies", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseA, vm2BaseA)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, ""},
		{"two alarms on A, then A acknowledged again: both end", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.detect(vm2Asset, vm2BaseA, v6At(5), 0)
			b.cfgAck(vm2Asset, vm2BaseA, vm2BaseA)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, ""},
		{"A to B to C after an alarm: an approved change from C verifies", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.cfgAck(vm2Asset, v6BaseC, vm2BaseB)
			ap := b.approve(vm2Asset, v6BaseC)
			b.detect(vm2Asset, v6BaseC, v6At(10), ap)
		}, ""},
		{"an approval accepted between the alarm and the acknowledgement", func(b *v6) {
			// Not ruled on by D4-18; recorded as what 0.6 does: the
			// approval names the baseline active when it was accepted.
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.cfgAck(vm2Asset, vm2BaseA, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, ""},

		// An alarm raised after the latest acknowledgement still blocks.
		{"an alarm on B after B was acknowledged blocks an approval", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.detect(vm2Asset, vm2BaseB, v6At(5), 0)
			ap := b.approve(vm2Asset, vm2BaseB)
			b.detect(vm2Asset, vm2BaseB, v6At(10), ap)
		}, "is still open"},
		{"an alarm on A after A was acknowledged again blocks an approval", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseA, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(5), 0)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, "is still open"},
		{"the approval accepted before the later alarm still does not silence it", func(b *v6) {
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			ap := b.approve(vm2Asset, vm2BaseB)
			b.detect(vm2Asset, vm2BaseB, v6At(5), 0)
			b.detect(vm2Asset, vm2BaseB, v6At(10), ap)
		}, "is still open"},
		{"the later alarm ends at the next acknowledgement", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.detect(vm2Asset, vm2BaseB, v6At(5), 0)
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseB)
			ap := b.approve(vm2Asset, vm2BaseB)
			b.detect(vm2Asset, vm2BaseB, v6At(10), ap)
		}, ""},

		// An event-kind acknowledgement ends nothing.
		{"an event-kind acknowledgement does not end a configuration alarm", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.ack(vm2Asset, ev, v6EventA, "", audit.OutcomeSucceeded)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, "is still open"},
		{"an event-kind acknowledgement naming A's digest ends nothing either", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.ack(vm2Asset, ev, vm2BaseA, "", audit.OutcomeSucceeded)
			b.ack(vm2Asset, ev, vm2BaseA, vm2BaseA, audit.OutcomeSucceeded)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, "is still open"},
		{"an event-kind acknowledgement does not move the configuration baseline", func(b *v6) {
			b.ack(vm2Asset, ev, vm2BaseB, "", audit.OutcomeSucceeded)
			b.detect(vm2Asset, vm2BaseB, vm2R1, 0)
		}, "acknowledged configuration baseline is"},
		{"event-kind acknowledgements keep their own previous digest", func(b *v6) {
			b.ack(vm2Asset, ev, v6EventA, "", audit.OutcomeSucceeded)
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.ack(vm2Asset, ev, v6EventB, v6EventA, audit.OutcomeSucceeded)
			b.detect(vm2Asset, vm2BaseB, vm2R1, 0)
		}, ""},

		// A denied or failed acknowledgement moves neither alarm nor baseline.
		{"a denied acknowledgement does not end the alarm", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.ack(vm2Asset, authz.BaselineConfiguration, vm2BaseA, vm2BaseA, audit.OutcomeDenied)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, "is still open"},
		{"a failed acknowledgement does not end the alarm", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.ack(vm2Asset, authz.BaselineConfiguration, vm2BaseA, vm2BaseA, audit.OutcomeFailed)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, "is still open"},
		{"a denied acknowledgement of B does not move the baseline to B", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.ack(vm2Asset, authz.BaselineConfiguration, vm2BaseB, vm2BaseA, audit.OutcomeDenied)
			b.detect(vm2Asset, vm2BaseB, v6At(10), 0)
		}, "acknowledged configuration baseline is"},
		{"after a denied acknowledgement of B, the next one still replaces A", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.ack(vm2Asset, authz.BaselineConfiguration, vm2BaseB, vm2BaseA, audit.OutcomeDenied)
			b.cfgAck(vm2Asset, v6BaseC, vm2BaseB)
		}, "names \""},
		{"after a denied acknowledgement of B, one replacing A verifies and ends the alarm", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.ack(vm2Asset, authz.BaselineConfiguration, vm2BaseB, vm2BaseA, audit.OutcomeDenied)
			b.cfgAck(vm2Asset, v6BaseC, vm2BaseA)
			ap := b.approve(vm2Asset, v6BaseC)
			b.detect(vm2Asset, v6BaseC, v6At(10), ap)
		}, ""},

		// Another asset's alarm stays open.
		{"an acknowledgement of one asset leaves the other's alarm open", func(b *v6) {
			b.detect(vm2Other, vm2BaseA, vm2R1, 0)
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseA, vm2BaseA)
			ap := b.approve(vm2Other, vm2BaseA)
			b.detect(vm2Other, vm2BaseA, v6At(10), ap)
		}, "is still open"},
		{"same chain: the acknowledged asset's approved change verifies", func(b *v6) {
			b.detect(vm2Other, vm2BaseA, vm2R1, 0)
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseA, vm2BaseA)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, ""},
		{"an acknowledgement of one asset to B leaves the other on A", func(b *v6) {
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.detect(vm2Other, vm2BaseB, vm2R1, 0)
		}, "acknowledged configuration baseline is"},
		{"an acknowledgement after a reinstall still ends the alarm", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.c.reset(v6At(4))
			b.mark(vm2Asset, 0, v6At(4))
			b.cfgAck(vm2Asset, vm2BaseA, vm2BaseA)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, ""},
	}
	for _, tc := range cases {
		b := v6Base()
		tc.build(b)
		err := audit.VerifyConfig(b.c.recs)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && err == nil:
			t.Errorf("%s: accepted", tc.name)
		case tc.want != "" && !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: refused for another reason: %v", tc.name, err)
		}
	}
}

// The 0.5 rules D4-18 leaves as they were.
func TestC8V06B6Keeps05(t *testing.T) {
	cases := []struct {
		name  string
		build func(b *v6)
		want  string
	}{
		{"an approved change with no alarm", func(b *v6) {
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, vm2R1, ap)
		}, ""},
		{"a restore still ends the alarm", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.restore(vm2Asset, vm2BaseA, v6At(5))
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, ""},
		{"a restore ends only its asset's alarm", func(b *v6) {
			b.detect(vm2Other, vm2BaseA, vm2R1, 0)
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.restore(vm2Asset, vm2BaseA, v6At(5))
			ap := b.approve(vm2Other, vm2BaseA)
			b.detect(vm2Other, vm2BaseA, v6At(10), ap)
		}, "is still open"},
		{"an approval after the alarm, no restore and no acknowledgement", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			ap := b.approve(vm2Asset, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), ap)
		}, "is still open"},
		{"an acknowledgement chain of three, each naming the last", func(b *v6) {
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.cfgAck(vm2Asset, v6BaseC, vm2BaseB)
			b.cfgAck(vm2Asset, vm2BaseA, v6BaseC)
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
		}, ""},
		{"an acknowledgement naming a baseline that is not the last", func(b *v6) {
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.cfgAck(vm2Asset, v6BaseC, vm2BaseA)
		}, "names \""},
		{"an acknowledgement with no acceptance does not end the alarm: it is refused", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.c.ack(999, vm2Person, "no acceptance", vm2Asset, vm2BaseA)
		}, "no earlier acceptance"},
		{"an acknowledgement on a change-approval acceptance is refused", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			s := b.decision()
			b.c.accept(s, vm2Person, "approval bytes", authz.KindNodeChangeApproval)
			b.c.ack(s, vm2Person, "approval bytes", vm2Asset, vm2BaseA)
		}, "not node.baseline_ack"},
		{"an acknowledgement by another person than the one verified is refused", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			s := b.decision()
			b.c.accept(s, vm2Person, "ack bytes", authz.KindNodeBaselineAck)
			b.c.ack(s, vm2Other2, "ack bytes", vm2Asset, vm2BaseA)
		}, "does not match the acceptance"},
		{"a detection against the old baseline after an acknowledgement", func(b *v6) {
			b.detect(vm2Asset, vm2BaseA, vm2R1, 0)
			b.cfgAck(vm2Asset, vm2BaseB, vm2BaseA)
			b.detect(vm2Asset, vm2BaseA, v6At(10), 0)
		}, "acknowledged configuration baseline is"},
	}
	for _, tc := range cases {
		b := v6Base()
		tc.build(b)
		err := audit.VerifyConfig(b.c.recs)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && err == nil:
			t.Errorf("%s: accepted", tc.name)
		case tc.want != "" && !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: refused for another reason: %v", tc.name, err)
		}
	}
}

package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// configKinds is a pinned key's list that adds the configuration kinds to
// the 0.5 ones (docs/phase4/B3-c7-0.6-c8-0.5.md, the enrolment step).
var configKinds = append(append([]authz.RequestKind{}, authz.DefaultAdminKinds...), authz.KindNodeChangeApproval, authz.KindNodeBaselineAck)

// signedCfgNode is a cfgNode whose collector is an adminMux: runs are
// answered by the cfgNode's fake, the administrator's signed requests by an
// adminCollector whose key may sign the configuration kinds, and both are
// numbered from one counter.
type signedCfgNode struct {
	*cfgNode
	nc    *nodeconfigtest.Config
	mux   *adminMux
	files int
	ids   map[string]string // file name: request ID
}

func newSignedCfgNode(t *testing.T, mod func(*nodeconfigtest.Config)) *signedCfgNode {
	t.Helper()
	var nc *nodeconfigtest.Config
	c, dir := schedConfig(t, withConfigRead(t, func(n *nodeconfigtest.Config) {
		n.AdminDir = n.TLSDir
		nc = n
		if mod != nil {
			mod(n)
		}
	}))
	if err := store.CreateDir(nc.TLSDir, ""); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
	locked := *nc
	t.Cleanup(func() { locked.UnlockTLS() })
	r, st, _ := start(t, c, dir)
	t.Cleanup(func() { r.Close() })
	n := &signedCfgNode{cfgNode: &cfgNode{t: t, r: r, st: st}, nc: nc, ids: map[string]string{}}
	n.f = &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		raw, err := json.Marshal(n.next)
		if err != nil {
			t.Fatal(err)
		}
		return collectorclient.Response{Reply: accepted(req, 0),
			Outcome: &collectorclient.Outcome{InvocationID: okInvocation, Result: n.next, ResultJSON: raw}}, nil
	}}
	n.mux = &adminMux{run: n.f, admin: newAdminCollector()}
	n.mux.admin.installKey, n.mux.admin.kinds = kid(testInstallKey), configKinds
	n.s = newScheduler(t, r, n.mux)
	return n
}

// read is cfgNode.read with the mux's numbering.
func (n *signedCfgNode) read(name string) Report {
	n.t.Helper()
	n.next = cfgResult(n.t, name)
	rep := n.s.RunOnce(bg, 1)
	if !rep.Sent || rep.Outcome == "" {
		n.t.Fatalf("read %s: %+v", name, rep)
	}
	return rep
}

// sign leaves a signed request of kind in admin_dir, with edit setting its
// body, and relays it.
func (n *signedCfgNode) sign(kind authz.RequestKind, edit func(*authz.AdminRequest)) string {
	n.t.Helper()
	n.files++
	env := signN(n.t, kind, n.files, func(p *authz.AdminRequest) {
		p.InstallKeyID = kid(testInstallKey)
		edit(p)
	})
	name := "admin-request-" + strings.Repeat("x", n.files) + ".json"
	b := writeAdminFile(n.t, n.nc, name, kind, env)
	sum := sha256.Sum256(b)
	n.ids[name] = adminRequestID(hex.EncodeToString(sum[:]))
	n.s.relayAdmin(bg)
	return name
}

func (n *signedCfgNode) ackSigned(kind authz.BaselineKind, digest string) string {
	return n.sign(authz.KindNodeBaselineAck, func(p *authz.AdminRequest) {
		p.NodeBaselineAck = &authz.NodeBaselineAckBody{AssetID: relayID, Kind: kind, BaselineDigest: digest}
	})
}

func (n *signedCfgNode) approveSigned(digest string) string {
	now := time.Now().UTC().Truncate(time.Second)
	return n.sign(authz.KindNodeChangeApproval, func(p *authz.AdminRequest) {
		p.NodeChangeApproval = &authz.NodeChangeApprovalBody{AssetID: relayID, BaselineDigest: digest,
			WindowStart: now.Add(-time.Hour).Format(time.RFC3339), WindowEnd: now.Add(time.Hour).Format(time.RFC3339), Reason: "Replace CT ratio (work order 4711)"}
	})
}

// decisions are the chain's records of the action, and the chain verifies.
func (n *signedCfgNode) decisions(action audit.Action) []*audit.Record {
	n.t.Helper()
	all := auditRecords(n.t, n.r)
	if err := audit.VerifyConfig(all); err != nil {
		n.t.Fatalf("the chain does not verify: %v", err)
	}
	var out []*audit.Record
	for _, r := range all {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// acceptance is the collector's accepted record of the request in file
// name.
func (n *signedCfgNode) acceptance(name string) *audit.Record {
	n.t.Helper()
	for _, rec := range requestRecords(auditRecords(n.t, n.r), n.ids[name]) {
		if rec.Verified != nil {
			return rec
		}
	}
	n.t.Fatal("no acceptance")
	return nil
}

func (n *signedCfgNode) part(name string) AdminRequestStatus {
	n.t.Helper()
	for _, a := range adminShown(n.st) {
		if a.File == name {
			return a
		}
	}
	n.t.Fatalf("%s not in status: %+v", name, adminShown(n.st))
	return AdminRequestStatus{}
}

// A signed acknowledgement of a stored snapshot is recorded once, as the
// verified person's, with the collector's decision, and the snapshot is
// held as the baseline at once; the next read compares against it. Relayed
// again, and after a restart, nothing more is recorded. Evidence class:
// simulated.
func TestSignedConfigurationAcknowledgement(t *testing.T) {
	n := newSignedCfgNode(t, nil)
	base := n.snapshotOf("ok")
	n.read("ok")
	name := n.ackSigned(authz.BaselineConfiguration, base)

	acks := n.decisions(audit.ActionConfigBaselineAcknowledge)
	if len(acks) != 1 {
		t.Fatalf("%d acknowledgements", len(acks))
	}
	a, acc := acks[0], n.acceptance(name)
	if a.Outcome != audit.OutcomeSucceeded || a.Actor.Type != authz.PrincipalHuman || a.Actor.ID != relayAdmin.ID ||
		a.Config.DecisionSeq != acc.CollectorSeq || a.Config.PayloadSHA256 != acc.Verified.PayloadSHA256 ||
		a.Config.Kind != authz.BaselineConfiguration || a.Config.BaselineDigest != base || a.Config.PreviousDigest != "" {
		t.Fatalf("acknowledgement %+v %+v", a, a.Config)
	}
	if h := n.holds(); len(h) != 1 || h[1] != c5.HoldBaseline {
		t.Fatalf("holds %v", h)
	}
	if p := n.part(name); p.NodePart != partDone {
		t.Fatalf("part %+v", p)
	}
	n.read("ok")
	if res := n.results(); len(res) != 1 || res[0].Action != audit.ActionConfigReadCompared || res[0].Config.BaselineDigest != base {
		t.Fatalf("results %+v", res)
	}

	n.s.relayAdmin(bg)
	n.s = newScheduler(t, n.r, n.mux)
	n.s.relayAdmin(bg)
	if got := n.decisions(audit.ActionConfigBaselineAcknowledge); len(got) != 1 {
		t.Fatalf("%d acknowledgements after a restart", len(got))
	}
}

// A second acknowledgement names the first as previous_digest, holds the
// new baseline and moves the old one to superseded; one of the baseline
// already acknowledged records nothing. Evidence class: simulated.
func TestSignedConfigurationAcknowledgementSucceeds(t *testing.T) {
	n := newSignedCfgNode(t, nil)
	base, next := n.snapshotOf("ok"), n.snapshotOf("ok-all-present")
	n.read("ok")
	n.ackSigned(authz.BaselineConfiguration, base)
	n.read("ok-all-present")
	again := n.ackSigned(authz.BaselineConfiguration, base)
	if p := n.part(again); p.NodePart != partNothing {
		t.Fatalf("part %+v", p)
	}
	n.ackSigned(authz.BaselineConfiguration, next)
	acks := n.decisions(audit.ActionConfigBaselineAcknowledge)
	if len(acks) != 2 || acks[1].Config.BaselineDigest != next || acks[1].Config.PreviousDigest != base {
		t.Fatalf("acknowledgements %+v", acks)
	}
	var codes []c5.HoldCode
	for _, seq := range []c5.Seq{1, 2} {
		codes = append(codes, n.holds()[seq])
	}
	if codes[0] != c5.HoldSupersededBaseline {
		t.Fatalf("holds %v", n.holds())
	}
	if !holdsBaseline(n.holds()) {
		t.Fatalf("holds %v: the new baseline is not held", n.holds())
	}
}

func holdsBaseline(h map[c5.Seq]c5.HoldCode) bool {
	for _, c := range h {
		if c == c5.HoldBaseline {
			return true
		}
	}
	return false
}

// What the node does not hold is refused and recorded as denied, once: a
// digest no record has, a configuration acknowledgement of an event
// baseline's kind, and an approval against a baseline no one acknowledged.
// The chain still verifies, the file's part is refused, and neither a
// second relay nor a new scheduler records them again. Evidence class:
// simulated.
func TestSignedConfigurationDenials(t *testing.T) {
	n := newSignedCfgNode(t, nil)
	base := n.snapshotOf("ok")
	n.read("ok")
	none := "sha256:" + strings.Repeat("c", 64)

	name := n.ackSigned(authz.BaselineConfiguration, none)
	n.ackSigned(authz.BaselineEvent, base)
	approval := n.approveSigned(base)
	acks := n.decisions(audit.ActionConfigBaselineAcknowledge)
	if len(acks) != 2 || acks[0].Outcome != audit.OutcomeDenied || acks[0].ReasonCode != ReasonBaselineNotHeld ||
		acks[1].Outcome != audit.OutcomeDenied || acks[1].ReasonCode != ReasonBaselineNotHeld {
		t.Fatalf("acknowledgements %+v", acks)
	}
	aps := n.decisions(audit.ActionConfigChangeApproved)
	if len(aps) != 1 || aps[0].Outcome != audit.OutcomeDenied || aps[0].ReasonCode != ReasonBaselineNotAcknowledged || aps[0].Config.Reason == "" {
		t.Fatalf("approvals %+v", aps)
	}
	for _, f := range []string{name, approval} {
		if p := n.part(f); p.NodePart != partRefused {
			t.Fatalf("%s: part %+v", f, p)
		}
	}
	if h := n.holds(); len(h) != 0 {
		t.Fatalf("holds %v", h)
	}
	n.s.relayAdmin(bg)
	n.s = newScheduler(t, n.r, n.mux) // what was recorded is known from the chain
	n.s.relayAdmin(bg)
	if len(n.decisions(audit.ActionConfigBaselineAcknowledge)) != 2 || len(n.decisions(audit.ActionConfigChangeApproved)) != 1 {
		t.Fatal("recorded again")
	}
}

// A signed approval against the acknowledged baseline is recorded, and the
// change a later read finds is approved by it. Evidence class: simulated.
func TestSignedChangeApproval(t *testing.T) {
	n := newSignedCfgNode(t, nil)
	base := n.snapshotOf("ok")
	n.read("ok")
	n.ackSigned(authz.BaselineConfiguration, base)
	name := n.approveSigned(base)
	aps := n.decisions(audit.ActionConfigChangeApproved)
	acc := n.acceptance(name)
	if len(aps) != 1 || aps[0].Outcome != audit.OutcomeSucceeded || aps[0].Config.DecisionSeq != acc.CollectorSeq || aps[0].Config.BaselineDigest != base {
		t.Fatalf("approvals %+v", aps)
	}
	n.read("ok-all-present")
	res := n.results()
	if len(res) != 1 || res[0].ReasonCode != audit.ReasonApprovedChange || res[0].Config.ApprovalSeq != acc.CollectorSeq {
		t.Fatalf("results %+v", res)
	}
}

// Without the kind in the key's list the collector refuses at authority,
// and the node records nothing of its own. Evidence class: simulated.
func TestSignedConfigurationKindNotPinned(t *testing.T) {
	n := newSignedCfgNode(t, nil)
	n.mux.admin.kinds = nil
	base := n.snapshotOf("ok")
	n.read("ok")
	name := n.ackSigned(authz.BaselineConfiguration, base)
	if got := n.decisions(audit.ActionConfigBaselineAcknowledge); len(got) != 0 {
		t.Fatalf("recorded %+v", got)
	}
	if p := n.part(name); p.State != "refused" {
		t.Fatalf("part %+v", p)
	}
}

// A signed acknowledgement of the event baseline the node recorded is
// recorded, holds the baseline, and activates it in the lifecycle at the
// record's time; again, it is nothing to do. One of a stored baseline whose
// recording is not in the chain is not the next, and is denied. Evidence
// class: simulated.
func TestSignedEventAcknowledgement(t *testing.T) {
	n := newSignedCfgNode(t, func(nc *nodeconfigtest.Config) { nc.AddEventBaseline(relayID) })
	if n.s.events == nil {
		t.Fatal("no event baselines")
	}
	l := n.s.events.life
	learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	h := recordedOf(t, n.r)[0].Config.BaselineDigest

	l.assets[relayID].unrecorded = true
	early := n.ackSigned(authz.BaselineEvent, h)
	if p := n.part(early); p.NodePart != partRefused {
		t.Fatalf("part %+v", p)
	}
	l.assets[relayID].unrecorded = false

	name := n.ackSigned(authz.BaselineEvent, h)
	acks := n.decisions(audit.ActionConfigBaselineAcknowledge)
	if len(acks) != 2 || acks[0].ReasonCode != ReasonBaselineNotNext || acks[1].Outcome != audit.OutcomeSucceeded ||
		acks[1].Config.Kind != authz.BaselineEvent || acks[1].Config.BaselineDigest != h || acks[1].Config.PreviousDigest != "" {
		t.Fatalf("acknowledgements %+v", acks)
	}
	if p := n.part(name); p.NodePart != partDone {
		t.Fatalf("part %+v", p)
	}
	if hs := n.holds(); len(hs) != 1 || !holdsBaseline(hs) {
		t.Fatalf("holds %v", hs)
	}
	if _, d := l.half(relayID); d == nil {
		t.Fatal("the baseline is not active")
	}
	at, _ := time.Parse(time.RFC3339Nano, acks[1].Time.UTC)
	if !l.assets[relayID].activeFrom.Equal(at) {
		t.Fatalf("active from %v, want the record's time %v", l.assets[relayID].activeFrom, at)
	}
	again := n.ackSigned(authz.BaselineEvent, h)
	if p := n.part(again); p.NodePart != partNothing || len(n.decisions(audit.ActionConfigBaselineAcknowledge)) != 2 {
		t.Fatalf("part %+v", p)
	}
}

// An acknowledgement whose record is not written is not done: the part
// stays pending, no hold is taken and nothing is activated, and the next
// relay writes the record once (C6 on #406). Evidence class: simulated.
func TestSignedAcknowledgementNotWritten(t *testing.T) {
	n := newSignedCfgNode(t, func(nc *nodeconfigtest.Config) { nc.AddEventBaseline(relayID) })
	l := n.s.events.life
	learnOnce(t, l, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	h := recordedOf(t, n.r)[0].Config.BaselineDigest
	appendFault = func() error { return errors.New("forced fault") }
	t.Cleanup(func() { appendFault = nil })
	name := n.ackSigned(authz.BaselineEvent, h)
	if p := n.part(name); p.NodePart != partPending || !strings.Contains(p.Detail, "forced fault") {
		t.Fatalf("part %+v", p)
	}
	if acks := n.decisions(audit.ActionConfigBaselineAcknowledge); len(acks) != 0 {
		t.Fatalf("acknowledgements %+v", acks)
	}
	if hs := n.holds(); holdsBaseline(hs) {
		t.Fatalf("holds %v", hs)
	}
	if _, d := l.half(relayID); d != nil {
		t.Fatal("the baseline is active with no acknowledgement in the chain")
	}

	appendFault = nil
	n.s.relayAdmin(bg)
	if acks := n.decisions(audit.ActionConfigBaselineAcknowledge); len(acks) != 1 || acks[0].Outcome != audit.OutcomeSucceeded {
		t.Fatalf("acknowledgements %+v", acks)
	}
	if p := n.part(name); p.NodePart != partDone {
		t.Fatalf("part %+v", p)
	}
	if hs := n.holds(); !holdsBaseline(hs) {
		t.Fatalf("holds %v", hs)
	}
	if _, d := l.half(relayID); d == nil {
		t.Fatal("the baseline is not active")
	}
	n.s.relayAdmin(bg)
	if acks := n.decisions(audit.ActionConfigBaselineAcknowledge); len(acks) != 1 {
		t.Fatalf("%d acknowledgements after another relay", len(acks))
	}
}

// A repeat answer's record names the first acceptance as decision_seq
// (repeat_of), not the repeat's own number, and the decision is recorded
// once. Evidence class: simulated.
func TestSignedConfigurationRepeatAnswer(t *testing.T) {
	n := newSignedCfgNode(t, nil)
	n.mux.admin.repeat, n.mux.admin.lose = true, true
	base := n.snapshotOf("ok")
	n.read("ok")
	name := n.ackSigned(authz.BaselineConfiguration, base) // decided, reply lost
	if got := n.decisions(audit.ActionConfigBaselineAcknowledge); len(got) != 0 {
		t.Fatalf("recorded before any reply: %+v", got)
	}
	n.mux.admin.mu.Lock()
	n.mux.admin.lose = false
	n.mux.admin.mu.Unlock()
	n.s.relayAdmin(bg)
	acc := n.acceptance(name)
	if acc.RepeatOf == 0 || acc.RepeatOf == acc.CollectorSeq {
		t.Fatalf("not a repeat answer: %+v", acc)
	}
	acks := n.decisions(audit.ActionConfigBaselineAcknowledge)
	if len(acks) != 1 || acks[0].Outcome != audit.OutcomeSucceeded || acks[0].Config.DecisionSeq != acc.RepeatOf {
		t.Fatalf("acknowledgements %+v, want decision_seq %d", acks, acc.RepeatOf)
	}
}

// configPart is the node's part of an accepted configuration request
// built by hand: the entry is the folded acceptance, as in
// TestApplyAdminPartGates.
func (n *signedCfgNode) configPart(edit func(*authz.AdminRequest)) adminPart {
	n.t.Helper()
	n.files++
	env := signN(n.t, authz.KindNodeBaselineAck, n.files, func(p *authz.AdminRequest) {
		p.InstallKeyID = kid(testInstallKey)
		p.NodeBaselineAck = &authz.NodeBaselineAckBody{AssetID: relayID, Kind: authz.BaselineConfiguration, BaselineDigest: n.snapshotOf("ok")}
		if edit != nil {
			edit(p)
		}
	})
	f := &adminFile{name: "admin-request-gate.json", sum: strings.Repeat("cd", 32), kind: authz.KindNodeBaselineAck, signed: env,
		claims: adminClaims{Kind: authz.KindNodeBaselineAck, Principal: relayAdmin}}
	f.id = adminRequestID(f.sum)
	n.s.mu.Lock()
	n.s.relayed[f.id] = relayEntry{Outcome: audit.OutcomeAllowed, CollectorSeq: 5, Verified: &audit.Admin{AdminKeyID: env.KeyID,
		Principal: relayAdmin.ID, Nonce: strings.Repeat("A", 22), PayloadSHA256: authz.AdminPayloadSHA256(env), Kind: authz.KindNodeBaselineAck}}
	n.s.mu.Unlock()
	return n.s.applyAdminParts(bg, []*adminFile{f})[f.id]
}

// The configuration kinds are bound to the install key the node trusts: an
// acceptance for another key is refused for good, and one while a reset is
// open waits, and neither records anything. Evidence class: simulated.
func TestSignedConfigurationInstallKeyGates(t *testing.T) {
	n := newSignedCfgNode(t, nil)
	n.read("ok")
	if p := n.configPart(func(p *authz.AdminRequest) { p.InstallKeyID = kid("other-install-key") }); p.state != partRefused || !strings.Contains(p.detail, "not the key the node trusts") {
		t.Fatalf("another key: %+v", p)
	}
	n.s.mu.Lock()
	n.s.cs.OpenResetKey = kid("new-install-key")
	n.s.mu.Unlock()
	if p := n.configPart(nil); p.state != partPending || !strings.Contains(p.detail, "not acknowledged yet") {
		t.Fatalf("an open reset: %+v", p)
	}
	if got := n.decisions(audit.ActionConfigBaselineAcknowledge); len(got) != 0 {
		t.Fatalf("recorded: %+v", got)
	}
}

// A configuration acknowledgement of a stored C10 baseline is denied
// baseline_not_held: the record with the digest is not a snapshot.
// Evidence class: simulated.
func TestSignedConfigurationAckOfAnEventBaseline(t *testing.T) {
	n := newSignedCfgNode(t, func(nc *nodeconfigtest.Config) { nc.AddEventBaseline(relayID) })
	learnOnce(t, n.s.events.life, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	h := recordedOf(t, n.r)[0].Config.BaselineDigest
	name := n.ackSigned(authz.BaselineConfiguration, h)
	acks := n.decisions(audit.ActionConfigBaselineAcknowledge)
	if len(acks) != 1 || acks[0].Outcome != audit.OutcomeDenied || acks[0].ReasonCode != ReasonBaselineNotHeld {
		t.Fatalf("acknowledgements %+v", acks)
	}
	if p := n.part(name); p.NodePart != partRefused {
		t.Fatalf("part %+v", p)
	}
	if _, d := n.s.events.life.half(relayID); d != nil {
		t.Fatal("the event baseline was activated")
	}
}

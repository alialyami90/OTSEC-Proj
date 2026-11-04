package node

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
)

const heldRef = "7d1f9e2a-4b3c-4d5e-8f60-1a2b3c4d5e6f"

// holdingCollector answers like suspendingCollector until hold is set.
// Then it holds the asset suspended by held, as a collector whose reply to
// the suspending run was lost: runs are refused asset_suspended naming it,
// a clear of it is accepted and lifts it, and a clear of another is
// refused suspension_mismatch naming it (C7 0.3, A3 #125).
type holdingCollector struct {
	*fakeCollector
	mu   sync.Mutex
	held *authz.HeldSuspension
	seq  uint64
}

func newHoldingCollector(t *testing.T) *holdingCollector {
	h := &holdingCollector{fakeCollector: suspendingCollector(t, false)}
	base := h.answer
	refuse := func(req *authz.CollectorRequest, code authz.RefusalCode, held *authz.HeldSuspension) collectorclient.Response {
		h.seq++
		return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, Status: authz.ReplyRefused,
			Refusal: &authz.Refusal{Code: code, Detail: "test", Suspension: held}, CollectorSeq: 1000 + h.seq}}
	}
	h.answer = func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		held := h.held
		switch {
		case held == nil:
			return base(req)
		case req.Kind == authz.KindAssetClearSusp && req.AssetClearSusp.Ref == held.Ref:
			h.held = nil
			h.seq++
			return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID,
				Status: authz.ReplyAccepted, CollectorSeq: 1000 + h.seq}}, nil
		case req.Kind == authz.KindAssetClearSusp:
			return refuse(req, authz.RefuseSuspensionMismatch, held), nil
		}
		return refuse(req, authz.RefuseAssetSuspended, held), nil
	}
	return h
}

func (h *holdingCollector) hold(s *authz.HeldSuspension) { h.mu.Lock(); h.held = s; h.mu.Unlock() }

func (h *holdingCollector) holding() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.held != nil }

var heldAuth = &authz.HeldSuspension{Reason: asset.SuspendAuthFailed, Ref: heldRef, Code: string(adapter.FailedAuthRejected)}

// adoptedRecord is the node's asset.suspend record of ref, checked to say
// it was adopted and to carry the collector's reason and code.
func adoptedRecord(t *testing.T, r *Runtime, ref string) {
	t.Helper()
	suspends, _ := suspensionRecords(t, r)
	for _, rec := range suspends {
		if rec.CorrelationID == ref {
			if !strings.HasPrefix(rec.Detail, adoptedDetail) || rec.Suspension.Reason != heldAuth.Reason || rec.Suspension.Code != heldAuth.Code || rec.Actor.Type != authz.PrincipalNode {
				t.Fatalf("adopted record %+v", rec)
			}
			return
		}
	}
	t.Fatalf("no asset.suspend of %s", ref)
}

// A suspension only the collector holds, after the suspending run's reply
// was lost (A6 on #120): the run is refused asset_suspended naming it, the
// node adopts it, sends nothing more for the asset, and the
// administrator's file naming it clears it at both ends.
func TestAdoptLostSuspension(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newHoldingCollector(t)
	col.hold(heldAuth)
	s := newScheduler(t, r, col)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended || !rep.Sent || rep.Decision != authz.ReplyRefused {
		t.Fatalf("refused run: %+v", rep)
	}
	if sp := s.Suspensions()[relayID]; sp.Ref != heldRef || sp.Reason != asset.SuspendAuthFailed {
		t.Fatalf("node suspension after the refusal: %+v", sp)
	}
	adoptedRecord(t, r, heldRef)
	if countAlarms(st, AlarmAssetSuspended) != 1 || countAlarms(st, AlarmCollectorRefused) != 0 {
		t.Fatal("the adoption is not raised as the asset's suspension")
	}
	if rep := s.RunOnce(bg, 0); rep.Sent || col.n() != 1 {
		t.Fatalf("a run after the adoption: %+v, %d sent", rep, col.n())
	}
	writeClear(t, nc, relayID, heldRef)
	rep := s.RunOnce(bg, 0)
	if col.holding() || col.nClears() != 1 || col.n() != 2 || !rep.Sent {
		t.Fatalf("after the clear: run %+v, collector holding %v, %d clears, %d runs", rep, col.holding(), col.nClears(), col.n())
	}
	auditRecords(t, r) // verifies the chain, suspensions included
}

// The node cleared X and owes the collector clear of X, but the collector
// holds Y (A3 #125): the clear is refused suspension_mismatch naming Y, the
// node adopts Y and keeps X owed, and the file naming Y then clears Y at
// both ends. The fold replacing the owed ref is what lets it through.
func TestAdoptOnMismatch(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col := newHoldingCollector(t)
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	x := s.Suspensions()[relayID].Ref
	col.hold(heldAuth)
	writeClear(t, nc, relayID, x)
	if rep := s.RunOnce(bg, 0); rep.Sent || col.nClears() != 1 {
		t.Fatalf("clear of X: run %+v, %d clears", rep, col.nClears())
	}
	if sp := s.Suspensions()[relayID]; sp.Ref != heldRef {
		t.Fatalf("node suspension after the mismatch: %+v", sp)
	}
	if owed := s.CollectorClears()[relayID]; owed != x {
		t.Fatalf("owed clear after the adoption: %q, want %q", owed, x)
	}
	adoptedRecord(t, r, heldRef)
	if rep := s.RunOnce(bg, 0); rep.Sent || col.nClears() != 1 {
		t.Fatalf("held by the adoption: run %+v, %d clears", rep, col.nClears())
	}
	writeClear(t, nc, relayID, heldRef)
	rep := s.RunOnce(bg, 0)
	if col.holding() || col.nClears() != 2 || !rep.Sent || len(s.CollectorClears()) != 0 {
		t.Fatalf("after the clear of Y: run %+v, holding %v, %d clears, owed %v", rep, col.holding(), col.nClears(), s.CollectorClears())
	}
}

// A named suspension the node cannot adopt changes nothing and is raised
// once, without quoting the reply.
func TestAdoptRefused(t *testing.T) {
	c, dir, _ := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, &fakeCollector{})
	reply := func(code authz.RefusalCode, h *authz.HeldSuspension) authz.CollectorReply {
		return authz.CollectorReply{Contract: authz.ContractID, Status: authz.ReplyRefused, Refusal: &authz.Refusal{Code: code, Detail: "x", Suspension: h}}
	}
	with := func(f func(*authz.HeldSuspension)) *authz.HeldSuspension { h := *heldAuth; f(&h); return &h }
	quote := "\x1bQUOTED"
	for name, c := range map[string]struct {
		reply authz.CollectorReply
		setup func()
		want  string // in the alarm's detail
	}{
		"asset_suspended naming none": {reply: reply(authz.RefuseAssetSuspended, nil)},
		"on another code":             {reply: reply(authz.RefuseRateLimited, heldAuth)},
		"malformed ref":               {reply: reply(authz.RefuseAssetSuspended, with(func(h *authz.HeldSuspension) { h.Ref = quote }))},
		"no code":                     {reply: reply(authz.RefuseAssetSuspended, with(func(h *authz.HeldSuspension) { h.Code = "" })), want: "has no C2 code"},
		"unknown code":                {reply: reply(authz.RefuseAssetSuspended, with(func(h *authz.HeldSuspension) { h.Code = "failed.quoted_x" }))},
		"code of another reason":      {reply: reply(authz.RefuseAssetSuspended, with(func(h *authz.HeldSuspension) { h.Code = string(adapter.RefusedIdentityMismatch) }))},
		"code that suspends nothing":  {reply: reply(authz.RefuseAssetSuspended, with(func(h *authz.HeldSuspension) { h.Code = string(adapter.FailedConnect) }))},
		"the node holds another": {reply: reply(authz.RefuseAssetSuspended, heldAuth), setup: func() {
			s.mu.Lock()
			s.susp[relayID] = asset.Suspension{Reason: asset.SuspendAuthFailed, Ref: "inv-own", Since: "2026-10-25T06:00:00Z"}
			s.mu.Unlock()
		}},
		"the owed clear's ref": {reply: reply(authz.RefuseSuspensionMismatch, heldAuth), setup: func() {
			s.mu.Lock()
			s.collClear[relayID] = heldRef
			s.mu.Unlock()
		}},
	} {
		s.mu.Lock()
		s.susp, s.collClear, s.quiet = map[string]asset.Suspension{}, map[string]string{}, map[string]bool{}
		s.mu.Unlock()
		if c.setup != nil {
			c.setup()
		}
		before := countAlarms(st, AlarmSuspensionNotAdopted)
		if s.adopt(bg, relayID, c.reply) || s.adopt(bg, relayID, c.reply) {
			t.Fatalf("%s: adopted", name)
		}
		if sp := s.Suspensions()[relayID]; sp.Ref == heldRef {
			t.Fatalf("%s: node suspension %+v", name, sp)
		}
		if n := countAlarms(st, AlarmSuspensionNotAdopted) - before; n != 1 {
			t.Fatalf("%s: %d not-adopted alarms, want 1", name, n)
		}
		if as := st.Snapshot("x").Alarms; !strings.Contains(as[len(as)-1].Detail, c.want) {
			t.Fatalf("%s: alarm %q, want %q in it", name, as[len(as)-1].Detail, c.want)
		}
	}
	for _, a := range st.Snapshot("x").Alarms {
		if strings.Contains(a.Detail, "QUOTED") || strings.Contains(a.Detail, "quoted") {
			t.Fatalf("alarm quotes the reply: %q", a.Detail)
		}
	}
	if suspends, _ := suspensionRecords(t, r); len(suspends) != 0 {
		t.Fatalf("records written: %+v", suspends)
	}
	// A reply naming nothing is not an adoption and raises nothing.
	before := countAlarms(st, AlarmSuspensionNotAdopted)
	if s.adopt(bg, relayID, reply(authz.RefuseRateLimited, nil)) || countAlarms(st, AlarmSuspensionNotAdopted) != before {
		t.Fatal("a refusal naming no suspension")
	}
}

// An adopted suspension whose record was not written when the node stopped
// is kept as adopted in the checkpoint, so the record written at the next
// start still says where it came from.
func TestUnauditedAdoptionSurvivesRestart(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	s := newScheduler(t, r, &fakeCollector{})
	db := r.find(AuditDB)
	r.state.Lock()
	log := db.log
	db.log = nil
	r.state.Unlock()
	if !s.adopt(bg, relayID, authz.CollectorReply{Contract: authz.ContractID, Status: authz.ReplyRefused,
		Refusal: &authz.Refusal{Code: authz.RefuseAssetSuspended, Detail: "x", Suspension: heldAuth}}) {
		t.Fatal("not adopted")
	}
	f, err := readSuspensions(filepath.Join(c.Store.Dir, SuspensionsFileName))
	if err != nil || len(f.Unaudited) != 1 || f.Unaudited[0] != (pendingSuspension{relayID, heldRef, heldAuth.Code, true}) {
		t.Fatalf("checkpoint %+v: %v", f, err)
	}
	r.state.Lock()
	db.log = log
	r.state.Unlock()
	r.Close()

	r, _, _ = start(t, c, dir)
	defer r.Close()
	newScheduler(t, r, &fakeCollector{})
	adoptedRecord(t, r, heldRef)
}

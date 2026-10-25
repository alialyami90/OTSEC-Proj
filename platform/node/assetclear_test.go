package node

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
)

// clearMode makes clearingCollector lose the reply to a clear, or refuse
// it, after the collector numbered its decision.
type clearMode struct {
	lost   bool
	refuse authz.RefusalCode
	got    []*authz.CollectorRequest
}

// clearingCollector is suspendingCollector with its asset clears under m.
func clearingCollector(t *testing.T) (*fakeCollector, *clearMode) {
	t.Helper()
	col := suspendingCollector(t, false)
	m := &clearMode{}
	base := col.answer
	col.clear = func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		m.got = append(m.got, req)
		resp, err := base(req)
		switch {
		case m.lost:
			return collectorclient.Response{}, errors.New("test: the reply was lost")
		case m.refuse != "":
			return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID,
				Status: authz.ReplyRefused, Refusal: &authz.Refusal{Code: m.refuse, Detail: "test"}, CollectorSeq: resp.Reply.CollectorSeq}}, nil
		}
		return resp, err
	}
	return col, m
}

// clearRequests are the node's collector.request records for asset clears.
func clearRequests(t *testing.T, r *Runtime) []*audit.Record {
	t.Helper()
	var out []*audit.Record
	for _, rec := range auditRecords(t, r) {
		if rec.Action == audit.ActionCollectorRequest && rec.Actor.Type == authz.PrincipalNode {
			out = append(out, rec)
		}
	}
	return out
}

// After its own clear, the node sends the collector asset.clear_suspension
// (C7 0.2, A3 #117) on its own behalf, naming the suspension's ref, audited
// before it is sent and with the collector's decision after; only then
// does the asset run again.
func TestClearReachesCollector(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col, m := clearingCollector(t)
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	writeClear(t, nc, relayID, ref)
	if rep := s.RunOnce(bg, 0); rep.Alarm == AlarmCollectorStillSuspended || col.nClears() != 1 || col.n() != 2 {
		t.Fatalf("clear: run %+v, %d clears, %d runs", rep, col.nClears(), col.n())
	}
	req := m.got[0]
	if req.Contract != authz.ContractID || req.Kind != authz.KindAssetClearSusp || req.OnBehalfOf != (authz.Principal{Type: authz.PrincipalNode, ID: string(c.NodeID)}) ||
		req.AssetClearSusp == nil || *req.AssetClearSusp != (authz.AssetClearSuspBody{AssetID: relayID, Ref: ref}) || req.Run != nil {
		t.Fatalf("clear request %+v", req)
	}
	recs := auditRecords(t, r)
	order := []string{}
	for _, rec := range recs {
		switch {
		case rec.Action == audit.ActionAssetSuspensionClear:
			order = append(order, "clear")
		case rec.Action == audit.ActionCollectorRequest && rec.Actor.Type == authz.PrincipalNode:
			if rec.Target == nil || rec.Target.AssetID != relayID || rec.CorrelationID != req.RequestID || !strings.HasPrefix(rec.CorrelationID, clearRequestPrefix+ref+":") {
				t.Fatalf("clear request record %+v", rec)
			}
			order = append(order, "collector "+string(rec.Outcome))
		case rec.Action == audit.ActionCollectorRequest && len(order) > 0 && order[len(order)-1] == "collector allowed":
			order = append(order, "run")
		}
	}
	if strings.Join(order, ",") != "clear,collector info,collector allowed,run" {
		t.Fatalf("audit order %v", order)
	}
	if len(s.CollectorClears()) != 0 || len(st.Snapshot("x").CollectorClears) != 0 {
		t.Fatalf("owed clears %v, status %v", s.CollectorClears(), st.Snapshot("x").CollectorClears)
	}
	// While the clear was owed the file was expected. Left in place after
	// the collector accepted, it names a cleared ref, so it is refused
	// once, as before.
	if n := countAlarms(st, AlarmSuspensionClearRefused); n != 0 {
		t.Fatalf("%d clear-refused alarms while the clear was owed", n)
	}
	s.RunOnce(bg, 0)
	s.RunOnce(bg, 0)
	if n := countAlarms(st, AlarmSuspensionClearRefused); n != 1 {
		t.Fatalf("%d clear-refused alarms for the stale file", n)
	}
}

// A lost reply leaves the clear owed, with the asset's runs held, across a
// restart and a rebuild from the chain; the next run sends it again, and a
// collector that already lifted the suspension accepts it (A3 #117).
func TestLostClearReplyRetried(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	col, m := clearingCollector(t)
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	writeClear(t, nc, relayID, ref)
	m.lost = true
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorStillSuspended || col.nClears() != 1 || col.n() != 1 {
		t.Fatalf("lost reply: run %+v, %d clears, %d runs", rep, col.nClears(), col.n())
	}
	if got := st.Snapshot("x").CollectorClears; got[relayID] != ref {
		t.Fatalf("status collector_clears %v", got)
	}
	if countAlarms(st, AlarmCollectorStillSuspended) != 1 {
		t.Fatal("no collector-still-suspended alarm")
	}
	// The file names a ref the node no longer holds, but the clear is owed,
	// so the file is expected and not refused.
	if n := countAlarms(st, AlarmSuspensionClearRefused); n != 0 {
		t.Fatalf("%d clear-refused alarms while the clear is owed", n)
	}
	r.Close()

	for _, rebuild := range []bool{false, true} {
		if rebuild {
			os.Remove(filepath.Join(c.Store.Dir, SuspensionsFileName))
		}
		r, st, _ = start(t, c, dir)
		s = newScheduler(t, r, col)
		if got := s.CollectorClears(); got[relayID] != ref {
			r.Close()
			t.Fatalf("rebuild %v: owed clears %v", rebuild, got)
		}
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorStillSuspended || col.n() != 1 {
			r.Close()
			t.Fatalf("rebuild %v: run %+v, %d runs", rebuild, rep, col.n())
		}
		r.Close()
	}
	r, st, _ = start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, col)
	m.lost = false
	if rep := s.RunOnce(bg, 0); rep.Alarm == AlarmCollectorStillSuspended || col.n() != 2 || col.nClears() != 4 {
		t.Fatalf("retried: run %+v, %d clears, %d runs", rep, col.nClears(), col.n())
	}
	if len(s.CollectorClears()) != 0 || len(st.Snapshot("x").CollectorClears) != 0 {
		t.Fatalf("owed clears %v", s.CollectorClears())
	}
	allowed := 0
	for _, rec := range clearRequests(t, r) {
		if rec.Outcome == audit.OutcomeAllowed {
			allowed++
		}
	}
	if allowed != 1 {
		t.Fatalf("%d allowed clear records", allowed)
	}
}

// A refused clear is recorded denied with the collector's code and stays
// owed, with the asset's runs held; without a clear-suspension.json naming
// it, nothing is sent at all, since the collector checks the same file.
func TestRefusedClearHolds(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col, m := clearingCollector(t)
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	writeClear(t, nc, relayID, ref)
	m.refuse = authz.RefuseSuspensionMismatch
	for i := 1; i <= 2; i++ {
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorStillSuspended || col.nClears() != i || col.n() != 1 {
			t.Fatalf("refusal %d: run %+v, %d clears, %d runs", i, rep, col.nClears(), col.n())
		}
	}
	denied := 0
	for _, rec := range clearRequests(t, r) {
		if rec.Outcome == audit.OutcomeDenied {
			if rec.ReasonCode != string(authz.RefuseSuspensionMismatch) || rec.CollectorSeq == 0 {
				t.Fatalf("denied record %+v", rec)
			}
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("%d denied clear records", denied)
	}
	if n := countAlarms(st, AlarmCollectorStillSuspended); n != 1 {
		t.Fatalf("%d collector-still-suspended alarms for one refusal code", n)
	}
	// The file names a ref the node no longer holds, but the clear is
	// owed, so the file is expected and not refused.
	if n := countAlarms(st, AlarmSuspensionClearRefused); n != 0 {
		t.Fatalf("%d clear-refused alarms while the clear is owed", n)
	}

	// The administrator removed the file too early: nothing is sent.
	nc.UnlockTLS()
	os.Remove(filepath.Join(nc.AdminDir, ClearSuspensionFileName))
	lockTLS(t, nc)
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorStillSuspended || col.nClears() != 2 || col.n() != 1 {
		t.Fatalf("no file: run %+v, %d clears, %d runs", rep, col.nClears(), col.n())
	}
	if n := countAlarms(st, AlarmCollectorStillSuspended); n != 2 {
		t.Fatalf("%d collector-still-suspended alarms, want one more for the missing file", n)
	}
	// A file naming the asset with another ref is not the owed clear, so
	// nothing is sent either (A6 on #120).
	writeClear(t, nc, relayID, "inv-run-other")
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorStillSuspended || col.nClears() != 2 || col.n() != 1 {
		t.Fatalf("another ref: run %+v, %d clears, %d runs", rep, col.nClears(), col.n())
	}
	// Written again, the clear goes through.
	writeClear(t, nc, relayID, ref)
	m.refuse = ""
	if rep := s.RunOnce(bg, 0); rep.Alarm == AlarmCollectorStillSuspended || col.nClears() != 3 || col.n() != 2 {
		t.Fatalf("accepted: run %+v, %d clears, %d runs", rep, col.nClears(), col.n())
	}
}

// A clear owed when the collector is reinstalled waits for the reset to be
// acknowledged, like every request, and is then accepted by the new
// collector, which holds no suspension (A3 #117).
func TestOwedClearAcrossCollectorReinstall(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col, m := clearingCollector(t)
	s := newScheduler(t, r, col)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	writeClear(t, nc, relayID, ref)
	m.lost = true
	s.RunOnce(bg, 0)
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	m.lost = false
	if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmCollectorReset || col.nClears() != 1 {
		t.Fatalf("after the reinstall: run %+v, %d clears", rep, col.nClears())
	}
	writeAck(t, nc, "ik_test_second")
	writeClear(t, nc, relayID, ref)
	if rep := s.RunOnce(bg, 0); rep.Alarm == AlarmCollectorStillSuspended || col.nClears() != 2 || col.n() != 2 {
		t.Fatalf("acknowledged: run %+v, %d clears, %d runs", rep, col.nClears(), col.n())
	}
	if len(s.CollectorClears()) != 0 {
		t.Fatalf("owed clears %v", s.CollectorClears())
	}
}

// Only the collector's acceptance of the owed clear closes it: the allowed
// record of the node's request whose ID names the owed ref. A run's
// allowed request for the asset, a denied clear, or an accepted clear of
// another ref leaves it owed.
func TestApplyCollectorClear(t *testing.T) {
	node := authz.Principal{Type: authz.PrincipalNode, ID: "site-a-node1"}
	sched := authz.Principal{Type: authz.PrincipalSchedule, ID: "relay-ser"}
	req := func(p authz.Principal, outcome audit.Outcome, id string) *audit.Record {
		return &audit.Record{Action: audit.ActionCollectorRequest, Actor: audit.Actor{Type: p.Type, ID: p.ID}, Outcome: outcome,
			Target: &audit.Target{AssetID: relayID}, CorrelationID: id}
	}
	for _, c := range []struct {
		name   string
		rec    *audit.Record
		closes bool
	}{
		{"accepted clear of the owed ref", req(node, audit.OutcomeAllowed, clearRequestID("inv-b")), true},
		{"accepted clear of another ref", req(node, audit.OutcomeAllowed, clearRequestID("inv-a")), false},
		{"a ref that only starts the same", req(node, audit.OutcomeAllowed, clearRequestPrefix+"inv-bb:00"), false},
		{"denied clear", req(node, audit.OutcomeDenied, clearRequestID("inv-b")), false},
		{"sent clear", req(node, audit.OutcomeInfo, clearRequestID("inv-b")), false},
		{"a run of the asset", req(sched, audit.OutcomeAllowed, clearRequestID("inv-b")), false},
	} {
		m := map[string]string{relayID: "inv-b"}
		if got := applyCollectorClear(m, c.rec); got != c.closes || (len(m) == 0) != c.closes {
			t.Errorf("%s: closes %v, owed %v", c.name, got, m)
		}
	}
	m := map[string]string{}
	applyCollectorClear(m, &audit.Record{Action: audit.ActionAssetSuspensionClear, Target: &audit.Target{AssetID: relayID}, CorrelationID: "inv-b"})
	if m[relayID] != "inv-b" {
		t.Fatalf("a node clear opens an owed clear: %v", m)
	}
	// A later suspension leaves it owed: the collector still holds the
	// earlier one until it accepts (A6 on #120).
	if applyCollectorClear(m, &audit.Record{Action: audit.ActionAssetSuspend, Target: &audit.Target{AssetID: relayID}, CorrelationID: "inv-c"}) || m[relayID] != "inv-b" {
		t.Fatalf("a later suspension changed the owed clear: %v", m)
	}
}

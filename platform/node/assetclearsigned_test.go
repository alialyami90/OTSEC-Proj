package node

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// uuidSuspending is suspendingCollector with C2 invocation IDs, which a
// signed clear's ref must be (C7).
func uuidSuspending(t *testing.T) *fakeCollector {
	t.Helper()
	in := suspendingCollector(t, false)
	n := 0
	return &fakeCollector{answer: func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		r, err := in.answer(req)
		if r.Outcome != nil {
			n++
			id := fmt.Sprintf("6f1c2b9e-3d4a-4c1e-9b7a-%012d", n)
			r.Reply.InvocationID, r.Outcome.InvocationID, r.Outcome.Result.InvocationID = id, id, id
		}
		return r, err
	}}
}

// signedClearNode is a suspendConfig node whose collector is an adminMux,
// with the relay asset suspended by one run, and a function that leaves a
// signed clear of a ref in admin_dir.
type signedClearNode struct {
	t   *testing.T
	s   *Scheduler
	r   *Runtime
	st  *Status
	nc  *nodeconfigtest.Config
	run *fakeCollector
	mux *adminMux
	ref string
}

func newSignedClearNode(t *testing.T, target asset.EvidenceClass) (*signedClearNode, func(name string, n int, ref string)) {
	t.Helper()
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	t.Cleanup(func() { r.Close() })
	run := uuidSuspending(t)
	mux := &adminMux{run: run, admin: newAdminCollector()}
	mux.admin.installKey = kid(testInstallKey)
	s := newScheduler(t, r, mux)
	setTargets(t, c, target)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	if ref == "" {
		t.Fatal("the run did not suspend the asset")
	}
	n := &signedClearNode{t: t, s: s, r: r, st: st, nc: nc, run: run, mux: mux, ref: ref}
	return n, func(name string, i int, ref string) { n.signFor(name, i, ref, kid(testInstallKey)) }
}

// signFor leaves in admin_dir a signed clear of ref bound to install key
// ID key.
func (n *signedClearNode) signFor(name string, i int, ref, key string) {
	n.t.Helper()
	env := signN(n.t, authz.KindAssetClearSusp, i, func(p *authz.AdminRequest) {
		p.AssetClearSusp.Ref, p.InstallKeyID = ref, key
	})
	writeAdminFile(n.t, n.nc, name, authz.KindAssetClearSusp, env)
}

func (n *signedClearNode) clears() []*audit.Record {
	_, clears := suspensionRecords(n.t, n.r)
	return clears
}

// An administrator's signed asset.clear_suspension is relayed to the
// collector, and on its acceptance the node records asset.suspension_clear
// naming the person and that it was signed (P4-H1). The collector lifted its
// own half when it accepted, so nothing is owed to it: the next run is sent
// with no clear request first. Relayed again, it records nothing more. This
// holds on a lab-only node and on one with a device endpoint.
func TestSignedAssetClear(t *testing.T) {
	for name, target := range map[string]asset.EvidenceClass{"lab": asset.Simulated, "off-lab": asset.DeviceObserved} {
		t.Run(name, func(t *testing.T) {
			n, sign := newSignedClearNode(t, target)
			sign("admin-request-clear.json", 1, n.ref)
			n.s.relayAdmin(bg)
			cl := n.clears()
			if len(cl) != 1 || cl[0].CorrelationID != n.ref || cl[0].Target.AssetID != relayID ||
				!strings.Contains(cl[0].Detail, "signed by "+relayAdmin.ID) || !strings.Contains(cl[0].Detail, "admin-request-clear.json") ||
				strings.Contains(cl[0].Detail, "unsigned") {
				t.Fatalf("asset.suspension_clear records %+v", cl)
			}
			if _, held := n.s.Suspensions()[relayID]; held {
				t.Fatal("the asset is still suspended at the node")
			}
			if owed := n.s.CollectorClears(); len(owed) != 0 {
				t.Fatalf("clears owed to the collector after a signed clear: %v", owed)
			}
			if shown := adminShown(n.st); len(shown) != 1 || shown[0].NodePart != partDone {
				t.Fatalf("admin requests in status %+v", shown)
			}
			before := n.run.n()
			if rep := n.s.RunOnce(bg, 0); rep.Alarm == AlarmAssetSuspended || n.run.n() != before+1 || n.run.nClears() != 0 {
				t.Fatalf("the run after a signed clear: %+v, %d runs, %d unsigned clears sent", rep, n.run.n()-before, n.run.nClears())
			}
			n.s.relayAdmin(bg)
			if len(n.clears()) != 1 {
				t.Fatalf("%d clear records after relaying again", len(n.clears()))
			}
		})
	}
}

// A signed clear naming another suspension than the one the node holds
// clears nothing at the node.
func TestSignedAssetClearOfAnotherRef(t *testing.T) {
	n, sign := newSignedClearNode(t, asset.DeviceObserved)
	sign("admin-request-clear.json", 1, "6f1c2b9e-3d4a-4c1e-9b7a-999999999999")
	n.s.relayAdmin(bg)
	if shown := adminShown(n.st); len(shown) != 1 || shown[0].State != "accepted" || shown[0].NodePart != partNothing {
		t.Fatalf("admin requests in status %+v", shown)
	}
	if len(n.clears()) != 0 {
		t.Fatalf("a clear of another ref was recorded: %+v", n.clears())
	}
	if _, held := n.s.Suspensions()[relayID]; !held {
		t.Fatal("the asset is no longer suspended")
	}
}

// A signed clear the collector accepted for an install key the node does
// not trust is refused at the node, whatever the collector said: nothing is
// cleared, the asset stays suspended, and the entry says to sign again
// (D6 on #514).
func TestSignedAssetClearForAnUntrustedKey(t *testing.T) {
	n, _ := newSignedClearNode(t, asset.DeviceObserved)
	n.mux.admin.installKey = kid("ik_test_other")
	n.signFor("admin-request-clear.json", 1, n.ref, kid("ik_test_other"))
	for range 2 {
		n.s.relayAdmin(bg)
		if shown := adminShown(n.st); len(shown) != 1 || shown[0].State != "accepted" || shown[0].NodePart != partRefused ||
			!strings.Contains(shown[0].Detail, "Sign the request again") {
			t.Fatalf("admin requests in status %+v", shown)
		}
		if len(n.clears()) != 0 {
			t.Fatalf("a clear for an untrusted key was recorded: %+v", n.clears())
		}
		if _, held := n.s.Suspensions()[relayID]; !held {
			t.Fatal("the asset is no longer suspended")
		}
	}
	notApplied := 0
	for _, a := range n.st.Snapshot("x").Alarms {
		if a.Code == AlarmAdminRequestNotApplied {
			notApplied++
		}
	}
	if notApplied != 1 {
		t.Fatalf("%d admin-request-not-applied alarms", notApplied)
	}
}

// A signed clear the collector accepted for its new install key, which the
// node finds accepted while that key's reset is open, waits: nothing is
// cleared until the acknowledgement, and then the clear applies once (D6
// on #514). The relay sends nothing but an acknowledgement while a reset is
// open, so the acceptance is put in the fold as TestApplyAdminPartGates
// does: the node stopped between the collector's answer and its own part,
// and found the new key on starting again.
func TestSignedAssetClearWaitsForTheReset(t *testing.T) {
	// Lab-only, so the unsigned seq-reset-ack.json acknowledges the reset.
	n, _ := newSignedClearNode(t, asset.Simulated)
	if err := n.nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	if code, _ := n.s.collectorHold(bg); code != AlarmCollectorReset {
		t.Fatalf("hold %q, want the reset", code)
	}
	env := signN(t, authz.KindAssetClearSusp, 1, func(p *authz.AdminRequest) {
		p.AssetClearSusp.Ref, p.InstallKeyID = n.ref, kid("ik_test_second")
	})
	f := &adminFile{name: "admin-request-clear.json", sum: strings.Repeat("c1", 32), kind: authz.KindAssetClearSusp, signed: env,
		claims: adminClaims{Kind: authz.KindAssetClearSusp, Principal: relayAdmin}}
	f.id = adminRequestID(f.sum)
	n.s.mu.Lock()
	n.s.relayed[f.id] = relayEntry{Outcome: audit.OutcomeAllowed, CollectorSeq: 5, Verified: &audit.Admin{
		AdminKeyID: env.KeyID, Principal: relayAdmin.ID, Nonce: strings.Repeat("A", 22), PayloadSHA256: authz.AdminPayloadSHA256(env), Kind: authz.KindAssetClearSusp}}
	n.s.mu.Unlock()
	for range 2 {
		if part := n.s.applyAdminParts(bg, []*adminFile{f})[f.id]; part.state != partPending || !strings.Contains(part.detail, "not acknowledged yet") {
			t.Fatalf("the part during the open reset %+v", part)
		}
		if len(n.clears()) != 0 {
			t.Fatalf("a clear was recorded during the open reset: %+v", n.clears())
		}
		if _, held := n.s.Suspensions()[relayID]; !held {
			t.Fatal("the asset is no longer suspended during the open reset")
		}
	}

	writeAck(t, n.nc, "ik_test_second")
	n.s.checkAck(bg)
	n.s.mu.Lock()
	cs := n.s.cs
	n.s.mu.Unlock()
	if cs.OpenResetKey != "" || cs.TrustedKey != kid("ik_test_second") {
		t.Fatalf("reset not acknowledged: %+v", cs)
	}
	if part := n.s.applyAdminParts(bg, []*adminFile{f})[f.id]; part.state != partDone {
		t.Fatalf("the part after the acknowledgement %+v", part)
	}
	if cl := n.clears(); len(cl) != 1 || cl[0].CorrelationID != n.ref || !strings.Contains(cl[0].Detail, "signed by "+relayAdmin.ID) {
		t.Fatalf("clear records after the acknowledgement %+v", cl)
	}
	if _, held := n.s.Suspensions()[relayID]; held {
		t.Fatal("the asset is still suspended after the acknowledgement")
	}
}

// On a node with a device endpoint, clear-suspension.json is refused in
// code: unsigned-admin-file-refused once per file content, nothing cleared,
// and no clear sent to the collector. On the lab node it is acted on, the
// record says the file was unsigned, and unsigned-admin-file-accepted names
// it (P4-H1).
func TestUnsignedAssetClearRefusedOffLab(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := suspendingCollector(t, false)
	s := newScheduler(t, r, col)
	setTargets(t, c, asset.DeviceObserved)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	writeClear(t, nc, relayID, ref)
	for range 2 {
		if rep := s.RunOnce(bg, 0); rep.Alarm != AlarmAssetSuspended {
			t.Fatalf("an unsigned clear was acted on off-lab: %+v", rep)
		}
	}
	if _, clears := suspensionRecords(t, r); len(clears) != 0 || col.nClears() != 0 {
		t.Fatalf("off-lab: %d clear records, %d clears sent", len(clears), col.nClears())
	}
	count := func(code string) (n int, detail string) {
		for _, a := range st.Snapshot("x").Alarms {
			if a.Code == code {
				n, detail = n+1, a.Detail
			}
		}
		return
	}
	if k, d := count(AlarmUnsignedAdminFileRefused); k != 1 || !strings.Contains(d, ClearSuspensionFileName) || !strings.Contains(d, string(authz.KindAssetClearSusp)) {
		t.Fatalf("%d refusal alarms, the last %q", k, d)
	}
	if k, _ := count(AlarmUnsignedAdminFileAccepted); k != 0 {
		t.Fatal("accepted alarm raised for a refused file")
	}

	setTargets(t, c, asset.Simulated)
	s.RunOnce(bg, 0)
	_, clears := suspensionRecords(t, r)
	if len(clears) != 1 || !strings.Contains(clears[0].Detail, ClearSuspensionFileName+unsignedSuffix) {
		t.Fatalf("the lab node's record does not name the file as unsigned: %+v", clears)
	}
	if k, d := count(AlarmUnsignedAdminFileAccepted); k != 1 || !strings.Contains(d, ClearSuspensionFileName) {
		t.Fatalf("%d accepted alarms, the last %q", k, d)
	}
}

// On a lab-only node, a signed request and clear-suspension.json for the
// same clear: only the signed one is acted on, and the file raises
// unsigned-admin-file-ignored.
func TestSignedAssetClearWinsOverTheFile(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	run := uuidSuspending(t)
	mux := &adminMux{run: run, admin: newAdminCollector()}
	mux.admin.installKey = kid(testInstallKey)
	s := newScheduler(t, r, mux)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	env := signN(t, authz.KindAssetClearSusp, 1, func(p *authz.AdminRequest) {
		p.AssetClearSusp.Ref, p.InstallKeyID = ref, kid(testInstallKey)
	})
	writeAdminFile(t, nc, "admin-request-clear.json", authz.KindAssetClearSusp, env)
	writeClear(t, nc, relayID, ref)
	s.checkClear(bg)
	s.relayAdmin(bg)
	_, clears := suspensionRecords(t, r)
	if len(clears) != 1 || strings.Contains(clears[0].Detail, "unsigned") || !strings.Contains(clears[0].Detail, "admin-request-clear.json") {
		t.Fatalf("clear records %+v", clears)
	}
	ignored := 0
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == AlarmUnsignedAdminFileIgnored && strings.Contains(a.Detail, ClearSuspensionFileName) {
			ignored++
		}
	}
	if ignored != 1 {
		t.Fatalf("%d ignored alarms for the file", ignored)
	}
}

// The recovery path D3 asked for (P4-H1): the node cleared a suspension from
// the file on a lab-only node, the collector refused that clear, and then an
// endpoint stopped being simulated, so the file is refused at both ends. The
// administrator's signed clear of the same asset and ref closes the owed
// clear, though the node no longer holds the suspension: the next run is
// sent with no clear request first, and a rebuild from the chain keeps it
// closed.
func TestSignedAssetClearClosesAnOwedFileClear(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	run := uuidSuspending(t)
	answer := run.answer
	run.answer = func(req *authz.CollectorRequest) (collectorclient.Response, error) {
		if req.Kind == authz.KindAssetClearSusp {
			return collectorclient.Response{Reply: authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID,
				Status: authz.ReplyRefused, Refusal: authz.AdminRefusal(authz.AdminCheckEnvelope), CollectorSeq: 1000}}, nil
		}
		return answer(req)
	}
	mux := &adminMux{run: run, admin: newAdminCollector()}
	mux.admin.installKey = kid(testInstallKey)
	s := newScheduler(t, r, mux)
	s.RunOnce(bg, 0)
	ref := s.Suspensions()[relayID].Ref
	writeClear(t, nc, relayID, ref)
	if rep := s.RunOnce(bg, 0); rep.Sent || run.nClears() != 1 {
		t.Fatalf("the clear the collector refuses: run %+v, %d clears sent", rep, run.nClears())
	}
	if owed := s.CollectorClears(); owed[relayID] != ref {
		t.Fatalf("owed clears %v, want %s", owed, ref)
	}

	setTargets(t, c, asset.DeviceObserved)
	// An accepted signed clear of another ref leaves the owed clear open
	// (D3 on #514).
	other := signN(t, authz.KindAssetClearSusp, 2, func(p *authz.AdminRequest) {
		p.AssetClearSusp.Ref, p.InstallKeyID = "6f1c2b9e-3d4a-4c1e-9b7a-999999999999", kid(testInstallKey)
	})
	writeAdminFile(t, nc, "admin-request-other.json", authz.KindAssetClearSusp, other)
	s.relayAdmin(bg)
	if shown := adminShown(st); len(shown) != 1 || shown[0].State != "accepted" {
		t.Fatalf("the clear of another ref: %+v", shown)
	}
	if owed := s.CollectorClears(); owed[relayID] != ref {
		t.Fatalf("a signed clear of another ref closed the owed clear: %v", owed)
	}
	removeAdminFile(t, nc, "admin-request-other.json")

	env := signN(t, authz.KindAssetClearSusp, 1, func(p *authz.AdminRequest) {
		p.AssetClearSusp.Ref, p.InstallKeyID = ref, kid(testInstallKey)
	})
	writeAdminFile(t, nc, "admin-request-clear.json", authz.KindAssetClearSusp, env)
	s.relayAdmin(bg)
	if owed := s.CollectorClears(); len(owed) != 0 {
		t.Fatalf("the signed clear left owed clears %v", owed)
	}
	if _, clears := suspensionRecords(t, r); len(clears) != 1 {
		t.Fatalf("%d clear records, want the file's one", len(clears))
	}
	cleared := 0
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == AlarmSuspensionCleared && a.Asset == relayID && strings.Contains(a.Detail, "signed") {
			cleared++
		}
	}
	if cleared != 1 {
		t.Fatalf("%d signed clear alarms on the asset", cleared)
	}
	before := run.n()
	if rep := s.RunOnce(bg, 0); !rep.Sent || run.n() != before+1 || run.nClears() != 1 {
		t.Fatalf("the run after the signed clear: %+v, %d clears sent", rep, run.nClears())
	}

	// A rebuild from the chain keeps the owed clear closed.
	r.Close()
	if err := os.Remove(filepath.Join(c.Store.Dir, SuspensionsFileName)); err != nil {
		t.Fatal(err)
	}
	r, _, _ = start(t, c, dir)
	defer r.Close()
	s = newScheduler(t, r, mux)
	if owed := s.CollectorClears(); len(owed) != 0 {
		t.Fatalf("owed clears after a rebuild: %v", owed)
	}
}

package node

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorclient"
)

// adminMux is a collector for a test that makes runs and relays admin
// requests: runs go to run, admin-signed requests to admin, and every reply
// is numbered from one counter, as the real collector numbers every decision
// (C7-A5-2). force, when set, is the number of the next admin reply; hook
// runs before an admin request is decided.
type adminMux struct {
	mu    sync.Mutex
	run   Collector
	admin *adminCollector
	seq   uint64
	force uint64
	hook  func(*authz.CollectorRequest)
}

func (m *adminMux) Do(ctx context.Context, req *authz.CollectorRequest) (collectorclient.Response, error) {
	var r collectorclient.Response
	var err error
	if req.AdminSigned == nil {
		r, err = m.run.Do(ctx, req)
	} else {
		if m.hook != nil {
			m.hook(req)
		}
		r, err = m.admin.Do(ctx, req)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Reply.Status != "" {
		m.seq++
		r.Reply.CollectorSeq = m.seq
		if m.force != 0 {
			r.Reply.CollectorSeq, m.force = m.force, 0
		}
	}
	return r, err
}

// signN is signAdmin with the nonce told apart by n, for a test that signs
// more than one request.
func signN(t *testing.T, kind authz.RequestKind, n int, edit func(*authz.AdminRequest)) *authz.AdminSigned {
	t.Helper()
	return signAdmin(t, kind, func(p *authz.AdminRequest) {
		nonce := make([]byte, authz.AdminNonceLen)
		copy(nonce, fmt.Sprintf("%d-%s", n, t.Name()))
		p.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
		if edit != nil {
			edit(p)
		}
	})
}

// signedQuarantineNode is a quarantine node whose collector is an adminMux,
// with two quarantined runs exported and recorded.
func signedQuarantineNode(t *testing.T) (*quarantineNode, *adminMux, string) {
	t.Helper()
	q := newQuarantineNode(t)
	mux := &adminMux{run: q.f, admin: newAdminCollector()}
	mux.admin.installKey = kid(testInstallKey)
	q.via = mux
	q.restart()
	q.runs(2, false) // seqs 1 to 4
	q.export()
	q.s.QuarantineTick(bg)
	if len(q.records(audit.ActionQuarantineExported)) != 1 {
		t.Fatal("the export was not recorded")
	}
	return q, mux, q.manifestHash()
}

func (q *quarantineNode) signedClear(name string, n int, manifest string) (b []byte, sum string) {
	q.t.Helper()
	env := signN(q.t, authz.KindNodeQuarantineClear, n, func(p *authz.AdminRequest) {
		p.NodeQuarantineClear.ManifestSHA256, p.InstallKeyID = manifest, kid(testInstallKey)
	})
	b = writeAdminFile(q.t, q.nc, name, authz.KindNodeQuarantineClear, env)
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:])
}

// verifiedHash is the payload hash the collector's accepted record for the
// request of file hash sum names.
func verifiedHash(t *testing.T, q *quarantineNode, sum string) string {
	t.Helper()
	for _, rec := range requestRecords(auditRecords(t, q.r), adminRequestID(sum)) {
		if rec.Verified != nil {
			return rec.Verified.PayloadSHA256
		}
	}
	t.Fatal("no accepted record with verified")
	return ""
}

func clearRecords(q *quarantineNode) []*audit.Record { return q.records(audit.ActionQuarantineCleared) }

// A signed quarantine clear goes through the collector, and the node then
// clears from the payload it sent: quarantine.cleared names the file's hash
// and the verified person, the relay's records carry claimed and verified,
// and the removal steps follow as for the unsigned file. Relayed again, it
// changes nothing.
func TestSignedQuarantineClear(t *testing.T) {
	q, mux, manifest := signedQuarantineNode(t)
	b, sum := q.signedClear("admin-request-clear.json", 1, manifest)
	q.s.relayAdmin(bg)

	recs := requestRecords(auditRecords(t, q.r), adminRequestID(sum))
	if len(recs) != 2 || recs[0].Claimed == nil || recs[0].Claimed.Kind != authz.KindNodeQuarantineClear || recs[0].Claimed.Principal != relayAdmin.ID ||
		recs[1].Outcome != audit.OutcomeAllowed || recs[1].Verified == nil || recs[1].Verified.Kind != authz.KindNodeQuarantineClear ||
		recs[1].Verified.PayloadSHA256 == "" || recs[1].Actor.ID != relayAdmin.ID || recs[1].RepeatOf != 0 {
		t.Fatalf("relay records %+v", recs)
	}
	cl := clearRecords(q)
	if len(cl) != 1 || cl[0].Outcome != audit.OutcomeSucceeded || cl[0].Quarantine.ClearSHA256 != recs[1].Verified.PayloadSHA256 || cl[0].Quarantine.RequestedBy != relayAdmin.ID ||
		cl[0].Quarantine.ManifestSHA256 != manifest || cl[0].Quarantine.FirstSeq != 1 || cl[0].Quarantine.LastSeq != 4 {
		t.Fatalf("cleared records %+v", cl)
	}
	if !strings.Contains(cl[0].Detail, "admin-request-clear.json") || !strings.Contains(cl[0].Detail, relayAdmin.ID) {
		t.Fatalf("the clear record does not name the signed file and person: %q", cl[0].Detail)
	}
	got := adminShown(q.st)
	if len(got) != 1 || got[0].State != "accepted" || got[0].NodePart != "done" || got[0].Detail != "" {
		t.Fatalf("status %+v", got)
	}
	for i := 0; i < 3; i++ {
		q.s.QuarantineTick(bg) // the removal steps
	}
	if got := q.seqs(); len(got) != 0 {
		t.Fatalf("after the steps the stream holds %v", got)
	}

	// Again: not sent, not recorded again.
	q.s.relayAdmin(bg)
	q.restart()
	q.s.relayAdmin(bg)
	if n := len(mux.admin.requests()); n != 1 {
		t.Fatalf("%d admin requests, want 1", n)
	}
	if n := len(clearRecords(q)); n != 1 {
		t.Fatalf("%d cleared records after a restart, want 1", n)
	}
	_ = b
}

// The node acts on the bytes the collector accepted (A3 on #181). A file
// replaced while the request is with the collector is another request, and
// the clear is of the manifest the original named.
func TestSignedQuarantineClearActsOnTheBytesSent(t *testing.T) {
	q, mux, manifest := signedQuarantineNode(t)
	_, sum := q.signedClear("admin-request-clear.json", 1, manifest)
	other := strings.Repeat("ab", 32)
	mux.hook = func(*authz.CollectorRequest) {
		mux.hook = nil
		q.signedClear("admin-request-clear.json", 2, other)
	}
	q.s.relayAdmin(bg)
	cl := clearRecords(q)
	if len(cl) != 1 || cl[0].Quarantine.ManifestSHA256 != manifest || cl[0].Quarantine.ClearSHA256 != verifiedHash(t, q, sum) {
		t.Fatalf("the node acted on the replaced file: %+v", cl)
	}
	// The replacement is a new request: relayed, accepted, and refused by
	// the node's own check against its chain, which holds no such export.
	q.s.relayAdmin(bg)
	if n := len(mux.admin.requests()); n != 2 {
		t.Fatalf("%d admin requests, want 2", n)
	}
	if len(clearRecords(q)) != 1 || !q.hasAlarm(AlarmQuarantineClearRefused, "holds no quarantine.exported record") {
		t.Fatalf("the replacement was applied or not refused: %+v", clearRecords(q))
	}
	got := adminShown(q.st)
	if len(got) != 1 || got[0].NodePart != "pending" || !strings.Contains(got[0].Detail, "holds no quarantine.exported record") {
		t.Fatalf("status %+v", got)
	}
}

// What is owed is read from the chain: an accepted clear whose part could
// not be done (the manifest copy it checks against was missing) is done at
// a later tick, after a restart, without sending the request again, and
// only once.
func TestSignedQuarantineClearResumesFromTheChain(t *testing.T) {
	q, mux, manifest := signedQuarantineNode(t)
	copyName := QuarantineExportFileName(relayID)
	copyBytes, err := os.ReadFile(filepath.Join(q.nc.AdminDir, copyName))
	if err != nil {
		t.Fatal(err)
	}
	q.removeAdminFile(copyName)
	_, sum := q.signedClear("admin-request-clear.json", 1, manifest)
	q.s.relayAdmin(bg)
	if len(clearRecords(q)) != 0 {
		t.Fatal("cleared without the manifest copy")
	}
	if got := adminShown(q.st); len(got) != 1 || got[0].State != "accepted" || got[0].NodePart != "pending" {
		t.Fatalf("status %+v", got)
	}
	recs := requestRecords(auditRecords(t, q.r), adminRequestID(sum))
	if len(recs) != 2 || recs[1].Outcome != audit.OutcomeAllowed {
		t.Fatalf("relay records %+v", recs)
	}

	q.restart()
	q.adminFile(copyName, copyBytes)
	q.s.relayAdmin(bg)
	q.s.relayAdmin(bg)
	if n := len(clearRecords(q)); n != 1 {
		t.Fatalf("%d cleared records, want 1", n)
	}
	if n := len(mux.admin.requests()); n != 1 {
		t.Fatalf("the accepted request was sent %d times", n)
	}
	if got := adminShown(q.st); len(got) != 1 || got[0].NodePart != "done" {
		t.Fatalf("status %+v", got)
	}
}

// A reply that accepts a request but does not name it as verified is
// recorded without verified, and the node does nothing on it.
func TestSignedQuarantineClearNeedsTheVerifiedGroup(t *testing.T) {
	for name, edit := range map[string]func(*authz.CollectorReply){
		"no admin":    func(r *authz.CollectorReply) { r.Admin = nil },
		"other bytes": func(r *authz.CollectorReply) { r.Admin.PayloadSHA256 = strings.Repeat("0", 64) },
		"other person": func(r *authz.CollectorReply) {
			r.Admin.Principal = authz.Principal{Type: authz.PrincipalHuman, ID: "someone@else"}
		},
		"other key":     func(r *authz.CollectorReply) { r.Admin.AdminKeyID = "ed25519-0000000000000000" },
		"another nonce": func(r *authz.CollectorReply) { r.Admin.Nonce = strings.Repeat("A", 22) },
	} {
		t.Run(name, func(t *testing.T) {
			q, mux, manifest := signedQuarantineNode(t)
			mux.admin.edit = edit
			_, sum := q.signedClear("admin-request-clear.json", 1, manifest)
			q.s.relayAdmin(bg)
			if n := len(clearRecords(q)); n != 0 {
				t.Fatalf("%d cleared records on an acceptance that does not name the request", n)
			}
			recs := requestRecords(auditRecords(t, q.r), adminRequestID(sum))
			if len(recs) != 2 || recs[1].Outcome != audit.OutcomeAllowed || recs[1].Verified != nil || recs[1].Actor.Type != authz.PrincipalNode {
				t.Fatalf("relay records %+v", recs)
			}
			if countAlarms(q.st, AlarmAdminAcceptanceInvalid) != 1 {
				t.Fatal("no admin-request-acceptance-invalid alarm")
			}
			if got := adminShown(q.st); len(got) != 1 || got[0].NodePart != "pending" {
				t.Fatalf("status %+v", got)
			}
		})
	}
}

// An acceptance numbered at or below the collector's high mark leaves the
// collector held as restored, and the node does its part on nothing it
// decided (A3 on #181, item 3).
func TestSignedQuarantineClearNotAppliedOnARestoredCollector(t *testing.T) {
	q, mux, manifest := signedQuarantineNode(t)
	q.signedClear("admin-request-clear.json", 1, manifest)
	mux.force = 1 // below every number the runs got
	q.s.relayAdmin(bg)
	if n := len(clearRecords(q)); n != 0 {
		t.Fatalf("%d cleared records on a restored collector", n)
	}
	if !q.hasAlarm(AlarmAdminRequestNotApplied, "a collector the node did not trust") {
		t.Fatal("no admin-request-not-applied alarm naming the restored collector")
	}
	if got := adminShown(q.st); len(got) != 1 || got[0].State != "accepted" || got[0].NodePart != "refused" || !strings.Contains(got[0].Detail, "Sign the request again") {
		t.Fatalf("status %+v", got)
	}
}

// A collector that goes back after an acceptance was folded holds the node
// back from acting on it, and acts on it again once the hold is gone: only
// an acceptance numbered at or below the high mark is tainted for good.
func TestSignedQuarantineClearWaitsOutALaterRestoreHold(t *testing.T) {
	q, mux, manifest := signedQuarantineNode(t)
	copyName := QuarantineExportFileName(relayID)
	copyBytes, err := os.ReadFile(filepath.Join(q.nc.AdminDir, copyName))
	if err != nil {
		t.Fatal(err)
	}
	q.removeAdminFile(copyName)
	q.signedClear("admin-request-clear.json", 1, manifest)
	q.s.relayAdmin(bg) // accepted, part pending: no copy to check against
	mux.force = 1      // the collector's next reply goes back
	q.restart()
	q.s.RunOnce(bg, 0)
	q.adminFile(copyName, copyBytes)
	q.s.relayAdmin(bg)
	if len(clearRecords(q)) != 0 || !q.hasAlarm(AlarmAdminRequestNotApplied, "held as restored") {
		t.Fatalf("acted while the collector is held as restored: %+v", clearRecords(q))
	}
	if got := adminShown(q.st); len(got) != 1 || got[0].NodePart != "pending" {
		t.Fatalf("status %+v", got)
	}
}

func reinstall(t *testing.T, q *quarantineNode, name string) {
	t.Helper()
	if err := q.nc.WriteInstallKey(name); err != nil {
		t.Fatal(err)
	}
	q.s.RunOnce(bg, 0) // finds the new key and writes collector.seq_reset
	cs := q.st.Snapshot("x").Collector
	if cs == nil || cs.OpenResetKey != kid(name) {
		t.Fatalf("no reset open on %s: %+v", name, cs)
	}
	writeAck(t, q.nc, name)
	q.s.RunOnce(bg, 0)
	if cs := q.st.Snapshot("x").Collector; cs == nil || cs.OpenResetKey != "" || cs.TrustedKey != kid(name) {
		t.Fatalf("reset not acknowledged: %+v", cs)
	}
}

// A6's probe on #339: a clear the restored collector accepted is not acted
// on after the collector is reinstalled and the reset acknowledged, now or
// after a restart; the entry is refused and says to sign again.
func TestSignedQuarantineClearAcceptedWhileRestoredStaysRefused(t *testing.T) {
	q, mux, manifest := signedQuarantineNode(t)
	q.signedClear("admin-request-clear.json", 1, manifest)
	mux.force = 1
	q.s.relayAdmin(bg)
	if got := adminShown(q.st); len(got) != 1 || got[0].NodePart != "refused" {
		t.Fatalf("status %+v", got)
	}
	reinstall(t, q, "ik_test_second")
	for i := 0; i < 2; i++ {
		q.s.relayAdmin(bg)
		if n := len(clearRecords(q)); n != 0 {
			t.Fatalf("%d cleared records after the reinstall", n)
		}
		if got := adminShown(q.st); len(got) != 1 || got[0].State != "accepted" || got[0].NodePart != "refused" || !strings.Contains(got[0].Detail, "Sign the request again") {
			t.Fatalf("status %+v", got)
		}
		q.restart()
	}
}

// B1's rule (b) on its own: a clear accepted for the install key the node
// then replaces is refused, though the collector was never held as
// restored.
func TestSignedQuarantineClearRetiredByAReinstall(t *testing.T) {
	q, _, manifest := signedQuarantineNode(t)
	copyName := QuarantineExportFileName(relayID)
	copyBytes, err := os.ReadFile(filepath.Join(q.nc.AdminDir, copyName))
	if err != nil {
		t.Fatal(err)
	}
	q.removeAdminFile(copyName)
	q.signedClear("admin-request-clear.json", 1, manifest)
	q.s.relayAdmin(bg)
	if got := adminShown(q.st); len(got) != 1 || got[0].State != "accepted" || got[0].NodePart != "pending" {
		t.Fatalf("status %+v", got)
	}
	// While the reset is open the clear is held, and after its
	// acknowledgement it is retired.
	if err := q.nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	q.s.RunOnce(bg, 0)
	q.adminFile(copyName, copyBytes)
	q.s.relayAdmin(bg)
	if got := adminShown(q.st); len(got) != 1 || got[0].NodePart != "pending" || !strings.Contains(got[0].Detail, "not acknowledged yet") {
		t.Fatalf("status during the open reset %+v", got)
	}
	writeAck(t, q.nc, "ik_test_second")
	q.s.RunOnce(bg, 0)
	q.restart()
	q.s.relayAdmin(bg)
	if n := len(clearRecords(q)); n != 0 {
		t.Fatalf("%d cleared records for a retired key", n)
	}
	got := adminShown(q.st)
	if len(got) != 1 || got[0].NodePart != "refused" || !strings.Contains(got[0].Detail, "retired") || !strings.Contains(got[0].Detail, "Sign the request again") {
		t.Fatalf("status %+v", got)
	}
}

// The reply to a resend of bytes the collector already accepted is the
// repeat answer: recorded with repeat_of, and the node's part is done once.
func TestSignedQuarantineClearRepeatAnswer(t *testing.T) {
	q, mux, manifest := signedQuarantineNode(t)
	mux.admin.repeat = true
	mux.admin.lose = true
	_, sum := q.signedClear("admin-request-clear.json", 1, manifest)
	q.s.relayAdmin(bg) // decided, reply lost
	if n := len(clearRecords(q)); n != 0 {
		t.Fatalf("%d cleared records before any reply", n)
	}
	mux.admin.mu.Lock()
	mux.admin.lose = false
	mux.admin.mu.Unlock()
	q.s.relayAdmin(bg)
	recs := requestRecords(auditRecords(t, q.r), adminRequestID(sum))
	last := recs[len(recs)-1]
	if last.Outcome != audit.OutcomeAllowed || last.Verified == nil || last.RepeatOf == 0 || last.RepeatOf >= last.CollectorSeq {
		t.Fatalf("relay records %+v", recs)
	}
	if n := len(clearRecords(q)); n != 1 {
		t.Fatalf("%d cleared records, want 1", n)
	}
	q.s.relayAdmin(bg)
	if n := len(clearRecords(q)); n != 1 {
		t.Fatalf("%d cleared records after another tick, want 1", n)
	}
}

// A collector reinstalled holds every request except the administrator's
// signed acknowledgement of its new key, which is relayed, accepted, and
// then applied by the node: the reset is acknowledged and the old key stays
// distinct from the new one.
func TestSignedSeqResetAck(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	writeAdminFile(t, nc, "admin-request-first.json", authz.KindCredentialRevoke, signN(t, authz.KindCredentialRevoke, 1, nil))
	s.relayAdmin(bg)
	if len(col.requests()) != 1 {
		t.Fatalf("%d requests before the reinstall", len(col.requests()))
	}

	// The collector is reinstalled: a new install key.
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	col.mu.Lock()
	col.installKey = kid("ik_test_second")
	col.mu.Unlock()
	writeAdminFile(t, nc, "admin-request-second.json", authz.KindCredentialRevoke, signN(t, authz.KindCredentialRevoke, 2, func(p *authz.AdminRequest) { p.InstallKeyID = kid("ik_test_second") }))
	s.relayAdmin(bg)
	if len(col.requests()) != 1 {
		t.Fatalf("a request other than an acknowledgement was sent while the reset is open: %d requests", len(col.requests()))
	}
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.OpenResetKey != kid("ik_test_second") {
		t.Fatalf("status collector %+v", cs)
	}

	ack := signN(t, authz.KindNodeSeqResetAck, 3, func(p *authz.AdminRequest) { p.InstallKeyID = kid("ik_test_second") })
	b := writeAdminFile(t, nc, "admin-request-ack.json", authz.KindNodeSeqResetAck, ack)
	s.relayAdmin(bg)
	if len(col.requests()) != 2 || col.requests()[1].Kind != authz.KindNodeSeqResetAck {
		t.Fatalf("requests %d", len(col.requests()))
	}
	acks := actionsOf(t, r, audit.ActionCollectorSeqResetAck)
	if len(acks) != 1 || acks[0].InstallKeyID != kid("ik_test_second") || !strings.Contains(acks[0].Detail, "admin-request-ack.json") || !strings.Contains(acks[0].Detail, relayAdmin.ID) {
		t.Fatalf("acks %+v", acks)
	}
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.OpenResetKey != "" || cs.TrustedKey != kid("ik_test_second") {
		t.Fatalf("status collector %+v", cs)
	}
	if !slices.ContainsFunc(adminShown(st), func(a AdminRequestStatus) bool { return a.File == "admin-request-ack.json" && a.NodePart == "done" }) {
		t.Fatalf("status %+v", adminShown(st))
	}
	sum := sha256.Sum256(b)
	recs := requestRecords(auditRecords(t, r), adminRequestID(hex.EncodeToString(sum[:])))
	if len(recs) != 2 || recs[1].Verified == nil || recs[1].Verified.Kind != authz.KindNodeSeqResetAck {
		t.Fatalf("relay records %+v", recs)
	}
	// The held credential request goes now, and the acknowledgement is not
	// applied twice.
	s.relayAdmin(bg)
	s.relayAdmin(bg)
	if len(col.requests()) != 3 || len(actionsOf(t, r, audit.ActionCollectorSeqResetAck)) != 1 {
		t.Fatalf("%d requests, %d acks", len(col.requests()), len(actionsOf(t, r, audit.ActionCollectorSeqResetAck)))
	}
	if !slices.ContainsFunc(adminShown(st), func(a AdminRequestStatus) bool {
		return a.File == "admin-request-ack.json" && a.State == "accepted" && (a.NodePart == "done" || a.NodePart == "nothing")
	}) {
		t.Fatalf("status %+v", adminShown(st))
	}
}

// A signed acknowledgement with no reset open does nothing: for the key
// already trusted it says so, and for another it is refused.
func TestSignedSeqResetAckWithNoResetOpen(t *testing.T) {
	for name, tc := range map[string]struct {
		key, part, detail string
	}{
		"trusted key": {kid(testInstallKey), "nothing", "already the trusted key"},
		"other key":   {kid("ik_test_other"), "refused", "no reset is open"},
	} {
		t.Run(name, func(t *testing.T) {
			c, dir, nc := suspendConfig(t)
			r, st, _ := start(t, c, dir)
			defer r.Close()
			col := newAdminCollector()
			col.installKey = tc.key
			s := newScheduler(t, r, col)
			writeAdminFile(t, nc, "admin-request-ack.json", authz.KindNodeSeqResetAck,
				signN(t, authz.KindNodeSeqResetAck, 1, func(p *authz.AdminRequest) { p.InstallKeyID = tc.key }))
			s.relayAdmin(bg)
			if len(actionsOf(t, r, audit.ActionCollectorSeqResetAck)) != 0 {
				t.Fatal("acknowledged a reset that is not open")
			}
			got := adminShown(st)
			if len(got) != 1 || got[0].State != "accepted" || got[0].NodePart != tc.part || !strings.Contains(got[0].Detail, tc.detail) {
				t.Fatalf("status %+v", got)
			}
		})
	}
}

// The node's own check that an acknowledgement names the open reset's key,
// reached through a collector that accepts the mismatched one (A6 on #339):
// nothing is acknowledged, and the entry is refused.
func TestSignedSeqResetAckOfAnotherKey(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	writeAdminFile(t, nc, "admin-request-first.json", authz.KindCredentialRevoke, signN(t, authz.KindCredentialRevoke, 1, nil))
	s.relayAdmin(bg)
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	other := kid("ik_test_other")
	col.mu.Lock()
	col.installKey = other // this collector binds, and so accepts, the other key
	col.mu.Unlock()
	for name, key := range map[string]string{"another key": other, "the old trusted key": kid(testInstallKey)} {
		col.mu.Lock()
		col.installKey = key
		col.mu.Unlock()
		file := "admin-request-" + strings.ReplaceAll(name, " ", "-") + ".json"
		writeAdminFile(t, nc, file, authz.KindNodeSeqResetAck, signN(t, authz.KindNodeSeqResetAck, 2+len(name), func(p *authz.AdminRequest) { p.InstallKeyID = key }))
		s.relayAdmin(bg)
		if n := len(actionsOf(t, r, audit.ActionCollectorSeqResetAck)); n != 0 {
			t.Fatalf("%s: %d acknowledgements", name, n)
		}
		found := false
		for _, a := range adminShown(st) {
			if a.File == file {
				found = a.State == "accepted" && a.NodePart == "refused" && strings.Contains(a.Detail, "the open reset is on "+kid("ik_test_second"))
			}
		}
		if !found {
			t.Fatalf("%s: status %+v", name, adminShown(st))
		}
	}
	if cs := st.Snapshot("site-a-node1").Collector; cs == nil || cs.OpenResetKey != kid("ik_test_second") {
		t.Fatalf("the reset is no longer open: %+v", cs)
	}
}

// Each check on the chain's acceptance and on the payload, one field at a
// time: the node does nothing and says why. The entry is the folded record
// the node would read after a restart, so a field that differs is a chain
// record that differs (A3 on #339). The control, with nothing differing,
// clears.
func TestApplyAdminPartGates(t *testing.T) {
	for name, tc := range map[string]struct {
		edit  func(*authz.AdminRequest) // the signed payload
		entry func(*relayEntry)         // the folded acceptance
		file  func(*adminFile)          // what the node read
		want  string                    // "" for the control
	}{
		"control": {},
		"payload hash": {
			entry: func(e *relayEntry) { e.Verified.PayloadSHA256 = strings.Repeat("0", 64) },
			want:  "other signed bytes",
		},
		"verified person": {
			entry: func(e *relayEntry) { e.Verified.Principal = "someone@else" },
			want:  "other signed bytes",
		},
		"verified kind": {
			entry: func(e *relayEntry) { e.Verified.Kind = authz.KindNodeSeqResetAck },
			want:  "other signed bytes",
		},
		"node ID": {
			edit: func(p *authz.AdminRequest) { p.NodeID = "site-b-node9" },
			want: "bound to another node",
		},
		"payload kind": {
			file:  func(f *adminFile) { f.kind = authz.KindNodeSeqResetAck },
			entry: func(e *relayEntry) { e.Verified.Kind = authz.KindNodeSeqResetAck },
			want:  "kind or person is not the file's",
		},
		"payload person": {
			file:  func(f *adminFile) { f.claims.Principal.ID = "someone@else" },
			entry: func(e *relayEntry) { e.Verified.Principal = "someone@else" },
			want:  "kind or person is not the file's",
		},
	} {
		t.Run(name, func(t *testing.T) {
			q, _, manifest := signedQuarantineNode(t)
			env := signN(t, authz.KindNodeQuarantineClear, 1, func(p *authz.AdminRequest) {
				p.NodeQuarantineClear.ManifestSHA256, p.InstallKeyID = manifest, kid(testInstallKey)
				if tc.edit != nil {
					tc.edit(p)
				}
			})
			f := &adminFile{name: "admin-request-gate.json", sum: strings.Repeat("ab", 32), kind: authz.KindNodeQuarantineClear, signed: env,
				claims: adminClaims{Kind: authz.KindNodeQuarantineClear, Principal: relayAdmin}}
			f.id = adminRequestID(f.sum)
			e := relayEntry{Outcome: audit.OutcomeAllowed, CollectorSeq: 5, Verified: &audit.Admin{
				AdminKeyID: env.KeyID, Principal: relayAdmin.ID, Nonce: strings.Repeat("A", 22), PayloadSHA256: authz.AdminPayloadSHA256(env), Kind: authz.KindNodeQuarantineClear}}
			if tc.entry != nil {
				tc.entry(&e)
			}
			if tc.file != nil {
				tc.file(f)
			}
			q.s.mu.Lock()
			q.s.relayed[f.id] = e
			q.s.mu.Unlock()
			parts := q.s.applyAdminParts(bg, []*adminFile{f})
			if tc.want == "" {
				if parts[f.id].state != partDone || len(clearRecords(q)) != 1 {
					t.Fatalf("the control did not clear: %+v, %d records", parts[f.id], len(clearRecords(q)))
				}
				return
			}
			if n := len(clearRecords(q)); n != 0 {
				t.Fatalf("%d cleared records", n)
			}
			if p := parts[f.id]; p.state == partDone || !strings.Contains(p.detail, tc.want) || !q.hasAlarm(AlarmAdminRequestNotApplied, tc.want) {
				t.Fatalf("part %+v; no alarm naming %q", p, tc.want)
			}
		})
	}
}

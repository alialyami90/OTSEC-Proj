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
	env := signN(q.t, authz.KindNodeQuarantineClear, n, func(p *authz.AdminRequest) { p.NodeQuarantineClear.ManifestSHA256 = manifest })
	b = writeAdminFile(q.t, q.nc, name, authz.KindNodeQuarantineClear, env)
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:])
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
	if len(cl) != 1 || cl[0].Outcome != audit.OutcomeSucceeded || cl[0].Quarantine.ClearSHA256 != sum || cl[0].Quarantine.RequestedBy != relayAdmin.ID ||
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
	if len(cl) != 1 || cl[0].Quarantine.ManifestSHA256 != manifest || cl[0].Quarantine.ClearSHA256 != sum {
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
	if !q.hasAlarm(AlarmAdminRequestNotApplied, "held as restored") {
		t.Fatal("no admin-request-not-applied alarm naming the restore")
	}
	if got := adminShown(q.st); len(got) != 1 || got[0].State != "accepted" || got[0].NodePart != "pending" {
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
		return a.File == "admin-request-ack.json" && a.State == "accepted" && a.NodePart == "done"
	}) {
		t.Fatalf("status %+v", adminShown(st))
	}
}

// A signed acknowledgement of a key that is not the open reset's changes
// nothing, and says so rather than reading as applied.
func TestSignedSeqResetAckWithNoResetOpen(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	writeAdminFile(t, nc, "admin-request-ack.json", authz.KindNodeSeqResetAck,
		signN(t, authz.KindNodeSeqResetAck, 1, func(p *authz.AdminRequest) { p.InstallKeyID = testInstallKey }))
	s.relayAdmin(bg)
	if len(actionsOf(t, r, audit.ActionCollectorSeqResetAck)) != 0 {
		t.Fatal("acknowledged a reset that is not open")
	}
	got := adminShown(st)
	if len(got) != 1 || got[0].State != "accepted" || got[0].NodePart != "pending" || !strings.Contains(got[0].Detail, "no reset is open") {
		t.Fatalf("status %+v", got)
	}
}

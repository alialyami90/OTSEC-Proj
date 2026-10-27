package node

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

// The test administrator: a key made from a fixed seed (test only, D2-5)
// and the person it speaks for.
var (
	relayAdminPriv = ed25519.NewKeyFromSeed(func() []byte { s := sha256.Sum256([]byte("otsec node relay test admin")); return s[:] }())
	relayAdmin     = authz.Principal{Type: authz.PrincipalHuman, ID: "admin@site-a"}
)

// adminCollector is the collector's side of a signed request as far as the
// node can tell: VerifyAdminRequest against the pinned test key, this
// node and the current install key, then the nonce spent once. It numbers
// every decision. lose makes it decide and then drop the reply.
type adminCollector struct {
	mu     sync.Mutex
	seq    uint64
	spent  map[string]bool
	sent   []*authz.CollectorRequest
	runs   int
	lose   bool
	failed bool // no decision and no number: the pipe was not there
	// edit, when set, changes each reply to an admin-signed request
	// before it is returned.
	edit func(*authz.CollectorReply)
	// held is the time hangCollector held admin-signed requests.
	held time.Duration
}

func newAdminCollector() *adminCollector { return &adminCollector{spent: map[string]bool{}} }

func (c *adminCollector) Do(ctx context.Context, req *authz.CollectorRequest) (collectorclient.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if req.Kind == authz.KindRun {
		c.runs++
		return collectorclient.Response{}, errors.New("no run in these tests")
	}
	c.sent = append(c.sent, req)
	if c.failed {
		return collectorclient.Response{}, errors.New("dial: no collector")
	}
	c.seq++
	reply := authz.CollectorReply{Contract: authz.ContractID, RequestID: req.RequestID, CollectorSeq: c.seq, Status: authz.ReplyAccepted}
	keys := []authz.AdminKey{{KeyID: authz.AdminKeyID(relayAdminPriv.Public().(ed25519.PublicKey)),
		PublicKey: relayAdminPriv.Public().(ed25519.PublicKey), Principal: relayAdmin.ID, Status: authz.KeyActive}}
	p, err := authz.VerifyAdminRequest(req, keys, authz.AdminBinding{NodeID: "site-a-node1", InstallKeyID: testInstallKey}, time.Now())
	if err == nil && c.spent[p.Nonce] {
		err = &authz.AdminRejected{Check: authz.AdminCheckReplay}
	}
	var rej *authz.AdminRejected
	switch {
	case errors.As(err, &rej):
		reply.Status, reply.Refusal = authz.ReplyRefused, rej.Refusal()
	case err != nil:
		panic(err)
	default:
		c.spent[p.Nonce] = true
	}
	if c.lose {
		return collectorclient.Response{}, errors.New("collectorclient: no reply: EOF")
	}
	if c.edit != nil {
		c.edit(&reply)
	}
	return collectorclient.Response{Reply: reply}, nil
}

func (c *adminCollector) requests() []*authz.CollectorRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*authz.CollectorRequest{}, c.sent...)
}

// signAdmin signs a credential.revoke for this node, valid for ten
// minutes, as the administrator's client would. edit changes the payload
// before it is signed.
func signAdmin(t *testing.T, kind authz.RequestKind, edit func(*authz.AdminRequest)) *authz.AdminSigned {
	t.Helper()
	nonce := make([]byte, authz.AdminNonceLen)
	copy(nonce, t.Name())
	now := time.Now().UTC().Truncate(time.Second)
	p := authz.AdminRequest{Format: authz.AdminRequestFormat, Kind: kind, Principal: relayAdmin,
		AdminKeyID: authz.AdminKeyID(relayAdminPriv.Public().(ed25519.PublicKey)), NodeID: "site-a-node1",
		InstallKeyID: testInstallKey, Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339)}
	switch kind {
	case authz.KindCredentialRevoke:
		p.CredentialRevoke = &authz.CredentialRevokeBody{RefID: nodeconfigtest.TestCredentialRef, Reason: authz.RevokeRotated}
	case authz.KindAssetClearSusp:
		p.AssetClearSusp = &authz.AssetClearSuspBody{AssetID: relayID, Ref: okInvocation}
	}
	if edit != nil {
		edit(&p)
	}
	env, err := authz.SignAdminRequest(relayAdminPriv, p)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// writeAdminFile leaves an admin-request file in admin_dir, as an
// administrator would, and returns its bytes.
func writeAdminFile(t *testing.T, nc *nodeconfigtest.Config, name string, kind authz.RequestKind, env *authz.AdminSigned) []byte {
	t.Helper()
	b, err := json.Marshal(adminRequestFile{Schema: AdminRequestFileSchema, Kind: kind, Signed: env})
	if err != nil {
		t.Fatal(err)
	}
	writeAdminBytes(t, nc, name, b)
	return b
}

func writeAdminBytes(t *testing.T, nc *nodeconfigtest.Config, name string, b []byte) {
	t.Helper()
	nc.UnlockTLS()
	if err := os.WriteFile(filepath.Join(nc.AdminDir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
}

func removeAdminFile(t *testing.T, nc *nodeconfigtest.Config, name string) {
	t.Helper()
	nc.UnlockTLS()
	if err := os.Remove(filepath.Join(nc.AdminDir, name)); err != nil {
		t.Fatal(err)
	}
	lockTLS(t, nc)
}

func relayRecords(t *testing.T, s *Scheduler, b []byte) []*audit.Record {
	t.Helper()
	sum := sha256.Sum256(b)
	return requestRecords(auditRecords(t, s.rt), adminRequestID(hex.EncodeToString(sum[:])))
}

func adminShown(st *Status) []AdminRequestStatus { return st.Snapshot("x").AdminRequests }

// A relayed file is sent once, unchanged and on behalf of the person the
// payload names; the node records it before sending, with the payload's
// key, nonce and person marked unverified, and the acceptance with the
// person as actor. It is not sent again, on the next tick, after a
// restart, or after a restart whose checkpoint is lost: the chain holds
// the decision.
func TestRelaySendsOnce(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	env := signAdmin(t, authz.KindCredentialRevoke, nil)
	b := writeAdminFile(t, nc, "admin-request-revoke-1.json", authz.KindCredentialRevoke, env)
	s.relayAdmin(bg)
	sent := col.requests()
	if len(sent) != 1 {
		t.Fatalf("%d requests sent", len(sent))
	}
	req := sent[0]
	if req.OnBehalfOf != relayAdmin || req.Kind != authz.KindCredentialRevoke || req.CredentialRevoke != nil ||
		string(req.AdminSigned.Payload) != string(env.Payload) || string(req.AdminSigned.Signature) != string(env.Signature) {
		t.Fatalf("request %+v", req)
	}
	recs := relayRecords(t, s, b)
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	info, allowed := recs[0], recs[1]
	var p authz.AdminRequest
	json.Unmarshal(env.Payload, &p)
	if info.Outcome != audit.OutcomeInfo || info.Actor.Type != authz.PrincipalNode || !strings.Contains(info.Detail, "unverified") ||
		!strings.Contains(info.Detail, env.KeyID) || !strings.Contains(info.Detail, p.Nonce) || !strings.Contains(info.Detail, relayAdmin.ID) {
		t.Fatalf("info record %+v", info)
	}
	if allowed.Outcome != audit.OutcomeAllowed || allowed.Actor.Type != authz.PrincipalHuman || allowed.Actor.ID != relayAdmin.ID ||
		allowed.Actor.Role != authz.RoleAdmin || allowed.CollectorSeq != 1 || strings.Contains(allowed.Detail, "unverified") {
		t.Fatalf("allowed record %+v", allowed)
	}
	if got := adminShown(st); len(got) != 1 || got[0].State != "accepted" || got[0].CollectorSeq != 1 {
		t.Fatalf("status %+v", got)
	}

	s.relayAdmin(bg)
	s2 := newScheduler(t, r, col)
	s2.relayAdmin(bg)
	if err := os.Remove(filepath.Join(c.Store.Dir, SuspensionsFileName)); err != nil {
		t.Fatal(err)
	}
	s3 := newScheduler(t, r, col)
	s3.relayAdmin(bg)
	if n := len(col.requests()); n != 1 {
		t.Fatalf("%d requests after a tick and two restarts", n)
	}
}

// The checkpoint holds the decided set: a restart whose checkpoint was
// written after the decision reads it there, not from the stream.
func TestRelayedSetInCheckpoint(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	b := writeAdminFile(t, nc, "admin-request-a.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg)
	f, err := readSuspensions(filepath.Join(c.Store.Dir, SuspensionsFileName))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if e, ok := f.AdminRelayed[adminRequestID(hex.EncodeToString(sum[:]))]; !ok || e.Outcome != audit.OutcomeAllowed || e.CollectorSeq != 1 {
		t.Fatalf("checkpoint %+v", f.AdminRelayed)
	}
}

// A payload altered after signing is refused by the collector, with the
// check named; the node records the refusal as denied with the node as
// actor, raises the alarm and does not send it again.
func TestRelayAlteredPayloadRefused(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	env := signAdmin(t, authz.KindCredentialRevoke, nil)
	env.Payload = []byte(strings.Replace(string(env.Payload), `"rotated"`, `"compromised"`, 1))
	b := writeAdminFile(t, nc, "admin-request-altered.json", authz.KindCredentialRevoke, env)
	s.relayAdmin(bg)
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 1 {
		t.Fatalf("%d requests", n)
	}
	recs := relayRecords(t, s, b)
	if len(recs) != 2 || recs[1].Outcome != audit.OutcomeDenied || recs[1].ReasonCode != string(authz.RefuseAdminUnverified) ||
		recs[1].Actor.Type != authz.PrincipalNode || !strings.Contains(recs[1].Detail, "check signature") {
		t.Fatalf("records %+v", recs)
	}
	if countAlarms(st, AlarmAdminRequestRefused) != 1 {
		t.Fatal("no refused alarm")
	}
	if got := adminShown(st); len(got) != 1 || got[0].State != "refused" || got[0].Detail != string(authz.RefuseAdminUnverified) {
		t.Fatalf("status %+v", got)
	}
}

// A file the node itself could have written is no administrator's: it is
// never read, so nothing is sent or recorded, and the alarm says why.
func TestRelayNeedsAnAdministratorsFile(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	const name = "admin-request-writable.json"
	b := writeAdminFile(t, nc, name, authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	if err := nc.LoosenTLS(name); err != nil {
		t.Fatal(err)
	}
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 0 {
		t.Fatalf("%d requests from a node-writable file", n)
	}
	if recs := relayRecords(t, s, b); len(recs) != 0 {
		t.Fatalf("records %+v", recs)
	}
	if countAlarms(st, AlarmAdminRequestUnread) != 1 {
		t.Fatal("no unread alarm")
	}
	if got := adminShown(st); len(got) != 1 || got[0].State != "unread" {
		t.Fatalf("status %+v", got)
	}
}

// What the node cannot relay is not sent: another schema, a kind this node
// does not relay yet (the asset clear waits for C7 0.5), a payload of
// another kind, a principal that is not a person, an unknown key in the
// file, and a misnamed file. Each raises the unread alarm once.
func TestRelayRefusesWhatItCannotRelay(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	revoke := signAdmin(t, authz.KindCredentialRevoke, nil)
	good, _ := json.Marshal(adminRequestFile{Schema: AdminRequestFileSchema, Kind: authz.KindCredentialRevoke, Signed: revoke})
	cases := map[string][]byte{
		"schema":    []byte(strings.Replace(string(good), AdminRequestFileSchema, "otsec.admin-request-file/0.2", 1)),
		"extra key": []byte(strings.Replace(string(good), `{"schema"`, `{"x":1,"schema"`, 1)),
		"duplicate": []byte(strings.Replace(string(good), `{"schema"`, `{"kind":"credential.install","schema"`, 1)),
		"kind": func() []byte {
			b, _ := json.Marshal(adminRequestFile{Schema: AdminRequestFileSchema, Kind: authz.KindAssetClearSusp, Signed: signAdmin(t, authz.KindAssetClearSusp, nil)})
			return b
		}(),
		"payload kind": []byte(strings.Replace(string(good), `"kind":"credential.revoke"`, `"kind":"credential.install"`, 1)),
		"not a person": func() []byte {
			b, _ := json.Marshal(adminRequestFile{Schema: AdminRequestFileSchema, Kind: authz.KindCredentialRevoke,
				Signed: signAdmin(t, authz.KindCredentialRevoke, func(p *authz.AdminRequest) { p.Principal.Type = authz.PrincipalNode })})
			return b
		}(),
	}
	i := 0
	for name, b := range cases {
		i++
		file := "admin-request-case-" + string(rune('a'+i)) + ".json"
		writeAdminBytes(t, nc, file, b)
		s.relayAdmin(bg)
		if n := len(col.requests()); n != 0 {
			t.Fatalf("%s: %d requests", name, n)
		}
		if n := countAlarms(st, AlarmAdminRequestUnread); n != i {
			t.Fatalf("%s: %d unread alarms", name, n)
		}
		removeAdminFile(t, nc, file)
	}
	writeAdminBytes(t, nc, "admin-request-Upper.json", good)
	s.relayAdmin(bg)
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 0 || countAlarms(st, AlarmAdminRequestUnread) != len(cases)+1 {
		t.Fatalf("misnamed file: %d requests", n)
	}
}

// A request with no decision is sent again on the next tick, until the
// collector decides it; then the alarm is quiet and the file is decided.
// The node keeps the info record of each send, so the chain shows every
// attempt.
func TestRelayRetriedWithoutDecision(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	col.failed = true
	s := newScheduler(t, r, col)
	b := writeAdminFile(t, nc, "admin-request-retry.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg)
	s.relayAdmin(bg)
	if countAlarms(st, AlarmAdminRequestNoDecision) != 1 {
		t.Fatal("no-decision alarm not raised once")
	}
	if got := adminShown(st); len(got) != 1 || got[0].State != "waiting" {
		t.Fatalf("status %+v", got)
	}
	col.mu.Lock()
	col.failed = false
	col.mu.Unlock()
	s.relayAdmin(bg)
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 3 {
		t.Fatalf("%d requests", n)
	}
	recs := relayRecords(t, s, b)
	if len(recs) != 4 || recs[3].Outcome != audit.OutcomeAllowed {
		t.Fatalf("records %+v", recs)
	}
}

// A reply lost after the collector spent the nonce: under C7 0.4 the
// resend is refused as a replay, which the node records and does not
// retry. For the credential kinds the collector's part was the whole
// operation, so nothing is lost (#181, B2).
func TestRelayLostReplyIsAReplay(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	col.lose = true
	s := newScheduler(t, r, col)
	b := writeAdminFile(t, nc, "admin-request-lost.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg)
	col.mu.Lock()
	col.lose = false
	col.mu.Unlock()
	s.relayAdmin(bg)
	s.relayAdmin(bg)
	recs := relayRecords(t, s, b)
	if len(recs) != 3 || recs[2].Outcome != audit.OutcomeDenied || !strings.Contains(recs[2].Detail, "check replay") || recs[2].CollectorSeq != 2 {
		t.Fatalf("records %+v", recs)
	}
	alarm := false
	for _, a := range st.Snapshot("x").Alarms {
		alarm = alarm || (a.Code == AlarmAdminRequestRefused && strings.Contains(a.Detail, "may already have been applied"))
	}
	if !alarm {
		t.Fatal("the replay alarm does not say the request may already have been applied")
	}
}

// Nothing is relayed while the collector is held: here a reinstall the
// administrator has not acknowledged.
func TestRelayHeldWithTheCollector(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	writeAdminFile(t, nc, "admin-request-a.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg) // trusts testInstallKey
	if err := nc.WriteInstallKey("ik_test_second"); err != nil {
		t.Fatal(err)
	}
	writeAdminFile(t, nc, "admin-request-b.json", authz.KindCredentialRevoke,
		signAdmin(t, authz.KindCredentialRevoke, func(p *authz.AdminRequest) { p.Nonce = "AAAAAAAAAAAAAAAAAAAAAA" }))
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 1 {
		t.Fatalf("%d requests", n)
	}
	if countAlarms(st, AlarmCollectorReset) != 1 {
		t.Fatal("no reset alarm")
	}
	got := adminShown(st)
	if len(got) != 2 || got[1].State != "waiting" || !strings.Contains(got[1].Detail, AlarmCollectorReset) {
		t.Fatalf("status %+v", got)
	}
}

// A decided request whose file is gone is forgotten, so the set stays as
// small as admin_dir. A file put back is sent again and refused as a
// replay, which changes nothing.
func TestRelayForgetsRemovedFiles(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	const name = "admin-request-gone.json"
	b := writeAdminFile(t, nc, name, authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg)
	removeAdminFile(t, nc, name)
	s.relayAdmin(bg)
	s.settle(bg)
	if n := len(s.relayed); n != 0 {
		t.Fatalf("%d decided requests kept", n)
	}
	f, err := readSuspensions(filepath.Join(c.Store.Dir, SuspensionsFileName))
	if err != nil || len(f.AdminRelayed) != 0 {
		t.Fatalf("checkpoint %+v %v", f.AdminRelayed, err)
	}
	writeAdminBytes(t, nc, name, b)
	s.relayAdmin(bg)
	if recs := relayRecords(t, s, b); len(recs) != 4 || recs[3].ReasonCode != string(authz.RefuseAdminUnverified) {
		t.Fatalf("records %+v", recs)
	}
}

// The record's detail fits C8's 512 bytes at the longest claims the
// patterns allow.
func TestRelayRecordFits(t *testing.T) {
	c, dir, _ := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, newAdminCollector())
	f := &adminFile{name: "admin-request-" + strings.Repeat("x", 64) + ".json", sum: strings.Repeat("f", 64), kind: authz.KindCredentialClearSusp,
		claims: adminClaims{Kind: authz.KindCredentialClearSusp, Principal: authz.Principal{Type: authz.PrincipalHuman, ID: "a" + strings.Repeat("b", 127)},
			AdminKeyID: "ed25519-0123456789abcdef", Nonce: strings.Repeat("A", 22), ExpiresAt: "2026-10-26T12:00:00Z"}}
	f.id = adminRequestID(f.sum)
	req := &authz.CollectorRequest{RequestID: f.id, PolicyVersion: 3}
	for _, o := range []struct {
		outcome audit.Outcome
		reply   authz.CollectorReply
	}{
		{audit.OutcomeInfo, authz.CollectorReply{}},
		{audit.OutcomeAllowed, authz.CollectorReply{CollectorSeq: 1 << 62}},
		{audit.OutcomeDenied, authz.CollectorReply{CollectorSeq: 1 << 62, Refusal: authz.AdminRefusal(authz.AdminCheckSignature)}},
	} {
		if _, err := s.relayRecord(f, req, o.outcome, o.reply); err != nil {
			t.Fatalf("%s: %v", o.outcome, err)
		}
	}
}

// Run relays at start and between runs, without waiting for a run.
func TestRunRelaysBetweenRuns(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	writeAdminFile(t, nc, "admin-request-run.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	if err := s.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	col.mu.Lock()
	defer col.mu.Unlock()
	if len(col.sent) != 1 || col.runs != 0 {
		t.Fatalf("%d relayed, %d runs", len(col.sent), col.runs)
	}
}

// Through the real client and the collector's strict decoder: a relayed
// file is a valid C7 request on the wire.
func TestRelayOverTheWire(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	client := collectorclient.NewWithDialer(func(ctx context.Context) (net.Conn, error) {
		cl, sv := net.Pipe()
		go func() {
			defer sv.Close()
			sv.SetDeadline(time.Now().Add(5 * time.Second))
			b, err := collectorwire.ReadFrame(sv, authz.MaxRequestBytes)
			if err != nil {
				return
			}
			req, err := authz.DecodeRequest(b)
			if err != nil {
				t.Errorf("collector decode: %v", err)
				return
			}
			resp, _ := col.Do(ctx, req)
			out, _ := json.Marshal(resp.Reply)
			collectorwire.WriteFrame(sv, out, collectorwire.MaxReplyBytes)
		}()
		return cl, nil
	})
	s := newScheduler(t, r, client)
	b := writeAdminFile(t, nc, "admin-request-wire.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg)
	if recs := relayRecords(t, s, b); len(recs) != 2 || recs[1].Outcome != audit.OutcomeAllowed {
		t.Fatalf("records %+v", recs)
	}
}

// An expired request is refused with check window, and the alarm says it
// may already have been applied, as for a replay: a file put back after
// its decision, resent after expiry, must not be re-signed blindly (A3 on
// #189).
func TestRelayExpiredSaysCheckFirst(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	s := newScheduler(t, r, newAdminCollector())
	b := writeAdminFile(t, nc, "admin-request-expired.json", authz.KindCredentialRevoke,
		signAdmin(t, authz.KindCredentialRevoke, func(p *authz.AdminRequest) {
			then := time.Now().UTC().Add(-20 * time.Minute).Truncate(time.Second)
			p.IssuedAt, p.ExpiresAt = then.Format(time.RFC3339), then.Add(10*time.Minute).Format(time.RFC3339)
		}))
	s.relayAdmin(bg)
	if recs := relayRecords(t, s, b); len(recs) != 2 || !strings.Contains(recs[1].Detail, "check window") {
		t.Fatalf("records %+v", recs)
	}
	alarm := false
	for _, a := range st.Snapshot("x").Alarms {
		alarm = alarm || (a.Code == AlarmAdminRequestRefused && strings.Contains(a.Detail, "may already have been applied"))
	}
	if !alarm {
		t.Fatal("the window alarm does not say the request may already have been applied")
	}
}

// adminAlarm is the detail of the one alarm with code, or "" if there is
// not exactly one.
func adminAlarm(st *Status, code string) string {
	var out []string
	for _, a := range st.Snapshot("x").Alarms {
		if a.Code == code {
			out = append(out, a.Detail)
		}
	}
	if len(out) != 1 {
		return ""
	}
	return out[0]
}

// signNonce signs a credential.revoke whose nonce is i: files that differ
// only in it are different requests.
func signNonce(t *testing.T, i int) *authz.AdminSigned {
	return signAdmin(t, authz.KindCredentialRevoke, func(p *authz.AdminRequest) {
		n := make([]byte, authz.AdminNonceLen)
		copy(n, fmt.Sprintf("%d-%s", i, t.Name()))
		p.Nonce = base64.RawURLEncoding.EncodeToString(n)
	})
}

// Only a decided collector.request record for an admin request marks a
// file decided: no other action, outcome or correlation ID does, so an
// unrelated record never stops a file from being sent (A6 on #189, N1
// and N3).
func TestRelayFoldsOnlyItsDecisions(t *testing.T) {
	const id = "admin-0123456789abcdef"
	for name, rec := range map[string]*audit.Record{
		"action":  {Action: audit.ActionPolicyApply, Outcome: audit.OutcomeAllowed, CorrelationID: id},
		"outcome": {Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeInfo, CorrelationID: id},
		"run":     {Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeAllowed, CorrelationID: "run-0123456789abcdef"},
	} {
		m := map[string]relayEntry{}
		if applyRelay(m, rec) || len(m) != 0 {
			t.Errorf("%s: folded %+v", name, m)
		}
	}
	m := map[string]relayEntry{}
	if !applyRelay(m, &audit.Record{Action: audit.ActionCollectorRequest, Outcome: audit.OutcomeDenied, CorrelationID: id,
		ReasonCode: string(authz.RefuseAdminUnverified), CollectorSeq: 7}) || m[id].CollectorSeq != 7 || m[id].Outcome != audit.OutcomeDenied {
		t.Fatalf("a denied admin request not folded: %+v", m)
	}

	// Through the scheduler: an unrelated record carrying the file's ID
	// leaves it to be sent.
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	b := writeAdminFile(t, nc, "admin-request-other.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	sum := sha256.Sum256(b)
	other, err := json.Marshal(audit.Record{Contract: audit.ContractID, NodeID: "site-a-node1", Time: s.rt.received(),
		Actor:  audit.Actor{Type: authz.PrincipalNode, ID: "site-a-node1"},
		Action: audit.ActionPolicyApply, Outcome: audit.OutcomeAllowed, PolicyVersion: c.PolicyVersion,
		CorrelationID: adminRequestID(hex.EncodeToString(sum[:])), Detail: "not a decision of this request"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.ValidatePending(other); err != nil {
		t.Fatal(err)
	}
	s.appendAudit(bg, "", []c5.Record{{Stream: AuditStream, Class: c5.ClassAudit, Event: other}})
	s.settle(bg)
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 1 {
		t.Fatalf("%d requests: an unrelated record marked the file decided", n)
	}
}

// A refusal the collector did not number is no decision: nothing is
// recorded as decided, the no-decision alarm is raised, and the file is
// sent again on the next tick (A6 on #189, N18).
func TestRelayRefusalWithoutSeqRetried(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	col.edit = func(rep *authz.CollectorReply) {
		rep.Status, rep.CollectorSeq = authz.ReplyRefused, 0
		rep.Refusal = &authz.Refusal{Code: authz.RefuseStateUnavailable}
	}
	s := newScheduler(t, r, col)
	b := writeAdminFile(t, nc, "admin-request-noseq.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg)
	if d := adminAlarm(st, AlarmAdminRequestNoDecision); !strings.Contains(d, "without collector_seq") {
		t.Fatalf("no-decision alarm %q", d)
	}
	if got := adminShown(st); len(got) != 1 || got[0].State != "waiting" {
		t.Fatalf("status %+v", got)
	}
	if _, done := s.decided(relayRecords(t, s, b)[0].CorrelationID); done {
		t.Fatal("recorded as decided")
	}
	// A collector that could not flush its state has not spent the nonce.
	col.mu.Lock()
	col.edit, col.spent = nil, map[string]bool{}
	col.mu.Unlock()
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 2 {
		t.Fatalf("%d requests, want the refusal without a number and one more", n)
	}
	if recs := relayRecords(t, s, b); len(recs) != 3 || recs[2].Outcome != audit.OutcomeAllowed {
		t.Fatalf("records %+v", recs)
	}
}

// A refusal check the node does not know is shown as unknown, never as
// the collector wrote it (A6 on #189, N21).
func TestRelayUnknownCheckNotEchoed(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	const made = "made-up-check"
	col.edit = func(rep *authz.CollectorReply) {
		rep.Status = authz.ReplyRefused
		rep.Refusal = &authz.Refusal{Code: authz.RefuseAdminUnverified, Check: made}
	}
	s := newScheduler(t, r, col)
	b := writeAdminFile(t, nc, "admin-request-check.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg)
	d := adminAlarm(st, AlarmAdminRequestRefused)
	if !strings.Contains(d, "check unknown") || strings.Contains(d, made) {
		t.Fatalf("refused alarm %q", d)
	}
	recs := relayRecords(t, s, b)
	if len(recs) != 2 || recs[1].Outcome != audit.OutcomeDenied || !strings.Contains(recs[1].Detail, "check unknown") ||
		strings.Contains(recs[1].Detail, made) {
		t.Fatalf("records %+v", recs)
	}
}

// Sixteen files are all read; a seventeenth is not, and says so (A6 on
// #189, N24).
func TestRelayFileCapBoundary(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	// The design's cap, as a literal: a change to the constant fails here.
	const fileCap = 16
	if MaxAdminRequestFiles != fileCap {
		t.Fatalf("MaxAdminRequestFiles is %d, the design says %d", MaxAdminRequestFiles, fileCap)
	}
	for i := 0; i < fileCap; i++ {
		writeAdminFile(t, nc, fmt.Sprintf("admin-request-cap-%02d.json", i), authz.KindCredentialRevoke, signNonce(t, i))
	}
	s.relayAdmin(bg)
	if n := len(col.requests()); n != fileCap || countAlarms(st, AlarmAdminRequestUnread) != 0 {
		t.Fatalf("%d files: %d requests, %d unread alarms", fileCap, n, countAlarms(st, AlarmAdminRequestUnread))
	}
	writeAdminFile(t, nc, "admin-request-cap-zz.json", authz.KindCredentialRevoke, signNonce(t, fileCap))
	s.relayAdmin(bg)
	if n := len(col.requests()); n != fileCap {
		t.Fatalf("the file past the fileCap was sent: %d requests", n)
	}
	if d := adminAlarm(st, AlarmAdminRequestUnread); !strings.Contains(d, fmt.Sprintf("holds %d", fileCap+1)) {
		t.Fatalf("unread alarm %q", d)
	}
}

// A signed payload over authz.MaxAdminPayload is refused at the node,
// although the file is under its own cap: the collector would refuse it
// too, and the node does not send it (A6 on #189, N27).
func TestRelayPayloadCap(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	env := signAdmin(t, authz.KindCredentialRevoke, nil)
	// Valid JSON, padded with trailing spaces to one byte over the cap.
	env.Payload = append(env.Payload, []byte(strings.Repeat(" ", authz.MaxAdminPayload+1-len(env.Payload)))...)
	b := writeAdminFile(t, nc, "admin-request-big.json", authz.KindCredentialRevoke, env)
	if int64(len(b)) > MaxAdminRequestFileBytes {
		t.Fatalf("the file is %d bytes, over the file cap %d: not the boundary under test", len(b), MaxAdminRequestFileBytes)
	}
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 0 {
		t.Fatalf("%d requests", n)
	}
	if got := adminShown(st); len(got) != 1 || got[0].State != "unread" || !strings.Contains(got[0].Detail, "bytes") {
		t.Fatalf("status %+v", got)
	}
}

// A misnamed file makes the scan incomplete, so a decided file renamed to
// a name that is not read is not forgotten: renamed back, it is not sent
// again (A6 on #189, N9).
func TestRelayMisnamedKeepsDecided(t *testing.T) {
	c, dir, nc := suspendConfig(t)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, col)
	const name, misnamed = "admin-request-keep.json", "admin-request-Keep.json"
	b := writeAdminFile(t, nc, name, authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	s.relayAdmin(bg)
	removeAdminFile(t, nc, name)
	writeAdminBytes(t, nc, misnamed, b)
	s.relayAdmin(bg)
	removeAdminFile(t, nc, misnamed)
	writeAdminBytes(t, nc, name, b)
	s.relayAdmin(bg)
	if n := len(col.requests()); n != 1 {
		t.Fatalf("%d requests: the decided file was forgotten during an incomplete scan", n)
	}
}

// hangCollector takes every admin-signed request and never answers, until
// the request's context ends.
type hangCollector struct{ *adminCollector }

func (h hangCollector) Do(ctx context.Context, req *authz.CollectorRequest) (collectorclient.Response, error) {
	if req.Kind == authz.KindRun {
		return h.adminCollector.Do(ctx, req)
	}
	h.mu.Lock()
	h.sent = append(h.sent, req)
	h.mu.Unlock()
	began := time.Now()
	<-ctx.Done()
	h.mu.Lock()
	h.held += time.Since(began)
	h.mu.Unlock()
	return collectorclient.Response{}, ctx.Err()
}

// A collector that never answers holds the relay for RelayTimeout and no
// longer: the request is left undecided, the no-decision alarm is raised,
// and it is sent again on the next tick (A6 on #189).
func TestRelayTimeout(t *testing.T) {
	defer func(d time.Duration) { RelayTimeout = d }(RelayTimeout)
	RelayTimeout = 100 * time.Millisecond
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, hangCollector{col})
	b := writeAdminFile(t, nc, "admin-request-hang.json", authz.KindCredentialRevoke, signAdmin(t, authz.KindCredentialRevoke, nil))
	began := time.Now()
	s.relayAdmin(bg)
	if d := time.Since(began); d > 10*time.Second {
		t.Fatalf("the relay was held %s", d)
	}
	if countAlarms(st, AlarmAdminRequestNoDecision) != 1 {
		t.Fatal("no-decision alarm not raised")
	}
	if got := adminShown(st); len(got) != 1 || got[0].State != "waiting" {
		t.Fatalf("status %+v", got)
	}
	s2 := newScheduler(t, r, col)
	s2.relayAdmin(bg)
	if n := len(col.requests()); n != 2 {
		t.Fatalf("%d requests, want the cut-off one and one more", n)
	}
	if recs := relayRecords(t, s2, b); len(recs) != 3 || recs[2].Outcome != audit.OutcomeAllowed {
		t.Fatalf("records %+v", recs)
	}
}

// A collector that never answers holds one tick for one RelayTimeout, not
// one per file: after the first unanswered request the rest wait for the
// next tick, and status says why (A3 on #197).
func TestRelayStopsAtFirstUnanswered(t *testing.T) {
	defer func(d time.Duration) { RelayTimeout = d }(RelayTimeout)
	RelayTimeout = 300 * time.Millisecond
	c, dir, nc := suspendConfig(t)
	r, st, _ := start(t, c, dir)
	defer r.Close()
	col := newAdminCollector()
	s := newScheduler(t, r, hangCollector{col})
	for i := range 3 {
		writeAdminFile(t, nc, fmt.Sprintf("admin-request-stall-%d.json", i), authz.KindCredentialRevoke, signNonce(t, i))
	}
	began := time.Now()
	s.relayAdmin(bg)
	tick := time.Since(began)
	if n := len(col.requests()); n != 1 {
		t.Fatalf("%d requests sent in the tick, want 1", n)
	}
	// The bound is on the time the collector held the tick, not on the
	// tick: the rest is the node's own audit commits and status writes,
	// about 30 ms alone on a Windows runner but over a RelayTimeout while
	// the rest of go test ./... runs beside it (A1 on #197). One request
	// held for one RelayTimeout is what is claimed.
	col.mu.Lock()
	held := col.held
	col.mu.Unlock()
	t.Logf("tick %s: held by the collector %s, the node's own work %s", tick, held, tick-held)
	if held < RelayTimeout || held >= 2*RelayTimeout {
		t.Fatalf("the collector held the tick for %s, want one RelayTimeout (%s)", held, RelayTimeout)
	}
	got := adminShown(st)
	if len(got) != 3 {
		t.Fatalf("status %+v", got)
	}
	for i, a := range got {
		if a.State != "waiting" || (i > 0 && !strings.Contains(a.Detail, "did not answer admin-request-stall-0.json")) {
			t.Fatalf("status %d: %+v", i, a)
		}
	}
	if countAlarms(st, AlarmAdminRequestNoDecision) != 1 {
		t.Fatal("no-decision alarm not raised once")
	}
	// The collector answers again: the next tick sends all three.
	s2 := newScheduler(t, r, col)
	s2.relayAdmin(bg)
	if n := len(col.requests()); n != 4 {
		t.Fatalf("%d requests after the collector answered, want 1 + 3", n)
	}
}

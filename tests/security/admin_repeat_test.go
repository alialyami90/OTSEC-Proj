package security

// C7 0.5 on the collector (#186): the same signed bytes sent again, while
// their nonce is held, get the repeat answer and run nothing. A6's own
// pipeline and files, built only through the collector's exported API, and
// its own administrator key (a test key, D2-5). Ground truth is the C7 0.5
// rule (A1 on #184): a repeat is accepted only for the exact payload that
// was accepted, takes a fresh collector_seq, names the first decision, and
// never acts twice; anything else with a spent nonce is a replay. The
// cases here are the ones A3's suite does not cover: sends that race,
// a crash between the action and its record, a key revoked in between,
// a 0.4 resend, other bytes for the same meaning, a full nonce table, a
// clock put back after the nonce was dropped, and a hand-edited state
// file. Class: simulated.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/security/collector"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/modules/security/seal"
)

// rptSecret is a test value (D2-5), never a device password. It must not
// appear in any reply, alarm or file but the sealed store.
var rptSecret = []byte("A6-Rpt-4kQz")

var rptAdmin = authz.Principal{Type: authz.PrincipalHuman, ID: "a6-admin@site-a"}

var rptPriv = func() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("otsec a6 repeat test admin key"))
	return ed25519.NewKeyFromSeed(seed[:])
}()

func rptKey(status authz.KeyStatus) authz.AdminKey {
	pub := rptPriv.Public().(ed25519.PublicKey)
	return authz.AdminKey{KeyID: authz.AdminKeyID(pub), PublicKey: pub, Principal: rptAdmin.ID, Status: status}
}

const rptRef = "cred_a6repeat01"

// rptRig is a collector over files in one directory, which restart opens
// again from those files alone.
type rptRig struct {
	dir     string
	clock   *a6Clock
	anchor  authz.TrustAnchor
	env     []byte
	asset   collector.Enrolled
	pipe    *collector.Pipeline
	state   *collector.State
	creds   *collector.CredStore
	alarmMu sync.Mutex
	alarms  []error
	// hook, if set, is called with each alarm after it is kept. Set it
	// only while no request is in flight.
	hook func(error)
}

func newRptRig(t *testing.T) *rptRig {
	t.Helper()
	r := &rptRig{dir: t.TempDir(), clock: &a6Clock{time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}}
	if err := collector.InitState(r.statePath(), r.clock.t.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(readLockFixture(t, "sel-751-simulated.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := asset.DecodeProfile(readLockFixture(t, "profile-sel-751-ascii.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.asset = collector.Enrolled{Asset: a, Profile: p}
	if err := collector.InitCredStore(r.credPath(), string(a.NodeID), r.clock.now); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("otsec a6 repeat test release key"))
	rel := ed25519.NewKeyFromSeed(seed[:])
	r.anchor = authz.TrustAnchor{KeyID: "a6-release", PublicKey: rel.Public().(ed25519.PublicKey), Status: authz.KeyActive}
	payload := readLockFixture(t, "register-sel-751.json")
	if r.env, err = json.Marshal(register.Envelope{Contract: register.ContractID, Algorithm: "ed25519", KeyID: "a6-release",
		Payload: payload, Signature: ed25519.Sign(rel, authz.RegisterSigningInput(payload))}); err != nil {
		t.Fatal(err)
	}
	r.open(t, rptKey(authz.KeyActive), true)
	return r
}

func (r *rptRig) statePath() string { return filepath.Join(r.dir, "state.json") }
func (r *rptRig) credPath() string  { return filepath.Join(r.dir, "credentials.json") }

// open builds the pipeline from the files, pinning keys; activate also
// activates the register, which only the first open needs.
func (r *rptRig) open(t *testing.T, key authz.AdminKey, activate bool) {
	t.Helper()
	st, err := collector.OpenState(r.statePath(), r.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	node := string(r.asset.Asset.NodeID)
	creds, err := collector.OpenCredStore(r.credPath(), collector.CredStoreConfig{NodeID: node, Now: r.clock.now, Generations: st})
	if err != nil {
		t.Fatal(err)
	}
	regs := collector.NewRegisters(st, []authz.TrustAnchor{r.anchor})
	if activate {
		if _, err := regs.Activate(r.env); err != nil {
			t.Fatalf("activate the register: %v", err)
		}
	}
	pipe, err := collector.NewPipeline(collector.PipelineConfig{
		NodeID: node, PolicyVersion: 3,
		Assets: []collector.Enrolled{r.asset},
		State:  st, Creds: creds, Registers: regs, Runner: &dialRunner{},
		AdminKeys: []authz.AdminKey{key}, Now: r.clock.now,
		Alarm: func(err error) {
			r.alarmMu.Lock()
			r.alarms = append(r.alarms, err)
			r.alarmMu.Unlock()
			if r.hook != nil {
				r.hook(err)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.pipe, r.state, r.creds = pipe, st, creds
}

// restart is a new process over the same files.
func (r *rptRig) restart(t *testing.T, key authz.AdminKey) {
	t.Helper()
	r.open(t, key, false)
}

func (r *rptRig) ref() authz.CredentialRef {
	return authz.CredentialRef{
		ID: rptRef, AssetID: lockAsset, NodeID: string(r.asset.Asset.NodeID), EndpointID: "port1-telnet",
		Transport: authz.TransportTelnet, Purpose: authz.PurposeCollectReadOnly, AccessLevel: "1",
		DownstreamSecurity: authz.DownstreamPlaintext, PlaintextScope: authz.PlaintextLabOnly,
		Version: 1, CreatedBy: rptAdmin, CreatedAt: "2026-10-26T08:00:00Z",
	}
}

// payload is what the administrator signs for kind now, with a fresh
// nonce and ten minutes to live.
func (r *rptRig) payload(t *testing.T, kind authz.RequestKind) authz.AdminRequest {
	t.Helper()
	now := r.clock.now()
	p := authz.AdminRequest{
		Format: authz.AdminRequestFormat, Kind: kind, Principal: rptAdmin,
		AdminKeyID: rptKey(authz.KeyActive).KeyID, NodeID: string(r.asset.Asset.NodeID), InstallKeyID: r.creds.InstallKey().KeyID,
		Nonce:    a6NewNonce(t),
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339),
	}
	switch kind {
	case authz.KindCredentialInstall:
		ref := r.ref()
		sealed, err := seal.Seal(r.creds.InstallKey(), r.creds.Fingerprint(), ref, rptSecret, nil)
		if err != nil {
			t.Fatal(err)
		}
		p.CredentialInstall = &authz.CredentialInstallBody{Ref: ref, Sealed: sealed}
	case authz.KindCredentialRevoke:
		p.CredentialRevoke = &authz.CredentialRevokeBody{RefID: rptRef, Reason: authz.RevokeOperator}
	case authz.KindNodeSeqResetAck:
		p.NodeSeqResetAck = &authz.NodeSeqResetAckBody{}
	default:
		t.Fatalf("no payload for %s", kind)
	}
	return p
}

// request carries env stamped contract.
func rptRequest(kind authz.RequestKind, env *authz.AdminSigned, contract, id string) *authz.CollectorRequest {
	return &authz.CollectorRequest{Contract: contract, Kind: kind, RequestID: id,
		OnBehalfOf: rptAdmin, PolicyVersion: 3, AdminSigned: env}
}

func (r *rptRig) signed(t *testing.T, kind authz.RequestKind) *authz.CollectorRequest {
	t.Helper()
	env, err := authz.SignAdminRequest(rptPriv, r.payload(t, kind))
	if err != nil {
		t.Fatal(err)
	}
	return rptRequest(kind, env, authz.ContractID, "a6-"+string(kind))
}

func (r *rptRig) handle(req *authz.CollectorRequest) authz.CollectorReply {
	reply, _ := r.pipe.Handle(context.Background(), req)
	return reply
}

// stateDoc is state.json as a generic document, for counting and editing.
func (r *rptRig) stateDoc(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(r.statePath())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func (r *rptRig) writeStateDoc(t *testing.T, doc map[string]json.RawMessage) {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.statePath(), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *rptRig) installs(t *testing.T) int {
	t.Helper()
	var ts []string
	if raw, ok := r.stateDoc(t)["installs"]; ok {
		if err := json.Unmarshal(raw, &ts); err != nil {
			t.Fatal(err)
		}
	}
	return len(ts)
}

func (r *rptRig) decisions(t *testing.T) map[string]struct {
	PayloadSHA256 string `json:"payload_sha256"`
	CollectorSeq  uint64 `json:"collector_seq"`
} {
	t.Helper()
	out := map[string]struct {
		PayloadSHA256 string `json:"payload_sha256"`
		CollectorSeq  uint64 `json:"collector_seq"`
	}{}
	if raw, ok := r.stateDoc(t)["admin_decisions"]; ok {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func (r *rptRig) credBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(r.credPath())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (r *rptRig) versions() int { return len(r.creds.Status(rptRef)) }

func rptCheck(reply authz.CollectorReply) authz.AdminCheck {
	if reply.Refusal == nil {
		return ""
	}
	return reply.Refusal.Check
}

func rptWantRefused(t *testing.T, name string, reply authz.CollectorReply, check authz.AdminCheck) {
	t.Helper()
	if reply.Accepted() || rptCheck(reply) != check || reply.RepeatOf != 0 || reply.Admin != nil {
		t.Fatalf("%s: %+v, want refused for %s", name, reply, check)
	}
}

// rptWantRepeat checks reply is the repeat of first: accepted, its own
// number above last, naming first, with first's admin acceptance, and
// valid on the wire.
func rptWantRepeat(t *testing.T, name string, req *authz.CollectorRequest, reply, first authz.CollectorReply, last uint64) {
	t.Helper()
	if !reply.Accepted() || reply.RepeatOf != first.CollectorSeq || reply.CollectorSeq <= last || reply.RequestID != req.RequestID {
		t.Fatalf("%s: %+v, want a repeat of %d above %d", name, reply, first.CollectorSeq, last)
	}
	got, err := reply.AdminAcceptance(req)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	sent := *req
	sent.RequestID = first.RequestID // the first send's request_id
	if want, _ := first.AdminAcceptance(&sent); want == nil || *got != *want {
		t.Fatalf("%s: names %+v, first named %+v", name, got, want)
	}
	b, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collectorwire.DecodeReply(b); err != nil {
		t.Fatalf("%s: the repeat reply is not a valid reply on the wire: %v", name, err)
	}
}

// noSecret: the test secret is in no reply, no alarm and no file but the
// sealed store, where it is sealed and so also absent as plain bytes.
func (r *rptRig) noSecret(t *testing.T, replies ...authz.CollectorReply) {
	t.Helper()
	for i, reply := range replies {
		b, _ := json.Marshal(reply)
		if bytes.Contains(b, rptSecret) {
			t.Fatalf("reply %d holds the secret", i)
		}
	}
	r.alarmMu.Lock()
	defer r.alarmMu.Unlock()
	for _, a := range r.alarms {
		if bytes.Contains([]byte(a.Error()), rptSecret) {
			t.Fatal("an alarm holds the secret")
		}
	}
	for _, p := range []string{r.statePath(), r.credPath()} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, rptSecret) {
			t.Fatalf("%s holds the secret in the clear", filepath.Base(p))
		}
	}
}

// The control: an install, then the same bytes under another request_id
// and after a restart, are repeats, and nothing is installed twice.
func TestRepeatA6Control(t *testing.T) {
	r := newRptRig(t)
	req := r.signed(t, authz.KindCredentialInstall)
	first := r.handle(req)
	if !first.Accepted() || first.RepeatOf != 0 || first.Admin == nil {
		t.Fatalf("first: %+v", first)
	}
	installs, creds := r.installs(t), r.credBytes(t)
	if installs != 1 || r.versions() != 1 {
		t.Fatalf("installs %d, versions %d", installs, r.versions())
	}
	again := *req
	again.RequestID = "a6-resend" // outside the signed bytes
	rep := r.handle(&again)
	rptWantRepeat(t, "resend", &again, rep, first, first.CollectorSeq)
	r.restart(t, rptKey(authz.KeyActive))
	rep2 := r.handle(req)
	rptWantRepeat(t, "after a restart", req, rep2, first, rep.CollectorSeq)
	if r.installs(t) != installs || !bytes.Equal(r.credBytes(t), creds) || r.versions() != 1 {
		t.Fatal("a repeat installed again")
	}
	r.noSecret(t, first, rep, rep2)
}

// Sends that race: one signed install sent by many callers at once, as
// the server's per-connection goroutines may. Exactly one decision acts
// and is a first acceptance; every other answer is its repeat or a
// replay, each with its own number; one install is taken. Which answer
// each send gets depends on the scheduler; TestRepeatA6NeverNamesALater
// Decision forces the order this one can only hit by chance.
func TestRepeatA6ConcurrentSends(t *testing.T) {
	for _, kind := range []authz.RequestKind{authz.KindCredentialInstall, authz.KindNodeSeqResetAck} {
		t.Run(string(kind), func(t *testing.T) {
			r := newRptRig(t)
			req := r.signed(t, kind)
			const n = 24
			replies := make([]authz.CollectorReply, n)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := range replies {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					replies[i] = r.handle(req)
				}(i)
			}
			close(start)
			wg.Wait()
			var firsts []authz.CollectorReply
			seqs := map[uint64]bool{}
			for _, reply := range replies {
				if seqs[reply.CollectorSeq] || reply.CollectorSeq == 0 {
					t.Fatalf("collector_seq %d handed out twice or not at all", reply.CollectorSeq)
				}
				seqs[reply.CollectorSeq] = true
				if reply.Accepted() && reply.RepeatOf == 0 {
					firsts = append(firsts, reply)
				}
			}
			if len(firsts) != 1 {
				t.Fatalf("%d first acceptances of one signed request, want 1: %+v", len(firsts), firsts)
			}
			first := firsts[0]
			for i, reply := range replies {
				switch {
				case reply.CollectorSeq == first.CollectorSeq:
				case reply.Accepted():
					rptWantRepeat(t, fmt.Sprintf("reply %d", i), req, reply, first, first.CollectorSeq)
				default:
					// Sent between the spend and the record: the safe answer.
					rptWantRefused(t, fmt.Sprintf("reply %d", i), reply, authz.AdminCheckReplay)
				}
			}
			if kind == authz.KindCredentialInstall && (r.installs(t) != 1 || r.versions() != 1) {
				t.Fatalf("installs %d, versions %d after a race of one request", r.installs(t), r.versions())
			}
			// Once the race is over, the next send is a repeat.
			var last uint64
			for s := range seqs {
				last = max(last, s)
			}
			rptWantRepeat(t, "after the race", req, r.handle(req), first, last)
			r.noSecret(t, replies...)
		})
	}
}

// A crash after the install acted and before its decision was recorded
// leaves the nonce spent and no decision. After the restart the resend
// must be a replay, not a repeat and not a second install.
func TestRepeatA6CrashBeforeTheRecord(t *testing.T) {
	r := newRptRig(t)
	req := r.signed(t, authz.KindCredentialInstall)
	if first := r.handle(req); !first.Accepted() {
		t.Fatalf("first: %+v", first)
	}
	if len(r.decisions(t)) != 1 {
		t.Fatalf("decisions %v", r.decisions(t))
	}
	doc := r.stateDoc(t)
	delete(doc, "admin_decisions")
	r.writeStateDoc(t, doc)
	installs, creds := r.installs(t), r.credBytes(t)
	r.restart(t, rptKey(authz.KeyActive))
	rptWantRefused(t, "resend after the crash", r.handle(req), authz.AdminCheckReplay)
	if r.installs(t) != installs || !bytes.Equal(r.credBytes(t), creds) {
		t.Fatal("the resend installed again")
	}
	if len(r.decisions(t)) != 0 {
		t.Fatal("a refused resend recorded a decision")
	}
}

// A repeat is checked like a first send: a key revoked, or no longer
// pinned, after the first decision refuses the resend for the key. The
// decision is kept, so the same bytes repeat again once the key is back.
func TestRepeatA6KeyRevokedInBetween(t *testing.T) {
	r := newRptRig(t)
	req := r.signed(t, authz.KindNodeSeqResetAck)
	first := r.handle(req)
	if !first.Accepted() {
		t.Fatalf("first: %+v", first)
	}
	r.restart(t, rptKey(authz.KeyRevoked))
	rptWantRefused(t, "revoked key", r.handle(req), authz.AdminCheckKey)
	other := rptKey(authz.KeyActive)
	other.KeyID = "a6-another-key"
	r.restart(t, other)
	rptWantRefused(t, "key not pinned", r.handle(req), authz.AdminCheckKey)
	r.restart(t, rptKey(authz.KeyActive))
	rep := r.handle(req)
	rptWantRepeat(t, "key active again", req, rep, first, first.CollectorSeq)
}

// The repeat answer is C7 0.5's: the same bytes first accepted at 0.5 and
// resent stamped 0.4 are a replay, as 0.4 has no repeat, and that replay
// does not lose the decision for a 0.5 resend. A replay at 0.4 carries no
// 0.5 field.
func TestRepeatA6ResentAt04(t *testing.T) {
	r := newRptRig(t)
	req := r.signed(t, authz.KindCredentialInstall)
	first := r.handle(req)
	if !first.Accepted() {
		t.Fatalf("first: %+v", first)
	}
	old := *req
	old.Contract = "otsec.authz/0.4"
	reply := r.handle(&old)
	rptWantRefused(t, "resent at 0.4", reply, authz.AdminCheckReplay)
	rptWantRepeat(t, "then at 0.5", req, r.handle(req), first, reply.CollectorSeq)
	if r.installs(t) != 1 || r.versions() != 1 {
		t.Fatal("installed twice")
	}
}

// Only the exact bytes repeat. The same payload, same nonce and same
// meaning, encoded with other whitespace and signed by the same key, is
// not the payload accepted: it must be refused, and nothing acts.
func TestRepeatA6OtherBytesSameMeaning(t *testing.T) {
	r := newRptRig(t)
	p := r.payload(t, authz.KindCredentialInstall)
	env, err := authz.SignAdminRequest(rptPriv, p)
	if err != nil {
		t.Fatal(err)
	}
	req := rptRequest(p.Kind, env, authz.ContractID, "a6-install")
	if first := r.handle(req); !first.Accepted() {
		t.Fatalf("first: %+v", first)
	}
	indented, err := json.MarshalIndent(p, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(indented, env.Payload) {
		t.Fatal("the rig: the indented payload is the same bytes")
	}
	other := &authz.AdminSigned{KeyID: env.KeyID, Algorithm: "ed25519", Payload: indented,
		Signature: ed25519.Sign(rptPriv, authz.AdminSigningInput(p.Kind, indented))}
	reply := r.handle(rptRequest(p.Kind, other, authz.ContractID, "a6-reencoded"))
	if reply.Accepted() {
		t.Fatalf("other bytes with the same nonce accepted: %+v", reply)
	}
	if c := rptCheck(reply); c != authz.AdminCheckReplay && c != authz.AdminCheckPayload {
		t.Fatalf("other bytes with the same nonce: check %q, want replay (or payload, if the encoding is refused)", c)
	}
	if r.installs(t) != 1 || r.versions() != 1 || len(r.decisions(t)) != 1 {
		t.Fatal("the re-encoded request acted or was recorded")
	}
}

// A repeat spends no nonce: with the nonce table full, the same bytes are
// still a repeat, while a new request is refused for capacity.
func TestRepeatA6FullNonceTable(t *testing.T) {
	r := newRptRig(t)
	req := r.signed(t, authz.KindNodeSeqResetAck)
	first := r.handle(req)
	if !first.Accepted() {
		t.Fatalf("first: %+v", first)
	}
	exp := r.clock.t.Add(10 * time.Minute)
	for i := 1; i < collector.MaxAdminNonces; i++ {
		if err := r.state.SpendAdminNonce(a6NewNonce(t), exp); err != nil {
			t.Fatalf("nonce %d: %v", i, err)
		}
	}
	fresh := r.handle(r.signed(t, authz.KindNodeSeqResetAck))
	rptWantRefused(t, "a new request, table full", fresh, authz.AdminCheckCapacity)
	rptWantRepeat(t, "the repeat, table full", req, r.handle(req), first, fresh.CollectorSeq)
}

// The window holds across a dropped decision and a clock put back. After
// the request expired and another nonce was spent, its nonce and decision
// are gone; with the clock then put back inside the request's window, a
// resend must not be a fresh first acceptance (a second install): the
// collector judges admin requests at its admin clock, which never goes
// back. Across a restart too.
func TestRepeatA6DroppedThenClockBack(t *testing.T) {
	r := newRptRig(t)
	start := r.clock.t
	req := r.signed(t, authz.KindCredentialInstall)
	if first := r.handle(req); !first.Accepted() {
		t.Fatalf("first: %+v", first)
	}
	r.clock.t = start.Add(11 * time.Minute)
	if next := r.handle(r.signed(t, authz.KindNodeSeqResetAck)); !next.Accepted() {
		t.Fatalf("next: %+v", next)
	}
	if len(r.decisions(t)) != 1 {
		t.Fatalf("decisions after the first expired: %v", r.decisions(t))
	}
	r.clock.t = start.Add(time.Minute)
	rptWantRefused(t, "clock put back", r.handle(req), authz.AdminCheckWindow)
	r.restart(t, rptKey(authz.KeyActive))
	rptWantRefused(t, "clock put back, after a restart", r.handle(req), authz.AdminCheckWindow)
	if r.installs(t) != 1 || r.versions() != 1 {
		t.Fatal("installed twice")
	}
}

// A hand-edited state file is refused on open when a decision is not one
// the collector could have written; a decision whose hash no longer
// matches is a replay, never a repeat.
func TestRepeatA6EditedState(t *testing.T) {
	r := newRptRig(t)
	req := r.signed(t, authz.KindNodeSeqResetAck)
	first := r.handle(req)
	if !first.Accepted() {
		t.Fatalf("first: %+v", first)
	}
	good := r.stateDoc(t)
	var nonce string
	for n := range r.decisions(t) {
		nonce = n
	}
	hash := r.decisions(t)[nonce].PayloadSHA256
	edit := func(decisions string) map[string]json.RawMessage {
		doc := map[string]json.RawMessage{}
		for k, v := range good {
			doc[k] = v
		}
		doc["admin_decisions"] = json.RawMessage(decisions)
		return doc
	}
	upper := bytes.ToUpper([]byte(hash))
	for name, d := range map[string]string{
		"nonce not held":   fmt.Sprintf(`{%q:{"payload_sha256":%q,"collector_seq":%d}}`, a6NewNonce(t), hash, first.CollectorSeq),
		"upper-case hash":  fmt.Sprintf(`{%q:{"payload_sha256":%q,"collector_seq":%d}}`, nonce, upper, first.CollectorSeq),
		"short hash":       fmt.Sprintf(`{%q:{"payload_sha256":%q,"collector_seq":%d}}`, nonce, hash[:62], first.CollectorSeq),
		"seq zero":         fmt.Sprintf(`{%q:{"payload_sha256":%q,"collector_seq":0}}`, nonce, hash),
		"seq not given":    fmt.Sprintf(`{%q:{"payload_sha256":%q,"collector_seq":%d}}`, nonce, hash, first.CollectorSeq+1),
		"an unknown field": fmt.Sprintf(`{%q:{"payload_sha256":%q,"collector_seq":%d,"x":1}}`, nonce, hash, first.CollectorSeq),
	} {
		r.writeStateDoc(t, edit(d))
		if _, err := collector.OpenState(r.statePath(), r.clock.now); err == nil {
			t.Errorf("%s: the edited state opened", name)
		}
	}
	other := sha256.Sum256([]byte("another payload"))
	r.writeStateDoc(t, edit(fmt.Sprintf(`{%q:{"payload_sha256":"%x","collector_seq":%d}}`, nonce, other, first.CollectorSeq)))
	r.restart(t, rptKey(authz.KeyActive))
	rptWantRefused(t, "hash edited", r.handle(req), authz.AdminCheckReplay)
}

// A repeat never names a later decision than its own number (C7 0.5:
// repeat_of is below collector_seq, and authz.CollectorReply.Validate
// refuses anything else). Two sends of the same signed bytes, ordered so
// that the one numbered first is checked for a repeat only after the one
// numbered second was accepted and recorded. The order is forced, not
// left to the scheduler: with the clock well behind the admin clock every
// admin request raises the clock alarm before its checks, outside the
// state's lock, and the first send is held in that alarm. The rule's
// answer for the held send is a repeat numbered above the first decision,
// or a replay; never a repeat_of at or above its own collector_seq.
func TestRepeatA6NeverNamesALaterDecision(t *testing.T) {
	r := newRptRig(t)
	start := r.clock.t
	req := r.signed(t, authz.KindNodeSeqResetAck) // issued at start, ten minutes to live
	r.clock.t = start.Add(6 * time.Minute)
	if other := r.handle(r.signed(t, authz.KindNodeSeqResetAck)); !other.Accepted() {
		t.Fatalf("other: %+v", other)
	}
	r.clock.t = start // more than MaxAdminClockSkew behind the admin clock, so each admin request alarms

	held, release := make(chan struct{}), make(chan struct{})
	var holding atomic.Bool
	alarm := func(error) {
		if holding.CompareAndSwap(false, true) { // the first send only
			close(held)
			<-release
		}
	}
	r.hook = alarm

	var late authz.CollectorReply
	done := make(chan struct{})
	go func() { defer close(done); late = r.handle(req) }()
	<-held
	first := r.handle(req)
	close(release)
	<-done
	if !first.Accepted() || first.RepeatOf != 0 || late.CollectorSeq >= first.CollectorSeq {
		t.Fatalf("the rig: first %+v, held %+v", first, late)
	}
	b, err := json.Marshal(late)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collectorwire.DecodeReply(b); err != nil {
		t.Fatalf("the held send's reply is not a valid C7 reply: %v\nreply %s\nfirst decision collector_seq %d", err, b, first.CollectorSeq)
	}
	if late.Accepted() {
		rptWantRepeat(t, "held send", req, late, first, 0)
	} else {
		rptWantRefused(t, "held send", late, authz.AdminCheckReplay)
	}
}

// Only an acceptance at 0.5 is kept for a repeat. A request the collector
// refused after its checks (a revoke of a credential it does not hold),
// and an install first accepted stamped 0.4, are replays when resent at
// 0.5, and neither leaves a decision in the state.
func TestRepeatA6OnlyA05AcceptanceIsKept(t *testing.T) {
	r := newRptRig(t)
	revoke := r.signed(t, authz.KindCredentialRevoke)
	if first := r.handle(revoke); first.Accepted() || first.Refusal == nil || first.Refusal.Check != "" {
		t.Fatalf("revoke of a credential not held: %+v", first)
	}
	rptWantRefused(t, "refused, then resent", r.handle(revoke), authz.AdminCheckReplay)

	install := r.signed(t, authz.KindCredentialInstall)
	old := *install
	old.Contract = "otsec.authz/0.4"
	if first := r.handle(&old); !first.Accepted() || first.Admin != nil || first.RepeatOf != 0 {
		t.Fatalf("install at 0.4: %+v", first)
	}
	rptWantRefused(t, "accepted at 0.4, resent at 0.5", r.handle(install), authz.AdminCheckReplay)
	if d := r.decisions(t); len(d) != 0 {
		t.Fatalf("decisions kept: %v", d)
	}
	if r.installs(t) != 1 || r.versions() != 1 {
		t.Fatal("installed twice")
	}
}

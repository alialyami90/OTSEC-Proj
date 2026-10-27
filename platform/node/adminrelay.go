package node

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorwire"
	"otsec.local/otsec/platform/store/protect"
)

// The node relays an administrator's signed requests to the collector
// (docs/phase3/A5-signed-admin-files.md). It holds no admin key and
// verifies no signature: the collector does, spends the nonce and numbers
// its decision. An administrator's signing client leaves each request in
// admin_dir as admin-request-<name>.json; the node sends it unchanged, on
// behalf of the person the payload names, and records the decision. PR 1
// relays the three credential kinds only: their collector part is the whole
// operation, so the node acts on nothing after the reply.
//
// Which files were decided is read from the audit stream, like the
// suspensions: a collector.request allowed or denied record whose request
// ID has adminRequestPrefix closes the file whose bytes hash to it. The
// suspension checkpoint keeps the set (admin_relayed), so a crash between
// the reply record and the checkpoint sends nothing again: the fold finds
// the record first.
const (
	// AdminRequestFileSchema is the schema of an admin-request file:
	// {"schema", "kind": the C7 kind, "signed": the authz.AdminSigned
	// envelope as the administrator's client made it}.
	AdminRequestFileSchema = "otsec.admin-request-file/0.1"
	// MaxAdminRequestFiles is how many admin-request files a tick reads,
	// in name order. More raise AlarmAdminRequestUnread; an administrator
	// removes relayed files when convenient.
	MaxAdminRequestFiles = 16
	// RelayEverySeconds is how often the node looks for admin-request
	// files between runs. A signed request lives at most 15 minutes
	// (authz.MaxAdminLifetime), so a relay cannot wait for the next run.
	RelayEverySeconds = 15

	// AlarmAdminRequestRefused: the collector refused a relayed request.
	// It is not sent again; the administrator signs a new one.
	AlarmAdminRequestRefused = "admin-request-refused"
	// AlarmAdminRequestUnread: an admin-request file, or admin_dir, was
	// refused by the protected-file rule or the decoder, or there are
	// more than MaxAdminRequestFiles. The alarm says why, never what the
	// file holds.
	AlarmAdminRequestUnread = "admin-request-unread"
	// AlarmAdminRequestNoDecision: a relayed request got no decision (no
	// reply, or a refusal the collector did not number). It is sent again
	// each tick until it is decided or expires.
	AlarmAdminRequestNoDecision = "admin-request-no-decision"

	adminRequestPrefix = "admin-"
)

// MaxAdminRequestFileBytes caps an admin-request file before it is
// decoded: the largest payload base64-encoded, and 1 KiB for the rest of
// the envelope.
var MaxAdminRequestFileBytes = int64(base64.StdEncoding.EncodedLen(authz.MaxAdminPayload) + 1<<10)

var (
	adminRequestName = regexp.MustCompile(`^admin-request-[a-z0-9-]{1,64}\.json$`)
	// The payload's claims are recorded only once they pass these, the
	// patterns VerifyAdminRequest applies (A3 on #181).
	adminKeyIDClaim = regexp.MustCompile(`^ed25519-[0-9a-f]{16}$`)
	adminNonceClaim = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

// relayKinds are the kinds this node relays.
var relayKinds = map[authz.RequestKind]bool{
	authz.KindCredentialInstall: true, authz.KindCredentialRevoke: true, authz.KindCredentialClearSusp: true,
}

// adminRequestFile is an admin-request file as the client writes it.
type adminRequestFile struct {
	Schema string             `json:"schema"`
	Kind   authz.RequestKind  `json:"kind"`
	Signed *authz.AdminSigned `json:"signed"`
}

// adminClaims are what the payload says, read before the collector has
// verified anything: only to address the request (on_behalf_of) and to
// record it. No body is decoded.
type adminClaims struct {
	Kind       authz.RequestKind `json:"kind"`
	Principal  authz.Principal   `json:"principal"`
	AdminKeyID string            `json:"admin_key_id"`
	Nonce      string            `json:"nonce"`
	ExpiresAt  string            `json:"expires_at"`
}

// relayEntry is the collector's decision on one relayed request, as the
// audit stream holds it.
type relayEntry struct {
	Outcome      audit.Outcome `json:"outcome"` // allowed or denied
	Reason       string        `json:"reason,omitempty"`
	CollectorSeq uint64        `json:"collector_seq"`
}

// AdminRequestStatus is one admin-request file as node status shows it.
type AdminRequestStatus struct {
	File      string `json:"file"`
	RequestID string `json:"request_id,omitempty"`
	Kind      string `json:"kind,omitempty"`
	// State is accepted, refused, waiting (not yet decided) or unread.
	State        string `json:"state"`
	Detail       string `json:"detail,omitempty"`
	CollectorSeq uint64 `json:"collector_seq,omitempty"`
}

// adminFile is one admin-request file read this tick.
type adminFile struct {
	name   string
	sum    string // SHA-256 of the file's bytes, lowercase hex
	id     string // the request ID: adminRequestPrefix and 16 hex digits of sum
	kind   authz.RequestKind
	signed *authz.AdminSigned
	claims adminClaims
}

// adminRequestID is the request ID of the file whose bytes hash to sum.
func adminRequestID(sum string) string { return adminRequestPrefix + sum[:16] }

// applyRelay applies one audit record to the decided set m, request ID to
// decision. It returns true when the record decides a relayed request.
func applyRelay(m map[string]relayEntry, rec *audit.Record) bool {
	if rec.Action != audit.ActionCollectorRequest || (rec.Outcome != audit.OutcomeAllowed && rec.Outcome != audit.OutcomeDenied) ||
		!strings.HasPrefix(rec.CorrelationID, adminRequestPrefix) {
		return false
	}
	m[rec.CorrelationID] = relayEntry{Outcome: rec.Outcome, Reason: rec.ReasonCode, CollectorSeq: rec.CollectorSeq}
	return true
}

// relayAdmin relays every admin-request file in admin_dir that the audit
// stream does not show as decided. Nothing is sent while collectorHold
// holds requests. It is called between runs and before each run, never
// during one.
func (s *Scheduler) relayAdmin(ctx context.Context) {
	if s.rt.cfg.AdminDir == "" {
		return
	}
	files, shown, complete := s.scanAdmin()
	seen := map[string]bool{}
	var todo []*adminFile
	for _, f := range files {
		seen[f.id] = true
		if _, done := s.decided(f.id); !done {
			todo = append(todo, f)
		}
	}
	if len(todo) > 0 {
		s.reload(ctx)
		if code, detail := s.collectorHold(ctx); code != "" {
			// collectorHold folded the stream if it could, so a decided
			// file still shows as decided below.
			s.raiseOnceKey("collector "+code, "", code, detail)
			for i := range shown {
				if shown[i].State == "waiting" {
					shown[i].Detail = "not sent: " + code
				}
			}
			todo = nil
		}
	}
	for i, f := range todo {
		// Decided since the scan, if collectorHold's fold found the
		// decision in the stream (a crash before the checkpoint).
		if _, done := s.decided(f.id); done {
			continue
		}
		if !s.relayOne(ctx, f) {
			// No answer: the rest wait for the next tick, so a collector
			// that never answers holds the scheduler for one RelayTimeout
			// a tick, not one per file (A3 on #197).
			left := map[string]bool{}
			for _, g := range todo[i+1:] {
				left[g.id] = true
			}
			for j := range shown {
				if left[shown[j].RequestID] {
					shown[j].Detail = "not sent this tick: the collector did not answer " + f.name
				}
			}
			break
		}
	}
	for i := range shown {
		if e, done := s.decided(shown[i].RequestID); done {
			shown[i].State, shown[i].Detail, shown[i].CollectorSeq = "refused", e.Reason, e.CollectorSeq
			if e.Outcome == audit.OutcomeAllowed {
				shown[i].State, shown[i].Detail = "accepted", ""
			}
		}
	}
	if complete {
		s.pruneRelayed(seen)
	}
	s.mu.Lock()
	changed := !reflect.DeepEqual(s.adminShown, shown)
	s.adminShown = shown
	s.mu.Unlock()
	if changed {
		s.rt.opt.Status.SetAdminRequests(shown)
		s.rt.opt.Status.Write(string(s.rt.cfg.NodeID))
	}
}

// scanAdmin reads the admin-request files under the protected-file rule.
// It returns the files to relay or to keep as relayed, every file as
// status shows it, and whether the scan saw every file (so that decided
// requests whose file is gone may be forgotten).
func (s *Scheduler) scanAdmin() (files []*adminFile, shown []AdminRequestStatus, complete bool) {
	dir := s.rt.cfg.AdminDir
	if err := protect.CheckDirFor(dir, AdminReaders()); err != nil {
		s.unread("dir "+err.Error(), "admin_dir refused, so no admin-request file is read: "+err.Error())
		return nil, nil, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.unread("list "+err.Error(), "admin_dir could not be listed, so no admin-request file is read: "+err.Error())
		return nil, nil, false
	}
	complete = true
	var names []string
	for _, e := range entries {
		n := e.Name()
		switch {
		case adminRequestName.MatchString(n):
			names = append(names, n)
		case strings.HasPrefix(n, "admin-request-"):
			// Never echoed: a name that fails the pattern is not shown.
			s.unread("name "+digest([]byte(n)), "a file in admin_dir starts with admin-request- but is not named admin-request-<a-z0-9->.json; it is not read")
			complete = false
		}
	}
	if len(names) > MaxAdminRequestFiles {
		s.unread(fmt.Sprintf("count %d", len(names)), fmt.Sprintf("admin_dir holds %d admin-request files; the first %d by name are read. Remove the relayed ones (otsec health)", len(names), MaxAdminRequestFiles))
		names, complete = names[:MaxAdminRequestFiles], false
	}
	for _, n := range names {
		f, why := readAdminFile(filepath.Join(dir, n))
		if f == nil {
			complete = false
			s.unread("file "+n+" "+why, n+" is not relayed: "+why)
			shown = append(shown, AdminRequestStatus{File: n, State: "unread", Detail: why})
			continue
		}
		f.name = n
		files = append(files, f)
		shown = append(shown, AdminRequestStatus{File: n, RequestID: f.id, Kind: string(f.kind), State: "waiting"})
	}
	return files, shown, complete
}

// readAdminFile reads and checks one admin-request file. On a refusal it
// returns nil and why, which never quotes the file.
func readAdminFile(path string) (*adminFile, string) {
	b, err := protect.ReadFileFor(path, MaxAdminRequestFileBytes, AdminReaders())
	if err != nil {
		return nil, "refused by the protected-file rule: " + err.Error()
	}
	sum := sha256.Sum256(b)
	f := &adminFile{sum: hex.EncodeToString(sum[:])}
	f.id = adminRequestID(f.sum)
	var raw adminRequestFile
	// Strict as every admin file (A3 #117): keys exactly as named, no
	// duplicate, nothing after the object.
	if err := collectorwire.DecodeStrict(b, &raw); err != nil || raw.Schema != AdminRequestFileSchema || raw.Signed == nil {
		return nil, "not a " + AdminRequestFileSchema + " object with kind and signed"
	}
	if !relayKinds[raw.Kind] {
		return nil, fmt.Sprintf("kind %q is not relayed by this node", raw.Kind)
	}
	if len(raw.Signed.Payload) == 0 || len(raw.Signed.Payload) > authz.MaxAdminPayload {
		return nil, fmt.Sprintf("signed payload is %d bytes, not 1 to %d", len(raw.Signed.Payload), authz.MaxAdminPayload)
	}
	// Unverified: read only to address and record the request. The
	// collector decodes the payload strictly after the signature.
	var c adminClaims
	if err := json.Unmarshal(raw.Signed.Payload, &c); err != nil {
		return nil, "signed payload is not JSON"
	}
	_, timeErr := time.Parse(time.RFC3339, c.ExpiresAt)
	switch {
	case c.Kind != raw.Kind:
		return nil, "signed kind is not the file's kind"
	case c.Principal.Type != authz.PrincipalHuman || c.Principal.Validate() != nil:
		return nil, "signed principal is not a person"
	case !adminKeyIDClaim.MatchString(c.AdminKeyID) || !adminKeyIDClaim.MatchString(raw.Signed.KeyID):
		return nil, "signed or envelope key ID is malformed"
	case !adminNonceClaim.MatchString(c.Nonce):
		return nil, "signed nonce is malformed"
	case timeErr != nil:
		return nil, "signed expires_at is not RFC 3339"
	}
	f.kind, f.signed, f.claims = raw.Kind, raw.Signed, c
	return f, ""
}

// RelayTimeout bounds one relayed request's exchange with the collector.
// The relay runs in the scheduler's loop, so a collector that takes the
// connection and never answers would otherwise hold the relay and every
// run behind it (A6 on #189). A request cut off is left undecided and sent
// again; if the collector did decide it, the resend gets its repeat
// answer (C7 0.5) when it was accepted, or a replay refusal, which says
// the request may already have been applied, when it was refused.
var RelayTimeout = 30 * time.Second

// relayOne sends one file's request: recorded first, then sent, then the
// decision recorded, as for a run (D1-11). A request with no decision is
// left undecided and sent again next tick. It reports false when the
// collector did not answer (no reply within RelayTimeout, or no
// connection), so the caller sends nothing more this tick.
func (s *Scheduler) relayOne(ctx context.Context, f *adminFile) (answered bool) {
	answered = true
	req := &authz.CollectorRequest{Contract: authz.ContractID, Kind: f.kind, RequestID: f.id,
		OnBehalfOf: f.claims.Principal, PolicyVersion: s.rt.cfg.PolicyVersion, AdminSigned: f.signed}
	nodecide := func(why string) {
		s.raiseOnceKey(AlarmAdminRequestNoDecision+" "+f.id+" "+why, "", AlarmAdminRequestNoDecision,
			fmt.Sprintf("%s in %s got no decision (%s); it is sent again every %d s until it expires at %s", f.kind, f.name, why, RelayEverySeconds, f.claims.ExpiresAt))
	}
	sent, err := s.relayRecord(f, req, audit.OutcomeInfo, authz.CollectorReply{})
	if err != nil {
		nodecide("not recorded, so not sent: " + err.Error())
		return
	}
	var reply authz.CollectorReply
	var doErr error
	if err := c5.AuditBeforeAct(ctx, s.rt.Log(AuditStream), sent, func(c5.Receipt) error {
		dctx, cancel := context.WithTimeout(ctx, RelayTimeout)
		defer cancel()
		r, err := s.c.Do(dctx, req)
		reply, doErr = r.Reply, err
		return nil
	}); err != nil {
		nodecide("not sent: " + err.Error())
		return
	}
	outcome := audit.OutcomeAllowed
	switch {
	case reply.Status == "":
		nodecide(noDecisionDetail(doErr))
		return false
	case !reply.Accepted() && reply.CollectorSeq == 0:
		// A refusal the collector did not number cannot be recorded as
		// its decision (C7-A5-2): state_unavailable is one.
		nodecide("a refusal without collector_seq")
		return
	case !reply.Accepted():
		outcome = audit.OutcomeDenied
	}
	rec, err := s.relayRecord(f, req, outcome, reply)
	if err != nil {
		s.rt.opt.Status.Raise("", AlarmAuditUnavailable, "collector.request "+string(outcome)+" record of "+f.id+": "+err.Error())
		return
	}
	s.appendAudit(ctx, "", append(s.resetFirst(reply.CollectorSeq), rec))
	// The decision applies from the stream, as at a start.
	s.settle(ctx)
	if _, done := s.decided(f.id); !done {
		nodecide("decided, but the record is not in the audit stream yet")
		return
	}
	s.clearQuietPrefix(AlarmAdminRequestNoDecision + " " + f.id + " ")
	if outcome == audit.OutcomeDenied {
		code, check := refusalOf(reply)
		next := "sign a new request"
		if check == authz.AdminCheckReplay || check == authz.AdminCheckWindow {
			// An earlier send of the same bytes may have been accepted:
			// its reply was lost, or the file was put back after it was
			// decided. Signing again would then act twice, which for a
			// clear_suspension clears whatever is open now (A3 on #189).
			next = "it may already have been applied by an earlier send whose decision this node did not record. " +
				"Check the credential's state and the collector's log for that decision before signing again"
		}
		s.raiseOnceKey(AlarmAdminRequestRefused+" "+f.id, "", AlarmAdminRequestRefused,
			fmt.Sprintf("the collector refused %s in %s: %s, check %s. It is not sent again; %s", f.kind, f.name, code, check, next))
	}
	return
}

// refusalOf is a refused reply's code and admin check, each from its
// closed set; anything else reads as unknown.
func refusalOf(r authz.CollectorReply) (string, authz.AdminCheck) {
	if r.Refusal == nil {
		return string(authz.RefuseUnknown), "unknown"
	}
	check := authz.AdminCheck("none")
	if r.Refusal.Check != "" {
		check = "unknown"
		if slices.Contains(authz.AdminChecks, r.Refusal.Check) {
			check = r.Refusal.Check
		}
	}
	return string(r.Refusal.Code.Normalize()), check
}

// relayRecord is the C8 collector.request record of a relayed request.
// Before the collector decides, the payload's claims are recorded as
// unverified and the actor is the node, which sends it. On an acceptance
// the actor is the person the payload names, whom the collector verified
// with the key; on a refusal it stays the node.
func (s *Scheduler) relayRecord(f *adminFile, req *authz.CollectorRequest, outcome audit.Outcome, reply authz.CollectorReply) (c5.Record, error) {
	c := f.claims
	rec := audit.Record{Contract: audit.ContractID, NodeID: string(s.rt.cfg.NodeID), Time: s.rt.received(),
		Actor:  audit.Actor{Type: authz.PrincipalNode, ID: string(s.rt.cfg.NodeID)},
		Action: audit.ActionCollectorRequest, Outcome: outcome,
		PolicyVersion: req.PolicyVersion, CorrelationID: req.RequestID, CollectorSeq: reply.CollectorSeq}
	claims := fmt.Sprintf("key %s, nonce %s, person %s, expires %s, file sha256 %s", c.AdminKeyID, c.Nonce, c.Principal.ID, c.ExpiresAt, f.sum)
	switch outcome {
	case audit.OutcomeInfo:
		rec.Detail = fmt.Sprintf("admin-signed %s relayed; unverified until the collector decides: %s", f.kind, claims)
	case audit.OutcomeAllowed:
		rec.Actor = audit.Actor{Type: authz.PrincipalHuman, ID: c.Principal.ID, Role: authz.RoleAdmin}
		rec.Detail = fmt.Sprintf("admin-signed %s accepted by the collector, which verified: %s", f.kind, claims)
	case audit.OutcomeDenied:
		code, check := refusalOf(reply)
		rec.ReasonCode = code
		rec.Detail = fmt.Sprintf("admin-signed %s refused by the collector, check %s; unverified: %s", f.kind, check, claims)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return c5.Record{}, err
	}
	if _, err := audit.ValidatePending(b); err != nil {
		return c5.Record{}, err
	}
	return c5.Record{Stream: AuditStream, Class: c5.ClassAudit, Event: b}, nil
}

// decided returns the collector's decision on request ID id, if the audit
// stream holds one.
func (s *Scheduler) decided(id string) (relayEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.relayed[id]
	return e, ok
}

// pruneRelayed forgets decided requests whose file is gone, after a scan
// that saw every file. A file put back is sent again and refused as a
// replay or as expired, which changes nothing.
func (s *Scheduler) pruneRelayed(seen map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.relayed {
		if !seen[id] {
			delete(s.relayed, id)
			s.fileStale = true
		}
	}
}

func (s *Scheduler) unread(key, detail string) {
	s.raiseOnceKey(AlarmAdminRequestUnread+" "+key, "", AlarmAdminRequestUnread, detail)
}

func (s *Scheduler) clearQuietPrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.quiet {
		if strings.HasPrefix(k, prefix) {
			delete(s.quiet, k)
		}
	}
}

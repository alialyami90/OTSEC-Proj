package node

import (
	"context"
	"fmt"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
)

// The node's part of an accepted node kind (docs/phase3/A5-signed-admin-files.md,
// relay PR 2). The collector verified the signature and spent the nonce; it
// does nothing else for node.quarantine_clear and node.seq_reset_ack. The
// node then does its own part, under A3's four rules on #181:
//
//   - It acts only on the payload bytes the collector accepted: the file's
//     bytes are read once per tick under the protected-file rule, the
//     accepted record names their SHA-256 (verified.payload_sha256), and the
//     payload is decoded strictly from those bytes. A file replaced after
//     the send has another hash, so it is another request.
//   - It branches on the payload's kind, which the collector verified, and
//     checks it against the file's.
//   - It acts only once the reply record has been folded without the
//     restored-collector hold, so a reply whose collector_seq is at or below
//     the high mark is recorded and acted on by nothing.
//   - It acts only on an acceptance whose verified group names the request.
//
// What is owed comes from the audit stream, not from memory: an allowed
// record with verified for a request whose file is still in admin_dir. A
// crash between the acceptance record and the node's part finds the part
// again at the next tick, applied once (the part is idempotent: a clear is
// named by the file's hash, and an acknowledgement applies only to the open
// reset). A file the administrator removes before the part is done loses it:
// health says "pending" until it is, and the administrator signs again.

// adminPart is the state of the node's part of one accepted request.
type adminPart struct {
	done   bool
	detail string
}

// applyAdminParts does the node's part of every accepted node-kind request
// in files, and returns each one's state by request ID. It holds settleMu
// and decides only after folding the chain as it stands.
func (s *Scheduler) applyAdminParts(ctx context.Context, files []*adminFile) map[string]adminPart {
	var todo []*adminFile
	for _, f := range files {
		if e, ok := s.decided(f.id); ok && nodeActKinds[f.kind] && e.Outcome == audit.OutcomeAllowed {
			todo = append(todo, f)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	out := map[string]adminPart{}
	s.settleMu.Lock()
	defer s.settleMu.Unlock()
	if err := s.fold(ctx, true); err != nil {
		s.foldOK(err)
		for _, f := range todo {
			out[f.id] = adminPart{detail: "the audit stream could not be read: " + err.Error()}
		}
		return out
	}
	for _, f := range todo {
		out[f.id] = s.applyAdminPart(ctx, f)
	}
	return out
}

// notApplied raises AlarmAdminRequestNotApplied once per request and cause
// and returns the part as pending for that cause.
func (s *Scheduler) notApplied(f *adminFile, why string) adminPart {
	s.raiseOnceKey(AlarmAdminRequestNotApplied+" "+f.id+" "+why, "", AlarmAdminRequestNotApplied,
		fmt.Sprintf("the collector accepted %s in %s, and the node has not applied it: %s", f.kind, f.name, why))
	return adminPart{detail: why}
}

// applyAdminPart does the node's part of one accepted request, with
// settleMu held and the chain folded.
func (s *Scheduler) applyAdminPart(ctx context.Context, f *adminFile) adminPart {
	e, ok := s.decided(f.id)
	switch {
	case !ok || e.Outcome != audit.OutcomeAllowed:
		return adminPart{detail: "no acceptance in the audit stream"}
	case e.Verified == nil:
		// The reply did not name the request as verified; the alarm for it
		// was raised when it was recorded.
		return adminPart{detail: "the acceptance does not name the verified administrator"}
	case e.Verified.PayloadSHA256 != authz.AdminPayloadSHA256(f.signed) || e.Verified.Kind != f.kind || e.Verified.Principal != f.claims.Principal.ID:
		return s.notApplied(f, "the acceptance in the audit stream names other signed bytes, kind or person than this file")
	}
	s.mu.Lock()
	restored := s.cs.Restored != nil
	s.mu.Unlock()
	if restored {
		return s.notApplied(f, "the collector is held as restored (a reply's collector_seq went back), so no decision of its is acted on until an administrator acknowledges it")
	}
	// The payload the collector verified, decoded strictly: the only source
	// of what to do.
	var p authz.AdminRequest
	if err := collectorwire.DecodeStrict(f.signed.Payload, &p); err != nil {
		return s.notApplied(f, "the accepted payload does not decode: "+err.Error())
	}
	switch {
	case p.Kind != f.kind || p.Principal != f.claims.Principal:
		return s.notApplied(f, "the accepted payload's kind or person is not the file's")
	case p.NodeID != string(s.rt.cfg.NodeID):
		return s.notApplied(f, "the accepted payload is bound to another node")
	}
	source := fmt.Sprintf("%s (signed by %s, collector_seq %d)", f.name, e.Verified.Principal, e.CollectorSeq)
	switch p.Kind {
	case authz.KindNodeQuarantineClear:
		b := p.NodeQuarantineClear
		if b == nil || !sha256Hex.MatchString(b.ManifestSHA256) {
			return s.notApplied(f, "the accepted payload has no valid node_quarantine_clear body")
		}
		c := quarantineClear{source: source, hash: f.sum, assetID: b.AssetID, manifest: b.ManifestSHA256, principal: e.Verified.Principal}
		if s.quarantineApplied(c.hash) {
			return adminPart{done: true}
		}
		if done, why := s.applyQuarantineClear(ctx, c); !done {
			return adminPart{detail: why}
		}
		return adminPart{done: true}
	case authz.KindNodeSeqResetAck:
		if p.NodeSeqResetAck == nil || p.InstallKeyID == "" {
			return s.notApplied(f, "the accepted payload has no node_seq_reset_ack body or no install key")
		}
		s.mu.Lock()
		open, trusted := s.cs.OpenResetKey, s.cs.TrustedKey
		s.mu.Unlock()
		switch {
		case open == "" && trusted == p.InstallKeyID:
			return adminPart{done: true, detail: "install key " + p.InstallKeyID + " is already the trusted key"}
		case open == "":
			return adminPart{detail: "no reset is open, so there is nothing to acknowledge for install key " + p.InstallKeyID}
		}
		if done, why := s.applySeqAck(ctx, source, AlarmResetAckRefused+" file "+f.sum, p.InstallKeyID, open); !done {
			return adminPart{detail: why}
		}
		return adminPart{done: true}
	}
	return s.notApplied(f, "the node does no part of "+string(p.Kind))
}

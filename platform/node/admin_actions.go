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

// The states of the node's part of one accepted request.
const (
	partPending = "pending" // not yet done; tried again at the next tick
	partDone    = "done"
	// partNothing: there was nothing to do (an acknowledgement of the key
	// already trusted).
	partNothing = "nothing"
	// partRefused: the collector accepted it, but the node will never act on
	// it (a decision of a collector it did not trust, or of a key it no
	// longer does); the administrator signs the request again.
	partRefused = "refused"
)

// adminPart is the state of the node's part of one accepted request.
type adminPart struct {
	state  string
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
			out[f.id] = adminPart{state: partPending, detail: "the audit stream could not be read: " + err.Error()}
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
	return adminPart{state: partPending, detail: why}
}

// neverApplied is notApplied for an acceptance the node will not act on, now
// or later: the part is refused, and the administrator signs again.
func (s *Scheduler) neverApplied(f *adminFile, why string) adminPart {
	p := s.notApplied(f, why)
	p.state = partRefused
	return p
}

// applyAdminPart does the node's part of one accepted request, with
// settleMu held and the chain folded.
func (s *Scheduler) applyAdminPart(ctx context.Context, f *adminFile) adminPart {
	e, ok := s.decided(f.id)
	switch {
	case !ok || e.Outcome != audit.OutcomeAllowed:
		return adminPart{state: partPending, detail: "no acceptance in the audit stream"}
	case e.Verified == nil:
		// The reply did not name the request as verified; the alarm for it
		// was raised when it was recorded.
		return adminPart{state: partPending, detail: "the acceptance does not name the verified administrator"}
	case e.Verified.PayloadSHA256 != authz.AdminPayloadSHA256(f.signed) || e.Verified.Kind != f.kind || e.Verified.Principal != f.claims.Principal.ID:
		return s.notApplied(f, "the acceptance in the audit stream names other signed bytes, kind or person than this file")
	}
	s.mu.Lock()
	restored := s.cs.Restored != nil
	s.mu.Unlock()
	if e.Tainted {
		return s.neverApplied(f, "accepted by a collector the node did not trust: the reply was numbered at or below the high mark, so the collector was held as restored; the node does not act on it, even after a reinstall. Sign the request again")
	}
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
	s.mu.Lock()
	open, trusted := s.cs.OpenResetKey, s.cs.TrustedKey
	s.mu.Unlock()
	source := fmt.Sprintf("%s (signed by %s, collector_seq %d)", f.name, e.Verified.Principal, e.CollectorSeq)
	switch p.Kind {
	case authz.KindNodeQuarantineClear:
		b := p.NodeQuarantineClear
		if b == nil || !sha256Hex.MatchString(b.ManifestSHA256) {
			return s.notApplied(f, "the accepted payload has no valid node_quarantine_clear body")
		}
		// The acceptance was bound to an install key, and the node acts on it
		// only while that is the key it trusts: a reinstall retires every
		// acceptance of the old key, and a collector that goes back to an
		// earlier key does not revive them (B1 on #339, rule b).
		switch {
		case open != "":
			return s.notApplied(f, "the collector was reinstalled and the reset on install key "+open+" is not acknowledged yet; the clear is bound to install key "+p.InstallKeyID)
		case p.InstallKeyID != trusted:
			return s.neverApplied(f, "accepted for install key "+p.InstallKeyID+", which is not the key the node trusts ("+keyOrNone(trusted)+"): a reinstall retired it. Sign the request again")
		}
		// The record links to the collector's accepted request by the hash of
		// the payload it verified, not to a separate read of the file.
		c := quarantineClear{source: source, hash: e.Verified.PayloadSHA256, assetID: b.AssetID, manifest: b.ManifestSHA256, principal: e.Verified.Principal}
		if s.quarantineApplied(c.hash) {
			return adminPart{state: partDone}
		}
		if done, why := s.applyQuarantineClear(ctx, c); !done {
			return adminPart{state: partPending, detail: why}
		}
		return adminPart{state: partDone}
	case authz.KindNodeSeqResetAck:
		if p.NodeSeqResetAck == nil || p.InstallKeyID == "" {
			return s.notApplied(f, "the accepted payload has no node_seq_reset_ack body or no install key")
		}
		switch {
		case open == "" && trusted == p.InstallKeyID:
			return adminPart{state: partNothing, detail: "install key " + p.InstallKeyID + " is already the trusted key"}
		case open == "":
			return s.neverApplied(f, "no reset is open, so there is nothing to acknowledge for install key "+p.InstallKeyID+" (the trusted key is "+keyOrNone(trusted)+"). Sign the request again if a reset opens")
		case p.InstallKeyID != open:
			return s.neverApplied(f, "it acknowledges install key "+p.InstallKeyID+", but the open reset is on "+open+". Sign an acknowledgement of that key")
		}
		if done, why := s.applySeqAck(ctx, source, AlarmResetAckRefused+" file "+f.sum, p.InstallKeyID, open); !done {
			return adminPart{state: partPending, detail: why}
		}
		return adminPart{state: partDone}
	}
	return s.notApplied(f, "the node does no part of "+string(p.Kind))
}

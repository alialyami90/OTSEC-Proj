package node

import (
	"context"
	"fmt"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/authz"
)

// A suspension only the collector holds, after the reply to the suspending
// run was lost or the node stopped before recording it, could otherwise be
// lifted only by reinstalling the collector (A6 on #120). Since C7 0.3 the
// collector names the suspension it holds when it refuses a run
// (asset_suspended) or a clear of another suspension (suspension_mismatch).
// The node adopts a named suspension it does not hold: it records its own
// asset.suspend with the collector's reason, ref and C2 code, and the
// administrator's clear-suspension.json naming that ref then clears it at
// both ends as any other. Adopting only adds a restriction the collector
// already enforces (A3 on #125).

// AlarmSuspensionNotAdopted: the collector's refusal names a suspension
// the node cannot adopt. Nothing was recorded; the refusal is in the audit
// stream.
const AlarmSuspensionNotAdopted = "asset-suspension-not-adopted"

// adoptedDetail starts an adopted suspension's record detail.
const adoptedDetail = "adopted from the collector's refusal"

// adopt adopts the suspension a refused reply names, if any, and reports
// whether it did. The alarm's detail never quotes the reply.
func (s *Scheduler) adopt(ctx context.Context, assetID string, reply authz.CollectorReply) bool {
	h, err := reply.HeldSuspension()
	if err == nil && h == nil {
		return false
	}
	no := func(key, why string) bool {
		s.raiseOnceKey(assetID+" "+AlarmSuspensionNotAdopted+" "+key, assetID, AlarmSuspensionNotAdopted,
			"the collector's refusal names a suspension the node does not adopt: "+why+"; nothing recorded")
		return false
	}
	if err != nil {
		return no("malformed", "it fails C7 0.3's check")
	}
	code := adapter.Code(h.Code)
	switch {
	case h.Code == "":
		// A collector state written before codes were kept (A3 on #125).
		return no(h.Ref+" code", "it has no C2 code, which the node's asset.suspend record needs; reinstalling the collector, or a clear at the collector, is the way out")
	case !code.Known() || code.Suspends() != h.Reason:
		return no(h.Ref+" code", fmt.Sprintf("its code is not a C2 code that suspends with reason %s", h.Reason))
	}
	s.mu.Lock()
	cur, held := s.susp[assetID]
	owed := s.collClear[assetID]
	s.mu.Unlock()
	switch {
	case held && cur.Ref == h.Ref:
		return false
	case held:
		// C8 holds one suspension per asset; the node's own stays.
		return no(h.Ref+" held", "the node holds suspension "+cur.Ref+" for the asset")
	case owed == h.Ref:
		return no(h.Ref+" owed", "it is the suspension whose clear the node is sending")
	}
	s.hold(ctx, assetID, h.Ref, code, true)
	return true
}

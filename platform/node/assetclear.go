package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"maps"
	"strings"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
)

// A clear has two halves (D2-15, A3 #117). The node's half is its own
// asset.suspension_clear, from the administrator's clear-suspension.json
// (checkClear). The collector holds the same suspension in its own state
// and lifts it only for a C7 0.2 asset.clear_suspension that matches the
// same file, which it reads itself. So after its own clear the node sends
// that request, on its own behalf, and keeps the asset's runs held until
// the collector accepts it: a run sent before would only be refused.
//
// Which clears are still owed is read from the audit stream, like the
// suspensions: an asset.suspension_clear opens one, and the collector's
// allowed collector.request for it closes it. The node's request IDs for
// these requests are clearRequestPrefix, the suspension's ref, a colon and
// random hex, so the allowed record names the clear it closes exactly.
const (
	// AlarmCollectorStillSuspended: the node has cleared a suspension but
	// the collector has not yet accepted the clear, so the asset's runs
	// stay held. It stays up through a lost reply and a refusal, and is
	// retried before each of the asset's runs while clear-suspension.json
	// still names the suspension.
	AlarmCollectorStillSuspended = "asset-collector-still-suspended"

	clearRequestPrefix = "clr:"
)

// clearRequestID is a new request ID for the clear of the suspension ref.
func clearRequestID(ref string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	return clearRequestPrefix + ref + ":" + hex.EncodeToString(b[:])
}

// applyCollectorClear applies one audit record to the clears owed to the
// collector, m: asset ID to the ref the node cleared. It returns true when
// the record is the collector's acceptance of an owed clear. A later
// suspension of the asset leaves the owed clear in place: the collector
// still holds the earlier one until it accepts it.
func applyCollectorClear(m map[string]string, rec *audit.Record) bool {
	switch {
	case rec.Action == audit.ActionAssetSuspensionClear && rec.Target != nil:
		m[rec.Target.AssetID] = rec.CorrelationID
	case rec.Action == audit.ActionCollectorRequest && rec.Outcome == audit.OutcomeAllowed &&
		rec.Actor.Type == authz.PrincipalNode && rec.Target != nil:
		ref, ok := m[rec.Target.AssetID]
		if ok && strings.HasPrefix(rec.CorrelationID, clearRequestPrefix+ref+":") {
			delete(m, rec.Target.AssetID)
			return true
		}
	}
	return false
}

// collectorClearing reports whether the node has cleared suspension ref of
// assetID and the collector has not yet accepted it.
func (s *Scheduler) collectorClearing(assetID, ref string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.collClear[assetID] == ref
}

// CollectorClears returns the clears the collector has not yet accepted:
// asset ID to the suspension's ref.
func (s *Scheduler) CollectorClears() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.collClear)
}

// clearAtCollector sends the asset's owed clear, if it has one, and
// reports whether the asset's run may go on: true when nothing is owed or
// the collector accepted the clear and its record is in the audit stream.
// The request is sent only while clear-suspension.json names the
// suspension, since the collector checks the same file; it is audited
// before it is sent, and the collector's decision after, as for a run. A
// lost reply or a refusal leaves the clear owed, and the next run of the
// asset sends it again: a collector that already lifted the suspension, or
// a reinstalled one that never held it, accepts a matching clear.
func (s *Scheduler) clearAtCollector(ctx context.Context, assetID string) bool {
	s.mu.Lock()
	ref, owed := s.collClear[assetID]
	file := s.clearFile
	s.mu.Unlock()
	if !owed {
		return true
	}
	still := func(why, detail string) bool {
		s.raiseOnceKey(assetID+" "+AlarmCollectorStillSuspended+" "+why, assetID, AlarmCollectorStillSuspended,
			"the node cleared suspension "+ref+", but the collector still holds it; "+detail)
		return false
	}
	if file == nil || file.AssetID != assetID || file.Ref != ref {
		return still("file", "runs stay held until it accepts the clear, which it checks against "+ClearSuspensionFileName+": leave or write that file naming this asset and ref")
	}
	req := &authz.CollectorRequest{Contract: authz.ContractID, Kind: authz.KindAssetClearSusp, RequestID: clearRequestID(ref),
		OnBehalfOf:     authz.Principal{Type: authz.PrincipalNode, ID: string(s.rt.cfg.NodeID)},
		PolicyVersion:  s.rt.cfg.PolicyVersion,
		AssetClearSusp: &authz.AssetClearSuspBody{AssetID: assetID, Ref: ref}}
	sent, err := s.requestRecord(req, audit.OutcomeInfo, "", 0)
	if err != nil {
		return still("audit", "the clear request was not recorded, so not sent: "+err.Error())
	}
	var reply authz.CollectorReply
	var doErr error
	if err := c5.AuditBeforeAct(ctx, s.rt.Log(AuditStream), sent, func(c5.Receipt) error {
		r, err := s.c.Do(ctx, req)
		reply, doErr = r.Reply, err
		return nil
	}); err != nil {
		return still("audit", "the clear request was not sent: "+err.Error())
	}
	switch {
	case reply.Status == "":
		return still("no-decision", "no decision on the clear ("+noDecisionDetail(doErr)+"); it is sent again before the asset's next run")
	case !reply.Accepted():
		code := string(authz.RefuseUnknown)
		if reply.Refusal != nil {
			code = string(reply.Refusal.Code.Normalize())
		}
		if rec, err := s.requestRecord(req, audit.OutcomeDenied, code, reply.CollectorSeq); err == nil {
			s.appendAudit(ctx, assetID, append(s.resetFirst(reply.CollectorSeq), rec))
		} else {
			s.rt.opt.Status.Raise(assetID, AlarmAuditUnavailable, "collector.request denied record: "+err.Error())
		}
		return still("refused "+code, "it refused the clear ("+code+"); it is sent again before the asset's next run")
	}
	rec, err := s.requestRecord(req, audit.OutcomeAllowed, "", reply.CollectorSeq)
	if err != nil {
		s.rt.opt.Status.Raise(assetID, AlarmAuditUnavailable, "collector.request allowed record: "+err.Error())
		return still("audit", "it accepted the clear, but the record was not written; the clear is sent again")
	}
	s.appendAudit(ctx, assetID, append(s.resetFirst(reply.CollectorSeq), rec))
	// The acceptance closes the owed clear from the stream, as at a start.
	s.settle(ctx)
	if s.collectorClearing(assetID, ref) {
		return still("audit", "it accepted the clear, but the record is not in the audit stream yet; the clear is sent again")
	}
	s.mu.Lock()
	for k := range s.quiet {
		if strings.HasPrefix(k, assetID+" "+AlarmCollectorStillSuspended+" ") {
			delete(s.quiet, k)
		}
	}
	s.mu.Unlock()
	s.publishSuspensions()
	return true
}

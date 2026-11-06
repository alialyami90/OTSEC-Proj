package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"maps"
	"regexp"
	"slices"
	"strings"

	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	c5 "otsec.local/otsec/contracts/store"
)

// A clear has two halves (D2-15, A3 #117). The node's half is its own
// asset.suspension_clear. The collector holds the same suspension in its own
// state. There are two ways to clear both:
//
//   - An administrator's signed asset.clear_suspension (P4-H1), relayed like
//     any signed request. The collector lifts its half when it accepts it,
//     and the node then records its own clear from the payload it sent
//     (applySignedClear), naming the person and that it was signed. Nothing
//     is owed to the collector after it.
//   - On a lab-only node only, the unsigned clear-suspension.json
//     (checkClear, unsigned.go). The collector lifts its half only for a C7
//     0.2 asset.clear_suspension that matches the same file, which it reads
//     itself, and refuses it for an asset with an endpoint that is not
//     simulated (#508). So after its own clear the node sends that request,
//     on its own behalf, and keeps the asset's runs held until the collector
//     accepts it: a run sent before would only be refused.
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

// signedClearDetail is the detail of the node's asset.suspension_clear for
// a signed clear (applySignedClear), the only record that tells it from the
// clear of the unsigned file. The node writes both, in its own chain.
var signedClearDetail = regexp.MustCompile(`^cleared by admin-request-[a-z0-9-]{1,64}\.json \(signed by `)

// applySignedClear records the node's clear of suspension b.Ref of asset
// b.AssetID, from a signed asset.clear_suspension the collector accepted
// (source names the file, the person and the decision). It holds settleMu
// and the chain is folded. It clears only an exact asset and ref match, and
// only a suspension already in the audit stream, as checkClear does.
func (s *Scheduler) applySignedClear(ctx context.Context, b *authz.AssetClearSuspBody, source string) adminPart {
	s.mu.Lock()
	sp, held := s.susp[b.AssetID]
	unwritten := slices.ContainsFunc(s.unaudited, func(u unaudited) bool { return u.assetID == b.AssetID && u.sp.Ref == b.Ref })
	s.mu.Unlock()
	switch {
	case !held || sp.Ref != b.Ref:
		return adminPart{state: partNothing, detail: "the node holds no suspension " + b.Ref + " of asset " + b.AssetID + ": it is cleared already, or was never held here"}
	case unwritten:
		return adminPart{state: partPending, detail: "suspension " + b.Ref + " is not yet in the audit stream; the clear waits until it is"}
	}
	if err := s.commitSuspensionRecord(ctx, audit.ActionAssetSuspensionClear, b.AssetID, sp, "", "cleared by "+source); err != nil {
		return adminPart{state: partPending, detail: "the clear was not recorded in the audit stream, so not applied: " + err.Error()}
	}
	// It applies from the stream, as at a start.
	s.settleLocked(ctx)
	return adminPart{state: partDone}
}

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
// still holds the earlier one until it accepts it. A later node clear
// replaces it, which is right while node suspensions come only from run
// outcomes, since the asset's runs are held while a clear is owed. A
// node-only suspension (reason operator) would break that: its clear would
// replace a ref the collector still holds (A3 on #120), so such a path
// must keep the owed refs per suspension.
//
// A signed clear opens nothing, since the collector accepted it before the
// node recorded it, and it closes an owed clear of the same ref.
func applyCollectorClear(m map[string]string, rec *audit.Record) bool {
	switch {
	case rec.Action == audit.ActionAssetSuspensionClear && rec.Target != nil && signedClearDetail.MatchString(rec.Detail):
		if m[rec.Target.AssetID] == rec.CorrelationID {
			delete(m, rec.Target.AssetID)
		}
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
		if s.adopt(ctx, assetID, reply) {
			return false
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

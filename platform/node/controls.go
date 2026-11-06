package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/applicability"
)

// AssetControls is one asset_controls entry: the network controls in front
// of an asset, as C11 control keys (<tcp|udp>/<port>), each naming what a
// control blocks (D4-56). They are the operator's, from this file only,
// never from a device, the collector or a result, and they sit beside the
// C1 records, never in them.
type AssetControls struct {
	AssetID  string   `json:"asset_id"`
	Controls []string `json:"controls"`
}

// MaxAssetControls is the most keys one asset may list: sixteen fit the
// policy.apply detail bound (D4-56).
const MaxAssetControls = 16

// ReasonAssetControlsDeclared is the reason_code of the policy.apply record
// of an asset's controls (D4-56). Its detail is controlsDetail's.
const ReasonAssetControlsDeclared = "asset_controls_declared"

// AlarmControlsNotRecorded is raised once per asset when the policy.apply
// record of its controls cannot be written. The asset is then evaluated
// with no controls, so an unrecorded control is never cited (D4-56).
const AlarmControlsNotRecorded = "asset-controls-not-recorded"

// controlKeyRe is C11's control key form (contracts/advisory).
var controlKeyRe = regexp.MustCompile(`^(tcp|udp)/([1-9][0-9]{0,4})$`)

var controlsDetailRe = regexp.MustCompile(`^asset (\S+) controls sha256:([0-9a-f]{64}) keys \S+$`)

func validControlKey(k string) bool {
	m := controlKeyRe.FindStringSubmatch(k)
	if m == nil {
		return false
	}
	port, _ := strconv.Atoi(m[2])
	return port <= 65535
}

// checkAssetControls refuses an entry for no asset, an asset listed twice,
// a malformed or repeated key, and more than MaxAssetControls keys.
func (c *Config) checkAssetControls(fail func(format string, args ...any)) {
	seen := map[string]bool{}
	for i, e := range c.AssetControls {
		p := fmt.Sprintf("asset_controls[%d]", i)
		if _, ok := c.Asset(e.AssetID); !ok {
			fail("%s.asset_id %q is not a configured asset", p, e.AssetID)
		}
		if seen[e.AssetID] {
			fail("%s: asset %s is listed twice", p, e.AssetID)
		}
		seen[e.AssetID] = true
		if len(e.Controls) > MaxAssetControls {
			fail("%s: %d controls, at most %d", p, len(e.Controls), MaxAssetControls)
		}
		keys := map[string]bool{}
		for j, k := range e.Controls {
			if !validControlKey(k) {
				fail("%s.controls[%d] %q is not <tcp|udp>/<port 1 to 65535>", p, j, k)
			}
			if keys[k] {
				fail("%s.controls[%d]: %s is listed twice", p, j, k)
			}
			keys[k] = true
		}
	}
}

// assetControls returns the asset's controls in byte order, and whether
// asset_controls lists the asset.
func (c *Config) assetControls(assetID string) ([]string, bool) {
	for _, e := range c.AssetControls {
		if e.AssetID == assetID {
			keys := slices.Clone(e.Controls)
			slices.Sort(keys)
			return keys, true
		}
	}
	return nil, false
}

// controlsSum is the SHA-256 of the sorted keys, each followed by one LF;
// an empty list hashes the empty string (D4-56).
func controlsSum(sorted []string) string {
	var b strings.Builder
	for _, k := range sorted {
		b.WriteString(k)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// controlsDetail is the policy.apply detail of an asset's controls: the
// hash and the keys in the hashed order, or "none", so the attested keys
// can be read from the chain (C3 on #468).
func controlsDetail(assetID string, sorted []string) string {
	keys := "none"
	if len(sorted) > 0 {
		keys = strings.Join(sorted, ",")
	}
	return fmt.Sprintf("asset %s controls sha256:%s keys %s", assetID, controlsSum(sorted), keys)
}

// startControls writes the policy.apply record of every asset whose
// controls are new or changed, with applicability on (D4-56). An asset
// that had controls recorded and is no longer listed is recorded as
// having none, so the chain shows the withdrawal.
func (s *Scheduler) startControls(ctx context.Context) {
	if s.adv == nil {
		return
	}
	for _, a := range s.rt.cfg.assets {
		if _, err := s.controlsInput(ctx, a.AssetID); err != nil {
			s.raiseOnceKey("controls "+a.AssetID, a.AssetID, AlarmControlsNotRecorded, err.Error())
		}
	}
}

// controlsInput returns the asset's controls for the matcher, each cited
// by the record of the list as it is now, writing that record if the
// newest one is of another list. An asset with no list and no record has
// no controls and writes nothing.
func (s *Scheduler) controlsInput(ctx context.Context, assetID string) ([]applicability.Control, error) {
	if err := s.loadRecorded(ctx); err != nil {
		return nil, err
	}
	keys, listed := s.rt.cfg.assetControls(assetID)
	r, recorded := s.controls[assetID]
	if !listed && !recorded {
		return nil, nil
	}
	sum := controlsSum(keys)
	if !recorded || r.SHA256 != sum {
		seq, err := s.writePolicyApply(ctx, ReasonAssetControlsDeclared, controlsDetail(assetID, keys))
		if err != nil {
			return nil, fmt.Errorf("the controls' policy.apply record was not written: %w", err)
		}
		r = declaredRecord{SHA256: sum, Seq: seq}
		s.controls[assetID] = r
		s.writeRecordedFile()
	}
	s.clearQuietKey("controls " + assetID)
	ref := fmt.Sprintf("audit:%s:%d", s.rt.cfg.NodeID, r.Seq)
	out := make([]applicability.Control, len(keys))
	for i, k := range keys {
		out[i] = applicability.Control{Key: k, Evidence: ref}
	}
	return out, nil
}

// writePolicyApply appends one policy.apply record and returns its seq.
func (s *Scheduler) writePolicyApply(ctx context.Context, reason, detail string) (uint64, error) {
	rec, err := s.rt.AuditRecord(audit.ActionPolicyApply, audit.OutcomeInfo, reason, detail)
	if err != nil {
		return 0, err
	}
	log := s.rt.Log(AuditStream)
	if log == nil {
		return 0, errAuditNotOpen
	}
	got, err := log.AppendBatch(ctx, []c5.Record{rec})
	if err != nil {
		return 0, err
	}
	return uint64(got[0].Key().Seq), nil
}

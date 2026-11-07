package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"otsec.local/otsec/contracts/version"
)

// The network baseline acknowledgement (0.10, D4-68 ruling 8,
// docs/phase4/D3-c7-0.10-c8-0.12.md §1). A network baseline belongs to a
// sensor, not an asset, and through its authorized writers it decides
// which hosts may write to relays without an alert. That is a different
// grant from accepting a configuration or event baseline, so it has its
// own kind, and a key signs it only when its list names it.
const (
	// KindNodeNetworkBaselineAck acknowledges one sensor's network
	// baseline, with the authorized writers the person added (C13 §8).
	KindNodeNetworkBaselineAck RequestKind = "node.network_baseline_ack"
	// networkAckSince is the minor that added the kind,
	// AdminAccepted.KeysDigest and AdminAccepted.Keys.
	networkAckSince = 10
)

// BaselineNetwork is a C13 network baseline (since 0.10). Only
// node.network_baseline_ack acknowledges one: NodeBaselineAckBody refuses
// it, so a key allowed node.baseline_ack gains nothing here.
const BaselineNetwork BaselineKind = "network"

// sensorIDPattern is a C13 sensor ID, a lowercase UUID.
var sensorIDPattern = assetIDPattern

// NodeNetworkBaselineAckBody (since 0.10) accepts one sensor's network
// baseline. BaselineDigest names the accepted document: the frozen draft
// with the person's authorized_writers filled in, in C13's canonical
// encoding. DraftDigest names the frozen draft it was built from. Both are
// signed, so the person attests to the draft as well as to what they
// added. The two are equal when the person added no writer.
//
// The collector checks the shape only, and has no asset to check: it does
// not know the node's sensors. The node adopts the document only after the
// collector accepts, and only under the checks in
// docs/phase4/D3-c7-0.10-c8-0.12.md §1.2.
type NodeNetworkBaselineAckBody struct {
	SensorID       string `json:"sensor_id"`
	DraftDigest    string `json:"draft_digest"`
	BaselineDigest string `json:"baseline_digest"`
}

// Validate checks the body as the collector does (payload).
func (b *NodeNetworkBaselineAckBody) Validate() error {
	switch {
	case !sensorIDPattern.MatchString(b.SensorID):
		return refuse(RefuseInvalid, "sensor_id")
	case !baselineDigestPattern.MatchString(b.DraftDigest):
		return refuse(RefuseInvalid, "draft_digest")
	case !baselineDigestPattern.MatchString(b.BaselineDigest):
		return refuse(RefuseInvalid, "baseline_digest")
	}
	return nil
}

// AdminKeyEntry is one pinned administrator key as an accepted reply names
// it (since 0.10): its ID, the principal it speaks for, its status, and
// the kinds it may sign, sorted. A key pinned without a list is written
// with the DefaultAdminKinds it actually has.
type AdminKeyEntry struct {
	KeyID     string        `json:"key_id"`
	Principal string        `json:"principal"`
	Status    KeyStatus     `json:"status"`
	Kinds     []RequestKind `json:"kinds"`
}

// AdminKeyEntries lists keys as an accepted reply names them: sorted by
// key ID, each with its sorted kinds. The collector calls it on its pinned
// keys for every accepted 0.10 reply.
func AdminKeyEntries(keys []AdminKey) []AdminKeyEntry {
	out := make([]AdminKeyEntry, 0, len(keys))
	for _, k := range keys {
		kinds := k.Kinds
		if kinds == nil {
			kinds = DefaultAdminKinds
		}
		kinds = slices.Clone(kinds)
		slices.Sort(kinds)
		out = append(out, AdminKeyEntry{KeyID: k.KeyID, Principal: k.Principal, Status: k.Status, Kinds: kinds})
	}
	slices.SortFunc(out, func(a, b AdminKeyEntry) int { return strings.Compare(a.KeyID, b.KeyID) })
	return out
}

// AdminKeysDigest is "sha256:" and the lowercase hex SHA-256 of entries,
// one line per entry in the order given, each line the key ID, the
// principal, the status and the kinds joined by commas, separated by
// spaces and ended by a line feed. Over AdminKeyEntries it changes when a
// key's kinds, status or principal change, and not when only their order
// in the configuration does.
func AdminKeysDigest(entries []AdminKeyEntry) string {
	var b strings.Builder
	for _, e := range entries {
		kinds := make([]string, len(e.Kinds))
		for i, k := range e.Kinds {
			kinds[i] = string(k)
		}
		fmt.Fprintf(&b, "%s %s %s %s\n", e.KeyID, e.Principal, e.Status, strings.Join(kinds, ","))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NamesAdminKeys reports whether a request stamped contract gets
// AdminAccepted.KeysDigest and Keys: from 0.10. A reader built for 0.9
// decodes replies strictly and knows neither field, so a collector leaves
// them out of the reply to an older request.
func NamesAdminKeys(contract string) bool {
	got, err := version.Parse(contract)
	return err == nil && got.Minor >= networkAckSince
}

// validateKeys checks keys_digest and keys (since 0.10): both or neither,
// only on a reply stamped 0.10 or later, the entries well formed and in
// order, and the digest the one AdminKeysDigest gives over them, so a node
// that records the list records what the digest names.
func (a *AdminAccepted) validateKeys(contract string) error {
	if a.KeysDigest == "" && a.Keys == nil {
		return nil
	}
	switch {
	case !NamesAdminKeys(contract):
		return fmt.Errorf("authz: a reply stamped %q carries admin.keys_digest or admin.keys, which need 0.%d", contract, networkAckSince)
	case a.KeysDigest == "" || len(a.Keys) == 0:
		return errors.New("authz: admin.keys_digest and admin.keys come together")
	case !baselineDigestPattern.MatchString(a.KeysDigest):
		return errors.New("authz: admin.keys_digest is not sha256: and 64 lowercase hex digits")
	}
	for i, e := range a.Keys {
		switch {
		case !adminKeyIDPattern.MatchString(e.KeyID):
			return fmt.Errorf("authz: admin.keys[%d].key_id is malformed", i)
		case i > 0 && e.KeyID <= a.Keys[i-1].KeyID:
			return fmt.Errorf("authz: admin.keys[%d] is not sorted by key_id, or repeats one", i)
		case !principalIDPattern.MatchString(e.Principal):
			return fmt.Errorf("authz: admin.keys[%d].principal is malformed", i)
		case e.Status != KeyActive && e.Status != KeyRevoked:
			return fmt.Errorf("authz: admin.keys[%d].status %q", i, e.Status)
		case !slices.IsSorted(e.Kinds) || len(slices.Compact(slices.Clone(e.Kinds))) != len(e.Kinds):
			return fmt.Errorf("authz: admin.keys[%d].kinds are not sorted, or repeat one", i)
		}
		if err := ValidateAdminKinds(e.Kinds); err != nil {
			return fmt.Errorf("authz: admin.keys[%d]: %w", i, err)
		}
	}
	if AdminKeysDigest(a.Keys) != a.KeysDigest {
		return errors.New("authz: admin.keys_digest is not the digest of admin.keys")
	}
	return nil
}

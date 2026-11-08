// Package netack holds the node's checks for a network baseline's
// acknowledgement (C7 0.10 node.network_baseline_ack, C13 §8,
// docs/phase4/D3-c7-0.10-c8-0.12.md §1). The functions are pure: the node
// reads the admin folder, its audit chain and its store, and passes the
// bytes and digests here. Nothing in this package opens a file, a socket
// or a store (TestOwnImports).
package netack

import (
	"fmt"
	"slices"

	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/netobs"
)

// The reasons Adopt refuses an accepted acknowledgement. The node writes
// config.baseline_acknowledged with outcome denied and one of these as its
// reason_code, and takes nothing (§1.2).
const (
	// ReasonBody: the accepted payload has no valid
	// node_network_baseline_ack body.
	ReasonBody = "network_ack_body"
	// ReasonSensor: the body names a sensor other than the node's
	// network_sensor.
	ReasonSensor = "network_sensor_not_configured"
	// ReasonDraftNotLatest: draft_digest is not the latest network draft
	// the node recorded for the sensor, or none is recorded.
	ReasonDraftNotLatest = "network_draft_not_latest"
	// ReasonFileMissing: the digests differ and there is no file.
	ReasonFileMissing = "network_file_missing"
	// ReasonFileDigest: the file is larger than MaxBaselineBytes, or its
	// SHA-256 is not baseline_digest.
	ReasonFileDigest = "network_file_digest"
	// ReasonNotCanonical: the file is not a valid document in C13 §8's
	// canonical encoding, such as one re-encoded with other whitespace or
	// key order, though its hash is the signed one.
	ReasonNotCanonical = "network_not_canonical"
	// ReasonChanged: the file differs from the draft in something other
	// than authorized_writers.
	ReasonChanged = "network_not_draft_with_writers"
)

// Refusal is why Adopt refused: a reason code and its explanation.
type Refusal struct {
	Reason string
	Detail string
}

func (r *Refusal) Error() string { return "netack: " + r.Reason + ": " + r.Detail }

func refuse(reason, format string, args ...any) *Refusal {
	return &Refusal{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Adopt decides one acknowledgement the collector accepted (§1.2). sensorID
// is the node's network_sensor.sensor_id; draft is the exact bytes of the
// latest network draft the node recorded for it, or nil; file is the
// admin folder's network-baseline-<sensor_id>.json, read once, or nil.
// When the two digests are equal the draft is the accepted document and
// file is not looked at, so a file present then is ignored (D6, T5).
//
// It returns the bytes to store as the accepted baseline: a copy, so the
// stored bytes are the checked bytes whatever happens to file afterwards
// (D6, T3). Every refusal is a *Refusal.
func Adopt(sensorID string, draft, file []byte, body *authz.NodeNetworkBaselineAckBody) ([]byte, error) {
	if body == nil || body.Validate() != nil {
		return nil, refuse(ReasonBody, "the accepted payload has no valid node_network_baseline_ack body")
	}
	if body.SensorID != sensorID {
		return nil, refuse(ReasonSensor, "sensor %s is not the node's network sensor %s", body.SensorID, sensorID)
	}
	if draft == nil {
		return nil, refuse(ReasonDraftNotLatest, "the node has recorded no network draft for sensor %s", sensorID)
	}
	if got := netobs.Digest(draft); got != body.DraftDigest {
		return nil, refuse(ReasonDraftNotLatest, "draft %s is not the latest recorded draft %s", body.DraftDigest, got)
	}
	accepted := draft
	if body.BaselineDigest != body.DraftDigest {
		switch {
		case file == nil:
			return nil, refuse(ReasonFileMissing, "no accepted document for baseline %s", body.BaselineDigest)
		case len(file) > netobs.MaxBaselineBytes:
			return nil, refuse(ReasonFileDigest, "the accepted document is %d bytes, above %d", len(file), netobs.MaxBaselineBytes)
		case netobs.Digest(file) != body.BaselineDigest:
			return nil, refuse(ReasonFileDigest, "the accepted document's digest is %s, not the signed %s", netobs.Digest(file), body.BaselineDigest)
		}
		accepted = file
	}
	if !netobs.IsCanonical(accepted) {
		return nil, refuse(ReasonNotCanonical, "the accepted document is not a valid network baseline in canonical encoding")
	}
	if !netobs.OnlyWritersAdded(draft, accepted) {
		return nil, refuse(ReasonChanged, "the accepted document differs from draft %s outside authorized_writers", body.DraftDigest)
	}
	if b, _ := netobs.DecodeBaseline(accepted); b == nil || b.SensorID != sensorID {
		return nil, refuse(ReasonSensor, "the accepted document is not sensor %s's", sensorID)
	}
	return slices.Clone(accepted), nil
}

// NeedsGrantRecord reports whether the node must write policy.apply with
// reason admin_keys before it applies the decision in an accepted reply
// (ruling 9, §1.1): the reply names a key set other than lastDigest, the
// digest of the node's latest admin_keys record ("" when there is none).
// sent is the request the reply answers, and accepted its AdminAcceptance.
//
// A reply to a request stamped 0.10 or later must name its key set: one
// without keys_digest is refused, so the node applies nothing. A reply to
// an older request names none and needs no record.
func NeedsGrantRecord(lastDigest string, sent *authz.CollectorRequest, accepted *authz.AdminAccepted) (bool, error) {
	if sent == nil || accepted == nil {
		return false, fmt.Errorf("netack: no request or acceptance")
	}
	if !authz.NamesAdminKeys(sent.Contract) {
		if accepted.KeysDigest != "" || accepted.Keys != nil {
			return false, fmt.Errorf("netack: the reply to a request stamped %s names a key set", sent.Contract)
		}
		return false, nil
	}
	if err := authz.ValidateAdminKeys(accepted.KeysDigest, accepted.Keys); err != nil {
		return false, fmt.Errorf("netack: the reply to a request stamped %s does not name its key set: %w", sent.Contract, err)
	}
	return accepted.KeysDigest != lastDigest, nil
}

// BuildAccepted builds the accepted document from a frozen draft and the
// authorized writers a person chose (deliverable 4; there is no admin
// client yet). It returns the document's bytes in C13 §8's canonical
// encoding, and both digests computed over the bytes it returns and the
// draft it was given, so what is shown is what is signed (HR-14). With no
// writers the document is the draft, and the digests are equal.
func BuildAccepted(draft []byte, writers []netobs.Writer) (doc []byte, baselineDigest, draftDigest string, err error) {
	if !netobs.IsCanonical(draft) {
		return nil, "", "", fmt.Errorf("netack: the draft is not a canonical network baseline")
	}
	b, err := netobs.DecodeBaseline(draft)
	if err != nil {
		return nil, "", "", err
	}
	if len(b.AuthorizedWriters) != 0 {
		return nil, "", "", fmt.Errorf("netack: the draft already has authorized writers")
	}
	b.AuthorizedWriters = slices.Clone(writers)
	netobs.SortBaseline(b)
	doc, err = b.Encode()
	if err != nil {
		return nil, "", "", err
	}
	if !netobs.OnlyWritersAdded(draft, doc) {
		return nil, "", "", fmt.Errorf("netack: the built document is not the draft with writers added")
	}
	return doc, netobs.Digest(doc), netobs.Digest(draft), nil
}

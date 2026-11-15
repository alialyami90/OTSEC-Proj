package authz

import (
	"fmt"
	"net/netip"
	"strconv"
)

// The sensor kinds (0.11, docs/phase4/D3-sensor-link.md §11.1, C7-1 to C7-3,
// D4-92). Each is a grant of its own: a key signs one only when its list
// names it, and neither is in DefaultAdminKinds (SL-7). The payload format
// stays AdminRequestFormat, so an older reader refuses either body as a
// payload error.
//
// No product path accepts, relays or applies either kind yet (D4-103 ruling
// 3, F-027's gate): the node does not relay them, and the collector's
// pipeline refuses a verified one. C7-4 (the reason against the pin) is the
// node's and the link agent's, C7-5 the collector's, and C7-6 the sensor's
// own verifier; each is owed by a later brief.
const (
	// KindNodeSensorEnrol pins one sensor and this node to each other.
	KindNodeSensorEnrol RequestKind = "node.sensor_enrol"
	// KindNodeSensorRevoke ends trust in one enrolment.
	KindNodeSensorRevoke RequestKind = "node.sensor_revoke"
	// sensorKindsSince is the minor that added the two kinds.
	sensorKindsSince = 11
)

// SensorEnrolReason is what an enrolment says it is (C7-2, C7-4).
type SensorEnrolReason string

const (
	SensorEnrolNew     SensorEnrolReason = "new"     // the first enrolment of a sensor, at generation 1
	SensorEnrolRenew   SensorEnrolReason = "renew"   // the same host and key, with a new not_after
	SensorEnrolRekey   SensorEnrolReason = "rekey"   // the same host made a new key
	SensorEnrolReplace SensorEnrolReason = "replace" // another host, or a re-imaged one, takes the sensor_id
)

// SensorRevokeReason is why a revocation ends trust (C7-3).
type SensorRevokeReason string

const (
	SensorRevokeCompromised SensorRevokeReason = "compromised"
	SensorRevokeLost        SensorRevokeReason = "lost"
	SensorRevokeRetired     SensorRevokeReason = "retired"
)

// NodeSensorEnrolBody (since 0.11) pins one sensor and this node to each
// other. The collector checks its shape only (C7-2): it does not know the
// node's sensors. not_after's comparison with issued_at is the node's (C8-2,
// check 6).
type NodeSensorEnrolBody struct {
	SensorID      string            `json:"sensor_id"`      // lowercase UUID, drawn by the administrator's client
	Generation    string            `json:"generation"`     // decimal from 1; one above this sensor_id's last enrolment
	SensorSPKI    string            `json:"sensor_spki"`    // "sha256:" and 64 hex digits, over the sensor key's SubjectPublicKeyInfo
	SensorAddress string            `json:"sensor_address"` // an IP literal and a port; never a hostname
	NodeSPKI      string            `json:"node_spki"`      // the node's link key, the same form
	NodeAddress   string            `json:"node_address"`   // an IP literal: the source the sensor admits
	NotAfter      string            `json:"not_after"`      // RFC 3339, UTC
	Reason        SensorEnrolReason `json:"reason"`
}

// NodeSensorRevokeBody (since 0.11) ends trust in one enrolment (C7-3).
type NodeSensorRevokeBody struct {
	SensorID    string             `json:"sensor_id"`
	Generation  string             `json:"generation"`
	SensorSPKI  string             `json:"sensor_spki"`
	Reason      SensorRevokeReason `json:"reason"`
	SuspectFrom string             `json:"suspect_from,omitempty"` // RFC 3339, UTC; absent means from enrolment
}

// ValidGeneration reports whether s is an enrolment's generation: a decimal
// from 1 in C13's form, canonical and within 64 bits.
func ValidGeneration(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n >= 1 && strconv.FormatUint(n, 10) == s
}

// ValidSPKI reports whether s is a key's pin: "sha256:" and 64 lowercase
// hex digits, over its SubjectPublicKeyInfo.
func ValidSPKI(s string) bool { return baselineDigestPattern.MatchString(s) }

// Validate checks the enrolment body as the collector does (payload).
func (b *NodeSensorEnrolBody) Validate() error {
	switch {
	case !sensorIDPattern.MatchString(b.SensorID):
		return refuse(RefuseInvalid, "sensor_id")
	case !ValidGeneration(b.Generation):
		return refuse(RefuseInvalid, "generation")
	case !ValidSPKI(b.SensorSPKI):
		return refuse(RefuseInvalid, "sensor_spki")
	case !ValidSPKI(b.NodeSPKI):
		return refuse(RefuseInvalid, "node_spki")
	case b.SensorSPKI == b.NodeSPKI:
		return refuse(RefuseInvalid, "sensor_spki and node_spki are the same key")
	case !validSensorAddress(b.SensorAddress):
		return refuse(RefuseInvalid, "sensor_address")
	case !validNodeAddress(b.NodeAddress):
		return refuse(RefuseInvalid, "node_address")
	}
	if _, err := parseUTC(b.NotAfter); err != nil {
		return refuse(RefuseInvalid, "not_after: %v", err)
	}
	switch b.Reason {
	case SensorEnrolNew, SensorEnrolRenew, SensorEnrolRekey, SensorEnrolReplace:
	default:
		return refuse(RefuseInvalid, "reason %q", b.Reason)
	}
	// Generation 1 is a sensor's first enrolment, which is new; a new one
	// is at generation 1 only.
	if (b.Reason == SensorEnrolNew) != (b.Generation == "1") {
		return refuse(RefuseInvalid, "reason %s at generation %s", b.Reason, b.Generation)
	}
	return nil
}

// Validate checks the revocation body as the collector does (payload).
// That suspect_from is not after issued_at needs the envelope, so
// AdminRequest.validate checks it.
func (b *NodeSensorRevokeBody) Validate() error {
	switch {
	case !sensorIDPattern.MatchString(b.SensorID):
		return refuse(RefuseInvalid, "sensor_id")
	case !ValidGeneration(b.Generation):
		return refuse(RefuseInvalid, "generation")
	case !ValidSPKI(b.SensorSPKI):
		return refuse(RefuseInvalid, "sensor_spki")
	}
	switch b.Reason {
	case SensorRevokeCompromised, SensorRevokeLost, SensorRevokeRetired:
	default:
		return refuse(RefuseInvalid, "reason %q", b.Reason)
	}
	if b.SuspectFrom != "" {
		if _, err := parseUTC(b.SuspectFrom); err != nil {
			return refuse(RefuseInvalid, "suspect_from: %v", err)
		}
	}
	return nil
}

// checkIssued refuses a suspect_from after the request's issued_at (C7-3):
// it would leave unmarked the records committed before it.
func (b *NodeSensorRevokeBody) checkIssued(issuedAt string) error {
	if b.SuspectFrom == "" {
		return nil
	}
	from, _ := parseUTC(b.SuspectFrom) // checked by Validate
	issued, _ := parseUTC(issuedAt)    // checked by AdminRequest.validate
	if from.After(issued) {
		return fmt.Errorf("suspect_from %s is after issued_at %s", b.SuspectFrom, issuedAt)
	}
	return nil
}

// validSensorAddress reports whether s is an IP literal and a port from 1
// to 65535, with no zone, in its one written form: 192.0.2.10:8443 or
// [2001:db8::10]:8443. A hostname never parses.
func validSensorAddress(s string) bool {
	ap, err := netip.ParseAddrPort(s)
	return err == nil && ap.Port() != 0 && ap.Addr().Zone() == "" && ap.String() == s
}

// validNodeAddress reports whether s is an IP literal with no port, no
// brackets and no zone, in its one written form.
func validNodeAddress(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == "" && a.String() == s
}

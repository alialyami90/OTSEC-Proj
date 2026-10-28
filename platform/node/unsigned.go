package node

import (
	"fmt"
	"slices"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/audit"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/modules/security/collectorwire"
)

// Unsigned administrator files (relay PR 2b, A3 on #181 and B1 on #339).
//
// clear-quarantine.json and seq-reset-ack.json are the Phase 2 interim way
// to tell the node something: a JSON file in admin_dir with no signature,
// protected only by the directory's ACL. A signed C7 request
// (node.quarantine_clear, node.seq_reset_ack; admin_actions.go) carries the
// administrator's key and a nonce, and the collector verifies it. So:
//
//   - On a node with a lab endpoint only (every endpoint of every asset has
//     target simulated), the unsigned files still work, and each one the node
//     acts on raises unsigned-admin-file-accepted and is named unsigned in
//     the audit record it causes.
//   - On a node with any endpoint that is not simulated, they are refused in
//     code: unsigned-admin-file-refused, once per file content, and nothing
//     is done. There is no flag that lifts this; the administrator signs a
//     request instead.
//   - When an unsigned file and a signed request in admin_dir name the same
//     clear (the same export, or the same install key), the unsigned file is
//     ignored (unsigned-admin-file-ignored): the signed one is acted on, and
//     the signed one only.
//     A signed request the collector has refused does not count.
//
// clear-suspension.json is not covered here: the node's suspension clear has
// no signed counterpart yet (the collector reads the same file for its own
// part), so refusing it would leave no way to clear a suspension on a
// non-lab node. That needs asset.clear_suspension relayed and acted on, and
// the collector's own refusal of the file; it is a separate PR.
const (
	// AlarmUnsignedAdminFileRefused: an unsigned file on a node with a
	// non-lab endpoint. Level 0 (asset-less), once per file content.
	AlarmUnsignedAdminFileRefused = "unsigned-admin-file-refused"
	// AlarmUnsignedAdminFileAccepted: the node acted on an unsigned file,
	// on a lab-only node.
	AlarmUnsignedAdminFileAccepted = "unsigned-admin-file-accepted"
	// AlarmUnsignedAdminFileIgnored: an unsigned file that a signed request
	// in admin_dir supersedes.
	AlarmUnsignedAdminFileIgnored = "unsigned-admin-file-ignored"
)

// LabOnly reports whether every endpoint of every asset has target
// simulated: the only nodes on which the unsigned administrator files are
// honoured. A node with no endpoint is lab-only, since nothing it holds is a
// device.
func (c *Config) LabOnly() bool {
	for _, a := range c.assets {
		for _, ep := range a.Endpoints {
			if ep.Target != asset.Simulated {
				return false
			}
		}
	}
	return true
}

// unsignedWants is what the signed requests in admin_dir name, read from
// their payloads before the collector has verified anything: enough to know
// that an unsigned file is superseded, never to act. A payload that does not
// decode names nothing.
type unsignedWants struct {
	quarantine map[string]bool // asset ID + " " + manifest SHA-256
	ack        map[string]bool // install key ID
}

func unsignedWantsOf(files []*adminFile) unsignedWants {
	w := unsignedWants{quarantine: map[string]bool{}, ack: map[string]bool{}}
	for _, f := range files {
		var p authz.AdminRequest
		if f.signed == nil || collectorwire.DecodeStrict(f.signed.Payload, &p) != nil {
			continue
		}
		switch f.kind {
		case authz.KindNodeQuarantineClear:
			if b := p.NodeQuarantineClear; b != nil && p.Kind == f.kind {
				w.quarantine[b.AssetID+" "+b.ManifestSHA256] = true
			}
		case authz.KindNodeSeqResetAck:
			if p.NodeSeqResetAck != nil && p.Kind == f.kind {
				w.ack[p.InstallKeyID] = true
			}
		}
	}
	return w
}

// signedWants reads admin_dir now and returns what its signed requests name,
// other than the ones the collector has refused: a request it refused is never
// acted on, so it must not withhold the unsigned file (B6 on #347). It is read
// at the moment of the check, not remembered from the relay's last scan, because
// the quarantine tick and the relay run on their own timers and a signed file
// may have arrived between them.
func (s *Scheduler) signedWants() unsignedWants {
	files, _, _ := s.scanAdmin()
	return unsignedWantsOf(slices.DeleteFunc(files, func(f *adminFile) bool {
		e, done := s.decided(f.id)
		return done && e.Outcome == audit.OutcomeDenied
	}))
}

// unsignedGate decides whether the node may act on the unsigned file name
// (content hash sum). superseded says, from what the signed requests in
// admin_dir name now, that one names the same thing. It raises the alarm for a refusal or an ignored file, once per file
// content, and returns whether to go on.
func (s *Scheduler) unsignedGate(name, sum string, superseded func(unsignedWants) bool) bool {
	if !s.rt.cfg.LabOnly() {
		s.raiseOnceKey(AlarmUnsignedAdminFileRefused+" "+sum, "", AlarmUnsignedAdminFileRefused,
			fmt.Sprintf("%s is not signed, and this node has an endpoint that is not simulated, so it is not acted on. Sign a request (node.quarantine_clear, node.seq_reset_ack) instead", name))
		return false
	}
	if superseded(s.signedWants()) {
		s.raiseOnceKey(AlarmUnsignedAdminFileIgnored+" "+sum, "", AlarmUnsignedAdminFileIgnored,
			fmt.Sprintf("%s is not acted on: a signed request in admin_dir names the same clear, and only the signed one is acted on. Remove the unsigned file", name))
		return false
	}
	return true
}

// unsignedAccepted raises AlarmUnsignedAdminFileAccepted for a file the node
// acted on.
func (s *Scheduler) unsignedAccepted(name, sum, assetID string) {
	s.raiseOnceKey(AlarmUnsignedAdminFileAccepted+" "+sum, assetID, AlarmUnsignedAdminFileAccepted,
		fmt.Sprintf("%s is an unsigned administrator file, acted on because every endpoint of this node is simulated; a node with a device endpoint refuses it", name))
}

// unsignedSuffix is added to the source a record names, so the audit record
// of an unsigned clear says so.
const unsignedSuffix = " (unsigned file)"

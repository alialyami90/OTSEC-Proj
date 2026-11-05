package audit

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/authz"
)

// The advisory actions (0.11, C11 1.5 and section 3 of
// docs/phase4/C3-c11-advisory.md): the node's record of a set it installed,
// and of a set file it refused.
const (
	ActionAdvisorySetInstalled Action = "advisory.set_installed"
	ActionAdvisorySetRefused   Action = "advisory.set_refused"
)

// advisorySince is the minor that added the advisory actions and Advisory.
const advisorySince = 11

// Advisory is on the advisory actions only (0.11), required there.
//
// On advisory.set_installed (outcome succeeded) it names the set installed:
// set_id, version, issued_at, the payload's SHA-256 and the signing key,
// and previous_version, the version it replaced, absent on a node's first
// set (and so on the first set after a store reset, which AP-29 lists).
//
// On advisory.set_refused (outcome denied, reason_code a C11 refusal code)
// it carries the refused file's SHA-256, and set_id, version and key_id only
// when C11's verifier had checked them before the refusal (advisory.Refusal).
// The node writes one per refused file's SHA-256, not one per read.
type Advisory struct {
	SetID           string `json:"set_id,omitempty"`
	Version         uint64 `json:"version,omitempty"`
	IssuedAt        string `json:"issued_at,omitempty"`
	PayloadSHA256   string `json:"payload_sha256,omitempty"`
	KeyID           string `json:"key_id,omitempty"`
	PreviousVersion uint64 `json:"previous_version,omitempty"`
	FileSHA256      string `json:"file_sha256,omitempty"`
}

func (r *Record) validateAdvisory(minor int) error {
	installed := r.Action == ActionAdvisorySetInstalled
	refused := r.Action == ActionAdvisorySetRefused
	if !installed && !refused {
		if r.Advisory != nil {
			return fmt.Errorf("audit: advisory belongs on the advisory actions, not %s", r.Action)
		}
		return nil
	}
	a := r.Advisory
	switch {
	case a == nil:
		return fmt.Errorf("audit: %s needs advisory", r.Action)
	case minor < advisorySince:
		return fmt.Errorf("audit: advisory is new in 0.%d, so a 0.%d record cannot carry it", advisorySince, minor)
	case r.Actor.Type != authz.PrincipalNode:
		return fmt.Errorf("audit: %s is the node's record (actor type node)", r.Action)
	case a.SetID != "" && !setIDPattern(a.SetID):
		return errors.New("audit: advisory set_id is not a C11 set ID")
	case a.KeyID != "" && !adminKeyIDPattern.MatchString(a.KeyID):
		return errors.New("audit: advisory key_id is not ed25519-<16 hex>")
	}
	if installed {
		switch {
		case r.Outcome != OutcomeSucceeded:
			return errors.New("audit: advisory.set_installed is succeeded")
		case a.SetID == "" || a.Version == 0 || a.KeyID == "":
			return errors.New("audit: advisory.set_installed needs set_id, version and key_id")
		case !hashPattern.MatchString(a.PayloadSHA256):
			return errors.New("audit: advisory.set_installed needs payload_sha256, 64 lowercase hex digits")
		case !utcZ(a.IssuedAt):
			return errors.New("audit: advisory issued_at is not RFC 3339 UTC with Z")
		case a.PreviousVersion >= a.Version && a.PreviousVersion != 0:
			return errors.New("audit: advisory previous_version is not below version")
		case a.FileSHA256 != "":
			return errors.New("audit: file_sha256 belongs on advisory.set_refused")
		}
		return nil
	}
	switch {
	case r.Outcome != OutcomeDenied:
		return errors.New("audit: advisory.set_refused is denied")
	case !slices.Contains(advisory.Codes, advisory.Code(r.ReasonCode)):
		return fmt.Errorf("audit: %q is not a C11 refusal code", r.ReasonCode)
	case !hashPattern.MatchString(a.FileSHA256):
		return errors.New("audit: advisory.set_refused needs file_sha256, 64 lowercase hex digits")
	case (a.SetID == "") != (a.Version == 0):
		return errors.New("audit: advisory set_id and version go together")
	case a.PayloadSHA256 != "" || a.IssuedAt != "" || a.PreviousVersion != 0:
		return errors.New("audit: advisory.set_refused carries no payload_sha256, issued_at or previous_version")
	}
	return nil
}

// setIDPattern is C11's set ID form.
func setIDPattern(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

func utcZ(s string) bool {
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && strings.HasSuffix(s, "Z")
}

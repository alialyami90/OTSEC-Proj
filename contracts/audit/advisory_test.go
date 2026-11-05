package audit

import (
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/authz"
)

func advisoryRec(action Action) *Record {
	r := &Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 30, PrevHash: strings.Repeat("6", 64), Time: baseTime(),
		Actor: Actor{Type: authz.PrincipalNode, ID: "site-a-node-1"}, Action: action}
	switch action {
	case ActionAdvisorySetInstalled:
		r.Outcome = OutcomeSucceeded
		r.Advisory = &Advisory{SetID: "otsec-sel", Version: 8, IssuedAt: "2026-11-05T00:00:00Z",
			PayloadSHA256: strings.Repeat("ab", 32), KeyID: "ed25519-3a9102fbf7b9c919", PreviousVersion: 7}
	case ActionAdvisorySetRefused:
		r.Outcome, r.ReasonCode = OutcomeDenied, string(advisory.OlderVersion)
		r.Advisory = &Advisory{SetID: "otsec-sel", Version: 6, KeyID: "ed25519-3a9102fbf7b9c919", FileSHA256: strings.Repeat("cd", 32)}
	}
	return r
}

func TestAdvisoryRecords(t *testing.T) {
	for _, a := range []Action{ActionAdvisorySetInstalled, ActionAdvisorySetRefused} {
		if err := advisoryRec(a).Validate(); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	// The first set has no previous_version.
	first := advisoryRec(ActionAdvisorySetInstalled)
	first.Advisory.PreviousVersion = 0
	if err := first.Validate(); err != nil {
		t.Fatalf("first set: %v", err)
	}
	// A refusal before the envelope's key ID was checked carries the file's
	// hash alone; every C11 code is a reason.
	for _, c := range advisory.Codes {
		r := advisoryRec(ActionAdvisorySetRefused)
		r.ReasonCode, r.Advisory = string(c), &Advisory{FileSHA256: strings.Repeat("cd", 32)}
		if err := r.Validate(); err != nil {
			t.Errorf("refused %s with the file hash only: %v", c, err)
		}
	}

	for name, c := range map[string]struct {
		action Action
		mut    func(*Record)
	}{
		"installed stamped 0.10":             {ActionAdvisorySetInstalled, func(r *Record) { r.Contract = "otsec.audit/0.10" }},
		"refused stamped 0.10":               {ActionAdvisorySetRefused, func(r *Record) { r.Contract = "otsec.audit/0.10" }},
		"installed with no advisory":         {ActionAdvisorySetInstalled, func(r *Record) { r.Advisory = nil }},
		"installed by a person":              {ActionAdvisorySetInstalled, func(r *Record) { r.Actor = Actor{Type: authz.PrincipalHuman, ID: "alice"} }},
		"installed denied":                   {ActionAdvisorySetInstalled, func(r *Record) { r.Outcome, r.ReasonCode = OutcomeDenied, "invalid" }},
		"installed without key_id":           {ActionAdvisorySetInstalled, func(r *Record) { r.Advisory.KeyID = "" }},
		"installed without payload_sha256":   {ActionAdvisorySetInstalled, func(r *Record) { r.Advisory.PayloadSHA256 = "" }},
		"installed with a local issued_at":   {ActionAdvisorySetInstalled, func(r *Record) { r.Advisory.IssuedAt = "2026-11-05T03:00:00+03:00" }},
		"installed not above previous":       {ActionAdvisorySetInstalled, func(r *Record) { r.Advisory.PreviousVersion = 8 }},
		"installed with file_sha256":         {ActionAdvisorySetInstalled, func(r *Record) { r.Advisory.FileSHA256 = strings.Repeat("cd", 32) }},
		"installed with a bad set_id":        {ActionAdvisorySetInstalled, func(r *Record) { r.Advisory.SetID = "-otsec" }},
		"refused succeeded":                  {ActionAdvisorySetRefused, func(r *Record) { r.Outcome, r.ReasonCode = OutcomeSucceeded, "" }},
		"refused with a C7 code":             {ActionAdvisorySetRefused, func(r *Record) { r.ReasonCode = string(authz.RefusePrincipal) }},
		"refused without file_sha256":        {ActionAdvisorySetRefused, func(r *Record) { r.Advisory.FileSHA256 = "" }},
		"refused with set_id but no version": {ActionAdvisorySetRefused, func(r *Record) { r.Advisory.Version = 0 }},
		"refused with payload_sha256":        {ActionAdvisorySetRefused, func(r *Record) { r.Advisory.PayloadSHA256 = strings.Repeat("ab", 32) }},
		"refused with a bad key_id":          {ActionAdvisorySetRefused, func(r *Record) { r.Advisory.KeyID = "ed25519-<script>" }},
		"advisory on another action":         {ActionAdvisorySetInstalled, func(r *Record) { r.Action = ActionServiceStart; r.Outcome = OutcomeInfo }},
	} {
		r := advisoryRec(c.action)
		c.mut(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

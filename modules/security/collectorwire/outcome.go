package collectorwire

import (
	"encoding/json"
	"errors"
	"fmt"

	"otsec.local/otsec/contracts/authz"
)

// WireID identifies this framing and the RunOutcome shape. A reader refuses
// any other value.
const WireID = "otsec.collectorwire/0.1"

// MaxOutcomeRecords bounds the audit records one run may report. A run is
// one session of a few register operations; 256 leaves room for a refusal
// record per line without letting a faulty collector flood the node.
const MaxOutcomeRecords = 256

// RunOutcome is what the collector sends after an accepted run: the C2
// result exactly as the adapter produced it and checked by the collector
// (Validate, CheckLines, CheckAgainst), and the pending C8 records of the
// events the collector reports for that run, each carrying its
// collector_seq. The node checks both (collectorclient) and writes the
// records; the collector writes no audit record itself (C7-A5-2).
type RunOutcome struct {
	Wire         string            `json:"wire"`
	InvocationID string            `json:"invocation_id"`
	Result       json.RawMessage   `json:"result"`
	Audit        []json.RawMessage `json:"audit"`
}

// EncodeOutcome encodes an outcome and checks it fits one frame.
func EncodeOutcome(o RunOutcome) ([]byte, error) {
	o.Wire = WireID
	if o.Audit == nil {
		o.Audit = []json.RawMessage{}
	}
	if len(o.Audit) > MaxOutcomeRecords {
		return nil, fmt.Errorf("collectorwire: %d audit records, limit %d", len(o.Audit), MaxOutcomeRecords)
	}
	b, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxOutcomeBytes {
		return nil, fmt.Errorf("%w: outcome %d bytes", ErrFrameTooLarge, len(b))
	}
	return b, nil
}

// DecodeOutcome decodes an outcome strictly. It checks the envelope only;
// collectorclient checks the result and the records against the reply.
func DecodeOutcome(b []byte) (RunOutcome, error) {
	var o RunOutcome
	if err := DecodeStrict(b, &o); err != nil {
		return RunOutcome{}, fmt.Errorf("collectorwire: outcome: %w", err)
	}
	if o.Wire != WireID {
		return RunOutcome{}, fmt.Errorf("collectorwire: outcome wire %q, want %q", o.Wire, WireID)
	}
	if o.InvocationID == "" || len(o.Result) == 0 || o.Audit == nil {
		return RunOutcome{}, errors.New("collectorwire: outcome needs invocation_id, result and audit")
	}
	if len(o.Audit) > MaxOutcomeRecords {
		return RunOutcome{}, fmt.Errorf("collectorwire: %d audit records, limit %d", len(o.Audit), MaxOutcomeRecords)
	}
	return o, nil
}

// DecodeReply decodes a CollectorReply strictly: an unknown field, a
// duplicate key or trailing data is an error, and so is a reply whose C7
// 0.5 fields its stamp or status rules out (authz.CollectorReply.Validate).
// It does not otherwise judge the reply; a caller still uses Accepted,
// which fails closed.
func DecodeReply(b []byte) (authz.CollectorReply, error) {
	var r authz.CollectorReply
	if err := DecodeStrict(b, &r); err != nil {
		return authz.CollectorReply{}, fmt.Errorf("collectorwire: reply: %w", err)
	}
	if err := r.Validate(); err != nil {
		return authz.CollectorReply{}, fmt.Errorf("collectorwire: reply: %w", err)
	}
	return r, nil
}

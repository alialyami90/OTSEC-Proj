package collectorwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

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
// duplicate key or trailing data is an error. It does not judge the reply;
// a caller still uses Accepted, which fails closed.
func DecodeReply(b []byte) (authz.CollectorReply, error) {
	var r authz.CollectorReply
	if err := DecodeStrict(b, &r); err != nil {
		return authz.CollectorReply{}, fmt.Errorf("collectorwire: reply: %w", err)
	}
	return r, nil
}

// DecodeStrict decodes one JSON value into v and refuses what a lenient
// decoder would let through: invalid UTF-8, a duplicate object key at any
// depth (which a reader could resolve differently from the writer), a field
// v does not define, and anything after the value. The contracts have the
// same rules in their own strict decoder (D1-10), which is internal to
// contracts/.
func DecodeStrict(b []byte, v any) error {
	if !utf8.Valid(b) {
		return errors.New("not UTF-8")
	}
	if err := checkDuplicateKeys(b); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// checkDuplicateKeys walks the token stream and refuses an object that
// names a key twice. Keys are compared exactly and also case-folded,
// because encoding/json matches field names case-insensitively, so "Kind"
// and "kind" would land in the same field.
func checkDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	type frame struct {
		object bool
		keys   map[string]bool
		key    bool // the next token in this object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.key {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				continue
			}
			k, ok := tok.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			fk := strings.ToLower(k)
			if top.keys[fk] {
				return fmt.Errorf("duplicate key %q", k)
			}
			top.keys[fk] = true
			top.key = false
			continue
		}
		if top != nil && top.object {
			top.key = true // the value is consumed below; the next token is a key
		}
		switch d, _ := tok.(json.Delim); d {
		case '{':
			stack = append(stack, &frame{object: true, keys: map[string]bool{}, key: true})
		case '[':
			stack = append(stack, &frame{})
		case ']':
			stack = stack[:len(stack)-1]
		}
	}
}

package audit

import (
	"encoding/json"
	"fmt"

	"otsec.local/otsec/contracts/internal/strictjson"
)

// A producer cannot know a record's seq or prev_hash: both exist only when
// the store commits it, in order, after the record before it (C5 group
// commit). So a producer hands the store a pending record, with seq 0 and no
// prev_hash, and the store seals it inside the commit transaction:
//
//	prev := hash of the last stored record (GenesisPrevHash on a new node)
//	for each pending record in the batch, in order:
//		stored, err := Seal(pending, lastSeq+1, prev)
//		store stored exactly; prev = Hash(stored); lastSeq++
//
// Seal is the only place a record is encoded. From then on the stored bytes
// are never re-encoded: readers, forwarders and exports carry them as they
// are, and VerifyChain hashes them as they are.

// ValidatePending checks a record a producer hands to the store. It applies
// every ParseRecord rule except the chain fields, which must be absent, and
// it decodes with the shared strict decoder (D1-10), so an unknown field is
// rejected: Seal re-encodes the record from its fields, so an unknown one
// would be dropped silently. A secret-named field is unknown, so it is
// rejected too.
func ValidatePending(pending []byte) (*Record, error) {
	if len(pending) > MaxRecordBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrRecordRejected, len(pending))
	}
	var r Record
	if err := strictjson.Decode(pending, &r); err != nil {
		return nil, fmt.Errorf("%w: pending record: %v", ErrRecordRejected, err)
	}
	if r.Seq != 0 || r.PrevHash != "" {
		return nil, fmt.Errorf("%w: a pending record carries no seq or prev_hash; the store assigns them", ErrRecordRejected)
	}
	probe := r
	probe.Seq, probe.PrevHash = 2, Hash(nil)
	if r.Action == ActionAuditChainStart {
		probe.Seq, probe.PrevHash = 1, GenesisPrevHash
	}
	if err := probe.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordRejected, err)
	}
	return &r, nil
}

// Seal assigns seq and prev_hash to a pending record and returns the bytes
// to store. The result passes ParseRecord, so a record that would not verify
// is never stored.
func Seal(pending []byte, seq uint64, prevHash string) ([]byte, error) {
	r, err := ValidatePending(pending)
	if err != nil {
		return nil, err
	}
	r.Seq, r.PrevHash = seq, prevHash
	out, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordRejected, err)
	}
	if _, err := ParseRecord(out); err != nil {
		return nil, err
	}
	return out, nil
}

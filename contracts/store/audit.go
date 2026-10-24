package store

import (
	"context"
	"crypto/sha256"
)

// Audit records (class audit) are C8 records, not C4 events. A node has one
// audit stream, and its records form one hash chain: each record carries its
// seq and the SHA-256 of the exact stored bytes of the record before it.
// Neither value exists until the store commits the record after its
// predecessor, so the store seals records inside the commit transaction and
// never re-encodes them afterwards (A3 review of C5, C5-A3-1).

// ChainLink is one position of the audit chain: a seq and the SHA-256 of the
// exact bytes stored at it. Seq 0 with the chain's genesis hash is the
// position before the first record.
// TODO(C8): becomes audit.Checkpoint.
type ChainLink struct {
	Seq  Seq
	Hash [32]byte
}

// AuditChain is the part of C8 the store calls.
// TODO(C8): an adapter over audit.ValidatePending, audit.Seal and
// audit.GenesisPrevHash once C8 merges.
type AuditChain interface {
	// ValidatePending checks a pending record, which has no seq and no
	// previous hash yet.
	ValidatePending(pending []byte) error
	// Seal returns the record's final bytes with seq and prevHash in them.
	Seal(pending []byte, seq Seq, prevHash [32]byte) ([]byte, error)
	// Genesis is the previous hash of a node's first record.
	Genesis() [32]byte
}

// SealAudit seals a batch of pending audit records after head, the link of
// the last stored record (ChainLink{0, chain.Genesis()} on a new node). A
// Committer calls it inside the CommitBatch transaction for class audit,
// stores sealed[i] exactly as the Event of record i, and stores the returned
// head in the same transaction. Outbox.Read returns those bytes unchanged.
//
// Every record is validated before any is sealed. On error nothing may be
// written, and the Committer returns the error, which has CodeInvalid.
func SealAudit(chain AuditChain, head ChainLink, recs []Record) ([][]byte, ChainLink, error) {
	for i, r := range recs {
		if r.Class != ClassAudit {
			return nil, head, errf(CodeInvalid, nil, "record %d of an audit batch has class %s", i, r.Class)
		}
		if err := chain.ValidatePending(r.Event); err != nil {
			return nil, head, errf(CodeInvalid, err, "audit record %d is not a valid pending record", i)
		}
	}
	sealed := make([][]byte, len(recs))
	for i, r := range recs {
		b, err := chain.Seal(r.Event, head.Seq+1, head.Hash)
		if err != nil {
			return nil, head, errf(CodeInvalid, err, "sealing audit record %d", i)
		}
		sealed[i] = b
		head = ChainLink{Seq: head.Seq + 1, Hash: sha256.Sum256(b)}
	}
	return sealed, head, nil
}

// AuditBeforeAct appends rec, the audit record of a privileged operation or
// of a collector request that uses a credential, and runs act only once rec
// holds a Receipt (C5-A3-3, A1 D1-11). With no receipt, for any reason, act
// does not run and the error has CodeAuditUnavailable. The reasons include a
// stopped Log, a full audit quota, an audit database that is not open (l is
// nil) and a cancelled ctx. The caller reports the refusal through node
// status, because the audit store may be what failed.
func AuditBeforeAct(ctx context.Context, l *Log, rec Record, act func(Receipt) error) error {
	if rec.Class != ClassAudit {
		return errf(CodeInvalid, nil, "AuditBeforeAct needs an audit record, got class %s", rec.Class)
	}
	if l == nil {
		return errf(CodeAuditUnavailable, nil, "audit store not open; operation refused")
	}
	r, err := l.Append(ctx, rec)
	if err != nil {
		return errf(CodeAuditUnavailable, err, "no audit receipt; operation refused")
	}
	return act(r)
}

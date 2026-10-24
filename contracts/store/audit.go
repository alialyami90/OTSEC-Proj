package store

import (
	"context"

	"otsec.local/otsec/contracts/audit"
)

// Audit records (class audit) are C8 records, not C4 events. A node has one
// audit stream, and its records form one hash chain: each record carries its
// seq and the SHA-256 of the exact stored bytes of the record before it.
// Neither value exists until the store commits the record after its
// predecessor, so the store seals records inside the commit transaction and
// never re-encodes them afterwards (A3 review of C5, C5-A3-1).

// ChainLink is one position of the audit chain: the node, a seq and the
// chain hash (audit.Hash) of the exact bytes stored at it. It is C8's
// Checkpoint, so a ChainAnchor can be passed to audit.VerifyChain as from.
type ChainLink = audit.Checkpoint

// GenesisLink is the position before a node's first audit record.
func GenesisLink(n NodeID) ChainLink {
	return ChainLink{NodeID: string(n), Seq: 0, Hash: audit.GenesisPrevHash}
}

// SealAudit seals a batch of pending C8 records after head, the link of the
// last stored record (GenesisLink on a new node). A Committer calls it inside
// the CommitBatch transaction for class audit, stores sealed[i] exactly as
// the Event of record i, and stores the returned head in the same
// transaction. Outbox.Read returns those bytes unchanged.
//
// Every record is checked with audit.ValidatePending, and must name head's
// node, before any is sealed; audit.Seal then requires seq 1 to be the
// audit.chain.start record. On error nothing may be written, and the
// Committer returns the error, which has CodeInvalid.
func SealAudit(head ChainLink, recs []Record) ([][]byte, ChainLink, error) {
	for i, r := range recs {
		if r.Class != ClassAudit {
			return nil, head, errf(CodeInvalid, nil, "record %d of an audit batch has class %s", i, r.Class)
		}
		p, err := audit.ValidatePending(r.Event)
		if err != nil {
			return nil, head, errf(CodeInvalid, err, "audit record %d is not a valid pending record", i)
		}
		if p.NodeID != head.NodeID {
			return nil, head, errf(CodeInvalid, nil, "audit record %d is for node %s, the chain is %s", i, p.NodeID, head.NodeID)
		}
	}
	sealed := make([][]byte, len(recs))
	for i, r := range recs {
		b, err := audit.Seal(r.Event, head.Seq+1, head.Hash)
		if err != nil {
			return nil, head, errf(CodeInvalid, err, "sealing audit record %d", i)
		}
		sealed[i] = b
		head = ChainLink{NodeID: head.NodeID, Seq: head.Seq + 1, Hash: audit.Hash(b)}
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
	if c, ok := l.ClassOf(rec.Stream); !ok || c != ClassAudit {
		return errf(CodeInvalid, nil, "stream %s is not this log's audit stream; operation refused", rec.Stream)
	}
	r, err := l.Append(ctx, rec)
	if err != nil {
		return errf(CodeAuditUnavailable, err, "no audit receipt; operation refused")
	}
	if r.Key().Stream != rec.Stream {
		return errf(CodeAuditUnavailable, nil, "receipt for stream %s, not %s; operation refused", r.Key().Stream, rec.Stream)
	}
	return act(r)
}

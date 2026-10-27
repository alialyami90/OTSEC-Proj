package store

import "context"

// HoldCode is why a record is held (0.4). Closed set.
type HoldCode string

const (
	// HoldBaseline: the record is an asset's acknowledged baseline. Ref is
	// the accepted node.baseline_ack C8 record.
	HoldBaseline HoldCode = "baseline"
	// HoldUnapprovedDifference: the record is a snapshot or difference
	// whose change is not yet approved or acknowledged. Ref is the
	// config.change_detected C8 record.
	HoldUnapprovedDifference HoldCode = "unapproved-difference"
)

// HoldReason names the C8 record that justifies a hold, never free text
// (B3 on #246), so a reviewer or the node's start-up reconcile can check
// each hold against the audit stream.
type HoldReason struct {
	Code HoldCode
	// Ref is the key of the C8 record in the node's audit stream.
	Ref Key
}

// Validate checks the reason.
func (r HoldReason) Validate() error {
	if r.Code != HoldBaseline && r.Code != HoldUnapprovedDifference {
		return errf(CodeInvalid, nil, "unknown hold code %q", r.Code)
	}
	if !r.Ref.NodeID.Valid() || !r.Ref.Stream.Valid() || r.Ref.Seq == 0 {
		return errf(CodeInvalid, nil, "hold reason %s names no C8 record: %v", r.Code, r.Ref)
	}
	return nil
}

// Hold names one record to hold and why.
type Hold struct {
	// Stream and Seq name the record. In Record.Holds an empty Stream is
	// the record's own stream, and Seq 0 is the record itself.
	Stream StreamID
	Seq    Seq
	Reason HoldReason
}

// HeldRecord is one hold as Holder.Held lists it.
type HeldRecord struct {
	Seq    Seq
	Reason HoldReason
	// Bytes is what the hold keeps: the event, and its capture when no
	// unheld record refers to it.
	Bytes int64
}

// Holder keeps records that pruning must not remove (0.4): an asset's
// acknowledged baseline, and any snapshot or difference with an
// unapproved change. Only configuration-class records can be held; a hold
// on any other class is refused with CodeNotHoldable, so a hold never pins
// events or audit. A hold is kept in the database beside the record and
// survives a restart. It is derived state: the C8 records are the
// authority, and the node reconciles its holds with them at start
// (AlarmHoldsReconciled).
type Holder interface {
	// Hold holds a stored record, in one transaction committed at
	// SyncFull. Holding a held record again replaces its reason.
	Hold(ctx context.Context, h Hold) error
	// Release ends the hold on stream's seq, in one transaction committed
	// at SyncFull. Releasing a record that is not held is not an error.
	// The node releases only after the C8 record that ends the hold has a
	// Receipt (audit before act).
	Release(ctx context.Context, stream StreamID, seq Seq) error
	// Held lists stream's holds in seq order.
	Held(ctx context.Context, stream StreamID) ([]HeldRecord, error)
}

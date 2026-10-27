package node

import (
	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
)

// The commit cap of the evidence database (C5 0.4, D4-9). An SER read is one
// atomic batch: its events, its capture and the device cursor commit
// together or not at all, so the database's MaxCommitBytes must be at least
// the largest read the node can build, and the recovery reserve is sized
// from it (c5.RecoveryReserveFor). B1 ruled the cap is a bound derived by
// construction, not a measured sample, and a test holds it (serbound_test.go).
//
// One read is at most
//
//	MaxResponseBytes × (1 + k) + MaxReadRowsCeiling × F + H
//
// where the first term is the capture plus the encoded bytes each row byte
// can add to its event, and:
//   - k (SERBytesPerRowByteX100/100) is the most encoded bytes one byte of a
//     row adds to its event. A row's bytes appear in native.bytes (base64,
//     4/3), in native.fields, in normalized (subject or value), in
//     collection.native_position (the row number), and in
//     device_time.native (date and time), so at most 4/3 + 1 + 1 + 1 for a
//     parsed row, 3.34 measured. 4.34 is B1's figure, one more than that. It
//     holds for rows the SEL-751 adapter marks parsed, whose grammar has no
//     character that JSON escapes (modules/ied/sel751 serRowRE: digits,
//     dates, and [A-Za-z0-9_] and [A-Za-z] for the element and state). The
//     normalizer itself accepts any C2-valid result, and a result whose
//     parsed row held escapable characters would be larger (a '<' costs
//     six bytes in each copy); such a read is refused by the Log over the
//     cap and quarantined (commitResult), never partly stored.
//   - F (SERFixedEventBytes) is the fixed part of one event: everything
//     but the bytes copied from its row.
//   - H (SERHealthBytes) is the read's health events.
//
// The device cursor is not counted by the Log (it counts events and
// captures); at most MaxReadRowsCeiling alignment keys of 71 bytes, about
// 143 KiB, and the 10% in CommitWALBytes covers it.
const (
	SERBytesPerRowByteX100 = 434
	SERFixedEventBytes     = 2560
	SERHealthBytes         = 64 << 10

	// MaxOperationBytes is the longest schedule operation ID the
	// configuration accepts: it is in every SER event, so it is part of F.
	MaxOperationBytes = 64
)

// SERReadBound is the most event, capture and health bytes one SER read
// can commit.
const SERReadBound = adapter.MaxResponseBytes + adapter.MaxResponseBytes*SERBytesPerRowByteX100/100 +
	asset.MaxReadRowsCeiling*SERFixedEventBytes + SERHealthBytes

// SERCommitBytes is the evidence database's MaxCommitBytes: SERReadBound
// rounded up to a MiB. serbound_test.go fails if the bound rises above it.
const SERCommitBytes int64 = 11 << 20

// groupFor is the group-commit options of database d: the node's options
// with the database's commit cap. The evidence database's cap is the SER
// bound; every other database keeps c5's default, 1 MiB, unless the caller
// set one.
func groupFor(d c5.Database, g c5.GroupOptions) c5.GroupOptions {
	if g.MaxCommitBytes == 0 && d.ID == EvidenceDB {
		g.MaxCommitBytes = SERCommitBytes
	}
	return g
}

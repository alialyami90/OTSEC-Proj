package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	c5 "otsec.local/otsec/contracts/store"
)

var _ c5.Holder = (*DB)(nil)

// holdsSchema is created in a database whose layout holds the
// configuration class (C5 0.4), and only there, so a 0.3 database opens
// unchanged. A hold is keyed by the record it holds; its reason names the
// C8 record that justifies it.
const holdsSchema = `
CREATE TABLE IF NOT EXISTS holds (
	stream     TEXT NOT NULL,
	seq        INTEGER NOT NULL,
	code       TEXT NOT NULL,
	ref_node   TEXT NOT NULL,
	ref_stream TEXT NOT NULL,
	ref_seq    INTEGER NOT NULL,
	PRIMARY KEY (stream, seq)
) WITHOUT ROWID;
`

// holdable reports whether this database's layout holds the configuration
// class, the only class whose records may be held.
func holdable(db c5.Database) bool {
	for _, c := range db.Classes {
		if c == c5.ClassConfiguration {
			return true
		}
	}
	return false
}

// ensureHolds creates the holds table if the layout needs it. The caller
// holds d.mu, or is open.
func (d *DB) ensureHolds(ctx context.Context) error {
	if !holdable(d.opt.Database) || d.readOnly {
		return nil
	}
	return d.tx(ctx, "holds", func() error {
		_, err := d.conn.ExecContext(ctx, holdsSchema)
		return err
	})
}

// hasHolds reports whether the holds table exists. A database that never
// held the configuration class has none, and nothing in it is held.
func (d *DB) hasHolds(ctx context.Context) (bool, error) {
	var n int
	err := d.conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'holds'`).Scan(&n)
	return n > 0, err
}

// checkHold refuses a hold on a stream that is not of the configuration
// class in this database. The caller holds d.mu.
func (d *DB) checkHold(stream c5.StreamID) error {
	class, ok := d.streams[stream]
	switch {
	case !ok:
		return codeErr(c5.CodeNotHoldable, nil, "database %s holds no stream %s", d.opt.Database.ID, stream)
	case class != c5.ClassConfiguration:
		return codeErr(c5.CodeNotHoldable, nil, "stream %s is %s; only configuration records may be held", stream, class)
	}
	return nil
}

// putHold writes one hold inside the caller's transaction. The record must
// be stored. Holding a held record again replaces its reason.
func (d *DB) putHold(ctx context.Context, h c5.Hold) error {
	var one int
	err := d.conn.QueryRowContext(ctx, `SELECT 1 FROM events WHERE stream = ? AND seq = ?`, string(h.Stream), int64(h.Seq)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return codeErr(c5.CodeNotHoldable, nil, "%s seq %d is not stored", h.Stream, h.Seq)
	}
	if err != nil {
		return err
	}
	_, err = d.conn.ExecContext(ctx, `INSERT INTO holds (stream, seq, code, ref_node, ref_stream, ref_seq) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (stream, seq) DO UPDATE SET code = excluded.code, ref_node = excluded.ref_node,
			ref_stream = excluded.ref_stream, ref_seq = excluded.ref_seq`,
		string(h.Stream), int64(h.Seq), string(h.Reason.Code),
		string(h.Reason.Ref.NodeID), string(h.Reason.Ref.Stream), int64(h.Reason.Ref.Seq))
	return err
}

// Hold implements c5.Holder.
func (d *DB) Hold(ctx context.Context, h c5.Hold) error {
	if err := h.Reason.Validate(); err != nil {
		return err
	}
	if h.Seq == 0 {
		return invalid("hold on %s names no seq", h.Stream)
	}
	if err := d.lock(); err != nil {
		return err
	}
	defer d.mu.Unlock()
	if err := d.checkHold(h.Stream); err != nil {
		return err
	}
	var refusal error
	err := d.tx(ctx, "hold", func() error {
		if err := d.putHold(ctx, h); err != nil {
			if errors.Is(err, &c5.Error{Code: c5.CodeNotHoldable}) {
				refusal = err
			}
			return err
		}
		return nil
	})
	if refusal != nil && err == refusal {
		return refusal
	}
	return err
}

// Release implements c5.Holder.
func (d *DB) Release(ctx context.Context, stream c5.StreamID, seq c5.Seq) error {
	if err := d.lock(); err != nil {
		return err
	}
	defer d.mu.Unlock()
	if err := d.checkHold(stream); err != nil {
		return err
	}
	return d.tx(ctx, "release", func() error {
		_, err := d.conn.ExecContext(ctx, `DELETE FROM holds WHERE stream = ? AND seq = ?`, string(stream), int64(seq))
		return err
	})
}

// Held implements c5.Holder. Bytes is the event and its source cursor, as
// the quota counts them, plus its capture when no unheld record refers to
// it.
func (d *DB) Held(ctx context.Context, stream c5.StreamID) ([]c5.HeldRecord, error) {
	if err := d.lock(); err != nil {
		return nil, err
	}
	defer d.mu.Unlock()
	if err := d.checkHold(stream); err != nil {
		return nil, err
	}
	if ok, err := d.hasHolds(ctx); err != nil || !ok {
		return nil, err
	}
	rows, err := d.conn.QueryContext(ctx, `SELECT h.seq, h.code, h.ref_node, h.ref_stream, h.ref_seq,
			length(e.event) + coalesce(length(e.source_cursor), 0) +
			coalesce((SELECT length(c.bytes) FROM captures c WHERE c.sha256 = e.capture
				AND NOT EXISTS (SELECT 1 FROM events o WHERE o.capture = e.capture
					AND NOT EXISTS (SELECT 1 FROM holds oh WHERE oh.stream = o.stream AND oh.seq = o.seq))), 0)
		FROM holds h JOIN events e ON e.stream = h.stream AND e.seq = h.seq
		WHERE h.stream = ? ORDER BY h.seq`, string(stream))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []c5.HeldRecord
	for rows.Next() {
		var (
			seq, refSeq, n         int64
			code, refNode, refStrm string
		)
		if err := rows.Scan(&seq, &code, &refNode, &refStrm, &refSeq, &n); err != nil {
			return nil, err
		}
		out = append(out, c5.HeldRecord{Seq: c5.Seq(seq), Bytes: n, Reason: c5.HoldReason{Code: c5.HoldCode(code),
			Ref: c5.Key{NodeID: c5.NodeID(refNode), Stream: c5.StreamID(refStrm), Seq: c5.Seq(refSeq)}}})
	}
	return out, rows.Err()
}

// topStreams names the streams of class holding the most event bytes, for
// the detail of a full alarm (C5 0.4: one asset churning shows as itself).
// The caller holds d.mu.
func (d *DB) topStreams(ctx context.Context, class c5.StreamClass, n int) string {
	rows, err := d.conn.QueryContext(ctx, `SELECT e.stream, sum(length(e.event)) AS b FROM events e
		JOIN streams s ON s.stream = e.stream WHERE s.class = ? GROUP BY e.stream ORDER BY b DESC, e.stream LIMIT ?`, string(class), n)
	if err != nil {
		return ""
	}
	defer rows.Close()
	out := ""
	for rows.Next() {
		var s string
		var b int64
		if rows.Scan(&s, &b) != nil {
			return out
		}
		if out != "" {
			out += ", "
		}
		out += fmt.Sprintf("%s %d bytes", s, b)
	}
	return out
}

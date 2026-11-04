package store

import (
	"context"
	"database/sql"
	"errors"

	c5 "otsec.local/otsec/contracts/store"
)

var _ c5.ConfigRemover = (*DB)(nil)

// RemoveConfig implements C5 0.7's ConfigRemover: the named unheld records
// of one series of a configuration stream, and the captures no retained
// record refers to any more, in one transaction (D4-20 rule 3, D4-32 item
// 2). Every named seq is checked before anything is deleted, so a refusal
// removes nothing.
func (d *DB) RemoveConfig(ctx context.Context, stream c5.StreamID, series string, seqs []c5.Seq) (c5.Removed, error) {
	if err := c5.CheckRemoveConfig(stream, series, seqs); err != nil {
		return c5.Removed{}, err
	}
	if err := d.lock(); err != nil {
		return c5.Removed{}, err
	}
	defer d.mu.Unlock()
	class, err := d.classOf(stream)
	if err != nil {
		return c5.Removed{}, err
	}
	if class != c5.ClassConfiguration {
		return c5.Removed{}, invalid("remove from %s: it is %s; only configuration records are removed this way", stream, class)
	}
	var (
		out     c5.Removed
		refusal error
	)
	err = d.tx(ctx, "remove", func() error {
		// The newest record of the series in the stream, by seq. A record
		// with no series (pre-0.7) is not counted (the index skips it).
		var newest sql.NullInt64
		if err := d.conn.QueryRowContext(ctx, `SELECT max(seq) FROM events WHERE stream = ? AND doc_series = ?`,
			string(stream), series).Scan(&newest); err != nil {
			return err
		}
		var stored []c5.Seq
		for _, seq := range seqs {
			var got sql.NullString
			var held bool
			err := d.conn.QueryRowContext(ctx, `SELECT e.doc_series,
					EXISTS (SELECT 1 FROM holds h WHERE h.stream = e.stream AND h.seq = e.seq)
				FROM events e WHERE e.stream = ? AND e.seq = ?`, string(stream), int64(seq)).Scan(&got, &held)
			switch {
			case errors.Is(err, sql.ErrNoRows): // removed already, or never committed
				out.Skipped = append(out.Skipped, seq)
				continue
			case err != nil:
				return err
			}
			switch {
			case held:
				refusal = invalid("remove from %s: seq %d is held", stream, seq)
			case !got.Valid:
				refusal = invalid("remove from %s: seq %d has no series (committed before C5 0.7)", stream, seq)
			case got.String != series:
				refusal = invalid("remove from %s: seq %d is of series %s, not %s", stream, seq, got.String, series)
			case newest.Valid && int64(seq) == newest.Int64:
				refusal = invalid("remove from %s: seq %d is the newest record of series %s", stream, seq, series)
			}
			if refusal != nil {
				return refusal
			}
			stored = append(stored, seq)
		}
		var captures []string
		for _, seq := range stored {
			var ev, cursor []byte
			var cap sql.NullString
			if err := d.conn.QueryRowContext(ctx, `DELETE FROM events WHERE stream = ? AND seq = ?
				RETURNING event, capture, source_cursor`, string(stream), int64(seq)).Scan(&ev, &cap, &cursor); err != nil {
				return err
			}
			freed := int64(len(ev) + len(cursor))
			if err := d.addClassBytes(ctx, class, -freed); err != nil {
				return err
			}
			out.Records++
			out.Bytes += freed
			if cap.Valid {
				captures = append(captures, cap.String)
			}
		}
		for _, sha := range captures {
			var capClass string
			var size int64
			err := d.conn.QueryRowContext(ctx, `DELETE FROM captures WHERE sha256 = ?
				AND NOT EXISTS (SELECT 1 FROM events WHERE capture = ?) RETURNING class, length(bytes)`, sha, sha).Scan(&capClass, &size)
			switch {
			case errors.Is(err, sql.ErrNoRows): // still referred to, or already deleted in this call
			case err != nil:
				return err
			default:
				if err := d.addClassBytes(ctx, c5.StreamClass(capClass), -size); err != nil {
					return err
				}
				out.Bytes += size
			}
		}
		return nil
	})
	if refusal != nil && err == refusal {
		return c5.Removed{}, refusal // rolled back: nothing was removed
	}
	if err != nil {
		return c5.Removed{}, err
	}
	if out.Records > 0 {
		d.clearQuotaAlarms(ctx)
	}
	return out, nil
}

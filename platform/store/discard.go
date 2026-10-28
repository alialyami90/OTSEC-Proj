package store

import (
	"context"
	"database/sql"
	"errors"

	c5 "otsec.local/otsec/contracts/store"
)

var _ c5.Discarder = (*DB)(nil)

// Discard implements C5 0.3's Discarder: the named events of a quarantine
// stream that are still stored, and the captures no retained record refers
// to any more, in one transaction (D3-1). It runs CheckDiscard, then
// refuses a stream with a persisted cursor.
func (d *DB) Discard(ctx context.Context, consumers []c5.Consumer, stream c5.StreamID, seqs []c5.Seq) (c5.Discarded, error) {
	if err := c5.CheckDiscard(consumers, stream, seqs); err != nil {
		return c5.Discarded{}, err
	}
	if err := d.lock(); err != nil {
		return c5.Discarded{}, err
	}
	defer d.mu.Unlock()
	class, err := d.classOf(stream)
	if err != nil {
		return c5.Discarded{}, err
	}
	if class == c5.ClassConfiguration {
		// Its records may be held, and only pruning past a boundary removes
		// them (C5 0.4).
		return c5.Discarded{}, invalid("discard from %s: configuration records are never discarded", stream)
	}
	var out c5.Discarded
	err = d.tx(ctx, "discard", func() error {
		var n int
		if err := d.conn.QueryRowContext(ctx, `SELECT count(*) FROM cursors WHERE stream = ?`, string(stream)).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return invalid("discard from %s: it has a persisted consumer cursor", stream)
		}
		var captures []string
		for _, seq := range seqs {
			var ev, cursor []byte
			var cap sql.NullString
			err := d.conn.QueryRowContext(ctx, `DELETE FROM events WHERE stream = ? AND seq = ?
				RETURNING event, capture, source_cursor`, string(stream), int64(seq)).Scan(&ev, &cap, &cursor)
			switch {
			case errors.Is(err, sql.ErrNoRows): // already discarded: a clear finished on a later call
				continue
			case err != nil:
				return err
			}
			freed := int64(len(ev) + len(cursor))
			if err := d.addClassBytes(ctx, class, -freed); err != nil {
				return err
			}
			out.Events++
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
	if err != nil {
		return c5.Discarded{}, err
	}
	if out.Events > 0 {
		d.clearQuotaAlarms(ctx)
	}
	return out, nil
}

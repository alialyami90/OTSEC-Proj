package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"otsec.local/otsec/contracts/audit"
	c5 "otsec.local/otsec/contracts/store"
)

// MaxRead is the most events one Read returns.
const MaxRead = 10000

func (d *DB) classOf(stream c5.StreamID) (c5.StreamClass, error) {
	c, ok := d.streams[stream]
	if !ok {
		return "", invalid("database %s holds no stream %s", d.opt.Database.ID, stream)
	}
	return c, nil
}

// Read returns up to max committed events of stream with seq > after, in
// seq order. Past the prune point it returns the first retained events; the
// caller sees the jump in seq.
func (d *DB) Read(ctx context.Context, stream c5.StreamID, after c5.Seq, max int) ([]c5.Stored, error) {
	if max < 1 || max > MaxRead {
		return nil, invalid("read of %d events, want 1 to %d", max, MaxRead)
	}
	if err := d.lock(); err != nil {
		return nil, err
	}
	defer d.mu.Unlock()
	class, err := d.classOf(stream)
	if err != nil {
		return nil, err
	}
	rows, err := d.conn.QueryContext(ctx, `SELECT seq, event, capture, source_cursor, committed_at FROM events
		WHERE stream = ? AND seq > ? ORDER BY seq LIMIT ?`, string(stream), int64(after), max)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []c5.Stored
	for rows.Next() {
		var (
			seq    int64
			ev     []byte
			cap    sql.NullString
			cursor []byte
			at     int64
		)
		if err := rows.Scan(&seq, &ev, &cap, &cursor, &at); err != nil {
			return nil, err
		}
		s := c5.Stored{Key: c5.Key{NodeID: d.opt.Node, Stream: stream, Seq: c5.Seq(seq)}, Class: class, Event: ev,
			SourceCursor: cursor, CommittedAt: time.Unix(0, at).UTC()}
		if cap.Valid {
			s.EvidenceRef = c5.EvidenceRef(cap.String)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ReadCapture returns the capture ref names ("sha256:<hex>").
func (d *DB) ReadCapture(ctx context.Context, ref string) (c5.Capture, error) {
	sha, ok := strings.CutPrefix(ref, "sha256:")
	if !ok {
		return c5.Capture{}, invalid("evidence ref %q is not sha256:<hex>", ref)
	}
	if err := d.lock(); err != nil {
		return c5.Capture{}, err
	}
	defer d.mu.Unlock()
	var b []byte
	err := d.conn.QueryRowContext(ctx, `SELECT bytes FROM captures WHERE sha256 = ?`, sha).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return c5.Capture{}, invalid("no capture %s", ref)
	}
	if err != nil {
		return c5.Capture{}, err
	}
	c := c5.Capture{SHA256: sha, Bytes: b}
	if err := c.Validate(); err != nil {
		return c5.Capture{}, fmt.Errorf("stored capture %s: %w", ref, err)
	}
	return c, nil
}

// ChainAnchor returns the link of the last audit record pruned, or
// GenesisLink if none was.
func (d *DB) ChainAnchor(ctx context.Context, stream c5.StreamID) (c5.ChainLink, error) {
	if err := d.lock(); err != nil {
		return c5.ChainLink{}, err
	}
	defer d.mu.Unlock()
	class, err := d.classOf(stream)
	if err != nil {
		return c5.ChainLink{}, err
	}
	if class != c5.ClassAudit {
		return c5.ChainLink{}, invalid("stream %s is %s, not the audit stream", stream, class)
	}
	var seq sql.NullInt64
	var hash sql.NullString
	if err := d.conn.QueryRowContext(ctx, `SELECT anchor_seq, anchor_hash FROM streams WHERE stream = ?`, string(stream)).Scan(&seq, &hash); err != nil {
		return c5.ChainLink{}, err
	}
	if !seq.Valid {
		return c5.GenesisLink(d.opt.Node), nil
	}
	return c5.ChainLink{NodeID: string(d.opt.Node), Seq: uint64(seq.Int64), Hash: hash.String}, nil
}

// SourceCursor is the device-side position of the newest committed record
// of stream that carried one, nil if none did. A collector resumes from it.
func (d *DB) SourceCursor(ctx context.Context, stream c5.StreamID) ([]byte, error) {
	if err := d.lock(); err != nil {
		return nil, err
	}
	defer d.mu.Unlock()
	if _, err := d.classOf(stream); err != nil {
		return nil, err
	}
	var b []byte
	err := d.conn.QueryRowContext(ctx, `SELECT source_cursor FROM streams WHERE stream = ?`, string(stream)).Scan(&b)
	return b, err
}

func (d *DB) seqQuery(ctx context.Context, stream c5.StreamID, q string, args ...any) (c5.Seq, error) {
	if err := d.lock(); err != nil {
		return 0, err
	}
	defer d.mu.Unlock()
	if _, err := d.classOf(stream); err != nil {
		return 0, err
	}
	var n sql.NullInt64
	if err := d.conn.QueryRowContext(ctx, q, append([]any{string(stream)}, args...)...).Scan(&n); err != nil {
		return 0, err
	}
	return c5.Seq(n.Int64), nil
}

// LastCommitted is the highest seq ever committed in stream, pruned or not.
func (d *DB) LastCommitted(ctx context.Context, stream c5.StreamID) (c5.Seq, error) {
	return d.seqQuery(ctx, stream, `SELECT last_seq FROM streams WHERE stream = ?`)
}

// LastCommittedBy is the highest retained seq of stream committed at or
// before t. Events already pruned are not counted, which can only lower the
// answer, and a lower answer prunes less.
func (d *DB) LastCommittedBy(ctx context.Context, stream c5.StreamID, t time.Time) (c5.Seq, error) {
	return d.seqQuery(ctx, stream, `SELECT MAX(seq) FROM events WHERE stream = ? AND committed_at <= ?`, t.UnixNano())
}

// FirstRetained is the lowest seq of stream still stored, 0 if none.
func (d *DB) FirstRetained(ctx context.Context, stream c5.StreamID) (c5.Seq, error) {
	return d.seqQuery(ctx, stream, `SELECT MIN(seq) FROM events WHERE stream = ?`)
}

// SaveCursor commits c at synchronous=FULL. It refuses to move a cursor
// back (CodeCursorRegress) or past the last committed seq
// (CodeCursorAhead).
func (d *DB) SaveCursor(ctx context.Context, c c5.Cursor) error {
	if c.Consumer == "" {
		return invalid("cursor has no consumer")
	}
	if err := d.lock(); err != nil {
		return err
	}
	defer d.mu.Unlock()
	if _, err := d.classOf(c.Stream); err != nil {
		return err
	}
	if d.sync != c5.SyncFull {
		return errors.New("store: settings not checked; CheckSettings must pass before a cursor is saved")
	}
	var refusal error
	err := d.tx(ctx, "cursor", func() error {
		var last int64
		if err := d.conn.QueryRowContext(ctx, `SELECT last_seq FROM streams WHERE stream = ?`, string(c.Stream)).Scan(&last); err != nil {
			return err
		}
		if c.Through > c5.Seq(last) {
			refusal = codeErr(c5.CodeCursorAhead, nil, "cursor %s/%s at %d, stream at %d", c.Consumer, c.Stream, c.Through, last)
			return refusal
		}
		var have int64
		err := d.conn.QueryRowContext(ctx, `SELECT through FROM cursors WHERE consumer = ? AND stream = ?`, string(c.Consumer), string(c.Stream)).Scan(&have)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		case c.Through < c5.Seq(have):
			refusal = codeErr(c5.CodeCursorRegress, nil, "cursor %s/%s from %d back to %d", c.Consumer, c.Stream, have, c.Through)
			return refusal
		}
		_, err = d.conn.ExecContext(ctx, `INSERT INTO cursors (consumer, stream, through) VALUES (?, ?, ?)
			ON CONFLICT (consumer, stream) DO UPDATE SET through = excluded.through`, string(c.Consumer), string(c.Stream), int64(c.Through))
		return err
	})
	return err
}

// LoadCursors reads the persisted cursors of stream from the database.
func (d *DB) LoadCursors(ctx context.Context, stream c5.StreamID) ([]c5.Cursor, error) {
	if err := d.lock(); err != nil {
		return nil, err
	}
	defer d.mu.Unlock()
	if _, err := d.classOf(stream); err != nil {
		return nil, err
	}
	rows, err := d.conn.QueryContext(ctx, `SELECT consumer, through FROM cursors WHERE stream = ? ORDER BY consumer`, string(stream))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []c5.Cursor
	for rows.Next() {
		var id string
		var through int64
		if err := rows.Scan(&id, &through); err != nil {
			return nil, err
		}
		out = append(out, c5.Cursor{Consumer: c5.ConsumerID(id), Stream: stream, Through: c5.Seq(through)})
	}
	return out, rows.Err()
}

// PruneStep deletes, in one transaction, the oldest at most max events of
// b's stream with seq <= b.Through(), every capture no retained record
// refers to any more, and for the audit stream writes the link of the last
// deleted record as the chain anchor.
func (d *DB) PruneStep(ctx context.Context, b c5.Boundary, max int) (int, error) {
	if b == nil {
		return 0, invalid("no boundary")
	}
	if max < 1 {
		return 0, invalid("prune step of %d events", max)
	}
	if err := d.lock(); err != nil {
		return 0, err
	}
	defer d.mu.Unlock()
	stream := b.Stream()
	class, err := d.classOf(stream)
	if err != nil {
		return 0, err
	}
	n := 0
	err = d.tx(ctx, "prune", func() error {
		rows, err := d.conn.QueryContext(ctx, `SELECT seq, event, capture, source_cursor FROM events
			WHERE stream = ? AND seq <= ? ORDER BY seq LIMIT ?`, string(stream), int64(b.Through()), max)
		if err != nil {
			return err
		}
		var (
			lastSeq   int64
			lastEvent []byte
			freed     int64
			captures  []string
		)
		for rows.Next() {
			var ev, cursor []byte
			var cap sql.NullString
			if err := rows.Scan(&lastSeq, &ev, &cap, &cursor); err != nil {
				rows.Close()
				return err
			}
			lastEvent = ev
			freed += int64(len(ev) + len(cursor))
			if cap.Valid {
				captures = append(captures, cap.String)
			}
			n++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		if _, err := d.conn.ExecContext(ctx, `DELETE FROM events WHERE stream = ? AND seq <= ?`, string(stream), lastSeq); err != nil {
			return err
		}
		if err := d.addClassBytes(ctx, class, -freed); err != nil {
			return err
		}
		for _, sha := range captures {
			var capClass string
			var size int64
			err := d.conn.QueryRowContext(ctx, `DELETE FROM captures WHERE sha256 = ?
				AND NOT EXISTS (SELECT 1 FROM events WHERE capture = ?) RETURNING class, length(bytes)`, sha, sha).Scan(&capClass, &size)
			switch {
			case errors.Is(err, sql.ErrNoRows): // still referred to, or already deleted in this step
			case err != nil:
				return err
			default:
				if err := d.addClassBytes(ctx, c5.StreamClass(capClass), -size); err != nil {
					return err
				}
			}
		}
		if class == c5.ClassAudit {
			if _, err := d.conn.ExecContext(ctx, `UPDATE streams SET anchor_seq = ?, anchor_hash = ? WHERE stream = ?`,
				lastSeq, audit.Hash(lastEvent), string(stream)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if n > 0 {
		d.clearQuotaAlarms(ctx)
	}
	return n, nil
}

// clearQuotaAlarms re-arms the warning and quota alarms of classes that
// pruning brought back under their thresholds.
func (d *DB) clearQuotaAlarms(ctx context.Context) {
	for class, q := range d.quotas {
		used, err := d.classBytes(ctx, class)
		if err != nil {
			continue
		}
		if used < q.Bytes {
			d.full[class] = false
		}
		if float64(used) < q.WarnFraction*float64(q.Bytes) {
			d.warned[class] = false
		}
	}
}

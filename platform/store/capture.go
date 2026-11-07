package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	c5 "otsec.local/otsec/contracts/store"
)

// chargeFromKey is the meta key holding the first captures.id charged per
// class (C5 0.9, docs/phase4/D5-c5-0.9.md section 2). A capture with a
// lower id was stored by a 0.8 binary, which charged it once, to the class
// whose record stored it first (captures.class), and it is charged that way
// until its row is deleted. Every later capture is charged once to each
// class that holds a record citing it, so one class's records never hold
// another class's quota. The key is a meta row, not a new table, so the
// store's Format is unchanged.
const chargeFromKey = "capture_charge_from"

// ensureCaptureCharge reads chargeFromKey into d.chargeFrom, writing it on
// the first open by this binary: one past the highest capture id, or 1 on
// a database with no captures.
func (d *DB) ensureCaptureCharge(ctx context.Context) error {
	var v string
	err := d.conn.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, chargeFromKey).Scan(&v)
	switch {
	case err == nil:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			return invalid("store meta %s is %q, not a capture id", chargeFromKey, v)
		}
		d.chargeFrom = n
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("read meta %s: %w", chargeFromKey, err)
	}
	return d.tx(ctx, "capture-charge", func() error {
		var n int64
		if err := d.conn.QueryRowContext(ctx, `SELECT coalesce(max(id), 0) + 1 FROM captures`).Scan(&n); err != nil {
			return err
		}
		if _, err := d.conn.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES (?, ?)`, chargeFromKey, strconv.FormatInt(n, 10)); err != nil {
			return err
		}
		d.chargeFrom = n
		return nil
	})
}

// classCites reports whether a stored record of class cites the capture
// sha. events_by_capture bounds it to the records citing that capture.
func (d *DB) classCites(ctx context.Context, class c5.StreamClass, sha string) (bool, error) {
	var one int
	err := d.conn.QueryRowContext(ctx, `SELECT 1 FROM events e JOIN streams s ON s.stream = e.stream
		WHERE e.capture = ? AND s.class = ? LIMIT 1`, sha, string(class)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// releaseCaptures ends class's charge for each capture in shas whose last
// citing record of class has just been deleted, and deletes each capture
// no record of any class cites any more. It returns the capture bytes
// freed: class's ended charges, and each 0.8 capture deleted. A capture of the 0.8 accounting (id below d.chargeFrom) is charged
// to its first class only, so its bytes come off that class when its row is
// deleted, as 0.8 did. The caller holds the transaction.
func (d *DB) releaseCaptures(ctx context.Context, class c5.StreamClass, shas []string) (int64, error) {
	var freed int64
	seen := map[string]bool{}
	for _, sha := range shas {
		if seen[sha] {
			continue
		}
		seen[sha] = true
		var (
			id       int64
			capClass string
			size     int64
		)
		err := d.conn.QueryRowContext(ctx, `SELECT id, class, length(bytes) FROM captures WHERE sha256 = ?`, sha).Scan(&id, &capClass, &size)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			continue // deleted by an earlier step that cleared its last citation
		case err != nil:
			return 0, err
		}
		perClass := id >= d.chargeFrom
		if perClass {
			cites, err := d.classCites(ctx, class, sha)
			if err != nil {
				return 0, err
			}
			if !cites {
				if err := d.addClassBytes(ctx, class, -size); err != nil {
					return 0, err
				}
				freed += size
			}
		}
		res, err := d.conn.ExecContext(ctx, `DELETE FROM captures WHERE sha256 = ?
			AND NOT EXISTS (SELECT 1 FROM events WHERE capture = ?)`, sha, sha)
		if err != nil {
			return 0, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return 0, err
		} else if n == 1 && !perClass {
			if err := d.addClassBytes(ctx, c5.StreamClass(capClass), -size); err != nil {
				return 0, err
			}
			freed += size
		}
	}
	return freed, nil
}

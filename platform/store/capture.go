package store

import (
	"context"
	"database/sql"
	"errors"

	c5 "otsec.local/otsec/contracts/store"
)

// perClassCapture reports whether a capture whose first class is capClass
// (captures.class) is charged per class (C5 0.9, docs/phase4/D5-c5-0.9.md
// section 2): once to each class that holds a record citing it, so an
// alert's capture is charged to the alert class even when the observation
// class stored it first. Only the network classes are. Every other capture
// keeps 0.8's accounting exactly: charged once, to its first class, until
// its row is deleted. A 0.8 binary never opens the network database (its
// ActionFor knows no network class), so a rollback can't mix the two rules
// in one database (D6's R1 on #544, D1).
func perClassCapture(capClass c5.StreamClass) bool {
	return capClass == c5.ClassNetworkObservation || capClass == c5.ClassNetworkAlert
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

// releaseCaptures deletes each capture in shas that no record of any class
// cites any more, and returns the capture bytes freed. A network capture
// (perClassCapture) also ends class's charge once class's last citing record
// has been deleted, whether or not the row goes. Any other capture's bytes
// come off its first class when its row is deleted, as in 0.8. The caller
// holds the transaction.
func (d *DB) releaseCaptures(ctx context.Context, class c5.StreamClass, shas []string) (int64, error) {
	var freed int64
	seen := map[string]bool{}
	for _, sha := range shas {
		if seen[sha] {
			continue
		}
		seen[sha] = true
		var (
			capClass string
			size     int64
		)
		err := d.conn.QueryRowContext(ctx, `SELECT class, length(bytes) FROM captures WHERE sha256 = ?`, sha).Scan(&capClass, &size)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			continue // deleted by an earlier step that cleared its last citation
		case err != nil:
			return 0, err
		}
		perClass := perClassCapture(c5.StreamClass(capClass))
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

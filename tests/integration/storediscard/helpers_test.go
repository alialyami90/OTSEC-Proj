package storediscard

import (
	"database/sql"
	"errors"
	"net/url"

	_ "modernc.org/sqlite"
)

func errorsAs(err error, target any) bool { return errors.As(err, target) }

// checkpoint empties the WAL from a connection of A6's own.
func checkpoint(path string) error {
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath())
	if err != nil {
		return err
	}
	defer db.Close()
	var busy, log, done int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); err != nil {
		return err
	}
	if busy != 0 {
		return errors.New("checkpoint busy")
	}
	return nil
}

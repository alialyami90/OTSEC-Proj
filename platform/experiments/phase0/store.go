package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite" // pure Go driver: no cgo, static binary
)

// payload approximates one SER record plus its preserved native text:
// a few hundred bytes per event.
var payload = []byte(strings.Repeat("SER 10/23/2026 15:00:00.123456 51P1T Asserted;", 8))

const schema = `CREATE TABLE IF NOT EXISTS events (
	seq      INTEGER PRIMARY KEY AUTOINCREMENT,
	recv_ns  INTEGER NOT NULL,
	native   BLOB    NOT NULL
)`

// openStore opens an event store the way the platform would: WAL journal,
// an explicit synchronous level, and a busy timeout.
func openStore(path, syncMode string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=" + syncMode,
		"PRAGMA busy_timeout=5000",
		schema,
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	return db, nil
}

// insertBatch commits n events in one transaction and returns the highest
// sequence number committed.
func insertBatch(db *sql.DB, n int, recvNs int64) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	var last int64
	for i := 0; i < n; i++ {
		res, err := tx.Exec("INSERT INTO events(recv_ns, native) VALUES(?, ?)", recvNs, payload)
		if err != nil {
			tx.Rollback()
			return 0, err
		}
		last, _ = res.LastInsertId()
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return last, nil
}

type storeState struct {
	integrity string
	count     int64
	minSeq    int64
	maxSeq    int64
}

func inspect(db *sql.DB) (storeState, error) {
	var s storeState
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&s.integrity); err != nil {
		return s, err
	}
	err := db.QueryRow("SELECT COUNT(*), COALESCE(MIN(seq),0), COALESCE(MAX(seq),0) FROM events").
		Scan(&s.count, &s.minSeq, &s.maxSeq)
	return s, err
}

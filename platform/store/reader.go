package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"

	cnode "otsec.local/otsec/contracts/node"
	c5 "otsec.local/otsec/contracts/store"
)

// fileURI is the SQLite URI of path. The store always opens its files by
// URI: the driver cuts a plain name at its first '?', so a directory with
// '?' in its name would open a file outside the checked directory (found
// with A6's test of #92). url.URL escapes a space, '?' and '#'. A Windows
// path C:\x becomes file:///C:/x: without the leading slash SQLite reads
// "C:" as the URI authority and refuses it (A6, native Windows run of #92).
func fileURI(path, query string) string {
	p := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p, RawQuery: query}
	return u.String()
}

// OpenReadOnly opens database id of node in dir for reading, alongside a
// running node, for the read-only CLI. It takes no lock and writes no
// database content: SQLite opens the file read-only, the connection is
// query_only, and every transaction is refused before BEGIN. Like any
// SQLite reader of a WAL database, it creates an empty -wal when the node
// is stopped and writes the -shm index; cmd/otsec's TestReadOnlyCommands
// checks that nothing else is created or changed (A6 #92 nit 5). CommitBatch, SaveCursor and
// SaveSourceCursor refuse too, because CheckSettings never runs. It refuses
// a database that does not exist, rather than creating one, and one that
// belongs to another node or database.
//
// A reader sees committed transactions only (WAL). It needs read access to
// the database files, which the directory's mode or DACL gives only to the
// node's account, SYSTEM and Administrators.
func OpenReadOnly(ctx context.Context, dir string, node cnode.ID, id c5.DatabaseID) (*DB, error) {
	path := filepath.Join(dir, string(id)+".db")
	ok, err := exists(path)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("store: %s does not exist", path)
	}
	if err := refuseLegacy(ctx, path); err != nil {
		return nil, err
	}
	sdb, err := sql.Open("sqlite", fileURI(path, "mode=ro"))
	if err != nil {
		return nil, err
	}
	sdb.SetMaxOpenConns(1)
	conn, err := sdb.Conn(ctx)
	if err != nil {
		sdb.Close()
		return nil, err
	}
	d := &DB{opt: Options{Dir: dir, Node: node, Database: c5.Database{ID: id}}, path: path, db: sdb, conn: conn, readOnly: true,
		streams: map[c5.StreamID]c5.StreamClass{}, quotas: map[c5.StreamClass]c5.Quota{},
		full: map[c5.StreamClass]bool{}, warned: map[c5.StreamClass]bool{}}
	// busy_timeout first, as in connPragmas, so no statement reads the
	// file before a WAL recovery it meets can be waited for.
	for _, q := range []string{"PRAGMA busy_timeout=5000", "PRAGMA query_only=1", "PRAGMA temp_store=MEMORY"} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			d.Close()
			return nil, fmt.Errorf("open %s read-only: %s: %w", path, q, err)
		}
	}
	meta := map[string]string{}
	rows, err := conn.QueryContext(ctx, `SELECT key, value FROM meta`)
	if err != nil {
		d.Close()
		return nil, fmt.Errorf("open %s read-only: %w", path, err)
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			d.Close()
			return nil, err
		}
		meta[k] = v
	}
	rows.Close()
	if meta["format"] == legacyFormat {
		d.Close()
		return nil, legacyRefusal(path)
	}
	if meta["format"] != Format || meta["node_id"] != string(node) || meta["database"] != string(id) {
		d.Close()
		return nil, fmt.Errorf("store: %s is format %q, node %q, database %q; want %q, %q, %q",
			path, meta["format"], meta["node_id"], meta["database"], Format, node, id)
	}
	srows, err := conn.QueryContext(ctx, `SELECT stream, class FROM streams`)
	if err != nil {
		d.Close()
		return nil, err
	}
	defer srows.Close()
	for srows.Next() {
		var s, c string
		if err := srows.Scan(&s, &c); err != nil {
			d.Close()
			return nil, err
		}
		d.streams[c5.StreamID(s)] = c5.StreamClass(c)
	}
	return d, srows.Err()
}

var errReadOnly = errors.New("store: database opened read-only")

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/version"
)

// CommitBatch writes recs, all of stream, in one transaction at
// synchronous=FULL and returns the Commit. Only a contracts/store.Log calls
// it.
//
// It refuses a batch, having written nothing, with CodeInvalid (an unknown
// stream, a class that is not the stream's, an event that is not a pending
// C4 event of this node and stream, or a pending audit record SealAudit
// rejects) or CodeQuotaReached (the class's quota cannot hold the batch).
// Any other error leaves the batch's durability unknown, and the Log stops.
func (d *DB) CommitBatch(ctx context.Context, stream c5.StreamID, recs []c5.Record) (c5.Commit, error) {
	if err := d.lock(); err != nil {
		return c5.Commit{}, err
	}
	defer d.mu.Unlock()
	if d.sync != c5.SyncFull {
		return c5.Commit{}, errors.New("store: settings not checked; CheckSettings must pass before the first commit")
	}
	class, ok := d.streams[stream]
	if !ok {
		return c5.Commit{}, invalid("database %s holds no stream %s", d.opt.Database.ID, stream)
	}
	if len(recs) == 0 {
		return c5.Commit{}, invalid("empty batch")
	}
	for i, r := range recs {
		if r.Stream != stream || r.Class != class {
			return c5.Commit{}, invalid("record %d is %s/%s in a batch of %s/%s", i, r.Stream, r.Class, stream, class)
		}
	}

	var (
		out     c5.Commit
		refusal error
		alarm   *c5.Alarm
	)
	err := d.tx(ctx, "commit", func() error {
		var last, lastAt int64
		var headSeq sql.NullInt64
		var headHash sql.NullString
		if err := d.conn.QueryRowContext(ctx, `SELECT last_seq, last_at, head_seq, head_hash FROM streams WHERE stream = ?`, string(stream)).
			Scan(&last, &lastAt, &headSeq, &headHash); err != nil {
			return fmt.Errorf("read stream %s: %w", stream, err)
		}
		first := c5.Seq(last) + 1

		payload := make([][]byte, len(recs))
		var head c5.ChainLink
		if class == c5.ClassAudit {
			prev := c5.GenesisLink(d.opt.Node)
			if headSeq.Valid {
				prev = c5.ChainLink{NodeID: string(d.opt.Node), Seq: uint64(headSeq.Int64), Hash: headHash.String}
			}
			if prev.Seq != uint64(last) {
				return fmt.Errorf("audit chain head %d differs from stream seq %d", prev.Seq, last)
			}
			sealed, h, err := c5.SealAudit(prev, recs)
			if err != nil {
				refusal = err
				return err
			}
			payload, head = sealed, h
		} else {
			for i, r := range recs {
				b, err := assignSeq(r.Event, event.EventID{NodeID: d.opt.Node, Stream: stream, Seq: first + c5.Seq(i)})
				if err != nil {
					refusal = invalid("record %d: %v", i, err)
					return refusal
				}
				payload[i] = b
			}
		}

		add, newCaptures, err := d.batchBytes(ctx, recs, payload)
		if err != nil {
			return err
		}
		used, err := d.classBytes(ctx, class)
		if err != nil {
			return err
		}
		if q, ok := d.quotas[class]; ok && used+add > q.Bytes {
			refusal = codeErr(c5.CodeQuotaReached, nil, "class %s: %d of %d bytes used, batch needs %d", class, used, q.Bytes, add)
			if !d.full[class] {
				d.full[class] = true
				code := c5.AlarmQuotaReached
				if class == c5.ClassAudit {
					code = c5.AlarmAuditFull
				}
				alarm = &c5.Alarm{Code: code, Class: class, Stream: stream, Detail: refusal.Error()}
			}
			return refusal
		}

		// Commit time never goes backwards within a stream, so LastCommittedBy
		// is a range query. A clock stepped back lengthens replay windows,
		// which keeps more, never less.
		at := max(d.opt.now().UnixNano(), lastAt)
		for i, r := range recs {
			var capture any
			if r.Capture != nil {
				capture = r.Capture.SHA256
				if newCaptures[r.Capture.SHA256] {
					if _, err := d.conn.ExecContext(ctx, `INSERT INTO captures (sha256, class, bytes) VALUES (?, ?, ?)`,
						r.Capture.SHA256, string(class), r.Capture.Bytes); err != nil {
						return fmt.Errorf("insert capture: %w", err)
					}
					delete(newCaptures, r.Capture.SHA256)
				}
			}
			if _, err := d.conn.ExecContext(ctx, `INSERT INTO events (stream, seq, event, capture, source_cursor, committed_at) VALUES (?, ?, ?, ?, ?, ?)`,
				string(stream), int64(first)+int64(i), payload[i], capture, nullBytes(r.SourceCursor), at); err != nil {
				return fmt.Errorf("insert event: %w", err)
			}
		}
		var cursor []byte
		for _, r := range recs {
			if r.SourceCursor != nil {
				cursor = r.SourceCursor
			}
		}
		newLast := last + int64(len(recs))
		q := `UPDATE streams SET last_seq = ?, last_at = ?, source_cursor = COALESCE(?, source_cursor) WHERE stream = ?`
		args := []any{newLast, at, nullBytes(cursor), string(stream)}
		if class == c5.ClassAudit {
			if head.Seq != uint64(newLast) {
				return fmt.Errorf("sealed head %d, stream at %d", head.Seq, newLast)
			}
			q = `UPDATE streams SET last_seq = ?, last_at = ?, source_cursor = COALESCE(?, source_cursor), head_seq = ?, head_hash = ? WHERE stream = ?`
			args = []any{newLast, at, nullBytes(cursor), int64(head.Seq), head.Hash, string(stream)}
		}
		if _, err := d.conn.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("update stream: %w", err)
		}
		if err := d.addClassBytes(ctx, class, add); err != nil {
			return err
		}
		if q, ok := d.quotas[class]; ok && !d.warned[class] && float64(used+add) >= q.WarnFraction*float64(q.Bytes) {
			d.warned[class] = true
			alarm = &c5.Alarm{Code: c5.AlarmQuotaWarning, Class: class, Stream: stream,
				Detail: fmt.Sprintf("class %s: %d of %d bytes used", class, used+add, q.Bytes)}
		}
		out = c5.Commit{Node: d.opt.Node, Stream: stream, FirstSeq: first, Count: len(recs), Sync: d.sync, At: time.Unix(0, at).UTC()}
		return nil
	})
	if alarm != nil {
		d.raise(*alarm)
	}
	if refusal != nil && err == refusal {
		return c5.Commit{}, refusal // rolled back: nothing was written
	}
	if err != nil {
		return c5.Commit{}, err
	}
	return out, nil
}

// batchBytes is the payload a batch adds to its class: event bytes, source
// cursors, and each capture not yet stored. newCaptures lists those.
func (d *DB) batchBytes(ctx context.Context, recs []c5.Record, payload [][]byte) (int64, map[string]bool, error) {
	var n int64
	newCaptures := map[string]bool{}
	seen := map[string]bool{}
	for i, r := range recs {
		n += int64(len(payload[i]) + len(r.SourceCursor))
		if r.Capture == nil || seen[r.Capture.SHA256] {
			continue
		}
		seen[r.Capture.SHA256] = true
		var one int
		err := d.conn.QueryRowContext(ctx, `SELECT 1 FROM captures WHERE sha256 = ?`, r.Capture.SHA256).Scan(&one)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			newCaptures[r.Capture.SHA256] = true
			n += int64(len(r.Capture.Bytes))
		case err != nil:
			return 0, nil, fmt.Errorf("read capture: %w", err)
		}
	}
	return n, newCaptures, nil
}

func (d *DB) classBytes(ctx context.Context, class c5.StreamClass) (int64, error) {
	var n int64
	err := d.conn.QueryRowContext(ctx, `SELECT bytes FROM class_bytes WHERE class = ?`, string(class)).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

func (d *DB) addClassBytes(ctx context.Context, class c5.StreamClass, n int64) error {
	_, err := d.conn.ExecContext(ctx, `INSERT INTO class_bytes (class, bytes) VALUES (?, ?)
		ON CONFLICT (class) DO UPDATE SET bytes = bytes + excluded.bytes`, string(class), n)
	return err
}

// ClassBytes is the payload a class holds in this database, as the quota
// counts it.
func (d *DB) ClassBytes(ctx context.Context, class c5.StreamClass) (int64, error) {
	if err := d.lock(); err != nil {
		return 0, err
	}
	defer d.mu.Unlock()
	return d.classBytes(ctx, class)
}

func (d *DB) raise(a c5.Alarm) {
	if a.At.IsZero() {
		a.At = d.opt.now()
	}
	if d.opt.Alarms != nil {
		d.opt.Alarms(a)
	}
}

func nullBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

var eventVersion = mustParse(event.Identifier)

func mustParse(s string) version.ID {
	v, err := version.Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

// assignSeq writes id into a pending C4 event (C5 Record.Event): b must pass
// C4's ValidatePending with id's node and stream and seq 0. Only the value
// of the top-level "id" member is replaced; every other byte stays as the
// producer wrote it. The result must pass C4's Decode, which reads strictly
// and validates the full event.
func assignSeq(b []byte, id event.EventID) ([]byte, error) {
	e, _ := event.Decode(b) // Decode validates as stored; seq 0 fails that, so check pending below
	if e == nil {
		_, err := event.Decode(b)
		return nil, fmt.Errorf("not a C4 event: %w", err)
	}
	if v, err := version.Parse(e.Schema); err != nil || v.Name != eventVersion.Name || v.Major != eventVersion.Major || v.Minor > eventVersion.Minor {
		// A later minor's fields would be stored without this binary
		// having read them.
		return nil, fmt.Errorf("event schema %q is not one this store reads exactly", e.Schema)
	}
	if err := e.ValidatePending(); err != nil {
		return nil, fmt.Errorf("not a pending C4 event: %w", err)
	}
	if e.ID.NodeID != id.NodeID || e.ID.Stream != id.Stream {
		return nil, fmt.Errorf("event is for %s:%s, stored in %s:%s", e.ID.NodeID, e.ID.Stream, id.NodeID, id.Stream)
	}
	idJSON, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	out, err := replaceMember(b, "id", idJSON)
	if err != nil {
		return nil, err
	}
	got, err := event.Decode(out)
	if err != nil {
		return nil, fmt.Errorf("event with its seq does not validate: %w", err)
	}
	if got.ID != id {
		return nil, fmt.Errorf("event id is %v after assignment, want %v", got.ID, id)
	}
	return out, nil
}

// replaceMember returns the JSON object b with the value of its top-level
// member key replaced by value. Other members keep their bytes and order.
// b must hold exactly one object, with key once.
func replaceMember(b []byte, key string, value []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, fmt.Errorf("not a JSON object")
	}
	var out bytes.Buffer
	out.WriteByte('{')
	found := 0
	for i := 0; dec.More(); i++ {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, ok := t.(string)
		if !ok {
			return nil, fmt.Errorf("member name is %v", t)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if i > 0 {
			out.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		out.Write(kb)
		out.WriteByte(':')
		if k == key {
			found++
			out.Write(value)
		} else {
			out.Write(raw)
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, fmt.Errorf("unterminated object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("data after the object")
	}
	if found != 1 {
		return nil, fmt.Errorf("member %q appears %d times", key, found)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

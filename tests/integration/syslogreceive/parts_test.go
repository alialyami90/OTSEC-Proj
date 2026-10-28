package syslogreceive

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/receive"
)

// A stream batch over the commit cap (B6 on #281, B4's split in #284).
// Claim under test: a TCP connection's batch whose events together pass
// the Log's byte cap (C5 0.4, 1 MiB here) is stored in full, in the order
// read, with nothing dropped and nothing held: before the split, the store
// refused the whole batch as too large and the stream retried it forever.
//
// The batch is made over the cap, not hoped for: a second connection
// holds SQLite's write lock while the frames are read, so the writer waits
// in its commit and the frames queue behind it. Frames of '<' store at
// about seven times their length (the JSON encoder escapes '<' to six
// bytes, and the native bytes are base64), the escaped frames
// HeldBatchBytes is sized for.

// bigFrame is frame i: 8000 bytes, under the 8192 MaxMessage, whose index
// is in its text so order can be checked.
func bigFrame(i int) []byte {
	head := fmt.Sprintf("<13>big %03d ", i)
	return []byte(head + strings.Repeat("<", 8000-len(head)))
}

// pinWriter takes SQLite's write lock on the store's file from another
// connection and returns its release. The store waits on busy_timeout
// (5 s), so the pin is held well under that.
func pinWriter(t *testing.T, path string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if _, err := c.ExecContext(ctx, "ROLLBACK"); err != nil {
			t.Error(err)
		}
		c.Close()
		db.Close()
	}
	t.Cleanup(release)
	return release
}

func TestStreamBatchOverTheCommitCapIsStoredInParts(t *testing.T) {
	const n = 200
	g := start(t, asset.SyslogTCP, nil, receive.Limits{Rate: 100000, Burst: 100000})
	release := pinWriter(t, g.db)
	a := dialFrom(t, ipA, "tcp", g.addr)
	sent := make(chan error, 1)
	go func() {
		w := bufio.NewWriter(a)
		for i := range n {
			w.Write(bigFrame(i))
			w.WriteByte('\n')
		}
		sent <- w.Flush()
	}()
	// Wait until the listener has read enough frames that the batch in
	// hand or the queue behind it passes the cap (checked below against
	// the stored sizes), at most 3 s so the store's 5 s busy wait is not
	// reached.
	const want = 61
	st := g.waitStatus(func(st receive.Status) bool { return st.Received >= want }, 3*time.Second)
	read := st.Received
	if read < want {
		t.Fatalf("with the store pinned, the listener read %d frames in 3 s, not %d: the test cannot tell", read, want)
	}
	if st.Stored != 0 {
		t.Fatalf("%d stored while the write lock was held: the pin did not hold", st.Stored)
	}
	release()
	ev := g.waitN(n, 20*time.Second)
	if err := <-sent; err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(ev) != n {
		st := g.r.Status()
		t.Fatalf("%d of %d frames stored (received %d, stored %d, dropped %v, last error %q): a batch over the commit cap was not stored",
			len(ev), n, st.Received, st.Stored, st.Dropped, st.LastErr)
	}
	// The power check: whatever split the read frames between the batch
	// in hand (b) and the queue (q), b + q + 1 >= read, so the larger of
	// the two held at least (read-1)/2 frames, each at least least bytes.
	least := int64(len(ev[0].Raw))
	for i, s := range ev {
		checkBytes(t, i, s, bigFrame(i))
		least = min(least, int64(len(s.Raw)))
	}
	if batch := (read - 1) / 2 * least; batch <= c5.DefaultMaxCommitBytes {
		t.Fatalf("a batch held at least %d frames of at least %d bytes, %d in all, not over the %d cap: the test cannot tell",
			(read-1)/2, least, batch, c5.DefaultMaxCommitBytes)
	}
	t.Logf("%d frames read with the store pinned; stored events of %d bytes or more, so one batch held more than %d bytes against the %d cap",
		read, least, (read-1)/2*least, c5.DefaultMaxCommitBytes)
	st = g.waitStatus(func(st receive.Status) bool { return st.Stored >= n }, 20*time.Second)
	if st.Received != n || st.Stored != n || sumMap(st.Dropped) != 0 {
		t.Errorf("received %d, stored %d, dropped %v; want %d, %d and none", st.Received, st.Stored, st.Dropped, n, n)
	}
}

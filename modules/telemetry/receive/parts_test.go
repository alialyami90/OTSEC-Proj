package receive

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/store"
)

// tapLog sits between the receiver and a real store.Log, and records each
// AppendBatch the receiver makes. It can hold the first call so that the
// frames behind it queue up into one large batch, and refuse calls from the
// n-th on while hold is set (a full quota), having written nothing.
type tapLog struct {
	inner Appender
	gate  chan struct{} // the first call waits for this to close; nil is no wait

	mu     sync.Mutex
	sizes  []int64 // len(Event) summed, per call
	counts []int   // records per call
	failed []int   // the calls refused by failFrom
	// failFrom, when above 0, refuses the call with that number (counting
	// from 1) and, unless once is set, every later one while hold is true.
	failFrom int
	hold     bool
	once     bool
	first    sync.Once
}

func (l *tapLog) AppendBatch(ctx context.Context, recs []store.Record) ([]store.Receipt, error) {
	l.first.Do(func() {
		if l.gate != nil {
			<-l.gate
		}
	})
	var n int64
	for _, r := range recs {
		n += int64(len(r.Event))
	}
	l.mu.Lock()
	l.sizes = append(l.sizes, n)
	l.counts = append(l.counts, len(recs))
	call := len(l.sizes)
	refuse := l.failFrom > 0 && (call == l.failFrom || call > l.failFrom && l.hold && !l.once)
	if refuse {
		l.failed = append(l.failed, call)
	}
	l.mu.Unlock()
	if refuse {
		return nil, &store.Error{Code: store.CodeQuotaReached, Detail: "test quota"}
	}
	return l.inner.AppendBatch(ctx, recs)
}

func (l *tapLog) release() {
	l.mu.Lock()
	l.hold = false
	l.mu.Unlock()
}

func (l *tapLog) calls() (sizes []int64, counts []int, failed []int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]int64(nil), l.sizes...), append([]int(nil), l.counts...), append([]int(nil), l.failed...)
}

// bytesCap is a group whose commit is capped at n bytes and, as the rigs'
// default, 100 records.
func bytesCap(n int64) store.GroupOptions {
	return store.GroupOptions{MaxEvents: 100, MaxWait: 5 * time.Millisecond, MaxCommitBytes: n}
}

// splitRig is a rig whose store.Log is built with opt, behind a tap. cfgCap
// and cfgN are Config.MaxCommitBytes and MaxCommitRecords: the node sets
// them from the options it builds its Log with, so tests do the same.
func splitRig(t *testing.T, transport asset.Transport, opt store.GroupOptions, cfgCap int64, cfgN int, tap *tapLog, mut func(*Config)) *rig {
	t.Helper()
	mc := &memCommitter{}
	class := store.ClassSyslogStream
	if transport == asset.SyslogUDP {
		class = store.ClassSyslogDatagram
	}
	log, err := store.NewLog(mc, testNode, map[store.StreamID]store.StreamClass{testStream: class}, opt, nil)
	if err != nil {
		t.Fatal(err)
	}
	tap.inner = log
	g := newRig(t, transport, func(c *Config) {
		c.Log = tap
		c.MaxCommitBytes = cfgCap
		c.MaxCommitRecords = cfgN
		if mut != nil {
			mut(c)
		}
	})
	g.store = mc
	return g
}

// bigMsgs returns n syslog messages of about size bytes, numbered, so that
// order is checkable.
func bigMsgs(n, size int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("<13>Oct 11 22:14:15 host app: msg %04d %s", i, strings.Repeat("x", size))
	}
	return out
}

// TestBatchSplitsAtCommitCap: frames that queue behind a slow commit are
// committed in parts of at most the commit cap, in order, each message once.
// The Log refuses a batch over its cap, so a part over it would show as a
// store error: none is allowed, which is what makes this a test of the
// split and not of the retry below.
func TestBatchSplitsAtCommitCap(t *testing.T) {
	const logCap = store.MinRecordBytes
	tap := &tapLog{gate: make(chan struct{})}
	g := splitRig(t, asset.SyslogTCP, bytesCap(logCap), logCap, 100, tap, nil)
	sent := bigMsgs(40, 6000)
	c := g.dial(addrA)
	defer c.Close()
	c.Write(octet(sent...))
	g.wait("all read", func() bool { return g.r.Status().Received == int64(len(sent)) })
	close(tap.gate)
	g.wait("all stored", func() bool { return g.store.count() == len(sent) })

	sizes, counts, _ := tap.calls()
	multi := 0
	for i, n := range sizes {
		if n > logCap && counts[i] > 1 {
			t.Errorf("call %d: %d records, %d bytes, over the cap %d", i+1, counts[i], n, logCap)
		}
		if counts[i] > 1 {
			multi++
		}
	}
	if multi < 3 {
		t.Errorf("only %d parts of several records in %v: the batch did not split", multi, counts)
	}
	if st := g.r.Status(); st.LastErr != "" || len(st.Dropped) != 0 && st.Dropped[DropStore] != 0 {
		t.Errorf("a store error or drop: %q %v", st.LastErr, st.Dropped)
	}
	got := msgs(t, g.store.events(t))
	if fmt.Sprint(got) != fmt.Sprint(sent) {
		t.Errorf("stored %d messages, not the %d sent, once each and in order", len(got), len(sent))
	}
}

// TestHeldPartDoesNotResendEarlierParts: a stream part the store refuses is
// held and tried again alone. The parts before it stay stored and are not
// stored twice; the parts after it wait, so the stream stays in order. A
// crash while a part is held would leave only the earlier parts stored, and
// the sender's resend would give duplicates, never a loss.
func TestHeldPartDoesNotResendEarlierParts(t *testing.T) {
	const logCap = store.MinRecordBytes
	tap := &tapLog{gate: make(chan struct{}), failFrom: 3, hold: true}
	g := splitRig(t, asset.SyslogTCP, bytesCap(logCap), logCap, 100, tap, nil)
	sent := bigMsgs(40, 6000)
	c := g.dial(addrA)
	defer c.Close()
	c.Write(octet(sent...))
	g.wait("all read", func() bool { return g.r.Status().Received == int64(len(sent)) })
	close(tap.gate)
	g.wait("held", func() bool { return g.r.Status().Held })
	_, counts, _ := tap.calls()
	// Calls 1 (the first frame) and 2 are stored; call 3 and its retries are not.
	want := counts[0] + counts[1]
	time.Sleep(100 * time.Millisecond) // the retries (Limits.Retry is 10 ms) run
	if n := g.store.count(); n != want {
		t.Fatalf("while a part is held, %d stored; the %d of the parts before it must stay, and no more", n, want)
	}
	if _, _, failed := tap.calls(); len(failed) < 2 {
		t.Fatalf("part refused %d times, want it retried", len(failed))
	}
	tap.release()
	g.wait("all stored", func() bool { return g.store.count() == len(sent) })
	got := msgs(t, g.store.events(t))
	if fmt.Sprint(got) != fmt.Sprint(sent) {
		t.Errorf("stored %d messages, not the %d sent, once each and in order", len(got), len(sent))
	}
	if st := g.r.Status(); st.Held || st.Stored != int64(len(sent)) || st.Dropped[DropStore] != 0 {
		t.Errorf("status %+v", st)
	}
}

// TestDatagramPartRefusedIsDroppedAndCounted: a datagram part the store
// refuses is dropped and counted; the parts before and after it are stored.
// Every datagram read is stored or counted.
func TestDatagramPartRefusedIsDroppedAndCounted(t *testing.T) {
	const logCap = store.MinRecordBytes
	tap := &tapLog{gate: make(chan struct{}), failFrom: 3, once: true}
	g := splitRig(t, asset.SyslogUDP, bytesCap(logCap), logCap, 100, tap, nil)
	sent := bigMsgs(40, 6000)
	c := g.udp(addrA)
	defer c.Close()
	for _, m := range sent {
		c.Write([]byte(m))
	}
	// The kernel may drop a datagram on a loaded runner; the reader's own
	// count is the denominator.
	g.wait("read", func() bool { return g.r.Status().Received >= 20 })
	time.Sleep(200 * time.Millisecond)
	read := g.r.Status().Received
	close(tap.gate)
	g.wait("a part refused", func() bool { _, _, f := tap.calls(); return len(f) > 0 })
	g.wait("all accounted for", func() bool {
		st := g.r.Status()
		return st.Stored+st.Dropped[DropStore] == read
	})
	st := g.r.Status()
	_, counts, failed := tap.calls()
	if len(failed) != 1 || st.Dropped[DropStore] != int64(counts[failed[0]-1]) {
		t.Errorf("failed calls %v of %v; dropped %d", failed, counts, st.Dropped[DropStore])
	}
	if st.Stored == 0 || st.Dropped[DropStore] == 0 || st.Stored != int64(g.store.count()) {
		t.Errorf("stored %d (store holds %d), dropped %d: a refused part must cost only its own datagrams", st.Stored, g.store.count(), st.Dropped[DropStore])
	}
}

// TestLowerLogCapIsLearnt: Config.MaxCommitBytes above the Log's real cap
// (here the default 1 MiB against 64 KiB) does not stall the stream: the
// Log's refusal halves the cap until the parts fit, and nothing is dropped.
func TestLowerLogCapIsLearnt(t *testing.T) {
	const logCap = store.MinRecordBytes
	tap := &tapLog{gate: make(chan struct{})}
	g := splitRig(t, asset.SyslogTCP, bytesCap(logCap), 0, 0, tap, nil)
	sent := bigMsgs(40, 6000)
	c := g.dial(addrA)
	defer c.Close()
	c.Write(octet(sent...))
	g.wait("all read", func() bool { return g.r.Status().Received == int64(len(sent)) })
	close(tap.gate)
	g.wait("all stored", func() bool { return g.store.count() == len(sent) })
	// The cap is halved until a part fits, so it ends within a factor of
	// two of the Log's, not at it.
	if cap := g.r.commitAt.Load(); cap >= store.DefaultMaxCommitBytes || cap < logCap/2 {
		t.Errorf("cap %d after learning from a Log that takes %d", cap, logCap)
	}
	if st := g.r.Status(); st.Dropped[DropStore] != 0 || !strings.Contains(st.LastErr, string(store.CodeRecordTooLarge)) {
		t.Errorf("dropped %d, last error %q: the refusal that taught the cap must show", st.Dropped[DropStore], st.LastErr)
	}
	if got := msgs(t, g.store.events(t)); fmt.Sprint(got) != fmt.Sprint(sent) {
		t.Errorf("stored %d messages, not the %d sent, once each and in order", len(got), len(sent))
	}
}

// TestRecordOverCommitCapIsCountedNotHeld: one record that no commit can
// take is dropped and counted as store, with the Log's reason in LastErr,
// and the messages behind it are stored. Holding it would stop the stream
// for good.
func TestRecordOverCommitCapIsCountedNotHeld(t *testing.T) {
	const logCap = store.MinRecordBytes
	tap := &tapLog{}
	g := splitRig(t, asset.SyslogTCP, bytesCap(logCap), logCap, 100, tap, func(c *Config) { c.Limits.MaxMessage = 65536 })
	huge := "<13>Oct 11 22:14:15 host app: huge " + strings.Repeat("x", 60000)
	after := "<13>Oct 11 22:14:16 host app: after"
	c := g.dial(addrA)
	defer c.Close()
	c.Write(octet(huge, after))
	g.wait("the message behind it stored", func() bool { return g.store.count() == 1 })
	st := g.r.Status()
	if st.Dropped[DropStore] != 1 || st.Held || !strings.Contains(st.LastErr, string(store.CodeRecordTooLarge)) {
		t.Errorf("status %+v", st)
	}
	if got := msgs(t, g.store.events(t)); fmt.Sprint(got) != fmt.Sprint([]string{after}) {
		t.Errorf("stored %q", got)
	}
}

func TestNewRefusesCommitCaps(t *testing.T) {
	for _, n := range []int64{-1, 1, store.MinRecordBytes - 1} {
		if _, err := New(Config{MaxCommitBytes: n}); !errors.Is(err, ErrConfig) {
			t.Errorf("MaxCommitBytes %d: %v", n, err)
		}
	}
	for _, n := range []int{-1, store.MaxBatch + 1} {
		if _, err := New(Config{MaxCommitRecords: n}); !errors.Is(err, ErrConfig) {
			t.Errorf("MaxCommitRecords %d: %v", n, err)
		}
	}
}

// recs returns n records with events of the given sizes (the last size
// repeats).
func recsOf(sizes ...int) []store.Record {
	out := make([]store.Record, len(sizes))
	for i, n := range sizes {
		out[i] = store.Record{Event: make([]byte, n)}
	}
	return out
}

// TestPartEndAtBothCaps: the boundary of each cap, exactly: a part holds as
// many records as fit the byte cap and the record cap, whichever is
// reached first, and cap+1 of either starts another part. A record over the
// byte cap is a part of its own.
func TestPartEndAtBothCaps(t *testing.T) {
	r := &Receiver{}
	for _, c := range []struct {
		name    string
		bytes   int64
		records int64
		recs    []store.Record
		want    []int // the sizes of the parts, in records
	}{
		{"bytes: exactly the cap", 100, 1000, recsOf(40, 40, 20), []int{3}},
		{"bytes: cap+1", 100, 1000, recsOf(40, 40, 21), []int{2, 1}},
		{"bytes: a record alone over the cap", 100, 1000, recsOf(10, 150, 10), []int{1, 1, 1}},
		{"records: exactly the cap", 1 << 30, 4, recsOf(1, 1, 1, 1), []int{4}},
		{"records: cap+1", 1 << 30, 4, recsOf(1, 1, 1, 1, 1), []int{4, 1}},
		{"records: twice the cap+1", 1 << 30, 4, recsOf(1, 1, 1, 1, 1, 1, 1, 1, 1), []int{4, 4, 1}},
		{"bytes reached first", 10, 4, recsOf(5, 5, 5, 5, 5), []int{2, 2, 1}},
		{"records reached first", 1000, 2, recsOf(5, 5, 5, 5, 5), []int{2, 2, 1}},
	} {
		r.commitAt.Store(c.bytes)
		r.commitN.Store(c.records)
		var got []int
		for lo := 0; lo < len(c.recs); {
			hi := r.partEnd(c.recs, lo)
			if hi <= lo {
				t.Fatalf("%s: no progress at %d", c.name, lo)
			}
			got = append(got, hi-lo)
			lo = hi
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: parts %v, want %v", c.name, got, c.want)
		}
	}
}

// TestRecordCapPlusOneDatagramsAllStored: with the Log refusing a batch of
// more records than its record cap (C5 0.5), a queue that hands the writer
// cap+1 datagrams, and then more, loses none: every part is within the cap,
// the Log refuses nothing, and every datagram read is stored. The caps come
// from the group options, as the node sets them.
func TestRecordCapPlusOneDatagramsAllStored(t *testing.T) {
	opt := store.GroupOptions{MaxEvents: 4, MaxWait: 5 * time.Millisecond, MaxCommitRecords: 8}
	for _, tr := range []asset.Transport{asset.SyslogUDP, asset.SyslogTCP} {
		t.Run(string(tr), func(t *testing.T) {
			tap := &tapLog{gate: make(chan struct{})}
			g := splitRig(t, tr, opt, store.DefaultMaxCommitBytes, opt.CommitRecords(), tap, nil)
			// One more than the cap, behind the call the gate holds, then
			// two caps and one more.
			const n = 1 + 9 + 17
			sent := bigMsgs(n, 100)
			var send func(string)
			if tr == asset.SyslogUDP {
				c := g.udp(addrA)
				defer c.Close()
				send = func(m string) { c.Write([]byte(m)) }
			} else {
				c := g.dial(addrA)
				defer c.Close()
				send = func(m string) { c.Write(octet(m)) }
			}
			for _, m := range sent {
				send(m)
			}
			// The kernel may drop a datagram; the reader's count is the
			// denominator, and a stream loses none.
			g.wait("read", func() bool { return g.r.Status().Received >= 20 })
			time.Sleep(200 * time.Millisecond)
			read := g.r.Status().Received
			if tr == asset.SyslogTCP && read != n {
				t.Fatalf("read %d of %d", read, n)
			}
			close(tap.gate)
			g.wait("all stored", func() bool { return g.r.Status().Stored == read })
			_, counts, failed := tap.calls()
			over := 0
			for _, c := range counts {
				if c > opt.CommitRecords() {
					over++
				}
			}
			if over != 0 || len(failed) != 0 {
				t.Errorf("calls of %v records against a cap of %d", counts, opt.CommitRecords())
			}
			multi := 0
			for _, c := range counts {
				if c == opt.CommitRecords() {
					multi++
				}
			}
			if multi < 2 {
				t.Errorf("calls %v: the queued datagrams were not carried in full parts", counts)
			}
			if st := g.r.Status(); st.LastErr != "" && !strings.Contains(st.LastErr, "EOF") || st.Dropped[DropStore] != 0 || int64(g.store.count()) != read {
				t.Errorf("status %+v, store holds %d of %d read", st, g.store.count(), read)
			}
		})
	}
}

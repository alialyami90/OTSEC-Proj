package syslogreceive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/url"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/modules/telemetry/receive"
)

// The unknown budget across restarts (A4, #178; A3's conditions on D3-3).
// Claim under test: across any number of restarts, each passing what
// unknown senders stored on the stream in the trailing UnknownWindow,
// unknown senders store at most UnknownBytes x (1 + T/UnknownWindow) in any
// time T. The count passed at each start is A6's own, read from the real
// C5 store between runs: the sum of len(event) over the stream's records
// that carry asset-unresolved, by received time, a record stamped after
// now counting as inside the window (the rule in receive.Config). It is
// not the receiver's or the node's count.

// strangerMsg is about 9 KiB as a stored event.
var strangerMsg = []byte("<13>" + strings.Repeat("unknown sender a6 ", 200))

// serveOn serves one listener on an existing log, as a restart does.
func serveOn(t *testing.T, log *c5.Log, path string, lim receive.Limits, spent int64) *rig {
	t.Helper()
	h := &healths{}
	r, err := receive.New(receive.Config{
		Node: node, ID: "a6", Stream: sDgram, Transport: asset.SyslogUDP, Address: "127.0.0.1:0",
		Target: asset.Simulated, Plaintext: true,
		Senders: receive.Senders{ipA: {AssetID: assetA, Target: asset.Simulated, Dialect: normalize.DialectRFC}},
		Log:     log, Health: h, Received: received, Limits: lim, UnknownSpent: spent,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := r.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := &rig{t: t, r: r, log: log, addr: addr, db: path, stream: sDgram, h: h, stop: cancel, done: make(chan error, 1)}
	go func() { g.done <- r.Serve(ctx) }()
	t.Cleanup(g.close)
	return g
}

// unknownRecord is one stored record from an unknown sender.
type unknownRecord struct {
	at        time.Time // received.utc
	committed time.Time // the store's committed_at, a diagnostic only
	bytes     int64
}

// committedAt reads the store's commit time of each of the stream's events.
func (g *rig) committedAt() map[int64]time.Time {
	g.t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: g.db}).EscapedPath()+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		g.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT seq, committed_at FROM events WHERE stream = ?", string(g.stream))
	if err != nil {
		g.t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64]time.Time{}
	for rows.Next() {
		var seq, ns int64
		if err := rows.Scan(&seq, &ns); err != nil {
			g.t.Fatal(err)
		}
		out[seq] = time.Unix(0, ns)
	}
	if err := rows.Err(); err != nil {
		g.t.Fatal(err)
	}
	return out
}

// unknownRecords reads the stream's asset-unresolved records with their
// received time, commit time and stored length.
func (g *rig) unknownRecords() []unknownRecord {
	g.t.Helper()
	var out []unknownRecord
	committed := g.committedAt()
	for _, s := range g.events() {
		var e struct {
			Received struct {
				UTC string `json:"utc"`
			} `json:"received"`
		}
		if err := json.Unmarshal(s.Raw, &e); err != nil {
			g.t.Fatal(err)
		}
		if !s.has("asset-unresolved") {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, e.Received.UTC)
		if err != nil {
			g.t.Fatalf("seq %d: received %q: %v", s.Seq, e.Received.UTC, err)
		}
		out = append(out, unknownRecord{at, committed[s.Seq], int64(len(s.Raw))})
	}
	return out
}

// spentIn is A6's node count: what unknown senders stored in the window
// before now, a record stamped after now counting as inside it.
func spentIn(recs []unknownRecord, now time.Time, window time.Duration) (n int64) {
	for _, r := range recs {
		if r.at.After(now.Add(-window)) {
			n += r.bytes
		}
	}
	return n
}

// floodUntil sends from the stranger, and from known asset A now and then,
// until end; then it waits until a marker from A, sent after the flood, is
// stored, so every stranger datagram before it has been spent or dropped.
func (g *rig) floodUntil(end time.Time, mark string) {
	g.t.Helper()
	c := dialFrom(g.t, ipStranger, "udp", g.addr)
	known := dialFrom(g.t, ipA, "udp", g.addr)
	for i := 0; time.Now().Before(end); i++ {
		c.Write(strangerMsg)
		if i%20 == 0 {
			fmt.Fprintf(known, "<13>known %d", i)
		}
		time.Sleep(2 * time.Millisecond)
	}
	for wait := time.Now().Add(20 * time.Second); time.Now().Before(wait); {
		known.Write([]byte(mark))
		if g.hasMarker(mark) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	g.t.Fatalf("marker %q not stored: %s", mark, g.why(mark))
}

// why is a diagnostic for a marker not found: the listener's counts,
// whether the Log has stopped and Serve has returned, and how many stored events hold the marker read both ways
// (hasMarker's text search, and the decoded native bytes).
func (g *rig) why(mark string) string {
	st := g.r.Status()
	served := "running"
	select {
	case err := <-g.done:
		served = fmt.Sprintf("returned (%v)", err)
		g.done <- err
	default:
	}
	var text, native int
	ev := g.events()
	for _, s := range ev {
		if strings.Contains(string(s.Raw), mark[len("<13>"):]) {
			text++
		}
		if string(s.Bytes) == mark {
			native++
		}
	}
	var dropped int64
	for _, d := range st.Dropped {
		dropped += d
	}
	return fmt.Sprintf("received %d, stored %d, dropped %v, held %v, last error %q, so %d read and neither stored nor dropped; "+
		"log stopped %v; Serve %s; store write lock %s; "+
		"%d events on the stream, %d holding the marker's text, %d whose native bytes are the marker\n%s",
		st.Received, st.Stored, st.Dropped, st.Held, st.LastErr, st.Received-st.Stored-dropped-st.Empty,
		g.log.Stopped(), served, g.writeLock(), len(ev), text, native, stacks())
}

// writeLock says whether another connection holds SQLite's write lock now,
// as the store does while it commits: free means the store is not in a
// commit, so a stalled writer is waiting elsewhere.
func (g *rig) writeLock() string {
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: g.db}).EscapedPath()+"?_pragma=busy_timeout(1000)")
	if err != nil {
		return err.Error()
	}
	defer db.Close()
	ctx := context.Background()
	c, err := db.Conn(ctx)
	if err != nil {
		return err.Error()
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return "held (" + err.Error() + ")"
	}
	c.ExecContext(ctx, "ROLLBACK")
	return "free"
}

// stacks is every goroutine stack that runs this module's code, grouped:
// where the listener's writer and the Log wait when a marker is lost.
func stacks() string {
	var w strings.Builder
	pprof.Lookup("goroutine").WriteTo(&w, 1)
	var out []string
	for _, s := range strings.Split(w.String(), "\n\n") {
		if strings.Contains(s, "otsec.local/otsec/modules/") || strings.Contains(s, "otsec.local/otsec/contracts/store") ||
			strings.Contains(s, "otsec.local/otsec/platform/store") {
			out = append(out, s)
		}
	}
	return strings.Join(out, "\n\n")
}

// hasMarker reports whether a stored event holds mark, without reading and
// decoding every event on each poll: the rig's own reads must not take the
// CPU the receiver needs on a slow runner. The marker's text appears
// verbatim in the event's native bytes, and events() confirms it.
func (g *rig) hasMarker(mark string) bool {
	g.t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: g.db}).EscapedPath()+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		g.t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE stream = ? AND instr(event, ?) > 0", string(g.stream), mark[len("<13>"):]).Scan(&n); err != nil {
		g.t.Fatal(err)
	}
	if n == 0 {
		return false
	}
	for _, s := range g.events() {
		if string(s.Bytes) == mark {
			return true
		}
	}
	return false
}

type runSpan struct {
	from, to time.Time // before New, after the marker is stored
	stored   int64     // unknown bytes this run stored
	// edge is a diagnostic: the unknown bytes that the count at this start
	// left out by received time but that were committed inside its window
	// (read before from-W, stored after it), and lag the largest
	// committed-received gap among the records counted so far.
	edge int64
	lag  time.Duration
}

// restarts runs n listeners one after another on one store, each flooded
// for a random part of the window after a random gap, each started with
// spent(i, records so far). It returns each run's span and stored bytes.
func restarts(t *testing.T, seed int64, n int, lim receive.Limits, spent func(now time.Time, recs []unknownRecord) int64) []runSpan {
	t.Helper()
	log, path := open(t, 256<<20)
	rnd := rand.New(rand.NewSource(seed))
	var runs []runSpan
	var before int64
	for i := range n {
		time.Sleep(time.Duration(rnd.Int63n(int64(lim.UnknownWindow / 4))))
		from := time.Now()
		var recs []unknownRecord
		var edge int64
		var lag time.Duration
		if i > 0 {
			recs = (&rig{t: t, db: path, stream: sDgram}).unknownRecords()
			for _, r := range recs {
				if start := from.Add(-lim.UnknownWindow); !r.at.After(start) && r.committed.After(start) {
					edge += r.bytes
				}
				lag = max(lag, r.committed.Sub(r.at))
			}
		}
		g := serveOn(t, log, path, lim, spent(from, recs))
		g.floodUntil(time.Now().Add(lim.UnknownWindow/10+time.Duration(rnd.Int63n(int64(lim.UnknownWindow/3)))), fmt.Sprintf("<13>a6 marker %d", i))
		to := time.Now()
		var all int64
		for _, r := range g.unknownRecords() {
			all += r.bytes
		}
		g.close()
		runs = append(runs, runSpan{from, to, all - before, edge, lag})
		before = all
	}
	return runs
}

// worst is the largest excess over UnknownBytes x (1 + T/window) across
// every run of consecutive restarts i..j, T from before run i's New to
// after run j's last spend: the claim must hold for every such span, not
// only the whole.
func worst(runs []runSpan, per int64, window time.Duration) (excess float64, at string) {
	excess = math.Inf(-1)
	for i := range runs {
		var sum int64
		for j := i; j < len(runs); j++ {
			sum += runs[j].stored
			T := runs[j].to.Sub(runs[i].from)
			if e := float64(sum) - float64(per)*(1+T.Seconds()/window.Seconds()); e > excess {
				excess, at = e, fmt.Sprintf("runs %d..%d: %d bytes in %v", i, j, sum, T)
			}
		}
	}
	return excess, at
}

func TestUnknownSpentAcrossRestarts(t *testing.T) {
	const (
		per    = 512 << 10
		window = 3 * time.Second
	)
	lim := receive.Limits{Rate: 100000, Burst: 100000, UnknownBytes: per, UnknownWindow: window}
	for _, seed := range []int64{1, 2} {
		t.Run(fmt.Sprint("seed ", seed), func(t *testing.T) {
			runs := restarts(t, seed, 10, lim, func(now time.Time, recs []unknownRecord) int64 {
				return spentIn(recs, now, window)
			})
			e, at := worst(runs, per, window)
			var total int64
			for _, r := range runs {
				total += r.stored
			}
			var edges int64
			var lag time.Duration
			for _, r := range runs {
				edges += r.edge
				lag = max(lag, r.lag)
			}
			t.Logf("%d restarts: %d unknown bytes; worst span %s, %.0f bytes from the bound", len(runs), total, at, e)
			// Diagnostic for the cause, not part of the claim: records read
			// before a start's window and committed inside it are left out
			// of a count by received time (A4, A3 on #178's handoff).
			t.Logf("read-to-commit: largest lag %v; %d bytes read before a start's window and committed inside it, over all starts", lag, edges)
			if e > 0 {
				t.Errorf("unknown senders stored past UnknownBytes x (1 + T/window): %s, %.0f bytes over (%d bytes read before a start's window and committed inside it; largest lag %v)", at, e, edges, lag)
			}
			if runs[0].stored < per*8/10 {
				t.Errorf("the first run stored %d of a budget of %d: the flood did not reach the budget, so the test cannot tell", runs[0].stored, per)
			}
		})
	}
	// Control: the same restarts each passing 0, as before #178, break the
	// bound; otherwise the check above could not tell.
	runs := restarts(t, 1, 10, lim, func(time.Time, []unknownRecord) int64 { return 0 })
	if e, at := worst(runs, per, window); e <= 0 {
		t.Errorf("control: restarts passing 0 kept to the bound (%s, %.0f), so the test cannot tell", at, e)
	}
}

// A count below 0 or above UnknownBytes starts the budget empty: within a
// window of an hour, nothing from an unknown sender is stored. A count of
// exactly UnknownBytes leaves nothing either; 0 starts it full.
func TestUnknownSpentOutOfRangeStartsEmpty(t *testing.T) {
	const per = 512 << 10
	lim := receive.Limits{Rate: 100000, Burst: 100000, UnknownBytes: per, UnknownWindow: time.Hour}
	for _, spent := range []int64{-1, math.MinInt64, per + 1, math.MaxInt64, per, 0} {
		t.Run(fmt.Sprint(spent), func(t *testing.T) {
			t.Parallel()
			log, path := open(t, 64<<20)
			g := serveOn(t, log, path, lim, spent)
			g.floodUntil(time.Now().Add(400*time.Millisecond), "<13>a6 marker")
			recs := g.unknownRecords()
			st := g.r.Status()
			g.close()
			switch {
			case spent == 0 && (len(recs) == 0 || st.Dropped[receive.DropUnknownBudget] == 0):
				t.Errorf("spent 0: %d records stored, dropped %v; want a full budget used up", len(recs), st.Dropped)
			case spent != 0 && len(recs) != 0:
				t.Errorf("spent %d: %d records stored from an unknown sender; the budget should start empty", spent, len(recs))
			case spent != 0 && st.Dropped[receive.DropUnknownBudget] == 0:
				t.Errorf("spent %d: nothing dropped as unknown-budget, so the flood did not reach the receiver", spent)
			}
		})
	}
}

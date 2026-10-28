package syslogreceive

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
	"otsec.local/otsec/modules/telemetry/receive"
	"otsec.local/otsec/platform/store"
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
	rows0, st0 := g.rows(), g.r.Status()
	for i := 0; time.Now().Before(end); i++ {
		c.Write(strangerMsg)
		if i%20 == 0 {
			fmt.Fprintf(known, "<13>known %d", i)
		}
		time.Sleep(2 * time.Millisecond)
	}
	g.awaitMarker(known, mark, rows0, st0)
}

// markerUnread is how long the receiver may sit settled, with markers sent
// every 50 ms and none of them read, before the test says the datagrams
// are not reaching it. It bounds only that: never a commit in progress.
const markerUnread = 20 * time.Second

// markerDrops is how many sends in a row may each be read alone and
// dropped, the receiver holding nothing, before that is the receiver
// dropping the marker: a datagram left from the flood is read with or
// before a marker, so it cannot make that many rounds alone.
const markerDrops = 20

// awaitMarker sends mark from A until it is stored (B6, #230). The wait
// is on the receiver's own accounting, not on a deadline (#247's Windows
// run, job 122396769041: a fixed 20 s wait failed while the same runner's
// store commits sat in FlushFileBuffers for minutes). Every message read
// is held (queued, or in a commit), stored, dropped and counted, or empty:
//
//   - while any is held, the store has it, and a slow commit is not a
//     loss, so the wait goes on with no deadline; the test binary's
//     timeout is the backstop. A hold past markerUnread prints the
//     receiver's goroutines, which tell a commit in progress from a
//     message lost uncounted;
//   - settled (none held), every marker read was stored or dropped and
//     counted (queue-full behind a slow commit is the receiver's
//     documented behaviour under load), so the marker is sent again; and
//     the store's new rows must equal the receiver's Stored, or a message
//     counted stored is not in the store: a real loss, which fails; and
//     markerDrops sends in a row each read alone and dropped, while the
//     receiver held nothing, are the receiver dropping A's marker itself,
//     which fails with the reason; a marker the store refused or failed
//     (reason store, LastErr "store: ...") fails at once as a store
//     failure, not the receiver's: in this rig neither a refusal nor a
//     failure is expected, and a failed commit stops the C5 log, so no
//     later send could be stored (B5 on #255);
//   - messages held while the writer waits on an empty queue were lost
//     without a count, which fails;
//   - settled with nothing read for markerUnread while markers are sent:
//     the datagrams are not reaching the receiver (the OS dropped them, or
//     the reader is not scheduled). That fails as such, and is not counted
//     as a drop the receiver made.
func (g *rig) awaitMarker(known net.Conn, mark string, rows0 int64, st0 receive.Status) {
	g.t.Helper()
	var (
		sent, unread int
		dropRounds   int
		idle         int            // polls with messages held and the writer idle
		last         receive.Status // at the last send
		lastSend     time.Time
		quiet        time.Time // since when settled with nothing read
		heldSince    time.Time
		longest      time.Duration
		noted        bool
	)
	send := func(st receive.Status) {
		known.Write([]byte(mark))
		sent, last, lastSend = sent+1, st, time.Now()
	}
	for {
		st := g.r.Status()
		if g.hasMarker(mark) {
			g.t.Logf("marker %q stored after %d sends (%d not read when sent again); since the flood began: dropped %v, longest hold %v",
				mark, sent, unread, dropsSince(st, st0), longest)
			return
		}
		held := st.Received - st.Stored - st.Empty - dropped(st)
		switch {
		case held > 0:
			quiet = time.Time{}
			// Held, yet the writer waits on an empty queue and the reader
			// on the socket: on two polls in a row with nothing changed,
			// those messages are gone uncounted. Read from the goroutine
			// states; a renamed function only disables this check, and
			// the wait then ends at the binary's timeout.
			if again := g.r.Status(); again.Received == st.Received && again.Stored == st.Stored && dropped(again) == dropped(st) && writerIdle(g.r) {
				idle++
			} else {
				idle = 0
			}
			if idle >= 2 {
				g.markerFatalf(mark, "marker %q: the receiver holds %d read messages and its writer waits on an empty queue: messages lost without a count (%+v)\n%s",
					mark, held, st, receiverStacks())
			}
			if heldSince.IsZero() {
				heldSince = time.Now()
			}
			if d := time.Since(heldSince); d > longest {
				longest = d
				if d > markerUnread && !noted {
					// t.Logf is lost if the binary's timeout ends the test.
					noted = true
					// The receiver's goroutines tell a commit in progress
					// (the writer in AppendBatch) from a message lost
					// uncounted (the writer idle with messages held).
					fmt.Fprintf(os.Stderr, "%s: marker %q: the receiver has held %d read messages for %v; waiting. Its goroutines:\n%s\nThe store's commits:\n%s\n",
						g.t.Name(), mark, held, d, receiverStacks(), g.commitTrail())
				}
			}
		case sent == 0 || st.Received > last.Received:
			heldSince, quiet = time.Time{}, time.Time{}
			alone := sent > 0 && st.Received-last.Received == 1 && dropped(st)-dropped(last) == 1 && st.Stored == last.Stored
			switch {
			case alone && st.Dropped[receive.DropStore] > last.Dropped[receive.DropStore] && strings.HasPrefix(st.LastErr, "store: "):
				g.markerFatalf(mark, "marker %q: the store refused or failed it (log stopped: %v; %s): a store failure, not a drop the receiver made",
					mark, strings.Contains(st.LastErr, string(c5.CodeLogStopped)), st.LastErr)
			case alone:
				dropRounds++
			default:
				dropRounds = 0
			}
			if dropRounds >= markerDrops {
				g.markerFatalf(mark, "marker %q: %d sends in a row each read alone and dropped while the receiver held nothing (dropped since the flood began: %v): the receiver drops A's marker",
					mark, dropRounds, dropsSince(st, st0))
			}
			if rows, again := g.rows(), g.r.Status(); again.Received == st.Received && again.Stored == st.Stored && rows-rows0 != st.Stored-st0.Stored {
				g.markerFatalf(mark, "marker %q: the receiver counts %d stored since the flood began and the store has %d new rows: a message counted stored is not in the store (%+v)",
					mark, st.Stored-st0.Stored, rows-rows0, st)
			}
			send(st)
		default:
			heldSince = time.Time{}
			if quiet.IsZero() {
				quiet = time.Now()
			}
			if time.Since(quiet) > markerUnread {
				g.markerFatalf(mark, "marker %q: %d sent; the receiver held nothing and read none of the %d sent in the last %v (received %d, stored %d, dropped %v): the datagrams did not reach it (an OS drop, or the reader not scheduled), not a drop the receiver made",
					mark, sent, unread+1, markerUnread, st.Received, st.Stored, st.Dropped)
			}
			if time.Since(lastSend) >= 50*time.Millisecond {
				unread++
				send(last)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// receiverStacks is the stacks of the goroutines in the receive package.
// Tests run in parallel, so writerIdle picks out one receiver's by the
// pointer its methods print as their first argument.
func receiverStacks() string {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var out []string
	for _, gr := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(gr, "modules/telemetry/receive.") {
			out = append(out, gr)
		}
	}
	return strings.Join(out, "\n\n")
}

// writerIdle reports whether r's datagram writer waits on its queue and
// its reader on the socket, as their goroutine states show.
func writerIdle(r *receive.Receiver) bool {
	var writer, reader bool
	p := fmt.Sprintf("%p", r)
	for _, gr := range strings.Split(receiverStacks(), "\n\n") {
		head, _, _ := strings.Cut(gr, "\n")
		switch {
		case strings.Contains(gr, "receive.(*Receiver).writeDatagrams("+p):
			writer = strings.Contains(head, "[chan receive") && !strings.Contains(gr, "AppendBatch")
		case strings.Contains(gr, "receive.(*Receiver).serveDatagrams("+p):
			reader = strings.Contains(gr, "ReadFrom")
		}
	}
	return writer && reader
}

func dropped(st receive.Status) (n int64) {
	for _, d := range st.Dropped {
		n += d
	}
	return n
}

func dropsSince(st, st0 receive.Status) map[string]int64 {
	out := map[string]int64{}
	for r, n := range st.Dropped {
		if d := n - st0.Dropped[r]; d > 0 {
			out[r] = d
		}
	}
	return out
}

// rows counts the stream's stored events.
func (g *rig) rows() (n int64) {
	g.t.Helper()
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: g.db}).EscapedPath()+"?_pragma=query_only(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		g.t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE stream = ?", string(g.stream)).Scan(&n); err != nil {
		g.t.Fatal(err)
	}
	return n
}

// markerFatalf fails the test for mark with the listener's diagnostic
// (why) after the message.
func (g *rig) markerFatalf(mark, format string, args ...any) {
	g.t.Helper()
	g.t.Fatalf(format+"\n%s", append(args, g.why(mark))...)
}

// why is a diagnostic for a marker not found: the listener's counts, the
// commit caps it has learnt, whether the Log has stopped and Serve has
// returned, and how many stored events hold the marker read both ways
// (hasMarker's text search, and the decoded native bytes).
func (g *rig) why(mark string) string {
	// The trail first: every probe below opens a connection of its own,
	// and writeLock's BEGIN IMMEDIATE by itself puts a committing store in
	// SQLite's busy handler.
	trail := g.commitTrail()
	st := g.r.Status()
	b, n := g.r.CommitCaps()
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
		"caps %d bytes %d records; log stopped %v; Serve %s; store write lock %s; "+
		"%d events on the stream, %d holding the marker's text, %d whose native bytes are the marker; files %s\n"+
		"the store's commits, sampled before these probes:\n%s\n%s",
		st.Received, st.Stored, st.Dropped, st.Held, st.LastErr, st.Received-st.Stored-dropped-st.Empty,
		b, n, g.log.Stopped(), served, g.writeLock(), len(ev), text, native, g.files(), trail, stacks())
}

// writeLock says whether another connection holds SQLite's write lock at
// this instant (no busy wait), as the store does while it commits: free
// means the store is not in a commit, so a stalled writer is waiting
// elsewhere. The error text carries SQLite's extended code.
func (g *rig) writeLock() string {
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: g.db}).EscapedPath()+"?_pragma=busy_timeout(0)")
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

// commitTrail samples the Log's commit goroutines four times, a second
// apart: the rows stored, the database/sql pools open in this process (one
// connectionOpener goroutine each, so a connection left open by anyone
// shows), and where each commit goroutine is. A commit in one place on
// every sample is stuck there; one that moves is slow.
func (g *rig) commitTrail() string {
	var out []string
	for i := range 4 {
		if i > 0 {
			time.Sleep(time.Second)
		}
		var w strings.Builder
		pprof.Lookup("goroutine").WriteTo(&w, 1)
		all := w.String()
		pools := 0
		var commits []string
		for _, s := range strings.Split(all, "\n\n") {
			n := 1
			fmt.Sscanf(s, "%d @", &n)
			if strings.Contains(s, "database/sql.(*DB).connectionOpener") {
				pools += n
			}
			if strings.Contains(s, "contracts/store.(*Log).run") {
				commits = append(commits, fmt.Sprintf("%d at %s", n, frames(s)))
			}
		}
		if len(commits) == 0 {
			commits = []string{"none"}
		}
		out = append(out, fmt.Sprintf("  t+%ds: received %d stored %d; %d sql pools open; BEGIN IMMEDIATE %s; commits: %s",
			i, g.r.Status().Received, g.r.Status().Stored, pools, g.begins(), strings.Join(commits, "; ")))
	}
	return strings.Join(out, "\n")
}

// begins is the store's BEGIN IMMEDIATE waits (store.DB.BeginStats): how
// many, their total and longest, and how long the one in progress has
// waited.
func (g *rig) begins() string {
	v, ok := stores.Load(g.db)
	if !ok {
		return "not known"
	}
	b := v.(*store.DB).BeginStats()
	return fmt.Sprintf("%d, total %v, longest %v, waiting %v", b.Count, b.Total, b.Max, b.Waiting)
}

// frames is a pprof debug=1 stack's innermost frames, to the first in this
// module, each as its function and line.
func frames(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || f[0] != "#" {
			continue
		}
		fn, _, _ := strings.Cut(f[2], "+0x")
		file := f[len(f)-1]
		if i := strings.LastIndex(file, "/"); i >= 0 {
			file = file[i+1:]
		}
		out = append(out, fn[strings.LastIndex(fn, "/")+1:]+" "+file)
		if strings.HasPrefix(fn, "otsec.local/otsec/") || len(out) == 12 {
			break
		}
	}
	return strings.Join(out, " < ")
}

// files is the store's file and its -wal and -shm, with their sizes.
func (g *rig) files() string {
	var out []string
	for _, f := range []string{g.db, g.db + "-wal", g.db + "-shm"} {
		fi, err := os.Stat(f)
		if err != nil {
			out = append(out, f[strings.LastIndexAny(f, `/\`)+1:]+" absent")
			continue
		}
		out = append(out, fmt.Sprintf("%s %d bytes", fi.Name(), fi.Size()))
	}
	return strings.Join(out, ", ")
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

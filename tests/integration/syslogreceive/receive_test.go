// Package syslogreceive is A6's acceptance check of the Syslog listener
// (#150, P3-A4) on the real store: every listener commits through C5
// startup, a real c5.Log and the platform SQLite store, and A6 reads the
// events back from the database file with its own connection. None of A4's
// test helpers are used. The oracle is the sender's bytes, frame by frame
// (R4.4, V-S8), and the rule text of the package documentation:
//   - native.bytes are the bytes sent, without their framing, and
//     record_sha256 and evidence.sha256 are their SHA-256;
//   - framing faults keep their bytes and a flag, earlier messages survive,
//     and the listener keeps serving;
//   - a flood from one sender does not cost another sender a message, a
//     stream is slowed and not dropped, and datagram drops are counted;
//   - a TLS sender that does not prove the configured CA is refused at the
//     handshake, and nothing it sent is stored;
//   - an unknown sender is kept, unresolved, and alarmed once per address;
//   - a duplicate is stored again with the same record_sha256.
//
// Class: simulated. Senders are test sockets on 127.0.0.x.
package syslogreceive

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/telemetry/receive"
)

// payloads returns n messages of mixed shape from a fixed seed: RFC 5424,
// RFC 3164, the SEL 3164 time form, nested PRI, non-UTF-8, NUL, a CR left
// before the LF, and random bytes. Messages for LF framing contain no LF
// and start with "<", so the framing cannot be mistaken for a count.
func payloads(seed int64, n int, lf bool) [][]byte {
	rnd := rand.New(rand.NewSource(seed))
	fixed := [][]byte{
		[]byte("<165>1 2026-10-26T12:00:00.123456Z relay-a6 app 42 ID47 [ex@32473 a=\"1\"] An application event"),
		[]byte("<13>Oct 26 12:00:00 relay-a6 su: 'su root' failed"),
		[]byte("<14>Oct 26 2026 12:00:00 SEL-2488 time source changed"),
		[]byte("<13><14>nested pri"),
		[]byte("<13>bad utf8 \xff\xfe\xc3("),
		[]byte("<13>nul \x00 inside"),
		[]byte("<13>ends with CR\r"),
		[]byte("<13>  two leading spaces, trailing  "),
		[]byte("<999>pri out of range"),
		[]byte("<13>" + strings.Repeat("x", 2000)),
	}
	var out [][]byte
	for i := 0; i < n; i++ {
		if i < len(fixed) {
			out = append(out, fixed[i])
			continue
		}
		b := make([]byte, 1+rnd.Intn(300))
		rnd.Read(b)
		if lf {
			b[0] = '<'
			b = bytes.ReplaceAll(b, []byte("\n"), []byte("_"))
		}
		out = append(out, b)
	}
	return out
}

// clientTLS always presents its certificate, if it has one: Go's default
// client sends none when the certificate does not match the server's CA
// list, which would test the wrong refusal.
func clientTLS(roots *x509.CertPool, certs ...tls.Certificate) *tls.Config {
	c := &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	if len(certs) > 0 {
		c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &certs[0], nil }
	}
	return c
}

func dialTLS(t *testing.T, from netip.Addr, to net.Addr, cfg *tls.Config) (*tls.Conn, error) {
	t.Helper()
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: from.AsSlice()}, Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", to.String(), cfg)
	if err == nil {
		t.Cleanup(func() { c.Close() })
	}
	return c, err
}

// TestStoredBytesAreTheSendersBytes: mutual TLS from asset B, 300 messages,
// octet-counted and LF frames mixed on one connection.
func TestStoredBytesAreTheSendersBytes(t *testing.T) {
	srvCA, cliCA := newCA(t, "a6 server ca"), newCA(t, "a6 sender ca")
	srv := srvCA.leaf(t, "a6 listener", x509.ExtKeyUsageServerAuth)
	cfg, err := receive.ServerTLS(&srv, cliCA.pool, true)
	if err != nil {
		t.Fatal(err)
	}
	g := start(t, asset.SyslogTLS, cfg, receive.Limits{Rate: 1000, Burst: 1000})
	c, err := dialTLS(t, ipB, g.addr, clientTLS(srvCA.pool, cliCA.leaf(t, "a6 sender", x509.ExtKeyUsageClientAuth)))
	if err != nil {
		t.Fatal(err)
	}
	octet, lf := payloads(1, 150, false), payloads(2, 150, true)
	var sent [][]byte
	var wire bytes.Buffer
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&wire, "%d ", len(octet[i]))
		wire.Write(octet[i])
		wire.Write(lf[i])
		wire.WriteByte('\n')
		sent = append(sent, octet[i], lf[i])
	}
	// The largest frame kept whole, MaxMessage (default 8192).
	big := append([]byte("<13>"), bytes.Repeat([]byte{0xa6}, 8192-4)...)
	fmt.Fprintf(&wire, "%d ", len(big))
	wire.Write(big)
	sent = append(sent, big)
	// In uneven pieces, so frames straddle writes.
	b := wire.Bytes()
	for len(b) > 0 {
		n := min(len(b), 1+rand.Intn(700))
		if _, err := c.Write(b[:n]); err != nil {
			t.Fatal(err)
		}
		b = b[n:]
	}
	ev := g.waitN(len(sent), 20*time.Second)
	if len(ev) != len(sent) {
		t.Fatalf("%d stored, %d sent", len(ev), len(sent))
	}
	for i, s := range ev {
		checkBytes(t, i, s, sent[i])
		if len(s.Flags) != 0 {
			t.Errorf("message %d flagged %v", i, s.Flags)
		}
		if s.Asset == nil || s.Asset.ID != assetB || s.Asset.Binding.Method != "sender-address" || s.Asset.Binding.Confidence != "configured" {
			t.Errorf("message %d: asset %+v", i, s.Asset)
		}
		if s.OriginAuth != "tls-mutual" || s.Class != "simulated" || s.Sender != "127.0.0.2" {
			t.Errorf("message %d: %s %s %s", i, s.OriginAuth, s.Class, s.Sender)
		}
		if s.ID.Seq != uint64(i+1) || string(s.ID.Stream) != string(sStream) {
			t.Errorf("message %d: id %+v", i, s.ID)
		}
	}
	want := int64(len(sent))
	if st := g.waitStatus(func(st receive.Status) bool { return st.Stored >= want }, 20*time.Second); st.Received != want || st.Stored != want {
		t.Errorf("status received %d stored %d, want %d", st.Received, st.Stored, len(sent))
	}
}

// TestDatagramsAreKeptWhole: a datagram is one message, LF and all, up to
// a 60000-byte datagram.
func TestDatagramsAreKeptWhole(t *testing.T) {
	g := start(t, asset.SyslogUDP, nil, receive.Limits{Rate: 1000, Burst: 1000})
	c := dialFrom(t, ipA, "udp", g.addr)
	sent := payloads(3, 40, false)
	sent = append(sent, []byte("<13>two\nlines\n"), []byte("1 octet-count lookalike"), bytes.Repeat([]byte{'<', 0xa6}, 30000))
	for _, p := range sent {
		if _, err := c.Write(p); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	ev := g.waitN(len(sent), 10*time.Second)
	if len(ev) != len(sent) {
		t.Fatalf("%d stored, %d sent", len(ev), len(sent))
	}
	for i, s := range ev {
		checkBytes(t, i, s, sent[i])
		if s.OriginAuth != "none" || s.Asset == nil || s.Asset.ID != assetA {
			t.Errorf("message %d: %s %+v", i, s.OriginAuth, s.Asset)
		}
	}
}

// closed reports whether the server closed c within d.
func closed(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

// TestHostileFraming: each fault keeps its bytes with a flag, the messages
// before it survive, and the listener keeps serving.
func TestHostileFraming(t *testing.T) {
	const max = 2048
	g := start(t, asset.SyslogTCP, nil, receive.Limits{MaxMessage: max, FrameTimeout: time.Second, Rate: 1000, Burst: 1000})
	n := 0
	expect := func(t *testing.T, want ...func(stored)) []stored {
		t.Helper()
		n += len(want)
		ev := g.waitN(n, 10*time.Second)
		if len(ev) != n {
			t.Fatalf("%d stored, want %d", len(ev), n)
		}
		time.Sleep(200 * time.Millisecond)
		if more := g.events(); len(more) != n {
			t.Fatalf("%d stored, want exactly %d", len(more), n)
		}
		got := ev[n-len(want):]
		for i, w := range want {
			w(got[i])
		}
		return got
	}
	exact := func(b string, flags ...string) func(stored) {
		return func(s stored) {
			checkBytes(t, int(s.ID.Seq), s, []byte(b))
			if strings.Join(s.Flags, ",") != strings.Join(flags, ",") {
				t.Errorf("seq %d %q: flags %v, want %v", s.ID.Seq, s.Bytes, s.Flags, flags)
			}
		}
	}
	prefix := func(of []byte, flag string) func(stored) {
		return func(s stored) {
			if len(s.Bytes) == 0 || len(s.Bytes) > max || !bytes.HasPrefix(of, s.Bytes) || !s.has(flag) {
				t.Errorf("seq %d: %d bytes, flags %v: not a flagged prefix of what was sent", s.ID.Seq, len(s.Bytes), s.Flags)
			}
			if s.Record != sum(s.Bytes) {
				t.Errorf("seq %d: record_sha256 is not the stored bytes' hash", s.ID.Seq)
			}
		}
	}

	t.Run("count above the limit closes the connection", func(t *testing.T) {
		c := dialFrom(t, ipA, "tcp", g.addr)
		body := bytes.Repeat([]byte("Z"), 5000)
		fmt.Fprintf(c, "<13>before the lie\n%d ", len(body))
		c.Write(body)
		c.Write([]byte("<13>never a frame\n"))
		expect(t, exact("<13>before the lie"), prefix(body, "frame-truncated"))
		if !closed(c, 5*time.Second) {
			t.Error("connection still open after an oversized count")
		}
	})
	t.Run("count cut by the end of the connection", func(t *testing.T) {
		c := dialFrom(t, ipA, "tcp", g.addr)
		fmt.Fprint(c, "<13>two\n100 <13>abc")
		c.(*net.TCPConn).CloseWrite()
		expect(t, exact("<13>two"), exact("<13>abc", "frame-truncated"))
	})
	t.Run("count lies short", func(t *testing.T) {
		c := dialFrom(t, ipA, "tcp", g.addr)
		// 5 bytes counted, 9 sent: the frame is the 5, the rest is the next
		// message.
		fmt.Fprint(c, "5 <13>abcd\n")
		c.(*net.TCPConn).CloseWrite()
		got := expect(t, exact("<13>a"), func(stored) {})
		if !bytes.Equal(got[1].Bytes, []byte("bcd")) && !bytes.Equal(got[1].Bytes, []byte("bcd\n")) {
			t.Errorf("rest of a short count stored as %q", got[1].Bytes)
		}
	})
	t.Run("over-long line", func(t *testing.T) {
		c := dialFrom(t, ipA, "tcp", g.addr)
		line := append([]byte("<13>"), bytes.Repeat([]byte("L"), 3000)...)
		before := g.r.Status().Discarded
		c.Write(append(line, "\n<13>after the long line\n"...))
		expect(t, prefix(line, "frame-truncated"), exact("<13>after the long line"))
		if d := g.r.Status().Discarded - before; d < int64(len(line)-max) {
			t.Errorf("discarded %d bytes, want at least %d", d, len(line)-max)
		}
	})
	t.Run("misframed bytes", func(t *testing.T) {
		c := dialFrom(t, ipA, "tcp", g.addr)
		fmt.Fprint(c, "12abc\n<13>next\n")
		expect(t, exact("12abc", "frame-invalid"), exact("<13>next"))
	})
	t.Run("stalled frame", func(t *testing.T) {
		c := dialFrom(t, ipA, "tcp", g.addr)
		fmt.Fprint(c, "<13>complete\n<13>stalled")
		expect(t, exact("<13>complete"), exact("<13>stalled", "frame-truncated"))
	})
	t.Run("still serving", func(t *testing.T) {
		c := dialFrom(t, ipB, "tcp", g.addr)
		fmt.Fprint(c, "<13>still serving\n")
		expect(t, exact("<13>still serving"))
	})
}

// TestDatagramFloodIsCountedAndIsolated: A floods UDP far past its rate; B
// sends inside its rate; every datagram the listener read is stored or
// counted as dropped, and A's drops are counted and reported. A datagram
// the OS dropped before the listener read it (its socket buffer full while
// the read loop is starved of CPU, as on a slow Windows runner) is not
// read, so it is neither stored nor counted: that is UDP's stated limit
// (A4), and the only place it shows is Received falling short of what was
// sent. So B may be short by at most the datagrams never read; a datagram
// of B's that was read and then lost fails (#187, job 121917868556: B 14
// of 15 stored, with nothing to tell which).
func TestDatagramFloodIsCountedAndIsolated(t *testing.T) {
	g := start(t, asset.SyslogUDP, nil, receive.Limits{Rate: 20, Burst: 20, ReportEvery: 500 * time.Millisecond})
	a, b := dialFrom(t, ipA, "udp", g.addr), dialFrom(t, ipB, "udp", g.addr)
	const floodN, quietN = 2000, 15
	var wg sync.WaitGroup
	wg.Add(1)
	began := time.Now()
	go func() {
		defer wg.Done()
		for i := 0; i < floodN; i++ {
			fmt.Fprintf(a, "<13>flood %d", i)
			if i%50 == 0 {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()
	for i := 0; i < quietN; i++ {
		fmt.Fprintf(b, "<13>quiet %d", i)
		time.Sleep(80 * time.Millisecond)
	}
	wg.Wait()
	elapsed := time.Since(began)
	// Every datagram read is stored or counted as dropped, once the writer
	// has caught up.
	accounted := func(st receive.Status) bool {
		return st.Received == st.Stored+sumMap(st.Dropped)+st.Empty
	}
	time.Sleep(time.Second)
	st := g.waitStatus(accounted, 30*time.Second)
	if !accounted(st) {
		t.Errorf("read %d datagrams, but %d stored, %d dropped %v and %d empty", st.Received, st.Stored, sumMap(st.Dropped), st.Dropped, st.Empty)
	}
	sent := int64(floodN + quietN)
	if st.Received > sent {
		t.Fatalf("read %d datagrams, %d sent", st.Received, sent)
	}
	notRead := sent - st.Received
	if notRead > 0 {
		t.Logf("%d of %d datagrams were never read: lost before the listener, where it cannot count them (UDP)", notRead, sent)
	}
	var fromA, fromB []stored
	for _, s := range g.events() {
		switch s.Asset.ID {
		case assetA:
			fromA = append(fromA, s)
		case assetB:
			fromB = append(fromB, s)
		}
	}
	// B's stored datagrams are B's, each once, in the order sent.
	next := 0
	for _, s := range fromB {
		var i int
		if _, err := fmt.Sscanf(string(s.Bytes), "<13>quiet %d", &i); err != nil || i < next || i >= quietN {
			t.Errorf("B: stored %q out of order or not sent (next %d)", s.Bytes, next)
			continue
		}
		checkBytes(t, i, s, fmt.Appendf(nil, "<13>quiet %d", i))
		next = i + 1
	}
	if missing := int64(quietN - len(fromB)); missing > notRead {
		t.Errorf("B: %d of %d stored; %d missing, but only %d datagrams were never read, so the listener lost one it read", len(fromB), quietN, missing, notRead)
	} else if missing > 0 {
		t.Logf("B: %d of %d stored; the %d missing are within the %d never read", len(fromB), quietN, missing, notRead)
	}
	if limit := 20 + int(20*elapsed.Seconds()) + 20; len(fromA) > limit {
		t.Errorf("A: %d stored in %s, over its rate (at most %d)", len(fromA), elapsed, limit)
	}
	if st.Dropped[receive.DropRateLimit] == 0 {
		t.Errorf("no rate-limit drops counted: %+v", st.Dropped)
	}
	g.close()
	var reported int64
	for _, h := range g.h.of(event.HealthDropCounted) {
		if h.Details["reason"] == receive.DropRateLimit && h.Details["stream"] == string(sDgram) {
			var n int64
			fmt.Sscan(h.Details["count"], &n)
			reported += n
		}
	}
	// Every drop counted is reported by the time the listener has stopped.
	if counted := g.r.Status().Dropped[receive.DropRateLimit]; reported != counted || counted == 0 {
		t.Errorf("intake.drop-counted reports %d rate-limit drops, the listener counted %d", reported, counted)
	}
}

// TestStreamFloodIsSlowedNotDropped: A writes 200 messages over TCP at ten
// times its rate; every one of A's is stored in order, A is slowed to its
// rate, and nothing is dropped. B, on another connection, keeps its own
// bucket: none of its messages waits for a token while A's flood holds
// A's bucket empty. That is read from when the listener read each of B's
// frames (received.utc), which the reader takes after its token wait and
// before the store, so a slow store cannot move it: B's 10 frames fit in
// its burst, so with its own bucket they are read back to back, and with
// a bucket shared with A each one waits for a token, the nine after the
// first at least 1/Rate apart. The wall-clock lag of B behind A's flood
// was the property before; it flaked on slow stores (#187, jobs
// 121862674585 and 121924487638: 3.8 s and 4.2 s) and did not catch a
// shared bucket (376 ms), so it stays only as a generous liveness bound.
func TestStreamFloodIsSlowedNotDropped(t *testing.T) {
	const rate, floodN, quietN = 20, 200, 10
	g := start(t, asset.SyslogTCP, nil, receive.Limits{Rate: rate, Burst: rate})
	b := dialFrom(t, ipB, "tcp", g.addr)
	// quiet sends B's 10 messages in one write and returns how long the
	// listener took to read the last of them (by its own received time),
	// how long they took to be stored, and how far apart the listener read
	// the first and the last.
	quiet := func(prefix string) (read, lag, span time.Duration) {
		sent := time.Now()
		var w bytes.Buffer
		for i := 0; i < quietN; i++ {
			fmt.Fprintf(&w, "<13>%s %d\n", prefix, i)
		}
		if _, err := b.Write(w.Bytes()); err != nil {
			t.Fatal(err)
		}
		for end := time.Now().Add(60 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			var got []stored
			for _, s := range g.events() {
				if s.Asset.ID == assetB && strings.HasPrefix(string(s.Bytes), "<13>"+prefix+" ") {
					got = append(got, s)
				}
			}
			if len(got) == quietN {
				return got[quietN-1].Received.Sub(sent), time.Since(sent), got[quietN-1].Received.Sub(got[0].Received)
			}
		}
		return 0, 0, 0
	}
	aloneRead, alone, aloneSpan := quiet("alone")
	if alone == 0 {
		t.Fatal("B's 10 messages with no flood were not stored in 60 s")
	}
	a := dialFrom(t, ipA, "tcp", g.addr)
	w := bufio.NewWriter(a)
	for i := 0; i < floodN; i++ {
		fmt.Fprintf(w, "<13>flood %03d\n", i)
	}
	go w.Flush()
	// A's burst is spent within this, and B's bucket has refilled.
	time.Sleep(time.Second)
	readB, lagB, span := quiet("quiet")
	t.Logf("B's 10 messages: read %s and stored %s after sending, read within %s, with no flood; %s, %s and %s behind A's flood",
		aloneRead, alone, aloneSpan, readB, lagB, span)
	// B's own bucket: read back to back. A shared bucket spaces the nine
	// after the first at least 1/Rate apart (450 ms here); half that is
	// the line, far above a reader that never waited.
	if shared := 9 * time.Second / rate; lagB == 0 || span >= shared/2 {
		t.Errorf("B's 10 frames were read over %s behind A's flood (%s with none): B waited for tokens, as if it shared A's bucket (a shared bucket takes at least %s)",
			span, aloneSpan, shared)
	}
	// Liveness is the listener's: B is read while A floods, judged by the
	// received time the listener stamps as it reads. How long the store
	// then takes to commit is the store's, and a slow commit there is not
	// starvation (F-016: hosted Windows held one commit for 37.9 s; job
	// 122655194850 stored B 5.39 s behind A's flood against the old 5.12 s
	// bound, read within 0 s). Every message read is still required stored,
	// below.
	if limit := 3*aloneRead + 5*time.Second; readB > limit {
		t.Errorf("the listener read B's 10 messages %s after they were sent, behind A's flood, past the liveness bound %s (3 x %s with none, + 5 s): B waited behind A",
			readB, limit, aloneRead)
	}
	ev := g.waitN(floodN+2*quietN, 20*time.Second)
	var fromA []stored
	for _, s := range ev {
		if s.Asset.ID == assetA {
			fromA = append(fromA, s)
		}
	}
	if len(fromA) != floodN {
		t.Fatalf("A: %d of %d stored", len(fromA), floodN)
	}
	// 200 at 20 a second with a burst of 20 is at least 9 s: A was slowed.
	// Read off the listener's own times, so a slow store cannot hide it.
	if took := fromA[floodN-1].Received.Sub(fromA[0].Received); took < 8*time.Second {
		t.Errorf("A's %d messages were read within %s, faster than its rate", floodN, took)
	}
	for i, s := range fromA {
		checkBytes(t, i, s, fmt.Appendf(nil, "<13>flood %03d", i))
	}
	// A stream is slowed, never dropped: every message read is stored.
	want := int64(floodN + 2*quietN)
	st := g.waitStatus(func(st receive.Status) bool { return st.Stored >= want }, 20*time.Second)
	if st.Received != want || st.Stored != want || sumMap(st.Dropped) != 0 {
		t.Errorf("received %d, stored %d, dropped %v; want %d, %d and none", st.Received, st.Stored, st.Dropped, want, want)
	}
}

func sumMap(m map[string]int64) (n int64) {
	for _, v := range m {
		n += v
	}
	return n
}

// TestTLSRefusesTheWrongAnchor: each sender that cannot prove the
// configured CA, or will not trust the listener, is refused at the
// handshake and nothing it sent is stored; a sender that does is stored.
func TestTLSRefusesTheWrongAnchor(t *testing.T) {
	srvCA, cliCA, other := newCA(t, "a6 server ca"), newCA(t, "a6 sender ca"), newCA(t, "a6 other ca")
	srv := srvCA.leaf(t, "a6 listener", x509.ExtKeyUsageServerAuth)
	cfg, err := receive.ServerTLS(&srv, cliCA.pool, true)
	if err != nil {
		t.Fatal(err)
	}
	g := start(t, asset.SyslogTLS, cfg, receive.Limits{HandshakeTimeout: 2 * time.Second})
	good := cliCA.leaf(t, "a6 sender", x509.ExtKeyUsageClientAuth)
	try := func(name string, cc *tls.Config) {
		t.Run(name, func(t *testing.T) {
			c, err := dialTLS(t, ipA, g.addr, cc)
			if err == nil {
				// TLS 1.3: the client finishes before the server checks its
				// certificate. Whatever it writes must not be stored.
				fmt.Fprintf(c, "<13>%s\n", name)
				if !closed(c, 5*time.Second) {
					t.Error("connection not closed")
				}
			}
		})
	}
	try("sender certificate from another CA", clientTLS(srvCA.pool, other.leaf(t, "intruder", x509.ExtKeyUsageClientAuth)))
	try("no sender certificate", clientTLS(srvCA.pool))
	try("sender trusts another CA", clientTLS(other.pool, good))
	old := clientTLS(srvCA.pool, good)
	old.MinVersion, old.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	try("TLS 1.1", old)
	try("server certificate as a sender certificate", clientTLS(srvCA.pool, cliCA.leaf(t, "wrong usage", x509.ExtKeyUsageServerAuth)))
	// The refusals are counted when the listener's handshake ends, which
	// on a slow runner can be after the client's side has returned.
	st := g.waitStatus(func(st receive.Status) bool { return st.Refused["tls"] >= 4 }, 20*time.Second)
	time.Sleep(500 * time.Millisecond)
	if ev := g.events(); len(ev) != 0 {
		t.Fatalf("%d messages stored from refused senders: %q", len(ev), ev[0].Bytes)
	}
	if st.Refused["tls"] < 4 {
		t.Errorf("refused %+v, want at least 4 tls", st.Refused)
	}
	c, err := dialTLS(t, ipA, g.addr, clientTLS(srvCA.pool, good))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "<13>proved\n")
	ev := g.waitN(1, 5*time.Second)
	if len(ev) != 1 {
		t.Fatal("the good sender was not stored")
	}
	checkBytes(t, 0, ev[0], []byte("<13>proved"))
	if ev[0].OriginAuth != "tls-mutual" {
		t.Errorf("origin_auth %s", ev[0].OriginAuth)
	}
}

// TestTLSOptionalSenderCertificate: with a sender CA set and no
// requirement, a sender without a certificate is tls-server-only and one
// with a certificate is tls-mutual.
func TestTLSOptionalSenderCertificate(t *testing.T) {
	srvCA, cliCA := newCA(t, "a6 server ca"), newCA(t, "a6 sender ca")
	srv := srvCA.leaf(t, "a6 listener", x509.ExtKeyUsageServerAuth)
	cfg, err := receive.ServerTLS(&srv, cliCA.pool, false)
	if err != nil {
		t.Fatal(err)
	}
	g := start(t, asset.SyslogTLS, cfg, receive.Limits{})
	c1, err := dialTLS(t, ipA, g.addr, clientTLS(srvCA.pool))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c1, "<13>anonymous\n")
	g.waitN(1, 5*time.Second)
	c2, err := dialTLS(t, ipB, g.addr, clientTLS(srvCA.pool, cliCA.leaf(t, "a6 sender", x509.ExtKeyUsageClientAuth)))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c2, "<13>proved\n")
	ev := g.waitN(2, 5*time.Second)
	if len(ev) != 2 || ev[0].OriginAuth != "tls-server-only" || ev[1].OriginAuth != "tls-mutual" {
		t.Fatalf("%+v", ev)
	}
	// A certificate from another CA is still refused when one is offered.
	other := newCA(t, "a6 other ca")
	if c3, err := dialTLS(t, ipA, g.addr, clientTLS(srvCA.pool, other.leaf(t, "intruder", x509.ExtKeyUsageClientAuth))); err == nil {
		fmt.Fprint(c3, "<13>intruder\n")
		closed(c3, 5*time.Second)
	}
	time.Sleep(300 * time.Millisecond)
	if ev := g.events(); len(ev) != 2 {
		t.Errorf("%d stored, want 2; third: %q %s", len(ev), ev[2].Bytes, ev[2].OriginAuth)
	}
}

// TestUnknownSendersAreKeptAndAlarmedOnce: senders no asset claims are
// stored unresolved with the listener's class, alarmed once per address
// with the stored event as the related ID, and past MaxUnknown one summary
// is raised; a known sender's events are untouched.
//
// UDP promises no delivery, even on loopback, so the counts are the
// receiver's own (#262, job 122460526290: 21 of 25 stored on a loaded
// Windows runner, and nothing then said where the four went). A datagram
// the receiver has not read is sent again; every datagram it read must be
// stored, none dropped with these limits, and each of the 25 stored.
func TestUnknownSendersAreKeptAndAlarmedOnce(t *testing.T) {
	g := start(t, asset.SyslogUDP, nil, receive.Limits{MaxUnknown: 2})
	unknown := []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("127.0.0.4"), netip.MustParseAddr("127.0.0.5"), netip.MustParseAddr("127.0.0.6")}
	want, read, again := 0, int64(0), 0
	for _, from := range append(unknown, ipA) {
		c := dialFrom(t, from, "udp", g.addr)
		for i := 0; i < 5; i++ {
			for try := 0; ; try++ {
				if try == 5 {
					t.Fatalf("the receiver read none of 5 sends of datagram %d from %s: %+v", i, from, g.r.Status())
				}
				if _, err := fmt.Fprintf(c, "<13>from %s %d", from, i); err != nil {
					t.Fatalf("send %d from %s: %v", i, from, err)
				}
				if st := g.waitStatus(func(s receive.Status) bool { return s.Received > read }, 2*time.Second); st.Received > read {
					read = st.Received
					break
				}
				again++
			}
			want++
		}
	}
	st := g.waitStatus(func(s receive.Status) bool { return s.Received == s.Stored+sumMap(s.Dropped)+s.Empty }, 10*time.Second)
	ev := g.events()
	perSender := map[string]int{}
	for _, s := range ev {
		perSender[s.Sender]++
	}
	t.Logf("%d datagrams, %d sent again; receiver read %d, stored %d, dropped %v, empty %d, last error %q; stored by sender %v",
		want, again, st.Received, st.Stored, st.Dropped, st.Empty, st.LastErr, perSender)
	if sumMap(st.Dropped) != 0 || st.Empty != 0 || st.Received != st.Stored || int64(len(ev)) != st.Stored {
		t.Fatalf("the receiver lost datagrams it read: read %d, stored %d (%d in the database), dropped %v, empty %d, last error %q",
			st.Received, st.Stored, len(ev), st.Dropped, st.Empty, st.LastErr)
	}
	texts := map[string]bool{}
	for _, s := range ev {
		texts[string(s.Bytes)] = true
	}
	for _, from := range append(unknown, ipA) {
		for i := 0; i < 5; i++ {
			if m := fmt.Sprintf("<13>from %s %d", from, i); !texts[m] {
				t.Errorf("%q was never stored", m)
			}
		}
	}
	if len(ev) < want || len(ev) > want+again {
		t.Fatalf("%d stored, %d datagrams, %d sent again", len(ev), want, again)
	}
	byID := map[string]stored{}
	for _, s := range ev {
		byID[fmt.Sprintf("%s/%d", s.ID.Stream, s.ID.Seq)] = s
		known := s.Sender == "127.0.0.1"
		switch {
		case known && (s.Asset == nil || s.Asset.ID != assetA || s.has("asset-unresolved")):
			t.Errorf("known sender's event: %+v %v", s.Asset, s.Flags)
		case !known && (s.Asset != nil || !s.has("asset-unresolved") || s.Class != "simulated"):
			t.Errorf("unknown sender %s: asset %+v, flags %v, class %s", s.Sender, s.Asset, s.Flags, s.Class)
		}
		if !known && strings.Contains(string(s.Raw), assetA) {
			t.Errorf("unknown sender's event names asset A: %s", s.Raw)
		}
	}
	alarms := g.h.of(receive.HealthUnknownSource)
	if len(alarms) != 3 {
		t.Fatalf("%d unknown-source alarms, want 2 and a summary: %+v", len(alarms), alarms)
	}
	for i, h := range alarms {
		if len(h.Related) != 1 {
			t.Fatalf("alarm %d related %v", i, h.Related)
		}
		s, ok := byID[fmt.Sprintf("%s/%d", h.Related[0].Stream, h.Related[0].Seq)]
		if !ok || s.Sender != h.Details["sender"] || s.Asset != nil {
			t.Errorf("alarm %d relates %+v, not a stored event from %s", i, h.Related[0], h.Details["sender"])
		}
		if summary := h.Details["more_senders"] == "true"; summary != (i == 2) {
			t.Errorf("alarm %d: summary %v", i, summary)
		}
	}
	if st := g.r.Status(); st.UnknownSenders != 2 || !st.UnknownOverflow {
		t.Errorf("unknown senders %d, overflow %v", st.UnknownSenders, st.UnknownOverflow)
	}
}

// TestDuplicatesAreKept: the same bytes three times are three events with
// equal record_sha256 and distinct seqs.
func TestDuplicatesAreKept(t *testing.T) {
	g := start(t, asset.SyslogTCP, nil, receive.Limits{})
	c := dialFrom(t, ipA, "tcp", g.addr)
	msg := "<13>Oct 26 2026 12:00:00 SEL-2730M repeating alarm"
	fmt.Fprintf(c, "%s\n%d %s%s\n", msg, len(msg), msg, msg)
	ev := g.waitN(3, 5*time.Second)
	if len(ev) != 3 {
		t.Fatalf("%d stored", len(ev))
	}
	for i, s := range ev {
		checkBytes(t, i, s, []byte(msg))
		if s.ID.Seq != uint64(i+1) {
			t.Errorf("seq %d", s.ID.Seq)
		}
	}
}

// TestPlaintextNeedsTheFlag: TCP and UDP are refused without Plaintext, and
// TLS without a TLS configuration; nothing is bound.
func TestPlaintextNeedsTheFlag(t *testing.T) {
	log, _ := open(t, 1<<20)
	for _, c := range []struct {
		tr        asset.Transport
		plaintext bool
	}{{asset.SyslogTCP, false}, {asset.SyslogUDP, false}, {asset.SyslogTLS, false}, {asset.SyslogTLS, true}} {
		_, err := receive.New(receive.Config{Node: node, ID: "a6", Stream: sStream, Transport: c.tr, Address: "127.0.0.1:0",
			Target: asset.Simulated, Plaintext: c.plaintext, Log: log, Health: &healths{}, Received: received})
		if !errors.Is(err, receive.ErrConfig) {
			t.Errorf("%s plaintext=%v: %v", c.tr, c.plaintext, err)
		}
	}
	srvCA := newCA(t, "a6 server ca")
	expired := srvCA.leaf(t, "a6 listener", x509.ExtKeyUsageClientAuth)
	if _, err := receive.ServerTLS(&expired, nil, false); !errors.Is(err, receive.ErrConfig) {
		t.Errorf("a client-auth-only listener certificate: %v", err)
	}
}

// TestDualStackKeysByIPv4: on a dual-stack listener an IPv4 sender arrives
// as ::ffff:a.b.c.d and must still be its asset.
func TestDualStackKeysByIPv4(t *testing.T) {
	if l, err := net.Listen("tcp", "[::]:0"); err != nil {
		t.Skipf("no dual-stack socket here: %v", err)
	} else {
		l.Close()
	}
	g := start(t, asset.SyslogTCP, nil, receive.Limits{}, func(c *receive.Config) { c.Address = "[::]:0" })
	port := g.addr.(*net.TCPAddr).Port
	c := dialFrom(t, ipB, "tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	fmt.Fprint(c, "<13>v4 on v6\n")
	ev := g.waitN(1, 5*time.Second)
	if len(ev) != 1 || ev[0].Asset == nil || ev[0].Asset.ID != assetB || ev[0].Sender != "127.0.0.2" {
		t.Fatalf("%+v", ev)
	}
	_ = context.Background
}

// TestStoreFullOnTheRealStore: at the class quota of the real store, a
// stream is held (refuse-new: nothing dropped, the connection no longer
// read) and the Log is not stopped, so the listener can resume when space
// is made; datagrams are dropped and counted as store.
func TestStoreFullOnTheRealStore(t *testing.T) {
	for _, tr := range []asset.Transport{asset.SyslogTCP, asset.SyslogUDP} {
		t.Run(string(tr), func(t *testing.T) {
			g := startQuota(t, 256<<10, tr, nil, receive.Limits{Rate: 10000, Burst: 10000, Retry: 100 * time.Millisecond})
			c := dialFrom(t, ipA, map[asset.Transport]string{asset.SyslogTCP: "tcp", asset.SyslogUDP: "udp"}[tr], g.addr)
			line := "<13>" + strings.Repeat("q", 1000)
			// 600 KiB of frames, or 2000 datagrams (some may be lost before
			// the listener on a slow runner), against a 256 KiB quota.
			n := map[asset.Transport]int{asset.SyslogTCP: 600, asset.SyslogUDP: 2000}[tr]
			go func() {
				for i := 0; i < n; i++ {
					if tr == asset.SyslogTCP {
						c.SetWriteDeadline(time.Now().Add(3 * time.Second))
						if _, err := fmt.Fprintf(c, "%s\n", line); err != nil {
							return
						}
					} else {
						fmt.Fprint(c, line)
						time.Sleep(time.Millisecond)
					}
				}
			}()
			// Wait for the quota's effect, not a fixed time: a slow store
			// can take more than a few seconds to fill 256 KiB.
			atQuota := func(st receive.Status) bool {
				if tr == asset.SyslogTCP {
					return st.Held
				}
				return st.Dropped[receive.DropStore] > 0
			}
			g.waitStatus(atQuota, 60*time.Second)
			time.Sleep(500 * time.Millisecond)
			st := g.r.Status()
			ev := g.events()
			t.Logf("%s: received %d, stored %d (%d in the file), held %v, dropped %+v, last error %q", tr, st.Received, st.Stored, len(ev), st.Held, st.Dropped, st.LastErr)
			if len(ev) == 0 || len(ev) >= n {
				t.Fatalf("%d stored: the quota was not reached", len(ev))
			}
			if err := g.log.Stopped(); err != nil {
				t.Errorf("the Log stopped at the quota: %v", err)
			}
			for i, s := range ev {
				checkBytes(t, i, s, []byte(line))
			}
			if tr == asset.SyslogTCP {
				if !st.Held || sumMap(st.Dropped) != 0 {
					t.Errorf("stream at quota: held %v, dropped %+v", st.Held, st.Dropped)
				}
				// In memory: the held batch (at most Queue), the queue
				// refilled behind it (Queue) and the frame in the reader's
				// hand: 2 x Queue + 1 (A4's bound after A6 on #150).
				if n := st.Received - st.Stored; n > 2*64+1 {
					t.Errorf("%d read but not stored: more than the held batch and the queue", n)
				}
			} else if st.Dropped[receive.DropStore] == 0 {
				t.Errorf("datagrams at quota: dropped %+v", st.Dropped)
			}
		})
	}
}

// TestUnknownSendersCannotDisplaceDevices (A3 F1, F2): unknown senders hold
// at most MaxUnknownConns connections and UnknownBytes of records; a known
// sender still connects and loses nothing.
func TestUnknownSendersCannotDisplaceDevices(t *testing.T) {
	g := start(t, asset.SyslogTCP, nil, receive.Limits{MaxConns: 4, MaxUnknownConns: 1, Rate: 10000, Burst: 10000,
		UnknownRate: 10000, UnknownBurst: 10000, UnknownBytes: 256 << 10, UnknownWindow: time.Hour})
	var open []net.Conn
	for i := 3; i <= 6; i++ {
		c := dialFrom(t, netip.AddrFrom4([4]byte{127, 0, 0, byte(i)}), "tcp", g.addr)
		open = append(open, c)
	}
	// Accepting can lag the dials on a slow runner: wait for all four to
	// be decided, then check the split.
	if st := g.waitStatus(func(st receive.Status) bool {
		return int64(st.UnknownConnections)+st.Refused["unknown-limit"] >= 4
	}, 20*time.Second); st.UnknownConnections != 1 || st.Refused["unknown-limit"] != 3 {
		t.Fatalf("unknown connections %d, refused %+v", st.UnknownConnections, st.Refused)
	}
	// The admitted unknown sender spends the budget and more.
	big := "<13>" + strings.Repeat("u", 4000)
	w := bufio.NewWriter(open[0])
	for i := 0; i < 200; i++ {
		fmt.Fprintf(w, "%s\n", big)
	}
	go w.Flush()
	a := dialFrom(t, ipA, "tcp", g.addr)
	for i := 0; i < 20; i++ {
		fmt.Fprintf(a, "<13>device %d\n", i)
	}
	// Wait until the known sender's 20 are stored and all 200 of the
	// unknown sender's are stored or dropped, while either moves: the
	// store serializes commits, so on a slow store the known sender waits
	// behind the unknown sender's commits in flight, which the budget
	// bounds (#187, job 121862674585: known 0 after a fixed 3 s).
	var known, unknown int
	var unknownBytes int64
	var st receive.Status
	moved, was := time.Now(), -1
	for limit := time.Now().Add(2 * time.Minute); ; time.Sleep(50 * time.Millisecond) {
		known, unknown, unknownBytes = 0, 0, 0
		for _, s := range g.events() {
			if s.Asset != nil {
				known++
			} else {
				unknown++
				unknownBytes += int64(len(s.Raw))
			}
		}
		st = g.r.Status()
		progress := known + unknown + int(st.Dropped[receive.DropUnknownBudget])
		if progress != was {
			was, moved = progress, time.Now()
		}
		if progress == 220 || time.Since(moved) > 10*time.Second || time.Now().After(limit) {
			break
		}
	}
	t.Logf("known %d, unknown %d (%d record bytes), dropped %+v", known, unknown, unknownBytes, st.Dropped)
	if known != 20 {
		t.Errorf("known sender: %d of 20 stored", known)
	}
	if unknown == 0 || unknown == 200 || st.Dropped[receive.DropUnknownBudget] != int64(200-unknown) {
		t.Errorf("unknown: %d stored, dropped %+v", unknown, st.Dropped)
	}
	if unknownBytes > 256<<10 {
		t.Errorf("unknown senders stored %d record bytes, budget %d", unknownBytes, 256<<10)
	}
	if len(g.h.of(receive.HealthUnknownBudget)) != 1 {
		t.Errorf("unknown-budget alarms: %+v", g.h.of(receive.HealthUnknownBudget))
	}
}

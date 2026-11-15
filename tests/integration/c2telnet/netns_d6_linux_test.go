//go:build linux

package c2telnet

// C2 0.10's tests 8 (the CI-Linux legs) and 10 (docs/phase4/D2-c2-0.10-
// proposal.md §1.4, §3.3 and §8), through the collector's SEL751Runner and
// its own Rexmit seam. They run only in a6-c2-netns, as root, in a network
// namespace of their own (unshare -n) that holds nothing but lo, so the nft
// rules they set touch no other interface and no other network.
//
// The far end listens on 127.0.0.1 in that namespace. A packet socket on lo
// is the capture: it keeps the copy of each packet that lo's receive path
// delivers, which taps see before netfilter's input hook, so a segment the
// nft rule drops at the far end's ingress is still in the capture (§8 test
// 8). The rule drops every client segment to the far end's port that
// carries PSH, which on Linux is each segment of a line written in one
// write, and lets ACKs, the FIN and an RST through.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"otsec.local/otsec/contracts/adapter"
)

// The range for rexmit_octets, pinned before the run (§8 test 8, D4's N4):
// at most rexmitAbove over and at most rexmitBelow under the payload octets
// the capture shows the client sending again. Both are 0. Linux adds
// skb->len to tcpi_bytes_retrans for each segment it retransmits, a tail-
// loss probe and an RTO retransmission alike, and on lo nothing between the
// client's transmit and the capture can drop or split a segment, so the two
// counts are the same octets. An over-count is the direction that hides an
// injection (§1.4), so the upper bound is never widened to make a run pass.
const (
	rexmitBelow = 0
	rexmitAbove = 0
)

const (
	nftTable = "otsec_d6_c2"
	nftChain = "d6in"
)

// netnsReady skips unless a6-c2-netns asked for these tests, and refuses to
// set an nft rule anywhere but in a namespace of its own.
func netnsReady(t *testing.T) {
	t.Helper()
	if os.Getenv("OTSEC_C2_NETNS") != "1" {
		t.Skip("C2 0.10's tests 8 and 10 run in a6-c2-netns, as root under unshare -n (OTSEC_C2_NETNS=1)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("OTSEC_C2_NETNS=1 needs root, for nft and a packet socket")
	}
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifs {
		if i.Name != "lo" {
			t.Fatalf("interface %s is here: this is not a namespace of its own, so no nft rule is set (run under unshare -n)", i.Name)
		}
	}
	if len(ifs) != 1 || ifs[0].Flags&net.FlagUp == 0 {
		sh(t, "ip", "link", "set", "lo", "up")
	}
	sh(t, "nft", "add", "table", "inet", nftTable)
	sh(t, "nft", "add", "chain", "inet", nftTable, nftChain, "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}")
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", nftTable).Run() })
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// dropper drops the client's segments that carry PSH at the far end's
// ingress, while armed.
type dropper struct {
	t    *testing.T
	mu   sync.Mutex
	port string    // the far end's port
	at   time.Time // when the rule took effect; zero while disarmed
}

func newDropper(t *testing.T, f *farEnd) *dropper {
	_, port, err := net.SplitHostPort(f.addr)
	if err != nil {
		t.Fatal(err)
	}
	return &dropper{t: t, port: port}
}

func (d *dropper) arm() {
	d.mu.Lock()
	port := d.port
	d.mu.Unlock()
	out, err := exec.Command("nft", "add", "rule", "inet", nftTable, nftChain, "tcp", "dport", port,
		"tcp", "flags", "&", "psh", "==", "psh", "counter", "drop").CombinedOutput()
	if err != nil {
		d.t.Errorf("arming the drop: %v: %s", err, out)
		return
	}
	d.mu.Lock()
	d.at = time.Now()
	d.mu.Unlock()
}

func (d *dropper) armedAt() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.at
}

// disarm logs the rule with its counter, then removes it.
func (d *dropper) disarm() {
	out, _ := exec.Command("nft", "list", "chain", "inet", nftTable, nftChain).CombinedOutput()
	d.t.Logf("nft before the drop ends:\n%s", out)
	if out, err := exec.Command("nft", "flush", "chain", "inet", nftTable, nftChain).CombinedOutput(); err != nil {
		d.t.Errorf("ending the drop: %v: %s", err, out)
	}
}

// seg is one captured TCP segment.
type seg struct {
	at       time.Time
	src, dst int
	seq      uint32
	flags    byte
	payload  int
}

const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
)

// capture reads IPv4 packets from a packet socket bound to lo.
type capture struct {
	fd   int
	stop chan struct{}
	done chan struct{}
	mu   sync.Mutex
	segs []seg
	err  error
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func startCapture(t *testing.T) *capture {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		t.Fatalf("packet socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: lo.Index}); err != nil {
		unix.Close(fd)
		t.Fatalf("bind to lo: %v", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 8<<20)
	tv := unix.NsecToTimeval(int64(20 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	// Clear the statistics, so that the drops read at the end are this
	// capture's.
	_, _ = unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	c := &capture{fd: fd, stop: make(chan struct{}), done: make(chan struct{})}
	go c.loop()
	t.Cleanup(func() { c.end() })
	return c
}

func (c *capture) loop() {
	defer close(c.done)
	buf := make([]byte, 1<<17)
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		n, from, err := unix.Recvfrom(c.fd, buf, 0)
		now := time.Now()
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			c.mu.Lock()
			c.err = err
			c.mu.Unlock()
			return
		}
		// A socket bound to ETH_P_IP gets the copy lo's receive path
		// delivers, before ip_rcv and so before the nft input hook: the far
		// end's ingress. A copy as sent (PACKET_OUTGOING), which a socket
		// bound to ETH_P_ALL would also get, is skipped, so each packet is
		// held once (rexmitOctets checks that by the SYNs).
		if ll, ok := from.(*unix.SockaddrLinklayer); !ok || ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		if s, ok := parseTCP(buf[:n]); ok {
			s.at = now
			c.mu.Lock()
			c.segs = append(c.segs, s)
			c.mu.Unlock()
		}
	}
}

func parseTCP(b []byte) (seg, bool) {
	if len(b) < 20 || b[0]>>4 != 4 || b[9] != 6 {
		return seg{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	tot := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) < ihl+20 {
		return seg{}, false
	}
	p := b[ihl:]
	doff := int(p[12]>>4) * 4
	return seg{
		src: int(binary.BigEndian.Uint16(p[0:2])), dst: int(binary.BigEndian.Uint16(p[2:4])),
		seq: binary.BigEndian.Uint32(p[4:8]), flags: p[13], payload: tot - ihl - doff,
	}, true
}

// end stops the capture and fails the test if the kernel dropped a packet
// on the way to it: an incomplete capture is never a count.
func (c *capture) end() error {
	select {
	case <-c.stop:
		return nil
	default:
	}
	close(c.stop)
	<-c.done
	st, err := unix.GetsockoptTpacketStats(c.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	unix.Close(c.fd)
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.err != nil:
		return fmt.Errorf("capture: %v", c.err)
	case err != nil:
		return fmt.Errorf("capture statistics: %v", err)
	case st.Drops != 0:
		return fmt.Errorf("the capture lost %d packets", st.Drops)
	}
	return nil
}

// from returns the captured segments from src to dst, in capture order.
func (c *capture) from(src, dst int) []seg {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []seg
	for _, s := range c.segs {
		if s.src == src && s.dst == dst {
			out = append(out, s)
		}
	}
	return out
}

// sent counts the client's payload segments to the far end since t0.
func (c *capture) sent(src, dst int, t0 time.Time) int {
	n := 0
	for _, s := range c.from(src, dst) {
		if s.payload > 0 && s.at.After(t0) {
			n++
		}
	}
	return n
}

// rexmitOctets counts, from the capture, the payload octets the client sent
// again: for each of its segments in order, the part of the payload at or
// below the highest sequence number it had already sent. syns is the number
// of SYNs captured, which is 1 for a capture that holds each packet once.
func rexmitOctets(segs []seg) (octets int64, copies, syns int) {
	if len(segs) == 0 {
		return 0, 0, 0
	}
	base := segs[0].seq
	var high int64
	for _, s := range segs {
		if s.flags&flagSYN != 0 {
			syns++
		}
		if s.payload <= 0 {
			continue
		}
		start := int64(s.seq - base)
		end := start + int64(s.payload)
		if start < high {
			octets += min(end, high) - start
			copies++
		}
		high = max(high, end)
	}
	return octets, copies, syns
}

// ports are the session's client and far-end ports, once the far end has
// accepted the connection.
func ports(f *farEnd) (client, sim int, ok bool) {
	f.mu.Lock()
	addr := f.r.client
	f.mu.Unlock()
	_, cp, err1 := net.SplitHostPort(addr)
	_, sp, err2 := net.SplitHostPort(f.addr)
	client, err3 := strconv.Atoi(cp)
	sim, err4 := strconv.Atoi(sp)
	return client, sim, err1 == nil && err2 == nil && err3 == nil && err4 == nil
}

// sentSince counts the client's payload segments to the far end since the
// drop was armed; 0 while it is not.
func sentSince(cp *capture, f *farEnd, d *dropper) int {
	at := d.armedAt()
	client, sim, ok := ports(f)
	if at.IsZero() || !ok {
		return 0
	}
	return cp.sent(client, sim, at)
}

func waitUntil(d time.Duration, cond func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

// TestC2v10T8RexmitWithinCaptureRange: test 8's first CI-Linux leg. The
// client's ID line is dropped at the far end's ingress, its first copy and
// its first retransmission, and the drop then ends, so the session goes on
// and ends at the relay's EOF with nothing in flight. rexmit_octets, read by
// the collector's seam, lies within the pinned range of the retransmitted
// payload octets counted from the same run's capture.
func TestC2v10T8RexmitWithinCaptureRange(t *testing.T) {
	netnsReady(t)
	cp := startCapture(t)
	armed := make(chan *dropper, 1)
	quis := 0
	f := newFarEnd(t, script{
		late: func(w *writer) { w.data("\r\nlate octets") },
		onLine: func(l string) {
			// The probe's QUI is in; the client's next line is ID.
			if l == "QUI" && quis == 0 {
				quis++
				d := <-armed
				d.arm()
				armed <- d
			}
		},
	})
	d := newDropper(t, f)
	armed <- d
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		// End the drop once the capture holds two copies of ID: both were
		// dropped by then, since the capture and the input hook see each
		// packet in the same pass, before this goroutine reads it.
		if !waitUntil(10*time.Second, func() bool { return sentSince(cp, f, d) >= 2 }) {
			t.Errorf("the capture never held two copies of the dropped line")
		}
		d.disarm()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := runRunner(t, ctx, f, false)
	rec := f.wait(t, 10*time.Second)
	<-ended
	time.Sleep(50 * time.Millisecond)
	if err := cp.end(); err != nil {
		t.Fatal(err)
	}
	client, sim, ok := ports(f)
	if !ok {
		t.Fatalf("the far end saw no connection")
	}
	octets, copies, syns := rexmitOctets(cp.from(client, sim))
	passive(t, r, rec, true)
	tf := r.Session.Telnet
	t.Logf("capture: %d retransmitted segments, %d payload octets; result: rexmit_octets %v, rexmit_unknown %q, read_to_eof %v",
		copies, octets, deref(tf.RexmitOctets), tf.RexmitUnknown, readToEOF(r))
	if syns != 1 {
		t.Fatalf("the capture holds %d SYNs from the client: it does not hold each packet once", syns)
	}
	if copies < 1 {
		t.Fatalf("the capture shows no retransmission: the leg would prove nothing")
	}
	if !readToEOF(r) || code(r) != "ok" {
		t.Errorf("code %s, read_to_eof %v: want an ok run that ends at the relay's EOF", code(r), readToEOF(r))
	}
	if tf.RexmitOctets == nil {
		t.Fatalf("no rexmit_octets (rexmit_unknown %q) after a session that ended with nothing in flight", tf.RexmitUnknown)
	}
	if got := *tf.RexmitOctets; got < octets-rexmitBelow || got > octets+rexmitAbove {
		t.Errorf("rexmit_octets %d; the capture shows %d retransmitted payload octets, and the range is [%d, %d]",
			got, octets, octets-rexmitBelow, octets+rexmitAbove)
	}
}

// abortObs is what one aborted run left: the result, the far side, and
// the capture.
type abortObs struct {
	r          adapter.Result
	rec        record
	dropEnd    time.Time // when the drop ended
	quiCopies  int       // copies of the close phase's QUI captured while it was dropped
	clientRSTs []seg
	captureErr error
}

// abortRun: test 10's run, and test 8's in-flight leg. The close phase's QUI
// is dropped at the far end's ingress, and the run is aborted (its context
// ends) once the capture holds QUI's first copy. Run then reads the count
// with QUI in flight and closes the socket. The drop ends 300 ms after Run
// returns, and the far end, which never answers that QUI, waits for it.
// linger0 is the control: SO_LINGER 0 on the session's socket.
func abortRun(t *testing.T, linger0 bool) abortObs {
	t.Helper()
	netnsReady(t)
	cp := startCapture(t)
	armed := make(chan *dropper, 1)
	f := newFarEnd(t, script{
		quiSilent: true,
		onLine: func(l string) {
			// ID is in; the client's next line is the close phase's QUI.
			if l == "ID" {
				d := <-armed
				d.arm()
				armed <- d
			}
		},
	})
	d := newDropper(t, f)
	armed <- d
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var o abortObs
	aborted := make(chan bool)
	go func() {
		// Abort once QUI's first copy is in the capture, and so dropped.
		ok := waitUntil(30*time.Second, func() bool { return ctx.Err() != nil || sentSince(cp, f, d) >= 1 })
		cancel()
		aborted <- ok && sentSince(cp, f, d) >= 1
	}()
	o.r = runRunner(t, ctx, f, linger0)
	if !<-aborted {
		t.Errorf("the run ended before the capture held the close phase's QUI")
	}
	time.Sleep(300 * time.Millisecond)
	o.quiCopies = sentSince(cp, f, d)
	client, sim, _ := ports(f)
	d.disarm()
	o.dropEnd = time.Now()
	o.rec = f.wait(t, 20*time.Second)
	time.Sleep(50 * time.Millisecond)
	o.captureErr = cp.end()
	for _, s := range cp.from(client, sim) {
		if s.flags&flagRST != 0 {
			o.clientRSTs = append(o.clientRSTs, s)
		}
	}
	t.Logf("result: code %s, quit_sent %v, read_to_eof %v, rexmit_octets %v, rexmit_unknown %q; QUI copies dropped %d; far end: lines %q, QUI at %v after the drop ended, read ended with %v; client RSTs %d",
		code(o.r), o.r.Session.QuitSent, readToEOF(o.r), deref(o.r.Session.Telnet.RexmitOctets), o.r.Session.Telnet.RexmitUnknown,
		o.quiCopies, o.rec.lines, sinceOrNever(o.rec.quiAt, o.dropEnd), o.rec.readEnd, len(o.clientRSTs))
	return o
}

func sinceOrNever(at, t0 time.Time) string {
	if at.IsZero() {
		return "never"
	}
	return at.Sub(t0).String()
}

// gotQUI: the far end received the close phase's QUI.
func (o abortObs) gotQUI() bool { return !o.rec.quiAt.IsZero() }

// check10 is test 10's pass condition: the far end receives QUI once the
// drop ends, and no RST from the client comes before it.
func (o abortObs) check10() []string {
	var bad []string
	if o.quiCopies < 1 {
		bad = append(bad, "QUI's first copy was not captured while dropped")
	}
	if !o.gotQUI() {
		bad = append(bad, fmt.Sprintf("the far end never received QUI (its read ended with %v)", o.rec.readEnd))
	} else if o.rec.quiAt.Before(o.dropEnd) {
		bad = append(bad, "the far end received QUI before the drop ended")
	}
	for _, s := range o.clientRSTs {
		if !o.gotQUI() || s.at.Before(o.rec.quiAt) {
			bad = append(bad, fmt.Sprintf("an RST from the client at %v, before QUI reached the far end", s.at.Format("15:04:05.000000")))
		}
	}
	return bad
}

// checkGraceful is test 8's in-flight leg's close: the socket closes
// gracefully, so QUI and then the FIN reach the far end, and the client
// sends no RST.
func (o abortObs) checkGraceful() []string {
	var bad []string
	if !o.gotQUI() || o.rec.finAt.IsZero() {
		bad = append(bad, fmt.Sprintf("the far end's read ended with %v, not QUI and then the FIN", o.rec.readEnd))
	}
	if len(o.clientRSTs) != 0 {
		bad = append(bad, fmt.Sprintf("%d RSTs from the client", len(o.clientRSTs)))
	}
	return bad
}

// TestC2v10T8InFlightClosesGracefully: test 8's second CI-Linux leg. With
// the close phase's QUI unacknowledged at the read, the seam gives
// rexmit_unknown "in-flight" and no count, and the socket still closes
// gracefully (§1.4, §3.3: no abortive close). The far end receives the
// transcript's lines and octets and nothing else: the Rexmit seam, called
// here while the socket is still writable, sends no payload octet (§3.3;
// D3's N1 on #684).
func TestC2v10T8InFlightClosesGracefully(t *testing.T) {
	o := abortRun(t, false)
	if o.captureErr != nil {
		t.Fatal(o.captureErr)
	}
	passive(t, o.r, o.rec, false)
	tf := o.r.Session.Telnet
	if tf.RexmitUnknown != adapter.RexmitInFlight || tf.RexmitOctets != nil {
		t.Errorf("rexmit_octets %v, rexmit_unknown %q: want %q and no count, with QUI in flight",
			deref(tf.RexmitOctets), tf.RexmitUnknown, adapter.RexmitInFlight)
	}
	if !o.r.Session.QuitSent || readToEOF(o.r) {
		t.Errorf("quit_sent %v, read_to_eof %v: want QUI sent and no read to EOF", o.r.Session.QuitSent, readToEOF(o.r))
	}
	for _, b := range o.checkGraceful() {
		t.Error(b)
	}
}

// TestC2v10T10AbortDeliversQUI: test 10. QUI's first copy is dropped and the
// run aborted; the far end receives QUI once the drop ends, and no RST
// comes before it (D6's B1: no abortive close). As in test 8's in-flight
// leg, the far end receives nothing but the transcript's lines and octets
// (§3.3; D3's N1 on #684).
func TestC2v10T10AbortDeliversQUI(t *testing.T) {
	o := abortRun(t, false)
	if o.captureErr != nil {
		t.Fatal(o.captureErr)
	}
	passive(t, o.r, o.rec, false)
	for _, b := range o.check10() {
		t.Error(b)
	}
}

// TestC2v10T10LingerZeroControl: test 10's control, the SO_LINGER 0
// mutant, set on the session's socket through the plan's Dial so that no
// product file is patched. The close is then abortive: the far end never
// receives QUI and an RST comes first. Test 10's and test 8's pass
// conditions must both fail on this run; if either passed, it could not
// tell an abortive close from a graceful one.
func TestC2v10T10LingerZeroControl(t *testing.T) {
	o := abortRun(t, true)
	if o.captureErr != nil {
		t.Fatal(o.captureErr)
	}
	bad10, badGraceful := o.check10(), o.checkGraceful()
	t.Logf("test 10's check under SO_LINGER 0: %q", bad10)
	t.Logf("test 8's graceful check under SO_LINGER 0: %q", badGraceful)
	if len(bad10) == 0 {
		t.Errorf("test 10's pass condition held under SO_LINGER 0")
	}
	if len(badGraceful) == 0 {
		t.Errorf("test 8's graceful-close condition held under SO_LINGER 0")
	}
}

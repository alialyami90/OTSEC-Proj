package collector

import (
	"io"
	"net"
	"reflect"
	"runtime"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/authz"
)

// The tests of the collector's C2 0.10 seams (telnetseams.go). Every far
// end is on loopback: simulated evidence only.

// tcpPair is a connected loopback TCP pair: the near end dialled, the far
// end accepted.
func tcpPair(t *testing.T) (near, far *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	for _, x := range []net.Conn{c, s} {
		_ = x.SetDeadline(time.Now().Add(10 * time.Second))
	}
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

// halfClose sends a FIN and keeps the read side: the far end reads a clean
// EOF, not a reset, and what it sends afterwards is still read.
func TestHalfCloseKeepsReadSide(t *testing.T) {
	near, far := tcpPair(t)
	if err := halfClose(near); err != nil {
		t.Fatal(err)
	}
	if b, err := io.ReadAll(far); err != nil || len(b) != 0 {
		t.Fatalf("far end read %q, %v; want a clean EOF and no octet", b, err)
	}
	if _, err := far.Write([]byte("late\r\n=")); err != nil {
		t.Fatal(err)
	}
	far.Close()
	if b, err := io.ReadAll(near); err != nil || string(b) != "late\r\n=" {
		t.Fatalf("near end read %q, %v after the half-close", b, err)
	}
}

// Any connection that is not a TCP socket is refused, and left open.
func TestHalfCloseRefusesOtherConns(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()
	if err := halfClose(near); err == nil {
		t.Fatal("half-close of a net.Pipe returned nil")
	}
	go func() { _, _ = near.Write([]byte("x")) }()
	b := make([]byte, 1)
	_ = far.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(far, b); err != nil {
		t.Fatalf("the refused connection no longer carries data: %v", err)
	}
}

// judge is §3.3's read rule: a count only when nothing written is
// unacknowledged or unsent.
func TestRexmitJudge(t *testing.T) {
	for _, c := range []struct {
		name    string
		s       sockCounts
		octets  int64
		unknown string
	}{
		{"unsupported", sockCounts{retrans: 7}, 0, adapter.RexmitUnsupported},
		{"unacked", sockCounts{supported: true, unacked: 1, retrans: 7}, 0, adapter.RexmitInFlight},
		{"unsent", sockCounts{supported: true, unsent: 1, retrans: 7}, 0, adapter.RexmitInFlight},
		{"settled", sockCounts{supported: true, retrans: 7}, 7, ""},
		{"settled, none", sockCounts{supported: true}, 0, ""},
	} {
		if o, u := c.s.judge(); o != c.octets || u != c.unknown {
			t.Errorf("%s: %d %q, want %d %q", c.name, o, u, c.octets, c.unknown)
		}
	}
}

// rexmit reads a settled loopback socket as a count of 0, a closed one as a
// failed call, and a connection with no socket as unsupported.
func TestRexmitReads(t *testing.T) {
	near, far := tcpPair(t)
	// A request answered: the reply acknowledges the request.
	if _, err := near.Write([]byte("QUI\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(far, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	if _, err := far.Write([]byte("\r\n=")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(near, make([]byte, 3)); err != nil {
		t.Fatal(err)
	}
	wantO, wantU := int64(0), ""
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		wantU = adapter.RexmitUnsupported
	}
	if o, u := rexmit(near); o != wantO || u != wantU {
		t.Errorf("settled socket: %d %q, want %d %q", o, u, wantO, wantU)
	}

	near.Close()
	if o, u := rexmit(near); o != 0 || u != adapter.RexmitCallFailed {
		t.Errorf("closed socket: %d %q, want call-failed", o, u)
	}

	p, q := net.Pipe()
	defer p.Close()
	defer q.Close()
	if o, u := rexmit(p); o != 0 || u != adapter.RexmitUnsupported {
		t.Errorf("net.Pipe: %d %q, want unsupported", o, u)
	}
}

// Through the runner, a Level 0 run whose QUI is answered half-closes: the
// far end reads our FIN, closes, and the adapter reads its EOF. The count is
// read from the run's own socket, settled on loopback.
func TestSEL751RunnerSetsSeams(t *testing.T) {
	f, l := hostedFixture(t)
	ok := replayTurns(goldenResult(t, "ok"))
	turns := append(ok[:4:4], ok[len(ok)-1]) // wake, QUI probe, ID; then the closing QUI
	_, res, _, _ := hostedRun(t, f, l, hostedReq("sel.id", ""), turns, false)
	tf := res.Session.Telnet
	if tf == nil || tf.ReadToEOF == nil || !*tf.ReadToEOF {
		t.Fatalf("session.telnet %+v: want read_to_eof true", tf)
	}
	switch runtime.GOOS {
	case "linux", "windows":
		if tf.RexmitOctets == nil || *tf.RexmitOctets != 0 || tf.RexmitUnknown != "" {
			t.Errorf("rexmit %v %q: want a count of 0 on loopback", tf.RexmitOctets, tf.RexmitUnknown)
		}
	default:
		if tf.RexmitUnknown != adapter.RexmitUnsupported {
			t.Errorf("rexmit_unknown %q, want unsupported", tf.RexmitUnknown)
		}
	}
}

// connFuncs returns the path of every field, reached from root through
// struct fields, pointers, slices, arrays and maps, whose type is a function
// given a connection. Interfaces have no fields.
func connFuncs(root reflect.Type) []string {
	conn := reflect.TypeFor[net.Conn]()
	var out []string
	seen := map[reflect.Type]bool{}
	var walk func(path string, ty reflect.Type)
	walk = func(path string, ty reflect.Type) {
		if seen[ty] {
			return
		}
		seen[ty] = true
		switch ty.Kind() {
		case reflect.Func:
			for i := range ty.NumIn() {
				if in := ty.In(i); in == conn || in.Implements(conn) {
					out = append(out, path)
					break
				}
			}
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(path, ty.Elem())
		case reflect.Map:
			walk(path, ty.Key())
			walk(path, ty.Elem())
		case reflect.Struct:
			for i := range ty.NumField() {
				walk(path+"."+ty.Field(i).Name, ty.Field(i).Type)
			}
		}
	}
	walk(root.Name(), root)
	return out
}

// No field of a request, a plan or the runner can carry a function that is
// given the device connection, so nothing but SEL751Runner.Run's own
// assignment sets or replaces either seam (§3.3).
func TestSeamsNotFromPlanOrRequest(t *testing.T) {
	for _, root := range []reflect.Type{
		reflect.TypeFor[authz.CollectorRequest](),
		reflect.TypeFor[RunPlan](),
		reflect.TypeFor[SEL751Runner](),
	} {
		if p := connFuncs(root); len(p) != 0 {
			t.Errorf("%s can carry a seam: %v", root, p)
		}
	}
	// The walk sees a seam-shaped field however deep, by pointer or slice.
	type probe struct {
		Plan *struct {
			Steps []struct {
				Rexmit func(*net.TCPConn) (int64, string)
			}
		}
	}
	if p := connFuncs(reflect.TypeFor[probe]()); len(p) != 1 || p[0] != "probe.Plan.Steps.Rexmit" {
		t.Fatalf("probe: %v", p)
	}
}

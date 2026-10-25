package forward

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// FuzzCollectorBytes plays a collector that answers the open properly and
// then sends arbitrary bytes. Whatever it sends, the session ends without a
// panic or a hang, and no cursor moves further than the number of 200 OK
// answers in those bytes: nothing but an acknowledgement advances delivery.
func FuzzCollectorBytes(f *testing.F) {
	for _, s := range []string{
		"2 rsp 6 200 OK\n3 rsp 6 200 OK\n4 rsp 6 200 OK\n",
		"3 rsp 6 200 OK\n2 rsp 6 200 OK\n",
		"2 rsp 6 200 OK\n2 rsp 6 200 OK\n",
		"2 rsp 10 500 failed\n",
		"0 serverclose 0\n",
		"2 rsp 6 200 OK",
		"02 rsp 6 200 OK\n",
		"2 rsp 9999 200 OK\n",
		"9 rsp 6 200 OK\n",
		"",
	} {
		f.Add([]byte(s))
	}
	e := row8(f)
	f.Fuzz(func(t *testing.T, resp []byte) {
		m := newStore()
		for range 5 {
			m.commit(t, serStream, e)
		}
		cli, srv := net.Pipe()
		defer srv.Close()
		go io.Copy(io.Discard, srv)
		go func() {
			open := "200 OK\nrelp_version=0\ncommands=syslog"
			srv.Write([]byte("1 rsp " + itoa(len(open)) + " " + open + "\n"))
			srv.Write(resp)
			srv.Close()
		}()
		tg := newTarget(t, 2514, nil)
		fw, err := New(Config{
			Target:          tg,
			Streams:         []Stream{{ID: serStream, Outbox: m, Cursors: m}, {ID: hlStream, Outbox: m, Cursors: m}},
			HealthStream:    hlStream,
			Dial:            func(context.Context) (net.Conn, error) { return cli, nil },
			Health:          sink{t: t, m: m},
			ResponseTimeout: 200 * time.Millisecond, Poll: 10 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := fw.session(ctx); err == nil {
			t.Fatal("session ended cleanly")
		}
		if ctx.Err() != nil {
			t.Fatal("session did not end on its own")
		}
		oks := bytes.Count(resp, []byte("200 OK"))
		if got := int(m.cursor(serStream) + m.cursor(hlStream)); got > oks {
			t.Fatalf("cursors at %d with %d acknowledgements in %q", got, oks, resp)
		}
	})
}

func itoa(n int) string {
	b := []byte{}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			return string(b)
		}
	}
}

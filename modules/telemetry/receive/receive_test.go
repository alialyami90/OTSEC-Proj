package receive

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/telemetry/normalize"
)

const (
	m1 = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8"
	m2 = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
)

// TestTLSMutual: a sender with a certificate from the listener's CA sends
// octet-counted frames; each is stored once, byte for byte, with
// tls-mutual and its asset (V-S8 for this origin).
func TestTLSMutual(t *testing.T) {
	p := newPKI(t, "a4-ca")
	cfg, err := ServerTLS(&p.server, p.roots, true)
	if err != nil {
		t.Fatal(err)
	}
	g := newRig(t, asset.SyslogTLS, func(c *Config) { c.TLS = cfg })
	c, err := tls.Dial("tcp", g.addr, sender(p.roots, &p.client))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(octet(m1, m2, m1)); err != nil {
		t.Fatal(err)
	}
	c.Close()
	g.wait("3 stored", func() bool { return g.store.count() == 3 })
	es := g.store.events(t)
	if got := msgs(t, es); !slices.Equal(got, []string{m1, m2, m1}) {
		t.Fatalf("stored %q", got)
	}
	for _, e := range es {
		if e.Source.OriginAuth != event.AuthTLSMutual || e.Source.Asset == nil || e.Source.Asset.ID != assetA || e.Source.EvidenceClass != asset.Simulated {
			t.Errorf("source %+v", e.Source)
		}
		if e.Collection.ParseStatus != event.ParseOK || e.ID.Stream != testStream {
			t.Errorf("collection %+v id %+v", e.Collection, e.ID)
		}
	}
	// A retrying sender's duplicate is stored again and has the same hash.
	if es[0].Native.RecordSHA256 != es[2].Native.RecordSHA256 {
		t.Error("duplicate messages must share their record hash")
	}
	if s := g.r.Status(); s.Received != 3 || s.Stored != 3 || s.LastMessage.IsZero() || !s.Open {
		t.Errorf("status %+v", s)
	}
}

// TestTLSRefused: a sender whose certificate chains to another CA, a sender
// with no certificate where one is required, and a sender that does not
// trust the listener are all refused at the handshake, and nothing is
// stored.
func TestTLSRefused(t *testing.T) {
	p, other := newPKI(t, "a4-ca"), newPKI(t, "other-ca")
	cfg, err := ServerTLS(&p.server, p.roots, true)
	if err != nil {
		t.Fatal(err)
	}
	g := newRig(t, asset.SyslogTLS, func(c *Config) { c.TLS = cfg })
	for name, sc := range map[string]*tls.Config{
		"client cert from another CA": sender(p.roots, &other.client),
		"no client cert":              sender(p.roots, nil),
		"sender trusts another CA":    sender(other.roots, &p.client),
	} {
		c, err := tls.Dial("tcp", g.addr, sc)
		if err == nil {
			// TLS 1.3 reports a client-certificate refusal on first read;
			// a listener that accepted would leave the read to time out.
			c.Write(octet(m1))
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = c.Read(make([]byte, 1))
			c.Close()
		}
		var ne net.Error
		if err == nil || errors.As(err, &ne) && ne.Timeout() {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
	g.wait("two refusals", func() bool { return g.r.Status().Refused["tls"] >= 2 })
	time.Sleep(50 * time.Millisecond)
	if n := g.store.count(); n != 0 {
		t.Errorf("%d events stored from refused senders", n)
	}
}

// TestTLSServerOnly: without a client CA set, events say tls-server-only.
func TestTLSServerOnly(t *testing.T) {
	p := newPKI(t, "a4-ca")
	cfg, err := ServerTLS(&p.server, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	g := newRig(t, asset.SyslogTLS, func(c *Config) { c.TLS = cfg })
	c, err := tls.Dial("tcp", g.addr, sender(p.roots, &p.client))
	if err != nil {
		t.Fatal(err)
	}
	c.Write(octet(m2))
	c.Close()
	g.wait("stored", func() bool { return g.store.count() == 1 })
	if a := g.store.events(t)[0].Source.OriginAuth; a != event.AuthTLSServerOnly {
		t.Errorf("origin_auth %s", a)
	}
}

func TestServerTLSRefusesCertificate(t *testing.T) {
	p := newPKI(t, "a4-ca")
	now := time.Now()
	for name, cert := range map[string]tls.Certificate{
		"client-only usage": p.issue(t, "node.test", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour), now.Add(time.Hour)),
		"expired":           p.issue(t, "node.test", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(-2*time.Hour), now.Add(-time.Hour)),
		"not yet valid":     p.issue(t, "node.test", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now.Add(time.Hour), now.Add(2*time.Hour)),
	} {
		if _, err := ServerTLS(&cert, p.roots, false); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ServerTLS(&p.server, nil, true); err == nil {
		t.Error("required client certificates with no CA set: accepted")
	}
	if _, err := ServerTLS(nil, nil, false); err == nil {
		t.Error("no certificate: accepted")
	}
}

// TestHostileFraming sends, on one plaintext TCP connection, frames that
// break RFC 6587 in turn. Every earlier message survives each break, every
// byte received is stored or counted, and the listener keeps serving.
func TestHostileFraming(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, func(c *Config) { c.Limits.MaxMessage = 2048 })
	long := strings.Repeat("x", 3000)
	stream := string(octet(m1)) +
		m2 + "\n" + // non-transparent framing
		"\n\n" + // empty lines
		"<13><14>Oct 11 22:14:15 nested\n" + // nested priority
		"<13>Oct 11 22:14:15 h \xff\xfe bad utf-8\n" +
		"12x not a count\n" + // a count followed by no space
		"<13>" + long + "\n" + // over-long line
		string(octet(m2))
	c := g.dial(addrA)
	c.Write([]byte(stream))
	c.Close()
	g.wait("7 stored", func() bool { return g.store.count() == 7 })
	es := g.store.events(t)
	got := msgs(t, es)
	want := []string{m1, m2, "<13><14>Oct 11 22:14:15 nested", "<13>Oct 11 22:14:15 h \xff\xfe bad utf-8", "12x not a count", ("<13>" + long)[:2048], m2}
	if !slices.Equal(got, want) {
		t.Fatalf("stored %q", got)
	}
	if !slices.Contains(es[4].Flags, normalize.FlagFraming) || !slices.Contains(es[5].Flags, normalize.FlagTruncated) {
		t.Errorf("flags %v %v", es[4].Flags, es[5].Flags)
	}
	if es[2].Collection.ParseStatus != event.ParsePartial || es[4].Collection.ParseStatus != event.ParseFailed {
		t.Errorf("parse status %s %s", es[2].Collection.ParseStatus, es[4].Collection.ParseStatus)
	}
	s := g.r.Status()
	if s.Empty != 2 || s.Discarded != int64(len("<13>"+long)-2048) || s.Truncated != 1 || s.Misframed != 1 {
		t.Errorf("status %+v", s)
	}
}

// TestOctetCountLies: a count larger than what follows keeps the bytes that
// came, marked truncated; a count above the limit keeps the first bytes and
// closes the connection; every earlier message is kept, and a new
// connection is served.
func TestOctetCountLies(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, func(c *Config) { c.Limits.MaxMessage = 2048 })
	c := g.dial(addrA)
	c.Write([]byte(string(octet(m1)) + "500 <13>short"))
	c.Close()
	g.wait("2 stored", func() bool { return g.store.count() == 2 })

	c = g.dial(addrA)
	c.Write([]byte(string(octet(m2)) + "999999 <13>" + strings.Repeat("y", 3000) + string(octet(m1))))
	g.wait("4 stored", func() bool { return g.store.count() == 4 })
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection still open after an oversized count")
	}
	c.Close()

	c = g.dial(addrA)
	c.Write(octet(m1))
	c.Close()
	g.wait("5 stored", func() bool { return g.store.count() == 5 })
	es := g.store.events(t)
	got := msgs(t, es)
	want := []string{m1, "<13>short", m2, ("<13>" + strings.Repeat("y", 3000))[:2048], m1}
	if !slices.Equal(got, want) {
		t.Fatalf("stored %q", got)
	}
	for _, i := range []int{1, 3} {
		if !slices.Contains(es[i].Flags, normalize.FlagTruncated) || es[i].Collection.ParseStatus == event.ParseOK {
			t.Errorf("event %d: flags %v status %s", i, es[i].Flags, es[i].Collection.ParseStatus)
		}
	}
}

// TestFrameTimeout: a frame that stops halfway is stored truncated when its
// deadline passes, and the connection is closed; a connection that never
// starts a frame is closed at the idle timeout. Neither holds the listener.
func TestFrameTimeout(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, func(c *Config) {
		c.Limits.FrameTimeout = 100 * time.Millisecond
		c.Limits.IdleTimeout = 200 * time.Millisecond
	})
	idle := g.dial(addrB)
	defer idle.Close()
	c := g.dial(addrA)
	defer c.Close()
	c.Write([]byte(string(octet(m1)) + "80 <13>Oct 11"))
	g.wait("2 stored", func() bool { return g.store.count() == 2 })
	if got := msgs(t, g.store.events(t)); got[1] != "<13>Oct 11" {
		t.Errorf("stored %q", got)
	}
	g.wait("both closed", func() bool { return g.r.Status().Connections == 0 })
}

// TestUnknownSender: a message from an address no asset claims is stored
// with asset-unresolved and the listener's target, and alarmed once.
func TestUnknownSender(t *testing.T) {
	g := newRig(t, asset.SyslogUDP, func(c *Config) { c.Senders = Senders{} })
	c := g.udp(addrA)
	for i := 0; i < 3; i++ {
		c.Write([]byte(m2))
	}
	c.Close()
	g.wait("3 stored", func() bool { return g.store.count() == 3 })
	for _, e := range g.store.events(t) {
		if e.Source.Asset != nil || !slices.Contains(e.Flags, "asset-unresolved") || e.Source.Sender.Address != "127.0.0.1" ||
			e.Source.OriginAuth != event.AuthNone || e.Source.EvidenceClass != asset.Simulated {
			t.Errorf("source %+v flags %v", e.Source, e.Flags)
		}
	}
	g.wait("alarm", func() bool { return len(g.health.of(HealthUnknownSource)) == 1 })
	h := g.health.of(HealthUnknownSource)[0]
	if h.Details["sender"] != "127.0.0.1" || h.Details["listener"] != "lab" || len(h.Related) != 1 || h.Related[0].Seq != 1 || h.Related[0].Stream != testStream {
		t.Errorf("alarm %+v", h)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(g.health.of(HealthUnknownSource)); n != 1 {
		t.Errorf("%d alarms for one sender", n)
	}
	if s := g.r.Status(); s.UnknownSenders != 1 {
		t.Errorf("status %+v", s)
	}
}

// TestUnknownAlarmRetried: an alarm the health stream refuses is raised
// again with the sender's next message.
func TestUnknownAlarmRetried(t *testing.T) {
	g := newRig(t, asset.SyslogUDP, func(c *Config) { c.Senders = Senders{} })
	g.health.fail.Store(true)
	c := g.udp(addrA)
	defer c.Close()
	c.Write([]byte(m2))
	g.wait("stored", func() bool { return g.store.count() == 1 })
	g.wait("error noted", func() bool { return strings.Contains(g.r.Status().LastErr, "unknown-source") })
	g.health.fail.Store(false)
	c.Write([]byte(m2))
	g.wait("alarm", func() bool { return len(g.health.of(HealthUnknownSource)) == 1 })
}

// TestEvidenceClass: device-observed only when both the endpoint and the
// listener are; an unknown sender takes the listener's.
func TestEvidenceClass(t *testing.T) {
	cases := []struct {
		listener, endpoint asset.EvidenceClass
		known              bool
		want               asset.EvidenceClass
	}{
		{asset.DeviceObserved, asset.DeviceObserved, true, asset.DeviceObserved},
		{asset.DeviceObserved, asset.Simulated, true, asset.Simulated},
		{asset.Simulated, asset.DeviceObserved, true, asset.Simulated},
		{asset.DeviceObserved, "", false, asset.DeviceObserved},
		{asset.Simulated, "", false, asset.Simulated},
	}
	for _, c := range cases {
		r, err := New(Config{Node: testNode, ID: "x", Stream: testStream, Transport: asset.SyslogUDP, Address: "127.0.0.1:0", Target: c.listener,
			Plaintext: true, Senders: Senders{addrA: {AssetID: assetA, Target: asset.DeviceObserved}}, Log: nopLog{}, Health: &sink{}, Received: received})
		if err != nil {
			t.Fatal(err)
		}
		if c.known {
			r.cfg.Senders[addrA] = Source{AssetID: assetA, Target: c.endpoint, Dialect: normalize.DialectRFC}
		} else {
			r.cfg.Senders = Senders{}
		}
		rec, err := r.record(msg{frame: frame{msg: []byte(m2)}, from: addrA, auth: event.AuthNone, rcv: received()})
		if err != nil {
			t.Fatal(err)
		}
		var e event.Event
		if err := json.Unmarshal(rec.Event, &e); err != nil {
			t.Fatal(err)
		}
		if e.Source.EvidenceClass != c.want {
			t.Errorf("listener %s endpoint %s known %v: %s, want %s", c.listener, c.endpoint, c.known, e.Source.EvidenceClass, c.want)
		}
	}
}

// TestDatagramFloodIsolated: a flood from one known sender is held to its
// rate and counted; another sender's messages all arrive (A6: a flood from
// one source does not affect another).
func TestDatagramFloodIsolated(t *testing.T) {
	g := newRig(t, asset.SyslogUDP, func(c *Config) {
		c.Limits.Rate, c.Limits.Burst = 1, 10
	})
	flood, quiet := g.udp(addrA), g.udp(addrB)
	defer flood.Close()
	defer quiet.Close()
	for i := 0; i < 200; i++ {
		flood.Write([]byte(m2))
		if i%40 == 0 {
			quiet.Write([]byte(m1))
		}
	}
	g.wait("all handled", func() bool {
		s := g.r.Status()
		return s.Received == 205 && s.Stored+s.Dropped[DropRateLimit] == 205
	})
	var fromB, fromA int
	for _, e := range g.store.events(t) {
		switch e.Source.Asset.ID {
		case assetB:
			fromB++
		case assetA:
			fromA++
		}
	}
	if fromB != 5 || fromA > 11 || fromA < 10 {
		t.Errorf("stored %d from the flood, %d from the quiet sender", fromA, fromB)
	}
	// Every drop is reported, in one or more intake.drop-counted events.
	g.wait("drops reported", func() bool {
		reported := 0
		for _, h := range g.health.of(event.HealthDropCounted) {
			if h.Details["reason"] != DropRateLimit || h.Details["listener"] != "lab" {
				t.Errorf("report %+v", h)
			}
			n, _ := strconv.Atoi(h.Details["count"])
			reported += n
		}
		return reported == 200-fromA
	})
}

// TestDatagramUnknownShare: unknown senders share one bucket on top of
// their own, so they cannot take a known sender's share.
func TestDatagramUnknownShare(t *testing.T) {
	l := newLimiter(Limits{Rate: 1, Burst: 3, UnknownRate: 1, UnknownBurst: 4, MaxSources: 10})
	now := time.Now()
	u1, u2, known := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3")
	n := 0
	for i := 0; i < 10; i++ {
		if l.allow(u1, false, now) {
			n++
		}
		if l.allow(u2, false, now) {
			n++
		}
	}
	if n != 4 {
		t.Errorf("unknown senders got %d, want the shared burst 4", n)
	}
	for i := 0; i < 3; i++ {
		if !l.allow(known, true, now) {
			t.Errorf("known sender refused at %d", i)
		}
	}
}

// TestLimiterBounded: past MaxSources the limiter forgets a refilled
// sender, and never grows.
func TestLimiterBounded(t *testing.T) {
	l := newLimiter(Limits{Rate: 1, Burst: 2, UnknownRate: 1000, UnknownBurst: 1000, MaxSources: 8})
	now := time.Now()
	for i := 0; i < 100; i++ {
		l.allow(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), false, now)
	}
	if len(l.sources) > 8 {
		t.Errorf("%d sources tracked", len(l.sources))
	}
}

// TestStreamFloodSlowed: a stream over its rate is slowed, not dropped:
// every frame arrives, and another sender's connection is not held.
func TestStreamFloodSlowed(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, func(c *Config) { c.Limits.Rate, c.Limits.Burst = 50, 1 })
	flood := g.dial(addrA)
	defer flood.Close()
	var frames []string
	for i := 0; i < 26; i++ {
		frames = append(frames, m2)
	}
	start := time.Now()
	flood.Write(octet(frames...))
	quiet := g.dial(addrB)
	quiet.Write(octet(m1))
	quiet.Close()
	g.wait("quiet sender stored", func() bool {
		for _, e := range g.store.events(t) {
			if e.Source.Asset.ID == assetB {
				return true
			}
		}
		return false
	})
	quietAt := time.Since(start)
	g.wait("all stored", func() bool { return g.store.count() == 27 })
	if el := time.Since(start); el < 400*time.Millisecond {
		t.Errorf("26 frames at 50/s took %s; the flood was not slowed", el)
	}
	if quietAt > 300*time.Millisecond {
		t.Errorf("the quiet sender waited %s behind the flood", quietAt)
	}
}

// TestStreamQuotaHolds: while the store refuses (refuse-new), the
// connection's batch is held, nothing is dropped, and it all commits in
// order once the store takes it.
func TestStreamQuotaHolds(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, nil)
	g.store.refuse.Store(true)
	c := g.dial(addrA)
	defer c.Close()
	c.Write(octet(m1, m2))
	g.wait("held", func() bool { return g.r.Status().Held })
	c.Write(octet(m1))
	time.Sleep(50 * time.Millisecond)
	if n := g.store.count(); n != 0 {
		t.Fatalf("%d stored while refused", n)
	}
	g.store.refuse.Store(false)
	g.wait("3 stored", func() bool { return g.store.count() == 3 })
	if got := msgs(t, g.store.events(t)); !slices.Equal(got, []string{m1, m2, m1}) {
		t.Errorf("stored %q", got)
	}
	g.wait("not held", func() bool { return !g.r.Status().Held })
}

// TestDatagramQuotaDrops: while the store refuses, datagrams are dropped
// and counted with reason store, and the count is reported.
func TestDatagramQuotaDrops(t *testing.T) {
	g := newRig(t, asset.SyslogUDP, nil)
	g.store.refuse.Store(true)
	c := g.udp(addrA)
	defer c.Close()
	for i := 0; i < 5; i++ {
		c.Write([]byte(m2))
	}
	g.wait("dropped", func() bool { return g.r.Status().Dropped[DropStore] == 5 })
	g.wait("reported", func() bool {
		for _, h := range g.health.of(event.HealthDropCounted) {
			if h.Details["reason"] == DropStore && h.Details["count"] == "5" {
				return true
			}
		}
		return false
	})
	g.store.refuse.Store(false)
	c.Write([]byte(m1))
	g.wait("stored after", func() bool { return g.store.count() == 1 })
}

// TestConnectionLimits: a connection over the per-source limit is closed at
// accept and counted; another source still connects.
func TestConnectionLimits(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, func(c *Config) { c.Limits.MaxConnsPerSource = 1 })
	first := g.dial(addrA)
	defer first.Close()
	first.Write(octet(m1))
	g.wait("first stored", func() bool { return g.store.count() == 1 })
	second := g.dial(addrA)
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Error("second connection from one source was served")
	}
	g.wait("refused", func() bool { return g.r.Status().Refused["limit"] == 1 })
	other := g.dial(addrB)
	other.Write(octet(m2))
	other.Close()
	g.wait("other stored", func() bool { return g.store.count() == 2 })
}

// TestShutdownCommitsQueued: messages read before the listener stops still
// commit within the grace.
func TestShutdownCommitsQueued(t *testing.T) {
	g := newRig(t, asset.SyslogTCP, nil)
	g.store.refuse.Store(true)
	c := g.dial(addrA)
	c.Write(octet(m1, m2))
	g.wait("held", func() bool { return g.r.Status().Held })
	go func() {
		time.Sleep(100 * time.Millisecond)
		g.store.refuse.Store(false)
	}()
	g.stop()
	c.Close()
	if got := msgs(t, g.store.events(t)); !slices.Equal(got, []string{m1, m2}) {
		t.Errorf("stored %q", got)
	}
}

func TestNewRefuses(t *testing.T) {
	p := newPKI(t, "a4-ca")
	tc, _ := ServerTLS(&p.server, nil, false)
	base := func() Config {
		return Config{Node: testNode, ID: "x", Stream: testStream, Transport: asset.SyslogTLS, Address: "127.0.0.1:6514", Target: asset.Simulated,
			TLS: tc, Senders: testSenders(), Log: nopLog{}, Health: &sink{}, Received: received}
	}
	if _, err := New(base()); err != nil {
		t.Fatalf("base: %v", err)
	}
	for name, mut := range map[string]func(*Config){
		"tcp without the lab flag": func(c *Config) { c.Transport, c.TLS = asset.SyslogTCP, nil },
		"udp without the lab flag": func(c *Config) { c.Transport, c.TLS = asset.SyslogUDP, nil },
		"tls without config":       func(c *Config) { c.TLS = nil },
		"tcp with tls config":      func(c *Config) { c.Transport, c.Plaintext = asset.SyslogTCP, true },
		"telnet":                   func(c *Config) { c.Transport = asset.Telnet },
		"host name":                func(c *Config) { c.Address = "localhost:6514" },
		"no port":                  func(c *Config) { c.Address = "127.0.0.1" },
		"no target":                func(c *Config) { c.Target = "" },
		"no log":                   func(c *Config) { c.Log = nil },
		"no health":                func(c *Config) { c.Health = nil },
		"no clock":                 func(c *Config) { c.Received = nil },
		"bad stream":               func(c *Config) { c.Stream = "Syslog:x" },
		"bad node":                 func(c *Config) { c.Node = "Node_1" },
		"small max message":        func(c *Config) { c.Limits.MaxMessage = 100 },
		"sender without asset":     func(c *Config) { c.Senders = Senders{addrA: {Target: asset.Simulated}} },
		"mapped sender": func(c *Config) {
			c.Senders = Senders{netip.MustParseAddr("::ffff:127.0.0.1"): {AssetID: assetA, Target: asset.Simulated}}
		},
	} {
		c := base()
		mut(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestSendersFor builds a sender table from C1 assets: the RTAC example
// asset (udp, 192.0.2.40, port 514) gets the RTAC dialect.
func TestSendersFor(t *testing.T) {
	a := rtacAsset(t)
	s, err := SendersFor([]asset.Asset{a}, asset.SyslogUDP, 514)
	if err != nil {
		t.Fatal(err)
	}
	if src, ok := s[netip.MustParseAddr("192.0.2.40")]; !ok || src.AssetID != a.AssetID || src.Dialect != normalize.DialectRTAC || src.Target != asset.Simulated {
		t.Errorf("senders %+v", s)
	}
	if s, _ := SendersFor([]asset.Asset{a}, asset.SyslogUDP, 1514); len(s) != 0 {
		t.Errorf("an endpoint for port 514 matched a listener on 1514: %+v", s)
	}
	if s, _ := SendersFor([]asset.Asset{a}, asset.SyslogTLS, 514); len(s) != 0 {
		t.Errorf("a udp endpoint matched a tls listener: %+v", s)
	}
	named := rtacAsset(t)
	named.Endpoints[0].Host = "rtac.example"
	if _, err := SendersFor([]asset.Asset{named}, asset.SyslogUDP, 514); err == nil {
		t.Error("a host name was accepted")
	}
	twin := rtacAsset(t)
	twin.AssetID = assetA
	if _, err := SendersFor([]asset.Asset{a, twin}, asset.SyslogUDP, 514); err == nil {
		t.Error("two assets with one sender address were accepted")
	}
	if _, err := SendersFor(nil, asset.Telnet, 23); err == nil {
		t.Error("telnet accepted")
	}
}

// TestUDPKeepsWholeDatagram: a datagram longer than MaxMessage is kept
// whole; the limit bounds stream frames only.
func TestUDPKeepsWholeDatagram(t *testing.T) {
	g := newRig(t, asset.SyslogUDP, func(c *Config) { c.Limits.MaxMessage = 2048 })
	big := "<13>Oct 11 22:14:15 h " + strings.Repeat("z", 9000)
	c := g.udp(addrA)
	defer c.Close()
	if _, err := c.Write([]byte(big)); err != nil {
		t.Skipf("this host cannot send a %d-byte datagram: %v", len(big), err)
	}
	g.wait("stored", func() bool { return g.store.count() == 1 })
	if got := msgs(t, g.store.events(t)); got[0] != big {
		t.Errorf("stored %d bytes, sent %d", len(got[0]), len(big))
	}
}

var _ Appender = (*store.Log)(nil)

// nopLog is an Appender for tests that build records without storing them.
type nopLog struct{}

func (nopLog) AppendBatch(context.Context, []store.Record) ([]store.Receipt, error) {
	return nil, errors.New("test: nothing is stored")
}

func rtacAsset(t testing.TB) asset.Asset {
	t.Helper()
	b, err := os.ReadFile("../../../contracts/asset/testdata/valid/sel-rtac-syslog.json")
	if err != nil {
		t.Fatal(err)
	}
	a, err := asset.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestUnknownSendersBounded: past MaxUnknown addresses, one summary alarm
// is raised and no more are remembered.
func TestUnknownSendersBounded(t *testing.T) {
	g := newRig(t, asset.SyslogUDP, func(c *Config) { c.Senders, c.Limits.MaxUnknown = Senders{}, 2 })
	for i, a := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"} {
		c := g.udp(netip.MustParseAddr(a))
		c.Write([]byte(m2))
		c.Close()
		g.wait("stored", func() bool { return g.store.count() == i+1 })
	}
	g.wait("alarms", func() bool { return len(g.health.of(HealthUnknownSource)) == 3 })
	time.Sleep(50 * time.Millisecond)
	hs := g.health.of(HealthUnknownSource)
	if len(hs) != 3 || hs[2].Details["more_senders"] != "true" || hs[2].Details["sender"] != "127.0.0.3" {
		t.Errorf("alarms %+v", hs)
	}
	if s := g.r.Status(); s.UnknownSenders != 2 || !s.UnknownOverflow || len(g.r.unknown) != 2 {
		t.Errorf("status %+v", s)
	}
}

// blockingLog holds every AppendBatch until release is closed.
type blockingLog struct {
	Appender
	entered chan struct{}
	release chan struct{}
}

func (b *blockingLog) AppendBatch(ctx context.Context, recs []store.Record) ([]store.Receipt, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return b.Appender.AppendBatch(ctx, recs)
}

// TestDatagramQueueBytes: while the store is slow, datagrams wait up to
// MaxQueueBytes; past it they are dropped as queue-full and counted.
func TestDatagramQueueBytes(t *testing.T) {
	var bl *blockingLog
	g := newRig(t, asset.SyslogUDP, func(c *Config) {
		bl = &blockingLog{Appender: c.Log, entered: make(chan struct{}, 1), release: make(chan struct{})}
		c.Log, c.Limits.MaxQueueBytes = bl, maxDatagram
	})
	big := "<13>Oct 11 22:14:15 h " + strings.Repeat("q", 30000)
	c := g.udp(addrA)
	defer c.Close()
	if _, err := c.Write([]byte(big)); err != nil {
		t.Skipf("this host cannot send a %d-byte datagram: %v", len(big), err)
	}
	<-bl.entered
	c.Write([]byte(big))
	g.wait("second queued", func() bool { return g.r.Status().Received == 2 })
	c.Write([]byte(big))
	c.Write([]byte(big))
	g.wait("dropped", func() bool { return g.r.Status().Dropped[DropQueueFull] >= 1 })
	close(bl.release)
	g.wait("settled", func() bool {
		s := g.r.Status()
		return s.Received == 4 && s.Stored+s.Dropped[DropQueueFull] == 4
	})
	if s := g.r.Status(); s.Stored < 2 {
		t.Errorf("status %+v", s)
	}
}

// TestTLSOptionalClient: with a CA set for senders but no requirement, a
// sender with a certificate from that CA is tls-mutual, a sender without
// one is tls-server-only, and a certificate from another CA is refused.
func TestTLSOptionalClient(t *testing.T) {
	p, other := newPKI(t, "a4-ca"), newPKI(t, "other-ca")
	cfg, err := ServerTLS(&p.server, p.roots, false)
	if err != nil {
		t.Fatal(err)
	}
	g := newRig(t, asset.SyslogTLS, func(c *Config) { c.TLS = cfg })
	for _, client := range []*tls.Certificate{&p.client, nil} {
		c, err := tls.Dial("tcp", g.addr, sender(p.roots, client))
		if err != nil {
			t.Fatal(err)
		}
		c.Write(octet(m2))
		c.Close()
	}
	c, err := tls.Dial("tcp", g.addr, sender(p.roots, &other.client))
	if err == nil {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Errorf("a certificate from another CA was accepted (%v)", err)
	}
	g.wait("2 stored", func() bool { return g.store.count() == 2 })
	var auths []event.OriginAuth
	for _, e := range g.store.events(t) {
		auths = append(auths, e.Source.OriginAuth)
	}
	slices.Sort(auths)
	if !slices.Equal(auths, []event.OriginAuth{event.AuthTLSMutual, event.AuthTLSServerOnly}) {
		t.Errorf("origin_auth %v", auths)
	}
}

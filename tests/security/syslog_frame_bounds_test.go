package security

// Hostile received Syslog frames against the node's two size bounds (A6,
// #174; A5 #169 sizing, A4's normalizer). From the rule text, not A4's
// frames: a received frame of at most MaxMessage (8192) bytes is stored as
// an event of at most HeldBatchBytes / Queue = 8 x 8192 + 4096 = 69632
// bytes, and renders whole (text and summary kept) in at most
// RecommendedTargetOctets = 2 x (8192 + 2 x 1024) + 2048 = 22528 octets. An
// RTAC-dialect frame over 1024 bytes is not read as an RTAC Logger message:
// it is partial and keeps its bytes and hashes.
//
// The frames come from A6's own generator: random dialect-shaped frames
// built from bytes the encoders expand (JSON escapes <, >, &, controls and
// invalid UTF-8 to six bytes; U+2028 to six from three; SD escapes ", \ and
// ] to two), then a seeded hill climb that keeps any change that grows the
// stored event or the rendering. Seeds are fixed, so a run is reproducible;
// OTSEC_A6_FUZZ_ROUNDS raises the effort.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/syslog"
	"otsec.local/otsec/modules/telemetry/normalize"
)

const (
	a6MaxFrame      = 8192
	a6StoredBound   = 69632
	a6RenderedBound = 22528
	a6RTACPacket    = 1024
)

// a6Bytes are the pieces the generator draws from, worst first.
var a6Bytes = []string{"<", ">", "&", "\x01", "\x7f", "\xff", "\xe2\x80\xa8", `"`, `\`, "]", "[", "=", ", ", ": ", " ", "-", "a", "\xc3\xa9", "\x00", "\t", "\r", "\n", "%", "'"}

func a6Input(frame []byte, d normalize.Dialect, flags []string) normalize.SyslogInput {
	return normalize.SyslogInput{
		Node: "site-a-node1", Stream: "syslog/a6-hostile-listener-with-a-long-id", Message: frame,
		Sender: "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255", Auth: event.AuthTLSMutual, SenderCert: bytes.Repeat([]byte{0x30}, 64),
		AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", EvidenceClass: asset.Simulated, Dialect: d,
		Received: event.Received{UTC: "2026-10-26T15:00:00.123456789Z", ResolutionNS: 1, Clock: event.Clock{Sync: event.SyncSynchronized}},
		Flags:    flags,
	}
}

type a6Measure struct {
	stored, rendered int
	whole            bool
}

func a6Target(t testing.TB) *syslog.Target {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "syslog", "testdata", "targets", "valid", "relp-tls-required.json"))
	if err != nil {
		t.Fatal(err)
	}
	tg, err := syslog.ParseTarget(b)
	if err != nil {
		t.Fatal(err)
	}
	on := true
	tg.DeviceContent, tg.MaxMessageOctets = &on, a6RenderedBound
	if err := tg.Validate(); err != nil {
		t.Fatal(err)
	}
	return tg
}

func a6Measure1(t testing.TB, tg *syslog.Target, in normalize.SyslogInput) a6Measure {
	t.Helper()
	e, err := normalize.Syslog(in)
	if err != nil {
		// A sender the listener would refuse is not a stored frame; the
		// inputs here are all valid, so this is a failure.
		t.Fatalf("Syslog(%d bytes, %s): %v", len(in.Message), in.Dialect, err)
	}
	e.ID.Seq = math.MaxInt64
	stored, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	msg, out, err := syslog.Render(&e, tg)
	if err != nil {
		t.Fatalf("Render(%d bytes): %v", len(in.Message), err)
	}
	return a6Measure{stored: len(stored), rendered: len(msg), whole: !out.TextOmitted && !out.SummaryDropped}
}

// a6Shape builds one frame of at most a6MaxFrame bytes in a random dialect
// shape, filled from fill.
func a6Shape(r *rand.Rand, fill func(n int) string) []byte {
	var s string
	switch r.Intn(6) {
	case 0: // RFC 3164, long host and tag
		s = "<13>Oct 26 12:00:00 " + strings.ReplaceAll(fill(1+r.Intn(255)), " ", "h") + " " + strings.ReplaceAll(fill(1+r.Intn(48)), " ", "t") + ": " + fill(a6MaxFrame)
	case 1: // RFC 5424 with structured data
		var sd strings.Builder
		for i := 0; i < 1+r.Intn(20); i++ {
			sd.WriteString("[x" + strconv.Itoa(i) + "@1")
			for j := 0; j < 1+r.Intn(5); j++ {
				sd.WriteString(" p" + strconv.Itoa(j) + `="` + strings.NewReplacer(`"`, `\"`, `\`, `\\`, "]", `\]`).Replace(fill(r.Intn(400))) + `"`)
			}
			sd.WriteString("]")
		}
		s = "<13>1 2026-10-26T12:00:00.000001Z " + strings.Repeat("h", 1+r.Intn(255)) + " " + strings.Repeat("a", 1+r.Intn(48)) + " " + strings.Repeat("p", 1+r.Intn(128)) + " " + strings.Repeat("m", 1+r.Intn(32)) + " " + sd.String() + " " + fill(a6MaxFrame)
	case 2, 3: // RTAC Logger, at or under the packet limit and over it
		parts := []string{"2015-03-21 12:09:58.593", fill(r.Intn(40)), fill(r.Intn(40)), fill(r.Intn(600)), fill(r.Intn(a6MaxFrame))}
		s = "<190>Mar 21 2015 12:10:08 SEL-3530-xxxxxx RTAC Logger: " + strings.Join(parts, ", ")
		if r.Intn(2) == 0 && len(s) > a6RTACPacket {
			s = s[:a6RTACPacket-r.Intn(64)]
		}
	case 4: // no header at all
		s = fill(a6MaxFrame)
	case 5: // a 3164 header with an offset-looking token and a long MSG
		s = "<190>Oct 26 2026 12:00:00 -07:00 " + fill(a6MaxFrame)
	}
	if len(s) > a6MaxFrame {
		s = s[:a6MaxFrame]
	}
	return []byte(s)
}

func a6Rounds() int {
	if n, err := strconv.Atoi(os.Getenv("OTSEC_A6_FUZZ_ROUNDS")); err == nil && n > 0 {
		return n
	}
	return 300
}

func TestA6HostileFramesStayInTheNodesBounds(t *testing.T) {
	tg := a6Target(t)
	flagSets := [][]string{nil, {normalize.FlagTruncated}, {normalize.FlagFraming}, {normalize.FlagTruncated, normalize.FlagFraming}}
	var worstStored, worstRendered a6Measure
	var worstStoredName, worstRenderedName string
	check := func(name string, frame []byte) a6Measure {
		var top a6Measure
		for _, d := range []normalize.Dialect{normalize.DialectRFC, normalize.DialectRTAC} {
			for _, fl := range flagSets {
				m := a6Measure1(t, tg, a6Input(frame, d, fl))
				if m.stored > a6StoredBound {
					t.Errorf("%s (%s, flags %v): %d-byte frame stored as %d bytes, over %d", name, d, fl, len(frame), m.stored, a6StoredBound)
				}
				if !m.whole {
					t.Errorf("%s (%s, flags %v): %d-byte frame does not render whole in %d octets", name, d, fl, len(frame), a6RenderedBound)
				}
				top.stored, top.rendered = max(top.stored, m.stored), max(top.rendered, m.rendered)
			}
		}
		if top.stored > worstStored.stored {
			worstStored, worstStoredName = top, name
		}
		if top.rendered > worstRendered.rendered {
			worstRendered, worstRenderedName = top, name
		}
		return top
	}
	r := rand.New(rand.NewSource(20261026))
	for round := 0; round < a6Rounds() && !t.Failed(); round++ {
		// One alphabet per region: a single piece, or a mix.
		pieces := []string{a6Bytes[r.Intn(len(a6Bytes))]}
		if r.Intn(3) == 0 {
			pieces = append(pieces, a6Bytes[r.Intn(len(a6Bytes))], a6Bytes[r.Intn(len(a6Bytes))])
		}
		fill := func(n int) string {
			var b strings.Builder
			for b.Len() < n {
				b.WriteString(pieces[r.Intn(len(pieces))])
			}
			return b.String()[:n]
		}
		frame := a6Shape(r, fill)
		best := check("round "+strconv.Itoa(round), frame)
		// Hill climb: rewrite a random region with the worst JSON pieces and
		// keep the change when the stored event or the rendering grows.
		for step := 0; step < 8 && !t.Failed(); step++ {
			next := append([]byte(nil), frame...)
			at, n := r.Intn(len(next)), 1+r.Intn(512)
			piece := []byte(a6Bytes[r.Intn(7)])
			for i := at; i < at+n && i+len(piece) <= len(next); i += len(piece) {
				copy(next[i:], piece)
			}
			if m := check("round "+strconv.Itoa(round)+" step "+strconv.Itoa(step), next); m.stored > best.stored || m.rendered > best.rendered {
				frame, best = next, m
			}
		}
	}
	t.Logf("largest stored %d bytes (%s), bound %d; largest rendering %d octets (%s), bound %d",
		worstStored.stored, worstStoredName, a6StoredBound, worstRendered.rendered, worstRenderedName, a6RenderedBound)
}

// The frames A4 reported on main before the fix: a tag full of "<", the
// whole frame. Each must be in the bounds now.
func TestA6RTACTagOfLessThan(t *testing.T) {
	tg := a6Target(t)
	head := "<190>Mar 21 2015 12:10:08 SEL-3530-xxxxxx RTAC Logger: 2015-03-21 12:09:58.593, I, S, "
	for _, n := range []int{a6RTACPacket - len(head) - 3, 900, 4000, a6MaxFrame - len(head) - 3} {
		frame := []byte(head + strings.Repeat("<", n) + ", m")
		if len(frame) > a6MaxFrame {
			frame = frame[:a6MaxFrame]
		}
		m := a6Measure1(t, tg, a6Input(frame, normalize.DialectRTAC, []string{normalize.FlagTruncated}))
		t.Logf("%d-byte frame: stored %d, rendered %d, whole %v", len(frame), m.stored, m.rendered, m.whole)
		if m.stored > a6StoredBound || !m.whole {
			t.Errorf("%d-byte frame: stored %d (bound %d), whole %v", len(frame), m.stored, a6StoredBound, m.whole)
		}
	}
}

// An RTAC-dialect frame over 1024 bytes is partial, and keeps its bytes and
// hashes; one of 1024 bytes in the RTAC Logger shape is read as RTAC.
func TestA6RTACOverThePacketLimitIsPartial(t *testing.T) {
	head := "<190>Mar 21 2015 12:10:08 SEL-3530-xxxxxx RTAC Logger: 2015-03-21 12:09:58.593, Informational, Security, SystemTags. X, "
	r := rand.New(rand.NewSource(1024))
	lengths := []int{a6RTACPacket, a6RTACPacket + 1, a6RTACPacket + 2, 2048, a6MaxFrame}
	for i := 0; i < 20; i++ {
		lengths = append(lengths, a6RTACPacket+1+r.Intn(a6MaxFrame-a6RTACPacket))
	}
	for _, n := range lengths {
		frame := []byte(head + strings.Repeat("m", n-len(head)))
		e, err := normalize.Syslog(a6Input(frame, normalize.DialectRTAC, nil))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(frame)
		h := hex.EncodeToString(sum[:])
		nv := e.Native
		if nv == nil || !bytes.Equal(nv.Bytes, frame) || nv.RecordSHA256 != h || nv.RecordLength != int64(n) || nv.Evidence.SHA256 != h {
			t.Errorf("%d bytes: native bytes or hashes not kept", n)
			continue
		}
		rtac := e.Normalized.Subject == "SystemTags. X"
		switch {
		case n <= a6RTACPacket && (!rtac || e.Collection.ParseStatus != event.ParseOK):
			t.Errorf("%d bytes: not read as RTAC: %s %+v", n, e.Collection.ParseStatus, e.Normalized)
		case n > a6RTACPacket && (rtac || e.Collection.ParseStatus != event.ParsePartial || e.Normalized.Value != ""):
			t.Errorf("%d bytes: %s, normalized %+v; want partial and not read as RTAC", n, e.Collection.ParseStatus, e.Normalized)
		}
		for _, f := range nv.Fields {
			if n > a6RTACPacket && (f.Name == "tag" || f.Name == "category" || f.Name == "severity_name") {
				t.Errorf("%d bytes: RTAC field %s copied: %.40q", n, f.Name, f.Value)
			}
		}
	}
}

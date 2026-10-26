package normalize

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/syslog"
)

// The two size bounds the node sizes listeners by (A5 on #169, from A4's
// review there):
//   - a received frame of at most maxFrame bytes is stored as an event of at
//     most storedBound bytes (node.HeldBatchBytes: Queue × this);
//   - its C6 rendering, device text included, fits renderedBound octets
//     (node.RecommendedTargetOctets).
//
// They are measured here on hostile frames, the worst for each: characters
// JSON escapes to six bytes or SD escapes to two, invalid UTF-8, and each
// dialect's longest fields. The node's constants are copied, not imported
// (platform must not be a dependency of modules); a change on either side
// must change both.
const (
	maxFrame      = 8192                             // receive.Limits.MaxMessage default
	storedBound   = 8*maxFrame + 4<<10               // node: ReceivedRecordFactor × MaxMessage + ReceivedRecordOverhead
	renderedBound = 2*(maxFrame+2*rtacMaxMSG) + 2048 // node.RecommendedTargetOctets
)

// hostileFrames are frames of at most maxFrame bytes built to make the
// stored event and the rendering as large as the parser allows.
func hostileFrames() map[string][]byte {
	cut := func(s string) []byte {
		if len(s) > maxFrame {
			s = s[:maxFrame]
		}
		return []byte(s)
	}
	fill := func(prefix, c string, n int) string {
		return prefix + strings.Repeat(c, (n-len(prefix))/len(c)+1)
	}
	const (
		h3164 = "<13>Oct 26 12:00:00 host app: "
		h5424 = "<13>1 2026-10-26T12:00:00Z host app - - "
		hRTAC = "<190>Mar 21 2015 12:10:08 SEL-3530-xxxxxx RTAC Logger: 2015-03-21 12:09:58.593, "
	)
	out := map[string][]byte{}
	for name, c := range map[string]string{"lt": "<", "quote": `"`, "bslash": `\`, "bracket": "]", "ctl": "\x01", "badutf8": "\xff", "ascii": "a"} {
		out["3164-msg-"+name] = cut(fill(h3164, c, maxFrame))
		out["3164-host-"+name] = cut(fill("<13>Oct 26 12:00:00 "+strings.Repeat(c, 255)+" "+strings.Repeat("t", 48)+": ", c, maxFrame))
		out["5424-msg-"+name] = cut(fill(h5424+"- ", c, maxFrame))
		out["5424-sd-"+name] = cut(fill(h5424+`[x@1 a="`, c, maxFrame-2) + `"]`)
		out["none-"+name] = cut(strings.Repeat(c, maxFrame))
		// RTAC: the longest MSG still read as RTAC, its text in the tag,
		// in the message, and split between them; and longer ones.
		at := func(parts ...string) []byte { return cut(hRTAC + strings.Join(parts, ", ")) }
		room := rtacMaxMSG - len("RTAC Logger: 2015-03-21 12:09:58.593, I, S, , ")
		out["rtac-tag-"+name] = at("I", "S", strings.Repeat(c, room/len(c)), "m")
		out["rtac-message-"+name] = at("I", "S", "T", strings.Repeat(c, room/len(c)))
		out["rtac-split-"+name] = at("I", "S", strings.Repeat(c, room/2/len(c)), strings.Repeat(c, room/2/len(c)))
		out["rtac-long-tag-"+name] = at("I", "S", strings.Repeat(c, maxFrame), "m")
		out["rtac-long-category-"+name] = at("I", strings.Repeat(c, 6000), strings.Repeat(c, 1024), strings.Repeat(c, 1024))
	}
	return out
}

func TestSyslogSizeBounds(t *testing.T) {
	b, err := os.ReadFile("../../../contracts/syslog/testdata/targets/valid/relp-tls-required.json")
	if err != nil {
		t.Fatal(err)
	}
	tg, err := syslog.ParseTarget(b)
	if err != nil {
		t.Fatal(err)
	}
	on := true
	tg.DeviceContent, tg.MaxMessageOctets = &on, renderedBound
	var maxStored, maxRendered int
	for name, frame := range hostileFrames() {
		for _, d := range []Dialect{DialectRFC, DialectRTAC} {
			in := sysInput(frame, d)
			in.Flags = []string{FlagTruncated} // the most a listener adds
			e := mustSyslog(t, in)
			stored, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			e.ID.Seq = 1 << 40 // the store's seq, at its widest plausible
			msg, out, err := syslog.Render(&e, tg)
			if err != nil {
				t.Fatalf("%s %s: %v", name, d, err)
			}
			if len(stored) > storedBound {
				t.Errorf("%s %s: %d-byte frame stored as %d bytes, bound %d", name, d, len(frame), len(stored), storedBound)
			}
			if out.TextOmitted || out.SummaryDropped {
				t.Errorf("%s %s: %d-byte frame does not fit %d octets whole (%d without its text)", name, d, len(frame), renderedBound, len(msg))
			}
			maxStored, maxRendered = max(maxStored, len(stored)), max(maxRendered, len(msg))
		}
	}
	t.Logf("largest stored %d (bound %d), largest rendered %d (bound %d)", maxStored, storedBound, maxRendered, renderedBound)
}

// A MSG over rtacMaxMSG is not read as an RTAC Logger message (S23 p. 636:
// the RTAC limits a whole packet to 1024 bytes): it is partial, with the
// whole MSG as msg and the host as its subject, no RTAC part is copied into
// a field or the normalized subject or value, and its bytes and hashes are
// kept like any other frame's.
func TestSyslogRTACOverlong(t *testing.T) {
	head := "<190>Mar 21 2015 12:10:08 SEL-3530-xxxxxx "
	body := "RTAC Logger: 2015-03-21 12:09:58.593, Informational, Security, SystemTags. X, "
	for _, n := range []int{rtacMaxMSG, rtacMaxMSG + 1} {
		msg := body + strings.Repeat("m", n-len(body))
		e := mustSyslog(t, sysInput([]byte(head+msg), DialectRTAC))
		f := fieldMap(e)
		read := e.Collection.ParseStatus == event.ParseOK && f["tag"] == "SystemTags. X" && e.Normalized.Subject == "SystemTags. X"
		if read != (n <= rtacMaxMSG) {
			t.Errorf("MSG of %d bytes: status %s, fields %d, normalized %+v", n, e.Collection.ParseStatus, len(f), e.Normalized.Subject)
		}
		if n > rtacMaxMSG && (f["msg"] != msg || e.Normalized.Subject != "SEL-3530-xxxxxx" || e.Normalized.Value != "" || e.DeviceTime != nil) {
			t.Errorf("overlong MSG: fields %v, normalized %+v, device time %+v", len(f), e.Normalized, e.DeviceTime)
		}
		// Partial, never dropped: the frame's bytes and hashes are kept (R1.4).
		frame := []byte(head + msg)
		if nv := e.Native; nv == nil || !bytes.Equal(nv.Bytes, frame) || nv.RecordSHA256 != sha256hex(frame) || nv.RecordLength != int64(len(frame)) || nv.Evidence.SHA256 != sha256hex(frame) {
			t.Errorf("MSG of %d bytes: native bytes or hashes not kept", n)
		}
	}
}

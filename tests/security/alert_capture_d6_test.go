package security

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/platform/node"
	"otsec.local/otsec/platform/sensorlink"
)

// V-M6's frames_missing row (C13 §7.1 and §14 item 18, D1 in D4-74), D6's
// independent check through the node's exported API, beside D5's
// TestDetectorAlertCapture. For every alert the node commits with a
// capture, the capture's frames are cited frames: each hashes to a cite,
// they appear in citation order as a subsequence of the alert's cites, and
// there are exactly cited − frames_missing of them. The stream mixes first
// sights of one and two frames, flows citing frames no first sight holds,
// and a restart between, so the frame index is rebuilt from the store.
// Evidence class: simulated (in process, no network, no sensor, no device).

// acFrame is a 74-byte frame that differs by n.
func acFrame(n byte) []byte {
	b := make([]byte, 74)
	for i := range b {
		b[i] = byte(i*7) ^ n
	}
	return b
}

func acHash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// acFlow is a flow start from the node's address on the node's VLAN, sent
// from a MAC that is not the node's and tied to no run, at first: the
// detector raises node-address-spoofed and own-session-outside-record on
// it. It cites the frames hashes; with data, it is a first sight that
// carries those frames' bytes, in the same order.
func acFlow(seq int, first string, hashes []string, data ...[]byte) *netobs.Observation {
	p := func(v int) *int { return &v }
	o := &netobs.Observation{
		Schema: netobs.Identifier, Type: netobs.TypeObservation, SensorID: unrSensor, RunID: unrRun, Seq: strconv.Itoa(seq),
		Kind: netobs.KindFlow, FirstUTC: first, LastUTC: first, ResolutionNS: 1000,
		L2:        netobs.L2{SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02", VLAN: p(10), EtherType: "0x0800"},
		IP:        &netobs.IP{Src: "192.0.2.5", Dst: "127.0.0.1", L4: "tcp", Sport: p(40000 + seq), Dport: p(2323)},
		Direction: netobs.DirectionClientServer, Protocol: "unknown",
		Citation: netobs.Citation{CaptureID: "ring:" + unrRun + ":3", FramesTotal: int64(len(hashes))},
		Coverage: netobs.Coverage{
			SensorVersion: "0.1.0", Engine: netobs.Engine{Name: "test-engine", Version: "1"},
			Interfaces: []netobs.Interface{{Name: "eth1", Attachment: "span", LAN: "single"}},
			PRP:        netobs.PRP{LANsSeen: []string{}}, HSR: netobs.HSRNotDecoded,
			VLANsSeen: []int{10}, UntaggedSeen: true, Decodes: []string{}, Degraded: []string{},
			Settings: netobs.Settings{SAReplyTimeoutMS: netobs.DefaultSAReplyTimeoutMS, MaxPendingDNP3: netobs.DefaultMaxPendingDNP3, FlowIdleS: netobs.DefaultFlowIdleS},
			SinceUTC: "2026-11-08T08:00:00.000000Z",
		},
		Flow: &netobs.Flow{Phase: "start", Packets: 3, Bytes: 222},
	}
	for i, h := range hashes {
		n := int64(seq*10 + i)
		o.Citation.Frames = append(o.Citation.Frames, netobs.CitedFrame{N: n, CapturedLen: 74, WireLen: 74, SHA256: h})
		if data != nil {
			o.Frames = append(o.Frames, netobs.Frame{N: n, TS: first, Data: base64.StdEncoding.EncodeToString(data[i])})
		}
	}
	o.FirstSight = data != nil
	return o
}

// acChecked is what the check found over the committed alerts.
type acChecked struct {
	captured, whole, mixed, headerOnly, framesMissing int
}

// acCheck checks every committed alert's capture against its cites.
func acCheck(t *testing.T, r *node.Runtime) acChecked {
	t.Helper()
	ctx := context.Background()
	stream := node.NetAlertStream(unrSensor)
	db := r.Store(stream)
	got, err := db.Read(ctx, stream, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var c acChecked
	for _, st := range got {
		e, err := event.Decode(st.Event)
		if err != nil {
			t.Fatal(err)
		}
		a, err := netobs.AlertFromEvent(e)
		if err != nil {
			t.Fatal(err)
		}
		var cited []string
		for _, ct := range a.Cites {
			for _, f := range ct.Frames {
				cited = append(cited, f.SHA256)
			}
		}
		if a.FramesMissing > 0 {
			c.framesMissing++
		}
		if a.Rule == netobs.RuleOwnSessionUnseen {
			continue // no capture (C13 §7.1)
		}
		if st.EvidenceRef == "" || a.Capture == "" || "sha256:"+a.Capture != st.EvidenceRef {
			t.Errorf("alert %d (%s): capture %q, evidence %q", st.Key.Seq, a.Rule, a.Capture, st.EvidenceRef)
			continue
		}
		cp, err := db.ReadCapture(ctx, st.EvidenceRef)
		if err != nil {
			t.Fatal(err)
		}
		if acHash(cp.Bytes) != a.Capture {
			t.Errorf("alert %d: the stored capture does not hash to the alert's capture", st.Key.Seq)
		}
		frames, err := sensorlink.ParseCapture(cp.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		// Each frame hashes to the next cite at or after the last match:
		// the frames are cited frames, in citation order.
		i := 0
		for _, f := range frames {
			h := acHash(f.Data)
			for i < len(cited) && cited[i] != h {
				i++
			}
			if i == len(cited) {
				t.Errorf("alert %d (%s): a capture frame %s is not a cite, or is out of citation order", st.Key.Seq, a.Rule, h[:12])
				break
			}
			if f.WireLen != len(f.Data) {
				t.Errorf("alert %d: frame wire length %d for %d bytes", st.Key.Seq, f.WireLen, len(f.Data))
			}
			i++
		}
		if int64(len(frames)) != int64(len(cited))-a.FramesMissing || a.FramesMissing < 0 {
			t.Errorf("alert %d (%s): %d frames, %d cited, frames_missing %d", st.Key.Seq, a.Rule, len(frames), len(cited), a.FramesMissing)
		}
		c.captured++
		switch {
		case a.FramesMissing == 0:
			c.whole++
		case len(frames) == 0:
			c.headerOnly++
		default:
			c.mixed++
		}
	}
	return c
}

func TestD6AlertCaptureFramesMissing(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "store")
	f1, f2, f3 := acFrame(1), acFrame(2), acFrame(3)
	gone := acHash(acFrame(9)) // no first sight ever holds it
	r, st := bcStart(t, dir, true, nil)
	r.Tick(ctx)
	// Before the restart: a first sight of two frames, one of one, and a
	// flow citing a held frame between two that are not.
	serveRecs(t, r,
		acFlow(1, "2026-11-08T10:00:00.000001Z", []string{acHash(f1), acHash(f2)}, f1, f2),
		acFlow(2, "2026-11-08T10:00:01.000001Z", []string{acHash(f3)}, f3),
		acFlow(3, "2026-11-08T10:00:02.000001Z", []string{gone, acHash(f2), acHash(acFrame(8))}),
	)
	r.Tick(ctx)
	waitStep(t, r)
	r.Close()

	// After the restart, the index comes from the store: flows citing the
	// earlier first sights' frames out of their stored order, one citing
	// only a frame no first sight holds, then a flow at 10:30 that closes
	// the 10:00 windows, whose summaries cite across all of them, and opens
	// new ones citing only frames no first sight holds, and one at 11:00
	// that closes those.
	r, st = bcStart(t, dir, false, nil)
	defer r.Close()
	r.Tick(ctx)
	serveRecs(t, r,
		acFlow(4, "2026-11-08T10:00:03.000001Z", []string{acHash(f2), acHash(f1)}),
		acFlow(5, "2026-11-08T10:00:04.000001Z", []string{gone}),
		acFlow(6, "2026-11-08T10:00:05.000001Z", []string{acHash(f3), gone, acHash(f1)}),
		acFlow(7, "2026-11-08T10:30:00.000001Z", []string{gone, acHash(acFrame(8))}),
		acFlow(8, "2026-11-08T11:00:00.000001Z", []string{acHash(f3), acHash(f2)}),
	)
	r.Tick(ctx)
	waitStep(t, r)

	c := acCheck(t, r)
	d := bcDetector(t, st, "after the stream")
	// Two rules on each hit, coalesced: before the restart each rule's
	// first alert (whole); after it, each rule's 10:00 summary (frames
	// missing, some held), its 10:30 first alert (header-only, two
	// missing) and its 11:00 first alert, citing held frames (whole).
	if c != (acChecked{captured: 8, whole: 4, mixed: 2, headerOnly: 2, framesMissing: 4}) {
		t.Errorf("alerts checked: %+v", c)
	}
	// Status counts since this start: the alerts committed after the
	// restart, and those of them with frames missing.
	if d.Alerts != 6 || d.AlertsFramesMissing != 4 || d.AlertsNotStored != 0 || d.AlertCommitFailures != 0 || d.Through != 8 {
		t.Fatalf("status %+v", d)
	}
	t.Logf("%d alerts with a capture: %d whole, %d with frames missing, %d header-only; status since restart: %d alerts, %d with frames missing",
		c.captured, c.whole, c.mixed, c.headerOnly, d.Alerts, d.AlertsFramesMissing)
}

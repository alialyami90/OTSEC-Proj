package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/detection/eventbaseline"
	"otsec.local/otsec/platform/node/nodeconfigtest"
)

func snapCapture(b []byte) c5.Capture {
	sum := sha256.Sum256(b)
	return c5.Capture{SHA256: hex.EncodeToString(sum[:]), Bytes: b}
}

// testCheckpoint is a learner checkpoint of relayID for snap.
func testCheckpoint(snap []byte) eventCheckpoint {
	c := snapCapture(snap)
	return eventCheckpoint{Schema: EventCheckpointSchema, Half: CheckpointLearner, AssetID: relayID, Version: 1,
		Watermark: "2026-11-01T10:00:00Z",
		Streams:   []checkpointStream{{Stream: "ser/" + relayID, RestartAfter: 4, ReadThrough: 6}, {Stream: string(HealthStream), RestartAfter: 9, ReadThrough: 9}},
		PrevKeys:  []string{"sha256:" + strings.Repeat("0", 64)},
		Gap:       &checkpointGap{From: "2026-11-01T09:00:00Z", Reason: "collection.missed"},
		Late:      2, Snapshot: checkpointSnapshot{SHA256: c.SHA256, Length: int64(len(snap))}}
}

// widestKeys is MaxAlignRows alignment keys of the widest form normalize
// accepts.
func widestKeys(t *testing.T) []string {
	t.Helper()
	keys := make([]string, event.MaxAlignRows)
	for i := range keys {
		keys[i] = fmt.Sprintf("sha256:%064x", i)
	}
	return keys
}

// The checkpoint document round-trips through its encoder, and the
// configuration validator accepts it with its snapshot as the capture.
func TestEventCheckpointRoundTrip(t *testing.T) {
	snap := []byte("snapshot bytes")
	for name, cp := range map[string]eventCheckpoint{
		"learner": testCheckpoint(snap),
		"detector": func() eventCheckpoint {
			cp := testCheckpoint(snap)
			cp.Half, cp.Version, cp.Baseline, cp.Gap, cp.PrevKeys = CheckpointDetector, 0, "sha256:"+strings.Repeat("a", 64), nil, nil
			return cp
		}(),
		"re-learn": func() eventCheckpoint {
			cp := testCheckpoint(snap)
			cp.Version, cp.Previous = 2, "sha256:"+strings.Repeat("b", 64)
			return cp
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			b, err := encodeCheckpoint(cp)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeCheckpoint(b)
			if err != nil {
				t.Fatal(err)
			}
			again, _ := encodeCheckpoint(got)
			if string(again) != string(b) {
				t.Fatalf("round trip changed the bytes:\n%s\n%s", b, again)
			}
			capture := snapCapture(snap)
			if err := ConfigDocuments(b, &capture); err != nil {
				t.Fatalf("ConfigDocuments: %v", err)
			}
		})
	}
}

// Every field outside its form or cap is refused by the encoder and by the
// validator, and the validator refuses a capture that is not the snapshot,
// bytes the encoder would not write, and unknown or trailing data.
func TestEventCheckpointRefusals(t *testing.T) {
	snap := []byte("snapshot bytes")
	capture := snapCapture(snap)
	for name, mut := range map[string]func(*eventCheckpoint){
		"schema":              func(c *eventCheckpoint) { c.Schema = "otsec.eventcheckpoint/0.2" },
		"half":                func(c *eventCheckpoint) { c.Half = "both" },
		"asset":               func(c *eventCheckpoint) { c.AssetID = "relay-1" },
		"learner version 0":   func(c *eventCheckpoint) { c.Version = 0 },
		"learner previous v1": func(c *eventCheckpoint) { c.Previous = "sha256:" + strings.Repeat("b", 64) },
		"learner no previous": func(c *eventCheckpoint) { c.Version = 2 },
		"learner baseline":    func(c *eventCheckpoint) { c.Baseline = "sha256:" + strings.Repeat("a", 64) },
		"detector version": func(c *eventCheckpoint) {
			c.Half, c.Baseline = CheckpointDetector, "sha256:"+strings.Repeat("a", 64)
		},
		"detector no baseline": func(c *eventCheckpoint) { c.Half, c.Version = CheckpointDetector, 0 },
		"previous form":        func(c *eventCheckpoint) { c.Version, c.Previous = 2, "sha256:XYZ" },
		"watermark":            func(c *eventCheckpoint) { c.Watermark = "2026-11-01 10:00:00" },
		"watermark not utc":    func(c *eventCheckpoint) { c.Watermark = "2026-11-01T10:00:00+01:00" },
		// time.Parse never gives time.UTC for an explicit offset, so the
		// location check refuses it (C6 on #376).
		"watermark +00:00": func(c *eventCheckpoint) { c.Watermark = "2026-11-01T10:00:00+00:00" },
		"no streams":       func(c *eventCheckpoint) { c.Streams = nil },
		"too many streams": func(c *eventCheckpoint) {
			for i := len(c.Streams); i <= MaxCheckpointStreams; i++ {
				c.Streams = append(c.Streams, checkpointStream{Stream: fmt.Sprintf("syslog/l%d", i)})
			}
		},
		"stream token":      func(c *eventCheckpoint) { c.Streams[0].Stream = "SER/x" },
		"stream twice":      func(c *eventCheckpoint) { c.Streams[1].Stream = c.Streams[0].Stream },
		"restart past read": func(c *eventCheckpoint) { c.Streams[0].RestartAfter = c.Streams[0].ReadThrough + 1 },
		"key form":          func(c *eventCheckpoint) { c.PrevKeys = []string{"not a key"} },
		"too many keys":     func(c *eventCheckpoint) { c.PrevKeys = append(widestKeys(t), c.PrevKeys...) },
		"gap from":          func(c *eventCheckpoint) { c.Gap.From = "" },
		"gap reason":        func(c *eventCheckpoint) { c.Gap.Reason = "Collection Missed" },
		"gap end":           func(c *eventCheckpoint) { c.LastGapEnd = "yesterday" },
		"late":              func(c *eventCheckpoint) { c.Late = -1 },
		"snapshot digest":   func(c *eventCheckpoint) { c.Snapshot.SHA256 = strings.ToUpper(c.Snapshot.SHA256) },
		"snapshot empty":    func(c *eventCheckpoint) { c.Snapshot.Length = 0 },
		"snapshot too big":  func(c *eventCheckpoint) { c.Snapshot.Length = eventbaseline.MaxSnapshotBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			cp := testCheckpoint(snap)
			mut(&cp)
			if _, err := encodeCheckpoint(cp); err == nil {
				t.Fatal("encoded")
			}
		})
	}

	b, err := encodeCheckpoint(testCheckpoint(snap))
	if err != nil {
		t.Fatal(err)
	}
	other := snapCapture([]byte("other bytes"))
	// The same length as the snapshot: only the digest comparison refuses
	// it (C6 on #376).
	sameLength := snapCapture([]byte("snapshot bytez"))
	// The right digest with another length: only the length comparison
	// refuses it (C6 on #376).
	long := testCheckpoint(snap)
	long.Snapshot.Length++
	lb, err := encodeCheckpoint(long)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		doc     string
		capture *c5.Capture
	}{
		"no capture":                         {string(b), nil},
		"other capture":                      {string(b), &other},
		"bad capture":                        {string(b), &c5.Capture{SHA256: capture.SHA256, Bytes: []byte("x")}},
		"other capture of the same length":   {string(b), &sameLength},
		"a length that is not the capture's": {string(lb), &capture},
		// The document's digest and length, over other bytes: only the
		// capture's own Validate refuses it.
		"a capture whose bytes are not its digest": {string(b), &c5.Capture{SHA256: capture.SHA256, Bytes: []byte("snapshot bytez")}},
		"not canonical":  {" " + string(b), &capture},
		"unknown field":  {strings.Replace(string(b), `{"schema"`, `{"extra":1,"schema"`, 1), &capture},
		"trailing data":  {string(b) + "{}", &capture},
		"a mutated half": {strings.Replace(string(b), `"half":"learner"`, `"half":"detector"`, 1), &capture},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ConfigDocuments([]byte(tc.doc), tc.capture); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// The widest checkpoint record (MaxSnapshotBytes of snapshot as its
// capture, and a document with every list at its cap and every string at its
// widest) is stored by the real configuration database, and its document is
// within the allowance D4-38 counts for it. Evidence class: simulated.
func TestWidestEventCheckpointIsStored(t *testing.T) {
	snap := make([]byte, eventbaseline.MaxSnapshotBytes)
	for i := range snap {
		snap[i] = byte(i * 7)
	}
	cp := testCheckpoint(snap)
	cp.Version, cp.Previous = 1<<62, "sha256:"+strings.Repeat("f", 64)
	cp.Watermark, cp.LastGapEnd = "2026-11-01T10:00:00.123456789Z", "2026-11-01T09:59:59.123456789Z"
	cp.Gap = &checkpointGap{From: "2026-11-01T09:00:00.123456789Z", Reason: "a" + strings.Repeat("z", 63)}
	cp.Late = 1<<63 - 1
	cp.Streams = nil
	for i := 0; i < MaxCheckpointStreams; i++ {
		cp.Streams = append(cp.Streams, checkpointStream{Stream: fmt.Sprintf("syslog/%s%02d", strings.Repeat("l", 60), i), RestartAfter: 1<<63 - 2, ReadThrough: 1<<63 - 1})
	}
	cp.PrevKeys = widestKeys(t)
	doc, err := encodeCheckpoint(cp)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc) > MaxCheckpointDocBytes {
		t.Fatalf("the widest checkpoint document is %d bytes, above MaxCheckpointDocBytes %d", len(doc), MaxCheckpointDocBytes)
	}
	t.Logf("widest checkpoint: document %d bytes, snapshot %d bytes, record %d of %d", len(doc), len(snap), len(doc)+len(snap), ConfigRecordBytes)

	c, dir := configNode(t, func(nc *nodeconfigtest.Config) { nc.Store.Quotas["configuration"] = 64 << 20 })
	r, _, _ := start(t, c, dir)
	defer r.Close()
	_, log, _ := r.view(r.find(ConfigDB))
	capture := snapCapture(snap)
	if _, err := log.Append(bg, c5.Record{Stream: ConfigStream(relayID), Class: c5.ClassConfiguration, Event: doc, Capture: &capture}); err != nil {
		t.Fatal(err)
	}
	got, err := r.Store(ConfigStream(relayID)).Read(bg, ConfigStream(relayID), 0, 1)
	if err != nil || len(got) != 1 || string(got[0].Event) != string(doc) {
		t.Fatalf("read back: %v, %d records", err, len(got))
	}
}

// The checkpoint's bytes are what today's encoder writes, and decode refuses
// anything else. Two committed documents must decode and re-encode byte for
// byte, so a toolchain whose encoding/json output differs fails here, in CI,
// not at a site's first restore after an upgrade (C6 on #376). Evidence
// class: desk.
func TestEventCheckpointGolden(t *testing.T) {
	for _, name := range []string{"eventcheckpoint-learner.json", "eventcheckpoint-detector.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		cp, err := decodeCheckpoint(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		again, err := encodeCheckpoint(cp)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("%s: re-encoded %v\n%s\nwant\n%s", name, err, again, b)
		}
	}
}

// The node configuration holds an observed asset to MaxCheckpointStreams
// feeder streams at load, so a checkpoint can always name them all (C6 on
// #376). The relay's SER read gives two (its SER and the health stream), and
// each listener that takes its Syslog gives one more.
func TestEventBaselineStreamsHeldAtLoad(t *testing.T) {
	if MaxCheckpointStreams != eventbaseline.MaxStreams {
		t.Fatalf("MaxCheckpointStreams %d, eventbaseline.MaxStreams %d", MaxCheckpointStreams, eventbaseline.MaxStreams)
	}
	for listeners, ok := range map[int]bool{MaxCheckpointStreams - 2: true, MaxCheckpointStreams - 1: false} {
		_, err := ParseConfig(ebConfig(t, func(nc *nodeconfigtest.Config) {
			nc.AddEventBaseline(relayID).AddSyslogSender(relayID, "syslog", "syslog-udp", "127.0.0.2", 0)
			nc.Store.Quotas["syslog-datagram"] = 1 << 30 // HR-11's room for unknown senders per listener
			for i := 0; i < listeners; i++ {
				nc.AddListener(fmt.Sprintf("udp%d", i), "syslog-udp", fmt.Sprintf("127.0.0.1:%d", 5514+i))
			}
		}))
		if ok != (err == nil) || (!ok && !strings.Contains(err.Error(), fmt.Sprintf("at most %d", MaxCheckpointStreams))) {
			t.Errorf("%d listeners: %v", listeners, err)
		}
	}
}

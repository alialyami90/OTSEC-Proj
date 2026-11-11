package contract

// The test-only C13 source, judged by the contract's own decoder (D6,
// P4-4-R1 deliverable 3). tests/integration/sensor_rig/c13_source.py turns
// GT-PCAP's labels into C13 records, from the contract's text and with no
// code from contracts/netobs. testdata/c13-source/gt-pcap-dnp3.stream is
// what it sends for five GT-PCAP captures, each as a run of its own, and a
// Python test pins the file to the source. Here every record of that stream
// must read as C13's framing, pass DecodeChannel, and follow the heartbeat
// before it. If the source and the decoder read C13 differently, one of
// them is wrong, and this fails. Ground truth: GT-PCAP's labels. Evidence
// class: desk.

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

// The decoder's acceptance above means something only if it refuses a
// wrong record, and for the reason the contract names. Each case takes the
// stream's first observation, a first sight that the decoder accepts, and
// breaks one rule of C13 in its bytes: a duplicate key at the top level and
// inside the citation (strict JSON, §1: decode), the node's object on a
// channel record (§5: conflict), frame bytes that no longer hash to their
// citation (§4.2: hash), and a record that says it is an alert, which the
// channel never carries (§1, AP-34: type). The last case is a heartbeat
// whose counters fall within its run (§6: order).
func TestC13SourceRecordsBrokenOnPurposeAreRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "c13-source", "gt-pcap-dnp3.stream"))
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	if _, err := netobs.ReadFrame(r); err != nil { // the opening heartbeat
		t.Fatal(err)
	}
	good, err := netobs.ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if rec, err := netobs.DecodeChannel(good); err != nil || rec.Observation == nil || !rec.Observation.FirstSight {
		t.Fatalf("the stream's second record should be an accepted first sight: %v", err)
	}
	swap := func(old, new string) []byte {
		if bytes.Count(good, []byte(old)) != 1 {
			t.Fatalf("%q is in the record %d times, want once", old, bytes.Count(good, []byte(old)))
		}
		return bytes.Replace(good, []byte(old), []byte(new), 1)
	}
	node := `,"node":{"src_asset":"asset-unresolved","dst_asset":"asset-unresolved","resolved_by":"none","evidence_class":"simulated"}}`
	// The frame's data with its first base64 character changed.
	rehashed := append([]byte{}, good...)
	at := bytes.Index(rehashed, []byte(`"data":"`)) + len(`"data":"`)
	if rehashed[at] == 'A' {
		rehashed[at] = 'B'
	} else {
		rehashed[at] = 'A'
	}
	for _, c := range []struct {
		name string
		b    []byte
		want netobs.Code
	}{
		{"a key twice at the top level", swap(`"kind":"flow"`, `"kind":"flow","kind":"flow"`), netobs.CodeDecode},
		{"a key twice inside the citation", swap(`"frames_total":1`, `"frames_total":1,"frames_total":1`), netobs.CodeDecode},
		{"the node's object on the channel", append(append([]byte{}, good[:len(good)-1]...), node...), netobs.CodeConflict},
		{"frame bytes that do not hash to the citation", rehashed, netobs.CodeHash},
		{"a record that says it is an alert", swap(`"type":"observation"`, `"type":"alert"`), netobs.CodeType},
	} {
		_, err := netobs.DecodeChannel(c.b)
		if err == nil {
			t.Errorf("%s: the decoder accepted the record", c.name)
		} else if !slices.Contains(netobs.Codes(err), c.want) {
			t.Errorf("%s: refused as %v, want %s: %v", c.name, netobs.Codes(err), c.want, err)
		}
	}

	// The run's two heartbeats, the wrong way round: the opening one, with
	// its lower seq and its zero counters, does not follow the closing one.
	var beats []*netobs.Heartbeat
	for r = bytes.NewReader(raw); len(beats) < 2; {
		b, err := netobs.ReadFrame(r)
		if err != nil {
			t.Fatal(err)
		}
		if rec, err := netobs.DecodeChannel(b); err != nil {
			t.Fatal(err)
		} else if rec.Heartbeat != nil {
			beats = append(beats, rec.Heartbeat)
		}
	}
	if beats[0].RunID != beats[1].RunID || beats[1].Counters.Packets == 0 {
		t.Fatalf("the stream's first two heartbeats should open and close one run")
	}
	if err := beats[1].Follows(beats[0]); err != nil {
		t.Errorf("the closing heartbeat does not follow the opening one: %v", err)
	}
	if err := beats[0].Follows(beats[1]); err == nil {
		t.Error("a heartbeat whose seq and counters fall within its run was accepted")
	} else if !slices.Contains(netobs.Codes(err), netobs.CodeOrder) {
		t.Errorf("falling counters refused as %v, want %s", netobs.Codes(err), netobs.CodeOrder)
	}
}

func TestC13SourceStreamIsAcceptedByTheContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "c13-source", "gt-pcap-dnp3.stream"))
	if err != nil {
		t.Fatal(err)
	}
	r := bytes.NewReader(raw)
	var prev *netobs.Heartbeat
	runs := map[string]bool{}
	kinds := map[netobs.Kind]int{}
	sa := map[string]int{}
	heartbeats, firstSights := 0, 0
	for n := 1; ; n++ {
		b, err := netobs.ReadFrame(r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("record %d: %v", n, err)
		}
		rec, err := netobs.DecodeChannel(b)
		if err != nil {
			t.Fatalf("record %d is refused: %v\n%s", n, err, b)
		}
		if h := rec.Heartbeat; h != nil {
			if err := h.Follows(prev); err != nil {
				t.Fatalf("record %d: %v", n, err)
			}
			prev = h
			runs[h.RunID] = true
			heartbeats++
			continue
		}
		o := rec.Observation
		kinds[o.Kind]++
		if o.FirstSight {
			firstSights++
		}
		if o.Function != nil {
			sa[o.Function.SA]++
		}
		if o.Node != nil {
			t.Fatalf("record %d carries the node's object", n)
		}
	}
	// What the five captures' labels hold: a flow start and end each, a
	// service each, and nine function rows over every sa outcome, two of
	// them with sa unknown: the request with no response, and the request
	// completed early by a reused sequence number.
	if len(runs) != 5 || heartbeats != 10 {
		t.Errorf("%d runs and %d heartbeats, want 5 and 10", len(runs), heartbeats)
	}
	if kinds[netobs.KindFlow] != 10 || kinds[netobs.KindService] != 5 || kinds[netobs.KindFunction] != 9 {
		t.Errorf("kinds %v, want 10 flow, 5 service and 9 function records", kinds)
	}
	if firstSights != 5+5+9 {
		t.Errorf("%d first sights, want 19: every record but the five flow ends", firstSights)
	}
	want := map[string]int{netobs.SANone: 4, netobs.SAChallenged: 1, netobs.SAAggressive: 1, netobs.SAFailed: 1, "": 2}
	for k, v := range want {
		if sa[k] != v {
			t.Errorf("sa %q on %d function records, want %d (all: %v)", k, sa[k], v, sa)
		}
	}
}

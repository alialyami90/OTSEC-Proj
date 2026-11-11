package contract

// The test-only C13 source, judged by the contract's own decoder (D6,
// P4-4-R1 deliverable 3). tests/integration/sensor_rig/c13_source.py turns
// GT-PCAP's labels into C13 records, from the contract's text and with no
// code from contracts/netobs. testdata/c13-source/gt-pcap-dnp3.stream is
// what it sends for four GT-PCAP captures, each as a run of its own, and a
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
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

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
	// What the four captures' labels hold: a flow start and end each, a
	// service each, and seven function rows over every sa outcome, two of
	// them with sa unknown: the request with no response, and the request
	// completed early by a reused sequence number.
	if len(runs) != 4 || heartbeats != 8 {
		t.Errorf("%d runs and %d heartbeats, want 4 and 8", len(runs), heartbeats)
	}
	if kinds[netobs.KindFlow] != 8 || kinds[netobs.KindService] != 4 || kinds[netobs.KindFunction] != 7 {
		t.Errorf("kinds %v, want 8 flow, 4 service and 7 function records", kinds)
	}
	if firstSights != 4+4+7 {
		t.Errorf("%d first sights, want 15: every record but the four flow ends", firstSights)
	}
	want := map[string]int{netobs.SANone: 2, netobs.SAChallenged: 1, netobs.SAAggressive: 1, netobs.SAFailed: 1, "": 2}
	for k, v := range want {
		if sa[k] != v {
			t.Errorf("sa %q on %d function records, want %d (all: %v)", k, sa[k], v, sa)
		}
	}
}

package netack

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/contracts/node"
)

const (
	testSensor = "5f0c2a7e-3b1d-4c8e-9a2f-6d4e8b1c7a90"
	testNode   = node.ID("site-a-node1")
	relay      = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
	master     = "7c1e5a20-4d3b-4f6a-8b2c-9e0d1f2a3b4c"
)

// testDraft is a frozen draft: the master polls the relay over DNP3, and an
// unresolved address reads it over Modbus.
func testDraft(t *testing.T) []byte {
	t.Helper()
	pair := netobs.Pair{Client: master, Server: relay, L4: "tcp", Port: 20000, Protocol: "dnp3"}
	other := netobs.Pair{Client: "addr:192.0.2.99", Server: relay, L4: "tcp", Port: 502, Protocol: "modbus"}
	b := &netobs.Baseline{
		Schema: netobs.BaselineIdentifier, SensorID: testSensor, Version: 1, FunctionTable: netobs.FunctionTable,
		Period: netobs.Period{StartUTC: "2026-11-01T00:00:00Z", EndUTC: "2026-11-08T00:00:00Z",
			Observations: netobs.Counts{Flow: 40, Function: 12}},
		Params:    netobs.BaselineParams{TieGraceS: netobs.DefaultTieGraceS, CoalesceWindowS: netobs.DefaultCoalesceWindowS},
		Pairs:     []netobs.Pair{pair, other},
		Services:  []netobs.BaselineService{{Server: relay, L4: "tcp", Port: 20000, Protocol: "dnp3", Basis: "content"}},
		Functions: []netobs.BaselineFunction{{Pair: pair, Code: 1, Objects: []string{"g60v1"}}, {Pair: other, Code: 3}},
		Addresses: []netobs.Address{
			{IP: "192.0.2.10", Endpoint: master, VLANs: []int{10}},
			{IP: "192.0.2.20", Endpoint: relay, VLANs: []int{10}},
			{IP: "192.0.2.99", Endpoint: "addr:192.0.2.99", VLANs: []int{10}},
		},
	}
	netobs.SortBaseline(b)
	out, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var testWriters = []netobs.Writer{{Client: master, Server: relay, Class: netobs.ClassControl}}

func ack(draft, accepted []byte) *authz.NodeNetworkBaselineAckBody {
	return &authz.NodeNetworkBaselineAckBody{SensorID: testSensor, DraftDigest: netobs.Digest(draft), BaselineDigest: netobs.Digest(accepted)}
}

func reasonOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

// The builder's bytes are what the digests name (HR-14), and with no writers
// the document is the draft.
func TestBuildAccepted(t *testing.T) {
	draft := testDraft(t)
	doc, bd, dd, err := BuildAccepted(draft, testWriters)
	if err != nil {
		t.Fatal(err)
	}
	if bd != netobs.Digest(doc) || dd != netobs.Digest(draft) || bd == dd {
		t.Fatalf("digests %s %s over the document and draft", bd, dd)
	}
	if !netobs.IsCanonical(doc) || !netobs.OnlyWritersAdded(draft, doc) {
		t.Fatal("the built document is not the canonical draft with writers")
	}
	same, bd, dd, err := BuildAccepted(draft, nil)
	if err != nil || !bytes.Equal(same, draft) || bd != dd {
		t.Fatalf("no writers: %v, digests %s %s", err, bd, dd)
	}
	// Writers in any order give the same bytes.
	two := []netobs.Writer{{Client: master, Server: relay, Class: netobs.ClassWrite}, testWriters[0]}
	a, _, _, errA := BuildAccepted(draft, two)
	b, _, _, errB := BuildAccepted(draft, []netobs.Writer{two[1], two[0]})
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		t.Fatalf("writer order changed the bytes: %v %v", errA, errB)
	}
	for name, tc := range map[string]struct {
		draft   []byte
		writers []netobs.Writer
	}{
		"a writer of class read":       {draft, []netobs.Writer{{Client: master, Server: relay, Class: netobs.ClassRead}}},
		"a writer that is no endpoint": {draft, []netobs.Writer{{Client: "master", Server: relay, Class: netobs.ClassWrite}}},
		"a draft not canonical":        {append([]byte(" "), draft...), nil},
		"a draft that has writers":     {a, nil},
	} {
		if _, _, _, err := BuildAccepted(tc.draft, tc.writers); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}

func TestAdopt(t *testing.T) {
	draft := testDraft(t)
	doc, _, _, err := BuildAccepted(draft, testWriters)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Adopt(testSensor, draft, doc, ack(draft, doc))
	if err != nil || !bytes.Equal(got, doc) {
		t.Fatalf("the accepted document: %v", err)
	}
	// With equal digests the draft is adopted and any file is ignored
	// (D6, T5).
	got, err = Adopt(testSensor, draft, []byte("anything"), ack(draft, draft))
	if err != nil || !bytes.Equal(got, draft) {
		t.Fatalf("no writers: %v", err)
	}
	if _, err := Adopt(testSensor, draft, nil, ack(draft, draft)); err != nil {
		t.Fatalf("no writers, no file: %v", err)
	}

	// The returned bytes are a copy: a file changed after the check does
	// not change what is stored (D6, T3).
	file := slices.Clone(doc)
	got, err = Adopt(testSensor, draft, file, ack(draft, doc))
	if err != nil {
		t.Fatal(err)
	}
	file[0] = 'X'
	if !bytes.Equal(got, doc) {
		t.Fatal("the adopted bytes follow the file")
	}

	other, _, _, err := BuildAccepted(draft, []netobs.Writer{{Client: "addr:192.0.2.99", Server: relay, Class: netobs.ClassWrite}})
	if err != nil {
		t.Fatal(err)
	}
	reencoded := bytes.Replace(doc, []byte(`","`), []byte(`", "`), 1)
	changed := func() []byte {
		b, err := netobs.DecodeBaseline(doc)
		if err != nil {
			t.Fatal(err)
		}
		b.Params.TieGraceS++
		out, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}()
	otherSensor := func() ([]byte, []byte) {
		b, _ := netobs.DecodeBaseline(draft)
		b.SensorID = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
		d, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		a, _, _, err := BuildAccepted(d, testWriters)
		if err != nil {
			t.Fatal(err)
		}
		return d, a
	}
	osDraft, osDoc := otherSensor()
	big := make([]byte, netobs.MaxBaselineBytes+1)
	read := netobs.Writer{Client: master, Server: relay, Class: netobs.ClassRead}
	badClass := bytes.Replace(doc, []byte(`"class":"control"`), []byte(`"class":"`+read.Class+`"`), 1)

	for name, tc := range map[string]struct {
		sensor      string
		draft, file []byte
		body        *authz.NodeNetworkBaselineAckBody
		want        string
	}{
		"no body":           {testSensor, draft, doc, nil, ReasonBody},
		"a bad body":        {testSensor, draft, doc, &authz.NodeNetworkBaselineAckBody{SensorID: testSensor}, ReasonBody},
		"another sensor":    {"1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", draft, doc, ack(draft, doc), ReasonSensor},
		"no draft recorded": {testSensor, nil, doc, ack(draft, doc), ReasonDraftNotLatest},
		"a draft that is not the latest": {testSensor, draft, doc, &authz.NodeNetworkBaselineAckBody{SensorID: testSensor,
			DraftDigest: netobs.Digest(doc), BaselineDigest: netobs.Digest(doc)}, ReasonDraftNotLatest},
		"no file":                  {testSensor, draft, nil, ack(draft, doc), ReasonFileMissing},
		"a file with another hash": {testSensor, draft, other, ack(draft, doc), ReasonFileDigest},
		"a file above the cap, with its own hash signed": {testSensor, draft, big, ack(draft, big), ReasonFileDigest},
		"a body for another sensor": {testSensor, draft, doc, &authz.NodeNetworkBaselineAckBody{SensorID: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
			DraftDigest: netobs.Digest(draft), BaselineDigest: netobs.Digest(doc)}, ReasonSensor},
		"the signed hash, re-encoded":  {testSensor, draft, reencoded, ack(draft, reencoded), ReasonNotCanonical},
		"a writer of class read":       {testSensor, draft, badClass, ack(draft, badClass), ReasonNotCanonical},
		"a change outside the writers": {testSensor, draft, changed, ack(draft, changed), ReasonChanged},
		"a document for another sensor than the body": {testSensor, osDraft, osDoc,
			&authz.NodeNetworkBaselineAckBody{SensorID: testSensor, DraftDigest: netobs.Digest(osDraft), BaselineDigest: netobs.Digest(osDoc)}, ReasonSensor},
	} {
		got, err := Adopt(tc.sensor, tc.draft, tc.file, tc.body)
		if got != nil || reasonOf(err) != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
}

// A 0.10 acceptance must name its key set; the record is needed exactly
// when the set changes; an older request's reply names none.
func TestNeedsGrantRecord(t *testing.T) {
	entries := []authz.AdminKeyEntry{{KeyID: "ed25519-183d5080d1a2ef2b", Principal: "admin@site-a", Status: authz.KeyActive,
		Kinds: []authz.RequestKind{authz.KindNodeNetworkBaselineAck}}}
	digest := authz.AdminKeysDigest(entries)
	sent := &authz.CollectorRequest{Contract: authz.ContractID}
	acc := &authz.AdminAccepted{KeysDigest: digest, Keys: entries}

	for name, tc := range map[string]struct {
		last string
		want bool
	}{"the first set": {"", true}, "a new set": {"sha256:" + strings.Repeat("0", 64), true}, "the same set": {digest, false}} {
		got, err := NeedsGrantRecord(tc.last, sent, acc)
		if err != nil || got != tc.want {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	old := &authz.CollectorRequest{Contract: "otsec.authz/0.9"}
	if got, err := NeedsGrantRecord(digest, old, &authz.AdminAccepted{}); err != nil || got {
		t.Errorf("a 0.9 request: %v %v", got, err)
	}
	for name, tc := range map[string]struct {
		sent *authz.CollectorRequest
		acc  *authz.AdminAccepted
	}{
		"a 0.10 acceptance without keys_digest": {sent, &authz.AdminAccepted{}},
		"keys_digest not over the keys":         {sent, &authz.AdminAccepted{KeysDigest: "sha256:" + strings.Repeat("0", 64), Keys: entries}},
		"a 0.9 reply that names a key set":      {old, acc},
		"no acceptance":                         {sent, nil},
		"no request":                            {nil, acc},
	} {
		if _, err := NeedsGrantRecord(digest, tc.sent, tc.acc); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// An asset end the node does not connect to at an address in the baseline
// is marked; one it connects to is not (D4-70).
func TestInboundOnly(t *testing.T) {
	b, err := netobs.DecodeBaseline(testDraft(t))
	if err != nil {
		t.Fatal(err)
	}
	ep := func(id string, tr asset.Transport, host string, path asset.Path) asset.Endpoint {
		return asset.Endpoint{ID: id, Transport: tr, Host: host, Port: 22, Path: path, Target: asset.Simulated}
	}
	assets := []asset.Asset{
		{AssetID: relay, NodeID: testNode, Endpoints: []asset.Endpoint{ep("ssh", asset.SSH, "::ffff:192.0.2.20", asset.Direct)}},
		{AssetID: master, NodeID: testNode, Endpoints: []asset.Endpoint{ep("syslog", asset.SyslogUDP, "192.0.2.10", "")}},
	}
	if got := InboundOnly(b, testNode, assets); len(got) != 1 || !got[master] {
		t.Fatalf("marked %v, want the master only", got)
	}
	// The master also polled from a direct endpoint at the same address:
	// not marked.
	withDirect := slices.Clone(assets)
	withDirect[1].Endpoints = append(slices.Clone(assets[1].Endpoints), ep("ssh", asset.SSH, "192.0.2.10", asset.Direct))
	if got := InboundOnly(b, testNode, withDirect); len(got) != 0 {
		t.Errorf("marked %v with a direct endpoint", got)
	}
	// A direct endpoint at another address, a port server's, another
	// node's asset, or no C1 record at all leaves the end marked.
	for name, as := range map[string][]asset.Asset{
		"another address": {assets[0], {AssetID: master, NodeID: testNode, Endpoints: []asset.Endpoint{ep("ssh", asset.SSH, "192.0.2.11", asset.Direct)}}},
		"a port server":   {assets[0], {AssetID: master, NodeID: testNode, Endpoints: []asset.Endpoint{ep("ssh", asset.SSH, "192.0.2.10", asset.PortServer)}}},
		"another node":    {assets[0], {AssetID: master, NodeID: "site-b-node1", Endpoints: []asset.Endpoint{ep("ssh", asset.SSH, "192.0.2.10", asset.Direct)}}},
		"no record":       {assets[0]},
	} {
		if got := InboundOnly(b, testNode, as); len(got) != 1 || !got[master] {
			t.Errorf("%s: marked %v", name, got)
		}
	}
	// The relay's own connected address is what spares it: with that
	// endpoint gone it is marked too.
	if got := InboundOnly(b, testNode, assets[1:]); !got[relay] || !got[master] {
		t.Errorf("no relay endpoint: marked %v", got)
	}
	// The master polled at .11 and sending Syslog from .10, both in b:
	// one connected address must not hide the spoofable one, since b
	// does not say which address a pair was learned at (D5 on #558).
	dual := *b
	dual.Addresses = append(slices.Clone(b.Addresses), netobs.Address{IP: "192.0.2.11", Endpoint: master, VLANs: []int{0}, LANs: []string{}})
	dualAssets := []asset.Asset{assets[0], {AssetID: master, NodeID: testNode, Endpoints: []asset.Endpoint{ep("syslog", asset.SyslogUDP, "192.0.2.10", ""), ep("ssh", asset.SSH, "192.0.2.11", asset.Direct)}}}
	if got := InboundOnly(&dual, testNode, dualAssets); len(got) != 1 || !got[master] {
		t.Errorf("one connected and one inbound address: marked %v, want the master", got)
	}
	// The mirror, with the direct address first in b's IP order: the
	// result does not depend on which address comes first (D6 on #558, R3).
	mirror := []asset.Asset{assets[0], {AssetID: master, NodeID: testNode, Endpoints: []asset.Endpoint{ep("ssh", asset.SSH, "192.0.2.10", asset.Direct), ep("syslog", asset.SyslogUDP, "192.0.2.11", "")}}}
	if got := InboundOnly(&dual, testNode, mirror); len(got) != 1 || !got[master] {
		t.Errorf("mirror, direct address first: marked %v, want the master", got)
	}
	// With both addresses polled directly, nothing is marked.
	dualAssets[1].Endpoints = append(slices.Clone(dualAssets[1].Endpoints), ep("ssh2", asset.SSH, "192.0.2.10", asset.Direct))
	if got := InboundOnly(&dual, testNode, dualAssets); len(got) != 0 {
		t.Errorf("both addresses direct: marked %v", got)
	}
	// A session open before capture began leaves a function, or a
	// service, with no entry in pairs: its inbound-only end is marked
	// too (D4 on #558, N1).
	const (
		writer = "3a9d6b42-1e7f-4c08-a5d3-6f2b8e0c4d91"
		server = "4e2c8a16-9b3d-4f5a-8c71-0d6e2f4a9b37"
		outstn = "5d1b7f38-2c6e-4a90-b4e7-8f3a1c5d0e62"
		rtu    = "6f4a2d90-7e1b-4c35-9a08-1b5c3e7d2f84"
		poller = "8b3e5c71-4d2a-4f96-b0c8-2e7a9d1f6c53"
	)
	mid := *b
	mid.Functions = append(slices.Clone(b.Functions),
		netobs.BaselineFunction{Pair: netobs.Pair{Client: writer, Server: relay, L4: "tcp", Port: 20000, Protocol: "dnp3"}, Code: 2},
		netobs.BaselineFunction{Pair: netobs.Pair{Client: relay, Server: outstn, L4: "tcp", Port: 20000, Protocol: "dnp3"}, Code: 1})
	mid.Services = append(slices.Clone(b.Services), netobs.BaselineService{Server: server, L4: "tcp", Port: 502, Protocol: "modbus", Basis: "content"})
	// A pair with no decoded function, such as an undecoded protocol's
	// flow, is marked through pairs alone, at both ends (D6's R1 and D4
	// on #558).
	mid.Pairs = append(slices.Clone(b.Pairs), netobs.Pair{Client: poller, Server: rtu, L4: "tcp", Port: 2404, Protocol: "unknown"})
	if got := InboundOnly(&mid, testNode, assets); len(got) != 6 || !got[master] || !got[writer] || !got[outstn] || !got[server] || !got[rtu] || !got[poller] {
		t.Errorf("midstream functions, service and undecoded pair: marked %v, want the master, the writer, the outstation, the server, the RTU and the poller", got)
	}
}

// TestDraftFill: the view shows the draft's period.overflow and its size
// against the bound, and the accepted document built from that draft
// carries the same overflow (D4-71).
func TestDraftFill(t *testing.T) {
	for _, overflow := range []int64{0, 7, netobs.MaxOverflow} {
		b, err := netobs.DecodeBaseline(testDraft(t))
		if err != nil {
			t.Fatal(err)
		}
		b.Period.Overflow = overflow
		draft, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		shown, err := DraftFill(draft)
		if err != nil {
			t.Fatalf("overflow %d: %v", overflow, err)
		}
		if want := (Fill{Overflow: overflow, Bytes: len(draft), MaxBytes: netobs.MaxBaselineBytes}); shown != want {
			t.Fatalf("overflow %d: shown %+v, want %+v", overflow, shown, want)
		}
		doc, _, _, err := BuildAccepted(draft, testWriters)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := netobs.DecodeBaseline(doc)
		if err != nil {
			t.Fatal(err)
		}
		if accepted.Period.Overflow != shown.Overflow {
			t.Errorf("accepted overflow %d, shown %d", accepted.Period.Overflow, shown.Overflow)
		}
	}
	if _, err := DraftFill([]byte(`{"schema":`)); err == nil {
		t.Error("DraftFill accepted a truncated draft")
	}
}

package netobs

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func fxBaseline() *Baseline {
	pair := Pair{Client: fxMaster, Server: fxAsset, L4: "tcp", Port: 20000, Protocol: "dnp3"}
	b := &Baseline{
		Schema: BaselineIdentifier, SensorID: fxSensor, Version: 1, FunctionTable: FunctionTable,
		Period: Period{StartUTC: "2026-11-01T00:00:00Z", EndUTC: "2026-11-08T00:00:00Z",
			Observations: Counts{Flow: 40, Function: 12, Insecure: 3}, Degraded: 2, PlatformSession: 5},
		Params: BaselineParams{TieGraceS: DefaultTieGraceS, CoalesceWindowS: DefaultCoalesceWindowS},
		Pairs:  []Pair{pair, {Client: "addr:192.0.2.99", Server: fxAsset, L4: "tcp", Port: 502, Protocol: "modbus"}},
		Services: []BaselineService{
			{Server: fxAsset, L4: "tcp", Port: 20000, Protocol: "dnp3", Basis: "content"},
			{Server: fxAsset, L4: "tcp", Port: 23, Protocol: "telnet", Basis: "port"},
		},
		Functions: []BaselineFunction{
			{Pair: pair, Code: 1, Objects: []string{"g60v1", "g60v2"}},
			{Pair: pair, Code: 2, Objects: []string{"g50v1"}},
			{Pair: Pair{Client: "addr:192.0.2.99", Server: fxAsset, L4: "tcp", Port: 502, Protocol: "modbus"}, Code: 8, Sub: ptr(0)},
		},
		Addresses: []Address{
			{IP: "192.0.2.10", Endpoint: fxMaster, VLANs: []int{10}},
			{IP: "192.0.2.20", Endpoint: fxAsset, VLANs: []int{0, 10}, LANs: []string{"a", "b"}},
			{IP: "192.0.2.99", Endpoint: "addr:192.0.2.99", VLANs: []int{10}},
		},
	}
	SortBaseline(b)
	return b
}

func TestBaselineCanonical(t *testing.T) {
	b := fxBaseline()
	out, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !IsCanonical(out) {
		t.Fatalf("Encode's bytes are not canonical: %s", out)
	}
	if !bytes.HasPrefix(out, []byte(`{"schema":"`+BaselineIdentifier+`"`)) {
		t.Error("schema is not the first field")
	}
	if !bytes.Contains(out, []byte(`"authorized_writers":[]`)) || bytes.Contains(out, []byte("null")) {
		t.Errorf("an empty list is [] and never null: %s", out)
	}
	got, err := DecodeBaseline(out)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := got.Encode()
	if !bytes.Equal(again, out) {
		t.Error("decode and encode changed the bytes")
	}
	// Other whitespace, another key order or an unsorted list is not
	// canonical, though each decodes to the same document.
	var indented bytes.Buffer
	_ = json.Indent(&indented, out, "", " ")
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	reordered, _ := json.Marshal(m)
	unsorted := strings.Replace(string(out), `"g60v1","g60v2"`, `"g60v2","g60v1"`, 1)
	for name, x := range map[string][]byte{"indented": indented.Bytes(), "reordered": reordered, "unsorted": []byte(unsorted),
		"trailing newline": append(slices.Clone(out), '\n')} {
		if IsCanonical(x) {
			t.Errorf("%s accepted as canonical", name)
		}
	}
	if Digest(out) != "sha256:"+hash(out) {
		t.Error("Digest is not sha256: and the hex of the bytes")
	}
}

// TestAcceptedDiffersOnlyInWriters: the node's adoption check (baseline
// note §2.3) is the accepted document with its writers emptied, encoded
// again, byte for byte the draft.
func TestAcceptedDiffersOnlyInWriters(t *testing.T) {
	draft, _ := fxBaseline().Encode()
	acc := fxBaseline()
	acc.AuthorizedWriters = []Writer{{Client: fxMaster, Server: fxAsset, Class: ClassControl}}
	accepted, err := acc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeBaseline(accepted)
	if err != nil {
		t.Fatal(err)
	}
	back.AuthorizedWriters = nil
	if again, _ := back.Encode(); !bytes.Equal(again, draft) {
		t.Error("emptying the writers does not give the draft")
	}
	if Digest(accepted) == Digest(draft) {
		t.Error("a writer did not change the digest")
	}
	if !OnlyWritersAdded(draft, accepted) || !OnlyWritersAdded(draft, draft) {
		t.Error("OnlyWritersAdded refuses the draft with writers added, or the draft itself")
	}
	other := fxBaseline()
	other.AuthorizedWriters = acc.AuthorizedWriters
	other.Params.TieGraceS++
	changed, _ := other.Encode()
	reminor := bytes.Replace(accepted, []byte(BaselineIdentifier), []byte("otsec.netbaseline/0.2"), 1)
	for name, b := range map[string][]byte{
		"another change":    changed,
		"another minor":     reminor,
		"not canonical":     append([]byte(" "), accepted...),
		"draft not decoded": nil,
	} {
		if OnlyWritersAdded(draft, b) {
			t.Errorf("%s: accepted", name)
		}
	}
	if !IsCanonical(reminor) {
		t.Error("IsCanonical pins the minor; its comment says it doesn't")
	}
}

func TestBaselineRules(t *testing.T) {
	cases := []struct {
		name string
		code Code
		mut  func(b *Baseline)
	}{
		{"schema", CodeSchema, func(b *Baseline) { b.Schema = Identifier }},
		{"version 0", CodeRange, func(b *Baseline) { b.Version = 0 }},
		{"table", CodeForm, func(b *Baseline) { b.FunctionTable = "fc classes" }},
		{"period backwards", CodeOrder, func(b *Baseline) { b.Period.EndUTC = "2026-10-01T00:00:00Z" }},
		{"tie grace 0", CodeRange, func(b *Baseline) { b.Params.TieGraceS = 0 }},
		{"window 59", CodeRange, func(b *Baseline) { b.Params.CoalesceWindowS = 59 }},
		{"pairs out of order", CodeOrder, func(b *Baseline) { b.Pairs[0], b.Pairs[1] = b.Pairs[1], b.Pairs[0] }},
		{"pair repeated", CodeOrder, func(b *Baseline) { b.Pairs = append(b.Pairs, b.Pairs[len(b.Pairs)-1]) }},
		{"endpoint", CodeForm, func(b *Baseline) { b.Pairs[0].Client = "relay-1" }},
		{"endpoint mapped", CodeForm, func(b *Baseline) { b.Pairs[0].Client = "addr:::ffff:192.0.2.99" }},
		{"service basis", CodeForm, func(b *Baseline) { b.Services[0].Basis = "guess" }},
		{"objects unsorted", CodeOrder, func(b *Baseline) { b.Functions[0].Objects = []string{"g60v2", "g60v1"} }},
		{"address endpoint not its own", CodeConflict, func(b *Baseline) { b.Addresses[2].Endpoint = "addr:192.0.2.98" }},
		{"lan", CodeForm, func(b *Baseline) { b.Addresses[1].LANs = []string{"c"} }},
		{"sub on DNP3", CodeConflict, func(b *Baseline) { b.Functions[0].Sub = ptr(1) }},
		{"sub on Modbus 3", CodeConflict, func(b *Baseline) { b.Functions[2].Code = 3 }},
		{"sub-function above 65535", CodeRange, func(b *Baseline) { b.Functions[2].Sub = ptr(65536) }},
		{"MEI type above 255", CodeRange, func(b *Baseline) { b.Functions[2].Code, b.Functions[2].Sub = 43, ptr(256) }},
		{"writer class read", CodeForm, func(b *Baseline) {
			b.AuthorizedWriters = []Writer{{Client: fxMaster, Server: fxAsset, Class: ClassRead}}
		}},
	}
	for _, tc := range cases {
		b := fxBaseline()
		tc.mut(b)
		if got := Codes(b.Validate()); !slices.Contains(got, tc.code) {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.code)
		}
		if _, err := b.Encode(); err == nil {
			t.Errorf("%s: encoded", tc.name)
		}
	}
	for _, sub := range []*int{nil, ptr(255)} {
		b := fxBaseline()
		b.Functions[2].Code, b.Functions[2].Sub = 43, sub
		if err := b.Validate(); err != nil {
			t.Errorf("Modbus 43 sub %v: %v", sub, err)
		}
	}
	big := make([]byte, MaxBaselineBytes+1)
	if _, err := DecodeBaseline(big); !slices.Contains(Codes(err), CodeRange) {
		t.Errorf("over MaxBaselineBytes: %v", err)
	}
	if IsCanonical(big) {
		t.Error("over MaxBaselineBytes is canonical")
	}
}

// TestFoldOrder: SortBaseline makes the bytes independent of the order
// entries were folded in (baseline note §1).
func TestFoldOrder(t *testing.T) {
	want, _ := fxBaseline().Encode()
	b := fxBaseline()
	slices.Reverse(b.Pairs)
	slices.Reverse(b.Functions)
	slices.Reverse(b.Addresses)
	b.Pairs = append(b.Pairs, b.Pairs[0])
	for i := range b.Functions {
		if b.Functions[i].Code == 1 {
			b.Functions[i].Objects = []string{"g60v2", "g60v1", "g60v1"}
		}
	}
	SortBaseline(b)
	got, err := b.Encode()
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("fold order changed the bytes: %v", err)
	}
}

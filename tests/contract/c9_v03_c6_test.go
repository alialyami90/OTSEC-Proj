package contract

// C9 0.3 (D4-25, #345; comments #363): C6's cases on the snapshot bounds.
//
//   - Encode is the form the byte bound is measured on: compact, no HTML
//     escaping, no trailing newline. The bound is exact on that form: a
//     snapshot that encodes to MaxSnapshotBytes validates, and one more
//     byte is refused with ErrTooLarge.
//   - RecordHeadroom covers what a configuration run's transcript holds
//     beyond the bytes it receives: every line the run sends, the
//     credential marker, and the SEL-751 adapter's allowance for the QUI
//     reply (#363).
//   - RecordsFit's precondition (C1's choice (b), 2026-11-01): Adapter.Version
//     and the operation ID have no length bound of their own, so a result
//     with long ones passes RecordsFit; Validate must then refuse its
//     snapshot for size, so the run fails closed at the node and no snapshot
//     over the bound is ever valid.
//
// Ground truth: independent for the properties (C9's own statements of its
// bounds, D4-25 and C1's ruling); the register is the signed SEL-751
// register as it is in the tree, and contracts/config's valid snapshot is
// used as an input only. Evidence class: desk. No device.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/config"
	"otsec.local/otsec/contracts/register"
)

// c9Input is contracts/config's read-1 snapshot, as an input.
func c9Input(t *testing.T) config.Snapshot {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "config", "testdata", "valid", "snapshot-read-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := config.DecodeSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// c9Fill puts n settings of value v in the first present section, and
// returns the snapshot and the records a run would report for it.
func c9Fill(t *testing.T, s config.Snapshot, n int, v string) (config.Snapshot, []adapter.Record) {
	t.Helper()
	const d = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	s.Sections = append([]config.Section{}, s.Sections...)
	var recs []adapter.Record
	done := false
	for i := range s.Sections {
		sec := &s.Sections[i]
		if sec.State == config.Present && !done {
			done = true
			sec.Settings = nil
			for k := 0; k < n; k++ {
				sec.Settings = append(sec.Settings, config.Setting{Name: string([]byte{d[k/1296%36], d[k/36%36], d[k%36]}), Value: v})
			}
		}
		r := adapter.Record{Kind: adapter.RecordConfigSection, ParseOK: true}
		if sec.State == config.Absent {
			r.Kind = adapter.RecordConfigAbsent
		}
		for _, st := range sec.Settings {
			r.Fields = append(r.Fields, adapter.Field{Name: st.Name, Value: st.Value})
		}
		recs = append(recs, r)
	}
	if !done {
		t.Fatal("the input snapshot has no present section")
	}
	return s, recs
}

func c9Encode(t *testing.T, s config.Snapshot) []byte {
	t.Helper()
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Encode is compact UTF-8 JSON with no HTML escaping and no trailing
// newline: "<", ">" and "&" cost one byte each, which is what RecordsFit and
// the byte bound count.
func TestC9EncodeForm(t *testing.T) {
	s, _ := c9Fill(t, c9Input(t), 1, "a<b>&c")
	b := c9Encode(t, s)
	if !bytes.Contains(b, []byte(`"a<b>&c"`)) || bytes.Contains(b, []byte("\\u003c")) || bytes.Contains(b, []byte("\\u0026")) {
		t.Errorf("the value is not written as it is: %s", b)
	}
	if len(b) == 0 || b[len(b)-1] != '}' {
		t.Errorf("the encoding does not end at its closing brace: %q", b[max(0, len(b)-8):])
	}
	if bytes.Contains(b, []byte("\n")) || bytes.Contains(b, []byte(": ")) {
		t.Error("the encoding is not compact")
	}
	// Decoding and encoding again gives the same bytes: one stored form.
	again, err := config.DecodeSnapshot(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c9Encode(t, again), b) {
		t.Error("the encoding does not survive a decode")
	}
}

// The byte bound is exact on Encode's output: MaxSnapshotBytes validates,
// one byte more is refused for size.
func TestC9ByteBoundIsExact(t *testing.T) {
	in := c9Input(t)
	const n = 3000
	lo, hi := 1, 1000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if s, _ := c9Fill(t, in, n, strings.Repeat("V", mid)); len(c9Encode(t, s)) <= config.MaxSnapshotBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	s, _ := c9Fill(t, in, n, strings.Repeat("V", lo))
	short := config.MaxSnapshotBytes - len(c9Encode(t, s))
	if short < 0 || short >= n {
		t.Fatalf("the search left %d bytes", short)
	}
	sec := sectionWithSettings(t, &s)
	last := &sec.Settings[len(sec.Settings)-1]
	last.Value += strings.Repeat("V", short)
	if got := len(c9Encode(t, s)); got != config.MaxSnapshotBytes {
		t.Fatalf("built %d bytes, not %d", got, config.MaxSnapshotBytes)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("a snapshot of exactly MaxSnapshotBytes: %v", err)
	}
	last.Value += "V"
	if err := s.Validate(); !errors.Is(err, config.ErrTooLarge) {
		t.Errorf("a snapshot of MaxSnapshotBytes+1: %v", err)
	}
}

func sectionWithSettings(t *testing.T, s *config.Snapshot) *config.Section {
	t.Helper()
	for i := range s.Sections {
		if len(s.Sections[i].Settings) > 0 {
			return &s.Sections[i]
		}
	}
	t.Fatal("no section holds settings")
	return nil
}

// qui allowance: the SEL-751 adapter keeps up to 4,096 bytes of the QUI
// reply past the run's max_total_bytes (closeAllowance in
// modules/ied/sel751/run.go, #363). It is unexported, so it is restated here;
// a larger allowance must come back to this test.
const sel751CloseAllowance = 4096

// RecordHeadroom covers the transcript beyond the received bytes: each line
// the run sends with its CRLF, ACC, the credential marker, QUI, the probe's
// CRLF, and the QUI allowance. The redaction of a secret echo can also grow
// a reply, by 10 bytes less the secret's length per whole echo, which this
// does not count; a record past the cap is refused by the store.
func TestC9HeadroomCoversTheSentBytes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	run := p.Run("sel.config.read_all")
	if run == nil {
		t.Fatal("the register has no run sel.config.read_all")
	}
	if run.MaxTotalBytes != config.MaxTranscriptBytes {
		t.Fatalf("the run receives up to %d bytes, MaxTranscriptBytes is %d", run.MaxTotalBytes, config.MaxTranscriptBytes)
	}
	lines := map[string]string{}
	for _, op := range p.Operations {
		lines[op.ID] = op.Line
	}
	sent := len("\r\n") + len("ACC\r\n") + len(adapter.RedactionMarker+"\r\n") + len("QUI\r\n")
	for _, id := range run.Steps {
		l, ok := lines[id]
		if !ok || strings.Contains(l, "{") {
			t.Fatalf("step %s: no literal line (%q)", id, l)
		}
		sent += len(l) + len("\r\n")
	}
	if beyond := sent + sel751CloseAllowance; beyond > config.RecordHeadroom {
		t.Errorf("the transcript can hold %d bytes beyond MaxTranscriptBytes (%d sent, %d allowance), over RecordHeadroom %d",
			beyond, sent, sel751CloseAllowance, config.RecordHeadroom)
	}
}

// C1's choice (b): a result whose adapter version is long passes
// RecordsFit, which allows SnapshotFixedMax for everything but the settings,
// and its snapshot is refused by Validate for size. So the gap fails closed:
// no snapshot over MaxSnapshotBytes validates, whatever passed RecordsFit.
func TestC9LongHeaderFailsClosed(t *testing.T) {
	in := c9Input(t)
	in.Adapter.Version = strings.Repeat("9", 20<<10)
	if err := in.Validate(); err != nil {
		t.Fatalf("a 20 KiB adapter version alone: %v (C9 0.3 sets no bound on it; if one is added, this case changes)", err)
	}
	const n = 3000
	lo, hi := 1, 1000
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if _, recs := c9Fill(t, in, n, strings.Repeat("V", mid)); config.RecordsFit(recs) == nil {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	s, recs := c9Fill(t, in, n, strings.Repeat("V", lo))
	if err := config.RecordsFit(recs); err != nil {
		t.Fatalf("the largest read RecordsFit passes: %v", err)
	}
	enc := c9Encode(t, s)
	if len(enc) <= config.MaxSnapshotBytes {
		t.Fatalf("the snapshot is %d bytes, within the bound: the case does not reach the gap", len(enc))
	}
	if err := s.Validate(); !errors.Is(err, config.ErrTooLarge) {
		t.Errorf("a %d-byte snapshot that RecordsFit passed: Validate %v, want ErrTooLarge", len(enc), err)
	}
	// The same through decoding, which is how the node reads a document.
	if _, err := config.DecodeSnapshot(enc); !errors.Is(err, config.ErrTooLarge) {
		t.Errorf("DecodeSnapshot of the %d-byte snapshot: %v, want ErrTooLarge", len(enc), err)
	}
}

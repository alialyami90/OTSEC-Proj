package contract

import (
	"encoding/json"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

// D1-25: sel.ser.row field names are the headings Figure 10.16 prints
// (gtSERColumns, checked against A6's transcription in groundtruth_test.go).
// Each single change to the chain result's names is refused for the names.
// GT-HAND, same-source (manual).
func TestD125SERFieldNames(t *testing.T) {
	got := adapter.RecordFields["sel.ser.row"]
	if strings.Join(got, "|") != strings.Join(gtSERColumns, "|") {
		t.Fatalf("RecordFields %q, Figure 10.16 heading %q", got, gtSERColumns)
	}
	r := chainSession(t)
	enc, _ := json.Marshal(r.res)
	if _, err := adapter.DecodeResult(enc); err != nil {
		t.Fatalf("control: %v", err)
	}
	muts := map[string]func(fs []adapter.Field){
		"lower date":      func(fs []adapter.Field) { fs[1].Name = "date" },
		"Date":            func(fs []adapter.Field) { fs[1].Name = "Date" },
		"old row":         func(fs []adapter.Field) { fs[0].Name = "row" },
		"No.":             func(fs []adapter.Field) { fs[0].Name = "No." },
		"# with space":    func(fs []adapter.Field) { fs[0].Name = "# " },
		"fullwidth #":     func(fs []adapter.Field) { fs[0].Name = "＃" },
		"swap DATE TIME":  func(fs []adapter.Field) { fs[1].Name, fs[2].Name = fs[2].Name, fs[1].Name },
		"STATE lowercase": func(fs []adapter.Field) { fs[4].Name = "state" },
	}
	for name, m := range muts {
		res := r.res
		res.Records = append([]adapter.Record(nil), r.res.Records...)
		fs := append([]adapter.Field(nil), res.Records[3].Fields...)
		m(fs)
		res.Records[3].Fields = fs
		enc, _ := json.Marshal(res)
		if _, err := adapter.DecodeResult(enc); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "carries the fields") {
			t.Errorf("%s: refused for another reason: %v", name, err)
		}
	}
	for name, n := range map[string]int{"missing STATE": 4, "extra field": 6} {
		res := r.res
		res.Records = append([]adapter.Record(nil), r.res.Records...)
		fs := append([]adapter.Field(nil), res.Records[3].Fields...)
		if n < len(fs) {
			fs = fs[:n]
		} else {
			fs = append(fs, adapter.Field{Name: "EXTRA", Value: "x"})
		}
		res.Records[3].Fields = fs
		enc, _ := json.Marshal(res)
		if _, err := adapter.DecodeResult(enc); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), "carries the fields") {
			t.Errorf("%s: refused for another reason: %v", name, err)
		}
	}
}

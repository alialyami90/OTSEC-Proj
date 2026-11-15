//go:build a6_c2_old_reader

// Package c2oldreader is C2 0.10's test 6 (i), the old reader itself
// (docs/phase4/D2-c2-0.10-proposal.md section 8; D1's 6862737844 on #671;
// D4-102 item 5 (b); brief P4-4-CC). Only the a6-c2-old-reader job builds
// it. The job copies this file into a worktree of the last 0.9 code on main
// and runs it there, with OTSEC_C2_010_GOLDENS set to the 0.10 head's
// contracts/adapter/testdata. So the adapter package below is 0.9's, and
// the goldens are 0.10's. The build tag keeps the file out of the head's own
// build, where adapter is 0.10. Ground truth: GT-HAND. Evidence class: desk.
package c2oldreader

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

type golden struct {
	rel    string
	b      []byte
	telnet bool
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// goldens010 is every result golden at 0.10 under a results/valid
// directory, at any depth, of the head's testdata.
func goldens010(t *testing.T) []golden {
	t.Helper()
	dir := os.Getenv("OTSEC_C2_010_GOLDENS")
	if dir == "" {
		t.Fatal("OTSEC_C2_010_GOLDENS is not set: the job sets it to the head's contracts/adapter/testdata")
	}
	var out []golden
	telnet := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if !strings.Contains("/"+rel, "/results/valid/") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		m := decode(t, b)
		if m["schema"] != "otsec.adapter/0.10" {
			return nil
		}
		_, has := m["session"].(map[string]any)["telnet"]
		if has {
			telnet++
		}
		out = append(out, golden{rel: rel, b: b, telnet: has})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// At 0f10fa02: five SEL Telnet goldens and one SNMPv3.
	if len(out) < 6 || telnet < 5 {
		t.Fatalf("%d 0.10 goldens in %s, %d with session.telnet; want at least 6 and 5", len(out), dir, telnet)
	}
	return out
}

func edit(t *testing.T, b []byte, f func(m map[string]any)) []byte {
	t.Helper()
	m := decode(t, b)
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// view is what the reader made of a result.
func view(t *testing.T, r adapter.Result) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The reader under test is the 0.9 code, so a run against any other tree
// fails here.
func TestOldReaderIs09(t *testing.T) {
	if adapter.Contract != "otsec.adapter/0.9" {
		t.Fatalf("the reader is %s, want otsec.adapter/0.9", adapter.Contract)
	}
}

// Each 0.10 golden decodes under the 0.9 code, which ignores
// session.telnet: the result reads the same without it, and with one that
// breaks every 0.10 rule.
func TestOldReaderReads010Goldens(t *testing.T) {
	for _, g := range goldens010(t) {
		r, err := adapter.DecodeResult(g.b)
		if err != nil {
			t.Errorf("%s: %v", g.rel, err)
			continue
		}
		if !g.telnet {
			continue
		}
		without := edit(t, g.b, func(m map[string]any) { delete(m["session"].(map[string]any), "telnet") })
		r0, err := adapter.DecodeResult(without)
		if err != nil {
			t.Errorf("%s without session.telnet: %v", g.rel, err)
			continue
		}
		if view(t, r) != view(t, r0) {
			t.Errorf("%s: the 0.9 reader reads something from session.telnet", g.rel)
		}
		broken := edit(t, g.b, func(m map[string]any) {
			m["session"].(map[string]any)["telnet"] = map[string]any{
				"refusals":       json.Number("-1"),
				"read_to_eof":    "no",
				"rexmit_unknown": "NOT A TOKEN",
				"rexmit_octets":  json.Number("0.5"),
				"added_in_0_11":  true,
			}
		})
		rx, err := adapter.DecodeResult(broken)
		if err != nil {
			t.Errorf("%s with a session.telnet that breaks every 0.10 rule: %v, want it ignored", g.rel, err)
			continue
		}
		if view(t, rx) != view(t, r0) {
			t.Errorf("%s: the 0.9 reader reads something from a broken session.telnet", g.rel)
		}
	}
}

// tenDigits is the same instant with ten fractional digits.
func tenDigits(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok || !strings.HasSuffix(s, "Z") {
		t.Fatalf("started_at %v is not a UTC time", v)
	}
	whole, frac, _ := strings.Cut(strings.TrimSuffix(s, "Z"), ".")
	return whole + "." + frac + strings.Repeat("0", 10-len(frac)) + "Z"
}

// The control: a 0.10 golden that breaks a 0.9 rule is refused. The rule is
// D4-61's, from 0.9: every result's times, of any minor, have at most nine
// fractional digits.
func TestOldReaderRefusesBroken010Golden(t *testing.T) {
	for _, g := range goldens010(t) {
		b := edit(t, g.b, func(m map[string]any) { m["started_at"] = tenDigits(t, m["started_at"]) })
		if _, err := adapter.DecodeResult(b); err == nil || !strings.Contains(err.Error(), "nine fractional digits") {
			t.Errorf("%s with ten fractional digits in started_at: %v, want refused", g.rel, err)
		}
	}
}

package netobs

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestTextRoundTrip(t *testing.T) {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	for _, in := range [][]byte{nil, []byte("SEL-751 R100"), all, bytes.Repeat([]byte{'\\'}, 300), bytes.Repeat([]byte{0x1b}, 256)} {
		tx := NewText(in)
		c := &checker{}
		tx.check(c, "t")
		if err := c.err(); err != nil {
			t.Errorf("%q: %v", in, err)
		}
		got, err := tx.Bytes()
		want := in[:min(len(in), MaxTextBytes)]
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
		if len(tx.Value) > MaxTextEscaped {
			t.Errorf("escaped value %d bytes", len(tx.Value))
		}
		if strings.ContainsAny(tx.Value, "\n\r\x1b\x00") {
			t.Errorf("control byte in %q", tx.Value)
		}
	}
	if tx := NewText(bytes.Repeat([]byte("a"), 300)); !tx.Truncated || tx.Length != 300 || len(tx.Value) != MaxTextBytes {
		t.Errorf("truncation: %+v", tx)
	}
}

// TestTextRefused: only the one canonical form is accepted (C13 §3.1).
func TestTextRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		tx   Text
		code Code
	}{
		"upper-case hex":          {Text{Value: `\x1B`, Length: 1}, CodeForm},
		"printable byte escaped":  {Text{Value: `\x41`, Length: 1}, CodeForm},
		"lone backslash":          {Text{Value: `a\`, Length: 2}, CodeForm},
		"other escape":            {Text{Value: `\n`, Length: 1}, CodeForm},
		"raw newline":             {Text{Value: "a\nb", Length: 3}, CodeForm},
		"raw non-ASCII":           {Text{Value: "é", Length: 2}, CodeForm},
		"length mismatch":         {Text{Value: "abc", Length: 4}, CodeConflict},
		"truncated when it isn't": {Text{Value: "abc", Length: 3, Truncated: true}, CodeConflict},
		"negative length":         {Text{Value: "", Length: -1}, CodeRange},
	} {
		c := &checker{}
		tc.tx.check(c, "t")
		if !slices.Contains(Codes(c.err()), tc.code) {
			t.Errorf("%s: %v, want %s", name, c.err(), tc.code)
		}
	}
}

func TestValidToken(t *testing.T) {
	for _, ok := range []string{"dnp3", "c37.118", "TLSv1.3", "eth0", "a:b+c-d_e"[:7], strings.Repeat("a", 64)} {
		if !ValidToken(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "-x", "a b", "a/b", "a\x1b", strings.Repeat("a", 65), "é"} {
		if ValidToken(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

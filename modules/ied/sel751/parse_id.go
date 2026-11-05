package sel751

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"otsec.local/otsec/contracts/adapter"
)

// idField is one line of the ID response: "KEY=value","XXXX" (S22 Figure
// 7.38, p. 7.64). The checksum is the four-digit hex of the byte sum of
// "KEY=value", (quotes and comma included); it holds on every line of
// Figure 7.38 and fails on six lines of Figure 3.20, which a parser must
// report rather than accept (tests/fixtures/ied/sel/751/documented-example).
type idField struct {
	key, value string
	span       adapter.Span // the value, in the transcript
	checksumOK bool
}

type idReport struct {
	fields []idField
	other  []line // non-blank lines that are not ID fields
}

var idLine = regexp.MustCompile(`^"([^"=]+)=([^"]*)","([0-9A-F]{4})"$`)

var errDuplicateKey = errors.New("sel751: a key appears twice")

// parseID reads every field of an ID message. A key printed twice is an
// error: which value the relay meant cannot be known.
func parseID(m message) (idReport, error) {
	var r idReport
	seen := map[string]bool{}
	for _, l := range m.lines() {
		t := l.trimmed()
		if len(t) == 0 {
			continue
		}
		g := idLine.FindSubmatchIndex(t)
		if g == nil {
			r.other = append(r.other, l)
			continue
		}
		key := string(t[g[2]:g[3]])
		if seen[key] {
			return idReport{}, fmt.Errorf("%w: ID %q", errDuplicateKey, key)
		}
		seen[key] = true
		want, _ := strconv.ParseUint(string(t[g[6]:g[7]]), 16, 16)
		var sum uint64
		for _, c := range t[:g[5]+2] { // "KEY=value",
			sum += uint64(c)
		}
		r.fields = append(r.fields, idField{
			key: key, value: string(t[g[4]:g[5]]), span: l.span(g[4], g[5]),
			checksumOK: sum&0xFFFF == want,
		})
	}
	return r, nil
}

func (r idReport) field(key string) (idField, bool) {
	for _, f := range r.fields {
		if f.key == key {
			return f, true
		}
	}
	return idField{}, false
}

// fidGrammar is the SEL-751 FID as S22 Appendix A prints it, for example
// SEL-751-R501-V0-Z104101-D20260910: the product, the R (or X) and V parts,
// the Z part and the date code.
var fidGrammar = regexp.MustCompile(`^(SEL-[0-9A-Z]+)-([RX][0-9]{3}-V[0-9]+)-Z[0-9]{6}-D[0-9]{8}$`)

// fidParts cuts the model (the product part, "SEL-751") and the firmware
// version (the R or X and V parts, "R501-V0") out of a FID, each as a
// sub-span of the FID's own bytes, so each is its own device read (C1 0.3
// §1.1 and §1.5). Values are kept as printed and nothing is mapped. A FID
// outside the grammar gives neither: it is never guessed.
func fidParts(f *found) (model, version *found) {
	if f == nil {
		return nil, nil
	}
	g := fidGrammar.FindStringSubmatchIndex(f.value)
	if g == nil {
		return nil, nil
	}
	cut := func(a, b int) *found {
		return &found{f.value[a:b], adapter.Span{Offset: f.span.Offset + int64(a), Length: int64(b - a)}}
	}
	return cut(g[2], g[3]), cut(g[4], g[5])
}

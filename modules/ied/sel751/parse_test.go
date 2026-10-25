package sel751

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/adapter"
)

// golden decodes a C2 example result (contracts/adapter/testdata). These are
// A2's own C2 goldens; A6's oracle under tests/ is never read.
func golden(t testing.TB, name string) adapter.Result {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "adapter", "testdata", "results", "valid", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := adapter.DecodeResult(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// reply returns the received segment that follows the send of cmd, and its
// offset in the transcript.
func reply(t *testing.T, r adapter.Result, cmd string) ([]byte, int64) {
	t.Helper()
	tr := r.Transcript
	for i, s := range tr.Segments {
		if s.Dir == adapter.Sent && string(tr.Data[s.Offset:s.Offset+s.Length]) == cmd && i+1 < len(tr.Segments) {
			n := tr.Segments[i+1]
			return tr.Data[n.Offset : n.Offset+n.Length], n.Offset
		}
	}
	t.Fatalf("no reply to %q", cmd)
	return nil, 0
}

// fixture reads a documented example and gives it CR LF line ends; the
// manual does not show the relay's line ends (SOURCE.md).
func fixture(t *testing.T, name string) message {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "ied", "sel", "751", "documented-example", name))
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
	return message{text: b}
}

func at(data []byte, s adapter.Span) string { return string(data[s.Offset : s.Offset+s.Length]) }

func TestFrame(t *testing.T) {
	m, err := frame([]byte("ID\r\n\x02abc\r\n\x03="), 100)
	if err != nil || string(m.text) != "abc\r\n" || m.off != 105 {
		t.Fatalf("got %q at %d, %v", m.text, m.off, err)
	}
	for name, rx := range map[string]string{
		"no STX":       "ID\r\nabc\x03=",
		"no ETX":       "ID\r\n\x02abc=",
		"two messages": "\x02a\x03\x02b\x03=",
		"STX inside":   "\x02a\x02b\x03=",
		"prompt only":  "\r\n=",
	} {
		if _, err := frame([]byte(rx), 0); err == nil {
			t.Errorf("%s: framed", name)
		}
	}
}

func TestLines(t *testing.T) {
	m := message{text: []byte("a\r\nb\rc\nd"), off: 10}
	var got []string
	var offs []int64
	for _, l := range m.lines() {
		got = append(got, string(l.b))
		offs = append(offs, l.off)
	}
	if want := []string{"a", "b", "c", "d"}; len(got) != 4 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] || got[3] != want[3] {
		t.Errorf("lines %q", got)
	}
	if offs[0] != 10 || offs[1] != 13 || offs[2] != 15 || offs[3] != 17 {
		t.Errorf("offsets %v", offs)
	}
}

// The parsers reproduce every span and value the ok golden records.
func TestParsersReproduceTheGolden(t *testing.T) {
	r := golden(t, "ok")
	data := r.Transcript.Data
	obs := map[string]adapter.Observation{}
	for _, o := range r.Observations {
		obs[o.Name] = o
	}

	rx, off := reply(t, r, "ID\r\n")
	m, err := frame(rx, off)
	if err != nil {
		t.Fatal(err)
	}
	id, err := parseID(m)
	if err != nil {
		t.Fatal(err)
	}
	for key, name := range map[string]string{"FID": "firmware_id", "CID": "sel.cid"} {
		f, ok := id.field(key)
		if !ok || f.value != obs[name].Value || f.span != obs[name].Span || at(data, f.span) != f.value {
			t.Errorf("ID %s: %+v, golden %+v", key, f, obs[name])
		}
	}
	if len(id.other) != 0 {
		t.Errorf("unparsed ID lines: %d", len(id.other))
	}

	rx, off = reply(t, r, "SHO P 1\r\n")
	if m, err = frame(rx, off); err != nil {
		t.Fatal(err)
	}
	set, err := parseSettings(m)
	if err != nil {
		t.Fatal(err)
	}
	w := r.Warnings[0]
	if s := set[w.Setting]; s.value != w.Observed || s.span != w.Span {
		t.Errorf("%s: %+v, golden %+v", w.Setting, s, w)
	}
	if set["LANG"].value != "ENGLISH" || len(set) != 7 {
		t.Errorf("settings %+v", set)
	}

	rx, off = reply(t, r, "SER\r\n")
	if m, err = frame(rx, off); err != nil {
		t.Fatal(err)
	}
	ser, err := parseSER(m)
	if err != nil {
		t.Fatal(err)
	}
	if ser.serial == nil || ser.serial.value != obs["serial_number"].Value || ser.serial.span != obs["serial_number"].Span {
		t.Errorf("serial %+v, golden %+v", ser.serial, obs["serial_number"])
	}
	if len(ser.rows) != len(r.Records) {
		t.Fatalf("%d rows, golden %d", len(ser.rows), len(r.Records))
	}
	for i, rec := range r.Records {
		row := ser.rows[i]
		if row.span != rec.Span || row.ok != rec.ParseOK || ser.context != *rec.ContextSpan {
			t.Errorf("row %d: %+v context %+v, golden %+v", i, row, ser.context, rec)
		}
		for j, f := range rec.Fields {
			if row.fields[j] != f.Value {
				t.Errorf("row %d field %s: %q, golden %q", i, f.Name, row.fields[j], f.Value)
			}
		}
	}
}

func TestParseSERUnparsedRowKept(t *testing.T) {
	r := golden(t, "partial.parse_errors")
	rx, off := reply(t, r, "SER\r\n")
	m, _ := frame(rx, off)
	ser, err := parseSER(m)
	if err != nil {
		t.Fatal(err)
	}
	for i, rec := range r.Records {
		if ser.rows[i].ok != rec.ParseOK || ser.rows[i].span != rec.Span {
			t.Errorf("row %d: %+v, golden %+v", i, ser.rows[i], rec)
		}
	}
}

// Figure 7.38's checksums all hold; Figure 3.20 has six that do not, and
// the parser reports each one rather than accepting it.
func TestParseIDChecksums(t *testing.T) {
	for name, wantBad := range map[string][]string{
		"id-response-fig7-38.txt": nil,
		"id-response-fig3-20.txt": {"FID", "DEVID", "DEVCODE", "PARTNO", "type ", "configVersion "},
	} {
		id, err := parseID(fixture(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var bad []string
		for _, f := range id.fields {
			if !f.checksumOK {
				bad = append(bad, f.key)
			}
		}
		if len(bad) != len(wantBad) {
			t.Errorf("%s: bad checksums %q, want %q", name, bad, wantBad)
			continue
		}
		for i := range bad {
			if bad[i] != wantBad[i] {
				t.Errorf("%s: bad checksums %q, want %q", name, bad, wantBad)
			}
		}
	}
	id, _ := parseID(fixture(t, "id-response-fig7-38.txt"))
	if f, _ := id.field("FID"); f.value != "SEL-751-R301-V2-Z009005-D20220607" {
		t.Errorf("FID %q", f.value)
	}
	// The command echo and the prompt lines are not fields.
	if len(id.fields) != 10 || len(id.other) != 1 {
		t.Errorf("%d fields, %d other lines", len(id.fields), len(id.other))
	}
}

func TestParseIDDuplicateKey(t *testing.T) {
	m := message{text: []byte("\"FID=A\",\"0000\"\r\n\"FID=B\",\"0000\"\r\n")}
	if _, err := parseID(m); !errors.Is(err, errDuplicateKey) {
		t.Errorf("error %v", err)
	}
}

func TestParseSERFigure(t *testing.T) {
	ser, err := parseSER(fixture(t, "ser-report-fig10-16.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ser.rows) != 9 { // eight rows and the "=>" prompt line, which is not a row
		t.Fatalf("%d rows", len(ser.rows))
	}
	ok := 0
	for _, r := range ser.rows {
		if r.ok {
			ok++
		}
	}
	if ok != 8 || ser.rows[7].fields[3] != "TRIP" || ser.rows[7].fields[4] != "Deasserted" || ser.rows[0].fields[0] != "8" {
		t.Errorf("rows %+v", ser.rows)
	}
	if ser.serial.value != "2007XXXXXXXXXXX" || ser.fid.value != "SEL-751-R100-V0-Z001001-D20070410" || ser.cid.value != "5052" {
		t.Errorf("header %+v %+v %+v", ser.serial, ser.fid, ser.cid)
	}
}

func TestParseSERRefusals(t *testing.T) {
	head := "#    DATE       TIME           ELEMENT           STATE\r\n"
	for name, text := range map[string]string{
		"no headings":    "Serial No = A\r\n1    10/24/2026 09:10:01.251   IN101   Asserted\r\n",
		"headings twice": head + head,
		"two serials":    "Serial No = A\r\nSerial No = B\r\n" + head,
	} {
		if _, err := parseSER(message{text: []byte(text)}); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	ser, err := parseSER(message{text: []byte(head + "1  2026/10/24  09:10:01.251  IN101  Asserted\r\n" +
		"2  10/24/2026  09:10:01.25  IN101  Asserted\r\n3  10/24/2026  09:10:01.251  Relay newly powered up\r\n")})
	if err != nil {
		t.Fatal(err)
	}
	if !ser.rows[0].ok || ser.rows[1].ok || ser.rows[2].ok {
		t.Errorf("rows %+v", ser.rows)
	}
}

func TestParseSettings(t *testing.T) {
	set, err := parseSettings(message{text: []byte("Port 1\r\nLANG    := ENGLISH  MAXACC  := 1\r\nRID     := FEEDER 1\r\n")})
	if err != nil {
		t.Fatal(err)
	}
	if set["LANG"].value != "ENGLISH" || set["MAXACC"].value != "1" || set["RID"].value != "FEEDER 1" {
		t.Errorf("%+v", set)
	}
	for name, text := range map[string]string{
		"no value":      "MAXACC  :=\r\n",
		"no name":       ":= 1\r\n",
		"lower-case":    "lang := ENGLISH\r\n",
		"twice":         "LANG := ENGLISH\r\nLANG := SPANISH\r\n",
		"twice on line": "LANG := ENGLISH  LANG := SPANISH\r\n",
		"value with :=": "LANG := EN:=GLISH\r\n",
		"glued pairs":   "LANG := ENGLISH MAXACC := 1\r\n",
		// A6 on #85: text before or after the pairs is not a setting.
		"trailing words":    "LANG := ENGLISH  trailing words\r\n",
		"lower-case prefix": "xLANG := ENGLISH\r\n",
		"hyphenated name":   "EN-LANG := ENGLISH\r\n",
		"digit prefix":      "1LANG := ENGLISH\r\n",
		"value split":       "TID := FEEDER  1\r\n",
	} {
		if _, err := parseSettings(message{text: []byte(text)}); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// Package contract holds A6's independent contract tests and the Phase 1
// chain test (P1-A6). See README.md.
//
// This file is the ground truth the chain test checks against. It is GT-HAND
// (docs/verification.md): written by A6 from A6's own transcription of the
// SEL-751 Instruction Manual, date code 20260910, without running any project
// code. Its tests check only that the hand-written values agree with the
// transcription files, so a typo in either is caught before a contract is
// judged against them.
//
// Independence (risk 3, P1-A6): the transcription is A6's, made separately
// from A2's, but both come from the same manual. A manual error therefore
// reaches both the contracts and these tests. Nothing here is device output;
// the evidence class is documented-example and supports `simulated` claims only.
package contract

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gtDir is A6's transcription (SOURCE.md there gives figure and page).
var gtDir = filepath.Join("..", "safety", "recording_simulator", "documented", "sel-751")

// gtID is Figure 7.38 "ID Command Response" (manual p. 7.64), field by field,
// in device order. Every line checksum in this figure is consistent (SOURCE.md).
var gtID = []struct{ Field, Value, Checksum string }{
	{"FID", "SEL-751-R301-V2-Z009005-D20220607", "08AF"},
	{"BFID", "SLBT7XX-R601-V0-Z000000-D20211116", "094D"},
	{"CID", "E754", "0262"},
	{"DEVID", "SEL-751", "03C7"},
	{"DEVCODE", "77", "0315"},
	{"PARTNO", "751301ABA1X7085B361", "06AF"},
	{"CONFIG", "111112010", "041B"},
	{"SPECIAL", "00", "030E"},
	{"SEL DISPLAY PACKAGE", "3.0.50751.3012", "0888"},
	{"CUSTOMER DISPLAY PACKAGE", "3.709393047", "099C"},
}

// gtSER is Figure 10.16 "Example SER Event Report" (manual p. 10.40), the
// response to `SER 8`, in the order the device prints it: row 8 first, row 1
// (the newest) last. Times carry milliseconds and no UTC offset; the report
// header says "Time Source: Internal".
var gtSER = []struct{ Row, Date, Time, Element, State string }{
	{"8", "02/28/2007", "13:54:09.602", "51P1P", "Asserted"},
	{"7", "02/28/2007", "13:54:09.602", "51AP", "Asserted"},
	{"6", "02/28/2007", "13:54:10.003", "51P1T", "Asserted"},
	{"5", "02/28/2007", "13:54:10.003", "TRIP", "Asserted"},
	{"4", "02/28/2007", "13:54:10.219", "51P1P", "Deasserted"},
	{"3", "02/28/2007", "13:54:10.219", "51AP", "Deasserted"},
	{"2", "02/28/2007", "13:54:10.236", "51P1T", "Deasserted"},
	{"1", "02/28/2007", "13:54:10.511", "TRIP", "Deasserted"},
}

// gtSERColumns is the column heading Figure 10.16 prints above the rows.
var gtSERColumns = []string{"#", "DATE", "TIME", "ELEMENT", "STATE"}

// gtSERHeader is what the report says about the device that produced it.
var gtSERHeader = struct{ Model, FID, CID, TimeSource string }{
	"SEL-751", "SEL-751-R100-V0-Z001001-D20070410", "5052", "Internal",
}

func readLines(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(gtDir, name))
	if err != nil {
		t.Fatalf("ground truth transcription missing: %v", err)
	}
	// A Windows checkout may turn LF into CRLF; the transcription has no CRs.
	return strings.Split(strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), "\n")
}

// idChecksum is the Compressed ASCII line checksum: the byte sum from the
// first byte of the line through the comma before the checksum (AG95-04).
func idChecksum(line string) string {
	i := strings.LastIndex(line, `,"`)
	var sum int
	for _, c := range []byte(line[:i+1]) {
		sum += int(c)
	}
	return fmt.Sprintf("%04X", sum)
}

func TestGroundTruthID(t *testing.T) {
	lines := readLines(t, "id-fig-7-38.txt")
	if len(lines) != len(gtID) {
		t.Fatalf("transcription has %d lines, ground truth %d", len(lines), len(gtID))
	}
	for i, want := range gtID {
		line := fmt.Sprintf(`"%s=%s","%s"`, want.Field, want.Value, want.Checksum)
		if lines[i] != line {
			t.Errorf("line %d: transcription %q, ground truth %q", i+1, lines[i], line)
		}
		if got := idChecksum(lines[i]); got != want.Checksum {
			t.Errorf("line %d: checksum computes to %s, printed %s", i+1, got, want.Checksum)
		}
	}
}

func TestGroundTruthIDNegativeFigure(t *testing.T) {
	// Figure 3.20 is kept as a negative example: 6 of its 12 checksums do not
	// match (SOURCE.md). If this stops failing, the transcription changed.
	bad := 0
	for _, l := range readLines(t, "id-fig-3-20.txt") {
		i := strings.LastIndex(l, `,"`)
		if idChecksum(l) != strings.Trim(l[i+1:], `"`) {
			bad++
		}
	}
	if bad != 6 {
		t.Fatalf("figure 3.20: %d inconsistent checksums, want 6", bad)
	}
}

func TestGroundTruthSER(t *testing.T) {
	lines := readLines(t, "ser-fig-10-16.txt")
	var rows [][]string
	headings := 0
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 5 && f[0] != "#" && strings.Count(f[1], "/") == 2 {
			rows = append(rows, f)
		}
		if len(f) > 0 && f[0] == "#" {
			headings++
			if strings.Join(f, " ") != strings.Join(gtSERColumns, " ") {
				t.Errorf("column heading %q, ground truth %q", f, gtSERColumns)
			}
		}
	}
	if headings != 1 {
		t.Errorf("transcription has %d column headings, want 1", headings)
	}
	if len(rows) != len(gtSER) {
		t.Fatalf("transcription has %d SER rows, ground truth %d", len(rows), len(gtSER))
	}
	for i, want := range gtSER {
		got := rows[i]
		if got[0] != want.Row || got[1] != want.Date || got[2] != want.Time || got[3] != want.Element || got[4] != want.State {
			t.Errorf("row %d: transcription %v, ground truth %+v", i+1, got, want)
		}
	}
	text := strings.Join(lines, "\n")
	for _, s := range []string{gtSERHeader.Model, "FID = " + gtSERHeader.FID, "CID = " + gtSERHeader.CID, "Time Source: " + gtSERHeader.TimeSource} {
		if !strings.Contains(text, s) {
			t.Errorf("SER header does not contain %q", s)
		}
	}
}

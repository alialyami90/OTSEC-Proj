package sel751

import (
	"errors"
	"regexp"
	"time"

	"otsec.local/otsec/contracts/adapter"
)

// A SER report (S22 Figure 10.16, p. 10.40): the Table 7.16 header (RID and
// date, TID and time source), "Serial No = ...", "FID = ... CID = ...", the
// column headings, then one row per record. Row 1 is the newest.
type serReport struct {
	context  adapter.Span // the header, up to the column headings (C4 native.context_span)
	serial   *serValue
	fid, cid *serValue
	rows     []serRow
}

type serValue struct {
	value string
	span  adapter.Span
}

// serRow is one row. fields follow adapter.RecordFields["sel.ser.row"] when
// ok; a row that does not fit the grammar keeps its bytes and is reported
// unparsed (EP-1), never guessed at.
type serRow struct {
	span   adapter.Span
	fields []string
	ok     bool
}

var (
	serHeadings = regexp.MustCompile(`^#\s+DATE\s+TIME\s+ELEMENT\s+STATE$`)
	serSerial   = regexp.MustCompile(`^Serial No = (\S+)$`)
	serFIDCID   = regexp.MustCompile(`^FID = (\S+)\s+CID = (\S+)$`)
	// The date is in the relay's DATE_F order (S22 p. 7.31): MDY and DMY
	// print dd/dd/dddd, YMD prints dddd/dd/dd. Which order applies is read
	// from SHO G, not guessed here.
	serRowRE = regexp.MustCompile(`^(\d+) +(\d{2}/\d{2}/\d{4}|\d{4}/\d{2}/\d{2}) +(\d{2}:\d{2}:\d{2}\.\d{3}) +([A-Za-z0-9_]+) +([A-Za-z]+)$`)
)

var (
	errNoHeadings  = errors.New("sel751: SER report without the column headings")
	errTwoHeadings = errors.New("sel751: SER report with the column headings twice")
	errTwoIdentity = errors.New("sel751: SER header names the serial number, FID or CID twice")
)

// parseSER reads a SER message. A report without the column headings is an
// error, because without them no row can be told from header text.
func parseSER(m message) (serReport, error) {
	var r serReport
	ls := m.lines()
	head := -1
	for i, l := range ls {
		if serHeadings.Match(l.trimmed()) {
			if head >= 0 {
				return serReport{}, errTwoHeadings
			}
			head = i
		}
	}
	if head < 0 {
		return serReport{}, errNoHeadings
	}
	first := -1
	for i, l := range ls[:head] {
		t := l.trimmed()
		if len(t) > 0 && first < 0 {
			first = i
		}
		if g := serSerial.FindSubmatchIndex(t); g != nil {
			if r.serial != nil {
				return serReport{}, errTwoIdentity
			}
			r.serial = &serValue{string(t[g[2]:g[3]]), l.span(g[2], g[3])}
		}
		if g := serFIDCID.FindSubmatchIndex(t); g != nil {
			if r.fid != nil {
				return serReport{}, errTwoIdentity
			}
			r.fid = &serValue{string(t[g[2]:g[3]]), l.span(g[2], g[3])}
			r.cid = &serValue{string(t[g[4]:g[5]]), l.span(g[4], g[5])}
		}
	}
	if first >= 0 {
		start := ls[first].off
		r.context = adapter.Span{Offset: start, Length: ls[head].off - start}
	}
	for _, l := range ls[head+1:] {
		t := l.trimmed()
		if len(t) == 0 {
			continue
		}
		row := serRow{span: l.span(0, len(t))}
		if g := serRowRE.FindSubmatch(t); g != nil {
			row.ok = true
			for _, f := range g[1:] {
				row.fields = append(row.fields, string(f))
			}
		}
		r.rows = append(r.rows, row)
	}
	return r, nil
}

// settingDateF is the one context read this build understands: the order
// of the DATE column of every SER row (S22 Table 4.84 p. 4.225, p. 7.31;
// D3-2). dateLayouts are its values, as Go layouts. That the rows follow
// DATE_F is inferred from p. 7.31, not stated (register rev 4), so the
// parser is documented-untested until a capture shows it (H-13).
const settingDateF = "DATE_F"

var dateLayouts = map[string]string{"MDY": "01/02/2006", "YMD": "2006/01/02", "DMY": "02/01/2006"}

// dateFits reports whether date is a calendar date printed in the DATE_F
// order named by order: two-digit month and day, four-digit year, "/"
// between, and a day that month has. An order this build does not know
// fits no date, so a row is never read in a guessed order.
func dateFits(order, date string) bool {
	layout, ok := dateLayouts[order]
	if !ok {
		return false
	}
	_, err := time.Parse(layout, date)
	return err == nil
}

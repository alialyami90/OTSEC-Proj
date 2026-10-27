package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/store"
	"otsec.local/otsec/contracts/version"
)

// Parser is C4 collection.parser on every SER event. Its version changes
// whenever the events built from the same result change.
var Parser = event.Parser{Name: "sel-ascii-ser", Version: "0.1"}

// SERKind is the C2 record kind this package normalizes.
const SERKind = "sel.ser.row"

// SubjectType is C4 normalized.subject_type of a SER row: the element is a
// Relay Word bit or another element the relay prints (S22 Figure 10.16).
const SubjectType = "ser-element"

// TimeFormat is C4 device_time.format of a SER row.
const TimeFormat = "sel-ascii-ser-row"

// accuracyRelativeNS is the SEL-751 SER time-stamp accuracy relative to the
// relay's own time source: "Time-Stamp Accuracy (With Respect to Time
// Source): ±1 ms" (SEL-751 data sheet 20260910, Specifications, Sequential
// Events Recorder; A2 source S16, documented-untested). It is not an
// accuracy against true time, so it goes in quality, never in accuracy_ns.
const accuracyRelativeNS = int64(1_000_000)

// Input is what the node knows about a read that the C2 result does not say.
type Input struct {
	Node event.NodeID
	// Stream is the asset's SER stream; HealthStream is where the node
	// commits platform health events.
	Stream       event.Stream
	HealthStream event.Stream
	// ClockResolutionNS and Clock are the node clock's status at the
	// invocation's ended_at (C4 Received).
	ClockResolutionNS int64
	Clock             event.Clock
	// Prev is the alignment state committed with the previous read of
	// Stream, as DecodeState returns it: nil before the first read, empty
	// after a read that found no rows.
	Prev []string
	// DateOrder is the relay's DATE_F, "MDY", "DMY" or "YMD", for a result
	// without a DATE_F setting (C2 0.4 or earlier, or a 0.5 adapter under a
	// register without the DATE_F read, D3-11): recorded by an operator, or
	// empty for unknown, and then MDY is assumed and every event says so.
	// When the result carries the DATE_F setting the adapter read in the
	// same session (D2-20), that is the order; DateOrder must then be empty
	// or equal to it.
	DateOrder string
	// Offset is the relay clock's offset from UTC, "+HH:MM" or "-HH:MM",
	// with the basis it came from. Empty means unknown, and no UTC is stated.
	Offset      string
	OffsetBasis event.OffsetBasis
}

// Output is what one read produces.
type Output struct {
	// Events are the new SER events, pending (seq 0), oldest first. They are
	// committed in this order, in one batch, on Input.Stream.
	Events []event.Event
	// Health are pending platform events about the read, for
	// Input.HealthStream.
	Health []event.Event
	// Capture is the C2 transcript as stored. Every event's native.evidence
	// names it (evidence.ref is store.EvidenceRef of its SHA-256).
	Capture store.Capture
	// State is the alignment state after this read, the next read's
	// Input.Prev. It is committed in the same transaction as Events.
	State []string
	// StateChanged is false when State is Input.Prev unchanged, either
	// because the read was not aligned or because it matched it exactly.
	StateChanged bool
}

// Errors returned by Normalize. A refused result produces no events; the
// caller keeps the result and raises an alarm.
var (
	ErrResult = errors.New("normalize: result refused")
	ErrInput  = errors.New("normalize: invalid input")
)

var (
	offsetForm = regexp.MustCompile(`^[+-]([01][0-9]|2[0-3]):[0-5][0-9]$`)
	keyForm    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Normalize builds the C4 events of one SER read. See the package doc for
// the rules.
func Normalize(res adapter.Result, inv adapter.Invocation, a asset.Asset, in Input) (*Output, error) {
	if err := res.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResult, err)
	}
	if err := res.CheckAgainst(inv, a); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrResult, err)
	}
	if err := in.check(); err != nil {
		return nil, err
	}
	order, err := dateOrder(res, in.DateOrder)
	if err != nil {
		return nil, err
	}
	in.DateOrder = order
	rd := &read{
		in:        in,
		assetID:   a.AssetID,
		target:    res.Target,
		invID:     res.InvocationID,
		opID:      res.OperationID,
		data:      res.Transcript.Data,
		sha:       res.Transcript.SHA256,
		endedAt:   res.EndedAt,
		records:   res.Records,
		rxAt:      res.Transcript.ReceivedAt,
		readError: "",
	}
	switch {
	case res.Error != nil && res.Error.Code == adapter.PartialReadRowsExceeded:
		rd.readError = "read over the profile's max_read_rows (D1-12): " + res.Error.Detail
	case res.Status != adapter.StatusOK && res.Status != adapter.StatusPartial:
		if len(res.Records) == 0 {
			// Nothing was read. The failure itself is the collector's to
			// audit and alarm; there is no record to keep.
			return &Output{Capture: rd.capture(), State: in.Prev}, nil
		}
		rd.readError = fmt.Sprintf("result status %s carries %d records of an unfinished read", res.Status, len(res.Records))
	}
	return rd.normalize()
}

// dateOrder is the date order the SER rows of res are read in. A result of
// C2 0.5 or later that carries a DATE_F setting states it, and only that is
// used: a caller's order that disagrees is refused, and so is a parsed row
// beside a DATE_F this package does not know, because the adapter must
// leave such rows unparsed (their bytes are then kept as parse-failed
// events). A caller's order is a defect in the input (ErrInput); a parsed
// row beside an unknown DATE_F is a defect in the result (ErrResult, A1 on
// the DATE_F plan, which had said ErrInput). A refused result is kept by
// the caller as quarantine, with its bytes, and alarmed (R1.4). A result
// with no DATE_F setting, of any minor, is read as before 0.5: the caller's
// order stands, and without one MDY is assumed and flagged. C2 0.5 makes
// Settings optional, and an adapter under a register without the DATE_F
// read stamps 0.5 and reports none (A2 on #203).
func dateOrder(res adapter.Result, caller string) (string, error) {
	id, err := version.Parse(res.Schema)
	if err != nil {
		return "", fmt.Errorf("%w: schema %q: %v", ErrResult, res.Schema, err)
	}
	if id.Minor < 5 {
		return caller, nil
	}
	s, ok := res.Setting(dateSetting)
	if !ok {
		return caller, nil
	}
	parsed := slices.ContainsFunc(res.Records, func(r adapter.Record) bool { return r.ParseOK })
	switch {
	case dateOrders[s.Value] != nil && caller != "" && caller != s.Value:
		return "", fmt.Errorf("%w: date order %q given, but the relay's DATE_F is %q", ErrInput, caller, s.Value)
	case dateOrders[s.Value] != nil:
		return s.Value, nil
	case caller != "":
		return "", fmt.Errorf("%w: date order %q given, but the relay's DATE_F is %q, not MDY, DMY or YMD", ErrInput, caller, s.Value)
	case parsed:
		return "", fmt.Errorf("%w: a parsed SER row, but the relay's DATE_F is %q, not MDY, DMY or YMD", ErrResult, s.Value)
	}
	// No row to read: the order is not needed, and none is assumed.
	return "", nil
}

// dateSetting is the SEL setting that orders printed dates (S22 p. 7.31).
const dateSetting = "DATE_F"

func (in Input) check() error {
	switch {
	case !in.Node.Valid() || !in.Stream.Valid() || !in.HealthStream.Valid():
		return fmt.Errorf("%w: node %q, stream %q or health stream %q", ErrInput, in.Node, in.Stream, in.HealthStream)
	case in.Stream == in.HealthStream:
		return fmt.Errorf("%w: SER and health events share stream %q", ErrInput, in.Stream)
	case in.ClockResolutionNS <= 0:
		return fmt.Errorf("%w: clock resolution %d ns", ErrInput, in.ClockResolutionNS)
	case !slices.Contains([]event.SyncState{event.SyncSynchronized, event.SyncUnsynchronized, event.SyncUnknown}, in.Clock.Sync):
		return fmt.Errorf("%w: clock sync %q", ErrInput, in.Clock.Sync)
	case in.DateOrder != "" && dateOrders[in.DateOrder] == nil:
		return fmt.Errorf("%w: date order %q is not MDY, DMY or YMD", ErrInput, in.DateOrder)
	case in.Offset == "" && in.OffsetBasis != "" && in.OffsetBasis != event.BasisNone:
		return fmt.Errorf("%w: offset basis %q without an offset", ErrInput, in.OffsetBasis)
	case in.Offset != "" && (!offsetForm.MatchString(in.Offset) || in.OffsetBasis == "" || in.OffsetBasis == event.BasisNone):
		return fmt.Errorf("%w: offset %q with basis %q", ErrInput, in.Offset, in.OffsetBasis)
	case len(in.Prev) > event.MaxAlignRows:
		return fmt.Errorf("%w: previous state holds %d keys", ErrInput, len(in.Prev))
	}
	for _, k := range in.Prev {
		if !keyForm.MatchString(k) {
			return fmt.Errorf("%w: previous state key %q", ErrInput, k)
		}
	}
	return nil
}

// read is one SER read being normalized.
type read struct {
	in        Input
	assetID   string
	target    asset.EvidenceClass
	invID     string
	opID      string
	data      []byte
	sha       string
	endedAt   string
	records   []adapter.Record
	rxAt      func(adapter.Span) string
	readError string // set when the read must not be aligned
}

// row is one record, in chronological position.
type row struct {
	rec      adapter.Record
	bytes    []byte
	verified bool // parsed, and every field value is in the bytes in order
	key      string
}

func (rd *read) capture() store.Capture {
	return store.Capture{SHA256: rd.sha, Bytes: rd.data}
}

func (rd *read) normalize() (*Output, error) {
	out := &Output{Capture: rd.capture(), State: rd.in.Prev}
	if rd.readError == "" {
		rd.readError = rd.checkRecords()
	}
	if rd.readError != "" {
		h, err := rd.health(event.HealthParseFailed, map[string]string{
			"records": strconv.Itoa(len(rd.records)),
			"aligned": "false",
			"reason":  rd.readError,
		})
		if err != nil {
			return nil, err
		}
		out.Health = append(out.Health, h)
		return out, nil
	}
	// Transcript order is chronological: the oldest row first, row 1 last.
	rows := make([]row, len(rd.records))
	keys := make([]string, len(rd.records))
	for i, rec := range rd.records {
		rows[i] = rd.row(rec)
		keys[i] = rows[i].key
	}
	al, err := event.Align(rd.in.Prev, keys)
	if err != nil {
		// Unreachable after checkRecords, kept so the bound never depends
		// on it.
		return nil, fmt.Errorf("%w: %v", ErrResult, err)
	}
	out.State = keys
	out.StateChanged = rd.in.Prev == nil || !slices.Equal(rd.in.Prev, keys)
	failed := 0
	for _, i := range al.Added {
		alignment, flag := rowAlignment(al, i)
		e, err := rd.event(rows[i], alignment, flag)
		if err != nil {
			return nil, err
		}
		if e.Collection.ParseStatus == event.ParseFailed {
			failed++
		}
		out.Events = append(out.Events, e)
	}
	switch al.Status {
	case event.AlignStatusGap:
		reason := "no overlap between consecutive reads"
		if len(al.Removed) > 0 {
			reason = "records of the previous read are missing from this one although later records remain"
		}
		h, err := rd.health(event.HealthSERGap, map[string]string{
			"stream":                string(rd.in.Stream),
			"previous_read_records": strconv.Itoa(len(rd.in.Prev)),
			"new_read_records":      strconv.Itoa(len(keys)),
			"added_records":         strconv.Itoa(len(al.Added)),
			"removed_records":       strconv.Itoa(len(al.Removed)),
			"possible_duplicates":   strconv.Itoa(len(al.PossibleDuplicates)),
			"reason":                reason,
		})
		if err != nil {
			return nil, err
		}
		out.Health = append(out.Health, h)
	case event.AlignStatusAmbiguous:
		h, err := rd.health(event.HealthAlignmentAmbiguous, map[string]string{
			"stream":                string(rd.in.Stream),
			"previous_read_records": strconv.Itoa(len(rd.in.Prev)),
			"new_read_records":      strconv.Itoa(len(keys)),
			"added_records":         strconv.Itoa(len(al.Added)),
			"possible_duplicates":   strconv.Itoa(len(al.PossibleDuplicates)),
			"reason":                "identical records make the overlap uncertain",
		})
		if err != nil {
			return nil, err
		}
		out.Health = append(out.Health, h)
	}
	if failed > 0 {
		h, err := rd.health(event.HealthParseFailed, map[string]string{
			"records":        strconv.Itoa(len(al.Added)),
			"records_failed": strconv.Itoa(failed),
			"aligned":        "true",
			"reason":         "rows kept as native bytes only: not parsed, or parsed fields not found in the row",
		})
		if err != nil {
			return nil, err
		}
		out.Health = append(out.Health, h)
	}
	return out, nil
}

// checkRecords returns why the read must not be aligned, or "".
func (rd *read) checkRecords() string {
	if len(rd.records) > event.MaxAlignRows {
		return fmt.Sprintf("%d records, more than C4 MaxAlignRows %d (D1-12)", len(rd.records), event.MaxAlignRows)
	}
	for i, rec := range rd.records {
		if rec.Kind != SERKind {
			return fmt.Sprintf("record %d is of kind %q, which is not normalized", i, rec.Kind)
		}
		if i > 0 && rec.Span.Offset < rd.records[i-1].Span.Offset+rd.records[i-1].Span.Length {
			return fmt.Sprintf("record %d does not follow record %d in the transcript", i, i-1)
		}
		if want := strconv.Itoa(len(rd.records) - i); rec.ParseOK && len(rec.Fields) > 0 && rec.Fields[0].Value != want {
			return fmt.Sprintf("record %d of %d prints row number %q, want %s: the relay prints the oldest row first and row 1, the newest, last", i, len(rd.records), rec.Fields[0].Value, want)
		}
	}
	return ""
}

func (rd *read) row(rec adapter.Record) row {
	b := rd.data[rec.Span.Offset : rec.Span.Offset+rec.Span.Length]
	r := row{rec: rec, bytes: b}
	start, ok := fieldsInRow(b, rec)
	r.verified = ok
	if !ok {
		start = fallbackKeyStart(b)
	}
	sum := sha256.Sum256(b[start:])
	r.key = "sha256:" + hex.EncodeToString(sum[:])
	return r
}

// fieldsInRow reports whether rec parsed and its field values appear in b in
// order, each after spaces (the first may have none before it), with only
// spaces after the last, and returns the offset of the DATE value. A row
// that holds a CR, LF, STX or ETX is never verified: C2 spans exclude them.
func fieldsInRow(b []byte, rec adapter.Record) (int, bool) {
	want := adapter.RecordFields[SERKind]
	if !rec.ParseOK || len(rec.Fields) != len(want) || strings.ContainsAny(string(b), "\r\n\x02\x03") {
		return 0, false
	}
	pos, date := 0, 0
	for i, f := range rec.Fields {
		if f.Name != want[i] || f.Value == "" {
			return 0, false
		}
		gap := pos
		for pos < len(b) && b[pos] == ' ' {
			pos++
		}
		if i > 0 && pos == gap {
			return 0, false
		}
		if !strings.HasPrefix(string(b[pos:]), f.Value) {
			return 0, false
		}
		if f.Name == "DATE" {
			date = pos
		}
		pos += len(f.Value)
	}
	for ; pos < len(b); pos++ {
		if b[pos] != ' ' {
			return 0, false
		}
	}
	return date, true
}

// fallbackKeyStart skips leading spaces, the first run of other bytes (the
// row number) and the spaces after it.
func fallbackKeyStart(b []byte) int {
	i := 0
	for i < len(b) && b[i] == ' ' {
		i++
	}
	for i < len(b) && b[i] != ' ' {
		i++
	}
	for i < len(b) && b[i] == ' ' {
		i++
	}
	return i
}

func rowAlignment(al event.AlignResult, i int) (event.Alignment, string) {
	if slices.Contains(al.PossibleDuplicates, i) {
		return event.AlignPossibleDuplicate, "possible-duplicate"
	}
	switch al.Status {
	case event.AlignStatusFirstRead:
		return event.AlignFirstRead, ""
	case event.AlignStatusGap:
		return event.AlignGapBefore, "gap-before"
	}
	return event.AlignOK, ""
}

func (rd *read) source() event.Source {
	return event.Source{
		Asset:      &event.AssetRef{ID: rd.assetID, Binding: event.Binding{Method: event.BindAdapterTarget, Confidence: event.ConfidenceConfigured}},
		OriginAuth: event.AuthSession,
	}
}

func (rd *read) received(utc string) (event.Received, error) {
	if utc == "" {
		return event.Received{}, fmt.Errorf("%w: a record is not in received bytes", ErrResult)
	}
	return event.Received{UTC: truncateUTC(utc, rd.in.ClockResolutionNS), ResolutionNS: rd.in.ClockResolutionNS, Clock: rd.in.Clock}, nil
}

func (rd *read) event(r row, alignment event.Alignment, flag string) (event.Event, error) {
	rcv, err := rd.received(rd.rxAt(r.rec.Span))
	if err != nil {
		return event.Event{}, err
	}
	src := rd.source()
	src.EvidenceClass = rd.target
	sum := sha256.Sum256(r.bytes)
	n := &event.Native{
		Bytes:        r.bytes,
		RecordSHA256: hex.EncodeToString(sum[:]),
		RecordLength: int64(len(r.bytes)),
		Evidence:     event.Evidence{SHA256: rd.sha, Length: int64(len(rd.data)), Ref: store.EvidenceRef(rd.sha)},
		Span:         &event.Span{Offset: r.rec.Span.Offset, Length: r.rec.Span.Length},
		AlignmentKey: r.key,
	}
	var timeSource string
	if cs := r.rec.ContextSpan; cs != nil {
		n.ContextSpan = &event.Span{Offset: cs.Offset, Length: cs.Length}
		timeSource = headerTimeSource(rd.data[cs.Offset : cs.Offset+cs.Length])
	}
	col := &event.Collection{
		Method:       event.MethodAdapterPoll,
		InvocationID: rd.invID,
		OperationID:  rd.opID,
		Parser:       &Parser,
		Alignment:    alignment,
		ParseStatus:  event.ParseFailed,
	}
	e := event.Event{
		Schema:     event.Identifier,
		ID:         event.EventID{NodeID: rd.in.Node, Stream: rd.in.Stream},
		Origin:     event.OriginDevice,
		Kind:       event.KindSER,
		Source:     src,
		Collection: col,
		Received:   rcv,
		Native:     n,
	}
	if flag != "" {
		e.Flags = []string{flag}
	}
	if r.verified {
		f := r.rec.Fields
		for _, x := range f {
			n.Fields = append(n.Fields, event.Field{Name: x.Name, Value: x.Value})
		}
		col.NativePosition = f[0].Value
		dt := deviceTime(f[1].Value, f[2].Value, rd.in, timeSource)
		e.DeviceTime = &dt
		col.ParseStatus = event.ParseOK
		if slices.Contains(dt.Flags, "invalid-time") {
			col.ParseStatus = event.ParsePartial
		}
		e.Normalized = &event.Normalized{Subject: f[3].Value, SubjectType: SubjectType, Value: f[4].Value, Category: event.Unmapped}
	}
	if err := e.ValidatePending(); err != nil {
		return event.Event{}, fmt.Errorf("normalize: built an invalid event: %w", err)
	}
	return e, nil
}

func (rd *read) health(typ string, details map[string]string) (event.Event, error) {
	rcv, err := rd.received(rd.endedAt)
	if err != nil {
		return event.Event{}, err
	}
	details["invocation_id"] = rd.invID
	details["evidence_sha256"] = rd.sha
	src := rd.source()
	src.OriginAuth = event.AuthPlatform
	e := event.Event{
		Schema:   event.Identifier,
		ID:       event.EventID{NodeID: rd.in.Node, Stream: rd.in.HealthStream},
		Origin:   event.OriginPlatform,
		Kind:     event.KindHealth,
		Source:   src,
		Received: rcv,
		Health:   &event.Health{Type: typ, Details: details},
	}
	if err := e.ValidatePending(); err != nil {
		return event.Event{}, fmt.Errorf("normalize: built an invalid health event: %w", err)
	}
	return e, nil
}

// headerTimeSource returns the value after "Time Source:" in a SER report
// header, up to the end of its line, without the spaces around it. It is ""
// when the header has none, or when the value is empty, longer than 32
// bytes, or not printable ASCII.
func headerTimeSource(h []byte) string {
	const label = "Time Source:"
	s := string(h)
	i := strings.Index(s, label)
	if i < 0 {
		return ""
	}
	v := s[i+len(label):]
	if j := strings.IndexAny(v, "\r\n"); j >= 0 {
		v = v[:j]
	}
	v = strings.Trim(v, " ")
	if v == "" || len(v) > 32 {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return ""
		}
	}
	return v
}

// truncateUTC cuts the fraction of an RFC 3339 UTC time to the digits the
// resolution supports: d digits express steps of 10^(9-d) ns (C4).
func truncateUTC(s string, resNS int64) string {
	dot := strings.LastIndexByte(s, '.')
	if dot < 0 || !strings.HasSuffix(s, "Z") {
		return s
	}
	digits, step := 0, int64(1_000_000_000)
	for digits < 9 && step/10 >= resNS {
		step /= 10
		digits++
	}
	frac := s[dot+1 : len(s)-1]
	if len(frac) <= digits {
		return s
	}
	if digits == 0 {
		return s[:dot] + "Z"
	}
	return s[:dot+1] + frac[:digits] + "Z"
}

// Records returns the C5 records of the output: the SER events on
// Input.Stream, each with the capture and the last with the state as its
// SourceCursor, and the health events. When there are no SER events, the
// first health record carries the capture, so a read that was not aligned
// still keeps its bytes (D1-12).
func (o *Output) Records(stream, health event.Stream) (ser, hl []store.Record, err error) {
	state, err := EncodeState(o.State)
	if err != nil {
		return nil, nil, err
	}
	capture := o.Capture
	for i := range o.Events {
		b, err := json.Marshal(&o.Events[i])
		if err != nil {
			return nil, nil, err
		}
		r := store.Record{Stream: stream, Class: store.ClassAdapterEvidence, Event: b, Capture: &capture}
		if i == len(o.Events)-1 {
			r.SourceCursor = state
		}
		ser = append(ser, r)
	}
	for i := range o.Health {
		b, err := json.Marshal(&o.Health[i])
		if err != nil {
			return nil, nil, err
		}
		r := store.Record{Stream: health, Class: store.ClassPlatform, Event: b}
		if i == 0 && len(ser) == 0 && len(capture.Bytes) > 0 {
			r.Capture = &capture
		}
		hl = append(hl, r)
	}
	return ser, hl, nil
}

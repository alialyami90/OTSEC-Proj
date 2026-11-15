package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// P4-C8-T (D4-108 item 3.1): time.utc's comma form is refused, as the schema
// refuses it, and the precision check counts the fraction's digits whatever
// separator reaches it.

var goldenUTC = regexp.MustCompile(`"time":\{"utc":"([^"]*)"`)

// toComma writes utc's fraction after a ','; a utc with no fraction gains ",0".
func toComma(utc string) string {
	if i := strings.IndexByte(utc, '.'); i >= 0 {
		return utc[:i] + "," + utc[i+1:]
	}
	return strings.TrimSuffix(utc, "Z") + ",0Z"
}

func isTimeFormErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "audit: time ") && strings.Contains(err.Error(), "is not RFC 3339 UTC with Z")
}

// TestTimeCommaRefusedGoldens rewrites time.utc in every golden record to the
// comma form and requires ParseRecord to refuse it for the form, while the
// record as written still parses.
func TestTimeCommaRefusedGoldens(t *testing.T) {
	files, _ := filepath.Glob("testdata/valid/*.json")
	var recs [][]byte
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, bytes.TrimRight(b, "\n"))
	}
	chainFile, err := os.ReadFile("testdata/chain/slice-session.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	recs = append(recs, bytes.Split(bytes.TrimRight(chainFile, "\n"), []byte("\n"))...)
	if len(recs) < 40 {
		t.Fatalf("golden records missing: %d", len(recs))
	}
	kinds := map[Action]bool{}
	for i, b := range recs {
		r, err := ParseRecord(b)
		if err != nil {
			t.Fatalf("record %d as written: %v", i, err)
		}
		kinds[r.Action] = true
		m := goldenUTC.FindSubmatch(b)
		if m == nil {
			t.Fatalf("record %d (%s): no time.utc", i, r.Action)
		}
		utc := string(m[1])
		comma := bytes.Replace(b, []byte(`"time":{"utc":"`+utc+`"`), []byte(`"time":{"utc":"`+toComma(utc)+`"`), 1)
		if _, err := ParseRecord(comma); !errors.Is(err, ErrRecordRejected) || !isTimeFormErr(err) {
			t.Errorf("record %d (%s), time.utc %q: got %v, want the time form refused", i, r.Action, toComma(utc), err)
		}
	}
	t.Logf("%d records, %d record kinds", len(recs), len(kinds))
}

// TestTimeCommaRefusedLaterMinor: a record stamped with a later minor is read
// forward-compatibly and still validated, so its comma form is refused too.
func TestTimeCommaRefusedLaterMinor(t *testing.T) {
	b, err := os.ReadFile("testdata/valid/sensor-revoked.json")
	if err != nil {
		t.Fatal(err)
	}
	later := bytes.Replace(bytes.TrimRight(b, "\n"), []byte(`"otsec.audit/0.13"`), []byte(`"otsec.audit/0.14"`), 1)
	if _, err := ParseRecord(later); err != nil {
		t.Fatalf("0.14 record as written: %v", err)
	}
	comma := bytes.Replace(later, []byte(`"utc":"2026-11-15T10:00:00.000125Z"`), []byte(`"utc":"2026-11-15T10:00:00,000125Z"`), 1)
	if bytes.Equal(comma, later) {
		t.Fatal("mutation did not apply")
	}
	if _, err := ParseRecord(comma); !errors.Is(err, ErrRecordRejected) || !isTimeFormErr(err) {
		t.Fatalf("0.14 record with a comma: got %v", err)
	}
}

// TestTimeCommaRefusedEveryAction: for every action this reader knows, a
// record whose time.utc has a comma is refused for the time's form, and the
// same record with a '.' is not refused for the time.
func TestTimeCommaRefusedEveryAction(t *testing.T) {
	for a := range actions {
		r := Record{Contract: ContractID, NodeID: "site-a-node-1", Seq: 2, PrevHash: strings.Repeat("6", 64), Action: a,
			Outcome: OutcomeInfo}
		if a == ActionAuditChainStart {
			r.Seq, r.PrevHash = 1, GenesisPrevHash
		}
		r.Time = Time{UTC: "2026-11-15T10:00:00.123456Z", ResolutionNS: 1000, Clock: Clock{Sync: event.SyncSynchronized, Source: "ntp"}}
		if err := r.Validate(); isTimeFormErr(err) {
			t.Fatalf("%s with a '.': %v", a, err)
		}
		r.Time.UTC = "2026-11-15T10:00:00,123456Z"
		if err := r.Validate(); !isTimeFormErr(err) {
			t.Errorf("%s with a ',': got %v, want the time form refused", a, err)
		}
	}
}

// TestTimeFieldsCommaRefused covers every other C8 time field the schema
// states in time.utc's form (properties with the pattern
// `(\.[0-9]{1,9})?Z$` in schema/record.json): each, in a golden that carries
// it, is refused in the comma form, with ten fraction digits, on 30 February
// and at hour 24, while the golden as written parses. applied_at, at most six digits, is #699's and is
// tested in sensor_test.go.
func TestTimeFieldsCommaRefused(t *testing.T) {
	for _, c := range []struct{ file, field string }{
		{"store-retention-moved-wall.json", "wall_utc"},
		{"store-retention-moved-wall.json", "cutoff_utc"},
		{"store-retention-moved-wall.json", "previous_cutoff_utc"},
		{"store-retention-moved-created.json", "wall_utc"},
		{"store-retention-moved-created.json", "cutoff_utc"},
		{"config-change-detected-unapproved.json", "unchanged_at"},
		{"config-change-detected-approved.json", "unchanged_at"},
		{"config-change-approved.json", "window_start"},
		{"config-change-approved.json", "window_end"},
		{"sensor-enrolled-rekey.json", "not_after"},
		{"sensor-revoked.json", "suspect_from"},
		{"collector-request-sensor-revoke.json", "suspect_from"},
	} {
		b, err := os.ReadFile(filepath.Join("testdata/valid", c.file))
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.TrimRight(b, "\n")
		if _, err := ParseRecord(b); err != nil {
			t.Fatalf("%s as written: %v", c.file, err)
		}
		m := regexp.MustCompile(`"` + c.field + `":"([^"]*)"`).FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no %s", c.file, c.field)
		}
		v := string(m[1])
		whole := v
		if i := strings.IndexByte(v, '.'); i >= 0 {
			whole = v[:i] + "Z"
		}
		// The comma and ten digits fail the pattern; 30 February and hour 24
		// pass it and fail only the parse.
		for _, bad := range []string{toComma(v), strings.TrimSuffix(whole, "Z") + ".1234567890Z",
			v[:5] + "02-30" + v[10:], v[:11] + "24" + v[13:]} {
			rec := bytes.Replace(b, []byte(`"`+c.field+`":"`+v+`"`), []byte(`"`+c.field+`":"`+bad+`"`), 1)
			_, err := ParseRecord(rec)
			if !errors.Is(err, ErrRecordRejected) || !strings.Contains(err.Error(), "RFC 3339") {
				t.Errorf("%s %s %q: got %v, want the form refused", c.file, c.field, bad, err)
			}
		}
	}
}

// TestTimeOtherFormsRefused pins the rest of the schema's form for time.utc.
func TestTimeOtherFormsRefused(t *testing.T) {
	for name, utc := range map[string]string{
		"lower-case z":     "2026-11-15T10:00:00.5z",
		"lower-case t":     "2026-11-15t10:00:00.5Z",
		"ten digits":       "2026-11-15T10:00:00.1234567890Z",
		"no digits":        "2026-11-15T10:00:00.Z",
		"offset":           "2026-11-15T13:00:00.5+03:00",
		"zero offset":      "2026-11-15T10:00:00.5+00:00",
		"comma, no digits": "2026-11-15T10:00:00,Z",
		"one-digit hour":   "2026-11-15T9:00:00.5Z", // time.Parse takes it
		// The pattern takes these two; only the parse refuses them.
		"30 February": "2026-02-30T10:00:00.5Z",
		"hour 24":     "2026-11-15T24:00:00.5Z",
	} {
		tm := Time{UTC: utc, ResolutionNS: 1, Clock: Clock{Sync: event.SyncSynchronized}}
		if err := validateTime(tm); !isTimeFormErr(err) {
			t.Errorf("%s (%q): got %v", name, utc, err)
		}
	}
}

// TestTimePrecisionBoundary: a time may claim exactly its resolution and no
// finer. Each pair kills an off-by-one on the digit count or on the
// comparison.
func TestTimePrecisionBoundary(t *testing.T) {
	cases := []struct {
		utc  string
		res  int64
		want bool
	}{
		{"2026-11-15T10:00:00Z", 1_000_000_000, true},
		{"2026-11-15T10:00:00Z", 1_000_000_001, false},
		{"2026-11-15T10:00:00.5Z", 100_000_000, true},
		{"2026-11-15T10:00:00.5Z", 100_000_001, false},
		{"2026-11-15T10:00:00.123456Z", 1000, true},
		{"2026-11-15T10:00:00.123456Z", 1001, false},
		{"2026-11-15T10:00:00.123456789Z", 1, true},
		{"2026-11-15T10:00:00.123456789Z", 2, false},
	}
	for _, c := range cases {
		err := validateTime(Time{UTC: c.utc, ResolutionNS: c.res, Clock: Clock{Sync: event.SyncSynchronized}})
		if (err == nil) != c.want {
			t.Errorf("%s at %d ns: got %v, want accepted %v", c.utc, c.res, err, c.want)
		}
		if err != nil && !strings.Contains(err.Error(), "claims more precision") {
			t.Errorf("%s at %d ns: refused for another reason: %v", c.utc, c.res, err)
		}
	}
}

// TestFractionDigitsEitherSeparator: the digit count is the same after a ','
// as after a '.', so a comma that reached the precision check could not skip it.
func TestFractionDigitsEitherSeparator(t *testing.T) {
	for utc, want := range map[string]int{
		"2026-11-15T10:00:00Z":           0,
		"2026-11-15T10:00:00.5Z":         1,
		"2026-11-15T10:00:00,5Z":         1,
		"2026-11-15T10:00:00.123456Z":    6,
		"2026-11-15T10:00:00,123456Z":    6,
		"2026-11-15T10:00:00.123456789Z": 9,
		"2026-11-15T10:00:00,123456789Z": 9,
	} {
		if got := fractionDigits(utc); got != want {
			t.Errorf("%s: %d digits, want %d", utc, got, want)
		}
	}
}

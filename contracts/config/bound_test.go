package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

// The configuration record's size is a derived bound, as the SER cap is (D4-9,
// D4-13): the largest record a read can commit follows from the run's total
// cap T, and the configuration database's record cap must hold it. The test
// computes the bound from the register's run and fails if a change to the
// register, to this contract or to C2 raises it above the cap.
//
// A record is the snapshot (its Event) and the transcript (its Capture):
//
//   - the transcript is at most T (the run's max_total_bytes, itself at most
//     C2's session ceiling);
//   - the snapshot is at most snapshotFixed bytes plus snapshotPerSetting for
//     each of at most maxSettings settings, plus the printed values, which the
//     transcript also holds and so are at most T.
//
// So the record is at most 2*T + snapshotFixed + maxSettings*snapshotPerSetting.
// That arithmetic holds while the count is S22's. Since 0.3 (D4-25) the code
// enforces it: MaxSettings and MaxSnapshotBytes, tested below.
// snapshotFixed and snapshotPerSetting are B5's measurement of the golden
// snapshot, encoded compact (5.3 KB fixed, 25 bytes of JSON and up to 16 of
// name per setting), and maxSettings is the count of names in the 24 forms on
// S22's settings sheets (contracts/register/testdata/count_settings.py).
const (
	snapshotFixed      = 5348
	snapshotPerSetting = 25 + 16
	maxSettings        = MaxSettings
	s22Settings        = 8734
	// recordCap is the configuration database's commit cap (B1, D4-13), 1.5
	// MiB. B5's Quota.MaxRecordBytes for the configuration class is this value.
	recordCap = 3 << 19
)

func TestRecordBoundFitsTheCap(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "register", "testdata", "sel-751.json"))
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
	if fixed := snapshotFixed + s22Settings*snapshotPerSetting; fixed != 363_442 {
		t.Fatalf("the snapshot's fixed bytes are %d, not the 363,442 D4-13 states", fixed)
	}
	bound := 2*run.MaxTotalBytes + snapshotFixed + maxSettings*snapshotPerSetting
	if bound > recordCap {
		t.Errorf("a record can reach %d bytes (2 x %d + %d), over the %d cap", bound, run.MaxTotalBytes, snapshotFixed+maxSettings*snapshotPerSetting, recordCap)
	}
	if run.MaxTotalBytes > register.MaxSessionBytes {
		t.Errorf("max_total_bytes %d is over C2's session ceiling %d", run.MaxTotalBytes, register.MaxSessionBytes)
	}
	// The bound is tight enough to matter: T = C2's ceiling would not fit.
	if over := 2*register.MaxSessionBytes + snapshotFixed + maxSettings*snapshotPerSetting; over <= recordCap {
		t.Errorf("the bound at T = %d is %d, which fits the cap; the cap is looser than D4-13 needs", register.MaxSessionBytes, over)
	}
}

// A record at both bounds fits the cap, including the longest transcript a run
// can keep (D4-25): the bytes bound with T, and the count bound with its
// values.
func TestBoundsFitTheCap(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "register", "testdata", "sel-751.json"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := register.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	T := p.Run("sel.config.read_all").MaxTotalBytes
	if got := MaxSnapshotBytes + T; got > recordCap {
		t.Errorf("a snapshot at MaxSnapshotBytes with a %d-byte transcript is %d bytes, over the %d cap", T, got, recordCap)
	}
	if MaxSettings != s22Settings+(s22Settings+3)/4 {
		t.Errorf("MaxSettings %d is not S22's %d plus a quarter", MaxSettings, s22Settings)
	}
	if SnapshotFixedMax >= MaxSnapshotBytes {
		t.Error("the fixed allowance leaves no room for settings")
	}
}

// bigSnapshot is read 1 with the first present section holding n settings of
// value v each, and the records a run would report for it.
func bigSnapshot(t *testing.T, n int, v string) (Snapshot, []adapter.Record) {
	t.Helper()
	s, _ := snapshot(t, "1")
	var recs []adapter.Record
	done := false
	for i := range s.Sections {
		sec := &s.Sections[i]
		if sec.State == Present && !done {
			done = true
			sec.Settings = nil
			for k := 0; k < n; k++ {
				sec.Settings = append(sec.Settings, Setting{Name: nm(k), Value: v})
			}
		}
		r := adapter.Record{Kind: adapter.RecordConfigSection, ParseOK: true}
		if sec.State == Absent {
			r.Kind = adapter.RecordConfigAbsent
		}
		for _, st := range sec.Settings {
			r.Fields = append(r.Fields, adapter.Field{Name: st.Name, Value: st.Value})
		}
		recs = append(recs, r)
	}
	return s, recs
}

// nm is the k-th name, unique up to 36^3 and within the name pattern.
func nm(k int) string {
	const d = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	return string([]byte{d[k/1296%36], d[k/36%36], d[k%36]})
}

func TestSizeBounds(t *testing.T) {
	big := strings.Repeat("V", 200)
	cases := []struct {
		name    string
		n       int
		value   string
		tooBig  bool
		because string
	}{
		{"the golden", 10, "1", false, ""},
		{"far over the count", MaxSettings, "1", true, "settings, more than"},
		{"a long value past the bytes", 8000, big, true, "bytes encoded"},
		// "<" is written as it is (no HTML escaping), so it costs one byte; a
		// quote costs two.
		{"quotes double", 6000, strings.Repeat(`"`, 150), true, "bytes encoded"},
	}
	for _, c := range cases {
		s, recs := bigSnapshot(t, c.n, c.value)
		verr := s.Validate()
		ferr := RecordsFit(recs)
		if c.tooBig {
			if !errors.Is(verr, ErrTooLarge) || !strings.Contains(verr.Error(), c.because) {
				t.Errorf("%s: Validate: %v", c.name, verr)
			}
			if !errors.Is(ferr, ErrTooLarge) {
				t.Errorf("%s: RecordsFit: %v", c.name, ferr)
			}
			continue
		}
		if verr != nil || ferr != nil {
			t.Errorf("%s: Validate %v, RecordsFit %v", c.name, verr, ferr)
		}
	}
}

// The count bound is exact: MaxSettings settings in all pass, one more does not.
func TestCountBoundIsExact(t *testing.T) {
	one, _ := bigSnapshot(t, 1, "1")
	var total int
	for _, sec := range one.Sections {
		total += len(sec.Settings)
	}
	other := total - 1 // the settings of every section but the one grown
	for _, tc := range []struct {
		all int
		ok  bool
	}{{MaxSettings, true}, {MaxSettings + 1, false}} {
		s, recs := bigSnapshot(t, tc.all-other, "1")
		if err := RecordsFit(recs); (err == nil) != tc.ok {
			t.Errorf("%d settings: RecordsFit %v", tc.all, err)
		}
		if err := s.Validate(); (err == nil) != tc.ok {
			t.Errorf("%d settings: Validate %v", tc.all, err)
		}
	}
}

// What RecordsFit passes, Validate passes: the adapter never reports an ok run
// whose snapshot the node would refuse for size. Checked on a grid around the
// byte bound, with the characters that cost most to encode.
func TestRecordsFitImpliesValidate(t *testing.T) {
	for _, ch := range []string{"V", `"`, `\`, "<", "&"} {
		for _, n := range []int{100, 2000, 5000, 9000, MaxSettings - 40} {
			lo, hi := 1, 600
			for lo < hi { // the longest value length that RecordsFit passes
				mid := (lo + hi + 1) / 2
				_, recs := bigSnapshot(t, n, strings.Repeat(ch, mid))
				if RecordsFit(recs) == nil {
					lo = mid
				} else {
					hi = mid - 1
				}
			}
			s, recs := bigSnapshot(t, n, strings.Repeat(ch, lo))
			if err := RecordsFit(recs); err != nil {
				continue // even one byte does not fit at this count
			}
			if err := s.Validate(); err != nil {
				t.Errorf("%d settings of %q x %d: RecordsFit passes, Validate: %v", n, ch, lo, err)
			}
		}
	}
}

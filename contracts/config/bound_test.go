package config

import (
	"os"
	"path/filepath"
	"testing"

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
// snapshotFixed and snapshotPerSetting are B5's measurement of the golden
// snapshot, encoded compact (5.3 KB fixed, 25 bytes of JSON and up to 16 of
// name per setting), and maxSettings is the count of names in the 24 forms on
// S22's settings sheets (contracts/register/testdata/count_settings.py).
const (
	snapshotFixed      = 5348
	snapshotPerSetting = 25 + 16
	maxSettings        = 8734
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
	if fixed := snapshotFixed + maxSettings*snapshotPerSetting; fixed != 363_442 {
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

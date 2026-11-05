package node

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
)

// A run's end is read before the run's status is written, so a harness that
// steps the test clock as soon as it sees the run in status cannot move the
// asset's quiet window past its step (C6 on #447). Here the scheduler's
// clock jumps an hour once status.json shows the run, as the harness's step
// would. Evidence class: simulated.
func TestRunEndIsTakenBeforeStatusIsWritten(t *testing.T) {
	c, dir := schedConfig(t, nil)
	r, _, _ := start(t, c, dir)
	defer r.Close()
	var seq uint64
	s := newScheduler(t, r, wireCollector(t, func(*authz.CollectorRequest) {}, &seq))
	statusPath := filepath.Join(dir, "status.json")
	if err := os.Remove(statusPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	after := before.Add(time.Hour)
	s.now = func() time.Time {
		if b, err := os.ReadFile(statusPath); err == nil && bytes.Contains(b, []byte(`"assets"`)) {
			return after
		}
		return before
	}
	rep, ended := s.runOnceEnded(bg, 0)
	if rep.Outcome != "ok" {
		t.Fatalf("run: %+v", rep)
	}
	if b, err := os.ReadFile(statusPath); err != nil || !bytes.Contains(b, []byte(`"assets"`)) {
		t.Fatalf("the run's result is not in status: %v", err)
	}
	if !ended.Equal(before) {
		t.Fatalf("the run ended at %v, after its status was written; want %v", ended, before)
	}
}

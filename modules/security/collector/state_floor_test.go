package collector

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/authz"
)

// breakWrites makes the next replace of path fail at its temporary file (a
// directory stands where the file would go) and returns the undo. The
// failure is the one a holder of the state file causes, in a form that
// needs no second process and works on every platform.
func breakWrites(t *testing.T, path string) (undo func()) {
	t.Helper()
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Remove(path + ".tmp"); err != nil {
			t.Fatal(err)
		}
	}
}

// A failed state write wraps the OS error with %w, so a caller or a test can
// name the cause, and still matches ErrStateUnavailable (A3's D4-3 item).
func TestStateWriteWrapsTheOSError(t *testing.T) {
	path, s, _ := newState(t)
	undo := breakWrites(t, path)
	defer undo()
	err := s.BeginAuth(testAsset)
	var pe *fs.PathError
	if !errors.Is(err, ErrStateUnavailable) || !errors.As(err, &pe) {
		t.Fatalf("BeginAuth with the replace failing: %v, want ErrStateUnavailable wrapping a *fs.PathError", err)
	}
}

// The credential store's write wraps it the same way.
func TestCredStoreWriteWrapsTheOSError(t *testing.T) {
	f := newCredStore(t)
	undo := breakWrites(t, f.path)
	defer undo()
	_, err := f.install(t, telnetRef("cred_slice0001", assetA, 1), canary)
	var pe *fs.PathError
	if !errors.Is(err, ErrStateUnavailable) || !errors.As(err, &pe) {
		t.Fatalf("Install with the replace failing: %v, want ErrStateUnavailable wrapping a *fs.PathError", err)
	}
}

// A session reached Level 1, the state broke at "=>", and the session ended
// without QUI. The floor on disk runs from ACC; FloorAfterBreak moves it to
// the session's end, so after a restart it still covers the relay's Level 1
// (D4-3, A3's floor-from-ACC finding).
func TestFloorAfterBreakRunsFromTheSessionEnd(t *testing.T) {
	path, s, c := newState(t)
	acc := c.t
	if err := s.BeginAuth(testAsset); err != nil {
		t.Fatal(err)
	}
	undo := breakWrites(t, path)
	c.t = acc.Add(20 * time.Second)
	if err := s.OpenLevel(testAsset); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("OpenLevel with the replace failing: %v", err)
	}
	// Broken, and BeginAuth cannot write the floor now.
	if err := s.BeginAuth(testAsset); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("BeginAuth on a broken state: %v", err)
	}
	undo()
	end := acc.Add(5 * time.Minute)
	c.t = end
	if err := s.FloorAfterBreak(testAsset); err != nil {
		t.Fatalf("FloorAfterBreak: %v", err)
	}
	// The break stands for this process.
	if err := s.CheckFloor(testAsset); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("CheckFloor after FloorAfterBreak: %v, want the break to stand", err)
	}
	floor := authz.FailureFloor(0) // TIDLE unknown: the longest floor
	re := func(at time.Time) error {
		c2 := &clock{t: at}
		s2, err := OpenState(path, c2.now)
		if err != nil {
			t.Fatal(err)
		}
		return s2.CheckFloor(testAsset)
	}
	// Past the floor counted from ACC, inside the floor from the session's end.
	if err := re(acc.Add(floor + time.Second)); !isRateLimited(err) {
		t.Fatalf("a restart after the ACC floor but inside the session-end floor: %v, want rate_limited", err)
	}
	if err := re(end.Add(floor + time.Second)); err != nil {
		t.Fatalf("a restart after the session-end floor: %v", err)
	}
}

// Without FloorAfterBreak the same sequence expires early: this is the gap
// the call closes, so the test above is not passing for another reason.
func TestFloorFromACCExpiresEarlierWithoutIt(t *testing.T) {
	path, s, c := newState(t)
	acc := c.t
	if err := s.BeginAuth(testAsset); err != nil {
		t.Fatal(err)
	}
	undo := breakWrites(t, path)
	defer undo()
	c.t = acc.Add(20 * time.Second)
	s.OpenLevel(testAsset)
	c2 := &clock{t: acc.Add(authz.FailureFloor(0) + time.Second)}
	s2, err := OpenState(path, c2.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.CheckFloor(testAsset); err != nil {
		t.Fatalf("expected the ACC floor to have passed: %v", err)
	}
}

// FloorAfterBreak changes only the asset's floor: the sequence number, other
// assets and their suspensions are as the disk held them.
func TestFloorAfterBreakChangesOnlyTheFloor(t *testing.T) {
	const other = "9f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f"
	path, s, c := newState(t)
	for i := 0; i < 3; i++ {
		if _, err := s.NextSeq(); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SuspendAsset(other, adapter.RefusedIdentityMismatch, "inv-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginAuth(testAsset); err != nil {
		t.Fatal(err)
	}
	undo := breakWrites(t, path)
	s.OpenLevel(testAsset)
	undo()
	c.t = c.t.Add(time.Minute)
	if err := s.FloorAfterBreak(testAsset); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.LastSeq(); got != 3 {
		t.Fatalf("collector_seq %d after FloorAfterBreak, want 3", got)
	}
	if err := s2.CheckSuspended(other); err == nil {
		t.Fatal("the other asset's suspension was lost")
	}
	if a := s2.doc.Assets[testAsset]; a.LevelOpen || a.UnconfirmedAuthUTC != c.t.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("asset state %+v, want a floor from %s and no open level", a, c.t.UTC().Format(time.RFC3339Nano))
	}
}

// A state file that is behind what this process handed out is not written
// over, and a state that is not broken is not given this path.
func TestFloorAfterBreakRefusals(t *testing.T) {
	path, s, c := newState(t)
	if err := s.FloorAfterBreak(testAsset); err == nil {
		t.Fatal("FloorAfterBreak on a state that is not broken")
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.NextSeq(); err != nil {
			t.Fatal(err)
		}
	}
	undo := breakWrites(t, path)
	s.BeginAuth(testAsset)
	undo()
	// Put the older file back: it is behind the 2 handed out.
	if err := ReplaceFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(time.Minute)
	if err := s.FloorAfterBreak(testAsset); err == nil {
		t.Fatal("FloorAfterBreak wrote over a file behind this process's sequence")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, old) {
		t.Fatal("the refused FloorAfterBreak changed the file")
	}
}

// The whole path: the relay confirms Level 1, the state write that records it
// fails, and the relay then hangs up before QUI. The pipeline moves the
// floor to the session's end rather than leaving the one from ACC, and the
// state stays broken (D4-3). The sabotage is removing the temporary file of
// the write that carries level_open, so the rename fails.
func TestPipelineSetsTheFloorAtTheSessionEndAfterABreak(t *testing.T) {
	f, l := hostedFixture(t)
	want := goldenResult(t, "failed.transport_closed")
	var brokeAt time.Time
	replaceHook = func(step string) {
		if step != stepWritten || !brokeAt.IsZero() {
			return
		}
		if b, err := os.ReadFile(f.state.path + ".tmp"); err == nil && bytes.Contains(b, []byte(`"level_open":true`)) {
			f.clock.t = f.clock.t.Add(10 * time.Minute) // the session runs on
			brokeAt = f.clock.t
			os.Remove(f.state.path + ".tmp")
		}
	}
	defer func() { replaceHook = nil }()
	// Not hostedRun: it checks the transcript against the records, and a
	// broken state hands out no sequence numbers for records.
	done := farEndOn(l, replayTurns(want), true)
	f.run(t, hostedReq("sel.ser.read_all", pipeCred))
	<-done
	if brokeAt.IsZero() {
		t.Fatal("the write that opens the level was never seen")
	}
	if err := f.state.CheckFloor(testAsset); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("state after the break: %v, want it to stay broken", err)
	}
	var opened, unclean bool
	for _, a := range f.alarmList() {
		opened = opened || errors.Is(a, ErrStateUnavailable)
		unclean = unclean || strings.Contains(a.Error(), "after unclean exit")
	}
	if !opened || unclean {
		t.Fatalf("alarms %v: want the failed write raised and no failure to set the floor after the exit", f.alarmList())
	}
	s2, err := OpenState(f.state.path, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := s2.doc.Assets[testAsset]
	at, perr := time.Parse(time.RFC3339Nano, a.UnconfirmedAuthUTC)
	if perr != nil || at.Before(brokeAt) || a.LevelOpen {
		t.Fatalf("floor on disk %+v: want a floor from the session's end (not before %s) and no open level", a, brokeAt.UTC().Format(time.RFC3339Nano))
	}
}

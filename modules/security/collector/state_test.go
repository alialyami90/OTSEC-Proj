package collector

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"otsec.local/otsec/contracts/authz"
)

const asset = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newState(t *testing.T) (string, *State, *clock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := InitState(path); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	s, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return path, s, c
}

func isRateLimited(err error) bool {
	var r *authz.Refusal
	return errors.As(err, &r) && r.Code == authz.RefuseRateLimited
}

func TestInitStateRefusesExisting(t *testing.T) {
	path, _, _ := newState(t)
	if err := InitState(path); err == nil {
		t.Fatal("InitState overwrote an existing state")
	}
}

// A missing, unreadable or malformed state is never replaced by a fresh one:
// that would reopen every floor and restart collector_seq.
func TestOpenStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"missing":        filepath.Join(dir, "absent.json"),
		"a directory":    dir,
		"empty":          write("empty.json", ""),
		"truncated":      write("trunc.json", `{"format":"otsec.collector-state/0.1","collector_seq":4,"ass`),
		"other format":   write("fmt.json", `{"format":"otsec.collector-state/9.0","collector_seq":4,"assets":{}}`),
		"unknown field":  write("unk.json", `{"format":"otsec.collector-state/0.1","collector_seq":4,"assets":{},"reset":true}`),
		"duplicate key":  write("dup.json", `{"format":"otsec.collector-state/0.1","collector_seq":4,"collector_seq":1,"assets":{}}`),
		"no assets":      write("noassets.json", `{"format":"otsec.collector-state/0.1","collector_seq":4}`),
		"bad time":       write("time.json", `{"format":"otsec.collector-state/0.1","collector_seq":4,"assets":{"a":{"unconfirmed_auth_utc":"yesterday"}}}`),
		"negative TIDLE": write("tidle.json", `{"format":"otsec.collector-state/0.1","collector_seq":4,"assets":{"a":{"tidle_seconds":-1}}}`),
	}
	for name, p := range cases {
		if _, err := OpenState(p, nil); !errors.Is(err, ErrStateUnavailable) {
			t.Errorf("%s: %v, want ErrStateUnavailable", name, err)
		}
	}
}

func TestSeqIsDurableAndNeverReused(t *testing.T) {
	path, s, _ := newState(t)
	for want := uint64(1); want <= 3; want++ {
		got, err := s.NextSeq()
		if err != nil || got != want {
			t.Fatalf("NextSeq = %d, %v; want %d", got, err, want)
		}
	}
	// A restart continues after the last number handed out.
	s2, err := OpenState(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s2.NextSeq(); err != nil || got != 4 {
		t.Fatalf("after restart NextSeq = %d, %v; want 4", got, err)
	}
}

// T-9 at the state layer: an unconfirmed authentication refuses the asset
// until the floor has passed; TIDLE shortens the floor; a clock stepped back
// does not reopen it.
func TestFailedAuthFloor(t *testing.T) {
	_, s, c := newState(t)
	if err := s.CheckFloor(asset); err != nil {
		t.Fatalf("fresh asset: %v", err)
	}
	if err := s.BeginAuth(asset); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, time.Minute, 30 * time.Minute, 31*time.Minute - time.Nanosecond} {
		c.t = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC).Add(d)
		if err := s.CheckFloor(asset); !isRateLimited(err) {
			t.Fatalf("%s after ACC with TIDLE unknown: %v, want rate_limited", d, err)
		}
	}
	c.t = time.Date(2026, 10, 24, 12, 31, 0, 0, time.UTC)
	if err := s.CheckFloor(asset); err != nil {
		t.Fatalf("31 minutes after ACC: %v", err)
	}
	c.t = time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC) // stepped back
	if err := s.CheckFloor(asset); !isRateLimited(err) {
		t.Fatalf("clock stepped back: %v, want rate_limited", err)
	}
	if err := s.SetTIDLE(asset, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	c.t = time.Date(2026, 10, 24, 12, 6, 0, 0, time.UTC)
	if err := s.CheckFloor(asset); err != nil {
		t.Fatalf("TIDLE 5 min, 6 min after ACC: %v", err)
	}
	c.t = time.Date(2026, 10, 24, 12, 5, 59, 0, time.UTC)
	if err := s.CheckFloor(asset); !isRateLimited(err) {
		t.Fatalf("TIDLE 5 min, 5:59 after ACC: %v", err)
	}
	// Other assets are unaffected; a confirmed login clears the floor.
	if err := s.CheckFloor("other-asset"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmAuth(asset); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckFloor(asset); err != nil {
		t.Fatalf("after confirm: %v", err)
	}
}

func TestTIDLEOutOfRangeIsUnknown(t *testing.T) {
	_, s, c := newState(t)
	s.BeginAuth(asset)
	for _, d := range []time.Duration{0, 30 * time.Second, 31 * time.Minute, -time.Minute} {
		if err := s.SetTIDLE(asset, d); err != nil {
			t.Fatal(err)
		}
		c.t = time.Date(2026, 10, 24, 12, 30, 0, 0, time.UTC)
		if err := s.CheckFloor(asset); !isRateLimited(err) {
			t.Fatalf("TIDLE %s: %v, want the 31-minute floor", d, err)
		}
	}
}

// T-9b at the state layer: the collector process is killed after ACC was
// recorded and before any confirmation. A new process reading the same file
// refuses the asset. The kill is real (the helper process exits without
// returning), so nothing but the file carries the state across.
func TestFloorSurvivesKill(t *testing.T) {
	if os.Getenv("OTSEC_STATE_HELPER") != "" {
		s, err := OpenState(os.Getenv("OTSEC_STATE_HELPER"), nil)
		if err != nil {
			os.Exit(3)
		}
		if err := s.BeginAuth(asset); err != nil {
			os.Exit(4)
		}
		p, _ := os.FindProcess(os.Getpid())
		p.Kill() // as a crash between ACC and "=>"
		select {}
	}
	path, _, _ := newState(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestFloorSurvivesKill$")
	cmd.Env = append(os.Environ(), "OTSEC_STATE_HELPER="+path)
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() == 3 || ee.ExitCode() == 4 {
		t.Fatalf("helper: %v", err)
	}
	s, err := OpenState(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckFloor(asset); !isRateLimited(err) {
		t.Fatalf("after a kill between ACC and confirmation: %v, want rate_limited", err)
	}
}

// A write that fails breaks the state: the in-memory copy may no longer
// match the disk, so nothing more is decided from it.
func TestFailedWriteBreaksState(t *testing.T) {
	path, s, _ := newState(t)
	if err := os.Mkdir(path+".tmp", 0o700); err != nil { // the temporary file cannot be created
		t.Fatal(err)
	}
	if err := s.BeginAuth(asset); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("BeginAuth: %v", err)
	}
	if _, err := s.NextSeq(); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("NextSeq after a failed write: %v", err)
	}
	if err := s.CheckFloor("other-asset"); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("CheckFloor after a failed write: %v", err)
	}
	if s.LastSeq() != 0 {
		t.Fatalf("seq advanced by a failed write: %d", s.LastSeq())
	}
}

func TestFloorGate(t *testing.T) {
	_, s, _ := newState(t)
	g := NewFloorGate(s, asset)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.BeforeACC(ctx); err == nil {
		t.Fatal("BeforeACC with a cancelled context")
	}
	if err := s.CheckFloor(asset); err != nil {
		t.Fatal("a refused BeforeACC set the floor")
	}
	if err := g.BeforeACC(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckFloor(asset); !isRateLimited(err) {
		t.Fatalf("after BeforeACC: %v", err)
	}
	g.Confirmed(context.Background())
	if err := s.CheckFloor(asset); err != nil {
		t.Fatalf("after Confirmed: %v", err)
	}
}

func TestFloorGateAlarmsOnFailedClear(t *testing.T) {
	path, s, c := newState(t)
	g := NewFloorGate(s, asset)
	var alarmed error
	g.Alarm = func(err error) { alarmed = err }
	if err := g.BeforeACC(context.Background()); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(path+".tmp", 0o700)
	g.Confirmed(context.Background())
	if !errors.Is(alarmed, ErrStateUnavailable) {
		t.Fatalf("alarm %v", alarmed)
	}
	// The floor stays set on disk: a restart still refuses the asset.
	os.Remove(path + ".tmp")
	s2, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.CheckFloor(asset); !isRateLimited(err) {
		t.Fatalf("after a failed clear and a restart: %v", err)
	}
}

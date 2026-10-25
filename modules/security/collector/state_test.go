package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
)

const testAsset = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newState(t *testing.T) (string, *State, *clock) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	// Created an hour ago, so the fresh state's own floor has passed.
	if err := InitState(path, c.t.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
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
	if err := InitState(path, time.Now()); err == nil {
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
		"bad last run":   write("run.json", `{"format":"otsec.collector-state/0.1","collector_seq":4,"assets":{"a":{"last_run_utc":"soon"}}}`),
		"bad floor hash": write("fam.json", `{"format":"otsec.collector-state/0.1","collector_seq":4,"assets":{},"families":{"sel-751":{"revision":2,"payload_sha256":"ABCD"}}}`),
		"bad install":    write("inst.json", `{"format":"otsec.collector-state/0.1","collector_seq":4,"assets":{},"installs":["x"]}`),
	}
	for name, p := range cases {
		if _, err := OpenState(p, nil); !errors.Is(err, ErrStateUnavailable) {
			t.Errorf("%s: %v, want ErrStateUnavailable", name, err)
		}
	}
}

// A stored suspension is checked when the state is opened: a reason without
// its invocation, an invocation without a reason, or an unknown reason
// makes the state unavailable (A6 nit on #106).
func TestOpenStateChecksSuspension(t *testing.T) {
	path, s, _ := newState(t)
	if err := s.SuspendAsset(testAsset, adapter.FailedUnexpectedLevel, "inv-1"); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(path, nil); err != nil {
		t.Fatalf("a valid suspension: %v", err)
	}
	for name, edit := range map[string]func(a map[string]any){
		"no invocation":                 func(a map[string]any) { delete(a, "suspended_by") },
		"no reason":                     func(a map[string]any) { delete(a, "suspended") },
		"unknown reason":                func(a map[string]any) { a["suspended"] = "made-up" },
		"code that sets another reason": func(a map[string]any) { a["suspended_code"] = string(adapter.FailedAuthRejected) },
		"code with no suspension": func(a map[string]any) {
			delete(a, "suspended")
			delete(a, "suspended_by")
		},
	} {
		var doc map[string]any
		if err := json.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		edit(doc["assets"].(map[string]any)[testAsset].(map[string]any))
		b, _ := json.Marshal(doc)
		p := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenState(p, nil); !errors.Is(err, ErrStateUnavailable) {
			t.Errorf("%s: %v, want ErrStateUnavailable", name, err)
		}
	}
	// A state written before codes were kept opens, and names the held
	// suspension without a code, which the node does not adopt (A1 on #125).
	var doc map[string]any
	if err := json.Unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc["assets"].(map[string]any)[testAsset].(map[string]any), "suspended_code")
	b, _ := json.Marshal(doc)
	p := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := OpenState(p, nil)
	if err != nil {
		t.Fatalf("a state without codes: %v", err)
	}
	if err := old.CheckSuspended(testAsset); codeOf(err) != authz.RefuseAssetSuspended ||
		*err.(*authz.Refusal).Suspension != (authz.HeldSuspension{Reason: asset.SuspendUnexpectedLevel, Ref: "inv-1"}) {
		t.Fatalf("a state without codes: %v", err)
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

// T-9 at the state layer: an unconfirmed authentication refuses the testAsset
// until the floor has passed; TIDLE shortens the floor; a clock stepped back
// does not reopen it.
func TestFailedAuthFloor(t *testing.T) {
	_, s, c := newState(t)
	if err := s.CheckFloor(testAsset); err != nil {
		t.Fatalf("fresh asset: %v", err)
	}
	if err := s.BeginAuth(testAsset); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, time.Minute, 30 * time.Minute, 31*time.Minute - time.Nanosecond} {
		c.t = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC).Add(d)
		if err := s.CheckFloor(testAsset); !isRateLimited(err) {
			t.Fatalf("%s after ACC with TIDLE unknown: %v, want rate_limited", d, err)
		}
	}
	c.t = time.Date(2026, 10, 24, 12, 31, 0, 0, time.UTC)
	if err := s.CheckFloor(testAsset); err != nil {
		t.Fatalf("31 minutes after ACC: %v", err)
	}
	c.t = time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC) // stepped back
	if err := s.CheckFloor(testAsset); !isRateLimited(err) {
		t.Fatalf("clock stepped back: %v, want rate_limited", err)
	}
	if err := s.SetTIDLE(testAsset, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	c.t = time.Date(2026, 10, 24, 12, 6, 0, 0, time.UTC)
	if err := s.CheckFloor(testAsset); err != nil {
		t.Fatalf("TIDLE 5 min, 6 min after ACC: %v", err)
	}
	c.t = time.Date(2026, 10, 24, 12, 5, 59, 0, time.UTC)
	if err := s.CheckFloor(testAsset); !isRateLimited(err) {
		t.Fatalf("TIDLE 5 min, 5:59 after ACC: %v", err)
	}
	// Other assets are unaffected; a confirmed login clears the floor.
	if err := s.CheckFloor("other-testAsset"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfirmAuth(testAsset); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckFloor(testAsset); err != nil {
		t.Fatalf("after confirm: %v", err)
	}
}

func TestTIDLEOutOfRangeIsUnknown(t *testing.T) {
	_, s, c := newState(t)
	s.BeginAuth(testAsset)
	for _, d := range []time.Duration{0, 30 * time.Second, 31 * time.Minute, -time.Minute} {
		if err := s.SetTIDLE(testAsset, d); err != nil {
			t.Fatal(err)
		}
		c.t = time.Date(2026, 10, 24, 12, 30, 0, 0, time.UTC)
		if err := s.CheckFloor(testAsset); !isRateLimited(err) {
			t.Fatalf("TIDLE %s: %v, want the 31-minute floor", d, err)
		}
	}
}

// T-9b at the state layer: the collector process is killed after ACC was
// recorded and before any confirmation. A new process reading the same file
// refuses the testAsset. The kill is real (the helper process exits without
// returning), so nothing but the file carries the state across.
func TestFloorSurvivesKill(t *testing.T) {
	if os.Getenv("OTSEC_STATE_HELPER") != "" {
		s, err := OpenState(os.Getenv("OTSEC_STATE_HELPER"), nil)
		if err != nil {
			os.Exit(3)
		}
		if err := s.BeginAuth(testAsset); err != nil {
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
	if err := s.CheckFloor(testAsset); !isRateLimited(err) {
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
	if err := s.BeginAuth(testAsset); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("BeginAuth: %v", err)
	}
	if _, err := s.NextSeq(); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("NextSeq after a failed write: %v", err)
	}
	if err := s.CheckFloor("other-testAsset"); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("CheckFloor after a failed write: %v", err)
	}
	if s.LastSeq() != 0 {
		t.Fatalf("seq advanced by a failed write: %d", s.LastSeq())
	}
}

func TestFloorGate(t *testing.T) {
	_, s, _ := newState(t)
	g := NewFloorGate(s, testAsset)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.BeforeACC(ctx); err == nil {
		t.Fatal("BeforeACC with a cancelled context")
	}
	if err := s.CheckFloor(testAsset); err != nil {
		t.Fatal("a refused BeforeACC set the floor")
	}
	if err := g.BeforeACC(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckFloor(testAsset); !isRateLimited(err) {
		t.Fatalf("after BeforeACC: %v", err)
	}
	g.Confirmed(context.Background())
	if err := s.CheckFloor(testAsset); err != nil {
		t.Fatalf("after Confirmed: %v", err)
	}
}

func TestFloorGateAlarmsOnFailedClear(t *testing.T) {
	path, s, c := newState(t)
	g := NewFloorGate(s, testAsset)
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
	// The floor stays set on disk: a restart still refuses the testAsset.
	os.Remove(path + ".tmp")
	s2, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.CheckFloor(testAsset); !isRateLimited(err) {
		t.Fatalf("after a failed clear and a restart: %v", err)
	}
}

func TestMinimumInterval(t *testing.T) {
	_, s, c := newState(t)
	if err := s.CheckInterval(testAsset, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginRun(testAsset); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckInterval(testAsset, time.Minute); !isRateLimited(err) {
		t.Fatalf("inside the interval: %v", err)
	}
	c.t = c.t.Add(time.Minute)
	if err := s.CheckInterval(testAsset, time.Minute); err != nil {
		t.Fatalf("after the interval: %v", err)
	}
	c.t = c.t.Add(-time.Hour) // the clock went back
	if err := s.CheckInterval(testAsset, time.Minute); !isRateLimited(err) {
		t.Fatalf("a run in the future counts as recent: %v", err)
	}
}

func TestInstallBudget(t *testing.T) {
	path, s, c := newState(t)
	for i := 0; i < 3; i++ {
		if err := s.TakeInstall(3, time.Hour); err != nil {
			t.Fatal(err)
		}
		c.t = c.t.Add(time.Minute)
	}
	if err := s.TakeInstall(3, time.Hour); !isRateLimited(err) {
		t.Fatalf("fourth install: %v", err)
	}
	// The budget survives a restart.
	again, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.TakeInstall(3, time.Hour); !isRateLimited(err) {
		t.Fatalf("budget reset by a restart: %v", err)
	}
	c.t = c.t.Add(58 * time.Minute) // the first install leaves the window
	if err := again.TakeInstall(3, time.Hour); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func TestFamilyFloorDurable(t *testing.T) {
	path, s, c := newState(t)
	f := authz.FamilyFloor{Revision: 7}
	f.PayloadSHA256[0] = 0xab
	if err := s.SetFamilyFloor("sel-751", f); err != nil {
		t.Fatal(err)
	}
	again, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.FamilyFloors()["sel-751"]; got != f {
		t.Fatalf("floor %+v, want %+v", got, f)
	}
}

// A fresh state does not know what the previous one held, so every asset is
// inside the longest floor from its creation: a reinstall never shortens a
// floor (A1, collector_seq reset).
func TestFreshStateFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	c := &clock{t: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	if err := InitState(path, c.t); err != nil {
		t.Fatal(err)
	}
	s, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{0, 30*time.Minute + 59*time.Second} {
		c.t = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC).Add(d)
		if err := s.CheckFloor(testAsset); !isRateLimited(err) {
			t.Fatalf("fresh state at +%s: %v", d, err)
		}
	}
	c.t = time.Date(2026, 10, 24, 12, 31, 0, 0, time.UTC)
	if err := s.CheckFloor(testAsset); err != nil {
		t.Fatalf("after the floor: %v", err)
	}
	// A clock set back before the creation is inside the floor.
	c.t = time.Date(2026, 10, 24, 11, 0, 0, 0, time.UTC)
	if err := s.CheckFloor(testAsset); !isRateLimited(err) {
		t.Fatalf("clock before creation: %v", err)
	}
}

func TestStateWithoutCreationRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"format":"otsec.collector-state/0.1","collector_seq":0,"assets":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(path, nil); !errors.Is(err, ErrStateUnavailable) {
		t.Fatalf("state without created_utc: %v", err)
	}
}

func TestAssetSuspension(t *testing.T) {
	path, s, c := newState(t)
	if err := s.CheckSuspended(testAsset); err != nil {
		t.Fatal(err)
	}
	if err := s.SuspendAsset(testAsset, adapter.Code("refused.made_up"), "inv-1"); err == nil {
		t.Fatal("an unknown reason was recorded")
	}
	if err := s.SuspendAsset(testAsset, adapter.FailedUnexpectedLevel, ""); err == nil {
		t.Fatal("a suspension without its invocation was recorded")
	}
	if err := s.SuspendAsset(testAsset, adapter.FailedUnexpectedLevel, "inv-1"); err != nil {
		t.Fatal(err)
	}
	// A later reason does not replace the first, except identity-mismatch.
	if err := s.SuspendAsset(testAsset, adapter.RefusedLanguageNotEnglish, "inv-2"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSuspended(testAsset); codeOf(err) != authz.RefuseAssetSuspended || !strings.Contains(err.Error(), "unexpected-access-level") ||
		*err.(*authz.Refusal).Suspension != (authz.HeldSuspension{Reason: asset.SuspendUnexpectedLevel, Ref: "inv-1", Code: string(adapter.FailedUnexpectedLevel)}) {
		t.Fatalf("suspended asset: %v", err)
	}
	if err := s.SuspendAsset(testAsset, adapter.RefusedIdentityMismatch, "inv-3"); err != nil {
		t.Fatal(err)
	}
	// Durable.
	again, err := OpenState(path, c.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.CheckSuspended(testAsset); !strings.Contains(fmt.Sprint(err), "identity-mismatch") || !strings.Contains(err.Error(), "inv-3") ||
		err.(*authz.Refusal).Suspension.Code != string(adapter.RefusedIdentityMismatch) {
		t.Fatalf("after reopening: %v", err)
	}
	if err := again.CheckSuspended("another-asset"); err != nil {
		t.Fatalf("another asset: %v", err)
	}
}

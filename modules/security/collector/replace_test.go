package collector

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The process is killed at each step of ReplaceFile: after the temporary
// file is flushed, after the rename, and after the directory flush. A new
// process opening the state finds either the old doc or the new one, whole,
// and opens it. The kill is real, so only the file carries anything across.
//
// Evidence: process kill on the CI runner (Linux and the hosted Windows
// runner); power-loss durability is not shown.
func TestReplaceSurvivesKillAtEachStep(t *testing.T) {
	if step := os.Getenv("OTSEC_REPLACE_STEP"); step != "" {
		s, err := OpenState(os.Getenv("OTSEC_REPLACE_PATH"), nil)
		if err != nil {
			os.Exit(3)
		}
		replaceHook = func(at string) {
			if at == step {
				p, _ := os.FindProcess(os.Getpid())
				p.Kill()
				select {}
			}
		}
		s.BeginAuth(testAsset)
		os.Exit(4) // the hook did not fire
	}
	for _, step := range []string{stepWritten, stepRenamed, stepFlushed} {
		t.Run(step, func(t *testing.T) {
			path, _, _ := newState(t)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestReplaceSurvivesKillAtEachStep$")
			cmd.Env = append(os.Environ(), "OTSEC_REPLACE_STEP="+step, "OTSEC_REPLACE_PATH="+path)
			err = cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() == 3 || ee.ExitCode() == 4 {
				t.Fatalf("helper: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			s, err := OpenState(path, nil)
			if err != nil {
				t.Fatalf("state after a kill at %s: %v", step, err)
			}
			floorSet := s.CheckFloor(testAsset) != nil
			switch step {
			case stepWritten:
				if !bytes.Equal(before, after) || floorSet {
					t.Fatalf("killed before the rename, but state.json changed (floor set %v)", floorSet)
				}
			default:
				if bytes.Equal(before, after) || !floorSet {
					t.Fatalf("killed after the rename, but state.json holds the old doc (floor set %v)", floorSet)
				}
			}
		})
	}
}

// A state write that takes longer than a step's timeout, at every write of
// a run (BeginAuth before ACC, OpenLevel at "=>", NextSeq, EndAuth), leaves
// a Level 1 run's result and records unchanged: the adapter arms each
// step's timeout at its send, after the write, so a slow write costs only
// the run's DeadlineMS (A3 on #221, question 4). The step timeout here is
// below the delay, so arming before a write would fail the run (B6 on
// #257); the delay is also above the rename's 500 ms retry budget on
// Windows.
func TestSlowStateWriteStaysInsideTheRun(t *testing.T) {
	// The step timeout stays above the adapter's 1 s wake wait, which the
	// golden's silent connect needs.
	const slow = 1500 * time.Millisecond
	limits := DefaultLimits
	limits.StepTimeoutMS = 1200
	f, l := hostedFixture(t, func(c *PipelineConfig, _ *pipeFixture) { c.Limits = limits })
	want := goldenResult(t, "ok")
	replaceHook = func(step string) {
		if step == stepWritten {
			time.Sleep(slow)
		}
	}
	defer func() { replaceHook = nil }()
	start := time.Now()
	_, res, recs, _ := hostedRun(t, f, l, hostedReq("sel.ser.read_all", pipeCred), replayTurns(want), false)
	took := time.Since(start)
	if resultCode(res) != "" || res.Transcript.SHA256 != want.Transcript.SHA256 {
		t.Fatalf("result %s (transcript %s), want ok (%s)", resultCode(res), res.Transcript.SHA256, want.Transcript.SHA256)
	}
	if got, want := shape(recs), "device.session.open/succeeded credential.use/succeeded device.posture_warning/warning/maxacc_above_1 device.op/succeeded device.session.close/succeeded"; got != want {
		t.Fatalf("records\n got %s\nwant %s", got, want)
	}
	if a := f.alarmList(); len(a) != 0 {
		t.Fatalf("alarms: %v", a)
	}
	if err := f.state.CheckFloor(testAsset); err != nil {
		t.Fatalf("floor after QUI: %v", err)
	}
	if took < 2*slow {
		t.Fatalf("the run took %s: the state writes were not delayed", took)
	}
	if limit := time.Duration(limits.DeadlineMS) * time.Millisecond; took >= limit {
		t.Fatalf("the run took %s, beyond its deadline %s", took, limit)
	}
	t.Logf("run with every state write delayed %s and a %d ms step timeout took %s", slow, limits.StepTimeoutMS, took)
}

// ReplaceFile replaces the file whole each time and leaves no temporary
// file behind.
func TestReplaceFileWritesWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	for _, b := range [][]byte{[]byte("one"), []byte("two, longer"), []byte("3")} {
		if err := ReplaceFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("read %q, %v; want %q", got, err, b)
		}
	}
	if _, err := os.Stat(path + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".tmp left after a successful replace: %v", err)
	}
}

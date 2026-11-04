package security

// D4-40 point 4 (V-M4): the stepped test clock lives behind the build tag
// otsec_testclock, so a build without the tag cannot be driven by it. For
// both binaries, a release build (no tag) must refuse the clock's control,
// -test-clock, as an unknown flag (exit 2) and hold none of the clock's
// code. The tagged build is the control: it takes the flag, refuses a clock
// file it cannot read (exit 1), and holds the code, so neither check is
// vacuous. Ground truth: D4-40's text. Evidence class: simulated (the
// binaries are built and run here; nothing else is contacted).

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type clockBinary struct {
	pkg  string
	args func(clock, dir string) []string
	// marker is in the clock's code only: its stderr prefix.
	marker string
}

var clockBinaries = []clockBinary{
	{"./cmd/otsec", func(clock, dir string) []string {
		return []string{"node", "-test-clock", clock, "-config", filepath.Join(dir, "node.json")}
	}, "otsec test clock: "},
	{"./cmd/otsec-collector", func(clock, dir string) []string {
		return []string{"run", "-test-clock", clock, "-data", dir}
	}, "otsec-collector test clock: "},
}

// buildBinary builds pkg from the module root, with tags if any, and returns
// the binary's path.
func buildBinary(t *testing.T, pkg string, tags ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), filepath.Base(pkg))
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	args := []string{"build", "-o", out}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	cmd := exec.Command("go", append(args, pkg)...)
	cmd.Dir = filepath.Join("..", "..")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(cmd.Args[1:], " "), err, b)
	}
	return out
}

func runBinary(t *testing.T, bin string, args []string) (int, string) {
	t.Helper()
	var stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return 0, stderr.String()
	}
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("%s: %v", bin, err)
	}
	return ee.ExitCode(), stderr.String()
}

// The clock's files are compiled only with the tag: in a release build no
// package holds them, not only no binary.
func TestC6TestClockFilesAreTagged(t *testing.T) {
	for _, pkg := range []string{"./platform/node", "./cmd/otsec", "./cmd/otsec-collector"} {
		list := func(tags ...string) []string {
			args := []string{"list", "-f", "{{join .GoFiles \" \"}}"}
			if len(tags) > 0 {
				args = append(args, "-tags", strings.Join(tags, ","))
			}
			cmd := exec.Command("go", append(args, pkg)...)
			cmd.Dir = filepath.Join("..", "..")
			b, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list %s: %v", pkg, err)
			}
			return strings.Fields(string(b))
		}
		if slices.Contains(list(), "testclock.go") {
			t.Errorf("%s compiles testclock.go without the tag", pkg)
		}
		if !slices.Contains(list("otsec_testclock"), "testclock.go") {
			t.Errorf("%s has no testclock.go with the tag, so the check above proves nothing", pkg)
		}
	}
}

// CI runs the tagged tests with -run TestTestClock (ci.yml, "test clock
// (C6)"), so a tagged test whose name the pattern does not match would never
// run (C1). Every test that only the tagged build has must start with it.
func TestC6TaggedTestsMatchTheCIPattern(t *testing.T) {
	list := func(pkg string, tags ...string) map[string]bool {
		args := []string{"test", "-list", "."}
		if len(tags) > 0 {
			args = append(args, "-tags", strings.Join(tags, ","))
		}
		cmd := exec.Command("go", append(args, pkg)...)
		cmd.Dir = filepath.Join("..", "..")
		b, err := cmd.Output()
		if err != nil {
			t.Fatalf("go test -list %s: %v", pkg, err)
		}
		out := map[string]bool{}
		for _, l := range strings.Fields(string(b)) {
			if strings.HasPrefix(l, "Test") {
				out[l] = true
			}
		}
		return out
	}
	tagged := 0
	for _, pkg := range []string{"./platform/node", "./cmd/otsec", "./cmd/otsec-collector"} {
		release := list(pkg)
		for name := range list(pkg, "otsec_testclock") {
			if release[name] {
				continue
			}
			tagged++
			if !strings.HasPrefix(name, "TestTestClock") {
				t.Errorf("%s: tagged test %s does not match -run TestTestClock, so CI never runs it", pkg, name)
			}
		}
	}
	if tagged == 0 {
		t.Error("no tagged tests found, so the check proves nothing")
	}
}

func TestC6ReleaseBuildsRefuseTheTestClock(t *testing.T) {
	for _, b := range clockBinaries {
		t.Run(filepath.Base(b.pkg), func(t *testing.T) {
			dir := t.TempDir()
			clock := filepath.Join(dir, "no-such-clock")

			release := buildBinary(t, b.pkg)
			code, stderr := runBinary(t, release, b.args(clock, dir))
			if code != 2 || !strings.Contains(stderr, "flag provided but not defined: -test-clock") {
				t.Fatalf("release build with -test-clock: exit %d, stderr %q; want exit 2 and the flag unknown", code, stderr)
			}
			bin, err := os.ReadFile(release)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(bin, []byte(b.marker)) {
				t.Fatalf("the release build holds the test clock's code (%q)", b.marker)
			}

			tagged := buildBinary(t, b.pkg, "otsec_testclock")
			code, stderr = runBinary(t, tagged, b.args(clock, dir))
			if code != 1 || !strings.Contains(stderr, "test clock: ") {
				t.Fatalf("tagged build with an unreadable clock: exit %d, stderr %q; want exit 1 and the clock's error", code, stderr)
			}
			if bin, err = os.ReadFile(tagged); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(bin, []byte(b.marker)) {
				t.Fatalf("the tagged build does not hold %q, so the release check proves nothing", b.marker)
			}
		})
	}
}

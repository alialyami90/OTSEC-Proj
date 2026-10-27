package nodekey

import (
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestCNGPointersEscape compiles cng_windows.go for Windows with the
// compiler's escape report and checks what call's go:uintptrescapes
// promises: every buffer and out-parameter whose address is passed to
// NCrypt lives on the heap, so a goroutine stack that grows inside call
// cannot move it while NCrypt writes it (#199's Windows job). It runs on
// any OS; TestCNGStackMoves exercises the same calls on Windows but did
// not fail there without the fix, so this check is the deterministic one.
func TestCNGPointersEscape(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the package")
	}
	cmd := exec.Command("go", "build", "-gcflags=-m", ".")
	cmd.Env = append(cmd.Environ(), "GOOS=windows", "GOARCH=amd64")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	var stack []string
	heap := map[string]bool{}
	moved := regexp.MustCompile(`moved to heap: (\w+)$`)
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(l, "cng_windows.go:") {
			continue
		}
		if strings.Contains(l, "make([]byte") && strings.HasSuffix(l, "does not escape") {
			stack = append(stack, l)
		}
		if m := moved.FindStringSubmatch(l); m != nil {
			heap[m[1]] = true
		}
	}
	if len(stack) > 0 {
		t.Errorf("buffers passed to NCrypt stay on the stack:\n%s", strings.Join(stack, "\n"))
	}
	// The out-parameters whose addresses go to NCrypt.
	var missing []string
	for _, v := range []string{"h", "key", "n", "policy"} {
		if !heap[v] {
			missing = append(missing, v)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("out-parameters passed to NCrypt not moved to the heap: %v", missing)
	}
}

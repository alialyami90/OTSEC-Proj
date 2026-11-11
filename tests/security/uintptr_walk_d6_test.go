package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The rule for a test that walks the repository tree (brief P4-PC-1): a
// directory below the walk's root that holds a go.mod is another module, as
// the go command has it, and the walk does not enter it. Everything else
// below the root is the module's and is read, and a directory that cannot
// be read is an error.
//
// TestD6UintptrWalkStaysInTheModule runs the uintptr walker on a module
// built in a temporary directory. The same breach of the rule is planted
// three times: in the module, in a nested module, and in a directory of the
// nested module that cannot be read. Only the first may be reported, and
// the walk may not fail. The control then deletes the nested go.mod: the
// walk must fail on the unreadable directory, and once that is readable it
// must report all three, so the first result came from the go.mod and from
// nothing else. Evidence class: desk (a source rule on a built tree), any OS.
func TestD6UintptrWalkStaysInTheModule(t *testing.T) {
	const breach = "package p\n\nimport \"unsafe\"\n\nfunc f(b *byte) uintptr { return uintptr(unsafe.Pointer(b)) }\n"
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.test/m\n")
	write("in/breach.go", breach)
	write("other/go.mod", "module example.test/other\n")
	write("other/breach.go", breach)
	write("other/closed/breach.go", breach)

	closed := filepath.Join(root, "other", "closed")
	reopen := makeUnreadable(t, closed)
	_, readErr := os.ReadDir(closed)
	unreadable := readErr != nil

	walk := func() ([]string, error) {
		var reports []string
		_, _, err := checkUintptrConversions(root, func(format string, args ...any) {
			reports = append(reports, filepath.ToSlash(fmt.Sprintf(format, args...)))
		})
		return reports, err
	}
	names := func(reports []string) string { return strings.Join(reports, "\n") }

	got, err := walk()
	if err != nil {
		t.Fatalf("the walk failed inside a nested module: %v", err)
	}
	if len(got) != 1 || !strings.Contains(got[0], "/in/breach.go:") {
		t.Fatalf("with a nested module, want the one breach in in/breach.go, got %d:\n%s", len(got), names(got))
	}

	// The control: without its go.mod, other/ is the module's own.
	if err := os.Remove(filepath.Join(root, "other", "go.mod")); err != nil {
		t.Fatal(err)
	}
	if unreadable {
		if got, err := walk(); err == nil {
			t.Fatalf("the walk passed over a directory of the module that it cannot read; it reported:\n%s", names(got))
		}
	}
	reopen()
	got, err = walk()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("without the nested go.mod, want the three breaches, got %d:\n%s", len(got), names(got))
	}
	if !unreadable {
		t.Skip("the go.mod legs passed; the unreadable-directory legs did not run, because this process can read a directory closed to it (root?)")
	}
}

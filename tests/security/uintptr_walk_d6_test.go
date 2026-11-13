package security

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The rule for a test that walks the repository tree (brief P4-PC-1): a
// directory below the walk's root that holds a go.mod file is another
// module, as the go command has it, and the walk does not enter it. Nothing
// else is skipped for being unlike the module: not a directory with a
// familiar name, and not one the walk cannot read. That one is an error.
//
// TestD6UintptrWalkStaysInTheModule runs the uintptr walker on modules built
// in a temporary directory, with the same breach of the uintptr rule planted
// in each place the rule has to tell apart. Evidence class: desk (a source
// rule on a built tree), any OS.
func TestD6UintptrWalkStaysInTheModule(t *testing.T) {
	const breach = "package p\n\nimport \"unsafe\"\n\nfunc f(b *byte) uintptr { return uintptr(unsafe.Pointer(b)) }\n"
	// module builds a module with a breach in each of the named directories
	// and the given other files.
	module := func(t *testing.T, breaches []string, others map[string]string) string {
		t.Helper()
		root := t.TempDir()
		write := func(rel, content string) {
			p := filepath.Join(root, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write("go.mod", "module example.test/m\n")
		for _, dir := range breaches {
			write(dir+"/breach.go", breach)
		}
		for rel, content := range others {
			write(rel, content)
		}
		return root
	}
	// walk returns the directories, relative to root, that hold a reported
	// breach.
	walk := func(root string) ([]string, error) {
		var dirs []string
		_, _, err := checkUintptrConversions(root, func(format string, args ...any) {
			file, _, _ := strings.Cut(fmt.Sprintf(format, args...), ".go:")
			rel, _ := filepath.Rel(root, filepath.Dir(file))
			dirs = append(dirs, filepath.ToSlash(rel))
		})
		slices.Sort(dirs)
		return dirs, err
	}
	// closed makes dir unreadable, and skips the test where it cannot.
	closed := func(t *testing.T, dir string) (reopen func()) {
		t.Helper()
		reopen = makeUnreadable(t, dir)
		if _, err := os.ReadDir(dir); err == nil {
			t.Skip("this process can read a directory closed to it (root?), so this leg proves nothing here")
		}
		return reopen
	}

	// Another module is not entered, and not read: the breach in it is not
	// reported, and a directory in it that cannot be read does not fail the
	// walk. The control deletes its go.mod, which makes it the module's own:
	// the walk must then fail, and report all three once it can read them.
	t.Run("another module is not entered", func(t *testing.T) {
		root := module(t, []string{"in", "other", "other/closed"}, map[string]string{"other/go.mod": "module example.test/other\n"})
		reopen := closed(t, filepath.Join(root, "other", "closed"))
		got, err := walk(root)
		if err != nil {
			t.Fatalf("the walk failed inside another module: %v", err)
		}
		if want := []string{"in"}; !slices.Equal(got, want) {
			t.Fatalf("breaches reported in %q, want %q", got, want)
		}
		if err := os.Remove(filepath.Join(root, "other", "go.mod")); err != nil {
			t.Fatal(err)
		}
		if got, err := walk(root); err == nil {
			t.Fatalf("without its go.mod the directory is the module's, and the walk passed over the part it cannot read; breaches reported in %q", got)
		}
		reopen()
		got, err = walk(root)
		if want := []string{"in", "other", "other/closed"}; err != nil || !slices.Equal(got, want) {
			t.Fatalf("without the go.mod: breaches reported in %q (%v), want %q", got, err, want)
		}
	})

	// The rule is anchored at the root the walk starts from: the root's own
	// go.mod does not close it, and below it only a go.mod file closes a
	// directory. A directory deeper in the module that looks like a closed
	// one is read: one with the name of the other module, or of a local
	// folder of the owner's PC; one that holds a directory named go.mod, or
	// a file whose name only starts with it; one named testdata, .git or
	// node_modules; and platform/experiments, whose phase0 module is closed
	// by its own go.mod.
	t.Run("only a go.mod file closes a directory", func(t *testing.T) {
		in := []string{".", "in/other", "in/reference", "in/tools", "in/.claude/worktrees/w", "in/dir", "in/dir/go.mod", "in/near",
			"in/testdata", "in/.git", "in/node_modules", "platform/experiments"}
		root := module(t, append([]string{"other"}, in...), map[string]string{
			"other/go.mod":        "module example.test/other\n",
			"in/near/go.mod.orig": "module example.test/near\n",
			"in/near/go.model":    "module example.test/near\n",
		})
		got, err := walk(root)
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(in)
		if !slices.Equal(got, in) {
			t.Fatalf("breaches reported in %q, want %q", got, in)
		}
	})

	// A directory of the module that cannot be read fails the walk, wherever
	// it is and whatever it is called: a walker never passes because it
	// could not look.
	for _, dir := range []string{"in/closed", "reference", "in/deep/tools"} {
		t.Run("an unreadable "+dir+" fails the walk", func(t *testing.T) {
			root := module(t, []string{"in", dir}, nil)
			closed(t, filepath.Join(root, filepath.FromSlash(dir)))
			if got, err := walk(root); err == nil {
				t.Fatalf("the walk passed over a directory of the module that it cannot read; breaches reported in %q", got)
			}
		})
	}
}

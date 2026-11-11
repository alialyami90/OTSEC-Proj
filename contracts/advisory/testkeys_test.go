package advisory_test

import (
	"crypto/ed25519"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
)

// TestTestKeyIDsAreTheSeeds holds the release build's refusal list to the one
// source of test keys (1.6).
func TestTestKeyIDsAreTheSeeds(t *testing.T) {
	var ids []string
	for i := range advisorytest.Seeds {
		ids = append(ids, advisory.KeyID(advisorytest.Key(i).Public().(ed25519.PublicKey)))
	}
	if !slices.Equal(ids, advisory.TestKeyIDs) {
		t.Fatalf("TestKeyIDs %q, but the seeds give %q", advisory.TestKeyIDs, ids)
	}
}

// TestNoOtherAdvisoryTestKey is 1.6's scan. A Go or Python file anywhere in
// the repository that signs an advisory set must take its key from
// advisorytest. One that also builds a key from a seed, generates one from a
// fixed reader, or holds a private-key literal fails the test, because such a
// key is public and TestKeyIDs would not name it. What it cannot catch is a
// key made outside these conventions on purpose; that is HR-18's custody.
//
// The repository is this module and the nested modules it tracks (ownModules).
// Any other directory below the root that holds a go.mod file is another
// module, as the go command has it, and the scan does not enter it: a
// worktree's copy of the repository, or a local folder that Git ignores (brief
// P4-PC-1). A CI runner's checkout holds the repository and nothing else, so
// there such a directory fails the test: a go.mod cannot take tracked files
// out of the scan unseen.
func TestNoOtherAdvisoryTestKey(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	signs := regexp.MustCompile(`otsec\.advisory/0 set|advisory\.SigningInput\(|advisorytest\.Sign\(`)
	fixedKey := regexp.MustCompile(`NewKeyFromSeed|ed25519\.GenerateKey\((?:[^n)]|n[^i]|ni[^l])[^)]*\)|from_private_bytes|SigningKey\(|PRIVATE KEY-----`)
	allowed := map[string]bool{
		filepath.Join(root, "contracts", "advisory", "advisorytest", "advisorytest.go"): true,
		filepath.Join(root, "contracts", "advisory", "testkeys_test.go"):                true,
	}
	ownModules := map[string]bool{
		filepath.Join(root, "platform", "experiments", "phase0"):                                               true,
		filepath.Join(root, "tests", "contract", "testdata", "imports", "bad", "platform", "experiments", "x"): true,
	}
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			if path != root && !ownModules[path] {
				if fi, err := os.Stat(filepath.Join(path, "go.mod")); err == nil && !fi.IsDir() {
					if os.Getenv("GITHUB_ACTIONS") == "true" {
						t.Errorf("%s is a nested module that the scan does not read; name it in ownModules", path)
					}
					return filepath.SkipDir
				}
			}
			return nil
		}
		if ext := filepath.Ext(path); ext != ".go" && ext != ".py" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !signs.Match(b) {
			return nil
		}
		checked++
		if allowed[path] {
			return nil
		}
		for _, line := range strings.Split(string(b), "\n") {
			if m := fixedKey.FindString(line); m != "" && !strings.Contains(line, "rand.Reader") {
				t.Errorf("%s signs an advisory set and makes its own key (%q); take it from advisorytest", path, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 2 {
		t.Fatalf("the scan found %d signing files; it is not looking where it should", checked)
	}
}

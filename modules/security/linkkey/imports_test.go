package linkkey

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// NK-2, as settled with D5 in P4-4-F27 (4): no package outside the tests
// imports the link key's reader except platform/sensorlink. The sensor
// manager in platform/node reads the file through it (NK-5), so the signer
// stays in the package that makes the link's handshake, apart from the
// node's register users (NewForwarding, NewListening). Test files may
// import it, to write the file a test needs.

const readerPath = "otsec.local/otsec/modules/security/linkkey"

// importers is the only package directory, from the module root, whose
// non-test files may import the reader.
var importers = []string{"platform/sensorlink"}

// strays lists each non-test Go file under root, slash-separated from
// root, that imports the reader from a directory not in importers. Only a
// go.mod file closes a directory, as in P4-PC-1's walk
// (tests/security/uintptr_walk_d6_test.go). The go command leaves
// testdata, tools, _ and . directories and the like out of ./... only: it
// builds a package there when another imports it by path, so the walk
// reads them (D6's B1 on #672, and on #678 for a leading dot). The owner's
// PC's tools and reference folders each hold a go.mod, and so does each
// worktree under .claude. read is the number of non-test Go files parsed.
func strays(t *testing.T, root string) (out []string, read int) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if fi, err := os.Stat(filepath.Join(p, "go.mod")); err == nil && !fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		read++
		for _, s := range f.Imports {
			ip, _ := strconv.Unquote(s.Path.Value)
			if ip == readerPath && !slices.Contains(importers, path.Dir(rel)) {
				out = append(out, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	return out, read
}

// TestOnlySensorlinkImports reads every non-test Go file of the module.
// Control: a product file of platform/node that imports the reader.
func TestOnlySensorlinkImports(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the module root is not at %s: %v", root, err)
	}
	out, read := strays(t, root)
	if read < 100 {
		t.Fatalf("only %d Go files read", read)
	}
	for _, f := range out {
		t.Errorf("%s imports the link key's reader; only %v may", f, importers)
	}
}

// TestImportCheckBites: on a tree with one file of each kind, the check
// finds the product importers outside platform/sensorlink, a package
// under it included and packages under tools, reference, testdata, vendor,
// _ and . directories, and passes the tests, platform/sensorlink itself,
// and a nested module (the root tools folder of the owner's PC among
// them).
func TestImportCheckBites(t *testing.T) {
	root := t.TempDir()
	src := "package x\n\nimport _ " + strconv.Quote(readerPath) + "\n"
	files := map[string]bool{ // path: whether the check must find it
		"platform/node/sensormgr_link.go":        true,
		"platform/node/linkkey_windows.go":       true,
		"platform/sensorlink/dialkey/dialkey.go": true,
		"modules/telemetry/forward/key.go":       true,
		"cmd/otsec/main.go":                      true,
		"platform/node/tools/x/x.go":             true,
		"cmd/otsec/reference/x/x.go":             true,
		"tests/tools/x/x.go":                     true,
		"platform/node/testdata/x.go":            true,
		"platform/node/_x/x.go":                  true,
		"platform/node/vendor/x/x.go":            true,
		"platform/sensorlink/dial.go":            false,
		"platform/node/sensorlink_key_test.go":   false,
		"tests/security/link_key_d6_test.go":     false,
		"platform/node/.x/x.go":                  true,
		"platform/experiments/phase0/x/x.go":     false,
		"tools/gopath/x/x.go":                    false,
	}
	for p := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []string{"platform/experiments/phase0", "tools"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(m), "go.mod"), []byte("module x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, _ := strays(t, root)
	for p, want := range files {
		if got := slices.Contains(out, p); got != want {
			t.Errorf("%s: found %v, want %v", p, got, want)
		}
	}
}

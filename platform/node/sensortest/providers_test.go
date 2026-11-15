package sensortest

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// NK-2's node leg (docs/phase4/D3-sensor-link.md section 11.4; D4-101
// item 4): the node never opens the link key itself. Outside their tests,
// platform/node, its packages and cmd/otsec make no use of
// nodekey.KeyName, of a nodekey provider's Open, Create or Delete (the
// Keys interface's or a provider type's), or of any function or method
// that returns a crypto.Signer. So the node reaches a provider's key only
// through the register's own methods and through platform/sensorlink,
// which keeps the link key's signer (TestSensorlinkKeepsSigner in
// modules/security/linkkey). The check reads the packages' types, built
// for the platform the test runs on, so both go jobs read their own
// platform's files.
//
// Limit: it reads static uses only. A key opened through reflection, or
// through a function value of another package that returns a signer as an
// interface without crypto.Signer's methods, is not found; D3's review of
// the wiring is the check there.

const (
	modPath     = "otsec.local/otsec"
	nodekeyPath = modPath + "/modules/security/nodekey"
)

// checked are the packages read: every non-test package under
// platform/node, and cmd/otsec.
var checked = []string{modPath + "/platform/node/...", modPath + "/cmd/otsec"}

type listed struct {
	ImportPath string
	Dir        string
	Export     string
	GoFiles    []string
	DepOnly    bool
}

var (
	listOnce sync.Once
	listPkgs []listed
	listErr  error
)

// list runs go list -export -deps once for the checked packages: their
// files, and the export data of every package they import.
func list(t *testing.T) []listed {
	t.Helper()
	listOnce.Do(func() {
		cmd := exec.Command("go", append([]string{"list", "-export", "-deps", "-json=ImportPath,Dir,Export,GoFiles,DepOnly"}, checked...)...)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			listErr = err
			return
		}
		for d := json.NewDecoder(strings.NewReader(string(out))); ; {
			var p listed
			if err := d.Decode(&p); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				listErr = err
				return
			}
			listPkgs = append(listPkgs, p)
		}
	})
	if listErr != nil {
		t.Fatal(listErr)
	}
	return listPkgs
}

// newImporter reads the export data go list named.
func newImporter(fset *token.FileSet, pkgs []listed) types.Importer {
	export := map[string]string{}
	for _, p := range pkgs {
		export[p.ImportPath] = p.Export
	}
	return importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		f, ok := export[path]
		if !ok || f == "" {
			return nil, errors.New("no export data for " + path)
		}
		return os.Open(f)
	})
}

// keyUses lists each use in files of nodekey.KeyName, of a nodekey
// provider's Open, Create or Delete, or of a function or method returning
// a crypto.Signer.
func keyUses(fset *token.FileSet, info *types.Info, files []*ast.File) (found []string) {
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			fn, ok := info.Uses[id].(*types.Func)
			if !ok || fn.Pkg() == nil {
				return true
			}
			sig := fn.Type().(*types.Signature)
			bad := fn.Pkg().Path() == nodekeyPath && (fn.Name() == "KeyName" ||
				sig.Recv() != nil && slices.Contains([]string{"Open", "Create", "Delete"}, fn.Name()))
			for v := range sig.Results().Variables() {
				if n, ok := types.Unalias(v.Type()).(*types.Named); ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "crypto" && n.Obj().Name() == "Signer" {
					bad = true
				}
			}
			if bad {
				found = append(found, fset.Position(id.Pos()).String()+": "+fn.FullName())
			}
			return true
		})
	}
	return found
}

// check type-checks the files of one package and returns keyUses.
func check(t *testing.T, fset *token.FileSet, imp types.Importer, path string, files []*ast.File) []string {
	t.Helper()
	info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
	if _, err := (&types.Config{Importer: imp}).Check(path, fset, files, info); err != nil {
		t.Fatalf("type-checking %s: %v", path, err)
	}
	return keyUses(fset, info, files)
}

func TestNodeOpensNoProviderKey(t *testing.T) {
	pkgs := list(t)
	fset := token.NewFileSet()
	imp := newImporter(fset, pkgs)
	read := 0
	for _, p := range pkgs {
		if p.DepOnly {
			continue
		}
		var files []*ast.File
		for _, name := range p.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
		read += len(files)
		for _, u := range check(t, fset, imp, p.ImportPath, files) {
			t.Errorf("%s opens a provider's key itself: %s", p.ImportPath, u)
		}
	}
	if read < 50 {
		t.Fatalf("only %d files read", read)
	}
}

// TestKeyUseCheckBites: on a package of one file, the check finds each way
// of reaching a provider's key, and passes what is not one: the register's
// own methods, nodekey's other names, and os.Open.
func TestKeyUseCheckBites(t *testing.T) {
	pkgs := list(t)
	const head = "package x\n\nimport (\n\t\"crypto\"\n\t\"os\"\n\n\t\"otsec.local/otsec/modules/security/nodekey\"\n)\n\nvar _ crypto.Signer\nvar _ = os.Open\nvar _ = nodekey.RefPattern\n\n"
	cases := []struct {
		name, src string
		bites     bool
	}{
		{"KeyName", `var _ = nodekey.KeyName("nodekey_link0001", 1)`, true},
		{"a provider type's Open", `func f() { nodekey.LabFiles{}.Open("k") }`, true},
		{"the Keys interface's Create", `func f(k nodekey.Keys) { k.Create("k") }`, true},
		{"a method value of Delete", `func f(k nodekey.CNG) { _ = k.Delete }`, true},
		{"a method expression", `var _ = nodekey.LabFiles.Open`, true},
		{"OpenPinned", `func f(k nodekey.Keys) { nodekey.OpenPinned(k, "k", nil) }`, true},
		{"a local interface returning a signer", "type opener interface{ Open(string) (crypto.Signer, error) }\nfunc f(o opener) { o.Open(\"k\") }", true},
		{"the register's methods", `func f(r *nodekey.Register, k nodekey.Keys) { r.LoadCertificate("nodekey_client01", k) }`, false},
		{"nodekey's other names", `var _ = nodekey.RefPattern.MatchString("x")`, false},
		{"os.Open", `func f() { os.Open("x") }`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", head+c.src+"\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			got := check(t, fset, newImporter(fset, pkgs), "x", []*ast.File{f})
			if bites := len(got) > 0; bites != c.bites {
				t.Fatalf("found %q; want a finding %v", got, c.bites)
			}
		})
	}
}

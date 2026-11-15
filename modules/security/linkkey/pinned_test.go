package linkkey

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
	"strings"
	"testing"
)

// TestOnlyPinnedOpens (D4-106 item 3, test 3): the two readers that open a
// key the file or the register names reach it only through
// nodekey.OpenPinned, which frees a refused key's handle, and never through
// a provider's Open, which would leave the caller holding a refused handle
// (D6's N1 on #685). No non-test package under modules, platform or cmd,
// other than nodekey, uses a provider's Open: platform/sensorlink, which
// keeps the link key, among them (D6's N2 on #697). In nodekey it holds for
// Register.LoadCertificate. This package and LoadCertificate must each use
// OpenPinned. The packages are type-checked, for the platform the test
// runs on, so a method value, a method expression or an interface's Open
// is found as a call is. The patterns are the module's own directories,
// not ./..., because tools sits inside the checkout on the owner's PC.
// Controls: Load, or LoadCertificate, back to the provider's Open, or a
// provider's Open in platform/sensorlink: each compiles and is named.
//
// Limit: it reads static uses only, as keyUses does in
// platform/node/sensortest.
func TestOnlyPinnedOpens(t *testing.T) {
	const nodekeyPath = "otsec.local/otsec/modules/security/nodekey"
	cmd := exec.Command("go", "list", "-export", "-deps", "-json=ImportPath,Dir,Export,GoFiles,DepOnly",
		"otsec.local/otsec/modules/...", "otsec.local/otsec/platform/...", "otsec.local/otsec/cmd/...")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	type listed struct {
		ImportPath, Dir, Export string
		GoFiles                 []string
		DepOnly                 bool
	}
	var pkgs []listed
	for d := json.NewDecoder(strings.NewReader(string(out))); ; {
		var p listed
		if err := d.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	export := map[string]string{}
	for _, p := range pkgs {
		export[p.ImportPath] = p.Export
	}
	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		if f := export[path]; f != "" {
			return os.Open(f)
		}
		return nil, errors.New("no export data for " + path)
	})
	read := map[string]bool{}
	for _, p := range pkgs {
		if p.DepOnly || len(p.GoFiles) == 0 { // a package of tests only
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
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}}
		if _, err := (&types.Config{Importer: imp}).Check(p.ImportPath, fset, files, info); err != nil {
			t.Fatalf("type-checking %s: %v", p.ImportPath, err)
		}
		var nodes []ast.Node
		if p.ImportPath == nodekeyPath {
			for _, f := range files {
				for _, d := range f.Decls {
					if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && fd.Name.Name == "LoadCertificate" {
						nodes = append(nodes, fd)
					}
				}
			}
		} else {
			for _, f := range files {
				nodes = append(nodes, f)
			}
		}
		if len(nodes) == 0 {
			t.Fatalf("%s: nothing to read", p.ImportPath)
		}
		read[p.ImportPath] = true
		pinned := 0
		for _, n := range nodes {
			ast.Inspect(n, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				fn, ok := info.Uses[id].(*types.Func)
				if !ok || fn.Pkg() == nil {
					return true
				}
				sig := fn.Type().(*types.Signature)
				switch {
				case fn.Pkg().Path() == nodekeyPath && sig.Recv() == nil && fn.Name() == "OpenPinned":
					pinned++
				case sig.Recv() != nil && fn.Name() == "Open" && returnsSigner(sig):
					t.Errorf("%s: %s opens a key without its pin", fset.Position(id.Pos()), fn.FullName())
				}
				return true
			})
		}
		if pinned == 0 && (p.ImportPath == readerPath || p.ImportPath == nodekeyPath) {
			t.Errorf("%s: no use of nodekey.OpenPinned found", p.ImportPath)
		}
	}
	for _, want := range []string{readerPath, nodekeyPath, "otsec.local/otsec/platform/sensorlink", "otsec.local/otsec/platform/node", "otsec.local/otsec/cmd/otsec"} {
		if !read[want] {
			t.Errorf("%s was not read", want)
		}
	}
	if len(read) < 20 { // 28 at the time of writing
		t.Fatalf("only %d packages read", len(read))
	}
}

// returnsSigner reports whether sig returns a crypto.Signer.
func returnsSigner(sig *types.Signature) bool {
	for v := range sig.Results().Variables() {
		if n, ok := types.Unalias(v.Type()).(*types.Named); ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "crypto" && n.Obj().Name() == "Signer" {
			return true
		}
	}
	return false
}

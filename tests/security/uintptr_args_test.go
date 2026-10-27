package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// A pointer converted to uintptr is only kept alive, and kept off a stack
// that can move, while the conversion is written in the argument list of a
// call to a function marked go:uintptrescapes (LazyProc.Call, Proc.Call,
// syscall.SyscallN and the like). Converted anywhere else (a helper that
// returns uintptr, a variable set before the call), the buffer can be
// collected, or left on a goroutine stack that moves while Windows writes
// it: #199's Windows job read a P-256 public key's length as 0 (A3, #201;
// the same class as golang/go#78041).
//
// TestUintptrConversionsInCallArgs reads every Go file of the root module
// and fails on any uintptr(unsafe.Pointer(...)) that is not a direct
// argument of such a call. The compiler's escape report (nodekey's
// TestCNGPointersEscape) checks that the directive works; this checks that
// every site uses it. platform/experiments is a separate module that CI
// does not build, and testdata holds fixtures, so both are left out.
// Evidence class: desk (a source rule), any OS.
func TestUintptrConversionsInCallArgs(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	type parsed struct {
		dir string
		f   *ast.File
	}
	var files []parsed
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "node_modules":
				return filepath.SkipDir
			}
			if rel, _ := filepath.Rel(root, path); filepath.ToSlash(rel) == "platform/experiments" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		files = append(files, parsed{filepath.Dir(path), f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 100 {
		t.Fatalf("read %d Go files from %s; is the root right?", len(files), root)
	}

	directive := func(fn *ast.FuncDecl) bool {
		if fn.Doc == nil {
			return false
		}
		for _, c := range fn.Doc.List {
			if strings.TrimSpace(c.Text) == "//go:uintptrescapes" {
				return true
			}
		}
		return false
	}
	// The package-level functions that carry the directive, by directory.
	// Any method named Call is allowed below (x/sys's LazyProc.Call and
	// Proc.Call), so a method named Call in this module must carry the
	// directive too, or a wrapper of #199's shape would pass (A3).
	escapes := map[string]bool{}
	for _, p := range files {
		for _, decl := range p.f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			switch {
			case fn.Recv == nil && directive(fn):
				escapes[p.dir+"."+fn.Name.Name] = true
			case fn.Recv != nil && fn.Name.Name == "Call" && !directive(fn):
				t.Errorf("%s: method Call without go:uintptrescapes; the rule allows every method named Call", fset.Position(fn.Pos()))
			}
		}
	}

	allowed := func(dir string, fun ast.Expr) bool {
		switch f := fun.(type) {
		case *ast.Ident:
			return escapes[dir+"."+f.Name]
		case *ast.SelectorExpr:
			if f.Sel.Name == "Call" { // windows.LazyProc.Call, windows.Proc.Call
				return true
			}
			if x, ok := f.X.(*ast.Ident); ok && (x.Name == "syscall" || x.Name == "windows") && strings.HasPrefix(f.Sel.Name, "Syscall") {
				return true
			}
		}
		return false
	}
	isIdent := func(e ast.Expr, name string) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == name
	}
	isConv := func(e ast.Expr, pkg, name string) (ast.Expr, bool) {
		c, ok := e.(*ast.CallExpr)
		if !ok || len(c.Args) != 1 {
			return nil, false
		}
		switch f := c.Fun.(type) {
		case *ast.Ident:
			if pkg == "" && f.Name == name {
				return c.Args[0], true
			}
		case *ast.SelectorExpr:
			if x, ok := f.X.(*ast.Ident); ok && x.Name == pkg && f.Sel.Name == name {
				return c.Args[0], true
			}
		}
		return nil, false
	}

	isPointerType := func(e ast.Expr) bool {
		x, ok := e.(*ast.SelectorExpr)
		return ok && x.Sel.Name == "Pointer" && isIdent(x.X, "unsafe")
	}
	// pointerNames is, by name, every variable a file declares as an
	// unsafe.Pointer or sets from unsafe.Pointer(...): uintptr(v) of one
	// of them is the same conversion, written in two steps (A3). A name is
	// matched across the whole file, so a shadowed name is checked too.
	pointerNames := func(f *ast.File) map[string]bool {
		names := map[string]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, r := range x.Rhs {
					if _, ok := isConv(r, "unsafe", "Pointer"); ok && i < len(x.Lhs) {
						if id, ok := x.Lhs[i].(*ast.Ident); ok {
							names[id.Name] = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, id := range x.Names {
					conv := false
					if i < len(x.Values) {
						_, conv = isConv(x.Values[i], "unsafe", "Pointer")
					}
					if conv || (x.Type != nil && isPointerType(x.Type)) {
						names[id.Name] = true
					}
				}
			case *ast.Field:
				if isPointerType(x.Type) {
					for _, id := range x.Names {
						names[id.Name] = true
					}
				}
			}
			return true
		})
		return names
	}

	checked := 0
	for _, p := range files {
		ptrs := pointerNames(p.f)
		var stack []ast.Node
		ast.Inspect(p.f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			defer func() { stack = append(stack, n) }()
			e, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			inner, ok := isConv(e, "", "uintptr")
			if !ok {
				return true
			}
			_, conv := isConv(inner, "unsafe", "Pointer")
			if id, ok := inner.(*ast.Ident); !conv && !(ok && ptrs[id.Name]) {
				return true
			}
			checked++
			if len(stack) > 0 {
				if call, ok := stack[len(stack)-1].(*ast.CallExpr); ok && allowed(p.dir, call.Fun) {
					for _, a := range call.Args {
						if a == e {
							return true
						}
					}
				}
			}
			t.Errorf("%s: a pointer converted to uintptr outside the argument list of a go:uintptrescapes call; convert it in the call expression", fset.Position(e.Pos()))
			return true
		})
	}
	if checked == 0 {
		t.Fatal("no uintptr(unsafe.Pointer(...)) found; the rule checked nothing")
	}
	t.Logf("%d conversions in %d files checked", checked, len(files))
}

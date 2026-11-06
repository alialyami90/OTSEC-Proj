package asset

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The asset module opens no socket and runs nothing (AP-28, D4-50, §3 of
// docs/phase4/C2-c1-0.3-c3-0.4.md): it imports no network, syscall or os/exec
// package and no modules/ied package. The SNMP client is collector code.

// forbidden reports why an import path is not allowed in the package's own
// files, or "".
func forbidden(path string) string {
	switch {
	case path == "net" || strings.HasPrefix(path, "net/"):
		return "a network package"
	case path == "syscall" || strings.HasPrefix(path, "golang.org/x/sys/"):
		return "a syscall package"
	case path == "os/exec":
		return "os/exec"
	case path == "unsafe":
		return "unsafe"
	case path == "otsec.local/otsec/modules/ied" || strings.HasPrefix(path, "otsec.local/otsec/modules/ied/"):
		return "a modules/ied package"
	}
	return ""
}

// importsOf returns the imports of a Go source file.
func importsOf(t *testing.T, name string, src any) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		out = append(out, p)
	}
	return out
}

func TestOwnImports(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		n++
		for _, p := range importsOf(t, f, nil) {
			if why := forbidden(p); why != "" {
				t.Errorf("%s imports %s, %s", f, p, why)
			}
		}
	}
	if n == 0 {
		t.Fatal("no package files read")
	}
}

// The check catches each kind it names: a mutation of a package file.
func TestOwnImportsCheckBites(t *testing.T) {
	for _, p := range []string{"net", "net/netip", "net/http", "syscall", "os/exec", "unsafe",
		"golang.org/x/sys/windows", "otsec.local/otsec/modules/ied/sel751", "otsec.local/otsec/modules/ied/snmpv3"} {
		src := "package asset\nimport _ " + strconv.Quote(p) + "\n"
		if forbidden(importsOf(t, "mutant.go", src)[0]) == "" {
			t.Errorf("%s not caught", p)
		}
	}
	for _, p := range []string{"fmt", "os", "slices", "otsec.local/otsec/contracts/asset", "otsec.local/otsec/modules/assetx"} {
		if why := forbidden(p); why != "" {
			t.Errorf("%s refused as %s", p, why)
		}
	}
}

// Nothing the package links, however deep, is a modules/ied package or
// os/exec. The contracts it imports may use net for address parsing; they
// open nothing.
func TestNoClientInTheDependencies(t *testing.T) {
	gobin := filepath.Join(os.Getenv("GOROOT"), "bin", "go")
	if _, err := os.Stat(gobin); err != nil {
		if gobin, err = exec.LookPath("go"); err != nil {
			t.Skip("no go tool to list dependencies")
		}
	}
	out, err := exec.Command(gobin, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		if p == "os/exec" || strings.HasPrefix(p, "otsec.local/otsec/modules/ied") || strings.HasPrefix(p, "otsec.local/otsec/platform/") {
			t.Errorf("the asset module links %s", p)
		}
	}
}

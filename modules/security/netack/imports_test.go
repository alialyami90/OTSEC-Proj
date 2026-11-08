package netack

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The checks are pure functions (P4-4-B3 deliverable 3): the node reads the
// admin folder, the audit chain and the store, and passes bytes here. So
// the package's own files import no file, network, store or process
// package. net/netip parses addresses and opens nothing.
func forbidden(path string) string {
	switch {
	case path == "net" || (strings.HasPrefix(path, "net/") && path != "net/netip"):
		return "a network package"
	case path == "os" || strings.HasPrefix(path, "os/") || path == "io/fs" || path == "path/filepath":
		return "a file or process package"
	case path == "syscall" || path == "unsafe" || strings.HasPrefix(path, "golang.org/x/sys/"):
		return "a system package"
	case path == "database/sql" || strings.HasPrefix(path, "database/sql/"):
		return "a database package"
	case path == "otsec.local/otsec/contracts/store" || strings.HasPrefix(path, "otsec.local/otsec/platform/"):
		return "the store or the node runtime"
	case strings.HasPrefix(path, "otsec.local/otsec/modules/"):
		return "another module"
	}
	return ""
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
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range parsed.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if why := forbidden(p); why != "" {
				t.Errorf("%s imports %s, %s", f, p, why)
			}
		}
	}
	if n == 0 {
		t.Fatal("no source files checked")
	}
}

// The check itself refuses what it must.
func TestForbidden(t *testing.T) {
	for _, p := range []string{"net", "net/http", "os", "os/exec", "io/fs", "path/filepath", "syscall", "unsafe", "database/sql",
		"otsec.local/otsec/contracts/store", "otsec.local/otsec/platform/node", "otsec.local/otsec/modules/ied/sel751"} {
		if forbidden(p) == "" {
			t.Errorf("%s is allowed", p)
		}
	}
	for _, p := range []string{"net/netip", "fmt", "slices", "otsec.local/otsec/contracts/netobs", "otsec.local/otsec/contracts/authz"} {
		if forbidden(p) != "" {
			t.Errorf("%s is refused", p)
		}
	}
}

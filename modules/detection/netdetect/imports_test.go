package netdetect

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// P4-4-B4: the package is pure functions. Its own files import no network,
// file, process, system or store package, and nothing from modules/ied or
// the node runtime; the node reads and writes, and this package decides.
// net/netip parses addresses and opens nothing.
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
		return "another module, modules/ied among them"
	}
	return ""
}

func TestImports(t *testing.T) {
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
	if n < 2 {
		t.Fatalf("%d source files checked", n)
	}
}

// The check itself refuses what it must.
func TestForbidden(t *testing.T) {
	for _, p := range []string{"net", "net/http", "os", "os/exec", "io/fs", "path/filepath", "syscall", "unsafe", "database/sql",
		"otsec.local/otsec/contracts/store", "otsec.local/otsec/platform/node", "otsec.local/otsec/modules/ied/sel751",
		"otsec.local/otsec/modules/detection/eventbaseline"} {
		if forbidden(p) == "" {
			t.Errorf("%s is allowed", p)
		}
	}
	for _, p := range []string{"net/netip", "encoding/json", "slices", "otsec.local/otsec/contracts/netobs"} {
		if forbidden(p) != "" {
			t.Errorf("%s is refused", p)
		}
	}
}

package contract

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The D2-1 import rules (A1), checked from the source, not from the build:
//
//   - A package under modules/ imports contracts/, the standard library and
//     approved dependencies. It never imports platform/, cmd/ or another
//     agent's module. modules/security/collector may import modules/ied/.
//   - The node binary contains no device transport and no credential code:
//     nothing that cmd/otsec or platform/node reaches, directly or through
//     other packages, is under modules/ied/ or modules/security/collector.
//   - Third-party modules are only those D2-2 approves.
//   - Nothing outside tests/ imports tests/, so the oracle stays independent
//     (D2-3).
//
// Ground truth: the rule text of D2-1, D2-2 and D2-3. The checker is tested
// on a tree with one violation of each kind (testdata/imports/bad), so a
// checker that finds nothing cannot pass.

const repoModule = "otsec.local/otsec"

// approvedThirdParty is D2-2.
var approvedThirdParty = []string{"modernc.org/sqlite", "golang.org/x/sys"}

// moduleAgent maps the first directory under modules/ to its owner (D2-1,
// CLAUDE.md §4).
var moduleAgent = map[string]string{
	"ied": "A2", "security": "A3", "access": "A3", "telemetry": "A4", "detection": "A4",
}

type goImport struct {
	path string
	file string // relative to the scanned root, slash-separated
	test bool
}

// scanImports parses the imports of every Go file under root, by package.
// It skips testdata, hidden directories and nested Go modules, as the go
// command does.
func scanImports(t *testing.T, root string) map[string][]goImport {
	t.Helper()
	pkgs := map[string][]goImport{}
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
			name := d.Name()
			if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(p, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		pkg := repoModule
		if dir := path.Dir(rel); dir != "." {
			pkg += "/" + dir
		}
		if _, ok := pkgs[pkg]; !ok {
			pkgs[pkg] = []goImport{}
		}
		for _, s := range f.Imports {
			ip, _ := strconv.Unquote(s.Path.Value)
			pkgs[pkg] = append(pkgs[pkg], goImport{path: ip, file: rel, test: strings.HasSuffix(rel, "_test.go")})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}
	return pkgs
}

// under reports whether p is the repository directory dir or inside it.
func under(p, dir string) bool {
	d := repoModule + "/" + dir
	return p == d || strings.HasPrefix(p, d+"/")
}

func agentOf(p string) string {
	if !under(p, "modules") {
		return ""
	}
	rest := strings.TrimPrefix(p, repoModule+"/modules/")
	return moduleAgent[strings.SplitN(rest, "/", 2)[0]]
}

func isStdlib(ip string) bool {
	first := strings.SplitN(ip, "/", 2)[0]
	return !strings.Contains(first, ".")
}

func approved(ip string) bool {
	for _, a := range approvedThirdParty {
		if ip == a || strings.HasPrefix(ip, a+"/") {
			return true
		}
	}
	return false
}

// checkImports returns one line per violation: "<file>: <rule>: <import>".
func checkImports(pkgs map[string][]goImport) []string {
	var out []string
	bad := func(imp goImport, rule string) {
		out = append(out, imp.file+": "+rule+": "+imp.path)
	}
	for pkg, imps := range pkgs {
		for _, imp := range imps {
			ip := imp.path
			ours := ip == repoModule || strings.HasPrefix(ip, repoModule+"/")
			switch {
			case !ours && !isStdlib(ip) && !approved(ip):
				bad(imp, "D2-2 dependency not approved")
			case ours && under(ip, "tests") && !under(pkg, "tests"):
				bad(imp, "D2-3 imports tests/")
			case ours && under(pkg, "modules") && !under(ip, "contracts"):
				same := agentOf(ip) != "" && agentOf(ip) == agentOf(pkg)
				hosted := under(pkg, "modules/security/collector") && under(ip, "modules/ied")
				if !same && !hosted {
					bad(imp, "D2-1 module imports outside contracts/ and its own agent's modules")
				}
			}
		}
	}
	// The node binary: everything cmd/otsec and platform/node reach without
	// test files.
	forbidden := func(p string) bool {
		return under(p, "modules/ied") || under(p, "modules/security/collector") || under(p, "cmd/otsec-collector")
	}
	for root := range pkgs {
		if !under(root, "cmd/otsec") && !under(root, "platform/node") {
			continue
		}
		// Breadth-first, keeping the path for the message.
		via := map[string]string{root: ""}
		queue := []string{root}
		for len(queue) > 0 {
			p := queue[0]
			queue = queue[1:]
			for _, imp := range pkgs[p] {
				if imp.test {
					continue
				}
				if _, seen := via[imp.path]; seen {
					continue
				}
				if !(imp.path == repoModule || strings.HasPrefix(imp.path, repoModule+"/")) {
					continue
				}
				via[imp.path] = p
				if forbidden(imp.path) {
					chain := []string{imp.path}
					for q := p; q != ""; q = via[q] {
						chain = append(chain, q)
					}
					slices.Reverse(chain)
					out = append(out, strings.TrimPrefix(root, repoModule+"/")+": D2-1 node binary reaches "+
						strings.TrimPrefix(imp.path, repoModule+"/")+" via "+strings.Join(trim(chain), " -> "))
					continue
				}
				queue = append(queue, imp.path)
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func trim(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = strings.TrimPrefix(p, repoModule+"/")
	}
	return out
}

func TestD21ImportRules(t *testing.T) {
	pkgs := scanImports(t, "../..")
	if len(pkgs) < 10 || pkgs[repoModule+"/contracts/adapter"] == nil {
		t.Fatalf("scanned %d packages; the scan did not reach the repository", len(pkgs))
	}
	if v := checkImports(pkgs); len(v) > 0 {
		t.Errorf("%d D2-1 import violations:\n%s", len(v), strings.Join(v, "\n"))
	}
	var mods, node []string
	for p := range pkgs {
		if under(p, "modules") {
			mods = append(mods, p)
		}
		if under(p, "cmd/otsec") || under(p, "platform/node") {
			node = append(node, p)
		}
	}
	// Until the Phase 2 packages land, the module and node rules have
	// nothing to check. Say so instead of passing silently.
	t.Logf("checked %d packages: %d under modules/, %d node roots", len(pkgs), len(mods), len(node))
}

// TestD21ImportRulesCatch runs the checker on a tree with one violation of
// each kind and one allowed import of each kind. A checker that misses a
// violation, or flags an allowed import, fails here.
func TestD21ImportRulesCatch(t *testing.T) {
	got := checkImports(scanImports(t, filepath.Join("testdata", "imports", "bad")))
	want := []string{
		"cmd/otsec: D2-1 node binary reaches modules/ied/telnet via cmd/otsec -> platform/node -> platform/helper -> modules/ied/telnet",
		"cmd/otsec: D2-1 node binary reaches modules/security/collector via cmd/otsec -> platform/node -> modules/security/collector",
		"modules/ied/sel751/sel751.go: D2-1 module imports outside contracts/ and its own agent's modules: otsec.local/otsec/platform/store",
		"modules/ied/sel751/sel751_test.go: D2-3 imports tests/: otsec.local/otsec/tests/contract",
		"modules/telemetry/forward/forward.go: D2-2 dependency not approved: github.com/example/relp",
		"modules/telemetry/normalize/normalize.go: D2-1 module imports outside contracts/ and its own agent's modules: otsec.local/otsec/cmd/otsec",
		"modules/telemetry/normalize/normalize.go: D2-1 module imports outside contracts/ and its own agent's modules: otsec.local/otsec/modules/ied/sel751",
		"platform/node: D2-1 node binary reaches modules/ied/telnet via platform/node -> platform/helper -> modules/ied/telnet",
		"platform/node: D2-1 node binary reaches modules/security/collector via platform/node -> modules/security/collector",
		"platform/store/store.go: D2-2 dependency not approved: modernc.org/sqlitefake",
	}
	// Allowed in the same tree, so not in want: an adapter importing its own
	// agent's telnet package; the collector importing modules/ied/ and its
	// own client; cmd/otsec importing collectorclient; platform/node
	// importing a telemetry module; modernc.org/sqlite and golang.org/x/sys;
	// a nested Go module and a testdata directory, which are not scanned.
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("violations found:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

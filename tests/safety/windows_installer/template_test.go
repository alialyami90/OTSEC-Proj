package windowsinstaller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/platform/node"
)

// The installer check (installer_check.ps1) installs the node with
// node.template.json after substituting STOREDIR and PUBLICDIR. It runs
// elevated on a PC only, so a node config change that the template no
// longer meets would first show there. This test loads the template the
// way the script fills it, on every CI run.
func TestNodeTemplateLoads(t *testing.T) {
	raw, err := os.ReadFile("node.template.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, ph := range []string{"STOREDIR", "PUBLICDIR"} {
		if !strings.Contains(string(raw), `"`+ph+`"`) {
			t.Fatalf("the template has no %s placeholder, which installer_check.ps1 substitutes", ph)
		}
	}
	quoted := func(p string) string { b, _ := json.Marshal(p); return string(b) }
	dir := t.TempDir()
	s := strings.Replace(string(raw), `"STOREDIR"`, quoted(filepath.Join(dir, "store")), 1)
	s = strings.Replace(s, `"PUBLICDIR"`, quoted(filepath.Join(dir, "collector", "public")), 1)
	if runtime.GOOS != "windows" {
		// The script runs on Windows, where the collector is reached on a
		// named pipe and named by its service SID; elsewhere the node needs
		// a socket path and the collector's uid.
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		m["collector_pipe"] = filepath.Join(dir, "collector.sock")
		m["collector_peer"] = "1000"
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		s = string(b)
	}
	cfg, err := node.ParseConfig([]byte(s))
	if err != nil {
		t.Fatalf("the filled template does not load: %v", err)
	}

	// The node names register_version in every run request and the
	// collector refuses a request for another revision, so the template
	// follows the SEL-751 register on main.
	b, err := os.ReadFile("../../../contracts/register/testdata/sel-751.json")
	if err != nil {
		t.Fatal(err)
	}
	var reg register.Package
	if err := json.Unmarshal(b, &reg); err != nil {
		t.Fatal(err)
	}
	if cfg.RegisterVersion != reg.Revision {
		t.Errorf("register_version %d, the SEL-751 register is revision %d", cfg.RegisterVersion, reg.Revision)
	}
}

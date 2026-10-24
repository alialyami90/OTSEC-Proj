package winsvc

import (
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/modules/security/collectorwire"
)

// The directory descriptors grant exactly what W-4 and the store's own
// directory check allow: owner Administrators, a protected DACL, full
// control for SYSTEM and Administrators, and each service only where it
// needs it. Nothing names Users, Everyone or Authenticated Users.
func TestDirs(t *testing.T) {
	node := collectorwire.ServiceSID(NodeService)
	coll := collectorwire.ServiceSID(CollectorService)
	dirs := Dirs(`C:\ProgramData`)
	want := map[string]string{
		`OTSEC`:                       "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;" + node + ")(A;;0x1200a9;;;" + coll + ")",
		`OTSEC/config`:                "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + node + ")",
		`OTSEC/store`:                 "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + node + ")",
		`OTSEC/collector`:             "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + coll + ")",
		`OTSEC/collector/credentials`: "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + coll + ")",
		`OTSEC/collector/state`:       "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + coll + ")",
	}
	if len(dirs) != len(want) {
		t.Fatalf("%d directories", len(dirs))
	}
	for _, d := range dirs {
		rel := strings.TrimPrefix(strings.ReplaceAll(d.Path, `\`, "/"), "C:/ProgramData/")
		if want[rel] != d.SDDL {
			t.Errorf("%s: %s\nwant %s", rel, d.SDDL, want[rel])
		}
		for _, bad := range []string{";;;WD)", ";;;BU)", ";;;AU)", ";;;IU)"} {
			if strings.Contains(d.SDDL, bad) {
				t.Errorf("%s grants %s", rel, bad)
			}
		}
		if strings.Contains(d.SDDL, coll) && strings.Contains(d.SDDL, node) && rel != "OTSEC" {
			t.Errorf("%s grants both services", rel)
		}
	}
	if node == coll || !strings.HasPrefix(node, "S-1-5-80-") {
		t.Fatalf("service SIDs %s %s", node, coll)
	}
}

// The collector configuration sits in OTSEC\collector, so it inherits a
// DACL that names the collector service and not the node service (A3).
func TestCollectorConfigPath(t *testing.T) {
	node := collectorwire.ServiceSID(NodeService)
	coll := collectorwire.ServiceSID(CollectorService)
	pd := `C:\ProgramData`
	parent := filepath.Dir(CollectorConfigPath(pd))
	for _, d := range Dirs(pd) {
		if d.Path != parent {
			continue
		}
		if !strings.Contains(d.SDDL, "(A;OICI;0x1200a9;;;"+coll+")") || strings.Contains(d.SDDL, node) {
			t.Fatalf("collector directory %s", d.SDDL)
		}
		return
	}
	t.Fatalf("no directory %s", parent)
}

package sensortest

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// setsSeams matches Go text that sets node.RuntimeOptions.SensorSeams or
// one of its fields: a composite-literal key, or an assignment.
var setsSeams = regexp.MustCompile(`\bSensorSeams\s*:|\.SensorSeams(\.\w+)?\s*=[^=]`)

// The seams are test hooks: no product code sets them (brief P4-4-F27).
// Every non-test Go file of the module is read; only _test.go files may
// set them. Control: a product file that sets one.
func TestSensorSeamsUnsetInProduct(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the module root is not at %s: %v", root, err)
	}
	read := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "tools", "reference", "experiments":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		read++
		if loc := setsSeams.FindIndex(b); loc != nil {
			t.Errorf("%s sets the sensor seams: %q", p, b[loc[0]:loc[1]])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if read < 100 {
		t.Fatalf("only %d Go files read", read)
	}
}

package asset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func schemaDefs(t *testing.T, file string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("schema", file))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if s["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("%s: not a 2020-12 schema", file)
	}
	return s["$defs"].(map[string]any)
}

func enumOf(t *testing.T, defs map[string]any, name string) []string {
	t.Helper()
	d, ok := defs[name].(map[string]any)
	if !ok {
		t.Fatalf("schema has no $defs/%s", name)
	}
	var out []string
	for _, v := range d["enum"].([]any) {
		out = append(out, v.(string))
	}
	sort.Strings(out)
	return out
}

func sorted[T ~string](xs []T) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = string(x)
	}
	sort.Strings(out)
	return out
}

// The schema's enum lists must equal the Go lists, so the two cannot drift.
func TestSchemaEnumsMatchGo(t *testing.T) {
	a := schemaDefs(t, "asset.schema.json")
	p := schemaDefs(t, "capability-profile.schema.json")
	for name, want := range map[string][]string{
		"confidence":       sorted(Confidences),
		"evidenceClass":    sorted(EvidenceClasses),
		"sourceMethod":     sorted(SourceMethods),
		"transport":        sorted(Transports),
		"securityLevel":    sorted(SecurityLevels),
		"bindingMethod":    sorted(BindingMethods),
		"bindingStrength":  sorted(BindingStrengths),
		"suspensionReason": sorted(SuspensionReasons),
		"postureCode":      sorted(PostureCodes),
		"deviceClass":      sorted(DeviceClasses),
	} {
		if got := enumOf(t, a, name); !reflect.DeepEqual(got, want) {
			t.Errorf("asset.schema.json $defs/%s = %v, Go has %v", name, got, want)
		}
	}
	for name, want := range map[string][]string{
		"capabilityName":   sorted(CapabilityNames),
		"mechanism":        sorted(Mechanisms),
		"capabilityStatus": sorted(CapabilityStatuses),
		"deviceClass":      sorted(DeviceClasses),
	} {
		if got := enumOf(t, p, name); !reflect.DeepEqual(got, want) {
			t.Errorf("capability-profile.schema.json $defs/%s = %v, Go has %v", name, got, want)
		}
	}
	names := a["attributeName"].(map[string]any)["anyOf"].([]any)[0].(map[string]any)["enum"].([]any)
	var got []string
	for _, n := range names {
		got = append(got, n.(string))
	}
	sort.Strings(got)
	if want := sorted(AttributeNames); !reflect.DeepEqual(got, want) {
		t.Errorf("attribute names in schema = %v, Go has %v", got, want)
	}
}

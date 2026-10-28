package baseline

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/node"
)

func loadSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile("schema/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestSchemaMatchesTypes keeps both schemas and the Go types in step: every
// object in a schema has exactly the properties of the matching Go struct,
// and lists as required exactly the fields without omitempty.
func TestSchemaMatchesTypes(t *testing.T) {
	b := loadSchema(t, "baseline.json")
	defs := map[string]map[string]any{"": b["$defs"].(map[string]any), "baseline.json": b["$defs"].(map[string]any)}
	compare(t, "baseline", reflect.TypeOf(Baseline{}), b, defs)
	a := loadSchema(t, "alarm.json")
	defs[""] = a["$defs"].(map[string]any)
	compare(t, "alarm", reflect.TypeOf(Alarm{}), a, defs)
}

func resolve(n map[string]any, defs map[string]map[string]any) map[string]any {
	ref, ok := n["$ref"].(string)
	if !ok {
		return n
	}
	file, name, _ := strings.Cut(ref, "#/$defs/")
	d, _ := defs[file][name].(map[string]any)
	return d
}

func compare(t *testing.T, path string, typ reflect.Type, n map[string]any, defs map[string]map[string]any) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
		if items, ok := n["items"].(map[string]any); ok {
			n = resolve(items, defs)
		}
	}
	n = resolve(n, defs)
	if typ.Kind() != reflect.Struct {
		return
	}
	props, _ := n["properties"].(map[string]any)
	var goNames, goRequired []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		goNames = append(goNames, name)
		if !strings.Contains(opts, "omitempty") {
			goRequired = append(goRequired, name)
		}
		child, ok := props[name].(map[string]any)
		if !ok {
			t.Errorf("%s.%s: in Go, not in the schema", path, name)
			continue
		}
		compare(t, path+"."+name, f.Type, child, defs)
	}
	var schemaNames, schemaRequired []string
	for k := range props {
		schemaNames = append(schemaNames, k)
	}
	if req, ok := n["required"].([]any); ok {
		for _, r := range req {
			schemaRequired = append(schemaRequired, r.(string))
		}
	}
	for _, s := range [][]string{goNames, goRequired, schemaNames, schemaRequired} {
		sort.Strings(s)
	}
	if !reflect.DeepEqual(goNames, schemaNames) {
		t.Errorf("%s: properties: Go %v, schema %v", path, goNames, schemaNames)
	}
	if !reflect.DeepEqual(goRequired, schemaRequired) && !(len(goRequired) == 0 && len(schemaRequired) == 0) {
		t.Errorf("%s: required: Go %v, schema %v", path, goRequired, schemaRequired)
	}
}

// The schemas cannot import Go, so they repeat contracts/node's patterns;
// they must stay identical (A1 D1-1).
func TestSchemaNodePatterns(t *testing.T) {
	b := loadSchema(t, "baseline.json")
	if got := b["properties"].(map[string]any)["node_id"].(map[string]any)["pattern"]; got != node.IDPattern {
		t.Errorf("baseline.json node_id pattern %q, want %q", got, node.IDPattern)
	}
	a := loadSchema(t, "alarm.json")
	p := a["$defs"].(map[string]any)["event_id"].(map[string]any)["properties"].(map[string]any)
	if p["node_id"].(map[string]any)["pattern"] != node.IDPattern || p["stream"].(map[string]any)["pattern"] != node.StreamPattern {
		t.Errorf("alarm.json event_id patterns differ from contracts/node")
	}
}

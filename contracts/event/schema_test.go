package event

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/node"
)

// TestSchemaMatchesTypes keeps schema/event.json and the Go types in step:
// every object in the schema has exactly the properties of the matching Go
// struct, and lists as required exactly the fields without omitempty.
func TestSchemaMatchesTypes(t *testing.T) {
	b, err := os.ReadFile("schema/event.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	defs, _ := root["$defs"].(map[string]any)
	compare(t, "event", reflect.TypeOf(Event{}), root, defs)
}

func resolve(node map[string]any, defs map[string]any) map[string]any {
	if ref, ok := node["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/$defs/")
		d, _ := defs[name].(map[string]any)
		return d
	}
	return node
}

func compare(t *testing.T, path string, typ reflect.Type, node map[string]any, defs map[string]any) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
		typ = typ.Elem()
		if items, ok := node["items"].(map[string]any); ok {
			node = resolve(items, defs)
		}
	}
	node = resolve(node, defs)
	if typ.Kind() != reflect.Struct {
		return
	}
	props, _ := node["properties"].(map[string]any)
	var goNames, goRequired []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
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
	if req, ok := node["required"].([]any); ok {
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

// The schema cannot import Go, so it repeats the node ID and stream patterns
// of contracts/node; they must stay identical (A1 D1-1).
func TestSchemaNodePatterns(t *testing.T) {
	b, err := os.ReadFile("schema/event.json")
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Defs struct {
			EventID struct {
				Properties map[string]struct {
					Pattern string `json:"pattern"`
				} `json:"properties"`
			} `json:"event_id"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	p := root.Defs.EventID.Properties
	if p["node_id"].Pattern != node.IDPattern || p["stream"].Pattern != node.StreamPattern {
		t.Errorf("schema patterns %q, %q differ from contracts/node", p["node_id"].Pattern, p["stream"].Pattern)
	}
}

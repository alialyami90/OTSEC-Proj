package strictjson

import (
	"strings"
	"testing"
)

type inner struct {
	Line string `json:"line"`
	N    *int   `json:"n,omitempty"`
}

type Embedded struct {
	Kind string `json:"kind"`
}

type doc struct {
	Embedded
	Name   string            `json:"name"`
	Items  []inner           `json:"items"`
	Fields map[string]string `json:"fields,omitempty"`
	Any    any               `json:"any,omitempty"`
	Skip   string            `json:"-"`
}

func TestAccepts(t *testing.T) {
	var d doc
	in := `{"kind":"k","name":"a","items":[{"line":"ID","n":2}],"fields":{"Line":"x","line":"y"},"any":{"A":1,"a":[1,{"b":2}]}}`
	if err := Decode([]byte(in), &d); err != nil {
		t.Fatal(err)
	}
	if d.Kind != "k" || d.Items[0].Line != "ID" || *d.Items[0].N != 2 || d.Fields["Line"] != "x" {
		t.Errorf("decoded %+v", d)
	}
}

func TestRejects(t *testing.T) {
	for name, in := range map[string]string{
		"case variant key":                      `{"name":"a","Name":"b","items":[]}`,
		"case variant only":                     `{"NAME":"a","items":[]}`,
		"duplicate key":                         `{"name":"a","name":"b","items":[]}`,
		"nested case variant":                   `{"name":"a","items":[{"line":"ID","Line":"EVE"}]}`,
		"nested unknown":                        `{"name":"a","items":[{"line":"ID","x":1}]}`,
		"unknown top level":                     `{"name":"a","items":[],"extra":true}`,
		"ignored field present":                 `{"name":"a","items":[],"Skip":"x"}`,
		"duplicate map key":                     `{"name":"a","items":[],"fields":{"k":"1","k":"2"}}`,
		"duplicate key in any":                  `{"name":"a","items":[],"any":{"x":1,"x":2}}`,
		"embedded case variant":                 `{"kind":"a","Kind":"b","items":[]}`,
		"trailing object":                       `{"name":"a","items":[]}{}`,
		"trailing bracket":                      `{"name":"a","items":[]}]`,
		"trailing text":                         `{"name":"a","items":[]} x`,
		"dotless i lookalike":                   `{"name":"a","items":[{"lıne":"ID"}]}`,
		"nul in key":                            `{"name":"a","items":[{"line\u0000":"ID"}]}`,
		"truncated":                             `{"name":"a","items":[`,
		"wrong type passes check, fails decode": `{"name":1,"items":[]}`,
	} {
		var d doc
		if err := Decode([]byte(in), &d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTarget(t *testing.T) {
	var d doc
	if err := Decode([]byte(`{}`), d); err == nil || !strings.Contains(err.Error(), "pointer") {
		t.Errorf("non-pointer target: %v", err)
	}
}

package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"

	"otsec.local/otsec/contracts/version"
)

// Decode reads one event so that every reader reads it the same way, then
// validates it (A1 decision D1-9, A6 C4 review item 6). Go's encoding/json
// alone matches keys case-insensitively, lets a later duplicate key win and
// ignores unknown fields, so {"origin":"device","ORIGIN":"platform"} would
// depend on key order. Decode rejects, with CodeDecode:
//
//   - anything but a single JSON object, and anything after it;
//   - a key that occurs twice in one object, compared without case;
//   - a key that is not spelled exactly as a C4 field name, except inside
//     health.details, whose keys are free text;
//   - in an event stamped otsec.event/0.1 (or an earlier 0.x), any key that
//     is not a C4 field name.
//
// An event stamped with a later 0.x minor may carry fields that minor adds.
// Decode ignores them, as contracts/README.md requires of every reader, but
// they must still be lowercase snake_case and unique.
func Decode(b []byte) (*Event, error) {
	unknown, err := checkKeys(b)
	if err != nil {
		return nil, &Error{Code: CodeDecode, Field: "event", Detail: err.Error()}
	}
	var e Event
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "event", Detail: err.Error()}
	}
	if len(unknown) > 0 {
		if got, err := version.Parse(e.Schema); err != nil || got.Name != self.Name || got.Minor <= self.Minor {
			return nil, &Error{Code: CodeDecode, Field: unknown[0], Detail: fmt.Sprintf("not a field of %s", Identifier)}
		}
	}
	return &e, e.Validate()
}

var keyForm = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// fields maps the exact JSON names of a struct's fields to their types.
func fields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			out[name] = f.Type
		}
	}
	return out
}

// checkKeys walks the document beside the Event type and returns the paths
// of keys that are not fields of the type at that place.
func checkKeys(b []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil {
		return nil, err
	} else if tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var unknown []string
	if err := walkObject(dec, "", reflect.TypeOf(Event{}), &unknown); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the event")
	}
	return unknown, nil
}

// walkObject checks the keys of an object whose '{' has been read. t is the
// Go type the object decodes into, or nil inside a field C4 does not know.
func walkObject(dec *json.Decoder, path string, t reflect.Type, unknown *[]string) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	var known map[string]reflect.Type
	free := t != nil && t.Kind() == reflect.Map // health.details: free-text keys
	if t != nil && t.Kind() == reflect.Struct {
		known = fields(t)
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		k := tok.(string)
		if seen[strings.ToLower(k)] {
			return fmt.Errorf("%s: duplicate key %q", where(path), k)
		}
		seen[strings.ToLower(k)] = true
		var vt reflect.Type
		switch {
		case free:
			vt = t.Elem()
		case !keyForm.MatchString(k):
			return fmt.Errorf("%s: key %q is not spelled as a field name", where(path), k)
		case known[k] != nil:
			vt = known[k]
		case t != nil:
			*unknown = append(*unknown, join(path, k))
		}
		if err := walkValue(dec, join(path, k), vt, unknown); err != nil {
			return err
		}
	}
	_, err := dec.Token() // '}'
	return err
}

func walkValue(dec *json.Decoder, path string, t reflect.Type, unknown *[]string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		return walkObject(dec, path, t, unknown)
	case json.Delim('['):
		var et reflect.Type
		if t != nil && t.Kind() == reflect.Slice {
			et = t.Elem()
		}
		for dec.More() {
			if err := walkValue(dec, path+"[]", et, unknown); err != nil {
				return err
			}
		}
		_, err := dec.Token() // ']'
		return err
	}
	return nil
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func where(path string) string {
	if path == "" {
		return "event"
	}
	return path
}

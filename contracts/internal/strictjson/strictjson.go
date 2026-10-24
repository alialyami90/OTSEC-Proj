// Package strictjson decodes JSON so that every reader of a contract document
// reads the same thing. encoding/json on its own matches keys to fields
// without regard to case, keeps the last of duplicate keys, ignores unknown
// fields and stops at the first value, so one document can show a reviewer
// one value and a collector another (A3 C3-A3-2, A6 reviews of C3, C4, C1).
//
// Decode walks the document against the target's Go type before decoding it:
//
//   - a struct object may hold only its fields' exact JSON names, each once,
//     and no two keys that differ only in case;
//   - a map object may hold any keys, each once;
//   - nothing may follow the first value.
//
// Decode rejects unknown fields, for strict contracts (C3, C7 IPC). Forward
// is for contracts whose readers accept later minors (contracts/README.md):
// it ignores a key that is not a field name, but still rejects a key that
// differs from a field name only in case, and duplicate keys.
//
// Used by every contract that decodes a document crossing a process, network
// or storage boundary (A1 decisions D1-9, D1-10).
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Decode checks data against v's type and then decodes it into v, which must
// be a non-nil pointer. Unknown fields are errors.
func Decode(data []byte, v any) error { return decode(data, v, false) }

// Forward is Decode for a contract that accepts later minors: unknown fields
// spelled differently from every field name are ignored.
func Forward(data []byte, v any) error { return decode(data, v, true) }

func decode(data []byte, v any, forward bool) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("strictjson: target must be a non-nil pointer")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	c := checker{forward: forward}
	if err := c.check(dec, rv.Type().Elem(), ""); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("strictjson: data after the first value")
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	if !forward {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("strictjson: %w", err)
	}
	return nil
}

var (
	unmarshaler = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	anyType     = reflect.TypeOf((*any)(nil)).Elem()
)

type checker struct{ forward bool }

func (c checker) check(dec *json.Decoder, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("strictjson: %s: %w", where(path), err)
	}
	switch tok {
	case json.Delim('{'):
		var fields map[string]reflect.Type
		var elem reflect.Type
		switch {
		case t.Kind() == reflect.Struct && !reflect.PointerTo(t).Implements(unmarshaler):
			fields = structFields(t)
		case t.Kind() == reflect.Map:
			elem = t.Elem()
		default:
			elem = anyType
		}
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return fmt.Errorf("strictjson: %s: %w", where(path), err)
			}
			key := k.(string)
			ft := elem
			if fields != nil {
				var ok bool
				if ft, ok = fields[key]; !ok {
					if !c.forward || caseVariant(fields, key) {
						return fmt.Errorf("strictjson: %s: key %q is not a field name", where(path), key)
					}
					ft = anyType
				}
				if seen[strings.ToLower(key)] {
					return fmt.Errorf("strictjson: %s: duplicate key %q", where(path), key)
				}
				seen[strings.ToLower(key)] = true
			} else {
				if seen[key] {
					return fmt.Errorf("strictjson: %s: duplicate key %q", where(path), key)
				}
				seen[key] = true
			}
			if err := c.check(dec, ft, path+"."+key); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
		return err
	case json.Delim('['):
		elem := anyType
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			elem = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := c.check(dec, elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
		return err
	}
	return nil
}

// structFields maps each JSON name of t, including those promoted from
// embedded structs, to its field type.
func structFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || (!f.IsExported() && !f.Anonymous) {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if f.Anonymous && name == "" && ft.Kind() == reflect.Struct {
			for k, v := range structFields(ft) {
				if _, ok := out[k]; !ok {
					out[k] = v
				}
			}
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	return out
}

// caseVariant reports whether key matches a field name when case is ignored,
// which encoding/json would decode into that field.
func caseVariant(fields map[string]reflect.Type, key string) bool {
	for name := range fields {
		if strings.EqualFold(name, key) {
			return true
		}
	}
	return false
}

func where(path string) string {
	if path == "" {
		return "top level"
	}
	return strings.TrimPrefix(path, ".")
}

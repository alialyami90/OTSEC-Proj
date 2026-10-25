package collectorwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

// DecodeStrict decodes one JSON value into v, which must be a non-nil
// pointer, with the D1-10 rules every contract decoder applies: an object
// for a struct may hold only its fields' exact JSON names, each once, and no
// two keys that differ only in case; a map object may hold any keys, each
// once; nothing may follow the value; and the bytes are UTF-8. Exact names
// matter because encoding/json alone matches a key to a field by Unicode
// case folding, so "STATUS" or "ſtatus" would land in "status" (A6 review of
// #79).
//
// It is a copy of contracts/internal/strictjson.Decode, which is internal to
// contracts/ and so cannot be imported here; a C7 0.2 DecodeReply would let
// this copy go. Keep the two in step.
func DecodeStrict(data []byte, v any) error {
	if !utf8.Valid(data) {
		return errors.New("not UTF-8")
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("target must be a non-nil pointer")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := (checker{}).check(dec, rv.Type().Elem(), ""); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

var (
	unmarshaler = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	anyType     = reflect.TypeOf((*any)(nil)).Elem()
)

type checker struct{}

func (c checker) check(dec *json.Decoder, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", where(path), err)
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
				return fmt.Errorf("%s: %w", where(path), err)
			}
			key := k.(string)
			ft := elem
			if fields != nil {
				var ok bool
				if ft, ok = fields[key]; !ok {
					return fmt.Errorf("%s: key %q is not a field name", where(path), key)
				}
				if seen[strings.ToLower(key)] {
					return fmt.Errorf("%s: duplicate key %q", where(path), key)
				}
				seen[strings.ToLower(key)] = true
			} else {
				if seen[key] {
					return fmt.Errorf("%s: duplicate key %q", where(path), key)
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

func where(path string) string {
	if path == "" {
		return "top level"
	}
	return strings.TrimPrefix(path, ".")
}

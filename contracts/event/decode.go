package event

import (
	"otsec.local/otsec/contracts/internal/strictjson"
	"otsec.local/otsec/contracts/version"
)

// Decode reads one event so that every reader reads it the same way, then
// validates it (A1 decisions D1-9 and D1-10, A6 C4 review item 6). Go's
// encoding/json alone matches keys case-insensitively, lets a later
// duplicate key win and ignores unknown fields, so
// {"origin":"device","ORIGIN":"platform"} would depend on key order.
//
// An event stamped otsec.event/0.1 (or an earlier 0.x) is read with
// strictjson.Decode: exact field names only, no duplicate keys, nothing
// after the object. An event stamped with a later 0.x minor is read with
// strictjson.Forward, which also ignores fields that minor adds, as
// contracts/README.md requires of every reader, but still rejects duplicate
// keys and case variants of known fields. Failures have CodeDecode.
func Decode(b []byte) (*Event, error) {
	var e Event
	if err := strictjson.Forward(b, &e); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "event", Detail: err.Error()}
	}
	if got, err := version.Parse(e.Schema); err == nil && got.Name == self.Name && got.Minor <= self.Minor {
		e = Event{}
		if err := strictjson.Decode(b, &e); err != nil {
			return nil, &Error{Code: CodeDecode, Field: "event", Detail: err.Error()}
		}
	}
	return &e, e.Validate()
}

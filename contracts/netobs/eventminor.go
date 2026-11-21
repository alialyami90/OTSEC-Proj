package netobs

import (
	"fmt"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/version"
)

// eventSelf is C4's own identifier, event.Identifier, parsed. It is never
// C13's self.
var eventSelf = func() version.ID {
	id, err := version.Parse(event.Identifier)
	if err != nil {
		panic("netobs: event.Identifier does not parse: " + err.Error())
	}
	return id
}()

// CheckEventMinor refuses a C4 event stamped with a later minor than this
// build's C4 minor (event.Identifier), at judging on the network path:
// ObservationFromEvent's network-observation and the node's collection.run
// (docs/phase4/D4-c4-0.6-proposal.md §3.1, C4-0.6-3). It returns nil, or
// an *Error with CodeSchema and Field "schema": with ErrLaterMinor for a
// later minor, and without it for a schema it cannot read (empty,
// unparseable, another name or another major), which fails closed.
// event.Decode is unchanged and still reads a later minor forward.
func CheckEventMinor(e *event.Event) error {
	return checkEventMinor(e.Schema, eventSelf.Minor)
}

// checkEventMinor is CheckEventMinor against a reader's C4 minor, passed
// in so that a test can set it apart from both C4's and C13's.
func checkEventMinor(schema string, minor int) error {
	got, err := version.Parse(schema)
	if err != nil || !eventSelf.Accepts(got) {
		return &Error{Code: CodeSchema, Field: "schema", Detail: fmt.Sprintf("%q is not %s or another %d.x minor of it", schema, event.Identifier, eventSelf.Major)}
	}
	if got.Minor > minor {
		return &Error{Code: CodeSchema, Field: "schema", Detail: fmt.Sprintf("%q is a later minor than this reader's %s", schema, version.ID{Name: eventSelf.Name, Major: eventSelf.Major, Minor: minor}), err: ErrLaterMinor}
	}
	return nil
}

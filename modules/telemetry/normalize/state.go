package normalize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"otsec.local/otsec/contracts/event"
)

// StateFormat names the encoding of the alignment state. The state is this
// package's own record, kept by the node as C5 SourceCursor; it is not a
// shared contract.
const StateFormat = "otsec.normalize.ser-state/1"

// maxStateBytes bounds an encoded state: MaxAlignRows keys of 71 bytes, with
// quotes and commas, plus the envelope.
const maxStateBytes = event.MaxAlignRows*(71+3) + 128

type stateDoc struct {
	Format string   `json:"format"`
	Keys   []string `json:"keys"`
}

// EncodeState encodes the alignment state of a read: its keys, oldest
// first. Nil (no read yet) encodes as nil; an empty read encodes as an
// empty list, so the next read is compared with it (D1-7).
func EncodeState(keys []string) ([]byte, error) {
	if keys == nil {
		return nil, nil
	}
	if err := checkKeys(keys); err != nil {
		return nil, err
	}
	return json.Marshal(stateDoc{Format: StateFormat, Keys: keys})
}

// DecodeState reads a state EncodeState wrote. Nil or empty input is no
// state (first read). Anything else must be exactly one state document of
// this format with at most MaxAlignRows well-formed keys; it is read back
// from the node's own store, but checked as if it were not.
func DecodeState(b []byte) ([]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if len(b) > maxStateBytes {
		return nil, fmt.Errorf("%w: state of %d bytes", ErrInput, len(b))
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d stateDoc
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: state: %v", ErrInput, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%w: state has trailing data", ErrInput)
	}
	if d.Format != StateFormat || d.Keys == nil {
		return nil, fmt.Errorf("%w: state format %q", ErrInput, d.Format)
	}
	if err := checkKeys(d.Keys); err != nil {
		return nil, err
	}
	return d.Keys, nil
}

func checkKeys(keys []string) error {
	if len(keys) > event.MaxAlignRows {
		return fmt.Errorf("%w: state holds %d keys", ErrInput, len(keys))
	}
	for _, k := range keys {
		if !keyForm.MatchString(k) {
			return fmt.Errorf("%w: state key %q", ErrInput, k)
		}
	}
	return nil
}

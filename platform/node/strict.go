package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// checkKeys walks b and refuses a duplicate key in any object and any key
// that is not lowercase (letters, digits, _ and -). encoding/json matches keys without
// regard to case and lets a later duplicate win, so without this check
// {"node_id":"a","NODE_ID":"b"} would load whichever came last (the reason
// for A1 D1-10). Every key of this format, of C1 and of C6 is lowercase; quota keys are C5 class names.
func checkKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := walk(dec, "$"); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("data after the configuration object")
	}
	return nil
}

func walk(dec *json.Decoder, path string) error {
	t, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			k := kt.(string)
			if !keyPattern.MatchString(k) {
				return fmt.Errorf("%s: key %q is not lowercase", path, k)
			}
			if seen[k] {
				return fmt.Errorf("%s: duplicate key %q", path, k)
			}
			seen[k] = true
			if err := walk(dec, path+"."+k); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case json.Delim('['):
		for i := 0; dec.More(); i++ {
			if err := walk(dec, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return nil
}

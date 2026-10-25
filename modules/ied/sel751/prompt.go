package sel751

import "bytes"

// Prompts the SEL ASCII port prints (S22 p. 7.16, p. 7.33).
const (
	promptLevel0   = "="
	promptLevel1   = "=>"
	promptLevel2   = "=>>"
	promptPassword = "Password: ?"
)

var promptLevels = map[string]int{promptLevel0: 0, promptLevel1: 1, promptLevel2: 2}

// promptOf returns the prompt rx ends with, or "". It copies C2's rule
// (contracts/adapter dialogue.go, unexported there), and the adapter acts on
// exactly this rule, after the quiet interval, so that what it does and what
// Result.Validate reads from the bytes never differ. A stricter rule (no
// prompt inside an open STX message) was tried and made results the
// contract refuses; narrowing the rule is C2's to do once a capture shows
// where the prompt sits (H-13).
// NUL, XON, XOFF and trailing spaces are ignored, and a prompt counts only
// first in rx or right after CR, LF, STX or ETX, so "MAXACC  :=" and
// "DEVID=" are not prompts.
func promptOf(rx []byte) string {
	clean := bytes.Map(func(r rune) rune {
		switch r {
		case 0x00, 0x11, 0x13:
			return -1
		}
		return r
	}, rx)
	clean = bytes.TrimRight(clean, " ")
	for _, p := range []string{promptPassword, promptLevel2, promptLevel1, promptLevel0} {
		if !bytes.HasSuffix(clean, []byte(p)) {
			continue
		}
		before := clean[:len(clean)-len(p)]
		if len(before) == 0 || bytes.IndexByte([]byte("\r\n\x02\x03"), before[len(before)-1]) >= 0 {
			return p
		}
		return ""
	}
	return ""
}

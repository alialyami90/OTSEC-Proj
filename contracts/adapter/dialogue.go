package adapter

import (
	"bytes"
	"fmt"
	"strconv"
)

// The session rules, checked against the transcript bytes rather than the
// session facts (A3 C2 review changes 1, 2, 4 and 7; A6 C2 review changes 1,
// 2, 5, 6 and 7). Every sent segment is judged by the bytes received since
// the send before it.

// Prompts the SEL ASCII port prints (S22 p. 7.16, p. 7.33).
const (
	promptLevel0   = "="
	promptLevel1   = "=>"
	promptLevel2   = "=>>"
	promptPassword = "Password: ?"
)

var promptLevels = map[string]int{promptLevel0: 0, promptLevel1: 1, promptLevel2: 2}

// promptOf returns the prompt rx ends with, or "". NUL, XON and XOFF are
// ignored, and so are trailing spaces. A prompt counts only at the start of a
// line: first in rx, or right after CR, LF, STX or ETX. So "MAXACC  :=" and
// "DEVID=" are not prompts, and "\x03=" and "\r\n=" are. Whether the prompt
// follows ETX on the wire is not documented (H-13); when a capture shows it,
// the rule can be narrowed to after-ETX only.
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

// send is one sent segment and what was received since the send before it.
type send struct {
	seg    int // index in Transcript.Segments
	phase  Phase
	b      []byte
	before []byte
	cred   bool // the segment holds the credential redaction
}

// sends cuts a transcript whose segments cover it exactly into sends, and
// returns the bytes received after the last send.
func sends(t Transcript) (out []send, tail []byte) {
	var rx []byte
	for i, sg := range t.Segments {
		b := t.Data[sg.Offset : sg.Offset+sg.Length]
		if sg.Dir == Received {
			rx = append(rx, b...)
			continue
		}
		x := send{seg: i, phase: sg.Phase, b: b, before: rx}
		for _, rd := range t.Redactions {
			if rd.Reason == RedactCredential && rd.Offset >= sg.Offset && rd.Offset+rd.Length <= sg.Offset+sg.Length {
				x.cred = true
			}
		}
		out = append(out, x)
		rx = nil
	}
	return out, rx
}

// isLine reports whether b is exactly text followed by one line end.
func isLine(b []byte, text string) bool {
	for _, eol := range []string{"\r\n", "\r", "\n"} {
		if string(b) == text+eol {
			return true
		}
	}
	return false
}

// isWake reports whether a sent segment is the bare line end that wakes the
// port.
func isWake(b []byte) bool { return isLine(b, "") }

// dialogue checks every send against the prompt before it, the credential
// slot, the phase contents, and the session facts the bytes decide.
func (c *check) dialogue(r Result, code Code) {
	t, s := r.Transcript, r.Session
	ss, tail := sends(t)
	at := func(x send) string { return fmt.Sprintf("transcript.segments[%d]", x.seg) }

	level := -1 // the highest level a prompt showed
	first := "" // the first prompt received
	see := func(rx []byte) string {
		p := promptOf(rx)
		if l, ok := promptLevels[p]; ok {
			if first == "" {
				first = p
			}
			level = max(level, l)
		}
		return p
	}

	wakes, acc, cred := 0, -1, -1
	passwordPrompt := false
	probed := false
	for k, x := range ss {
		p := see(x.before)
		if probed {
			c.probeOutcome(x.before, s)
			probed = false
		}
		if acc >= 0 && k == acc+1 {
			passwordPrompt = p == promptPassword
		}
		switch {
		case x.phase == PhaseProbe && isWake(x.b):
			// Only first, and only into silence: a relay that printed
			// anything, "Password: ?" above all, may take the line end as
			// input (C7-A2 change 1; A3 change 7).
			if k != 0 || len(stripFraming(x.before)) != 0 {
				c.fail("%s: the wake line end is sent once, first, and only when nothing was received", at(x))
			}
			wakes++
			continue
		case x.cred:
			// The slot (HR-3, C-17): ACC, the password prompt received, then
			// exactly the marker and a line end.
			if !isLine(x.b, RedactionMarker) || x.phase != PhaseAuth {
				c.fail("%s: the credential segment is exactly the redaction marker and one line end, in the auth phase", at(x))
			}
			if k == 0 || k-1 != acc {
				c.fail("%s: the credential follows ACC directly", at(x))
			}
			if p != promptPassword {
				c.fail("%s: the credential was sent without a received password prompt", at(x))
			}
			cred = k
			continue
		}

		switch x.phase {
		case PhaseAuth:
			if acc >= 0 || !isLine(x.b, "ACC") {
				c.fail("%s: the auth phase sends ACC once, then only the credential", at(x))
			}
			acc = k
		case PhaseClose:
			if !isLine(x.b, "QUI") {
				c.fail("%s: the close phase sends QUI only", at(x))
			}
		case PhaseProbe:
			probed = isLine(x.b, "QUI")
		}

		// Every line follows a prompt, and the right one.
		switch {
		case cred >= 0 && k == cred+1:
			// Nothing after the password until a level prompt confirms it
			// (C-19, D1-20): QUI into "Password: ?" is a second attempt.
			if p != promptLevel1 && !(code == FailedUnexpectedLevel && p == promptLevel2) {
				c.fail("%s: sent after a password that no level prompt confirmed (C-19, D1-20)", at(x))
			}
		case x.phase == PhaseClose && p == "" && (code == FailedTimeout || code == FailedResponseTooLarge) &&
			(cred < 0 || k > cred+1):
			// The one line not sent after a prompt: a step ended without
			// one, and QUI drops a level already confirmed back to 0 (D18,
			// V-S13). It is never the first send after the password.
		case x.phase == PhaseProbe || x.phase == PhaseAuth:
			if p != promptLevel0 {
				c.fail("%s: %q sent before the %q prompt", at(x), bytes.TrimRight(x.b, "\r\n"), promptLevel0)
			}
		case x.phase == PhaseOperate:
			if p != promptLevel1 {
				c.fail("%s: %q sent before the %q prompt", at(x), bytes.TrimRight(x.b, "\r\n"), promptLevel1)
			}
		default:
			if _, ok := promptLevels[p]; !ok {
				c.fail("%s: %q sent before a prompt", at(x), bytes.TrimRight(x.b, "\r\n"))
			}
		}
	}
	last := see(tail)
	if probed {
		c.probeOutcome(tail, s)
	}
	if acc >= 0 && acc == len(ss)-1 {
		passwordPrompt = last == promptPassword
	}

	if (wakes == 1) != s.WakeSent || wakes > 1 {
		c.fail("session: wake_sent must match exactly one wake line end in the probe phase (found %d)", wakes)
	}
	if s.PasswordPrompt != passwordPrompt {
		c.fail("session: password_prompt is %v, but the bytes after ACC say %v", s.PasswordPrompt, passwordPrompt)
	}
	if acc >= 0 && s.LanguageProbe != ProbeAccepted {
		c.fail("session: ACC sent without an accepted language probe (ADR-0005, F-007)")
	}
	if s.LanguageProbe != ProbeNotRun && !sawProbe(ss) {
		c.fail("session: language_probe %s but no QUI probe in the probe phase", s.LanguageProbe)
	}
	quit := len(ss) > 0 && ss[len(ss)-1].phase == PhaseClose
	if s.QuitSent != quit {
		c.fail("session: quit_sent must match a QUI sent last, in the close phase")
	}
	if s.Connected {
		want := "0"
		if level > 0 {
			want = strconv.Itoa(level)
		}
		if s.AccessLevel != want {
			c.fail("session: access_level %q, but the highest prompt received shows %q", s.AccessLevel, want)
		}
	}
	if code == RefusedSessionPendingPassword && (len(ss) != 0 || last != promptPassword) {
		c.fail("%s: the device printed only %q, and nothing was sent", code, promptPassword)
	}
	if code == RefusedSessionElevated && first != promptLevel1 && first != promptLevel2 {
		c.fail("%s: the first prompt received is %q, not an elevated one", code, first)
	}
	// A session that reached Level 1 ends with QUI (D18, V-S13), except where
	// the bytes make it impossible or unsafe: the connection closed, the level
	// already dropped, the port is not English (D16), or the session was
	// found elevated and left to TIDLE.
	if level >= 1 && !quit {
		switch code {
		case FailedTransportClosed, FailedAccessLevelDropped, RefusedLanguageNotEnglish, RefusedSessionElevated:
		default:
			c.fail("session: Level %d was reached, so the session ends with QUI (D18, V-S13)", level)
		}
	}
	if code == FailedAccessLevelDropped && last != promptLevel0 && !quit {
		c.fail("%s: the last prompt received is %q, not %q", code, last, promptLevel0)
	}
}

func (c *check) probeOutcome(reply []byte, s SessionFacts) {
	ok := ProbeReplyAccepted(reply)
	switch {
	case s.LanguageProbe == ProbeAccepted && !ok:
		c.fail("session: language_probe accepted, but the reply does not match the probe grammar")
	case s.LanguageProbe == ProbeRejected && ok:
		c.fail("session: language_probe rejected, but the reply matches the probe grammar")
	case s.LanguageProbe == ProbeNotRun:
		c.fail("session: a QUI probe was sent, so language_probe is accepted or rejected")
	}
}

func sawProbe(ss []send) bool {
	for _, x := range ss {
		if x.phase == PhaseProbe && isLine(x.b, "QUI") {
			return true
		}
	}
	return false
}

package adapter

import (
	"bytes"
	"errors"
	"fmt"

	"otsec.local/otsec/contracts/register"
)

// CheckLines checks every line the result says was sent against the register
// package and the invocation it ran (A3 C2 review change 3). It is the oracle
// for "no unauthorized write" (brief section 7, EP-4): Validate checks what
// the bytes and the prompts allow, and CheckLines checks what the register
// allows. Run both on every result, from the collector or a simulator.
//
//   - The result names the invocation and operation, and the package that
//     permitted its lines (register_version is the package's revision).
//   - Each sent line, apart from the wake and the credential, is one line of
//     printable ASCII with one line end, and passes the register's egress
//     check (Matcher.Permit) for its phase. So probe lines are QUI and level
//     0 operations, the auth line is ACC, and the close line is QUI.
//   - An operate line is the invocation's operation, rendered with its
//     parameters, or an operation the register reads a precondition, a
//     posture warning or a firmware condition with, or a context setting
//     for the invocation's operation (C3 0.2, D3-2). Nothing else, even when
//     it is read-only: a context read for another operation is refused.
//   - Each reported setting (0.5) is one a context read for the invocation's
//     operation names, and its span lies in the reply to that read's line:
//     the bytes received after it was sent and before the next send. So a
//     DATE_F can only come from the SHO G reply, never from a SER row that
//     happens to hold "MDY" (A4 on #164). Validate checks that the span
//     selects the value; this checks where the value came from.
func (r Result) CheckLines(p *register.Package, inv Invocation) error {
	m, err := register.NewMatcher(p)
	if err != nil {
		return fmt.Errorf("adapter: lines: %w", err)
	}
	var errs []error
	fail := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if r.InvocationID != inv.InvocationID || r.OperationID != inv.OperationID {
		fail("the result is for invocation %s, operation %s, not %s, %s", r.InvocationID, r.OperationID, inv.InvocationID, inv.OperationID)
	}
	unverified := r.Error != nil && r.Error.Code == RefusedRegisterUnverified && r.RegisterVersion == 0
	if r.RegisterVersion != p.Revision && !unverified {
		fail("register_version %d, but the package is revision %d", r.RegisterVersion, p.Revision)
	}
	own, err := m.Render(inv.OperationID, inv.Params)
	if err != nil {
		fail("the invocation's operation does not render: %v", err)
	}
	reads := map[string]bool{inv.OperationID: true}
	for _, s := range p.Preconditions {
		reads[s.ReadBy] = true
	}
	for _, w := range p.Warnings {
		reads[w.ReadBy] = true
	}
	for _, b := range p.Firmware.Branches {
		for _, s := range b.Conditions {
			reads[s.ReadBy] = true
		}
	}
	for _, c := range p.ContextFor(inv.OperationID) {
		reads[c.ReadBy] = true
	}
	if !r.coversExactly() {
		return fmt.Errorf("adapter: lines: the segments do not cover the transcript")
	}
	ss, _ := sends(r.Transcript)
	// replyTo[i] is the operation whose line send i was, when it was an
	// operate line the register knows; its reply runs to the next send.
	replyTo := make([]string, len(ss))
	for i, x := range ss {
		at := fmt.Sprintf("transcript.segments[%d]", x.seg)
		if x.cred || (x.phase == PhaseProbe && isWake(x.b)) {
			continue
		}
		line, ok := oneLine(x.b)
		if !ok {
			fail("%s: a send is one line with one line end", at)
			continue
		}
		v, id, err := m.Permit(register.Phase(x.phase), line)
		if err != nil {
			fail("%s: %v", at, err)
			continue
		}
		if x.phase != PhaseOperate || v != register.VerdictOperation {
			continue
		}
		replyTo[i] = id
		if !reads[id] {
			fail("%s: %q is operation %s, which this invocation does not run or need", at, line, id)
		}
		if id == inv.OperationID && line != own {
			fail("%s: %q is not the invocation's line %q", at, line, own)
		}
	}
	ctx := p.ContextFor(inv.OperationID)
	for i, st := range r.Settings {
		from := map[string]bool{}
		for _, c := range ctx {
			if c.Setting == st.Name {
				from[c.ReadBy] = true
			}
		}
		if len(from) == 0 {
			fail("settings[%d]: %s is not a context read of %s in this package", i, st.Name, inv.OperationID)
			continue
		}
		if !from[r.replyHolding(ss, replyTo, st.Span)] {
			fail("settings[%d]: %s does not lie in the reply to the line that reads it", i, st.Name)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("adapter: lines: %w", errors.Join(errs...))
	}
	return nil
}

// replyHolding returns the operation whose reply holds sp: the bytes from
// the end of its send to the start of the next send, or to the end of the
// transcript. It returns "" when no single such reply holds sp.
func (r Result) replyHolding(ss []send, replyTo []string, sp Span) string {
	t := r.Transcript
	for i, x := range ss {
		sg := t.Segments[x.seg]
		start, end := sg.Offset+sg.Length, int64(len(t.Data))
		if i+1 < len(ss) {
			end = t.Segments[ss[i+1].seg].Offset
		}
		if sp.Offset >= start && sp.Length > 0 && sp.Offset+sp.Length <= end {
			return replyTo[i]
		}
	}
	return ""
}

// oneLine returns b without its one line end, when b is one line.
func oneLine(b []byte) (string, bool) {
	for _, eol := range []string{"\r\n", "\r", "\n"} {
		if text, ok := bytes.CutSuffix(b, []byte(eol)); ok && !bytes.ContainsAny(text, "\r\n") && len(text) > 0 {
			return string(text), true
		}
	}
	return "", false
}

// coversExactly reports whether the segments cover the data in order.
func (r Result) coversExactly() bool {
	var next int64
	for _, s := range r.Transcript.Segments {
		if s.Offset != next || s.Length <= 0 {
			return false
		}
		next += s.Length
	}
	return next == int64(len(r.Transcript.Data))
}

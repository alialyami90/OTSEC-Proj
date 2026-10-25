package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/modules/ied/sel751"
	"otsec.local/otsec/modules/security/collectorwire"
)

// SEL751Runner is the Runner for the SEL-751 adapter (D2-1): it runs A2's
// sel751.Run with what the plan carries, and reports the session's records
// through plan.Audit. sel751.Run never returns a Go error; every outcome is
// a C2 result, which the pipeline checks.
type SEL751Runner struct {
	// Now is the transcript clock; nil means time.Now.
	Now func() time.Time
	// Alarm receives a result that cannot be encoded. Nil drops it.
	Alarm func(error)
}

// passwordPrompt is the SEL-751 password prompt (C3 register, prompts).
var passwordPrompt = []byte("Password: ?")

// Run runs one plan.
func (r *SEL751Runner) Run(ctx context.Context, plan RunPlan) RunReport {
	cfg := sel751.Config{
		Asset: plan.Asset, Profile: plan.Profile, Register: plan.Register,
		Endpoint: plan.Endpoint.ID, Dial: plan.Dial, Now: r.Now,
	}
	// A nil *SecretHandle stored in the interface is not a nil interface,
	// and Run would refuse every Level 0 run (A2 on #97): set the slot and
	// its gate only when there is a secret.
	if plan.Secret != nil {
		cfg.Secret, cfg.Floor = plan.Secret, plan.Floor
	}
	res := sel751.Run(ctx, plan.Invocation, cfg)

	if endsAtPasswordPrompt(res.Transcript) {
		// A line the adapter sent, the wake line end or ID, may have
		// landed as a password, and a Level 0 run has no gate to record
		// it (A3 on #99, A6 on #112).
		plan.Floor.Unconfirmed()
	}
	confirmed := plan.Floor.LoginConfirmed()
	plan.Audit.ReportSession(res, confirmed)

	report := RunReport{
		// The pipeline reads QUISent only after a confirmed login.
		QUISent: res.Session.QuitSent || !confirmed,
		// TIDLE stays 0, so the floor after an exit without QUI is the
		// 31-minute fallback, until sel751 reports the TIDLE it read (A2
		// on #97).
	}
	b, err := json.Marshal(res)
	if err != nil {
		if r.Alarm != nil {
			r.Alarm(fmt.Errorf("collector: encode the result of %s: %w", plan.Invocation.InvocationID, err))
		}
		b = nil
	}
	report.Outcome = collectorwire.RunOutcome{Wire: collectorwire.WireID, InvocationID: plan.Invocation.InvocationID, Result: b}
	return report
}

// endsAtPasswordPrompt reports a session whose last received bytes, since
// the last line sent, end at the password prompt: whatever the adapter sent
// before them may have been taken as a password attempt (S22 p. 7.33,
// three failures pulse SALARM), so the floor is set whatever the result's
// code. On the path through ACC the gate has already set it, and setting it
// again only moves it later.
//
// The prompt rule is sel751's promptOf for the password prompt (itself
// C2's rule; both are unexported): NUL, XON and XOFF are ignored, trailing
// spaces are trimmed, and the prompt counts only first in the bytes or
// right after CR, LF, STX or ETX.
func endsAtPasswordPrompt(t adapter.Transcript) bool {
	start := len(t.Segments)
	for start > 0 && t.Segments[start-1].Dir == adapter.Received {
		start--
	}
	var rx []byte
	for _, sg := range t.Segments[start:] {
		if sg.Offset < 0 || sg.Length < 0 || sg.Offset+sg.Length > int64(len(t.Data)) {
			return false
		}
		rx = append(rx, t.Data[sg.Offset:sg.Offset+sg.Length]...)
	}
	clean := bytes.Map(func(r rune) rune {
		switch r {
		case 0x00, 0x11, 0x13:
			return -1
		}
		return r
	}, rx)
	clean = bytes.TrimRight(clean, " ")
	if !bytes.HasSuffix(clean, passwordPrompt) {
		return false
	}
	before := clean[:len(clean)-len(passwordPrompt)]
	return len(before) == 0 || bytes.IndexByte([]byte("\r\n\x02\x03"), before[len(before)-1]) >= 0
}

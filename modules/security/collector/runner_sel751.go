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

	if wakeHitPassword(res) {
		// The bare line end probably landed as a blank password, and a
		// Level 0 run has no gate to record it (A3 on #99).
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

// wakeHitPassword reports a session whose wake was answered by the
// password prompt: sel751 ends it as failed.internal with wake_sent, and
// the last bytes received are the prompt.
func wakeHitPassword(res adapter.Result) bool {
	if res.Error == nil || res.Error.Code != adapter.FailedInternal || !res.Session.WakeSent {
		return false
	}
	t := res.Transcript
	for i := len(t.Segments) - 1; i >= 0; i-- {
		sg := t.Segments[i]
		if sg.Dir != adapter.Received {
			continue
		}
		if sg.Offset < 0 || sg.Offset+sg.Length > int64(len(t.Data)) {
			return false
		}
		rx := bytes.TrimRight(t.Data[sg.Offset:sg.Offset+sg.Length], " \x00\x11\x13")
		return bytes.HasSuffix(rx, passwordPrompt)
	}
	return false
}

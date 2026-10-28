package sel751

import (
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

// B3 on #331 (D4-13 condition 4): the run's own deadline ends a run that an
// invocation allows more time. The relay stops answering at SHO 2, and the
// invocation's deadline and step timeout are far off; the run's deadline,
// from the signed register, is what ends it, not the step's timeout. QUI is sent (the login was
// confirmed), the bytes read are kept, and no record is reported.
func TestConfigRunDeadlineIsTheRuns(t *testing.T) {
	f := loadConfig(t)
	p := *f.reg
	p.Runs = append([]register.Run(nil), p.Runs...)
	p.Runs[0].DeadlineMS = 1000
	// The register holds a step's timeout to the run's deadline, so each is
	// as long as the deadline: the deadline, which runs from the connection,
	// is reached first.
	p.Operations = append([]register.Operation(nil), p.Operations...)
	for i := range p.Operations {
		if l := p.Operations[i].Limits; l != nil {
			c := *l
			c.TimeoutMS = 1000
			p.Operations[i].Limits = &c
		}
	}
	f.reg = &p
	f.inv.Limits.DeadlineMS, f.inv.Limits.StepTimeoutMS = 600_000, 60_000

	steps := stepsUpTo(t, "SHO 2", func([]byte) []byte { return nil })
	start := time.Now()
	got, _, _ := play(t, f, steps, false, nil)
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v: the run did not stop at its own deadline", d)
	}
	if got.Error == nil || got.Error.Code != adapter.FailedTimeout || !got.Session.QuitSent || len(got.Records) != 0 {
		t.Fatalf("result %s", jsonOf(t, got.Error))
	}
	if !strings.Contains(got.Error.Detail, "deadline") {
		t.Errorf("detail %q does not name the deadline", got.Error.Detail)
	}
	if len(got.Transcript.Data) == 0 {
		t.Error("the bytes read were not kept")
	}
}

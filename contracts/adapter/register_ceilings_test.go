package adapter

import (
	"testing"

	"otsec.local/otsec/contracts/register"
)

// C3 0.3 bounds a register's limits and runs by C2's invocation ceilings, but
// register cannot import adapter, so it holds its own copies. They must be
// the same numbers: a run that the register accepts must fit an invocation
// that C2 accepts (P4-A2, D4-13).
func TestRegisterCeilingsAreC2s(t *testing.T) {
	if register.MaxSessionBytes != MaxResponseBytes || register.MaxStepMS != MaxStepTimeoutMS || register.MaxDeadlineMS != MaxDeadlineMS {
		t.Fatalf("register ceilings %d bytes, %d ms step, %d ms deadline; C2's are %d, %d, %d",
			register.MaxSessionBytes, register.MaxStepMS, register.MaxDeadlineMS, MaxResponseBytes, MaxStepTimeoutMS, MaxDeadlineMS)
	}
}

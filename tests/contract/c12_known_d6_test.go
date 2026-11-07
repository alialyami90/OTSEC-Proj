package contract

// finding.Known (P4-H3 step 1, D4-61): D6's cases. Known names the minors
// this build reads. Validate is a writer's check and accepts any 0.x minor
// of C12, so a reader that decided what to fold by Validate would take a
// newer minor it does not understand: the reader's question is Known's.
// Expected outcomes come from D4-61's rule text: this build's minor and
// every earlier one are read, nothing newer and nothing in another
// spelling. Evidence class: desk.

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/finding"
)

func TestC12KnownIsWhatThisBuildReads(t *testing.T) {
	cur, err := strconv.Atoi(strings.TrimPrefix(finding.Identifier, "otsec.finding/0."))
	if err != nil {
		t.Fatalf("Identifier %q", finding.Identifier)
	}
	want := map[string]bool{}
	for m := 1; m <= cur; m++ {
		want[fmt.Sprintf("otsec.finding/0.%d", m)] = true
	}
	cases := []string{
		fmt.Sprintf("otsec.finding/0.%d", cur+1), fmt.Sprintf("otsec.finding/0.%d", cur+9), "otsec.finding/0.10",
		"otsec.finding/1.0", "otsec.finding/0.0", "otsec.finding/0.01", "otsec.finding/0.1 ", " otsec.finding/0.1",
		"otsec.finding/0.1\x00", "otsec.finding/", "otsec.finding/0", "otsec.config/0.1", "OTSEC.FINDING/0.1", "",
	}
	for s := range want {
		cases = append(cases, s)
	}
	for _, s := range cases {
		if got := finding.Known(s); got != want[s] {
			t.Errorf("Known(%q) = %v, want %v", s, got, want[s])
		}
		f := c12Finding()
		f.Schema = s
		if finding.Known(s) && f.Validate() != nil {
			t.Errorf("Known(%q), but Validate refuses a finding stamped with it: %v", s, f.Validate())
		}
	}
	// The gap Known closes: Validate takes a newer minor.
	f := c12Finding()
	f.Schema = fmt.Sprintf("otsec.finding/0.%d", cur+1)
	if f.Validate() != nil {
		t.Logf("Validate now refuses %s too", f.Schema)
	}
}

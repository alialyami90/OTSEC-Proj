package contract

// C13 §6's counter names pinned by value (D6 on #566, D4-72), with the
// eight C13 0.2 adds (CH-26, CH-29, CH-34) and C4 0.4 accepts from 0.4 on
// (C4-0.4-1; P4-4-CC deliverable 2). The counters a C4 sensor.counters
// event may carry as diff.<name> are the heartbeat's counters. The lists
// below are copied from C13 §6, in its order, and from C4 0.4 §2's table,
// in its order. netobs.Counters' JSON names, the heartbeat the node reads
// them from (D3 on #566), must be the thirteen then the eight;
// event.SensorCounters, the names C4 accepts at every minor from 0.3, the
// thirteen (D6's S1 and S2 on #566); and event.SensorCounters04, the names
// it accepts from 0.4, the eight. A name that drifts on either side would
// refuse the node's own events. Ground truth: GT-HAND, from the contract
// text. Evidence class: desk.

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/contracts/netobs"
)

var c13Counters = []string{"packets", "bytes", "drops_driver", "drops_decoder", "drops_channel", "decoder_errors",
	"sessions_unparsed", "table_evictions", "dnp3_pending_overflows", "dnp3_seq_reused", "prp_discards",
	"redactions", "logins_not_placed"}

var c13Counters02 = []string{"drops_holder", "frames_overlong", "frames_outgoing", "prp_mismatched",
	"prp_table_full", "prp_tag_differs", "prp_wrong_lan", "engine_lines_refused"}

func TestSensorCountersByValue(t *testing.T) {
	if !slices.Equal(event.SensorCounters, c13Counters) {
		t.Errorf("event.SensorCounters %v, C13 §6 lists %v", event.SensorCounters, c13Counters)
	}
	if !slices.Equal(event.SensorCounters04, c13Counters02) {
		t.Errorf("event.SensorCounters04 %v, C4 0.4 §2 lists %v", event.SensorCounters04, c13Counters02)
	}
	var tags []string
	ty := reflect.TypeOf(netobs.Counters{})
	for i := range ty.NumField() {
		name, _, _ := strings.Cut(ty.Field(i).Tag.Get("json"), ",")
		tags = append(tags, name)
	}
	if want := append(slices.Clone(c13Counters), c13Counters02...); !slices.Equal(tags, want) {
		t.Errorf("netobs.Counters' JSON names %v, C13 §6 and C13 0.2 list %v", tags, want)
	}
}

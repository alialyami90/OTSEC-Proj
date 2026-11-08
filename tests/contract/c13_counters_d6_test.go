package contract

// C13 §6's counter names pinned by value (D6 on #566, D4-72). The counters
// a C4 0.3 sensor.counters event may carry as diff.<name> are C13 §6's
// heartbeat counters. The list below is copied from that section, in its
// order. It must equal the JSON names of netobs.Counters, the heartbeat the
// node reads them from (D3 on #566), and event.SensorCounters, the names
// C4 0.3's Validate accepts (D6's S1 and S2 on #566). A name that drifts on
// either side would refuse the node's own events. Ground truth: GT-HAND, from the contract text. Evidence class:
// desk.

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

func TestSensorCountersByValue(t *testing.T) {
	if !slices.Equal(event.SensorCounters, c13Counters) {
		t.Errorf("event.SensorCounters %v, C13 §6 lists %v", event.SensorCounters, c13Counters)
	}
	var tags []string
	ty := reflect.TypeOf(netobs.Counters{})
	for i := range ty.NumField() {
		name, _, _ := strings.Cut(ty.Field(i).Tag.Get("json"), ",")
		tags = append(tags, name)
	}
	if !slices.Equal(tags, c13Counters) {
		t.Errorf("netobs.Counters' JSON names %v, C13 §6 lists %v", tags, c13Counters)
	}
}

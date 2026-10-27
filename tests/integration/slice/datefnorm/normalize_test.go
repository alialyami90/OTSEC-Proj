// Package datefnorm is the normalizer step of the slice's DATE_F reconcile
// (A2, P3-A2; test_sel751_date_orders.py): it reads one C2 result that the
// SEL-751 adapter produced against A6's recording simulator, with the
// invocation and asset it answered, and writes the C4 events
// normalize.Normalize makes of it. The checks are in the Python test,
// against A6's transcription of S22 Figure 10.16, not here.
//
// Evidence class: simulated. It covers the adapter's result through the
// normalizer only, not the store, the forwarder or the real binaries.
package datefnorm

import (
	"encoding/json"
	"os"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/telemetry/normalize"
)

// TestNormalizeSimResult is skipped unless OTSEC_DATEF_RESULT is set:
//
//	OTSEC_DATEF_RESULT  the C2 result (sel751 TestSimulator's
//	                    OTSEC_SEL751_SIM_RESULT), with .inv.json and
//	                    .asset.json beside it
//	OTSEC_DATEF_EVENTS  a file to write the events to, as a JSON array
//
// No date order is given: the order must come from the result's DATE_F.
func TestNormalizeSimResult(t *testing.T) {
	p := os.Getenv("OTSEC_DATEF_RESULT")
	if p == "" {
		t.Skip("OTSEC_DATEF_RESULT not set")
	}
	read := func(path string) []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	res, err := adapter.DecodeResult(read(p))
	if err != nil {
		t.Fatalf("result: %v", err)
	}
	inv, err := adapter.DecodeInvocation(read(p + ".inv.json"))
	if err != nil {
		t.Fatalf("invocation: %v", err)
	}
	a, err := asset.Decode(read(p + ".asset.json"))
	if err != nil {
		t.Fatalf("asset: %v", err)
	}
	out, err := normalize.Normalize(res, inv, a, normalize.Input{
		Node: "site-a-node1", Stream: "sel751-feeder1/ser", HealthStream: "platform/health",
		ClockResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized, Source: "w32time"},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	b, err := json.Marshal(out.Events)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("OTSEC_DATEF_EVENTS"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

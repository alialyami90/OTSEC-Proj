package sel751

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestSimulator runs one invocation against A6's recording simulator
// (tests/safety/recording_simulator, profile sel-751-doc), which must already
// be listening. It is skipped unless OTSEC_SEL751_SIM is set:
//
//	OTSEC_SEL751_SIM          host:port of the simulator
//	OTSEC_SEL751_SIM_PASSWORD its --profile-password (unset: ACC needs none)
//	OTSEC_SEL751_SIM_FID      its --profile-fid, declared on the asset
//	OTSEC_SEL751_SIM_SERIAL   the serial its SER report prints, declared
//	OTSEC_SEL751_SIM_OP       sel.ser.read_all (default) or sel.id
//	OTSEC_SEL751_SIM_EXPECT   the expected error code, or "ok" (default)
//
// The simulator answers from manual examples, so a pass is simulated
// evidence only (CLAUDE.md section 3).
func TestSimulator(t *testing.T) {
	addr := os.Getenv("OTSEC_SEL751_SIM")
	if addr == "" {
		t.Skip("OTSEC_SEL751_SIM not set")
	}
	f := load(t)
	if os.Getenv("OTSEC_SEL751_SIM_OP") == "sel.id" {
		level0(t, &f)
	}
	if v := os.Getenv("OTSEC_SEL751_SIM_FID"); v != "" {
		f.declare("firmware_id", v)
	}
	if v := os.Getenv("OTSEC_SEL751_SIM_SERIAL"); v != "" {
		f.declare("serial_number", v)
	}
	cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}}
	fl := &floor{}
	if f.inv.OperationID != opID {
		cfg.Floor = fl
		cfg.Secret = &secret{b: []byte(os.Getenv("OTSEC_SEL751_SIM_PASSWORD"))}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	got := Run(ctx, f.inv, cfg)
	t.Logf("result:\n%s", jsonOf(t, got))
	t.Logf("transcript:\n%s", strings.ReplaceAll(string(got.Transcript.Data), "\r\n", "\\r\\n\n"))
	t.Logf("floor calls: %v", fl.calls)
	check(t, f, got)
	want := os.Getenv("OTSEC_SEL751_SIM_EXPECT")
	code := "ok"
	if got.Error != nil {
		code = string(got.Error.Code)
	}
	if want == "" {
		want = "ok"
	}
	if code != want {
		t.Errorf("code %s, want %s", code, want)
	}
	if got.Target != "simulated" {
		t.Errorf("target %s", got.Target)
	}
}

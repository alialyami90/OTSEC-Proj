package sel751

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
)

// The replay tests drive Run against a scripted far end built from each C2
// golden result (contracts/adapter/testdata/results/valid): the far end
// checks that every line Run sends is exactly the golden's sent segment and
// answers with the golden's received segments. Run's result must then equal
// the golden, apart from times, the adapter version, and an error detail
// the golden leaves out. Every transcript is invented (C2 testdata README);
// this is simulated evidence only.

const (
	testSecret = "Lab!pw-0451" // a test value, never a real credential; TestTestSecretInstalls
	goldenDir  = "../../../contracts/adapter/testdata"
	fidR402    = "SEL-751-R402-V2-Z102100-D20250731"
	fidOther   = "SEL-751-R500-V1-Z103101-D20260910"
	fidDenied  = "SEL-751-R302-V9-Z010005-D20260831"
)

// inputs is everything one run needs, loaded from the contract testdata.
type inputs struct {
	inv     adapter.Invocation
	asset   asset.Asset
	profile asset.CapabilityProfile
	reg     *register.Package
}

func load(t testing.TB) inputs {
	t.Helper()
	read := func(p string) []byte {
		b, err := os.ReadFile(filepath.Join("../../..", p))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var f inputs
	var err error
	if f.inv, err = adapter.DecodeInvocation(read("contracts/adapter/testdata/invocations/valid/sel-ser-read.json")); err != nil {
		t.Fatal(err)
	}
	if f.asset, err = asset.Decode(read("contracts/asset/testdata/valid/sel-751-simulated.json")); err != nil {
		t.Fatal(err)
	}
	if f.profile, err = asset.DecodeProfile(read("contracts/asset/testdata/valid/profile-sel-751-ascii.json")); err != nil {
		t.Fatal(err)
	}
	if f.reg, err = register.Decode(read("contracts/register/testdata/sel-751-rev4.json")); err != nil {
		t.Fatal(err)
	}
	return f
}

// declare sets a declared attribute on the asset and in the invocation.
func (f *inputs) declare(name, value string) {
	for i, a := range f.asset.Attributes {
		if a.Name != name {
			continue
		}
		f.asset.Attributes[i].Value = value
		obs := append([]asset.Observation(nil), a.Observations...)
		for j := range obs {
			obs[j].Value = value
		}
		f.asset.Attributes[i].Observations = obs
	}
	for i, e := range f.inv.Expected {
		if e.Name == name {
			f.inv.Expected[i].Value = value
		}
	}
}

// secret is a test credential slot that records how it was used.
type secret struct {
	b    []byte
	uses int
}

func (s *secret) Use(f func([]byte) error) error {
	if s.uses++; s.uses > 1 {
		return errors.New("secret: used twice")
	}
	return f(append([]byte(nil), s.b...))
}

func (s *secret) EchoSpans(rx []byte) [][2]int {
	var out [][2]int
	for i := 0; ; {
		j := bytes.Index(rx[i:], s.b)
		if j < 0 {
			return out
		}
		out = append(out, [2]int{i + j, i + j + len(s.b)})
		i += j + len(s.b)
	}
}

// floor records the gate calls in order.
type floor struct {
	calls []string
	fail  bool
}

func (f *floor) BeforeACC(context.Context) error {
	f.calls = append(f.calls, "before")
	if f.fail {
		return errors.New("floor: store unavailable")
	}
	return nil
}
func (f *floor) Confirmed(context.Context) { f.calls = append(f.calls, "confirmed") }

// clock advances 100 ms per reading, so times are distinct and ordered.
func clock() func() time.Time {
	t := time.Date(2026, 10, 24, 9, 15, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(100 * time.Millisecond); return t }
}

// step is one turn of the scripted far end: the bytes it must receive
// (none for the first turn), then the bytes it sends back.
type step struct {
	expect []byte
	reply  []byte
}

// script cuts a golden transcript into turns. The credential segment is
// expected as the test secret and CR LF, and an echo redaction is sent as
// the secret itself, as a relay that echoes would.
func script(r adapter.Result) []step {
	t := r.Transcript
	red := map[int64]adapter.RedactionReason{}
	for _, rd := range t.Redactions {
		red[rd.Offset] = rd.Reason
	}
	wire := func(sg adapter.Segment) []byte {
		b := t.Data[sg.Offset : sg.Offset+sg.Length]
		var out []byte
		for i := int64(0); i < int64(len(b)); i++ {
			if _, ok := red[sg.Offset+i]; ok {
				out = append(out, testSecret...)
				i += int64(len(adapter.RedactionMarker)) - 1
				continue
			}
			out = append(out, b[i])
		}
		return out
	}
	steps := []step{{}}
	for _, sg := range t.Segments {
		if sg.Dir == adapter.Sent {
			steps = append(steps, step{expect: wire(sg)})
			continue
		}
		last := &steps[len(steps)-1]
		last.reply = append(last.reply, wire(sg)...)
	}
	return steps
}

// farEnd plays a script on one connection. hangUp closes the connection
// after the last reply instead of waiting for Run to close it.
func farEnd(c net.Conn, steps []step, hangUp bool) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer c.Close()
		for i, st := range steps {
			if len(st.expect) > 0 {
				got := make([]byte, len(st.expect))
				_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, st.expect) {
					done <- fmt.Errorf("turn %d: received %q (%v), want %q", i, got, err, st.expect)
					return
				}
			}
			if len(st.reply) > 0 {
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := c.Write(st.reply); err != nil {
					done <- fmt.Errorf("turn %d: %v", i, err)
					return
				}
			}
		}
		if hangUp {
			done <- nil
			return
		}
		// Anything more Run sends is a line the golden does not have.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		extra, _ := io.ReadAll(c)
		if len(extra) > 0 {
			done <- fmt.Errorf("after the script: received %q", extra)
			return
		}
		done <- nil
	}()
	return done
}

// normal clears what a replay cannot reproduce: times, the build version,
// the schema (Run stamps this package's minor, a golden the minor it was
// written for), and a detail the golden does not state.
func normal(r adapter.Result, keepDetail bool) adapter.Result {
	r.StartedAt, r.EndedAt = "", ""
	r.Schema = ""
	r.Adapter.Version = ""
	r.Transcript.Segments = append([]adapter.Segment(nil), r.Transcript.Segments...)
	for i := range r.Transcript.Segments {
		r.Transcript.Segments[i].At = ""
	}
	if r.Error != nil && !keepDetail {
		e := *r.Error
		e.Detail = ""
		r.Error = &e
	}
	return r
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// check runs the collector's own checks on a result (C2 doc: Validate,
// CheckLines, CheckAgainst).
func check(t *testing.T, f inputs, r adapter.Result) {
	t.Helper()
	if err := r.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if f.reg != nil {
		if err := r.CheckLines(f.reg, f.inv); err != nil {
			t.Errorf("CheckLines: %v", err)
		}
	}
	if err := r.CheckAgainst(f.inv, f.asset); err != nil {
		t.Errorf("CheckAgainst: %v", err)
	}
	if bytes.Contains(r.Transcript.Data, []byte(testSecret)) {
		t.Error("the secret is in the transcript")
	}
}

// replay is one golden and how to set the far end and the run up for it.
type replay struct {
	golden string
	setup  func(f *inputs, cfg *Config)
	hangUp bool
	// limits derive from the script: the step timeout for a silent far end,
	// the response budget for one that sends too much.
	limits func(l *adapter.Limits, steps []step)
}

var replays = []replay{
	{golden: "ok"},
	{golden: "ok-with-echo"},
	{golden: "ok-missing-setting"},
	{golden: "partial.parse_errors"},
	{golden: "partial.read_rows_exceeded"},
	// DATE_F from SHO G (register rev 4, D3-2): the three orders, and the
	// three ways the order is unknown, which leave the rows unparsed.
	{golden: "ok-date-ymd"},
	{golden: "ok-date-dmy"},
	{golden: "partial.parse_errors-date-f-unknown"},
	{golden: "partial.parse_errors-date-f-missing"},
	{golden: "partial.parse_errors-date-misfit"},
	{golden: "refused.session_elevated"},
	{golden: "refused.session_pending_password"},
	{golden: "refused.language_probe_rejected"},
	{golden: "failed.timeout-probe-unanswered", limits: func(l *adapter.Limits, _ []step) { l.StepTimeoutMS = 300 }},
	{golden: "failed.transport_closed-probe-unanswered", hangUp: true},
	{golden: "refused.identity_mismatch"},
	{golden: "failed.identity_unreadable"},
	{golden: "failed.identity_unreadable-no-fid-line"},
	{golden: "refused.password_prompt_absent"},
	{golden: "refused.language_not_english"},
	{golden: "refused.firmware_condition_not_met", setup: func(f *inputs, _ *Config) { f.declare("firmware_id", fidR402) }},
	{golden: "failed.auth_rejected"},
	{golden: "failed.unexpected_access_level"},
	{golden: "failed.identity_mismatch"},
	{golden: "failed.access_level_dropped"},
	{golden: "failed.device_error"},
	{golden: "failed.timeout", limits: func(l *adapter.Limits, _ []step) { l.StepTimeoutMS = 300 }},
	{golden: "failed.transport_closed", hangUp: true},
	{golden: "failed.response_too_large", limits: func(l *adapter.Limits, steps []step) {
		// The budget ends exactly where the golden's SER reply stops.
		var n int64
		for _, st := range steps[:len(steps)-1] {
			n += int64(len(st.reply))
		}
		l.MaxResponseBytes = n
	}},
	{golden: "failed.egress_violation", setup: func(_ *inputs, cfg *Config) {
		cfg.hooks.egress = func(_ adapter.Phase, line string) error {
			if line == "SHO P 1" {
				return errors.New("test: refused")
			}
			return nil
		}
	}},
	{golden: "failed.internal", setup: func(_ *inputs, cfg *Config) { cfg.Floor.(*floor).fail = true }},
	// The wake answered by the password prompt: nothing more is sent, and
	// the collector sets the floor from the result (A3 on #99).
	{golden: "failed.internal-wake-password-prompt"},
	// C2 0.2 (D2-14): the two device states FuzzRun found.
	{golden: "failed.unexpected_password_prompt"},
	{golden: "probe-rejected-at-level1"},
}

// floorCalls is what each replay must do with the failed-auth floor: the
// attempt is recorded before ACC, and cleared only on "=>" after ACC,
// whether or not the password was sent (D1-20 as amended, AP-23).
var floorCalls = map[string]string{
	"ok": "before,confirmed", "ok-with-echo": "before,confirmed", "ok-missing-setting": "before,confirmed",
	"partial.parse_errors": "before,confirmed", "partial.read_rows_exceeded": "before,confirmed",
	"ok-date-ymd": "before,confirmed", "ok-date-dmy": "before,confirmed",
	"partial.parse_errors-date-f-unknown": "before,confirmed", "partial.parse_errors-date-f-missing": "before,confirmed",
	"partial.parse_errors-date-misfit": "before,confirmed",
	"refused.password_prompt_absent":   "before,confirmed", "refused.language_not_english": "before,confirmed",
	"refused.firmware_condition_not_met": "before,confirmed", "failed.identity_mismatch": "before,confirmed",
	"failed.access_level_dropped": "before,confirmed", "failed.device_error": "before,confirmed",
	"failed.timeout": "before,confirmed", "failed.transport_closed": "before,confirmed",
	"failed.response_too_large": "before,confirmed", "failed.egress_violation": "before,confirmed",
	"failed.unexpected_password_prompt": "before,confirmed",
	// Nothing after a rejected probe, so the floor is never touched (D16).
	"probe-rejected-at-level1": "",
	// Nothing after the wake: ACC is never reached, so the adapter does not
	// touch the floor; the collector sets it from the result.
	"failed.internal-wake-password-prompt": "",
	// The floor stays set: no "=>" confirmed the attempt.
	"failed.auth_rejected": "before", "failed.unexpected_access_level": "before", "failed.internal": "before",
}

// reportsTIDLE are the replays that end ok or partial after a SHO P 1 reply
// showing an English port with TIDLE := 15, so Config.TIDLE is called once
// with 15 minutes. No other replay calls it: a failed or refused run's
// TIDLE is not reported, though SHO P 1 showed it (P3-A2), and the Spanish
// port's TIDLE is not read at all (D16).
var reportsTIDLE = map[string]bool{
	"ok": true, "ok-with-echo": true, "ok-missing-setting": true, "partial.parse_errors": true,
	"partial.read_rows_exceeded": true, "ok-date-ymd": true, "ok-date-dmy": true,
	"partial.parse_errors-date-f-unknown": true, "partial.parse_errors-date-f-missing": true,
	"partial.parse_errors-date-misfit": true,
}

func TestReplayGoldens(t *testing.T) {
	for _, rp := range replays {
		t.Run(rp.golden, func(t *testing.T) {
			want := golden(t, rp.golden)
			f := load(t)
			sec := &secret{b: []byte(testSecret)}
			fl := &floor{}
			var tidles []time.Duration
			cfg := Config{Secret: sec, Floor: fl, Now: clock(),
				TIDLE: func(d time.Duration) { tidles = append(tidles, d) },
				hooks: &hooks{quiet: 20 * time.Millisecond, wakeWait: 50 * time.Millisecond}}
			if rp.setup != nil {
				rp.setup(&f, &cfg)
			}
			steps := script(want)
			if rp.limits != nil {
				rp.limits(&f.inv.Limits, steps)
			}
			near, far := net.Pipe()
			done := farEnd(far, steps, rp.hangUp)
			dials := 0
			cfg.Asset, cfg.Profile, cfg.Register = f.asset, f.profile, f.reg
			cfg.Endpoint = f.inv.EndpointID
			cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if dials++; dials > 1 {
					return nil, errors.New("dialled twice")
				}
				if network != "tcp" || addr != "192.0.2.21:23" {
					return nil, fmt.Errorf("dialled %s %s", network, addr)
				}
				return near, nil
			}
			got := Run(context.Background(), f.inv, cfg)
			if err := <-done; err != nil {
				t.Errorf("far end: %v", err)
			}
			check(t, f, got)
			keep := want.Error != nil && want.Error.Detail != ""
			if g, w := jsonOf(t, normal(got, keep)), jsonOf(t, normal(want, keep)); g != w {
				t.Errorf("result differs from the golden\n%s", diff(g, w))
			}
			if sec.uses > 1 {
				t.Errorf("secret used %d times", sec.uses)
			}
			if got.Session.CredentialSent != (sec.uses == 1) {
				t.Errorf("credential_sent %v, secret used %d times", got.Session.CredentialSent, sec.uses)
			}
			if w := floorCalls[rp.golden]; strings.Join(fl.calls, ",") != w {
				t.Errorf("floor calls %v, want %q", fl.calls, w)
			}
			if reportsTIDLE[rp.golden] != (len(tidles) == 1 && tidles[0] == 15*time.Minute) || len(tidles) > 1 {
				t.Errorf("TIDLE reported %v, want 15m: %v", tidles, reportsTIDLE[rp.golden])
			}
		})
	}
}

// diff shows the first lines where two JSON texts differ.
func diff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var a, b string
		if i < len(g) {
			a = g[i]
		}
		if i < len(w) {
			b = w[i]
		}
		if a != b {
			lo := max(0, i-3)
			return fmt.Sprintf("line %d:\n got: %s\nwant: %s\n(got context)\n%s", i+1, a, b,
				strings.Join(g[lo:min(len(g), i+6)], "\n"))
		}
	}
	return ""
}

// Every golden in the directory is either replayed above or listed here
// with the reason Run does not produce it.
var notReplayed = map[string]string{
	"failed.unknown":                     "a 0.7 result read by a 0.6 reader; no 0.6 adapter writes it",
	"refused.session_busy":               "decided by the collector (D9), before Run",
	"refused.rate_limited":               "decided by the collector (min_interval_ms), before Run",
	"refused.plaintext_not_acknowledged": "decided by the collector from the C1 endpoint, before Run",
	// CheckAgainst refuses a Level 1 run on a binding without firmware_id
	// first (credential_unavailable: nothing to compare before the
	// password). Run's own check is TestLevel0WithoutDeclaredFID.
	"refused.firmware_undeclared": "decided by the collector's FID gate (A3); see TestLevel0WithoutDeclaredFID",
}

func TestEveryGoldenAccountedFor(t *testing.T) {
	names, err := filepath.Glob(filepath.Join(goldenDir, "results", "valid", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]bool{}
	for _, rp := range replays {
		covered[rp.golden] = true
	}
	for _, bc := range beforeConnect {
		covered[bc.golden] = true
	}
	var missing []string
	for _, n := range names {
		g := strings.TrimSuffix(filepath.Base(n), ".json")
		if !covered[g] && notReplayed[g] == "" {
			missing = append(missing, g)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("goldens neither replayed nor explained: %v", missing)
	}
}

// beforeConnect are the refusals Run decides with no traffic, each set up
// by changing one input.
var beforeConnect = []struct {
	golden string
	setup  func(f *inputs, cfg *Config)
}{
	{"refused.register_unverified", func(_ *inputs, cfg *Config) { cfg.Register = nil }},
	{"refused.limits_out_of_range", func(f *inputs, _ *Config) { f.inv.Limits.MaxResponseBytes = 1 << 30 }},
	{"refused.invalid_parameters", func(f *inputs, _ *Config) { f.inv.Params = map[string]string{"rows": "10"} }},
	{"refused.operation_not_invocable", func(f *inputs, _ *Config) {
		caps := append([]asset.Capability(nil), f.profile.Capabilities...)
		for i, c := range caps {
			var keep []string
			for _, op := range c.Operations {
				if op != "sel.ser.read_all" {
					keep = append(keep, op)
				}
			}
			caps[i].Operations = keep
		}
		f.profile.Capabilities = caps
	}},
	{"refused.invocation_mismatch", func(f *inputs, _ *Config) {
		f.inv.Expected[1].Value = "SIM0000000000009"
	}},
	{"refused.asset_suspended", func(f *inputs, _ *Config) {
		f.asset.Suspension = &asset.Suspension{Reason: asset.SuspendAuthFailed, Since: "2026-10-24T09:00:00Z",
			Ref: "6f1c2b9e-3d4a-4c1e-9b7a-000000000000"}
	}},
	{"refused.firmware_not_allowlisted", func(f *inputs, _ *Config) { f.declare("firmware_id", fidDenied) }},
	{"refused.credential_unavailable", func(_ *inputs, cfg *Config) { cfg.Secret = nil }},
	// C1 0.2 (D2-16, H-13): a port server gets no session, and no dial.
	// TestEndpointPathRefused covers no path and an unknown path.
	{"refused.endpoint_path", func(f *inputs, _ *Config) { f.asset.Endpoints[0].Path = asset.PortServer }},
	{"failed.connect", nil},
}

func TestBeforeConnect(t *testing.T) {
	for _, bc := range beforeConnect {
		t.Run(bc.golden, func(t *testing.T) {
			want := golden(t, bc.golden)
			f := load(t)
			dials := 0
			cfg := Config{Secret: &secret{b: []byte(testSecret)}, Floor: &floor{}, Now: clock(),
				Dial: func(context.Context, string, string) (net.Conn, error) {
					dials++
					return nil, errors.New("test: refused")
				}}
			cfg.Asset, cfg.Profile, cfg.Register = f.asset, f.profile, f.reg
			if bc.setup != nil {
				bc.setup(&f, &cfg)
			}
			cfg.Asset, cfg.Profile = f.asset, f.profile
			got := Run(context.Background(), f.inv, cfg)
			if got.Error == nil || got.Error.Code != want.Error.Code {
				t.Fatalf("result %s, want %s (%+v)", jsonOf(t, got.Error), want.Error.Code, got.Error)
			}
			f.reg = cfg.Register
			if bc.golden == "refused.invalid_parameters" {
				f.reg = nil // CheckLines refuses an invocation whose operation does not render
			}
			check(t, f, got)
			if g, w := jsonOf(t, normal(got, false)), jsonOf(t, normal(want, false)); g != w {
				t.Errorf("result differs from the golden\n%s", diff(g, w))
			}
			wantDials := 0
			if bc.golden == "failed.connect" {
				wantDials = f.inv.Limits.ConnectRetries + 1
			}
			if dials != wantDials {
				t.Errorf("dialled %d times, want %d", dials, wantDials)
			}
		})
	}
}

// level0 loads the Level 0 ID invocation.
func level0(t *testing.T, f *inputs) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, "invocations", "valid", "sel-id-level0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if f.inv, err = adapter.DecodeInvocation(b); err != nil {
		t.Fatal(err)
	}
}

// A Level 0 ID read: wake, probe, ID, QUI. No floor, no secret, no ACC.
func TestLevel0ID(t *testing.T) {
	ok := script(golden(t, "ok"))
	steps := append(ok[:4:4], ok[len(ok)-1]) // wake, QUI probe, ID; then the closing QUI
	f := load(t)
	level0(t, &f)
	near, far := net.Pipe()
	done := farEnd(far, steps, false)
	cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID, Now: clock(),
		hooks: &hooks{quiet: 20 * time.Millisecond, wakeWait: 50 * time.Millisecond},
		Dial:  func(context.Context, string, string) (net.Conn, error) { return near, nil }}
	got := Run(context.Background(), f.inv, cfg)
	if err := <-done; err != nil {
		t.Errorf("far end: %v", err)
	}
	check(t, f, got)
	if got.Status != adapter.StatusOK || got.Session.CredentialSent || !got.Session.QuitSent || got.Session.AccessLevel != "0" {
		t.Fatalf("result %s", jsonOf(t, got))
	}
	var names []string
	for _, o := range got.Observations {
		names = append(names, o.Name)
	}
	if strings.Join(names, ",") != "firmware_id,sel.cid" || len(got.Identity.Items) != 1 {
		t.Errorf("observations %v, identity %+v", names, got.Identity)
	}
}

// With no declared FID there is no session (ADR-0005 (b), C-23).
func TestLevel0WithoutDeclaredFID(t *testing.T) {
	f := load(t)
	level0(t, &f)
	f.asset.IdentityBinding.Attributes = []string{"serial_number"}
	f.asset.IdentityBinding.PreCredential = nil
	f.inv.Expected = f.inv.Expected[1:]
	cfg := Config{Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID, Now: clock(),
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("dialled")
			return nil, errors.New("test")
		}}
	got := Run(context.Background(), f.inv, cfg)
	if got.Error == nil || got.Error.Code != adapter.RefusedFirmwareUndeclared {
		t.Fatalf("result %s", jsonOf(t, got.Error))
	}
	check(t, f, got)
}

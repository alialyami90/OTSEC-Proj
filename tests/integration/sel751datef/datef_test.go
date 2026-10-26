// Package sel751datef checks the SEL-751 adapter's DATE_F handling (A2,
// #175; P3-A2, docs/phase3/A2-sel751-datef.md) from outside the adapter
// package, against A6's own scripted relay: a far end that answers each line
// it receives, not a replay of A2's goldens. Expected results come from the
// rule text: S22 Table 4.84 (DATE_F: MDY, YMD or DMY), the register's
// context read (revision 4), C2 0.5, D3-2 and D2-16. A row parses only when
// its DATE is a calendar date in the order DATE_F names, worked out here
// with A6's own date check; DATE_F counts only under its own label.
//
// Evidence class: simulated. Every relay reply is invented; S22 prints no
// SHO G reply.
package sel751datef

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/register"
	"otsec.local/otsec/modules/ied/sel751"
)

const pw = "A6-test-pw-17" // a test value only

func read(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type inputs struct {
	inv     adapter.Invocation
	asset   asset.Asset
	profile asset.CapabilityProfile
	reg     *register.Package
}

func load(t *testing.T, editReg func(map[string]any)) inputs {
	t.Helper()
	var f inputs
	var err error
	if f.inv, err = adapter.DecodeInvocation(read(t, "contracts/adapter/testdata/invocations/valid/sel-ser-read.json")); err != nil {
		t.Fatal(err)
	}
	if f.asset, err = asset.Decode(read(t, "contracts/asset/testdata/valid/sel-751-simulated.json")); err != nil {
		t.Fatal(err)
	}
	if f.profile, err = asset.DecodeProfile(read(t, "contracts/asset/testdata/valid/profile-sel-751-ascii.json")); err != nil {
		t.Fatal(err)
	}
	rb := read(t, "contracts/register/testdata/sel-751.json")
	if editReg != nil {
		var m map[string]any
		if err := json.Unmarshal(rb, &m); err != nil {
			t.Fatal(err)
		}
		editReg(m)
		rb, _ = json.Marshal(m)
	}
	if f.reg, err = register.Decode(rb); err != nil {
		t.Fatal(err)
	}
	return f
}

type secret struct{ uses int }

func (s *secret) Use(f func([]byte) error) error {
	if s.uses++; s.uses > 1 {
		return errors.New("used twice")
	}
	return f([]byte(pw))
}
func (s *secret) EchoSpans(rx []byte) [][2]int {
	var out [][2]int
	for i := 0; ; {
		j := bytes.Index(rx[i:], []byte(pw))
		if j < 0 {
			return out
		}
		out = append(out, [2]int{i + j, i + j + len(pw)})
		i += j + len(pw)
	}
}

type floor struct{}

func (floor) BeforeACC(context.Context) error { return nil }
func (floor) Confirmed(context.Context)       {}

// relay is A6's scripted SEL-751: it answers by the line it receives. The
// framing (echo, STX, ETX, prompt) is S22's as A6 transcribed it for the
// recording simulator (#166).
type relay struct {
	mu      sync.Mutex
	lines   []string // every line received, the password as "<pw>"
	showG   string   // the SHO G body, between STX and ETX; "" for Invalid Command
	ser     string   // the SER body
	hangSER bool     // close the connection instead of answering SER
	tidle   string   // SHO P 1 TIDLE; "" means 15
	dials   int
}

func frame(echo, body, prompt string) string {
	return echo + "\r\n\x02" + body + "\x03" + prompt
}

const header = "\r\nSEL-751          Date: 10/24/2026  Time: 09:15:00\r\nFEEDER 1         Time Source: Internal\r\n\r\n"

func (r *relay) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	quis, auth := 0, false
	for {
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		l, err := br.ReadString('\n')
		if err != nil {
			return
		}
		l = strings.TrimSuffix(strings.TrimSuffix(l, "\n"), "\r")
		r.mu.Lock()
		if auth {
			r.lines = append(r.lines, "<pw>")
		} else {
			r.lines = append(r.lines, l)
		}
		r.mu.Unlock()
		var out string
		switch {
		case auth:
			auth = false
			out = "\x02" + header + "Level 1\r\n\x03=>"
		case l == "":
			out = "\r\n="
		case l == "QUI":
			quis++
			out = frame("QUI", header, "=")
		case l == "ID":
			out = "ID\r\n\x02\"FID=SEL-751-R501-V0-Z104101-D20260910\",\"0000\"\r\n\"BFID=BOOTLDR-R500-V0-Z000000-D20090925\",\"0000\"\r\n\"CID=E754\",\"0000\"\r\n\"DEVID=FEEDER 1\",\"0000\"\r\n\"DEVCODE=91\",\"0000\"\r\n\"PARTNO=751501A1A5A0X8C080\",\"0000\"\r\n\x03="
		case l == "ACC":
			out, auth = "ACC\r\nPassword: ? ", true
		case l == "SHO P 1":
			tidle := r.tidle
			if tidle == "" {
				tidle = "15"
			}
			out = frame("SHO P 1", "Port 1\r\n\r\nMAXACC  := 1\r\nFASTOP  := N\r\nLANG    := ENGLISH\r\nEHTTP   := N\r\nFTPACC  := 1\r\nHTTPACC := 1\r\nTIDLE   := "+tidle+"\r\n\r\n", "=>")
		case l == "SHO G":
			if r.showG == "" {
				out = "SHO G\r\nInvalid Command\r\n=>"
			} else {
				out = frame("SHO G", "\r\nGlobal Settings\r\n\r\n"+r.showG+"\r\n\r\n", "=>")
			}
		case l == "SER":
			if r.hangSER {
				return
			}
			out = frame("SER", r.ser, "=>")
		default:
			out = l + "\r\nInvalid Command\r\n=>"
		}
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte(out)); err != nil {
			return
		}
	}
}

// serBody is a SER report whose rows print the given DATE values.
func serBody(dates ...string) string {
	var b strings.Builder
	b.WriteString(header + "Serial No = SIM0000000000001\r\nFID = SEL-751-R501-V0-Z104101-D20260910     CID = E754\r\n\r\n#    DATE       TIME           ELEMENT           STATE\r\n")
	for i, d := range dates {
		n := len(dates) - i
		b.WriteString(strconv.Itoa(n) + "    " + d + " 09:10:0" + strconv.Itoa(i%10) + ".004   IN101             Asserted\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

func globals(dateF string) string {
	return "PHROT    := ABC     FNOM    := 60      DATE_F := " + dateF + "\r\nIRIGC    := NONE    UTC_OFF := 0.00"
}

type outcome struct {
	r      adapter.Result
	lines  []string
	tidle  []time.Duration
	dials  int
	inputs inputs
}

func run(t *testing.T, f inputs, rl *relay) outcome {
	t.Helper()
	var o outcome
	var mu sync.Mutex
	clock := time.Date(2026, 10, 24, 9, 15, 0, 0, time.UTC)
	cfg := sel751.Config{
		Asset: f.asset, Profile: f.profile, Register: f.reg, Endpoint: f.inv.EndpointID,
		Secret: &secret{}, Floor: floor{},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			o.dials++
			mu.Unlock()
			a, b := net.Pipe()
			go rl.serve(b)
			return a, nil
		},
		Now:   func() time.Time { clock = clock.Add(50 * time.Millisecond); return clock },
		TIDLE: func(d time.Duration) { mu.Lock(); o.tidle = append(o.tidle, d); mu.Unlock() },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	o.r = sel751.Run(ctx, f.inv, cfg)
	time.Sleep(20 * time.Millisecond)
	rl.mu.Lock()
	o.lines = append([]string(nil), rl.lines...)
	rl.mu.Unlock()
	o.inputs = f
	// The collector's own checks pass on every result here (C2 doc).
	if err := o.r.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if err := o.r.CheckLines(f.reg, f.inv); err != nil {
		t.Errorf("CheckLines: %v", err)
	}
	return o
}

// fits is A6's own calendar check: two-digit month and day, four-digit
// year, "/" between, in the order named, a day the month has.
func fits(order, date string) bool {
	p := strings.Split(date, "/")
	if len(p) != 3 {
		return false
	}
	var y, m, d string
	switch order {
	case "MDY":
		m, d, y = p[0], p[1], p[2]
	case "YMD":
		y, m, d = p[0], p[1], p[2]
	case "DMY":
		d, m, y = p[0], p[1], p[2]
	default:
		return false
	}
	if len(y) != 4 || len(m) != 2 || len(d) != 2 {
		return false
	}
	yi, e1 := strconv.Atoi(y)
	mi, e2 := strconv.Atoi(m)
	di, e3 := strconv.Atoi(d)
	if e1 != nil || e2 != nil || e3 != nil || mi < 1 || mi > 12 || di < 1 {
		return false
	}
	days := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[mi-1]
	if mi == 2 && yi%4 == 0 && (yi%100 != 0 || yi%400 == 0) {
		days = 29
	}
	return di <= days
}

func rowsParsed(r adapter.Result) (parsed, total int, dates []string) {
	for _, rec := range r.Records {
		if rec.Kind != "sel.ser.row" {
			continue
		}
		total++
		if rec.ParseOK {
			parsed++
		}
		dates = append(dates, string(r.Transcript.Data[rec.Span.Offset:rec.Span.Offset+rec.Span.Length]))
	}
	return
}

func operateLines(o outcome) []string {
	var out []string
	seen := false
	for _, l := range o.lines {
		if l == "<pw>" {
			seen = true
			continue
		}
		if seen && l != "QUI" {
			out = append(out, l)
		}
	}
	return out
}

func TestRowsParseOnlyInTheReportedOrder(t *testing.T) {
	dates := []string{"10/24/2026", "2026/10/24", "24/10/2026", "02/03/2026", "2026/02/30", "13/13/2026", "02/29/2026", "02/29/2028", "29/02/2028", "2028/02/29", "1/2/2026", "10-24-2026", "00/10/2026", "10/24/26"}
	for _, order := range []string{"MDY", "YMD", "DMY"} {
		for _, d := range dates {
			t.Run(order+" "+d, func(t *testing.T) {
				t.Parallel()
				o := run(t, load(t, nil), &relay{showG: globals(order), ser: serBody(d, d)})
				parsed, total, spans := rowsParsed(o.r)
				want := 0
				if fits(order, d) {
					want = total
				}
				if total != 2 || parsed != want {
					t.Errorf("%d of %d rows parsed, want %d (code %s)", parsed, total, want, code(o.r))
				}
				for _, s := range spans {
					if !strings.Contains(s, d) {
						t.Errorf("row bytes %q do not hold the printed date", s)
					}
				}
				if st, ok := o.r.Setting("DATE_F"); !ok || st.Value != order {
					t.Errorf("settings %+v, want DATE_F %s", o.r.Settings, order)
				}
				wantCode := adapter.Code("ok")
				if want == 0 {
					wantCode = adapter.PartialParseErrors
				}
				if code(o.r) != wantCode {
					t.Errorf("code %s, want %s", code(o.r), wantCode)
				}
				if got := strings.Join(operateLines(o), ","); got != "SHO P 1,SHO G,SER" {
					t.Errorf("operate lines %s", got)
				}
			})
		}
	}
}

// Only the DATE_F label names the order (case 14), and a SHO G reply that
// does not give one refuses nothing: SER is still read, every row is kept
// unparsed (cases 5, 6, 8).
func TestDateFOnlyUnderItsOwnLabel(t *testing.T) {
	const mdyRow = "10/24/2026" // fits MDY only
	const dmyRow = "24/10/2026" // fits DMY only
	for _, c := range []struct {
		name     string
		showG    string
		row      string
		parsed   bool
		reported string // DATE_F's reported value, "" for none
	}{
		{"the real DATE_F", globals("MDY"), mdyRow, true, "MDY"},
		{"no DATE_F", "PHROT    := ABC     FNOM    := 60", mdyRow, false, ""},
		{"DMY as another setting's value", "PHROT    := DMY     FNOM    := 60", dmyRow, false, ""},
		{"XDATE_F", "PHROT    := ABC     XDATE_F := DMY", dmyRow, false, ""},
		{"DATE_FX", "PHROT    := ABC     DATE_FX := DMY", dmyRow, false, ""},
		{"1DATE_F", "PHROT    := ABC     1DATE_F := DMY", dmyRow, false, ""},
		{"lowercase date_f", "PHROT    := ABC     date_f := DMY", dmyRow, false, ""},
		{"DATE_F with DMY elsewhere", "PHROT    := DMY     FNOM    := 60      DATE_F := MDY", mdyRow, true, "MDY"},
		{"DATE_F with DMY elsewhere, a DMY row", "PHROT    := DMY     FNOM    := 60      DATE_F := MDY", dmyRow, false, "MDY"},
		{"an order the register does not list", globals("MYD"), mdyRow, false, "MYD"},
		{"lowercase value", globals("mdy"), mdyRow, false, "mdy"},
		{"DATE_F twice", globals("MDY") + "\r\nDATE_F := DMY", mdyRow, false, ""},
		{"Invalid Command", "", mdyRow, false, ""},
		{"DATE_F inside an Event Messenger text", "MPTX01   := CALL ENG  DATE_F := DMY\r\n" + globals("MDY"), mdyRow, false, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			o := run(t, load(t, nil), &relay{showG: c.showG, ser: serBody(c.row, c.row)})
			parsed, total, _ := rowsParsed(o.r)
			if total != 2 || (parsed == total) != c.parsed || (parsed != 0 && parsed != total) {
				t.Errorf("%d of %d rows parsed, want all %v (code %s)", parsed, total, c.parsed, code(o.r))
			}
			st, ok := o.r.Setting("DATE_F")
			if c.reported == "" && ok {
				t.Errorf("DATE_F reported as %q", st.Value)
			}
			if c.reported != "" && (!ok || st.Value != c.reported) {
				t.Errorf("settings %+v, want DATE_F %q", o.r.Settings, c.reported)
			}
			if got := strings.Join(operateLines(o), ","); got != "SHO P 1,SHO G,SER" {
				t.Errorf("operate lines %s: SER must still be read", got)
			}
			if o.r.Status == adapter.StatusFailed || o.r.Status == adapter.StatusRefused {
				t.Errorf("status %s %s: a context read refuses nothing", o.r.Status, code(o.r))
			}
		})
	}
}

// A path that is not direct gets no session: nothing dialled, nothing
// sent, refused.endpoint_path, no TIDLE (case 1, D2-16).
func TestNoSessionOnAPathThatIsNotDirect(t *testing.T) {
	for _, path := range []string{"port-server", "", "a6-unknown"} {
		t.Run("path "+strconv.Quote(path), func(t *testing.T) {
			t.Parallel()
			f := load(t, nil)
			for i := range f.asset.Endpoints {
				if f.asset.Endpoints[i].ID == f.inv.EndpointID {
					f.asset.Endpoints[i].Path = asset.Path(path)
				}
			}
			rl := &relay{showG: globals("MDY"), ser: serBody("10/24/2026")}
			o := run(t, f, rl)
			if code(o.r) != adapter.RefusedEndpointPath || o.dials != 0 || len(o.lines) != 0 || len(o.r.Transcript.Data) != 0 || o.r.Session.Connected || len(o.tidle) != 0 {
				t.Errorf("code %s, dials %d, lines %v, transcript %d bytes, connected %v, TIDLE %v", code(o.r), o.dials, o.lines, len(o.r.Transcript.Data), o.r.Session.Connected, o.tidle)
			}
		})
	}
}

// TIDLE is handed over once, after an ok or partial run, never after a
// failed one (case 12).
func TestTIDLEAfterOKOrPartialOnly(t *testing.T) {
	for _, c := range []struct {
		name string
		rl   *relay
		want int
	}{
		{"ok", &relay{showG: globals("MDY"), ser: serBody("10/24/2026")}, 1},
		{"partial", &relay{showG: globals("DMY"), ser: serBody("10/24/2026")}, 1},
		{"failed in SER", &relay{showG: globals("MDY"), hangSER: true}, 0},
		// TIDLE is the port's (SHO P 1, S22 Table 4.104), never a value a
		// Global settings reply happens to print.
		{"TIDLE only in SHO G", &relay{tidle: "0", showG: "MPTX01   := X  LANG := ENGLISH  TIDLE := 1\r\n" + globals("MDY"), ser: serBody("10/24/2026")}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			o := run(t, load(t, nil), c.rl)
			if len(o.tidle) != c.want || (c.want == 1 && o.tidle[0] != 15*time.Minute) {
				t.Errorf("status %s %s: TIDLE calls %v, want %d of 15m", o.r.Status, code(o.r), o.tidle, c.want)
			}
		})
	}
}

// SHO G is sent only because the register declares it (case 10): under a
// package without the context read, the run sends SHO P 1 and SER only and
// reports no settings.
func TestNoContextNoSHOG(t *testing.T) {
	f := load(t, func(m map[string]any) { delete(m, "context") })
	if len(f.reg.ContextFor(f.inv.OperationID)) != 0 {
		t.Fatal("context still declared")
	}
	o := run(t, f, &relay{showG: globals("DMY"), ser: serBody("10/24/2026")})
	if got := strings.Join(operateLines(o), ","); got != "SHO P 1,SER" || len(o.r.Settings) != 0 {
		t.Errorf("operate lines %s, settings %+v", got, o.r.Settings)
	}
}

func code(r adapter.Result) adapter.Code {
	if r.Error == nil {
		return "ok"
	}
	return r.Error.Code
}

package normalize

import (
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// poller reads windows of a constructed SER buffer one after another,
// carrying the alignment state through its C5 encoding as the node does,
// and records every event emitted.
type poller struct {
	t      *testing.T
	state  []byte
	emits  map[string]int // emitted count per row body (the row without its number)
	events []event.Event
	health []event.Event
}

func newPoller(t *testing.T) *poller { return &poller{t: t, emits: map[string]int{}} }

func (p *poller) poll(window []string) *Output {
	p.t.Helper()
	inv, a := c2Fixtures(p.t)
	prev, err := DecodeState(p.state)
	if err != nil {
		p.t.Fatal(err)
	}
	out, err := Normalize(withRows(p.t, readOf(window)), inv, a, testInput(prev))
	if err != nil {
		p.t.Fatal(err)
	}
	if p.state, err = EncodeState(out.State); err != nil {
		p.t.Fatal(err)
	}
	for _, e := range out.Events {
		body := string(e.Native.Bytes)
		body = strings.TrimLeft(body[strings.IndexByte(body, ' '):], " ")
		p.emits[body]++
	}
	p.events = append(p.events, out.Events...)
	p.health = append(p.health, out.Health...)
	return out
}

// Acceptance (P2-A4): re-reading with 0, 50 and 100 percent overlap emits
// no duplicate, and every row of the buffer is emitted exactly once.
func TestOverlapEmitsNoDuplicate(t *testing.T) {
	buf := bufferRows(40)
	for _, c := range []struct {
		overlap int // percent of the second read already in the first
		status  event.AlignStatus
	}{
		{0, event.AlignStatusGap},
		{50, event.AlignStatusOK},
		{100, event.AlignStatusOK},
	} {
		t.Run(fmt.Sprintf("%d%%", c.overlap), func(t *testing.T) {
			const w = 20
			p := newPoller(t)
			p.poll(buf[:w])
			next := w - w*c.overlap/100
			out := p.poll(buf[next : next+w])
			for body, n := range p.emits {
				if n != 1 {
					t.Errorf("row %q emitted %d times", body, n)
				}
			}
			if want := next + w; len(p.emits) != want || len(p.events) != want {
				t.Errorf("%d rows emitted, %d events, want %d", len(p.emits), len(p.events), want)
			}
			wantAdded := w - (w - next)
			if len(out.Events) != wantAdded {
				t.Errorf("second read added %d, want %d", len(out.Events), wantAdded)
			}
			gaps := 0
			for _, h := range p.health {
				if h.Health.Type == event.HealthSERGap {
					gaps++
				}
			}
			switch c.status {
			case event.AlignStatusGap:
				// No shared row: nothing proves no row was missed in
				// between, so a gap is reported, but nothing is repeated.
				if gaps != 1 || out.Events[0].Collection.Alignment != event.AlignGapBefore {
					t.Errorf("0%% overlap: %d gaps, first alignment %s", gaps, out.Events[0].Collection.Alignment)
				}
			default:
				if gaps != 0 {
					t.Errorf("%d gaps", gaps)
				}
				for _, e := range out.Events {
					if e.Collection.Alignment != event.AlignOK || len(e.Flags) != 0 {
						t.Errorf("alignment %s flags %v", e.Collection.Alignment, e.Flags)
					}
				}
				if c.overlap == 100 && out.StateChanged {
					t.Error("an identical read changed the state")
				}
			}
		})
	}
}

// A sliding window over many polls stores each row once, in order.
func TestSlidingPolls(t *testing.T) {
	buf := bufferRows(300)
	p := newPoller(t)
	for start := 0; start+64 <= len(buf); start += 7 {
		p.poll(buf[start : start+64])
	}
	if len(p.health) != 0 {
		t.Errorf("health events: %+v", p.health)
	}
	for i, e := range p.events {
		if !strings.HasSuffix(string(e.Native.Bytes), buf[i]) {
			t.Fatalf("event %d is %q, want row %q", i, e.Native.Bytes, buf[i])
		}
	}
}

// D1-7: clearing the buffer raises exactly one gap, at the clear. The empty
// read adds no events but changes the state, which the node must keep.
func TestClearRaisesOneGap(t *testing.T) {
	buf := bufferRows(30)
	p := newPoller(t)
	p.poll(buf[:10])
	empty := p.poll(nil)
	if len(empty.Events) != 0 || !empty.StateChanged || empty.State == nil || len(empty.State) != 0 {
		t.Fatalf("empty read: %+v", empty)
	}
	after := p.poll(buf[10:15])
	gaps := 0
	for _, h := range p.health {
		if h.Health.Type == event.HealthSERGap {
			gaps++
		}
	}
	if gaps != 1 || len(after.Health) != 0 {
		t.Errorf("%d gaps, %d health after the clear", gaps, len(after.Health))
	}
	for _, e := range after.Events {
		if e.Collection.Alignment != event.AlignOK {
			t.Errorf("after the clear: %s", e.Collection.Alignment)
		}
	}
}

// Identical rows make the overlap ambiguous: the uncertain rows are kept as
// possible duplicates and the read says so, never dropped (D1-14).
func TestAmbiguousOverlapKeepsRows(t *testing.T) {
	same := "10/24/2026 09:00:00.000   IN101             Asserted"
	p := newPoller(t)
	p.poll([]string{same, same})
	out := p.poll([]string{same, same, same})
	if len(out.Events) == 0 || len(out.Health) != 1 || out.Health[0].Health.Type != event.HealthAlignmentAmbiguous {
		t.Fatalf("%d events, health %+v", len(out.Events), out.Health)
	}
	dups := 0
	for _, e := range out.Events {
		if e.Collection.Alignment == event.AlignPossibleDuplicate {
			dups++
		}
	}
	if dups == 0 {
		t.Error("no row flagged possible-duplicate")
	}
}

// A row removed from the middle of the buffer (an edited or restarted
// buffer) is a gap, and the rows after it are not stored again.
func TestRemovedRowIsAGap(t *testing.T) {
	buf := bufferRows(10)
	p := newPoller(t)
	p.poll(buf[:6])
	edited := append(append([]string{}, buf[:2]...), buf[3:8]...)
	out := p.poll(edited)
	if len(out.Health) != 1 || out.Health[0].Health.Type != event.HealthSERGap || out.Health[0].Health.Details["removed_records"] != "1" {
		t.Fatalf("health %+v", out.Health)
	}
	if len(out.Events) != 2 {
		t.Errorf("%d events, want the 2 new rows", len(out.Events))
	}
}

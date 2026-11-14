package netobs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"otsec.local/otsec/contracts/internal/strictjson"
)

// ErrFrameTooLarge is returned by ReadFrame for a length above
// MaxChannelFrame. The stream cannot be resynchronized after it, so the
// reader closes the channel and counts it (C13 §1).
var ErrFrameTooLarge = errors.New("netobs: frame length above MaxChannelFrame")

// ReadFrame reads one record: a 4-byte big-endian length, then that many
// bytes. Any other error is the stream's own, io.EOF at a record boundary.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxChannelFrame {
		return nil, ErrFrameTooLarge
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return b, nil
}

// WriteFrame writes b as one record. It refuses a record above
// MaxChannelFrame.
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) > MaxChannelFrame {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err := w.Write(buf)
	return err
}

// ChannelRecord is one record read from the channel: exactly one of the two.
type ChannelRecord struct {
	Heartbeat   *Heartbeat
	Observation *Observation
}

// DecodeChannel decodes and validates one channel record. C13 is strict:
// an unknown field, a minor other than this one, or an unknown closed-enum
// value refuses the record. A type other than heartbeat or observation is
// refused with CodeType, an alert-shaped record included (AP-34). A refused
// record never closes the channel; the node counts it under
// sensor-record-refused.
func DecodeChannel(b []byte) (*ChannelRecord, error) {
	if len(b) > MaxChannelFrame {
		return nil, &Error{Code: CodeRange, Field: "record", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxChannelFrame)}
	}
	var head struct {
		Schema string `json:"schema"`
		Type   string `json:"type"`
	}
	if err := strictjson.Forward(b, &head); err != nil {
		return nil, &Error{Code: CodeDecode, Field: "record", Detail: err.Error()}
	}
	if head.Schema != Identifier {
		return nil, &Error{Code: CodeSchema, Field: "schema", Detail: fmt.Sprintf("%q is not %s", head.Schema, Identifier)}
	}
	switch head.Type {
	case TypeObservation:
		var o Observation
		if err := strictjson.Decode(b, &o); err != nil {
			return nil, &Error{Code: CodeDecode, Field: "record", Detail: err.Error()}
		}
		return &ChannelRecord{Observation: &o}, o.validateChannel(Identifier, keyPaths(b))
	case TypeHeartbeat:
		var h Heartbeat
		if err := strictjson.Decode(b, &h); err != nil {
			return nil, &Error{Code: CodeDecode, Field: "record", Detail: err.Error()}
		}
		return &ChannelRecord{Heartbeat: &h}, h.validateChannel(Identifier, keyPaths(b))
	}
	return nil, &Error{Code: CodeType, Field: "type", Detail: fmt.Sprintf("%q: the channel carries only %s and %s", head.Type, TypeHeartbeat, TypeObservation)}
}

// Heartbeat is the sensor's periodic report (C13 §6). It carries no device
// text and no frame bytes.
type Heartbeat struct {
	Schema         string   `json:"schema"`
	Type           string   `json:"type"`
	SensorID       string   `json:"sensor_id"`
	RunID          string   `json:"run_id"`
	Seq            string   `json:"seq"`
	AtUTC          string   `json:"at_utc"`
	Coverage       Coverage `json:"coverage"`
	Counters       Counters `json:"counters"`
	RingOldestUTC  string   `json:"ring_oldest_utc,omitempty"`
	InterfaceCheck string   `json:"interface_check"`

	// New in 0.2 (C13 0.2 §11), each absent in a 0.1 heartbeat.
	// Interfaces and Agent are required in a 0.2 heartbeat (CH-31, CH-43).
	// EgressCheck is ok or absent, and left out when the agent cannot read
	// it (CH-27).
	Interfaces  []InterfaceCount `json:"interfaces,omitempty"`
	Agent       *Agent           `json:"agent,omitempty"`
	EgressCheck string           `json:"egress_check,omitempty"`

	// FrameStage is new in 0.3 and required in a 0.3 heartbeat (CH-53).
	// Its count is status only, never in Counters.
	FrameStage *FrameStage `json:"frame_stage,omitempty"`
}

// FrameStage is the frame stage's own counts, run totals (CH-53). Every
// key is required; a pointer is nil only when the key was absent.
type FrameStage struct {
	// OverlapTableFull counts the entries refused because the overlap
	// table held MaxOverlapFlows.
	OverlapTableFull *uint64 `json:"overlap_table_full"`
}

// InterfaceCount is one capture interface's frames read since the run
// began, before the PRP discard, and its link state (CH-31).
type InterfaceCount struct {
	Name    string `json:"name"`
	Carrier string `json:"carrier"`
	Packets uint64 `json:"packets"`
}

// Agent is the link agent's own counts, run totals (CH-43). Every key is
// required; a pointer is nil only when the key was absent.
type Agent struct {
	Closes            AgentCloses `json:"closes"`
	TakenAhead        *uint64     `json:"taken_ahead"`
	SyncLate          *uint64     `json:"sync_late"`
	EntriesUnreadable *uint64     `json:"entries_unreadable"`

	// New in 0.3 and required in a 0.3 heartbeat (CH-53): the overlap
	// records refused at MaxOverlapJoinPending, and those that left the
	// join buffer unjoined. Absent in a 0.2 heartbeat, so omitempty: it
	// leaves out nil only, never 0.
	OverlapJoinRefused *uint64 `json:"overlap_join_refused,omitempty"`
	OverlapUnjoined    *uint64 `json:"overlap_unjoined,omitempty"`
}

// counts03 lists the agent's counts new in 0.3 by their field names.
func (a *Agent) counts03() []struct {
	name string
	v    *uint64
} {
	return []struct {
		name string
		v    *uint64
	}{{"overlap_join_refused", a.OverlapJoinRefused}, {"overlap_unjoined", a.OverlapUnjoined}}
}

// AgentCloses counts the agent's closes by reason: the closed set
// AgentCloseReasons (CH-11, CH-43).
type AgentCloses struct {
	Handshake        *uint64 `json:"handshake"`
	NodeHello        *uint64 `json:"node-hello"`
	NodeHelloTimeout *uint64 `json:"node-hello-timeout"`
	Binding          *uint64 `json:"binding"`
	Ack              *uint64 `json:"ack"`
	Type             *uint64 `json:"type"`
	Idle             *uint64 `json:"idle"`
	FrameTooLarge    *uint64 `json:"frame-too-large"`
	Superseded       *uint64 `json:"superseded"`
	RunComplete      *uint64 `json:"run-complete"`
	Shutdown         *uint64 `json:"shutdown"`
}

// counts lists the agent's counts by their field names, in a fixed order.
func (a *Agent) counts() []struct {
	name string
	v    *uint64
} {
	k := &a.Closes
	return []struct {
		name string
		v    *uint64
	}{
		{"closes.handshake", k.Handshake}, {"closes.node-hello", k.NodeHello}, {"closes.node-hello-timeout", k.NodeHelloTimeout},
		{"closes.binding", k.Binding}, {"closes.ack", k.Ack}, {"closes.type", k.Type}, {"closes.idle", k.Idle},
		{"closes.frame-too-large", k.FrameTooLarge}, {"closes.superseded", k.Superseded},
		{"closes.run-complete", k.RunComplete}, {"closes.shutdown", k.Shutdown},
		{"taken_ahead", a.TakenAhead}, {"sync_late", a.SyncLate}, {"entries_unreadable", a.EntriesUnreadable},
	}
}

// Counters are totals since the run began, and never decrease within a run.
// DropsDriver is absent when the capture driver reports nothing, which
// means unknown, never zero.
type Counters struct {
	Packets              uint64  `json:"packets"`
	Bytes                uint64  `json:"bytes"`
	DropsDriver          *uint64 `json:"drops_driver,omitempty"`
	DropsDecoder         uint64  `json:"drops_decoder"`
	DropsChannel         uint64  `json:"drops_channel"`
	DecoderErrors        uint64  `json:"decoder_errors"`
	SessionsUnparsed     uint64  `json:"sessions_unparsed"`
	TableEvictions       uint64  `json:"table_evictions"`
	DNP3PendingOverflows uint64  `json:"dnp3_pending_overflows"`
	DNP3SeqReused        uint64  `json:"dnp3_seq_reused"`
	PRPDiscards          uint64  `json:"prp_discards"`
	Redactions           uint64  `json:"redactions"`
	LoginsNotPlaced      uint64  `json:"logins_not_placed"`

	// New in 0.2, required in a 0.2 heartbeat and absent in a 0.1 one: the
	// socket holder's (CH-26), the PRP discard's (CH-29) and the agent's
	// allow-list count (CH-34).
	DropsHolder        *uint64 `json:"drops_holder,omitempty"`
	FramesOverlong     *uint64 `json:"frames_overlong,omitempty"`
	FramesOutgoing     *uint64 `json:"frames_outgoing,omitempty"`
	PRPMismatched      *uint64 `json:"prp_mismatched,omitempty"`
	PRPTableFull       *uint64 `json:"prp_table_full,omitempty"`
	PRPTagDiffers      *uint64 `json:"prp_tag_differs,omitempty"`
	PRPWrongLAN        *uint64 `json:"prp_wrong_lan,omitempty"`
	EngineLinesRefused *uint64 `json:"engine_lines_refused,omitempty"`
}

// counts02 lists the counters new in 0.2 by name.
func (k *Counters) counts02() []struct {
	name string
	v    *uint64
} {
	return []struct {
		name string
		v    *uint64
	}{
		{"drops_holder", k.DropsHolder}, {"frames_overlong", k.FramesOverlong}, {"frames_outgoing", k.FramesOutgoing},
		{"prp_mismatched", k.PRPMismatched}, {"prp_table_full", k.PRPTableFull}, {"prp_tag_differs", k.PRPTagDiffers},
		{"prp_wrong_lan", k.PRPWrongLAN}, {"engine_lines_refused", k.EngineLinesRefused},
	}
}

// Carrier values of a heartbeat's interfaces (CH-31). Closed.
var carriers = []string{"up", "down", "unknown"}

// Validate checks a heartbeat of the 0.1 channel, the one main's intake
// reads: every rule of C13 that holds on one heartbeat. It refuses any
// field new in 0.2.
func (h *Heartbeat) Validate() error { return h.validateChannel(Identifier, nil) }

// validateChannel checks a heartbeat of the minor want; keys are the
// decoded document's key paths, nil for a Go value.
func (h *Heartbeat) validateChannel(want string, keys map[string]bool) error {
	c := &checker{keys: keys}
	c.strictSchema(h.Schema, want)
	if h.Type != TypeHeartbeat {
		c.fail(CodeType, "type", "%q is not %s", h.Type, TypeHeartbeat)
	}
	c.uuid("sensor_id", h.SensorID)
	c.uuid("run_id", h.RunID)
	c.seq("seq", h.Seq)
	c.utc("at_utc", h.AtUTC)
	h.Coverage.check(c, "coverage")
	if h.RingOldestUTC != "" {
		c.utc("ring_oldest_utc", h.RingOldestUTC)
	}
	if !contains([]string{"ok", "bound", "unknown"}, h.InterfaceCheck) {
		c.fail(CodeForm, "interface_check", "%q is not ok, bound or unknown", h.InterfaceCheck)
	}
	// A key present with null decodes as absent; it is refused, not read
	// as the count or object it lacks.
	for _, x := range h.Counters.counts02() {
		if c.new02("counters."+x.name, x.v != nil) && x.v == nil {
			c.fail(CodeForm, "counters."+x.name, "null is not a count")
		}
	}
	// egress_check is optional at 0.2 (CH-27), so it is only refused at 0.1.
	if h.EgressCheck != "" || c.keys["egress_check"] {
		if c.new02("egress_check", true) && h.EgressCheck != "ok" && h.EgressCheck != "absent" {
			c.fail(CodeForm, "egress_check", "%q is not ok or absent", h.EgressCheck)
		}
	}
	if c.new02("interfaces", h.Interfaces != nil) {
		h.checkInterfaces(c)
	}
	if c.new02("agent", h.Agent != nil) && h.Agent == nil {
		c.fail(CodeForm, "agent", "null is not the agent's counts")
	}
	if h.Agent != nil {
		for _, x := range h.Agent.counts() {
			if x.v == nil {
				c.fail(CodeMissing, "agent."+x.name, "required")
			}
		}
		for _, x := range h.Agent.counts03() {
			if c.new03("agent."+x.name, x.v != nil) {
				c.null("agent."+x.name, x.v == nil)
			}
		}
	}
	if c.new03("frame_stage", h.FrameStage != nil) {
		c.null("frame_stage", h.FrameStage == nil)
	}
	if h.FrameStage != nil && h.FrameStage.OverlapTableFull == nil {
		c.fail(CodeMissing, "frame_stage.overlap_table_full", "required")
	}
	return c.err()
}

// checkInterfaces applies CH-31: one entry for each interface of the
// coverage statement, by name; carrier in its set; and the packets summing
// to counters.packets.
func (h *Heartbeat) checkInterfaces(c *checker) {
	if n := len(h.Interfaces); n == 0 || n > MaxInterfaces {
		c.fail(CodeRange, "interfaces", "%d interfaces, not in [1, %d]", n, MaxInterfaces)
	}
	want := map[string]bool{}
	for _, in := range h.Coverage.Interfaces {
		want[in.Name] = true
	}
	seen := map[string]bool{}
	var sum uint64
	overflow := false
	for i, in := range h.Interfaces {
		f := fmt.Sprintf("interfaces[%d]", i)
		c.token(f+".name", in.Name)
		if !contains(carriers, in.Carrier) {
			c.fail(CodeForm, f+".carrier", "%q is not up, down or unknown", in.Carrier)
		}
		if seen[in.Name] || !want[in.Name] {
			c.fail(CodeConflict, f+".name", "%q: the names are the coverage statement's, each once", in.Name)
		}
		seen[in.Name] = true
		if sum+in.Packets < sum {
			overflow = true
		}
		sum += in.Packets
	}
	if len(seen) != len(want) {
		c.fail(CodeConflict, "interfaces", "%d names for the coverage statement's %d", len(seen), len(want))
	}
	if overflow || sum != h.Counters.Packets {
		c.fail(CodeConflict, "interfaces", "packets sum to %d, but counters.packets is %d", sum, h.Counters.Packets)
	}
}

// Follows checks h against prev, the last heartbeat accepted from the same
// sensor: in the same run, seq increases and no counter decreases. A
// counter absent from either is skipped. A new run starts afresh, so
// Follows returns nil when the runs differ. The node refuses a heartbeat
// that fails it (C13 §6).
func (h *Heartbeat) Follows(prev *Heartbeat) error {
	if prev == nil || prev.RunID != h.RunID {
		return nil
	}
	c := &checker{}
	if seqLess(h.Seq, prev.Seq) || h.Seq == prev.Seq {
		c.fail(CodeOrder, "seq", "%s does not follow %s", h.Seq, prev.Seq)
	}
	a, b := prev.Counters, h.Counters
	for _, x := range []struct {
		name       string
		prev, next uint64
	}{
		{"packets", a.Packets, b.Packets}, {"bytes", a.Bytes, b.Bytes},
		{"drops_decoder", a.DropsDecoder, b.DropsDecoder}, {"drops_channel", a.DropsChannel, b.DropsChannel},
		{"decoder_errors", a.DecoderErrors, b.DecoderErrors}, {"sessions_unparsed", a.SessionsUnparsed, b.SessionsUnparsed},
		{"table_evictions", a.TableEvictions, b.TableEvictions}, {"dnp3_pending_overflows", a.DNP3PendingOverflows, b.DNP3PendingOverflows},
		{"dnp3_seq_reused", a.DNP3SeqReused, b.DNP3SeqReused}, {"prp_discards", a.PRPDiscards, b.PRPDiscards},
		{"redactions", a.Redactions, b.Redactions}, {"logins_not_placed", a.LoginsNotPlaced, b.LoginsNotPlaced},
	} {
		if x.next < x.prev {
			c.fail(CodeOrder, "counters."+x.name, "%d is below the run's last %d", x.next, x.prev)
		}
	}
	if a.DropsDriver != nil && b.DropsDriver != nil && *b.DropsDriver < *a.DropsDriver {
		c.fail(CodeOrder, "counters.drops_driver", "%d is below the run's last %d", *b.DropsDriver, *a.DropsDriver)
	}
	// The counts new in 0.2 (CH-26, CH-29, CH-31, CH-34, CH-43): each one
	// absent from either heartbeat is skipped, as above.
	fall := func(name string, prev, next *uint64) {
		if prev != nil && next != nil && *next < *prev {
			c.fail(CodeOrder, name, "%d is below the run's last %d", *next, *prev)
		}
	}
	pc, nc := a.counts02(), b.counts02()
	for i := range pc {
		fall("counters."+pc[i].name, pc[i].v, nc[i].v)
	}
	for _, p := range prev.Interfaces {
		for _, n := range h.Interfaces {
			if n.Name == p.Name {
				fall("interfaces."+n.Name+".packets", &p.Packets, &n.Packets)
			}
		}
	}
	if prev.Agent != nil && h.Agent != nil {
		pa, na := prev.Agent.counts(), h.Agent.counts()
		for i := range pa {
			fall("agent."+pa[i].name, pa[i].v, na[i].v)
		}
		pa, na = prev.Agent.counts03(), h.Agent.counts03()
		for i := range pa {
			fall("agent."+pa[i].name, pa[i].v, na[i].v)
		}
	}
	// The frame stage's count, new in 0.3 (CH-53).
	if prev.FrameStage != nil && h.FrameStage != nil {
		fall("frame_stage.overlap_table_full", prev.FrameStage.OverlapTableFull, h.FrameStage.OverlapTableFull)
	}
	return c.err()
}

// seqLess compares two seq decimals without leading zeros.
func seqLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

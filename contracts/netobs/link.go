package netobs

import (
	"fmt"
	"strconv"
	"time"

	"otsec.local/otsec/contracts/internal/strictjson"
)

// This file is C13 0.2's channel over the network link (C13 0.2 §3, §4):
// its four messages, their strict decoding, and the pure checks of a
// hello, a tick, an ack and a record's place in its run. Nothing here
// opens a connection, keeps state or reads a clock: the node and the agent
// hold the state and pass it in. No product code calls these yet (F-027's
// gate, D4-96); the C13 0.2 intake brief and the sensor's brief wire them.

// The channel's message types (CH-5). Messages are never stored and never
// numbered.
const (
	TypeNodeHello   = "node-hello"
	TypeAck         = "ack"
	TypeSensorHello = "sensor-hello"
	TypeTick        = "tick"
)

// NodeTypes and SensorTypes are each direction's closed set on the 0.2
// channel (CH-5, M-1).
var (
	NodeTypes   = []string{TypeNodeHello, TypeAck}
	SensorTypes = []string{TypeSensorHello, TypeTick, TypeHeartbeat, TypeObservation}
)

// Close reasons (CH-11). The node's and the agent's sets share four names.
const (
	CloseHello            = "hello"
	CloseHelloTimeout     = "hello-timeout"
	CloseBinding          = "binding"
	CloseRunRegressed     = "run-regressed"
	CloseRunForked        = "run-forked"
	CloseRun              = "run"
	CloseTick             = "tick"
	CloseIdle             = "idle"
	CloseFrameTooLarge    = "frame-too-large"
	CloseStore            = "store"
	ClosePositionNotSaved = "position-not-saved"
	CloseSecondConnection = "second-connection"
	CloseEnrolment        = "enrolment"
	CloseShutdown         = "shutdown"
	CloseStateUnread      = "state-unread"
	CloseHandshake        = "handshake"
	CloseNodeHello        = "node-hello"
	CloseNodeHelloTimeout = "node-hello-timeout"
	CloseAck              = "ack"
	CloseType             = "type"
	CloseSuperseded       = "superseded"
	CloseRunComplete      = "run-complete"
)

// NodeCloseReasons and AgentCloseReasons are the two closed sets of close
// reasons (CH-11, M-8). closed-before-hello is a count of the node's, not
// a reason.
var (
	NodeCloseReasons = []string{CloseHello, CloseHelloTimeout, CloseBinding, CloseRunRegressed, CloseRunForked,
		CloseRun, CloseTick, CloseIdle, CloseFrameTooLarge, CloseStore, ClosePositionNotSaved,
		CloseSecondConnection, CloseEnrolment, CloseShutdown, CloseStateUnread}
	AgentCloseReasons = []string{CloseHandshake, CloseNodeHello, CloseNodeHelloTimeout, CloseBinding,
		CloseAck, CloseType, CloseIdle, CloseFrameTooLarge, CloseSuperseded, CloseRunComplete, CloseShutdown}
)

// The closed sets of sensor-hello's fields (CH-7, CH-33, CH-42).
var (
	pinnedBys    = []string{"signature", "console"}
	previousEnds = []string{"clean", "unclean"}
	startedBys   = []string{"agent", "capture", "engine", "enrolment"}
)

// Span is a capture interval a loss covers (CH-40), and a node.lost window.
type Span struct {
	FromUTC string `json:"from_utc"`
	ToUTC   string `json:"to_utc"`
}

// NodeHello is the node's first frame on every connection (CH-6). Taken is
// absent when the node holds no position that carries over.
type NodeHello struct {
	Schema     string `json:"schema"`
	Type       string `json:"type"`
	SensorID   string `json:"sensor_id"`
	Generation string `json:"generation"`
	Taken      *Taken `json:"taken,omitempty"`
}

// Taken is the node's saved position for the sensor: a run, and its taken
// seq T, 0 when nothing of it is taken.
type Taken struct {
	RunCounter string `json:"run_counter"`
	RunID      string `json:"run_id"`
	Seq        string `json:"seq"`
}

// Ack is the node's acknowledgement of its saved T in the connection's run
// (CH-9).
type Ack struct {
	Schema     string `json:"schema"`
	Type       string `json:"type"`
	RunCounter string `json:"run_counter"`
	RunID      string `json:"run_id"`
	Seq        string `json:"seq"`
}

// SensorHello is the sensor's first frame, after it reads node-hello
// (CH-7). Prior is present exactly when it opens a run the node has not
// accepted; Current is a pointer so that its absence is seen.
type SensorHello struct {
	Schema       string `json:"schema"`
	Type         string `json:"type"`
	SensorID     string `json:"sensor_id"`
	Generation   string `json:"generation"`
	RunCounter   string `json:"run_counter"`
	RunID        string `json:"run_id"`
	Current      *bool  `json:"current"`
	FirstSeq     string `json:"first_seq"`
	NewestSeq    string `json:"newest_seq"`
	DropsChannel string `json:"drops_channel"`
	Lost         []Span `json:"lost"`
	Prior        *Prior `json:"prior,omitempty"`
	PinnedBy     string `json:"pinned_by"`
	ConfigDigest string `json:"config_digest"`
	BufferBytes  string `json:"buffer_bytes"`
	SensorUTC    string `json:"sensor_utc"`
}

// Prior declares what came before a new run (CH-16, CH-42).
type Prior struct {
	RunsSkipped string `json:"runs_skipped"`
	RecordsLost string `json:"records_lost"`
	Lost        []Span `json:"lost"`
	PreviousEnd string `json:"previous_end"`
	StartedBy   string `json:"started_by"`
}

// Tick is the sensor's live message, made when it is sent (CH-8).
type Tick struct {
	Schema          string `json:"schema"`
	Type            string `json:"type"`
	SensorID        string `json:"sensor_id"`
	RunID           string `json:"run_id"`
	SensorUTC       string `json:"sensor_utc"`
	NewestSeq       string `json:"newest_seq"`
	SentSeq         string `json:"sent_seq"`
	DropsChannel    string `json:"drops_channel"`
	Lost            []Span `json:"lost"`
	BufferedRecords string `json:"buffered_records"`
	BufferedBytes   string `json:"buffered_bytes"`
}

// num reads a decimal a Validate has already checked.
func num(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// Validate checks node-hello's strict form (CH-5, CH-6).
func (m *NodeHello) Validate() error {
	c := &checker{}
	c.strictSchema(m.Schema, Identifier02)
	if m.Type != TypeNodeHello {
		c.fail(CodeType, "type", "%q is not %s", m.Type, TypeNodeHello)
	}
	c.uuid("sensor_id", m.SensorID)
	c.decimal("generation", m.Generation, true)
	if t := m.Taken; t != nil {
		c.decimal("taken.run_counter", t.RunCounter, true)
		c.uuid("taken.run_id", t.RunID)
		c.decimal("taken.seq", t.Seq, false)
	}
	return c.err()
}

// Validate checks an ack's strict form (CH-5, CH-9).
func (m *Ack) Validate() error {
	c := &checker{}
	c.strictSchema(m.Schema, Identifier02)
	if m.Type != TypeAck {
		c.fail(CodeType, "type", "%q is not %s", m.Type, TypeAck)
	}
	c.decimal("run_counter", m.RunCounter, true)
	c.uuid("run_id", m.RunID)
	c.decimal("seq", m.Seq, false)
	return c.err()
}

// Validate is CH-13's row 1 on a sensor-hello: its strict form, every
// field in its form and range, and every lost span in its form (CH-40).
// A failure closes the node's connection as hello.
func (m *SensorHello) Validate() error {
	c := &checker{}
	c.strictSchema(m.Schema, Identifier02)
	if m.Type != TypeSensorHello {
		c.fail(CodeType, "type", "%q is not %s", m.Type, TypeSensorHello)
	}
	c.uuid("sensor_id", m.SensorID)
	c.decimal("generation", m.Generation, true)
	c.decimal("run_counter", m.RunCounter, true)
	c.uuid("run_id", m.RunID)
	if m.Current == nil {
		c.fail(CodeMissing, "current", "required")
	}
	first := c.decimal("first_seq", m.FirstSeq, true)
	newest := c.decimal("newest_seq", m.NewestSeq, false)
	if first >= 1 && newest < first-1 {
		c.fail(CodeRange, "newest_seq", "%d is below first_seq - 1, %d", newest, first-1)
	}
	c.decimal("drops_channel", m.DropsChannel, false)
	c.declared("lost", m.Lost)
	if p := m.Prior; p != nil {
		c.decimal("prior.runs_skipped", p.RunsSkipped, false)
		c.decimal("prior.records_lost", p.RecordsLost, false)
		c.declared("prior.lost", p.Lost)
		if !contains(previousEnds, p.PreviousEnd) {
			c.fail(CodeForm, "prior.previous_end", "%q is not clean or unclean", p.PreviousEnd)
		}
		if !contains(startedBys, p.StartedBy) {
			c.fail(CodeForm, "prior.started_by", "%q is not agent, capture, engine or enrolment", p.StartedBy)
		}
	}
	if !contains(pinnedBys, m.PinnedBy) {
		c.fail(CodeForm, "pinned_by", "%q is not signature or console", m.PinnedBy)
	}
	if !baselineHashForm.MatchString(m.ConfigDigest) {
		c.fail(CodeForm, "config_digest", "%q is not sha256:<hex>", m.ConfigDigest)
	}
	if b := c.decimal("buffer_bytes", m.BufferBytes, true); b < MinBufferBytes || b > MaxBufferBytes {
		c.fail(CodeRange, "buffer_bytes", "%d not in [%d, %d]", b, MinBufferBytes, uint64(MaxBufferBytes))
	}
	c.utc("sensor_utc", m.SensorUTC)
	return c.err()
}

// Validate checks a tick's strict form (CH-8). A failure closes the node's
// connection as tick.
func (m *Tick) Validate() error {
	c := &checker{}
	c.strictSchema(m.Schema, Identifier02)
	if m.Type != TypeTick {
		c.fail(CodeType, "type", "%q is not %s", m.Type, TypeTick)
	}
	c.uuid("sensor_id", m.SensorID)
	c.uuid("run_id", m.RunID)
	c.utc("sensor_utc", m.SensorUTC)
	c.decimal("newest_seq", m.NewestSeq, false)
	c.decimal("sent_seq", m.SentSeq, false)
	c.decimal("drops_channel", m.DropsChannel, false)
	c.declared("lost", m.Lost)
	c.decimal("buffered_records", m.BufferedRecords, false)
	c.decimal("buffered_bytes", m.BufferedBytes, false)
	return c.err()
}

// spans checks a list of spans: at most MaxLostSpans, each in RFC 3339 UTC
// with from_utc at or before to_utc (CH-40).
func (c *checker) spans(field string, list []Span) {
	if len(list) > MaxLostSpans {
		c.fail(CodeRange, field, "%d spans, above %d", len(list), MaxLostSpans)
	}
	for i, s := range list {
		f := fmt.Sprintf("%s[%d]", field, i)
		from, ok1 := c.utc(f+".from_utc", s.FromUTC)
		to, ok2 := c.utc(f+".to_utc", s.ToUTC)
		if ok1 && ok2 && from.After(to) {
			c.fail(CodeOrder, f, "from_utc after to_utc")
		}
	}
}

// declared checks a declared lost list (CH-40): present, possibly empty,
// and the run's full set of disjoint spans, oldest first.
func (c *checker) declared(field string, list []Span) {
	if list == nil {
		c.fail(CodeMissing, field, "required, [] when nothing is lost")
	}
	c.spans(field, list)
	for i := 1; i < len(list); i++ {
		prev, err1 := time.Parse(time.RFC3339Nano, list[i-1].ToUTC)
		next, err2 := time.Parse(time.RFC3339Nano, list[i].FromUTC)
		if err1 == nil && err2 == nil && !next.After(prev) {
			c.fail(CodeOrder, fmt.Sprintf("%s[%d]", field, i), "spans disjoint, oldest first")
		}
	}
}

// FromSensor is one frame the 0.2 node reads from a sensor: at most one of
// the four is set. Type is the frame's type when it could be read.
type FromSensor struct {
	Type        string
	Hello       *SensorHello
	Tick        *Tick
	Heartbeat   *Heartbeat
	Observation *Observation
}

// DecodeFromSensor decodes and validates one frame from a sensor on the
// 0.2 channel, strictly: an unknown or duplicate key, a minor other than
// 0.2, or an unknown closed-enum value is refused. What a refusal does is
// the node's: a sensor-hello or tick that fails closes the connection
// (hello, tick); a heartbeat or observation that fails is one record
// refused by its code; a type outside SensorTypes is CodeType, an alert's
// included (CH-5, CH-11, AP-34). The 0.2 records require the fields C13
// 0.2 adds (made_utc, the coverage statement's config_digest and
// settings.prp_window_ms, and the heartbeat's new counters, interfaces and
// agent).
func DecodeFromSensor(b []byte) (*FromSensor, error) {
	if len(b) > MaxChannelFrame {
		return &FromSensor{}, &Error{Code: CodeRange, Field: "record", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxChannelFrame)}
	}
	var head struct {
		Schema string `json:"schema"`
		Type   string `json:"type"`
	}
	if err := strictjson.Forward(b, &head); err != nil {
		return &FromSensor{}, &Error{Code: CodeDecode, Field: "record", Detail: err.Error()}
	}
	m := &FromSensor{Type: head.Type}
	if !contains(SensorTypes, head.Type) {
		return m, &Error{Code: CodeType, Field: "type", Detail: fmt.Sprintf("%q: the channel carries only %v from a sensor", head.Type, SensorTypes)}
	}
	if head.Schema != Identifier02 {
		return m, &Error{Code: CodeSchema, Field: "schema", Detail: fmt.Sprintf("%q is not %s", head.Schema, Identifier02)}
	}
	decode := func(v any, validate func() error) error {
		if err := strictjson.Decode(b, v); err != nil {
			return &Error{Code: CodeDecode, Field: "record", Detail: err.Error()}
		}
		return validate()
	}
	switch head.Type {
	case TypeSensorHello:
		m.Hello = &SensorHello{}
		return m, decode(m.Hello, m.Hello.Validate)
	case TypeTick:
		m.Tick = &Tick{}
		return m, decode(m.Tick, m.Tick.Validate)
	case TypeHeartbeat:
		m.Heartbeat = &Heartbeat{}
		return m, decode(m.Heartbeat, func() error { return m.Heartbeat.validateChannel(Identifier02) })
	default:
		m.Observation = &Observation{}
		return m, decode(m.Observation, func() error { return m.Observation.validateChannel(Identifier02) })
	}
}

// FromNode is one frame the agent reads from the node: at most one of the
// two is set. Close is the agent's close reason when the frame is refused,
// and every refusal closes (CH-5): type for a frame whose type is outside
// NodeTypes, that cannot be read as a typed frame, or that carries a field
// not listed; node-hello or ack for a frame of that type that fails its
// strict decode otherwise; frame-too-large above MaxNodeMessage (CH-2).
type FromNode struct {
	Type  string
	Close string
	Hello *NodeHello
	Ack   *Ack
}

// DecodeFromNode decodes and validates one frame from the node, strictly.
func DecodeFromNode(b []byte) (*FromNode, error) {
	if len(b) > MaxNodeMessage {
		return &FromNode{Close: CloseFrameTooLarge}, &Error{Code: CodeRange, Field: "message", Detail: fmt.Sprintf("%d bytes, above %d", len(b), MaxNodeMessage)}
	}
	var head struct {
		Schema string `json:"schema"`
		Type   string `json:"type"`
	}
	if err := strictjson.Forward(b, &head); err != nil {
		return &FromNode{Close: CloseType}, &Error{Code: CodeDecode, Field: "message", Detail: err.Error()}
	}
	m := &FromNode{Type: head.Type}
	var v interface{ Validate() error }
	switch head.Type {
	case TypeNodeHello:
		m.Hello = &NodeHello{}
		v = m.Hello
	case TypeAck:
		m.Ack = &Ack{}
		v = m.Ack
	default:
		m.Close = CloseType
		return m, &Error{Code: CodeType, Field: "type", Detail: fmt.Sprintf("%q: the node sends only %v", head.Type, NodeTypes)}
	}
	// Forward reads the document as Decode does, but passes a key that is
	// not a field: so a frame Forward reads and Decode refuses carries a
	// field not listed, which closes as type (CH-5).
	if err := strictjson.Forward(b, v); err != nil {
		m.Close = head.Type
		return m, &Error{Code: CodeDecode, Field: "message", Detail: err.Error()}
	}
	if err := strictjson.Decode(b, v); err != nil {
		m.Close = CloseType
		return m, &Error{Code: CodeDecode, Field: "message", Detail: err.Error()}
	}
	if err := v.Validate(); err != nil {
		m.Close = head.Type
		return m, err
	}
	return m, nil
}

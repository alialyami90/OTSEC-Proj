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
		return &ChannelRecord{Observation: &o}, o.Validate()
	case TypeHeartbeat:
		var h Heartbeat
		if err := strictjson.Decode(b, &h); err != nil {
			return nil, &Error{Code: CodeDecode, Field: "record", Detail: err.Error()}
		}
		return &ChannelRecord{Heartbeat: &h}, h.Validate()
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
}

// Validate checks every rule of C13 that holds on one heartbeat.
func (h *Heartbeat) Validate() error {
	c := &checker{}
	c.strictSchema(h.Schema)
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
	return c.err()
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
	return c.err()
}

// seqLess compares two seq decimals without leading zeros.
func seqLess(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

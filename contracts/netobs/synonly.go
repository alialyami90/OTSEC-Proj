package netobs

// TCP flag bits, as in the TCP header's flags byte.
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPAck = 0x10
	TCPEce = 0x40
	TCPCwr = 0x80
)

// Segment is what SynOnly needs of one TCP segment of a flow: who sent it,
// its flags byte, and its payload length.
type Segment struct {
	FromClient bool
	Flags      uint8
	Payload    int
}

// SynOnly is flow.syn_only (C13 §4.3, §14 item 10): true when the flow
// holds at least one client SYN and every segment is either a client SYN
// with no ACK and no payload, or a server RST with no SYN and no payload.
// ECN's ECE and CWR bits are ignored. Anything else, a SYN carrying data
// (TFO) included, makes it false, so one-sided capture of a session that
// carried data never reads as a failed dial.
func SynOnly(segs []Segment) bool {
	sawSyn := false
	for _, s := range segs {
		f := s.Flags &^ (TCPEce | TCPCwr)
		switch {
		case s.Payload != 0:
			return false
		case s.FromClient && f == TCPSyn:
			sawSyn = true
		case !s.FromClient && f&TCPRst != 0 && f&^(TCPRst|TCPAck) == 0:
		default:
			return false
		}
	}
	return sawSyn
}

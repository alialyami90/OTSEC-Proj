package receive

import (
	"bufio"
	"errors"
	"io"
	"time"

	"otsec.local/otsec/modules/telemetry/normalize"
)

// frame is one message read off a stream, without its framing.
type frame struct {
	msg   []byte
	flags []string
}

// errOversized ends a connection after a frame whose octet count is above
// the limit: the frame's first bytes are kept, and the rest of the stream
// cannot be framed without trusting the count.
var errOversized = errors.New("receive: octet count above the frame limit")

// maxCountDigits bounds MSG-LEN. Any count with more digits is far above
// every frame limit.
const maxCountDigits = 9

// framer reads RFC 6587 frames from one connection. A frame that starts with
// a nonzero digit is octet-counted (RFC 5425 and RFC 6587 section 3.4.1:
// MSG-LEN SP SYSLOG-MSG); any other frame is non-transparent, ended by LF
// (section 3.4.2). Senders may mix them, as rsyslog's receiver allows.
//
// Every byte read becomes part of a frame or is counted in discarded; a
// frame the bytes do not fit is kept with a flag, never dropped:
//
//   - an octet count followed by anything but a space: the bytes up to the
//     next LF, with FlagFraming;
//   - an octet count above max: the first max bytes, with FlagTruncated,
//     then errOversized, and the caller closes the connection;
//   - a line longer than max: the first max bytes, with FlagTruncated; the
//     rest of the line up to its LF is discarded and counted;
//   - a frame cut by the end of the stream, a read error or the frame
//     deadline: the bytes received, with FlagTruncated, and the error.
//
// An empty line is no message and is counted in empty.
type framer struct {
	r   *bufio.Reader
	max int
	// deadline sets the read deadline: idle while waiting for a frame to
	// start, whole for the rest of a frame once its first byte is in.
	deadline    func(time.Time) error
	idle, whole time.Duration
	now         func() time.Time

	discarded, empty int64
}

// next returns the next frame. A non-nil error ends the stream; the frame
// returned with it, if any, holds the bytes received before it.
func (f *framer) next() (*frame, error) {
	for {
		if err := f.deadline(f.now().Add(f.idle)); err != nil {
			return nil, err
		}
		c, err := f.r.ReadByte()
		if err != nil {
			return nil, err
		}
		if err := f.deadline(f.now().Add(f.whole)); err != nil {
			return nil, err
		}
		if c >= '1' && c <= '9' {
			return f.counted(c)
		}
		fr, err := f.line([]byte{c})
		if fr == nil && err == nil {
			f.empty++
			continue
		}
		return fr, err
	}
}

// counted reads an octet-counted frame whose first count digit is c.
func (f *framer) counted(c byte) (*frame, error) {
	head := []byte{c}
	n := int(c - '0')
	for {
		b, err := f.r.ReadByte()
		if err != nil {
			return truncated(head, err)
		}
		head = append(head, b)
		switch {
		case b == ' ':
			return f.body(n)
		case b >= '0' && b <= '9' && len(head) <= maxCountDigits:
			n = n*10 + int(b-'0')
		case b == '\n':
			return &frame{msg: head[:len(head)-1], flags: []string{normalize.FlagFraming}}, nil
		default:
			fr, err := f.line(head)
			if fr != nil {
				fr.flags = append([]string{normalize.FlagFraming}, fr.flags...)
			}
			return fr, err
		}
	}
}

// body reads the n octets of a counted frame.
func (f *framer) body(n int) (*frame, error) {
	take := min(n, f.max)
	buf := make([]byte, take)
	got, err := io.ReadFull(f.r, buf)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			err = io.EOF
		}
		return truncated(buf[:got], err)
	}
	if n > f.max {
		return &frame{msg: buf, flags: []string{normalize.FlagTruncated}}, errOversized
	}
	return &frame{msg: buf}, nil
}

// line reads a non-transparent frame that starts with start, up to LF. It
// returns nil and no error for an empty line.
func (f *framer) line(start []byte) (*frame, error) {
	buf := start
	if len(buf) > 0 && buf[0] == '\n' {
		return nil, nil
	}
	for len(buf) < f.max {
		b, err := f.r.ReadByte()
		if err != nil {
			return truncated(buf, err)
		}
		if b == '\n' {
			return &frame{msg: buf}, nil
		}
		buf = append(buf, b)
	}
	// The line has reached the limit: it is whole if LF comes next.
	b, err := f.r.ReadByte()
	if err != nil {
		return truncated(buf, err)
	}
	if b == '\n' {
		return &frame{msg: buf}, nil
	}
	// It is over the limit: keep what fits, discard to its end.
	f.discarded++
	fr := &frame{msg: buf[:f.max], flags: []string{normalize.FlagTruncated}}
	for {
		b, err := f.r.ReadByte()
		if err != nil {
			return fr, err
		}
		if b == '\n' {
			return fr, nil
		}
		f.discarded++
	}
}

// truncated is the frame of the bytes received before err, if any.
func truncated(b []byte, err error) (*frame, error) {
	if len(b) == 0 {
		return nil, err
	}
	return &frame{msg: b, flags: []string{normalize.FlagTruncated}}, err
}

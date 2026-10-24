package collectorwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxReplyBytes bounds one CollectorReply frame. A reply carries a
	// request ID, an invocation ID and a refusal detail, so 4 KiB is ample.
	MaxReplyBytes = 4 << 10
	// MaxOutcomeBytes bounds one RunOutcome frame: a C2 result whose
	// transcript holds at most adapter.MaxResponseBytes received, in base64,
	// plus at most MaxOutcomeRecords audit records of audit.MaxRecordBytes.
	MaxOutcomeBytes = 8 << 20
)

// ErrFrameTooLarge is returned when a frame's length exceeds the limit the
// reader was given. Nothing of the body has been read.
var ErrFrameTooLarge = errors.New("collectorwire: frame exceeds its limit")

// ErrEmptyFrame is returned for a frame of length zero. No message is empty.
var ErrEmptyFrame = errors.New("collectorwire: empty frame")

// WriteFrame writes one frame. It refuses a body over max, so a sender
// cannot emit a frame its peer is bound to refuse.
func WriteFrame(w io.Writer, body []byte, max int) error {
	if len(body) == 0 {
		return ErrEmptyFrame
	}
	if len(body) > max {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, len(body), max)
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	// One Write, so a frame is never interleaved with another writer's.
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame of at most max bytes. A clean end of stream
// before the first header byte is io.EOF; anything shorter than the frame
// it announced is io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, ErrEmptyFrame
	}
	if uint64(n) > uint64(max) {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrFrameTooLarge, n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return body, nil
}

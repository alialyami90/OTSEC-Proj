package netobs

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

// Citation names the packets that show an item (C13 §3.2): a capture, and
// the first min(FramesTotal, MaxCitedFrames) frames in it.
type Citation struct {
	CaptureID   string       `json:"capture_id"`
	Frames      []CitedFrame `json:"frames"`
	FramesTotal int64        `json:"frames_total"`
}

// CitedFrame is one frame of a citation. SHA256 is over the frame's
// link-layer bytes as stored, redacted, with no pcap record header.
type CitedFrame struct {
	N           int64       `json:"n"`
	CapturedLen int         `json:"captured_len"`
	WireLen     int         `json:"wire_len"`
	SHA256      string      `json:"sha256"`
	LAN         string      `json:"lan,omitempty"`
	Redactions  []Redaction `json:"redactions,omitempty"`
}

// Redaction is a stored-frame byte range replaced by RedactionByte.
type Redaction struct {
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	Reason string `json:"reason"`
}

// RedactionByte is the constant every redacted byte is replaced by. It is
// never derived from the secret (HR-3).
const RedactionByte = 0x2a

// Redaction reasons. Closed.
const (
	ReasonCredential    = "credential"
	ReasonSlotNotPlaced = "slot-not-placed"
)

var captureIDForm = regexp.MustCompile(`^(?:ring:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(0|[1-9][0-9]{0,18})|file:[0-9a-f]{64})$`)

// ValidCaptureID reports whether s is "ring:<run_id>:<n>" or
// "file:<sha256>" (C13 §2).
func ValidCaptureID(s string) bool { return captureIDForm.MatchString(s) }

// captureRun returns the run ID of a ring capture ID, or "" for a file.
func captureRun(s string) string {
	if m := captureIDForm.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func (ct *Citation) check(c *checker, field string) {
	if !ValidCaptureID(ct.CaptureID) {
		c.fail(CodeForm, field+".capture_id", "%q is not ring:<run_id>:<n> or file:<sha256>", ct.CaptureID)
	}
	n := len(ct.Frames)
	switch {
	case n == 0:
		c.fail(CodeMissing, field+".frames", "a citation lists at least one frame")
	case n > MaxCitedFrames:
		c.fail(CodeRange, field+".frames", "%d frames, above %d", n, MaxCitedFrames)
	}
	if ct.FramesTotal < int64(n) || (n < MaxCitedFrames && ct.FramesTotal != int64(n)) {
		c.fail(CodeConflict, field+".frames_total", "%d, but %d frames are listed: the list holds the first min(total, %d)", ct.FramesTotal, n, MaxCitedFrames)
	}
	for i, f := range ct.Frames {
		ff := fmt.Sprintf("%s.frames[%d]", field, i)
		if i > 0 && f.N <= ct.Frames[i-1].N {
			c.fail(CodeOrder, ff+".n", "%d does not follow %d", f.N, ct.Frames[i-1].N)
		}
		f.check(c, ff)
	}
}

func (f *CitedFrame) check(c *checker, field string) {
	if f.N < 1 {
		c.fail(CodeRange, field+".n", "%d: frame numbers start at 1", f.N)
	}
	if f.CapturedLen < 1 || f.CapturedLen > MaxFrameBytes {
		c.fail(CodeRange, field+".captured_len", "%d not in [1, %d]", f.CapturedLen, MaxFrameBytes)
	}
	// wire_len is larger only for a frame cut at MaxFrameBytes.
	if f.WireLen < f.CapturedLen || (f.WireLen > f.CapturedLen && f.CapturedLen != MaxFrameBytes) {
		c.fail(CodeConflict, field+".wire_len", "%d with captured_len %d: a frame is cut only at %d", f.WireLen, f.CapturedLen, MaxFrameBytes)
	}
	c.sha256(field+".sha256", f.SHA256)
	if f.LAN != "" && f.LAN != "a" && f.LAN != "b" {
		c.fail(CodeForm, field+".lan", "%q is not a or b", f.LAN)
	}
	if len(f.Redactions) > MaxRedactions {
		c.fail(CodeRange, field+".redactions", "%d, above %d", len(f.Redactions), MaxRedactions)
	}
	end := 0
	for i, r := range f.Redactions {
		rf := fmt.Sprintf("%s.redactions[%d]", field, i)
		if r.Reason != ReasonCredential && r.Reason != ReasonSlotNotPlaced {
			c.fail(CodeForm, rf+".reason", "%q is not %s or %s", r.Reason, ReasonCredential, ReasonSlotNotPlaced)
		}
		switch {
		case r.Offset < 0 || r.Length < 1 || r.Offset+r.Length > f.CapturedLen:
			c.fail(CodeRange, rf, "offset %d length %d is not inside the %d stored bytes", r.Offset, r.Length, f.CapturedLen)
		case r.Offset < end:
			c.fail(CodeOrder, rf, "offset %d: redactions are sorted and never overlap", r.Offset)
		}
		end = max(end, r.Offset+r.Length)
	}
	// A slot-not-placed entry covers that side's whole payload in the frame
	// and replaces the per-slot entries over it, so it is the frame's only
	// redaction (C13 §3.2, §14, D1 on #543).
	if len(f.Redactions) > 1 && slices.ContainsFunc(f.Redactions, func(r Redaction) bool { return r.Reason == ReasonSlotNotPlaced }) {
		c.fail(CodeConflict, field+".redactions", "a slot-not-placed entry covers the payload, so it is the frame's only redaction")
	}
}

// Coverage is the sensor's coverage statement (C13 §3.3): what it could see.
// It is at most MaxCoverageBytes encoded compact.
type Coverage struct {
	SensorVersion string      `json:"sensor_version"`
	Engine        Engine      `json:"engine"`
	Interfaces    []Interface `json:"interfaces"`
	PRP           PRP         `json:"prp"`
	HSR           string      `json:"hsr"`
	VLANsSeen     []int       `json:"vlans_seen"`
	VLANsOverflow bool        `json:"vlans_overflow"`
	UntaggedSeen  bool        `json:"untagged_seen"`
	Decodes       []string    `json:"decodes"`
	Degraded      []string    `json:"degraded"`
	Settings      Settings    `json:"settings"`
	SinceUTC      string      `json:"since_utc"`
}

// Engine names the sensor's decoding engine.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Interface is one capture interface, as the sensor's configuration
// declares it.
type Interface struct {
	Name       string `json:"name"`
	Attachment string `json:"attachment"`
	LAN        string `json:"lan"`
}

// PRP says which PRP LANs the sensor has seen RCTs from, and whether it
// discards duplicates before decoding (C13 §4.4).
type PRP struct {
	LANsSeen            []string `json:"lans_seen"`
	DuplicatesDiscarded bool     `json:"duplicates_discarded"`
}

// Settings are the sensor settings a checker needs to read its records.
type Settings struct {
	SAReplyTimeoutMS int `json:"sa_reply_timeout_ms"`
	MaxPendingDNP3   int `json:"max_pending_dnp3"`
}

// HSRNotDecoded is coverage.hsr in 0.1.
const HSRNotDecoded = "not-decoded"

// Degraded lists what coverage.degraded may name. Closed.
var Degraded = []string{"drops-driver", "drops-decoder", "drops-channel", "decoder-errors",
	"sessions-unparsed", "table-evictions", "dnp3-pending-overflow", "interface-bound"}

var (
	attachments   = []string{"span", "tap", "unknown"}
	interfaceLANs = []string{"a", "b", "single", "unknown"}
)

func (cv *Coverage) check(c *checker, field string) {
	if b, err := json.Marshal(cv); err != nil || len(b) > MaxCoverageBytes {
		c.fail(CodeRange, field, "%d bytes encoded, above %d", len(b), MaxCoverageBytes)
	}
	c.token(field+".sensor_version", cv.SensorVersion)
	c.token(field+".engine.name", cv.Engine.Name)
	c.token(field+".engine.version", cv.Engine.Version)
	if n := len(cv.Interfaces); n == 0 || n > MaxInterfaces {
		c.fail(CodeRange, field+".interfaces", "%d interfaces, not in [1, %d]", n, MaxInterfaces)
	}
	for i, in := range cv.Interfaces {
		f := fmt.Sprintf("%s.interfaces[%d]", field, i)
		c.token(f+".name", in.Name)
		if !contains(attachments, in.Attachment) {
			c.fail(CodeForm, f+".attachment", "%q is not span, tap or unknown", in.Attachment)
		}
		if !contains(interfaceLANs, in.LAN) {
			c.fail(CodeForm, f+".lan", "%q is not a, b, single or unknown", in.LAN)
		}
	}
	if !slices.Equal(cv.PRP.LANsSeen, nil) && !slices.Equal(cv.PRP.LANsSeen, []string{}) &&
		!slices.Equal(cv.PRP.LANsSeen, []string{"a"}) && !slices.Equal(cv.PRP.LANsSeen, []string{"b"}) &&
		!slices.Equal(cv.PRP.LANsSeen, []string{"a", "b"}) {
		c.fail(CodeForm, field+".prp.lans_seen", "%q is not a sorted subset of a and b", cv.PRP.LANsSeen)
	}
	if cv.HSR != HSRNotDecoded {
		c.fail(CodeForm, field+".hsr", "%q: HSR is %s in 0.1", cv.HSR, HSRNotDecoded)
	}
	if len(cv.VLANsSeen) > MaxVLANs {
		c.fail(CodeRange, field+".vlans_seen", "%d VLANs, above %d", len(cv.VLANsSeen), MaxVLANs)
	}
	for i, v := range cv.VLANsSeen {
		if v < 1 || v > 4094 {
			c.fail(CodeRange, fmt.Sprintf("%s.vlans_seen[%d]", field, i), "%d not in [1, 4094]", v)
		}
		if i > 0 && v <= cv.VLANsSeen[i-1] {
			c.fail(CodeOrder, field+".vlans_seen", "ascending, without repeats")
		}
	}
	if cv.VLANsOverflow && len(cv.VLANsSeen) != MaxVLANs {
		c.fail(CodeConflict, field+".vlans_overflow", "set with %d VLANs listed: the list is full before it overflows", len(cv.VLANsSeen))
	}
	for i, p := range cv.Decodes {
		c.token(fmt.Sprintf("%s.decodes[%d]", field, i), p)
		if slices.Index(cv.Decodes, p) != i {
			c.fail(CodeOrder, field+".decodes", "%q repeated", p)
		}
	}
	for i, d := range cv.Degraded {
		if !contains(Degraded, d) {
			c.fail(CodeForm, fmt.Sprintf("%s.degraded[%d]", field, i), "%q is not a degraded condition", d)
		}
		if slices.Index(cv.Degraded, d) != i {
			c.fail(CodeOrder, field+".degraded", "%q repeated", d)
		}
	}
	s := cv.Settings
	if s.SAReplyTimeoutMS < MinSAReplyTimeoutMS || s.SAReplyTimeoutMS > MaxSAReplyTimeoutMS {
		c.fail(CodeRange, field+".settings.sa_reply_timeout_ms", "%d not in [%d, %d]", s.SAReplyTimeoutMS, MinSAReplyTimeoutMS, MaxSAReplyTimeoutMS)
	}
	if s.MaxPendingDNP3 < MinMaxPendingDNP3 || s.MaxPendingDNP3 > MaxMaxPendingDNP3 {
		c.fail(CodeRange, field+".settings.max_pending_dnp3", "%d not in [%d, %d]", s.MaxPendingDNP3, MinMaxPendingDNP3, MaxMaxPendingDNP3)
	}
	c.utc(field+".since_utc", cv.SinceUTC)
}

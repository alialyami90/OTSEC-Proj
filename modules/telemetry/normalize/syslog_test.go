package normalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
)

var update = flag.Bool("update", false, "rewrite the Syslog goldens in testdata/syslog")

const (
	rtacFixture = "../../../tests/fixtures/ied/sel/rtac/documented-example/syslog-user-logon.txt"
	sysStream   = event.Stream("syslog/lab-tls")
	sysAsset    = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"
)

// sysCert stands for a tls-mutual sender's DER certificate. Syslog only
// hashes it, so these bytes are not a certificate.
var sysCert = []byte("test: not a certificate")

func sysInput(msg []byte, d Dialect) SyslogInput {
	return SyslogInput{
		Node: testNode, Stream: sysStream, Message: msg, Sender: "127.0.0.1",
		Auth: event.AuthTLSMutual, SenderCert: sysCert, AssetID: sysAsset, EvidenceClass: asset.Simulated, Dialect: d,
		Received: event.Received{UTC: "2026-10-26T15:00:00.000000Z", ResolutionNS: 1000, Clock: event.Clock{Sync: event.SyncSynchronized}},
	}
}

func mustSyslog(t testing.TB, in SyslogInput) event.Event {
	t.Helper()
	e, err := Syslog(in)
	if err != nil {
		t.Fatalf("Syslog(%q): %v", in.Message, err)
	}
	return e
}

func fieldMap(e event.Event) map[string]string {
	m := map[string]string{}
	if e.Native != nil {
		for _, f := range e.Native.Fields {
			m[f.Name] = f.Value
		}
	}
	return m
}

// rtacMessage is the RTAC documented example as one message: A2's
// transcription is one line ending in LF, which is the file's line end, not
// part of the message (a datagram carries no line end).
func rtacMessage(t testing.TB) []byte {
	t.Helper()
	b := readFile(t, rtacFixture)
	return bytes.TrimSuffix(b, []byte("\n"))
}

// TestSyslogRTAC reads the RTAC documented example (S23 p. 636, A2's
// transcription) with the RTAC dialect. Expected values are read off the
// manual's example: the event time is the tag time stamp, 9.4 s before the
// header time, and the header time is kept only as a field.
func TestSyslogRTAC(t *testing.T) {
	msg := rtacMessage(t)
	e := mustSyslog(t, sysInput(msg, DialectRTAC))
	want := map[string]string{
		"pri": "190", "timestamp": "Mar 21 2015 12:10:08", "hostname": "SEL-3530-xxxxxx",
		"app": "RTAC Logger", "event_time": "2015-03-21 12:09:58.593", "level": "Informational",
		"category": "Security", "tag": "SystemTags. User_Logged_On", "message": "'SEL logged on device via Web'.",
		"msg": strings.SplitN(string(msg), "SEL-3530-xxxxxx ", 2)[1],
	}
	if got := fieldMap(e); !maps.Equal(got, want) {
		t.Errorf("fields\n got %v\nwant %v", got, want)
	}
	dt := e.DeviceTime
	if dt == nil || dt.Native != "2015-03-21 12:09:58.593" || dt.Format != FormatRTAC || dt.WallClock != "2015-03-21T12:09:58.593" ||
		dt.ResolutionNS != 1_000_000 || dt.Offset != "unknown" || dt.UTC != "" || len(dt.Flags) != 0 {
		t.Errorf("device time %+v", dt)
	}
	if e.Collection.ParseStatus != event.ParseOK {
		t.Errorf("parse status %s", e.Collection.ParseStatus)
	}
	if n := e.Normalized; n == nil || n.Subject != "SystemTags. User_Logged_On" || n.SubjectType != SubjectRTACTag ||
		n.Value != "'SEL logged on device via Web'." || n.Category != event.Unmapped {
		t.Errorf("normalized %+v", n)
	}
	golden(t, "rtac-user-logon.json", e)
}

// TestSyslogRTACWithoutDialect shows why the dialect is configuration: read
// as plain RFC 3164, the same bytes give the header time (the send time) as
// the device time.
func TestSyslogRTACWithoutDialect(t *testing.T) {
	e := mustSyslog(t, sysInput(rtacMessage(t), DialectRFC))
	if dt := e.DeviceTime; dt == nil || dt.Format != FormatYear || dt.WallClock != "2015-03-21T12:10:08" {
		t.Fatalf("device time %+v", dt)
	}
	if e.Collection.ParseStatus != event.ParseOK {
		t.Errorf("parse status %s", e.Collection.ParseStatus)
	}
	if _, ok := fieldMap(e)["tag"]; ok {
		t.Errorf("'RTAC Logger:' is not an RFC 3164 TAG (it holds a space): %v", fieldMap(e))
	}
}

// TestSyslogRFCExamples reads the examples printed in RFC 5424 section 6.5
// and RFC 3164 section 5.4 (standards examples, not device output).
func TestSyslogRFCExamples(t *testing.T) {
	bom := "\xef\xbb\xbf"
	cases := []struct {
		name, msg string
		fields    map[string]string
		wall, utc string
		offset    string
		res       int64
		flags     []string
		subject   string
	}{
		{
			name: "rfc5424-1",
			msg:  "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - " + bom + "'su root' failed for lonvick on /dev/pts/8",
			fields: map[string]string{"pri": "34", "version": "1", "timestamp": "2003-10-11T22:14:15.003Z", "hostname": "mymachine.example.com",
				"app_name": "su", "procid": "-", "msgid": "ID47", "structured_data": "-", "msg": bom + "'su root' failed for lonvick on /dev/pts/8"},
			wall: "2003-10-11T22:14:15.003", utc: "2003-10-11T22:14:15.003Z", offset: "+00:00", res: 1_000_000, subject: "su",
		},
		{
			name: "rfc5424-2",
			msg:  "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.",
			fields: map[string]string{"pri": "165", "version": "1", "timestamp": "2003-08-24T05:14:15.000003-07:00", "hostname": "192.0.2.1",
				"app_name": "myproc", "procid": "8710", "msgid": "-", "structured_data": "-", "msg": "%% It's time to make the do-nuts."},
			wall: "2003-08-24T05:14:15.000003", utc: "2003-08-24T12:14:15.000003Z", offset: "-07:00", res: 1000, subject: "myproc",
		},
		{
			name: "rfc5424-3",
			msg:  `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] ` + bom + "An application event log entry...",
			fields: map[string]string{"pri": "165", "version": "1", "timestamp": "2003-10-11T22:14:15.003Z", "hostname": "mymachine.example.com",
				"app_name": "evntslog", "procid": "-", "msgid": "ID47", "structured_data": `[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]`,
				"msg": bom + "An application event log entry..."},
			wall: "2003-10-11T22:14:15.003", utc: "2003-10-11T22:14:15.003Z", offset: "+00:00", res: 1_000_000, subject: "evntslog",
		},
		{
			name: "rfc5424-4",
			msg:  `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]`,
			fields: map[string]string{"pri": "165", "version": "1", "timestamp": "2003-10-11T22:14:15.003Z", "hostname": "mymachine.example.com",
				"app_name": "evntslog", "procid": "-", "msgid": "ID47", "structured_data": `[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]`},
			wall: "2003-10-11T22:14:15.003", utc: "2003-10-11T22:14:15.003Z", offset: "+00:00", res: 1_000_000, subject: "evntslog",
		},
		{
			name: "rfc3164",
			msg:  "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
			fields: map[string]string{"pri": "34", "timestamp": "Oct 11 22:14:15", "hostname": "mymachine", "tag": "su",
				"msg": "su: 'su root' failed for lonvick on /dev/pts/8"},
			wall: "2026-10-11T22:14:15", offset: "unknown", res: 1_000_000_000, flags: []string{"year-absent", "year-assumed"}, subject: "su",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := mustSyslog(t, sysInput([]byte(c.msg), DialectRFC))
			if got := fieldMap(e); !maps.Equal(got, c.fields) {
				t.Errorf("fields\n got %v\nwant %v", got, c.fields)
			}
			dt := e.DeviceTime
			if dt == nil || dt.WallClock != c.wall || dt.UTC != c.utc || dt.Offset != c.offset || dt.ResolutionNS != c.res || !slices.Equal(dt.Flags, c.flags) {
				t.Errorf("device time %+v", dt)
			}
			if e.Collection.ParseStatus != event.ParseOK {
				t.Errorf("parse status %s", e.Collection.ParseStatus)
			}
			if e.Normalized == nil || e.Normalized.Subject != c.subject {
				t.Errorf("normalized %+v", e.Normalized)
			}
		})
	}
}

// TestSyslogHostile feeds messages that break the formats. Every one still
// becomes a valid event that keeps its bytes exactly, with the status the
// parser could justify.
func TestSyslogHostile(t *testing.T) {
	cases := []struct {
		name, msg string
		status    event.ParseStatus
		check     func(t *testing.T, e event.Event)
	}{
		{"no pri", "hello", event.ParseFailed, nil},
		{"pri too big", "<192>Oct 11 22:14:15 h x", event.ParseFailed, nil},
		{"pri leading zero", "<01>Oct 11 22:14:15 h x", event.ParseFailed, nil},
		{"pri empty", "<>x", event.ParseFailed, nil},
		{"pri four digits", "<1234>x", event.ParseFailed, nil},
		{"pri unclosed", "<13", event.ParseFailed, nil},
		{"nested pri", "<13><14>Oct 11 22:14:15 h x", event.ParsePartial, func(t *testing.T, e event.Event) {
			if f := fieldMap(e); f["pri"] != "13" || f["msg"] != "<14>Oct 11 22:14:15 h x" || e.DeviceTime != nil {
				t.Errorf("fields %v, time %+v", f, e.DeviceTime)
			}
		}},
		{"pri only", "<13>", event.ParsePartial, nil},
		{"invalid utf-8 3164", "<13>Oct 11 22:14:15 host \xff\xfe", event.ParsePartial, func(t *testing.T, e event.Event) {
			if _, ok := fieldMap(e)["msg"]; ok {
				t.Error("a msg that is not UTF-8 must be left out of fields")
			}
		}},
		{"invalid utf-8 5424", "<13>1 2003-10-11T22:14:15Z h a p m - \xef\xbb\xbf\xff", event.ParsePartial, nil},
		{"5424 truncated header", "<13>1 2003-10-11T22:14:15Z host", event.ParsePartial, nil},
		{"5424 unknown version", "<13>2 2003-10-11T22:14:15Z h a p m -", event.ParsePartial, nil},
		{"5424 bad sd", "<13>1 2003-10-11T22:14:15Z h a p m [id x=\"1\"", event.ParsePartial, nil},
		{"5424 sd escapes", `<13>1 2003-10-11T22:14:15Z h a p m [id x="a\"b\]c\\"] m`, event.ParseOK, func(t *testing.T, e event.Event) {
			if f := fieldMap(e); f["structured_data"] != `[id x="a\"b\]c\\"]` || f["msg"] != "m" {
				t.Errorf("fields %v", f)
			}
		}},
		{"5424 no space before msg", "<13>1 2003-10-11T22:14:15Z h a p m -x", event.ParsePartial, nil},
		{"5424 bad month", "<13>1 2003-13-11T22:14:15Z h a p m -", event.ParsePartial, invalidTime},
		{"5424 offset beyond 14h", "<13>1 2003-10-11T22:14:15+15:00 h a p m -", event.ParsePartial, invalidTime},
		{"5424 leap second", "<13>1 2016-12-31T23:59:60Z h a p m -", event.ParseOK, func(t *testing.T, e event.Event) {
			if dt := e.DeviceTime; dt.WallClock != "2016-12-31T23:59:60" || dt.UTC != "" {
				t.Errorf("device time %+v", dt)
			}
		}},
		{"5424 leap second not at day end", "<13>1 2016-12-31T22:59:60Z h a p m -", event.ParsePartial, invalidTime},
		{"5424 nil timestamp", "<13>1 - h a p m -", event.ParseOK, func(t *testing.T, e event.Event) {
			if e.DeviceTime != nil {
				t.Errorf("device time %+v", e.DeviceTime)
			}
		}},
		{"3164 29 February without a leap year near", "<13>Feb 29 10:00:00 h x", event.ParsePartial, func(t *testing.T, e event.Event) {
			if dt := e.DeviceTime; dt == nil || !slices.Equal(dt.Flags, []string{"year-absent", "invalid-time"}) {
				t.Errorf("device time %+v", dt)
			}
		}},
		{"3164 lower-case month", "<13>oct 11 22:14:15 h x", event.ParsePartial, nil},
		{"3164 timestamp then nothing", "<13>Oct 11 22:14:15", event.ParseOK, nil},
		{"3164 hostname control byte", "<13>Oct 11 22:14:15 h\x01st x", event.ParsePartial, nil},
		{"3164 offset token after the time", "<37>Jul 09 2009 08:17:29 -07:00 myhostname Login: x", event.ParsePartial, func(t *testing.T, e event.Event) {
			f := fieldMap(e)
			if _, ok := f["hostname"]; ok || e.Normalized != nil || f["msg"] != "-07:00 myhostname Login: x" || e.DeviceTime.Offset != "unknown" {
				t.Errorf("fields %v normalized %+v time %+v", f, e.Normalized, e.DeviceTime)
			}
		}},
		{"3164 hours-only offset token", "<37>Jul 09 2009 08:17:29 +03 h x", event.ParsePartial, nil},
		{"3164 offset glued to the time", "<37>Jul 09 2009 08:17:29-07 myhostname x", event.ParsePartial, func(t *testing.T, e event.Event) {
			if f := fieldMap(e); f["hostname"] != "" || e.Normalized != nil || e.DeviceTime != nil {
				t.Errorf("fields %v normalized %+v time %+v", f, e.Normalized, e.DeviceTime)
			}
		}},
		{"3164 rfc3339 stamp", "<13>2026-10-26T14:00:00.5+03:00 h x", event.ParseOK, func(t *testing.T, e event.Event) {
			if dt := e.DeviceTime; dt.Format != FormatRFC3339 || dt.UTC != "2026-10-26T11:00:00.5Z" || dt.OffsetBasis != event.BasisOnWire {
				t.Errorf("device time %+v", dt)
			}
		}},
		{"3164 digits not a time", "<13>2026-xx-26T14:00:00Z h x", event.ParsePartial, invalidTime},
		{"nul bytes", "<13>Oct 11 22:14:15 h a\x00b", event.ParseOK, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := mustSyslog(t, sysInput([]byte(c.msg), DialectRFC))
			if e.Collection.ParseStatus != c.status {
				t.Errorf("parse status %s, want %s (fields %v)", e.Collection.ParseStatus, c.status, fieldMap(e))
			}
			checkKept(t, e, []byte(c.msg))
			if c.check != nil {
				c.check(t, e)
			}
		})
	}
}

func invalidTime(t *testing.T, e event.Event) {
	t.Helper()
	if e.DeviceTime == nil || !slices.Contains(e.DeviceTime.Flags, "invalid-time") || e.DeviceTime.WallClock != "" || e.DeviceTime.Offset != "unknown" {
		t.Errorf("device time %+v", e.DeviceTime)
	}
}

// checkKept checks that the event passes C4 and that its stored form holds
// the message bytes exactly, with their hash.
func checkKept(t *testing.T, e event.Event, msg []byte) {
	t.Helper()
	if err := e.ValidatePending(); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var back event.Event
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Native.Bytes, msg) || back.Native.RecordSHA256 != sha256hex(msg) || back.Native.Evidence.SHA256 != back.Native.RecordSHA256 {
		t.Errorf("stored bytes differ from the message")
	}
}

// TestSyslogYearAssumed takes the year that puts the time nearest the
// receive time.
func TestSyslogYearAssumed(t *testing.T) {
	for _, c := range []struct{ rcv, msg, wall string }{
		{"2026-01-01T00:00:10.000000Z", "<13>Dec 31 23:59:50 h x", "2025-12-31T23:59:50"},
		{"2025-12-31T23:59:50.000000Z", "<13>Jan  1 00:00:10 h x", "2026-01-01T00:00:10"},
		{"2026-06-01T00:00:00.000000Z", "<13>Jun  1 00:00:00 h x", "2026-06-01T00:00:00"},
		{"2027-03-01T00:00:00.000000Z", "<13>Feb 29 12:00:00 h x", "2028-02-29T12:00:00"},
	} {
		in := sysInput([]byte(c.msg), DialectRFC)
		in.Received.UTC = c.rcv
		e := mustSyslog(t, in)
		if e.DeviceTime == nil || e.DeviceTime.WallClock != c.wall {
			t.Errorf("%s at %s: device time %+v, want wall %s", c.msg, c.rcv, e.DeviceTime, c.wall)
		}
	}
}

// TestSyslogSource covers attribution: a known sender is the subject by
// address, an unknown sender is kept with asset-unresolved, and receive
// flags make an otherwise good message partial.
func TestSyslogSource(t *testing.T) {
	msg := []byte("<13>Oct 11 22:14:15 h x")
	e := mustSyslog(t, sysInput(msg, DialectRFC))
	if a := e.Source.Asset; a == nil || a.ID != sysAsset || a.Binding.Method != event.BindSenderAddress || a.Binding.Confidence != event.ConfidenceConfigured {
		t.Errorf("asset %+v", a)
	}
	if e.Source.Sender.Address != "127.0.0.1" || e.Source.Sender.AssetID != sysAsset || e.Source.OriginAuth != event.AuthTLSMutual {
		t.Errorf("sender %+v auth %s", e.Source.Sender, e.Source.OriginAuth)
	}
	// C4 0.2: the certificate that spoke is named, and the binding is no
	// stronger for it.
	if e.Schema != event.Identifier || e.Source.Sender.TLSLeafSHA256 != sha256hex(sysCert) {
		t.Errorf("schema %s, tls leaf %q", e.Schema, e.Source.Sender.TLSLeafSHA256)
	}
	in0 := sysInput(msg, DialectRFC)
	in0.Auth, in0.SenderCert = event.AuthTLSServerOnly, nil
	if e := mustSyslog(t, in0); e.Source.Sender.TLSLeafSHA256 != "" {
		t.Errorf("tls-server-only event names a certificate")
	}
	in := sysInput(msg, DialectRFC)
	in.AssetID = ""
	in.Flags = []string{FlagTruncated}
	e = mustSyslog(t, in)
	if e.Source.Asset != nil || !slices.Equal(e.Flags, []string{"asset-unresolved", FlagTruncated}) || e.Collection.ParseStatus != event.ParsePartial {
		t.Errorf("unknown sender: asset %+v flags %v status %s", e.Source.Asset, e.Flags, e.Collection.ParseStatus)
	}
	for name, mut := range map[string]func(*SyslogInput){
		"empty message":    func(in *SyslogInput) { in.Message = nil },
		"no sender":        func(in *SyslogInput) { in.Sender = " " },
		"session auth":     func(in *SyslogInput) { in.Auth = event.AuthSession },
		"mutual, no cert":  func(in *SyslogInput) { in.SenderCert = nil },
		"cert, not mutual": func(in *SyslogInput) { in.Auth = event.AuthNone },
		"no class":         func(in *SyslogInput) { in.EvidenceClass = "" },
		"unknown dialect":  func(in *SyslogInput) { in.Dialect = "sel-2488" },
		"bad stream":       func(in *SyslogInput) { in.Stream = "Syslog:x" },
	} {
		in := sysInput(msg, DialectRFC)
		mut(&in)
		if _, err := Syslog(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// FuzzSyslog: whatever bytes arrive, Syslog returns a valid event that
// keeps them exactly, and never panics.
func FuzzSyslog(f *testing.F) {
	f.Add([]byte("<190>Mar 21 2015 12:10:08 SEL-3530-xxxxxx RTAC Logger: 2015-03-21 12:09:58.593, Informational, Security, SystemTags. User_Logged_On, 'SEL logged on device via Web'."), true)
	f.Add([]byte(`<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3"] x`), false)
	f.Add([]byte("<13><14>Feb 29 23:59:60 h\xff"), false)
	f.Add([]byte("<0>2026-10-26T14:00:00.123456789-00:00 h t[1]: m"), true)
	f.Fuzz(func(t *testing.T, msg []byte, rtac bool) {
		if len(msg) == 0 || len(msg) > 1<<16 {
			return
		}
		d := DialectRFC
		if rtac {
			d = DialectRTAC
		}
		e, err := Syslog(sysInput(msg, d))
		if err != nil {
			t.Fatal(err)
		}
		checkKept(t, e, msg)
	})
}

func golden(t *testing.T, name string, e event.Event) {
	t.Helper()
	got, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := "testdata/syslog/" + name
	if *update {
		if err := os.MkdirAll("testdata/syslog", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A golden is this package's own JSON, not evidence: a Windows checkout
	// may have turned its line ends into CRLF, which says nothing about it.
	want := bytes.ReplaceAll(readFile(t, path), []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden; run with -update after checking the change\n got %s", name, got)
	}
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestSyslogRTACOtherMessage: an RTAC message whose MSG is not the Logger
// layout keeps its fields and is partial, and its header time (the send
// time) is still not taken as the device time.
func TestSyslogRTACOtherMessage(t *testing.T) {
	e := mustSyslog(t, sysInput([]byte("<190>Mar 21 2015 12:10:08 SEL-3530-xxxxxx something else: x"), DialectRTAC))
	if e.Collection.ParseStatus != event.ParsePartial || e.DeviceTime != nil {
		t.Errorf("status %s, device time %+v", e.Collection.ParseStatus, e.DeviceTime)
	}
	if f := fieldMap(e); f["msg"] != "something else: x" || f["timestamp"] != "Mar 21 2015 12:10:08" {
		t.Errorf("fields %v", f)
	}
}

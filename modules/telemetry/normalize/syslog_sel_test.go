package normalize

import (
	"bytes"
	"maps"
	"testing"

	"otsec.local/otsec/contracts/event"
)

// TestSyslogSELExamples reads the SEL-2488 and SEL-2730M documented
// examples (A2's transcriptions, S26 p. D.2 and S43 p. 126) with the RFC
// parser: both are RFC 3164 with a year after the day. The 2488's UTC
// offset is not in its only wire example, so the offset is unknown and no
// UTC is stated. The 2730M sample has no tag; its subject is the host.
func TestSyslogSELExamples(t *testing.T) {
	cases := []struct {
		golden, fixture string
		fields          map[string]string
		subject, stype  string
	}{
		{"sel2488-login-failed.json", "../../../tests/fixtures/ied/sel/2488/documented-example/syslog-login-failed.txt",
			map[string]string{"pri": "37", "timestamp": "Jul 09 2009 08:17:29", "hostname": "myhostname", "tag": "Login",
				"msg": "Login: Login to web: failed from 192.168.1.1"}, "Login", SubjectSyslogApp},
		{"sel2730m-invalid-login.json", "../../../tests/fixtures/ied/sel/2730m/documented-example/syslog-invalid-login.txt",
			map[string]string{"pri": "34", "timestamp": "Jul 09 2009 08:17:29", "hostname": "myhostname",
				"msg": "Invalid login attempt by: root at 192.168.1.1"}, "myhostname", SubjectSyslogHost},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			msg := bytes.TrimSuffix(readFile(t, c.fixture), []byte("\n"))
			e := mustSyslog(t, sysInput(msg, DialectRFC))
			if got := fieldMap(e); !maps.Equal(got, c.fields) {
				t.Errorf("fields\n got %v\nwant %v", got, c.fields)
			}
			dt := e.DeviceTime
			if dt == nil || dt.Format != FormatYear || dt.WallClock != "2009-07-09T08:17:29" || dt.Offset != "unknown" || dt.UTC != "" || len(dt.Flags) != 0 {
				t.Errorf("device time %+v", dt)
			}
			if e.Collection.ParseStatus != event.ParseOK || e.Normalized == nil || e.Normalized.Subject != c.subject || e.Normalized.SubjectType != c.stype {
				t.Errorf("status %s normalized %+v", e.Collection.ParseStatus, e.Normalized)
			}
			golden(t, c.golden, e)
		})
	}
}

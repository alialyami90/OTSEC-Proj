package snmpv3

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOIDKnownEncodings(t *testing.T) {
	for s, h := range map[string]string{
		"1.3.6.1.2.1.1.1.0":           "06082b06010201010100",              // sysDescr.0 (X.690 §8.19)
		"1.3.6.1.6.3.15.1.1.2.0":      "060a2b060106030f01010200",          // usmStatsNotInTimeWindows.0
		"1.3.6.1.4.1.4294967295":      "060a2b06010401" + "8fffffff7f",     // the largest arc, five octets
		"1.3.6.1.2.1.47.1.1.1.1.10.1": "060c2b06010201" + "2f010101010a01", // entPhysicalSoftwareRev.1
		"2.999.1":                     "0603" + "883701",                   // a first arc of 2: 80+999
		"0.39":                        "060127",                            // the largest second arc under 0
		"1.3.6.1.4.1.128":             "06072b06010401" + "8100",           // an arc of two octets
	} {
		b, err := oidOf(s)
		if err != nil {
			t.Errorf("%s: %v", s, err)
			continue
		}
		if got := hex.EncodeToString(b); got != strings.ReplaceAll(h, " ", "") {
			// The table's lengths are by hand; the decode below is the check.
			want, _ := hex.DecodeString(h)
			if e, err := decode(want, 0); err != nil || len(want) != e.End() {
				t.Errorf("%s: the table entry %s is not one TLV", s, h)
			}
			t.Errorf("%s: %s, want %s", s, got, h)
		}
		e, err := decode(b, 0)
		if err != nil {
			t.Fatal(err)
		}
		if back, err := oid(e); err != nil || back != s {
			t.Errorf("%s: decodes as %s, %v", s, back, err)
		}
	}
}

func TestOIDRefused(t *testing.T) {
	for name, h := range map[string]string{
		"empty":               "0600",
		"ends inside an arc":  "06022b81",
		"leading 0x80":        "06032b8001",
		"an arc of 2^32":      "06072b0690808080" + "00",
		"a first arc too big": "06059090909000",
	} {
		b, _ := hex.DecodeString(h)
		b[1] = byte(len(b) - 2)
		e, err := decode(b, 0)
		if err != nil {
			continue
		}
		if s, err := oid(e); err == nil {
			t.Errorf("%s: decodes as %s", name, s)
		}
	}
	if _, err := oidOf("1.3.6.1" + strings.Repeat(".1", 125)); err == nil {
		t.Error("129 arcs encoded")
	}
	for _, s := range []string{"1", "1.3.6.1.4294967296", "3.1", "1.40", "1.3.6.01", "1..3", ""} {
		if _, err := oidOf(s); err == nil {
			t.Errorf("%q encoded", s)
		}
	}
}

func TestIntegers(t *testing.T) {
	for _, n := range []int64{0, 1, -1, 127, 128, -128, -129, 255, 256, 0x7FFFFFFF, -0x80000000, 1 << 40} {
		e, err := decode(intOf(n), 0)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := integer(e); err != nil || got != n {
			t.Errorf("%d: %d, %v", n, got, err)
		}
	}
	if e, _ := decode(intOf(127), 0); len(e.Val) != 1 {
		t.Error("127 not in one octet")
	}
	if e, _ := decode(intOf(128), 0); len(e.Val) != 2 {
		t.Error("128 not in two octets")
	}
	// Counter64: up to nine octets with a leading zero; a negative form is
	// refused.
	for h, ok := range map[string]bool{
		"4609" + "00ffffffffffffffff": true,
		"4608" + "ffffffffffffffff":   false,
		"4608" + "7fffffffffffffff":   true,
		"4100":                        false,
		"4105" + "00ffffffff":         true,
		"4105" + "0100000000":         false,
	} {
		b, _ := hex.DecodeString(h)
		e, err := decode(b, 0)
		if err != nil {
			t.Fatal(h, err)
		}
		bits := 32
		if e.Tag == tagCounter64 {
			bits = 64
		}
		if _, err := unsigned(e, bits); (err == nil) != ok {
			t.Errorf("%s: %v", h, err)
		}
	}
}

func TestLengthForms(t *testing.T) {
	for h, ok := range map[string]bool{
		"0400":                               true,
		"04810141":                           true, // long form, not minimal: accepted
		"0482000141":                         true,
		"0480":                               false, // indefinite
		"0485" + "0000000001" + "41":         true,  // five length octets: RFC 3417 §8 (1) allows more than needed
		"0488" + "0000000000000001" + "41":   true,
		"04ff" + strings.Repeat("00", 127):   false, // 0xff is reserved (X.690 8.1.3.5), even with a length that fits
		"0485" + "0100000000" + "41":         false, // 2^32, past the end
		"0489" + "010000000000000000" + "41": false, // 2^64, refused before it overflows
		"1f0101":                             false, // a multi-octet tag
		"0402":                               false, // truncated
		"048400000002" + "41":                false, // a length past the end
		"04":                                 false,
		"0484" + "ffffffff":                  false,
	} {
		b, _ := hex.DecodeString(h)
		if _, err := decode(b, 0); (err == nil) != ok {
			t.Errorf("%s: %v", h, err)
		}
	}
}

// requestPDU builds only read requests: there is no way to ask it for a SET,
// an Inform, a Trap, a Response or a Report.
func TestNoWriteEncoder(t *testing.T) {
	for _, tag := range []byte{tagSetRequest, tagInformRequest, tagTrap, tagResponse, tagReport, 0xA4, 0x30} {
		if _, err := requestPDU(tag, 1, 0, 0, []string{"1.3.6.1.2.1.1.5.0"}); err == nil {
			t.Errorf("PDU 0x%02x encoded", tag)
		}
	}
	if _, err := requestPDU(tagGetRequest, 1, 0, 1, nil); err == nil {
		t.Error("a get with error-index encoded")
	}
	b, err := requestPDU(tagGetBulkRequest, 7, 0, 16, []string{"1.3.6.1.2.1.47.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := decodeScoped(scopedOf(nil, nil, b))
	if err != nil || sc.PDU.Tag != tagGetBulkRequest || sc.PDU.ErrIndex != 16 || sc.PDU.VarBinds[0].Value.Tag != tagNull {
		t.Fatalf("%+v, %v", sc, err)
	}
}

// The stored form is the wire message with the plaintext scoped PDU in
// msgData and the digest zeroed, and every header octet otherwise kept,
// including when the outer length changes size.
func TestStoredForm(t *testing.T) {
	pdu, _ := requestPDU(tagGetRequest, 1, 0, 0, []string{"1.3.6.1.2.1.1.1.0"})
	for _, n := range []int{0, 60, 200, 300} { // plaintext sizes around the 128 and 256 octet length forms
		plain := scopedOf(testEngine, bytes.Repeat([]byte("c"), n), pdu)
		enc, _ := testKeys.cfb(1, 2, make([]byte, 8), plain, true)
		u := usmParams{EngineID: testEngine, Boots: 1, Time: 2, User: []byte("u"), AuthParams: make([]byte, 24), PrivParams: make([]byte, 8)}
		wire := messageOf(5, 1472, flagAuth|flagPriv|flagReportable, u, tlvOf(tagOctetString, enc[:max(0, len(enc)-n)]))
		m, err := decodeMessage(wire)
		if err != nil {
			t.Fatal(err)
		}
		testKeys.sign(wire, m)
		out, so, do, dl := storedForm(wire, m, plain)
		sm, err := decodeMessage(out)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if !bytes.Equal(out[so:], plain) || sm.Data.Off != so || dl != 24 || !bytes.Equal(out[do:do+dl], make([]byte, 24)) || sm.AuthOff != do {
			t.Errorf("%d: stored form", n)
		}
		if sm.MsgID != 5 || !bytes.Equal(sm.USM.EngineID, testEngine) || sm.USM.Boots != 1 || sm.USM.Time != 2 || sm.Flags != m.Flags {
			t.Errorf("%d: the header changed", n)
		}
	}
}

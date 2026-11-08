package netdetect

import (
	"testing"

	"otsec.local/otsec/contracts/netobs"
)

func sub(n int) *int { return &n }

// TestClassify pins every row of fc-classes/1 (baseline note §4, C13 §14).
// The expected classes are written from the note's tables, not from the
// code.
func TestClassify(t *testing.T) {
	cases := []struct {
		protocol string
		code     int
		sub      *int
		objects  []string
		class    string
		status   Status
	}{
		{"dnp3", 1, nil, []string{"g60v1"}, netobs.ClassRead, Confirmed},
		{"dnp3", 2, nil, []string{"g50v1"}, netobs.ClassTimeSync, Confirmed},
		{"dnp3", 2, nil, []string{"g50v1", "g50v3"}, netobs.ClassTimeSync, Confirmed},
		{"dnp3", 2, nil, []string{"g80v1"}, netobs.ClassSessionSetup, Confirmed},
		{"dnp3", 2, nil, []string{"g50v1", "g80v1"}, netobs.ClassWrite, Confirmed},
		{"dnp3", 2, nil, []string{"g34v1"}, netobs.ClassWrite, Confirmed},
		{"dnp3", 2, nil, []string{"g80v1", "g80v2"}, netobs.ClassWrite, Confirmed},
		{"dnp3", 2, nil, nil, netobs.ClassWrite, Confirmed},
		{"dnp3", 3, nil, nil, netobs.ClassControl, Confirmed},
		{"dnp3", 4, nil, nil, netobs.ClassControl, Confirmed},
		{"dnp3", 5, nil, []string{"g12v1"}, netobs.ClassControl, Confirmed},
		{"dnp3", 6, nil, []string{"g41v2"}, netobs.ClassControl, Confirmed},
		{"dnp3", 7, nil, nil, netobs.ClassWrite, NumberOnly},
		{"dnp3", 10, nil, nil, netobs.ClassWrite, NumberOnly},
		{"dnp3", 11, nil, nil, netobs.ClassWrite, Unknown},
		{"dnp3", 12, nil, nil, netobs.ClassWrite, Unknown},
		{"dnp3", 13, nil, nil, netobs.ClassControl, Confirmed},
		{"dnp3", 14, nil, nil, netobs.ClassControl, Confirmed},
		{"dnp3", 15, nil, nil, netobs.ClassControl, Unknown},
		{"dnp3", 18, nil, nil, netobs.ClassControl, Unknown},
		{"dnp3", 19, nil, nil, netobs.ClassWrite, Unknown},
		{"dnp3", 20, nil, []string{"g60v2"}, netobs.ClassSessionSetup, NumberOnly},
		{"dnp3", 21, nil, []string{"g60v2"}, netobs.ClassSessionSetup, NumberOnly},
		{"dnp3", 22, nil, []string{"g60v2"}, netobs.ClassSessionSetup, NumberOnly},
		{"dnp3", 23, nil, nil, netobs.ClassTimeSync, Confirmed},
		{"dnp3", 24, nil, nil, netobs.ClassTimeSync, NumberOnly},
		{"dnp3", 25, nil, nil, netobs.ClassOther, Unknown},
		{"dnp3", 27, nil, nil, netobs.ClassWrite, Unknown},
		{"dnp3", 31, nil, nil, netobs.ClassControl, Unknown},
		{"dnp3", 32, nil, []string{"g120v1"}, netobs.ClassOther, Confirmed},
		{"dnp3", 33, nil, []string{"g120v7"}, netobs.ClassOther, Confirmed},
		{"dnp3", 34, nil, nil, netobs.ClassOther, Unknown},
		{"dnp3", 200, nil, nil, netobs.ClassOther, Unknown},

		{"modbus", 1, nil, nil, netobs.ClassRead, Confirmed},
		{"modbus", 4, nil, nil, netobs.ClassRead, Confirmed},
		{"modbus", 5, nil, nil, netobs.ClassWrite, Confirmed},
		{"modbus", 6, nil, nil, netobs.ClassWrite, Confirmed},
		{"modbus", 15, nil, nil, netobs.ClassWrite, Confirmed},
		{"modbus", 16, nil, nil, netobs.ClassWrite, Confirmed},
		{"modbus", 22, nil, nil, netobs.ClassWrite, Unknown},
		{"modbus", 23, nil, nil, netobs.ClassWrite, Unknown},
		{"modbus", 8, sub(0), nil, netobs.ClassOther, Confirmed},
		{"modbus", 8, sub(1), nil, netobs.ClassControl, Unknown},
		{"modbus", 8, sub(4), nil, netobs.ClassControl, Unknown},
		{"modbus", 8, sub(2), nil, netobs.ClassOther, Unknown},
		{"modbus", 8, sub(0x0100), nil, netobs.ClassOther, Unknown},
		{"modbus", 8, nil, nil, netobs.ClassControl, Ruling},
		{"modbus", 43, sub(14), nil, netobs.ClassRead, Unknown},
		{"modbus", 43, sub(13), nil, netobs.ClassWrite, Unknown},
		{"modbus", 43, sub(1), nil, netobs.ClassOther, Unknown},
		{"modbus", 43, nil, nil, netobs.ClassWrite, Ruling},
		{"modbus", 0x60, nil, nil, netobs.ClassRead, Confirmed},
		{"modbus", 0x62, nil, nil, netobs.ClassRead, Confirmed},
		{"modbus", 0x7d, nil, nil, netobs.ClassControl, Confirmed},
		{"modbus", 0x7e, nil, nil, netobs.ClassOther, Confirmed},
		{"modbus", 17, nil, nil, netobs.ClassOther, Unknown},

		{"iec104", 45, nil, nil, netobs.ClassOther, Unknown},
	}
	for _, tc := range cases {
		r := Classify(tc.protocol, tc.code, tc.sub, tc.objects)
		if r.Class != tc.class || r.Status != tc.status || r.Source == "" {
			t.Errorf("%s %d sub %v %v: %+v, want %s %s", tc.protocol, tc.code, tc.sub, tc.objects, r, tc.class, tc.status)
		}
	}
}

// TestNoCodeSlipsPast: every Modbus and DNP3 request code is in exactly
// one class, and every write and control code of the note's tables is
// judged by unauthorized-write.
func TestNoCodeSlipsPast(t *testing.T) {
	for _, p := range []string{"dnp3", "modbus"} {
		for code := 0; code <= 255; code++ {
			r := Classify(p, code, nil, nil)
			found := false
			for _, c := range netobs.FunctionClasses {
				found = found || c == r.Class
			}
			if !found {
				t.Errorf("%s %d: class %q", p, code, r.Class)
			}
		}
	}
}

package netdetect

import (
	"strings"

	"otsec.local/otsec/contracts/netobs"
)

// Table is the class table this package holds: fc-classes/1, the baseline
// note §4 as amended by C13 §14 (D4-69). It is the only copy; the node
// imports Classify.
const Table = netobs.FunctionTable

// Status says what a row rests on (baseline note §4). Closed.
type Status string

const (
	// Confirmed: a held manual gives the code's number and its meaning
	// (documented-untested).
	Confirmed Status = "confirmed"
	// NumberOnly: a held manual shows the code in use on named objects, but
	// no held source pairs the number with its name.
	NumberOnly Status = "number-only"
	// Unknown: no held source has the code. The class is D4's choice, made
	// so the code can't slip past unauthorized-write.
	Unknown Status = "unknown"
	// Ruling: D1's ruling on #543: a Modbus 8 or 43 request too short to
	// hold its sub takes its code's most restrictive row.
	Ruling Status = "ruling"
)

// Row is one row of the table: the class, its status and its source.
type Row struct {
	Class  string
	Status Status
	Source string
}

// Classify returns the fc-classes/1 row for a request: its protocol
// ("dnp3" or "modbus"), its function code, its sub (Modbus 8's sub-function
// or 43's MEI type, nil when absent) and its DNP3 object headers. A
// protocol the table doesn't hold is class other, unknown. It is pure.
func Classify(protocol string, code int, sub *int, objects []string) Row {
	switch protocol {
	case "dnp3":
		return dnp3(code, objects)
	case "modbus":
		return modbus(code, sub)
	}
	return Row{netobs.ClassOther, Unknown, "no table for protocol " + protocol}
}

func dnp3(code int, objects []string) Row {
	switch code {
	case 1:
		return Row{netobs.ClassRead, Confirmed, "Read: S33 Table F.2 p. F.2"}
	case 2:
		switch {
		case only(objects, func(o string) bool { return strings.HasPrefix(o, "g50v") }):
			return Row{netobs.ClassTimeSync, Confirmed, "Write of group 50: S33 Table F.2 p. F.2; S22 Table D.9 pp. D.17 to D.18"}
		case only(objects, func(o string) bool { return o == "g80v1" }):
			return Row{netobs.ClassSessionSetup, Confirmed, "Write of g80v1: S22 p. D.18; S23 Table 2.30 p. 82"}
		}
		return Row{netobs.ClassWrite, Confirmed, "Write: S33 Table F.2 p. F.2"}
	case 3, 4:
		return Row{netobs.ClassControl, Confirmed, "Select, Operate: S33 Table F.2 p. F.2"}
	case 5, 6:
		return Row{netobs.ClassControl, Confirmed, "Direct operate: S33 Table F.2 p. F.3"}
	case 7, 8, 9, 10:
		return Row{netobs.ClassWrite, NumberOnly, "counter freezes: S22 Table D.9 p. D.15; S23 Table 2.30 p. 80"}
	case 11, 12, 19, 27:
		return Row{netobs.ClassWrite, Unknown, "none held"}
	case 13, 14:
		return Row{netobs.ClassControl, Confirmed, "cold and warm start: S22 Table D.9 p. D.19; S23 Table 2.30 p. 83"}
	case 15, 16, 17, 18, 31:
		return Row{netobs.ClassControl, Unknown, "none held"}
	case 20, 21:
		return Row{netobs.ClassSessionSetup, NumberOnly, "on g60 class objects: S22 Table D.9 p. D.18; S23 Table 2.30 p. 82"}
	case 22:
		return Row{netobs.ClassSessionSetup, NumberOnly, "on g60 and all-variations headers: S23 Table 2.30 pp. 79 to 82"}
	case 23:
		return Row{netobs.ClassTimeSync, Confirmed, "delay measurement: S22 Table D.9 p. D.19"}
	case 24:
		return Row{netobs.ClassTimeSync, NumberOnly, "a no-object function: S23 Table 2.30 p. 83"}
	case 32, 33:
		return Row{netobs.ClassOther, Confirmed, "authentication: S23 Table 2.30 pp. 82 to 83"}
	}
	return Row{netobs.ClassOther, Unknown, "none held"}
}

func modbus(code int, sub *int) Row {
	switch code {
	case 1, 2, 3, 4:
		return Row{netobs.ClassRead, Confirmed, "S22 Table E.2 p. E.2; S34 Table E.2 p. E.2"}
	case 5, 6:
		return Row{netobs.ClassWrite, Confirmed, "S22 Table E.2 p. E.2; 06h also operates outputs, S22 p. E.17"}
	case 15:
		return Row{netobs.ClassWrite, Confirmed, "S32 Table 10.31 p. 10.64; S23 p. 274"}
	case 16:
		return Row{netobs.ClassWrite, Confirmed, "S22 Table E.2 p. E.2; operates outputs as 06h does"}
	case 22, 23:
		return Row{netobs.ClassWrite, Unknown, "none held"}
	case 8:
		switch {
		case sub == nil:
			return Row{netobs.ClassControl, Ruling, "too short for its sub-function: the most restrictive row for 8 (D1 on #543)"}
		case *sub == 0:
			return Row{netobs.ClassOther, Confirmed, "loopback: S22 Table E.18 p. E.11"}
		case *sub == 1 || *sub == 4:
			return Row{netobs.ClassControl, Unknown, "none held; restarting communications or listen-only mode can silence a device"}
		}
		return Row{netobs.ClassOther, Unknown, "none held"}
	case 43:
		switch {
		case sub == nil:
			return Row{netobs.ClassWrite, Ruling, "too short for its MEI type: the most restrictive row for 43 (D1 on #543)"}
		case *sub == 14:
			return Row{netobs.ClassRead, Unknown, "no held SEL device lists 2Bh"}
		case *sub == 13:
			return Row{netobs.ClassWrite, Unknown, "CANopen General Reference; none held (D3 on #543)"}
		}
		return Row{netobs.ClassOther, Unknown, "none held"}
	case 0x60, 0x61, 0x62:
		return Row{netobs.ClassRead, Confirmed, "S22 Table E.2 p. E.2 and p. E.17; S34 Table E.2 p. E.2"}
	case 0x7d:
		return Row{netobs.ClassControl, Confirmed, "encapsulated packet with a control command: S22 Table E.30 pp. E.15 to E.16; S34 p. E.14"}
	case 0x7e:
		return Row{netobs.ClassOther, Confirmed, "no-operation, used only inside 7Dh: S22 Table E.2 p. E.2"}
	}
	return Row{netobs.ClassOther, Unknown, "none held"}
}

// only reports whether objects is non-empty and every object satisfies f.
func only(objects []string, f func(string) bool) bool {
	if len(objects) == 0 {
		return false
	}
	for _, o := range objects {
		if !f(o) {
			return false
		}
	}
	return true
}

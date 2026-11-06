package agent

// What GT-MIB serves: exactly S29's list of supported MIBs and OIDs (pp. 46
// and 47, served.json), with SYNTHESIZED values (docs/phase4/C6-gt-mib-plan.md
// section 1.1). entPhysicalTable follows RFC 6933 section 4: entPhysicalEntry
// is 1.3.6.1.2.1.47.1.1.1.1 (mib-2 47, RFC 2578 section 2 for mib-2), its
// index is not accessible, and its accessible columns are 2 to 19.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

//go:embed served.json
var servedJSON []byte

// Served is one line of S29's table.
type Served struct {
	OID    string `json:"oid"`
	Name   string `json:"name"`
	MIB    string `json:"mib"`
	Page   int    `json:"page"`
	Kind   string `json:"kind"`   // scalar, column or table (C6's reading)
	Syntax string `json:"syntax"` // C6's reading
}

// ServedList is S29's table as served.json holds it.
func ServedList() []Served {
	var f struct {
		Objects []Served `json:"objects"`
	}
	if err := json.Unmarshal(servedJSON, &f); err != nil {
		panic(err)
	}
	return f.Objects
}

// Var is one served instance: its name, and its value's tag and contents.
type Var struct {
	OID string
	Tag byte
	Val []byte
}

// MIB is the agent's served instances in lexicographic order, and the
// object prefixes that decide noSuchObject from noSuchInstance.
type MIB struct {
	vars    []Var
	objects []string
}

// Entity OIDs (RFC 6933 section 4).
const (
	EntPhysicalTable = "1.3.6.1.2.1.47.1.1.1"
	EntPhysicalEntry = EntPhysicalTable + ".1"
	SysDescr         = "1.3.6.1.2.1.1.1.0" // RFC 3418 section 2: system is mib-2 1, sysDescr system 1
	SysObjectID      = "1.3.6.1.2.1.1.2.0"
	SysName          = "1.3.6.1.2.1.1.5.0" // sysName is system 5
	SnmpEngineIDOID  = "1.3.6.1.6.3.10.2.1.1.0"
)

// EntCol is the instance OID of entPhysicalTable's column col on row.
func EntCol(col, row int) string { return fmt.Sprintf("%s.%d.%d", EntPhysicalEntry, col, row) }

// Options are what a case may change in the default MIB.
type Options struct {
	EngineID []byte
	FID      string         // the FID cell's value
	FIDCell  string         // the FID's instance; default EntCol(10, 1), entPhysicalSoftwareRev of the chassis
	Rows     int            // entPhysicalTable rows; default 6
	Extra    map[string]Var // instances set after the FID (I4, F2)
	Delete   []string       // instances removed with their object (I5)
}

// NewMIB builds the default served MIB for opts.
func NewMIB(opts Options) *MIB {
	if opts.Rows == 0 {
		opts.Rows = 6
	}
	if opts.FIDCell == "" {
		opts.FIDCell = EntCol(10, 1)
	}
	m := &MIB{}
	for _, s := range ServedList() {
		m.objects = append(m.objects, s.OID)
		switch s.Kind {
		case "scalar":
			m.Set(s.OID+".0", synth(s, opts))
		case "column":
			m.Set(s.OID+".1", synth(s, opts))
		case "table":
			if s.OID == EntPhysicalTable {
				continue
			}
			// A table whose columns S29 does not list and whose MIB is not in
			// the project's texts: one SYNTHESIZED cell, entry 1, column 1,
			// row 1, so a walk sees the table and nothing is invented about
			// its columns. dot1dStpPortTable's columns are listed, and their
			// cells lie under it already.
			if s.Name != "dot1dStpPortTable" {
				m.Set(s.OID+".1.1.1", Var{Tag: TagInteger, Val: []byte{1}})
			}
		}
	}
	for row := 1; row <= opts.Rows; row++ {
		for col := 2; col <= 19; col++ {
			m.Set(EntCol(col, row), entCell(col, row))
		}
	}
	if opts.FID != "" {
		m.Set(opts.FIDCell, Octets(opts.FID))
	}
	for oid, v := range opts.Extra {
		m.Set(oid, v)
	}
	for _, oid := range opts.Delete {
		m.Delete(oid)
	}
	return m
}

// Octets is an OCTET STRING value.
func Octets(s string) Var { return Var{Tag: TagOctets, Val: []byte(s)} }

// synth is a SYNTHESIZED value of s's syntax.
func synth(s Served, opts Options) Var {
	switch s.Name {
	case "sysDescr":
		return Octets("GT-MIB synthesized switch, RSTP mode")
	case "sysObjectID":
		// Under SEL's enterprise arc (S29 p. 47 prints 31823 for the
		// power-supply MIB), at a made-up branch.
		return Var{Tag: TagOID, Val: EncOID("1.3.6.1.4.1.31823.99.2731")[2:]}
	case "sysContact":
		return Octets("gt-mib test contact")
	case "sysName":
		return Octets("gt-mib-sw1")
	case "sysLocation":
		return Octets("gt-mib test rack")
	case "snmpEngineID":
		return Var{Tag: TagOctets, Val: opts.EngineID}
	case "dot1dBaseBridgeAddress":
		return Var{Tag: TagOctets, Val: []byte{0x02, 0x00, 0x00, 0x27, 0x31, 0x01}}
	}
	switch s.Syntax {
	case "octets":
		return Octets("gt-mib")
	case "oid":
		return Var{Tag: TagOID, Val: []byte{0}} // zeroDotZero (RFC 2578 section 2)
	case "timeticks":
		return Var{Tag: TagTimeTicks, Val: []byte{0x01, 0x00}}
	case "counter32":
		return Var{Tag: TagCounter32, Val: []byte{0x07}}
	}
	return Var{Tag: TagInteger, Val: []byte{1}}
}

// entCell is a SYNTHESIZED entPhysicalTable cell (RFC 6933 section 4 gives
// each column's syntax): row 1 is the chassis, row 2 a power supply, the
// rest port modules. No text matches the FID grammar. The class and
// TruthValue numbers are SYNTHESIZED: IANA-ENTITY-MIB and SNMPv2-TC are not
// in the project's texts, and the client does not read them.
func entCell(col, row int) Var {
	name := map[int]string{1: "chassis", 2: "power supply"}[row]
	if name == "" {
		name = "port module " + strconv.Itoa(row-2)
	}
	switch col {
	case 2, 7: // entPhysicalDescr, entPhysicalName
		return Octets("GT-MIB " + name)
	case 3: // entPhysicalVendorType: zeroDotZero
		return Var{Tag: TagOID, Val: []byte{0}}
	case 4: // entPhysicalContainedIn
		if row == 1 {
			return Var{Tag: TagInteger, Val: []byte{0}}
		}
		return Var{Tag: TagInteger, Val: []byte{1}}
	case 5: // entPhysicalClass
		return Var{Tag: TagInteger, Val: []byte{byte(map[bool]int{true: 3, false: 9}[row == 1])}}
	case 6: // entPhysicalParentRelPos
		return Var{Tag: TagInteger, Val: []byte{byte(row - 1)}}
	case 8, 9, 10: // entPhysicalHardwareRev, FirmwareRev, SoftwareRev
		return Octets("rev " + strconv.Itoa(row))
	case 11: // entPhysicalSerialNum
		return Octets("GTMIB000" + strconv.Itoa(row))
	case 12: // entPhysicalMfgName
		return Octets("GT-MIB test maker")
	case 13: // entPhysicalModelName
		return Octets("test " + name)
	case 14, 15: // entPhysicalAlias, entPhysicalAssetID
		return Octets("")
	case 16: // entPhysicalIsFRU
		return Var{Tag: TagInteger, Val: []byte{2}}
	case 17: // entPhysicalMfgDate: "the special value '0000000000000000'H"
		return Var{Tag: TagOctets, Val: make([]byte, 8)}
	case 18, 19: // entPhysicalUris, entPhysicalUUID (SIZE (0|16))
		return Octets("")
	}
	panic(col)
}

// Set adds or replaces the instance oid.
func (m *MIB) Set(oid string, v Var) {
	v.OID = oid
	i := sort.Search(len(m.vars), func(i int) bool { return CompareOID(m.vars[i].OID, oid) >= 0 })
	if i < len(m.vars) && m.vars[i].OID == oid {
		m.vars[i] = v
		return
	}
	m.vars = append(m.vars, Var{})
	copy(m.vars[i+1:], m.vars[i:])
	m.vars[i] = v
}

// Delete removes the instance oid and the object it belongs to, so a Get
// answers noSuchObject.
func (m *MIB) Delete(oid string) {
	for i, v := range m.vars {
		if v.OID == oid {
			m.vars = append(m.vars[:i], m.vars[i+1:]...)
			break
		}
	}
	for i, o := range m.objects {
		if Under(oid, o) {
			m.objects = append(m.objects[:i], m.objects[i+1:]...)
			break
		}
	}
}

// Vars returns the served instances in order.
func (m *MIB) Vars() []Var { return m.vars }

// Get answers one GetRequest varbind (RFC 3416 section 4.2.1).
func (m *MIB) Get(oid string) Var {
	for _, v := range m.vars {
		if v.OID == oid {
			return v
		}
	}
	for _, o := range m.objects {
		if Under(oid, o) {
			return Var{OID: oid, Tag: NoSuchInstance}
		}
	}
	return Var{OID: oid, Tag: NoSuchObject}
}

// Next answers one GetNextRequest varbind (RFC 3416 section 4.2.2): the
// first lexicographic successor, or endOfMibView under the requested name.
func (m *MIB) Next(oid string) Var {
	i := sort.Search(len(m.vars), func(i int) bool { return CompareOID(m.vars[i].OID, oid) > 0 })
	if i < len(m.vars) {
		return m.vars[i]
	}
	return Var{OID: oid, Tag: EndOfMibView}
}

// Bulk answers a GetBulkRequest (RFC 3416 section 4.2.3) before any size
// limit: N non-repeaters, then M repetitions of the R others.
func (m *MIB) Bulk(nonRep, maxRep int64, oids []string) []Var {
	n := int(min(max(nonRep, 0), int64(len(oids))))
	out := make([]Var, 0, n)
	for _, o := range oids[:n] {
		out = append(out, m.Next(o))
	}
	rest := append([]string(nil), oids[n:]...)
	for i := int64(0); i < maxRep && len(rest) > 0; i++ {
		allEnd := true
		for r, o := range rest {
			v := m.Next(o)
			if v.Tag != EndOfMibView {
				allEnd = false
				rest[r] = v.OID
			}
			out = append(out, v)
		}
		if allEnd {
			break // RFC 3416 4.2.3 reason (2)
		}
	}
	return out
}

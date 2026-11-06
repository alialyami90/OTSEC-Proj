package snmpv3

import (
	"encoding/hex"
	"strings"
	"testing"

	c1 "otsec.local/otsec/contracts/asset"
)

func identityOf(t *testing.T, a *agent) ([]Observation, []string, Outcome) {
	t.Helper()
	o := run(t, a, nil)
	if o.Code != "" {
		t.Fatalf("%s %s", o.Code, o.Detail)
	}
	obs, missing := Identity(o)
	return obs, missing, o
}

func TestIdentity(t *testing.T) {
	obs, missing, o := identityOf(t, newAgent(t))
	if len(missing) != 0 {
		t.Fatalf("missing %v", missing)
	}
	want := map[string][2]string{
		c1.AttrHostname:        {"sw-bay-1", oidSysName},
		c1.AttrFirmwareID:      {testFID, "1.3.6.1.2.1.47.1.1.1.1.10.1"},
		c1.AttrModel:           {"SEL-2731M", "1.3.6.1.2.1.47.1.1.1.1.10.1"},
		c1.AttrFirmwareVersion: {"R102-V1", "1.3.6.1.2.1.47.1.1.1.1.10.1"},
		c1.AttrSNMPEngineID:    {hex.EncodeToString(testEngine), ""},
	}
	if len(obs) != len(want) {
		t.Fatalf("%d observations: %+v", len(obs), obs)
	}
	for _, ob := range obs {
		w, ok := want[ob.Name]
		if !ok || ob.Value != w[0] || ob.OID != w[1] {
			t.Errorf("%+v, want %v", ob, w)
			continue
		}
		got := o.Segments[ob.Segment].Bytes[ob.Offset : ob.Offset+ob.Length]
		if ob.Header == c1.HeaderEngineID {
			if hex.EncodeToString(got) != ob.Value {
				t.Errorf("engine ID bytes %x", got)
			}
		} else if string(got) != ob.Value {
			t.Errorf("%s: bytes %q", ob.Name, got)
		}
	}
	// The engine ID comes from an authenticated Response, after the
	// time-window Report.
	for _, ob := range obs {
		if ob.Name == c1.AttrSNMPEngineID && o.Segments[ob.Segment].Phase != "operate" {
			t.Errorf("engine ID read in %s", o.Segments[ob.Segment].Phase)
		}
	}
}

// Mutations of the family parse: each value below is put where the FID is,
// and the parse must find no FID, or the FID it names.
func TestIdentityFIDMutations(t *testing.T) {
	for v, ok := range map[string]bool{
		testFID:                                true,
		"SEL-2741M-R102-V1-Z003001-D20260408":  true,
		"SEL-2731M-X102-V1-Z003001-D20260408":  true,
		"SEL-2732M-R102-V1-Z003001-D20260408":  false,
		"SEL-2731-R102-V1-Z003001-D20260408":   false,
		"sel-2731M-R102-V1-Z003001-D20260408":  false,
		"SEL-2731M-R102-V1-Z003001-D2026040":   false,
		"SEL-2731M-R102-V1-Z003001-D20260408 ": false,
		" SEL-2731M-R102-V1-Z003001-D20260408": false,
		"SEL-2731M-R12-V1-Z003001-D20260408":   false,
		"SEL-2731M-R102-V-Z003001-D20260408":   false,
		"SEL-751-R501-V0-Z104101-D20260910":    false,
		"":                                     false,
	} {
		a := newAgent(t)
		a.mib["1.3.6.1.2.1.47.1.1.1.1.10.1"] = str(v)
		obs, missing, _ := identityOf(t, a)
		got := ""
		for _, ob := range obs {
			if ob.Name == c1.AttrFirmwareID {
				got = ob.Value
			}
		}
		if (ok && (got != v || len(missing) != 0)) || (!ok && (got != "" || len(missing) == 0)) {
			t.Errorf("%q: firmware_id %q, missing %v", v, got, missing)
		}
	}
	// Two distinct FIDs: none is chosen. The same FID twice: it is.
	a := newAgent(t)
	a.mib["1.3.6.1.2.1.47.1.1.1.1.10.2"] = str("SEL-2731M-R101-V0-Z003001-D20260101")
	if obs, missing, _ := identityOf(t, a); len(missing) != 1 || !strings.Contains(missing[0], "more than one") || has(obs, c1.AttrModel) {
		t.Errorf("two FIDs: %v %+v", missing, obs)
	}
	a = newAgent(t)
	a.mib["1.3.6.1.2.1.47.1.1.1.1.10.2"] = str(testFID)
	if _, missing, _ := identityOf(t, a); len(missing) != 0 {
		t.Errorf("the same FID twice: %v", missing)
	}
	// sysDescr.0 holding exactly the FID counts; a FID outside sysDescr.0
	// and the table does not, and neither does one in a non-string type.
	a = newAgent(t)
	a.mib["1.3.6.1.2.1.47.1.1.1.1.10.1"] = str("")
	a.mib[oidSysDescr] = str(testFID)
	if obs, _, _ := identityOf(t, a); !has(obs, c1.AttrFirmwareID) {
		t.Error("a FID in sysDescr.0 not found")
	}
	a = newAgent(t)
	a.mib["1.3.6.1.2.1.47.1.1.1.1.10.1"] = str("")
	a.mib[oidSysName] = str(testFID)
	if obs, _, _ := identityOf(t, a); has(obs, c1.AttrFirmwareID) {
		t.Error("a FID in sysName.0 taken")
	}
	a = newAgent(t)
	a.mib["1.3.6.1.2.1.47.1.1.1.1.10.1"] = tlvOf(tagOpaque, []byte(testFID))
	if obs, _, _ := identityOf(t, a); has(obs, c1.AttrFirmwareID) {
		t.Error("a FID in an Opaque taken")
	}
}

func TestIdentityHostname(t *testing.T) {
	for v, ok := range map[string]bool{"sw-bay-1": true, "": false, " sw": false, "sw\x07": false, strings.Repeat("h", 257): false} {
		a := newAgent(t)
		a.mib[oidSysName] = str(v)
		if obs, _, _ := identityOf(t, a); has(obs, c1.AttrHostname) != ok {
			t.Errorf("%q: hostname %v", v, !ok)
		}
	}
}

func has(obs []Observation, name string) bool {
	for _, ob := range obs {
		if ob.Name == name {
			return true
		}
	}
	return false
}

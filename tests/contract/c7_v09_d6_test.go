package contract

// C7 0.9 (otsec.authz/0.9, docs/phase4/D3-c7-0.9.md): D6's own cases for
// the engine ID rule. RFC 3411 section 5 (SnmpEngineID, rfc3411.txt in the
// project files) says an engine ID is never all zeros nor all 'ff'H, so an
// snmpv3 credential install naming one is refused off the wire, whatever
// the request is stamped, and C1 0.3's declared snmp_engine_id (#498) still
// takes exactly the strings C7 takes, because the collector compares the
// two (HR-16). Expected outcomes come from the rule text, not from the
// code. Requests are built from C7's credential.install golden as
// c7_v08_c6_test.go builds them; every value is invented. Ground truth:
// GT-HAND. Evidence class: desk.

import (
	"errors"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
)

// c7v09IDs are the engine IDs the 0.9 rule decides: all zeros and all ff at
// the shortest and longest lengths C7 takes, and the near misses, one octet
// off, which stay valid.
var c7v09IDs = []struct {
	id   string
	want bool
}{
	{strings.Repeat("00", 5), false},
	{strings.Repeat("00", 32), false},
	{strings.Repeat("ff", 5), false},
	{strings.Repeat("ff", 32), false},
	{strings.Repeat("00", 4) + "01", true},
	{strings.Repeat("00", 4) + "ff", true},
	{"ff" + strings.Repeat("00", 4), true},
	{strings.Repeat("ff", 4) + "fe", true},
	{strings.Repeat("ff", 31) + "00", true},
	{"01" + strings.Repeat("00", 31), true},
}

func TestC7V09ContractID(t *testing.T) {
	if authz.ContractID != "otsec.authz/0.9" {
		t.Fatalf("ContractID %q, want otsec.authz/0.9", authz.ContractID)
	}
	// Nothing new goes on the wire, so a 0.9 reader still reads 0.8.
	if !authz.AcceptsContract("otsec.authz/0.8") {
		t.Error("a 0.9 reader refuses otsec.authz/0.8")
	}
}

func TestC7V09EngineIDRefusedOffTheWire(t *testing.T) {
	for _, stamp := range []string{"otsec.authz/0.8", "otsec.authz/0.9"} {
		for _, c := range c7v09IDs {
			_, err := authz.DecodeRequest(c7SNMPInstall(t, func(m map[string]any) {
				m["contract"] = stamp
				c7USM(m)["engine_id"] = c.id
			}))
			var r *authz.Refusal
			switch {
			case c.want && err != nil:
				t.Errorf("%s, engine ID %s: refused (%v), want accepted", stamp, c.id, err)
			case !c.want && (err == nil || !errors.As(err, &r)):
				t.Errorf("%s, engine ID %s: got %v, want a refusal", stamp, c.id, err)
			}
		}
	}
}

// One rule in both, as TestC7V08EngineIDOneRuleInBoth asks, for the strings
// 0.9 changes: an ID only C1 refused could be pinned in a credential no
// asset can declare.
func TestC7V09EngineIDOneRuleInBoth(t *testing.T) {
	for _, c := range c7v09IDs {
		u := authz.USM{UserName: "otsec-ro", Auth: authz.USMAuthHMACSHA512, Priv: authz.USMPrivAES128, EngineID: c.id, SoleDeviceAttested: true}
		inC7 := u.Validate() == nil
		b, err := c1SNMP(t, func(m map[string]any) {
			c1OperatorOnly(m, asset.AttrSNMPEngineID)
			c1Attr(m, asset.AttrSNMPEngineID)["value"] = c.id
			c1Obs(m, asset.AttrSNMPEngineID, 0)["value"] = c.id
		})
		if err != nil {
			t.Fatal(err)
		}
		_, derr := asset.Decode(b)
		if inC1 := derr == nil; inC7 != c.want || inC1 != c.want {
			t.Errorf("engine ID %s: C7 takes it %v, C1 0.3 takes it %v, want %v (C1: %v)", c.id, inC7, inC1, c.want, derr)
		}
	}
}

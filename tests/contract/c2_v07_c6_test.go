package contract

// C2 0.7, the SNMPv3 result (docs/phase4/C2-c1-0.3-c3-0.4.md §2.4 and
// docs/phase4/C2-adapter-0.7-snmp-results.md, approved by C1 on #445,
// D4-53): C6's own cases. Expected outcomes come from the rule text.
// Results are C2's invented ok example, edited; nothing is a capture.
// Ground truth: GT-HAND.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	"otsec.local/otsec/contracts/register"
)

func c2SNMPFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", "adapter", "testdata", "snmp", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func c2SNMPResult(t *testing.T, name string, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(c2SNMPFile(t, filepath.Join("results", "valid", name)), &m); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// c2KeepDigest drops the usm-digest redaction at offset and writes a
// non-zero digest there, as a client that forgot to zero it would store.
func c2KeepDigest(t *testing.T, m map[string]any, offset float64) {
	tr := m["transcript"].(map[string]any)
	var keep []any
	var length int
	for _, r := range tr["redactions"].([]any) {
		if rd := r.(map[string]any); rd["offset"] == offset {
			length = int(rd["length"].(float64))
		} else {
			keep = append(keep, r)
		}
	}
	if length == 0 {
		t.Fatalf("no redaction at %v", offset)
	}
	tr["redactions"] = keep
	data, err := base64.StdEncoding.DecodeString(tr["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < length; i++ {
		data[int(offset)+i] = 0xa5
	}
	sum := sha256.Sum256(data)
	tr["data"], tr["sha256"] = base64.StdEncoding.EncodeToString(data), hex.EncodeToString(sum[:])
}

func c2Obs(m map[string]any, name string) map[string]any {
	for _, o := range m["observations"].([]any) {
		if ob := o.(map[string]any); ob["name"] == name {
			return ob
		}
	}
	panic("no observation " + name)
}

func TestC2V07SNMPResult(t *testing.T) {
	for _, c := range []struct {
		name, file string
		edit       func(m map[string]any)
		ok         bool
	}{
		{"ok", "ok.json", nil, true},

		// §2.4: msgAuthenticationParameters is stored as zero octets in
		// every segment. A message the collector sent in auth or operate
		// always carries its own digest, so its redaction is required.
		{"a sent auth digest kept", "ok.json", func(m map[string]any) { c2KeepDigest(t, m, 210) }, false},
		{"a sent operate digest kept", "ok.json", func(m map[string]any) { c2KeepDigest(t, m, 488) }, false},

		// 2.1: the SEL facts and codes do not apply to SNMP.
		{"a SEL-only code", "ok.json", func(m map[string]any) {
			m["status"], m["error"] = "failed", map[string]any{"code": "failed.auth_rejected"}
		}, false},
		{"ok not authenticated", "ok.json", func(m map[string]any) {
			m["session"].(map[string]any)["snmp"].(map[string]any)["authenticated"] = false
		}, false},
		{"QUI on SNMP", "ok.json", func(m map[string]any) { m["session"].(map[string]any)["quit_sent"] = true }, false},
		{"a 0.6 result with session.snmp", "ok.json", func(m map[string]any) { m["schema"] = "otsec.adapter/0.6" }, false},
		{"engine ID mismatch, yet authenticated", "refused.engine_id_mismatch.json", func(m map[string]any) {
			m["session"].(map[string]any)["snmp"].(map[string]any)["authenticated"] = true
		}, false},

		// 2.2: ok needs the identity to match, the FID included.
		{"ok with another FID", "ok.json", func(m map[string]any) {
			id := m["identity"].(map[string]any)
			id["result"] = "mismatch"
			id["items"].([]any)[1].(map[string]any)["expected"] = "SEL-2731M-R102-V2-Z003001-D20260408"
		}, false},

		// 2.3: the read path.
		{"FID read from the header", "ok.json", func(m map[string]any) {
			c2Obs(m, "firmware_id")["read"] = map[string]any{"operation": "sel27x1.snmp.entity", "header": "msgAuthoritativeEngineID"}
		}, false},
		{"engine ID read from a varbind", "ok.json", func(m map[string]any) {
			c2Obs(m, "snmp_engine_id")["read"] = map[string]any{"operation": "sel27x1.snmp.system", "oid": "1.3.6.1.6.3.10.2.1.1.0"}
		}, false},
		{"an observation without read", "ok.json", func(m map[string]any) { delete(c2Obs(m, "hostname"), "read") }, false},

		// failed.snmp_fid_unreadable (C1 on #445, D4-54): after
		// authentication, the engine ID alone, and nothing cut from a FID.
		{"FID unreadable", "failed.snmp_fid_unreadable.json", nil, true},
		{"FID unreadable, two FIDs", "failed.snmp_fid_unreadable.two-fids.json", nil, true},
		{"FID unreadable, not authenticated", "failed.snmp_fid_unreadable.json", func(m map[string]any) {
			m["session"].(map[string]any)["snmp"].(map[string]any)["authenticated"] = false
		}, false},
		{"FID unreadable with a model", "failed.snmp_fid_unreadable.json", func(m map[string]any) {
			c2Obs(m, "hostname")["name"] = "model"
		}, false},
		{"FID unreadable with a firmware version", "failed.snmp_fid_unreadable.json", func(m map[string]any) {
			c2Obs(m, "hostname")["name"] = "firmware_version"
		}, false},
		{"FID unreadable with the engine ID differing", "failed.snmp_fid_unreadable.json", func(m map[string]any) {
			id := m["identity"].(map[string]any)
			id["result"] = "mismatch"
			id["items"].([]any)[0].(map[string]any)["expected"] = "80007c4f03020000273102"
		}, false},
		{"FID unreadable with no identity item", "failed.snmp_fid_unreadable.json", func(m map[string]any) {
			m["identity"].(map[string]any)["items"] = []any{}
		}, false},
	} {
		_, err := adapter.DecodeResult(c2SNMPResult(t, c.file, c.edit))
		if c.ok != (err == nil) {
			t.Errorf("%s: decode %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// 2.3, checked against the register: an observation's operation is a step
// of the invoked run, and its OID is one the operation names (get) or lies
// strictly inside its subtree (walk).
func TestC2V07CheckSNMP(t *testing.T) {
	pkg, err := register.Decode(c2SNMPFile(t, "register.json"))
	if err != nil {
		t.Fatal(err)
	}
	inv, err := adapter.DecodeInvocation(c2SNMPFile(t, "invocation.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		edit func(m map[string]any)
		ok   bool
	}{
		{"ok", nil, true},
		{"an OID the get does not name", func(m map[string]any) {
			c2Obs(m, "hostname")["read"].(map[string]any)["oid"] = "1.3.6.1.2.1.1.6.0"
		}, false},
		{"an OID outside the walk's subtree", func(m map[string]any) {
			c2Obs(m, "firmware_id")["read"].(map[string]any)["oid"] = "1.3.6.1.2.1.47.1.1.2.1"
		}, false},
		{"an OID sharing the subtree's prefix", func(m map[string]any) {
			c2Obs(m, "firmware_id")["read"].(map[string]any)["oid"] = "1.3.6.1.2.1.47.1.1.10.1"
		}, false},
		{"the subtree itself", func(m map[string]any) {
			c2Obs(m, "firmware_id")["read"].(map[string]any)["oid"] = "1.3.6.1.2.1.47.1.1.1"
		}, false},
		{"an OID the walk could reach, read by the get", func(m map[string]any) {
			c2Obs(m, "hostname")["read"].(map[string]any)["oid"] = "1.3.6.1.2.1.47.1.1.1.1.7.1"
		}, false},
		{"an operation the run does not have", func(m map[string]any) {
			c2Obs(m, "hostname")["read"].(map[string]any)["operation"] = "sel27x1.snmp.interfaces"
		}, false},
	} {
		r, err := adapter.DecodeResult(c2SNMPResult(t, "ok.json", c.edit))
		if err != nil {
			t.Fatalf("%s: the edited result does not decode: %v", c.name, err)
		}
		err = r.CheckSNMP(pkg, inv)
		if c.ok != (err == nil) {
			t.Errorf("%s: CheckSNMP %v, want ok %v", c.name, err, c.ok)
		}
	}
}

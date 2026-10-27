package contract

// C8 0.3 quarantine.exported and quarantine.cleared (#155, D3-1, P3-A5):
// A6's own cases against ParseRecord. Expected outcomes come from the
// contract's doc text: both actions are written by the node about one
// asset, with the verified range; exported is info; cleared is succeeded,
// or info with reason already_cleared, and carries clear_sha256 and a human
// requested_by; a record stamped 0.2 or earlier carries neither action nor
// the quarantine object. Records are built by editing A6's own JSON, not
// A3's goldens. Ground truth: GT-HAND.

import (
	"encoding/json"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
)

const c8QuarantineCleared = `{"contract":"otsec.audit/0.3","node_id":"site-a6-node-1","seq":7,` +
	`"prev_hash":"a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",` +
	`"time":{"utc":"2026-10-26T16:00:00.000000Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},` +
	`"actor":{"type":"node","id":"site-a6-node-1"},"action":"quarantine.cleared","outcome":"succeeded",` +
	`"target":{"asset_id":"0b6c2f4e-1d3a-4c5b-8e7f-9a0b1c2d3e4f"},` +
	`"quarantine":{"manifest_sha256":"1111111111111111111111111111111111111111111111111111111111111111",` +
	`"first_seq":5,"last_seq":9,"items":5,` +
	`"clear_sha256":"2222222222222222222222222222222222222222222222222222222222222222","requested_by":"admin@site-a6"}}`

// c8Q returns A6's quarantine.cleared record with edit applied to its
// decoded form.
func c8Q(t *testing.T, edit func(m map[string]any, q map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(c8QuarantineCleared), &m); err != nil {
		t.Fatal(err)
	}
	q := m["quarantine"].(map[string]any)
	if edit != nil {
		edit(m, q)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func c8Exported(m, q map[string]any) {
	m["action"], m["outcome"] = "quarantine.exported", "info"
	delete(q, "clear_sha256")
	delete(q, "requested_by")
}

func TestC8QuarantineRecords(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(m, q map[string]any)
		ok   bool
	}{
		{"cleared, succeeded", nil, true},
		{"cleared, already_cleared", func(m, q map[string]any) { m["outcome"], m["reason_code"] = "info", "already_cleared" }, true},
		{"exported", c8Exported, true},
		{"exported, one seq", func(m, q map[string]any) { c8Exported(m, q); q["first_seq"], q["last_seq"], q["items"] = 9, 9, 1 }, true},
		{"exported, gaps in the range", func(m, q map[string]any) { c8Exported(m, q); q["items"] = 2 }, true},

		{"exported at 0.2", func(m, q map[string]any) { c8Exported(m, q); m["contract"] = "otsec.audit/0.2" }, false},
		{"cleared at 0.2", func(m, q map[string]any) { m["contract"] = "otsec.audit/0.2" }, false},
		{"quarantine on service.start", func(m, q map[string]any) { m["action"], m["outcome"] = "service.start", "info"; delete(m, "target") }, false},
		{"quarantine on asset.suspend at 0.2", func(m, q map[string]any) { m["contract"], m["action"] = "otsec.audit/0.2", "asset.suspend" }, false},
		{"no quarantine object", func(m, q map[string]any) { delete(m, "quarantine") }, false},

		{"actor human", func(m, q map[string]any) { m["actor"] = map[string]any{"type": "human", "id": "admin@site-a6"} }, false},
		{"actor schedule", func(m, q map[string]any) { m["actor"] = map[string]any{"type": "schedule", "id": "sch-a6"} }, false},
		{"no target", func(m, q map[string]any) { delete(m, "target") }, false},
		{"target without asset", func(m, q map[string]any) { m["target"] = map[string]any{"credential_ref": "cred_a6a6a6a6"} }, false},

		{"first_seq 0", func(m, q map[string]any) { q["first_seq"] = 0 }, false},
		{"last before first", func(m, q map[string]any) { q["first_seq"], q["last_seq"] = 9, 5 }, false},
		{"items 0", func(m, q map[string]any) { q["items"] = 0 }, false},
		{"items over the range", func(m, q map[string]any) { q["items"] = 6 }, false},
		{"negative seq", func(m, q map[string]any) { q["first_seq"] = -1 }, false},
		{"manifest hash upper case", func(m, q map[string]any) { q["manifest_sha256"] = strings.Repeat("A", 64) }, false},
		{"manifest hash short", func(m, q map[string]any) { q["manifest_sha256"] = strings.Repeat("1", 63) }, false},
		{"unknown field in quarantine", func(m, q map[string]any) { q["a6_extra"] = 1 }, false},

		{"exported, succeeded", func(m, q map[string]any) { c8Exported(m, q); m["outcome"] = "succeeded" }, false},
		{"exported with clear_sha256", func(m, q map[string]any) { c8Exported(m, q); q["clear_sha256"] = strings.Repeat("2", 64) }, false},
		{"exported with requested_by", func(m, q map[string]any) { c8Exported(m, q); q["requested_by"] = "admin@site-a6" }, false},
		{"cleared, succeeded with a reason", func(m, q map[string]any) { m["reason_code"] = "already_cleared" }, false},
		{"cleared, info without a reason", func(m, q map[string]any) { m["outcome"] = "info" }, false},
		{"cleared, info, another reason", func(m, q map[string]any) { m["outcome"], m["reason_code"] = "info", "operator" }, false},
		{"cleared, failed", func(m, q map[string]any) { m["outcome"] = "failed" }, false},
		{"cleared, denied", func(m, q map[string]any) { m["outcome"] = "denied" }, false},
		{"cleared without clear_sha256", func(m, q map[string]any) { delete(q, "clear_sha256") }, false},
		{"cleared without requested_by", func(m, q map[string]any) { delete(q, "requested_by") }, false},
		{"requested_by empty", func(m, q map[string]any) { q["requested_by"] = "" }, false},
		{"requested_by with a newline", func(m, q map[string]any) { q["requested_by"] = "admin@site-a6\nforged" }, false},
		{"requested_by with spaces", func(m, q map[string]any) { q["requested_by"] = "admin site a6" }, false},
	} {
		_, err := audit.ParseRecord(c8Q(t, c.edit))
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// A pending record goes through the same rules before the store seals it.
func TestC8QuarantinePending(t *testing.T) {
	pending := c8Q(t, func(m, q map[string]any) { delete(m, "seq"); delete(m, "prev_hash") })
	if _, err := audit.ValidatePending(pending); err != nil {
		t.Fatalf("pending clear: %v", err)
	}
	bad := c8Q(t, func(m, q map[string]any) {
		delete(m, "seq")
		delete(m, "prev_hash")
		m["actor"] = map[string]any{"type": "human", "id": "admin@site-a6"}
	})
	if _, err := audit.ValidatePending(bad); err == nil {
		t.Fatal("a pending clear by a person was accepted")
	}
}

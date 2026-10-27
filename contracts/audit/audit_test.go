package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/authz"
	"otsec.local/otsec/contracts/event"
)

func baseTime() Time {
	return Time{UTC: "2026-10-24T11:40:00.123456Z", ResolutionNS: 1000, Clock: Clock{Sync: event.SyncSynchronized, Source: "ntp"}}
}

func telnetTarget() *Target {
	return &Target{AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", Transport: authz.TransportTelnet, DownstreamSecurity: authz.DownstreamPlaintext,
		CredentialRef: "cred_7f3k2m9q4x", CredentialVersion: 2, Family: "sel-751"}
}

// chain builds a valid chain from record templates, filling seq and prev_hash.
func chain(t *testing.T, recs []Record) [][]byte {
	t.Helper()
	prev := GenesisPrevHash
	var out [][]byte
	for i := range recs {
		r := recs[i]
		r.Contract, r.NodeID, r.Seq, r.PrevHash = ContractID, "site-a-node-1", uint64(i+1), prev
		if r.Time.UTC == "" {
			r.Time = baseTime()
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRecord(b); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		out = append(out, b)
		prev = Hash(b)
	}
	return out
}

func sliceRecords() []Record {
	collector := Actor{Type: authz.PrincipalSchedule, ID: "sch-ser-751-feeder-3", Role: authz.RoleCollector}
	system := Actor{Type: authz.PrincipalSystem, ID: "collector"}
	recs := []Record{
		{Actor: system, Action: ActionAuditChainStart, Outcome: OutcomeInfo},
		{Actor: system, Action: ActionRegisterVerify, Outcome: OutcomeSucceeded, Target: &Target{Family: "sel-751"}, RegisterRevision: 6},
		{Actor: collector, Action: ActionCollectorRequest, Outcome: OutcomeAllowed, CorrelationID: "req-20261024-0001", OperationID: "sel.ser.read_all", PolicyVersion: 3},
		{Actor: collector, Action: ActionDeviceSessionOpen, Outcome: OutcomeSucceeded, Target: telnetTarget(), CorrelationID: "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71"},
		{Actor: collector, Action: ActionCredentialUse, Outcome: OutcomeSucceeded, Target: telnetTarget(), CorrelationID: "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71"},
		{Actor: collector, Action: ActionDevicePostureWarning, Outcome: OutcomeWarning, ReasonCode: "maxacc_above_1", Target: telnetTarget(), CorrelationID: "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71"},
		{Actor: collector, Action: ActionDeviceOp, Outcome: OutcomeSucceeded, Target: telnetTarget(), OperationID: "sel.ser.read_all", RegisterRevision: 6,
			BytesSentDigest: "sha256:" + strings.Repeat("ab", 32), CorrelationID: "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71"},
		{Actor: collector, Action: ActionDeviceSessionClose, Outcome: OutcomeSucceeded, Target: telnetTarget(), CorrelationID: "0f3e6c1a-8b2d-4e7f-9a15-6c4d2b8e0a71",
			TranscriptSHA256: strings.Repeat("cd", 32)},
		{Actor: collector, Action: ActionCollectorRequest, Outcome: OutcomeDenied, ReasonCode: string(authz.RefuseNotInvocable), CorrelationID: "req-20261024-0002"},
	}
	// The collector numbers every event it reports (C7-A5-2).
	var n uint64
	for i := range recs {
		if CollectorReported(&recs[i]) {
			n++
			recs[i].CollectorSeq = n
		}
	}
	return recs
}

func TestChainVerifies(t *testing.T) {
	recs := chain(t, sliceRecords())
	if err := VerifyChain("site-a-node-1", recs, nil, nil); err != nil {
		t.Fatal(err)
	}
	head := &Checkpoint{NodeID: "site-a-node-1", Seq: uint64(len(recs)), Hash: Hash(recs[len(recs)-1])}
	if err := VerifyChain("site-a-node-1", recs, nil, head); err != nil {
		t.Fatal(err)
	}
	// Verifying a later run from a checkpoint.
	from := &Checkpoint{NodeID: "site-a-node-1", Seq: 4, Hash: Hash(recs[3])}
	if err := VerifyChain("site-a-node-1", recs[4:], from, head); err != nil {
		t.Fatal(err)
	}
}

func TestChainDetectsTampering(t *testing.T) {
	recs := chain(t, sliceRecords())
	n := len(recs)
	head := &Checkpoint{NodeID: "site-a-node-1", Seq: uint64(n), Hash: Hash(recs[n-1])}
	without := func(i int) [][]byte { return append(append([][]byte{}, recs[:i]...), recs[i+1:]...) }
	altered := func(i int, from, to string) [][]byte {
		out := append([][]byte{}, recs...)
		out[i] = bytes.Replace(recs[i], []byte(from), []byte(to), 1)
		if bytes.Equal(out[i], recs[i]) {
			t.Fatalf("alteration %q did not apply to record %d", from, i)
		}
		return out
	}
	swapped := append([][]byte{}, recs...)
	swapped[5], swapped[6] = swapped[6], swapped[5]
	cases := map[string]struct {
		recs [][]byte
		head *Checkpoint
	}{
		"middle record removed":                  {without(4), nil},
		"first record removed":                   {without(0), nil},
		"refusal turned into acceptance":         {altered(8, `"outcome":"denied","reason_code":"not_invocable"`, `"outcome":"allowed"`), head},
		"posture warning reason changed":         {altered(5, `maxacc_above_1`, `ftpacc_above_1`), nil},
		"credential use outcome changed":         {altered(4, `"succeeded"`, `"failed","reason_code":"auth_failed"`), nil},
		"newest record altered, head checkpoint": {altered(n-1, `not_invocable`, `busy`), head},
		"newest record removed, head checkpoint": {recs[:n-1], head},
		"two records swapped":                    {swapped, nil},
		"record from another node spliced in":    {altered(3, `"node_id":"site-a-node-1"`, `"node_id":"site-b-node-1"`), nil},
		"whitespace added (bytes, not meaning)":  {altered(2, `{"contract"`, `{ "contract"`), nil},
	}
	for name, c := range cases {
		if err := VerifyChain("site-a-node-1", c.recs, nil, c.head); !errors.Is(err, ErrChainBroken) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	// Without a trusted head, altering the newest record is not detectable:
	// that is the residual window between checkpoints (AP-17).
	if err := VerifyChain("site-a-node-1", altered(n-1, `not_invocable`, `busy`), nil, nil); err != nil {
		t.Fatalf("expected the documented residual: %v", err)
	}
}

func TestEveryC7RefusalMapsToAnAuditRecord(t *testing.T) {
	for _, code := range authz.RefusalCodes {
		r := Record{Contract: ContractID, NodeID: "n1", Seq: 2, PrevHash: strings.Repeat("0", 63) + "1", Time: baseTime(),
			Actor:  Actor{Type: authz.PrincipalSchedule, ID: "sch-1", Role: authz.RoleCollector},
			Action: ActionCollectorRequest, Outcome: OutcomeDenied, ReasonCode: string(code), CorrelationID: "req-1", CollectorSeq: 3}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", code, err)
		}
	}
	r := Record{Contract: ContractID, NodeID: "n1", Seq: 2, PrevHash: strings.Repeat("0", 63) + "1", Time: baseTime(),
		Actor: Actor{Type: authz.PrincipalSchedule, ID: "sch-1"}, Action: ActionCollectorRequest, Outcome: OutcomeDenied,
		ReasonCode: "made_up", CorrelationID: "req-1", CollectorSeq: 3}
	if err := r.Validate(); err == nil {
		t.Fatal("a code outside C7 accepted for collector.request")
	}
}

// TODO(C2): when contracts/adapter merges, iterate its refusal and posture
// codes here and check that each maps to device.refused or
// device.posture_warning with that reason code.
func TestDeviceRefusalRecords(t *testing.T) {
	for _, code := range []string{"fid_not_allowlisted", "lang_not_english", "password_prompt_absent", "auth_failed", "identity_mismatch", "unexpected_access_level"} {
		r := Record{Contract: ContractID, NodeID: "n1", Seq: 2, PrevHash: strings.Repeat("0", 63) + "1", Time: baseTime(),
			Actor: Actor{Type: authz.PrincipalSchedule, ID: "sch-1"}, Action: ActionDeviceRefused, Outcome: OutcomeDenied,
			ReasonCode: code, Target: telnetTarget(), CorrelationID: "inv-1", CollectorSeq: 3}
		if err := r.Validate(); err != nil {
			t.Fatalf("%s: %v", code, err)
		}
	}
}

func TestRecordRules(t *testing.T) {
	good := sliceRecords()[3]
	good.Contract, good.NodeID, good.Seq, good.PrevHash, good.Time = ContractID, "n1", 4, strings.Repeat("a", 64), baseTime()
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(*Record)) Record {
		r := good
		t := *good.Target
		r.Target = &t
		f(&r)
		return r
	}
	bad := map[string]Record{
		"plaintext transport labelled encrypted":  mut(func(r *Record) { r.Target.DownstreamSecurity = authz.DownstreamEncryptedAuthenticated }),
		"device action without label":             mut(func(r *Record) { r.Target.DownstreamSecurity = "" }),
		"device action without target":            mut(func(r *Record) { r.Target = nil }),
		"failed without reason":                   mut(func(r *Record) { r.Outcome = OutcomeFailed }),
		"unknown action":                          mut(func(r *Record) { r.Action = "device.write" }),
		"unknown outcome":                         mut(func(r *Record) { r.Outcome = "partly" }),
		"other major":                             mut(func(r *Record) { r.Contract = "otsec.audit/1.0" }),
		"seq zero":                                mut(func(r *Record) { r.Seq = 0 }),
		"genesis hash after seq 1":                mut(func(r *Record) { r.PrevHash = GenesisPrevHash }),
		"more precision than resolution":          mut(func(r *Record) { r.Time.UTC = "2026-10-24T11:40:00.123456789Z" }),
		"local time":                              mut(func(r *Record) { r.Time.UTC = "2026-10-24T14:40:00.123456+03:00" }),
		"digest not sha256":                       mut(func(r *Record) { r.BytesSentDigest = "md5:abc" }),
		"detail too long":                         mut(func(r *Record) { r.Detail = strings.Repeat("x", 513) }),
		"collector event without collector_seq":   mut(func(r *Record) { r.CollectorSeq = 0 }),
		"device action without invocation ID":     mut(func(r *Record) { r.CorrelationID = "" }),
		"clock sync outside the C4 enum":          mut(func(r *Record) { r.Time.Clock.Sync = "ok" }),
		"upper-case node":                         mut(func(r *Record) { r.NodeID = "Site-A" }),
		"asset ID that is not a C1 UUID":          mut(func(r *Record) { r.Target.AssetID = "site-a.relay.feeder-3" }),
		"transcript digest on session open":       mut(func(r *Record) { r.TranscriptSHA256 = strings.Repeat("cd", 32) }),
		"session close without transcript digest": mut(func(r *Record) { r.Action = ActionDeviceSessionClose }),
		"transcript digest not lowercase hex": mut(func(r *Record) {
			r.Action, r.TranscriptSHA256 = ActionDeviceSessionClose, strings.Repeat("CD", 32)
		}),
		"transcript digest with a prefix": mut(func(r *Record) {
			r.Action, r.TranscriptSHA256 = ActionDeviceSessionClose, "sha256:"+strings.Repeat("cd", 32)
		}),
		"node record with collector_seq": mut(func(r *Record) {
			r.Action, r.Outcome, r.Target, r.CorrelationID = ActionCollectorRequest, OutcomeInfo, nil, "req-1"
		}),
	}
	for name, r := range bad {
		if err := r.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// A later minor is accepted; unknown actions normalise to unrecognized.
	later := good
	later.Contract = "otsec.audit/0.4"
	if err := later.Validate(); err != nil {
		t.Fatalf("later minor: %v", err)
	}
	if Action("device.new_in_0_4").Normalize() != ActionUnrecognized {
		t.Fatal("normalize")
	}
}

func TestParseRecordRejectsSecretsAndAmbiguity(t *testing.T) {
	recs := chain(t, sliceRecords())
	ok := recs[4]
	cases := map[string]string{
		"password field":    strings.Replace(string(ok), `"outcome"`, `"password":"hunter2","outcome"`, 1),
		"nested secret":     strings.Replace(string(ok), `"family":"sel-751"`, `"family":"sel-751","secret":"x"`, 1),
		"raw device output": strings.Replace(string(ok), `"outcome"`, `"raw_output":"PSVTAgo=","outcome"`, 1),
		"duplicate outcome": strings.Replace(string(ok), `"outcome":"succeeded"`, `"outcome":"succeeded","outcome":"failed"`, 1),
		"trailing data":     string(ok) + `{}`,
		// Sealed bytes never hold a raw CR, LF or NUL, so a forwarder can
		// frame them without escaping (C8-A4-6).
		"raw LF":  strings.Replace(string(ok), `,"outcome"`, ",\n\"outcome\"", 1),
		"raw CR":  strings.Replace(string(ok), `,"outcome"`, ",\r\"outcome\"", 1),
		"raw NUL": strings.Replace(string(ok), `,"outcome"`, ",\x00\"outcome\"", 1),
		// encoding/json fills a field from a key that differs only in case,
		// so these would show a reviewer one outcome and a reader another.
		"case-folded duplicate": strings.Replace(string(ok), `"outcome":"succeeded"`, `"outcome":"succeeded","Outcome":"failed"`, 1),
		"case-folded key":       strings.Replace(string(ok), `"outcome":"succeeded"`, `"OUTCOME":"succeeded"`, 1),
		"case-folded nested":    strings.Replace(string(ok), `"family":"sel-751"`, `"family":"sel-751","Family":"sel-487e"`, 1),
		"oversize":              strings.Replace(string(ok), `"outcome"`, `"pad":"`+strings.Repeat("x", MaxRecordBytes)+`","outcome"`, 1),
	}
	for name, raw := range cases {
		if raw == string(ok) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := ParseRecord([]byte(raw)); !errors.Is(err, ErrRecordRejected) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	// The transcript digest is allowed, spelled exactly so and only on the
	// session close; any other transcript-named field is content and is
	// refused at any depth and in any case (D1-25).
	closeRec := recs[7]
	if _, err := ParseRecord(closeRec); err != nil || !bytes.Contains(closeRec, []byte(`"transcript_sha256":"`)) {
		t.Fatalf("session close with its transcript digest: %v", err)
	}
	for name, raw := range map[string]string{
		"transcript field":       strings.Replace(string(closeRec), `"outcome"`, `"transcript":"PSVTAgo=","outcome"`, 1),
		"transcript content":     strings.Replace(string(closeRec), `"outcome"`, `"transcript_data":"PSVTAgo=","outcome"`, 1),
		"nested transcript":      strings.Replace(string(closeRec), `"family":"sel-751"`, `"family":"sel-751","transcript_bytes":"x"`, 1),
		"case-variant digest":    strings.Replace(string(closeRec), `"transcript_sha256"`, `"Transcript_SHA256"`, 1),
		"digest on another type": strings.Replace(string(ok), `"outcome"`, `"transcript_sha256":"`+strings.Repeat("cd", 32)+`","outcome"`, 1),
	} {
		if raw == string(closeRec) || raw == string(ok) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := ParseRecord([]byte(raw)); !errors.Is(err, ErrRecordRejected) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	// An unknown, harmless field from a later minor is kept; the same field
	// on a record of this minor is refused (C8-A6-2).
	later := strings.Replace(string(ok), `"`+ContractID+`"`, `"otsec.audit/0.6"`, 1)
	if _, err := ParseRecord([]byte(strings.Replace(later, `"outcome"`, `"new_field_in_0_6":1,"outcome"`, 1))); err != nil {
		t.Fatalf("unknown field in a later minor: %v", err)
	}
	if _, err := ParseRecord([]byte(strings.Replace(string(ok), `"outcome"`, `"api_token":"x","outcome"`, 1))); !errors.Is(err, ErrRecordRejected) {
		t.Fatalf("unknown field in a record of this minor: %v", err)
	}
}

func TestGoldenRecords(t *testing.T) {
	valid, _ := filepath.Glob("testdata/valid/*.json")
	invalid, _ := filepath.Glob("testdata/invalid/*.json")
	if len(valid) < 1 || len(invalid) < 3 {
		t.Fatalf("golden examples missing: %d valid, %d invalid", len(valid), len(invalid))
	}
	for _, p := range valid {
		b, _ := os.ReadFile(p)
		if _, err := ParseRecord(bytes.TrimRight(b, "\n")); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	for _, p := range invalid {
		b, _ := os.ReadFile(p)
		if _, err := ParseRecord(bytes.TrimRight(b, "\n")); err == nil {
			t.Fatalf("%s accepted", p)
		}
	}
	chainFile, err := os.ReadFile("testdata/chain/slice-session.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	for _, l := range bytes.Split(bytes.TrimRight(chainFile, "\n"), []byte("\n")) {
		lines = append(lines, l)
	}
	if err := VerifyChain("site-a-node-1", lines, nil, nil); err != nil {
		t.Fatalf("golden chain: %v", err)
	}
}

func TestSchemaIsJSON(t *testing.T) {
	b, err := os.ReadFile("schema/record.json")
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil || s["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema: %v", err)
	}
}

// The store seals pending records in commit order (C5); the stored bytes then
// verify as a chain, and sealing is deterministic.
func TestSealBuildsAVerifiableChain(t *testing.T) {
	prev, stored := GenesisPrevHash, [][]byte{}
	for i, r := range sliceRecords() {
		r.Contract, r.NodeID, r.Time = ContractID, "site-a-node-1", baseTime()
		pending, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Seal(pending, uint64(i+1), prev)
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		again, _ := Seal(pending, uint64(i+1), prev)
		if !bytes.Equal(b, again) {
			t.Fatalf("record %d: sealing is not deterministic", i)
		}
		stored, prev = append(stored, b), Hash(b)
	}
	if err := VerifyChain("site-a-node-1", stored, nil, nil); err != nil {
		t.Fatal(err)
	}
	base := `"contract":"otsec.audit/0.1","node_id":"site-a-node-1","time":{"utc":"2026-10-24T11:00:00Z","resolution_ns":1000000000,"clock":{"sync":"synchronized","source":"ntp"}},"actor":{"type":"system","id":"collector"},"action":"service.start","outcome":"info"`
	if _, err := ValidatePending([]byte("{" + base + "}")); err != nil {
		t.Fatalf("valid pending record rejected: %v", err)
	}
	for name, raw := range map[string]string{
		"seq set":       `{` + base + `,"seq":7}`,
		"prev_hash set": `{` + base + `,"prev_hash":"` + GenesisPrevHash + `"}`,
		"unknown field": `{` + base + `,"note":"x"}`,
		"secret field":  `{` + base + `,"password":"x"}`,
		"duplicate key": `{` + base + `,"outcome":"info"}`,
		"trailing data": `{` + base + `}]`,
		"invalid":       `{` + strings.Replace(base, `"info"`, `"maybe"`, 1) + `}`,
	} {
		if _, err := Seal([]byte(raw), 2, Hash(nil)); !errors.Is(err, ErrRecordRejected) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// A chain-start record sealed anywhere but seq 1 does not verify.
	start := `{` + strings.Replace(base, `"service.start"`, `"audit.chain.start"`, 1) + `}`
	if _, err := Seal([]byte(start), 5, strings.Repeat("ab", 32)); err == nil {
		t.Error("audit.chain.start sealed at seq 5")
	}
}

func TestVerifyCollectorSeq(t *testing.T) {
	var recs []*Record
	for _, b := range chain(t, sliceRecords()) {
		r, err := ParseRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r)
	}
	var last uint64
	for _, r := range recs {
		last = max(last, r.CollectorSeq)
	}
	if err := VerifyCollectorSeq(recs, 0, last); err != nil {
		t.Fatal(err)
	}
	// The node leaves out the credential.use record.
	var without []*Record
	for _, r := range recs {
		if r.Action != ActionCredentialUse {
			without = append(without, r)
		}
	}
	if err := VerifyCollectorSeq(without, 0, last); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("suppressed credential.use: got %v", err)
	}
	// The collector's latest reply is ahead of the records: the tail is missing.
	if err := VerifyCollectorSeq(recs, 0, last+1); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("missing tail: got %v", err)
	}
	// One collector event recorded twice.
	dup := append(append([]*Record{}, recs...), recs[len(recs)-1])
	if err := VerifyCollectorSeq(dup, 0, last); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("duplicate: got %v", err)
	}
}

// TestSchemaPatterns keeps the schema's shared identifier patterns equal to
// the ones the code enforces (C8-A4-1, C8-A4-2).
func TestSchemaPatterns(t *testing.T) {
	b, err := os.ReadFile("schema/record.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			NodeID struct{ Pattern string } `json:"node_id"`
			Target struct {
				Properties struct {
					AssetID struct{ Pattern string } `json:"asset_id"`
				}
			}
		}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Properties.NodeID.Pattern, nodeIDPattern.String(); got != want {
		t.Errorf("schema node_id pattern %q, code %q", got, want)
	}
	// The record checks a target asset ID with C1's asset.ValidAssetID;
	// the schema's copy must agree with it.
	schemaAsset := regexp.MustCompile(s.Properties.Target.Properties.AssetID.Pattern)
	for _, id := range []string{
		"2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", // valid, version 4
		"2b7d4e10-8c3f-8a5b-9e21-7c4f0d6a8b13", // version 8
		"2B7D4E10-8C3F-4A5B-9E21-7C4F0D6A8B13", // upper case
		"2b7d4e10-8c3f-0a5b-9e21-7c4f0d6a8b13", // version 0
		"2b7d4e10-8c3f-9a5b-9e21-7c4f0d6a8b13", // version 9
		"2b7d4e10-8c3f-4a5b-cе21-7c4f0d6a8b13", // a non-ASCII letter
		"2b7d4e10-8c3f-4a5b-c021-7c4f0d6a8b13", // variant c
		"2b7d4e108c3f4a5b9e217c4f0d6a8b13",     // no hyphens
		"{2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13}",
		"2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13\n",
		"",
	} {
		if schemaAsset.MatchString(id) != asset.ValidAssetID(id) {
			t.Errorf("asset id %q: schema %v, C1 %v", id, schemaAsset.MatchString(id), asset.ValidAssetID(id))
		}
	}
}

// TestVerifyChainBindsNode: the verifier names the node; it is never taken
// from the records (C8-A6-1).
func TestVerifyChainBindsNode(t *testing.T) {
	recs := chain(t, sliceRecords())
	if err := VerifyChain("site-b-node-1", recs, nil, nil); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("chain of another node: %v", err)
	}
	noNode := &Checkpoint{Seq: 2, Hash: Hash(recs[1])}
	if err := VerifyChain("site-a-node-1", recs[2:], noNode, nil); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("checkpoint without a node: %v", err)
	}
	if err := VerifyChain("", recs, nil, nil); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("no expected node: %v", err)
	}
}

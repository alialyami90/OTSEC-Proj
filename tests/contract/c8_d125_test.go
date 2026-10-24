package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/audit"
)

// D1-25 (A1): device.session.close carries transcript_sha256, the C2
// transcript digest. GT-HAND from D1-25 and the C8 prose; independent of
// A3's testdata.

const d125Head = `{"contract":"%s","node_id":"site-a6-node-1","time":{"utc":"2026-10-24T12:00:03.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},"actor":{"type":"schedule","id":"sch-a6"},"action":%q,"outcome":"succeeded","target":{"asset_id":"0b6c2f4e-1d3a-4c5b-8e7f-9a0b1c2d3e4f","transport":"telnet","downstream_security":"plaintext-unauthenticated","credential_ref":"cred_a6a6a6a6","credential_version":1,"family":"sel-751"},"operation_id":"sel.ser.read_all","register_revision":1,"correlation_id":"6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30","collector_seq":1%s}`

func d125Digest() string {
	s := sha256.Sum256([]byte("a6 transcript"))
	return hex.EncodeToString(s[:])
}

func d125(contract, action, extra string) []byte {
	return []byte(fmt.Sprintf(d125Head, contract, action, extra))
}

// asStored adds the fields Seal adds, without Seal's checks, so that
// ParseRecord sees the record as a reader would.
func asStored(b []byte) []byte {
	return []byte(`{"seq":2,"prev_hash":"` + strings.Repeat("1", 64) + `",` + string(b[1:]))
}

func sealOne(t *testing.T, pending []byte) ([]byte, []byte, error) {
	t.Helper()
	start, err := audit.Seal([]byte(`{"contract":"otsec.audit/0.1","node_id":"site-a6-node-1","time":{"utc":"2026-10-24T11:00:00.000001Z","resolution_ns":1000,"clock":{"sync":"synchronized","source":"ntp"}},"actor":{"type":"system","id":"node"},"action":"audit.chain.start","outcome":"info"}`), 1, audit.GenesisPrevHash)
	if err != nil {
		t.Fatalf("chain start: %v", err)
	}
	sealed, err := audit.Seal(pending, 2, audit.Hash(start))
	return start, sealed, err
}

func TestD125TranscriptDigest(t *testing.T) {
	dg := d125Digest()
	ok := d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q`, dg))
	if _, err := audit.ValidatePending(ok); err != nil {
		t.Fatalf("control: %v", err)
	}
	start, sealed, err := sealOne(t, ok)
	if err != nil {
		t.Fatalf("control seal: %v", err)
	}
	rec, err := audit.ParseRecord(sealed)
	if err != nil || rec.TranscriptSHA256 != dg {
		t.Fatalf("control parse: %v %+v", err, rec)
	}

	refused := map[string][]byte{
		"close without digest":        d125("otsec.audit/0.1", "device.session.close", ""),
		"close with empty digest":     d125("otsec.audit/0.1", "device.session.close", `,"transcript_sha256":""`),
		"upper-case hex":              d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q`, strings.ToUpper(dg))),
		"sha256: prefix":              d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":"sha256:%s"`, dg)),
		"63 digits":                   d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q`, dg[:63])),
		"65 digits":                   d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q`, dg+"0")),
		"digest as number":            d125("otsec.audit/0.1", "device.session.close", `,"transcript_sha256":1`),
		"digest on device.op":         d125("otsec.audit/0.1", "device.op", fmt.Sprintf(`,"bytes_sent_digest":"sha256:%s","transcript_sha256":%q`, dg, dg)),
		"digest on session open":      d125("otsec.audit/0.1", "device.session.open", fmt.Sprintf(`,"transcript_sha256":%q`, dg)),
		"digest on credential.use":    d125("otsec.audit/0.1", "credential.use", fmt.Sprintf(`,"transcript_sha256":%q`, dg)),
		"mis-cased key":               d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"Transcript_SHA256":%q`, dg)),
		"duplicate key":               d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q,"transcript_sha256":%q`, dg, dg)),
		"duplicate key, case":         d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q,"TRANSCRIPT_SHA256":%q`, dg, dg)),
		"transcript key":              d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q,"transcript":"x"`, dg)),
		"transcript_data key":         d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q,"transcript_data":"x"`, dg)),
		"transcript_sha256x key":      d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q,"transcript_sha256x":"x"`, dg)),
		"TranscriptText nested, 0.2":  d125("otsec.audit/0.2", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q,"ext":{"TranscriptText":"x"}`, dg)),
		"escaped key spelling":        d125("otsec.audit/0.1", "device.session.close", fmt.Sprintf(`,"transcript_sha256":%q,"transcript_raw":"x"`, dg)),
		"later minor close no digest": d125("otsec.audit/0.2", "device.session.close", ""),
		"later minor digest on op":    d125("otsec.audit/0.2", "device.op", fmt.Sprintf(`,"bytes_sent_digest":"sha256:%s","transcript_sha256":%q`, dg, dg)),
	}
	for name, b := range refused {
		if _, err := audit.ValidatePending(b); err == nil {
			t.Errorf("%s: ValidatePending accepted", name)
		}
		if _, err := audit.ParseRecord(asStored(b)); err == nil {
			t.Errorf("%s: ParseRecord accepted", name)
		}
	}

	// The chain covers the digest.
	forged := []byte(strings.Replace(string(sealed), dg, strings.Repeat("0", 64), 1))
	head := &audit.Checkpoint{NodeID: "site-a6-node-1", Seq: 2, Hash: audit.Hash(sealed)}
	if err := audit.VerifyChain("site-a6-node-1", [][]byte{start, sealed}, nil, head); err != nil {
		t.Fatalf("control chain: %v", err)
	}
	if err := audit.VerifyChain("site-a6-node-1", [][]byte{start, forged}, nil, head); err == nil {
		t.Error("forged digest verified against its own head")
	}
}

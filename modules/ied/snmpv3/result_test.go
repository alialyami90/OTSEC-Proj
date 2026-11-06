package snmpv3

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
)

func invocation(fid string) adapter.Invocation {
	exp := []adapter.Expected{{Name: c1.AttrSNMPEngineID, Value: hex.EncodeToString(testEngine)}}
	if fid != "" {
		exp = append(exp, adapter.Expected{Name: c1.AttrFirmwareID, Value: fid})
	}
	return adapter.Invocation{Schema: adapter.Contract, InvocationID: "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30",
		RequestedAt: "2026-11-06T00:00:00Z", PrincipalRef: "scheduler:site-a-node1",
		AssetID: "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13", EndpointID: "mgmt-snmpv3", ProfileID: "sel-27x1-rstp",
		OperationID: runID, CredentialRef: "cred_lab2731usm", Expected: exp,
		Limits: adapter.Limits{ConnectTimeoutMS: 5000, StepTimeoutMS: 10000, DeadlineMS: 120000,
			MaxResponseBytes: 262144, ConnectRetries: 1, MinIntervalMS: 60000}}
}

// built runs a, builds the result, and checks it as the node would: decoded
// from its JSON (Validate), then against the register (CheckSNMP).
func built(t *testing.T, a *agent, inv adapter.Invocation) adapter.Result {
	t.Helper()
	p := identityPackage(t, nil)
	o := session(a).Run(p, runID)
	r := Result(o, inv, p, Meta{Adapter: adapter.AdapterRef{ID: "sel-27x1-snmpv3", Version: "0.1.0-test"},
		Target: c1.Simulated, Started: time.Now().Add(-time.Second)})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := adapter.DecodeResult(b)
	if err != nil {
		t.Fatalf("%s: %v", o.Code, err)
	}
	if err := got.CheckSNMP(p, inv); err != nil {
		t.Fatalf("%s: CheckSNMP: %v", o.Code, err)
	}
	return got
}

func names(r adapter.Result) map[string]string {
	out := map[string]string{}
	for _, o := range r.Observations {
		out[o.Name] = o.Value
	}
	return out
}

func codeOf(r adapter.Result) adapter.Code {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

// Every way the test agent ends a run gives a result the contract accepts,
// with the code, the identity and the observations it should have.
func TestResults(t *testing.T) {
	fidRev := "1.3.6.1.2.1.47.1.1.1.1.10.1"
	cases := []struct {
		name     string
		agent    func(a *agent)
		fid      string // the declared FID
		code     adapter.Code
		identity adapter.IdentityResult
		fidObs   bool
	}{
		{"ok", nil, testFID, "", adapter.IdentityMatch, true},
		{"ok, no FID declared", nil, "", "", adapter.IdentityMatch, true},
		{"another FID", func(a *agent) { a.mib[fidRev] = str("SEL-2731M-R101-V0-Z003001-D20260101") }, testFID,
			adapter.FailedIdentityMismatchLate, adapter.IdentityMismatch, false},
		{"no FID", func(a *agent) { delete(a.mib, fidRev) }, testFID, adapter.FailedSNMPFIDUnreadable, adapter.IdentityMatch, false},
		{"two FIDs", func(a *agent) { a.mib["1.3.6.1.2.1.47.1.1.1.1.10.2"] = str("SEL-2731M-R101-V0-Z003001-D20260101") },
			testFID, adapter.FailedSNMPFIDUnreadable, adapter.IdentityMatch, false},
		{"another engine", func(a *agent) { a.engineID = mustHex("80007c4f03020000273102") }, testFID,
			adapter.RefusedEngineIDMismatch, adapter.IdentityMismatch, false},
		{"error status", func(a *agent) { a.errorStatus = 16 }, testFID, adapter.FailedSNMPErrorStatus, adapter.IdentityMatch, false},
		{"walk loops", func(a *agent) { a.loopWalk = true }, testFID, adapter.FailedSNMPWalkNotIncreasing, adapter.IdentityMatch, false},
		{"silence", func(a *agent) { a.noAnswer = true }, testFID, adapter.FailedTimeout, adapter.IdentityNotChecked, false},
		{"unauthenticated time-window Report", func(a *agent) { a.unauthTimeRep = true }, testFID,
			adapter.FailedUSMNotInTimeWindow, adapter.IdentityMatch, false},
		{"wrong digest Report", func(a *agent) {
			a.before = func(m *message, id int64) [][]byte {
				if m.Flags&flagAuth == 0 {
					return nil
				}
				return [][]byte{a.report(id, 0, oidWrongDigests, false)}
			}
		}, testFID, adapter.FailedUSMWrongDigest, adapter.IdentityMatch, false},
		{"unexpected Report at discovery", func(a *agent) {
			a.before = func(m *message, id int64) [][]byte {
				if m.Flags&flagAuth != 0 {
					return nil
				}
				return [][]byte{a.report(id, 0, oidNotInTimeWindows, false)}
			}
		}, testFID, adapter.FailedSNMPUnexpectedReport, adapter.IdentityNotChecked, false},
		{"ScopedPDU unreadable", func(a *agent) {
			a.before = func(m *message, id int64) [][]byte {
				if m.Flags&flagAuth == 0 || len(a.sent) < 3 {
					return nil
				}
				return [][]byte{a.protect(id, []byte{0x30, 0x10, 0x04, 0x00}, true)}
			}
		}, testFID, adapter.FailedSNMPScopedPDUUnreadable, adapter.IdentityMatch, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := newAgent(t)
			if c.agent != nil {
				c.agent(a)
			}
			r := built(t, a, invocation(c.fid))
			if codeOf(r) != c.code || r.Identity.Result != c.identity {
				t.Fatalf("%s %v, identity %s", codeOf(r), r.Error, r.Identity.Result)
			}
			got := names(r)
			_, has := got[c1.AttrFirmwareID]
			if has != c.fidObs {
				t.Errorf("FID observation %v, want %v: %v", has, c.fidObs, got)
			}
			if c.fidObs && (got[c1.AttrModel] != "SEL-2731M" || got[c1.AttrFirmwareVersion] != "R102-V1") {
				t.Errorf("model and version: %v", got)
			}
			if r.SuspendsCredential() != "" {
				t.Error("an SNMP result suspends the credential")
			}
		})
	}
}

// A walk that ended early never reports a FID it did not compare.
func TestNoUncomparedFID(t *testing.T) {
	a := newAgent(t)
	a.loopWalk = true
	r := built(t, a, invocation(testFID))
	if _, ok := names(r)[c1.AttrFirmwareID]; ok {
		t.Fatal("a FID was reported from a run that did not finish")
	}
}

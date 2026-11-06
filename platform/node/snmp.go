package node

import (
	"context"

	"otsec.local/otsec/contracts/asset"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/modules/security/collectorclient"
)

// snmpEntry reports whether schedule entry col reads over SNMPv3: its
// endpoint's transport is snmpv3 (the note, section 5). Such an entry is
// the asset module's, so it loads only with asset on. The collector checks
// the operation against the register and enforces its limits; the node
// only names it, and runs it at most once per every_seconds, never sooner
// than MinIntervalSeconds after the asset's last session.
func (c *Config) snmpEntry(col Collection) bool {
	a, ok := c.Asset(col.AssetID)
	if !ok {
		return false
	}
	ep, ok := endpoint(a, col.Endpoint)
	return ok && ep.Transport == asset.SNMPv3
}

// commitSNMP commits an SNMP poll's run: one collection.run health event
// that keeps the run's transcript, as a configuration read that failed does.
// An SNMP result has no SER rows for the normalizer. Its identity is stored
// after it, as every run's is (storeIdentity).
func (s *Scheduler) commitSNMP(ctx context.Context, rep Report, col Collection, o *collectorclient.Outcome) Report {
	if o.Result.Error != nil {
		rep.Detail = o.Result.Error.Detail
	}
	tr := o.Result.Transcript
	rec, err := s.runRecord(HealthStream, HealthCollectionRun, col, rep.RequestID, o.InvocationID, map[string]string{
		"status": string(o.Result.Status), "events": "0"})
	if err == nil && len(tr.Data) > 0 {
		rec.Capture = &c5.Capture{SHA256: tr.SHA256, Bytes: tr.Data}
	}
	return s.storeRun(ctx, rep, col, rec, err)
}

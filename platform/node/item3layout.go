package node

import (
	"fmt"

	c5 "otsec.local/otsec/contracts/store"
)

// AdvisoryStream is the node-level stream of installed advisory sets (C5
// 0.8 section 4). It is in the configuration database, of class
// configuration, and exists only with applicability on.
const AdvisoryStream c5.StreamID = "advisory"

// The item 3 record bounds (C5 0.8 section 1).
const (
	// MaxIdentityRecordBytes bounds an identity record, document and
	// capture together.
	MaxIdentityRecordBytes int64 = 64 << 10
	// MaxIdentityReadBytes bounds a latest-read record.
	MaxIdentityReadBytes int64 = 4 << 10
)

// The item 3 floor terms (C5 0.8 section 5), added to the configuration
// quota floor.
const (
	// IdentityFloorBytes is for each asset with asset on: the newest
	// identity record and one change, and two identity.read records.
	IdentityFloorBytes = 2*MaxIdentityRecordBytes + 2*MaxIdentityReadBytes
	// FindingsFloorBytes is for each asset with applicability on: a fixed
	// allowance, because the number of findings depends on the set.
	FindingsFloorBytes = ConfigRecordBytes
	// AdvisorySetsFloorBytes is once per node with applicability on: the set
	// in use and the one being installed, each at most one record.
	AdvisorySetsFloorBytes = 2 * ConfigRecordBytes
)

// configModuleFloor is the configuration module's own floor: the D4-20 term
// for each asset whose configuration is read, and the event-baseline terms.
// The item 3 ceiling leaves it free.
func (c *Config) configModuleFloor() int64 {
	return int64(c.ConfigAssets())*ConfigQuotaFloorRecords*ConfigRecordBytes + c.EventBaselineQuotaFloor()
}

// item3Floor is the floor 0.8 adds: the identity term for each asset with
// asset on, and with applicability on the findings term for each asset and
// the sets term once.
func (c *Config) item3Floor() int64 {
	var f int64
	n := int64(len(c.assets))
	if c.AssetOn() {
		f += n * IdentityFloorBytes
	}
	if c.ApplicabilityOn() {
		f += n*FindingsFloorBytes + AdvisorySetsFloorBytes
	}
	return f
}

// item3FloorTerms names each item 3 term and the count behind it, for the
// load error (as B3 asked on #319 for the other terms).
func (c *Config) item3FloorTerms() string {
	n := len(c.assets)
	s := fmt.Sprintf("item 3 needs %d bytes: %d bytes of identity records for each of %d assets (asset)", c.item3Floor(), IdentityFloorBytes, n)
	if c.ApplicabilityOn() {
		s += fmt.Sprintf(", %d bytes of findings for each of %d assets and %d bytes for two advisory sets (applicability)", FindingsFloorBytes, n, AdvisorySetsFloorBytes)
	}
	return s
}

// Item3Ceiling is the most the configuration class may hold after an item 3
// write (C5 0.8 section 5, C1 on #444): the quota less the configuration
// module's own floor terms, so identity records, latest reads, findings and
// sets can never take the room configuration monitoring needs. It is 0 when
// the configuration class has no quota.
func (c *Config) Item3Ceiling() int64 {
	q, ok := c.Store.Quotas[string(c5.ClassConfiguration)]
	if !ok {
		return 0
	}
	return q - c.configModuleFloor()
}

package collector

import "otsec.local/otsec/modules/ied/sel751"

// The collector's side of the seam agreed with A2 (modules/ied/sel751).
var (
	_ sel751.FloorGate = (*FloorGate)(nil)
	_ sel751.Secret    = (*SecretHandle)(nil)
)

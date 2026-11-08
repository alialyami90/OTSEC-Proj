package sensorlink

import (
	"net/netip"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/node"
)

// Resolver names the asset behind an address (C13 section 5 and section 14
// item 9). It counts, among the assets enrolled on this node, the inbound
// endpoints and the outbound endpoints whose CheckPath passes. Every host is
// compared after Unmap().WithZone(""), as the sensor sees it. An address two
// assets share is ambiguous and names neither. A resolution is a label for
// detection and for the C4 event's source.asset, never identity evidence.
type Resolver struct {
	byAddr map[netip.Addr]string // the asset ID, or "" when ambiguous
}

// NewResolver indexes the endpoints of the assets enrolled on nodeID.
func NewResolver(nodeID node.ID, assets []asset.Asset) *Resolver {
	r := &Resolver{byAddr: map[netip.Addr]string{}}
	for _, a := range assets {
		if a.NodeID != nodeID {
			continue
		}
		for _, ep := range a.Endpoints {
			if !ep.Transport.Inbound() && ep.CheckPath() != nil {
				continue // a port server, no path, or a later transport
			}
			addr, err := netip.ParseAddr(ep.Host)
			if err != nil {
				continue // C1 holds IP literals; a serial line has none
			}
			addr = addr.Unmap().WithZone("")
			if id, ok := r.byAddr[addr]; ok && id != a.AssetID {
				r.byAddr[addr] = ""
				continue
			}
			r.byAddr[addr] = a.AssetID
		}
	}
	return r
}

// Resolve returns the asset at addr: its ID and true; "" and true when two
// assets share it; "" and false when none has it.
func (r *Resolver) Resolve(addr netip.Addr) (id string, known bool) {
	id, known = r.byAddr[addr.Unmap().WithZone("")]
	return id, known
}

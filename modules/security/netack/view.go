package netack

import (
	"net/netip"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/netobs"
	"otsec.local/otsec/contracts/node"
)

// InboundOnly returns the asset ends of b's pairs that are named only
// through an inbound (Syslog sender) address, which the acknowledgement
// view must mark (C13 §14 item 9, baseline note §2.3, D4-70). The baseline
// does not record how an end resolved, so this derives it from b's
// addresses and the node's current C1 records, as the resolver counts
// them: an asset end is marked unless one of its addresses in b is the
// host of one of its outbound endpoints whose CheckPath passes. An asset
// end with no address in b is marked too, since nothing shows the node
// connects to it.
//
// Such an end is a label from a sender's address, which anyone on the
// segment can spoof, so a pair learned from it must not look like one the
// node connects to.
func InboundOnly(b *netobs.Baseline, nodeID node.ID, assets []asset.Asset) map[string]bool {
	direct := map[string]map[netip.Addr]bool{}
	for _, a := range assets {
		if a.NodeID != nodeID {
			continue
		}
		for _, ep := range a.Endpoints {
			if ep.Transport.Inbound() || ep.CheckPath() != nil {
				continue
			}
			addr, err := netip.ParseAddr(ep.Host)
			if err != nil {
				continue
			}
			if direct[a.AssetID] == nil {
				direct[a.AssetID] = map[netip.Addr]bool{}
			}
			direct[a.AssetID][addr.Unmap().WithZone("")] = true
		}
	}
	connected := map[string]bool{}
	for _, ad := range b.Addresses {
		addr, err := netip.ParseAddr(ad.IP)
		if err == nil && direct[ad.Endpoint][addr.Unmap().WithZone("")] {
			connected[ad.Endpoint] = true
		}
	}
	marked := map[string]bool{}
	for _, p := range b.Pairs {
		for _, end := range []string{p.Client, p.Server} {
			if netobs.ValidUUID(end) && !connected[end] {
				marked[end] = true
			}
		}
	}
	return marked
}

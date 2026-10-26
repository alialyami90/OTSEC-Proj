package receive

import (
	"fmt"
	"net/netip"

	"otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/modules/telemetry/normalize"
)

// Source is what the node knows about one sender address on a listener.
type Source struct {
	AssetID string
	// Target is the asset endpoint's admin-set target. An event is
	// device-observed only when this and the listener's target both are.
	Target  asset.EvidenceClass
	Dialect normalize.Dialect
}

// Senders maps a sender's IP address, as the listener sees it, to its
// asset. An address not in the map is an unknown sender.
type Senders map[netip.Addr]Source

// SendersFor builds a listener's sender table from the node's C1 assets:
// every endpoint with the listener's transport whose port is unset or the
// listener's port (C1-A4-2). The endpoint host must be an IP literal: a
// name would make attribution depend on name resolution. Two assets
// claiming one address is an error (C1 CheckSenders), and so is a host
// that is not an address.
func SendersFor(assets []asset.Asset, t asset.Transport, port int) (Senders, error) {
	if !t.Inbound() {
		return nil, fmt.Errorf("receive: %s is not a Syslog transport", t)
	}
	if err := asset.CheckSenders(assets); err != nil {
		return nil, err
	}
	s := Senders{}
	for _, a := range assets {
		for _, ep := range a.Endpoints {
			if ep.Transport != t || (ep.Port != 0 && ep.Port != port) {
				continue
			}
			addr, err := netip.ParseAddr(ep.Host)
			if err != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("receive: asset %s endpoint %s: host %q is not an IP address", a.AssetID, ep.ID, ep.Host)
			}
			addr = addr.Unmap()
			if prev, ok := s[addr]; ok && prev.AssetID != a.AssetID {
				return nil, fmt.Errorf("receive: %s sender %s belongs to both %s and %s", t, addr, prev.AssetID, a.AssetID)
			}
			s[addr] = Source{AssetID: a.AssetID, Target: ep.Target, Dialect: DialectOf(a)}
		}
	}
	return s, nil
}

// DialectOf is the Syslog dialect of an asset, from its operator-declared
// product family. A family without a dialect of its own uses the RFC
// parser.
func DialectOf(a asset.Asset) normalize.Dialect {
	if v, ok := a.Declared(asset.AttrProductFamily); ok && v == "sel-rtac" {
		return normalize.DialectRTAC
	}
	return normalize.DialectRFC
}

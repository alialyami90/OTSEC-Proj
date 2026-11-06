package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/advisory"
	"otsec.local/otsec/contracts/advisory/advisorytest"
	c5 "otsec.local/otsec/contracts/store"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// advKey is a fresh advisory key: not a published test key, so a release
// build accepts it as an anchor.
type advKey struct {
	priv ed25519.PrivateKey
	id   string
}

func newAdvKey(t *testing.T) advKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return advKey{priv: priv, id: advisory.KeyID(pub)}
}

func (k advKey) anchor(status string) nodeconfigtest.AdvisoryAnchor {
	pub := k.priv.Public().(ed25519.PublicKey)
	return nodeconfigtest.AdvisoryAnchor{KeyID: k.id, PublicKey: base64.StdEncoding.EncodeToString(pub), Status: status}
}

// item3Quota is the configuration quota at the item 3 floor for a node with
// one asset, both switches on and no configuration read.
const item3Quota = IdentityFloorBytes + FindingsFloorBytes + AdvisorySetsFloorBytes

// item3Config is schedConfig's node, with its admin_dir, the configuration
// quota at item3Quota and mod applied, as bytes and as ParseConfig takes
// them. nc is the builder, for the admin_dir helpers.
func item3Config(t *testing.T, mod func(*nodeconfigtest.Config)) ([]byte, error) {
	b, _, _, err := item3Node(t, mod)
	return b, err
}

func item3Node(t *testing.T, mod func(*nodeconfigtest.Config)) ([]byte, string, *nodeconfigtest.Config, error) {
	t.Helper()
	dir := t.TempDir()
	storeDir := filepath.Join(dir, "store")
	if err := store.CreateDir(storeDir, ""); err != nil {
		t.Fatal(err)
	}
	nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL751(relayID, "", 2323, 300)
	if err := nc.WriteInstallKey(testInstallKey); err != nil {
		t.Fatal(err)
	}
	nc.Store.Quotas["configuration"] = item3Quota
	nc.AdminDir = nc.TLSDir
	if mod != nil {
		mod(nc)
	}
	b := nc.Bytes()
	_, err := ParseConfig(b)
	return b, dir, nc, err
}

// The four combinations of D4-50: both off, asset alone and both on load;
// applicability alone is refused at load, with the reason.
func TestItem3Switches(t *testing.T) {
	k := newAdvKey(t)
	on := &nodeconfigtest.Applicability{Anchors: []nodeconfigtest.AdvisoryAnchor{k.anchor("active")}}
	for _, tc := range []struct {
		name          string
		asset, applic bool
		refused       string
	}{
		{name: "both off"},
		{name: "asset alone", asset: true},
		{name: "both on", asset: true, applic: true},
		{name: "applicability alone", applic: true, refused: "applicability is set without asset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := item3Config(t, func(nc *nodeconfigtest.Config) {
				if tc.asset {
					nc.Asset = &struct{}{}
				}
				if tc.applic {
					nc.Applicability = on
				}
			})
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refused) || !strings.Contains(err.Error(), "D4-50") {
					t.Fatalf("loaded, or refused for another reason: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c, _ := ParseConfig(b)
			if c.AssetOn() != tc.asset || c.ApplicabilityOn() != tc.applic {
				t.Fatalf("asset %v applicability %v", c.AssetOn(), c.ApplicabilityOn())
			}
			l, err := c.Layout()
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := l.StreamClasses()[AdvisoryStream]; ok != tc.applic {
				t.Fatalf("advisory stream present %v with applicability %v", ok, tc.applic)
			}
		})
	}
}

func TestItem3ConfigRefused(t *testing.T) {
	k := newAdvKey(t)
	good := []nodeconfigtest.AdvisoryAnchor{k.anchor("active")}
	for _, tc := range []struct {
		name string
		mod  func(*nodeconfigtest.Config)
		want string
	}{
		{"no admin_dir", func(nc *nodeconfigtest.Config) { nc.AdminDir = "" }, "applicability needs admin_dir"},
		{"no anchors", func(nc *nodeconfigtest.Config) { nc.Applicability.Anchors = nil }, "anchors is empty"},
		{"bad key", func(nc *nodeconfigtest.Config) { nc.Applicability.Anchors[0].PublicKey = "AAAA" }, "not 32 bytes"},
		{"wrong key ID", func(nc *nodeconfigtest.Config) { nc.Applicability.Anchors[0].KeyID = "ed25519-0000000000000000" }, "is not its key's ID"},
		{"status", func(nc *nodeconfigtest.Config) { nc.Applicability.Anchors[0].Status = "retired" }, "status"},
		{"quota below the item 3 floor", func(nc *nodeconfigtest.Config) { nc.Store.Quotas["configuration"] = item3Quota - 1 },
			"below the floor with item 3"},
		{"no quota", func(nc *nodeconfigtest.Config) { delete(nc.Store.Quotas, "configuration") }, "item 3 needs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := item3Config(t, func(nc *nodeconfigtest.Config) {
				nc.Asset = &struct{}{}
				nc.Applicability = &nodeconfigtest.Applicability{Anchors: append([]nodeconfigtest.AdvisoryAnchor{}, good...)}
				tc.mod(nc)
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	// A published test key is an anchor only in a test build (C11 1.6).
	_, err := item3Config(t, func(nc *nodeconfigtest.Config) {
		nc.Asset = &struct{}{}
		pub := advisorytest.Key(0).Public().(ed25519.PublicKey)
		nc.Applicability = &nodeconfigtest.Applicability{Anchors: []nodeconfigtest.AdvisoryAnchor{{KeyID: advisory.KeyID(pub),
			PublicKey: base64.StdEncoding.EncodeToString(pub), Status: "active"}}}
	})
	if advisoryTestBuild != (err == nil) {
		t.Fatalf("test key as an anchor in a test build %v: %v", advisoryTestBuild, err)
	}
}

// The floor terms (C5 0.8 section 5): the identity term per asset with asset
// on, and with applicability the findings term per asset and the sets term
// once. The ceiling is the quota less the configuration module's own terms,
// so item 3 terms are not subtracted.
func TestItem3FloorAndCeiling(t *testing.T) {
	if IdentityFloorBytes != 136<<10 || FindingsFloorBytes != 1536<<10 || AdvisorySetsFloorBytes != 3<<20 {
		t.Fatalf("terms %d %d %d, want 136 KiB, 1.5 MiB, 3 MiB", IdentityFloorBytes, FindingsFloorBytes, AdvisorySetsFloorBytes)
	}
	k := newAdvKey(t)
	b, err := item3Config(t, func(nc *nodeconfigtest.Config) {
		nc.Asset = &struct{}{}
		// The class's own minimum, one record, is above the identity term.
		nc.Store.Quotas["configuration"] = ConfigRecordBytes
	})
	if err != nil {
		t.Fatalf("asset alone at its floor: %v", err)
	}
	c, _ := ParseConfig(b)
	if c.item3Floor() != IdentityFloorBytes || c.Item3Ceiling() != ConfigRecordBytes {
		t.Fatalf("asset alone: floor %d ceiling %d", c.item3Floor(), c.Item3Ceiling())
	}
	b, err = item3Config(t, func(nc *nodeconfigtest.Config) {
		nc.Asset = &struct{}{}
		nc.Applicability = &nodeconfigtest.Applicability{Anchors: []nodeconfigtest.AdvisoryAnchor{k.anchor("active")}}
		nc.AddEventBaseline(relayID)
		nc.Store.Quotas["configuration"] = 64 << 20
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ = ParseConfig(b)
	if c.item3Floor() != item3Quota {
		t.Fatalf("floor %d, want %d", c.item3Floor(), item3Quota)
	}
	if want := int64(64<<20) - c.EventBaselineQuotaFloor(); c.Item3Ceiling() != want || c.EventBaselineQuotaFloor() == 0 {
		t.Fatalf("ceiling %d, want the quota less the event-baseline terms, %d", c.Item3Ceiling(), want)
	}
	// The quota must hold the configuration module's floor and item 3's.
	_, err = item3Config(t, func(nc *nodeconfigtest.Config) {
		nc.Asset = &struct{}{}
		nc.Applicability = &nodeconfigtest.Applicability{Anchors: []nodeconfigtest.AdvisoryAnchor{k.anchor("active")}}
		nc.AddEventBaseline(relayID)
		nc.Store.Quotas["configuration"] = c.EventBaselineQuotaFloor() + item3Quota - 1
	})
	if err == nil || !strings.Contains(err.Error(), "below the floor with item 3") {
		t.Fatalf("quota one byte below both floors: %v", err)
	}
}

// Each item 3 series goes only on its own stream (C5 0.8 section 1, C6 on
// #450): the contract cannot see the stream, so the node's one writer
// refuses the others.
func TestItem3StreamRule(t *testing.T) {
	for _, tc := range []struct {
		stream c5.StreamID
		series string
		ok     bool
	}{
		{AdvisoryStream, c5.SeriesAdvisorySet, true},
		{ConfigStream(relayID), c5.SeriesAdvisorySet, false},
		{ConfigStream(relayID), c5.SeriesIdentity, true},
		{ConfigStream(relayID), c5.SeriesIdentityRead, true},
		{ConfigStream(relayID), c5.SeriesFinding, true},
		{AdvisoryStream, c5.SeriesIdentity, false},
		{AdvisoryStream, c5.SeriesIdentityRead, false},
		{AdvisoryStream, c5.SeriesFinding, false},
		{ConfigStream(relayID), c5.SeriesConfigSnapshot, false},
		{AdvisoryStream, c5.SeriesBaselineEvent, false},
	} {
		if got := item3StreamOK(tc.stream, tc.series); got != tc.ok {
			t.Errorf("%s on %s: %v, want %v", tc.series, tc.stream, got, tc.ok)
		}
	}
}

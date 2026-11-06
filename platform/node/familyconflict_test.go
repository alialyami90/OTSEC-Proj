package node

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"otsec.local/otsec/contracts/adapter"
	c1 "otsec.local/otsec/contracts/asset"
	"otsec.local/otsec/contracts/event"
	"otsec.local/otsec/modules/security/collectorclient"
	"otsec.local/otsec/platform/node/nodeconfigtest"
	"otsec.local/otsec/platform/store"
)

// A declared product_family whose models exclude the device-read model is
// an identity conflict (§1.5 of docs/phase4/C2-c1-0.3-c3-0.4.md, D4-53;
// GT-MIB case F6). The run is ok and the read model is kept; status shows
// the conflict on the asset's identity, the identity-family-conflict alarm
// is raised once per family and model, and one identity.family-conflict health event is
// committed; neither names the model, which is device text. A family that
// covers the read model shows none.
func TestIdentityFamilyConflict(t *testing.T) {
	for _, tc := range []struct {
		family, conflict string
	}{
		{"sel-2731", ""},
		{"sel-2741", "SEL-2731M"},
	} {
		t.Run(tc.family, func(t *testing.T) {
			id := "5d2e8f14-7a3b-4c69-b0e1-9f4a6c2d8e75"
			dir := t.TempDir()
			storeDir := filepath.Join(dir, "store")
			if err := store.CreateDir(storeDir, ""); err != nil {
				t.Fatal(err)
			}
			nc := nodeconfigtest.New("site-a-node1", storeDir).AddSEL2731M(id, "", 1161, 60)
			nc.Store.Quotas["configuration"] = 8 << 20
			for _, at := range nc.Assets[0]["attributes"].([]any) {
				if at := at.(map[string]any); at["name"] == c1.AttrProductFamily {
					at["value"] = tc.family
					at["observations"].([]any)[0].(map[string]any)["value"] = tc.family
				}
			}
			if err := nc.WriteInstallKey(testInstallKey); err != nil {
				t.Fatal(err)
			}
			c, err := ParseConfig(nc.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			r, st, _ := start(t, c, dir)
			defer r.Close()
			res, err := adapter.DecodeResult(readFile(t, "../../contracts/adapter/testdata/snmp/results/valid/ok.json"))
			if err != nil {
				t.Fatal(err)
			}
			rb, _ := json.Marshal(res)
			s := newScheduler(t, r, answering(&collectorclient.Outcome{InvocationID: res.InvocationID, Result: res, ResultJSON: rb}))
			for range 2 {
				if rep := s.RunOnce(bg, 0); rep.Outcome != "ok" || rep.Alarm != "" {
					t.Fatalf("%+v", rep)
				}
			}

			is := st.Snapshot("x").Identity[id]
			if m, ok := is.attribute(c1.AttrModel); !ok || m != "SEL-2731M" {
				t.Fatalf("the read model is not kept: %+v", is.Attributes)
			}
			if is.FamilyConflict != tc.conflict {
				t.Fatalf("status family_conflict %q, want %q", is.FamilyConflict, tc.conflict)
			}
			var alarms []string
			for _, a := range st.Snapshot("x").Alarms {
				if a.Code == AlarmIdentityFamilyConflict {
					alarms = append(alarms, a.Detail)
				}
			}
			hs, _ := r.Store(HealthStream).Read(bg, HealthStream, 0, 1000)
			var events []map[string]string
			for _, rec := range hs {
				if e, _ := event.Decode(rec.Event); e.Health != nil && e.Health.Type == HealthIdentityFamilyConflict {
					events = append(events, e.Health.Details)
				}
			}
			if tc.conflict == "" {
				if len(alarms) != 0 || len(events) != 0 {
					t.Fatalf("no conflict, and alarms %q, health events %v", alarms, events)
				}
				return
			}
			if len(alarms) != 1 || !strings.Contains(alarms[0], tc.family) || strings.Contains(alarms[0], tc.conflict) {
				t.Fatalf("alarms %q, want one naming %s", alarms, tc.family)
			}
			if len(events) != 1 || events[0]["asset_id"] != id || events[0]["product_family"] != tc.family || events[0]["evidence_id"] != res.InvocationID {
				t.Fatalf("health events %v", events)
			}

			// A model that alternates between runs raises each model once,
			// not once per run (D3 on #499), so it cannot crowd other
			// alarms out of status.
			ist := s.identityOf(bg, id)
			read := *ist.doc
			for _, model := range []string{"SEL-751", "SEL-2731M", "SEL-751", "SEL-2731M"} {
				d := read
				d.Asset.Attributes = slices.Clone(read.Asset.Attributes)
				for i, at := range d.Asset.Attributes {
					if at.Name == c1.AttrModel {
						at.Observations = slices.Clone(at.Observations)
						for j := range at.Observations {
							if at.Observations[j].EffectiveKind() == c1.DeviceRead {
								at.Observations[j].Value = model
							}
						}
						d.Asset.Attributes[i] = at
					}
				}
				ist.doc = &d
				s.familyConflict(bg, id, ist)
			}
			n := 0
			for _, a := range st.Snapshot("x").Alarms {
				if a.Code == AlarmIdentityFamilyConflict {
					n++
				}
			}
			if n != 2 {
				t.Fatalf("%d family conflict alarms after SEL-751 and SEL-2731M alternated, want 2 (one per model)", n)
			}
		})
	}
}

// attribute is the status attribute's value.
func (is IdentityStatus) attribute(name string) (string, bool) {
	for _, at := range is.Attributes {
		if at.Name == name {
			return at.Value, true
		}
	}
	return "", false
}

# C5 note: a register revision per family on the node

C5, 2026-11-06, for C1's item 3 scheduling after C3 on #463. C1 approved it on #464, keyed by profile ID, subject to C3's trust review. It changes the node configuration (`otsec.nodeconfig/0.1`), additively. C3 reviews the trust boundary, C6 adds a mixed-node case, and C1 approves. Evidence class: desk.

## The problem

The node sends one config-wide `register_version` in every run request (`runRequest`). The collector checks it against the package that the asset's profile names by `firmware.allowlist` (`registerFor`, #461). The SEL-751 package is at revision 3 or 4, and `sel-27x1-rstp` is at 1. So a node that schedules both a SEL-751 entry and an SNMP entry has one of them refused as `register_version` on every run. A real site node runs both.

## What the node can know

The collector chooses the package from the profile's `firmware.allowlist`. The node does not hold profiles. It holds only each asset's profile reference (`asset.profile.id`), which it already uses for C9's configuration rules (`ConfigRules`). So the node cannot name a family by allowlist unless it is told which one each profile uses.

## Proposal

The node configuration gains one optional section:

```json
"register_versions": { "sel-751-ascii": 4, "sel-27x1-rstp": 1 }
```

- **Key:** a profile ID, as the asset's `profile.id` names it. **Value:** the revision of the register package that profile's allowlist selects, at least 1.
- **The run's revision.** A schedule entry's run request names the revision for its asset's profile. An asset with no profile, or whose profile is not listed, uses the existing `register_version`. A configuration without the section is therefore exactly today's one-family case, and `register_version` stays required.
- **Load checks.** A key must be a profile that some scheduled asset names. Otherwise the load fails, so a typo cannot silently fall back to `register_version`. Each value must be at least 1.
- **The register copy (D4-40).** Today the copy's revision must equal `register_version`. Under this proposal it must equal the revision of every profile whose assets have a scheduled configuration read. If those profiles name different revisions, the load fails, because the node holds one copy.
- **Audit and health.** No new field. The `collector.request` audit record already carries the run's `register_revision`, taken from the request, so it shows the per-family revision as it is. `collectorclient`'s result check compares the result's `register_version` with the request's, and is unchanged.

## Why keyed by profile, not by family name

A key of family (allowlist) name would need the node to map each profile to its allowlist, which is collector knowledge. Keying by profile gives the node one exact rule from data it already holds. The collector still decides the package and refuses a wrong revision (`register_version`), so a wrong entry fails closed and is visible in the run's refusal, never a run against another package.

The one cost: two profiles that share an allowlist each name the revision, and they could disagree. The collector refuses the wrong one.

## Not in it

- No change to the collector, to C7, or to the register contract.
- The node keeps one register copy. Configuration reads stay SEL-751 only.

## Tests (C5, then C6)

- A mixed node, with one SEL-751 entry and one SNMP entry: each run request carries its own revision.
- Each refusal at load: a key no scheduled asset names, a value of 0, and a register copy whose revision is not that of the configuration-reading profiles.
- A configuration without the section is unchanged, byte for byte, in its requests.
- C6 adds the mixed-node case on the binaries. It needs no GT-MIB agent: an SNMP run that times out still shows its revision was not refused (C1 on #464).

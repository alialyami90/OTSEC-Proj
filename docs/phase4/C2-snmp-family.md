# The first SNMPv3 family (C2, P4-3-A2)

C2, 2026-11-05. This is the family note of P4-3-A2 (`docs/agent-handoffs.md`, "Phase 4 item 3: Stage A briefs"). C6's GT-MIB plan depends on it.

**Evidence class.** `desk`. Every statement here is from the SEL manuals in `reference/manuals-SEL/` (read through `pdftotext -layout`), and page numbers are the manuals' own. No device was contacted, no MIB was read, and nothing here is `hardware-verified`.

**Sources.** The source IDs are those in `docs/phase0/A2-sel-portfolio.md`:

- S43 is the SEL-2730M Instruction Manual, 20260408.
- S29 is the Rapid Spanning Tree Protocol user's guide for the SEL managed switches, 20260424.
- S27 and S28 are the SEL-2731 and SEL-2741 manuals.
- S26 is the SEL-2488 manual.

## Recommendation: the SEL-2731 and SEL-2741 in RSTP mode, not the SEL-2730M

The brief names the SEL-2730M "unless C2's evidence says otherwise". The evidence favours the SEL-2731 and SEL-2741 in RSTP mode, which this note treats as one family. Both run the same firmware line under one guide, S29. C1 chose it (D4-51): RSTP mode only, with the SEL-2730M second if the sites run it.

| Question | SEL-2730M (S43) | SEL-2731 and SEL-2741, RSTP mode (S29) |
| --- | --- | --- |
| SNMP versions | v1, v2c and v3, read-only (p. 80) | v2c and v3, and traps (p. 42). No v1. |
| Can the device be set below authPriv? | **Yes.** Authentication may be None, MD5 or SHA-1, and encryption None, DES or AES-128 (Table 5.14, p. 84). DES was removed in firmware R110-V0 (p. 108), but the table still lists it. | **No.** "Does not support none for the SNMPv3 profile: you must select a cryptographic algorithm", and no DES (p. 43). |
| Authentication algorithms | MD5, SHA-1. The default is SHA-1 (p. 84). | MD5, SHA-1, SHA-256, SHA-512. The default is SHA-1 (Table 4.13, p. 45). |
| Privacy algorithms | DES (do not use), AES-128. The default is AES-128 (p. 84). | AES-128, AES-256. The default is AES-128 (p. 45). |
| Which OIDs the agent serves | Not in the manual. The MIBs are on the device's "MIB Downloads" page (p. 86). The manual names only IF-MIB `ifTable` (Appendix J, p. 153) and, in the firmware history, Entity, UCD and Bridge MIB support (pp. 109 to 110). | **Listed** (pp. 46 to 47). All are standard MIBs except one SEL power-supply MIB. See "What the agent serves" below. |
| Where the FID is | "The SNMP Entity MIB" (p. 155) | "The SNMP Entity MIB" (p. 75) |
| SNMP on the device | UDP 161, "SNMP read-only", disabled by default (p. 156) | UDP 161, "SNMP read-only", disabled by default (p. 76) |
| Mode in the FID | n/a | The letter after the product number: `M` is RSTP, `S` is OT SDN, `U` is unmanaged (S29 pp. 7 to 8; S27 p. 23) |

These are the reasons for the recommendation:

1. **The device enforces authPriv.** R1.8 and V-M1 (c) require authPriv only. On the SEL-2731 and SEL-2741 the device cannot be set below it, so a misconfigured device profile cannot drop to noAuthNoPriv. On the SEL-2730M the platform alone holds that line.
2. **Stronger algorithms are available.** The family offers SHA-256 or SHA-512 authentication with AES-128 privacy. The SEL-2730M's best is SHA-1 with AES-128.
3. **GT-MIB can be built from the manual.** S29 lists every OID the agent serves, so a simulator can serve exactly that set and answer `noSuchObject` to the rest. For the SEL-2730M the served set is unknown beyond the few OIDs the manual names.
4. **The FID says the mode.** `SEL-2731M-…` is RSTP and `SEL-2731S-…` is OT SDN, whose SNMP is configured through the SEL-5056 (S30 p. 7). So the identity read itself shows whether the device is in the mode this family covers.

What counts against it:

- **The firmware line is young.** R100 dates from 2023 for the SEL-2731 and R101 from 2025 for the SEL-2741 (S29 p. 62). The SEL-2730M's line runs from 2012 to 2026 (S43 pp. 107 to 112), and it is probably more widely installed. Which switches the owner's sites have is `[open]`. If they are SEL-2730Ms, that may outweigh the points above, and the choice can be revisited without a contract change.
- **AES-256 for USM has no RFC.** Two key-extension variants are in use, and which one the device implements is not stated. The platform should offer AES-128 only (RFC 3826) until hardware shows the variant.

## Identity over SNMPv3: SEL-2731 and SEL-2741, RSTP mode

| Attribute | Where | OID | Evidence |
| --- | --- | --- | --- |
| FID, which also gives vendor, model, control plane, firmware R and V numbers, hardware Z number and build date | `entPhysicalTable` | 1.3.6.1.2.1.47.1.1.1, column and row `unknown` | The FID is in the Entity MIB (p. 75), and the table is served (p. 46). The FID format is on pp. 7 to 8. Which column holds it (for example firmware or software revision, or description) and which row (the chassis) is not stated. |
| Description, contact, name, location | SNMPv2-MIB system group | `sysDescr` .1.3.6.1.2.1.1.1, `sysContact` .4, `sysName` .5, `sysLocation` .6 | Served (p. 46). Their content is not stated. `sysContact`, `sysName` and `sysLocation` are operator-set, so they are weak identity. |
| Vendor object | `sysObjectID` | .1.3.6.1.2.1.1.2 | Served (p. 46). Its value is `unknown`. |
| Engine ID, which holds the MAC | SNMP-FRAMEWORK-MIB `snmpEngineID` | .1.3.6.1.6.3.10.2.1.1 | Served (p. 47). Its format is 11 bytes: `80 00 7C 4F 03` and then the unit's MAC (p. 42). The same value comes back in the USM discovery report before any authenticated request (RFC 3414). It is the one attribute available before the USM keys are used. |
| Part number, serial number | Device Information in the dashboard | not stated | The dashboard shows them (pp. 7 to 8). Whether the Entity MIB serves them is `unknown`. |

Reading the FID once gives vendor, model and firmware, as `ID` does on the SEL-751. The FID has the same form there (R, V, Z and D parts), so C4's matcher can read the firmware version of both families with one rule.

**The FID has to be found by its form, not by its column.** No manual names the column. So the read walks the whole `entPhysicalTable` (bounded, see C3 0.4) and records every row. The adapter takes as FID the one value that matches the family's FID grammar (`SEL-27[34]1M-R\d{3}-V\d+-Z\d{6}-D\d{8}`), and records which OID it came from. If no value matches, or more than one distinct value matches, there is no FID. That is a parse failure, with the bytes kept and no attribute. It is never a guess. The row count changes with firmware: R102-V1 "resolved an issue where the Entity MIB would show extra identifiers" (p. 62).

**Does the engine ID survive a firmware upgrade?** Not stated. Both manuals define the engine ID from the unit's MAC alone (S29 p. 42, S43 p. 80), and neither the upgrade procedure (S29 Appendix B, pp. 65 to 66) nor anything else gives it a firmware or settings term. So it should survive an upgrade and a factory-default reset, and change only with the unit's hardware. That is `inferred` from the format, not documented. A factory-default reset restores factory-default settings (S29 p. 14), in which SNMP is disabled (p. 42). So the USM user must be provisioned again; that the profiles are among the settings it clears is also `inferred`. Keys bound to a pinned engine ID would then still verify. The hardware item should check both.

### What the agent serves (S29 pp. 46 to 47)

The served MIBs are SNMPv2-MIB (system group), ENTITY-MIB (`entPhysicalTable`), UCD-SNMP-MIB (memory and disk), IF-MIB (`ifTable`, `ifXTable` counters), LLDP-MIB (local port and remote tables), BRIDGE-MIB, Q-BRIDGE-MIB, RSTP-MIB, SNMP-FRAMEWORK-MIB (engine), and one SEL MIB, SEL-2700-POWER-SUPPLY-MIB, under 1.3.6.1.4.1.31823.1.2700.2.1.1.1. Traps use SYSLOG-MSG-MIB (p. 48), and the platform does not receive SNMP traps. For identity, only the system group, `entPhysicalTable` and `snmpEngineID` are needed.

### USM settings the platform uses

- Only authPriv. Authentication is SHA-256 or SHA-512 (RFC 7860). Privacy is AES-128 (RFC 3826). Never MD5, SHA-1, DES or AES-256, and never v2c without the owner's approval for that device (R1.8, V-M1 (d)).
- **The user's profile on the device needs Read only, and no Trap** (Table 4.13 has both, and both default to enabled). The platform cannot see from outside how a profile is set, so this is a commissioning instruction, not something the platform checks.
- The device answers only hosts on its Permitted Hosts list, when that list is set (S43 p. 81 for the SEL-2730M; S29 Table 3.1, p. 15). A node that is not listed gets no answer. Health reports that as a timeout, not as an identity result.

## The SEL MIB text and GT-MIB

- **The project has no SEL MIB file.** Both manuals say the MIBs are downloaded from SEL: S29 p. 46 says from the product page, and S43 p. 86 says from the device. Neither prints the MIB text.
- **Identity needs no SEL MIB.** Its OIDs are all in standard MIBs: SNMPv2-MIB (RFC 3418), ENTITY-MIB (RFC 6933) and SNMP-FRAMEWORK-MIB (RFC 3411). Their text is public. **It was not among the project's reference files when this was written, and this container could not fetch it** (the proxy refused the RFC Editor, 2026-11-05). To build GT-MIB from MIB text rather than from memory, those three modules need to be added to the reference files by the owner or by a session with network access. The SEL power-supply MIB is needed only for health, which is not in item 3.
- **What GT-MIB cannot show from documents.** It cannot show which `entPhysicalTable` column and row hold the FID, what `sysDescr` and `sysObjectID` contain, or how many rows the table has. A simulator built now has to invent these and label them SYNTHESIZED, as V-M2's SHO replies were. So V-M1 (e) would show that the client reads and attributes exactly what the agent served. It would not show that the client finds the FID where a real switch puts it. Reading it by its form, as above, is what keeps that assumption from mattering, and a hardware item (V-M1's new H item) closes it.
- **For the SEL-2730M, if C1 keeps it.** Its served set is unknown beyond `ifTable`, `entPhysicalTable` and the history's MIB list. GT-MIB could serve the same standard identity OIDs, but which other OIDs exist would be invented. The FID point above applies the same way.

## The alternatives not chosen

- **SEL-2488 (S26).** SNMPv3 `GET`, `GETNEXT` and `WALK` (p. 18.6; Table 19.1 p. 19.3). Its MIBs come from the device (p. 19.6), and the OIDs that carry model and firmware are `unknown`. Its FID is not stated to be in any MIB. A clock is also a poorer first device: its time outputs feed relays' SER timestamps (C-05 in `docs/verification.md`).
- **SEL-2731 and SEL-2741 in OT SDN mode (S30).** SNMP is v2c or v3, and v3 is configured through the SEL-5056 (S30 p. 7), which was not read (S31). The FID's `S` letter excludes it from this family.

## Changes to `docs/device-capabilities.md`

The SEL-2730M and SEL-2731/2741 identity rows gain the USM levels and algorithms, the OID list and the FID's mode letter, with the citations above. No classification changes: both stay `documented-untested`.

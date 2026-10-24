# Node posture labels

Owner: A5. A2 carries these into C1 (`otsec.asset`), because a platform node is also an asset. Reviewers: A6 (V-S20, C-24), A3 (HR-9). Status: draft, 2026-10-24. Brief: P1-A5.

A node reports two posture labels about itself:

- **storage durability**, which says whether acknowledged commits are known to survive a power cut on this hardware;
- **OS support**, which says whether the operating system still receives security updates.

Neither label changes what the node does. Both appear in node status, in the asset view, in every health report from the node, and in the audit log whenever they change. An unsupported OS also raises a standing condition.

## 1. Storage durability (C-24)

| Label | When |
| --- | --- |
| `storage durability verified` | An H-11 pass is on record for this node's system model and every drive model that holds the store, and none of the disqualifying settings below is present. |
| `storage durability unverified` | Anything else, including a model never tested, a record that cannot be read, and an unreadable hardware identity. |

What the node reports, read at startup and every 24 hours *(proposed)*:

- System manufacturer and model (SMBIOS, `Win32_ComputerSystem`).
- For each physical drive under the store's volume: model, firmware revision, bus type, and whether the volume is mirrored (`Win32_DiskDrive`, `MSFT_PhysicalDisk`).
- The drive's write-cache policy. Windows can be set to "turn off Windows write-cache buffer flushing on the device". With that set, `FlushFileBuffers` no longer reaches the disk, and the A6 E-02 and H-14 flush evidence no longer applies. If the setting is present, or cannot be read, the label is `unverified` whatever the H-11 record says. `[inferred]`: the registry or API source has to be confirmed on the site image as part of H-14.

Rules:

- **The H-11 record is shipped, not configured.** It is a signed list of tested pairs (system model and drive model, with drive firmware recorded) in the release package, like the command register (C-A2-2). An operator cannot mark hardware as verified.
- **Flush latency never sets this label.** A drive that acknowledges flushes from a volatile cache looks fast exactly when commits are not durable (A6, F-011 note).
- **A changed drive model changes the label.** For example, a replaced SSD makes the label `unverified` until that model has an H-11 record.
- **Firmware is recorded but not part of the match.** *(proposed)* This is so that a routine firmware update does not flip every node to `unverified`. A6 may ask for firmware to be part of the key if H-11 shows firmware-dependent results.

## 2. OS support (V-S20)

| Label | When |
| --- | --- |
| `OS supported` | The edition and version are in the lifecycle table and the clock is before their end instant. |
| `OS out of support` | The edition and version are in the table and the clock is at or after their end instant. |
| `OS support unknown` | The edition or version is not in the table or cannot be read. It is warned, and never treated as supported. |

**Inputs.** The node reads `EditionID`, `DisplayVersion` and `CurrentBuild` from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.

- The edition is decided by `EditionID`, never by build number. Windows 10 Enterprise LTSC 2021 and Windows 10 IoT Enterprise LTSC 2021 both report build 19044 and end eight years apart.
- Windows 11 Pro is decided by `DisplayVersion`, because Pro is supported per feature version.

**Lifecycle table.** Sources and fetch dates are in [A5-platform-feasibility.md §15](../phase0/A5-platform-feasibility.md). The `EditionID` values are `[inferred]` from Microsoft's naming and have to be confirmed against the real site image (H-14).

| Edition | `EditionID` | Version key | End instant (PT, as Microsoft lists it) | End (UTC) | Source |
| --- | --- | --- | --- | --- | --- |
| Windows 10 Pro | `Professional` | 22H2 (build 19045) | 2025-10-15 06:59:59 | 2025-10-15T13:59:59Z | product page |
| Windows 10 Enterprise LTSC 2019 | `EnterpriseS` | build 17763 | 2029-01-10 06:59:59 | 2029-01-10T14:59:59Z | product page |
| Windows 10 IoT Enterprise LTSC 2019 | `IoTEnterpriseS` | build 17763 | nominal January 9, 2029 | 2029-01-10T14:59:59Z, derived | summary page only |
| Windows 10 Enterprise LTSC 2021 | `EnterpriseS` | build 19044 | 2027-01-13 06:59:59 | 2027-01-13T14:59:59Z | product page |
| Windows 10 IoT Enterprise LTSC 2021 | `IoTEnterpriseS` | build 19044 | 2032-01-14 06:59:59 | 2032-01-14T14:59:59Z | product page |
| Windows 11 Enterprise LTSC 2024 | `EnterpriseS` | build 26100 | nominal October 9, 2029 | 2029-10-10T13:59:59Z, derived | summary page only |
| Windows 11 IoT Enterprise LTSC 2024 | `IoTEnterpriseS` | build 26100 | 2034-10-11 06:59:59 | 2034-10-11T13:59:59Z | product page |
| Windows 11 Pro | `Professional` | `DisplayVersion` 24H2 | 2026-10-14 06:59:59 | 2026-10-14T13:59:59Z | product page |
| Windows 11 Pro | `Professional` | `DisplayVersion` 25H2 | 2027-10-13 06:59:59 | 2027-10-13T13:59:59Z | product page |
| Windows 11 Pro | `Professional` | `DisplayVersion` 26H1 | 2028-03-15 06:59:59 | 2028-03-15T13:59:59Z | product page |
| Windows 11 Pro | `Professional` | `DisplayVersion` 26H2 | 2028-10-10 06:59:59 | 2028-10-10T13:59:59Z | product page |

The product pages already give the last instant as 06:59:59 PT on the day after the nominal date. That instant is converted with the offset in force on that date: PST (UTC−8) gives 14:59:59Z, and PDT (UTC−7) gives 13:59:59Z. US daylight time starts on 2028-03-12, so the 26H1 instant is in PDT.

The two summary-page rows keep the nominal date as their source. Their UTC instant is derived with the same rule and is marked `derived`. A6's V-S20 fixture marks them the same way.

**Evaluation.** The label is evaluated at startup, every 24 hours *(proposed)*, and on a system clock change. A node therefore changes label when the instant passes, without a reinstall. Inside 180 days *(proposed)* of the end instant, the label stays `OS supported` and node status adds "support ends <date>".

**Installer.** In every case the installer warns and completes. It never refuses (owner decision, ADR-0007 item 9).

## 3. Standing condition and migration date for an unsupported OS

This follows the A3 proposal, which A1 accepted for this brief (HR-9; handoff log, "A3 (e3b8e4e, 09783c7, PR #1)").

- **The standing condition.** A node labelled `OS out of support` or `OS support unknown` raises the standing condition `node-os-unsupported`.
  - It is a state, not a recurring alert. It is raised once when the label is set, shown continuously in node status and the asset view, and cleared when the label returns to `OS supported`.
  - Raising it and clearing it are both audited.
  - Severity is low.
- **Collection is unaffected.** The node keeps collecting and forwarding. The hardening requirements of ADR-0007 item 9 still apply.
- **The migration date.** An operator records a migration date for the node, which is the date by which it will run a supported edition. Recording or changing it is an audited administrative action, with the operator's identity under C7 and C8.
  - If no migration date is recorded, the condition says "no migration date recorded".
  - Once the recorded date has passed, the severity rises to medium *(proposed)* and the condition says "migration date passed". Collection is still unaffected.
- **Commissioning.** The OS end-of-support date is recorded at commissioning (A3, HR-9), so it is visible before the node first reports.

## 4. One collecting node per asset (A1 D1-3)

- Each asset is collected by exactly one node in 0.x, as C1 records. A second node's request to collect an assigned asset is refused (A6 adds the negative test).
- Moving collection to another node is an explicit operator action, recorded in the audit log (C8). There is no automatic collector failover before Phase 4.
- Other nodes may still receive the asset's Syslog. Only collection is exclusive.
- Why: two nodes polling one relay double its session load (V-S13), and would produce two event streams for the same SER rows.

## 5. Shape proposed for C1 (A2 decides)

```json
"posture": {
  "storage_durability": {
    "label": "unverified",
    "system_model": "SEL SEL-3355-2",
    "drives": [{"model": "…", "firmware": "…", "bus": "SATA", "write_cache_flush_disabled": false}],
    "h11_record": null
  },
  "os_support": {
    "label": "out-of-support",
    "edition_id": "Professional",
    "display_version": "24H2",
    "build": "26100",
    "end_of_support": "2026-10-14T13:59:59Z",
    "end_source": "product-page",
    "evaluated_at": "2026-10-24T12:00:00Z"
  },
  "condition": {"code": "node-os-unsupported", "severity": "low", "migration_date": null}
}
```

All label values form closed enums. A reader that meets one it does not know treats it as `unverified` or `OS support unknown`, never as supported or verified. The `system_model` value above shows the field's shape only. It is not a reading from a device.

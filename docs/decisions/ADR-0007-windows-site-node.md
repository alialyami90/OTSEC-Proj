# ADR-0007: Windows site node on SEL-3355-2

- Status: proposed (owner fact accepted; technical consequences need A5 experiments and A3/A6 review)
- Date: 2026-10-23
- Deciders: project owner (site hardware and OS), A1 (consequences); owner of the follow-up work: A5, reviewers A3 and A6
- Related: ADR-0002, ADR-0003, ADR-0004, ADR-0005; R8

## Context

ADR-0002 to ADR-0004 assumed a Linux site node (systemd supervision, linux/amd64 and linux/arm64 builds, durability evidence gathered with strace on Linux). On 2026-10-23 the owner stated that sites use the SEL-3355-2 computer with Windows 10 Pro or Windows 11 Pro IoT LTSC. A5 had already proposed the SEL-3355-2 (TPM 2.0, mirrored SSD; Intel AMT on ETH1 must be disabled or isolated; RTC drift about 200 ppm, ~17 s/day, without a time source). SEL's SSD-lifetime application note is not available (owner).

## Decision

1. The site node runs on an SEL-3355-2 under the owner's Windows build. **Assumption:** the platform gets a dedicated SEL-3355-2 and does not share a host with the zenon HMI or historian; co-hosting would need its own decision, because a fault in either would affect the other.
2. `windows/amd64` becomes the primary build target (ADR-0003 item amended); linux targets stay for the central node and for CI.
3. Supervision uses the Windows Service Control Manager with restart-on-failure and backoff, replacing systemd (ADR-0002 item 5); SCM restart delays do not enforce device session limits, so the collector keeps a durable session record and does not reconnect to a device before its `TIDLE` has elapsed after an unclean exit (A5 §14).
4. The privileged collector process (ADR-0002) runs as a separate Windows service under its own virtual service account; only that account can read the credential store. Credentials at rest are protected with a key scoped to the collector's service SID (not machine-scope DPAPI), using user-scope DPAPI under that account or a TPM-backed CNG key whose ACL names only the collector SID (machine-scope DPAPI is readable by any local process); an administrator or SYSTEM compromise of the node remains a recorded residual risk (A3 AP-1, threat model §4.2, a10550b).
5. Durability evidence from Linux does not transfer. A5 repeats E-A5-1, A6 E-02 (acknowledged commits unsynced under NORMAL vs FULL) and E-03/E-04 (full-disk recovery) on Windows/NTFS before ADR-0004 is relied on for Windows. Until then ADR-0004's durability claims are `inferred` for Windows. A5 adds E-A5-6 (write amplification) and experiments W-1 to W-4 (A5 §14); A6 owns H-14 (flush check with Process Monitor). Group commit is required: about 10.6 KB written per event committed singly versus about 1 KB per event at 100-event groups (A5 estimate).
6. Time: the node takes time from the site time source (SEL-2488 or IRIG via the owner's clocks); without one, the ~17 s/day drift makes local timestamps unusable for correlation, so loss of time sync raises an alarm. Proposed threshold (A5): offset above 1 s or no successful sync within 1 h, NTP from the SEL-2488.
7. Device sessions originate only at site nodes. The owner stated (2026-10-23) that the customer's central HMI server may reach relays while central cybersecurity servers may not; the platform's central role is a cybersecurity server and never connects to devices. The HMI server's relay traffic is an existing authorized path that the IDS models, not a platform path.
8. Intel AMT on the SEL-3355-2 is disabled or kept off every routable network (deployment precondition, A5 §12).

9. Node hardening (A3 HR-9): service-SID firewall rules so only the collector service reaches the IED-facing NIC; WDAC or AppLocker application control; BitLocker with TPM; no domain join; Windows IoT Enterprise LTSC preferred. *Owner decision 2026-10-23:* plain Windows 10 Pro is also allowed as an owner-accepted risk; such a node is labelled "OS out of support" on the node, in the asset view, and in reports, and the installer warns rather than refuses.

## Consequences

- BitLocker uses a TPM-only protector so patch reboots need no PIN; the owner holds recovery keys for firmware-triggered recovery (A5).
- WDAC requires Authenticode-signed platform binaries and a policy update before each upgrade; the release process must sign and ship policy with the binaries (A5).
- Without a domain, local accounts on each node are managed by the site's own process; the platform does not manage them (A5).

- Windows 10 Pro (non-LTSC) left Microsoft support in October 2025; Windows 10/11 IoT Enterprise LTSC editions have longer support. Deployment guidance should prefer an LTSC edition; the owner's OS patch process becomes a dependency for the node's own security.
- Windows host events from the site node itself are collected by host push like any other Windows host (ADR-0006).
- File locking, path, and fsync semantics differ on Windows; the store and reserve-file logic need Windows tests.
- No SSD endurance data: WAL and pruning design must keep write amplification low and the node reports SSD wear (SMART) where readable; A5 to estimate writes per day from the event-rate assumptions.

## Verification

A6 adds Windows runs of the durability and recovery tests and a service-isolation test (the main service account cannot read the credential store). Results are `simulated` on a Windows VM until run on SEL-3355-2 hardware.

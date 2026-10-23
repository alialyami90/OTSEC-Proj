# Threat Model

Owner: A3. Reviewed by A6. Status: **not started.** This skeleton defines what the threat model must contain. No analysis has been performed yet.

## Scope and assumptions

To be written. Must state the deployment topologies in scope (single-server, central plus collectors, distributed site-local), the network zones the platform touches, and any assumption about the trustworthiness of upstream systems.

## Assets to protect

Protection priority, highest first:

1. Protection and control functions of IEDs and controllers. The platform must never degrade them (P1, R8 constraint).
2. IED configurations and settings (integrity and confidentiality).
3. Engineering and monitoring credentials held by the platform.
4. Audit records and collected evidence (integrity and availability).
5. Collected telemetry (integrity, availability).
6. Platform control plane (enrollment, policy, upgrades).

## Trust boundaries

To be drawn. Minimum set to consider:

- User or operator to platform (upstream authentication).
- Platform to IED (downstream, including insecure legacy transports).
- Monitoring plane to engineering/privileged plane.
- Site-local node to central management server (WAN).
- Platform to upstream Syslog/SIEM.
- Platform to network sensors (passive taps, SPAN).
- Administrator to platform (policy and credential management).

## Actors

To be enumerated. At minimum: external attacker on enterprise/WAN; insider with monitoring privileges; insider with engineering privileges; compromised site node; compromised upstream collector; malicious or compromised IED; supply chain of platform dependencies.

## Attack paths through the platform (Q7)

Architecture-critical question Q7 asks whether the platform itself creates a new attack path into OT assets. Each candidate path must be listed with its mitigation and the test that demonstrates the mitigation. Candidate paths to analyse:

- Stored IED credentials exfiltrated or reused.
- Engineering access proxy abused to reach devices outside the authorised session.
- Adapter command framework abused to run non-approved commands.
- Compromised central server pushing configuration or commands to site nodes.
- Node enrollment spoofing.
- Telemetry channel used for lateral movement.
- Platform update mechanism as a supply-chain vector.

## Required security controls (minimum safe behaviour)

To be derived from the brief. Must cover: upstream authentication and authorization; separation of monitoring, engineering, administration, and security permissions; session audit, expiry, and revocation; fail-closed privileged access; observable telemetry failure; identification of insecure downstream connections; credential handling and rotation.

## Standards mapping

Alignment (not certification) with IEC 62443 (zones, conduits, security levels), IEC 62351 (secure communication for power systems), NIST SP 800-82, and MITRE ATT&CK for ICS techniques. Mapping table to be added once controls are defined.

## Unresolved high-risk concerns

Tracked here until resolved by an ADR or verified mitigation. Security and safety objections cannot be dismissed by majority agreement.

| ID | Concern | Raised by | Status |
| --- | --- | --- | --- |
| (none yet) | | | |

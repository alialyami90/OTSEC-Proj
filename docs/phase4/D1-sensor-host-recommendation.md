# D1: the sensor host, a recommendation to the owner

D4-86 owes the owner one recommendation on the sensor's host under option (b): the hardware, the operating system, and who builds and patches it. D3's note (`docs/phase4/D3-sensor-link.md` §10) lists twelve choices, O-1 to O-12, with what each costs in risk. This file gives D1's recommendation for each, in one place, for the owner to accept, change or refuse.

**Status: a recommendation.** Nothing here is decided, bought or built. The owner decides every row. Evidence class: `desk`, from D3's note, ADR-0009, and the measurements cited. No hardware, TAP, switch or distribution named or described here has been run by this project.

## What the owner is asked first

Three facts about the sites decide several rows. The first two are already owed (`HANDOFF.md`, "Waiting on the owner", item 2); the third is new with this file.

1. **Can each site take a network TAP on the links to be monitored,** or only a switch's mirror (SPAN) port?
2. **Is the station network PRP,** with two LANs?
3. **Where would the sensor sit:** in the node's cabinet, in the network cabinet, or in a relay room, and on what power?

Where a row depends on one of them, it says so. A statement marked "D1's judgment" has no source in the records; it is D1's reading, for the owner to weigh.

Where D1 recommends one of D3's options, the others remain open to the owner as D3's note states them.

## The recommendation, choice by choice

| | Choice | D1 recommends | Why | What it costs |
| --- | --- | --- | --- | --- |
| O-1 | How the sensor attaches | **A TAP of a model shown to be receive-only**, on each monitored link. A mirror port only where a TAP cannot be fitted, and then treated as accepting ingress until an H-row shows otherwise for that switch model. | Against a compromised sensor host, a receive-only TAP is the only measure that holds (D3, O-1; ADR-0009's corrected row). Everything else on the sensor's side is software on a host assumed compromised. "Receive-only" is a property of a TAP model, not of TAPs, so the model is chosen from its maker's documentation and then shown by D6's H-row. | One TAP for each monitored link, and one for each LAN on PRP. The H-row needs a TAP and the owner's authorization to run it. |
| O-2 | Where the sensor's private key rests | **In a TPM.** | A copied disk or image is then not a second sensor (SL-16). Root can use the key and cannot copy it (SL-3, an assumption). | Hardware with a TPM (version 2.0 is D1's judgment of what current hardware carries). |
| O-3 | Disk encryption | **Encrypted, unlocked by the TPM.** | It restarts unattended after a power loss. A disk taken alone is protected; a whole box taken and started is not. Unlock by a person at each start would make every power loss a coverage gap until someone attends (D3, O-3); at an unstaffed site that may be long (D1's judgment). | Protects the disk, not the box; the box's custody is O-4's question. |
| O-4 | Physical custody | **A locked enclosure, in the node's cabinet if question 3 allows,** rather than the network cabinet; contractors only with an escort; a revoked or retired machine's disk wiped or destroyed. | D3 notes that the network cabinet, closest to the mirror port, is opened by more people. The firmware password, a verified start-up chain and unused ports off are SL-24's requirements whatever the cabinet. | Cabling from the sensor's cabinet to the TAPs. Depends on question 3. |
| O-5 | Remote login to the sensor host | **SSH from one named management host, with a key for each person,** on a management interface of its own. No password login, no login from the node or the station LAN (SL-23). The owner's existing remote-management tool is D3's third option, and adds that tool to the same trust. | A host that parses hostile traffic in C and C++ must be patched on time (AP-30). Console only makes every patch a site visit, and patches come late. | The management host and its keys become part of the sensor's trust. |
| O-6 | The network between node and sensor | **A cable of its own between the two machines** for the link. | Nothing else can reach the link agent's listener or sit on the link's path, so SL-11 and SL-12 are not the only walls. | A spare port on each machine. **D3's note pairs a dedicated cable with management by console or media.** D1 recommends a dedicated link cable *and* a separate management interface (O-5). That combination is not in D3's note: D3 reviews it before it reaches the owner as final. |
| O-7 | Who builds and patches the sensor's image | **The project ships a signed image** with the engine, its packages and the base system. | Only then can AP-31 (1)'s pins and AP-10's refusals of a tampered, rolled-back or unsigned package be the project's to build and test (SL-25). If each site installs the system, the pins rest on each site's procedure. | **This changes what the product is:** the project becomes the distributor of everything in the image (D3's O-7, which cites D7 on #618), needs a build and patch line, and needs the release key the owner has not yet placed (TB9; `HANDOFF.md` item 12). No signed release exists today. Either way, the distribution's support period bounds how long the image can be patched (D3, O-7). |
| O-8 | Out-of-band management on the hardware | **Hardware without it,** or with it switched off in firmware and never on a port in use. | A management controller is access below every rule on the host, and one that shares the monitoring port transmits there, which breaks C-11 (SL-27). | Narrows the hardware that fits (D1's judgment). |
| O-9 | Physical or virtual | **Physical.** | On a virtual machine the hypervisor's administrators are root on the sensor, a snapshot is a copy of its key, and C-11 rests on the virtual switch too. | One machine for each site (two on PRP if O-12 says so). |
| O-10 | The sensor's time source | **The site's time server, reached on the management interface only, authenticated where the server supports it.** A clock signal is D3's other option. | A time client on the monitoring interface would transmit there (SL-29). The node's skew alarm is the check whatever the source (SL-17). | None beyond the site's time server. |
| O-11 | The capture ring on the sensor | **No ring** (size zero) by default; a site may turn one on. | A ring is a store of site traffic on a host the platform cannot audit (AP-33). The eight packets an observation cites reach the node's store, where reads are audited. | No packets beyond those eight for an investigation. |
| O-12 | On PRP | **One host with two monitoring ports, each on a receive-only TAP.** If either LAN can only give a mirror port, **two hosts**, one per LAN. D3's third option, one LAN only, needs no discard and leaves traffic on the other LAN unseen. | One host sees both copies, so the PRP discard can run (D4-69; E-D4-03's PRP result, 0 of 45 rows without it). Behind receive-only TAPs it cannot join the two LANs (SL-28). Behind mirror ports that may accept ingress it could, so the LANs get a host each. | Two hosts double the hardware and the patching, and the node then gets each flow twice under two `sensor_id`s, which C13 0.2 must handle. Depends on question 2 above. |

## The machine this describes

From the rows above, not from a product. **No model is named, and none has been tried.**

- 64-bit x86, small and fanless, rated for where it sits (question 3): an industrial or substation rating if it goes in a relay room (D1's judgment).
- TPM 2.0 (O-2, O-3); a firmware password and a verified start-up chain (SL-24).
- No out-of-band management controller, or one that can be switched off and has no shared port (O-8).
- Network ports: one monitoring port (two on PRP), one for the link to the node, one for management. Three or four ports. The monitoring ports are chosen with D4 for capture. The rig test of the egress rule (SL-T21) is run again on the chosen image's kernel, and the NIC and its driver need their H-row (H-18).
- Disk sized for the sensor's buffer during an outage, once C13 0.2 sets that figure.

## The operating system

**A long-term-support Linux distribution whose kernel has the nftables `netdev` egress hook.** D1 briefs D4 and D7 to choose it once the owner answers O-7, with SL-T21 run on that image's own kernel before it is relied on. The one measurement so far ran on one kernel on a veth pair (run 43077596916; D3 §9), so it shows nothing yet for the chosen kernel or NIC. The engine is approved as Zeek 9.0.1 with the project's script (D4-90), tested in a container image pinned by digest (run 43092601088), not on a sensor host.

## What stays unproven, whatever the owner chooses

- That the chosen TAP model is receive-only (D6's H-row; needs the owner's authorization).
- That the egress rule stops every send path on the chosen kernel and NIC (SL-T21 on the image; H-18 for the NIC).
- That the sensor host refuses a tampered, rolled-back or unsigned package (SL-25, SL-T17): no signed release and no updater exist.
- Anything about a real site's traffic: nothing has captured a site network (D4-66).

## What the owner is asked to decide

1. Answer questions 1 to 3 above.
2. Accept, change or refuse each row of the table. O-7 changes what the product is and needs the release key's holder (TB9).
3. Authorize, when the time comes, buying one TAP and one machine for the lab, so that D6's H-rows can run. Nothing is bought before that word.

D1 records the owner's answers in the decision log, and D3's note and ADR-0009 follow them.

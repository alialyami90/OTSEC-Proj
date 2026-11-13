"""GT-PCAP's PRP pairs for the discard stage's comparison (D6, P4-D6-GT2).

D4-87 owes tag, priority and padding pairs for the PRP duplicate check, and
C13 0.2's test P-2 names what the check must do with them
(docs/phase4/D4-c13-0.2-proposal.md, CH-28 and CH-29, a proposal not yet
approved). Under CH-28, two frames are copies of one PRP frame when their
source MAC and RCT sequence number are equal and their RCT LAN IDs differ;
the second is discarded only when the two are equal from the destination
MAC through the RCT, leaving out the whole 802.1Q tag (TPID and TCI),
masking the RCT's LAN ID, and ignoring any octets after the RCT.

This writes one capture of seven pairs, each a frame of the GT network
(M5 to O1 over UDP 20000, plan section 2B) sent twice with one RCT
sequence number, plus the writer's own claim of what the check does with
each, which prp_pairs_label.py checks against tshark and the bytes:

1. identical: the reference pair, as prp.py makes them;
2. tag-vid: VID 10 on LAN A, VID 20 on LAN B;
3. tag-absent: untagged on LAN A, VID 10 on LAN B;
4. priority: VID 10 on both, PCP 4 on LAN A and 0 on LAN B;
5. padding: a short frame, VID 10 on LAN A (62 octets, the RCT last), and
   on LAN B with the tag stripped by a bridge, which pads the 58 octets
   left to 60 after the RCT;
6. one-octet (a control): LAN B's copy has its IPv4 TTL changed from 64 to
   63, one octet, with the header checksum left as sent, as a frame altered
   on one LAN would be. Both are passed, and prp_mismatched counts it;
7. same-lan (a control): the same frame twice on LAN A. Both are passed,
   and nothing is counted.

The controls make a pass mean something: a check that ignored the frame's
content would pass pairs 1 to 5 and fail 6. A wrong-LAN case (CH-29's
`prp_wrong_lan`) needs the interface a frame arrived on, which a classic
pcap does not carry, so it stays with the rig.

Addresses are TEST-NET-1 and MACs locally administered (dnp3_cases.NET).
Nothing here sends a packet. Usage: python prp_pairs.py OUTDIR
"""

import json
import os
import struct
import sys

import dnp3
import dnp3_cases
import pcapfile
import prp
import synth

M5, O1 = dnp3_cases.NET["masters"]["M5"], dnp3_cases.NET["outstation"]
PORT = O1["port"]
START_NS = 1_762_563_600_000_000_000  # after every DNP3 case
SEQ_START = 0x2001  # high nibble 2: no octet pair of an RCT reads as a LAN ID A or B
TTL_AT = 14 + 8  # the IPv4 TTL's offset in an untagged frame


def l3(payload, ident):
    """M5's IPv4 UDP datagram from port 20000 to O1's DNPNUM."""
    return synth.ipv4(M5["ip"], O1["ip"], synth.UDP, synth.udp(M5["ip"], O1["ip"], PORT, PORT, payload), ident)


def poll():
    """M5's integrity poll, as dnp3-udp's first datagram carries it."""
    seg = dnp3.tpdu(0, dnp3.request(0, dnp3.READ, dnp3_cases.INTEGRITY))
    return l3(dnp3.link(O1["link"], M5["link"], True, seg), 1)


def link_status():
    """A link-layer request of link status (function 9, DIR and PRM set):
    a ten-octet datagram, so the frame is short."""
    hdr = b"\x05\x64" + struct.pack("<BBHH", 5, 0xC9, O1["link"], M5["link"])
    return l3(hdr + dnp3.crc(hdr), 2)


def frame(packet, tag=None):
    """The Ethernet frame M5 sends to O1, unpadded, with an 802.1Q tag
    (VID, PCP) or none."""
    t = struct.pack("!HH", synth.ETH_VLAN, (tag[1] << 13) | tag[0]) if tag else b""
    return synth.mac(O1["mac"]) + synth.mac(M5["mac"]) + t + struct.pack("!H", synth.ETH_IPV4) + packet


def copy(data, seq, lan):
    """data with its RCT; refused if under 60 octets, which a sender would
    pad before the RCT (prp.py) and these pairs never need."""
    out = data + prp.rct(seq, lan, data)
    if len(out) < 60:
        raise ValueError(f"{len(out)} octets: a sender pads before the RCT")
    return out


def strip_tag(data):
    """What a bridge that strips the 802.1Q tag makes of a frame: the tag
    gone, and the frame padded with zeros after its last octet to 60."""
    out = data[:12] + data[16:]
    return out + b"\0" * max(0, 60 - len(out))


def pairs():
    """[(name, [(LAN, frame bytes)], claim)]. The claim is the writer's
    statement of CH-28's outcome, which the labeller checks."""
    p = poll()
    discard = lambda note, **c: {"verdict": "second-discarded", "prp_discards": 1, "note": note, **c}  # noqa: E731
    out = []

    def add(name, a, b, claim, lan_b=prp.LAN_B):
        """b is LAN B's frame before its RCT, or a function of LAN A's copy
        and the sequence number that makes LAN B's copy whole."""
        seq = SEQ_START + len(out)
        ca = copy(a, seq, prp.LAN_A)
        cb = b(ca, seq) if callable(b) else copy(b, seq, lan_b)
        out.append((name, [(prp.LAN_A, ca), (lan_b, cb)], claim))

    add("identical", frame(p), frame(p), discard("the reference pair: both copies untagged and equal",
                                                 prp_tag_differs=0, prp_mismatched=0))
    add("tag-vid", frame(p, (10, 0)), frame(p, (20, 0)),
        discard("VID 10 on LAN A, VID 20 on LAN B", prp_tag_differs=1, prp_mismatched=0))
    add("tag-absent", frame(p), frame(p, (10, 0)),
        discard("untagged on LAN A, VID 10 on LAN B", prp_tag_differs=1, prp_mismatched=0))
    add("priority", frame(p, (10, 4)), frame(p, (10, 0)),
        discard("VID 10 on both LANs, PCP 4 on LAN A and 0 on LAN B", prp_tag_differs=1, prp_mismatched=0))
    # LAN B's copy left the sender as LAN A's did, tagged and with its RCT
    # last, and a bridge then stripped the tag.
    add("padding", frame(link_status(), (10, 0)),
        lambda ca, seq: strip_tag(ca[:-6] + prp.rct(seq, prp.LAN_B, ca[:-6])),
        discard("a short frame, VID 10 on LAN A; on LAN B a bridge stripped the tag and padded the 58 octets left "
                "to 60 after the RCT", prp_tag_differs=1, prp_mismatched=0))
    altered = bytearray(frame(p))
    altered[TTL_AT] -= 1
    add("one-octet", frame(p), bytes(altered),
        {"verdict": "both-passed", "prp_discards": 0, "prp_tag_differs": 0, "prp_mismatched": 1,
         "note": "a control: LAN B's copy has its IPv4 TTL 63 for 64, its header checksum as sent"})
    add("same-lan", frame(p), frame(p),
        {"verdict": "both-passed", "prp_discards": 0, "prp_tag_differs": 0, "prp_mismatched": 0,
         "note": "a control: the same frame twice on LAN A, a repeat on one LAN"}, lan_b=prp.LAN_A)
    return out


def frames():
    """The capture: pair k at START_NS + k seconds, its second copy
    prp.SKEW_NS after its first, far inside any prp_window_ms (CH-28)."""
    out = []
    for k, (_, copies, _) in enumerate(pairs()):
        for j, (_, data) in enumerate(copies):
            out.append(pcapfile.Frame(START_NS + k * 1_000_000_000 + j * prp.SKEW_NS, data))
    return out


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    pcapfile.write(os.path.join(outdir, "prp-pairs.pcap"), frames())
    meta = {"pairs": [{"name": n, "frames": [2 * k + 1, 2 * k + 2], "lans": ["%X" % lan for lan, _ in c], **claim}
                      for k, (n, c, claim) in enumerate(pairs())]}
    with open(os.path.join(outdir, "prp-pairs.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"prp_pairs: {len(meta['pairs'])} pairs, {2 * len(meta['pairs'])} frames")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

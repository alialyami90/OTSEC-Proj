"""Label GT-PCAP's PRP pairs with tshark, and check the writer's claims (D6, P4-D6-GT2).

The pass conditions of C13 0.2's test P-2 on these pairs come from CH-28's
text applied to the capture's bytes, never from a product or an engine
(docs/phase4/D4-c13-0.2-proposal.md, CH-28 and CH-29; a proposal, not yet
approved). Where each part of a frame is comes from the pinned tshark:

- the 802.1Q tag: present when tshark reads `vlan.id`, and then the
  Ethernet header is 18 octets, else 14;
- the RCT: the six octets after the IPv4 packet, whose length is tshark's
  `ip.len`. They must hold the suffix 0x88FB, a LAN ID of A or B, and an
  LSDU size of `ip.len` + 6 (octets after the EtherType, the RCT
  included). Where tshark's PRP dissector reads a trailer (it reads PRP-1
  only as a frame's last six octets), its sequence number, LAN ID and size
  must be these; where it reads none, octets must follow the RCT.

CH-28's comparison is then made on each pair: the frame from the
destination MAC through the RCT, with the whole tag left out, the RCT's
LAN ID masked, and nothing after the RCT. Its outcome and the counters it
moves must equal what prp_pairs.py claims, or the run fails.

Usage: python prp_pairs_label.py DIR   (reads DIR/prp-pairs.pcap and
DIR/prp-pairs.json, writes DIR/prp-pairs.tsv; exits 1 on any disagreement
or a different tshark)
"""

import hashlib
import json
import os
import struct
import subprocess
import sys

import pcapfile
import prp_check

COLUMNS = ["kind", "pair", "frames", "lan", "src_mac", "vlan_id", "vlan_pcp", "rct_seq", "rct_offset", "lsdu",
           "after_rct", "tshark_rct", "frame_sha256", "verdict", "prp_discards", "prp_tag_differs",
           "prp_mismatched", "note"]
COUNTERS = ("prp_discards", "prp_tag_differs", "prp_mismatched")


def comparable(data, header, at):
    """CH-28's comparison form of a frame whose Ethernet header is `header`
    octets and whose RCT starts at `at`: the whole tag left out, the RCT's
    LAN ID masked, nothing after the RCT."""
    rct = data[at:at + 6]
    return data[:12] + data[header - 2:at] + rct[:2] + bytes([rct[2] & 0x0F]) + rct[3:]


def tag(data, header):
    """The 802.1Q tag's four octets, or None for an untagged frame."""
    return data[12:16] if header == 18 else None


def verdict(a, b):
    """CH-28 on two frames, each (src MAC, seq, LAN, tag, comparison form),
    the first to arrive first. Returns (verdict, counters)."""
    if a[:2] != b[:2]:
        raise ValueError("not two copies: the source MAC or the RCT sequence number differs")
    zero = dict.fromkeys(COUNTERS, 0)
    if a[2] == b[2]:
        return "both-passed", zero  # a repeat on one LAN: passed, not counted
    if a[4] != b[4]:
        return "both-passed", {**zero, "prp_mismatched": 1}
    return "second-discarded", {**zero, "prp_discards": 1, "prp_tag_differs": int(a[3] != b[3])}


def tshark_frames(path, pick):
    fields = ["frame.number", "frame.len", "eth.src", "vlan.id", "vlan.priority", "ip.len",
              pick["seq"], pick["lan"], pick["size"]]
    out = prp_check.tshark("--enable-protocol", "prp", "-r", path, "-T", "fields", "-E", "separator=\t",
                           "-E", "occurrence=f", *sum((["-e", f] for f in fields), []))
    return fields, [dict(zip(fields, ln.split("\t"))) for ln in out.splitlines()]


def label(path, meta, pick, version):
    frames = pcapfile.read(path)
    fields, rows = tshark_frames(path, pick)
    if len(rows) != len(frames):
        return [], [f"tshark read {len(rows)} frames, the file has {len(frames)}"]
    bad, per_frame, out = [], {}, []
    for r in rows:
        n = int(r["frame.number"])
        data = frames[n - 1].data
        header = 18 if r["vlan.id"] else 14
        ip_len = int(r["ip.len"])
        at = header + ip_len
        seq, ls, suffix = struct.unpack("!HHH", data[at:at + 6])
        lan, lsdu, after = ls >> 12, ls & 0x0FFF, len(data) - at - 6
        if (header == 18) != (data[12:14] == b"\x81\x00"):
            bad.append(f"frame {n}: tshark's vlan.id {r['vlan.id']!r} and the TPID disagree")
        if suffix != 0x88FB or lan not in (0xA, 0xB) or lsdu != ip_len + 6 or after < 0:
            bad.append(f"frame {n}: no RCT after the IPv4 packet (suffix {suffix:#06x}, LAN {lan:#x}, LSDU {lsdu}, "
                       f"ip.len {ip_len})")
        if r[pick["seq"]]:
            got = (int(r[pick["seq"]], 0), int(r[pick["lan"]], 0), int(r[pick["size"]], 0))
            seen = f"prp-1 seq {got[0]:#06x} lan {got[1]:X} size {got[2]}"
            if got != (seq, lan, lsdu) or after:
                bad.append(f"frame {n}: tshark reads {seen}, the bytes give {seq:#06x} {lan:X} {lsdu} at {at}")
        else:
            seen = "none"
            if not after:
                bad.append(f"frame {n}: tshark reads no PRP trailer, and the RCT is the frame's last six octets")
        per_frame[n] = (data[6:12], seq, lan, tag(data, header), comparable(data, header, at))
        out.append([str(n), "%X" % lan, r["eth.src"], r["vlan.id"], r["vlan.priority"], f"{seq:#06x}", str(at),
                    str(lsdu), str(after), seen, hashlib.sha256(data).hexdigest()])
    lines, totals = [], dict.fromkeys(COUNTERS, 0)
    for p in meta["pairs"]:
        a, b = p["frames"]
        try:
            v, counts = verdict(per_frame[a], per_frame[b])
        except (KeyError, ValueError) as e:
            bad.append(f"{p['name']}: {e}")
            continue
        claim = (p["verdict"], {k: p[k] for k in COUNTERS})
        if (v, counts) != claim:
            bad.append(f"{p['name']}: CH-28 gives {v} {counts} on the bytes, the writer claims {claim}")
        for n in (a, b):
            fr = out[n - 1]
            lines.append(["frame", p["name"], *fr[:10], fr[10], "", "", "", "", ""])
        lines.append(["pair", p["name"], f"{a},{b}", "", "", "", "", "", "", "", "", "", "", v,
                      *(str(counts[k]) for k in COUNTERS), p["note"]])
        for k in COUNTERS:
            totals[k] += counts[k]
    passed = len(frames) - totals["prp_discards"]
    lines.append(["total", "", str(len(frames)), "", "", "", "", "", "", "", "", "", "", f"passed={passed}",
                  *(str(totals[k]) for k in COUNTERS), ""])
    head = [
        "# GT-PCAP labels for prp-pairs.pcap (D6, P4-D6-GT2; plan section 2C). desk until reviewed by D4 and D2.",
        f"# labeller: {version}; options: --enable-protocol prp; fields: {', '.join(fields)}.",
        "# frame rows: the header is 18 octets when tshark reads vlan.id, else 14; the RCT is the six octets after the"
        " IPv4 packet (tshark's ip.len), with suffix 0x88FB and LSDU size ip.len + 6. rct_offset is its first octet,"
        " 0-based; after_rct counts the octets that follow it.",
        "# tshark_rct: what tshark's PRP dissector reads, which it reads only as a frame's last six octets (PRP-1); none"
        " where octets follow the RCT.",
        "# pair rows: C13 0.2 CH-28's comparison (a proposal, not approved) on the two frames, the first to arrive first:"
        " the frame from the destination MAC through the RCT, the whole 802.1Q tag left out, the LAN ID masked, nothing"
        " after the RCT. Equal, with LAN IDs that differ: the second is discarded, prp_discards 1, and prp_tag_differs 1"
        " if the tags differ. Unequal: both passed, prp_mismatched 1. One LAN ID twice: both passed, nothing counted.",
        "# total row: the capture's frames, how many a discard stage passes, and each counter's rise over the capture"
        " (the difference between the heartbeats that bracket its replay).",
        "# frame_sha256 hashes each frame's link-layer bytes, no record header. Every frame is synthesized (prp_pairs.py).",
        "\t".join(COLUMNS),
    ]
    return head + ["\t".join(x) for x in lines], bad


def main(d):
    version = prp_check.tshark("-v").splitlines()[0]
    if version != prp_check.TSHARK:
        print(f"prp_pairs_label: tshark is {version!r}; the pinned labeller is {prp_check.TSHARK!r}")
        return 1
    pick, _ = prp_check.prp_fields()
    with open(os.path.join(d, "prp-pairs.json"), encoding="utf-8") as f:
        meta = json.load(f)
    lines, bad = label(os.path.join(d, "prp-pairs.pcap"), meta, pick, version)
    with open(os.path.join(d, "prp-pairs.tsv"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    for b in bad:
        print(f"prp_pairs_label: FAIL {b}")
    print(f"prp_pairs_label: {len(meta['pairs'])} pairs, {'FAIL' if bad else 'every claim holds'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

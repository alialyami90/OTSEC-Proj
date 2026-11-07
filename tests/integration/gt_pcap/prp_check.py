"""Check GT-PCAP's PRP derived captures with tshark, and write their labels (D6).

For each `<stem>-prp-ab.pcap` and `<stem>-prp-a.pcap` pair in a directory:

1. Tshark's own PRP dissector must read every frame's trailer as prp.py
   wrote it: the same sequence number on both copies, LAN A then LAN B,
   and the LSDU size it reports as correct. This is the independent check
   of the rewriter (plan section 2C, D2 on #527).
2. A label file `<stem>-prp-ab.tsv` is written from tshark's fields, one
   `flow` row per TCP or UDP conversation, in the plan's columns
   (section 1). Its `frames` list every frame of the flow in the -ab file,
   both copies, and `frame_sha256` hashes each frame's link-layer bytes.
   `packets` and `bytes` are the flow's counts in the LAN A only file:
   ADR-0009's PRP pass condition is that a sensor records each flow once,
   with these counts.

The labels are written to be reviewed (D4, D2) before they are committed;
nothing here runs the product. Usage: python prp_check.py DIR OUTDIR
"""

import collections
import glob
import hashlib
import os
import re
import subprocess
import sys

import pcapfile
import prp

# The pinned labeller (plan section 1, D4 on #529). A different tshark
# fails the run, so a re-label can't change silently with an image update;
# moving the pin is a reviewed change.
TSHARK = "TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3)."
APP = ("dnp3", "mbtcp", "modbus", "telnet", "ftp", "http", "snmp", "tls")
FIELDS = [
    "frame.number", "frame.len", "frame.protocols", "eth.src",
    "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "tcp.flags.syn", "tcp.flags.ack",
]


def tshark(*args):
    return subprocess.run(["tshark", *args], check=True, capture_output=True, text=True).stdout


def prp_fields():
    """Tshark's PRP trailer field names, discovered, not assumed."""
    names = [ln.split("\t")[2] for ln in tshark("-G", "fields").splitlines()
             if ln.startswith("F\t") and ln.split("\t")[2].startswith("prp.trailer.")]
    pick = {}
    for key, word in (("seq", "sequence"), ("lan", "lan"), ("size", "size"), ("suffix", "suffix")):
        hit = [n for n in names if word in n and not n.endswith("_wrong")]
        if not hit:
            raise SystemExit(f"prp_check: tshark has no PRP trailer field for {word!r}; it has {names}")
        pick[key] = sorted(hit, key=len)[0]
    return pick, names


def rows(path, fields, opts):
    out = tshark(*opts, "-r", path, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f",
                 *sum((["-e", f] for f in fields), []))
    return [dict(zip(fields, ln.split("\t"))) for ln in out.splitlines()]


def check_trailers(ab_path, pick, opts):
    frames = pcapfile.read(ab_path)
    got = rows(ab_path, ["frame.number", pick["seq"], pick["lan"], pick["size"], pick["suffix"]], opts)
    if len(got) != len(frames) or len(frames) % 2:
        return [f"{ab_path}: tshark read {len(got)} frames, the file has {len(frames)}"]
    bad = []
    for i in range(0, len(got), 2):
        a, b = got[i], got[i + 1]
        want_size = len(frames[i].data) - prp.header_len(frames[i].data)
        for row, lan in ((a, prp.LAN_A), (b, prp.LAN_B)):
            seq, ln, size = row[pick["seq"]], row[pick["lan"]], row[pick["size"]]
            if not seq or not size:
                bad.append(f"frame {row['frame.number']}: tshark found no PRP trailer")
                continue
            if int(ln, 0) != lan or int(size, 0) != want_size:
                bad.append(f"frame {row['frame.number']}: lan {ln} size {size}, want {lan:#x} {want_size}")
        if a[pick["seq"]] != b[pick["seq"]]:
            bad.append(f"frames {a['frame.number']} and {b['frame.number']}: sequence {a[pick['seq']]} != {b[pick['seq']]}")
    # Tshark's own verdict on each LSDU size, which it prints as
    # "LSDU size: N [correct]" or "[WRONG, should be M]" in its tree.
    verdicts = re.findall(r"LSDU size: \d+ \[([^\]]*)\]", tshark(*opts, "-r", ab_path, "-V"))
    wrong = [v for v in verdicts if v != "correct"]
    if len(verdicts) != len(frames) or wrong:
        bad.append(f"tshark judged {len(verdicts) - len(wrong)} of {len(frames)} LSDU sizes correct: {wrong[:3]}")
    return bad


def proto(protocols):
    layers = protocols.split(":")
    app = [p for p in layers if p in APP]
    return app[-1] if app else ("udp" if "udp" in layers else "tcp" if "tcp" in layers else layers[-1])


def label(stem, ab_path, a_path, opts, version, pick):
    ab = pcapfile.read(ab_path)
    a_rows = rows(a_path, FIELDS, opts)
    flows = collections.OrderedDict()
    for r in a_rows:
        l4 = "tcp" if r["tcp.srcport"] else "udp" if r["udp.srcport"] else ""
        if not l4 or not r["ip.src"]:
            continue
        sp, dp = r[f"{l4}.srcport"], r[f"{l4}.dstport"]
        key = (l4,) + tuple(sorted([(r["ip.src"], sp), (r["ip.dst"], dp)]))
        f = flows.setdefault(key, {"first": (r["ip.src"], sp, r["ip.dst"], dp), "client": None,
                                   "nums": [], "bytes": 0, "protos": []})
        f["nums"].append(int(r["frame.number"]))
        f["bytes"] += int(r["frame.len"])
        f["protos"].append(proto(r["frame.protocols"]))
        if r["tcp.flags.syn"] in ("1", "True") and r["tcp.flags.ack"] in ("0", "False") and not f["client"]:
            f["client"] = (r["ip.src"], sp, r["ip.dst"], dp)
    lines = [
        f"# GT-PCAP labels for {stem}-prp-ab.pcap (D6, plan sections 1 and 2C). desk until reviewed by D4 and D2.",
        f"# labeller: {version}; options: {' '.join(opts) or '(none)'}",
        "# kind: flow, one per TCP or UDP conversation (tshark ip.src, ip.dst, tcp/udp ports).",
        "# protocol: the last of " + ", ".join(APP) + " in frame.protocols over the flow's frames, else tcp or udp.",
        "# direction: client-server when the flow holds a frame with tcp.flags.syn==1 && tcp.flags.ack==0,"
        " whose sender is src; else midstream, with src as the first frame's sender.",
        "# frames: frame numbers in the -ab file, both PRP copies (LAN A copy n is 2n-1, LAN B is 2n); either copy satisfies the row.",
        "# frame_sha256: SHA-256 of each listed frame's link-layer bytes as captured (Ethernet frame with its RCT,"
        " no pcap record header, no timestamp), in the order of frames.",
        "# packets: the flow's frame count in the LAN A only file. This is the pass value: a sensor records each flow once,"
        " with this many packets (ADR-0009's PRP row).",
        "# bytes: the sum of frame.len over those frames, link-layer octets including the 6-octet RCT. A sensor that strips"
        " the RCT counts 6 x packets fewer; bytes is compared only once C13 defines which octets a flow counts (D4 on #529).",
        f"# trailer fields read: {pick['seq']}, {pick['lan']}, {pick['size']}, {pick['suffix']}",
        "\t".join(["kind", "src", "dst", "sport", "dport", "l4", "protocol", "version", "direction",
                   "asset", "frames", "frame_sha256", "packets", "bytes"]),
    ]
    for (l4, *_), f in flows.items():
        src, sp, dst, dp = f["client"] or f["first"]
        nums = [m for n in f["nums"] for m in (2 * n - 1, 2 * n)]
        hashes = [hashlib.sha256(ab[m - 1].data).hexdigest() for m in nums]
        named = [p for p in f["protos"] if p in APP]
        lines.append("\t".join([
            "flow", src, dst, sp, dp, l4, named[-1] if named else l4, "",
            "client-server" if f["client"] else "midstream", "asset-unresolved",
            ",".join(map(str, nums)), ",".join(hashes), str(len(f["nums"])), str(f["bytes"]),
        ]))
    return "\n".join(lines) + "\n", len(flows)


def main(src, outdir):
    version = tshark("-v").splitlines()[0]
    if version != TSHARK:
        print(f"prp_check: tshark is {version!r}; the pinned labeller is {TSHARK!r}")
        return 1
    pick, names = prp_fields()
    print(f"prp_check: {version}")
    print(f"prp_check: PRP trailer fields {names}")
    # Tshark ships its PRP dissector disabled; it is turned on by name.
    opts = ["--enable-protocol", "prp"]
    os.makedirs(outdir, exist_ok=True)
    failed = 0
    pairs = sorted(glob.glob(os.path.join(src, "*-prp-ab.pcap")))
    if not pairs:
        print(f"prp_check: no -prp-ab.pcap files in {src}")
        return 1
    for ab_path in pairs:
        stem = os.path.basename(ab_path)[: -len("-prp-ab.pcap")]
        bad = check_trailers(ab_path, pick, opts)
        for b in bad[:20]:
            print(f"prp_check: {stem}: {b}")
        text, n = label(stem, ab_path, ab_path.replace("-prp-ab.pcap", "-prp-a.pcap"), opts, version, pick)
        with open(os.path.join(outdir, f"{stem}-prp-ab.tsv"), "w", encoding="utf-8") as f:
            f.write(text)
        print(f"prp_check: {stem}: {'FAIL, ' + str(len(bad)) + ' problems' if bad else 'trailers ok'}; {n} flows labelled")
        failed += bool(bad)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))

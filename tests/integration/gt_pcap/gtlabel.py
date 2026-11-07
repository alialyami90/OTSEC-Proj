"""GT-PCAP's labeller for the synthesized DNP3 captures (D6, plan section 1).

Every value in a label comes from the pinned tshark's reading of the
capture, never from the product and never from the generator: the frame
numbers, addresses, ports, function codes, application sequence numbers and
object headers are tshark's fields. What this file adds is C13's rules for
turning those fields into rows (docs/phase4/D4-c13-netobs.md section 4), so a
reviewer can check each row against tshark's own output:

- `flow`: one per TCP conversation; packets and bytes are tshark's frame
  count and the sum of frame.len (C13 section 4.3, `bytes`).
- `service`: one per (server, l4, port, protocol).
- `function`: one per (flow, code, sorted objects, sa), at its first
  occurrence in the flow (C13 section 4.2), for requests only. DNP3 0, 129,
  130 and 131 are never functions, and a 32 or 33 carrying group 120 belongs
  to the pending exchange (D2, D1). Its `sa` follows the exchange keyed on
  (master, outstation, application sequence number): a group 120 v1
  challenge from the outstation is `challenged`, g120v3 in the request is
  `aggressive`, a g120v7 in 33 from the master or 131 from the outstation is
  `failed`, a 129 with none of these is `none`. A request still pending at
  sa_reply_timeout_ms or at the end of the capture keeps what was seen,
  else `sa` is empty (unknown). A new request with the same key completes
  the pending one early and counts under `dnp3_seq_reused`.
- `counter`: dnp3_seq_reused for the capture, as tshark's frames show it.
- `case`: the generator's case rows (dnp3_cases.py), each checked here
  against tshark: its first frame must be a request, and the sa this file
  derives for it must equal the sa the case states.

Usage: python gtlabel.py DIR   (reads DIR/dnp3-cases.json and DIR/*.pcap,
writes DIR/<name>.tsv; exits 1 on any disagreement or a different tshark)
"""

import collections
import hashlib
import json
import os
import subprocess
import sys

import pcapfile

TSHARK = "TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3)."
NOT_FUNCTIONS = {0, 129, 130, 131}
FIELDS = ["frame.number", "frame.len", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
          "tcp.flags.syn", "tcp.flags.ack", "dnp3.al.func", "dnp3.al.seq", "dnp3.al.obj",
          "dnp3.al.fragment.reassembled.length"]
COLUMNS = ["kind", "src", "dst", "sport", "dport", "l4", "protocol", "version", "direction", "asset",
           "frames", "frame_sha256", "packets", "bytes", "code", "objects", "sa", "sa_error_from",
           "rules", "context", "note"]


def tshark_rows(path):
    out = subprocess.run(["tshark", "-r", path, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
                          "-E", "aggregator=,", *sum((["-e", f] for f in FIELDS), [])],
                         check=True, capture_output=True, text=True).stdout
    return [dict(zip(FIELDS, ln.split("\t"))) for ln in out.splitlines()]


def wire_problems(path):
    """Tshark's own verdict on every frame: IPv4 and TCP checksums good, no
    DNP3 link CRC flagged, nothing malformed."""
    fields = ["frame.number", "ip.checksum.status", "tcp.checksum.status", "dnp3.hdr.CRC.incorrect", "_ws.malformed"]
    out = subprocess.run(["tshark", "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE", "-r", path,
                          "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,",
                          *sum((["-e", f] for f in fields), [])], check=True, capture_output=True, text=True).stdout
    bad = []
    for ln in out.splitlines():
        n, ipc, tcpc, crc, mal = (ln.split("\t") + [""] * 5)[:5]
        if ipc != "1" or tcpc != "1" or crc or mal:
            bad.append(f"frame {n}: ip checksum {ipc!r}, tcp checksum {tcpc!r}, crc flag {crc!r}, malformed {mal!r}")
    return bad


def obj_name(v):
    n = int(v, 0)
    return f"g{n >> 8}v{n & 0xFF}"


class Exchange:
    __slots__ = ("req", "flow", "code", "objects", "frames", "chal", "aggr", "err", "t0")

    def __init__(self, req, flow, code, objects, t0):
        self.req, self.flow, self.code, self.objects, self.t0 = req, flow, code, objects, t0
        self.frames, self.chal, self.aggr, self.err = [req], False, "g120v3" in objects, ""

    def sa(self, answered):
        if self.err:
            return "failed"
        if self.chal:
            return "challenged"
        if self.aggr:
            return "aggressive"
        return "none" if answered else ""


def label(path, net, timeout_ns):
    frames = pcapfile.read(path)
    rows = tshark_rows(path)
    if len(rows) != len(frames):
        raise SystemExit(f"{path}: tshark read {len(rows)} frames, the file has {len(frames)}")
    assets = {net["outstation"]["ip"]: net["outstation"]["asset"]}
    assets.update({m["ip"]: m["asset"] for m in net["masters"].values() if m["asset"]})
    flows = collections.OrderedDict()
    pending, done, reused = {}, [], 0

    def complete(key, answered):
        done.append((pending.pop(key), answered))

    for r in rows:
        n = int(r["frame.number"])
        ns = frames[n - 1].ns
        for key in [k for k, x in pending.items() if ns - x.t0 > timeout_ns]:
            complete(key, False)
        if not r["tcp.srcport"]:
            continue
        a, b = (r["ip.src"], r["tcp.srcport"]), (r["ip.dst"], r["tcp.dstport"])
        fk = ("tcp",) + tuple(sorted([a, b]))
        f = flows.setdefault(fk, {"client": None, "first": a + b, "nums": [], "bytes": 0, "dnp3": False})
        f["nums"].append(n)
        f["bytes"] += int(r["frame.len"])
        if r["tcp.flags.syn"] in ("1", "True") and r["tcp.flags.ack"] in ("0", "False"):
            f["client"] = a + b
        if not r["dnp3.al.func"]:
            continue
        f["dnp3"] = True
        client = (f["client"] or f["first"])[:2]
        from_client = a == client
        code, seq = int(r["dnp3.al.func"].split(",")[0]), int(r["dnp3.al.seq"].split(",")[0])
        objs = sorted({obj_name(v) for v in r["dnp3.al.obj"].split(",") if v})
        al_len = int((r["dnp3.al.fragment.reassembled.length"] or "0").split(",")[0])
        if not objs and from_client and al_len > 2:
            # The APDU holds object headers that this tshark doesn't dissect
            # (4.2.2 shows none for function 22): unlabelled, not empty.
            objs = ["?"]
        master, outst = (a[0], b[0]) if from_client else (b[0], a[0])
        key = (master, outst, seq)
        g120 = any(o.startswith("g120v") for o in objs)
        if from_client and code in (32, 33) and g120:
            x = pending.get(key)
            if x:
                x.frames.append(n)
                if code == 33 and "g120v7" in objs:
                    x.err = "master"
            continue
        if from_client and code not in NOT_FUNCTIONS:
            if key in pending:
                reused += 1
                complete(key, False)
            pending[key] = Exchange(n, fk, code, objs, ns)
            continue
        if not from_client and key in pending:
            x = pending[key]
            if code == 131 and "g120v1" in objs:
                x.chal = True
                x.frames.append(n)
            elif code == 131 and "g120v7" in objs:
                x.err = "outstation"
                x.frames.append(n)
                complete(key, True)
            elif code == 129:
                x.frames.append(n)
                complete(key, True)
    for key in list(pending):
        complete(key, False)

    def sha(nums):
        return ",".join(hashlib.sha256(frames[m - 1].data).hexdigest() for m in nums)

    out, functions, seen = [], {}, set()
    for fk, f in flows.items():
        src, sp, dst, dp = f["client"] or f["first"]
        proto = "dnp3" if f["dnp3"] else "tcp"
        common = [src, dst, sp, dp, "tcp", proto, "", "client-server" if f["client"] else "midstream",
                  assets.get(dst, "asset-unresolved")]
        out.append(["flow", *common, ",".join(map(str, f["nums"])), sha(f["nums"]), str(len(f["nums"])),
                    str(f["bytes"]), "", "", "", "", "", "", ""])
        skey = (dst, "tcp", dp, proto)
        if skey not in seen:
            seen.add(skey)
            out.append(["service", "", dst, "", dp, "tcp", proto, "", "", assets.get(dst, "asset-unresolved"),
                        str(f["nums"][0]), sha(f["nums"][:1]), "", "", "", "", "", "", "", "", ""])
    flow_common = {fk: [(f["client"] or f["first"])[i] for i in (0, 2, 1, 3)] for fk, f in flows.items()}
    for x, answered in sorted(done, key=lambda d: d[0].req):
        sa = x.sa(answered)
        k = (x.flow, x.code, tuple(x.objects), sa)
        functions[x.req] = sa
        if k in seen:
            continue
        seen.add(k)
        src, dst, sp, dp = flow_common[x.flow]
        out.append(["function", src, dst, sp, dp, "tcp", "dnp3", "", "client-server", assets.get(dst, "asset-unresolved"),
                    ",".join(map(str, x.frames)), sha(x.frames), "", "", str(x.code), ",".join(x.objects), sa,
                    x.err, "", "", ""])
    out.append(["counter", "", "", "", "", "", "dnp3", "", "", "", "", "", "", "", "", "", "", "", "", "",
                f"dnp3_seq_reused={reused}"])
    return out, functions, reused


def header(name, version, net):
    return [
        f"# GT-PCAP labels for {name}.pcap (D6, plan sections 1, 2B, 2C and 4). desk until reviewed by D4 and D2.",
        f"# labeller: {version}; options: (none); gtlabel.py applies C13 section 4's rules to tshark's fields.",
        "# fields: " + ", ".join(FIELDS) + ". objects are dnp3.al.obj as g<group>v<variation>, sorted.",
        "# objects '?': the request's APDU is longer than its 2-octet header, but this tshark dissects no object header"
        " in it (function 22 in 4.2.2). Unlabelled: the checker compares the code only.",
        f"# sa_reply_timeout_ms: {net['sa_reply_timeout_ms']} (C13 default). sa empty means unknown.",
        "# group 120 objects are synthetic at header level (no SA specification is held): only their headers are labelled.",
        "# frames are 1-based tshark frame numbers; frame_sha256 hashes each frame's link-layer bytes, no record header.",
        "# case rules: every rule D4's note expects; empty is a near-miss that must raise nothing.",
        "\t".join(COLUMNS),
    ]


def main(d):
    version = subprocess.run(["tshark", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    if version != TSHARK:
        print(f"gtlabel: tshark is {version!r}; the pinned labeller is {TSHARK!r}")
        return 1
    with open(os.path.join(d, "dnp3-cases.json"), encoding="utf-8") as f:
        meta = json.load(f)
    net, bad = meta["net"], []
    timeout = net["sa_reply_timeout_ms"] * 1_000_000
    learned = {}
    for name in sorted(list(meta["series"]) + list(meta["cases"])):
        path = os.path.join(d, name + ".pcap")
        bad += [f"{name}: {p}" for p in wire_problems(path)]
        rows, functions, reused = label(path, net, timeout)
        if name in meta["series"]:
            learned[name] = {(r[1], r[2], r[4], r[14], r[15]) for r in rows if r[0] == "function"}
        frames = pcapfile.read(path)
        for c in meta["cases"].get(name, []):
            first = c["frames"][0]
            if first not in functions:
                bad.append(f"{name}: case frame {first} is not a request tshark reads as a DNP3 function")
            elif functions[first] != c["sa"]:
                bad.append(f"{name}: case frame {first} has sa {functions[first]!r} from tshark, the case says {c['sa']!r}")
            rows.append(["case", "", "", "", "", "tcp", "dnp3", "", "", "", ",".join(map(str, c["frames"])),
                         ",".join(hashlib.sha256(frames[m - 1].data).hexdigest() for m in c["frames"]),
                         "", "", "", "", c["sa"], c.get("sa_error_from", ""), ",".join(c["rules"]),
                         c["context"], c["note"]])
        if name.startswith("dnp3-") and name in meta["series"] and reused:
            print(f"gtlabel: {name}: dnp3_seq_reused {reused} on a benign series (pass value as measured)")
        with open(os.path.join(d, name + ".tsv"), "w", encoding="utf-8") as f:
            f.write("\n".join(header(name, version, net) + ["\t".join(r) for r in rows]) + "\n")
        print(f"gtlabel: {name}: {len(rows)} rows, dnp3_seq_reused {reused}")
    # Plan section 3: the training series covers every pair and every
    # function the held-out series uses.
    for k in sorted(learned.get("dnp3-heldout", set()) - learned.get("dnp3-train", set())):
        bad.append(f"dnp3-heldout: function {k} is not in dnp3-train")
    for b in bad:
        print(f"gtlabel: FAIL {b}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

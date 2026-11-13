"""GT-PCAP's labeller for the synthesized DNP3 captures (D6, plan section 1).

Every value in a label comes from the pinned tshark's reading of the
capture, never from the product and never from the generator: the frame
numbers, addresses, ports, function codes, application sequence numbers and
object headers are tshark's fields. What this file adds is C13's rules for
turning those fields into rows (docs/phase4/D4-c13-netobs.md section 4), so a
reviewer can check each row against tshark's own output:

- `flow`: one per TCP connection or UDP conversation; packets and bytes
  are tshark's frame count and the sum of frame.len (C13 section 4.3,
  `bytes`). A UDP flow has no direction (`none`, C13 section 4.1): its
  `src` is the first datagram's sender.
- `service`: one per (server, l4, port, protocol). For DNP3 the server is
  the outstation's end of the flow, whichever end sent first.
- Who sent a DNP3 frame, the master or the outstation, is its link
  header's DIR bit (dnp3.ctl.dir, set by the master), never which end of
  the flow sent first. Over UDP the outstation's responses can come back on
  another 5-tuple (dnp3-udp-temp-port), and the first datagram of that
  flow is the outstation's.
- `function`: one per (flow, code, sorted objects, sa), at its first
  occurrence in the flow (C13 section 4.2), for requests only. Its src and
  sport are the request's sender, the master, and its dst and dport the
  outstation, whichever end of the flow sent first; its direction is the
  flow's (C13 section 14, item 14). On a flow the outstation starts
  (dnp3-udp-unsolicited) they are the flow row's ends swapped. DNP3 0, 129,
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
  The replay brackets each capture with heartbeats, and the product's value
  is the difference between the heartbeat after the capture and the one
  before it (D1 on #548).
- `case`: the generator's case rows (dnp3_cases.py), each checked here
  against tshark: its first frame must be a request, and the sa this file
  derives for it must equal the sa the case states.

A capture named under `decode` in dnp3-cases.json is not DNP3 on TCP 20000.
The labeller is told its transport, and the outstation's port as the asset
table's settings give it (plan section 2B), and reads that port as DNP3
with tshark's -d option. A UDP capture is read with the udp.* fields in
place of the tcp.* ones. Each label's header names the fields and the
options used for it.

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
          "tcp.flags.syn", "tcp.flags.ack", "dnp3.ctl.dir", "dnp3.al.func", "dnp3.al.seq", "dnp3.al.obj",
          "dnp3.al.fragment.reassembled.length"]
COLUMNS = ["kind", "src", "dst", "sport", "dport", "l4", "protocol", "version", "direction", "asset",
           "frames", "frame_sha256", "packets", "bytes", "code", "objects", "sa", "sa_error_from",
           "rules", "context", "note"]


TCP_20000 = {"l4": "tcp", "port": 20000}  # every capture not named under `decode`


def fields_for(l4):
    """FIELDS for a TCP capture; for UDP, the udp.* ports and no TCP flags."""
    if l4 == "tcp":
        return FIELDS
    return [f.replace("tcp.", "udp.") for f in FIELDS if not f.startswith("tcp.flags.")]


def options_for(decode):
    """Tshark's options for a capture: none for DNP3 on port 20000, else the
    outstation's port read as DNP3."""
    if decode["port"] == 20000:
        return []
    return ["-d", f"{decode['l4']}.port=={decode['port']},dnp3"]


def tshark_rows(path, decode=TCP_20000):
    fields = fields_for(decode["l4"])
    out = subprocess.run(["tshark", *options_for(decode), "-r", path, "-T", "fields", "-E", "separator=\t",
                          "-E", "occurrence=a", "-E", "aggregator=,", *sum((["-e", f] for f in fields), [])],
                         check=True, capture_output=True, text=True).stdout
    return [dict(zip(fields, ln.split("\t"))) for ln in out.splitlines()]


def wire_problems(path, decode=TCP_20000):
    """Tshark's own verdict on every frame: IPv4 and TCP or UDP checksums
    good, no DNP3 link CRC flagged, nothing malformed."""
    l4 = decode["l4"]
    fields = ["frame.number", "ip.checksum.status", l4 + ".checksum.status", "dnp3.hdr.CRC.incorrect", "_ws.malformed"]
    out = subprocess.run(["tshark", "-o", "ip.check_checksum:TRUE", "-o", l4 + ".check_checksum:TRUE",
                          *options_for(decode), "-r", path,
                          "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a", "-E", "aggregator=,",
                          *sum((["-e", f] for f in fields), [])], check=True, capture_output=True, text=True).stdout
    bad = []
    for ln in out.splitlines():
        n, ipc, l4c, crc, mal = (ln.split("\t") + [""] * 5)[:5]
        if ipc != "1" or l4c != "1" or crc or mal:
            bad.append(f"frame {n}: ip checksum {ipc!r}, {l4} checksum {l4c!r}, crc flag {crc!r}, malformed {mal!r}")
    return bad


def obj_name(v):
    n = int(v, 0)
    return f"g{n >> 8}v{n & 0xFF}"


class Exchange:
    __slots__ = ("req", "flow", "ends", "code", "objects", "frames", "chal", "aggr", "err", "t0")

    def __init__(self, req, flow, ends, code, objects, t0):
        self.req, self.flow, self.ends, self.code, self.objects, self.t0 = req, flow, ends, code, objects, t0
        self.frames, self.chal, self.aggr, self.err = [req], False, "g120v3" in objects, ""

    def sa(self, answered):
        if self.err:
            return "failed"
        if self.chal:
            return "challenged"
        if self.aggr:
            return "aggressive"
        return "none" if answered else ""


def label(path, net, timeout_ns, decode=TCP_20000):
    l4 = decode["l4"]
    frames = pcapfile.read(path)
    rows = tshark_rows(path, decode)
    if len(rows) != len(frames):
        raise SystemExit(f"{path}: tshark read {len(rows)} frames, the file has {len(frames)}")
    assets = {o["ip"]: o["asset"] for o in [net["outstation"], *net.get("outstations", {}).values()]}
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
        if not r[l4 + ".srcport"]:
            continue
        a, b = (r["ip.src"], r[l4 + ".srcport"]), (r["ip.dst"], r[l4 + ".dstport"])
        fk = (l4,) + tuple(sorted([a, b]))
        f = flows.setdefault(fk, {"client": None, "first": a + b, "nums": [], "bytes": 0, "dnp3": False,
                                  "server": None})
        f["nums"].append(n)
        f["bytes"] += int(r["frame.len"])
        if l4 == "tcp" and r["tcp.flags.syn"] in ("1", "True") and r["tcp.flags.ack"] in ("0", "False"):
            f["client"] = a + b
        if not r["dnp3.al.func"]:
            continue
        f["dnp3"] = True
        direction_bit = r["dnp3.ctl.dir"].split(",")[0]
        if direction_bit not in ("1", "True", "0", "False"):
            raise SystemExit(f"{path}: frame {n}: tshark gives the link direction as {direction_bit!r}")
        from_master = direction_bit in ("1", "True")
        if f["server"] is None:
            f["server"] = b if from_master else a  # the outstation's end
        code, seq = int(r["dnp3.al.func"].split(",")[0]), int(r["dnp3.al.seq"].split(",")[0])
        objs = sorted({obj_name(v) for v in r["dnp3.al.obj"].split(",") if v})
        al_len = int((r["dnp3.al.fragment.reassembled.length"] or "0").split(",")[0])
        if not objs and from_master and al_len > 2:
            # The APDU holds object headers that this tshark doesn't dissect
            # (4.2.2 shows none for function 22): unlabelled, not empty.
            objs = ["?"]
        master, outst = (a[0], b[0]) if from_master else (b[0], a[0])
        key = (master, outst, seq)
        g120 = any(o.startswith("g120v") for o in objs)
        if from_master and code in (32, 33) and g120:
            x = pending.get(key)
            if x:
                x.frames.append(n)
                if code == 33 and "g120v7" in objs:
                    x.err = "master"
            continue
        if from_master and code not in NOT_FUNCTIONS:
            if key in pending:
                reused += 1
                complete(key, False)
            pending[key] = Exchange(n, fk, (a, b), code, objs, ns)
            continue
        if not from_master and key in pending:
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

    def direction(f):
        return "none" if l4 == "udp" else "client-server" if f["client"] else "midstream"

    out, functions, seen = [], {}, set()
    for fk, f in flows.items():
        src, sp, dst, dp = f["client"] or f["first"]
        proto = "dnp3" if f["dnp3"] else l4
        common = [src, dst, sp, dp, l4, proto, "", direction(f), assets.get(dst, "asset-unresolved")]
        out.append(["flow", *common, ",".join(map(str, f["nums"])), sha(f["nums"]), str(len(f["nums"])),
                    str(f["bytes"]), "", "", "", "", "", "", ""])
        server, server_port = f["server"] or (dst, dp)
        skey = (server, l4, server_port, proto)
        if skey not in seen:
            seen.add(skey)
            out.append(["service", "", server, "", server_port, l4, proto, "", "", assets.get(server, "asset-unresolved"),
                        str(f["nums"][0]), sha(f["nums"][:1]), "", "", "", "", "", "", "", "", ""])
    for x, answered in sorted(done, key=lambda d: d[0].req):
        sa = x.sa(answered)
        k = (x.flow, x.code, tuple(x.objects), sa)
        functions[x.req] = sa
        if k in seen:
            continue
        seen.add(k)
        (src, sp), (dst, dp) = x.ends  # the request's sender and its receiver
        out.append(["function", src, dst, sp, dp, l4, "dnp3", "", direction(flows[x.flow]),
                    assets.get(dst, "asset-unresolved"),
                    ",".join(map(str, x.frames)), sha(x.frames), "", "", str(x.code), ",".join(x.objects), sa,
                    x.err, "", "", ""])
    out.append(["counter", "", "", "", "", "", "dnp3", "", "", "", "", "", "", "", "", "", "", "", "", "",
                f"dnp3_seq_reused={reused}"])
    return out, functions, reused


def header(name, version, net, decode=TCP_20000):
    told = []
    if decode != TCP_20000:
        told = [f"# the labeller is told this capture's transport ({decode['l4']}) and the outstation's port "
                f"({decode['port']}) from the asset table's settings, never from the product (plan section 2B)."
                + (" A UDP flow has direction none, and its src is the first datagram's sender (C13 section 4.1)."
                   if decode["l4"] == "udp" else "")]
    return [
        f"# GT-PCAP labels for {name}.pcap (D6, plan sections 1, 2B, 2C and 4). desk until reviewed by D4 and D2.",
        f"# labeller: {version}; options: {' '.join(options_for(decode)) or '(none)'}; gtlabel.py applies C13 "
        "section 4's rules to tshark's fields.",
        "# fields: " + ", ".join(fields_for(decode["l4"])) + ". objects are dnp3.al.obj as g<group>v<variation>, sorted.",
        "# a DNP3 frame is the master's when dnp3.ctl.dir is set and the outstation's when it is clear, whichever end"
        " of the flow sent first; a service row's server is the outstation's end, and a function row's src is the"
        " request's sender (C13 section 14, item 14).",
        *told,
        "# objects '?': the request's APDU is longer than its 2-octet header, but this tshark dissects no object header"
        " in it (function 22 in 4.2.2). Unlabelled: the checker compares the code only.",
        f"# sa_reply_timeout_ms: {net['sa_reply_timeout_ms']} (C13 default). sa empty means unknown.",
        "# group 120 objects are synthetic at header level (no SA specification is held): only their headers are labelled.",
        "# frames are 1-based tshark frame numbers; frame_sha256 hashes each frame's link-layer bytes, no record header.",
        "# case rules: every rule D4's note expects; empty is a near-miss that must raise nothing.",
        "# counter rows: the difference between the heartbeats that bracket this capture's replay (D1 on #548).",
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
        decode = meta.get("decode", {}).get(name, TCP_20000)
        bad += [f"{name}: {p}" for p in wire_problems(path, decode)]
        rows, functions, reused = label(path, net, timeout, decode)
        if name in meta["series"]:
            learned[name] = {(r[1], r[2], r[4], r[14], r[15]) for r in rows if r[0] == "function"}
        frames = pcapfile.read(path)
        for c in meta["cases"].get(name, []):
            first = c["frames"][0]
            if first not in functions:
                bad.append(f"{name}: case frame {first} is not a request tshark reads as a DNP3 function")
            elif functions[first] != c["sa"]:
                bad.append(f"{name}: case frame {first} has sa {functions[first]!r} from tshark, the case says {c['sa']!r}")
            rows.append(["case", "", "", "", "", decode["l4"], "dnp3", "", "", "", ",".join(map(str, c["frames"])),
                         ",".join(hashlib.sha256(frames[m - 1].data).hexdigest() for m in c["frames"]),
                         "", "", "", "", c["sa"], c.get("sa_error_from", ""), ",".join(c["rules"]),
                         c["context"], c["note"]])
        if name.startswith("dnp3-") and name in meta["series"] and reused:
            print(f"gtlabel: {name}: dnp3_seq_reused {reused} on a benign series (pass value as measured)")
        with open(os.path.join(d, name + ".tsv"), "w", encoding="utf-8") as f:
            f.write("\n".join(header(name, version, net, decode) + ["\t".join(r) for r in rows]) + "\n")
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

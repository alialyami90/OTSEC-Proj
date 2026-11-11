"""GT-PCAP's labeller for the derived Modbus/TCP capture on a moved port (D6).

Every value comes from the pinned tshark's reading of the derived capture,
never from the product and never from movedport.py. The labeller is told
the server's port, as the asset table's `MODNUM1` setting would give it
(plan section 2B), and reads that port as Modbus/TCP with tshark's -d
option. The rows, in gtlabel.py's columns:

- `flow`: one per TCP conversation, with tshark's frame count and the sum
  of frame.len. `direction` is `client-server` when the capture holds the
  client's SYN, else `midstream` with `src` as the first frame's sender.
- `service`: one per (server, tcp, port, modbus).
- `function`: one per (flow, function code, unit), at its first request. A
  request is an ADU sent to the server's port; a response repeats the
  request's code, so it is not a function (C13 section 4.3). The unit is in
  `note`, as `unit=<n>`.
- `insecure`: one per flow that carries Modbus/TCP, which has no
  authentication and is on V-M6's list (`reason=modbus-tcp`).

Before it labels, it checks the derived capture against its source: the
same number of frames, tshark's TCP checksum verdict the same on every
frame, and nothing malformed. So the port is all that moved.

Usage: python modbus_label.py SOURCE.pcap DERIVED.pcap PORT OUT.tsv
(exits 1 on any disagreement or a different tshark)
"""

import collections
import hashlib
import os
import subprocess
import sys

import gtlabel
import pcapfile

FIELDS = ["frame.number", "frame.len", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
          "tcp.flags.syn", "tcp.flags.ack", "mbtcp.unit_id", "modbus.func_code"]


def tshark(path, fields, *opts):
    out = subprocess.run(["tshark", *opts, "-r", path, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
                          "-E", "aggregator=,", *sum((["-e", f] for f in fields), [])],
                         check=True, capture_output=True, text=True).stdout
    return [dict(zip(fields, ln.split("\t"))) for ln in out.splitlines()]


def differences(source, derived, opts):
    """Where the derived capture is not its source on another port."""
    check = ["-o", "tcp.check_checksum:TRUE"]
    a = tshark(source, ["tcp.checksum.status"], *check)
    b = tshark(derived, ["tcp.checksum.status", "_ws.malformed"], *check, *opts)
    if len(a) != len(b):
        return [f"{len(b)} frames, the source has {len(a)}"]
    bad = []
    for n, (x, y) in enumerate(zip(a, b), 1):
        if x["tcp.checksum.status"] != y["tcp.checksum.status"]:
            bad.append(f"frame {n}: tcp checksum status {y['tcp.checksum.status']!r}, the source's is "
                       f"{x['tcp.checksum.status']!r}")
        if y["_ws.malformed"]:
            bad.append(f"frame {n}: malformed")
    return bad


def label(path, port, opts):
    frames = pcapfile.read(path)
    rows = tshark(path, FIELDS, *opts)
    if len(rows) != len(frames):
        raise SystemExit(f"{path}: tshark read {len(rows)} frames, the file has {len(frames)}")
    flows, functions = collections.OrderedDict(), collections.OrderedDict()
    for r in rows:
        if not r["tcp.srcport"]:
            continue
        n = int(r["frame.number"])
        a, b = (r["ip.src"], r["tcp.srcport"]), (r["ip.dst"], r["tcp.dstport"])
        fk = ("tcp",) + tuple(sorted([a, b]))
        f = flows.setdefault(fk, {"client": None, "first": a + b, "nums": [], "bytes": 0, "modbus": None})
        f["nums"].append(n)
        f["bytes"] += int(r["frame.len"])
        if r["tcp.flags.syn"] in ("1", "True") and r["tcp.flags.ack"] in ("0", "False"):
            f["client"] = a + b
        if not r["modbus.func_code"]:
            continue
        f["modbus"] = f["modbus"] or n
        if r["tcp.dstport"] != str(port):
            continue  # a response, or not to the server's port
        for code, unit in zip(r["modbus.func_code"].split(","), r["mbtcp.unit_id"].split(",")):
            functions.setdefault((fk, int(code), int(unit)), n)

    def sha(nums):
        return ",".join(hashlib.sha256(frames[m - 1].data).hexdigest() for m in nums)

    out, seen = [], set()
    for fk, f in flows.items():
        src, sp, dst, dp = f["client"] or f["first"]
        proto = "modbus" if f["modbus"] else "tcp"
        direction = "client-server" if f["client"] else "midstream"
        ends = [src, dst, sp, dp, "tcp", proto, "", direction, "asset-unresolved"]
        out.append(["flow", *ends, ",".join(map(str, f["nums"])), sha(f["nums"]), str(len(f["nums"])),
                    str(f["bytes"]), "", "", "", "", "", "", ""])
        if (dst, dp, proto) not in seen:
            seen.add((dst, dp, proto))
            out.append(["service", "", dst, "", dp, "tcp", proto, "", "", "asset-unresolved", str(f["nums"][0]),
                        sha(f["nums"][:1]), "", "", "", "", "", "", "", "", ""])
        for (k, code, unit), n in functions.items():
            if k == fk:
                out.append(["function", *ends, str(n), sha([n]), "", "", str(code), "", "", "", "", "", f"unit={unit}"])
        if f["modbus"]:
            out.append(["insecure", *ends, str(f["modbus"]), sha([f["modbus"]]), "", "", "", "", "", "", "", "",
                        "reason=modbus-tcp"])
    return out


def header(name, source, version, port, opts):
    return [
        f"# GT-PCAP labels for {name} (D6, plan sections 1, 2B and 2C). desk until reviewed by D4 and D2.",
        f"# derived from the public capture {source} by movedport.py: TCP port 502 is {port}, and nothing else differs.",
        f"# labeller: {version}; options: {' '.join(opts)}; the labeller is told the server's port ({port}) as the asset "
        "table's MODNUM1 setting would give it, never from the product (plan section 2B).",
        "# fields: " + ", ".join(FIELDS) + ".",
        "# function rows: one per (flow, function code, unit) at its first request, an ADU sent to the server's port. "
        "The unit is in note. A response repeats the request's code and is not a function.",
        "# insecure rows: Modbus/TCP has no authentication (V-M6's list). asset-unresolved: a public capture has no asset table.",
        "# frames are 1-based tshark frame numbers; frame_sha256 hashes each frame's link-layer bytes, no record header.",
        "\t".join(gtlabel.COLUMNS),
    ]


def main(source, derived, port, out_path):
    version = subprocess.run(["tshark", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    if version != gtlabel.TSHARK:
        print(f"modbus_label: tshark is {version!r}; the pinned labeller is {gtlabel.TSHARK!r}")
        return 1
    opts = ["-d", f"tcp.port=={port},mbtcp"]
    bad = differences(source, derived, opts)
    rows = label(derived, port, opts)
    if not any(r[0] == "function" for r in rows):
        bad.append(f"tshark read no Modbus request on port {port}")
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(header(os.path.basename(derived), os.path.basename(source), version, port, opts)
                          + ["\t".join(r) for r in rows]) + "\n")
    print(f"modbus_label: {os.path.basename(derived)}: {len(rows)} rows")
    for b in bad:
        print(f"modbus_label: FAIL {b}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:5]))

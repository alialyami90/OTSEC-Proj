"""P4-4-E2 (D4): the labels of the Modbus signature's corpus, one row per
flow, as D6's `label-` rows say (tests/integration/gt_pcap/
modbus-signature-conditions.tsv). Every value comes from the corpus manifest
(the source) and from the pinned tshark 4.2.2, never from an engine.

For each flow that flows.py reads (TCP and UDP):

- the server is the end that received the client's SYN; with no SYN, the
  end on the port the manifest's `server_port` names; else the end that
  received the first payload, or the first frame (`label-flow`);
- by_source: the manifest's `modbus` and `protocol` for the capture;
- by_tshark: with tshark's defaults, whether it reads Modbus/TCP on the
  flow; and told that the server's port is Modbus/TCP (`-d tcp.port==P,
  mbtcp`, or `udp.port==P,mbudp`), the requests it reads sent to the server
  and how many of them a response from the server answers with the same
  transaction ID and the same code, or that code plus 80h;
- class: `modbus` (`label-modbus`): the source says Modbus/TCP on that
  server port, and told the port, tshark reads at least one request to the
  server. `not-modbus` (`label-not-modbus`): the source says the flow is
  not Modbus/TCP (Modbus RTU framing in raw TCP included), tshark's
  defaults read no Modbus/TCP on it, and told the port, no request to the
  server is answered. `disputed`: anything else;
- near_miss (`fp-near`): for one end or the other, the first 8 octets it
  sent, as flows.py reassembles them, have octets 2 and 3 zero and octets
  4 and 5, big-endian, at least 2. The octets themselves are not written.

A label holds no payload byte and no host name. Usage:

  python -I corpus_label.py MANIFEST CAPTURE_DIR FLOWS.tsv OUT.tsv [--any-tshark]

CAPTURE_DIR holds each capture under its manifest name, a `.gz` one
decompressed (`mms.pcap.gz` as `mms.pcap`). It exits 1 if tshark is not the
pinned 4.2.2, unless --any-tshark is given, which is for a local trial only:
the file's header then names the other version, and it is not the labels.
"""

import collections
import os
import subprocess
import sys

TSHARK = "TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3)."
FIELDS = ["ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
          "mbtcp.trans_id", "modbus.func_code"]
COLUMNS = ["capture", "source", "l4", "src", "sport", "dst", "dport", "direction", "packets_src", "packets_dst",
           "payload_src", "payload_dst", "class", "protocol", "by_source", "by_tshark", "near_miss", "syn", "first"]


def stem(name):
    name = name[:-3] if name.endswith(".gz") else name
    return os.path.splitext(name)[0]


def table(path):
    head, out = None, []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if head is None:
                head = cols
            else:
                out.append(dict(zip(head, cols)))
    return out


def tshark(path, *opts):
    out = subprocess.run(["tshark", "-n", *opts, "-r", path, "-T", "fields", "-E", "separator=\t", "-E",
                          "occurrence=a", "-E", "aggregator=,", *sum((["-e", f] for f in FIELDS), [])],
                         check=True, capture_output=True, text=True).stdout
    rows = []
    for ln in out.splitlines():
        r = dict(zip(FIELDS, ln.split("\t")))
        l4 = "tcp" if r.get("tcp.srcport") else "udp" if r.get("udp.srcport") else None
        if not l4:
            continue
        src = ((r["ip.src"] or r["ipv6.src"]).split(",")[-1], r[f"{l4}.srcport"].split(",")[0])
        dst = ((r["ip.dst"] or r["ipv6.dst"]).split(",")[-1], r[f"{l4}.dstport"].split(",")[0])
        adus = list(zip([x for x in r["mbtcp.trans_id"].split(",") if x],
                        [int(x) for x in r["modbus.func_code"].split(",") if x]))
        rows.append((l4, src, dst, adus, bool(r["mbtcp.trans_id"])))
    return rows


def near(head):
    if len(head) < 16:
        return False
    b = bytes.fromhex(head)
    return b[2] == 0 and b[3] == 0 and (b[4] << 8 | b[5]) >= 2


def server_of(f, port):
    """(server end, client end) of a flows.py row, by label-flow."""
    a, b = (f["a"], f["ap"]), (f["b"], f["bp"])
    if f["syn"] in ("a", "b"):
        return (b, a) if f["syn"] == "a" else (a, b)
    if port != "-" and port in (f["ap"], f["bp"]) and f["ap"] != f["bp"]:
        return (a, b) if f["ap"] == port else (b, a)
    first = f["first_payload"] if f["first_payload"] in ("a", "b") else f["first"]
    return (b, a) if first == "a" else (a, b)


def label(manifest, capdir, flows_path, out_path, any_tshark=False):
    version = subprocess.run(["tshark", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    if version != TSHARK and not any_tshark:
        print(f"corpus_label: tshark is {version!r}; the pinned labeller is {TSHARK!r}")
        return 1
    flows = collections.defaultdict(list)
    for f in table(flows_path):
        flows[f["capture"]].append(f)
    out = []
    for m in table(manifest):
        cap = stem(m["name"])
        path = os.path.join(capdir, m["name"][:-3] if m["name"].endswith(".gz") else m["name"])
        if not flows[cap]:
            continue
        default = tshark(path)
        told = {}
        rows = []
        for f in flows[cap]:
            server, client = server_of(f, m["server_port"])
            rows.append((f, server, client))
            key = (f["l4"], server[1])
            if key not in told:
                proto = "mbtcp" if f["l4"] == "tcp" else "mbudp"
                told[key] = tshark(path, "-d", f"{f['l4']}.port=={server[1]},{proto}", "-Y", f"{f['l4']}.port=={server[1]}")
        for f, server, client in rows:
            l4, ends = f["l4"], {server, client}
            mine = [r for r in default if r[0] == l4 and {r[1], r[2]} == ends]
            by_default = "mbtcp" if any(r[4] for r in mine) else "none"
            reqs, resps = [], set()
            for r in told[(l4, server[1])]:
                if r[0] != l4 or {r[1], r[2]} != ends:
                    continue
                if r[2] == server:
                    reqs += r[3]
                elif r[1] == server:
                    resps.update((tid, fc & 0x7F) for tid, fc in r[3])
            answered = sum(1 for tid, fc in reqs if (tid, fc & 0x7F) in resps)
            mb = m["modbus"]
            if mb.startswith("tcp/") and l4 == "tcp" and server[1] == mb[4:]:
                klass = "modbus" if reqs else "disputed"
                protocol = "modbus"
            else:
                klass = "not-modbus" if by_default == "none" and not answered else "disputed"
                protocol = "modbus-rtu" if mb == "rtu" else m["protocol"]
            s, c = ("a", "b") if server == (f["a"], f["ap"]) else ("b", "a")
            out.append([cap, m["source"], l4, client[0], client[1], server[0], server[1],
                        "client-server" if f["syn"] == c else "midstream", f[f"packets_{c}"], f[f"packets_{s}"],
                        f[f"octets_{c}"], f[f"octets_{s}"], klass, protocol, f"modbus={mb}; protocol={m['protocol']}",
                        f"default={by_default}; told {l4}/{server[1]}: {len(reqs)} requests, {answered} answered",
                        "yes" if near(f["head_a"]) or near(f["head_b"]) else "no",
                        "client" if f["syn"] == c else "server" if f["syn"] == s else "none",
                        "client" if f["first"] == c else "server"])
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"# P4-4-E2 (D4): the labels of the Modbus signature's corpus, written by corpus_label.py from corpus.tsv and {version}\n")
        fh.write("# One row per flow (D6's label-flow). src and sport name the client, dst and dport the server. syn: which end sent a "
                 "SYN without ACK; first: which end sent the first frame. No payload byte and no host name.\n")
        fh.write("\t".join(COLUMNS) + "\n")
        for r in out:
            fh.write("\t".join(r) + "\n")
    c = collections.Counter(r[12] for r in out)
    print(f"corpus_label: {len(out)} flows: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
    return 0


if __name__ == "__main__":
    sys.exit(label(*sys.argv[1:5], any_tshark="--any-tshark" in sys.argv[5:]))

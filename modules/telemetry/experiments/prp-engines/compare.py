"""Compare per-flow packet counts on PRP -ab and -a captures (E-D4-02).

For each stem, and for each engine, it reads the flows the engine logged
(Zeek conn.log, Suricata eve.json flow events), keyed by the sorted pair
of (address, port) and the transport, and reports:

- flows: how many flows each capture produced (pass: equal);
- packets: for each flow, the engine's packet total on -ab against -a
  (pass: equal for every flow).

Usage: python -I compare.py OUT_DIR  (as run.sh lays it out)
"""
import json
import os
import sys


def zeek(path):
    flows = {}
    log = os.path.join(path, "conn.log")
    if not os.path.exists(log):
        return None
    with open(log, encoding="utf-8") as f:
        for line in f:
            if not line.startswith("{"):
                continue
            r = json.loads(line)
            key = (r.get("proto"),) + tuple(sorted([(r["id.orig_h"], r["id.orig_p"]), (r["id.resp_h"], r["id.resp_p"])]))
            flows[key] = flows.get(key, 0) + (r.get("orig_pkts") or 0) + (r.get("resp_pkts") or 0)
    return flows


def suricata(path):
    flows = {}
    log = os.path.join(path, "eve.json")
    if not os.path.exists(log):
        return None
    with open(log, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("event_type") != "flow":
                continue
            key = (str(r.get("proto", "")).lower(),) + tuple(sorted([(r["src_ip"], r.get("src_port")), (r["dest_ip"], r.get("dest_port"))]))
            fl = r.get("flow", {})
            flows[key] = flows.get(key, 0) + fl.get("pkts_toserver", 0) + fl.get("pkts_toclient", 0)
    return flows


def main(out):
    stems = sorted({d[: -len("-prp-ab")] for d in os.listdir(out) if d.endswith("-prp-ab")})
    print("| capture | engine | flows -a | flows -ab | packets -a | packets -ab | each flow once, counts equal |")
    print("| --- | --- | --- | --- | --- | --- | --- |")
    for s in stems:
        for name, read in (("zeek", zeek), ("suricata", suricata)):
            a = read(os.path.join(out, s + "-prp-a", name))
            ab = read(os.path.join(out, s + "-prp-ab", name))
            if a is None or ab is None:
                print(f"| {s} | {name} | no log | no log | | | not run |")
                continue
            ok = a.keys() == ab.keys() and all(a[k] == ab[k] for k in a)
            print(f"| {s} | {name} | {len(a)} | {len(ab)} | {sum(a.values())} | {sum(ab.values())} | {'yes' if ok else 'no'} |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

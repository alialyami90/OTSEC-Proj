"""Check Zeek and Suricata against ADR-0009's PRP pass condition (E-D4-02).

For each stem and each engine it reads the flows the engine logged on the
-ab capture (both LAN copies) and on the -a capture (LAN A only): Zeek's
conn.log and Suricata's eve.json flow events. A flow is keyed by its
transport and the sorted pair of (address, port). It also reads GT-PCAP's
label file for the stem, written by tshark through D6's prp_check.py.

A row passes only when all of these hold:

- once: each flow has as many records on -ab as on -a;
- packets: each flow's packet total on -ab equals its total on -a;
- service: each flow's service (Zeek `service`, Suricata `app_proto`) on
  -ab equals its service on -a;
- labels: every labelled flow is in the -a output, with the labelled
  packet count, so a flow that both runs drop does not pass.

A row whose logs are missing reads "not run". The script exits 1 if any
row is "not run" or fails, so a missing engine never reads as a pass.

Usage: python -I compare.py OUT_DIR LABEL_DIR  (as run.sh lays them out)
"""
import json
import os
import sys


def add(flows, key, pkts, service):
    f = flows.setdefault(key, {"records": 0, "packets": 0, "services": set()})
    f["records"] += 1
    f["packets"] += pkts
    f["services"].add(service or "-")


def zeek(path):
    log = os.path.join(path, "conn.log")
    if not os.path.exists(log):
        return None
    flows = {}
    with open(log, encoding="utf-8") as f:
        for line in f:
            if not line.startswith("{"):
                continue
            r = json.loads(line)
            key = (r.get("proto"),) + tuple(sorted([(r["id.orig_h"], str(r["id.orig_p"])), (r["id.resp_h"], str(r["id.resp_p"]))]))
            add(flows, key, (r.get("orig_pkts") or 0) + (r.get("resp_pkts") or 0), r.get("service"))
    return flows


def suricata(path):
    log = os.path.join(path, "eve.json")
    if not os.path.exists(log):
        return None
    flows = {}
    with open(log, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("event_type") != "flow":
                continue
            key = (str(r.get("proto", "")).lower(),) + tuple(sorted([(r["src_ip"], str(r.get("src_port"))), (r["dest_ip"], str(r.get("dest_port")))]))
            fl = r.get("flow", {})
            add(flows, key, fl.get("pkts_toserver", 0) + fl.get("pkts_toclient", 0), r.get("app_proto"))
    return flows


def labels(path):
    """Labelled flows: key -> packets in the LAN A only file."""
    if not os.path.exists(path):
        return None
    out = {}
    head = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            cols = line.rstrip("\n").split("\t")
            if head is None:
                head = cols
                continue
            r = dict(zip(head, cols))
            if r["kind"] == "flow":
                key = (r["l4"],) + tuple(sorted([(r["src"], r["sport"]), (r["dst"], r["dport"])]))
                out[key] = int(r["packets"])
    return out


def main(out, label_dir):
    stems = sorted({d[: -len("-prp-ab")] for d in os.listdir(out) if d.endswith("-prp-ab")})
    print("| capture | engine | labelled flows | flows -a | flows -ab | packets -a | packets -ab | once | packets equal | services equal | labels met | pass |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    bad = 0
    for s in stems:
        want = labels(os.path.join(label_dir, s + "-prp-ab.tsv"))
        for name, read in (("zeek", zeek), ("suricata", suricata)):
            a = read(os.path.join(out, s + "-prp-a", name))
            ab = read(os.path.join(out, s + "-prp-ab", name))
            if a is None or ab is None or want is None:
                print(f"| {s} | {name} | {'' if want is None else len(want)} | | | | | | | | | not run |")
                bad += 1
                continue
            same = a.keys() == ab.keys()
            once = same and all(a[k]["records"] == ab[k]["records"] for k in a)
            pkts = same and all(a[k]["packets"] == ab[k]["packets"] for k in a)
            svc = same and all(a[k]["services"] == ab[k]["services"] for k in a)
            met = sum(1 for k, n in want.items() if k in a and a[k]["packets"] == n)
            ok = once and pkts and svc and met == len(want)
            bad += not ok
            yn = lambda v: "yes" if v else "no"
            print(f"| {s} | {name} | {len(want)} | {len(a)} | {len(ab)} | {sum(f['packets'] for f in a.values())} "
                  f"| {sum(f['packets'] for f in ab.values())} | {yn(once)} | {yn(pkts)} | {yn(svc)} | {met} of {len(want)} | {yn(ok)} |")
    print()
    print(f"{bad} row(s) not run or failed." if bad else "Every row passes.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))

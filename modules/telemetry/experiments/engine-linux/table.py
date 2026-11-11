"""E-D4-03's tables (D4, P4-4-S2): what each engine configuration recorded.

The engine logs are never uploaded (they hold capture content), so every
reading of them happens here, in the job, and each result cites the log line
it rests on.

Each configuration's logs are first read into two lists, with no judgement:

- flow records: transport, originator and responder (address, port), and
  the protocol names the engine gave the flow (Zeek conn.log `service`,
  Suricata flow event `app_proto`);
- DNP3 messages: the flow, the sender, request or response, the function
  code and the object headers (g<group>v<variation>), from Zeek dnp3.log
  (requests only, `fc_request` mapped to a code through Zeek's own table,
  and only where a name maps to exactly one code), the probe's
  otsec_probe.log (zeek-probe, every application header in both
  directions), ICSNPP's dnp3_objects.log beside dnp3.log (zeek-icsnpp), or
  Suricata's dnp3 events.

dnp3 mode prints, per configuration:

1. A count per GT-PCAP case against its labels (written by tshark 4.2.2
   through D6's gtlabel.py, never by an engine). No verdict.
2. If D6's pass conditions are present (CONDITIONS below, from brief
   P4-4-R1), each of D6's rows judged as D4 reads D6's note
   `docs/phase4/D6-engine-run-pass-conditions.md`: pass, fail with the
   reason, or unknown, with the log line cited. Without the file, the
   verdict reads "pending D6's pass conditions". This script holds no pass
   condition of its own.

public mode prints, per capture and configuration, the protocol names, the
logs with their row counts and the SNMP field names logged.

Usage: python -I table.py dnp3 OUT GT_DNP3_DIR WORK ROOT
       python -I table.py public OUT
"""
import collections
import json
import os
import re
import sys

CONFIGS = ("zeek", "zeek-probe", "zeek-icsnpp", "suricata", "suricata-midstream")
# D1 on #625: zeek-probe stays a configuration of its own, labelled in every
# table, and its otsec_probe.log is not "the engine's own log files".
LABELS = {
    "zeek": "Zeek, stock",
    "zeek-probe": "Zeek with the project's script (zeek-probe; otsec_probe.log is not the engine's own log)",
    "zeek-icsnpp": "Zeek with ICSNPP",
    "suricata": "Suricata (the comparison, not the choice)",
    "suricata-midstream": "Suricata with stream.midstream=true (the comparison, not the choice)",
}
PENDING = "pending D6's pass conditions"
CONDITIONS = "tests/integration/gt_pcap/engine-pass-conditions.tsv"
RESPONSES = (129, 130, 131)


def lines(path):
    """(line number, record) for each JSON line of a log; [] if absent."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        return [(i, json.loads(l)) for i, l in enumerate(f, 1) if l.startswith("{")]


def ends(a, ap, b, bp):
    return tuple(sorted([(a, str(ap)), (b, str(bp))]))


def code_table(path, const):
    """name -> set of codes, from a Zeek `const NAME = { [0x..] = "..", }`."""
    out = {}
    text = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    m = re.search(r"const\s+" + const + r"\s*=\s*\{(.*?)\}", text, re.S)
    for code, name in re.findall(r'\[0x([0-9A-Fa-f]+)\]\s*=\s*"([^"]+)"', m.group(1) if m else ""):
        out.setdefault(name, set()).add(int(code, 16))
    return out


def ran(d):
    """None if the engine exited 0 on this capture, else why it did not run."""
    try:
        rc = open(os.path.join(d, "exit-code")).read().strip()
    except OSError:
        return "not run"
    return None if rc == "0" else f"not run (exit {rc})"


class Logs:
    """One configuration's records on one capture."""

    def __init__(self, objects_logged):
        self.flows = []  # {"cite", "l4", "orig", "resp", "names"}
        self.msgs = []  # {"cite", "ts", "l4", "ends", "sender", "request", "fc", "objs"}
        self.objects_logged = objects_logged
        self.notes = 0
        self.flow_notes = collections.defaultdict(list)  # (l4, ends) -> ["file:line text"]

    def msg(self, cite, ts, l4, e, sender, request, fc, objs=()):
        self.msgs.append({"cite": cite, "ts": ts, "l4": l4, "ends": e, "sender": sender,
                          "request": request, "fc": fc, "objs": list(objs)})


def zeek(d, cfg, t):
    s = Logs(cfg != "zeek")
    conn = {}
    for i, r in lines(os.path.join(d, "conn.log")):
        o, p = (r["id.orig_h"], str(r["id.orig_p"])), (r["id.resp_h"], str(r["id.resp_p"]))
        conn[r["uid"]] = (r["proto"], o, p)
        s.flows.append({"cite": f"conn.log:{i}", "l4": r["proto"], "orig": o, "resp": p,
                        "names": {x for x in (r.get("service") or "").split(",") if x}})

    def one(name):
        cs = t["zeek_fc"].get(name or "", ())
        return next(iter(cs)) if len(cs) == 1 else None

    # dnp3.log's requests. Its replies are not read: a reply is not a
    # function (D6's note), and dnp3.log stamps it with the request's time.
    # zeek-probe reads every application header from its own log instead.
    for i, r in lines(os.path.join(d, "dnp3.log")):
        if r["uid"] in conn and cfg != "zeek-probe" and one(r.get("fc_request")) is not None:
            l4, o, p = conn[r["uid"]]
            s.msg(f"dnp3.log:{i}", r["ts"], l4, ends(*o, *p), o[0], True, one(r["fc_request"]))
    if cfg == "zeek-probe":
        cur = {}
        for i, r in lines(os.path.join(d, "otsec_probe.log")):
            if r["uid"] not in conn or r["kind"] not in ("fc", "obj"):
                continue
            l4, o, p = conn[r["uid"]]
            side = (r["uid"], r["is_orig"])
            if r["kind"] == "fc":
                s.msg(f"otsec_probe.log:{i}", r["ts"], l4, ends(*o, *p), (o if r["is_orig"] else p)[0],
                      r["fc"] not in RESPONSES, r["fc"])
                cur[side] = s.msgs[-1]
            elif side in cur:
                cur[side]["objs"].append(f"g{r['group']}v{r['variation']}")
                cur[side]["cite"] += f",{i}"
    if cfg == "zeek-icsnpp":
        obj = {n: next(iter(c)) for n, c in t["icsnpp_obj"].items() if len(c) == 1}
        group = {}
        for i, r in lines(os.path.join(d, "dnp3_objects.log")):
            code = obj.get(r.get("object_type"))
            fcs = t["icsnpp_fc"].get(r.get("function_code") or "", ())
            if r["uid"] not in conn or code is None or len(fcs) != 1:
                continue
            l4, o, p = conn[r["uid"]]
            k = (r["uid"], r["is_orig"], r["ts"], r["function_code"])
            if k not in group:
                fc = next(iter(fcs))
                s.msg(f"dnp3_objects.log:{i}", r["ts"], l4, ends(*o, *p), (o if r["is_orig"] else p)[0],
                      fc not in RESPONSES, fc)
                group[k] = s.msgs[-1]
            else:
                group[k]["cite"] += f",{i}"
            group[k]["objs"].append(f"g{code // 256}v{code % 256}")
    for f, field in (("weird.log", "name"), ("analyzer.log", "failure_reason")):
        for i, r in lines(os.path.join(d, f)):
            s.notes += 1
            if r.get("uid") in conn:
                l4, o, p = conn[r["uid"]]
                s.flow_notes[(l4, ends(*o, *p))].append(f"{f}:{i} {r.get(field) or r.get('name') or '?'}")
    s.msgs.sort(key=lambda m: m["ts"])
    return s


def suricata(d):
    s = Logs(True)
    for i, r in lines(os.path.join(d, "eve.json")):
        ev = r.get("event_type")
        l4 = str(r.get("proto", "")).lower()
        o, p = (r.get("src_ip"), str(r.get("src_port"))), (r.get("dest_ip"), str(r.get("dest_port")))
        if ev == "flow":
            s.flows.append({"cite": f"eve.json:{i}", "l4": l4, "orig": o, "resp": p,
                            "names": {r["app_proto"]} if r.get("app_proto") else set()})
        elif ev == "anomaly":
            s.notes += 1
            s.flow_notes[(l4, ends(*o, *p))].append(f"eve.json:{i} {r.get('anomaly', {}).get('event', '?')}")
        elif ev == "dnp3":
            msgs = [r["dnp3"]] if "type" in r["dnp3"] else [v for v in r["dnp3"].values() if isinstance(v, dict)]
            for m in msgs:
                app = m.get("application", {})
                request = m.get("type") == "request"
                s.msg(f"eve.json:{i}", r.get("timestamp", ""), l4, ends(*o, *p), (o if request else p)[0], request,
                      app.get("function_code"), [f"g{x.get('group')}v{x.get('variation')}" for x in app.get("objects", [])])
    return s


def tsv(path):
    head, out = None, []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            cols = line.rstrip("\n").split("\t")
            if head is None:
                head = cols
            else:
                out.append(dict(zip(head, cols)))
    return out


def named(names, proto):
    """The engine named the flow as the labelled protocol (dnp3_tcp, modbus...)."""
    return any(proto in n for n in names)


def assign(rows, msgs, fits):
    """Each row gets a distinct message (D6 on #625): row index -> message.

    A maximum bipartite matching (augmenting paths), so two rows that share
    a flow and a code need two logged messages, and one logged message can
    never satisfy two rows.
    """
    owner = {}  # message index -> row index

    def take(i, seen):
        for k, m in enumerate(msgs):
            if k not in seen and fits(rows[i], m):
                seen.add(k)
                if k not in owner or take(owner[k], seen):
                    owner[k] = i
                    return True
        return False

    for i in range(len(rows)):
        take(i, set())
    return {i: msgs[k] for k, i in owner.items()}


def want_objs(row):
    return set(row["objects"].split(",")) if row["objects"] not in ("", "?") else None


def fits_fn(row, m):
    return (m["request"] and m["l4"] == row["l4"] and m["sender"] == row["src"] and m["fc"] == int(row["code"])
            and m["ends"] == ends(row["src"], row["sport"], row["dst"], row["dport"]))


def fits_obj(row, m):
    return fits_fn(row, m) and want_objs(row) <= set(m["objs"])


def match_functions(rows, s):
    """(function matching, object matching) over one capture's function rows."""
    reqs = [m for m in s.msgs if m["request"]]
    with_objs = [r for r in rows if want_objs(r) is not None]
    by_obj = assign(with_objs, reqs, fits_obj) if s.objects_logged else {}
    return assign(rows, reqs, fits_fn), {id(with_objs[i]): m for i, m in by_obj.items()}


def judge_flow(row, s, proto):
    """A protocol or service row."""
    l4 = row["l4"]
    if row["condition"] == "service":
        for f in s.flows:
            if f["l4"] == l4 and f["resp"] == (row["dst"], row["dport"]) and named(f["names"], proto):
                return "pass", f["cite"]
        return "fail", ""
    e = ends(row["src"], row["sport"], row["dst"], row["dport"])
    recs = [f for f in s.flows if f["l4"] == l4 and ends(*f["orig"], *f["resp"]) == e]
    if not recs:
        return "fail (no flow record)", ""
    if len(recs) > 1:
        return f"fail ({len(recs)} records)", ",".join(f["cite"] for f in recs)
    f = recs[0]
    if not named(f["names"], proto):
        return f"fail (not named {proto})", f["cite"]
    if l4 == "tcp" and f["orig"] != (row["src"], row["sport"]):
        return "fail (originator)", f["cite"]
    return ("pass" if l4 == "tcp" else f"pass (originator {f['orig'][0]})"), f["cite"]


def judge_g120(row, s, others_pass):
    """A g120 row. others_pass: whether this configuration passed every other
    g120 row of the capture (for the row that asks for no group 120 object)."""
    if not s.objects_logged:
        return "fail (no object logged)", ""
    e = ends(row["src"], row["sport"], row["dst"], row["dport"])
    mine = [m for m in s.msgs if m["l4"] == row["l4"] and m["ends"] == e]
    notes = s.flow_notes.get((row["l4"], e), [])
    m = re.match(r"(\d+):(g120v\d+) from (\S+)$", row["show"])
    if m:
        fc, obj, sender = int(m.group(1)), m.group(2), m.group(3)
        exact = [x for x in mine if x["fc"] == fc and x["sender"] == sender and obj in x["objs"]]
        if exact:
            return "pass", exact[0]["cite"]
        same = [x for x in mine if x["fc"] == fc and x["sender"] == sender]
        g = [o for x in same for o in x["objs"] if o.startswith("g120")]
        if g:
            return f"fail (variation: {','.join(g)})", same[0]["cite"]
        if notes:
            # Inferred: the engine wrote a parser note on this flow and shows
            # no such group 120 object. The note's own text is printed so a
            # reader can check it (D6 on #625).
            return f"fail (filler body refused: {'; '.join(notes[:3])})", ",".join(x["cite"] for x in same[:1])
        if same:
            return "fail (message shown, no group 120 object)", same[0]["cite"]
        g120 = [x for x in mine if any(o.startswith("g120") for o in x["objs"])]
        return ("fail (group only)" if g120 else "fail"), (g120[0]["cite"] if g120 else "")
    # "no group 120 object between the request and its response"
    req = [x for x in mine if fits_fn(row, x)]
    if not req:
        return "fail (request not shown)", ""
    a = mine.index(req[0])
    b = next((k for k in range(a + 1, len(mine)) if not mine[k]["request"] and mine[k]["sender"] == row["dst"]), None)
    if b is None:
        return "fail (response not shown)", req[0]["cite"]
    cite = f"{req[0]['cite']}..{mine[b]['cite']}"
    if any(o.startswith("g120") for x in mine[a:b + 1] for o in x["objs"]):
        return "fail (group 120 between)", cite
    if not others_pass:
        return "fail (cannot show group 120)", cite
    return "pass", cite


def evaluate(conds, loaded, protos, cfg):
    """[(row, result, citation)] for every one of D6's rows, in D6's order."""
    out = {}
    by_cap = collections.defaultdict(list)
    for n, row in enumerate(conds):
        by_cap[row["capture"]].append((n, row))
    for cap, rows in by_cap.items():
        s = loaded.get((cfg, cap), "no such capture in dnp3.sha256")
        if isinstance(s, str):
            for n, _ in rows:
                out[n] = (f"unknown ({s})", "")
            continue
        proto = protos.get(cap, "dnp3")
        fn_rows = [r for _, r in rows if r["condition"] == "function"]
        fn, ob = match_functions(fn_rows, s) if proto == "dnp3" else ({}, {})
        pos = {id(r): k for k, r in enumerate(fn_rows)}
        explicit = {}
        for n, row in rows:
            c = row["condition"]
            if c in ("protocol", "service"):
                out[n] = judge_flow(row, s, proto)
            elif proto != "dnp3":
                out[n] = ("unknown (this table reads DNP3 functions only)", "")
            elif c == "function":
                k = pos[id(row)]
                if k not in fn:
                    out[n] = ("fail", "")
                    continue
                if want_objs(row) is None:
                    obj = "objects skipped (?)"
                elif not s.objects_logged:
                    obj = "objects not logged"
                else:
                    hit = ob.get(id(row))
                    obj = f"objects pass {hit['cite']}" if hit else "objects fail"
                out[n] = (f"pass; {obj}", fn[k]["cite"])
            elif c == "g120" and not row["show"].startswith("no group 120"):
                out[n] = explicit[n] = judge_g120(row, s, True)
        others = all(r.startswith("pass") for r, _ in explicit.values()) and bool(explicit)
        for n, row in rows:
            if n not in out:
                out[n] = judge_g120(row, s, others)
    return [(row, *out[n]) for n, row in enumerate(conds)]


def dnp3(out, gt, work, root):
    t = {"zeek_fc": code_table(os.path.join(work, "zeek-dnp3-consts.zeek"), "function_codes")}
    icsnpp = os.path.join(work, "pkgs", "icsnpp-dnp3", "scripts", "consts.zeek")
    t["icsnpp_fc"] = code_table(icsnpp, "function_codes")
    t["icsnpp_obj"] = code_table(icsnpp, "dnp3_objects")
    # A table read wrong would turn into silent "0 of n" cells, so stop.
    if t["zeek_fc"].get("READ") != {1} or t["icsnpp_fc"].get("READ") != {1} or len(t["icsnpp_obj"]) < 50:
        sys.exit("could not read Zeek's or ICSNPP's DNP3 name tables")
    names = [l.split()[1] for l in open(os.path.join(gt, "dnp3.sha256")) if l.strip()]
    cases = sorted(n[: -len(".pcap")] for n in names if n.endswith(".pcap"))
    protos = {}
    for c in cases:
        path = os.path.join(gt, c + ".tsv")
        flows = [r for r in tsv(path) if r["kind"] == "flow"] if os.path.exists(path) else []
        protos[c] = flows[0]["protocol"] if flows else "dnp3"
    cpath = os.path.join(root, CONDITIONS)
    conds = tsv(cpath) if os.path.exists(cpath) else None
    print("# E-D4-03: GT-PCAP DNP3 cases\n")
    print("Generated by `run.sh dnp3`; do not edit by hand. Function names map to codes through Zeek's and ICSNPP's own "
          "`function_codes` tables (each name maps to one code). The engine logs are not uploaded; every citation is "
          "`file:line` in the run's own output for that capture and configuration.\n")
    print("No configuration names a port, an address or a capture: `run.sh`, `in-container.sh` and `probe.zeek` hold none "
          "(D6's rule 8). Content detection, where an engine finds a protocol off its port, comes only from each engine's "
          "stock settings: Zeek's DPD signatures in `base/protocols/dnp3/dpd.sig`, loaded by default; Suricata's stock "
          "`suricata.yaml` with `app-layer.protocols.dnp3.detection-ports` and `modbus.detection-ports` unchanged "
          "(dp 20000 and 502), and the two parsers switched on.\n")
    print("This table treats no function code as critical: it reports the codes that the labels and D6's rows name. "
          "S22 Table D.2 lists write, select, operate, direct operate and direct operate with no reply (codes 2 to 6); "
          "IEEE 1815's own list is not held, so any further code is `unknown`. D6's pass conditions are the authority.\n")
    source = f"`{CONDITIONS}` (D6), as D4 reads `docs/phase4/D6-engine-run-pass-conditions.md`" if conds else PENDING
    print(f"Pass conditions: {source}.\n")
    loaded = {}
    for cfg in CONFIGS:
        for c in cases:
            d = os.path.join(out, c, cfg)
            loaded[(cfg, c)] = ran(d) or (suricata(d) if cfg.startswith("suricata") else zeek(d, cfg, t))
    print("## 1. What each configuration logged, per case\n")
    print("Counts against GT-PCAP's labels. Each labelled function row needs a distinct logged request. `g120 messages` "
          "lists `code:variation from sender` for every message the configuration logged with a group 120 object on a "
          "labelled flow.\n")
    for cfg in CONFIGS:
        print(f"### {cfg}: {LABELS[cfg]}\n")
        print("| case | labelled protocol, transport/port | flows named as labelled | services | request functions | objects | g120 messages | extra request codes | notes |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for c in cases:
            s = loaded[(cfg, c)]
            path = os.path.join(gt, c + ".tsv")
            if isinstance(s, str) or not os.path.exists(path):
                print(f"| {c} | | | | | | | | {s if isinstance(s, str) else 'no label file'} |")
                continue
            lab = collections.defaultdict(list)
            for r in tsv(path):
                lab[r["kind"]].append(r)
            proto = protos[c]
            keys = {(r["l4"], ends(r["src"], r["sport"], r["dst"], r["dport"])) for r in lab["flow"]}
            flows = sum(1 for k in keys if any(f["l4"] == k[0] and ends(*f["orig"], *f["resp"]) == k[1] and named(f["names"], proto) for f in s.flows))
            svc = sum(1 for r in lab["service"] if any(f["l4"] == r["l4"] and f["resp"] == (r["dst"], r["dport"]) and named(f["names"], proto) for f in s.flows))
            ports = sorted({f"{r['l4']}/{r['dport']}" for r in lab["flow"]})
            if proto != "dnp3":
                print(f"| {c} | {proto} {', '.join(ports)} | {flows} of {len(keys)} | {svc} of {len(lab['service'])} "
                      f"| not read | not read | not read | not read | {s.notes} |")
                continue
            fn_rows = lab["function"]
            fn, ob = match_functions(fn_rows, s)
            n_obj = sum(1 for r in fn_rows if want_objs(r) is not None)
            objs = f"{len(ob)} of {n_obj}" if s.objects_logged else "not logged"
            reqs = [m for m in s.msgs if m["request"] and (m["l4"], m["ends"]) in keys]
            g120 = sorted({f"{m['fc']}:{o} from {m['sender']}" for m in s.msgs if (m["l4"], m["ends"]) in keys for o in m["objs"] if o.startswith("g120")})
            extra = sorted({f"{m['fc']} from {m['sender']}" for m in reqs} - {f"{r['code']} from {r['src']}" for r in fn_rows})
            print(f"| {c} | {proto} {', '.join(ports)} | {flows} of {len(keys)} | {svc} of {len(lab['service'])} | {len(fn)} of {len(fn_rows)} | {objs} "
                  f"| {'; '.join(g120) if s.objects_logged else 'not logged'} | {', '.join(extra) or '-'} | {s.notes} |")
        print()
    print("## 2. D6's pass conditions\n")
    if not conds:
        print(f"Verdict: {PENDING}. `{CONDITIONS}` is not in this checkout.")
        return
    print("A capture or configuration that did not run is `unknown`, and `unknown` is counted on its own. Rows that share "
          "a flow and a code are each matched to a distinct logged request. The g120 row \"no group 120 object between "
          "the request and its response\" passes only if the same configuration passes the capture's other g120 rows "
          "(D6's note: \"in the same session that holds the challenged and the aggressive operate\"); that reading is D4's. "
          "`fail (filler body refused)` is inferred: the engine shows no such group 120 object and wrote a parser note on "
          "the same flow, whose text is printed beside it. Every condition is reported for each configuration, so each "
          "reads three ways for Zeek: stock, with ICSNPP, and with the project's script. Only the first two are the "
          "engine's own log files (D1 on #625).\n")
    for cfg in CONFIGS:
        res = evaluate(conds, loaded, protos, cfg)
        print(f"### {cfg}: {LABELS[cfg]}\n")
        col = collections.OrderedDict()
        for row, r, _ in res:
            v = "unknown" if r.startswith("unknown") else "pass" if r.startswith("pass") else "fail"
            ks = [(row["condition"], v)]
            if row["condition"] in ("protocol", "service", "function"):
                ks += [(x, v) for x, hit in (("moved port", "moved-port" in row["capture"]), ("udp", row["capture"].endswith("-udp"))) if hit]
            if row["condition"] == "function" and want_objs(row) is not None:
                ks.append(("objects", "pass" if "objects pass" in r else "unknown" if v == "unknown" else "fail"))
            for k, x in ks:
                col.setdefault(k, collections.Counter())[x] += 1
        print("Columns: " + "; ".join(f"{k} {c['pass']} pass, {c['fail']} fail, {c['unknown']} unknown, of {sum(c.values())}"
                                     for k, c in col.items()) + ".\n")
        print("| capture | condition | src | dst | code | objects | show | result | cited |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for row, r, cite in res:
            print(f"| {row['capture']} | {row['condition']} | {row['src']}:{row['sport']} | {row['dst']}:{row['dport']}/{row['l4']} "
                  f"| {row['code']} | {row['objects']} | {row['show']} | {r} | {cite} |")
        print()


def public(out):
    print("# E-D4-03: public captures\n")
    print("What each configuration logged. MANIFEST.tsv's captures carry no GT-PCAP label; their tshark reading is E-A4-01's "
          "(`ids-coverage/results/coverage.md`, tshark 4.2.2, same SHA-256s). The extra captures carry none. No pass "
          "condition reads this table (D6's note, section 6). Generated by `run.sh public`; do not edit by hand.\n")
    print("| capture | config | protocol names (flows) | logs (rows) | SNMP fields logged | notes |")
    print("| --- | --- | --- | --- | --- | --- |")
    for name in sorted(os.listdir(out)):
        for cfg in CONFIGS:
            d = os.path.join(out, name, cfg)
            why = ran(d)
            if why:
                print(f"| {name} | {LABELS[cfg]} | | | | {why} |")
                continue
            svc, logs, snmp, notes = collections.Counter(), {}, set(), 0
            if cfg.startswith("suricata"):
                for _, r in lines(os.path.join(d, "eve.json")):
                    ev = r.get("event_type")
                    if ev == "flow":
                        svc[r.get("app_proto") or "none"] += 1
                    elif ev != "stats":
                        logs[ev] = logs.get(ev, 0) + 1
                    notes += ev == "anomaly"
                    if ev == "snmp":
                        snmp.update(r["snmp"].keys())
            else:
                for f in sorted(os.listdir(d)):
                    if not f.endswith(".log") or f in ("packet_filter.log", "loaded_scripts.log", "reporter.log"):
                        continue
                    rs = [r for _, r in lines(os.path.join(d, f))]
                    if f == "conn.log":
                        svc.update(r.get("service") or "-" for r in rs)
                        continue
                    logs[f[:-4]] = len(rs)
                    if f in ("weird.log", "analyzer.log"):
                        notes += len(rs)
                    if f == "snmp.log":
                        snmp.update(k for r in rs for k in r)
                    if f == "otsec_probe.log":
                        snmp.update(f"probe:{k}" for r in rs if r.get("kind") == "snmp" for k in r if k.startswith(("snmp_", "v3_")))
                        snmp.update(f"probe event:{r['ev']}" for r in rs if r.get("kind") == "snmp")
            fmt = lambda c: ", ".join(f"{k}={v}" for k, v in sorted(c.items())) or "-"
            print(f"| {name} | {LABELS[cfg]} | {fmt(svc)} | {fmt(logs)} | {', '.join(sorted(snmp)) or '-'} | {notes} |")


if __name__ == "__main__":
    if sys.argv[1] == "dnp3":
        dnp3(*sys.argv[2:6])
    else:
        public(sys.argv[2])

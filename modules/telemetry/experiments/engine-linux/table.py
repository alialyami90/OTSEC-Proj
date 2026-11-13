"""E-D4-03's tables (D4, P4-4-S2): what each engine configuration recorded.

The engine logs are never uploaded (they hold capture content), so every
reading of them happens here, in the job, and each result cites the log line
it rests on.

Each configuration's logs are first read into two lists, with no judgement:

- flow records: transport, originator and responder (address, port), and
  the protocol names the engine gave the flow (Zeek conn.log `service`,
  Suricata flow event `app_proto`);
- messages, DNP3 and Modbus: the flow, the protocol, the sender, request or
  response, the function code and, for DNP3, the object headers
  (g<group>v<variation>). From Zeek dnp3.log (requests only, `fc_request`)
  and modbus.log (`func` where `pdu_type` is REQ), each name mapped to a
  code through Zeek's own `function_codes` table and only where it maps to
  exactly one code (D6's rule 7); the probe's otsec_probe.log (zeek-probe,
  every DNP3 application header in both directions); ICSNPP's
  dnp3_objects.log beside dnp3.log (zeek-icsnpp); or Suricata's dnp3 and
  modbus events (`function_code`, `function_raw`).

dnp3 mode prints, per configuration:

1. A count per GT-PCAP case against its labels (written by tshark 4.2.2
   through D6's gtlabel.py and modbus_label.py, never by an engine).
2. If D6's pass conditions are present (CONDITIONS below), each of D6's
   rows judged as D4 reads `docs/phase4/D6-engine-run-pass-conditions.md`:
   pass, fail with the reason, or unknown, with the log line cited. Without
   the file, the verdict reads "pending D6's pass conditions". This script
   holds no pass condition of its own. Which function applies which of
   D6's rules is in each function's docstring.

public mode prints, per capture and configuration, the protocol names, the
logs with their row counts and the SNMP field names logged.

sig mode (P4-4-E2) judges every row of D6's conditions for the Modbus
signature (modbus-signature-conditions.tsv) on S0 beside S1, from the
corpus's committed labels, D6's engine-pass-conditions.tsv and the held-out
labels modbus_label.py writes in the run (`sig` below).

Usage: python -I table.py dnp3 OUT GT_PCAP_DIR WORK ROOT   (pipe runs in OUT-pipe)
       python -I table.py fifo OUT OUT-pipe
       python -I table.py public OUT
       python -I table.py sig SIG_DIR ROOT WORK
"""
import collections
import glob
import json
import os
import re
import sys

CONFIGS = ("zeek", "zeek-probe", "zeek-icsnpp", "zeek-modbus-sig", "suricata", "suricata-midstream")
# D1 on #625 and D6's rule 8: zeek-probe is a configuration of its own,
# labelled in every table, and its otsec_probe.log is not "the engine's own
# log files". zeek-modbus-sig (P4-4-E2) is zeek-probe with the Modbus
# signature added, an experiment that is not adopted.
LABELS = {
    "zeek": "Zeek, stock",
    "zeek-probe": "Zeek with the project's script (zeek-probe; otsec_probe.log is not the engine's own log)",
    "zeek-icsnpp": "Zeek with ICSNPP",
    "zeek-modbus-sig": "Zeek with the project's script and the Modbus signature (zeek-modbus-sig; P4-4-E2's experiment, not adopted)",
    "suricata": "Suricata (the comparison, not the choice)",
    "suricata-midstream": "Suricata with stream.midstream=true (the comparison, not the choice)",
}
# The configurations that load probe.zeek, so read otsec_probe.log.
PROBED = ("zeek-probe", "zeek-modbus-sig")
PENDING = "pending D6's pass conditions"
# The pipe case (D4-87): these configurations also read each capture from a pipe.
PIPED = ("zeek", "zeek-probe", "zeek-icsnpp")
CONDITIONS = "tests/integration/gt_pcap/engine-pass-conditions.tsv"
RESPONSES = (129, 130, 131)
# modbus-moved-port is modbus.pcap with port 502 moved to 15020
# (movedport.py's defaults); modbus.pcap is its control (D6's note, section 3).
MOVED, CONTROL, MOVED_PORT, CONTROL_PORT = "modbus-moved-port", "modbus", "15020", "502"


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


def one(table, name):
    """D6's rule 7: a name counts only if it maps to exactly one code."""
    cs = table.get(name or "", ())
    return next(iter(cs)) if len(cs) == 1 else None


def ran(d):
    """None if the engine exited 0 on this capture, else why it did not run
    (an exit code, or `skipped` after an earlier time-out)."""
    try:
        rc = open(os.path.join(d, "exit-code")).read().strip()
    except OSError:
        return "not run"
    return None if rc == "0" else f"not run (exit {rc})"


class Logs:
    """One configuration's records on one capture."""

    def __init__(self, objects_logged):
        self.flows = []  # {"cite", "l4", "orig", "resp", "names"}
        self.msgs = []  # {"cite", "ts", "proto", "l4", "ends", "sender", "request", "fc", "objs"}
        self.objects_logged = objects_logged
        self.notes = 0
        self.flow_notes = collections.defaultdict(list)  # (l4, ends) -> ["file:line text"]

    def in_content_order(self):
        """Puts flows and messages in an order taken from their own content,
        never from their line in a log, whose order the engine does not fix
        (D6 and D1 on #630). Every place the judge takes the first record
        that satisfies a row (a Service row's flow, rule 6's wrong server, a
        Protocol row's records, a group 120 message, rule 9's matching) then
        takes the same record from the file run and from the pipe run.
        Flows: start time, transport, ends, then the engine's own id (Zeek's
        uid, Suricata's flow_id). Messages: time, protocol, transport, ends,
        a request before a response at the same time, sender, code, objects."""
        self.flows.sort(key=lambda f: (f["first"][0], f["l4"], f["orig"], f["resp"], f["first"][1]))
        self.msgs.sort(key=lambda m: (m["ts"], m["proto"], m["l4"], m["ends"], not m["request"], str(m["sender"]),
                                      str(m["fc"]), tuple(m["objs"])))

    def msg(self, cite, ts, proto, l4, e, sender, request, fc, objs=()):
        self.msgs.append({"cite": cite, "ts": ts, "proto": proto, "l4": l4, "ends": e, "sender": sender,
                          "request": request, "fc": fc, "objs": list(objs)})


def zeek(d, cfg, t):
    s = Logs(cfg != "zeek")
    conn = {}
    for i, r in lines(os.path.join(d, "conn.log")):
        o, p = (r["id.orig_h"], str(r["id.orig_p"])), (r["id.resp_h"], str(r["id.resp_p"]))
        conn[r["uid"]] = (r["proto"], o, p)
        s.flows.append({"cite": f"conn.log:{i}", "l4": r["proto"], "orig": o, "resp": p, "first": (r["ts"], r["uid"]),
                        "names": {x for x in (r.get("service") or "").split(",") if x}})
    # dnp3.log's requests. Its replies are not read: a reply is not a
    # function (D6's note), and dnp3.log stamps it with the request's time.
    # zeek-probe reads every DNP3 application header from its own log instead.
    dnp3_rows = collections.defaultdict(list)  # uid -> [(ts, code, message)], in log order
    for i, r in lines(os.path.join(d, "dnp3.log")):
        fc = one(t["zeek_fc"], r.get("fc_request"))
        if r["uid"] in conn and cfg not in PROBED and fc is not None:
            l4, o, p = conn[r["uid"]]
            s.msg(f"dnp3.log:{i}", r["ts"], "dnp3", l4, ends(*o, *p), o[0], True, fc)
            dnp3_rows[r["uid"]].append((r["ts"], fc, s.msgs[-1]))
    for i, r in lines(os.path.join(d, "modbus.log")):
        fc = one(t["zeek_modbus_fc"], r.get("func"))
        if r["uid"] in conn and r.get("pdu_type") == "REQ" and fc is not None:
            l4, o, p = conn[r["uid"]]
            s.msg(f"modbus.log:{i}", r["ts"], "modbus", l4, ends(*o, *p), o[0], True, fc)
    if cfg in PROBED:
        cur = {}
        for i, r in lines(os.path.join(d, "otsec_probe.log")):
            if r["uid"] not in conn or r["kind"] not in ("fc", "obj"):
                continue
            l4, o, p = conn[r["uid"]]
            side = (r["uid"], r["is_orig"])
            if r["kind"] == "fc":
                s.msg(f"otsec_probe.log:{i}", r["ts"], "dnp3", l4, ends(*o, *p), (o if r["is_orig"] else p)[0],
                      r["fc"] not in RESPONSES, r["fc"])
                cur[side] = s.msgs[-1]
            elif side in cur:
                cur[side]["objs"].append(f"g{r['group']}v{r['variation']}")
                cur[side]["cite"] += f",{i}"
    if cfg == "zeek-icsnpp":
        # ICSNPP's two logs. dnp3_objects.log: object headers of READ requests
        # and RESPONSE replies, named through ICSNPP's dnp3_objects table.
        # dnp3_control.log: one row per control block, which Zeek raises as
        # dnp3_crob (group 12 variation 1) or dnp3_pcb (group 12 variation 2)
        # (events.bif at v9.0.1), named in `block_type`. ICSNPP stamps a row
        # with its message's arrival, so the rows of one message share
        # (uid, is_orig, ts, function_code) and form one message here.
        obj = {n: next(iter(c)) for n, c in t["icsnpp_obj"].items() if len(c) == 1}
        blocks = {"Control Relay Output Block": 0x0C01, "Pattern Control Block": 0x0C02}
        group = {}
        for log, code_of in (("dnp3_objects.log", lambda r: obj.get(r.get("object_type"))),
                             ("dnp3_control.log", lambda r: blocks.get(r.get("block_type")))):
            for i, r in lines(os.path.join(d, log)):
                code = code_of(r)
                fc = one(t["icsnpp_fc"], r.get("function_code"))
                if r["uid"] not in conn or code is None or fc is None or r.get("is_orig") is None:
                    continue
                l4, o, p = conn[r["uid"]]
                k = (r["uid"], r["is_orig"], r["ts"], r["function_code"])
                if k not in group:
                    s.msg(f"{log}:{i}", r["ts"], "dnp3", l4, ends(*o, *p), (o if r["is_orig"] else p)[0],
                          fc not in RESPONSES, fc)
                    group[k] = s.msgs[-1]
                    group[k]["rows"] = []
                else:
                    group[k]["cite"] += f",{log}:{i}"
                group[k]["objs"].append(f"g{code // 256}v{code % 256}")
                group[k]["rows"].append(f"{log}:{i}")
        # The join (D6 on #630). Zeek writes a dnp3.log row for the last request
        # before its reply, stamped with the reply's time when it is answered
        # (base/protocols/dnp3/main.zeek at v9.0.1). So an ICSNPP request
        # message is that row's request when it is on the same connection,
        # with the same code, and the latest such message after the
        # connection's previous dnp3.log row and not after this one. It then
        # joins that row: one request, one message, citing both logs, at the
        # request's own time. Every other ICSNPP message stays its own.
        for (uid, is_orig, ts, _), g in list(group.items()):
            g["uid"], g["is_orig"], g["gts"] = uid, is_orig, ts
        removed = set()
        for uid, rows in dnp3_rows.items():
            prev = None
            for ts, fc, m in rows:
                cands = [g for g in group.values() if g["uid"] == uid and g["is_orig"] and g["fc"] == fc
                         and g["gts"] <= ts and (prev is None or g["gts"] > prev) and id(g) not in removed]
                prev = ts
                if not cands:
                    continue
                g = max(cands, key=lambda x: x["gts"])
                m["objs"] += g["objs"]
                m["cite"] += "," + g["cite"]
                m["ts"] = g["gts"]
                m.setdefault("rows", []).extend(g["rows"])
                removed.add(id(g))
        s.msgs = [x for x in s.msgs if id(x) not in removed]
        # Self-check: every ICSNPP row of a request is in exactly one message,
        # and that message is a request; otherwise the table is not written.
        held = collections.Counter(row for x in s.msgs if x["request"] for row in x.get("rows", []))
        for g in group.values():
            for row in g["rows"] if g["is_orig"] else ():
                if held[row] != 1:
                    sys.exit(f"ICSNPP join: {row} under {d} is in {held[row]} request messages, not one")
    for f, field in (("weird.log", "name"), ("analyzer.log", "failure_reason")):
        for i, r in lines(os.path.join(d, f)):
            s.notes += 1
            if r.get("uid") in conn:
                l4, o, p = conn[r["uid"]]
                s.flow_notes[(l4, ends(*o, *p))].append(f"{f}:{i} {r.get(field) or r.get('name') or '?'}")
    s.in_content_order()
    return s


def suricata(d):
    """Suricata's eve.json. An app-layer event (dnp3, modbus) is tied to its
    flow record by `flow_id` (D6's rule 2), and its sender is the flow
    record's originator for a request and its responder for a response, never
    the event's own source fields (D6 on #625). An event whose flow record is
    missing has no sender, so it can pass no row."""
    s = Logs(True)
    rows = lines(os.path.join(d, "eve.json"))
    flow_of = {}
    for i, r in rows:
        if r.get("event_type") == "flow" and r.get("flow_id") is not None:
            o, p = (r.get("src_ip"), str(r.get("src_port"))), (r.get("dest_ip"), str(r.get("dest_port")))
            flow_of[r.get("flow_id")] = (o, p)

    def sender(r, request):
        f = flow_of.get(r.get("flow_id")) if r.get("flow_id") is not None else None
        return (f[0] if request else f[1])[0] if f else None

    for i, r in rows:
        ev = r.get("event_type")
        l4 = str(r.get("proto", "")).lower()
        o, p = (r.get("src_ip"), str(r.get("src_port"))), (r.get("dest_ip"), str(r.get("dest_port")))
        if ev == "flow":
            s.flows.append({"cite": f"eve.json:{i}", "l4": l4, "orig": o, "resp": p,
                            "first": (str(r.get("flow", {}).get("start", "")), str(r.get("flow_id"))),
                            "names": {r["app_proto"]} if r.get("app_proto") else set()})
        elif ev == "anomaly":
            s.notes += 1
            s.flow_notes[(l4, ends(*o, *p))].append(f"eve.json:{i} {r.get('anomaly', {}).get('event', '?')}")
        elif ev == "dnp3":
            msgs = [r["dnp3"]] if "type" in r["dnp3"] else [v for v in r["dnp3"].values() if isinstance(v, dict)]
            for m in msgs:
                app = m.get("application", {})
                request = m.get("type") == "request"
                s.msg(f"eve.json:{i}", r.get("timestamp", ""), "dnp3", l4, ends(*o, *p), sender(r, request), request,
                      app.get("function_code"), [f"g{x.get('group')}v{x.get('variation')}" for x in app.get("objects", [])])
        elif ev == "modbus" and isinstance(r["modbus"].get("request"), dict):
            s.msg(f"eve.json:{i}", r.get("timestamp", ""), "modbus", l4, ends(*o, *p), sender(r, True), True,
                  r["modbus"]["request"].get("function_raw"))
    s.in_content_order()
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
    """D6's rule 9: rows matched one to one with logged messages.

    A maximum bipartite matching (augmenting paths): each row gets a distinct
    message, one message never serves two rows, and rows left without one
    fail. Returns row index -> message.
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
    return set(row["objects"].split(",")) if row.get("objects") not in (None, "", "?") else None


def fits_fn(row, m):
    """A request of the row's protocol and code, from the row's src, on its flow."""
    return (m["request"] and m["proto"] == (row.get("protocol") or "dnp3") and m["l4"] == row["l4"]
            and m["sender"] == row["src"] and m["fc"] == int(row["code"])
            and m["ends"] == ends(row["src"], row["sport"], row["dst"], row["dport"]))


def fits_obj(row, m):
    return fits_fn(row, m) and want_objs(row) <= set(m["objs"])


def match_functions(rows, s):
    """D6's rule 9 for Function and for Objects: (function matching, object
    matching keyed by id(row)) over one capture's function rows."""
    reqs = [m for m in s.msgs if m["request"]]
    with_objs = [r for r in rows if want_objs(r) is not None]
    by_obj = assign(with_objs, reqs, fits_obj) if s.objects_logged else {}
    return assign(rows, reqs, fits_fn), {id(with_objs[i]): m for i, m in by_obj.items()}


def judge_flow(row, s, flow_rows):
    """Protocol and Service rows (D6's note, section 2, and rule 6).

    Protocol: one flow record with the row's transport and both ends, named
    as the row's `protocol`; where `direction` is client-server its
    originator is the row's src, and where it is `none` or `midstream`
    either orientation passes and the result says which. Two records fail.
    Service: the protocol attributed to the server end the row names, and
    to no end of a labelled flow that the labels do not name as its server
    (rule 6); flow_rows are the capture's protocol rows.
    """
    l4, proto = row["l4"], (row.get("protocol") or "dnp3")
    if row["condition"] == "service":
        servers = {(r["dst"], r["dport"]) for r in flow_rows if r["l4"] == l4}
        others = {(r["src"], r["sport"]) for r in flow_rows if r["l4"] == l4} - servers
        wrong = [f for f in s.flows if f["l4"] == l4 and f["resp"] in others and named(f["names"], proto)]
        if wrong:
            f = wrong[0]
            return f"fail (service also at {f['resp'][0]} {l4}/{f['resp'][1]})", f["cite"]
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
    if (row.get("direction") or "client-server") == "client-server":
        if f["orig"] != (row["src"], row["sport"]):
            return "fail (originator)", f["cite"]
        return "pass", f["cite"]
    return f"pass (originator {f['orig'][0]})", f["cite"]


def judge_g120(row, s, others_pass):
    """Group 120 rows (D6's note, section 2, "Group 120 per session").

    A row whose `show` names a message passes when a record tied to the flow
    carries that function code, that sender and that group 120 variation.
    The row that asks for no group 120 object passes only when the
    configuration shows the request and its response with no group 120
    object between them and passes every other g120 row of the capture
    (others_pass); it fails on a group 120 object between them, and is
    `unknown` in every other case. A parser note on the flow is appended to
    the observed reason, with "filler body refused" marked as D4's inference.
    """
    e = ends(row["src"], row["sport"], row["dst"], row["dport"])
    mine = [m for m in s.msgs if m["l4"] == row["l4"] and m["ends"] == e]
    notes = s.flow_notes.get((row["l4"], e), [])
    noted = (f"; parser notes on this flow: {'; '.join(notes[:3])} (filler body refused? D4's inference)"
             if notes else "")
    m = re.match(r"(\d+):(g120v\d+) from (\S+)$", row["show"])
    if m:
        if not s.objects_logged:
            return "fail (no object logged)", ""
        fc, obj, sender = int(m.group(1)), m.group(2), m.group(3)
        exact = [x for x in mine if x["fc"] == fc and x["sender"] == sender and obj in x["objs"]]
        if exact:
            return "pass", exact[0]["cite"]
        same = [x for x in mine if x["fc"] == fc and x["sender"] == sender]
        g = [o for x in same for o in x["objs"] if o.startswith("g120")]
        if g:
            return f"fail (variation: {','.join(g)}){noted}", same[0]["cite"]
        if same:
            return f"fail (message shown, no group 120 object){noted}", same[0]["cite"]
        g120 = [x for x in mine if any(o.startswith("g120") for o in x["objs"])]
        return (f"fail (group only){noted}" if g120 else f"fail{noted}"), (g120[0]["cite"] if g120 else "")
    # "no group 120 object between the request and its response"
    if not s.objects_logged:
        return "unknown (no object logged)", ""
    req = [x for x in mine if fits_fn(row, x)]
    if not req:
        return "unknown (request not shown)", ""
    a = mine.index(req[0])
    b = next((k for k in range(a + 1, len(mine)) if not mine[k]["request"] and mine[k]["sender"] == row["dst"]), None)
    if b is None:
        return "unknown (response not shown)", req[0]["cite"]
    cite = f"{req[0]['cite']}..{mine[b]['cite']}"
    if any(o.startswith("g120") for x in mine[a:b + 1] for o in x["objs"]):
        return "fail (group 120 between)", cite
    if not others_pass:
        return "unknown (the capture's other group 120 rows do not all pass)", cite
    return "pass", cite


def judge_capture(rows, s):
    """{index: (result, citation)} for one capture's rows under one
    configuration: Protocol and Service by judge_flow, Function and Objects
    by match_functions (rule 9), group 120 by judge_g120."""
    out = {}
    flow_rows = [r for _, r in rows if r["condition"] == "protocol"]
    fn_rows = [r for _, r in rows if r["condition"] == "function"]
    pos = {id(r): k for k, r in enumerate(fn_rows)}
    fn, ob = match_functions(fn_rows, s)
    explicit = {}
    for n, row in rows:
        c = row["condition"]
        if c in ("protocol", "service"):
            out[n] = judge_flow(row, s, flow_rows)
        elif c == "function":
            k = pos[id(row)]
            if k not in fn:
                orphan = [m for m in s.msgs if m["sender"] is None and m["request"] and m["l4"] == row["l4"]
                          and m["fc"] == int(row["code"]) and m["ends"] == ends(row["src"], row["sport"], row["dst"], row["dport"])]
                out[n] = ("fail (event has no flow record)", orphan[0]["cite"]) if orphan else ("fail", "")
                continue
            if want_objs(row) is None:
                obj = "objects skipped (? or none labelled)"
            elif not s.objects_logged:
                obj = "objects not logged"
            else:
                hit = ob.get(id(row))
                obj = f"objects pass {hit['cite']}" if hit else "objects fail"
            out[n] = (f"pass; {obj}", fn[k]["cite"])
        elif c == "g120" and not row["show"].startswith("no group 120"):
            out[n] = explicit[n] = judge_g120(row, s, True)
    others = bool(explicit) and all(r == "pass" for r, _ in explicit.values())
    for n, row in rows:
        if n not in out:
            out[n] = judge_g120(row, s, others)
    return out


def to_control(row):
    r = dict(row, capture=CONTROL)
    for k in ("sport", "dport"):
        if r.get(k) == MOVED_PORT:
            r[k] = CONTROL_PORT
    return r


def evaluate(conds, loaded, cfg):
    """[(row, result, citation)] for every one of D6's rows, in D6's order.
    The moved Modbus capture's rows are also judged on its control, modbus.pcap
    on port 502, and a row that fails on both reads `fail (also fails on port
    502)` (D6's note, section 3)."""
    out = {}
    by_cap = collections.defaultdict(list)
    for n, row in enumerate(conds):
        by_cap[row["capture"]].append((n, row))
    for cap, rows in by_cap.items():
        s = loaded.get((cfg, cap), "no such capture in the run")
        if isinstance(s, str):
            out.update({n: (f"unknown ({s})", "") for n, _ in rows})
            continue
        res = judge_capture(rows, s)
        if cap == MOVED:
            c = loaded.get((cfg, CONTROL), "not run")
            ctl = (judge_capture([(n, to_control(r)) for n, r in rows], c) if not isinstance(c, str)
                   else {n: (f"unknown ({c})", "") for n, _ in rows})
            for n, _ in rows:
                r, cite = res[n]
                cr, ccite = ctl[n]
                if r.startswith("fail") and cr.startswith("fail"):
                    r = "fail (also fails on port 502)"
                res[n] = (f"{r}; control on port 502: {cr} {ccite}".rstrip(), cite)
        out.update(res)
    return [(row, *out[n]) for n, row in enumerate(conds)]


def dnp3(out, gt, work, root):
    t = {"zeek_fc": code_table(os.path.join(work, "zeek-dnp3-consts.zeek"), "function_codes"),
         "zeek_modbus_fc": code_table(os.path.join(work, "zeek-modbus-consts.zeek"), "function_codes")}
    icsnpp = os.path.join(work, "pkgs", "icsnpp-dnp3", "scripts", "consts.zeek")
    t["icsnpp_fc"] = code_table(icsnpp, "function_codes")
    t["icsnpp_obj"] = code_table(icsnpp, "dnp3_objects")
    # A table read wrong would turn into silent "0 of n" cells, so stop.
    if (t["zeek_fc"].get("READ") != {1} or t["icsnpp_fc"].get("READ") != {1} or len(t["icsnpp_obj"]) < 50
            or t["zeek_modbus_fc"].get("READ_HOLDING_REGISTERS") != {3}):
        sys.exit("could not read Zeek's or ICSNPP's name tables")
    labdir = {}
    for sums in sorted(glob.glob(os.path.join(gt, "*", "*.sha256"))):
        for l in open(sums):
            if l.strip() and l.split()[1].endswith(".pcap"):
                labdir[l.split()[1][: -len(".pcap")]] = os.path.dirname(sums)
    cases = sorted(labdir)
    cpath = os.path.join(root, CONDITIONS)
    conds = tsv(cpath) if os.path.exists(cpath) else None
    print("# E-D4-03: GT-PCAP cases\n")
    print("Generated by `run.sh dnp3`; do not edit by hand. Function names map to codes through Zeek's and ICSNPP's own "
          "`function_codes` tables, only where a name maps to one code (D6's rule 7); Suricata logs the codes. The engine "
          "logs are not uploaded; every citation is `file:line` in the run's own output for that capture and configuration.\n")
    print("No configuration names a port, an address or a capture: `run.sh`, `in-container.sh`, `probe.zeek` and "
          "`modbus-sig.zeek` hold none (D6's rule 8). Content detection, where an engine finds a protocol off its port, "
          "comes from each engine's stock settings: Zeek's DPD signatures in `base/protocols/dnp3/dpd.sig`, loaded by "
          "default (Zeek's Modbus has none); Suricata's stock `suricata.yaml` with "
          "`app-layer.protocols.dnp3.detection-ports` and `modbus.detection-ports` unchanged (dp 20000 and 502), and the "
          "two parsers switched on. In `zeek-modbus-sig` only, it also comes from the project's Modbus/TCP signature "
          "(`modbus-sig.sig`, P4-4-E2's experiment), which names no port.\n")
    print("This table classes no function as critical: it reports the codes that the labels and D6's rows name, and D6's "
          "note (section 2, \"Which functions are critical\") is the authority. S22 Table D.2 lists codes 2 to 6; IEEE "
          "1815's own list is not held.\n")
    source = f"`{CONDITIONS}` (D6), as D4 reads `docs/phase4/D6-engine-run-pass-conditions.md`" if conds else PENDING
    print(f"Pass conditions: {source}.\n")
    loaded = {}
    for cfg in CONFIGS:
        for c in cases + [CONTROL]:
            d = os.path.join(out, c, cfg)
            loaded[(cfg, c)] = ran(d) or (suricata(d) if cfg.startswith("suricata") else zeek(d, cfg, t))
    for cfg in PIPED:
        for c in cases + [CONTROL]:
            d = os.path.join(out + "-pipe", c, cfg + "-pipe")
            loaded[(cfg + "-pipe", c)] = ran(d) or zeek(d, cfg, t)
    print("## 1. What each configuration logged, per case\n")
    print("Counts against GT-PCAP's labels. Each labelled function row needs a distinct logged request (rule 9). "
          "`g120 messages` lists `code:variation from sender` for every DNP3 message the configuration logged with a "
          "group 120 object on a labelled flow.\n")
    for cfg in CONFIGS:
        print(f"### {cfg}: {LABELS[cfg]}\n")
        print("| case | labelled protocol, transport/port | flows named as labelled | services | request functions | objects | g120 messages | extra request codes | notes |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for c in cases:
            s = loaded[(cfg, c)]
            path = os.path.join(labdir[c], c + ".tsv")
            if isinstance(s, str) or not os.path.exists(path):
                print(f"| {c} | | | | | | | | {s if isinstance(s, str) else 'no label file'} |")
                continue
            lab = collections.defaultdict(list)
            for r in tsv(path):
                lab[r["kind"]].append(r)
            proto = lab["flow"][0]["protocol"] if lab["flow"] else "dnp3"
            keys = {(r["l4"], ends(r["src"], r["sport"], r["dst"], r["dport"])) for r in lab["flow"]}
            flows = sum(1 for k in keys if any(f["l4"] == k[0] and ends(*f["orig"], *f["resp"]) == k[1] and named(f["names"], proto) for f in s.flows))
            svc = sum(1 for r in lab["service"] if any(f["l4"] == r["l4"] and f["resp"] == (r["dst"], r["dport"]) and named(f["names"], proto) for f in s.flows))
            ports = sorted({f"{r['l4']}/{r['dport']}" for r in lab["flow"]})
            fn_rows = lab["function"]
            fn, ob = match_functions(fn_rows, s)
            n_obj = sum(1 for r in fn_rows if want_objs(r) is not None)
            dnp = proto == "dnp3"
            objs = f"{len(ob)} of {n_obj}" if dnp and s.objects_logged else "not logged" if dnp else "-"
            reqs = [m for m in s.msgs if m["request"] and m["proto"] == proto and (m["l4"], m["ends"]) in keys]
            g120 = sorted({f"{m['fc']}:{o} from {m['sender']}" for m in s.msgs if (m["l4"], m["ends"]) in keys for o in m["objs"] if o.startswith("g120")})
            extra = sorted({f"{m['fc']} from {m['sender']}" for m in reqs} - {f"{r['code']} from {r['src']}" for r in fn_rows})
            print(f"| {c} | {proto} {', '.join(ports)} | {flows} of {len(keys)} | {svc} of {len(lab['service'])} | {len(fn)} of {len(fn_rows)} | {objs} "
                  f"| {('; '.join(g120) or 'none') if dnp and s.objects_logged else 'not logged' if dnp else '-'} | {', '.join(extra) or '-'} | {s.notes} |")
        print()
    print("## 2. D6's pass conditions\n")
    if not conds:
        print(f"Verdict: {PENDING}. `{CONDITIONS}` is not in this checkout.")
        pipe_case(conds, loaded, cases)
        return
    print("Each row is `pass`, `fail` or `unknown`, and each column counts the three apart. A capture or configuration "
          "that did not run is `unknown`. Rows that share a capture, a flow and a code are matched one to one with logged "
          "requests (rule 9). A service at the other end of a labelled flow fails that flow's Service row (rule 6). The "
          "row that asks for no group 120 object passes only with the capture's other group 120 rows, fails on a group "
          "120 object, and is otherwise `unknown`. A parser note on a group 120 row's flow is appended to the observed "
          "reason; reading it as a filler body refused is D4's inference. `modbus-moved-port` rows carry their control, "
          "`modbus.pcap` on port 502, and a row that fails on both reads `fail (also fails on port 502)`. Every condition "
          "is reported for each configuration, so each reads four ways for Zeek: stock, with ICSNPP, with the "
          "project's script, and with the project's script and the Modbus signature (P4-4-E2's experiment, not "
          "adopted). Only the first two are the engine's own log files (D1 on #625, D6's rule 8).\n")
    for cfg in CONFIGS:
        res = evaluate(conds, loaded, cfg)
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
        print("| capture | condition | protocol | src | dst | direction | code | objects | show | result | cited |")
        print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for row, r, cite in res:
            print(f"| {row['capture']} | {row['condition']} | {row.get('protocol', '')} | {row['src']}:{row['sport']} "
                  f"| {row['dst']}:{row['dport']}/{row['l4']} | {row.get('direction', '')} | {row['code']} | {row['objects']} "
                  f"| {row['show']} | {r} | {cite} |")
        print()
    pipe_case(conds, loaded, cases)


CITE = re.compile(r"[\w.]+\.(?:log|json):[\w.:,]*")


def records(logs):
    """cite -> the record it names, for the logs of one capture under one
    configuration: a flow by its transport and ends, a message by its
    protocol, flow, sender, direction, code, time and objects. Line numbers
    are not part of it, because the order of records in a log is not fixed."""
    out = {}
    for x in [] if isinstance(logs, str) else logs.flows:
        out[x["cite"]] = ("flow", x["l4"], x["orig"], x["resp"])
    for x in [] if isinstance(logs, str) else logs.msgs:
        out[x["cite"]] = ("msg", x["proto"], x["l4"], x["ends"], x["sender"], x["request"], x["fc"], x["ts"], tuple(x["objs"]))
    return out


def matched(text, table):
    """The records that a citation, or every citation inside a result text,
    names; a citation found in no record stays as text."""
    found = []
    for c in CITE.findall(text):
        for part in c.split(".."):
            found += [table[part]] if part in table else [table.get(q, q) for q in part.split(",")]
    return sorted(map(repr, found))


def pipe_case(conds, loaded, cases):
    """The pipe case (D4-87): each Zeek configuration again, reading every
    capture of this run from stdin through a pipe (`cat FILE | zeek -r -`),
    judged with the same functions, and compared row for row with its file
    run, by the result with its citations taken out and by the records those
    citations name (D6 on #630). Suricata through a FIFO is a note only."""
    caps = cases + [CONTROL]
    print("## 3. The pipe case\n")
    print("Each Zeek configuration reads every capture above from stdin through a pipe (`cat FILE | zeek -r -`), in a "
          "container with `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges` and a user that is not "
          "root (`versions.txt` records them), and is judged by the same functions as its file run. A pipe row equals its "
          "file row when the result, with its citations taken out, is the same, and the citations name the same records "
          "(a flow by its transport and ends; a message by its flow, sender, code, time and objects), whatever their line "
          "numbers. **Reads a pipe** is `yes` only when every capture exits 0 with at least one flow record and every one "
          "of D6's rows equals the file run's; `no` when no capture does; otherwise `partly`. An exit 0 with no flow "
          "record never counts. Rows that cite the same records at other line numbers are listed as a note, not as a "
          "difference. **A pipe of a finished capture is not a live stream:** it ends, it never stalls, and nothing pushes "
          "back, so this shows neither a stream that never ends, nor back-pressure, nor a writer that stalls or dies, nor "
          "a malformed record on the pipe.\n")
    print("| configuration | reads a pipe | captures with exit 0 and a flow record | rows equal to the file run (result and records) | rows that differ | note: same records at other line numbers |")
    print("| --- | --- | --- | --- | --- | --- |")
    for cfg in PIPED:
        pc = cfg + "-pipe"
        ok = sum(1 for c in caps if not isinstance(loaded[(pc, c)], str) and loaded[(pc, c)].flows)
        if not conds:
            reads = "no" if ok == 0 else "unknown (no conditions to compare rows)"
            print(f"| {LABELS[cfg]} | {reads} | {ok} of {len(caps)} | {PENDING} | | |")
            continue
        a, b = evaluate(conds, loaded, cfg), evaluate(conds, loaded, pc)
        diff, moved = [], []
        for (row, fr, fc), (_, pr, pcite) in zip(a, b):
            cap = row["capture"]
            ft = {**records(loaded[(cfg, CONTROL)]), **records(loaded[(cfg, cap)])}
            pt = {**records(loaded[(pc, CONTROL)]), **records(loaded[(pc, cap)])}
            same = (CITE.sub("", fr) == CITE.sub("", pr)
                    and matched(fr + " " + fc, ft) == matched(pr + " " + pcite, pt))
            if not same:
                diff.append((row, (fr, fc), (pr, pcite)))
            elif (fr, fc) != (pr, pcite):
                moved.append(row)
        reads = "yes" if ok == len(caps) and not diff else "no" if ok == 0 else "partly"
        shown = "; ".join(f"{r['capture']} {r['condition']} {r['code']}: file `{f[0]}` {f[1]}, pipe `{q[0]}` {q[1]}"
                          for r, f, q in diff) or "-"
        note = "; ".join(f"{r['capture']} {r['condition']} {r['code']}" for r in moved) or "-"
        print(f"| {LABELS[cfg]} | {reads} | {ok} of {len(caps)} | {len(a) - len(diff)} of {len(a)} | {shown} | {note} |")
    print()


def fifo(out, out_pipe):
    """Suricata through a FIFO (D4-87), a note and not a condition. Written
    last, after the judged tables, so that a hang here cannot cost them."""
    caps = sorted(c for c in os.listdir(out_pipe) if os.path.isdir(os.path.join(out_pipe, c, "suricata-fifo")))
    print("**Suricata through a FIFO, a note and not a condition** (`suricata -r FIFO`, a writer `cat FILE > FIFO`, "
          "with the pipe case's container options; the engine has 60 s and the writer 30 s per capture, and after the "
          "first time-out the rest are skipped):\n")
    print("| capture | exit (FIFO) | flow records (FIFO) | flow records (file) |")
    print("| --- | --- | --- | --- |")
    for c in caps:
        f, d = os.path.join(out_pipe, c, "suricata-fifo"), os.path.join(out, c, "suricata")
        fw, sw = ran(f), ran(d)
        nf = "" if fw else len(suricata(f).flows) or "0: no flow record, capture not decoded"
        print(f"| {c} | {fw or '0'} | {nf} | {sw or len(suricata(d).flows)} |")
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
            if not svc:
                # The engine exited 0 and logged no flow at all: the capture
                # was not decoded, which is not a negative result (D6 on #630).
                print(f"| {name} | {LABELS[cfg]} | no flow record: capture not decoded | {fmt(logs)} | - | {notes} |")
                continue
            print(f"| {name} | {LABELS[cfg]} | {fmt(svc)} | {fmt(logs)} | {', '.join(sorted(snmp)) or '-'} | {notes} |")


S1, S0 = "zeek-probe", "zeek-modbus-sig"
SIG_CONDITIONS = "tests/integration/gt_pcap/modbus-signature-conditions.tsv"
CORPUS = "tests/fixtures/network/modbus-sig-corpus"
PUBLIC_SEEN = "43314221626, 43315465228"


def modbus_named(d):
    """D6's `judge-named` for one configuration on one capture: {(l4, ends):
    [cite]} for the flows that any record names Modbus (conn.log `service`
    holding `modbus`, with or without a leading `-`, or a modbus.log row; the
    project's script logs no Modbus), and the set of (l4, ends) with a flow
    record. analyzer.log is not read."""
    conn, named_, recs = {}, collections.defaultdict(list), set()
    for i, r in lines(os.path.join(d, "conn.log")):
        k = (r["proto"], ends(r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"]))
        conn[r["uid"]] = k
        recs.add(k)
        if named({x for x in (r.get("service") or "").split(",") if x}, "modbus"):
            named_[k].append(f"conn.log:{i}")
    for i, r in lines(os.path.join(d, "modbus.log")):
        if r.get("uid") in conn:
            named_[conn[r["uid"]]].append(f"modbus.log:{i}")
    return named_, recs


def verdict(r):
    return "unknown" if r.startswith("unknown") else "pass" if r.startswith("pass") else "fail"


def sig(s, root, work):
    """P4-4-E2: every row of D6's conditions for the Modbus signature, judged
    on S0 (`zeek-modbus-sig`) beside S1 (`zeek-probe`), from the corpus's
    committed labels, D6's engine-pass-conditions.tsv, and the held-out
    labels modbus_label.py wrote in this run. Rows that are read and not
    measured (the configuration's text, the corpus's terms) say so."""
    cond = {r["id"]: r for r in tsv(os.path.join(root, SIG_CONDITIONS))}
    manifest = {m["name"][:-3] if m["name"].endswith(".gz") else m["name"]: m
                for m in tsv(os.path.join(root, CORPUS, "corpus.tsv"))}
    by_stem = {os.path.splitext(n)[0]: m for n, m in manifest.items()}
    committed = os.path.join(root, CORPUS, "labels.tsv")
    labels_from = committed if os.path.exists(committed) else os.path.join(s, "labels.tsv")
    labels = tsv(labels_from)
    out = os.path.join(s, "out")
    seen_logs = {}

    def run_of(cfg, cap):
        if (cfg, cap) not in seen_logs:
            d = os.path.join(out, cap, cfg)
            why = ran(d)
            seen_logs[(cfg, cap)] = why or modbus_named(d)
        return seen_logs[(cfg, cap)]

    v = {}  # row id -> (verdict text, detail)
    print("\n## P4-4-E2: the Modbus/TCP content signature against D6's conditions\n")
    lab_name = (f"`{os.path.relpath(labels_from, root)}`" if labels_from == committed
                else "this run's own, as no labels.tsv is committed (a rehearsal)")
    print(f"Conditions: `{SIG_CONDITIONS}`. Labels: {lab_name}. "
          "S0 is `zeek-modbus-sig` (the project's script with the signature), S1 is `zeek-probe` (the approved configuration), in "
          "this run, over the same files. The signature sets no `DPD::ignore_violations`, so S2 does not run (`cfg-alone`) and "
          "`report-redef` does not arise. Every flow is a pair of ends as `flows.py` reads it from the capture, labelled by "
          "`corpus_label.py` with the pinned tshark, never by an engine.\n")
    with open(os.path.join(s, "hashes.txt"), encoding="utf-8") as f:
        hashes = f.read().strip()
    print("**Files each configuration loads (`cfg-sig`, `cfg-base`):**\n\n```\n" + hashes + "\n```\n")

    # The labels regenerated in this run, against the committed ones.
    regen = os.path.join(s, "labels.tsv")
    if labels_from == committed and os.path.exists(regen):
        a = [l for l in open(committed, encoding="utf-8") if not l.startswith("#")]
        b = [l for l in open(regen, encoding="utf-8") if not l.startswith("#")]
        same = a == b
        print(f"**The labels, regenerated in this run** by the same labeller and tshark: "
              f"{'equal to the committed file, row for row' if same else f'**differ** from the committed file ({len(set(a) ^ set(b))} rows differ); the committed file decides'}.\n")

    # 1. D6's engine-pass-conditions rows under S0 and S1 (det-, ctl-, reg-).
    t = {"zeek_fc": code_table(os.path.join(work, "zeek-dnp3-consts.zeek"), "function_codes"),
         "zeek_modbus_fc": code_table(os.path.join(work, "zeek-modbus-consts.zeek"), "function_codes")}
    if t["zeek_fc"].get("READ") != {1} or t["zeek_modbus_fc"].get("READ_HOLDING_REGISTERS") != {3}:
        sys.exit("could not read Zeek's name tables")
    conds = tsv(os.path.join(root, CONDITIONS))
    caps = {r["capture"] for r in conds} | {CONTROL}
    loaded = {}
    for cfg in (S1, S0):
        for c in caps:
            d = os.path.join(out, c, cfg)
            loaded[(cfg, c)] = ran(d) or zeek(d, cfg, t)
    res = {cfg: evaluate(conds, loaded, cfg) for cfg in (S1, S0)}
    det = [(row, r, cite) for row, r, cite in res[S0] if row["capture"] == MOVED]
    base = [(row, r, cite) for row, r, cite in res[S1] if row["capture"] == MOVED]
    ctl = [r for _, r, _ in det]
    ctl_ok = all("control on port 502: pass" in r for r in ctl) and len(ctl) == 3
    ctl_unknown = not ctl or any("; control on port 502: " not in r or r.split("; control on port 502: ")[1].startswith("unknown")
                                 for r in ctl)
    v["ctl-502"] = ("pass" if ctl_ok else "unknown (not run)" if ctl_unknown else "fail",
                    "; ".join(r.split("; control on port 502: ")[-1] for r in ctl))
    base_v = [verdict(r) for _, r, _ in base]
    v["ctl-baseline"] = ("pass" if base_v and all(x == "fail" for x in base_v) else
                         "unknown (not run)" if not base_v or "unknown" in base_v else "fail",
                         f"S1 on {MOVED}: " + ", ".join(f"{row['condition']} {verdict(r)}" for row, r, _ in base))
    for key, condition in (("det-protocol", "protocol"), ("det-service", "service"), ("det-function", "function")):
        hit = [(r, cite) for row, r, cite in det if row["condition"] == condition]
        if not hit:
            v[key] = ("unknown (not run)", "")
            continue
        r, cite = hit[0]
        if v["ctl-baseline"][0] == "fail":
            v[key] = ("unknown (the baseline passes too)", r)
        elif not ctl_ok:
            v[key] = ("fail (also fails on port 502)" if verdict(r) == "fail" else verdict(r), r)
        else:
            v[key] = (verdict(r), f"{r} {cite}")
    pairs = list(zip(res[S1], res[S0]))
    s1_pass = [(a, b) for a, b in pairs if verdict(a[1]) == "pass"]
    lost = [a[0] for a, b in s1_pass if verdict(b[1]) != "pass"]
    s0_pass = sum(1 for _, b in pairs if verdict(b[1]) == "pass")
    v["reg-rows"] = ("pass" if s1_pass and not lost else "fail" if lost else "unknown (not run)",
                     f"S1 passes {len(s1_pass)} of {len(pairs)}, S0 {s0_pass} of {len(pairs)}; rows S1 passes that S0 does not: "
                     + ("; ".join(f"{r['capture']} {r['condition']} {r['code']}" for r in lost) or "none"))

    # 2. Held-out Modbus flows (held-502, held-other, held-count).
    ports = {}
    for cfg in (S1, S0):
        p = os.path.join(s, f"ports-{cfg}.txt")
        ports[cfg] = open(p, encoding="utf-8").read().strip() if os.path.exists(p) else "not printed"
    m = re.search(r"at zeek_init, priority -1000: tcp \[([^\]]*)\]", ports[S1])
    likely = {x.strip() for x in m.group(1).split(",")} if m else None
    held_rows, held = [], []
    for lab in labels:
        if lab["class"] != "modbus":
            continue
        meta = by_stem.get(lab["capture"])
        mb = meta["modbus"] if meta else ""
        public = meta is not None and not meta["source"].startswith("synthesized")
        no_roles = lab["syn"] != "client" and lab["first"] == "server"
        if mb == "tcp/502":
            cap, ctlcap, port = (MOVED if lab["capture"] == CONTROL else lab["capture"] + "-moved-port"), lab["capture"], MOVED_PORT
        else:
            cap, ctlcap, port = lab["capture"], None, lab["dport"]
        held.append({"lab": lab, "cap": cap, "ctl": ctlcap, "port": port, "public": public, "no_roles": no_roles,
                     "kind": "held-502" if ctlcap else "held-other"})
    by_cap = collections.defaultdict(list)
    for h in held:
        by_cap[h["cap"]].append(h)
    for cap, hs in sorted(by_cap.items()):
        ml = os.path.join(s, "labels", cap + ".tsv")
        refused = not os.path.exists(ml)
        fn = collections.defaultdict(list)
        if not refused:
            for r in tsv(ml):
                if r["kind"] == "function":
                    fn[ends(r["src"], r["sport"], r["dst"], r["dport"])].append(r)
        rows = []
        for h in hs:
            lab = h["lab"]
            h["rows"] = []
            if refused:
                h["result"] = "listed: modbus_label.py refused the capture, or it was not moved; in no count"
                continue
            e = dict(capture=cap, l4="tcp", src=lab["src"], sport=lab["sport"], dst=lab["dst"], dport=h["port"], code="",
                     objects="", sa="", show="", frames="", protocol="modbus",
                     direction="client-server" if lab["direction"] == "client-server" else "midstream")
            h["rows"].append(dict(e, condition="protocol"))
            if not h["no_roles"]:
                h["rows"].append(dict(e, condition="service", src="", sport="", direction=""))
                # held-other: its protocol and service rows only.
                for f in fn.get(ends(lab["src"], lab["sport"], lab["dst"], h["port"]), []) if h["kind"] == "held-502" else ():
                    if f["src"] == lab["src"]:
                        h["rows"].append(dict(e, condition="function", code=f["code"]))
            rows += h["rows"]
        if refused:
            continue
        numbered = list(enumerate(rows))
        for cfg in (S0, S1):
            lg = os.path.join(out, cap, cfg)
            sl = ran(lg) or zeek(lg, cfg, t)
            got = judge_capture(numbered, sl) if not isinstance(sl, str) else {n: (f"unknown ({sl})", "") for n, _ in numbered}
            gc = None
            if hs[0]["ctl"]:
                cl = os.path.join(out, hs[0]["ctl"], cfg)
                sc = ran(cl) or zeek(cl, cfg, t)
                crow = [(n, dict(r, capture=hs[0]["ctl"], dport=CONTROL_PORT)) for n, r in numbered]
                gc = judge_capture(crow, sc) if not isinstance(sc, str) else {n: (f"unknown ({sc})", "") for n, _ in numbered}
            for h in hs:
                idx = [n for n, r in numbered if any(r is x for x in h["rows"])]
                h[cfg] = [(rows[n]["condition"], rows[n].get("code", ""), got[n], gc[n] if gc else None) for n in idx]
    for h in held:
        if "rows" not in h or not h["rows"] or S0 not in h:
            h.setdefault("result", "listed: no rows judged")
            h["counts"] = False
            continue
        out_rows, ctl_pass, any_unknown, fail = [], True, False, False
        for cnd, code, (r, cite), c in h[S0]:
            cv = verdict(c[0]) if c else None
            rv = verdict(r)
            if c is not None and cv != "pass":
                ctl_pass = False
            if rv == "fail" and cv == "fail":
                out_rows.append(f"{cnd}{' ' + code if code else ''}: fail (also fails on port 502)")
                continue
            if rv == "fail" and (cv is None or cv == "pass"):
                fail = True
            any_unknown |= rv == "unknown"
            out_rows.append(f"{cnd}{' ' + code if code else ''}: {r} {cite}".strip()
                            + (f"; control on 502: {c[0]}" if c else ""))
        h["fail"], h["unknown"] = fail, any_unknown
        h["counts"] = h["public"] and not h["no_roles"] and (h["kind"] == "held-other" or ctl_pass) and not any_unknown
        h["counts_any"] = not h["no_roles"] and (h["kind"] == "held-other" or ctl_pass) and not any_unknown
        h["result"] = "; ".join(out_rows)
    for key in ("held-502", "held-other"):
        hs = [h for h in held if h["kind"] == key]
        judged = [h for h in hs if "fail" in h]
        if not judged:
            v[key] = ("unknown (no flow judged)", f"{len(hs)} flows")
            continue
        failed = [h for h in judged if h["fail"]]
        unk = [h for h in judged if h["unknown"] and not h["fail"]]
        v[key] = ("fail" if failed else "unknown" if unk else "pass",
                  f"{len(judged) - len(failed) - len(unk)} of {len(hs)} pass; fail: "
                  + (", ".join(f"{h['cap']} {h['lab']['src']}:{h['lab']['sport']}" for h in failed) or "none"))
    pub = [h for h in held if h.get("counts")]
    pub_caps = {h["lab"]["capture"] for h in pub} - {CONTROL}
    allc = [h for h in held if h.get("counts_any")]
    all_caps = {h["lab"]["capture"] for h in allc} - {CONTROL}
    ok_pub = len(pub) >= 5 and len(pub_caps) >= 2
    v["held-count"] = ("pass" if ok_pub else "unknown (fewer than 5 counting flows from 2 captures other than modbus.pcap)",
                       f"public held-out flows that count: {len(pub)}, from {len(pub_caps)} captures other than modbus.pcap "
                       f"(D1's ruling 6840362704: public only); with the synthesized ones, as the file alone reads: {len(allc)}, "
                       f"from {len(all_caps)}")
    if v["held-count"][0] != "pass":
        for key in ("held-502", "held-other"):
            if v[key][0] == "pass":
                v[key] = ("unknown (held-count)", v[key][1])

    # 3. False positives (fp-flows, fp-floor, fp-near, fp-control) and the labels' rows.
    def fp_count(rows_, cfg):
        fps, floor, undecoded, nm = [], [], collections.Counter(), []
        for lab in rows_:
            if lab["class"] != "not-modbus":
                continue
            r = run_of(cfg, lab["capture"])
            if isinstance(r, str) or not r[1]:
                undecoded[lab["capture"]] += 1
                continue
            k = (lab["l4"], ends(lab["src"], lab["sport"], lab["dst"], lab["dport"]))
            named_, recs = r
            if k in named_:
                fps.append((lab, named_[k]))
            if lab["l4"] == "tcp" and (int(lab["payload_src"]) or int(lab["payload_dst"])) and k in recs:
                floor.append(lab)
        return fps, floor, undecoded
    fp = {cfg: fp_count(labels, cfg) for cfg in (S1, S0)}
    fps, floor, undecoded = fp[S0]
    labelled_floor = [l for l in labels if l["class"] == "not-modbus" and l["l4"] == "tcp"
                      and (int(l["payload_src"]) or int(l["payload_dst"]))]
    v["fp-floor"] = ("pass" if len(floor) >= 300 else "fail", f"{len(floor)} not-modbus TCP flows with payload and a flow record "
                     f"under S0 (the labels hold {len(labelled_floor)}); captures with no flow record under S0: "
                     + (", ".join(f"{c} ({n})" for c, n in sorted(undecoded.items())) or "none"))
    synth = lambda l: by_stem.get(l["capture"], {}).get("source", "").startswith("synthesized")
    near = [l for l in floor if l["near_miss"] == "yes"]
    near_protos = {l["protocol"] for l in near}
    rtu = [l for l in near if l["protocol"] == "modbus-rtu"]
    v["fp-near"] = ("pass" if len(near) >= 10 and len(near_protos) >= 2 and rtu else "fail",
                    f"{len(near)} near misses ({sum(1 for l in near if not synth(l))} public, {sum(1 for l in near if synth(l))} "
                    f"synthesized), from {len(near_protos)} protocols: " + ", ".join(
                        f"{p} {sum(1 for l in near if l['protocol'] == p)}" for p in sorted(near_protos)))
    ctl_rows = [dict(l, **{"class": "not-modbus"}) if l["capture"] == CONTROL and l["dport"] == CONTROL_PORT else l for l in labels]
    fps_ctl = fp_count(ctl_rows, S0)[0]
    v["fp-control"] = ("pass" if len(fps_ctl) == len(fps) + 1 else "fail",
                       f"with modbus.pcap's flow on 502 relabelled not-modbus in a copy: {len(fps_ctl)} false positives, "
                       f"against {len(fps)} on the labels")
    if v["fp-control"][0] != "pass" or v["fp-floor"][0] != "pass" or v["fp-near"][0] != "pass":
        v["fp-flows"] = ("unknown (" + ", ".join(k for k in ("fp-floor", "fp-near", "fp-control") if v[k][0] != "pass") + ")",
                         f"{len(fps)} false positives")
    else:
        v["fp-flows"] = ("pass" if not fps else "fail", f"{len(fps)} false positives")
    per = collections.Counter(l["protocol"] for l in floor)
    big = per.most_common(1)[0] if per else ("-", 0)
    need = {"iec104", "mms", "enip", "dnp3"}
    v["corpus-protocols"] = ("pass" if len(per) >= 8 and need <= set(per) and big[1] * 2 <= len(floor) else "fail",
                             f"{len(per)} protocols; the largest is {big[0]} with {big[1]} of {len(floor)}; "
                             f"{', '.join(sorted(need - set(per))) or 'none'} of IEC 104, MMS, EtherNet/IP and DNP3 missing")
    tcp_pay = [l for l in labels if l["l4"] == "tcp" and (int(l["payload_src"]) or int(l["payload_dst"]))]
    disputed = [l for l in tcp_pay if l["class"] == "disputed"]
    v["label-disputed"] = ("pass" if len(disputed) * 100 <= 5 * len(tcp_pay) else "fail",
                           f"{len(disputed)} disputed of {len(tcp_pay)} TCP flows with payload")

    # 4. The table of rows, then the details.
    print("| row | verdict | what the run shows |")
    print("| --- | --- | --- |")
    readonly = {"cfg-sig": "read, not measured: the files and hashes above", "cfg-base": "read, not measured: the files and hashes above",
                "cfg-alone": "does not arise: S0 carries no redef", "judge-port": "read at review-text, not measured by the run",
                "judge-named": "applied: conn.log `service`, modbus.log; analyzer.log not read",
                "judge-verdict": "applied", "judge-counted": "the header above",
                "judge-seen": f"earlier runs of S0 over the corpus: {PUBLIC_SEEN} (the signature as at 3436c8dc), and this PR's "
                              "rehearsals of the amendment, which the PR lists by run ID; the manifest's `seen` column marks each capture",
                "review-text": "read by D2 and D6 on the PR, not measured by the run", "corpus-members": "the manifest",
                "corpus-sources": "the manifest's header (D7 and D6 confirm)", "corpus-terms": "the manifest's header (D7 confirms)",
                "corpus-pins": "pins.env and the header above", "corpus-not-held": "the manifest's header",
                "label-flow": f"{lab_name}, {len(labels)} rows",
                "label-modbus": f"{sum(1 for l in labels if l['class'] == 'modbus')} flows",
                "label-not-modbus": f"{sum(1 for l in labels if l['class'] == 'not-modbus')} flows",
                "report-redef": "does not arise: S0 carries no redef", "report-counts": "below",
                "adopt-limits": "stated by D6 and D1", "adopt-rerun": "for D1"}
    for rid, row in cond.items():
        if rid in v:
            print(f"| `{rid}` | {v[rid][0]} | {v[rid][1]} |")
        elif rid == "adopt-when":
            thr = [k for k, r in cond.items() if r["op"]]
            bad = [k for k in thr if k not in v or v[k][0] != "pass"]
            met = "every threshold row the run measures holds; review-text is the reviewers' to judge"
            print(f"| `{rid}` | {met if bad == ['review-text'] else 'not met'} "
                  f"| rows with a threshold that do not hold or are not measured here: {', '.join(bad) or 'none'} |")
        else:
            print(f"| `{rid}` | - | {readonly.get(rid, 'not judged by the run')} |")
    print("\n### Held-out Modbus flows, under S0 (and S1)\n")
    print("`held-502` flows run moved to 15020 by `movedport.py` and are labelled there by `modbus_label.py` with the pinned "
          "tshark; each row also runs on the unmoved capture on 502, its control. `held-other` flows run as written. A flow with no "
          "client SYN whose first frame is the server's is `(roles not recoverable off 502)`: its protocol row only, never counted. "
          "**Counts** is D1's public-only count (6840362704).\n")
    print("| capture | client | server | kind | source | rows under S0 | rows under S1 | counts |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for h in held:
        lab = h["lab"]
        s1 = "; ".join(f"{c}{' ' + k if k else ''}: {verdict(r[0])}" for c, k, r, _ in h.get(S1, [])) or "-"
        tag = " (roles not recoverable off 502)" if h["no_roles"] else ""
        print(f"| {h['cap']} | {lab['src']}:{lab['sport']} | {lab['dst']}:{h['port']} | {h['kind']}{tag} "
              f"| {'public' if h['public'] else 'synthesized'} | {h.get('result', '-')} | {s1} | {'yes' if h.get('counts') else 'no'} |")
    print("\n**Client ports of held-out flows with no client SYN, against `likely_server_ports` under S1** (D6's note section 1, "
          "D2's N2 on #647; the label review decides):\n")
    for h in held:
        lab = h["lab"]
        if lab["syn"] != "client":
            inset = "unknown (set not printed)" if likely is None else ("**in the set**" if lab["sport"] in likely else "not in the set")
            print(f"- {h['cap']}: client port {lab['sport']}, first frame from the {lab['first']}: {inset}")
    print("\n**`likely_server_ports`, printed after every `zeek_init` handler and at `zeek_done`:**\n")
    for cfg in (S1, S0):
        print(f"- {cfg}:\n\n```\n{ports[cfg]}\n```\n")
    sets = [l.split(": ", 1)[-1] for cfg in (S1, S0) for l in ports[cfg].splitlines() if l.startswith("likely_server_ports")]
    print(f"The prints are {'equal, all four' if len(sets) == 4 and len(set(sets)) == 1 else '**not four equal sets**: read them above'}.\n")
    print("### False positives and the corpus (`fp-`, `corpus-`, `label-`, `report-counts`)\n")
    print("| configuration | not-modbus flows named Modbus (all transports) | fp-floor | near misses in fp-floor | false positives among near misses |")
    print("| --- | --- | --- | --- | --- |")
    for cfg in (S0, S1):
        f_, fl_, _ = fp[cfg]
        nm = [l for l in fl_ if l["near_miss"] == "yes"]
        nfp = [l for l, _ in f_ if l["near_miss"] == "yes"]
        print(f"| {LABELS[cfg]} | {len(f_)} | {len(fl_)} | {len(nm)} | {len(nfp)} |")
    n = len(floor)
    print(f"\nWith zero false positives in N flows, the 95% upper bound on the per-flow rate is about 3/N: "
          f"{'%.2f%%' % (300 / n) if n else '-'} over fp-floor's {n}, and "
          f"{'%.1f%%' % (300 / len(near)) if near else '-'} over the {len(near)} near misses. A measured zero is not a rate of zero.\n")
    print("**Each false positive under S0** (capture, labelled protocol, server end; never its bytes): "
          + ("; ".join(f"{l['capture']}, {l['protocol']}, {l['dst']}:{l['dport']}/{l['l4']} ({', '.join(c[:2])})" for l, c in fps) or "none") + "\n")
    print("**fp-floor by protocol, public and synthesized:**\n")
    print("| protocol | flows | public | synthesized | near misses |")
    print("| --- | --- | --- | --- | --- |")
    for p, c in sorted(per.items(), key=lambda x: (-x[1], x[0])):
        print(f"| {p} | {c} | {sum(1 for l in floor if l['protocol'] == p and not synth(l))} "
              f"| {sum(1 for l in floor if l['protocol'] == p and synth(l))} | {sum(1 for l in near if l['protocol'] == p)} |")
    unseen = [l for l in floor if by_stem.get(l["capture"], {}).get("seen") == "-"]
    unseen_fp = [l for l, _ in fps if by_stem.get(l["capture"], {}).get("seen") == "-"]
    print(f"\n**Unseen before the amendment** (the manifest's `seen` is `-`; D1 on #643): {len(unseen)} of fp-floor's flows, "
          f"{len(unseen_fp)} false positives among them.\n")
    print("**Disputed flows** (in no count; named here if S0 names one): "
          + ("; ".join(f"{l['capture']} {l['src']}:{l['sport']} > {l['dst']}:{l['dport']} ({l['by_tshark']})"
                       + (" **named by S0**" + (" (on 502, Zeek's own port registration)" if l["dport"] == CONTROL_PORT else "")
                          if not isinstance(run_of(S0, l['capture']), str)
                          and (l['l4'], ends(l['src'], l['sport'], l['dst'], l['dport'])) in run_of(S0, l['capture'])[0] else "")
                       for l in labels if l["class"] == "disputed") or "none") + "\n")
    return v


if __name__ == "__main__":
    if sys.argv[1] == "dnp3":
        dnp3(*sys.argv[2:6])
    elif sys.argv[1] == "fifo":
        fifo(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "sig":
        sig(*sys.argv[2:5])
    else:
        public(sys.argv[2])

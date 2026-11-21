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
       python -I table.py hr23 OUT   (HR-23's readings, section 4.4 of its design)
       python -I -B table.py hr23judge OUT OUT_FP FP_KEPT ROOT PORTS PCAPS [--counted]   (HR-23's judge)
       python -I table.py fifo OUT OUT-pipe
       python -I table.py public OUT PCAPS MANIFEST EXTRA [--counted]
       python -I table.py sig SIG_DIR ROOT WORK
"""
import collections
import glob
import ipaddress
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
# HR-23 (brief P4-4-HR23, stage 3; docs/phase4/D4-hr23-design.md, section
# 4.1). zeek-probe is C1: the stock image with part (a). zeek-probe-c0 is C0:
# the stock image with the script as it was before part (a)
# (OtsecProbe::log_dir=F), whose DNP3 servers are conn.log's responders.
# zeek-probe-c1p and zeek-probe-c2 are the project's build without and with
# option (i)'s patch, with part (a); run.sh runs them only when the build's
# images are given, and a table lists them only when they ran.
HR23 = ("zeek-probe-c0", "zeek-probe-c1p", "zeek-probe-c2")
LABELS.update({
    "zeek-probe": "Zeek with the project's script (zeek-probe; HR-23's C1: the stock image with part (a); "
                  "otsec_probe.log is not the engine's own log)",
    "zeek-probe-c0": "Zeek with the project's script before HR-23's part (a) (HR-23's C0, the control: "
                     "DNP3 servers from conn.log's responder)",
    "zeek-probe-c1p": "The project's Zeek build without HR-23's patch, with the project's script (HR-23's C1p)",
    "zeek-probe-c2": "The project's Zeek build with HR-23's patch, option (i), with the project's script (HR-23's C2)",
})
# GT-PCAP's folder of HR-23's captures, which dnp3 mode's tables leave out.
HR23_DIR = "hr23"
# The configurations that load probe.zeek, so read otsec_probe.log.
PROBED = ("zeek-probe", "zeek-modbus-sig") + HR23
# The configurations whose DNP3 servers come from the link rows' DIR bit
# (part (a); the design's section 3 item 7). Every other configuration keeps
# conn.log's responder, as before.
LINKED = ("zeek-probe", "zeek-modbus-sig", "zeek-probe-c1p", "zeek-probe-c2")
RESPONSE_CODES = (129, 130, 131)
PENDING = "pending D6's pass conditions"
# The pipe case (D4-87): these configurations also read each capture from a pipe.
PIPED = ("zeek", "zeek-probe", "zeek-icsnpp")
CONDITIONS = "tests/integration/gt_pcap/engine-pass-conditions.tsv"
# DNP3 codes that are never a request: the confirm (0, sent by both ends) and
# the responses (129, 130, 131) (C13 0.1 section 4.3; D4's N3 on #657).
NOT_REQUESTS = (0, 129, 130, 131)
# modbus-moved-port is modbus.pcap with port 502 moved to 15020
# (movedport.py's defaults); modbus.pcap is its control (D6's note, section 3).
MOVED, CONTROL, MOVED_PORT, CONTROL_PORT = "modbus-moved-port", "modbus", "15020", "502"


def present(out):
    """CONFIGS, then each of HR23 that ran on at least one capture in OUT."""
    caps = [c for c in os.listdir(out) if os.path.isdir(os.path.join(out, c))] if os.path.isdir(out) else []
    return CONFIGS + tuple(h for h in HR23 if any(os.path.isdir(os.path.join(out, c, h)) for c in caps))


def broadcast(addr):
    """A limited broadcast or multicast address. A directed subnet broadcast
    is not known here, since no subnet is (a limit of part (a)'s exception)."""
    try:
        return addr == "255.255.255.255" or ipaddress.ip_address(addr).is_multicast
    except ValueError:
        return False


def server_of(o, p, is_orig, dir_set):
    """The server one DNP3 frame names (part (a); the design's section 3
    item 3): DIR clear names its sender, an outstation; DIR set names the
    other end, unless that end is a broadcast or multicast address, when it
    names none."""
    sender, other = (o, p) if is_orig else (p, o)
    if not dir_set:
        return sender
    return None if broadcast(other[0]) else other


def served(f, s, proto):
    """The ends a flow record names as servers of proto. Under LINKED, a DNP3
    flow's servers are the union of those its frames name, 0, 1 or 2 (part
    (a)); never its responder (CH-49). Otherwise the responder of a flow the
    engine named, as before."""
    if proto == "dnp3" and s.linked:
        return f.get("dnp3_servers", set())
    return {f["resp"]} if named(f["names"], proto) else set()


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
        self.linked = False  # DNP3 servers from the link rows (LINKED)
        self.dir_disagree = 0  # frames whose DIR disagrees with their code's class
        self.resp_as_request = 0  # fc rows with code 129 to 131 from the request header
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
        s.flows.append({"cite": f"conn.log:{i}", "uid": r["uid"], "l4": r["proto"], "orig": o, "resp": p,
                        "first": (r["ts"], r["uid"]),
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
        s.linked = cfg in LINKED
        cur, last_dir, servers = {}, {}, collections.defaultdict(set)
        for i, r in lines(os.path.join(d, "otsec_probe.log")):
            if r["uid"] not in conn or r["kind"] not in ("fc", "obj", "link"):
                continue
            l4, o, p = conn[r["uid"]]
            side = (r["uid"], r["is_orig"])
            if r["kind"] == "link":
                # dnp3_header_block comes at each fragment's first frame,
                # before that fragment's application header (section 3 item 1).
                last_dir[side] = r.get("link_dir")
                if r.get("link_dir") is not None:
                    sv = server_of(o, p, r["is_orig"], r["link_dir"])
                    if sv:
                        servers[r["uid"]].add(sv)
                continue
            if r["kind"] == "fc":
                if last_dir.get(side) is not None and last_dir[side] == (r["fc"] in RESPONSE_CODES):
                    s.dir_disagree += 1
                # A response code raised as a request header, from either
                # side: under C2, a fragment of 129 to 131 shorter than a
                # response header (D2's (A); D6's N9 on #715).
                if r["fc"] in RESPONSE_CODES and str(r.get("ev", "")).endswith("request_header"):
                    s.resp_as_request += 1
                last_dir[side] = None
                s.msg(f"otsec_probe.log:{i}", r["ts"], "dnp3", l4, ends(*o, *p), (o if r["is_orig"] else p)[0],
                      r["fc"] not in NOT_REQUESTS, r["fc"])
                cur[side] = s.msgs[-1]
            elif side in cur:
                cur[side]["objs"].append(f"g{r['group']}v{r['variation']}")
                cur[side]["cite"] += f",{i}"
        for f in s.flows:
            f["dnp3_servers"] = servers.get(f["uid"], set())
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
                          fc not in NOT_REQUESTS, fc)
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


def judge_flow(row, s, flow_rows, svc_rows):
    """Protocol and Service rows (D6's note, section 2, and rule 6).

    Protocol: one flow record with the row's transport and both ends, named
    as the row's `protocol`; where `direction` is client-server its
    originator is the row's src, and where it is `none` or `midstream`
    either orientation passes and the result says which. Two records fail.
    Service: the protocol attributed to the server end the row names, and
    to no end of a labelled flow that the labels do not name as its server
    (rule 6); flow_rows are the capture's protocol rows, svc_rows its
    service rows, which name the servers.
    """
    l4, proto = row["l4"], (row.get("protocol") or "dnp3")
    if row["condition"] == "service":
        # The servers are the ends the Service rows name, not the Protocol
        # rows' dst: a Protocol row's dst can be a master on a temporary
        # port (dnp3-udp-temp-port), and a service named there must fail
        # (D1 to D4 on #648; D6's note, section 7).
        # Under LINKED, a DNP3 flow's servers are the ends its frames' DIR
        # bits name (HR-23 part (a)); served() says which reading applies.
        servers = {(r["dst"], r["dport"]) for r in svc_rows if r["l4"] == l4}
        others = {e for r in flow_rows if r["l4"] == l4 for e in ((r["src"], r["sport"]), (r["dst"], r["dport"]))} - servers
        wrong = [(f, e) for f in s.flows if f["l4"] == l4 for e in sorted(served(f, s, proto) & others)]
        if wrong:
            f, e = wrong[0]
            return f"fail (service also at {e[0]} {l4}/{e[1]})", f["cite"]
        for f in s.flows:
            if f["l4"] == l4 and (row["dst"], row["dport"]) in served(f, s, proto):
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
    svc_rows = [r for _, r in rows if r["condition"] == "service"]
    fn_rows = [r for _, r in rows if r["condition"] == "function"]
    pos = {id(r): k for k, r in enumerate(fn_rows)}
    fn, ob = match_functions(fn_rows, s)
    explicit = {}
    for n, row in rows:
        c = row["condition"]
        if c in ("protocol", "service"):
            out[n] = judge_flow(row, s, flow_rows, svc_rows)
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


def gt_cases(gt):
    """{capture: its label folder} for every capture a GT-PCAP hash list
    names, but HR-23's: those are fed in their own folders, to C0, C1, C1p
    and C2 only, and only whether each ran is printed (run.sh's hr23_feed;
    D4-112 item 1.3), so dnp3 mode's tables do not list them."""
    labdir = {}
    for sums in sorted(glob.glob(os.path.join(gt, "*", "*.sha256"))):
        if os.path.basename(os.path.dirname(sums)) == HR23_DIR:
            continue
        for l in open(sums):
            if l.strip() and l.split()[1].endswith(".pcap"):
                labdir[l.split()[1][: -len(".pcap")]] = os.path.dirname(sums)
    return labdir


def dnp3(out, gt, work, root):
    global CONFIGS
    CONFIGS = present(out)
    t = {"zeek_fc": code_table(os.path.join(work, "zeek-dnp3-consts.zeek"), "function_codes"),
         "zeek_modbus_fc": code_table(os.path.join(work, "zeek-modbus-consts.zeek"), "function_codes")}
    icsnpp = os.path.join(work, "pkgs", "icsnpp-dnp3", "scripts", "consts.zeek")
    t["icsnpp_fc"] = code_table(icsnpp, "function_codes")
    t["icsnpp_obj"] = code_table(icsnpp, "dnp3_objects")
    # A table read wrong would turn into silent "0 of n" cells, so stop.
    if (t["zeek_fc"].get("READ") != {1} or t["icsnpp_fc"].get("READ") != {1} or len(t["icsnpp_obj"]) < 50
            or t["zeek_modbus_fc"].get("READ_HOLDING_REGISTERS") != {3}):
        sys.exit("could not read Zeek's or ICSNPP's name tables")
    labdir = gt_cases(gt)
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
    print(f"GT-PCAP's `{HR23_DIR}/` captures are not in these tables: they run under C0, C1, C1p and C2 only, in "
          "their own folders, and the last section of this file says only whether each ran.\n")
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
            svc = sum(1 for r in lab["service"] if any(f["l4"] == r["l4"] and (r["dst"], r["dport"]) in served(f, s, proto) for f in s.flows))
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
    hr23_regression(conds, loaded)
    pipe_case(conds, loaded, cases)


def hr23_regression(conds, loaded):
    """HR-23's regression over D6's rows, by reg-rows' rule: C2 against C1p
    (option (i) alone) and C1 against C0 (part (a) alone; the design's
    section 4.1). Printed for each pair whose two configurations ran."""
    pairs = [(a, b) for a, b in (("zeek-probe-c0", "zeek-probe"), ("zeek-probe-c1p", "zeek-probe-c2"))
             if a in CONFIGS and b in CONFIGS]
    if not pairs:
        return
    print("### HR-23's regression (reg-rows' rule: a row the first passes that fails under the second)\n")
    for ref, new in pairs:
        a, b = evaluate(conds, loaded, ref), evaluate(conds, loaded, new)
        v, lost = reg_rows([(x[1], y[1]) for x, y in zip(a, b)])
        shown = "; ".join(f"{a[i][0]['capture']} {a[i][0]['condition']} {a[i][0]['code']}" for i in lost) or "none"
        print(f"- {new} against {ref}: {v}; rows lost: {shown}")
    print()


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


def listed(paths):
    """Every capture MANIFEST.tsv and extra-captures.tsv name, as
    (file name in the run's capture folder, output folder name): run.sh
    gunzips a `.gz` capture, and in-container.sh names the folder after the
    file less its last extension."""
    names = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    n = line.split("\t", 1)[0]
                    n = n[:-3] if n.endswith(".gz") else n
                    names.append((n, os.path.splitext(n)[0]))
    return names


def public(out, pcaps, manifests, counted=False):
    """Returns the number of listed captures that were not fetched: each
    gets a `not run (not fetched)` row under every configuration (D6's
    finding on #744, D4-118 item 2.5). A counted run then exits non-zero
    (__main__)."""
    global CONFIGS
    CONFIGS = present(out)
    want = listed(manifests)
    missing = sorted(d for n, d in want if not os.path.isfile(os.path.join(pcaps, n)))
    print("# E-D4-03: public captures\n")
    print("What each configuration logged. MANIFEST.tsv's captures carry no GT-PCAP label; their tshark reading is E-A4-01's "
          "(`ids-coverage/results/coverage.md`, tshark 4.2.2, same SHA-256s). The extra captures carry none. No pass "
          "condition reads this table (D6's note, section 6). Generated by `run.sh public`; do not edit by hand.\n")
    print("| capture | config | protocol names (flows) | logs (rows) | SNMP fields logged | notes |")
    print("| --- | --- | --- | --- | --- | --- |")
    have = os.listdir(out) if os.path.isdir(out) else []
    for name in sorted(set(have) | {d for _, d in want}):
        for cfg in CONFIGS:
            d = os.path.join(out, name, cfg)
            why = "not run (not fetched)" if name in missing else ran(d)
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
    if missing:
        print(f"\n**{len(missing)} of the {len(want)} listed captures were not fetched or did not match their SHA-256:** "
              f"{', '.join(missing)}. Their rows read `not run (not fetched)`. "
              + ("This run is on refs/heads/main, where every counted run is made, so the job fails (D4-118 item 2.5)."
                 if counted else "This run is not on refs/heads/main, so it is not counted and the job stays green; on "
                 "refs/heads/main it fails (D4-118 item 2.5)."))
    return len(missing)


S1, S0 = "zeek-probe", "zeek-modbus-sig"
SIG_CONDITIONS = "tests/integration/gt_pcap/modbus-signature-conditions.tsv"
CORPUS = "tests/fixtures/network/modbus-sig-corpus"
# judge-seen: every earlier run of S0 over the corpus, by run ID, with the
# head it ran at and the signature it loaded (modbus-sig.zeek and
# modbus-sig.sig, SHA-256 prefixes). Runs of d4-engine-linux-eval.yml on #643.
# A run at the head that adds its line, or later, cannot be in this list.
SEEN = (
    ("43314221626", "21ffb801", "4a8b75d4/beda1433"),
    ("43315465228", "51540b17", "4a8b75d4/beda1433"),
    ("43344298828", "4011e49e", "7be2c6a2/96f335c0"),
    ("43345170729", "4da1f1c8", "7be2c6a2/96f335c0"),
    ("43346878016", "7bfa398a", "7be2c6a2/96f335c0"),
    ("43354762583", "ccfc4091", "7be2c6a2/96f335c0"),
    ("43355514690", "4c4ad119", "7be2c6a2/96f335c0"),
    ("43356139186", "9beba8d6", "7be2c6a2/96f335c0"),
    ("43361080550", "d980815f", "7be2c6a2/96f335c0"),
    ("43367830635", "71896c02", "7be2c6a2/96f335c0"),
)


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


def synthesized(source):
    """A member the project wrote (D4's synth_corpus.py, `synthesized (D4)`,
    or GT-PCAP's `GT-PCAP (D6), synthesized`), not a public capture (D6's N1
    on #643)."""
    return "synthesized" in source


def det_verdict(r, ctl_ok, ctl_unknown, baseline_fails):
    """One det- row under S0 (D6's ctl-502 and ctl-baseline): with the
    baseline passing too, unknown; with the control on 502 not run, unknown;
    with it failing, `fail (also fails on port 502)`, never a pass (D6's N2
    on #643)."""
    if baseline_fails:
        return "unknown (the baseline passes too)"
    if ctl_ok:
        return verdict(r)
    return "unknown (control on port 502 not run)" if ctl_unknown else "fail (also fails on port 502)"


def judge_held(rows):
    """One held-out flow under S0 (D6's held-502 and held-other). rows:
    (condition, code, (result, cite), control), control None for held-other
    and else the same row's (result, cite) on 502. Returns (state, ctl_pass,
    lines), state one of pass, fail, unknown, listed:

    - a row that fails under S0 with its control passing, or with none, fails
      the flow;
    - a row that fails on 502 too is `fail (also fails on port 502)`, listed
      and counted against nothing;
    - a row that fails under S0 while its control did not run is unknown,
      never a pass (D6's B1 on #643), as is a row that did not run;
    - a flow none of whose rows was judged is listed, not a pass (D6's N3)."""
    out, ctl_pass, unknown, fail, judged = [], True, False, False, 0
    for cnd, code, (r, cite), c in rows:
        name = f"{cnd}{' ' + code if code else ''}"
        cv = verdict(c[0]) if c else None
        rv = verdict(r)
        if c is not None and cv != "pass":
            ctl_pass = False
        if rv == "fail" and cv == "fail":
            out.append(f"{name}: fail (also fails on port 502)")
            continue
        judged += 1
        ctl = f"; control on 502: {c[0]}" if c else ""
        if rv == "fail" and cv in (None, "pass"):
            fail = True
        elif rv == "fail":
            unknown = True
            out.append(f"{name}: unknown (fails under S0, and its control on 502 did not run) {r} {cite}".strip() + ctl)
            continue
        unknown |= rv == "unknown"
        out.append(f"{name}: {r} {cite}".strip() + ctl)
    state = "fail" if fail else "unknown" if unknown else "pass" if judged else "listed"
    return state, ctl_pass, out


def reg_rows(pairs):
    """reg-rows over (S1 result, S0 result) pairs, one per row of D6's
    engine-pass-conditions: (verdict, indexes of the rows S1 passes that fail
    under S0). `fail` when such a row exists; else `unknown` when any row did
    not run under S1 or S0, or none ran; else `pass` (D6's B3 on #643)."""
    lost = [i for i, (a, b) in enumerate(pairs) if verdict(a) == "pass" and verdict(b) == "fail"]
    if lost:
        return "fail", lost
    if not pairs or any("unknown" in (verdict(a), verdict(b)) for a, b in pairs):
        return "unknown (not run)", lost
    return "pass", lost


def held_counts(state, ctl_pass, no_roles, kind, source):
    """held-count's rule for one held-out flow: (counts, counts_any). A flow
    counts when it was judged pass or fail (never unknown or listed), its
    roles are recoverable, and, on 502, its controls passed; `counts` also
    needs a public capture, by the manifest's source (D1's ruling 6840362704;
    D6's N7 on #643). source is None for a capture not in the manifest."""
    ok = state in ("pass", "fail") and not no_roles and (kind == "held-other" or ctl_pass)
    return ok and source is not None and not synthesized(source), ok


def seen_same(hashes):
    """judge-seen: this run's signature hashes (hashes.txt) against the last
    run SEEN lists, compared, not stated (D6's N9 on #643)."""
    got = {m.group(1): m.group(2)[:8] for m in re.finditer(r"zeek-modbus-sig: (modbus-sig\.(?:zeek|sig)) ([0-9a-f]{64})", hashes)}
    now = f"{got.get('modbus-sig.zeek', '?')}/{got.get('modbus-sig.sig', '?')}"
    last = SEEN[-1][2]
    first = next(h for _, h, sg in SEEN if sg == last)
    if now == last:
        return f"This run loads {now}, the signature the last listed run loaded, first run at {first}"
    return f"This run loads {now}, **not** the signature the last listed run loaded ({last}); the listed runs did not run it"


def held_tally(hs):
    """held-502 or held-other over its flows: (verdict, detail). Listed flows
    (refused, or every row also failing on 502) are named apart and are in no
    pass (D6's N3 on #643)."""
    st = collections.Counter(h.get("state", "listed") for h in hs)
    if not st["pass"] + st["fail"] + st["unknown"]:
        return "unknown (no flow judged)", f"{len(hs)} flows, {st['listed']} listed"
    failed = [h for h in hs if h.get("state") == "fail"]
    return ("fail" if st["fail"] else "unknown" if st["unknown"] else "pass",
            f"{st['pass']} pass, {st['fail']} fail, {st['unknown']} unknown, {st['listed']} listed, of {len(hs)}; fail: "
            + (", ".join(f"{h['cap']} {h['lab']['src']}:{h['lab']['sport']}" for h in failed) or "none")
            + "; judged on the protocol row only, roles not recoverable off 502, and in no count: "
            + (", ".join(f"{h['cap']} {h['lab']['src']}:{h['lab']['sport']}" for h in hs
                         if h.get("no_roles") and h.get("state") not in (None, "listed")) or "none"))


def held_count_gate(v):
    """held-count: with fewer counting flows, both held- rows are unknown,
    whatever they read (D6's N2 on #643)."""
    if v["held-count"][0] != "pass":
        for key in ("held-502", "held-other"):
            v[key] = ("unknown (held-count)", v[key][1])


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
    if labels_from == committed and not os.path.exists(regen):
        print("**The labels were not regenerated in this run:** `corpus_label.py` failed (the job log says so); "
              "the committed file decides (D6's N8 on #643).\n")
    elif labels_from == committed:
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
        v[key] = (det_verdict(r, ctl_ok, ctl_unknown, v["ctl-baseline"][0] == "fail"), f"{r} {cite}")
    pairs = list(zip(res[S1], res[S0]))
    rv, lost = reg_rows([(a[1], b[1]) for a, b in pairs])
    n_pass = {i: sum(1 for p in pairs if verdict(p[i][1]) == "pass") for i in (0, 1)}
    n_unrun = {i: sum(1 for p in pairs if verdict(p[i][1]) == "unknown") for i in (0, 1)}
    v["reg-rows"] = (rv, f"S1 passes {n_pass[0]} of {len(pairs)}, S0 {n_pass[1]} of {len(pairs)}; not run: {n_unrun[0]} under S1, "
                     f"{n_unrun[1]} under S0; rows S1 passes that fail under S0: "
                     + ("; ".join(f"{pairs[i][0][0]['capture']} {pairs[i][0][0]['condition']} {pairs[i][0][0]['code']}" for i in lost)
                        or "none"))

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
        public = meta is not None and not synthesized(meta["source"])
        no_roles = lab["syn"] != "client" and lab["first"] == "server"
        if mb == "tcp/502":
            cap, ctlcap, port = (MOVED if lab["capture"] == CONTROL else lab["capture"] + "-moved-port"), lab["capture"], MOVED_PORT
        else:
            cap, ctlcap, port = lab["capture"], None, lab["dport"]
        held.append({"lab": lab, "cap": cap, "ctl": ctlcap, "port": port, "public": public, "source": meta["source"] if meta else None, "no_roles": no_roles,
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
        state, ctl_pass, out_rows = judge_held(h[S0])
        h["state"] = state
        h["counts"], h["counts_any"] = held_counts(state, ctl_pass, h["no_roles"], h["kind"], h["source"])
        h["result"] = ("listed: every row also fails on port 502; " if state == "listed" else "") + "; ".join(out_rows)
    for key in ("held-502", "held-other"):
        v[key] = held_tally([h for h in held if h["kind"] == key])
    pub = [h for h in held if h.get("counts")]
    pub_caps = {h["lab"]["capture"] for h in pub} - {CONTROL}
    allc = [h for h in held if h.get("counts_any")]
    all_caps = {h["lab"]["capture"] for h in allc} - {CONTROL}
    ok_pub = len(pub) >= 5 and len(pub_caps) >= 2
    v["held-count"] = ("pass" if ok_pub else "unknown (fewer than 5 counting flows from 2 captures other than modbus.pcap)",
                       f"public held-out flows that count: {len(pub)}, from {len(pub_caps)} captures other than modbus.pcap "
                       f"(D1's ruling 6840362704: public only); with the synthesized ones, as the file alone reads: {len(allc)}, "
                       f"from {len(all_caps)}")
    held_count_gate(v)

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
    synth = lambda l: synthesized(by_stem.get(l["capture"], {}).get("source", ""))
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
                             f"{len(per)} protocol names, counted by capture (the manifest's `protocol` is one name per capture, "
                             f"so a capture's other flows carry its name); the largest is {big[0]} with {big[1]} of {len(floor)}; "
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
                "judge-seen": "earlier runs of S0 over the corpus, run ID at head (modbus-sig.zeek/modbus-sig.sig): "
                              + "; ".join(f"{r} at {h} ({sg})" for r, h, sg in SEEN)
                              + f". {seen_same(hashes)}; "
                              "the earlier signature ran over the captures the manifest's `seen` column marks. A run of S0 after "
                              f"{SEEN[-1][0]}, at the head that adds it to this list or later, is not in the list: "
                              "the counted result's comment names it",
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


def hr23_readings(d, cfg):
    """One configuration's HR-23 readings on one capture (the design's
    section 4.4): {"weirds": Counter of dnp3_ weird names, "analyzer":
    Counter of (analyzer, failure_reason), "disagree": count, "flows":
    [(flow ends, conn.log names DNP3, link-row servers)], "both": flows
    whose frames name two servers, "reporter": Counter of reporter.log's
    (level, message)}. analyzer.log's failure_data is never read: it carries
    payload (D3's N1 on #675). reporter.log carries no payload field; its
    level and message are read, its location is not (D4-100 item 2, D6's N6
    on #715)."""
    out = {"weirds": collections.Counter(), "analyzer": collections.Counter(), "reporter": collections.Counter()}
    for _, r in lines(os.path.join(d, "weird.log")):
        if str(r.get("name", "")).startswith("dnp3_"):
            out["weirds"][r["name"]] += 1
    for _, r in lines(os.path.join(d, "analyzer.log")):
        out["analyzer"][(r.get("analyzer_name") or "?", r.get("failure_reason") or "?")] += 1
    for _, r in lines(os.path.join(d, "reporter.log")):
        out["reporter"][f"{r.get('level') or '?'}: {r.get('message') or '?'}"] += 1
    s = zeek(d, cfg, {"zeek_fc": {}, "zeek_modbus_fc": {}})
    out["disagree"] = s.dir_disagree if cfg in LINKED else None
    out["resp_as_request"] = s.resp_as_request if cfg in PROBED else None
    out["flows"] = []
    for f in s.flows:
        by_conn = named(f["names"], "dnp3")
        links = f.get("dnp3_servers", set()) if cfg in LINKED else None
        if by_conn or links:
            out["flows"].append((f"{f['l4']} {f['orig'][0]}:{f['orig'][1]} > {f['resp'][0]}:{f['resp'][1]}", by_conn, links))
    out["both"] = sum(1 for _, _, l in out["flows"] if l and len(l) == 2)
    return out


def log_fields(out, cfg):
    """{(log, field)} over every capture under OUT for one configuration.
    JSON leaves an unset optional field out, so a field can be missing on
    one configuration only because no record set it."""
    seen = set()
    for c in sorted(os.listdir(out)):
        d = os.path.join(out, c, cfg)
        if not os.path.isdir(d) or ran(d):
            continue
        for f in os.listdir(d):
            if f.endswith(".log"):
                seen.update((f, k) for _, r in lines(os.path.join(d, f)) for k in r)
    return seen


def hr23(out):
    """The readings that show which DNP3 parser ran, per capture and
    configuration (the design's section 4.4). The judge reads none of them."""
    cfgs = [c for c in ("zeek",) + HR23 + ("zeek-probe",) if c in present(out)]
    print("\n## HR-23's readings (docs/phase4/D4-hr23-design.md, section 4.4)\n")
    print("Not judged: they show which parser ran. `named by conn.log` is C0's reading of a DNP3 flow (its `service` "
          "holds dnp3), and `servers from the link rows` is part (a)'s (C1, C1p, C2): the ends the frames' DIR bits "
          "name. `both ends` counts flows whose frames name two servers, which part (a) logs and never suppresses. "
          "`DIR against code` counts application headers whose frame's DIR disagrees with the code's class (DIR set "
          "on 129 to 131, or clear on any other code). `129-131 as request` counts application headers with code 129 "
          "to 131 raised as a request header, from either side: under C2, a fragment shorter than a response header "
          "(D2's (A) on #715). An outstation's such frame has DIR clear, so `DIR against code` does not count it. "
          "analyzer.log is read for the analyzer and `failure_reason` "
          "only, never `failure_data`. reporter.log is read for each row's level and message (D4-100 item 2: no "
          "reporter or analyzer error that the control lacks).\n")
    print("| capture | configuration | dnp3_ weirds | analyzer.log (analyzer: reason) | reporter.log (level: message) "
          "| DIR against code | 129-131 as request | both ends | DNP3 flows: named by conn.log; servers from the link rows |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for c in sorted(x for x in os.listdir(out) if os.path.isdir(os.path.join(out, x))):
        for cfg in cfgs:
            d = os.path.join(out, c, cfg)
            why = ran(d)
            if why:
                if os.path.isdir(d):
                    print(f"| {c} | {cfg} | | | | | | | {why} |")
                continue
            r = hr23_readings(d, cfg)
            if not (r["weirds"] or r["analyzer"] or r["reporter"] or r["flows"]):
                continue
            fmt = lambda k: ", ".join(f"{x}={n}" for x, n in sorted(k.items())) or "-"
            flows = "; ".join(f"{e}: {'yes' if b else 'no'}; "
                              + ("-" if l is None else ", ".join(f"{h}:{p}" for h, p in sorted(l)) or "none")
                              for e, b, l in r["flows"]) or "-"
            dis = "-" if r["disagree"] is None else r["disagree"]
            rar = "-" if r["resp_as_request"] is None else r["resp_as_request"]
            print(f"| {c} | {cfg} | {fmt(r['weirds'])} | {fmt({f'{a}: {b}': n for (a, b), n in r['analyzer'].items()})} "
                  f"| {fmt(r['reporter'])} | {dis} | {rar} | {r['both'] if cfg in LINKED else '-'} | {flows} |")
    have = present(out)
    if "zeek-probe-c2" in have:
        c2 = log_fields(out, "zeek-probe-c2")
        print("\n**Records and fields under C2 that C1 and C1p do not emit** (D4-100 item 2; the design's section 4.3): ")
        for ref in ("zeek-probe", "zeek-probe-c1p"):
            extra = sorted(c2 - log_fields(out, ref)) if ref in have else None
            shown = "not run" if extra is None else (", ".join(f"{f}:{k}" for f, k in extra) or "none")
            print(f"- against {ref}: {shown}")
        print()


# HR-23's judge (brief P4-4-HR23-JUDGE; D4-113 item 3.2): out-hr23/ and
# out-fp/, written by run.sh's hr23_feed, judged against D6's
# hr23-conditions.tsv, hr23-cases.tsv and hr23-malformed.tsv. Each rule is
# named by its id in hr23-conditions.tsv. A configuration that did not run,
# or did not exit 0, is never read as a pass or as zero.
JUDGED = ("zeek-probe-c0", "zeek-probe", "zeek-probe-c1p", "zeek-probe-c2")
CELL_OF = dict(zip(JUDGED, ("c0", "c1", "c1p", "c2")))
GP = "tests/integration/gt_pcap"
GT = "tests/fixtures/network/gt-pcap"
NO_TABLES = {"zeek_fc": {}, "zeek_modbus_fc": {}}
DNP3_ANALYZERS = ("DNP3_UDP", "DNP3_TCP")
# err=target: AddToBuffer's invalid-target-length reporter error (design 4.3).
TARGET_ERROR = "invalid target length"
# mal-link: inputs whose link rows are reported, not judged, under C1, C1p and C2.
MAL_LINK = tuple(f"dnp3-mal-udp-{x}" for x in ("len-0", "len-1", "len-2", "len-3", "len-4-nofir", "len-4-firfin",
                                                 "len-4-fir", "chunk-crc", "nofir", "nofin-fir", "limit")) + \
    tuple(f"dnp3-mal-tcp-eof-{x}" for x in ("firopen-fin", "firopen-open", "badchunk-fin", "len4-fin"))
# judge-objects: the case that is each object's own control under C0.
OBJ_CONTROL = {"g34v1": "dnp3-udp-swap-control", "g12v1": "dnp3-udp-dir-spoof",
               **{g: "dnp3-udp-master-short" for g in ("g60v1", "g60v2", "g60v3", "g60v4", "g80v1", "g50v1")}}
SWAP, PREMISE = "dnp3-udp-swap-control", "dnp3-udp-master-short"
BOTH_EXPECTED = ("dnp3-udp-dir-spoof", "dnp3-tcp-dir-spoof")  # judge-both
PORTS_LINE = re.compile(r"likely_server_ports at zeek_done: tcp \[([0-9, ]*)\]; udp \[([0-9, ]*)\]")


def read_ports(path):
    """cfg-ports: {"tcp": set, "udp": set} from ports.zeek's zeek_done line in
    PATH, or None when the file or the line is missing."""
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            m = PORTS_LINE.search(ln)
            if m:
                return {l4: {int(x) for x in g.split(",") if x.strip()} for l4, g in zip(("tcp", "udp"), m.groups())}
    return None


def sides_moved(ports, want, l4, flow_ports):
    """cfg-ports: None when every port of the flow falls on the same side of
    the configuration's likely_server_ports as of the pinned set (WANT), else
    why the flow reads unknown under that configuration. An empty port (a
    service row names no source port) is no port."""
    if ports is None:
        return "unknown (likely_server_ports not printed under this configuration)"
    moved = sorted({int(p) for p in flow_ports if p and (int(p) in ports[l4]) != (int(p) in want[l4])})
    return f"unknown (likely_server_ports differs from the pinned set at {l4}/{','.join(map(str, moved))})" \
        if moved else None


def flow_uids(d, l4, e):
    """The uids of conn.log's records of the flow with transport L4 and ends E."""
    return {r["uid"] for _, r in lines(os.path.join(d, "conn.log"))
            if r.get("proto") == l4 and ends(r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"]) == e}


def svc_names(r):
    """conn.log's service, split; a DNP3 name counts only exactly (mal-states)."""
    return {x.strip().lower() for x in str(r.get("service") or "").split(",") if x.strip()}


def packet_time_us(pcap, n):
    """The time of the capture's Nth packet (1-based), in microseconds, from
    its record header alone; None when it has fewer."""
    sys.path.insert(0, os.path.join(ROOT_DIR[0], GP))
    import pcapfile  # noqa: E402 (D6's reader; no payload is read here)
    frames = pcapfile.read(pcap)
    return round(frames[n - 1].ns / 1000) if len(frames) >= n else None


ROOT_DIR = ["."]


def link_present(d, row, pcap):
    """judge-link: a link row of the script's on the row's flow with is_orig
    as the row's `show` names, stamped with the time of the packet it names."""
    m = re.search(r"is_orig (true|false) stamped with packet (\d+)'s time", row["show"])
    if not m:
        return "unknown (the row's show names no packet)", ""
    t = packet_time_us(pcap, int(m.group(2))) if os.path.isfile(pcap) else None
    if t is None:
        return "unknown (the capture's packet time is not read)", ""
    uids = flow_uids(d, row["l4"], ends(row["src"], row["sport"], row["dst"], row["dport"]))
    for i, r in lines(os.path.join(d, "otsec_probe.log")):
        if (r.get("kind") == "link" and r.get("uid") in uids and r.get("is_orig") == (m.group(1) == "true")
                and round(float(r["ts"]) * 1e6) == t):
            return "present", f"otsec_probe.log:{i}"
    return "absent", ""


def case_results(rows, d, cfg, pcap, ports, want):
    """judge-rows, judge-link and cfg-ports: {index: (result, citation)} for
    one capture's hr23-cases.tsv rows under one configuration. An objects
    row is the Objects reading of the function row with the same columns,
    which rule 9 matches once (so the two never compete for one message)."""
    why = ran(d)
    if why:
        return {n: (f"unknown ({why})", "") for n, _ in rows}
    s = zeek(d, cfg, NO_TABLES)
    plain = [(n, r) for n, r in rows if r["condition"] not in ("objects", "link")]
    res = judge_capture(plain, s)
    key = lambda r: tuple(r[k] for k in ("l4", "src", "sport", "dst", "dport", "code", "objects"))
    fn_of = {key(r): n for n, r in plain if r["condition"] == "function"}
    out = {}
    for n, r in rows:
        moved = sides_moved(ports, want, r["l4"], (r["sport"], r["dport"]))
        if moved:
            out[n] = (moved, "")
        elif r["condition"] == "link":
            out[n] = link_present(d, r, pcap)
        elif r["condition"] == "objects":
            f = fn_of.get(key(r))
            if f is None:
                out[n] = ("unknown (no function row with the same columns)", "")
                continue
            fr, cite = res[f]
            m = re.search(r"objects pass (\S+)", fr)
            out[n] = ("pass", m.group(1)) if m else (fr if fr.startswith("unknown") else "fail", cite if m else "")
        else:
            out[n] = res[n]
    return out


def outcome(expected, result):
    """judge-cells: `as pinned`, `not as pinned`, `unknown` (a result that
    did not run, or cfg-ports) or `reported` (a ? cell)."""
    if result.startswith("unknown"):
        return "unknown"
    if expected.strip() == "?":
        return "reported"
    word = lambda x: x.split(" ", 1)[0].rstrip(";")
    return "as pinned" if word(result) == word(expected) else "not as pinned"


def relay_started(root, cap):
    """A UDP case whose first sender is the outstation (judge-swap), from the
    builder's labels only: hr23/ (the role of the first packet's unit) or
    dnp3/ (the flow's src is the service row's dst)."""
    p = os.path.join(root, GT, HR23_DIR, cap + ".tsv")
    if os.path.isfile(p):
        units = [r for r in tsv(p) if r.get("packets", "").split(",")[0].isdigit()]
        first = min(units, key=lambda r: int(r["packets"].split(",")[0]), default=None)
        return bool(first) and first["flow"].startswith("udp ") and first["role"] == "outstation"
    p = os.path.join(root, GT, "dnp3", cap + ".tsv")
    if os.path.isfile(p):
        lab = tsv(p)
        flows = [r for r in lab if r["kind"] == "flow" and r["l4"] == "udp"]
        servers = {r["dst"] for r in lab if r["kind"] == "service"}
        return bool(flows) and flows[0]["src"] in servers
    return False


def judge_cases(conds, res, root):
    """judge-fix, judge-control, judge-objects, judge-swap, judge-link,
    judge-regression and the premise, over every row's results under the
    four configurations (RES: {cfg: {index: (result, citation)}}). Returns
    ({index: {cfg: outcome}}, {index: fix reading}, [(captures, finding)],
    {index: the captures its fix reading was read from}); the last two let
    the cases' table hold back what rests on a held capture."""
    oc = {n: {cfg: outcome(r[CELL_OF[cfg]], res[cfg][n][0]) for cfg in JUDGED} for n, r in enumerate(conds)}
    findings = []
    deps = {n: {r["capture"]} for n, r in enumerate(conds)}
    # judge-link: without the replayed link row under C1, C1's pass on the
    # case's Service row reads unknown.
    for n, r in enumerate(conds):
        if r["condition"] == "link" and not res["zeek-probe"][n][0].startswith("present"):
            for k, x in enumerate(conds):
                if x["capture"] == r["capture"] and x["condition"] == "service" \
                        and res["zeek-probe"][k][0].startswith("pass"):
                    oc[k]["zeek-probe"] = "unknown"
    c0 = lambda n: res["zeek-probe-c0"][n][0]
    swap_failed = any(c0(n).startswith("fail") for n, r in enumerate(conds) if r["capture"] == SWAP)
    swap_unrun = any(c0(n).startswith("unknown") for n, r in enumerate(conds) if r["capture"] == SWAP)
    premise = [n for n, r in enumerate(conds) if r["capture"] == PREMISE]
    if any(c0(n).startswith("fail") for n in premise):
        findings.append(({PREMISE}, f"premise: a row of {PREMISE} fails under C0, so option (i)'s premise does not hold"))
    obj_failed = {}
    for g, cap in OBJ_CONTROL.items():
        ctl = [n for n, r in enumerate(conds) if r["capture"] == cap and r["condition"] == "objects"
               and g in r["objects"].split(",")]
        obj_failed[g] = "unknown" if not ctl or any(c0(n).startswith("unknown") for n in ctl) else \
            any(c0(n).startswith("fail") for n in ctl)
    fix = {}
    for n, r in enumerate(conds):
        o, f = oc[n], r["fix"]
        ctl_off = [CELL_OF[c] for c in ("zeek-probe-c0", "zeek-probe", "zeek-probe-c1p") if o[c] == "not as pinned"]
        if ctl_off and f not in ("unknown", "r1"):
            findings.append(({r["capture"]}, f"judge-control: {r['capture']} {r['condition']} {r['code']} "
                                              f"{r['objects']}: {', '.join(ctl_off)} not as pinned"))
        if f == "unknown":
            fix[n] = "unknown (C0 passes the row)"
        elif f == "r1":
            fix[n] = "r1: reported against its pin, never a pass"
        elif f in ("control", "premise"):
            fix[n] = f
        elif any(o[c] == "unknown" for c in JUDGED if not (f == "a" and c == "zeek-probe-c2")):
            fix[n] = "unknown (a configuration did not run, or cfg-ports)"
        elif ctl_off:
            fix[n] = f"unknown (judge-control: {', '.join(ctl_off)} not as pinned)"
        else:
            # From here on the reading rests on other captures' rows too.
            relay = relay_started(root, r["capture"])
            objs = r["objects"].split(",") if f == "b" and r["condition"] == "objects" else []
            if relay:
                deps[n].add(SWAP)
            if relay and (swap_failed or swap_unrun):
                fix[n] = "unknown (judge-swap: the swap's control " + ("fails under C0)" if swap_failed else "did not run)")
                continue
            deps[n].update(OBJ_CONTROL[g] for g in objs if g in OBJ_CONTROL)
            if any(obj_failed.get(g, "unknown") is not False for g in objs):
                fix[n] = "unknown (judge-objects: an object's own control does not pass under C0)"
            elif f == "a":
                fix[n] = "a shows"
            elif f == "b":
                fix[n] = "b shows" if o["zeek-probe-c2"] == "as pinned" else "b does not show"
            else:
                fix[n] = f"unknown (fix column {f} is not a judge-fix value)"
    # judge-regression.
    for n, r in enumerate(conds):
        if r["c2"] == "pass" and res["zeek-probe-c2"][n][0].startswith("fail"):
            by = "the patch" if res["zeek-probe-c1p"][n][0].startswith("pass") else "the build"
            findings.append(({r["capture"]}, f"judge-regression: {r['capture']} {r['condition']} {r['code']}: "
                                              f"C2 fails, of {by}"))
        if r["c1"] == "pass" and res["zeek-probe"][n][0].startswith("fail"):
            findings.append(({r["capture"]}, f"judge-regression: {r['capture']} {r['condition']} {r['code']}: "
                                              "C1 fails, of part (a)"))
    return oc, fix, findings, deps


def both_findings(out, caps):
    """judge-both: flows whose link rows name both ends, under C1, C1p and
    C2, anywhere but the two cases that expect them."""
    found = []
    for c in caps:
        for cfg in ("zeek-probe", "zeek-probe-c1p", "zeek-probe-c2"):
            d = os.path.join(out, c, cfg)
            if not ran(d) and hr23_readings(d, cfg)["both"] and c not in BOTH_EXPECTED:
                found.append(({c}, f"judge-both: {c} under {cfg}"))
    return found


# The malformed set (mal- rows).
def mal_tokens(cell):
    """[(name, value)] of a hr23-malformed.tsv cell; `=c1p` reads as [("=", "c1p")]."""
    cell = cell.strip()
    if cell == "=c1p":
        return [("=", "c1p")]
    return [tuple(t.strip().split("=", 1)) for t in cell.split(";") if t.strip()]


def mal_labels(root, inp):
    """{message: (sender address, code, objects)} and the flow (l4, ends,
    ports) from the builder's labels. The flow's first address is the
    sender of the earliest unit."""
    rows = tsv(os.path.join(root, GT, HR23_DIR, inp + ".tsv"))
    l4, pair = rows[0]["flow"].split(" ", 1)
    a, b = pair.split(">")
    (ah, ap), (bh, bp) = a.rsplit(":", 1), b.rsplit(":", 1)
    units = [r for r in rows if r["message"] not in ("-", "")]
    first = min(units, key=lambda r: int(r["packets"].split(",")[0]))["end"]
    addr = {first: ah, ("o" if first == "m" else "m"): bh}
    msgs = {}
    for r in units:
        # A message's code and objects come from its first unit that names a
        # code; a unit whose octets carry none names `-`.
        if msgs.get(r["message"], (None, None))[1] is None:
            objs = frozenset() if r["objects"] in ("-", "") else frozenset(r["objects"].split(","))
            msgs[r["message"]] = (addr[r["end"]], int(r["code"]) if r["code"].isdigit() else None, objs)
    return msgs, l4, ends(ah, ap, bh, bp), (ap, bp)


def mal_reading(d, l4, e):
    """What the judge reads on the input's flow: violations by analyzer,
    weirds by name, reporter rows, the probe's function rows (sender, code,
    objects) and link rows, reqhdr, and conn.log's service. No payload."""
    uids = flow_uids(d, l4, e)
    rd = {"viol": collections.Counter(), "weirds": collections.Counter(), "reporter": collections.Counter(),
          "fn": [], "link": [], "reqhdr": 0, "svc": set()}
    for _, r in lines(os.path.join(d, "conn.log")):
        if r["uid"] in uids:
            rd["svc"] |= svc_names(r)
    for _, r in lines(os.path.join(d, "analyzer.log")):
        if r.get("uid") in uids:
            rd["viol"][r.get("analyzer_name") or "?"] += 1
    for _, r in lines(os.path.join(d, "weird.log")):
        if r.get("uid") in uids:
            rd["weirds"][r.get("name") or "?"] += 1
    for _, r in lines(os.path.join(d, "reporter.log")):
        rd["reporter"][(str(r.get("level") or "?"), str(r.get("message") or "?"))] += 1
    cur = None
    for _, r in lines(os.path.join(d, "otsec_probe.log")):
        if r.get("uid") not in uids:
            continue
        if r["kind"] == "fc":
            cur = [r["is_orig"], r["fc"], []]
            rd["fn"].append(cur)
            if r["fc"] in RESPONSE_CODES and str(r.get("ev", "")).endswith("request_header"):
                rd["reqhdr"] += 1
        elif r["kind"] == "obj" and cur is not None and cur[0] == r["is_orig"]:
            cur[2].append(f"g{r['group']}v{r['variation']}")
        elif r["kind"] == "link":
            rd["link"].append((r["is_orig"], r.get("link_dir")))
    conn = {u: r for _, r in lines(os.path.join(d, "conn.log")) for u in [r["uid"]] if u in uids}
    orig = next((r["id.orig_h"] for r in conn.values()), None)
    resp = next((r["id.resp_h"] for r in conn.values()), None)
    rd["fn"] = sorted(((orig if o else resp), fc, frozenset(objs)) for o, fc, objs in rd["fn"])
    rd["link"] = sorted(rd["link"], key=str)
    return rd


def msg_states(msgs, tokens, fn):
    """mal-seen: {message: result} for every message the cell names =seen,
    =code or =absent, matched one to one with the flow's function rows
    (rule 9). A row fits a message of its sender and code when: =seen, it
    carries every object the label names; =code, none of them; otherwise
    (=absent, ?, or not named), it carries no object the label does not
    name. A message is absent when adding it to the others does not grow the
    matching."""
    named = {k: v for k, v in tokens if k in msgs}

    def fits(m, row):
        sender, code, objs = msgs[m]
        if row[0] != sender or row[1] != code:
            return False
        st = named.get(m)
        return objs <= row[2] if st == "seen" else not (objs & row[2]) if st == "code" else row[2] <= objs

    def size(ms):
        return len(assign(ms, fn, fits))

    out = {}
    pos = [m for m in msgs if named.get(m) in ("seen", "code")]
    got = assign(pos, fn, fits)
    for i, m in enumerate(pos):
        out[m] = "holds" if i in got else "does not hold"
    for m, st in named.items():
        if st == "absent":
            others = [x for x in msgs if x != m]
            out[m] = "holds" if size(others + [m]) == size(others) else "does not hold"
    return out


def judge_mal_cell(cell, rd, msgs):
    """[(token, holds?)] for one cell under one configuration, and the
    failures of mal-states' fourth state and mal-errors."""
    toks = mal_tokens(cell)
    res, fails = [], []
    states = msg_states(msgs, toks, rd["fn"])
    dnp3_viol = sum(n for a, n in rd["viol"].items() if a in DNP3_ANALYZERS)
    for k, v in toks:
        if v == "?":
            res.append((f"{k}=?", "reported"))
            continue
        if k == "viol":
            ok = dnp3_viol == int(v)
        elif k == "svc":
            has = bool(rd["svc"] & {"dnp3_udp", "dnp3_tcp"})
            ok = has if v == "dnp3" else not has
        elif k == "reqhdr":
            ok = rd["reqhdr"] == int(v)
        elif k == "weird":
            ok = rd["weirds"][v] > 0
        elif k == "err":
            ok = any(TARGET_ERROR in m for (lv, m) in rd["reporter"] if "ERROR" in lv.upper())
        elif k in msgs:
            ok = states.get(k) == "holds"
        else:
            res.append((f"{k}={v}", "not a token the judge knows"))
            fails.append(f"{k}={v}: not a token the judge knows")
            continue
        res.append((f"{k}={v}", "holds" if ok else "does not hold"))
        if not ok:
            fails.append(f"{k}={v}")
    other = sorted(a for a in rd["viol"] if a not in DNP3_ANALYZERS)
    if other:
        fails.append(f"analyzer.log row under {', '.join(other)} (mal-states' fourth state)")
    allowed = any(k == "err" and v == "target" for k, v in toks)
    errs = [m for (lv, m) in rd["reporter"] if "ERROR" in lv.upper() and not (allowed and TARGET_ERROR in m)]
    if errs:
        fails.append(f"{len(errs)} reporter error(s) the cell does not name (mal-errors)")
    return res, fails


def same_as(a, b, link):
    """mal-same: what differs between two readings (C2 against C1p)."""
    keys = ["viol", "weirds", "reporter", "fn", "reqhdr"] + (["link"] if link else [])
    return [k for k in keys if a[k] != b[k]]


def judge_malformed(out, root, mal, ports_of, want):
    """{input: {cfg: (verdict, detail)}} for every hr23-malformed.tsv input.
    Verdicts: pass, fail, unknown (did not run, or cfg-ports) or reported
    (mal-unknown's C2, a ? cell)."""
    res = {}
    for row in mal:
        inp = row["input"]
        msgs, l4, e, fports = mal_labels(root, inp)
        rds, res[inp] = {}, {}
        for cfg in JUDGED:
            d = os.path.join(out, inp, cfg)
            if not os.path.isfile(os.path.join(d, "exit-code")):
                res[inp][cfg] = ("unknown", "not run")
                continue
            why = ran(d)
            if why:
                res[inp][cfg] = ("fail", f"{why}: a crash is a finding (mal-errors)")
                continue
            moved = sides_moved(ports_of.get(cfg), want, l4, fports)
            if moved:
                res[inp][cfg] = ("unknown", moved[len("unknown ("):-1])
                continue
            rds[cfg] = mal_reading(d, l4, e)
        # mal-errors under C2 where its cell is not judged token by token: the
        # one reporter error the input's c0 cell names is allowed there too.
        errs_only = "; ".join(f"{k}={v}" for k, v in mal_tokens(row["c0"]) if k == "err")
        for cfg, rd in rds.items():
            c2 = cfg == "zeek-probe-c2"
            cell = row["c2"] if c2 else row["c0"]
            if c2 and row["judge"] == "unknown":
                _, fails = judge_mal_cell(errs_only, rd, msgs)
                ref = rds.get("zeek-probe-c1p")
                diff = "C1p not read" if ref is None else (", ".join(same_as(rd, ref, False)) or "none")
                res[inp][cfg] = ("fail", "; ".join(fails)) if fails else \
                    ("reported", f"mal-unknown: measured, not judged; differs from C1p in: {diff}")
                continue
            if c2 and cell.strip() == "=c1p":
                ref = rds.get("zeek-probe-c1p")
                if ref is None:
                    res[inp][cfg] = ("unknown", "C1p's reading is not there to compare")
                    continue
                diff = same_as(rd, ref, inp not in MAL_LINK)
                _, fails = judge_mal_cell(errs_only, rd, msgs)
                fails = ([f"differs from C1p in: {', '.join(diff)} (mal-same)"] if diff else []) + fails
                res[inp][cfg] = ("fail", "; ".join(fails)) if fails else ("pass", "equals C1p")
                continue
            toks, fails = judge_mal_cell(cell, rd, msgs)
            shown = "; ".join(f"{t} {h}" for t, h in toks)
            res[inp][cfg] = ("fail", "; ".join(fails)) if fails else ("pass", shown)
    return res


# The false-positive set (fp- rows).
FP_ZERO = ("1", "2", "4", "5", "6", "6-hole")  # fp-1245 and fp-6: = 0 under both readings


def fp_reading(d, cfg):
    """One class under one configuration: the flows named by conn.log, by a
    link row (C1, C1p, C2 only), the DNP3 violations and dnp3_ weirds."""
    s = zeek(d, cfg, NO_TABLES)
    key = lambda f: (f["l4"], ends(*f["orig"], *f["resp"]))
    by_conn = {key(f) for f in s.flows if {"dnp3_udp", "dnp3_tcp"} & {x.lower() for x in f["names"]}}
    by_link = {key(f) for f in s.flows if f.get("dnp3_servers")} if cfg in LINKED else None
    viol = sum(1 for _, r in lines(os.path.join(d, "analyzer.log")) if r.get("analyzer_name") in DNP3_ANALYZERS)
    weirds = collections.Counter(r["name"] for _, r in lines(os.path.join(d, "weird.log"))
                                 if str(r.get("name", "")).startswith("dnp3_"))
    return {"conn": by_conn, "link": by_link, "viol": viol, "weirds": weirds}


def judge_fp(out_fp, root, kept):
    """{class: {"items": n, "read": {cfg: reading or why not}, "rules": [(rule, verdict)]}}.
    A class that was not fed, not kept or did not run under a configuration
    reads `not run` for every rule that needs that configuration: an
    unfed class is never read as zero."""
    res = {}
    with open(os.path.join(root, GT, "fp", "fp.sha256"), encoding="utf-8") as fh:
        caps = sorted(f[1][: -len(".pcap")] for f in (ln.split() for ln in fh) if len(f) == 2 and f[1].endswith(".pcap"))
    for cap in caps:
        lab = tsv(os.path.join(root, GT, "fp", cap + ".tsv"))
        cls = lab[0]["class"] if lab else cap
        read = {}
        for cfg in JUDGED:
            d = os.path.join(out_fp, cap, cfg)
            why = "not fed" if cap not in kept else ran(d)
            read[cfg] = why if why else fp_reading(d, cfg)
        rules = []
        ok = lambda cfg: not isinstance(read[cfg], str)

        def bound(rule, cfgs, readings, want):
            for cfg in cfgs:
                for rdg in readings:
                    if not ok(cfg):
                        rules.append((f"{rule} {CELL_OF[cfg]} {rdg}", f"not run ({read[cfg]})"))
                        continue
                    v = read[cfg][rdg] if rdg != "viol" else read[cfg]["viol"]
                    if v is None:
                        continue
                    n = v if isinstance(v, int) else len(v)
                    w = want if isinstance(want, int) else want(len(lab))
                    rules.append((f"{rule} {CELL_OF[cfg]} {rdg}", f"{'pass' if n == w else 'fail'} ({n}, bound {w})"))
        if cls in FP_ZERO:
            bound("fp-1245" if cls in ("1", "2", "4", "5") else "fp-6", JUDGED, ("conn", "link"), 0)
        if cls == "3b-link":
            bound("fp-3blink", JUDGED[1:], ("link",), 0)
        if cls == "3c":
            bound("fp-3c", JUDGED[:3], ("viol",), lambda n: n)
        if cls in ("3b-data", "3c"):
            a, b = "zeek-probe-c2", "zeek-probe-c1p"
            if ok(a) and ok(b):
                diff = [k for k in ("conn", "link", "viol", "weirds") if read[a][k] != read[b][k]]
                rules.append((f"fp-{cls.replace('-', '')} C2 equals C1p",
                               "pass" if not diff else f"fail (differs in {', '.join(diff)})"))
            else:
                rules.append((f"fp-{cls.replace('-', '')} C2 equals C1p", "not run"))
        a, b = "zeek-probe-c2", "zeek-probe-c1p"
        for rdg in ("conn", "link"):
            if ok(a) and ok(b):
                extra = read[a][rdg] - read[b][rdg]
                rules.append((f"fp-b {rdg}", "pass" if not extra else f"fail ({len(extra)} flow(s) named by C2 alone)"))
            else:
                rules.append((f"fp-b {rdg}", "not run"))
        res[cls] = {"capture": cap, "items": len(lab), "read": read, "rules": rules}
    return res


def cases(out, pcaps, root, ports_of, want, counted, env=None):
    """hr23-cases.tsv's rows, under D1's ruling 7056743490 on #776 (D4-122).
    The held list and the salt come from the environment (hr23_feed.py's
    HELD_ENV and SALT_ENV), never from a committed file; without either, no
    row is judged or printed, and a counted run exits 3. Every row of a held
    capture reads HELD, and a fix reading that rests on a held capture reads
    `held (depends on a held row)`; no result, citation or finding of a held
    capture is printed, and held captures are left out of the counts. One
    SHA-256 is printed, over the salt and the held captures' verdict lines:
    each held row's line as this table would print it, then each finding
    that names a held capture, each followed by a newline. Returns the exit
    code."""
    # Imported here, not at the top: table.py's other modes run without -B,
    # and the import would write __pycache__ into the mounted folder.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import hashlib
    import hr23_feed
    print("\n### hr23-cases.tsv's rows\n")
    held, why = hr23_feed.held_list(set(hr23_feed.pins(os.path.join(root, GT, HR23_DIR, "hr23.sha256"))), env)
    salt = hr23_feed.salt_of(env)
    if not why and salt is None:
        why = f"the salt ({hr23_feed.SALT_ENV}) was not given, or is shorter than {hr23_feed.SALT_MIN} characters"
    if why:
        print(f"Not judged or printed: {why} (D1's ruling 7056743490 on #776)." +
              (" **This run is on refs/heads/main, so it fails: no counted HR-23 result is taken without the cases' "
               "rows.**" if counted and held is not False else ""))
        return 1 if held is False else (3 if counted else 0)
    conds = tsv(os.path.join(root, GP, "hr23-cases.tsv"))
    try:
        res = {cfg: {} for cfg in JUDGED}
        for cap in dict.fromkeys(r["capture"] for r in conds):
            rows = [(n, r) for n, r in enumerate(conds) if r["capture"] == cap]
            for cfg in JUDGED:
                res[cfg].update(case_results(rows, os.path.join(out, cap, cfg), cfg,
                                             os.path.join(pcaps, cap + ".pcap"), ports_of[cfg], want))
        oc, fix, findings, deps = judge_cases(conds, res, root)
        findings += both_findings(out, sorted({r["capture"] for r in conds}))
    except Exception:  # noqa: BLE001 (its text may concern a held capture)
        print("Not printed: the cases' judge stopped on an error, whose text is not printed because it may concern a "
              f"held capture ({hr23_feed.HELD}). The job fails.")
        return 1
    print("Each row under C0, C1, C1p and C2: `as pinned`, `not as pinned`, `unknown` or `reported`, with the result "
          f"and the log line it rests on; then the fix reading (judge-fix). Every row of a held capture reads "
          f"`{hr23_feed.HELD}`, and a fix reading that rests on a held capture reads `held (depends on a held row)` "
          "(D1's ruling 7056743490 on #776).\n")
    print("| capture | condition | code | objects | " + " | ".join(CELL_OF[c] for c in JUDGED) + " | fix |")
    print("| --- | --- | --- | --- |" + " --- |" * len(JUDGED) + " --- |")
    secret, tally, fixes = [], collections.Counter(), collections.Counter()
    for n, r in enumerate(conds):
        head = f"| {r['capture']} | {r['condition']} | {r['code']} | {r['objects']} | "
        cells = [f"{oc[n][cfg]}: {res[cfg][n][0]} {res[cfg][n][1]}".strip().replace("|", "/") for cfg in JUDGED]
        if r["capture"] in held:
            secret.append(head + " | ".join(cells) + f" | {fix[n]} |")
            print(head + " | ".join([hr23_feed.HELD] * (len(JUDGED) + 1)) + " |")
            continue
        f = "held (depends on a held row)" if deps[n] & held else fix[n]
        tally.update(oc[n][cfg] for cfg in JUDGED)
        fixes[f.split(" (")[0]] += 1
        print(head + " | ".join(cells) + f" | {f} |")
    shown = [t for caps, t in findings if not caps & held]
    secret += [t for caps, t in findings if caps & held]
    print("\nCells: " + ", ".join(f"{tally[k]} {k}" for k in ("as pinned", "not as pinned", "unknown", "reported")) +
          ". Fix readings: " + (", ".join(f"{n} {k}" for k, n in sorted(fixes.items())) or "none") +
          f". {len(held)} held captures are left out of these counts.")
    print("\n**Findings:** " + ("; ".join(shown) if shown else "none") + ".")
    digest = hashlib.sha256((salt + "\n" + "".join(x + "\n" for x in secret)).encode("utf-8")).hexdigest()
    print(f"\nHeld captures' verdict lines, salted SHA-256 (D1's ruling 7056743490 on #776): `{digest}`.")
    return 0


def kept_names(path):
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as fh:
        return {ln.strip() for ln in fh if ln.strip()}


def hr23judge(out, out_fp, fp_kept, root, ports_dir, pcaps, counted, env=None):
    """HR-23's judge: likely_server_ports under each configuration, the
    malformed set and the false-positive set judged, and hr23-cases.tsv's
    rows (`cases`, on the captures in PCAPS). Returns cases' exit code."""
    ROOT_DIR[0] = root
    sys.path.insert(0, os.path.join(root, GP))
    import hr23_cases  # noqa: E402 (LIKELY: the pinned set, cfg-ports)
    want = hr23_cases.LIKELY
    ports_of = {cfg: read_ports(os.path.join(ports_dir, cfg + ".txt")) for cfg in JUDGED}
    print("\n## HR-23's judge (hr23-conditions.tsv)\n")
    print("### likely_server_ports under each configuration (cfg-ports)\n")
    for cfg in JUDGED:
        p = ports_of[cfg]
        shown = "not printed" if p is None else \
            "; ".join(f"{l4} {', '.join(map(str, sorted(p[l4])))}" for l4 in ("tcp", "udp"))
        same = "" if p is None else (" (the pinned set)" if p == {k: set(v) for k, v in want.items()} else
                                     " (differs from the pinned set: flows on a moved port read unknown)")
        print(f"- {CELL_OF[cfg]} ({cfg}): {shown}{same}")
    mal = tsv(os.path.join(root, GP, "hr23-malformed.tsv"))
    mres = judge_malformed(out, root, mal, ports_of, want)
    print("\n### The malformed set (mal- rows)\n")
    print("Each input under C0, C1 and C1p on its c0 cell and under C2 on its c2 cell. An input that did not run "
          "reads unknown, never pass; a non-zero exit is a crash and fails (mal-errors).\n")
    print("| input | " + " | ".join(CELL_OF[c] for c in JUDGED) + " |")
    print("| --- |" + " --- |" * len(JUDGED))
    tally = collections.Counter()
    for row in mal:
        cells = []
        for cfg in JUDGED:
            v, detail = mres[row["input"]][cfg]
            tally[v] += 1
            cells.append(f"{v}: {detail}".replace("|", "/"))
        print(f"| {row['input']} | " + " | ".join(cells) + " |")
    print("\nMalformed cells: " + ", ".join(f"{tally[k]} {k}" for k in ("pass", "fail", "unknown", "reported")) + ".")
    fres = judge_fp(out_fp, root, kept_names(fp_kept))
    print("\n### The false-positive set (fp- rows)\n")
    print("Per class and configuration: flows named by conn.log, by a link row (C1, C1p, C2), DNP3 violations and "
          "dnp3_ weirds. A class not fed, or not run under a configuration, reads `not run`, never zero.\n")
    print("| class | items | " + " | ".join(CELL_OF[c] for c in JUDGED) + " | rules |")
    print("| --- | --- |" + " --- |" * len(JUDGED) + " --- |")
    for cls, r in fres.items():
        cells = []
        for cfg in JUDGED:
            x = r["read"][cfg]
            cells.append(f"not run ({x})" if isinstance(x, str) else
                         f"conn {len(x['conn'])}; link {'-' if x['link'] is None else len(x['link'])}; "
                         f"viol {x['viol']}; " + (", ".join(f"{k}={n}" for k, n in sorted(x["weirds"].items())) or "no weird"))
        rules = "; ".join(f"{k}: {v}" for k, v in r["rules"]) or "reported only"
        print(f"| {cls} | {r['items']} | " + " | ".join(cells) + f" | {rules} |")
    return cases(out, pcaps, root, ports_of, want, counted, env)

if __name__ == "__main__":
    if sys.argv[1] == "hr23":
        hr23(sys.argv[2])
        sys.exit(0)
    if sys.argv[1] == "hr23judge":
        if len(sys.argv) < 8 or sys.argv[8:] not in ([], ["--counted"]):
            print("usage: table.py hr23judge OUT OUT_FP FP_KEPT ROOT PORTS PCAPS [--counted]", file=sys.stderr)
            sys.exit(2)
        sys.exit(hr23judge(*sys.argv[2:8], sys.argv[8:] == ["--counted"], os.environ))
    if sys.argv[1] == "dnp3":
        dnp3(*sys.argv[2:6])
    elif sys.argv[1] == "fifo":
        fifo(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "sig":
        sig(*sys.argv[2:5])
    else:
        # public OUT PCAPS MANIFEST EXTRA [--counted]; any other trailing
        # argument is refused, never read as "not counted" (D3's N1 on #751).
        if len(sys.argv) < 6 or sys.argv[6:] not in ([], ["--counted"]):
            print("usage: table.py public OUT PCAPS MANIFEST EXTRA [--counted]", file=sys.stderr)
            sys.exit(2)
        counted = sys.argv[6:] == ["--counted"]
        if public(sys.argv[2], sys.argv[3], sys.argv[4:6], counted) and counted:
            sys.exit(3)

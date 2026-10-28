"""Writes the C2 0.6 golden examples for a configuration read (a register run)
in config/invocations/ and config/results/.

Run from this directory with `python3 -I generate_config.py`. The output is
committed; config_run_test.go checks it and config/README.md gives one line
per file. It builds on generate.py's Session, so the framing, prompts and
times are the ones every other C2 golden has.

The run is register revision 5's sel.config.read_all (C3 0.3, D4-13): SHO P 1
first, then SHO G, then the other 22 SHO forms of S22 Table 7.67 (p. 7.77),
one session. Every transcript is invented, and every result says target
"simulated". The setting lines are not S22's: the C9 goldens
(contracts/config/testdata) carry S22's printed layouts, and these exist to
give the C2 envelope something to point at. Each class prints a heading, a
blank line and a few settings, one of them wrapped. Whether a relay prints
anything like it is H-13.
"""

import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import generate as g  # noqa: E402  (a module of this directory, run with -I from here)

SCHEMA_0_6 = "otsec.adapter/0.6"
RUN = "sel.config.read_all"
REGISTER_REVISION = 5  # contracts/register/testdata/sel-751.json
# The commands of the run, in order (register revision 5). The first two are
# the gate (LANG, posture) and the DATE_F read; the others follow C9's order.
STEPS = [
    "SHO P 1", "SHO G",
    "SHO 1", "SHO 2", "SHO 3", "SHO 4", "SHO L 1", "SHO L 2", "SHO L 3", "SHO L 4",
    "SHO P F", "SHO P 2", "SHO P 3", "SHO P 4", "SHO R", "SHO F",
    "SHO M", "SHO I", "SHO E 1", "SHO E 2", "SHO E 3", "SHO DNP 1", "SHO DNP 2", "SHO DNP 3",
]
# Classes a relay may answer "Invalid Command" for (C9 decision 6).
OPTIONAL = {"SHO P 2", "SHO P 3", "SHO P 4", "SHO M", "SHO I", "SHO E 1", "SHO E 2", "SHO E 3",
            "SHO DNP 1", "SHO DNP 2", "SHO DNP 3"}
# What this relay does not have: the options it was not ordered with.
ABSENT = {"SHO P 2", "SHO P 3", "SHO P 4", "SHO M", "SHO I", "SHO E 1", "SHO E 2", "SHO E 3", "SHO DNP 2", "SHO DNP 3"}


def tag(cmd):
    return cmd[4:].replace(" ", "")


def body(cmd):
    """The invented reply of one class: rows, and the settings in them."""
    t = tag(cmd)
    rows = ["Class %s" % t, "",
            "S%sA := 10  S%sB := VALUE %s" % (t, t, t),
            "S%sC := IN101 AND" % t,
            "  NOT IN102",
            "S%sD := N" % t]
    fields = [("S%sA" % t, "10"), ("S%sB" % t, "VALUE %s" % t), ("S%sC" % t, "IN101 AND NOT IN102" % ()),
              ("S%sD" % t, "N")]
    return "\r\n".join(rows) + "\r\n\r\n", fields


def section(s, cmd, text=None, fields=None, prompt=b"=>"):
    """Sends cmd and receives its reply. Returns the received section's span
    and its fields."""
    s.tx("operate", (cmd + "\r\n").encode())
    if text is None:
        text, fields = body(cmd)
    start = s.rx("operate", g.framed((cmd + "\r\n").encode(), text, prompt))
    seg = s.segments[-1]
    a = s.data.index(g.STX, seg["offset"]) + 1
    b = s.data.index(g.ETX, a)
    return {"offset": a, "length": b - a}, fields, start


def rec(span, fields, absent=False, ok=True):
    r = {"kind": "sel.config.absent" if absent else "sel.config.section", "span": span, "parse_ok": ok}
    if fields and ok and not absent:
        r["fields"] = [{"name": n, "value": v} for n, v in fields]
    return r


def run_result(s, status, code, items, obs, warnings, records, detail=None):
    r = s.result(status, code, {"result": "match", "items": items}, obs, warnings, records, schema=SCHEMA_0_6)
    r["operation_id"] = RUN
    r["register_version"] = REGISTER_REVISION
    if detail:
        r["error"]["detail"] = detail
    return r


def read(upto=None, absent=ABSENT, bad=None, error_at=None, drop_at=None, timeout_at=None, big_at=None, echo=False):
    """A configuration read. upto is how many steps are sent before it fails;
    bad is a step whose reply the rule cannot read (a name printed twice);
    error_at answers a step with Invalid Command where the class may not be
    absent; drop_at ends a reply with the Level 0 prompt; timeout_at and
    big_at stop a reply in the middle."""
    s = g.Session()
    items, fid_span = g.to_level1(s, echo=echo)
    records, warnings, code = [], [], None
    for i, cmd in enumerate(STEPS):
        if cmd == "SHO P 1":
            s.sho_p1()
            warnings.append(g.maxacc_warning(s))
            span = s.message_span()
            records.append(rec(span, [("MAXACC", "2"), ("FASTOP", "N"), ("LANG", "ENGLISH"), ("EHTTP", "N"),
                                      ("FTPACC", "1"), ("HTTPACC", "1"), ("TIDLE", "15")]))
            continue
        if cmd == "SHO G":
            s.sho_g()
            span = s.message_span()
            records.append(rec(span, [("PHROT", "ABC"), ("FNOM", "60"), ("DATE_F", s.date_f),
                                      ("FAULT", "50G1P OR 50N1P OR 51P1P OR 51QP OR 50Q1P OR TRIP"),
                                      ("IRIGC", "NONE"), ("UTC_OFF", "0.00"), ("DST_BEGM", "OFF")]))
            continue
        if cmd == timeout_at:
            s.tx("operate", (cmd + "\r\n").encode())
            s.rx("operate", (cmd + "\r\n").encode() + g.STX + b"\r\nClass ")  # then nothing until the step timeout
            code = "failed.timeout"
            break
        if cmd == big_at:
            s.tx("operate", (cmd + "\r\n").encode())
            s.rx("operate", (cmd + "\r\n").encode() + g.STX + b"\r\n" + b"S1A := 10\r\n" * 40)
            code = "failed.response_too_large"
            break
        if cmd == drop_at:
            s.tx("operate", (cmd + "\r\n").encode())
            s.rx("operate", g.framed((cmd + "\r\n").encode(), b"Class\r\n\r\nS1A := 10\r\n\r\n", b"="))
            s.facts["access_level"] = "1"
            code = "failed.access_level_dropped"
            break
        if cmd == error_at:
            span, _, _ = section(s, cmd, b"Invalid Command\r\n", [])
            code = "failed.device_error"
            break
        if cmd in absent:
            span, _, _ = section(s, cmd, b"Invalid Command\r\n", [])
            records.append(rec(span, None, absent=True))
            continue
        if cmd == bad:
            text, fields = body(cmd)
            text = text.replace("S%sD := N" % tag(cmd), "S%sA := 11" % tag(cmd))  # a name printed twice
            span, _, _ = section(s, cmd, text, [])
            code = "failed.config_unparsable"
            break
        span, fields, _ = section(s, cmd)
        records.append(rec(span, fields))
    ok = code is None
    if code in ("failed.access_level_dropped",):
        pass
    elif code != "failed.timeout" and code != "failed.response_too_large":
        s.quit()
    else:
        s.quit()
    obs = [{"name": "firmware_id", "value": g.FID, "span": fid_span},
           {"name": "sel.cid", "value": g.CID, "span": s.span(g.CID, s.id_start)}]
    if ok:
        return run_result(s, "ok", None, items, obs, warnings, records)
    if code == "failed.config_unparsable":
        return run_result(s, "failed", code, items, [], warnings, [],
                          "the reply to %s is not a settings section; the read stops there" % bad)
    # A failed run keeps its bytes and reports no records and no observations.
    return run_result(s, "failed", code, items, [], warnings, [])


def results():
    out = {"ok": read(), "ok-with-echo": read(echo=True), "ok-all-present": read(absent=set())}
    out["failed.timeout-in-run"] = read(timeout_at="SHO L 2")
    out["failed.response_too_large-in-run"] = read(big_at="SHO 3")
    out["failed.access_level_dropped-in-run"] = read(drop_at="SHO L 1")
    out["failed.device_error-required-class-absent"] = read(error_at="SHO 2")
    out["failed.config_unparsable"] = read(bad="SHO F")
    return out


def invalid():
    """Results that C2 refuses. A run is ok with a parsed record per step, or
    it reports no record, so these break that rule on purpose."""
    out = {}
    # A failed run that still carries all 24 records.
    r = read()
    r["status"] = "failed"
    r["error"] = {"code": "failed.device_error"}
    out["failed-with-24-records"] = r
    # A run that ends partial.parse_errors, with the unparsed record that code needs.
    r = read()
    r["status"] = "partial"
    r["error"] = {"code": "partial.parse_errors"}
    bad = r["records"][5]
    r["records"][5] = {"kind": bad["kind"], "span": bad["span"], "parse_ok": False}
    out["partial.parse_errors-run"] = r
    return out


def invocation():
    with open(os.path.join(HERE, "invocations/valid/sel-ser-read.json")) as f:
        inv = json.load(f)
    inv["schema"] = SCHEMA_0_6
    inv["operation_id"] = RUN
    # expected_identity is the asset's whole binding, as for every invocation
    # (CheckAgainst). A run has no SER header, so it reads no serial_number and
    # its identity block holds the firmware_id item only, as for any SHO read.
    # Limits.ForRun: the run's total and deadline, the longest step timeout.
    inv["limits"].update(step_timeout_ms=10000, deadline_ms=300000, max_response_bytes=524288)
    return inv


def main():
    base = os.path.join(HERE, "config")
    for d in ("results/valid", "results/invalid", "invocations/valid"):
        p = os.path.join(base, d)
        os.makedirs(p, exist_ok=True)
        for f in os.listdir(p):
            if f.endswith(".json"):
                os.remove(os.path.join(p, f))
    for name, r in results().items():
        g.write(os.path.join(base, "results/valid", name + ".json"), r)
    for name, r in invalid().items():
        g.write(os.path.join(base, "results/invalid", name + ".json"), r)
    g.write(os.path.join(base, "invocations/valid", "sel-config-read.json"), invocation())


if __name__ == "__main__":
    main()

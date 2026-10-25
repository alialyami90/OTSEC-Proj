"""Reconcile what the upstream collector received with what the device printed
(A6, P2-A6). Standard library only, and independent of contracts/syslog: the
RFC 5424 parser here is A6's own.

Ground truth for the rows is A6's transcription of SEL-751 Figure 10.16
(tests/safety/recording_simulator/documented/sel-751/ser-fig-10-16.txt),
which is also what the simulator's documented profile answers to SER. The
claim checked is end to end: every row the device printed reaches the
collector exactly once, byte for byte, with its own time text, row number
and evidence class, and nothing else arrives as a SER event.
"""

import hashlib
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
SER_FIG = os.path.join(HERE, "..", "..", "safety", "recording_simulator", "documented", "sel-751",
                       "ser-fig-10-16.txt")
SDID = "otsec@32473"

_HEADER = re.compile(
    rb"<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) ")


def parse_rfc5424(msg):
    """Parse one RFC 5424 message (bytes). Returns a dict with pri, timestamp,
    hostname, app, procid, msgid, sd ({sd-id: [(name, value), ...]}) and msg
    (bytes or None). Raises ValueError on anything outside the grammar this
    suite needs."""
    m = _HEADER.match(msg)
    if not m:
        raise ValueError("not an RFC 5424 header")
    out = dict(pri=int(m[1]), timestamp=m[2].decode(), hostname=m[3].decode(), app=m[4].decode(),
               procid=m[5].decode(), msgid=m[6].decode(), sd={})
    i = m.end()
    if msg[i:i + 1] == b"-":
        i += 1
    else:
        while msg[i:i + 1] == b"[":
            j = i + 1
            k = j
            while k < len(msg) and msg[k:k + 1] not in (b" ", b"]"):
                k += 1
            sdid = msg[j:k].decode()
            params = []
            i = k
            while msg[i:i + 1] == b" ":
                eq = msg.index(b"=", i)
                name = msg[i + 1:eq].decode()
                if msg[eq + 1:eq + 2] != b'"':
                    raise ValueError("SD-PARAM value not quoted")
                v = bytearray()
                p = eq + 2
                while True:
                    c = msg[p:p + 1]
                    if c == b"":
                        raise ValueError("unterminated SD-PARAM value")
                    if c == b"\\" and msg[p + 1:p + 2] in (b'"', b"\\", b"]"):
                        v += msg[p + 1:p + 2]
                        p += 2
                        continue
                    if c == b'"':
                        break
                    v += c
                    p += 1
                params.append((name, v.decode("utf-8")))
                i = p + 1
            if msg[i:i + 1] != b"]":
                raise ValueError("SD-ELEMENT not closed")
            out["sd"].setdefault(sdid, []).extend(params)
            i += 1
    if i == len(msg):
        out["msg"] = None
    elif msg[i:i + 1] == b" ":
        out["msg"] = msg[i + 1:]
    else:
        raise ValueError("no SP before MSG")
    return out


def first(params, name):
    for n, v in params:
        if n == name:
            return v
    return None


def native_rows(path=SER_FIG):
    """The SER row lines as printed, newest last as in the figure, without
    their line end."""
    with open(path, "rb") as f:
        lines = f.read().replace(b"\r\n", b"\n").split(b"\n")
    rows = []
    for line in lines:
        fs = line.split()
        if len(fs) == 5 and fs[0].isdigit() and fs[1].count(b"/") == 2:
            rows.append(line)
    return rows


def row_time_text(row):
    """C4 device_time.native for a SEL ASCII SER row: the printed DATE and
    TIME field values joined by one space (C4 DeviceTime.Native, D1-25). The
    row's own spacing (three spaces) stays in the record bytes, dtext."""
    fs = row.split()
    return (fs[1] + b" " + fs[2]).decode()


def reconcile(messages, rows, invocation=None):
    """Compare received messages (bytes, in arrival order) with the device's
    rows. Returns (problems, stats). problems is a list of strings, empty on
    success."""
    problems = []
    by_eid = {}
    order = []
    duplicates = 0
    for k, raw in enumerate(messages):
        try:
            m = parse_rfc5424(raw)
        except ValueError as exc:
            problems.append(f"message {k}: {exc}")
            continue
        ps = m["sd"].get(SDID)
        if ps is None:
            problems.append(f"message {k}: no {SDID} element")
            continue
        if first(ps, "kind") != "ser":
            continue
        eid = first(ps, "eid")
        if eid is None:
            problems.append(f"message {k}: no eid")
            continue
        if eid in by_eid:
            duplicates += 1
            if by_eid[eid] != raw:
                problems.append(f"eid {eid}: delivered twice with different bytes")
            continue
        by_eid[eid] = raw
        order.append((eid, ps))
    want = {row: i for i, row in enumerate(rows)}
    seen = {}
    for eid, ps in order:
        dtext = first(ps, "dtext")
        if dtext is None:
            problems.append(f"eid {eid}: no dtext")
            continue
        row = dtext.encode("utf-8")
        if row not in want:
            problems.append(f"eid {eid}: dtext {dtext!r} is not a row the device printed")
            continue
        if row in seen:
            problems.append(f"row {want[row]}: two events ({seen[row]} and {eid})")
            continue
        seen[row] = eid
        checks = {
            "evc": "simulated",
            "pos": row.split()[0].decode(),
            "dt": row_time_text(row),
            "rsha256": hashlib.sha256(row).hexdigest(),
            "rlen": str(len(row)),
            "parse": "ok",
        }
        if invocation is not None:
            checks["inv"] = invocation
        for name, v in checks.items():
            got = first(ps, name)
            if got != v:
                problems.append(f"eid {eid} (row {checks['pos']}): {name}={got!r}, want {v!r}")
        if sum(1 for n, _ in ps if n == "evc") != 1:
            problems.append(f"eid {eid}: evc appears {sum(1 for n, _ in ps if n == 'evc')} times")
    for row, i in want.items():
        if row not in seen:
            problems.append(f"row {row.split()[0].decode()} ({i}): never arrived")
    # Order: the events, in the order the node numbered them, follow the
    # device's print order.
    numbered = sorted(((seq_of(eid), row) for row, eid in seen.items()), key=lambda x: x[0])
    got_order = [want[row] for _, row in numbered]
    if got_order != sorted(got_order):
        problems.append(f"event order {got_order} is not the device's print order")
    return problems, {"messages": len(messages), "unique": len(by_eid), "duplicates": duplicates,
                      "rows": len(rows), "matched": len(seen)}


def seq_of(eid):
    """The C5 seq at the end of a C4 event ID (node:stream:seq)."""
    tail = eid.rsplit(":", 1)[-1]
    return int(tail) if tail.isdigit() else -1


def row_key(row):
    """A row's content without its number: SEL-751 renumbers every row when
    a new one arrives (row 1 is the newest, Table 7.63), so across reads of a
    buffer that grows only the date, time, element and state identify it.
    Unique in the simulator's grown buffer, where every row has its own time;
    a real buffer can repeat it (C-13), which is why the product aligns
    snapshots instead."""
    return tuple(row.split()[1:])


def reconcile_grown(messages, rows, invocation=None):
    """reconcile for the simulator's grown buffer (ser="grow"), read many
    times with interruptions between and during the reads. rows are the
    buffer's rows as last printed, oldest first. Every row must arrive under
    exactly one event ID; one event ID may arrive more than once (a resend
    after a break), always with the same bytes. The row number in dtext is
    the one printed at the read that first saw the row, so it is checked
    against that read's own text only (pos equals it) and not against the
    last print. Returns (problems, stats) as reconcile does."""
    problems = []
    by_eid = {}
    order = []
    duplicates = 0
    for k, raw in enumerate(messages):
        try:
            m = parse_rfc5424(raw)
        except ValueError as exc:
            problems.append(f"message {k}: {exc}")
            continue
        ps = m["sd"].get(SDID)
        if ps is None:
            problems.append(f"message {k}: no {SDID} element")
            continue
        if first(ps, "kind") != "ser":
            continue
        eid = first(ps, "eid")
        if eid is None:
            problems.append(f"message {k}: no eid")
            continue
        if eid in by_eid:
            duplicates += 1
            if by_eid[eid] != raw:
                problems.append(f"eid {eid}: delivered twice with different bytes")
            continue
        by_eid[eid] = raw
        order.append((eid, ps))
    want = {row_key(row): i for i, row in enumerate(rows)}
    seen = {}
    for eid, ps in order:
        dtext = first(ps, "dtext")
        if dtext is None:
            problems.append(f"eid {eid}: no dtext")
            continue
        row = dtext.encode("utf-8")
        key = row_key(row)
        if key not in want:
            problems.append(f"eid {eid}: dtext {dtext!r} is not a row the device printed")
            continue
        if key in seen:
            problems.append(f"row {want[key]}: two events ({seen[key]} and {eid})")
            continue
        seen[key] = eid
        checks = {
            "evc": "simulated",
            "pos": row.split()[0].decode(),
            "dt": row_time_text(row),
            "rsha256": hashlib.sha256(row).hexdigest(),
            "rlen": str(len(row)),
            "parse": "ok",
        }
        if invocation is not None:
            checks["inv"] = invocation
        for name, v in checks.items():
            got = first(ps, name)
            if got != v:
                problems.append(f"eid {eid} (row {want[key]}): {name}={got!r}, want {v!r}")
    for key, i in want.items():
        if key not in seen:
            problems.append(f"row {i} ({b' '.join(key).decode()}): never arrived")
    numbered = sorted(((seq_of(eid), key) for key, eid in seen.items()), key=lambda x: x[0])
    got_order = [want[key] for _, key in numbered]
    if got_order != sorted(got_order):
        problems.append("event order is not the device's print order")
    return problems, {"messages": len(messages), "unique": len(by_eid), "duplicates": duplicates,
                      "rows": len(rows), "matched": len(seen)}

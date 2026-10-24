"""The reconciliation oracle catches what it claims to catch (A6).

Messages here are built by the test from A6's transcription, in the RFC 5424
shape C6 documents. A4's rendered golden is used as an input only.
"""

import hashlib
import os

import pytest

import reconcile as rc

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
ROWS = rc.native_rows()
INV = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30"


def esc(v):
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def message(row, seq, **over):
    p = {
        "v": "otsec.syslog/0.1", "eid": f"site-a6:a6/ser:{seq}", "kind": "ser", "evc": "simulated",
        "inv": INV, "pos": row.split()[0].decode(), "parse": "ok", "dt": rc.row_time_text(row),
        "rsha256": hashlib.sha256(row).hexdigest(), "rlen": str(len(row)), "dtext": row.decode(),
    }
    p.update(over)
    sd = " ".join(f'{k}="{esc(v)}"' for k, v in p.items() if v is not None)
    return f"<133>1 2026-10-24T12:00:05.123456Z site-a6 otsec - SER [{rc.SDID} {sd}] ser".encode()


def good():
    return [message(r, i + 1) for i, r in enumerate(ROWS)]


def test_rows_from_transcription():
    assert len(ROWS) == 8
    assert ROWS[0].split()[0] == b"8" and ROWS[-1].split()[0] == b"1"
    # The row prints three spaces between date and time; C4's native time
    # joins the two fields with one (D1-25), and dtext keeps the three.
    assert b"02/28/2007   13:54:09.602" in ROWS[0]
    assert rc.row_time_text(ROWS[0]) == "02/28/2007 13:54:09.602"


def test_good_reconciles():
    problems, stats = rc.reconcile(good(), ROWS, INV)
    assert problems == [] and stats["matched"] == 8 and stats["duplicates"] == 0


def test_identical_redelivery_is_counted_not_a_problem():
    msgs = good()
    problems, stats = rc.reconcile(msgs + [msgs[3]], ROWS, INV)
    assert problems == [] and stats["duplicates"] == 1


@pytest.mark.parametrize("name,mutate,expect", [
    ("lost row", lambda m: m[:4] + m[5:], "never arrived"),
    ("same eid, other bytes", lambda m: m + [message(ROWS[2], 3, val="x")], "different bytes"),
    ("two events for one row", lambda m: m + [message(ROWS[2], 99)], "two events"),
    ("time spacing changed", lambda m: [message(ROWS[0], 1, dt="02/28/2007   13:54:09.602")] + m[1:], "dt="),
    ("evc missing", lambda m: [message(ROWS[0], 1, evc=None)] + m[1:], "evc="),
    ("evc device-observed", lambda m: [message(ROWS[0], 1, evc="device-observed")] + m[1:], "evc="),
    ("wrong record hash", lambda m: [message(ROWS[0], 1, rsha256="0" * 64)] + m[1:], "rsha256="),
    ("wrong row number", lambda m: [message(ROWS[0], 1, pos="9")] + m[1:], "pos="),
    ("other invocation", lambda m: [message(ROWS[0], 1, inv="x")] + m[1:], "inv="),
    ("row not printed", lambda m: m + [message(ROWS[0].replace(b"51P1P", b"51P2P"), 50)], "not a row"),
    ("reordered", lambda m: [message(ROWS[1], 1), message(ROWS[0], 2)] + m[2:], "print order"),
    ("not RFC 5424", lambda m: m + [b"<13>Oct 24 12:00:00 host tag: x"], "not an RFC 5424"),
])
def test_mutations_caught(name, mutate, expect):
    problems, _ = rc.reconcile(mutate(good()), ROWS, INV)
    assert any(expect in p for p in problems), (name, problems)


def test_parser_escapes():
    m = rc.parse_rfc5424(b'<13>1 - h a - - [x@1 k="a\\"b\\\\c\\]d" j="e"] tail')
    assert m["sd"]["x@1"] == [("k", 'a"b\\c]d'), ("j", "e")] and m["msg"] == b"tail"
    assert rc.parse_rfc5424(b"<13>1 - h a - - -")["msg"] is None


def test_a4_golden_row8_matches_transcription():
    # Input only: A4's rendered row 8. The expected values come from A6's
    # transcription and SHA-256, not from the golden.
    p = os.path.join(REPO, "contracts", "syslog", "testdata", "rendered", "sel751-row8.rfc5424.txt")
    raw = open(p, "rb").read().rstrip(b"\r\n")
    ps = rc.parse_rfc5424(raw)["sd"][rc.SDID]
    assert rc.first(ps, "dtext").encode() == ROWS[0]
    assert rc.first(ps, "rsha256") == hashlib.sha256(ROWS[0]).hexdigest()
    assert rc.first(ps, "dt") == rc.row_time_text(ROWS[0])

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


# The grown buffer (ser="grow"): rows renumber at every read, so the oracle
# keys them on their content and allows a resend under the same event ID.

def grown(added):
    import sys
    sys.path.insert(0, os.path.join(REPO, "tests", "safety", "recording_simulator"))
    import profile_sel751
    return [l for l in profile_sel751.grown_ser(added).split(b"\r\n") if profile_sel751.SER_ROW.match(l)]


def grown_messages():
    """Two reads: 12 rows (8 new to the node), then 16 (4 new), each event's
    dtext as printed at the read that first saw it."""
    first, second = grown(4), grown(8)
    msgs = [message(r, i + 1) for i, r in enumerate(first)]
    return msgs + [message(r, len(first) + i + 1) for i, r in enumerate(second[len(first):])], second


def test_grown_good_passes():
    msgs, rows = grown_messages()
    problems, stats = rc.reconcile_grown(msgs, rows)
    assert problems == [] and stats["matched"] == 16 and stats["duplicates"] == 0, (problems, stats)


def test_grown_numbers_change_between_reads():
    # The first read's row 12 is the second read's row 16: the same row.
    assert grown(4)[0].split()[0] == b"12" and grown(8)[0].split()[0] == b"16"
    assert rc.row_key(grown(4)[0]) == rc.row_key(grown(8)[0])


def test_grown_resend_under_the_same_eid_is_a_duplicate_not_a_problem():
    msgs, rows = grown_messages()
    problems, stats = rc.reconcile_grown(msgs + msgs[3:7], rows)
    assert problems == [] and stats["duplicates"] == 4, (problems, stats)


@pytest.mark.parametrize("name,mutate,needle", [
    ("lost", lambda m: m[:5] + m[6:], "never arrived"),
    ("resend differs", lambda m: m + [m[2].replace(b"site-a6 otsec", b"site-a6 otsex")], "different bytes"),
    ("row twice", lambda m: m + [m[2].replace(b"a6/ser:3", b"a6/ser:99")], "two events"),
    ("reordered", lambda m: [m[1].replace(b"a6/ser:2", b"a6/ser:1"), m[0].replace(b"a6/ser:1", b"a6/ser:2")] + m[2:],
     "print order"),
    ("not printed", lambda m: m + [message(b"99    01/01/2030   00:00:00.000   TRIP                     Asserted", 77)],
     "not a row the device printed"),
    ("wrong evc", lambda m: [m[0].replace(b'evc="simulated"', b'evc="hardware-verified"')] + m[1:], "evc="),
])
def test_grown_oracle_catches(name, mutate, needle):
    msgs, rows = grown_messages()
    problems, _ = rc.reconcile_grown(mutate(msgs), rows)
    assert any(needle in p for p in problems), (name, problems)

"""rsyslogrun's reading of the file rsyslog writes fails on a broken input
(D6, P4-D6-H5). No process is started."""

import json

import rsyslogrun

MSG = '<134>1 2026-11-11T12:00:05.123456Z site-a-node1 otsec - ser [otsec@32473 eid="n:ser/a:1" dtext="a \\"q\\" {\\"raw\\":\\""]'


def _rec(msg=MSG, **changed):
    f = msg.split(" ", 6)
    r = {"raw": msg, "pv": "1", "pri": "134", "ts": "2026-11-11T12:00:05.123456+00:00", "host": f[2], "app": f[3],
         "procid": f[4], "msgid": f[5], "sd": f[6]}
    return {**r, **changed}


def _line(rec):
    return json.dumps(rec, separators=(",", ":")).encode() + b"\n"


def test_records_are_read_in_order_whatever_the_message_holds():
    a, b = _rec(), _rec(MSG.replace("a:1", "a:2"))
    recs, torn = rsyslogrun.records(_line(a) + _line(b))
    assert (recs, torn) == ([a, b], 0)
    assert rsyslogrun.raw(recs[0]) == MSG.encode()
    # Without the newline between records, and with spaces after the brace.
    assert rsyslogrun.records(_line(a).strip() + b'{ "raw" : "x"}') == ([a, {"raw": "x"}], 0)


def test_a_record_cut_short_is_torn_and_never_a_message():
    a, b = _line(_rec()), _line(_rec(MSG.replace("a:1", "a:2")))
    for cut in (10, len(a) // 2, len(a) - 2):
        # Killed inside the first record; the next start appended the second.
        recs, torn = rsyslogrun.records(a[:cut] + b)
        assert (len(recs), torn) == (1, 1) and recs[0]["raw"].endswith('a:2" dtext="a \\"q\\" {\\"raw\\":\\""]'), cut
        # Cut at the end of the file: torn once the writer has stopped,
        # still being written while it runs.
        assert rsyslogrun.records(b + a[:cut]) == ([json.loads(b)], 1), cut
        assert rsyslogrun.records(b + a[:cut], live=True) == ([json.loads(b)], 0), cut
    assert rsyslogrun.records(b"garbage\n" + b) == ([json.loads(b)], 1)
    assert rsyslogrun.records(b"") == ([], 0)


def test_rsyslogs_reading_must_be_an_rfc5424_reading_of_the_message():
    assert rsyslogrun.rfc5424_problems([_rec(), _rec(ts="2026-11-11T12:00:05.123456Z")]) == []
    broken = [_rec(pv="0"), _rec(app="other"), _rec(msgid="-"), _rec(host="elsewhere"), _rec(procid="7"),
              _rec(pri="13"), _rec(sd="-"), _rec(sd=""), _rec(ts="2026-11-11T12:00:06.123456+00:00"), _rec(ts="Nov 11"),
              {"raw": "<134>1 short", "pv": "1"}]
    for r in broken:
        assert len(rsyslogrun.rfc5424_problems([r])) == 1, r

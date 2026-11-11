"""V-S9 on the two ground truths it names: the local store's contents, and
GT-RX (D6, P4-D6-H5; R8.8, and R4.7's V-S9 half).

The run is test_slice_store_full_e2e.py's own (its fill() and recover()),
with one thing changed: the upstream collector is rsyslogd with imrelp
over mutual TLS (rsyslogrun.py), not relp_receiver.py. That file's checks
are imported and run on this module's run, so "every row the buffer held
arrives under exactly one event ID" is read from the file rsyslog wrote.

The store is read directly, twice, each time while no node process runs:
  - while full: after the node is SIGKILLed with the evidence class full
    and rsyslog down, and before it is started again;
  - at the end: after recovery, with the node SIGKILLed once more.
Each time the evidence database and its write-ahead log are copied as the
kill left them, and the copy is opened with Python's sqlite3. That is the
committed state the next start of the node would recover. No product code
reads it, and nothing here opens the node's own files.

The checks, on the asset's SER stream (the native records):
  - while full, every event the node had numbered and rsyslog did not
    hold is in the store, so no unforwarded record was evicted; there are
    such events, so the check is not empty; and each stored record is a
    row the simulator printed, byte for byte, each row once;
  - at the end, every event that is no longer in the store is one rsyslog
    wrote, so only forwarded records were pruned; some were pruned; and
    every record the full store held is in rsyslog's file with the hash
    of the bytes the store held, so each was readable and forwardable
    after the kill and the restart while full.
The last test runs the two checks on small stores it makes itself, each
broken in one way, so each check is shown to fail.

Evidence class: simulated. Linux only. The limit is the quota, not the
disk (F-013, F-014), as in that file.
"""

import base64
import hashlib
import json
import os
import sqlite3

import pytest

import harness
import reconcile
import test_slice_store_full_e2e as vs9
from conftest import need
from rsyslogrun import (  # noqa: F401  the checks every rsyslog leg makes
    RsyslogSlice, test_rsyslog_reads_every_message_as_rfc5424, test_the_upstream_is_a_stock_rsyslog)
from test_slice_store_full_e2e import (  # noqa: F401  V-S9's checks, on rsyslog's file
    test_no_run_is_sent_while_full, test_nothing_unforwarded_was_evicted, test_only_read_only_lines_reached_the_device,
    test_runs_resume_without_operator_action, test_the_warning_comes_before_runs_stop)


def _stored(path, stream):
    """(the last seq the store gave the stream, {seq: event}) from a copy
    of the evidence database."""
    db = sqlite3.connect(path)
    try:
        last = db.execute("SELECT last_seq FROM streams WHERE stream = ?", (stream,)).fetchone()
        events = {seq: json.loads(ev) for seq, ev in
                  db.execute("SELECT seq, event FROM events WHERE stream = ? ORDER BY seq", (stream,))}
    finally:
        db.close()
    assert last is not None, f"the store has no stream {stream}"
    return max([last[0], *events]), events


def _written(messages, stream):
    """{seq: rsha256} of the stream's events among the messages rsyslog
    wrote, by event ID (node:stream:seq)."""
    out = {}
    for m in messages:
        ps = reconcile.parse_rfc5424(m)["sd"].get(reconcile.SDID, [])
        _, _, rest = (reconcile.first(ps, "eid") or "").partition(":")
        name, _, seq = rest.rpartition(":")
        if name == stream:
            out[int(seq)] = reconcile.first(ps, "rsha256")
    return out


def full_store_problems(path, stream, written, printed):
    """(problems, counts) for the store while full. path is a copy of the
    evidence database, written is {seq: rsha256} from rsyslog's file, and
    printed the rows the simulator's buffer held."""
    last, events = _stored(path, stream)
    unforwarded = set(events) - set(written)
    problems = []
    evicted = sorted(set(range(1, last + 1)) - set(events) - set(written))
    if evicted:
        problems.append(f"SER events neither in the store nor in rsyslog's file: {evicted[:20]}")
    if len(unforwarded) < min(vs9.GROW, len(printed) // 2):
        problems.append(f"only {len(unforwarded)} events are in the store alone: the check above compared too little")
    keys = {reconcile.row_key(r) for r in printed}
    seen = set()
    for seq, ev in events.items():
        row = base64.b64decode(ev.get("native", {}).get("bytes", ""))
        key = reconcile.row_key(row) if row else None
        if ev["id"]["seq"] != seq or ev["id"]["stream"] != stream:
            problems.append(f"seq {seq}: its event says {ev['id']}")
        if key not in keys:
            problems.append(f"seq {seq}: {row!r} is not a row the simulator printed")
        elif key in seen:
            problems.append(f"seq {seq}: {row!r} is stored twice")
        seen.add(key)
        if ev.get("native", {}).get("record_sha256") != hashlib.sha256(row).hexdigest():
            problems.append(f"seq {seq}: record_sha256 is not the hash of the stored bytes")
    return problems, {"numbered": last, "in the store": len(events), "in rsyslog's file": len(written),
                      "in the store only": len(unforwarded)}


def end_store_problems(path, full_path, stream, written):
    """(problems, counts) for the store at the end. full_path is the copy
    taken while full."""
    last, events = _stored(path, stream)
    gone = set(range(1, last + 1)) - set(events)
    problems = []
    if gone - set(written):
        problems.append(f"pruned and not in rsyslog's file: {sorted(gone - set(written))[:20]}")
    if not gone:
        problems.append("nothing was pruned: the check above compared nothing")
    _, held = _stored(full_path, stream)
    wrong = [seq for seq, ev in held.items() if written.get(seq) != ev["native"]["record_sha256"]]
    if wrong:
        problems.append(f"held while full, and not in rsyslog's file with the same hash: {wrong[:20]}")
    return problems, {"numbered": last, "in the store": len(events), "pruned": len(gone),
                      "in rsyslog's file": len(written)}


def _while_killed(s):
    s.rx_when_full = s.received()
    s.added_when_killed = vs9._added(s)
    s.store_when_full = s.store_copy("evidence", "store-when-full")


@pytest.fixture(scope="module")
def full(tmp_path_factory):
    need(os.name != "nt", "rsyslog does not run on Windows")
    need(harness.rsyslogd() and harness.imrelp(), "rsyslogd with imrelp not installed (rsyslog and rsyslog-relp)")
    for s in vs9.fill(tmp_path_factory, RsyslogSlice, _while_killed):
        s.ser_stream = "ser/" + s.layout["asset_id"]
        yield s


@pytest.fixture(scope="module")
def run(full):
    s = vs9.recover(full)
    # Every stream is confirmed. The node is killed so that nothing has the
    # store open while it is copied.
    s.kill("node")
    s.store_at_end = s.store_copy("evidence", "store-at-end")
    return s


def test_the_full_store_held_every_unforwarded_record(full, capsys):
    written = _written(full.rx_when_full, full.ser_stream)
    problems, counts = full_store_problems(full.store_when_full, full.ser_stream, written,
                                           vs9._rows(full.added_when_killed))
    with capsys.disabled():
        print(f"\nSER events in the store while full: {counts}")
    assert problems == [], problems[:10]


def test_only_forwarded_records_left_the_store(run, capsys):
    written = _written(run.received(), run.ser_stream)
    problems, counts = end_store_problems(run.store_at_end, run.store_when_full, run.ser_stream, written)
    with capsys.disabled():
        print(f"\nSER events in the store at the end: {counts}; {run.torn} torn records in rsyslog's file")
    assert problems == [], problems


def _make_store(path, stream, rows, last):
    """A database with the two tables _stored reads, holding rows as
    {seq: row bytes}."""
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE streams (stream TEXT PRIMARY KEY, last_seq INTEGER NOT NULL)")
    db.execute("CREATE TABLE events (stream TEXT NOT NULL, seq INTEGER NOT NULL, event BLOB NOT NULL)")
    db.execute("INSERT INTO streams VALUES (?, ?)", (stream, last))
    for seq, row in rows.items():
        ev = {"id": {"node_id": "n", "stream": stream, "seq": seq},
              "native": {"bytes": base64.b64encode(row).decode(), "record_sha256": hashlib.sha256(row).hexdigest()}}
        db.execute("INSERT INTO events VALUES (?, ?, ?)", (stream, seq, json.dumps(ev).encode()))
    db.commit()
    db.close()
    return path


def test_the_store_checks_fail_on_a_broken_store(tmp_path):
    """The two checks above on stores made here, each broken in one way.
    No slice runs."""
    stream = "ser/a"
    rows = vs9._rows(4)
    held = {i + 1: r for i, r in enumerate(rows)}
    sha = {seq: hashlib.sha256(r).hexdigest() for seq, r in held.items()}
    n = len(held)

    def full(name, stored, written=()):
        path = _make_store(str(tmp_path / name), stream, stored, n)
        return full_store_problems(path, stream, {seq: sha[seq] for seq in written}, rows)[0]

    assert full("whole", held) == []
    assert full("forwarded-gone", {q: r for q, r in held.items() if q > 3}, written=(1, 2, 3)) == []
    evicted = full("one-evicted", {q: r for q, r in held.items() if q != 5})
    assert len(evicted) == 1 and "neither in the store nor in rsyslog's file: [5]" in evicted[0], evicted
    for name, stored in (("newest-evicted", {q: r for q, r in held.items() if q != n}),
                         ("not-printed", {**held, 5: b"9     11/11/2026  00:00:00.000   NEVER        Printed"}),
                         ("twice", {**held, 5: held[4]})):
        problems = full(name, stored)
        assert len(problems) == 1, (name, problems)
    assert len(full("nothing-unforwarded", {q: r for q, r in held.items() if q == n}, written=range(1, n + 1))) == 1

    while_full = _make_store(str(tmp_path / "while-full"), stream, held, n)
    kept = {q: r for q, r in held.items() if q > 4}

    def end(name, stored, written):
        return end_store_problems(_make_store(str(tmp_path / name), stream, stored, n), while_full, stream, written)[0]

    assert end("pruned-forwarded", kept, sha) == []
    assert len(end("nothing-pruned", held, sha)) == 1
    lost = end("pruned-unforwarded", kept, {q: h for q, h in sha.items() if q != 2})
    assert len(lost) == 2 and "pruned and not in rsyslog's file: [2]" in lost[0], lost
    changed = end("other-bytes", kept, {**sha, 7: sha[8]})
    assert len(changed) == 1 and "[7]" in changed[0], changed

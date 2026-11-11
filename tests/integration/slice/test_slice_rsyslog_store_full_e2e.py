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
    last, events = _stored(full.store_when_full, full.ser_stream)
    written = _written(full.rx_when_full, full.ser_stream)
    unforwarded = sorted(set(events) - set(written))
    with capsys.disabled():
        print(f"\nstore while full: SER events 1 to {last} numbered, {len(events)} in the store, "
              f"{len(written)} in rsyslog's file, {len(unforwarded)} in the store only")
    evicted = sorted(set(range(1, last + 1)) - set(events) - set(written))
    assert evicted == [], f"SER events neither in the store nor in rsyslog's file: {evicted[:20]}"
    assert len(unforwarded) >= vs9.GROW, (len(unforwarded), last)
    printed = {reconcile.row_key(r) for r in vs9._rows(full.added_when_killed)}
    seen = set()
    problems = []
    for seq, ev in events.items():
        row = base64.b64decode(ev.get("native", {}).get("bytes", ""))
        key = reconcile.row_key(row) if row else None
        if ev["id"]["seq"] != seq or ev["id"]["stream"] != full.ser_stream:
            problems.append(f"seq {seq}: its event says {ev['id']}")
        if key not in printed:
            problems.append(f"seq {seq}: {row!r} is not a row the simulator printed")
        elif key in seen:
            problems.append(f"seq {seq}: {row!r} is stored twice")
        seen.add(key)
        if ev.get("native", {}).get("record_sha256") != hashlib.sha256(row).hexdigest():
            problems.append(f"seq {seq}: record_sha256 is not the hash of the stored bytes")
    assert problems == [], problems[:10]


def test_only_forwarded_records_left_the_store(run, capsys):
    last, events = _stored(run.store_at_end, run.ser_stream)
    written = _written(run.received(), run.ser_stream)
    gone = set(range(1, last + 1)) - set(events)
    with capsys.disabled():
        print(f"\nstore at the end: SER events 1 to {last} numbered, {len(events)} in the store, "
              f"{len(gone)} pruned, {len(written)} in rsyslog's file, {run.torn} torn records")
    assert gone <= set(written), f"pruned and not in rsyslog's file: {sorted(gone - set(written))[:20]}"
    assert gone, "nothing was pruned: the check above compared nothing"
    _, held = _stored(run.store_when_full, run.ser_stream)
    wrong = [seq for seq, ev in held.items() if written.get(seq) != ev["native"]["record_sha256"]]
    assert wrong == [], f"held while full, and not in rsyslog's file with the same hash: {wrong[:20]}"

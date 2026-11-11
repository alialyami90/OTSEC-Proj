"""R4.6 on the real binaries: the node forwards to a stock rsyslog (D6,
P4-D6-H5).

The slice as in test_slice_e2e.py, with one thing changed: the upstream
collector is rsyslogd with imrelp over mutual TLS (rsyslogrun.py), not
relp_receiver.py. The node runs its schedule twice against the simulator's
Figure 10.16 buffer.

The oracle is the file rsyslog wrote, and nothing of the product reads it:
  - rsyslog's own parser read every message as RFC 5424, and the fields it
    found are the message's (R4.6: forwarded messages parse as valid
    RFC 5424 at an independent receiver);
  - the SER messages in the file, in the order rsyslog wrote them, are the
    rows the simulator printed, in its print order, each once and byte for
    byte (reconcile.py, D6's parser): count, content and order;
  - every event the node's health shows as confirmed is in the file, with
    no gap, so each acknowledgement followed rsyslog's write;
  - the second read added nothing.

Also: the recording check over the simulator's log (V-S7), and the
password in no file or message (V-S11's files and messages).

Evidence class: simulated. Linux only: rsyslog does not run on Windows.
"""

import os
import shutil
import time

import pytest

import harness
import reconcile
from conftest import need
from rsyslogrun import (  # noqa: F401  the checks every rsyslog leg makes
    RsyslogSlice, test_rsyslog_reads_every_message_as_rfc5424, test_the_upstream_is_a_stock_rsyslog)
from test_slice_interruptions_e2e import (  # noqa: F401  the same checks, on this run
    _confirmed, _eid, test_only_read_only_lines_reached_any_device, test_the_password_is_nowhere)

RUNS = 2
# As test_slice_e2e.py: the first run starts 60 s after the node, the
# second at least 60 s after the first ends.
RUN_TIMEOUT = 75.0 * RUNS + 30.0


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt", "rsyslog does not run on Windows")
    need(harness.rsyslogd() and harness.imrelp(), "rsyslogd with imrelp not installed (rsyslog and rsyslog-relp)")
    s = RsyslogSlice(str(tmp_path_factory.mktemp("slice-rsyslog")))
    s.build()
    try:
        s.start()
        rows = len(reconcile.native_rows())
        done = harness.wait_for(lambda: s.sessions_closed() >= RUNS and len(s.ser_received()) >= rows,
                                RUN_TIMEOUT, step=1.0)
        # The second read's events would arrive within a few seconds of its
        # session; give them the time to show up if they were sent.
        time.sleep(10)
        assert done, (f"{s.sessions_closed()} sessions, {len(s.ser_received())} SER messages after "
                      f"{RUN_TIMEOUT:.0f}s\nnode:\n{s.text('node')}\nrsyslogd:\n{s.text('receiver')}")

        def confirmed():
            streams = _confirmed(s.health())
            return streams and all(c == n == k for c, n, k in streams.values())
        assert harness.wait_for(confirmed, 60.0, step=1.0), s.health()
        s.final_health = s.health()
        yield s
    finally:
        s.stop()


def test_every_row_is_in_rsyslogs_file_once_and_in_order(run):
    rows = reconcile.native_rows()
    msgs = run.received()
    problems, stats = reconcile.reconcile(msgs, rows)
    assert problems == [], problems
    assert stats["matched"] == stats["rows"] == 8, stats
    assert stats["duplicates"] == 0, stats
    # The order rsyslog wrote them in is the device's print order.
    sd = [reconcile.parse_rfc5424(m)["sd"][reconcile.SDID] for m in msgs]
    wrote = [reconcile.first(ps, "dtext").encode("utf-8") for ps in sd if reconcile.first(ps, "kind") == "ser"]
    assert wrote == rows, wrote


def test_the_second_read_forwards_nothing_new(run):
    assert run.sessions_closed() >= RUNS
    assert len(run.ser_received()) == 8, len(run.ser_received())


def test_every_confirmed_event_is_in_rsyslogs_file(run):
    streams = _confirmed(run.final_health)
    assert streams, run.final_health
    got = {}
    order = {}
    for _, msg in run.received_by_line():
        e = _eid(msg)
        assert e is not None, msg[:200]
        got.setdefault(e[0], set()).add(e[1])
        order.setdefault(e[0], []).append(e[1])
    for name, (_, _, cursor) in streams.items():
        have = got.get(name, set())
        assert set(range(1, cursor + 1)) <= have, (name, cursor, sorted(set(range(1, cursor + 1)) - have)[:5])
        assert have == set(range(1, max(have) + 1)), (name, sorted(set(range(1, max(have) + 1)) - have)[:5])
    # No break in this run: each stream arrives in its own order, once.
    for name, seqs in order.items():
        assert seqs == sorted(set(seqs)), (name, seqs)
    assert run.torn == 0, run.torn

"""A busy audit database at node start is retried, on the real binaries (A6,
P3-A6; P3-A5 brief docs/phase2/A5-p3-failed-open-retry.md, test 3).

One slice: a normal start and one SER run, so the store exists. The node is
killed, and A6's own SQLite connection (Python's sqlite3, not the product's
driver) holds audit.db exclusively while the node starts again. Expected,
from C5 0.2 and the brief:
  - while the file is held, the node runs nothing: no session reaches the
    device for longer than a schedule interval, and health says the
    suspensions are unknown;
  - once the holder lets go, a Tick opens audit.db, the suspensions are
    rebuilt, and runs resume: a new SER session and a new collection.run;
  - the recovery is a store.mode_change of the audit database from failed
    to collecting, in the audit stream (the slice has no audit target, so
    forwarding of audit is not checked here);
  - the recording check passes.

Evidence class: simulated. A second process holding the file is stood in
for by a connection in the test process, as a read-only CLI or a backup
tool would hold it.
"""

import datetime
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time

import pytest

import harness
from conftest import need
from slicerun import CHECK, REGISTER, SERVICE, Slice

SCHEDULE = 60  # slicehelper's default SER interval, seconds
TICK = 60      # platform/node TickInterval


def _ser_sessions(s):
    return sum(1 for r in s.sim_records() if r["event"] == "line" and r["text"].startswith("SER"))


def _hold(path):
    """An exclusive connection that keeps the file once it has read and
    written: every other open is busy until it closes."""
    h = sqlite3.connect(path, isolation_level=None, timeout=1)
    h.execute("PRAGMA locking_mode=EXCLUSIVE")
    h.execute("BEGIN IMMEDIATE")
    h.execute("SELECT count(*) FROM sqlite_master").fetchall()
    h.execute("COMMIT")
    return h


def _audit_rows(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return [json.loads(ev) for (ev,) in db.execute("SELECT event FROM events WHERE stream = 'audit' ORDER BY seq")]
    finally:
        db.close()


@pytest.fixture(scope="module")
def got(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" or SERVICE, "the Windows leg of the end-to-end run is the PC run (D1-26)")
    s = Slice(str(tmp_path_factory.mktemp("slice-busy-open")))
    s.build()
    out = {}
    holder = None
    try:
        s.start()
        out["first_run"] = harness.wait_for(lambda: len(s.runs_reported()) >= 1, 150.0, step=1.0)
        s.kill("node")
        audit = os.path.join(s.layout["store_dir"], "audit.db")
        out["audit_exists"] = os.path.exists(audit)
        holder = _hold(audit)
        out["respawn_utc"] = datetime.datetime.now(datetime.timezone.utc)
        runs, sessions = len(s.runs_reported()), _ser_sessions(s)
        s.respawn("node")
        # Held for longer than a schedule interval and a tick.
        time.sleep(max(SCHEDULE, TICK) + 15)
        out["held_health"] = s.health()
        out["held_runs"] = len(s.runs_reported()) - runs
        out["held_sessions"] = _ser_sessions(s) - sessions
        out["released_utc"] = datetime.datetime.now(datetime.timezone.utc)
        holder.close()
        holder = None
        released = time.monotonic()
        out["resumed"] = harness.wait_for(lambda: len(s.runs_reported()) > runs and _ser_sessions(s) > sessions,
                                          TICK + SCHEDULE + 60, step=1.0)
        out["resumed_after"] = time.monotonic() - released
        out["health"] = s.health()
    finally:
        if holder is not None:
            holder.close()
        s.stop()
    # After stop(), in service mode, the store is the teardown's copy.
    out["audit"] = _audit_rows(os.path.join(s.layout["store_dir"], "audit.db"))
    out["sim_logs"] = list(s.sim_logs)
    print(json.dumps({k: v for k, v in out.items() if k != "audit"}, indent=1, default=str))
    return out


def test_runs_wait_while_the_audit_database_is_held(got):
    assert got["first_run"] and got["audit_exists"]
    assert got["held_runs"] == 0 and got["held_sessions"] == 0, got
    assert "asset-suspensions-unknown" in got["held_health"], got["held_health"]


def test_runs_resume_once_it_is_let_go(got):
    assert got["resumed"], got["health"]
    assert got["resumed_after"] <= TICK + SCHEDULE + 60
    assert "asset-suspensions-rebuilt" in got["health"] or "asset-suspensions-unknown" not in got["health"], got["health"]


def test_the_recovery_is_audited(got):
    changes = [r for r in got["audit"] if r["action"] == "store.mode_change"]
    assert any(r["detail"] == "database audit: failed to collecting" for r in changes), changes
    # The chain's numbers stay unique and in order across the retry.
    seqs = [r["seq"] for r in got["audit"]]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def _utc(r):
    # RFC 3339 with up to nanoseconds; Python keeps microseconds.
    t = re.sub(r"(\.\d{6})\d+", r"\1", r["time"]["utc"])
    return datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))


def test_the_restart_reaches_the_chain(got):
    """D3-6 (A1 on #147): the records the second start could not write while
    audit.db was held are in the chain, with the times they were made at
    (before the release), ahead of the recovery, in the order a start writes
    them, and nothing was lost."""
    rows = got["audit"]
    show = [(r["seq"], r["time"]["utc"], r["action"], r.get("detail")) for r in rows]
    idx = lambda pred: [i for i, r in enumerate(rows) if pred(r)]
    starts = idx(lambda r: r["action"] == "service.start")
    recovered = idx(lambda r: r["action"] == "store.mode_change" and r["detail"] == "database audit: failed to collecting")
    assert len(starts) == 2 and len(recovered) == 1, show
    rec = recovered[0]
    first_up = idx(lambda r: r["action"] == "store.mode_change" and r["detail"].startswith("database audit: none to collecting"))
    audit_failed = idx(lambda r: r["action"] == "store.mode_change" and r["detail"].startswith("database audit: none to failed"))
    evidence_up = idx(lambda r: r["action"] == "store.mode_change" and r["detail"].startswith("database evidence: none to "))
    posture = idx(lambda r: r["action"] == "node.posture_change" and (r.get("detail") or "").startswith("lab_tls_files is set"))
    assert len(first_up) == 1 and len(audit_failed) == 1 and len(evidence_up) == 2 and len(posture) == 2, show
    # Each start states its lab TLS posture (#176) right after service.start.
    assert posture == [starts[0] + 1, starts[1] + 1], show
    # The second start's four records sit together just before the recovery,
    # after everything the first process wrote.
    restart = sorted([starts[1], posture[1], audit_failed[0], evidence_up[1]])
    assert restart == list(range(rec - 4, rec)), show
    assert restart[0] > max(starts[0], posture[0], first_up[0], evidence_up[0]), show
    # In the same order as the first start wrote its own.
    first = sorted([starts[0], posture[0], first_up[0], evidence_up[0]])
    kind = lambda i: (rows[i]["action"], rows[i].get("detail", "").split(":")[0])
    assert [kind(i) for i in restart] == [kind(i) for i in first], show
    for i in restart:
        t = _utc(rows[i])
        assert got["respawn_utc"] - datetime.timedelta(seconds=5) <= t < got["released_utc"], (show[i], got["respawn_utc"], got["released_utc"])
    # Kept with their own times, so they are earlier than the recovery and
    # in the order they were made. (Across the whole chain, chain order is
    # commit order, not time order: D3-8, checked below.)
    times = [_utc(rows[i]) for i in restart + [rec]]
    assert all(a <= b for a, b in zip(times, times[1:])), [show[i] for i in restart + [rec]]
    assert not [r for r in rows if r["action"] == "storage.alarm" and "audit_not_recorded" in json.dumps(r)], show


def test_only_read_only_lines_reached_the_device(got):
    for log in got["sim_logs"]:
        out = subprocess.run([sys.executable, CHECK, "--log", log, "--register", REGISTER],
                             capture_output=True, text=True)
        report = json.loads(out.stdout)
        assert out.returncode == 0 and report["pass"], (log, report)


def test_relayed_records_are_timed_between_their_request_and_its_decision(got):
    """D3-8 (A1, #171): chain order is commit order. Per collector request,
    the node's info record is stamped and committed before the request
    leaves; the decision (allowed) is stamped after the reply and committed
    first in its batch, followed by the collector's relayed records, which
    the collector stamped as it acted. So, per request: info seq < decision
    seq < every relayed seq, and info time <= every relayed time <= decision
    time. Relayed records carry the invocation ID, not the request ID; they
    belong to the decision whose batch they follow, and an invocation ID
    never appears after two decisions."""
    rows = got["audit"]
    show = lambda r: (r["seq"], r["time"]["utc"], r["action"], r["outcome"], r.get("correlation_id"), r.get("collector_seq"))
    info, decision, relayed, owner = {}, {}, {}, {}
    current = None
    for r in rows:
        if r["action"] == "collector.request":
            rid = r["correlation_id"]
            if r["outcome"] == "info":
                assert rid not in info, show(r)
                info[rid] = r
                current = None
            else:
                assert rid not in decision, show(r)
                decision[rid] = r
                current = rid if r["outcome"] == "allowed" else None
            continue
        if r.get("collector_seq") and r["action"] != "collector.request":
            assert current is not None, ("a relayed record outside a decision's batch", show(r))
            inv = r["correlation_id"]
            assert owner.setdefault(inv, current) == current, ("invocation after two decisions", inv, show(r))
            relayed.setdefault(current, []).append(r)
        elif r["action"] not in ("collector.seq_reset",):
            current = None
    checked = 0
    for rid, d in decision.items():
        i = info.get(rid)
        assert i is not None, ("a decision with no info record", show(d))
        assert i["seq"] < d["seq"] and _utc(i) <= _utc(d), (show(i), show(d))
        for r in relayed.get(rid, []):
            assert d["seq"] < r["seq"], (show(i), show(d), show(r))
            assert _utc(i) <= _utc(r) <= _utc(d), ("relayed record timed outside its request", show(i), show(r), show(d))
            checked += 1
    # The slice ran at least twice, each with a session open and close.
    assert sum(1 for d in decision.values() if d["outcome"] == "allowed") >= 2 and checked >= 4, [show(r) for r in rows]

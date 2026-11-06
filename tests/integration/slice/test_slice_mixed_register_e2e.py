"""A mixed node on the real binaries: a SEL-751 and a SEL-2731M, each under
its own register package (C6, for C5's register_versions, #466).

The node schedules the slice's SEL-751 (sel.ser.read_all, register_version
5, the SEL-751 package) and a SEL-2731M polled over SNMPv3
(sel27x1.snmp.identity, register_versions["sel-27x1-rstp"] 1, C2's test
package). The collector holds both packages, signed by the run's release
key, and selects each by the profile's firmware allowlist. No SNMP agent
answers and no SNMPv3 credential is installed, so the SEL-2731M's run
cannot complete: what is checked is that the collector refused it only at
the credential (decideRun step 10, credential_unusable), so after its
register revision check (step 5), and that the SEL-751's run still
collects every SER row.

The control: the same node with the SEL-2731M's profile left out of
register_versions, so its run names the SEL-751's revision 5. The collector
must refuse it as register_version, and the SEL-751's run is unaffected.

Evidence class: simulated. No device is contacted; the SNMP port is a
loopback port this test holds and nothing listens on.
"""

import json
import os
import shutil

import pytest

import harness
import reconcile
from conftest import need
from slicerun import SERVICE, Slice
from test_slice_gtinj_feed_e2e import _query

# The first runs are 60 s after the node starts.
RUN_TIMEOUT = 150.0


def _audit(s):
    return [json.loads(e) for (e,) in _query(s.layout["store_dir"], "SELECT event FROM events WHERE stream = ? ORDER BY seq", "audit")]


def _snmp_decisions(s):
    """The collector's decisions on the SEL-2731M's run requests, as the
    node's audit chain records them (the request itself is an info
    record)."""
    asset = s.layout["snmp_asset"]
    return [r for r in _audit(s) if r.get("action") == "collector.request" and r.get("outcome") != "info" and asset in json.dumps(r)]


def _run(tmp_path_factory, name, unlisted):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "the mixed node's run is a Linux runner's")
    s = Slice(str(tmp_path_factory.mktemp(name)))
    s.build()
    port, hold = harness.reserve_port()
    try:
        s.start(setup_extra=("-snmp-port", str(port)) + (("-snmp-unlisted",) if unlisted else ()))
        rows = len(reconcile.native_rows())
        done = harness.wait_for(lambda: len(s.ser_received()) >= rows and _snmp_decisions(s), RUN_TIMEOUT, step=1.0)
        assert done, f"SER {len(s.ser_received())}/{rows}, SNMP decisions {_snmp_decisions(s)}\nhealth:\n{s.health()}\nnode:\n{s.text('node')[-4000:]}"
        s.decisions = _snmp_decisions(s)
        s.ser = s.received()
        s.health_text = s.health()
        return s
    finally:
        s.stop()
        hold.close()


@pytest.fixture(scope="module")
def listed(tmp_path_factory):
    return _run(tmp_path_factory, "mixed-listed", False)


@pytest.fixture(scope="module")
def unlisted(tmp_path_factory):
    return _run(tmp_path_factory, "mixed-unlisted", True)


def test_the_sel751_collects_on_a_mixed_node(listed):
    problems, stats = reconcile.reconcile(listed.ser, reconcile.native_rows())
    assert problems == [] and stats["matched"] == stats["rows"] == 8, (problems, stats)


def test_the_sel2731m_run_is_not_refused_for_its_revision(listed):
    # With no SNMPv3 credential installed, the run passes the register
    # check (decideRun step 5) and every check up to the credential (step
    # 10), where it is refused: no datagram is sent.
    assert listed.decisions, listed.health_text
    assert all(d.get("outcome") == "denied" and d.get("reason_code") == "credential_unusable" for d in listed.decisions), listed.decisions


def test_unlisted_the_sel2731m_run_is_refused_for_its_revision(unlisted):
    assert unlisted.decisions, unlisted.health_text
    assert all(d.get("outcome") == "denied" and d.get("reason_code") == "register_version" for d in unlisted.decisions), unlisted.decisions


def test_unlisted_the_sel751_still_collects(unlisted):
    problems, stats = reconcile.reconcile(unlisted.ser, reconcile.native_rows())
    assert problems == [] and stats["matched"] == stats["rows"] == 8, (problems, stats)

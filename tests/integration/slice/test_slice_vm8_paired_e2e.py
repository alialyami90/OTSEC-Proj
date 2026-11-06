"""V-M8's paired runs on the real binaries: applicability never probes a
device (C6, P4-3-C6; D4-49 Q12, D4-50).

Three runs of the slice, one after another, each the same build (tagged
otsec_testclock, so the R9 run may take GT-ADV's test set), the same
simulator profile and FID on the same port, and the same schedule
(sel.ser.read_all every 60 s), each stopped after its second collection
session:

  A1  the asset module on, R9 off (slicehelper setup -asset);
  A2  the same again: the A/A pair, which shows what differs between two
      identical runs before anything is read into the R9 run;
  B   R9 on as well, with GT-ADV's set in admin_dir (-gtadv-row D1).

The whole test runs in a network namespace of its own, as root
(sudo unshare -n; CI's integration-long leg does that). Its only
interfaces are lo and d0, a TUN device holding the default route, so every
packet any process of the runs sends is captured: on lo, or read from d0
had it been bound anywhere else (netcapture.py). The node and the
collector talk over a Unix socket, which is not a network flow.

Pass (V-M8, D4-49 Q12, D4-50), for A1 against A2 and for A1 against B:
  - the same collection sessions to the device address (127.0.0.1, the
    simulator's port), in order, with the same packet count each;
  - no flow in the second run that the first lacks, over every
    destination, servers named by role (device, upstream);
  - nothing at all routed to d0, in any run; before the runs, a datagram
    to an outside address of each family the kernel has is read from d0,
    and where the kernel has no IPv6, no IPv6 socket can be opened.
B against A1 measures R9 together with GT-ADV's declared identity (C5 on
#470), which is what a real R9 install configures.
The upstream RELP flow exists in every run; its volume may differ,
because the R9 run forwards its own health and finding events (D4-50).
If the A/A pair's packet counts differ, the difference is brought to C1
before anything changes (D4-49 Q12): the test fails and prints it.

Evidence class: simulated. No device is contacted.
"""

import os
import shutil
import socket

import pytest

import harness
import netcapture
from conftest import need
from slicerun import SERVICE, Slice, check_v_s7
from test_slice_gtinj_feed_e2e import _query, _status

SIM_PORT = 47021  # fixed for every run (D4-49 Q12)
SESSIONS = 2
# The first session is a minute after the node starts, the next a minute
# later; a session takes seconds.
LIMIT = 60 * SESSIONS + 90
PROBE = {}  # netcapture.probe()'s result, before the first run


def _closed(log):
    return sum(1 for r in harness.read_log(log, live=True) if r["event"] == "session_close") if os.path.exists(log) else 0


def _run(d, bin_dir, tun, r9):
    s = Slice(d, bin_dir=bin_dir)
    s.node_tags = ("otsec_testclock",)
    cap = netcapture.Capture(tun)
    out = {}
    try:
        s.start(sim_extra=("--port", str(SIM_PORT)), setup_extra=("-gtadv-row", "D1") if r9 else ("-asset",))
        ok = harness.wait_for(lambda: _closed(s.sim_log) >= SESSIONS and len(s.runs_reported()) >= SESSIONS, LIMIT, step=1.0)
        assert ok, f"{_closed(s.sim_log)} sessions in {LIMIT}s\nhealth:\n{s.health()}\nnode:\n{s.text('node')[-3000:]}"
        # The second run's records forwarded, then the capture stops before
        # any process does, so no shutdown is in it.
        harness.wait_for(lambda: False, 5, step=1.0)
        packets, external = cap.stop()
        out.update(layout=s.layout, relp_port=s.relp_port, sessions=_closed(s.sim_log), status=_status(s),
                   config_records=[r for (r,) in _query(s.layout["store_dir"], "SELECT COUNT(*) FROM events WHERE stream = ?",
                                                  "config/" + s.layout["asset_id"])])
    finally:
        if not cap._stop.is_set():
            packets, external = cap.stop()
        s.stop()
        out["checked"] = check_v_s7([l for l in s.sim_logs if os.path.exists(l)], s.d)
    out["connections"], out["external"] = netcapture.connections(packets), external
    return out


def _role(run, server):
    if server is None:
        return ("other",)
    addr, port = server
    if port == SIM_PORT:
        return ("device", addr)
    if port == run["relp_port"]:
        return ("upstream", addr)
    return ("server", addr, port)


def _flows(run):
    return {(c["proto"], _role(run, c["server"])) for c in run["connections"]}


def _device_sessions(run):
    return [c["packets"] for c in run["connections"] if _role(run, c["server"])[0] == "device"]


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    need(os.environ.get("OTSEC_VM8_BIN") or shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "the paired runs are a Linux runner's")
    need(hasattr(os, "geteuid") and os.geteuid() == 0 and netcapture.interfaces() == ["lo"],
         "the paired runs need root in a network namespace of their own: sudo unshare -n python -m pytest ...")
    tun = netcapture.setup()
    try:
        PROBE.update(netcapture.probe(tun))
        # No network in the namespace, so the module cache cannot be filled
        # here: CI builds the binaries before it enters (OTSEC_VM8_BIN:
        # otsec tagged otsec_testclock, otsec-collector and slicehelper).
        bin_dir = os.environ.get("OTSEC_VM8_BIN")
        if not bin_dir:
            builder = Slice(str(tmp_path_factory.mktemp("vm8-build")))
            builder.node_tags = ("otsec_testclock",)
            builder.build()
            bin_dir = builder.bin
        return {name: _run(str(tmp_path_factory.mktemp(name)), bin_dir, tun, r9)
                for name, r9 in (("A1", False), ("A2", False), ("B", True))}
    finally:
        os.close(tun)


def test_the_capture_sees_a_packet_to_an_outside_address(runs):
    # d0 takes what is routed off the host, in each family the kernel has.
    # A kernel with no IPv6 lets no process open an IPv6 socket, so nothing
    # can leave by IPv6 (C3 on #470); the test says which case it ran.
    assert PROBE["seen"].get(4), PROBE
    if PROBE["ipv6"]:
        assert PROBE["seen"].get(6), PROBE
    else:
        with pytest.raises(OSError):
            socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    print("IPv6 in the namespace:", PROBE["ipv6"], "; kernel packets on d0 at its start:", PROBE["other"])


def test_each_run_made_its_sessions_and_b_ran_r9(runs):
    for name, r in runs.items():
        assert r["sessions"] >= SESSIONS, (name, r["sessions"])
        assert bool((r["status"].get("applicability") or {}).get("set_in_use")) == (name == "B"), (name, r["status"].get("applicability"))
    # B's matcher stored findings, so B's configuration stream holds more.
    assert runs["B"]["config_records"][0] > runs["A1"]["config_records"][0], (runs["A1"]["config_records"], runs["B"]["config_records"])


@pytest.mark.parametrize("name", ["A1", "A2", "B"])
def test_nothing_leaves_the_host(runs, name):
    assert runs[name]["external"] == [], runs[name]["external"]


@pytest.mark.parametrize("second", ["A2", "B"])
def test_the_same_device_sessions_packet_for_packet(runs, second):
    a, b = _device_sessions(runs["A1"])[:SESSIONS], _device_sessions(runs[second])[:SESSIONS]
    assert len(a) == len(b) == SESSIONS and a == b, f"A1 {a}, {second} {b}"
    # No device session beyond the schedule's in either run.
    assert len(_device_sessions(runs["A1"])) == len(_device_sessions(runs[second])) == SESSIONS


@pytest.mark.parametrize("second", ["A2", "B"])
def test_no_flow_the_first_run_lacks(runs, second):
    extra = _flows(runs[second]) - _flows(runs["A1"])
    assert not extra, f"{second} has flows A1 lacks: {sorted(extra)}"


@pytest.mark.parametrize("name", ["A1", "A2", "B"])
def test_v_s7_only_read_only_register_lines_reached_the_device(runs, name):
    # V-S7 (b) over each run's recording.
    assert runs[name]["checked"], "no recording"
    for log, code, report in runs[name]["checked"]:
        assert code == 0 and report.get("pass") and not report.get("violations"), (log, report)
        assert report["commands_received"] > 0 and report["peak_concurrent_sessions"] == 1, (log, report)

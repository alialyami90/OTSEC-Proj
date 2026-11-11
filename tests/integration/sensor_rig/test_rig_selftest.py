"""Self-tests of the veth rig, the timed replayer, the C-11 run and the
capability check (D6, P4-4-R1). Each one fails when its rig is broken: the
negative control must show frames, the replayer is checked against its own
clock and the receiver's, and a process that kept its capabilities must be
flagged.

They need Linux, root and network namespaces, so they run in CI's
`integration-long (sensor_rig)` leg, where OTSEC_RIG_REQUIRED=1 turns a test
that can't run into a failure. Elsewhere they skip. Every interface is a
virtual one in a namespace made for the test. No sensor exists yet:
standin_sensor.py stands in for it and decodes nothing. Evidence class when
they pass in CI: CI-Linux, simulated.
"""

import errno
import os
import shutil
import subprocess
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "gt_pcap"))

import dnp3_cases  # noqa: E402
import pcapfile  # noqa: E402
import rig_caps  # noqa: E402
import rig_netns  # noqa: E402
import rig_replay  # noqa: E402
from rig_netns import MON, TAP  # noqa: E402

REQUIRED = os.environ.get("OTSEC_RIG_REQUIRED") == "1"
TOLERANCE_NS = 50_000_000  # a hosted runner's scheduling, not a property of the product
GAP_NS = 100_000_000


@pytest.fixture(autouse=True)
def need_rig():
    why = rig_netns.why_not()
    if why and REQUIRED:
        pytest.fail(f"OTSEC_RIG_REQUIRED=1, and {why}")
    if why:
        pytest.skip(why)


def gt_frames():
    """Every frame of GT-PCAP's DNP3 cases, in case order."""
    return [f for _, frames, _ in dnp3_cases.cases() for f in frames]


def timed_frames():
    """Fifteen GT-PCAP frames, 100 ms apart: gaps far above the tolerance."""
    return [pcapfile.Frame(i * GAP_NS, f.data) for i, f in enumerate(gt_frames()[:15])]


def replay_to_mon0(frames, **how):
    """Replay onto tap0 and return (the replayer's log, what arrived on
    mon0 with its receipt times)."""
    with rig_netns.Rig() as rig:
        cap = rig_netns.Capture(rig.sensor_ns, MON).start()
        rig.up()
        time.sleep(0.3)
        out = rig_netns.packet_socket(rig.rig_ns, TAP)
        log = rig_replay.replay(out, frames, **how)
        out.close()
        cap.stop()
        return log, cap.arrived()


def test_the_replay_keeps_its_schedule_by_its_own_clock_and_by_the_receivers():
    frames = timed_frames()
    log, arrived = replay_to_mon0(frames)
    assert rig_replay.check_log(log, TOLERANCE_NS) == []
    assert rig_replay.check_arrivals(frames, [(a[0], a[3]) for a in arrived], TOLERANCE_NS) == []
    worst = max(r["sent_ns"] - r["due_ns"] for r in log)
    print(f"MEASURED replay: {len(log)} frames, worst lateness {worst} ns, tolerance {TOLERANCE_NS} ns")


def test_a_replayer_off_its_schedule_is_caught_by_the_receivers_clock():
    """The broken rig: every frame is sent, in order and unchanged, at fifty
    times the pace. Judged against the capture's own pace it must fail."""
    frames = timed_frames()
    _, arrived = replay_to_mon0(frames, speed=50.0)
    bad = rig_replay.check_arrivals(frames, [(a[0], a[3]) for a in arrived], TOLERANCE_NS)
    assert len(bad) == len(frames) - 1, bad


def test_latency_is_a_known_delay_after_the_triggering_frame():
    """R6.4's measure on a known answer. A stand-in "alerts" 200 ms after
    frame 8 reaches mon0; the measured latency must be that delay plus the
    crossing, and it must follow the frame named, not its neighbour."""
    frames = timed_frames()
    delay = 200_000_000
    log, arrived = replay_to_mon0(frames)
    trigger = rig_netns.sha(frames[7].data)
    seen_wall = next(a[1] for a in arrived if rig_netns.sha(a[3]) == trigger)
    alert_wall = seen_wall + delay
    got = rig_replay.latency_ns(log, trigger, alert_wall)
    assert delay <= got <= delay + TOLERANCE_NS, got
    earlier = rig_replay.latency_ns(log, rig_netns.sha(frames[6].data), alert_wall)
    assert abs(earlier - got - GAP_NS) <= TOLERANCE_NS, (earlier, got)
    print(f"MEASURED latency: {got} ns for a {delay} ns delay, on the runner's wall clock (CLOCK_REALTIME)")


def start_standin(rig, mode):
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "standin_sensor.py"), rig.sensor_ns, MON, mode],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "ready"
    return p


def stop_standin(p):
    out, _ = p.communicate(timeout=20)
    got = dict(ln.split() for ln in out.splitlines())
    return int(got["frames"]), got["reopen"]


def test_c11_a_quiet_monitoring_interface_sends_nothing_over_the_whole_replay():
    """The passing arrangement: mon0 as a sensor's installer must leave it,
    a stand-in that only listens, the whole DNP3 case set replayed, and the
    interface up from before the stand-in starts until after it stops."""
    frames = gt_frames()
    seen = {}
    with rig_netns.Rig() as rig:
        got = rig_netns.c11(
            rig, frames, start_sensor=lambda: start_standin(rig, "drop"),
            stop_sensor=lambda p: seen.update(zip(("frames", "reopen"), stop_standin(p))),
            replay=lambda sock, fr: rig_replay.replay(sock, fr, max_gap_ns=2_000_000))
    assert got["from_mon0"] == [], got["kinds"]
    # Zero frames means something only if the link carried the replay.
    assert [rig_netns.sha(d) for d in got["replayed"]] == [rig_netns.sha(f.data) for f in frames]
    assert seen["frames"] == len(frames)
    print(f"MEASURED C-11: {len(frames)} frames replayed, {seen['frames']} seen on mon0, 0 sent from mon0")


def test_c11_negative_control_a_misconfigured_interface_is_seen_to_send():
    """The test of the test (plan section 6): the same run with mon0 given
    an IPv4 address, IPv6 and ARP, a neighbour to look for and a DHCP
    client's first message. If this showed no frame, a pass above would mean
    nothing."""
    def chatter(rig):
        rig_netns.reach_neighbour(rig.sensor_ns)
        rig_netns.dhcp_discover(rig.sensor_ns, MON)

    with rig_netns.Rig(misconfigured=True) as rig:
        got = rig_netns.c11(rig, gt_frames()[:20], start_sensor=lambda: chatter(rig), settle_s=2.0)
    kinds = got["kinds"]
    print(f"MEASURED C-11 negative control: {len(got['from_mon0'])} frames from mon0: {kinds}")
    assert got["from_mon0"], "the misconfigured interface sent nothing the rig could see"
    assert "arp" in kinds and "dhcp" in kinds and any(k.startswith("ipv6") for k in kinds), kinds


def test_a_packet_socket_send_is_seen_with_and_without_qdisc_bypass():
    """A quiet IP configuration does not stop a process that writes to the
    interface itself, and the rig must see it on either send path."""
    with rig_netns.Rig() as rig:
        cap = rig_netns.Capture(rig.rig_ns, TAP).start()
        rig.up()
        time.sleep(0.5)
        for tag, bypass in (("plain", False), ("bypass", True)):
            s = rig_netns.packet_socket(rig.sensor_ns, MON, bypass=bypass)
            s.send(rig_netns.marker_frame(tag))
            s.close()
        cap.stop()
    got = [f[3] for f in cap.arrived()]
    assert got == [rig_netns.marker_frame("plain"), rig_netns.marker_frame("bypass")]


def test_the_bypass_sender_really_skips_the_queueing_layer():
    """The control for the bypass sender. With a queue on mon0 that drops
    everything, an ordinary packet-socket send must not arrive and a
    PACKET_QDISC_BYPASS send must. Otherwise the sender below would be
    testing the egress rule against the ordinary path twice."""
    told, sent = {}, {}
    with rig_netns.Rig() as rig:
        cap = rig_netns.Capture(rig.rig_ns, TAP).start()
        rig.up()
        time.sleep(0.5)
        rig.qdisc_drop_all()
        for tag, bypass in (("plain", False), ("bypass", True)):
            s = rig_netns.packet_socket(rig.sensor_ns, MON, bypass=bypass)
            try:
                s.send(rig_netns.marker_frame(tag))
                told[tag] = "accepted"
            except OSError as e:
                told[tag] = errno.errorcode.get(e.errno, str(e.errno))
            s.close()
        cap.stop()
    got = [f[3] for f in cap.arrived()]
    sent = {t: rig_netns.marker_frame(t) in got for t in ("plain", "bypass")}
    print(f"MEASURED queue that drops everything on mon0: packet socket: send {told['plain']}, frame arrived "
          f"{sent['plain']}; with PACKET_QDISC_BYPASS: send {told['bypass']}, frame arrived {sent['bypass']}")
    assert not sent["plain"], "the queue did not drop an ordinary send, so it is no control"
    assert sent["bypass"], "the bypass sender did not skip the queueing layer"


def test_an_nftables_egress_rule_measured_against_each_send_path():
    """A netdev egress chain that drops everything on mon0, then three ways
    to send: the host's own stack, a packet socket, and a packet socket with
    PACKET_QDISC_BYPASS. The rule must stop the stack, or it isn't in
    force. What it does to the two packet-socket paths is the measurement
    this rig exists to make, so it is printed and recorded, not assumed."""
    if not shutil.which("nft"):
        if REQUIRED:
            pytest.fail("OTSEC_RIG_REQUIRED=1, and the runner has no nft")
        pytest.skip("no nft")
    with rig_netns.Rig(misconfigured=True) as rig:
        rig.up()
        time.sleep(2.0)
        rig.nft_egress_drop()
        cap = rig_netns.Capture(rig.rig_ns, TAP).start()
        told = {}  # what each sender was told: the kernel may refuse a send the rule drops

        def attempt(name, send):
            try:
                send()
                told[name] = "accepted"
            except OSError as e:
                told[name] = errno.errorcode.get(e.errno, str(e.errno))

        attempt("neighbour", lambda: rig_netns.reach_neighbour(rig.sensor_ns))
        attempt("dhcp", lambda: rig_netns.dhcp_discover(rig.sensor_ns, MON))
        for tag, bypass in (("plain", False), ("bypass", True)):
            s = rig_netns.packet_socket(rig.sensor_ns, MON, bypass=bypass)
            attempt(tag, lambda: s.send(rig_netns.marker_frame(tag)))
            s.close()
        time.sleep(1.5)
        cap.stop()
        kernel = os.uname().release
    got = [f[3] for f in cap.arrived()]
    stack = [rig_netns.classify(f) for f in got if not f[14:].startswith(b"otsec-rig:")]
    arrived = {t: rig_netns.marker_frame(t) in got for t in ("plain", "bypass")}
    print(f"MEASURED nft egress drop on mon0, kernel {kernel}: stack frames that passed: {stack} "
          f"(sends: neighbour {told['neighbour']}, dhcp {told['dhcp']}); "
          f"packet socket: send {told['plain']}, frame arrived {arrived['plain']}; "
          f"packet socket with PACKET_QDISC_BYPASS: send {told['bypass']}, frame arrived {arrived['bypass']}")
    assert stack == [], "the egress rule is not in force: the host's own frames passed it"
    for tag in ("plain", "bypass"):
        assert told[tag] == "accepted" or not arrived[tag], f"{tag}: the send was refused and the frame still arrived"


def test_capabilities_a_process_that_dropped_them_passes_and_one_that_kept_them_is_flagged():
    with rig_netns.Rig() as rig:
        rig.up()
        time.sleep(0.3)
        out = rig_netns.packet_socket(rig.rig_ns, TAP)
        result = {}
        for mode in ("drop", "keep"):
            p = start_standin(rig, mode)
            st = rig_caps.status(p.pid)  # while it is capturing
            for i in range(5):
                out.send(rig_netns.marker_frame(f"{mode}{i}"))
            time.sleep(0.3)
            result[mode] = (rig_caps.problems(st), *stop_standin(p))
        out.close()
    print(f"MEASURED capabilities: {result}")
    bad, frames, reopen = result["drop"]
    assert bad == [] and frames == 5 and reopen == "denied", result["drop"]
    bad, frames, reopen = result["keep"]
    assert any("CAP_NET_RAW" in b for b in bad) and frames == 5 and reopen == "ok", result["keep"]

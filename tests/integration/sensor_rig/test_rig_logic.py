"""The rig's rules on any machine: the replayer's schedule and its two
timing checks on a fake clock, the latency measure, the capability rule on
canned /proc status values, and the frame classifier (D6, P4-4-R1). No
socket, no namespace and no root. The same rules run against a real veth
pair in test_rig_selftest.py."""

import os
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "gt_pcap"))

import pcapfile  # noqa: E402
import rig_caps  # noqa: E402
import rig_netns  # noqa: E402
import rig_replay  # noqa: E402

MS = 1_000_000


class FakeClock:
    """A monotonic clock that only sleep() moves, plus `lag` per sleep: a
    scheduler that wakes late."""

    def __init__(self, lag_ns=0):
        self.ns, self.lag = 5_000 * MS, lag_ns

    def mono(self):
        return self.ns

    def wall(self):
        return 1_762_560_000_000 * MS + self.ns

    def sleep(self, s):
        self.ns += round(s * 1e9) + self.lag


class Sink:
    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(data)


def frames(*at_ms):
    return [pcapfile.Frame(1_000 * MS + t * MS, bytes([i]) * 60) for i, t in enumerate(at_ms)]


def run(fr, lag_ns=0, **how):
    c, sink = FakeClock(lag_ns), Sink()
    return rig_replay.replay(sink, fr, mono=c.mono, wall=c.wall, sleep=c.sleep, **how), sink


def test_the_schedule_follows_the_captures_offsets():
    fr = frames(0, 10, 10, 250, 4250)
    assert rig_replay.schedule(fr) == [0, 10 * MS, 10 * MS, 250 * MS, 4250 * MS]
    assert rig_replay.schedule(fr, speed=2.0) == [0, 5 * MS, 5 * MS, 125 * MS, 2125 * MS]
    # Only the gap above the cap is shortened; the frames after it keep their spacing.
    assert rig_replay.schedule(fr, max_gap_ns=100 * MS) == [0, 10 * MS, 10 * MS, 110 * MS, 210 * MS]
    assert rig_replay.schedule([]) == []


def test_a_replay_on_time_sends_every_frame_in_order_and_passes_its_own_check():
    fr = frames(0, 10, 30, 300)
    log, sink = run(fr)
    assert sink.sent == [f.data for f in fr]
    assert [r["n"] for r in log] == [1, 2, 3, 4]
    assert [r["sent_ns"] for r in log] == [r["due_ns"] for r in log] == [0, 10 * MS, 30 * MS, 300 * MS]
    assert all(r["sha256"] == rig_netns.sha(f.data) for r, f in zip(log, fr))
    assert rig_replay.check_log(log, 1 * MS) == []


def test_a_late_replayer_fails_its_own_check():
    log, _ = run(frames(0, 10, 30, 300), lag_ns=3 * MS)
    bad = rig_replay.check_log(log, 2 * MS)
    assert len(bad) == 3 and "frame 2" in bad[0]  # every frame it had to sleep for
    assert rig_replay.check_log(log, 3 * MS) == []


def test_a_frame_sent_before_it_was_due_fails_the_check():
    log, _ = run(frames(0, 10, 30))
    log[2]["sent_ns"] -= 1
    assert len(rig_replay.check_log(log, 1 * MS)) == 1


def arrivals(fr, at_ms):
    return [(9_000 * MS + t * MS, f.data) for f, t in zip(fr, at_ms)]


def test_the_receivers_check_passes_only_on_the_captures_pace():
    fr = frames(0, 100, 200, 300)
    assert rig_replay.check_arrivals(fr, arrivals(fr, (0, 101, 199, 300)), 5 * MS) == []
    # Sent in order and unchanged, at ten times the pace.
    assert len(rig_replay.check_arrivals(fr, arrivals(fr, (0, 10, 20, 30)), 5 * MS)) == 3
    # The same arrivals are right when the replay was asked for that pace.
    assert rig_replay.check_arrivals(fr, arrivals(fr, (0, 10, 20, 30)), 5 * MS, speed=10.0) == []
    # One frame held back 40 ms: its gap is long and the next one short.
    assert len(rig_replay.check_arrivals(fr, arrivals(fr, (0, 140, 200, 300)), 5 * MS)) == 2


@pytest.mark.parametrize("damage", ["lost", "reordered", "altered", "extra"])
def test_the_receivers_check_fails_on_a_frame_lost_reordered_altered_or_added(damage):
    fr = frames(0, 100, 200, 300)
    got = arrivals(fr, (0, 100, 200, 300))
    if damage == "lost":
        del got[2]
    elif damage == "reordered":
        got[1], got[2] = (got[1][0], got[2][1]), (got[2][0], got[1][1])
    elif damage == "altered":
        got[3] = (got[3][0], got[3][1][:-1] + b"\xff")
    else:
        got.append((got[-1][0] + 1, b"\x00" * 60))
    assert len(rig_replay.check_arrivals(fr, got, 5 * MS)) == 1


def test_latency_is_the_alert_minus_the_named_frames_send_on_the_wall_clock():
    fr = frames(0, 100, 200)
    log, _ = run(fr)
    alert = log[1]["sent_wall_ns"] + 250 * MS
    assert rig_replay.latency_ns(log, log[1]["sha256"], alert) == 250 * MS
    assert rig_replay.latency_ns(log, log[0]["sha256"], alert) == 350 * MS
    with pytest.raises(LookupError):  # the alert is before the frame it names was sent
        rig_replay.latency_ns(log, log[2]["sha256"], alert - 200 * MS)
    with pytest.raises(LookupError):
        rig_replay.latency_ns(log, "0" * 64, alert)


def test_latency_of_a_frame_sent_twice_counts_from_the_last_send_before_the_alert():
    fr = frames(0, 100, 200)
    fr[2] = pcapfile.Frame(fr[2].ns, fr[0].data)  # a retransmission of frame 1's bytes
    log, _ = run(fr)
    h = log[0]["sha256"]
    assert rig_replay.latency_ns(log, h, log[0]["sent_wall_ns"] + 150 * MS) == 150 * MS
    assert rig_replay.latency_ns(log, h, log[0]["sent_wall_ns"] + 230 * MS) == 30 * MS


def test_the_summary_gives_the_median_the_nearest_rank_p90_and_the_maximum():
    assert rig_replay.summary([7]) == {"count": 1, "median_ns": 7, "p90_ns": 7, "max_ns": 7}
    got = rig_replay.summary([10, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    assert got == {"count": 10, "median_ns": 5, "p90_ns": 9, "max_ns": 10}
    assert rig_replay.summary(list(range(1, 22)))["p90_ns"] == 19
    with pytest.raises(ValueError):
        rig_replay.summary([])


CLEAN = {"CapInh": "0000000000000000", "CapPrm": "0000000000000000", "CapEff": "0000000000000000",
         "CapBnd": "000001ffffffffff", "CapAmb": "0000000000000000", "NoNewPrivs": "1"}


def test_the_capability_rule():
    assert rig_caps.problems(CLEAN) == []
    assert rig_caps.problems({**CLEAN, "CapBnd": "0000000000000000", "NoNewPrivs": "0"}) == []
    # CAP_NET_RAW (bit 13) alone, in each set that counts as holding it.
    for name in rig_caps.SETS:
        bad = rig_caps.problems({**CLEAN, name: "0000000000002000"})
        assert len(bad) == 1 and name in bad[0] and "CAP_NET_RAW" in bad[0]
    # Another capability is still a capability.
    bad = rig_caps.problems({**CLEAN, "CapEff": "0000000000001000"})
    assert len(bad) == 1 and "CAP_NET_RAW" not in bad[0]
    # Nothing held now, but a program it runs could give one back.
    assert len(rig_caps.problems({**CLEAN, "NoNewPrivs": "0"})) == 1
    # A root process that dropped nothing fails on every count but ambient and inheritable.
    root = {**CLEAN, "CapPrm": "000001ffffffffff", "CapEff": "000001ffffffffff", "NoNewPrivs": "0"}
    assert len(rig_caps.problems(root)) == 3


def eth(ethertype, payload):
    return bytes(12) + struct.pack("!H", ethertype) + payload


def test_the_classifier_names_what_c11_forbids():
    assert rig_netns.classify(eth(0x0806, bytes(46))) == "arp"
    ip6 = lambda nxt, body: eth(0x86DD, bytes(6) + bytes([nxt, 255]) + bytes(32) + body)  # noqa: E731
    assert rig_netns.classify(ip6(58, bytes([133]) + bytes(7))) == "ipv6-router-solicitation"
    assert rig_netns.classify(ip6(58, bytes([135]) + bytes(23))) == "ipv6-neighbour-solicitation"
    assert rig_netns.classify(ip6(0, bytes([58, 0, 5, 2, 0, 0, 1, 0]) + bytes([143]) + bytes(27))) == "ipv6-mld-report"
    assert rig_netns.classify(ip6(17, bytes(8))) == "ipv6"
    udp = bytes([0x45]) + bytes(8) + bytes([17]) + bytes(10) + struct.pack("!HH", 68, 67) + bytes(4)
    assert rig_netns.classify(eth(0x0800, udp)) == "dhcp"
    assert rig_netns.classify(eth(0x88CC, bytes(46))) == "ethertype-0x88cc"
    marker = rig_netns.marker_frame("x")
    assert len(marker) == 60 and rig_netns.classify(marker) == "ethertype-0x88b5"

"""CH-53's and CH-57's requirements on the project's script, each with a test
and its control (D4-102 item 6; D1's ruling 1 on #715). D4's own synthetic
inputs (TEST-NET-1 addresses, RFC 5737), written from D6's byte helpers in
tests/integration/gt_pcap; no counted measurement reads them.

Each row runs one capture under a test configuration (probe.zeek, with
script-reqs/reqtest.zeek, which logs each connection's start and removal in
event order) and under a control configuration that undoes the one
requirement the row tests. A row passes when the test configuration meets
the expectation and the control does not, and both exited 0.

`connection_timing_out` (CH-53's third requirement) is checked on the
script's text by test_script_reqs.py, not here: Zeek 9.0.1 declares it in
init-bare.zeek as a type of the same name, and whether a script can define
a hook by that name is not read.

Usage: python -I script_reqs.py write OUT    the captures
       python -I script_reqs.py configs      one line per configuration:
                                             its name, then its arguments
       python -I script_reqs.py check OUT    OUT/<capture>/<config>/, as
                                             in-container.sh lays them out
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "tests", "integration", "gt_pcap"))
import dnp3  # noqa: E402
import pcapfile  # noqa: E402
import synth  # noqa: E402

S = 1_000_000_000
MS = 1_000_000
# The configurations run.sh runs (name: arguments after probe.zeek and
# reqtest.zeek). Each control undoes one requirement.
SHORT = "OtsecProbe::flow_idle=10sec tcp_inactivity_timeout=10sec OtsecProbe::sa_reply_timeout=30sec"
CONFIGS = {
    "req": "",
    "req-ctl-cap": "max_timer_expires=300",
    "req-ctl-idle": "tcp_inactivity_timeout=5min",
    "req-ctl-late": "OtsecProbe::sa_reply_timeout=1hr",
    "req-short": SHORT,
    "req-short-ctl-discard": SHORT + " /exp/script-reqs/ctl-discard.zeek",
    "req-short-ctl-complete": SHORT + " /exp/script-reqs/ctl-complete.zeek",
}


def h(n, port):
    return synth.Host("02:00:00:00:00:%02x" % n, "192.0.2.%d" % n, port)


class Cap:
    """Frames of several conversations on one clock, at times given from the
    capture's start."""

    def __init__(self):
        self.clock = synth.Clock()
        self.t0 = self.clock.ns
        self.convs = []

    def at(self, t_ns):
        gap = self.t0 + t_ns - self.clock.ns
        assert gap > 0, "frames are written in time order"
        return gap

    def udp(self, a, b):
        c = synth.UDPConv(a, b, self.clock)
        self.convs.append(c)
        return c

    def tcp(self, a, b):
        c = synth.TCPConv(a, b, self.clock)
        self.convs.append(c)
        return c

    def frames(self):
        return sorted((f for c in self.convs for f in c.frames), key=lambda f: f.ns)


def dnp3_frame(from_master, app):
    dest, src = (10, 1) if from_master else (1, 10)
    return dnp3.link(dest, src, from_master, dnp3.tpdu(0, app))


def cases():
    out = {}
    # CH-53 (i), the timer cap: 600 UDP flows, one datagram each, then a
    # spell of 120 s (udp_inactivity_timeout is 1 min), then one datagram on
    # a new flow. With max_timer_expires 0 every one of the 600 is removed
    # before that flow starts; at 300, only 300 are.
    c = Cap()
    dst = h(31, 9)
    for i in range(600):
        c.udp(synth.Host("02:00:00:00:00:1e", "192.0.2.30", 31000 + i), dst).send(True, b"x", gap_ns=c.at(i * MS + MS))
    c.udp(h(32, 5000), dst).send(True, b"x", gap_ns=c.at(600 * MS + 120 * S))
    out["req-timer-cap"] = c
    # CH-53 (ii), tcp_inactivity_timeout = flow_idle (60 s): a TCP flow,
    # then 120 s with no frame on it, then a frame on another flow, then the
    # TCP flow's next segment. The first connection is removed at the other
    # flow's frame; at 5 min, it is not.
    c = Cap()
    t = c.tcp(h(40, 40100), h(41, 8080))
    t.handshake()
    t.send(True, b"hello")
    last = c.clock.ns - c.t0
    c.udp(h(42, 5001), h(41, 9)).send(True, b"x", gap_ns=c.at(last + 120 * S))
    t.send(True, b"again", gap_ns=c.at(last + 130 * S))
    out["req-idle"] = c
    # CH-57 (i), the DNP3 timeout on network time: a READ with no response
    # at 0, then frames on another flow at 4.990 s and 5.010 s, and at 60 s.
    # The timeout (5 s) completes it at the frame at 5.010 s.
    c = Cap()
    c.udp(h(50, 20000), h(51, 20000)).send(True, dnp3_frame(True, dnp3.request(1, dnp3.READ, dnp3.all_objects(60, 1))),
                                           gap_ns=c.at(MS))
    o = c.udp(h(52, 5002), h(53, 9))
    for t_ns in (MS + 4990 * MS, MS + 5010 * MS, MS + 60 * S):
        o.send(True, b"x", gap_ns=c.at(t_ns))
    out["req-dnp3-timeout"] = c
    # CH-57 (ii), under flow_idle 10 s and sa_reply_timeout 30 s (C13 0.1
    # section 10's bounds): two masters each send a READ on a TCP flow at
    # about 0; a frame on another flow at 20 s cuts both flows; at 22 s
    # master A opens a new connection and the outstation answers A's
    # request there; frames on the other flow at 31 s and 40 s. A's request
    # completes at the response; B's at the timeout, at the frame at 31 s.
    c = Cap()
    reqs = []
    for n, port, seq in ((60, 40200, 2), (62, 40300, 3)):
        t = c.tcp(h(n, port), h(n + 1, 20000))
        t.handshake()
        t.send(True, dnp3_frame(True, dnp3.request(seq, dnp3.READ, dnp3.all_objects(60, 1))))
        reqs.append(t)
    o = c.udp(h(64, 5003), h(65, 9))
    o.send(True, b"x", gap_ns=c.at(20 * S))
    a2 = c.tcp(h(60, 40201), h(61, 20000))
    a2._frame(True, synth.SYN, gap_ns=c.at(22 * S))
    a2.seq[True] += 1
    a2._frame(False, synth.SYN | synth.ACK)
    a2.seq[False] += 1
    a2._frame(True, synth.ACK)
    a2.send(False, dnp3_frame(False, dnp3.response(2)))
    o.send(True, b"x", gap_ns=c.at(31 * S))
    o.send(True, b"x", gap_ns=c.at(40 * S))
    out["req-dnp3-idle"] = c
    return out


def write(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, c in cases().items():
        pcapfile.write(os.path.join(outdir, name + ".pcap"), c.frames())


def rows(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.startswith("{")]


def logs(d):
    """(reqtest rows in event order, the probe's `done` rows), or a string
    saying why the configuration's run cannot be read."""
    try:
        rc = open(os.path.join(d, "exit-code"), encoding="utf-8").read().strip()
    except OSError:
        return "not run"
    if rc != "0":
        return f"exit {rc}"
    t = sorted(rows(os.path.join(d, "otsec_reqtest.log")), key=lambda r: r["n"])
    done = [r for r in rows(os.path.join(d, "otsec_probe.log")) if r.get("kind") == "done"]
    return t, done


def near(a, b):
    return abs(a - b) < 0.0005


def t0(t):
    """The capture's start: each capture's first frame is 1 ms after it, and
    that frame starts the first connection reqtest.zeek logs."""
    return min(r["ts"] for r in t) - 0.001 if t else 0.0


def all_removed_first(t, done):
    new = [r["n"] for r in t if r["ev"] == "new" and r["orig_p"] == 5000]
    gone = [r for r in t if r["ev"] == "remove" and 31000 <= r["orig_p"] < 31600]
    return len(new) == 1 and len(gone) == 600 and all(r["n"] < new[0] for r in gone)


def cut_at_flow_idle(t, done):
    first = [r for r in t if r["ev"] == "new" and r["orig_p"] == 40100]
    other = [r for r in t if r["ev"] == "new" and r["orig_p"] == 5001]
    if not first or len(other) != 1:
        return False
    gone = [r for r in t if r["ev"] == "remove" and r["uid"] == first[0]["uid"]]
    return len(gone) == 1 and near(gone[0]["ts"], other[0]["ts"])


def timeout_at_frame_after_bound(t, done):
    start = t0(t)
    hit = [r for r in done if r.get("seq") == 1]
    return len(hit) == 1 and hit[0]["done"] == "timeout" and near(hit[0]["ts"] - start, 0.001 + 5.010)


def idle_cut(t):
    start = t0(t)
    firsts = [r["uid"] for r in t if r["ev"] == "new" and r["orig_p"] in (40200, 40300)]
    gone = [r for r in t if r["ev"] == "remove" and r["uid"] in firsts]
    return len(firsts) == 2 and len(gone) == 2 and all(near(r["ts"] - start, 20) for r in gone)


def not_discarded(t, done):
    a = [r for r in done if r.get("seq") == 2]
    return idle_cut(t) and len(a) == 1 and a[0]["done"] == "response" and a[0]["ts"] - t0(t) > 22


def not_completed(t, done):
    b = [r for r in done if r.get("seq") == 3]
    return idle_cut(t) and len(b) == 1 and b[0]["done"] == "timeout" and near(b[0]["ts"] - t0(t), 31)


ROWS = [
    ("CH-53: max_timer_expires is 0", "req-timer-cap", "req", "req-ctl-cap",
     "all 600 idle UDP flows are removed before the new flow at the first frame after the spell starts",
     all_removed_first),
    ("CH-53: tcp_inactivity_timeout is flow_idle", "req-idle", "req", "req-ctl-idle",
     "the TCP flow is removed at the first frame 120 s after its last (flow_idle 60 s)", cut_at_flow_idle),
    ("CH-57: the DNP3 timeout is an engine timer on network time", "req-dnp3-timeout", "req", "req-ctl-late",
     "the READ with no response completes as `timeout` at the frame at 5.010 s, not at 4.990 s", timeout_at_frame_after_bound),
    ("CH-57: an idle cut does not discard a pending request", "req-dnp3-idle", "req-short", "req-short-ctl-discard",
     "both flows are cut at 20 s; A's READ completes as `response` on the new connection at 22 s", not_discarded),
    ("CH-57: an idle cut does not complete a pending request", "req-dnp3-idle", "req-short", "req-short-ctl-complete",
     "both flows are cut at 20 s; B's READ completes as `timeout` at the frame at 31 s", not_completed),
]


def state(d, test):
    s = logs(d)
    if isinstance(s, str):
        return s
    return "met" if test(*s) else "not met"


def check(out):
    bad = 0
    print("\n## CH-53's and CH-57's requirements on the script (D4-102 item 6; D1's ruling 1 on #715)\n")
    print("D4's own synthetic captures (`script_reqs.py`). Each row passes when the test configuration meets the "
          "expectation and the control, which undoes that one requirement, does not.\n")
    print("| requirement | expectation | test (configuration: state) | control (configuration: state) | result |")
    print("| --- | --- | --- | --- | --- |")
    for req, cap, cfg, ctl, what, test in ROWS:
        a, b = state(os.path.join(out, cap, cfg), test), state(os.path.join(out, cap, ctl), test)
        res = "pass" if a == "met" and b == "not met" else "fail"
        bad |= res != "pass"
        print(f"| {req} | {what} | {cfg}: {a} | {ctl}: {b} | {res} |")
    print()
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1] == "write":
        write(sys.argv[2])
    elif sys.argv[1] == "check":
        sys.exit(check(sys.argv[2]))
    elif sys.argv[1] == "configs":
        for name, args in CONFIGS.items():
            print(f"{name} {args}".rstrip())
    else:
        sys.exit("usage: script_reqs.py write|check OUT, or configs")

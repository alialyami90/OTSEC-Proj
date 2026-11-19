"""HR-23 option (i): D4's unit and negative tests of the patch, on the
project's two builds (brief P4-4-HR23, stage 3).

These are D4's own inputs for the build, named `d4u-*`. They are not
GT-PCAP cases and not stage 2's cases, which D6 writes and pins; no counted
measurement reads them. Each input is written here from D6's byte helpers
(tests/integration/gt_pcap/dnp3.py, synth.py, pcapfile.py), used as they
are. Addresses are from TEST-NET-1 (RFC 5737).

`write OUT` writes the captures. `check OUT` reads what each build logged
(OUT/<case>/<config>/otsec_probe.log, analyzer.log and exit-code, as
in-container.sh lays them out) and judges each expectation for C2
(`zeek-probe-c2`, the patched build) and C1p (`zeek-probe-c1p`, the same
tree without the patch), which is each test's control: a test of the patch
passes only when C2 meets it and C1p does not, or, for a test of what must
not change, when both meet it. A configuration whose Zeek exited non-zero
fails the row, so a crash, which leaves partial logs, is never read as a
silent stop (D6's N3 on #715). It prints a table and exits 1 on any row
that is not `pass`.

(B') (D1's ruling on #715, 6907928324): the patch's catch in
DNP3_UDP_Analyzer::DeliverPacket raises the DNP3 violation itself. Its rows
are read by a judge with three states, `parsed on`, `recorded stop` and
`silent stop`, and a fourth, `recorded elsewhere`, for an analyzer.log row
that names another analyzer (`judge`). Each stop case is followed by whole
messages that the builder names (Flow.send's `bad`), so a silent stop is
told apart from nothing more to parse. Three controls, C2 with one control
patch each (controls/), must each read the state named for them on their
rows.

D1's experiment on #715 (6902545944): the `*-first` cases, over UDP and
TCP, also run under C0 (`zeek-probe-c0`, the stock image), and `check`
quotes, for each configuration, the exit code, conn.log's rows, every
analyzer.log row with no filter on the analyzer's name, and weird.log's and
reporter.log's rows. The inputs are D4's own synthetic bytes.

D4-116 item 6: `write` also writes one GT-PCAP capture of #718's,
dnp3-tcp-master-short, rebuilt by hr23_cases.py and refused unless it equals
its pin in hr23.sha256; `check` prints, under C0, C1 (`zeek-probe`, the
stock image with part (a)), C1p and C2, only whether each ran on it and its
exit code, and fails if any of the four did not run or exited non-zero.

Usage: python -I dispatch_unit.py write OUT
       python -I dispatch_unit.py check OUT
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "..", "tests", "integration", "gt_pcap"))
import dnp3  # noqa: E402
import hr23_cases  # noqa: E402
import pcapfile  # noqa: E402
import synth  # noqa: E402

C2, C1P, C0 = "zeek-probe-c2", "zeek-probe-c1p", "zeek-probe-c0"
MASTER = synth.Host("02:00:00:00:00:0e", "192.0.2.14", 20000)
RELAY = synth.Host("02:00:00:00:00:14", "192.0.2.20", 20000)
CLIENT_PORT = 40001
M_LINK, R_LINK = 1, 10


def link(dest, src, dir_set, user):
    """dnp3.link with DIR given apart from the sender, so that a frame can
    say the opposite of its sender's role (a forged DIR)."""
    ctrl = (0x80 if dir_set else 0) | 0x40 | 0x04
    hdr = b"\x05\x64" + struct.pack("<BBHH", 5 + len(user), ctrl, dest, src)
    out = hdr + dnp3.crc(hdr)
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + dnp3.crc(blk)
    return out


class Flow:
    """One UDP 5-tuple; `first` is the end whose datagram the sensor sees
    first, so it is Zeek's originator (both ports are 20000, which Zeek does
    not swap). With tcp=True, one TCP connection instead: `first` is the
    client, from port CLIENT_PORT to the other end's `server_port`, after a
    full handshake, and each frame is one segment, acknowledged."""

    def __init__(self, first, tcp=False, server_port=20000):
        self.clock = synth.Clock()
        a, b = (RELAY, MASTER) if first == "relay" else (MASTER, RELAY)
        if tcp:
            a = synth.Host(a.mac, a.ip, CLIENT_PORT)
            b = synth.Host(b.mac, b.ip, server_port)
            self.conv = synth.TCPConv(a, b, self.clock)
            self.conv.handshake()
        else:
            self.conv = synth.UDPConv(a, b, self.clock)
        self.relay_first = first == "relay"
        self.tseq = {True: 0, False: 0}
        # The builder's names for what the flow carries, read by `judge`:
        # each message as (is_orig, function code), and the index of the
        # one the case stops on, if any.
        self.msgs = []
        self.bad = None

    def send(self, from_master, apdu, dir_set=None, bad=False):
        seg = dnp3.tpdu(self.tseq[from_master], apdu)
        self.tseq[from_master] = (self.tseq[from_master] + 1) & 0x3F
        dest, src = (R_LINK, M_LINK) if from_master else (M_LINK, R_LINK)
        frame = link(dest, src, from_master if dir_set is None else dir_set, seg)
        is_orig = from_master != self.relay_first
        self.conv.send(is_orig, frame)
        self.msgs.append((is_orig, apdu[1] if len(apdu) > 1 else None))
        if bad:
            self.bad = len(self.msgs) - 1

    def trailing(self):
        """The whole messages after the stop, as the builder names them."""
        return self.msgs[self.bad + 1:]


def cases():
    out = {}
    # A flow the relay starts, both ends on 20000 (HR-23's trigger): the
    # relay's solicited 129 answers a request the sensor missed, then the
    # master's write, a confirm, a cold restart and a second write.
    f = Flow("relay")
    f.send(False, dnp3.response(0))
    f.send(True, dnp3.request(1, dnp3.WRITE, dnp3.iin_clear_restart()))
    f.send(False, dnp3.response(1))
    f.send(True, dnp3.confirm(1))
    f.send(True, dnp3.request(2, 13))
    f.send(True, dnp3.request(3, dnp3.WRITE, dnp3.iin_clear_restart()))
    f.send(False, dnp3.response(3))
    out["d4u-relay-start"] = f
    # A conforming flow the master starts: the parser is the control's.
    f = Flow("master")
    f.send(True, dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1)))
    f.send(False, dnp3.response(0))
    f.send(True, dnp3.request(1, dnp3.WRITE, dnp3.iin_clear_restart()))
    f.send(False, dnp3.response(1))
    out["d4u-master-start"] = f
    # Negative: a 129 of 2 application octets from the originator, after a
    # whole one. Under C2 the response parser needs 4 and throws; under C1p
    # the request parser's default arm takes it. Then a read, which C2 no
    # longer sees.
    f = Flow("relay")
    f.send(False, dnp3.response(0))
    f.send(False, bytes([0xC1, dnp3.RESPONSE]))
    f.send(True, dnp3.request(2, dnp3.READ, dnp3.all_objects(60, 1)))
    out["d4u-short-response-orig"] = f
    # D3's N3 on #715: (A)'s bound at 3 octets, from the originator (a `< 3`
    # bound would send it to the response parser, which needs 4).
    f = Flow("relay")
    f.send(False, dnp3.response(0))
    f.send(False, bytes([0xC1, dnp3.RESPONSE, 0x00]))
    f.send(True, dnp3.request(2, dnp3.READ, dnp3.all_objects(60, 1)))
    out["d4u-short3-response-orig"] = f
    # D3's N3 and D6's N9 on #715: (A)'s cost, measured. A 2-octet 129 from
    # the responder on a flow the master starts: C1p's response parser
    # needs 4 octets and throws; under C2 the request parser takes it, and
    # the master's next READ is seen.
    f = Flow("master")
    f.send(True, dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1)))
    f.send(False, bytes([0xC0, dnp3.RESPONSE]))
    f.send(True, dnp3.request(1, dnp3.READ, dnp3.all_objects(60, 1)))
    out["d4u-short-response-resp"] = f
    # D1's experiment (6902545944): two inputs as a flow's first datagram,
    # each followed by whole messages from both ends, over UDP and over TCP.
    # D3's stock control: a READ whose object header is cut after its group
    # octet (3 application octets), which the request parser rejects under
    # every build. D2's case: a 2-octet 129 from the originator.
    for tcp, sfx in ((False, ""), (True, "-tcp")):
        f = Flow("master", tcp)
        f.send(True, bytes([0xC0, dnp3.READ, 60]), bad=True)
        f.send(False, dnp3.response(0))
        f.send(True, dnp3.request(1, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(1))
        out["d4u-short-request-first" + sfx] = f
        f = Flow("relay", tcp)
        f.send(False, bytes([0xC0, dnp3.RESPONSE]))
        f.send(True, dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(0))
        out["d4u-short-response-first" + sfx] = f
        # D3's M1 on #718 (6907164763), at D1's request: a 129 of 4 octets
        # or more whose objects the response parser rejects (IIN, then one
        # object octet, shorter than an object header), as the flow's first
        # datagram. C1p's request parser takes it in its `default` arm;
        # C2's response parser throws on it.
        f = Flow("relay", tcp)
        f.send(False, dnp3.response(0, objects=b"\x01"), bad=True)
        f.send(True, dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(0))
        out["d4u-bad-objects-response-first" + sfx] = f
    # (B')'s ordinary path (D6's row 3 on #715): the same truncated READ as a
    # UDP flow's second datagram, which reaches the analyzer through
    # Analyzer::NextPacket, not the PIA's replay (dpd_dnp3_server_udp
    # matches the first datagram, dpd.sig).
    f = Flow("master")
    f.send(True, dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1)))
    f.send(True, bytes([0xC1, dnp3.READ, 60]), bad=True)
    f.send(False, dnp3.response(1))
    f.send(True, dnp3.request(2, dnp3.READ, dnp3.all_objects(60, 1)))
    f.send(False, dnp3.response(2))
    out["d4u-short-request-second"] = f
    # D4-115 item 4 (D4's N1 on #724): what a TCP stop leaves, in the orders
    # of #718's TCP cells, on D4's own bytes, each ending, as those do, with
    # the FIN exchange. Measured, not judged.
    # dnp3-mal-tcp-fc129-badobj-first's order: X, then the same end's P,
    # then R(P), Q and R(Q), on a connection to 20001, outside
    # likely_server_ports, so dpd_dnp3_server attaches DNP3_TCP at R(P) and
    # PIA_TCP replays X and P. X is the truncated READ, which every build
    # rejects (the stock engine's stop), or M1's 129 of 5 octets, which only
    # C2's parser rejects.
    for sfx, x in (("", bytes([0xC0, dnp3.READ, 60])), ("-badobj", dnp3.response(0, objects=b"\x01"))):
        f = Flow("master", True, server_port=20001)
        f.send(True, x, bad=True)
        f.send(True, dnp3.request(1, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(1))
        f.send(True, dnp3.request(2, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(2))
        f.conv.close()
        out["d4u-tcp-replay-same-end" + sfx] = f
    # dnp3-mal-tcp-fc0-resp-* and -fc13-resp-*'s order: P and R(P) on a
    # connection to 20000, which attaches DNP3_TCP by port, then X, a 2-octet
    # request code from the responder, which the response parser of C0 and
    # C1p rejects in mid-flow, then Q and R(Q); X's DIR clear, as its
    # role's, or set, against its side (#718's -dirclear and -dirset).
    for name, x, dirset, dn in ((n, x, d, dn) for n, x in (("fc0", dnp3.confirm(0)), ("fc13", dnp3.request(0, 13)))
                                for d, dn in ((False, ""), (True, "-dirset"))):
        f = Flow("master", True)
        f.send(True, dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(0))
        f.send(False, x, dir_set=dirset, bad=True)
        f.send(True, dnp3.request(1, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(1))
        f.conv.close()
        out[f"d4u-tcp-resp-{name}-mid{dn}"] = f
    # A master's direct operate with a control block and DIR clear, on a
    # flow the master starts: the code picks the request parser, so the
    # block is parsed under both builds (a selector keyed by DIR would not).
    f = Flow("master")
    f.send(True, dnp3.request(0, dnp3.DIRECT_OPERATE, dnp3.crob(7)), dir_set=False)
    f.send(False, dnp3.response(0, objects=dnp3.crob(7)))
    out["d4u-dir-clear-operate"] = f
    return out


# D4-116 item 6 (P4-4-HR23-TCPSHORT): one GT-PCAP capture of #718's, measured
# here and not judged, since `run.sh dnp3` does not feed hr23_cases.py's
# captures to the engines. It is rebuilt by D6's builder and must equal its
# pin in the committed hr23.sha256, or nothing is written.
GT_CASE = "dnp3-tcp-master-short"
GT_SUMS = os.path.join(HERE, "..", "..", "..", "..", "..", "tests", "fixtures", "network", "gt-pcap", "hr23",
                       "hr23.sha256")


def gt_capture(outdir, sums=GT_SUMS):
    """Writes GT_CASE's capture as hr23_cases.py builds it, and returns its
    frames' times in ns, in packet order. Refuses (SystemExit, no file left)
    when its SHA-256 differs from the pin in `sums`."""
    pin = next((ln.split()[0] for ln in open(sums, encoding="utf-8") if ln.split()[1:] == [GT_CASE + ".pcap"]),
               None)
    cap = next(c for c in hr23_cases.captures() if c.name == GT_CASE)
    frames = hr23_cases.frames_of(cap)
    path = os.path.join(outdir, GT_CASE + ".pcap")
    pcapfile.write(path, frames)
    with open(path, "rb") as fh:
        got = hashlib.sha256(fh.read()).hexdigest()
    if got != pin:
        os.remove(path)
        raise SystemExit(f"{GT_CASE}.pcap is {got}, not its pin {pin} in {sums}; not written")
    return [fr.ns for fr in frames]


def write(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, f in cases().items():
        pcapfile.write(os.path.join(outdir, name + ".pcap"), f.conv.frames)
    gt_capture(outdir)


def rows(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.startswith("{")]


def exit_code(d):
    """The engine's exit code as in-container.sh wrote it, or None when the
    configuration did not run on the capture."""
    p = os.path.join(d, "exit-code")
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return fh.read().strip()


def seen(d):
    """(application headers as (is_orig, fc, event kind, [g<g>v<v>]),
    link rows as (is_orig, link_dir), DNP3 analyzer violations), or None
    when the configuration left no probe log."""
    probe = rows(os.path.join(d, "otsec_probe.log"))
    if probe is None:
        return None
    msgs, links = [], []
    for r in probe:
        if r["kind"] == "fc":
            msgs.append([r["is_orig"], r["fc"], "req" if r["ev"].endswith("request_header") else "resp", []])
        elif r["kind"] == "obj" and msgs and msgs[-1][0] == r["is_orig"]:
            msgs[-1][3].append(f"g{r['group']}v{r['variation']}")
        elif r["kind"] == "link":
            links.append((r["is_orig"], r.get("link_dir")))
    viol = [r.get("failure_reason") for r in rows(os.path.join(d, "analyzer.log")) or []
            if "DNP3" in str(r.get("analyzer_name", ""))]
    return [tuple(m[:3]) + (tuple(m[3]),) for m in msgs], links, viol


# Expectations. Each is (case, what, test), where test takes one build's
# (msgs, links, violations) and returns True when met. `kind` says how C2
# and C1p are read: "fix" passes when C2 meets it and C1p does not (C1p is
# the control); "same" passes when both meet it.
RELAY_ALL = [(True, 129, "resp", ()), (False, 2, "req", ("g80v1",)), (True, 129, "resp", ()),
             (False, 0, "req", ()), (False, 13, "req", ()), (False, 2, "req", ("g80v1",)), (True, 129, "resp", ())]
EXPECT = [
    ("d4u-relay-start", "fix", "every message parsed by its code's parser, the write's g80v1 twice, no violation",
     lambda m, l, v: m == RELAY_ALL and not v),
    ("d4u-relay-start", "fix", "the cold restart (13) after the confirm is seen",
     lambda m, l, v: (False, 13, "req", ()) in m),
    ("d4u-relay-start", "same", "the link rows give DIR clear from the relay and DIR set from the master",
     lambda m, l, v: bool(l) and all(d is (not o) for o, d in l)),
    ("d4u-master-start", "same", "the conforming flow's messages, as the control reads them",
     lambda m, l, v: m == [(True, 1, "req", ("g60v1",)), (False, 129, "resp", ()), (True, 2, "req", ("g80v1",)),
                           (False, 129, "resp", ())] and not v),
    # D2's (A), after D1's experiment on #715: a fragment shorter than a
    # response header goes to the request parser under C2, as stock sends an
    # originator's fragment, so the short 129 is parsed and the read after
    # it is seen under both builds.
    ("d4u-short-response-orig", "same", "a 2-octet 129 from the originator, after a whole one, is parsed by the "
     "request parser, and the read after it is seen",
     lambda m, l, v: (True, 129, "req", ()) in m and any(x[:2] == (False, 1) for x in m) and not v),
    ("d4u-short3-response-orig", "same", "a 3-octet 129 from the originator, after a whole one, is parsed by "
     "the request parser, and the read after it is seen",
     lambda m, l, v: (True, 129, "req", ()) in m and any(x[:2] == (False, 1) for x in m) and not v),
    ("d4u-short-response-resp", "fix", "a 2-octet 129 from the responder is parsed by the request parser, and "
     "the master's READ after it is seen, with no violation ((A)'s cost: C1p throws on it)",
     lambda m, l, v: (False, 129, "req", ()) in m and m[-1][:2] == (True, 1) and not v),
    ("d4u-short-response-first", "same", "the same 129 as a UDP flow's first datagram: parsed by the request "
     "parser, and the master's READ after it is seen, with no violation",
     lambda m, l, v: m[:1] == [(True, 129, "req", ())] and any(x[:2] == (False, 1) for x in m) and not v),
    ("d4u-short-response-first-tcp", "same", "the same over TCP",
     lambda m, l, v: m[:1] == [(True, 129, "req", ())] and any(x[:2] == (False, 1) for x in m) and not v),
    ("d4u-dir-clear-operate", "same", "the direct operate's g12v1 is parsed although DIR is clear",
     lambda m, l, v: (True, 5, "req", ("g12v1",)) in m and (True, False) in l),
]

# D1's experiment (6902545944), and D3's M1 on #718: measured, not judged.
# `check` quotes what each of C0, C1p and C2 logged on them.
EXPERIMENT = ["d4u-short-request-first", "d4u-short-response-first",
              "d4u-short-request-first-tcp", "d4u-short-response-first-tcp",
              # D3's M1 on #718, at D1's request on #715.
              "d4u-bad-objects-response-first", "d4u-bad-objects-response-first-tcp",
              "d4u-short-request-second",
              # D4-115 item 4: the orders of #718's TCP cells.
              "d4u-tcp-replay-same-end", "d4u-tcp-replay-same-end-badobj",
              "d4u-tcp-resp-fc0-mid", "d4u-tcp-resp-fc13-mid",
              "d4u-tcp-resp-fc0-mid-dirset", "d4u-tcp-resp-fc13-mid-dirset"]


def state(d, test):
    """One configuration's reading of one expectation: `not run` (no exit
    code or no probe log), `exit N` (Zeek exited non-zero), `met` or `not
    met`."""
    rc = exit_code(d)
    s = seen(d)
    if rc is None or s is None:
        return "not run"
    if rc != "0":
        return f"exit {rc}"
    return "met" if test(*s) else "not met"


def verdict(kind, c2, c1):
    """A row's result from C2's and C1p's states. A configuration that did
    not run makes the row unknown; one that exited non-zero fails it."""
    if "not run" in (c2, c1):
        return "unknown (not run)"
    if c2 not in ("met", "not met") or c1 not in ("met", "not met"):
        return "fail"
    if kind == "same":
        return "pass" if c2 == c1 == "met" else "fail"
    # "fix" and "fix-negative": C2 meets it and the control does not.
    return "pass" if c2 == "met" and c1 == "not met" else "fail"


# (B')'s judge (D1's ruling on #715, condition 2; D6's 6907920954). The
# weird `dnp3_unexpected_flow_direction` is left out of the silent-stop test:
# ProcessData raises it on a frame's DIR against its side, before any parse,
# never on a stop (DNP3.cc), and C0, C1p and C2 raise it alike.
FLOW_DIRECTION = "dnp3_unexpected_flow_direction"
STATES = ("parsed on", "recorded stop", "silent stop", "recorded elsewhere")


def unrecorded_stop(n):
    """The judge's state for a stop that is neither recorded once nor
    silent, with the number of DNP3 violations raised."""
    return f"unclassified (a stop that is neither recorded once nor silent; {n} DNP3 violations raised)"


def judge(d, flow):
    """One configuration's state on a stop case, from its logs and the
    builder's names for the flow (`flow.msgs`, `flow.bad`). Returns (state,
    detail). The state is one of STATES, or `not run`, `exit N`, or
    `unclassified (why)`, which no row accepts.

    - frames: conn.log has one row, whose orig_pkts + resp_pkts is the
      number of frames the builder wrote, so the trailing frames arrived;
    - `recorded elsewhere`: an analyzer.log row for the flow names an
      analyzer other than DNP3's (the sensor keys on the DNP3 analyzer);
    - `parsed on`: the probe's last `fc` rows are the builder's trailing
      messages, in order, and no DNP3 violation was raised or logged;
    - stopped: the `fc` rows are, in order, a prefix of the builder's
      messages up to and including the stop's (D6's N12 on #715), so a
      trailing message parsed in the stop's place is never read as a stop;
    - `recorded stop`: stopped, exactly one
      DNP3 violation raised (otsec_viol.log, viol.zeek), exactly one DNP3
      analyzer.log row with a failure_reason, and conn.log's service no
      longer names DNP3;
    - `silent stop`: stopped, and no DNP3
      violation raised, no DNP3 analyzer.log row, no dnp3_ weird other than
      FLOW_DIRECTION and no reporter.log row.
    analyzer.log's failure_data is never read."""
    rc = exit_code(d)
    s = seen(d)
    if rc is None or s is None:
        return "not run", ""
    if rc != "0":
        return f"exit {rc}", ""
    conns = rows(os.path.join(d, "conn.log")) or []
    if len(conns) != 1:
        return f"unclassified ({len(conns)} conn.log rows)", ""
    c = conns[0]
    uid = c.get("uid")
    pkts = c.get("orig_pkts", 0) + c.get("resp_pkts", 0)
    if pkts != len(flow.conv.frames):
        return f"unclassified ({pkts} of {len(flow.conv.frames)} frames in conn.log)", ""
    an = [r for r in rows(os.path.join(d, "analyzer.log")) or [] if r.get("uid") == uid]
    named = [str(r.get("analyzer_name", "")) for r in an]
    reasons = [r.get("failure_reason") for r in an if "DNP3" in str(r.get("analyzer_name", ""))]
    raised = [r.get("analyzer") for r in rows(os.path.join(d, "otsec_viol.log")) or [] if r.get("uid") == uid]
    dviol = [a for a in raised if "DNP3" in str(a)]
    weird = [r.get("name") for r in rows(os.path.join(d, "weird.log")) or []
             if r.get("uid") == uid and str(r.get("name", "")).startswith("dnp3_") and r.get("name") != FLOW_DIRECTION]
    rep = rows(os.path.join(d, "reporter.log")) or []
    service = str(c.get("service", "")).lower()
    detail = (f"fc rows {[m[:2] for m in s[0]]}; violations raised {raised}; analyzer.log {named} "
              f"{reasons}; dnp3 weirds {weird}; reporter rows {len(rep)}; service {service or '-'}")
    if any("DNP3" not in n for n in named):
        return "recorded elsewhere", detail
    fc = [(m[0], m[1]) for m in s[0]]
    tail = flow.trailing()
    lead = flow.bad + 1
    if len(tail) < 2:
        raise ValueError("a stop case needs two or more whole messages after its stop")
    if fc[-len(tail):] == tail and len(fc) >= lead - 1 + len(tail) and not dviol and not reasons:
        return "parsed on", detail
    if len(fc) <= lead and fc == flow.msgs[:len(fc)]:
        if len(dviol) == 1 and len(reasons) == 1 and reasons[0] and "dnp3" not in service:
            return "recorded stop", detail
        if not dviol and not reasons and not weird and not rep:
            return "silent stop", detail
        return unrecorded_stop(len(dviol)), detail
    return "unclassified (neither parsed on nor stopped)", detail


def reasons_of(d):
    """analyzer.log's DNP3 failure_reasons for one configuration (never
    failure_data)."""
    return [r.get("failure_reason") for r in rows(os.path.join(d, "analyzer.log")) or []
            if "DNP3" in str(r.get("analyzer_name", ""))]


# The rows that prove (B') (D1's ruling on #715, condition 4), each read as
# C2 against C1p, with C0 quoted. Each is (id, case, kind, what, C2's state,
# C1p's state, same_reason). "fix" passes when C2 and C1p read their states
# (C1p, a different state, is the control); "same" when both read the
# state. same_reason also asks for one identical failure_reason under C2 and
# C1p. The states come from the rules, (A) and (B'), never from a run.
#
# "unchanged" (condition 4.4, the TCP twins): (B') does not touch TCP, so C2
# must read exactly as C2 with the stock catch (M_STOCK), state and all the
# judge read; C1p must read its state, or exactly as C2 (SAME_AS_C2) where
# (A) leaves the input's parser as C1p's. No state is expected for C2 here.
SAME_AS_STOCK, SAME_AS_C2 = "as C2 with the stock catch", "as C2"
STOPS = [
    ("4.1", "d4u-bad-objects-response-first", "fix", "M1 over UDP: a 129 of 5 application octets as the flow's "
     "first datagram (the PIA's replay); C2's response parser throws, C1p's request parser takes it",
     "recorded stop", "parsed on", False),
    ("4.2", "d4u-short-request-first", "fix", "a truncated READ as a UDP flow's first datagram (the PIA's "
     "replay): stock Zeek's silent stop, recorded under C2", "recorded stop", "silent stop", False),
    ("4.3", "d4u-short-request-second", "same", "the same truncated READ as a UDP flow's second datagram "
     "(Analyzer::NextPacket): one DNP3 violation, the same reason text", "recorded stop", "recorded stop", True),
    ("4.4a", "d4u-bad-objects-response-first-tcp", "unchanged", "4.1's TCP twin, unchanged by (B'); C1p's "
     "request parser takes the 129", SAME_AS_STOCK, "parsed on", False),
    ("4.4b", "d4u-short-request-first-tcp", "unchanged", "4.2's TCP twin, unchanged by (B'); its code agrees "
     "with its side", SAME_AS_STOCK, SAME_AS_C2, False),
]

# (B')'s controls (condition 4.5; D3's condition 3 in 6907898087): C2 with
# one control patch each (controls/). A control passes, that is the mutant is
# killed, when each row named for it reads the state named for it there
# (D6's N13 on #715): a crash, a run that did not happen, or any other
# reading fails it. By the rules: the stock catch rethrows with no violation, so a replayed
# stop is silent (4.1, 4.2); a catch that raises and rethrows raises a second
# violation in Analyzer::NextPacket on the ordinary path (4.3); a catch with
# no violation and no rethrow records nothing on either path.
M_STOCK, M_RERAISE, M_NOVIOL = "zeek-probe-m-stock-catch", "zeek-probe-m-raise-rethrow", "zeek-probe-m-no-violation"
CONTROLS = [
    (M_STOCK, {"4.1": "silent stop", "4.2": "silent stop"}, "the stock catch: no violation there, and a rethrow"),
    (M_RERAISE, {"4.3": unrecorded_stop(2)}, "the catch raises the violation and rethrows"),
    (M_NOVIOL, {"4.1": "silent stop", "4.2": "silent stop", "4.3": "silent stop"},
     "the catch raises no violation and does not rethrow"),
]


def stop_verdict(want2, want1, c2, c1, same_reason):
    """A stop row's result from C2's and C1p's judged states. A
    configuration that did not run makes it unknown."""
    if "not run" in (c2, c1):
        return "unknown (not run)"
    if c2 != want2 or c1 != want1:
        return "fail"
    if not same_reason:
        return "fail (reasons differ)"
    return "pass"


def unchanged_verdict(c2, stock, c1, want1):
    """An "unchanged" row's result from (state, detail) pairs: C2 reads
    exactly as C2 with the stock catch, and C1p reads want1 (or exactly as
    C2, for SAME_AS_C2). A configuration that did not run makes it unknown;
    one that exited non-zero fails it."""
    states = (c2[0], stock[0], c1[0])
    if "not run" in states:
        return "unknown (not run)"
    if any(x.startswith("exit") for x in states):
        return "fail"
    if c2 != stock:
        return "fail (changed by (B'))"
    return "pass" if (c1 == c2 if want1 == SAME_AS_C2 else c1[0] == want1) else "fail"


def control_verdict(states, want):
    """A control's result: `killed` when every named row reads exactly the
    state named for it, else `fail` (D6's N13 on #715): `exit N`, `not run`
    and any other reading are never a kill."""
    return "killed" if all(states.get(r) == w for r, w in want.items()) else "fail"


def quote(out, case):
    """Every row each configuration logged on one case, for the experiment:
    the exit code, conn.log, analyzer.log (every row, no filter on the
    analyzer's name), weird.log, reporter.log, and the probe's DNP3 rows."""
    for cfg in (C0, C1P, C2):
        d = os.path.join(out, case, cfg)
        print(f"\n#### {case} under {cfg}\n")
        print(f"- exit code: {exit_code(d)}")
        for log in ("conn", "analyzer", "otsec_viol", "weird", "reporter"):
            rs = rows(os.path.join(d, log + ".log"))
            print(f"- {log}.log: " + ("no file" if rs is None else f"{len(rs)} row(s)"))
            for r in rs or []:
                print("  - `" + json.dumps(r, sort_keys=True) + "`")
        s = seen(d)
        print("- probe: " + ("no file" if s is None else f"headers {s[0]}; link rows {s[1]}"))


def check(out):
    bad, failed = 0, []
    print("| case | kind | expectation | C2 | C1p | result |")
    print("| --- | --- | --- | --- | --- | --- |")
    for case, kind, what, test in EXPECT:
        c2, c1 = (state(os.path.join(out, case, cfg), test) for cfg in (C2, C1P))
        res = verdict(kind, c2, c1)
        ok = res == "pass"
        bad |= not ok
        print(f"| {case} | {kind} | {what} | {c2} | {c1} | {res} |")
        if not ok:
            failed.append(case)
    # What each build logged on a case with a row that did not pass: codes,
    # sides, object headers, DIR and analyzer.log's failure_reason only (no
    # payload; failure_data is never read).
    for case in dict.fromkeys(failed):
        for cfg in (C2, C1P):
            d = os.path.join(out, case, cfg)
            s = seen(d)
            w = [r.get("name") for r in rows(os.path.join(d, "weird.log")) or []]
            print(f"\n{case} under {cfg}: exit code {exit_code(d)}; " + (
                  "not run" if s is None else f"headers {s[0]}; link rows {s[1]}; DNP3 violations {s[2]}; weirds {w}"))
    flows = cases()
    print("\n### (B'): the three-state judge (D1's ruling on #715, conditions 2 to 4)\n")
    print("| row | case | kind | expectation | C2 | C1p | C0 (quoted) | result |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- |")
    details = []
    for rid, case, kind, what, want2, want1, same in STOPS:
        cfgs = (C2, C1P, C0, M_STOCK) if kind == "unchanged" else (C2, C1P, C0)
        st = {cfg: judge(os.path.join(out, case, cfg), flows[case]) for cfg in cfgs}
        if kind == "unchanged":
            res = unchanged_verdict(st[C2], st[M_STOCK], st[C1P], want1)
        else:
            same_ok = not same or (reasons_of(os.path.join(out, case, C2)) == reasons_of(os.path.join(out, case, C1P))
                                   and len(reasons_of(os.path.join(out, case, C2))) == 1)
            res = stop_verdict(want2, want1, st[C2][0], st[C1P][0], same_ok)
        bad |= res != "pass"
        print(f"| {rid} | {case} | {kind} | {what} (C2: {want2}; C1p: {want1}) | {st[C2][0]} | {st[C1P][0]} | "
              f"{st[C0][0]} | {res} |")
        details += [f"- {rid} {case} under {cfg}: {st[cfg][0]}; {st[cfg][1]}" for cfg in cfgs]
    print("\n| control | what it changes | the state each row must read | its states there | result |")
    print("| --- | --- | --- | --- | --- |")
    for cfg, rids, what in CONTROLS:
        st = {}
        for rid, case, *_ in STOPS:
            if rid in rids:
                st[rid], det = judge(os.path.join(out, case, cfg), flows[case])
                details.append(f"- {rid} {case} under {cfg}: {st[rid]}; {det}")
        res = control_verdict(st, rids)
        bad |= res != "killed"
        print(f"| {cfg} | {what} | {'; '.join(f'{r}: {w}' for r, w in rids.items())} | {'; '.join(f'{r}: {st[r]}' for r in rids)} | {res} |")
    print("\nWhat the judge read (failure_data is never read):\n")
    print("\n".join(details))
    print("\n### D1's experiment on #715: measured, not judged")
    for case in EXPERIMENT:
        quote(out, case)
    unrun = quote_gt(out)
    return 1 if bad or unrun else 0


C1 = "zeek-probe"
GT_CFGS = (C0, C1, C1P, C2)


def gt_not_run(out):
    """The configurations of GT_CFGS that left no exit code on GT_CASE, or a
    non-zero one: a measurement that did not happen, or a crash, fails
    `check`, never reads as quiet."""
    return [cfg for cfg in GT_CFGS if exit_code(os.path.join(out, GT_CASE, cfg)) != "0"]


def quote_gt(out):
    """GT_CASE under C0, C1, C1p and C2: only whether each configuration ran
    and its exit code. No row of any log is printed. Returns gt_not_run(out)."""
    print(f"\n### {GT_CASE} (#718's capture, hr23_cases.py, equal to its pin): ran or not\n")
    for cfg in GT_CFGS:
        code = exit_code(os.path.join(out, GT_CASE, cfg))
        print(f"- {cfg}: " + ("not run" if code is None else f"ran, exit code {code}"))
    unrun = gt_not_run(out)
    if unrun:
        print(f"\n**Not run, or a non-zero exit, under {', '.join(unrun)}: `check` fails.**")
    return unrun


if __name__ == "__main__":
    if sys.argv[1] == "write":
        write(sys.argv[2])
    elif sys.argv[1] == "check":
        sys.exit(check(sys.argv[2]))
    else:
        sys.exit("usage: dispatch_unit.py write|check OUT")

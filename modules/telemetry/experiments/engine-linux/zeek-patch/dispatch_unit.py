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

D1's experiment on #715 (6902545944): the `*-first` cases, over UDP and
TCP, also run under C0 (`zeek-probe-c0`, the stock image), and `check`
quotes, for each configuration, the exit code, conn.log's rows, every
analyzer.log row with no filter on the analyzer's name, and weird.log's and
reporter.log's rows. The inputs are D4's own synthetic bytes.

Usage: python -I dispatch_unit.py write OUT
       python -I dispatch_unit.py check OUT
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "..", "tests", "integration", "gt_pcap"))
import dnp3  # noqa: E402
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
    client, from port CLIENT_PORT to the other end's 20000, after a full
    handshake, and each frame is one segment, acknowledged."""

    def __init__(self, first, tcp=False):
        self.clock = synth.Clock()
        a, b = (RELAY, MASTER) if first == "relay" else (MASTER, RELAY)
        if tcp:
            a = synth.Host(a.mac, a.ip, CLIENT_PORT)
            self.conv = synth.TCPConv(a, b, self.clock)
            self.conv.handshake()
        else:
            self.conv = synth.UDPConv(a, b, self.clock)
        self.relay_first = first == "relay"
        self.tseq = {True: 0, False: 0}

    def send(self, from_master, apdu, dir_set=None):
        seg = dnp3.tpdu(self.tseq[from_master], apdu)
        self.tseq[from_master] = (self.tseq[from_master] + 1) & 0x3F
        dest, src = (R_LINK, M_LINK) if from_master else (M_LINK, R_LINK)
        frame = link(dest, src, from_master if dir_set is None else dir_set, seg)
        self.conv.send(from_master != self.relay_first, frame)


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
    # D1's experiment (6902545944): two inputs as a flow's first datagram,
    # each followed by whole messages from both ends, over UDP and over TCP.
    # D3's stock control: a READ whose object header is cut after its group
    # octet (3 application octets), which the request parser rejects under
    # every build. D2's case: a 2-octet 129 from the originator.
    for tcp, sfx in ((False, ""), (True, "-tcp")):
        f = Flow("master", tcp)
        f.send(True, bytes([0xC0, dnp3.READ, 60]))
        f.send(False, dnp3.response(0))
        f.send(True, dnp3.request(1, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(1))
        out["d4u-short-request-first" + sfx] = f
        f = Flow("relay", tcp)
        f.send(False, bytes([0xC0, dnp3.RESPONSE]))
        f.send(True, dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1)))
        f.send(False, dnp3.response(0))
        out["d4u-short-response-first" + sfx] = f
    # A master's direct operate with a control block and DIR clear, on a
    # flow the master starts: the code picks the request parser, so the
    # block is parsed under both builds (a selector keyed by DIR would not).
    f = Flow("master")
    f.send(True, dnp3.request(0, dnp3.DIRECT_OPERATE, dnp3.crob(7)), dir_set=False)
    f.send(False, dnp3.response(0, objects=dnp3.crob(7)))
    out["d4u-dir-clear-operate"] = f
    return out


def write(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, f in cases().items():
        pcapfile.write(os.path.join(outdir, name + ".pcap"), f.conv.frames)


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
    ("d4u-short-response-orig", "fix-negative", "a 2-octet 129 from the originator, after a whole one, throws in "
     "the response parser, and the read after it is not seen",
     lambda m, l, v: bool(v) and (False, 1, "req", ("g60v1",)) not in m),
    ("d4u-dir-clear-operate", "same", "the direct operate's g12v1 is parsed although DIR is clear",
     lambda m, l, v: (True, 5, "req", ("g12v1",)) in m and (True, False) in l),
]

# D1's experiment (6902545944): measured, not judged. `check` quotes what
# each of C0, C1p and C2 logged on them.
EXPERIMENT = ["d4u-short-request-first", "d4u-short-response-first",
              "d4u-short-request-first-tcp", "d4u-short-response-first-tcp"]


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


def quote(out, case):
    """Every row each configuration logged on one case, for the experiment:
    the exit code, conn.log, analyzer.log (every row, no filter on the
    analyzer's name), weird.log, reporter.log, and the probe's DNP3 rows."""
    for cfg in (C0, C1P, C2):
        d = os.path.join(out, case, cfg)
        print(f"\n#### {case} under {cfg}\n")
        print(f"- exit code: {exit_code(d)}")
        for log in ("conn", "analyzer", "weird", "reporter"):
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
        bad |= res != "pass"
        print(f"| {case} | {kind} | {what} | {c2} | {c1} | {res} |")
        if res != "pass":
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
    print("\n### D1's experiment on #715: measured, not judged")
    for case in EXPERIMENT:
        quote(out, case)
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1] == "write":
        write(sys.argv[2])
    elif sys.argv[1] == "check":
        sys.exit(check(sys.argv[2]))
    else:
        sys.exit("usage: dispatch_unit.py write|check OUT")

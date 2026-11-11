"""GT-PCAP's DNP3 captures: the R6.3 cases, the SA cases and the R6.2 series (D6).

Every capture here is synthesized by synth.py and dnp3.py on one simulated
network (NET below), so the baseline learned from the training series is the
baseline every case is judged against (plan sections 3 and 4). Each case
lists every rule D4's note expects to fire on it (plan section 4); an empty
list is a near-miss, which must raise nothing.

The rules and their pairs are D4's (docs/phase4/D4-network-baseline.md
section 4). What a frame carries is what tshark reads from it (gtlabel.py),
and the self-tests check that tshark reads each case as written here.

Usage: python dnp3_cases.py OUTDIR   (writes every .pcap and cases.json)
"""

import json
import os
import random
import sys

import dnp3
import pcapfile
import synth

# The simulated network. Addresses are TEST-NET-1; MACs locally
# administered; asset IDs are fixed UUIDs made for GT-PCAP. C1 has no DNP3
# transport, so each enrolled host resolves through one direct endpoint on
# its IP that C1 does have (c1_endpoint, D1 on #548): Telnet 23 for O1, SSH
# 22 for M1 to M3 and M5. No capture here holds a session on those endpoints.
# M4 is enrolled nowhere.
#
# A relay has one DNP3 port, for TCP and UDP alike, and a transport for each
# master's session (DNPNUM, 1 to 65534, default 20000; DNPTRn, UDP or TCP;
# S22 Table D.7, p. D.11). So the moved port is a second relay, O2, and DNP3
# over UDP is a fifth master's session on O1's own port. Neither is in the
# R6.2 series, so the baseline has never seen them.
NET = {
    "outstation": {"name": "O1", "ip": "192.0.2.20", "mac": "02:00:00:00:00:20", "port": 20000, "link": 10,
                   "asset": "6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a20",
                   "c1_endpoint": {"transport": "telnet", "port": 23, "path": "direct"}},
    "masters": {
        # Authorized to write and control O1 (the authorized_writers input).
        "M1": {"ip": "192.0.2.10", "mac": "02:00:00:00:00:10", "link": 1,
               "asset": "6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a10",
               "c1_endpoint": {"transport": "ssh", "port": 22, "path": "direct"}, "writes": ["write", "control"]},
        # A reading master that never does the reconnect sequence or a time sync.
        "M2": {"ip": "192.0.2.11", "mac": "02:00:00:00:00:11", "link": 2,
               "asset": "6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a11",
               "c1_endpoint": {"transport": "ssh", "port": 22, "path": "direct"}, "writes": []},
        # A reading master that does the reconnect sequence in learning.
        "M3": {"ip": "192.0.2.12", "mac": "02:00:00:00:00:12", "link": 3,
               "asset": "6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a12",
               "c1_endpoint": {"transport": "ssh", "port": 22, "path": "direct"}, "writes": []},
        # Not enrolled and never seen in learning: the new master.
        "M4": {"ip": "192.0.2.13", "mac": "02:00:00:00:00:13", "link": 4, "asset": None, "writes": []},
        # O1's UDP session (DNPTRn := UDP), authorized to control it. With
        # DNPUDPn at its default the relay answers to UDP 20000, so this
        # master sends from 20000 too.
        "M5": {"ip": "192.0.2.14", "mac": "02:00:00:00:00:14", "link": 5,
               "asset": "6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a14",
               "c1_endpoint": {"transport": "ssh", "port": 22, "path": "direct"}, "writes": ["control"]},
    },
    # Outstations beside O1. O2's DNPNUM is moved off the default; M1 is its
    # master, authorized to control it.
    "outstations": {
        "O2": {"name": "O2", "ip": "192.0.2.21", "mac": "02:00:00:00:00:21", "port": 20001, "link": 11,
               "asset": "6a1f3c2e-0d4b-4e8a-9c71-2b5d8e0f1a21",
               "c1_endpoint": {"transport": "telnet", "port": 23, "path": "direct"}},
    },
    "authorized_writers": [["M1", "O1", "write"], ["M1", "O1", "control"],
                           ["M1", "O2", "control"], ["M5", "O1", "control"]],
    "sa_reply_timeout_ms": 5000,
}

INTEGRITY = (dnp3.all_objects(60, 2) + dnp3.all_objects(60, 3) + dnp3.all_objects(60, 4)
             + dnp3.all_objects(60, 1))
TIME_MS = 1_762_545_600_000  # 2025-11-07T20:00:00Z, the series' wall clock in milliseconds


class Session:
    """One master's TCP connection to an outstation (O1 unless named), or
    its UDP conversation with it, with DNP3 helpers. Over UDP each datagram
    holds one link frame, and nothing below DNP3 is acknowledged."""

    def __init__(self, master, clock, sport, isn=1000, outstation="O1", l4="tcp"):
        m = NET["masters"][master]
        o = NET["outstation"] if outstation == "O1" else NET["outstations"][outstation]
        self.m, self.o = m, o
        ends = synth.Host(m["mac"], m["ip"], sport), synth.Host(o["mac"], o["ip"], o["port"])
        self.conv = (synth.UDPConv(*ends, clock, ident=isn) if l4 == "udp" else
                     synth.TCPConv(*ends, clock, isn_c=isn, isn_s=isn + 50_000, ident=isn))
        self.tseq = {True: 0, False: 0}
        self.app = 0

    def _link(self, from_master, apdu):
        src, dst = (self.m["link"], self.o["link"]) if from_master else (self.o["link"], self.m["link"])
        seg = dnp3.tpdu(self.tseq[from_master], apdu)
        self.tseq[from_master] = (self.tseq[from_master] + 1) & 0x3F
        return dnp3.link(dst, src, from_master, seg)

    def request(self, fc, objects=b"", seq=None, gap_ns=None):
        """Send a request; returns its frame. seq defaults to the next one."""
        if seq is None:
            seq, self.app = self.app, (self.app + 1) & 0x0F
        return self.conv.send(True, self._link(True, dnp3.request(seq, fc, objects)), gap_ns=gap_ns)[0], seq

    def reply(self, seq, fc=dnp3.RESPONSE, objects=b"", gap_ns=None):
        return self.conv.send(False, self._link(False, dnp3.response(seq, fc, 0, objects)), gap_ns=gap_ns)[0]

    def auth(self, seq, fc, objects):
        """A master's function 32 or 33 carrying group 120 objects, in the
        pending exchange's sequence number."""
        return self.conv.send(True, self._link(True, dnp3.request(seq, fc, objects)))[0]

    def poll(self, response_objects=b""):
        _, seq = self.request(dnp3.READ, INTEGRITY)
        self.reply(seq, objects=response_objects)

    def reconnect(self):
        """The reconnect sequence (D4's note section 4): clear IIN1.7 with
        g80v1, enable unsolicited reporting, assign classes. Returns the
        three request frames."""
        reqs = []
        for fc, objs in ((dnp3.WRITE, dnp3.iin_clear_restart()),
                         (dnp3.ENABLE_UNSOL, dnp3.all_objects(60, 2) + dnp3.all_objects(60, 3) + dnp3.all_objects(60, 4)),
                         (dnp3.ASSIGN_CLASS, dnp3.all_objects(60, 2) + dnp3.all_objects(1, 0))):
            fr, seq = self.request(fc, objs)
            reqs.append(fr)
            self.reply(seq)
        return reqs


def _case(clock, master, sport, body, outstation="O1", l4="tcp"):
    s = Session(master, clock, sport, outstation=outstation, l4=l4)
    if l4 == "tcp":
        s.conv.handshake()
    marks = body(s) or {}
    if l4 == "tcp":
        s.conv.close()
    return s.conv.frames, marks


def _frame_no(frames, fr):
    return next(i for i, f in enumerate(frames, 1) if f is fr)


def cases():
    """Each case: (name, frames, rows), where each row names the frames that
    make the sample (1-based, request first, then the frames that decided
    sa), the rules expected, and the context it is judged in."""
    out = []
    t0 = 1_762_560_000_000_000_000  # after both series

    def add(name, master, sport, body, rows, **where):
        clock = synth.Clock(start_ns=t0 + len(out) * 60_000_000_000)
        frames, marks = _case(clock, master, sport, body, **where)
        resolved = []
        for r in rows:
            r = dict(r)
            r["frames"] = [_frame_no(frames, marks[k]) for k in r.pop("marks")]
            resolved.append(r)
        out.append((name, frames, resolved))

    def sa_segment(s):
        marks = {}
        # Reads only: not challenged, so sa none, class read, no dnp3_no_sa.
        marks["read"], seq = s.request(dnp3.READ, INTEGRITY)
        s.reply(seq)
        # A challenged direct operate; the function 32 reply shares the
        # request's sequence number (D1, 2026-11-07).
        marks["op"], seq = s.request(dnp3.DIRECT_OPERATE, dnp3.crob(3))
        marks["chal"] = s.reply(seq, dnp3.AUTH_RESPONSE, dnp3.g120v1_challenge())
        marks["rep"] = s.auth(seq, dnp3.AUTH_REQ, dnp3.g120v2_reply())
        marks["resp"] = s.reply(seq, objects=dnp3.crob(3))
        # Aggressive mode: g120v3 and g120v9 in the request, no challenge.
        marks["aggr"], seq = s.request(dnp3.DIRECT_OPERATE, dnp3.g120v3_aggressive() + dnp3.crob(4) + dnp3.g120v9_hmac())
        marks["aggr_resp"] = s.reply(seq, objects=dnp3.crob(4))
        return marks

    add("dnp3-sa", "M1", 41001, sa_segment, [
        {"marks": ["read"], "rules": [], "context": "acknowledged", "sa": "none",
         "note": "reads only: sa none, class read, no dnp3_no_sa, no alert"},
        {"marks": ["op", "chal", "rep", "resp"], "rules": [], "context": "acknowledged", "sa": "challenged",
         "note": "challenged operate; the function 32 reply shares the sequence number; dnp3_seq_reused 0"},
        {"marks": ["aggr", "aggr_resp"], "rules": [], "context": "acknowledged", "sa": "aggressive",
         "note": "aggressive-mode operate (g120v3 with g120v9): no dnp3_no_sa, no alert"},
    ])

    def failed_outstation(s):
        m = {}
        m["op"], seq = s.request(dnp3.DIRECT_OPERATE, dnp3.crob(3))
        m["chal"] = s.reply(seq, dnp3.AUTH_RESPONSE, dnp3.g120v1_challenge())
        m["rep"] = s.auth(seq, dnp3.AUTH_REQ, dnp3.g120v2_reply())
        m["err"] = s.reply(seq, dnp3.AUTH_RESPONSE, dnp3.g120v7_error())
        return m

    failed_rows = lambda rules, ctx, note: [{"marks": ["op", "chal", "rep", "err"], "rules": rules, "context": ctx,
                                            "sa": "failed", "sa_error_from": "outstation", "note": note}]
    add("dnp3-sa-failed-outstation", "M1", 41002, failed_outstation,
        failed_rows(["sa-failed"], "acknowledged", "g120v7 in function 131 from the outstation; authorized master"))
    add("dnp3-sa-failed-before-ack", "M1", 41003, failed_outstation,
        failed_rows(["sa-failed"], "before-acknowledgement",
                    "replayed on a node whose network database starts empty, with no learner and no acknowledged "
                    "baseline: sa-failed and nothing else (D1, D4-68; D1 on #548)"))
    add("dnp3-sa-failed-unauthorized", "M2", 41004, failed_outstation,
        failed_rows(["sa-failed", "unauthorized-write"], "acknowledged", "the same failure from a read-only master"))

    def failed_master(s):
        m = {}
        m["op"], seq = s.request(dnp3.DIRECT_OPERATE, dnp3.crob(3))
        m["chal"] = s.reply(seq, dnp3.AUTH_RESPONSE, dnp3.g120v1_challenge())
        m["err"] = s.auth(seq, dnp3.AUTH_REQ_NO_ACK, dnp3.g120v7_error())
        return m

    add("dnp3-sa-failed-master", "M1", 41005, failed_master, [
        {"marks": ["op", "chal", "err"], "rules": ["sa-failed"], "context": "acknowledged", "sa": "failed",
         "sa_error_from": "master", "note": "g120v7 in function 33 from the master; dnp3_seq_reused 0"}])

    def operate(s):
        m = {}
        m["op"], seq = s.request(dnp3.DIRECT_OPERATE, dnp3.crob(3))
        m["resp"] = s.reply(seq, objects=dnp3.crob(3))
        return m

    add("dnp3-unauthorized-operate", "M2", 41006, operate, [
        {"marks": ["op", "resp"], "rules": ["unauthorized-write"], "context": "acknowledged", "sa": "none",
         "note": "direct operate from a read-only master; dnp3_no_sa"}])
    add("dnp3-authorized-operate", "M1", 41007, operate, [
        {"marks": ["op", "resp"], "rules": [], "context": "acknowledged", "sa": "none",
         "note": "the same operate from the authorized master; dnp3_no_sa, no alert"}])

    def one(fc, objects):
        def body(s):
            m = {}
            m["req"], seq = s.request(fc, objects)
            m["resp"] = s.reply(seq)
            return m
        return body

    add("dnp3-authorized-time-sync", "M1", 41008, one(dnp3.WRITE, dnp3.time_sync(TIME_MS)), [
        {"marks": ["req", "resp"], "rules": [], "context": "acknowledged", "sa": "none",
         "note": "time-sync from a pair that time-synced in learning (class time-sync, not write)"}])
    add("dnp3-reader-time-sync", "M2", 41009, one(dnp3.WRITE, dnp3.time_sync(TIME_MS)), [
        {"marks": ["req", "resp"], "rules": ["new-function"], "context": "acknowledged", "sa": "none",
         "note": "a pair that only read starts a time-sync"}])
    add("dnp3-reader-disable-unsolicited", "M2", 41010, one(dnp3.DISABLE_UNSOL, dnp3.all_objects(60, 2)), [
        {"marks": ["req", "resp"], "rules": ["new-function"], "context": "acknowledged", "sa": "none",
         "note": "function 21 from a pair that never did the reconnect sequence (session-setup)"}])

    def reconnect(s):
        return dict(zip(("g80", "enable", "assign"), s.reconnect()))

    add("dnp3-reconnect-learned", "M3", 41011, reconnect, [
        {"marks": ["g80", "enable", "assign"], "rules": [], "context": "acknowledged", "sa": "none",
         "note": "the reconnect sequence from a reading master that did it in learning (session-setup)"}])
    add("dnp3-reconnect-unlearned", "M2", 41012, reconnect, [
        {"marks": ["g80", "enable", "assign"], "rules": ["new-function"], "context": "acknowledged", "sa": "none",
         "note": "the same sequence from a reading master that never did it"}])

    def response_new_group(s):
        m = {}
        m["req"], seq = s.request(dnp3.READ, INTEGRITY)
        m["resp"] = s.reply(seq, objects=dnp3.count8(30, 1, b"\x01" + b"\x10\x00\x00\x00"))
        return m

    add("dnp3-response-new-group", "M1", 41013, response_new_group, [
        {"marks": ["req", "resp"], "rules": [], "context": "acknowledged", "sa": "none",
         "note": "the outstation's response carries g30v1, never seen in learning; a response is not a function"}])

    def poll(s):
        m = {}
        m["req"], seq = s.request(dnp3.READ, INTEGRITY)
        m["resp"] = s.reply(seq)
        return m

    add("dnp3-new-master", "M4", 41014, poll, [
        {"marks": ["req", "resp"], "rules": ["unknown-pair", "unresolved-address"], "context": "acknowledged",
         "sa": "none", "note": "a new master, enrolled nowhere, polls the outstation"}])
    add("dnp3-known-master-new-port", "M2", 52999, poll, [
        {"marks": ["req", "resp"], "rules": [], "context": "acknowledged", "sa": "none",
         "note": "the known master on a new TCP source port"}])

    def reused_seq(s):
        m = {}
        m["first"], seq = s.request(dnp3.DIRECT_OPERATE, dnp3.crob(3))
        m["second"], _ = s.request(dnp3.DIRECT_OPERATE, dnp3.crob(3), seq=seq, gap_ns=1_000_000_000)
        m["resp"] = s.reply(seq, objects=dnp3.crob(3))
        return m

    add("dnp3-reused-seq", "M1", 41015, reused_seq, [
        {"marks": ["first"], "rules": [], "context": "acknowledged", "sa": "",
         "note": "unanswered; completed early by the reuse, sa absent, no dnp3_no_sa"},
        {"marks": ["second", "resp"], "rules": [], "context": "acknowledged", "sa": "none",
         "note": "the reuse pairs with the response; dnp3_seq_reused exactly 1 for this capture"}])

    # Plan section 2B (P4-4-R1): DNP3 on a port where a port-only decoder
    # does not look for it, and DNP3 over UDP. Each is a poll, then a direct
    # operate with no SA from the authorized master. The baseline has seen
    # neither service nor pair, so each is a new-service sample as well.
    def poll_then_operate(s):
        m = {}
        m["req"], seq = s.request(dnp3.READ, INTEGRITY)
        m["resp"] = s.reply(seq)
        m["op"], seq = s.request(dnp3.DIRECT_OPERATE, dnp3.crob(3))
        m["op_resp"] = s.reply(seq, objects=dnp3.crob(3))
        return m

    def decode_rows(what):
        return [
            {"marks": ["req", "resp"], "rules": ["new-service", "unknown-pair"], "context": "acknowledged",
             "sa": "none", "note": what + ": a service and a pair the baseline never saw, one alert from each "
                                         "rule for the flow"},
            {"marks": ["op", "op_resp"], "rules": [], "context": "acknowledged", "sa": "none",
             "note": "the authorized master's operate on the same flow; dnp3_no_sa, and no alert beyond the "
                     "flow's two"}]

    add("dnp3-moved-port", "M1", 41016, poll_then_operate,
        decode_rows("DNP3 on TCP %d, the port O2's DNPNUM is set to" % NET["outstations"]["O2"]["port"]),
        outstation="O2")
    add("dnp3-udp", "M5", NET["outstation"]["port"], poll_then_operate,
        decode_rows("DNP3 over UDP 20000 on O1, both ends on 20000 (DNPUDPn at its default)"), l4="udp")

    # Derived (plan section 2C): the unauthorized operate with its response,
    # and that response's bare ACK, removed (D3 on #536), and the later
    # frames renumbered so the request is unanswered, not a capture gap
    # (D1 on #548).
    name, frames, rows = next(c for c in out if c[0] == "dnp3-unauthorized-operate")
    resp = rows[0]["frames"][1]
    keep = synth.remove_segments(frames, {resp, resp + 1})
    out.append(("dnp3-unauthorized-operate-no-response", keep, [
        {"frames": [rows[0]["frames"][0]], "rules": ["unauthorized-write"], "context": "acknowledged", "sa": "",
         "note": "derived from dnp3-unauthorized-operate, frames %d and %d removed and later frames renumbered; "
                 "emitted at sa_reply_timeout_ms with sa absent; latency includes that wait" % (resp, resp + 1)}]))
    return out


def series(seed, start_ns, duration_s):
    """One R6.2 benign series: M1, M2 and M3 each hold one connection to O1.
    M1 and M3 do the reconnect sequence once at the start; every master polls
    on its own period with seeded jitter; M1 time-syncs every 300 s and
    sends one authorized operate every 600 s. The seed varies only the
    jitter, the order of the masters' starts and the source ports."""
    rnd = random.Random(seed)
    clock = synth.Clock(start_ns=start_ns)
    sess = {m: Session(m, clock, rnd.randrange(49152, 65535), isn=rnd.randrange(1, 1 << 30))
            for m in ("M1", "M2", "M3")}
    events = []
    for m, period in (("M1", 10), ("M2", 15), ("M3", 20)):
        t = rnd.uniform(0, 2)
        events.append((t, m, "open"))
        if m in ("M1", "M3"):
            events.append((t + 0.5, m, "reconnect"))
        t += 1
        while t < duration_s:
            events.append((t, m, "poll"))
            t += period + rnd.uniform(-0.5, 0.5)
    for k in range(1, int(duration_s // 300)):
        events.append((k * 300 + rnd.uniform(0, 1), "M1", "time-sync"))
    for k in range(1, int(duration_s // 600)):
        events.append((k * 600 + 150 + rnd.uniform(0, 1), "M1", "operate"))
    events.sort(key=lambda e: e[0])
    for t, m, what in events:
        clock.ns = max(clock.ns, start_ns + int(t * 1e9))
        s = sess[m]
        if what == "open":
            s.conv.handshake()
        elif what == "reconnect":
            s.reconnect()
        elif what == "poll":
            s.poll()
        elif what == "time-sync":
            _, seq = s.request(dnp3.WRITE, dnp3.time_sync(TIME_MS + int(t * 1000)))
            s.reply(seq)
        elif what == "operate":
            _, seq = s.request(dnp3.DIRECT_OPERATE, dnp3.crob(3))
            s.reply(seq, objects=dnp3.crob(3))
    for s in sess.values():
        s.conv.close()
    return sorted((f for s in sess.values() for f in s.conv.frames), key=lambda f: f.ns)


# What the labeller is told about a capture that is not DNP3 on TCP 20000:
# the transport, and the outstation's port as its settings give it (plan
# section 2B: labelled from the asset table's settings, not from the port).
DECODE = {
    "dnp3-moved-port": {"l4": "tcp", "port": NET["outstations"]["O2"]["port"]},
    "dnp3-udp": {"l4": "udp", "port": NET["outstation"]["port"]},
}

SERIES = {
    # (seed, start, seconds). The held-out series is recorded after the
    # training series, and is as long (plan section 3).
    "dnp3-train": (1, 1_762_545_600_000_000_000, 3600),
    "dnp3-heldout": (2, 1_762_552_800_000_000_000, 3600),
}


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    meta = {"net": NET, "decode": DECODE, "series": {}, "cases": {}}
    for name, (seed, start, secs) in SERIES.items():
        pcapfile.write(os.path.join(outdir, name + ".pcap"), series(seed, start, secs))
        meta["series"][name] = {"seed": seed, "start_ns": start, "seconds": secs}
    for name, frames, rows in cases():
        pcapfile.write(os.path.join(outdir, name + ".pcap"), frames)
        meta["cases"][name] = rows
    with open(os.path.join(outdir, "dnp3-cases.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

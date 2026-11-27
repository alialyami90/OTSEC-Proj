"""Tests of hr25_unit.py (HR25-B1 and HR25-B2), and a desk check of its
expectations.

`Model` is a reference of the rules of docs/phase4/D4-hr25-design.md
sections 2.1 to 2.4, 2.7, 2.8 and 2.9 item 5, written from the design, with
one switch per mutant control of controls/hr25-*.patch and
controls/script-*.patch. It is not the patch or the script:
it shows that each input's expectation follows from the design's rules,
and that each control a row names breaks that expectation, before any
build runs (evidence class `desk`). Whether the patch does what the model
does is what the inputs test, once a run that D1 rules reads them.

Run: python -m pytest -q modules/telemetry/experiments/engine-linux/zeek-patch/test_hr25_unit.py
"""
import functools
import json
import os
import re

import pytest

import hr25_unit as u

HERE = os.path.dirname(os.path.abspath(__file__))


def crc_ok(b, at, n):
    return u.dnp3.crc(b[at:at + n]) == b[at + n:at + n + 2]


def header_cause(h, mutant=None):
    if h[0] != 0x05 or h[1] != 0x64:
        return "magic"
    if not crc_ok(h, 0, 8):
        return "header_crc"
    if h[2] < (6 if mutant == "link-length-lt6" else 5):
        return "link_length"
    return None


# DNP3::max_application_layer_fragment_size, Zeek 9.0.1's default (100 *
# 1024, init-bare.zeek), which neither the probe nor resync-unit.zeek
# redefines.
LIMIT = 100 * 1024


def frame_len(length):
    n = length - 5
    return 10 + n + 2 * ((n + 15) // 16)


class End:
    def __init__(self):
        self.buf = b""
        self.scanning = False
        self.counts = {}
        self.scanned = 0
        self.fcm_run = False
        self.mark = None
        self.first_ts = None
        self.interval_n = 0
        self.row = None
        self.clear()

    def clear(self):
        self.open = False
        self.app = b""
        self.tseq = None
        self.last = None
        self.after_fin = False
        self.fcb = None


# The six counts on which a flow that never confirms writes its end row
# (design 2.7), and invariant (design 2.9).
SIX = ("app_parse", "fragment_limit", "embedded_header", "first_chunk_missing", "transport_seq", "gap", "invariant")
WEIRD = dict(zip(u.CAUSES, (
    "dnp3_header_lacks_magic", "dnp3_corrupt_header_checksum", "dnp3_invalid_link_length",
    "dnp3_corrupt_app_chunk_checksum", "dnp3_embedded_header", "dnp3_first_application_layer_chunk_missing",
    "dnp3_fragment_restarted", "dnp3_transport_sequence", "dnp3_max_application_layer_fragment_size_exceeded",
    "dnp3_app_parse_failed", "dnp3_content_gap", "dnp3_truncated_frame", "dnp3_resync_budget_exhausted",
    "dnp3_invariant")))
F, O, INTERVAL_US = 8, 2048, 60_000_000
DPD_IGNORE_AFTER = 10 * 1024  # dpd.zeek's DPD::ignore_violations_after


class Model:
    """The rules as the design states them, on one flow's deliveries:
    sections 2.1 to 2.4 and 2.9 item 5 (HR25-B1), and 2.7 and 2.8 (HR25-B2).
    `rows` are (end, why, delivery index or "end", counts, scanned octets);
    `weirds` each weird raised, in order; `fc` (is_orig, code, cause)."""

    def __init__(self, tcp, mutant=None):
        self.tcp, self.mut = tcp, mutant
        self.ends = {True: End(), False: End()}
        self.fc = []
        self.skip = False
        self.confirmed = False
        self.fails = {True: 0, False: 0}
        self.octets = {True: 0, False: 0}
        self.exhausted = False
        self.rows = []
        self.weirds = []
        self.viol = 0
        self.pending = {}  # the script's pending cause, per end
        self.size = 0
        self.at = None
        self.now = 0

    # Counting, the budget and the rows (design 2.7, 2.8).
    def count(self, orig, cause):
        e = self.ends[orig]
        e.counts[cause] = e.counts.get(cause, 0) + 1
        if cause != "first_chunk_missing" and self.mut != "fcm-run-unbroken":
            e.fcm_run = False
        loud = self.confirmed or cause == "invariant" or self.mut == "weirds-before-confirm"
        if cause == "budget":
            loud = self.mut != "budget-weird-gated" or self.confirmed
        if loud:
            self.weirds.append(WEIRD[cause])

    def charge(self, orig, fails, octets):
        if self.confirmed or self.exhausted:
            return
        if self.mut == "budget-orig-only" and not orig:
            return
        k = True
        self.fails[k] += fails
        self.octets[k] += octets
        f_lim = 7 if self.mut == "budget-f-7" else F
        o_lim = 2047 if self.mut == "budget-o-2047" else O
        f_out = self.fails[k] > f_lim if self.mut == "budget-f-gt" else self.fails[k] >= f_lim
        o_out = self.octets[k] > o_lim if self.mut == "budget-o-gt" else self.octets[k] >= o_lim
        if not (f_out or o_out):
            return
        self.exhausted = True
        self.count(orig, "budget")
        self.raise_row(orig, "budget")
        if self.mut != "budget-no-violation":
            self.viol += 1
        if self.mut == "budget-no-skip":
            # dpd.zeek removes the analyzer on a violation unless the flow
            # has carried more than 10 KiB.
            self.skip = self.size <= DPD_IGNORE_AFTER
        elif self.mut == "budget-at-delivery-end":
            self.skip_after = True
        else:
            self.skip = True

    def raise_row(self, orig, why):
        e = self.ends[orig]
        if why == "first":
            e.first_ts, e.interval_n = self.now, 0
        e.row = (dict(e.counts), e.scanned)
        self.rows.append(("m" if orig else "o", why, self.at if why != "end" else "end", dict(e.counts), e.scanned))

    def confirm(self, orig):
        self.confirmed = True
        for o in (True, False):
            if self.ends[o].counts and self.mut != "no-first-at-confirm":
                self.raise_row(o, "first")

    def after_delivery(self, orig):
        e = self.ends[orig]
        if not self.confirmed:
            return
        if e.first_ts is None:
            if e.counts:
                self.raise_row(orig, "first")
            return
        since = self.now - e.first_ts
        n = (since - 1 if self.mut == "interval-strict" else since) // INTERVAL_US
        if n < e.interval_n or (n == e.interval_n and self.mut != "interval-twice"):
            return
        changed = (dict(e.counts), e.scanned) != e.row
        if self.mut == "interval-any-delivery" and not changed:
            return
        e.interval_n = n
        if changed or self.mut == "interval-no-change-check":
            self.raise_row(orig, "interval")

    def finish(self):
        self.at = "end"
        for orig in (True, False):
            c = self.ends[orig].counts
            if self.confirmed or self.mut == "end-any-count":
                any_ = bool(c)
            else:
                six = [x for x in SIX if not (self.mut == "end-five" and x == "transport_seq")]
                any_ = any(c.get(x) for x in six)
            if any_:
                self.raise_row(orig, "end")

    def drop(self, orig, cause, octets=0):
        e = self.ends[orig]
        in_run = cause == "first_chunk_missing" and e.fcm_run
        app = len(e.app)
        self.count(orig, cause)
        e.mark = cause
        e.clear()
        if cause == "first_chunk_missing":
            e.fcm_run = True
            each = self.mut == "fcm-each-charged"
            self.charge(orig, 1 if each or not in_run else 0, octets if self.mut == "fcm-octets-charged" else 0)
        elif cause == "transport_seq":
            self.charge(orig, 2 if self.mut == "tseq-charges-two" else 1,
                        octets + app if self.mut == "tseq-charges-fragment" else octets)
        else:
            self.charge(orig, 1, octets)

    def embedded(self, orig):
        self.count(orig, "embedded_header")
        self.charge(orig, 0 if self.mut == "embedded-free" else 1, 0)

    # The frame stage (design 2.1 to 2.4).
    def deliver(self, orig, data, at=None, now=0):
        self.at, self.now = at, now
        if self.skip:
            return
        self.size += len(data)
        self.skip_after = False
        e = self.ends[orig]
        e.buf += data
        while e.buf and not self.skip:
            if len(e.buf) < 10:
                break
            cause = header_cause(e.buf[:10], self.mut)
            if cause:
                if not e.scanning:
                    if self.mut == "scan-clears":
                        e.clear()
                    e.scanning = True
                    if self.mut != "mark-drop-only":
                        e.mark = cause
                    self.count(orig, cause)
                    self.charge(orig, 1, 0)
                    first = True
                else:
                    first = False
                step = {"header-skip-10": 10, "header-skip-2": 2}.get(self.mut, 1)
                e.scanned += step
                e.buf = e.buf[step:]
                if not (first and self.mut == "scan-first-octet-free"):
                    self.charge(orig, 0, step)
                continue
            e.scanning = False
            if self.mut == "confirm-at-header" and not self.confirmed:
                self.confirm(orig)
            length, ctrl = e.buf[2], e.buf[3]
            if length == 5:
                if self.mut == "linkonly-clears":
                    e.clear()
                elif ctrl & 0x40 and self.mut != "reset-keeps-fcb":
                    e.fcb = None
                e.buf = e.buf[10:]
                if self.mut == "linkonly-ends-delivery":
                    e.buf = b""
                    break
                continue
            need = frame_len(length)
            if len(e.buf) < need:
                break
            fr, e.buf = e.buf[:need], e.buf[need:]
            if self.frame(orig, fr, e.buf) == "chunk_crc" and self.mut == "chunk-crc-ends-delivery":
                e.buf = b""
                break
        if self.skip_after:
            self.skip = True
        if self.skip:
            return
        if not self.tcp:
            if e.scanning:
                e.scanning = False
            elif e.buf:
                self.drop(orig, "truncated", len(e.buf))
            e.buf = b""
        self.after_delivery(orig)

    def frame(self, orig, fr, rest):
        e = self.ends[orig]
        user, at = b"", 10
        n_user = fr[2] - 5
        bound = 249 if self.mut == "seg-249" else 250
        if n_user > bound or (self.mut == "seg-lt-250" and n_user >= 250):
            self.count(orig, "invariant")
            self.skip = True
            return
        left = n_user
        while left > 0:
            c = min(left, 16)
            if not crc_ok(fr, at, c):
                tail = fr + rest[:9]
                found = any(header_cause(tail[k:k + 10], self.mut) is None for k in range(1, len(fr))
                            if len(tail[k:k + 10]) == 10)
                self.drop(orig, "chunk_crc", len(fr))
                if found:
                    self.embedded(orig)
                return "chunk_crc"
            user += fr[at:at + c]
            at += c + 2
            left -= c
        self.transport(orig, fr[3], user, len(fr))

    def transport(self, orig, ctrl, s, flen):
        m = self.mut
        e = self.ends[orig]
        t = s[0]
        fir, fin, n = bool(t & 0x40), bool(t & 0x80), t & 0x3F
        tseq_end = self.ends[True] if m == "shared-tseq" else e
        tseq = tseq_end.tseq
        confirmed = bool(ctrl & 0x40) and bool(ctrl & 0x10) and (ctrl & 0x0F) == 3
        fcb = 1 if ctrl & 0x20 else 0
        retry = confirmed and (e.fcb == fcb or m == "ignore-fcb")
        if m == "any-repeat":
            retry = True
        if fir:
            e.fcm_run = False
            if e.open:
                self.drop(orig, "fir_restart")
            elif m == "fir-checked" and tseq is not None and n != (tseq + 1) % 64:
                self.drop(orig, "transport_seq", flen)
                return
        elif e.open:
            nxt = {"no-mod64": tseq + 1, "append-at-tseq": tseq,
                   "append-at-tseq2": (tseq + 2) % 64}.get(m, (tseq + 1) % 64)
            if m == "no-seq-check" or n == nxt or (m == "append-repeat" and n == tseq):
                pass
            elif m != "count-every-repeat" and n == tseq and retry and self.same(e, s):
                if m == "retry-charged":
                    self.charge(orig, 1, 0)
                return
            else:
                self.drop(orig, "transport_seq", flen)
                return
        else:
            if m != "no-window" and e.after_fin and n == tseq and retry and self.same(e, s):
                if m == "window-once":
                    e.after_fin = False
                return
            if m == "drop-keeps-window":
                self.count(orig, "first_chunk_missing")
            else:
                self.drop(orig, "first_chunk_missing", flen)
            return
        # The fragment-size limit, in application octets; a sum equal to
        # the limit passes (design 2.2).
        total = (0 if fir else len(e.app)) + len(s) - 1
        over = total >= LIMIT if m == "limit-ge" else total > LIMIT + (1 if m == "limit-plus-one" else 0)
        if over:
            self.drop(orig, "fragment_limit", flen)
            return
        tseq_end.tseq = n
        e.last, e.after_fin = s, fin
        e.fcb = fcb if confirmed else None
        e.app = (b"" if fir else e.app) + s[1:]
        e.open = True
        if fir:
            # The mark goes before the fragment's first part reaches the
            # parser; the script keeps it, per end, for that end's next fc row.
            if e.mark is not None:
                k = True if m == "script-mark-one-field" else orig
                self.pending[k] = e.mark
                e.mark = None
            if m == "confirm-at-fir" and not self.confirmed:
                self.confirm(orig)
        if fin:
            app = e.app
            e.open, e.app = False, b""
            if m == "confirm-before-eof" and not self.confirmed:
                self.confirm(orig)
            if app == u.BADOBJ:
                self.drop(orig, "app_parse", flen)
                return
            if len(app) >= 2:
                cause = self.pending.get(orig) if m == "script-mark-kept" and orig else self.pending.pop(orig, None)
                self.fc.append((orig, app[1], cause))
            if not self.confirmed:
                self.confirm(orig)

    def same(self, e, s):
        if self.mut == "cmp-number":
            return True
        if self.mut == "cmp-transport":
            return e.last is not None and s[0] == e.last[0]
        if self.mut == "cmp-shorter":
            k = min(len(s), len(e.last))
            return s[:k] == e.last[:k]
        if self.mut == "cmp-app-only":
            return e.last is not None and len(s) == len(e.last) and s[1:] == e.last[1:]
        return s == e.last


@functools.lru_cache(maxsize=1)
def all_cases():
    return u.cases()


def run_flow(f, mutant=None):
    mdl = Model(isinstance(f.conv, u.synth.TCPConv), mutant)
    t0 = None
    for i, (from_m, data, ns) in enumerate(f.sent):
        t0 = ns if t0 is None else t0
        mdl.deliver(from_m, data, i, ns // 1000)
    mdl.finish()
    return mdl


def reading_of(mdl):
    """What the check reads, from the model: the fc rows and their causes,
    each end's counts from its last row, the rows, the weirds and the
    violations."""
    fc = [(o, c) for o, c, _ in mdl.fc]
    marks = [(i, c) for i, (_, _, c) in enumerate(mdl.fc) if c]
    counts, scanned = {}, {}
    for end, _, _, c, sc in mdl.rows:
        counts = {k: v for k, v in counts.items() if k[0] != end}
        counts.update({(end, k): v for k, v in c.items()})
        scanned[end] = sc
    rows = [(end, why, at) for end, why, at, _, _ in mdl.rows]
    weirds = {}
    for w in dict.fromkeys(mdl.weirds):  # weird.log: once per flow and name
        weirds[w] = 1
    return fc, counts, rows, weirds, marks, mdl.viol, scanned


# The host's weird sampling (Weird::sampling_threshold, 25) and its cap K.
THRESHOLD, K = 25, 100


def run_hosts(h, mutant=None):
    """The host cap's inputs: each flow's model, then the script's cap and
    the weirds' sampling over every row and weird in time order."""
    rows, weirds, per = [], [], {}
    for idx, f in enumerate(h.flows):
        mdl = Model(False, mutant)
        last = 0
        for i, (from_m, data, ns) in enumerate(f.sent):
            n0 = len(mdl.rows), len(mdl.weirds)
            mdl.deliver(from_m, data, i, ns // 1000)
            rows += [(ns // 1000, idx, r[1]) for r in mdl.rows[n0[0]:]]
            weirds += [(ns // 1000, idx, w) for w in mdl.weirds[n0[1]:]]
            last = max(last, ns // 1000)
        mdl.finish()
        per[idx] = mdl
    end_t = max(ns for f in h.flows for _, _, ns in f.sent) // 1000
    for idx, mdl in per.items():
        rows += [(end_t, idx, r[1]) for r in mdl.rows if r[2] == "end"]
    rows.sort(key=lambda r: r[0])
    by_why, overflow = {}, []
    start, open_n, written, held = None, 0, 0, 0
    for t, _, why in rows:
        start = t if start is None else start
        n = (t - start) // INTERVAL_US
        if n != open_n:
            if held and not (mutant == "script-overflow-counted" and written >= K):
                overflow.append(held)
            open_n, written, held = n, 0, 0
        free = mutant == "script-end-free" and why in ("end", "budget")
        cap = K + 1 if mutant == "script-cap-gt" else K - 1 if mutant == "script-cap-lt" else K
        if written >= cap and not free:
            held += 1
            continue
        written += 1
        by_why[why] = by_why.get(why, 0) + 1
    if held and not (mutant == "script-overflow-counted" and written >= K):
        overflow.append(held)
    seen, logged, n_name = set(), {}, {}
    for t, idx, w in sorted(weirds):
        key = (idx if mutant == "script-no-sampling" else 0, w)
        n_name[key] = n_name.get(key, 0) + 1
        if n_name[key] > THRESHOLD or (idx, w) in seen:
            continue
        seen.add((idx, w))
        logged[w] = logged.get(w, 0) + 1
    return by_why, overflow, logged


def run_model(case, mutant=None):
    f = all_cases()[case]
    if isinstance(f, u.Hosts):
        return run_hosts(f, mutant)
    return reading_of(run_flow(f, mutant))


ROWS = [pytest.param(r, id=r[0]) for r in u.EXPECT]


@pytest.mark.parametrize("row", ROWS)
def test_the_design_gives_each_expectation(row):
    assert u.meets(row, run_model(row[0]))


@pytest.mark.parametrize("row,m", [pytest.param(r, m, id=f"{r[0]}-{m}") for r in u.EXPECT for m in r[4]])
def test_each_control_breaks_its_rows_expectation(row, m):
    assert not u.meets(row, run_model(row[0], m))


def test_every_input_has_its_expectation():
    assert set(u.MORE) == {r[0] for r in u.EXPECT}
    for r in u.EXPECT:
        host = isinstance(all_cases()[r[0]], u.Hosts)
        assert host == ("host" in u.MORE[r[0]]) == (r[2] is None)


def patch_text(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return fh.read()


def build_env():
    out = {}
    with open(os.path.join(HERE, "build.env"), encoding="utf-8") as fh:
        for ln in fh:
            if "=" in ln and not ln.startswith("#"):
                k, v = ln.rstrip("\n").split("=", 1)
                out[k] = v
    return out


def test_the_closed_set_is_the_patchs_in_its_order():
    p = patch_text("hr25-resync.patch")
    m = re.search(r"static const char\* const cause_name\[\] = \{(.*?)\};", p, re.S)
    names = re.findall(r'"([a-z_]+)"', m.group(1))
    assert names == u.CAUSES
    assert len(u.CAUSES) == 14 and u.CAUSES.index("transport_seq") == u.CAUSES.index("fir_restart") + 1


def test_every_control_has_its_patch_and_build_env_lists_exactly_them():
    files = sorted(f[len("hr25-"):-len(".patch")] for f in os.listdir(os.path.join(HERE, "controls"))
                   if f.startswith("hr25-"))
    assert sorted(u.patch_controls()) == files
    assert build_env()["HR25_CONTROLS"].strip('"').split() == u.patch_controls()
    scripts = sorted(f[:-len(".patch")] for f in os.listdir(os.path.join(HERE, "controls"))
                     if f.startswith("script-"))
    assert sorted(u.script_controls()) == scripts


CONTROL_FILES = sorted(f for f in os.listdir(os.path.join(HERE, "controls")) if f.startswith(("hr25-", "script-")))


@pytest.mark.parametrize("name", CONTROL_FILES)
def test_each_control_changes_one_hunk_and_names_its_rule(name):
    p = patch_text(os.path.join("controls", name))
    assert p.count("\n@@ ") == 1
    assert re.search(r"section (3\.1|2\.[1-9]), '", p.split("\n---", 1)[0])


def test_the_script_controls_change_the_script_part_only():
    for name in CONTROL_FILES:
        if name.startswith("script-"):
            p = patch_text(os.path.join("controls", name))
            assert "--- a/resync.zeek\n+++ b/resync.zeek\n" in p


def test_the_cause_inputs_hold_no_accidental_header():
    # header-crc's junk header fails its CRC; link-length's length-4 header
    # passes it, and its CRC octets are not 05 64 (no candidate at offset 8).
    f = u.cases()["d4u-hr25-header-crc"]
    assert header_cause(f.sent[2][1][:10]) == "header_crc"
    f = u.cases()["d4u-hr25-link-length"]
    d = f.sent[2][1]
    assert header_cause(d[:10]) == "link_length" and d[8:10] != b"\x05\x64"
    assert header_cause(u.badhdr()) == "header_crc" and b"\x05\x64" not in u.garbage(16)


def test_inputs_are_distinct_and_named():
    c = u.cases()
    assert all(n.startswith("d4u-hr25-") for n in c)
    assert {r[0] for r in u.EXPECT} == set(c)


def test_the_throwing_fragment_avoids_the_held_items_by_construction():
    # The one throwing fragment is a response (129) whose only object octet
    # is 3Ch (group 60), as D6's badobj; no input sends code 2 (D1's ruling
    # on D4-131 item 5.1; items held under D4-112 item 1.3).
    assert u.BADOBJ[1] == 129 and u.BADOBJ[4:] == b"\x3c"


# The shipped script part (design 2.8): its probe-log fields are exactly the
# design's, and it declares no container (D3's BM): the pending cause lives
# on the connection record only.
def script_text(path=os.path.join(HERE, "resync.zeek")):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def info_fields(text):
    m = re.search(r"redef record OtsecProbe::Info \+= \{(.*?)\};", text, re.S)
    return re.findall(r"^\s*([a-z_]+):", m.group(1), re.M)


def containers(text):
    return re.findall(r"^global\s+\w+\s*:\s*(?:table|set|vector)\b", text, re.M)


def test_the_script_adds_exactly_the_designs_fields():
    assert info_fields(script_text()) == ["why", "cause", "counts", "scanned_octets", "overflow", "resync_cause"]


def test_the_field_check_refuses_an_extra_field():
    t = script_text().replace("\tresync_cause: string &log &optional;\n",
                              "\tresync_cause: string &log &optional;\n\tdata: string &log &optional;\n")
    assert info_fields(t) != info_fields(script_text())


def test_the_script_holds_no_container():
    assert containers(script_text()) == []


def test_the_container_check_finds_a_table_keyed_by_connection():
    t = script_text() + "\nglobal pending: table[string, bool] of string;\n"
    assert containers(t) != []


def test_the_script_bounds_every_weird_of_the_closed_set():
    p = patch_text("hr25-resync.patch")
    m = re.search(r"static const char\* const cause_weird\[\] = \{(.*?)\};", p, re.S)
    weirds = re.findall(r'"(dnp3_[a-z_]+)"', m.group(1))
    m = re.search(r"redef Weird::sampling_global_list \+= \{(.*?)\};", script_text(), re.S)
    assert re.findall(r'"(dnp3_[a-z_]+)"', m.group(1)) == weirds and len(weirds) == 14


def write_cfg(d, code="0", fc=(), resync=(), weirds=(), viol=0):
    os.makedirs(d, exist_ok=True)
    if code is not None:
        open(os.path.join(d, "exit-code"), "w").write(code)
    with open(os.path.join(d, "otsec_probe.log"), "w") as fh:
        for o, c in fc:
            fh.write('{"kind":"fc","is_orig":%s,"fc":%d}\n' % ("true" if o else "false", c))
        for r in resync:
            fh.write(json.dumps(r) + "\n")
    with open(os.path.join(d, "weird.log"), "w") as fh:
        for w in weirds:
            fh.write('{"name":"%s"}\n' % w)
    with open(os.path.join(d, "otsec_viol.log"), "w") as fh:
        for _ in range(viol):
            fh.write('{"analyzer":"DNP3_UDP","reason":"x"}\n')


def row_of(case):
    return next(r for r in u.EXPECT if r[0] == case)


def end_row(end, counts):
    return {"kind": "resync", "ts": 0, "is_orig": end == "m", "why": "end",
            "counts": [counts.get(c, 0) for c in u.CAUSES], "scanned_octets": 0}


def test_state_reads_met_not_met_exit_and_not_run(tmp_path):
    row = row_of("d4u-hr25-unconfirmed-seq-only")
    f = u.cases()[row[0]]
    write_cfg(tmp_path / "a", resync=[end_row("m", {"transport_seq": 1})])
    assert u.state(str(tmp_path / "a"), row, f) == "met"
    write_cfg(tmp_path / "b", resync=[end_row("m", {"transport_seq": 2})])
    assert u.state(str(tmp_path / "b"), row, f) == "not met"
    write_cfg(tmp_path / "c", resync=[end_row("m", {"transport_seq": 1})], weirds=["dnp3_transport_sequence"])
    assert u.state(str(tmp_path / "c"), row, f) == "not met"
    write_cfg(tmp_path / "d", code="134")
    assert u.state(str(tmp_path / "d"), row, f) == "exit 134"
    assert u.state(str(tmp_path / "e"), row, f) == "not run"


def test_a_control_must_be_killed_and_a_crash_is_no_kill():
    assert u.verdict("met", [("x", "not met")]) == "pass"
    assert u.verdict("met", [("x", "met")]).startswith("FAIL")
    assert u.verdict("met", [("x", "exit 139")]).startswith("FAIL")
    assert u.verdict("met", [("x", "not run")]).startswith("FAIL")
    assert u.verdict("not met", []).startswith("FAIL")


def test_check_fails_on_a_missing_control_run(tmp_path, capsys):
    row = row_of("d4u-hr25-unconfirmed-seq-only")
    write_cfg(tmp_path / row[0] / u.C2A, resync=[end_row("m", {"transport_seq": 1})])
    rc = u.check(str(tmp_path))
    assert rc == 1 and "not run" in capsys.readouterr().out


def test_state_reads_a_probe_log_without_an_exit_code_as_not_run(tmp_path):
    # D6's N3 on #789: a missing exit-code is never read as a pass.
    row = row_of("d4u-hr25-unconfirmed-seq-only")
    write_cfg(tmp_path / "a", code=None, resync=[end_row("m", {"transport_seq": 1})])
    assert u.state(str(tmp_path / "a"), row, u.cases()[row[0]]) == "not run"


def only(rows, fn):
    orig = u.EXPECT
    try:
        u.EXPECT = rows
        return fn()
    finally:
        u.EXPECT = orig


def test_c2_is_printed_as_ran_or_its_exit_code_only(tmp_path, capsys):
    # D1's ruling on D4-131 item 5.1: C2's column says whether it ran and
    # its exit code, never met or not met, and never decides the row.
    row = row_of("d4u-hr25-unconfirmed-seq-only")
    base = tmp_path / row[0]
    write_cfg(base / u.C2A, resync=[end_row("m", {"transport_seq": 1})])
    for m in row[4]:
        write_cfg(base / ("zeek-hr25-m-" + m))
    write_cfg(base / u.C2)
    assert only([row], lambda: u.check(str(tmp_path))) == 0
    write_cfg(base / u.C2, code="1")
    assert only([row], lambda: u.check(str(tmp_path))) == 0
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.startswith("| " + row[0])]
    assert [ln.split(" | ")[4] for ln in lines] == ["ran", "exit 1"]
    assert all("met" not in ln.split(" | ")[4] for ln in lines)


def test_the_c2_column_control_a_judged_c2_is_refused(tmp_path):
    # The control: a C2 column that judged C2 would print `not met` here,
    # which ran() never prints.
    write_cfg(tmp_path / "c2", fc=[(True, 99)])
    assert u.ran(str(tmp_path / "c2")) == "ran"
    row = row_of("d4u-hr25-unconfirmed-seq-only")
    assert u.state(str(tmp_path / "c2"), row, u.cases()[row[0]]) == "not met"


def test_the_reading_holds_no_reason_text(tmp_path):
    # D1's ruling on D4-131 item 5.1: causes, counts and weird names only.
    # A violation's reason and a weird's other fields are never read.
    row = row_of("d4u-hr25-budget-f")
    f = u.cases()[row[0]]
    d = tmp_path / "a"
    write_cfg(d, resync=[], weirds=["dnp3_resync_budget_exhausted"], viol=1)
    with open(d / "otsec_viol.log", "w") as fh:
        fh.write('{"analyzer":"DNP3_UDP","reason":"SECRET-REASON"}\n')
    with open(d / "weird.log", "w") as fh:
        fh.write('{"name":"dnp3_resync_budget_exhausted","addl":"SECRET-ADDL"}\n')
    _, got = u.reading(str(d), f)
    assert "SECRET" not in repr(got)

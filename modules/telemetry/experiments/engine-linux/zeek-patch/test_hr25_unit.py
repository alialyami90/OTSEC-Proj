"""Tests of hr25_unit.py (HR25-B1), and a desk check of its expectations.

`Model` is a reference of the rules of docs/phase4/D4-hr25-design.md
sections 2.1 to 2.4 and 2.9 item 5, written from the design, with one
switch per mutant control of controls/hr25-*.patch. It is not the patch:
it shows that each input's expectation follows from the design's rules,
and that each control a row names breaks that expectation, before any
build runs (evidence class `desk`). Whether the patch does what the model
does is what the inputs test, once a run that D1 rules reads them.

Run: python -m pytest -q modules/telemetry/experiments/engine-linux/zeek-patch/test_hr25_unit.py
"""
import functools
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
        self.clear()

    def clear(self):
        self.open = False
        self.app = b""
        self.tseq = None
        self.last = None
        self.after_fin = False
        self.fcb = None


class Model:
    """The rules as the design states them, on one flow's deliveries."""

    def __init__(self, tcp, mutant=None):
        self.tcp, self.mut = tcp, mutant
        self.ends = {True: End(), False: End()}
        self.counts = {}
        self.fc = []
        self.skip = False

    def count(self, orig, cause):
        k = ("m" if orig else "o", cause)
        self.counts[k] = self.counts.get(k, 0) + 1

    def drop(self, orig, cause):
        self.count(orig, cause)
        self.ends[orig].clear()

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

    def deliver(self, orig, data):
        if self.skip:
            return
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
                    self.count(orig, cause)
                e.buf = e.buf[10:] if self.mut == "header-skip-10" else e.buf[1:]
                continue
            e.scanning = False
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
        if not self.tcp and not self.skip:
            if e.scanning:
                e.scanning = False
            elif e.buf:
                self.drop(orig, "truncated")
            e.buf = b""

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
                self.drop(orig, "chunk_crc")
                if found:
                    self.count(orig, "embedded_header")
                return "chunk_crc"
            user += fr[at:at + c]
            at += c + 2
            left -= c
        self.transport(orig, fr[3], user)

    def transport(self, orig, ctrl, s):
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
            if e.open:
                self.drop(orig, "fir_restart")
            elif m == "fir-checked" and tseq is not None and n != (tseq + 1) % 64:
                self.drop(orig, "transport_seq")
                return
        elif e.open:
            nxt = {"no-mod64": tseq + 1, "append-at-tseq": tseq,
                   "append-at-tseq2": (tseq + 2) % 64}.get(m, (tseq + 1) % 64)
            if m == "no-seq-check" or n == nxt or (m == "append-repeat" and n == tseq):
                pass
            elif m != "count-every-repeat" and n == tseq and retry and self.same(e, s):
                return
            else:
                self.drop(orig, "transport_seq")
                return
        else:
            if m != "no-window" and e.after_fin and n == tseq and retry and self.same(e, s):
                if m == "window-once":
                    e.after_fin = False
                return
            if m == "drop-keeps-window":
                self.count(orig, "first_chunk_missing")
            else:
                self.drop(orig, "first_chunk_missing")
            return
        # The fragment-size limit, in application octets; a sum equal to
        # the limit passes (design 2.2).
        total = (0 if fir else len(e.app)) + len(s) - 1
        over = total >= LIMIT if m == "limit-ge" else total > LIMIT + (1 if m == "limit-plus-one" else 0)
        if over:
            self.drop(orig, "fragment_limit")
            return
        tseq_end.tseq = n
        e.last, e.after_fin = s, fin
        e.fcb = fcb if confirmed else None
        e.app = (b"" if fir else e.app) + s[1:]
        e.open = True
        if fin:
            if len(e.app) >= 2:
                self.fc.append((orig, e.app[1]))
            e.open, e.app = False, b""


@functools.lru_cache(maxsize=1)
def all_cases():
    return u.cases()


def run_model(case, mutant=None):
    f = all_cases()[case]
    mdl = Model(isinstance(f.conv, u.synth.TCPConv), mutant)
    for from_m, data in f.sent:
        mdl.deliver(from_m, data)
    return mdl.fc, mdl.counts


ROWS = [pytest.param(r, id=r[0]) for r in u.EXPECT]


@pytest.mark.parametrize("row", ROWS)
def test_the_design_gives_each_expectation(row):
    case, _, want_fc, want_counts, _ = row
    assert run_model(case) == (want_fc, want_counts)


@pytest.mark.parametrize("row,m", [pytest.param(r, m, id=f"{r[0]}-{m}") for r in u.EXPECT for m in r[4]])
def test_each_control_breaks_its_rows_expectation(row, m):
    case, _, want_fc, want_counts, _ = row
    assert run_model(case, m) != (want_fc, want_counts)


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
    assert sorted(u.controls()) == files
    assert build_env()["HR25_CONTROLS"].strip('"').split() == u.controls()


@pytest.mark.parametrize("name", sorted(f for f in os.listdir(os.path.join(HERE, "controls")) if f.startswith("hr25-")))
def test_each_control_changes_one_hunk_and_names_its_rule(name):
    p = patch_text(os.path.join("controls", name))
    assert p.count("\n@@ ") == 1
    assert re.search(r"section (3\.1|2\.[12]), '", p.split("\n---", 1)[0])


def test_the_cause_inputs_hold_no_accidental_header():
    # header-crc's junk header fails its CRC; link-length's length-4 header
    # passes it, and its CRC octets are not 05 64 (no candidate at offset 8).
    f = u.cases()["d4u-hr25-header-crc"]
    assert header_cause(f.sent[2][1][:10]) == "header_crc"
    f = u.cases()["d4u-hr25-link-length"]
    d = f.sent[2][1]
    assert header_cause(d[:10]) == "link_length" and d[8:10] != b"\x05\x64"


def test_inputs_are_distinct_and_named():
    c = u.cases()
    assert all(n.startswith("d4u-hr25-") for n in c)
    assert {r[0] for r in u.EXPECT} == set(c)


def write_cfg(d, code="0", fc=(), counts=None):
    os.makedirs(d, exist_ok=True)
    if code is not None:
        open(os.path.join(d, "exit-code"), "w").write(code)
    with open(os.path.join(d, "otsec_probe.log"), "w") as fh:
        for o, c in fc:
            fh.write('{"kind":"fc","is_orig":%s,"fc":%d}\n' % ("true" if o else "false", c))
    if counts:
        with open(os.path.join(d, "otsec_resync_unit.log"), "w") as fh:
            for end, cs in counts.items():
                v = [cs.get(c, 0) for c in u.CAUSES]
                fh.write('{"why":"end","is_orig":%s,"counts":%s}\n' % ("true" if end == "m" else "false", v))


def test_state_reads_met_not_met_exit_and_not_run(tmp_path):
    want = [(True, 1)]
    write_cfg(tmp_path / "a", fc=want, counts={"m": {"magic": 1}})
    assert u.state(str(tmp_path / "a"), want, {("m", "magic"): 1}) == "met"
    assert u.state(str(tmp_path / "a"), want, {}) == "not met"
    write_cfg(tmp_path / "b", code="134", fc=want)
    assert u.state(str(tmp_path / "b"), want, {}) == "exit 134"
    assert u.state(str(tmp_path / "c"), want, {}) == "not run"


def test_a_control_must_be_killed_and_a_crash_is_no_kill():
    assert u.verdict("met", [("x", "not met")]) == "pass"
    assert u.verdict("met", [("x", "met")]).startswith("FAIL")
    assert u.verdict("met", [("x", "exit 139")]).startswith("FAIL")
    assert u.verdict("met", [("x", "not run")]).startswith("FAIL")
    assert u.verdict("not met", []).startswith("FAIL")


def test_check_fails_on_a_missing_control_run(tmp_path, capsys):
    row = u.EXPECT[0]
    write_cfg(tmp_path / row[0] / u.C2A, fc=row[2])
    rc = u.check(str(tmp_path))
    assert rc == 1 and "not run" in capsys.readouterr().out


def test_state_reads_a_probe_log_without_an_exit_code_as_not_run(tmp_path):
    # D6's N3 on #789: a missing exit-code is never read as a pass.
    want = [(True, 1)]
    write_cfg(tmp_path / "a", code=None, fc=want)
    assert u.state(str(tmp_path / "a"), want, {}) == "not run"


def test_check_quotes_c2_and_never_judges_it(tmp_path, capsys):
    # D6's N3 on #789: a row passes with C2 absent, and with C2 not met.
    row = u.EXPECT[0]
    base = tmp_path / row[0]
    write_cfg(base / u.C2A, fc=row[2])
    for m in row[4]:
        write_cfg(base / ("zeek-hr25-m-" + m), fc=row[2][:1])
    rows = [r for r in u.EXPECT if r[0] == row[0]]
    orig = u.EXPECT
    try:
        u.EXPECT = rows
        assert u.check(str(tmp_path)) == 0
        write_cfg(base / u.C2, fc=row[2][:1])
        assert u.check(str(tmp_path)) == 0
    finally:
        u.EXPECT = orig
    assert "| pass |" in capsys.readouterr().out

"""V-M2 on the real binaries with the stepped test clock (C6; D4-40).

Each change of the GT-INJ configuration series
(tests/integration/gt_inj/config.json) runs on a node of its own, with its
own simulator: the slice's asset is read with sel.config.read_all every 75
seconds (slicehelper setup -config-every), and both the node and the
collector are built with otsec_testclock and run on one stepped clock, so
the collector judges an approval's window and issue time on the series'
clock. The clock starts a minute after the wall clock, so the
administrator's credential install, signed at wall-clock time, is not in
the collector's future.

The timeline is config.json's, in seconds from R0, the first read: the
configuration baseline is acknowledged at baseline_ack with a signed
node.baseline_ack of kind configuration; the read Rm finds it unchanged;
the change is injected at change, through the simulator's settings file
(--profile-settings) or, for a non-semantic difference, by restarting the
simulator on the same port with the other SHO layout; R1 finds it; one more
read follows. An approval is signed with the time its text claims as
issued_at and its window from the series, by the administrator, or for
the non-approver case by the operator, whose key may not sign
node.change_approval, and is left in admin_dir so that the node relays it
at the first relay at or after its recorded time.

The clock jumps to each step, so a read begins exactly at its time; while
a read or a relay is in flight the clock moves a second per wall-clock
second, so the node's outcome deadline and the collector's run deadline
(both D4-24) are not crossed falsely.

The simulator answers the configuration run's SHO forms that the manual
does not print with SYNTHESIZED placeholders (--profile-config-run; see
tests/safety/recording_simulator/profile_sel751.py). Evidence class:
simulated.
"""

import base64
import concurrent.futures
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import threading
import time

import pytest

import harness
from conftest import need
from slicerun import SERVICE, Slice
from test_slice_gtinj_feed_e2e import Clock, _query, _stamp, _status

CONFIG = os.path.join(harness.REPO, "tests", "integration", "gt_inj", "config.json")
EVERY = 75  # R0 + 75 is after Rm's 105 is reached by a jump, and 105 + 75 = R1
SEC = datetime.timedelta(seconds=1)
RESULTS = ("config.read_compared", "config.change_detected", "config.baseline_restored")
WORKERS = 4


def _series():
    with open(CONFIG, encoding="utf-8") as f:
        return json.load(f)


class _Run:
    """One change's node, simulator and clock."""

    def __init__(self, d, change):
        self.d, self.change = d, change
        t0 = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)).replace(second=0, microsecond=0)
        self.clock = Clock(os.path.join(d, "clock"), t0)
        self.settings = os.path.join(d, "settings.json")
        s = self.s = Slice(d)
        s.node_tags = s.collector_tags = ("otsec_testclock",)
        s.node_args = s.collector_args = ("-test-clock", self.clock.path)

    def jump(self, at):
        """The clock to at in one step."""
        if at > self.clock.at:
            self.clock.set(at)
        if not harness.wait_for(self.clock.reached, 10, step=0.002):
            raise AssertionError(f"{self.change['id']}: the node's clock did not reach {_stamp(at)}")

    def live(self, done, what, limit=120):
        """A second of clock per wall-clock second until done() holds."""
        end = time.monotonic() + limit
        while not done():
            if time.monotonic() > end:
                raise AssertionError(f"{self.change['id']}: {what} by {_stamp(self.clock.at)}; audit {self.actions()[-6:]}")
            time.sleep(1)
            self.jump(self.clock.at + SEC)

    def audit(self):
        return [json.loads(e) for (e,) in _query(self.s.layout["store_dir"], "SELECT event FROM events WHERE stream = ? ORDER BY seq", "audit")]

    def actions(self):
        return [a.get("action") for a in self.audit()]

    def config(self):
        return [bytes(e) if not isinstance(e, str) else e.encode() for (e,) in _query(
            self.s.layout["store_dir"], "SELECT event FROM events WHERE stream = ? ORDER BY seq", "config/" + self.s.layout["asset_id"])]

    def results(self):
        return [a for a in self.audit() if a.get("action") in RESULTS]

    def admin(self, name, **flags):
        args = [self.s.exe("slicehelper"), "admin-file", "-root", self.s.root, "-name", name]
        for k, v in flags.items():
            args += ["-" + k.replace("_", "-")] + ([] if v is True else [str(v)])
        out = subprocess.run(args, capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)

    def decided(self, file):
        for r in _status(self.s).get("admin_requests") or []:
            if r.get("file") == file and r.get("state") not in (None, "", "waiting"):
                return r
        return None

    def approve(self, r0, a):
        """Leaves the change's approval in admin_dir, jumps to its recorded
        time and waits for the collector's decision."""
        w = ",".join(_stamp(r0 + s * SEC)[:19] + "Z" for s in a["window"])
        f = self.admin(f"approval-{self.change['id']}", kind="change-approval", digest=self.baseline, window=w,
                       issued=_stamp(r0 + a["claims"] * SEC)[:19] + "Z", device=a["device"],
                       **({} if a["approver"] else {"operator": True}))
        self.jump(r0 + a["recorded"] * SEC)
        self.live(lambda: self.decided(f["file"]), "no decision on the approval")
        return self.decided(f["file"])

    def read(self, at):
        """Jumps to at, where a read is due, and waits for its result."""
        n = len(self.results())
        self.jump(at)
        self.live(lambda: len(self.results()) > n, f"no result of the read at {_stamp(at)}")

    def run(self):
        ch, tl, s = self.change, _series()["timeline"], self.s
        s.build()
        starting = threading.Event()
        starting.set()

        def tick():  # the node's tickers wait on the clock while it starts
            while starting.is_set():
                self.clock.set(self.clock.at + SEC)
                time.sleep(0.1)

        stepper = threading.Thread(target=tick, daemon=True)
        stepper.start()
        out = {"change": ch}
        try:
            s.start(sim_extra=("--profile-settings", self.settings, "--profile-config-run"),
                    setup_extra=("-config-every", str(EVERY)))
            starting.clear()
            stepper.join()
            out["layout"] = s.layout
            # The schedule's first read is due a minute after the node's
            # start, so no later than this.
            r0 = out["r0"] = self.clock.at + 60 * SEC
            self.jump(r0)
            self.live(lambda: len(self.config()) >= 1, "no snapshot at R0")
            self.baseline = out["baseline"] = "sha256:" + hashlib.sha256(self.config()[0]).hexdigest()
            f = self.admin("baseline-ack", kind="baseline-ack", baseline_kind="configuration", digest=self.baseline,
                           issued=_stamp(r0 + tl["baseline_ack"] * SEC)[:19] + "Z")
            self.jump(r0 + tl["baseline_ack"] * SEC)
            self.live(lambda: "config.baseline_acknowledged" in self.actions(), "the baseline was not acknowledged")
            out["ack"] = self.decided(f["file"])
            a = ch.get("approval")
            if a and a["recorded"] < tl["Rm"]:
                out["approval"] = self.approve(r0, a)
            self.read(r0 + tl["Rm"] * SEC)
            # The change.
            inj = ch["inject"]
            if inj["layout"] == "figure":
                with open(self.settings, "w", encoding="utf-8") as fh:
                    json.dump(inj["settings"], fh)
            else:
                s.sim_extra = s.sim_extra + ("--profile-sho-layout", inj["layout"])
                s.replace_simulator(s.sim_fid)
            self.read(r0 + tl["R1"] * SEC)
            if a and a["recorded"] >= tl["Rm"]:
                out["approval"] = self.approve(r0, a)
            self.read(r0 + (tl["R1"] + EVERY) * SEC)
        finally:
            starting.clear()
            s.stop()
        out["audit"], out["config"], out["status"] = self.audit(), self.config(), _status(s)
        out["audit_raw"] = [bytes(e) if not isinstance(e, str) else e.encode() for (e,) in _query(
            s.layout["store_dir"], "SELECT event FROM events WHERE stream = ? ORDER BY seq", "audit")]
        out["slicehelper"] = s.exe("slicehelper")
        return out


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "the stepped two-binary run is a Linux runner's")
    changes = _series()["changes"]
    only = os.environ.get("OTSEC_VM2_CHANGES")  # a comma list of ids, for a local look at a few
    if only:
        changes = [c for c in changes if c["id"] in only.split(",")]
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
        futures = {c["id"]: pool.submit(_Run(str(tmp_path_factory.mktemp(c["id"])), c).run) for c in changes}
        return {i: f.result() for i, f in futures.items()}


IDS = [c["id"] for c in _series()["changes"]]


def _of(runs, cid):
    if cid not in runs:
        pytest.skip(f"{cid} not run (OTSEC_VM2_CHANGES)")
    return runs[cid]


def _digest(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _records(o, kind):
    """The asset's configuration records of kind, by digest."""
    return {_digest(b): json.loads(b) for b in o["config"] if json.loads(b).get("kind") == kind}


def _results(o):
    r = [a for a in o["audit"] if a.get("action") in RESULTS]
    assert len(r) == 3, [(a["seq"], a["action"]) for a in r]  # Rm, R1 and one more
    return r


def _approved(o):
    """The config.change_approved record of the change's approval, if any."""
    a = o.get("approval") or {}
    got = [r for r in o["audit"] if r.get("action") == "config.change_approved"
           and (r.get("config") or {}).get("decision_seq") == a.get("collector_seq")]
    assert len(got) <= 1, got
    return got[0] if got else None


@pytest.mark.parametrize("cid", IDS)
def test_the_baseline_is_the_r0_snapshot(runs, cid):
    o = _of(runs, cid)
    assert o["ack"] and o["ack"]["state"] == "accepted", o["ack"]
    acks = [r for r in o["audit"] if r.get("action") == "config.baseline_acknowledged"]
    assert len(acks) == 1 and acks[0]["config"]["baseline_digest"] == o["baseline"] == _digest(o["config"][0]), acks
    rm = _results(o)[0]
    assert (rm["action"], rm.get("reason_code"), rm["config"]["baseline_digest"]) == ("config.read_compared", "no_difference", o["baseline"]), rm


@pytest.mark.parametrize("cid", IDS)
def test_an_alarm_exactly_when_expected_at_r1(runs, cid):
    # Raised by the read that found the change (R1), so within one cycle of
    # it, and never by Rm (V-M2).
    o = _of(runs, cid)
    want = o["change"]["expect"]["alarm"]
    rm, r1, _ = _results(o)
    unapproved = [r for r in o["audit"] if r.get("reason_code") == "unapproved_change"]
    assert [r["seq"] for r in unapproved] == ([r1["seq"]] if want else []), (r1, unapproved)
    alarms = [a for a in o["status"].get("alarms") or [] if a.get("code") == "config-unapproved-change"
              and a.get("asset_id") == o["layout"]["asset_id"]]
    assert bool(alarms) == want, alarms


@pytest.mark.parametrize("cid", IDS)
def test_an_approved_change_links_its_approval(runs, cid):
    o = _of(runs, cid)
    r1 = _results(o)[1]
    if o["change"]["expect"]["approval_linked"]:
        rec = _approved(o)
        assert (r1["action"], r1.get("reason_code")) == ("config.change_detected", "approved_change"), r1
        assert r1["config"]["approval_seq"] == o["approval"]["collector_seq"] and rec and rec["seq"] < r1["seq"], (r1, rec)
    else:
        assert not (r1.get("config") or {}).get("approval_seq"), r1


@pytest.mark.parametrize("cid", IDS)
def test_an_approval_is_refused_exactly_when_expected_and_recorded(runs, cid):
    o = _of(runs, cid)
    ch, a = o["change"], o.get("approval")
    assert bool(a) == bool(ch["approval"]), a
    if not a:
        return
    sha = a["request_id"].removeprefix("admin-")
    denied = [r for r in o["audit"] if r.get("action") == "collector.request" and r.get("outcome") == "denied"
              and "node.change_approval" in r.get("detail", "") and f"file sha256 {sha}" in r.get("detail", "")]
    if ch["expect"]["approval_refused"]:
        assert a["state"] == "refused" and len(denied) == 1 and _approved(o) is None, (a, denied)
    else:
        rec = _approved(o)
        want = o["layout"]["other_asset"] if ch["approval"]["device"] == "other" else o["layout"]["asset_id"]
        assert a["state"] == "accepted" and not denied and rec and rec["target"]["asset_id"] == want, (a, rec)


@pytest.mark.parametrize("cid", IDS)
def test_prior_is_the_order_in_the_audit_chain(runs, cid):
    # An approval accepted for this asset counts only from where the chain
    # records it: before R1 for the approved and window-ended cases, after
    # it for the backdated one, whose text claims an earlier time.
    o = _of(runs, cid)
    ch, rec = o["change"], _approved(o)
    if not rec or ch["approval"]["device"] != "self":
        return
    r1 = _results(o)[1]
    assert (rec["seq"] < r1["seq"]) == (ch["case"] != "backdated"), (rec["seq"], r1["seq"], ch["case"])


@pytest.mark.parametrize("cid", IDS)
def test_both_snapshots_and_the_difference_are_stored(runs, cid):
    o = _of(runs, cid)
    ch, r1 = o["change"], _results(o)[1]
    snaps, diffs = _records(o, "config.snapshot"), _records(o, "config.difference")
    assert o["baseline"] in snaps and r1["config"]["snapshot_digest"] in snaps, r1
    r0s, r1s = snaps[o["baseline"]], snaps[r1["config"]["snapshot_digest"]]
    if ch["case"] == "non-semantic":
        # D4-46: no difference to store, and the layout change is in the
        # group sections' raw bytes, whose hashes differ; nothing else does.
        # no_difference holds only with no change held against the
        # baseline, so all three reads must be no_difference and nothing
        # in the chain may hold a change (C5 on #419). The R1 snapshot is
        # checked while its read is retained: D4-20 rule 3 removes it once
        # config.reads_removed is built.
        assert [(r["action"], r.get("reason_code")) for r in _results(o)] == [("config.read_compared", "no_difference")] * 3, _results(o)
        assert not [r for r in o["audit"] if r.get("action") == "config.change_detected"] and not diffs, list(diffs)
        h0, h1 = ({x["class"]: x["sha256"] for x in s["sections"]} for s in (r0s, r1s))
        assert {c for c in h0 if h0[c] != h1.get(c)} == {f"group.{n}" for n in range(1, 5)}, (h0, h1)
        return
    d = diffs.get(r1["config"]["difference_digest"])
    assert d and d["from"]["snapshot_digest"] == o["baseline"] and d["to"]["snapshot_digest"] == r1["config"]["snapshot_digest"], d
    got = [{k: c[k] for k in ("class", "name", "kind", "from", "to")} for c in d["changes"]]
    assert got == ch["expect_changes"], got


def _verify(o, records):
    path = os.path.join(o["layout"]["root"], "audit-check.txt")
    with open(path, "w", encoding="ascii") as f:
        f.write("\n".join(base64.b64encode(r).decode() for r in records))
    return subprocess.run([o["slicehelper"], "verify-audit", "-in", path], capture_output=True, text=True)


@pytest.mark.parametrize("cid", IDS)
def test_the_audit_chain_verifies_and_detects_a_deleted_or_edited_approval(runs, cid):
    o = _of(runs, cid)
    raw = o["audit_raw"]
    ok = _verify(o, raw)
    assert ok.returncode == 0, ok.stderr
    i = [k for k, b in enumerate(raw) if b'"config.change_approved"' in b]
    if not i:
        return
    i = i[0]
    deleted = _verify(o, raw[:i] + raw[i + 1:])
    edited = _verify(o, raw[:i] + [raw[i].replace(b"V-M2 test change", b"V-M2 test chanGe")] + raw[i + 1:])
    assert raw[i] != raw[i].replace(b"V-M2 test change", b"V-M2 test chanGe")
    assert deleted.returncode != 0 and "chain broken" in deleted.stderr, deleted.stderr
    assert edited.returncode != 0 and "chain broken" in edited.stderr, edited.stderr

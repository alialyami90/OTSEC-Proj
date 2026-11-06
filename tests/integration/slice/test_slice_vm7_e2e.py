"""V-M7 on the real binaries: R9 on the SEL-751 over GT-ADV (C6, P4-3-C6).

Each of GT-ADV's device-read rows (tests/integration/gt_adv) runs on a node
of its own, with its own simulator serving the row's FID: the slice's asset
declares that FID (slicehelper setup -gtadv-row), so the collector's
identity check passes and the run's ID read at Level 0 is the device read
the finding rests on. A row with EHTTP is read with sel.config.read_all
every 60 seconds, the simulator printing the row's EHTTP in SHO P 1
(--profile-settings); a row with no settings (D3, D9) is read with
sel.ser.read_all only, so no snapshot exists. D1's node also holds GT-ADV's
five operator rows, assets with a declared FID and no schedule
(-gtadv-operators). Every node is given GT-ADV's eight advisories as one
set, gt-adv version 1, signed with advisory test key 0 and left in
admin_dir; the node is built with otsec_testclock, the only build that
accepts a test key and a test set, and runs on the wall clock.

A row read with sel.config.read_all is checked after its second read. The
matcher counts the oldest stored snapshot as a change, since what came
before it is not known, and a change retrieved by the run that read the
identity is not before that read, so after the first read the identity is
stale; the second read, finding no change, makes it current. D7 is the
row whose second read retrieves a change: after the first read the
simulator's EFTPSERV is changed, so the identity stays stale, with the
second read's snapshot cited as the change. A row read with
sel.ser.read_all has no snapshot and is current after its first read.

What the run then gives `tests/integration/vm7/vm7.py` (the observed
dict), from the node's own status and store, and from the audit chain:
  - the set in use (status applicability.set_in_use);
  - per row: the identity's source (device-read when the newest identity
    record has a device-read firmware_id, else operator) and evidence ID
    (status identity[asset].evidence_id, or for an operator row the
    policy.apply asset_identity_declared record's audit:<node>:<seq>);
    last_evaluation (status applicability.assets[asset]); every stored
    finding revision, by advisory, in stream order; the identity.read
    document; and the evidence IDs the run made: the first run that read
    the identity, the newest snapshot's run, and the run that retrieved a
    change after the first one.

One more node is an operator-only mismatch (D1 on #504, D4-61, P4-H3
step 3): D2's asset declares D2's FID, and its simulator serves
MISMATCH_FID from the first read, so no read ever confirms the identity.
The run is refused as identity_mismatch, the identity stays the operator's,
and identity.read holds the mismatch alone. The finding must be
applicable-by-version with firmware-version unread and the declaration
stale, before and after a restart (vm7.check_mismatch with no confirming
read). Its cells are not GT-ADV's and are not checked.

A row with controls (D8, D9 and D10: tcp/80) has them as its asset's
asset_controls entry (D4-56). The node records them with a policy.apply
asset_controls_declared record, and a mitigation they hold cites that
record, so the control evidence is that record's audit:<node>:<seq>.

vm7.check then decides each of the 128 cells, and each failing cell is
reported with its reasons.

Evidence class: simulated. No device is contacted.
"""

import concurrent.futures
import hashlib
import json
import os
import shutil
import sys

import pytest

import harness
from conftest import need
from slicerun import SERVICE, Slice, check_v_s7
from test_slice_gtinj_feed_e2e import _parse, _query, _status

sys.path.insert(0, os.path.join(harness.REPO, "tests", "integration", "vm7"))
import vm7  # noqa: E402

GT = vm7.load_gt()
DEVICE_ROWS = [r for r in GT["identities"] if r["source"] == "device-read"]
OPERATOR_ROWS = [r["id"] for r in GT["identities"] if r["source"] == "operator"]
EVERY = 60
# The rows whose nodes are restarted (D1's with the operator rows, D8's with
# its recorded control), and the row whose device then answers with another
# FID (#451, D4-54): the FID's build date changed, so the collector refuses
# it as identity_mismatch.
RESTART_ROWS, MISMATCH_ROW = ("D1", "D8"), "D2"
MISMATCH_FID = "SEL-751-R501-V0-Z104101-D20260911"
# The operator-only mismatch's run, on MISMATCH_ROW's asset.
OP_MISMATCH = "op-mismatch"
# The first read is a minute after the node starts; a run takes seconds.
FIRST = 150
FINDING = "otsec.finding/"
IDENTITY = "otsec.identity/"
IDENTITY_READ = "otsec.identityread/"


def _events(store_dir, stream):
    return [json.loads(e) for (e,) in _query(store_dir, "SELECT event FROM events WHERE stream = ? ORDER BY seq", stream)]


def _audit(store_dir):
    """The audit chain's records, each with its seq."""
    return _events(store_dir, "audit")


def _schema(d):
    return d.get("schema") or ""


class _Run:
    """One device-read row's node and simulator."""

    def __init__(self, d, row, bin_dir, operators, op_mismatch=False):
        self.d, self.row, self.operators, self.op_mismatch = d, row, operators, op_mismatch
        self.s = Slice(d, bin_dir=bin_dir)
        self.s.node_tags = ("otsec_testclock",)
        self.settings = os.path.join(d, "settings.json")
        self.config_reads = (bool(row["settings"]) or row["stale"]) and not op_mismatch

    def asset(self):
        return self.s.layout["asset_id"]

    def evaluated(self, asset):
        return ((_status(self.s).get("applicability") or {}).get("assets") or {}).get(asset, {}).get("last_evaluation")

    def snapshots(self):
        return [e for e in _events(self.s.layout["store_dir"], "config/" + self.asset()) if e.get("kind") == "config.snapshot"]

    def settled(self, reads):
        """The asset's identity was read by `reads` runs, configuration
        reads when the row has them, and evaluated after the last."""
        ident = (_status(self.s).get("identity") or {}).get(self.asset()) or {}
        last, ev = ident.get("last_read") or {}, self.evaluated(self.asset())
        if not last or not ev or _parse(ev["at"]) < _parse(last["at"]):
            return False
        if not self.config_reads:
            return True
        snaps = self.snapshots()
        return len(snaps) >= reads and snaps[reads - 1].get("invocation_id") == last["invocation_id"]

    def wait(self, done, what, limit):
        if not harness.wait_for(done, limit, step=1.0):
            raise AssertionError(f"{self.row['id']}: {what} within {limit}s\nhealth:\n{self.s.health()}\nnode:\n{self.s.text('node')[-4000:]}")

    def run(self):
        s, row = self.s, self.row
        sim_extra, setup_extra = (), ("-gtadv-row", row["id"])
        if self.config_reads:
            with open(self.settings, "w", encoding="utf-8") as f:
                json.dump({"P1": dict(row["settings"])}, f)
            sim_extra = ("--profile-settings", self.settings, "--profile-config-run")
            setup_extra += ("-config-every", str(EVERY))
        if self.operators:
            setup_extra += ("-gtadv-operators",)
        out = {"row": OP_MISMATCH if self.op_mismatch else row["id"]}
        if self.op_mismatch:
            return self.run_op_mismatch(out, setup_extra)
        try:
            s.start(fid=row["fid"], sim_extra=sim_extra, setup_extra=setup_extra)
            out["layout"] = s.layout
            self.wait(lambda: self.settled(1), "no evaluation after the first read", FIRST)
            if self.config_reads:
                # The first snapshot is a change (what came before it is not
                # known), retrieved by the run that read the identity, so the
                # identity is current only after a later read. D7's change
                # is retrieved by that later read.
                if row["stale"]:
                    with open(self.settings, "w", encoding="utf-8") as f:
                        json.dump({"P1": dict(row["settings"], EFTPSERV="N")}, f)
                self.wait(lambda: self.settled(2), "no evaluation after the second read", EVERY + 60)
            for o in (OPERATOR_ROWS if self.operators else ()):
                self.wait(lambda: self.evaluated(s.layout["gtadv_assets"][o]), f"no evaluation of {o}", 30)
            # The cells are decided on this state, before any scenario.
            out["cells"] = self.collect()
            if row["id"] in RESTART_ROWS:
                self.restart()
                out["restarted"] = self.collect()
            if row["id"] == MISMATCH_ROW:
                ident = lambda: (_status(s).get("identity") or {}).get(self.asset()) or {}  # noqa: E731
                out["confirming"] = ident()["last_read"]["invocation_id"]
                s.replace_simulator(MISMATCH_FID)
                self.wait(lambda: ident().get("mismatch") and _parse(self.evaluated(self.asset())["at"]) >= _parse(ident()["mismatch"]["at"]),
                          "no evaluation after the mismatch read", EVERY + 60)
                out["mismatch"] = ident()["mismatch"]["invocation_id"]
                out["mismatched"] = self.collect()
                self.restart()
                out["mismatched_restarted"] = self.collect()
        finally:
            s.stop()
            out["checked"] = check_v_s7([l for l in s.sim_logs if os.path.exists(l)], s.d)
        return out

    def run_op_mismatch(self, out, setup_extra):
        """The operator-only mismatch: the declared FID is the row's, and the
        simulator serves MISMATCH_FID from the first read."""
        s = self.s
        ident = lambda: (_status(s).get("identity") or {}).get(self.asset()) or {}  # noqa: E731
        try:
            s.start(fid=MISMATCH_FID, setup_extra=setup_extra)
            out["layout"] = s.layout
            self.wait(lambda: ident().get("mismatch") and (self.evaluated(self.asset()) or {}).get("at")
                      and _parse(self.evaluated(self.asset())["at"]) >= _parse(ident()["mismatch"]["at"]),
                      "no evaluation after the mismatch read", FIRST)
            out["mismatch"] = ident()["mismatch"]["invocation_id"]
            out["mismatched"] = self.collect()
            self.restart()
            out["mismatched_restarted"] = self.collect()
        finally:
            s.stop()
            out["checked"] = check_v_s7([l for l in s.sim_logs if os.path.exists(l)], s.d)
        return out

    def collect(self):
        """What the node holds now: status, the audit chain, and each row
        asset's configuration stream."""
        l = self.s.layout
        return {"layout": l, "status": _status(self.s), "audit": _audit(l["store_dir"]),
                "config": {r: _events(l["store_dir"], "config/" + a) for r, a in l["gtadv_assets"].items()}}

    def restart(self):
        """The node killed and started again, once its start has evaluated
        every row asset again."""
        assets = list(self.s.layout["gtadv_assets"].values())
        before = {a: self.evaluated(a)["at"] for a in assets}
        self.s.kill("node")
        self.s.respawn("node")
        self.wait(lambda: all((self.evaluated(a) or {}).get("at", before[a]) != before[a] for a in assets),
                  "no evaluation after the restart", 60)


def _declared_ref(o, asset):
    """The newest policy.apply asset_identity_declared record of the asset,
    as operator evidence cites it."""
    node = o["layout"]["node_id"]
    refs = [f"audit:{node}:{r['seq']}" for r in o["audit"] if r.get("action") == "policy.apply"
            and r.get("reason_code") == "asset_identity_declared" and f"asset {asset} " in (r.get("detail") or "")]
    return refs[-1] if refs else None


def _controls_ref(o, asset):
    """The newest policy.apply asset_controls_declared record of the asset,
    as a mitigation it holds cites it (D4-56)."""
    node = o["layout"]["node_id"]
    refs = [f"audit:{node}:{r['seq']}" for r in o["audit"] if r.get("action") == "policy.apply"
            and r.get("reason_code") == "asset_controls_declared" and f"asset {asset} " in (r.get("detail") or "")]
    return refs[-1] if refs else None


def _first_read(config):
    """The run that first read the identity: the first identity record's."""
    recs = [e for e in config if _schema(e).startswith(IDENTITY)]
    return recs[0].get("invocation_id") if recs else None


def _device_read(config):
    recs = [e for e in config if _schema(e).startswith(IDENTITY)]
    if not recs:
        return False
    for a in (recs[-1].get("asset") or {}).get("attributes") or []:
        if a.get("name") == "firmware_id":
            return any((ob.get("source") or {}).get("kind") == "device-read" for ob in a.get("observations") or [])
    return False


def _observe(o, row):
    asset = o["layout"]["gtadv_assets"][row]
    config = o["config"][row]
    st = o["status"]
    device = _device_read(config)
    ident = (st.get("identity") or {}).get(asset) or {}
    snaps = [e for e in config if e.get("kind") == "config.snapshot"]
    reads = [e for e in config if _schema(e).startswith(IDENTITY_READ)]
    findings = {}
    for e in config:
        if _schema(e).startswith(FINDING):
            findings.setdefault(e["advisory"], []).append(e)
    evidence = {"identity": _first_read(config) if device else _declared_ref(o, asset)}
    if snaps:
        evidence["settings"] = snaps[-1].get("invocation_id")
    changed = [b for a, b in zip(snaps, snaps[1:]) if a.get("sections") != b.get("sections")]
    if changed:
        evidence["config-change"] = changed[-1].get("invocation_id")
    if _controls_ref(o, asset):
        evidence["control"] = _controls_ref(o, asset)
    return {
        "identity": {"source": "device-read" if device else "operator",
                     "evidence_id": ident.get("evidence_id") if device else _declared_ref(o, asset)},
        "last_evaluation": ((st.get("applicability") or {}).get("assets") or {}).get(asset, {}).get("last_evaluation"),
        "evidence": evidence,
        "findings": findings,
        "identity_read": reads[-1] if reads else None,
    }


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "V-M7's run of many nodes is a Linux runner's")
    builder = Slice(str(tmp_path_factory.mktemp("vm7-build")))
    builder.node_tags = ("otsec_testclock",)
    builder.build()
    rows = DEVICE_ROWS
    only = os.environ.get("OTSEC_VM7_ROWS")  # a comma list of device-read rows, for a local look at a few
    if only:
        rows = [r for r in rows if r["id"] in only.split(",")]
    with concurrent.futures.ThreadPoolExecutor(len(rows) + 1) as pool:
        futures = {r["id"]: pool.submit(_Run(str(tmp_path_factory.mktemp(r["id"])), r, builder.bin, r["id"] == "D1").run)
                   for r in rows}
        mm = next((r for r in rows if r["id"] == MISMATCH_ROW), None)
        if mm:
            futures[OP_MISMATCH] = pool.submit(_Run(str(tmp_path_factory.mktemp(OP_MISMATCH)), mm, builder.bin, False, True).run)
        out = {}
        for i, f in futures.items():
            # One row's failure is that row's, not every row's.
            try:
                out[i] = f.result()
            except Exception as e:  # noqa: BLE001
                out[i] = {"error": f"{type(e).__name__}: {e}"}
        return out


@pytest.fixture(scope="module")
def observed(runs):
    runs = {i: o for i, o in runs.items() if "error" not in o and i != OP_MISMATCH}
    assert runs, "no row's node ran"
    sets = {i: (o["cells"]["status"].get("applicability") or {}).get("set_in_use") for i, o in runs.items()}
    first = next(iter(sets.values()))
    assert first and all(v and (v["set_id"], v["version"]) == (first["set_id"], first["version"]) for v in sets.values()), sets
    obs = {"set": {"id": first["set_id"], "version": first["version"], "issued_at": first["issued_at"]}, "assets": {}}
    for i, o in runs.items():
        for row in o["cells"]["layout"]["gtadv_assets"]:
            obs["assets"][row] = _observe(o["cells"], row)
    return obs


def test_the_set_in_use_is_gt_adv(observed):
    assert (observed["set"]["id"], observed["set"]["version"]) == ("gt-adv", 1), observed["set"]


@pytest.mark.parametrize("row", [r["id"] for r in DEVICE_ROWS])
def test_the_rows_node_ran(runs, row):
    if row not in runs:
        pytest.skip(f"{row} not run (OTSEC_VM7_ROWS)")
    assert "error" not in runs[row], runs[row].get("error")


def test_every_row_has_its_source(observed):
    got = {row: a["identity"]["source"] for row, a in observed["assets"].items()}
    assert got == {r["id"]: r["source"] for r in GT["identities"]}, got


ROWS = [r["id"] for r in GT["identities"]]


@pytest.mark.parametrize("row", ROWS)
def test_each_cell_of_the_row(observed, row):
    got = vm7.check(GT, observed)
    bad = {adv: why for (r, adv), why in sorted(got.items()) if r == row and why}
    assert not bad, json.dumps(bad, indent=1)


CONTROL_ROWS = [r["id"] for r in DEVICE_ROWS if r["controls"]]


@pytest.mark.parametrize("row", CONTROL_ROWS)
def test_the_controls_record_names_its_keys_and_their_hash(runs, row):
    # D4-56: detail "asset <id> controls sha256:<hex> keys <k1,k2>", the
    # hash over the keys sorted in byte order, each followed by one LF.
    (o,) = _scenario(runs, row, "cells")
    keys = sorted(next(r for r in GT["identities"] if r["id"] == row)["controls"])
    asset = o["layout"]["gtadv_assets"][row]
    recs = [r for r in o["audit"] if r.get("action") == "policy.apply" and r.get("reason_code") == "asset_controls_declared"]
    sha = hashlib.sha256("".join(k + "\n" for k in keys).encode()).hexdigest()
    assert [r["detail"] for r in recs] == [f"asset {asset} controls sha256:{sha} keys {','.join(keys)}"], recs


def _scenario(runs, row, *keys):
    if row not in runs:
        pytest.skip(f"{row} not run (OTSEC_VM7_ROWS)")
    o = runs[row]
    assert "error" not in o, o["error"]
    return [o[k] for k in keys]


def _all(state):
    return {"assets": {row: _observe(state, row) for row in state["layout"]["gtadv_assets"]}}


@pytest.mark.parametrize("row", RESTART_ROWS)
def test_a_restart_changes_no_finding_and_no_evidence(runs, row):
    # D1's node holds D1 and the five operator rows, so each operator row
    # must still cite the same policy.apply record (D4-54); D8's mitigated
    # finding must still cite the same controls record (D4-56).
    cells, restarted = _scenario(runs, row, "cells", "restarted")
    before, after = _all(cells), _all(restarted)
    assert vm7.check_restart(before, after) == []
    assert {r: a["evidence"].get("control") for r, a in before["assets"].items()} == \
        {r: a["evidence"].get("control") for r, a in after["assets"].items()}


ADVISORIES_OF_THE_751 = [a["id"] for a in GT["advisories"] if a["product"] == "SEL-751"]


@pytest.mark.parametrize("when", ["mismatched", "mismatched_restarted"])
def test_a_later_mismatch_is_kept_apart_and_hides_no_advisory(runs, when):
    state, mismatch, confirming = _scenario(runs, MISMATCH_ROW, when, "mismatch", "confirming")
    asset = _observe(state, MISMATCH_ROW)
    bad = [b for adv in ADVISORIES_OF_THE_751 for b in vm7.check_mismatch(asset, adv, mismatch, MISMATCH_FID, confirming)]
    assert bad == [], bad


@pytest.mark.parametrize("when", ["mismatched", "mismatched_restarted"])
def test_an_operator_only_mismatch_is_kept_apart_and_hides_no_advisory(runs, when):
    # No read ever confirmed the identity, so it stays the operator's, the
    # identity.read document holds the mismatch alone, and every SEL-751
    # advisory is applicable-by-version with the declaration stale. Under
    # C12 0.1 the operator finding cannot cite the read (a C12 0.2 item).
    state, mismatch = _scenario(runs, OP_MISMATCH, when, "mismatch")
    asset = _observe(state, MISMATCH_ROW)
    assert asset["identity"]["source"] == "operator" and (asset["identity"]["evidence_id"] or "").startswith("audit:"), asset["identity"]
    bad = [b for adv in ADVISORIES_OF_THE_751 for b in vm7.check_mismatch(asset, adv, mismatch, MISMATCH_FID, None)]
    # Each finding rests on the declaration's policy.apply record.
    bad += [f"{adv}: identity evidence {asset['findings'][adv][-1]['identity']['evidence']}" for adv in ADVISORIES_OF_THE_751
            if asset["findings"].get(adv) and asset["findings"][adv][-1]["identity"]["evidence"][0]["id"] != asset["identity"]["evidence_id"]]
    assert bad == [], bad


def test_an_operator_only_mismatch_survives_a_restart(runs):
    before, after = _scenario(runs, OP_MISMATCH, "mismatched", "mismatched_restarted")
    assert vm7.check_restart(_all(before), _all(after)) == []


@pytest.mark.parametrize("row", [r["id"] for r in DEVICE_ROWS] + [OP_MISMATCH])
def test_v_s7_only_read_only_register_lines_reached_the_device(runs, row):
    # V-S7 (b) over this row's recordings, the mismatch's replacement
    # simulator included: every line is a revision 5 read-only line, none
    # before a prompt, none non-printable, and no second password.
    o = runs[row]
    assert "error" not in o, o.get("error")
    assert o["checked"], "no recording"
    for log, code, report in o["checked"]:
        assert code == 0 and report.get("pass") and not report.get("violations"), (log, report)
        assert report["commands_received"] > 0 and report["peak_concurrent_sessions"] == 1, (log, report)

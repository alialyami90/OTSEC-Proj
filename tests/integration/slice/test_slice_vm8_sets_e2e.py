"""V-M8's set cases on the real binaries (C6, P4-3-C6).

One node, built with otsec_testclock (the only build that accepts advisory
test keys and a test set) and run on the wall clock, with R9 on and two
advisory anchors: test key 0 active and test key 2 revoked
(slicehelper setup -vm8). The administrator's files are GT-ADV's set in
C11's form, left in admin_dir as advisory-set.json by
slicehelper advisory-file, one at a time; the node reads the file once per
tick (15 s).

  1. Version 2, valid: installed, and the set in use.
  2. Ten files, each wrong in one way, each refused with its C11 code:
     unsigned, truncated, signed by an unpinned key, signed by the revoked
     key, a changed signature byte, an entry with no source, a release set
     of test_only entries, another set ID, version 2 with other bytes, and
     version 1. For each: an advisory.set_refused record in the audit chain
     naming the file's SHA-256 and the code; the advisory-set-refused alarm
     naming the SHA-256; status's last refusal; and the set in use still
     version 2, with the same payload.
  3. Version 2's own bytes again: nothing is recorded.
  4. The node killed and restarted with version 1 still in admin_dir: the
     set in use is version 2, and version 1's refusal is not recorded again
     (once per file hash, across restarts).
  5. Version 3, valid: installed, naming previous version 2.
  6. Test key 0, which signed every set the node took, revoked in the
     node's configuration, and the node restarted: version 3 is dropped at
     start (C11 1.5, D4-53), no older set is used in its place, the
     advisory-set-refused alarm names the stored set's SHA-256 with
     revoked_key, the file still in admin_dir is refused and recorded with
     revoked_key, and no finding is stored after the restart.
Every finding the node stored names the set it was made under, by ID,
version and issued_at, each a set the node installed (every report
carries the set's version and date).

Evidence class: simulated. No device is contacted; every key is a test key.
"""

import datetime
import json
import os
import shutil
import subprocess

import pytest

import harness
from conftest import need
from slicerun import SERVICE, Slice
from test_slice_gtinj_feed_e2e import _query, _status

TICK = 15
CASES = [  # (case, version)
    ("unsigned", 2), ("truncated", 2), ("unknown-key", 2), ("revoked-key", 2), ("bad-signature", 2),
    ("no-source", 3), ("release-test-only", 3), ("other-set", 3), ("differs", 2), ("valid", 1),
]
WANT = {"unsigned": "malformed", "truncated": "malformed", "unknown-key": "unknown_key", "revoked-key": "revoked_key",
        "bad-signature": "bad_signature", "no-source": "invalid", "release-test-only": "invalid", "other-set": "wrong_set",
        "differs": "same_version_differs", "valid": "older_version"}


def _events(s, stream):
    return [json.loads(e) for (e,) in _query(s.layout["store_dir"], "SELECT event FROM events WHERE stream = ? ORDER BY seq", stream)]


def _advisory_records(s):
    return [r for r in _events(s, "audit") if (r.get("action") or "").startswith("advisory.")]


def _in_use(s):
    return (_status(s).get("applicability") or {}).get("set_in_use")


def _leave(s, case, version):
    out = subprocess.run([s.exe("slicehelper"), "advisory-file", "-root", s.root, "-repo", harness.REPO,
                          "-case", case, "-set-version", str(version)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _wait(s, done, what, limit=4 * TICK):
    assert harness.wait_for(done, limit, step=0.5), f"{what} within {limit}s\nhealth:\n{s.health()}\nnode:\n{s.text('node')[-3000:]}"


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "V-M8's set cases run on a Linux runner")
    s = Slice(str(tmp_path_factory.mktemp("vm8-sets")))
    s.node_tags = ("otsec_testclock",)
    s.build()
    out = {"refused": {}}
    try:
        s.start(setup_extra=("-vm8",))
        _wait(s, lambda: "applicability" in _status(s), "no applicability status")
        out["before"] = _status(s)["applicability"]

        # 1. Version 2.
        v2 = out["v2"] = _leave(s, "valid", 2)
        _wait(s, lambda: (_in_use(s) or {}).get("version") == 2, "version 2 not in use")
        out["in_use_v2"] = _in_use(s)

        # 2. Each wrong file in turn.
        for case, version in CASES:
            f = _leave(s, case, version)
            # The record, then status, which the node writes after it.
            _wait(s, lambda: any((r.get("advisory") or {}).get("file_sha256") == f["file_sha256"] for r in _advisory_records(s))
                  and ((_status(s).get("applicability") or {}).get("last_refusal") or {}).get("file_sha256") == f["file_sha256"],
                  f"no record of {case}, or status does not show it")
            out["refused"][case] = {"file": f, "records": [r for r in _advisory_records(s)
                                                           if (r.get("advisory") or {}).get("file_sha256") == f["file_sha256"]],
                                    "status": _status(s)}

        # 3. Version 2's bytes again: two ticks, nothing recorded.
        n = len(_advisory_records(s))
        again = _leave(s, "valid", 2)
        assert again["file_sha256"] == v2["file_sha256"], (again, v2)
        harness.wait_for(lambda: False, 2 * TICK + 2, step=1.0)
        out["same_again"] = _advisory_records(s)[n:]

        # 4. A restart with version 1 left in admin_dir.
        _leave(s, "valid", 1)
        harness.wait_for(lambda: False, TICK + 2, step=1.0)
        n = len(_advisory_records(s))
        _restart(s)
        _wait(s, lambda: _in_use(s), "no set in use after the restart")
        harness.wait_for(lambda: False, 2 * TICK + 2, step=1.0)
        out["restarted"] = {"in_use": _in_use(s), "records": _advisory_records(s)[n:]}

        # 5. Version 3.
        out["v3"] = _leave(s, "valid", 3)
        _wait(s, lambda: (_in_use(s) or {}).get("version") == 3, "version 3 not in use")
        out["in_use_v3"] = _in_use(s)
        _wait(s, lambda: any(f["set"]["version"] == 3 for f in _findings(s)), "no finding under version 3")
        out["records"] = _advisory_records(s)
        out["findings"] = _findings(s)

        # 6. Test key 0 revoked in the configuration, and a restart: version
        # 3, signed with it, is dropped at start, and no older set is used.
        _restart(s, revoke=out["v3"]["key_id"])
        harness.wait_for(lambda: False, 2 * TICK + 2, step=1.0)
        out["revoked"] = {"status": _status(s), "records": _advisory_records(s)[len(out["records"]):],
                          "findings": _findings(s)[len(out["findings"]):]}
    finally:
        s.stop()
    return out


def _written(s):
    w = _status(s).get("written")
    return datetime.datetime.fromisoformat(w.replace("Z", "+00:00")) if w else None


def _restart(s, revoke=None):
    """Kill the node, optionally mark the anchor revoke (a key ID) revoked
    in its configuration, start it again, and wait until it has written
    status since."""
    s.kill("node")
    killed = datetime.datetime.now(datetime.timezone.utc)
    if revoke:
        with open(s.layout["node_config"], "r+", encoding="utf-8") as f:
            nc = json.load(f)
            (a,) = [a for a in nc["applicability"]["anchors"] if a["key_id"] == revoke]
            a["status"] = "revoked"
            f.seek(0)
            json.dump(nc, f, indent=2)
            f.truncate()
    s.respawn("node")
    _wait(s, lambda: (_written(s) or killed) > killed and "applicability" in _status(s), "no status written after the restart")


def _findings(s):
    return [e for e in _events(s, "config/" + s.layout["asset_id"]) if (e.get("schema") or "").startswith("otsec.finding/")]


def test_no_set_before_the_first_file(run):
    assert not run["before"].get("set_in_use"), run["before"]


def test_version_2_is_taken(run):
    u = run["in_use_v2"]
    assert (u["set_id"], u["version"], u["payload_sha256"]) == ("gt-adv", 2, run["v2"]["payload_sha256"]), u


@pytest.mark.parametrize("case", [c for c, _ in CASES])
def test_each_wrong_file_is_refused_and_the_set_in_use_stays(run, case):
    r = run["refused"][case]
    f, want = r["file"], WANT[case]
    # What slicehelper built it to be; version 1 is a valid file, refused
    # only for its order.
    assert f["code"] == ("" if case == "valid" else want), f
    assert [(x["action"], x.get("outcome"), x.get("reason_code")) for x in r["records"]] == [("advisory.set_refused", "denied", want)], r["records"]
    app = r["status"]["applicability"]
    assert app["set_in_use"] == run["in_use_v2"], app["set_in_use"]
    assert (app["last_refusal"]["file_sha256"], app["last_refusal"]["code"]) == (f["file_sha256"], want), app["last_refusal"]
    alarms = [a for a in r["status"].get("alarms") or [] if a.get("code") == "advisory-set-refused" and f["file_sha256"] in (a.get("message") or a.get("detail") or "")]
    assert alarms, r["status"].get("alarms")
    if case == "unsigned":
        assert app["last_refusal"].get("detail") == "no signature", app["last_refusal"]


def test_the_set_in_use_again_records_nothing(run):
    assert run["same_again"] == [], run["same_again"]


def test_a_restart_keeps_version_2_and_records_no_refusal_again(run):
    u = run["restarted"]["in_use"]
    assert (u["version"], u["payload_sha256"]) == (2, run["v2"]["payload_sha256"]), u
    assert run["restarted"]["records"] == [], run["restarted"]["records"]


def test_version_3_is_taken_after_version_2(run):
    u = run["in_use_v3"]
    assert (u["version"], u["payload_sha256"]) == (3, run["v3"]["payload_sha256"]), u
    installed = [r for r in run["records"] if r["action"] == "advisory.set_installed"]
    assert [(r["advisory"]["version"], r["advisory"].get("previous_version", 0)) for r in installed] == [(2, 0), (3, 2)], installed


def test_every_finding_names_an_installed_set_by_version_and_date(run):
    installed = {(r["advisory"]["set_id"], r["advisory"]["version"]): r["advisory"]["issued_at"]
                 for r in run["records"] if r["action"] == "advisory.set_installed"}
    assert run["findings"]
    for f in run["findings"]:
        key = (f["set"]["id"], f["set"]["version"])
        assert key in installed and f["set"]["issued_at"] == installed[key], (f["set"], installed)


def test_a_revoked_key_drops_the_set_in_use_at_start(run):
    r, v3 = run["revoked"], run["v3"]
    app = r["status"]["applicability"]
    assert not app.get("set_in_use"), app
    alarms = [a for a in r["status"].get("alarms") or [] if a.get("code") == "advisory-set-refused"
              and v3["file_sha256"] in (a.get("message") or a.get("detail") or "") and "revoked_key" in (a.get("message") or a.get("detail") or "")]
    assert alarms, r["status"].get("alarms")
    assert [(x["action"], x.get("outcome"), x.get("reason_code"), x["advisory"]["file_sha256"]) for x in r["records"]] == \
        [("advisory.set_refused", "denied", "revoked_key", v3["file_sha256"])], r["records"]
    assert (app["last_refusal"]["file_sha256"], app["last_refusal"]["code"]) == (v3["file_sha256"], "revoked_key"), app["last_refusal"]
    assert r["findings"] == [], r["findings"]

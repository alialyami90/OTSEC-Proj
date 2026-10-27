"""The node's relay of an administrator's signed requests, on the real
binaries (A6, independent check of #189; design
docs/phase3/A5-signed-admin-files.md, approved on #181).

One slice. Its credential.install already goes through the relay (slicerun
starts the node first). Then, in order:
  - the node is killed and started again: nothing is sent again;
  - a tampered request and an expired one are refused, and a file the node
    could write (0640) is never read;
  - the node is killed and started again with the checkpoint from before
    those decisions (a crash after the decision record, before the
    checkpoint), and then with no checkpoint: nothing is sent again;
  - the collector is stopped (SIGSTOP) while a new install is relayed, the
    node is killed waiting for the reply, and the collector continues, so
    the reply is lost. Twice: an install the collector refuses (version 1
    again), whose resend is refused as a replay and the node says it may
    already have been applied; and a rotation to version 2 it accepts,
    whose resend gets the repeat answer naming the first decision (C7 0.5,
    #186), so the node records it accepted and nothing is installed again;
  - a decided file is removed and, once the node has forgotten it, put
    back: it gets the repeat answer, and nothing is installed again;
  - 16 files the node cannot read hold the 16 places a tick reads, so a
    signed revoke named after them is not read until they are removed;
    then it is relayed and accepted;
  - the 16 are put back ahead of the decided revoke and removed again:
    the revoke is not sent again;
  - admin_dir is left writable (0750): a new install in it is not read
    until it is 0550 again, then it is decided once.

The oracle for "sent" is the collector's own log: one "request decided"
line for each request it decided, with its request ID, status and
collector_seq. The node's record is checked against it, never the reverse.
The expected behaviour comes from the design text, not from A5's tests.

Evidence class: simulated (loopback, test keys, the recording simulator).
"""

import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import time

import pytest

import harness
from conftest import need
from slicerun import CANARY, Slice

# A platform exemption, not a missing tool, so OTSEC_SLICE_REQUIRED=1 does
# not fail it on Windows (A5's service-mode run svcdry6, #179): the checks
# stop the collector with SIGSTOP and set admin_dir's POSIX modes, neither
# of which Windows has. The Windows relay is covered only by C7's contract
# tests in the Go job; an end-to-end Windows check of admin_dir's ACLs and
# the relay is still owed (A6).
pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="Linux-only: needs SIGSTOP and POSIX file modes; it runs in CI's Linux integration-long job")

RELAY = 15      # platform/node RelayEverySeconds
SETTLE = RELAY + 8  # the relay at start and one tick after it

DECIDED = re.compile(r'msg="collector: (request decided|reply not written)" (.*)$')
KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')


def decisions(s):
    """The collector's own decisions, in its order: request_id, status,
    collector_seq and refusal, from its log. A decision whose reply could
    not be written is logged without its status; it reads "unwritten"."""
    out = []
    for line in s.text("collector").splitlines():
        m = DECIDED.search(line)
        if m:
            kv = {k: (json.loads(v) if v.startswith('"') else v) for k, v in KV.findall(m.group(2))}
            if m.group(1) == "reply not written":
                kv["status"] = "unwritten"
            out.append(kv)
    return out


def installs(s):
    """How many installs the collector's own state counts."""
    path = os.path.join(s.layout["collector_data"], "collector", "state", "state.json")
    with open(path, encoding="utf-8") as f:
        return len(json.load(f).get("installs", []))


def credential_versions(s):
    """The collector's stored versions of each credential reference and
    their state, from its credential store; nothing secret is read."""
    path = os.path.join(s.layout["collector_data"], "collector", "credentials", "credentials.json")
    with open(path, encoding="utf-8") as f:
        return [(e["ref"]["id"], e["ref"]["version"], e["status"]["state"]) for e in json.load(f).get("entries", [])]


def decided(s, rid):
    return [d for d in decisions(s) if d.get("request_id") == rid]


def admin_file(s, name, kind="install", expires="10m", tamper=False, mode=0o440, bad="", version=1):
    env = dict(os.environ, OTSEC_SLICE_SECRET=CANARY)
    argv = [s.exe("slicehelper"), "admin-file", "-root", s.root, "-kind", kind, "-name", name,
            "-expires", expires, "-mode", str(mode), "-version", str(version)]
    if tamper:
        argv.append("-tamper")
    if bad:
        argv += ["-bad", bad]
    out = subprocess.run(argv, capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def status(s):
    with open(os.path.join(s.layout["store_dir"], "status.json"), encoding="utf-8") as f:
        return json.load(f)


def shown(s, name):
    for a in status(s).get("admin_requests", []):
        if a["file"] == name:
            return a
    return None


def checkpoint(s):
    return os.path.join(s.layout["store_dir"], "suspensions.json")


def relayed(s):
    with open(checkpoint(s), encoding="utf-8") as f:
        return json.load(f).get("admin_relayed", {})


def audit(s):
    db = sqlite3.connect(f"file:{os.path.join(s.layout['store_dir'], 'audit.db')}?mode=ro", uri=True)
    try:
        return [json.loads(ev) for (ev,) in db.execute("SELECT event FROM events WHERE stream = 'audit' ORDER BY seq")]
    finally:
        db.close()


def in_admin_dir(s, fn):
    d = s.layout["admin_dir"]
    os.chmod(d, 0o750)
    try:
        fn(d)
    finally:
        os.chmod(d, 0o550)


def restart_node(s, before=None):
    """SIGKILL the node, run before() while it is down, start it again and
    let it relay at start and on one tick."""
    s.kill("node")
    if before:
        before()
    s.respawn("node")
    time.sleep(SETTLE)


@pytest.fixture(scope="module")
def got(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    s = Slice(str(tmp_path_factory.mktemp("slice-admin-relay")))
    s.build()
    out = {"steps": {}}
    stopped = False
    try:
        s.start()
        st = status(s)["admin_requests"]
        assert len(st) == 1 and st[0]["state"] == "accepted", st
        i1 = {"file": st[0]["file"], "request_id": st[0]["request_id"]}
        with open(os.path.join(s.layout["admin_dir"], i1["file"]), "rb") as f:
            i1_bytes = f.read()
        out["i1"] = i1

        # 1. A restart sends nothing again.
        restart_node(s)
        out["steps"]["restart"] = {"i1": decided(s, i1["request_id"]), "shown": shown(s, i1["file"])}

        # 2. Refused and unread files. The checkpoint from before their
        # decisions is kept for step 3.
        stale = os.path.join(s.d, "suspensions.before.json")
        shutil.copyfile(checkpoint(s), stale)
        t = admin_file(s, "a6-tampered", tamper=True)
        e = admin_file(s, "a6-expired", expires="-5m")
        w = admin_file(s, "a6-writable", mode=0o640)
        bn = admin_file(s, "a6-bad-nonce", bad="nonce")
        bk = admin_file(s, "a6-bad-key", bad="key")
        out.update(t=t, e=e, w=w, bn=bn, bk=bk)
        harness.wait_for(lambda: all((shown(s, f["file"]) or {}).get("state") == "refused" for f in (t, e)), 3 * RELAY)
        time.sleep(RELAY + 3)  # another tick: nothing is sent again
        out["steps"]["refused"] = {k: {"decided": decided(s, f["request_id"]), "shown": shown(s, f["file"])}
                                   for k, f in (("t", t), ("e", e), ("w", w), ("bn", bn), ("bk", bk))}
        out["steps"]["refused"]["relayed"] = relayed(s)
        out["steps"]["refused"]["health"] = s.health()

        # 3. A crash after the decision records, before the checkpoint:
        # the old checkpoint is put back while the node is down.
        restart_node(s, lambda: shutil.copyfile(stale, checkpoint(s)))
        out["steps"]["stale"] = {k: decided(s, f["request_id"]) for k, f in (("i1", i1), ("t", t), ("e", e))}
        out["steps"]["stale"]["relayed"] = relayed(s)
        # ... and with no checkpoint at all.
        restart_node(s, lambda: os.remove(checkpoint(s)))
        out["steps"]["none"] = {k: decided(s, f["request_id"]) for k, f in (("i1", i1), ("t", t), ("e", e))}

        # 4. The reply is lost: the collector is stopped while the node
        # waits for it, the node is killed, and the collector goes on.
        # First an install it refuses (version 1 is held), then the
        # rotation to version 2, which it accepts.
        def lose_reply(name, version):
            nonlocal stopped
            coll = s.procs["collector"]
            before = installs(s)
            coll.send_signal(signal.SIGSTOP)
            stopped = True
            f = admin_file(s, name, version=version)
            st = {"info_seen": harness.wait_for(
                lambda: any(r["action"] == "collector.request" and r.get("correlation_id") == f["request_id"]
                            and r["outcome"] == "info" for r in audit(s)), 3 * RELAY, step=0.5)}
            time.sleep(2)
            s.kill("node")
            coll.send_signal(signal.SIGCONT)
            stopped = False
            time.sleep(3)
            st["while_down"] = decided(s, f["request_id"])
            s.respawn("node")
            harness.wait_for(lambda: (shown(s, f["file"]) or {}).get("state") in ("accepted", "refused"), 3 * RELAY)
            time.sleep(RELAY + 3)
            st.update(decided=decided(s, f["request_id"]), shown=shown(s, f["file"]),
                      health=s.health(), installs=installs(s) - before, versions=credential_versions(s))
            return f, st

        out["i2r"], out["steps"]["lost_refused"] = lose_reply("a6-install-2-again", 1)
        out["i2"], out["steps"]["lost"] = lose_reply("a6-install-2", 2)
        runs = len(s.runs_reported())
        out["steps"]["lost"]["run_after"] = harness.wait_for(lambda: len(s.runs_reported()) > runs, 150, step=1.0)
        out["steps"]["lost"]["run_health"] = s.health()

        # 5. Removed, forgotten, put back. The unread files are removed
        # first, so a scan reads every file and may forget.
        in_admin_dir(s, lambda d: [os.remove(os.path.join(d, f["file"])) for f in (w, bn, bk, i1)])
        time.sleep(SETTLE)  # a full scan without the file
        out["steps"]["forget"] = {"shown_gone": shown(s, i1["file"])}

        def put_back(d):
            with open(os.path.join(d, i1["file"]), "wb") as f:
                f.write(i1_bytes)
            os.chmod(os.path.join(d, i1["file"]), 0o440)
        installs_before = installs(s)
        in_admin_dir(s, put_back)
        harness.wait_for(lambda: len(decided(s, i1["request_id"])) >= 2, 3 * RELAY)
        time.sleep(RELAY + 3)
        out["steps"]["forget"].update(decided=decided(s, i1["request_id"]), shown=shown(s, i1["file"]),
                                      installs=installs(s) - installs_before, versions=credential_versions(s))

        # 6. Sixteen unreadable files ahead of a signed revoke.
        def junk(d):
            for i in range(16):
                p = os.path.join(d, f"admin-request-a6-junk-{i:02d}.json")
                with open(p, "w", encoding="utf-8") as f:
                    f.write("{}")
                os.chmod(p, 0o440)
        in_admin_dir(s, junk)
        rv = admin_file(s, "zz-a6-revoke", kind="revoke")
        out["rv"] = rv
        time.sleep(SETTLE)
        out["steps"]["full"] = {"decided": decided(s, rv["request_id"]), "shown": shown(s, rv["file"]),
                                "health": s.health()}
        in_admin_dir(s, lambda d: [os.remove(os.path.join(d, f"admin-request-a6-junk-{i:02d}.json")) for i in range(16)])
        harness.wait_for(lambda: (shown(s, rv["file"]) or {}).get("state") in ("accepted", "refused"), 3 * RELAY)
        out["steps"]["full"].update(after=decided(s, rv["request_id"]), after_shown=shown(s, rv["file"]))

        # 7. A decided file behind the cap: the scan is partial, so the
        # node must not forget the revoke it cannot see, and when the
        # junk goes it sends nothing again.
        in_admin_dir(s, junk)
        time.sleep(SETTLE)
        in_admin_dir(s, lambda d: [os.remove(os.path.join(d, f"admin-request-a6-junk-{i:02d}.json")) for i in range(16)])
        time.sleep(SETTLE)
        out["steps"]["hidden"] = {"decided": decided(s, rv["request_id"]), "shown": shown(s, rv["file"])}

        # 8. admin_dir left writable by its owner (the node's account on
        # this platform): nothing in it is read until it is 0550 again.
        d = s.layout["admin_dir"]
        os.chmod(d, 0o750)
        try:
            i3 = admin_file(s, "a6-install-3")
            out["i3"] = i3
            os.chmod(d, 0o750)  # admin_file puts 0550 back
            time.sleep(SETTLE)
            out["steps"]["open_dir"] = {"decided": decided(s, i3["request_id"]), "shown": shown(s, i3["file"]),
                                        "health": s.health()}
        finally:
            os.chmod(d, 0o550)
        harness.wait_for(lambda: (shown(s, i3["file"]) or {}).get("state") in ("accepted", "refused"), 3 * RELAY)
        out["steps"]["open_dir"]["after"] = decided(s, i3["request_id"])
    finally:
        if stopped:
            s.procs["collector"].send_signal(signal.SIGCONT)
        s.stop()
    out["decisions"] = decisions(s)
    with open(os.path.join(s.layout["collector_data"], "collector", "state", "state.json"), encoding="utf-8") as f:
        out["held"] = json.load(f).get("admin_decisions", {})
    out["audit"] = [r for r in audit(s) if r["action"] == "collector.request" and
                    str(r.get("correlation_id", "")).startswith("admin-")]
    print(json.dumps({k: v for k, v in out.items() if k != "audit"}, indent=1, default=str))
    return out


def test_a_restart_sends_nothing_again(got):
    st = got["steps"]["restart"]
    assert [d["status"] for d in st["i1"]] == ["accepted"], st
    assert st["shown"]["state"] == "accepted", st


def test_refused_requests_are_decided_once_and_not_sent_again(got):
    st = got["steps"]["refused"]
    for k in ("t", "e"):
        assert [d["status"] for d in st[k]["decided"]] == ["refused"], (k, st[k])
        assert st[k]["shown"]["state"] == "refused", (k, st[k])
        assert got[k]["request_id"] in st["relayed"], (k, st["relayed"])
    # The alarm names the check; health's file line gives the code only.
    assert f"in {got['t']['file']}: admin_unverified, check signature" in st["health"], st["health"]
    assert f"in {got['e']['file']}: admin_unverified, check window" in st["health"], st["health"]


def test_a_file_the_node_could_write_is_never_read(got):
    st = got["steps"]["refused"]["w"]
    assert st["decided"] == [], st
    assert st["shown"]["state"] == "unread" and "request_id" not in st["shown"], st
    assert "ADMIN REQUEST UNREAD " + got["w"]["file"] in got["steps"]["refused"]["health"]


@pytest.mark.parametrize("k", ["bn", "bk"])
def test_a_malformed_claim_is_never_sent(got, k):
    # A valid signature over a nonce claim the collector's pattern refuses,
    # or an envelope key ID that is not one: the node reads the claims to
    # record them, so it refuses the file instead of sending it, and the
    # collector never decides it.
    st = got["steps"]["refused"][k]
    assert st["decided"] == [], st
    assert st["shown"]["state"] == "unread" and "request_id" not in st["shown"], st
    assert "ADMIN REQUEST UNREAD " + got[k]["file"] in got["steps"]["refused"]["health"]


@pytest.mark.parametrize("step", ["stale", "none"])
def test_an_old_or_missing_checkpoint_sends_nothing_again(got, step):
    st = got["steps"][step]
    assert [d["status"] for d in st["i1"]] == ["accepted"], st
    assert [d["status"] for d in st["t"]] == ["refused"], st
    assert [d["status"] for d in st["e"]] == ["refused"], st
    if step == "stale":
        # Folded from the audit stream, past the old checkpoint's through_seq.
        assert got["t"]["request_id"] in st["relayed"] and got["e"]["request_id"] in st["relayed"], st


def repeat_of(d):
    return int(d.get("repeat_of") or 0)


def test_a_lost_refusal_is_a_replay_and_the_node_says_it_may_have_applied(got):
    st = got["steps"]["lost_refused"]
    f = got["i2r"]["file"]
    assert st["info_seen"], "the node did not record the request before the collector was stopped"
    statuses = [d["status"] for d in st["decided"]]
    # The install budget is taken before the version is checked.
    assert st["installs"] == 1, st
    if st["while_down"]:
        # The collector refused the orphaned request (version 1 is held)
        # and could not reply; it kept no decision to repeat, so the
        # resend is a replay, and the node says what that may mean.
        assert [d["status"] for d in st["while_down"]] == ["unwritten"], st
        assert statuses == ["unwritten", "refused"] and st["decided"][1]["refusal"] == "admin_unverified", st
        assert st["shown"]["state"] == "refused", st
        assert (f"in {f}: admin_unverified, check replay. It is not sent again; "
                "it may already have been applied") in st["health"], st["health"]
    else:
        assert statuses == ["refused"] and st["shown"]["state"] == "refused", st
    assert ("cred_7f3k2m9q4x", 2, "active") not in st["versions"], st


def test_a_lost_acceptance_is_repeated_and_installed_once(got):
    st = got["steps"]["lost"]
    f = got["i2"]["file"]
    assert st["info_seen"], "the node did not record the request before the collector was stopped"
    statuses = [d["status"] for d in st["decided"]]
    assert st["installs"] == 1, st
    if st["while_down"]:
        # The collector accepted the orphaned rotation and could not reply.
        # The resend is the same signed bytes inside their window: the
        # collector answers with the first decision and runs nothing.
        assert [d["status"] for d in st["while_down"]] == ["unwritten"], st
        assert statuses == ["unwritten", "accepted"], st
        first, again = st["decided"]
        assert repeat_of(again) == int(first["collector_seq"]) and int(again["collector_seq"]) > repeat_of(again), st
    else:
        assert statuses == ["accepted"] and repeat_of(st["decided"][0]) == 0, st
    assert st["shown"]["state"] == "accepted", st
    assert f"in {f}:" not in st["health"], st["health"]
    assert [v for v in st["versions"] if v[0] == "cred_7f3k2m9q4x"] == [
        ("cred_7f3k2m9q4x", 1, "revoked"), ("cred_7f3k2m9q4x", 2, "active")], st


def test_runs_go_on_after_the_relay(got):
    st = got["steps"]["lost"]
    assert st["run_after"], st
    assert re.search(r"last run ok at", st["run_health"]), st["run_health"]


def test_a_file_put_back_changes_nothing(got):
    # i1's nonce is still held, so the put-back file is the same signed
    # bytes inside their window: the repeat answer, and nothing runs. Run
    # again, version 1 would be refused, since version 2 is now held.
    st = got["steps"]["forget"]
    assert st["shown_gone"] is None, st
    first, *rest = st["decided"]
    assert first["status"] == "accepted" and repeat_of(first) == 0, st
    assert [d["status"] for d in rest] == ["accepted"], st
    assert repeat_of(rest[0]) == int(first["collector_seq"]), st
    assert st["installs"] == 0, st
    assert [v for v in st["versions"] if v[0] == "cred_7f3k2m9q4x"] == [
        ("cred_7f3k2m9q4x", 1, "revoked"), ("cred_7f3k2m9q4x", 2, "active")], st
    assert st["shown"]["state"] == "accepted", st


def test_sixteen_places_then_the_revoke(got):
    st = got["steps"]["full"]
    assert st["decided"] == [] and st["shown"] is None, st
    assert "admin-request-unread" in st["health"], st["health"]
    assert [d["status"] for d in st["after"]] == ["accepted"], st
    assert st["after_shown"]["state"] == "accepted", st


def test_a_decided_file_behind_the_cap_is_not_sent_again(got):
    st = got["steps"]["hidden"]
    assert [d["status"] for d in st["decided"]] == ["accepted"], st
    assert st["shown"]["state"] == "accepted", st


def test_nothing_is_read_from_an_admin_dir_that_can_be_written(got):
    st = got["steps"]["open_dir"]
    assert st["decided"] == [] and st["shown"] is None, st
    assert "admin_dir refused" in st["health"], st["health"]
    # Read once the directory is 0550 again, and decided once.
    assert len(st["after"]) == 1, st


def test_the_collector_never_accepts_a_request_twice(got):
    # A repeat answer names the first acceptance and runs nothing; it is
    # not a second acceptance.
    accepted = [d["request_id"] for d in got["decisions"] if d["status"] == "accepted" and repeat_of(d) == 0]
    assert len(accepted) == len(set(accepted)), got["decisions"]


def test_the_log_holds_every_decision_the_collector_kept(got):
    """A second oracle for the first (A5 on #195): each acceptance the
    collector's state keeps for a repeat is a first acceptance in its log
    under the same collector_seq, so a log the parser cannot read fails
    here instead of passing with nothing seen."""
    assert len(got["held"]) >= 2, got["held"]  # the rotation and the revoke; i1 too while its nonce is held
    logged = {int(d["collector_seq"]) for d in got["decisions"] if d["status"] in ("accepted", "unwritten")
              and repeat_of(d) == 0}
    for nonce, d in got["held"].items():
        assert d["collector_seq"] in logged, (nonce, d, sorted(logged))


def test_every_decision_follows_its_record_and_matches_the_collector(got):
    """For each relayed request ID: the info record (actor the node, claims
    unverified) comes first; each decision record names the collector_seq
    the collector logged for it, in the collector's order; an acceptance's
    actor is the person, a refusal's the node."""
    by_id = {}
    for r in got["audit"]:
        by_id.setdefault(r["correlation_id"], []).append(r)
    coll = {}
    for d in got["decisions"]:
        if d["request_id"].startswith("admin-"):
            coll.setdefault(d["request_id"], []).append(d)
    assert set(by_id) >= {i for i in coll}, (sorted(by_id), sorted(coll))
    for rid, recs in by_id.items():
        assert recs[0]["outcome"] == "info", (rid, recs)
        decs = [r for r in recs if r["outcome"] != "info"]
        for r in recs:
            if r["outcome"] == "info":
                assert r["actor"]["type"] == "node", r
                assert "unverified" in r["detail"] and "nonce " in r["detail"] and "key ed25519-" in r["detail"], r
        # Every decision the node recorded is one the collector logged,
        # with the same number; the lost reply's acceptance is the one the
        # node could not record.
        logged = [(d["status"], int(d["collector_seq"])) for d in coll.get(rid, [])]
        for r in decs:
            want = "accepted" if r["outcome"] == "allowed" else "refused"
            assert (want, r["collector_seq"]) in logged, (rid, r, logged)
            if r["outcome"] == "allowed":
                assert r["actor"] == {"type": "human", "id": "admin@site-a", "role": "admin"}, r
            else:
                assert r["actor"]["type"] == "node" and r.get("reason_code"), r


def test_no_secret_in_the_relay_records(got):
    for r in got["audit"]:
        assert CANARY not in json.dumps(r), r

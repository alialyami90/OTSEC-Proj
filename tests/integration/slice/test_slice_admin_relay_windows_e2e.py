r"""The node's relay of an administrator's signed requests against the
installed Windows services, and config\admin's ACLs (B6, P4-B6: gate item
1's owed check, docs/phase-3-exit.md; the rule is protect.CheckDirFor and
protect.ReadFileFor with node.AdminReaders, platform/store/protect).

Service mode only (OTSEC_SLICE_SERVICE=1, elevated, Windows): the node and
the collector are the installed otsec-node and otsec-collector services,
and admin_dir is the installed %ProgramData%\OTSEC\config\admin. One
slice. Its credential.install already goes through the relay. Then:

  1. The node is killed and started again: nothing is sent again.
  2. A tampered request and an expired one are refused, once each.
  3. The reply is lost, twice, as on Linux: the collector is suspended
     (NtSuspendProcess, Windows' SIGSTOP) while a new install is relayed,
     the node is killed waiting for the reply, and the collector resumes.
     An install it refuses (version 1 again) and a rotation to version 2
     it accepts, whose resend gets the repeat answer (C7 0.5).
  4. Files the rule refuses, left while the node is stopped so that none
     can be read before its ACL is changed: a file that grants the node's
     service write; one that grants Users read; one owned by the node's
     service; one with a second hard link; and a symbolic link to a
     signed file. None is sent. Each is then put right (its DACL reset,
     its owner set back to Administrators, the second link removed, the
     link replaced by the file) and is decided once.
  5. config\admin itself made to inherit its DACL, and then made to grant
     Users write: nothing in it is read, and a file left meanwhile is
     decided once after the DACL is put back exactly as the installer
     wrote it (compared as SDDL).

Every file in steps 4 and 5 is tampered after signing, so the collector
refuses it at the signature check, before its install budget (10 an
hour): reading such a file after the fix is visible as one decision, and
spends nothing. The oracle for "sent" is the collector's own log, here
its Application log events: one "request decided" event per decision.

Not repeated here, because they are the same code on both platforms and
run in CI's Linux admin_relay leg: the stale and missing checkpoint, the
forgotten-and-put-back file, the sixteen-file cap and the malformed
claims. Linux's mode rule (0440 files in a 0550 folder) has its Windows
counterpart in steps 4 and 5.

Evidence class: simulated (a hosted Windows Server VM, loopback, test
keys, the recording simulator).
"""

import ctypes
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time

import pytest

import harness
from conftest import need
from slicerun import CANARY, SERVICE, Slice, read_live

pytestmark = pytest.mark.skipif(
    not (os.name == "nt" and SERVICE),
    reason="Windows service mode only (OTSEC_SLICE_SERVICE=1): it checks the installed config\\admin's DACL; "
           "Linux runs test_slice_admin_relay_e2e.py")

RELAY = 15      # platform/node RelayEverySeconds
SETTLE = RELAY + 8  # the relay at start and one tick after it

NODE_SVC = r"NT SERVICE\otsec-node"
USERS = "*S-1-5-32-545"
ADMINS = "*S-1-5-32-544"

# Linux's log line, msg="..." with quoted values, and the Event Log's
# description, the message and its attributes as key=value (serve_windows).
DECIDED = re.compile(r'(?:msg=")?collector: (request decided|reply not written)"? (.*)$', re.M)
KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')


def decisions(s):
    """The collector's own decisions, in its order, from its events."""
    out = []
    for m in DECIDED.finditer(s.text("collector")):
        kv = {k: (json.loads(v) if v.startswith('"') else v) for k, v in KV.findall(m.group(2))}
        if m.group(1) == "reply not written":
            kv["status"] = "unwritten"
        out.append(kv)
    return out


def decided(s, rid):
    return [d for d in decisions(s) if d.get("request_id") == rid]


def installs(s):
    path = os.path.join(s.layout["collector_data"], "collector", "state", "state.json")
    return len(json.loads(read_live(path)).get("installs", []))


def credential_versions(s):
    path = os.path.join(s.layout["collector_data"], "collector", "credentials", "credentials.json")
    return [(e["ref"]["id"], e["ref"]["version"], e["status"]["state"])
            for e in json.loads(read_live(path)).get("entries", [])]


def admin_file(s, name, kind="install", expires="10m", tamper=False, version=1):
    env = dict(os.environ, OTSEC_SLICE_SECRET=CANARY)
    argv = [s.exe("slicehelper"), "admin-file", "-root", s.root, "-kind", kind, "-name", name,
            "-expires", expires, "-version", str(version)]
    if tamper:
        argv.append("-tamper")
    out = subprocess.run(argv, capture_output=True, text=True, env=env)
    assert out.returncode == 0, out.stderr
    f = json.loads(out.stdout)
    f["path"] = os.path.join(s.layout["admin_dir"], f["file"])
    return f


def status(s):
    return json.loads(read_live(os.path.join(s.layout["store_dir"], "status.json")))


def shown(s, name):
    for a in status(s).get("admin_requests", []):
        if a["file"] == name:
            return a
    return None


def audit(s):
    db = sqlite3.connect(f"file:{os.path.join(s.layout['store_dir'], 'audit.db')}?mode=ro", uri=True)
    try:
        return [json.loads(ev) for (ev,) in db.execute("SELECT event FROM events WHERE stream = 'audit' ORDER BY seq")]
    finally:
        db.close()


def run(argv):
    out = subprocess.run(argv, capture_output=True, text=True)
    assert out.returncode == 0, f"{argv}: exit {out.returncode}: {out.stdout}{out.stderr}"
    return out.stdout


def icacls(path, *args):
    return run(["icacls", path, *args])


def sddl(path):
    """The object's owner and DACL as SDDL, read with GetNamedSecurityInfoW.
    Not Get-Acl: Windows PowerShell started from the runner's pwsh inherits
    pwsh's PSModulePath and cannot load Microsoft.PowerShell.Security (run
    40581770237)."""
    from ctypes import wintypes
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv.GetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p)]
    adv.GetNamedSecurityInfoW.restype = wintypes.DWORD
    adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p]
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    info = 0x1 | 0x4  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    sd = ctypes.c_void_p()
    err = adv.GetNamedSecurityInfoW(str(path), 1, info, None, None, None, None, ctypes.byref(sd))  # SE_FILE_OBJECT
    if err:
        raise ctypes.WinError(err)
    try:
        text = wintypes.LPWSTR()
        if not adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, info, ctypes.byref(text), None):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            k32.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        k32.LocalFree(sd)


SDDL = re.compile(r"^O:(?P<owner>[^:]+?)(?:G:[^:]+?)?D:(?P<flags>[A-Z]*)(?P<aces>(?:\([^)]*\))*)")


def rule_view(s):
    """What the rule reads of an SDDL string: the owner, whether the DACL
    is protected, and its entries in order. The auto-inherit flags and the
    group are left out: the rule does not read them, and how an object got
    its DACL can set them differently for the same entries."""
    m = SDDL.match(s)
    assert m, s
    return {"owner": m["owner"], "protected": "P" in m["flags"], "aces": re.findall(r"\([^)]*\)", m["aces"])}


def writable(path):
    """Clears the read-only attribute slicehelper's 0440 sets on Windows."""
    os.chmod(path, 0o666)


def _suspend(pid, resume=False):
    """NtSuspendProcess or NtResumeProcess on pid, with SeDebugPrivilege
    enabled in this elevated process: the service runs as its own virtual
    account, whose process an administrator opens only with it."""
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    nt = ctypes.WinDLL("ntdll")

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", LUID), ("Attributes", wintypes.DWORD)]

    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
    adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                          wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
    nt.NtSuspendProcess.argtypes = nt.NtResumeProcess.argtypes = [wintypes.HANDLE]
    nt.NtSuspendProcess.restype = nt.NtResumeProcess.restype = wintypes.LONG

    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x20 | 0x8, ctypes.byref(tok)):  # ADJUST_PRIVILEGES, QUERY
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        tp = TOKEN_PRIVILEGES(1, LUID(), 0x2)  # SE_PRIVILEGE_ENABLED
        if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(tp.Luid)):
            raise ctypes.WinError(ctypes.get_last_error())
        adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None)
        if ctypes.get_last_error() != 0:  # ERROR_NOT_ALL_ASSIGNED: not held
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        k32.CloseHandle(tok)
    h = k32.OpenProcess(0x0800, False, pid)  # PROCESS_SUSPEND_RESUME
    if not h:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        st = (nt.NtResumeProcess if resume else nt.NtSuspendProcess)(h)
        if st != 0:
            raise OSError(f"{'NtResumeProcess' if resume else 'NtSuspendProcess'}({pid}): NTSTATUS {st & 0xffffffff:#x}")
    finally:
        k32.CloseHandle(h)


def restart_node(s, before=None):
    """Kills the node (taskkill /F), runs before() while it is down, starts
    it again through the SCM and lets it relay at start and on one tick."""
    s.kill("node")
    if before:
        before()
    s.respawn("node")
    time.sleep(SETTLE)


def settled(s, files):
    """Waits until the node shows each file decided, or 3 relay ticks."""
    return harness.wait_for(lambda: all((shown(s, f["file"]) or {}).get("state") in ("accepted", "refused")
                                        for f in files), 3 * RELAY, step=1.0)


@pytest.fixture(scope="module")
def got(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    s = Slice(str(tmp_path_factory.mktemp("slice-admin-relay-win")))
    s.build()
    out = {"steps": {}}
    suspended = None
    try:
        s.start()
        d = s.layout["admin_dir"]
        out["dir_sddl"] = rule_view(sddl(d))
        st = status(s)["admin_requests"]
        assert len(st) == 1 and st[0]["state"] == "accepted", st
        i1 = {"file": st[0]["file"], "request_id": st[0]["request_id"]}
        out["i1"] = i1
        out["steps"]["start"] = {"i1": decided(s, i1["request_id"]), "file_sddl": sddl(os.path.join(d, i1["file"]))}
        out["steps"]["start"]["dir_sddl"] = sddl(d)

        # 1. A restart sends nothing again.
        restart_node(s)
        out["steps"]["restart"] = {"i1": decided(s, i1["request_id"]), "shown": shown(s, i1["file"])}

        # 2. Refused by the collector, once each.
        t = admin_file(s, "b6-tampered", tamper=True)
        e = admin_file(s, "b6-expired", expires="-5m")
        out.update(t=t, e=e)
        settled(s, (t, e))
        time.sleep(RELAY + 3)  # another tick: nothing is sent again
        out["steps"]["refused"] = {k: {"decided": decided(s, f["request_id"]), "shown": shown(s, f["file"])}
                                   for k, f in (("t", t), ("e", e))}
        out["steps"]["refused"]["health"] = s.health()

        # 3. The reply is lost.
        def lose_reply(name, version):
            nonlocal suspended
            before = installs(s)
            pid = s.procs["collector"].pid
            _suspend(pid)
            suspended = pid
            f = admin_file(s, name, version=version)
            st = {"info_seen": harness.wait_for(
                lambda: any(r["action"] == "collector.request" and r.get("correlation_id") == f["request_id"]
                            and r["outcome"] == "info" for r in audit(s)), 3 * RELAY, step=0.5)}
            time.sleep(2)
            s.kill("node")
            _suspend(pid, resume=True)
            suspended = None
            time.sleep(3)
            st["while_down"] = decided(s, f["request_id"])
            s.respawn("node")
            settled(s, (f,))
            time.sleep(RELAY + 3)
            st.update(decided=decided(s, f["request_id"]), shown=shown(s, f["file"]),
                      health=s.health(), installs=installs(s) - before, versions=credential_versions(s))
            return f, st

        out["i2r"], out["steps"]["lost_refused"] = lose_reply("b6-install-2-again", 1)
        out["i2"], out["steps"]["lost"] = lose_reply("b6-install-2", 2)

        # 4. Files the rule refuses, left while the node is stopped.
        s.service.stop("node")
        files = {}
        for k in ("write", "users", "owner", "hardlink", "symlink"):
            files[k] = admin_file(s, "b6-acl-" + k, tamper=True)
            writable(files[k]["path"])  # a read-only file cannot be unlinked
            files[k]["sddl"] = rule_view(sddl(files[k]["path"]))
        icacls(files["write"]["path"], "/grant", NODE_SVC + ":(W)")
        icacls(files["users"]["path"], "/grant", USERS + ":(R)")
        icacls(files["owner"]["path"], "/setowner", NODE_SVC)
        # The second name is outside admin_dir, on the same volume, inside
        # the installed tree that teardown removes.
        second = os.path.join(s.service.data, "b6-second-link.json")
        os.link(files["hardlink"]["path"], second)
        target = os.path.join(s.service.data, "b6-link-target.json")
        os.replace(files["symlink"]["path"], target)
        os.symlink(target, files["symlink"]["path"])
        s.respawn("node")
        time.sleep(SETTLE)
        out["files"] = {k: {kk: v[kk] for kk in ("file", "request_id", "sddl")} for k, v in files.items()}
        out["steps"]["acl"] = {k: {"decided": decided(s, f["request_id"]), "shown": shown(s, f["file"])}
                               for k, f in files.items()}
        out["steps"]["acl"]["health"] = s.health()

        icacls(files["write"]["path"], "/reset")
        icacls(files["users"]["path"], "/reset")
        icacls(files["owner"]["path"], "/setowner", ADMINS)
        os.remove(second)
        os.remove(files["symlink"]["path"])
        os.replace(target, files["symlink"]["path"])
        fixed = {k: rule_view(sddl(f["path"])) for k, f in files.items()}
        settled(s, files.values())
        time.sleep(RELAY + 3)
        out["steps"]["acl_fixed"] = {k: {"decided": decided(s, f["request_id"]), "shown": shown(s, f["file"]),
                                         "sddl": fixed[k]} for k, f in files.items()}

        # 5. config\admin's own DACL. The installer's DACL is saved with
        # icacls and put back from that copy.
        saved = os.path.join(s.d, "admin-dir.acl")
        parent = os.path.dirname(d)
        icacls(d, "/save", saved)

        def dir_case(name, change):
            change()
            f = admin_file(s, "b6-dir-" + name, tamper=True)
            time.sleep(SETTLE)
            st = {"decided": decided(s, f["request_id"]), "shown": shown(s, f["file"]),
                  "health": s.health(), "changed_sddl": rule_view(sddl(d))}
            icacls(parent, "/restore", saved)
            st["restored_sddl"] = rule_view(sddl(d))
            st["file_sddl"] = sddl(f["path"])  # for the log, if it is not read
            settled(s, (f,))
            time.sleep(RELAY + 3)
            st["after"] = decided(s, f["request_id"])
            st["after_shown"] = shown(s, f["file"])
            return f, st

        out["di"], out["steps"]["dir_inherits"] = dir_case("inherits", lambda: icacls(d, "/inheritance:e"))
        out["dw"], out["steps"]["dir_users_write"] = dir_case("users-write", lambda: icacls(d, "/grant", USERS + ":(W)"))
    finally:
        if suspended:
            _suspend(suspended, resume=True)
        s.stop()
    out["decisions"] = decisions(s)
    path = os.path.join(s.layout["collector_data"], "collector", "state", "state.json")
    with open(path, encoding="utf-8") as f:
        out["held"] = json.load(f).get("admin_decisions", {})
    out["audit"] = [r for r in audit(s) if r["action"] == "collector.request" and
                    str(r.get("correlation_id", "")).startswith("admin-")]
    print(json.dumps({k: v for k, v in out.items() if k != "audit"}, indent=1, default=str))
    return out


def repeat_of(d):
    return int(d.get("repeat_of") or 0)


def test_the_install_at_start_went_through_the_relay(got):
    # The oracle reads the Event Log: if it read nothing, every "never
    # sent" below would pass on an empty list.
    assert [d["status"] for d in got["steps"]["start"]["i1"]] == ["accepted"], got["steps"]["start"]


def test_a_restart_sends_nothing_again(got):
    st = got["steps"]["restart"]
    assert [d["status"] for d in st["i1"]] == ["accepted"], st
    assert st["shown"]["state"] == "accepted", st


def test_refused_requests_are_decided_once(got):
    st = got["steps"]["refused"]
    for k in ("t", "e"):
        assert [d["status"] for d in st[k]["decided"]] == ["refused"], (k, st[k])
        assert st[k]["shown"]["state"] == "refused", (k, st[k])
    assert f"in {got['t']['file']}: admin_unverified, check signature" in st["health"], st["health"]
    assert f"in {got['e']['file']}: admin_unverified, check window" in st["health"], st["health"]


def test_a_lost_refusal_is_not_applied_twice(got):
    st = got["steps"]["lost_refused"]
    assert st["info_seen"], "the node did not record the request before the collector was suspended"
    assert st["installs"] == 1, st
    statuses = [d["status"] for d in st["decided"]]
    if st["while_down"]:
        assert [d["status"] for d in st["while_down"]] == ["unwritten"], st
        assert statuses == ["unwritten", "refused"] and st["decided"][1]["refusal"] == "admin_unverified", st
        assert (f"in {got['i2r']['file']}: admin_unverified, check replay. It is not sent again; "
                "it may already have been applied") in st["health"], st["health"]
    else:
        assert statuses == ["refused"], st
    assert st["shown"]["state"] == "refused", st
    assert ("cred_7f3k2m9q4x", 2, "active") not in st["versions"], st


def test_a_lost_acceptance_is_repeated_and_installed_once(got):
    st = got["steps"]["lost"]
    assert st["info_seen"], "the node did not record the request before the collector was suspended"
    assert st["installs"] == 1, st
    statuses = [d["status"] for d in st["decided"]]
    if st["while_down"]:
        assert [d["status"] for d in st["while_down"]] == ["unwritten"], st
        assert statuses == ["unwritten", "accepted"], st
        first, again = st["decided"]
        assert repeat_of(again) == int(first["collector_seq"]) and int(again["collector_seq"]) > repeat_of(again), st
    else:
        assert statuses == ["accepted"] and repeat_of(st["decided"][0]) == 0, st
    assert st["shown"]["state"] == "accepted", st
    assert [v for v in st["versions"] if v[0] == "cred_7f3k2m9q4x"] == [
        ("cred_7f3k2m9q4x", 1, "revoked"), ("cred_7f3k2m9q4x", 2, "active")], st


ACL_WHY = {
    "write": "a reader may only read and traverse",
    "users": "grants access to S-1-5-32-545",
    "owner": "the owner must be SYSTEM or Administrators",
    "hardlink": "has 2 hard links",
    "symlink": "a link or reparse point is refused",
}


@pytest.mark.parametrize("k", sorted(ACL_WHY))
def test_a_file_the_rule_refuses_is_never_sent(got, k):
    st = got["steps"]["acl"][k]
    assert st["decided"] == [], st
    assert st["shown"]["state"] == "unread" and "request_id" not in st["shown"], st
    assert ACL_WHY[k] in st["shown"]["detail"], st
    assert "ADMIN REQUEST UNREAD " + got["files"][k]["file"] in got["steps"]["acl"]["health"]


@pytest.mark.parametrize("k", sorted(ACL_WHY))
def test_a_file_put_right_is_decided_once(got, k):
    st = got["steps"]["acl_fixed"][k]
    # Tampered after signing: the collector refuses it at the signature,
    # so one refusal is one read.
    assert [d["status"] for d in st["decided"]] == ["refused"], st
    assert st["decided"][0]["refusal"] == "admin_unverified", st
    assert st["shown"]["state"] == "refused", st
    # Put right means as the administrator first left it.
    assert st["sddl"] == got["files"][k]["sddl"], st


DIR_WHY = {"dir_inherits": "inherits its DACL", "dir_users_write": "grants access to S-1-5-32-545"}


@pytest.mark.parametrize("step", sorted(DIR_WHY))
def test_nothing_is_read_from_an_admin_dir_the_rule_refuses(got, step):
    st = got["steps"][step]
    assert st["changed_sddl"] != got["dir_sddl"], st
    assert st["decided"] == [] and st["shown"] is None, st
    assert "admin_dir refused" in st["health"] and DIR_WHY[step] in st["health"], st["health"]
    # Read once the installer's DACL is back, and decided once.
    assert st["restored_sddl"] == got["dir_sddl"], st
    assert [d["status"] for d in st["after"]] == ["refused"], st
    assert st["after_shown"]["state"] == "refused", st


def test_the_collector_never_accepts_a_request_twice(got):
    accepted = [d["request_id"] for d in got["decisions"] if d["status"] == "accepted" and repeat_of(d) == 0]
    assert len(accepted) == len(set(accepted)), got["decisions"]


def test_the_log_holds_every_decision_the_collector_kept(got):
    """A second oracle for the first (A5 on #195): each acceptance the
    collector's state keeps for a repeat is a first acceptance in its
    Event Log events under the same collector_seq."""
    assert len(got["held"]) >= 1, got["held"]
    logged = {int(d["collector_seq"]) for d in got["decisions"] if d["status"] in ("accepted", "unwritten")
              and repeat_of(d) == 0}
    for nonce, d in got["held"].items():
        assert d["collector_seq"] in logged, (nonce, d, sorted(logged))


def test_every_decision_follows_its_record_and_matches_the_collector(got):
    by_id = {}
    for r in got["audit"]:
        by_id.setdefault(r["correlation_id"], []).append(r)
    coll = {}
    for d in got["decisions"]:
        if d["request_id"].startswith("admin-"):
            coll.setdefault(d["request_id"], []).append(d)
    assert set(by_id) >= set(coll), (sorted(by_id), sorted(coll))
    for rid, recs in by_id.items():
        assert recs[0]["outcome"] == "info", (rid, recs)
        logged = [(d["status"], int(d["collector_seq"])) for d in coll.get(rid, [])]
        for r in recs:
            if r["outcome"] == "info":
                continue
            want = "accepted" if r["outcome"] == "allowed" else "refused"
            assert (want, r["collector_seq"]) in logged, (rid, r, logged)


def test_no_secret_in_the_relay_records(got):
    for r in got["audit"]:
        assert CANARY not in json.dumps(r), r

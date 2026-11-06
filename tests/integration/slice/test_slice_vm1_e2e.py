"""V-M1 over GT-MIB on the real binaries (D6, D4-59).

One node polls one SNMPv3 asset per GT-MIB case (tests/integration/gt_mib/
cases.json), each at its own agent process on a loopback port, with its own
engine ID, credential reference and USM password. The collector holds C2's
sel-27x1-rstp test package, and each credential is installed through the
node's admin relay, as an administrator would. The case table gives what
each run must end with; the agents' own decoded logs, node status and the
store give what happened.

Evidence class: simulated. No device is contacted: every agent is GT-MIB,
built from the RFC texts, on 127.0.0.1. The passwords are test values made
for the run and held only in this process and the agents' environment.
"""

import base64
import hashlib
import json
import os
import glob
import secrets
import shutil
import sqlite3
import subprocess
import time

import pytest

import harness
from conftest import need
from slicerun import SERVICE, Slice, _go_build

GT = os.path.join(harness.REPO, "tests", "integration", "gt_mib")
TABLE = json.load(open(os.path.join(GT, "cases.json"), encoding="utf-8"))
CASES = {c["id"]: c for c in TABLE["cases"]}

# Refused before any run: at load (U13, M1, M2) or at the credential's
# install (U14). Each has its own test below.
REFUSED_BEFORE = {"U13", "U14", "M1", "M2"}
# M3 is a check over the ok runs, not a case of its own.
NOT_RUN = REFUSED_BEFORE | {"M3"}
# U15's next run must succeed, so it runs every 60 s (the profile's
# minimum) and the run waits for its second result.
SECOND_RUN = {"U15": 60}

ENTITY = "1.3.6.1.2.1.47.1.1.1"
SYSTEM_OIDS = {"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"}
FID = {
    "I2": ("SEL-2741M-R102-V1-Z003001-D20260408", "sel-2741"),
    "I6": ("SEL-2731M-R100-V0-Z001001-D20231120", None),
    # F6 declares product_family sel-2731 and reads a SEL-2741M.
    "F6": ("SEL-2741M-R102-V1-Z003001-D20260408", "sel-2731"),
}


def expected(case):
    """The case table's expectation for a case or a hostile layer."""
    if case in CASES:
        return CASES[case]["expect"]
    hid, _, layer = case.partition("/")
    h = TABLE["hostile"]
    for p in h["positive"]:
        if p["id"] == hid:
            return p["expect"]
    if hid == "H17":
        # Each non-Response PDU is discarded (cases.json), so the
        # request goes unanswered.
        return {"code": "failed.timeout"}
    return h["expect_" + layer]


def _password_to_key(digest, password):
    """RFC 3414 A.2 with RFC 7860's hash: Ku over 1 MiB of the password."""
    pw = password.encode()
    buf = (pw * (1048576 // len(pw) + 1))[:1048576]
    return hashlib.new(digest, buf).digest()


def _localize(digest, ku, engine):
    return hashlib.new(digest, ku + engine + ku).digest()


class Agent:
    """One GT-MIB process for one case."""

    def __init__(self, s, i, case):
        self.case = case
        self.engine = "80007c4f03" + "020000" + f"{0x270000 + i:06x}"
        self.asset = f"{0x6d000000 + i:08x}-1b3d-4e5f-8a7b-{i:012x}"
        self.ref = f"cred_gtmib{i:04d}"
        self.password = "gtmib-test-" + secrets.token_hex(8)
        self.log = os.path.join(s.d, f"gtmib-{case.replace('/', '-')}.jsonl")
        self.env = dict(os.environ, GTMIB_PASSWORD=self.password)
        self.p = subprocess.Popen([s.exe("gtmib"), "-case", case, "-listen", "127.0.0.1:0", "-log", self.log,
                                   "-engine-id", self.engine], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, env=self.env)
        line = self.p.stdout.readline().decode()
        assert line.startswith("listening "), f"gtmib {case}: {line}"
        self.port = int(line.split()[1].rsplit(":", 1)[1])
        out = subprocess.run([s.exe("gtmib"), "-secret", "-case", case, "-engine-id", self.engine],
                             env=self.env, capture_output=True, check=True)
        self.secret = out.stdout.decode().strip()
        ku = _password_to_key("sha256", self.password)
        kul = _localize("sha256", ku, bytes.fromhex(self.engine))
        assert self.secret == (kul + kul[:16]).hex(), case
        self.keys = [self.password.encode(), ku, kul, kul[:16]]

    def entry(self):
        e = {"case": self.case, "asset_id": self.asset, "port": self.port, "engine_id": self.engine, "ref": self.ref}
        if self.case in FID:
            fid, family = FID[self.case]
            e["firmware_id"] = fid
            if family:
                e["product_family"] = family
        if self.case in SECOND_RUN:
            e["every"] = SECOND_RUN[self.case]
        return e

    def records(self):
        return harness.read_log(self.log, live=self.p.poll() is None) if os.path.exists(self.log) else []

    def stop(self):
        if self.p.poll() is None:
            self.p.stdin.close()
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(10)


def status(s):
    with open(os.path.join(s.layout["store_dir"], "status.json"), encoding="utf-8") as f:
        return json.load(f)


def transcripts(s):
    """Each asset's collection.run records' kept transcripts, in order:
    (the capture's SHA-256 as stored, its bytes)."""
    out = {}
    for path in glob.glob(os.path.join(s.layout["store_dir"], "*.db")):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = db.execute("SELECT e.event, e.capture, c.bytes FROM events e LEFT JOIN captures c ON c.sha256 = e.capture "
                              "WHERE e.stream = 'platform/health' ORDER BY e.seq").fetchall()
        except sqlite3.OperationalError:
            rows = []
        finally:
            db.close()
        for ev, sha, b in rows:
            h = json.loads(ev).get("health", {})
            if h.get("type") == "collection.run":
                out.setdefault(h["details"]["asset_id"], []).append((sha, b))
    return out


def _results(s):
    try:
        return status(s).get("assets", {})
    except (OSError, ValueError):
        return {}


@pytest.fixture(scope="module")
def vm1(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "V-M1's run is a Linux runner's")
    s = Slice(str(tmp_path_factory.mktemp("vm1")))
    s.build()
    _go_build(s.exe("gtmib"), "./tests/integration/gt_mib/agent/cmd/gtmib")
    ids = subprocess.run([s.exe("gtmib"), "-list"], capture_output=True, text=True, check=True).stdout.split()
    agents = {}
    try:
        for i, case in enumerate(c for c in ids if c not in NOT_RUN):
            agents[case] = Agent(s, i + 1, case)
        spec = os.path.join(s.d, "gtmib.json")
        with open(spec, "w", encoding="utf-8") as f:
            json.dump([a.entry() for a in agents.values()], f)
        if os.environ.get("OTSEC_VM1_KEYS_OUT"):
            # For M3's search over the CI job's own output
            # (vm1_keysearch.py, which deletes the file).
            fd = os.open(os.environ["OTSEC_VM1_KEYS_OUT"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump([k.hex() for a in agents.values() for k in a.keys], f)
        # The node starts with the GT-MIB assets but none of their entries,
        # so every credential is installed before any of them runs, and
        # each agent sees exactly one run (two for U15).
        t0 = time.time()
        s.start(setup_extra=("-gtmib", spec))
        env = dict(os.environ, OTSEC_GTMIB_SECRETS_HEX=json.dumps({c: a.secret for c, a in agents.items()}))
        out = subprocess.run([s.exe("slicehelper"), "install-gtmib", "-root", s.root, "-gtmib", spec],
                             capture_output=True, env=env, text=True, timeout=900)
        assert out.returncode == 0, "credential installs: " + out.stderr + "\n" + s.text("node")[-3000:]
        s.installed_in = time.time() - t0
        assert not any(a.records() for a in agents.values()), "an agent was polled before the restart"
        s.procs["node"].terminate()
        s.procs["node"].wait(30)
        shutil.copyfile(s.layout["gtmib_node_config"], s.layout["node_config"])
        t0 = time.time()
        s.respawn("node")

        by_asset = {a.asset: c for c, a in agents.items()}
        first = {}

        def done():
            res = _results(s)
            for asset, r in res.items():
                c = by_asset.get(asset)
                if c and c not in first:
                    first[c] = dict(r)
            return all(by_asset[x] in first for x in by_asset) and all(
                res.get(agents[c].asset, {}).get("at") != first[c]["at"] for c in SECOND_RUN)

        ok = harness.wait_for(done, 120 + 40 * len(agents), step=2.0)
        s.elapsed = time.time() - t0
        assert ok, f"no result for {sorted(set(agents) - set(first))}\nhealth:\n{s.health()}"
        s.first, s.last = first, {by_asset[k]: v for k, v in _results(s).items() if k in by_asset}
        s.status = status(s)
        s.health_text = s.health()
        s.agents = agents
        s.stop()
        s.logs_by_case = {c: a.records() for c, a in agents.items()}
        s.transcripts = transcripts(s)
        s.refusals = refusals_before_any_run(s)
        yield s
    finally:
        for a in agents.values():
            a.stop()
        s.stop()


def _codes(vm1):
    return {c: vm1.first[c]["code"] for c in vm1.agents}


def test_every_case_ends_with_its_code(vm1):
    wrong = {}
    for c in vm1.agents:
        want = expected(c)["code"]
        got = vm1.first[c]["code"]
        if got != want:
            wrong[c] = (got, want, vm1.first[c].get("detail"))
    assert not wrong, json.dumps(wrong, indent=1)


def test_u15_next_run_succeeds(vm1):
    assert vm1.last["U15"]["code"] == "ok", vm1.last["U15"]


def _first_run(recs):
    """The records of the first run: up to the second run's discovery."""
    disc = [i for i, r in enumerate(recs) if r.get("discovery")]
    return recs[:disc[1]] if len(disc) > 1 else recs


def test_counts(vm1):
    wrong = {}
    for c, a in vm1.agents.items():
        exp = expected(c)
        recs = vm1.logs_by_case[c]
        if c in SECOND_RUN:
            recs = _first_run(recs)
        if "datagrams" in exp and len(recs) != exp["datagrams"]:
            wrong[c] = ("datagrams", len(recs), exp["datagrams"])
        auth = [r for r in recs if r.get("level") == "authPriv" or r.get("flags", 0) & 3 == 3]
        if "authenticated_requests" in exp and len(auth) != exp["authenticated_requests"]:
            wrong[c] = ("authenticated_requests", len(auth), exp["authenticated_requests"])
    assert not wrong, json.dumps(wrong, indent=1)


def _device_reads(vm1, case, name):
    ident = vm1.status.get("identity", {}).get(vm1.agents[case].asset, {})
    for at in ident.get("attributes", []):
        if at["name"] == name:
            return at["value"], [o for o in at["observations"] if o["source"].get("kind") == "device-read"]
    return None, []


def test_bytes_kept(vm1):
    """Every SNMP run that reached the agent keeps its transcript on its
    collection.run record, stored under the transcript's own SHA-256 (C8's
    transcript_sha256, bytes kept)."""
    wrong = []
    for c, a in vm1.agents.items():
        runs = vm1.transcripts.get(a.asset, [])
        if len(runs) != (2 if c in SECOND_RUN else 1):
            wrong.append(f"{c}: {len(runs)} collection.run records")
        for sha, b in runs:
            if vm1.logs_by_case[c] and (not b or hashlib.sha256(b).hexdigest() != sha):
                wrong.append(f"{c}: transcript {sha} of {len(b or b'')} bytes")
    assert not wrong, "\n".join(wrong)


def test_attributes(vm1):
    """Each attribute the table names was read from the operation and OID
    it names, with its value; the engine ID is each case's own, where the
    table gives C1's example (one per asset, D3's notes). The node stores
    an identity only from an ok run, so for a failed one the value is
    looked for in the run's kept transcript instead."""
    wrong = []
    for c in vm1.agents:
        exp = expected(c)
        if exp["code"] != "ok":
            kept = b"".join(b or b"" for _, b in vm1.transcripts.get(vm1.agents[c].asset, []))
            for name, want in exp.get("attributes", {}).items():
                v = bytes.fromhex(vm1.agents[c].engine) if name == "snmp_engine_id" else want["value"].encode()
                if v not in kept:
                    wrong.append(f"{c} {name}: not in the kept transcript")
            continue
        for name, want in exp.get("attributes", {}).items():
            value = vm1.agents[c].engine if name == "snmp_engine_id" else want["value"]
            got, reads = _device_reads(vm1, c, name)
            if got != value or not reads or any(o["value"] != value for o in reads):
                wrong.append(f"{c} {name}: {got} {reads}, want {value}")
                continue
            r = reads[-1]["source"].get("read", {})
            for k in ("operation", "oid"):
                if k in want and r.get(k) != want[k]:
                    wrong.append(f"{c} {name}: read {r}, want {k} {want[k]}")
            if want.get("operation") and r.get("transport") != "snmpv3":
                wrong.append(f"{c} {name}: transport {r}")
        for name in exp.get("absent", []):
            if _device_reads(vm1, c, name)[1]:
                wrong.append(f"{c} {name}: read, but the table says absent")
    assert not wrong, "\n".join(wrong)


def test_f6_health_shows_the_family_conflict(vm1):
    """F6: the run is ok, the read model is kept, and health shows
    identity.family_conflict (the plan's 2.2; modules/asset FamilyConflict,
    C5 on #445)."""
    got, reads = _device_reads(vm1, "F6", "model")
    assert vm1.first["F6"]["code"] == "ok" and got == "SEL-2741M" and reads, (vm1.first["F6"], got)
    f6 = vm1.agents["F6"].asset
    assert "family_conflict" in vm1.health_text or "family_conflict" in json.dumps(vm1.status), \
        [line for line in vm1.health_text.splitlines() if f6 in line]


def test_every_run(vm1):
    """cases.json every_run, over every agent's decoded log."""
    bad = []
    for c, recs in vm1.logs_by_case.items():
        disc = 0
        for r in recs:
            where = f"{c} #{r['n']}"
            if r.get("community") is not None or r.get("version") != 3:
                bad.append(f"{where}: not an SNMPv3 message")
                continue
            if r["max_size"] != 1472:
                bad.append(f"{where}: msgMaxSize {r['max_size']}")
            if r["discovery"]:
                disc += 1
            elif r["flags"] & 3 != 3:
                bad.append(f"{where}: msgFlags {r['flags']}")
            p = r.get("pdu")
            if not p or r["discovery"]:
                continue
            if p["type"] == "GetRequest":
                if not {b["oid"] for b in p["varbinds"]} <= SYSTEM_OIDS:
                    bad.append(f"{where}: get of {p['varbinds']}")
            elif p["type"] == "GetBulkRequest":
                if p["f1"] != 0 or p["f2"] != 16 or len(p["varbinds"]) != 1 or not p["varbinds"][0]["oid"].startswith(ENTITY):
                    bad.append(f"{where}: bulk {p}")
            else:
                bad.append(f"{where}: PDU {p['type']}")
        if disc > 2:
            bad.append(f"{c}: {disc} discovery messages")
    assert not bad, "\n".join(bad)


def test_m3_no_key_anywhere(vm1):
    """M3: no password, Ku, localized key or AES key, raw, hex in either
    case or base64, anywhere in the run's folder (the node's store and
    configuration, the collector's data with its credential store and
    state, every log, every agent's log) or in health. The binaries are
    left out. A hit names the case, the key and the form, never the key."""
    forms = {"raw": lambda k: k, "hex": lambda k: k.hex().encode(), "HEX": lambda k: k.hex().upper().encode(),
             "base64": base64.b64encode}
    names = ("password", "Ku", "localized key", "AES key")
    hay = {"health": vm1.health_text.encode()}
    for d, dirs, files in os.walk(vm1.d):
        if d == vm1.d:
            dirs[:] = [x for x in dirs if os.path.join(d, x) != vm1.bin]
        for f in files:
            with open(os.path.join(d, f), "rb") as fh:
                hay[os.path.join(d, f)] = fh.read()
    assert any(p.startswith(vm1.layout["collector_data"]) for p in hay), "the collector's data was not searched"
    found = [(where, c, names[i], form) for c, a in vm1.agents.items() for i, k in enumerate(a.keys)
             for form, enc in forms.items() for where, b in hay.items() if enc(k) in b]
    assert not found, found


def _node_refuses(s, name, change):
    """Runs the node binary on a copy of the run's configuration, changed
    by change, after the run's node has stopped. What it printed, its exit
    code (None: it loaded and ran), and the datagrams the agents received
    meanwhile."""
    with open(s.layout["node_config"], encoding="utf-8") as f:
        cfg = json.load(f)
    change(cfg)
    path = os.path.join(s.d, name + "-node.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    before = sum(len(a.records()) for a in s.agents.values())
    try:
        out = subprocess.run([s.exe("otsec"), "node", "-config", path], capture_output=True, text=True, timeout=30)
        code, text = out.returncode, out.stdout + out.stderr
    except subprocess.TimeoutExpired as e:
        code, text = None, str(e.stdout or b"")
    return {"code": code, "out": text, "datagrams": sum(len(a.records()) for a in s.agents.values()) - before}


def _snmp_assets(cfg):
    return [a for a in cfg["assets"] if any(e.get("id") == "mgmt-snmpv3" for e in a.get("endpoints", []))]


def _m1(cfg):
    cfg.pop("asset", None)


def _m2(cfg):
    cfg.pop("asset", None)
    cfg["applicability"] = {"anchors": []}
    ids = {a["asset_id"] for a in _snmp_assets(cfg)}
    cfg["schedule"] = [e for e in cfg["schedule"] if e["asset_id"] not in ids]


def _u13(cfg):
    for a in _snmp_assets(cfg):
        for e in a["endpoints"]:
            e["transport"] = "snmpv2c"


LOAD_REFUSALS = {"M1": (_m1, "asset"), "M2": (_m2, "applicability"), "U13": (_u13, "snmpv2c")}
U14 = [("hmac-md5", "aes-128"), ("hmac-sha", "aes-128"), ("hmac-sha-256", "des"), ("hmac-sha-256", "aes-256")]


def refusals_before_any_run(s):
    """M1, M2, U13 and U14, with the run's node stopped and the agents still
    listening."""
    r = {c: _node_refuses(s, c.lower(), change) for c, (change, _) in LOAD_REFUSALS.items()}
    # U14: C7 0.8's enums cannot name MD5, SHA-1, DES or AES-256, so the
    # install is refused while it is built, before any request leaves
    # (contracts/authz/usm_test.go holds the decode side).
    a = s.agents["I1"]
    for auth, priv in U14:
        before = len(a.records())
        env = dict(os.environ, OTSEC_SLICE_SECRET_HEX=a.secret)
        out = subprocess.run([s.exe("slicehelper"), "install-credential", "-root", s.root, "-snmp-asset", a.asset,
                              "-snmp-ref", a.ref, "-usm-engine-id", a.engine, "-usm-auth", auth, "-usm-priv", priv],
                             capture_output=True, env=env, text=True, timeout=120)
        r[f"U14 {auth} {priv}"] = {"code": out.returncode, "out": out.stderr, "datagrams": len(a.records()) - before}
    return r


@pytest.mark.parametrize("case", sorted(LOAD_REFUSALS))
def test_refused_at_load(vm1, case):
    r = vm1.refusals[case]
    assert r["code"] not in (0, None) and LOAD_REFUSALS[case][1] in r["out"], r
    assert r["datagrams"] == 0, r


@pytest.mark.parametrize("auth,priv", U14)
def test_u14_a_credential_naming_md5_sha1_des_or_aes256_cannot_be_made(vm1, auth, priv):
    r = vm1.refusals[f"U14 {auth} {priv}"]
    assert r["code"] != 0 and "authz: usm" in r["out"], r
    assert r["datagrams"] == 0, r


# V-M1 (a), D4-50's three module combinations. The run above is "asset
# alone" (asset on, applicability off). The two others run I1 alone.


def _combination(tmp_path_factory, name, with_entry, extra=()):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "V-M1's run is a Linux runner's")
    s = Slice(str(tmp_path_factory.mktemp(name)))
    if "-vm8" in extra:
        # Advisory test key 0 loads only in a test build (V-M8's).
        s.node_tags = ("otsec_testclock",)
    s.build()
    _go_build(s.exe("gtmib"), "./tests/integration/gt_mib/agent/cmd/gtmib")
    a = Agent(s, 1, "I1")
    try:
        if not with_entry:
            # Both off: no SNMP entry, and the asset module off. The agent
            # listens for a whole schedule period and the SEL-751's run.
            s.start()
            rows = harness.wait_for(lambda: s.ser_received(), 150, step=1.0)
            assert rows, s.health()
            time.sleep(5)
            s.health_text, s.status, s.agent_log = s.health(), status(s), a.records()
            return s
        spec = os.path.join(s.d, "gtmib.json")
        with open(spec, "w", encoding="utf-8") as f:
            json.dump([a.entry()], f)
        s.start(setup_extra=("-gtmib", spec, *extra))
        env = dict(os.environ, OTSEC_GTMIB_SECRETS_HEX=json.dumps({"I1": a.secret}))
        out = subprocess.run([s.exe("slicehelper"), "install-gtmib", "-root", s.root, "-gtmib", spec],
                             capture_output=True, env=env, text=True, timeout=300)
        assert out.returncode == 0, out.stderr
        s.procs["node"].terminate()
        s.procs["node"].wait(30)
        shutil.copyfile(s.layout["gtmib_node_config"], s.layout["node_config"])
        s.respawn("node")
        assert harness.wait_for(lambda: _results(s).get(a.asset), 150, step=1.0), s.health()
        s.result = _results(s)[a.asset]
        s.health_text, s.status, s.agent_log = s.health(), status(s), a.records()
        return s
    finally:
        a.stop()
        s.stop()


@pytest.fixture(scope="module")
def both_off(tmp_path_factory):
    return _combination(tmp_path_factory, "vm1-both-off", False)


@pytest.fixture(scope="module")
def both_on(tmp_path_factory):
    # -vm8: the asset module and applicability on, with advisory test key 0
    # pinned and no set.
    return _combination(tmp_path_factory, "vm1-both-on", True, ("-vm8",))


def test_a_both_off_the_agent_receives_nothing(both_off):
    assert both_off.agent_log == [], both_off.agent_log
    assert not both_off.status.get("identity"), both_off.status.get("identity")


def test_a_asset_alone_reads_the_identity(vm1):
    assert vm1.first["I1"]["code"] == "ok"
    assert "applicability" not in vm1.status, vm1.status.get("applicability")


def test_a_both_on_reads_the_identity(both_on):
    assert both_on.result["code"] == "ok", both_on.result
    assert both_on.status.get("applicability") is not None, both_on.health_text
    assert len(both_on.agent_log) > 0

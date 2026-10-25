"""One run of the Phase 2 slice on the real binaries, for the end-to-end
tests (A6, P2-A6): the recording simulator as the SEL-751, otsec-collector,
otsec node and A6's RELP receiver as separate processes (D2-3), set up by
slicehelper. Evidence class: simulated.
"""

import base64
import json
import os
import re
import stat
import subprocess
import sys

import harness

# A test value (D2-5): 11 printable characters, inside the SEL-751 profile's
# secret policy (at most 12).
CANARY = "A6slice-9Qx"
CHECK = os.path.join(harness.REPO, "tests", "safety", "recording_simulator", "check.py")
REGISTER = os.path.join(harness.REPO, "tests", "safety", "recording_simulator", "sel751-collector-register.json")


def _go_build(out, pkg):
    subprocess.run(["go", "build", "-o", out, pkg], cwd=harness.REPO, check=True)


class Slice:
    """One run of the slice; every process is stopped at teardown."""

    def __init__(self, d):
        self.d = d
        self.bin = os.path.join(d, "bin")
        self.root = os.path.join(d, "root")
        os.makedirs(self.bin)
        os.mkdir(self.root, 0o700)
        self.procs = {}
        self.logs = {}

    def exe(self, name):
        return os.path.join(self.bin, name + (".exe" if os.name == "nt" else ""))

    def build(self):
        _go_build(self.exe("otsec"), "./cmd/otsec")
        _go_build(self.exe("otsec-collector"), "./cmd/otsec-collector")
        _go_build(self.exe("slicehelper"), "./tests/integration/slice/slicehelper")

    def spawn(self, name, argv, env=None):
        out = open(os.path.join(self.d, name + ".log"), "wb")
        self.logs[name] = out.name
        p = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env)
        self.procs[name] = p
        return p

    def start(self, fid=harness.ALLOWED_FID, framed=True):
        self.sim_logs = []
        self.relp_log = os.path.join(self.d, "relp.jsonl")
        sim = self.start_simulator(fid, framed=framed)
        relp_port = harness.free_port()
        out = subprocess.run([self.exe("slicehelper"), "setup", "-root", self.root, "-sim-port", str(sim.port),
                              "-relp-port", str(relp_port), "-repo", harness.REPO],
                             check=True, capture_output=True)
        self.layout = json.loads(out.stdout)
        relp = harness.Proc([sys.executable, harness.RECEIVER, "--port", str(relp_port), "--log", self.relp_log,
                             "--cert", self.layout["server_cert"], "--key", self.layout["server_key"],
                             "--ca", self.layout["ca"], "--require-client-cert",
                             "--permitted-peer", self.layout["node_id"]])
        self.procs["receiver"] = relp.p
        self.spawn("collector", [self.exe("otsec-collector"), "run", "-data", self.layout["collector_data"]])
        key = os.path.join(self.layout["public_dir"], "install-key.json")
        assert harness.wait_for(lambda: os.path.exists(key) and os.path.exists(self.layout["socket"]), 15), \
            "the collector did not publish its install key and socket:\n" + self.text("collector")
        env = dict(os.environ, OTSEC_SLICE_SECRET=CANARY)
        subprocess.run([self.exe("slicehelper"), "install-credential", "-root", self.root],
                       check=True, capture_output=True, env=env)
        self.spawn("node", [self.exe("otsec"), "node", "-config", self.layout["node_config"]])

    def start_simulator(self, fid, port=0, framed=True):
        """A simulator answering with fid, on port (0: one the OS chooses),
        logging to a new file: sim_log is always the current one."""
        self.sim_log = os.path.join(self.d, f"sim{len(self.sim_logs)}.jsonl")
        self.sim_logs.append(self.sim_log)
        sim = harness.start_simulator(self.sim_log, CANARY, fid=fid, extra=("--port", str(port)) if port else (),
                                      framed=framed)
        self.procs["simulator"] = sim.p
        self.sim_port = sim.port
        return sim

    def replace_simulator(self, fid):
        """The same device address, answering with fid from now on."""
        p = self.procs["simulator"]
        p.terminate()
        p.wait(10)
        self.start_simulator(fid, self.sim_port)

    def health(self):
        out = subprocess.run([self.exe("otsec"), "health", "-config", self.layout["node_config"]],
                             capture_output=True, text=True)
        return out.stdout + out.stderr

    def collector_asset(self):
        """The collector's own state for the asset (A3 #106, #117)."""
        path = os.path.join(self.layout["collector_data"], "collector", "state", "state.json")
        with open(path, encoding="utf-8") as f:
            return json.load(f)["assets"].get(self.layout["asset_id"], {})

    def write_clear(self, asset_id, ref):
        """What the administrator does: leave clear-suspension.json in the
        administrators' folder, 0440 in a 0550 folder (the Linux rule)."""
        d = self.layout["admin_dir"]
        p = os.path.join(d, "clear-suspension.json")
        os.chmod(d, 0o750)
        try:
            if os.path.exists(p):
                os.chmod(p, 0o640)
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"schema": "otsec.clear-suspension/0.1", "asset_id": asset_id, "ref": ref}, f)
            os.chmod(p, 0o440)
        finally:
            os.chmod(d, 0o550)

    def text(self, name):
        with open(self.logs[name], "rb") as f:
            return f.read().decode("utf-8", "replace")

    def sim_records(self):
        """Every simulator's records, in the order the simulators ran."""
        return [r for log in self.sim_logs if os.path.exists(log) for r in harness.read_log(log)]

    def sessions_closed(self):
        return sum(1 for r in self.sim_records() if r["event"] == "session_close")

    def received(self):
        if not os.path.exists(self.relp_log):
            return []
        return [base64.b64decode(r["b64"]) for r in harness.read_log(self.relp_log) if r.get("event") == "syslog"]

    def runs_reported(self):
        """The node's collection.run health reports the receiver got, as
        their hd key=value pairs."""
        out = []
        for m in self.received():
            if b' htype="collection.run" ' in m:
                out.append(dict(kv.split("=", 1) for kv in re.findall(r'hd="([^"]*)"', m.decode("utf-8", "replace"))))
        return out

    def ser_received(self):
        return [m for m in self.received() if b' kind="ser" ' in m]

    def stop(self):
        for name in ("node", "collector", "receiver", "simulator"):
            p = self.procs.get(name)
            if p is None or p.poll() is not None:
                continue
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(10)
        # The administrators' folder is 0550; let the temporary directory go.
        d = getattr(self, "layout", {}).get("admin_dir")
        if d and os.path.isdir(d):
            os.chmod(d, stat.S_IRWXU)

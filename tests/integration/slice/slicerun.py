r"""One run of the Phase 2 slice on the real binaries, for the end-to-end
tests (A6, P2-A6): the recording simulator as the SEL-751, otsec-collector,
otsec node and A6's RELP receiver as separate processes (D2-3), set up by
slicehelper. Evidence class: simulated.

Service mode (P3-A5/A6, gate condition 1). With OTSEC_SLICE_SERVICE=1, on
Windows, in an elevated shell, the node and the collector are not spawned:
the run installs them with the real installer (otsec install, which needs
the binaries under %ProgramFiles%) and drives the installed otsec-node and
otsec-collector services through the SCM. The simulator and the receiver
stay user processes on 127.0.0.1. Nothing of it runs otherwise: the
variable unset leaves the process mode exactly as it was, and the variable
set without Windows or without elevation stops the run before it changes
anything.

  - Preflight: the run refuses to start when any part of an OTSEC install
    is already there (either service, %ProgramData%\OTSEC,
    %ProgramFiles%\OTSEC, the W-3 firewall rule, the WER value, either
    event source), so everything it removes at teardown is something it
    created.
  - The credential goes the product's way, as in process mode: with both
    services running, install-credential leaves the administrator's
    signed credential.install in the installed config\admin, and the
    otsec-node service relays it to the collector over the pipe (P3-A5,
    #181). The collector is installed with ipc.node_peer naming the
    otsec-node service only.
  - The fresh-state floor: the installed collector creates its own stores
    at its first start (the provision marker), so its 31-minute failed-
    auth floor (A3 #106) starts then. The run stops it after that first
    start and moves created_utc in its state.json an hour back, in place,
    which stands for a collector commissioned earlier, as process mode's
    stores created an hour in the past do. This is a harness step, not a
    product path, and the fresh-state floor itself is not exercised on
    the installed services here.
  - Teardown, always, also when a test fails or start() stops halfway:
    stop both services through the SCM, copy each service's Application
    log events and %ProgramData%\OTSEC into the run's directory (so the
    password scan covers them), otsec uninstall, then remove
    %ProgramData%\OTSEC (which uninstall keeps by design), %ProgramFiles%
    \OTSEC and the WER key if this run created it. Then the leftovers
    check: anything still there fails the run (AssertionError). An atexit
    hook runs the same teardown if no stop() did.

kill() of a service is taskkill /F on its PID: TerminateProcess, which,
like SIGKILL, cannot be caught, so no shutdown path runs, and the kernel
closes the process's handles (files, the store's locks, the pipe) as it
does a killed process's descriptors. It differs from SIGKILL in what the
SCM does around it:

  - Recovery actions. The installer sets "restart after 60 s" on failure
    (reset after a day). A process that ends without reporting
    SERVICE_STOPPED is a failure, so the SCM starts the service again by
    itself 60 s after the kill. A SIGKILLed process stays dead until
    respawn(). respawn() starts the service through the SCM before then;
    when the SCM got there first, respawn() says so in the run's log
    (scm.log) and keeps that process. A test that waits more than 60 s
    after a kill sees the service back without asking for it.
  - The handles the SCM holds. The SCM holds a handle on the service
    process, so the process object and its PID outlive the process until
    the SCM has handled its exit, and until then the service still reads
    RUNNING or STOP_PENDING and a start fails as already running. kill()
    therefore waits for the SCM to report STOPPED, not only for the
    process to end. The SCM also writes event 7031 or 7034 ("terminated
    unexpectedly") to the System log, which a SIGKILL has no counterpart
    of.
  - Output. A service has no stdout: text() of a service is its events in
    the Application log since the run started, which hold the node's
    warnings and errors (oslog) and not the lines process mode captures.
"""

import atexit
import base64
import ctypes
import datetime
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time

import harness

# A test value (D2-5): 11 printable characters, inside the SEL-751 profile's
# secret policy (at most 12).
CANARY = "A6slice-9Qx"
CHECK = os.path.join(harness.REPO, "tests", "safety", "recording_simulator", "check.py")
REGISTER = os.path.join(harness.REPO, "tests", "safety", "recording_simulator", "sel751-collector-register.json")


SERVICE = os.environ.get("OTSEC_SLICE_SERVICE") == "1"
# The installed services, their folders and the W-3 rule are machine-wide,
# so in service mode one Slice holds the machine from start() to stop(): a
# test that runs cases in threads (test_slice_failures_e2e) runs them one
# after another there.
_MACHINE = threading.Lock()
SERVICES = {"node": "otsec-node", "collector": "otsec-collector"}
# platform/winsvc: the W-3 rule, the T-5 WER value, the event log sources.
FIREWALL_RULE = "otsec-node: no outbound Telnet (W-3)"
WER_KEY = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications"
WER_VALUE = "otsec-collector.exe"
EVENT_SOURCES = r"SYSTEM\CurrentControlSet\Services\EventLog\Application"
# SERVICE_STATUS dwCurrentState.
STOPPED, START_PENDING, STOP_PENDING, RUNNING = 1, 2, 3, 4


def _go_build(out, pkg):
    subprocess.run(["go", "build", "-o", out, pkg], cwd=harness.REPO, check=True)


def check_service_mode():
    """Stops a service-mode run that cannot be one before it changes
    anything: Windows and an elevated process only."""
    if os.name != "nt":
        raise RuntimeError("OTSEC_SLICE_SERVICE=1 drives the installed Windows services; this is not Windows")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("OTSEC_SLICE_SERVICE=1 installs the services and needs an elevated shell; nothing was changed")


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, errors="replace", **kw)


def read_live(path, timeout=5.0):
    """The bytes of a file a running service replaces by rename (the
    collector's state.json). On Windows, Python's open does not share
    delete, so a read held while the collector renames its new state over
    the file would make the collector's write fail; and an open that lands
    while the old file is delete-pending is refused with access denied
    (svcdry7, run 40456445874). So the file is opened sharing read, write
    and delete, and an access-denied or sharing-violation open is tried
    again for up to timeout seconds; the last refusal is raised."""
    if os.name != "nt":
        with open(path, "rb") as f:
            return f.read()
    import msvcrt
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    GENERIC_READ, SHARE_ALL, OPEN_EXISTING = 0x80000000, 0x7, 3
    deadline = time.monotonic() + timeout
    while True:
        h = k32.CreateFileW(path, GENERIC_READ, SHARE_ALL, None, OPEN_EXISTING, 0, None)
        if h is not None and h != wintypes.HANDLE(-1).value:
            break
        err = ctypes.get_last_error()
        if err not in (5, 32) or time.monotonic() >= deadline:  # ACCESS_DENIED, SHARING_VIOLATION
            raise OSError(err, ctypes.FormatError(err), path)
        time.sleep(0.05)
    with os.fdopen(msvcrt.open_osfhandle(h, os.O_RDONLY), "rb") as f:
        return f.read()


class ServiceProc:
    """What process mode keeps in procs for a spawned node or collector,
    for an installed service: pid and poll() as Popen has them."""

    def __init__(self, inst, name):
        self.inst, self.name = inst, name

    @property
    def pid(self):
        return self.inst.query(self.name)[1]

    def poll(self):
        """None while the service is RUNNING, else its Win32 exit code."""
        state, _, code = self.inst.query(self.name)
        return None if state == RUNNING else code


class ServiceLogs(dict):
    """Slice.logs in service mode: a service's file is rewritten with its
    Application log events whenever it is looked up while the services are
    installed, so a test that reads the files before teardown reads them
    as they stand (A3 on #179)."""

    def __init__(self, inst):
        super().__init__()
        self.inst = inst

    def _refresh(self, name):
        if name in SERVICES and self.inst.installed and dict.__contains__(self, name):
            with open(dict.__getitem__(self, name), "w", encoding="utf-8") as f:
                f.write(self.inst.events(name))

    def __getitem__(self, name):
        self._refresh(name)
        return dict.__getitem__(self, name)

    def items(self):
        for name in list(dict.keys(self)):
            self._refresh(name)
        return dict.items(self)

    def values(self):
        return [v for _, v in self.items()]


class Installed:
    """The installed services of one service-mode run, and their removal."""

    def __init__(self, d, node_exe, collector_exe):
        check_service_mode()
        import winreg
        self.winreg = winreg
        self.d = d
        self.program_data = os.environ["ProgramData"]
        self.data = os.path.join(self.program_data, "OTSEC")
        self.pf = os.path.join(os.environ["ProgramFiles"], "OTSEC")
        self.node_exe = os.path.join(self.pf, "otsec.exe")
        self.collector_exe = os.path.join(self.pf, "otsec-collector.exe")
        self.src = (node_exe, collector_exe)
        self.started = datetime.datetime.now(datetime.timezone.utc)
        self.scm_log = os.path.join(d, "scm.log")
        self.wer_key_existed = self._key_exists(WER_KEY)
        self.installed = False
        found = self.leftovers()
        if found:
            raise RuntimeError("an OTSEC install is already on this machine, and this run removes only what it "
                               "creates; nothing was changed. Found: " + "; ".join(found))

    def note(self, line):
        with open(self.scm_log, "a", encoding="utf-8") as f:
            f.write(datetime.datetime.now(datetime.timezone.utc).isoformat() + " " + line + "\n")

    def _key_exists(self, path, value=None):
        try:
            with self.winreg.OpenKey(self.winreg.HKEY_LOCAL_MACHINE, path) as k:
                if value is not None:
                    self.winreg.QueryValueEx(k, value)
            return True
        except OSError:
            return False

    def leftovers(self):
        """Every part of an install that is there now."""
        found = [f"service {s}" for s in SERVICES.values() if _run(["sc.exe", "query", s]).returncode == 0]
        found += [p for p in (self.data, self.pf) if os.path.lexists(p)]
        if _run(["netsh", "advfirewall", "firewall", "show", "rule", "name=" + FIREWALL_RULE]).returncode == 0:
            found.append("firewall rule " + FIREWALL_RULE)
        if self._key_exists(WER_KEY, WER_VALUE):
            found.append("WER value " + WER_VALUE)
        if not self.wer_key_existed and self._key_exists(WER_KEY):
            found.append("WER key this run created")
        found += [f"event source {s}" for s in SERVICES.values() if self._key_exists(EVENT_SOURCES + "\\" + s)]
        return found

    def cleanup_commands(self):
        """What an administrator runs, elevated, to remove by hand what a
        failed teardown left. Each command is safe when its part is gone."""
        lines = ["To remove what is left, run these in an elevated PowerShell:"]
        lines += [f"  sc.exe stop {s}; sc.exe delete {s}" for s in SERVICES.values()]
        lines += [f"  Remove-Item -Recurse -Force '{p}'" for p in (self.data, self.pf)]
        lines.append(f"  netsh advfirewall firewall delete rule name=\"{FIREWALL_RULE}\"")
        lines.append(f"  Remove-ItemProperty -Path 'HKLM:\\{WER_KEY}' -Name '{WER_VALUE}'")
        if not self.wer_key_existed:
            lines.append(f"  Remove-Item -Path 'HKLM:\\{WER_KEY}'  # only if empty: this run created it")
        lines += [f"  Remove-Item -Path 'HKLM:\\{EVENT_SOURCES}\\{s}'" for s in SERVICES.values()]
        return "\n".join(lines)

    def install(self, layout):
        """otsec install, with the collector configuration that admits the
        otsec-node service on the pipe."""
        self.installed = True  # from here on, teardown removes what exists
        os.mkdir(self.pf)
        shutil.copyfile(self.src[0], self.node_exe)
        shutil.copyfile(self.src[1], self.collector_exe)
        out = _run([self.node_exe, "install", "-config", layout["node_config_source"],
                    "-collector-exe", self.collector_exe, "-collector-config", layout["collector_config"]])
        self.note(f"otsec install: exit {out.returncode}: {out.stdout}{out.stderr}")
        if out.returncode != 0:
            raise RuntimeError(f"otsec install failed (exit {out.returncode}):\n{out.stdout}{out.stderr}")
        # The TLS reference files inherit tls_dir's DACL, as an
        # administrator's copies do (winsvc.TLSDir).
        for name in os.listdir(layout["tls_stage"]):
            shutil.copyfile(os.path.join(layout["tls_stage"], name), os.path.join(layout["tls_dir"], name))

    def query(self, name):
        """(state, pid, Win32 exit code) of the service; state 0 when the
        SCM does not know it."""
        out = _run(["sc.exe", "queryex", SERVICES[name]])
        field = lambda key: int(m.group(1)) if (m := re.search(key + r"\s*:\s*(\d+)", out.stdout)) else 0
        return field("STATE"), field("PID"), field("WIN32_EXIT_CODE")

    def wait_state(self, name, want, timeout):
        if harness.wait_for(lambda: self.query(name)[0] == want, timeout, 0.25):
            return
        raise RuntimeError(f"{SERVICES[name]} is in state {self.query(name)[0]}, not {want}, after {timeout:.0f} s:\n"
                           + self.events(name))

    def start(self, name, timeout=60.0):
        """Starts the service through the SCM. Returns False when it was
        already running (the SCM's own recovery restart got there first)."""
        out = _run(["sc.exe", "start", SERVICES[name]])
        already = out.returncode == 1056  # ERROR_SERVICE_ALREADY_RUNNING
        if out.returncode not in (0, 1056):
            raise RuntimeError(f"sc start {SERVICES[name]}: exit {out.returncode}: {out.stdout}{out.stderr}")
        self.wait_state(name, RUNNING, timeout)
        self.note(f"start {SERVICES[name]}: " + ("already running (the SCM's recovery restart)" if already else "started")
                  + f", pid {self.query(name)[1]}")
        return not already

    def stop(self, name, timeout=60.0):
        """SERVICE_CONTROL_STOP: the service's own shutdown path."""
        if self.query(name)[0] in (0, STOPPED):
            return
        out = _run(["sc.exe", "stop", SERVICES[name]])
        if out.returncode not in (0, 1062):  # ERROR_SERVICE_NOT_ACTIVE
            raise RuntimeError(f"sc stop {SERVICES[name]}: exit {out.returncode}: {out.stdout}{out.stderr}")
        self.wait_state(name, STOPPED, timeout)
        self.note(f"stop {SERVICES[name]}: stopped")

    def kill(self, name):
        """taskkill /F on the service's PID (see the module docstring for how
        it differs from SIGKILL), then wait for the SCM to report STOPPED."""
        state, pid, _ = self.query(name)
        if state != RUNNING or not pid:
            raise RuntimeError(f"kill {SERVICES[name]}: not running (state {state})")
        out = _run(["taskkill", "/F", "/PID", str(pid)])
        if out.returncode != 0:
            raise RuntimeError(f"taskkill /F /PID {pid}: exit {out.returncode}: {out.stdout}{out.stderr}")
        self.wait_state(name, STOPPED, 30)
        self.note(f"kill {SERVICES[name]}: taskkill /F pid {pid}; the SCM reports STOPPED")

    def events(self, name):
        """The service's events in the Application log since the run began."""
        since = self.started.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        q = f"*[System[Provider[@Name='{SERVICES[name]}'] and TimeCreated[@SystemTime>='{since}']]]"
        out = _run(["wevtutil", "qe", "Application", "/q:" + q, "/f:text"])
        return out.stdout + out.stderr

    def age_state(self, path):
        """Moves created_utc in the stopped collector's state.json an hour
        back, in place, so the file keeps the owner and DACL the collector
        gave it (see the module docstring)."""
        with open(path, "r+b") as f:
            doc = json.loads(f.read())
            # RFC 3339 in UTC as Go writes it; the fraction is dropped.
            created = datetime.datetime.strptime(doc["created_utc"][:19], "%Y-%m-%dT%H:%M:%S")
            doc["created_utc"] = (created - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            f.seek(0)
            f.write(json.dumps(doc).encode())
            f.truncate()
            f.flush()
            os.fsync(f.fileno())
        self.note("state.json created_utc moved back an hour: " + doc["created_utc"])

    def teardown(self, logs, keep):
        r"""Stops, records, uninstalls and removes; then the leftovers check,
        which raises AssertionError naming what is left. logs: name to the
        file each service's events go to. keep: where %ProgramData%\OTSEC
        is copied to first."""
        if not self.installed:
            return
        errs = []
        for name in ("node", "collector"):
            try:
                self.stop(name)
            except Exception as e:  # a service that will not stop is killed
                errs.append(f"stop {SERVICES[name]}: {e}")
                try:
                    if self.query(name)[0] == RUNNING:
                        self.kill(name)
                except Exception as e2:
                    errs.append(f"kill {SERVICES[name]}: {e2}")
        for name, path in logs.items():
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.events(name))
        if os.path.isdir(self.data):
            try:
                shutil.copytree(self.data, keep)
            except Exception as e:
                errs.append(f"copy {self.data}: {e}")
        exe = self.node_exe if os.path.exists(self.node_exe) else self.src[0]
        out = _run([exe, "uninstall"])
        self.note(f"otsec uninstall: exit {out.returncode}: {out.stdout}{out.stderr}")
        if out.returncode != 0:
            errs.append(f"otsec uninstall: exit {out.returncode}: {out.stdout}{out.stderr}")
        # A deleted service goes once the last handle on it closes.
        harness.wait_for(lambda: all(_run(["sc.exe", "query", s]).returncode != 0 for s in SERVICES.values()), 30, 0.5)

        def writable(fn, p, _):
            os.chmod(p, stat.S_IWRITE)
            fn(p)
        for p in (self.data, self.pf):
            if os.path.lexists(p):
                try:
                    shutil.rmtree(p, onerror=writable)
                except Exception as e:
                    errs.append(f"remove {p}: {e}")
        if not self.wer_key_existed and self._key_exists(WER_KEY):
            try:
                self.winreg.DeleteKey(self.winreg.HKEY_LOCAL_MACHINE, WER_KEY)  # refused unless empty
            except OSError as e:
                errs.append(f"remove the WER key this run created: {e}")
        left = self.leftovers()
        self.installed = False
        self.note("teardown: " + ("left behind: " + "; ".join(left) if left else "nothing left behind"))
        if left or errs:
            raise AssertionError("service-mode teardown: " + "; ".join(errs + ["left behind: " + x for x in left])
                                 + "\n" + self.cleanup_commands())


class Slice:
    """One run of the slice; every process is stopped at teardown."""

    def __init__(self, d, bin_dir=None):
        """bin_dir: binaries another Slice built, shared instead of building."""
        self.d = d
        self.bin = bin_dir or os.path.join(d, "bin")
        self.root = os.path.join(d, "root")
        os.makedirs(self.d, exist_ok=True)
        os.makedirs(self.bin, exist_ok=True)
        os.mkdir(self.root, 0o700)
        self.procs = {}
        self.logs = {}
        self.argv = {}
        self.sim_extra = ()
        self.sim_password = CANARY
        self.service = None
        if SERVICE:
            check_service_mode()

    def exe(self, name):
        return os.path.join(self.bin, name + (".exe" if os.name == "nt" else ""))

    def build(self):
        _go_build(self.exe("otsec"), "./cmd/otsec")
        _go_build(self.exe("otsec-collector"), "./cmd/otsec-collector")
        _go_build(self.exe("slicehelper"), "./tests/integration/slice/slicehelper")

    def spawn(self, name, argv, env=None):
        # Appended, so a restarted process keeps its earlier output.
        out = open(os.path.join(self.d, name + ".log"), "ab")
        self.logs[name] = out.name
        p = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=env)
        self.procs[name] = p
        self.argv[name] = (argv, env)
        return p

    def kill(self, name):
        """SIGKILL: no shutdown path runs. In service mode, the node and the
        collector get taskkill /F instead (see the module docstring)."""
        if self.service and name in SERVICES:
            self.service.kill(name)
            return
        p = self.procs[name]
        if p.poll() is None:
            p.kill()
        p.wait(10)

    def respawn(self, name):
        """The killed node or collector, started again as before: through
        the SCM in service mode."""
        if self.service and name in SERVICES:
            self.service.start(name)
            return self.procs[name]
        argv, env = self.argv[name]
        return self.spawn(name, argv, env)

    def start_receiver(self):
        """The RELP receiver on the run's port, appending to relp_log."""
        relp = harness.Proc([sys.executable, harness.RECEIVER, "--port", str(self.relp_port), "--log", self.relp_log,
                             "--cert", self.layout["server_cert"], "--key", self.layout["server_key"],
                             "--ca", self.layout["ca"], "--require-client-cert",
                             "--permitted-peer", self.layout["node_id"]])
        self.procs["receiver"] = relp.p
        return relp

    def start(self, fid=harness.ALLOWED_FID, framed=True, sim_extra=(), sim_password=CANARY, setup_extra=()):
        """sim_password: the device's Level 1 password, CANARY unless a test
        wants the installed credential to be wrong. setup_extra: more
        slicehelper setup flags."""
        self.sim_logs = []
        self.sim_extra = tuple(sim_extra)
        self.sim_password = sim_password
        self.relp_log = os.path.join(self.d, "relp.jsonl")
        sim = self.start_simulator(fid, framed=framed)
        # Held until stop(), so that the receiver can bind it now and again
        # after a test kills it, and nothing else on the runner takes it.
        self.relp_port, self.relp_hold = harness.reserve_port()
        if SERVICE:
            _MACHINE.acquire()
            self.holds_machine = True
            self.service = Installed(self.d, self.exe("otsec"), self.exe("otsec-collector"))
            atexit.register(self._teardown)
            setup_extra = (*setup_extra, "-programdata", self.service.program_data)
        out = subprocess.run([self.exe("slicehelper"), "setup", "-root", self.root, "-sim-port", str(sim.port),
                              "-relp-port", str(self.relp_port), "-repo", harness.REPO, *setup_extra],
                             check=True, capture_output=True)
        self.layout = json.loads(out.stdout)
        self.start_receiver()
        if SERVICE:
            self._start_services()
            return
        self.spawn("collector", [self.exe("otsec-collector"), "run", "-data", self.layout["collector_data"]])
        key = os.path.join(self.layout["public_dir"], "install-key.json")
        assert harness.wait_for(lambda: os.path.exists(key) and os.path.exists(self.layout["socket"]), 15), \
            "the collector did not publish its install key and socket:\n" + self.text("collector")
        self.spawn("node", [self.exe("otsec"), "node", "-config", self.layout["node_config"]])
        # The administrator's signed credential.install goes through the
        # node, which relays it within 15 s, well before its first run
        # (60 s after start); install-credential waits for the decision.
        env = dict(os.environ, OTSEC_SLICE_SECRET=CANARY)
        out = subprocess.run([self.exe("slicehelper"), "install-credential", "-root", self.root],
                             capture_output=True, env=env)
        assert out.returncode == 0, "credential.install was not relayed: " + out.stderr.decode(errors="replace") + \
            "\n" + self.text("node")

    def _start_services(self):
        """start() in service mode: install, the collector's first start and
        its aged state, both services, then the credential through the node
        (see the module docstring)."""
        inst, l = self.service, self.layout
        logs = ServiceLogs(inst)
        logs.update(self.logs)
        self.logs = logs
        for name in SERVICES:
            self.logs[name] = os.path.join(self.d, name + ".log")
            self.procs[name] = ServiceProc(inst, name)
        inst.install(l)
        inst.start("collector")
        key = os.path.join(l["public_dir"], "install-key.json")
        pipe = os.path.basename(l["socket"]).lower()
        assert harness.wait_for(lambda: os.path.exists(key) and pipe in (n.lower() for n in os.listdir("\\\\.\\pipe\\")), 30), \
            "the collector service did not publish its install key and pipe:\n" + inst.events("collector")
        inst.stop("collector")
        inst.age_state(os.path.join(l["collector_data"], "collector", "state", "state.json"))
        inst.start("collector")
        inst.start("node")
        env = dict(os.environ, OTSEC_SLICE_SECRET=CANARY)
        out = subprocess.run([self.exe("slicehelper"), "install-credential", "-root", self.root],
                             capture_output=True, env=env)
        assert out.returncode == 0, "credential.install was not relayed: " + out.stderr.decode(errors="replace") + \
            "\n" + inst.events("node")

    def _teardown(self):
        if not self.service:
            return
        keep = os.path.join(self.root, "installed")
        try:
            self.service.teardown({n: self.logs[n] for n in SERVICES if n in self.logs}, keep)
        finally:
            # The installed layout is gone; what a test reads after stop()
            # (the stores, status.json) is in the copy teardown made of it.
            if os.path.isdir(keep) and hasattr(self, "layout"):
                self.layout = {k: self._kept(v, keep) for k, v in self.layout.items()}

    def _kept(self, v, keep):
        """v, a layout value, moved from the installed %ProgramData%\\OTSEC
        to its copy at keep."""
        data = os.path.normcase(os.path.normpath(self.service.data))
        if not isinstance(v, str) or not os.path.normcase(os.path.normpath(v)).startswith(data + os.sep):
            return v
        return os.path.join(keep, os.path.relpath(v, self.service.data))

    def start_simulator(self, fid, port=0, framed=True):
        """A simulator answering with fid, on port (0: one the OS chooses),
        logging to a new file: sim_log is always the current one."""
        self.sim_log = os.path.join(self.d, f"sim{len(self.sim_logs)}.jsonl")
        self.sim_logs.append(self.sim_log)
        extra = self.sim_extra + (("--port", str(port)) if port else ())
        sim = harness.start_simulator(self.sim_log, self.sim_password, fid=fid, extra=extra, framed=framed)
        self.procs["simulator"] = sim.p
        self.sim_port, self.sim_fid, self.sim_framed = sim.port, fid, framed
        return sim

    def replace_simulator(self, fid):
        """The same device address, answering with fid from now on."""
        p = self.procs["simulator"]
        p.terminate()
        p.wait(10)
        self.start_simulator(fid, self.sim_port)

    def cmdline(self, name):
        """The process's command line as the OS has it, for the password
        check (V-S11)."""
        pid = self.procs[name].pid
        if os.name != "nt":
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                return f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        out = _run(["powershell", "-NoProfile", "-Command",
                    f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine"])
        return out.stdout

    def health(self):
        out = subprocess.run([self.exe("otsec"), "health", "-config", self.layout["node_config"]],
                             capture_output=True, text=True)
        return out.stdout + out.stderr

    def collector_asset(self):
        """The collector's own state for the asset (A3 #106, #117)."""
        path = os.path.join(self.layout["collector_data"], "collector", "state", "state.json")
        return json.loads(read_live(path))["assets"].get(self.layout["asset_id"], {})

    def write_clear(self, asset_id, ref):
        """What the administrator does: leave clear-suspension.json in the
        administrators' folder, 0440 in a 0550 folder (the Linux rule). In
        service mode, the installed config\admin, where the file inherits
        the folder's DACL and an elevated account's owner, Administrators."""
        d = self.layout["admin_dir"]
        p = os.path.join(d, "clear-suspension.json")
        if self.service:
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"schema": "otsec.clear-suspension/0.1", "asset_id": asset_id, "ref": ref}, f)
            return
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

    def running(self, name):
        p = self.procs.get(name)
        return p is not None and p.poll() is None

    def sim_records(self):
        """Every simulator's records, in the order the simulators ran. The
        current simulator's log is read live while it runs."""
        live = self.running("simulator")
        return [r for log in self.sim_logs if os.path.exists(log)
                for r in harness.read_log(log, live=live and log == self.sim_log)]

    def sessions_closed(self):
        return sum(1 for r in self.sim_records() if r["event"] == "session_close")

    def received(self):
        if not os.path.exists(self.relp_log):
            return []
        return [base64.b64decode(r["b64"]) for r in harness.read_log(self.relp_log, live=self.running("receiver"))
                if r.get("event") == "syslog"]

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
        """Stops every process. In service mode, the teardown in the module
        docstring runs first, and its leftovers check raises after the
        receiver and the simulator have stopped too."""
        failed = None
        try:
            self._teardown()
        except Exception as e:  # the processes below are stopped either way
            failed = e
        finally:
            if getattr(self, "holds_machine", False):
                self.holds_machine = False
                _MACHINE.release()
        for name in ("node", "collector", "receiver", "simulator"):
            p = self.procs.get(name)
            if isinstance(p, ServiceProc) or p is None or p.poll() is not None:
                continue
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(10)
        if getattr(self, "relp_hold", None):
            self.relp_hold.close()
            self.relp_hold = None
        # The administrators' folder is 0550; let the temporary directory go.
        d = getattr(self, "layout", {}).get("admin_dir")
        if d and os.path.isdir(d) and not self.service:
            os.chmod(d, stat.S_IRWXU)
        if failed:
            raise failed

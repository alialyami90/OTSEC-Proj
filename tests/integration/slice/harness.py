"""Process and TLS helpers for the slice suite (A6). Standard library only.

Every process the suite starts (the simulator, the RELP receiver, and later
the built binaries) runs as a separate OS process, as in production (D2-3).
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SIM = os.path.join(REPO, "tests", "safety", "recording_simulator", "sim.py")
RECEIVER = os.path.join(HERE, "relp_receiver.py")

# An FID the SEL-751 register allows (A2's allowlist; the same substitution as
# the Phase 1 chain). Figure 7.38's own FID is denied by the firmware gate.
ALLOWED_FID = "SEL-751-R501-V0-Z104101-D20260910"

# When set, a check that cannot run (a binary not built, openssl missing)
# fails instead of skipping. The integration job and the exit-gate runs set it.
REQUIRED = os.environ.get("OTSEC_SLICE_REQUIRED") == "1"


class Proc:
    """A child process that prints one JSON "ready" line with its port."""

    def __init__(self, argv, ready_timeout=15.0, cwd=None):
        self.argv = argv
        self.p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        self.stderr = []
        threading.Thread(target=self._drain, daemon=True).start()
        line = self._ready_line(ready_timeout)
        self.ready = json.loads(line)
        self.port = self.ready["port"]

    def _drain(self):
        for line in self.p.stderr:
            self.stderr.append(line.decode("utf-8", "replace"))

    def _ready_line(self, timeout):
        out = []

        def read():
            out.append(self.p.stdout.readline())

        t = threading.Thread(target=read, daemon=True)
        t.start()
        t.join(timeout)
        if not out or not out[0]:
            self.kill()
            raise RuntimeError(f"{self.argv[1:2]} gave no ready line in {timeout}s; stderr:\n{''.join(self.stderr)}")
        return out[0].decode()

    def kill(self):
        if self.p.poll() is None:
            self.p.kill()
        self.p.wait(10)

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(10)


def start_simulator(log, password, fid=ALLOWED_FID, extra=()):
    """The recording simulator with the SEL-751 documented profile, Telnet on
    an OS-chosen port. password is a test value (D2-5)."""
    argv = [sys.executable, SIM, "--transport", "tcp", "--telnet", "--port", "0", "--log", log,
            "--profile", "sel-751-doc", "--profile-password", password, "--profile-stx-etx"]
    if fid:
        argv += ["--profile-fid", fid]
    return Proc(argv + list(extra))


def start_receiver(log, tls=None, extra=()):
    argv = [sys.executable, RECEIVER, "--port", "0", "--log", log]
    if tls:
        argv += ["--cert", tls.server_cert, "--key", tls.server_key, "--ca", tls.ca, "--require-client-cert"]
    return Proc(argv + list(extra))


def read_log(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def wait_for(pred, timeout=10.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return pred()


class TLSMaterial:
    """A throwaway CA, a server certificate for localhost and 127.0.0.1, and a
    client certificate, made with the openssl command line. Test values only,
    created per test session and never committed."""

    def __init__(self, d):
        self.dir = d
        self.ca, self.ca_key = os.path.join(d, "ca.pem"), os.path.join(d, "ca.key")
        self.server_cert, self.server_key = os.path.join(d, "server.pem"), os.path.join(d, "server.key")
        self.client_cert, self.client_key = os.path.join(d, "client.pem"), os.path.join(d, "client.key")
        self.other_cert, self.other_key = os.path.join(d, "other.pem"), os.path.join(d, "other.key")

    @staticmethod
    def openssl():
        return shutil.which("openssl")

    def make(self):
        o = self.openssl()

        def run(*a):
            subprocess.run([o, *a], check=True, capture_output=True)

        def ext(name, body):
            p = os.path.join(self.dir, name)
            with open(p, "w") as f:
                f.write(body)
            return p

        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", self.ca_key, "-out", self.ca, "-days", "2", "-subj", "/CN=a6-slice-test-ca",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
        for cert, key, cn, extfile in (
                (self.server_cert, self.server_key, "localhost",
                 ext("server.ext", "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")),
                (self.client_cert, self.client_key, "a6-slice-node",
                 ext("client.ext", "extendedKeyUsage=clientAuth\n"))):
            csr = key + ".csr"
            run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", key, "-out", csr, "-subj", "/CN=" + cn)
            run("x509", "-req", "-in", csr, "-CA", self.ca, "-CAkey", self.ca_key, "-CAcreateserial",
                "-out", cert, "-days", "2", "-extfile", extfile)
        # A self-signed client certificate no CA here signed.
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", self.other_key, "-out", self.other_cert, "-days", "2", "-subj", "/CN=a6-stranger")
        return self

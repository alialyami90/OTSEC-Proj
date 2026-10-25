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


def start_receiver(log, tls=None, extra=(), permitted_peer=None):
    """The RELP receiver. With tls it requires a client certificate that
    chains to tls.ca and carries the permitted peer name, by default
    TLSMaterial.PERMITTED_PEER: the only collector setup C6 0.2 commissions
    (D2-9). It never runs in CA-only mode."""
    argv = [sys.executable, RECEIVER, "--port", "0", "--log", log]
    if tls:
        argv += ["--cert", tls.server_cert, "--key", tls.server_key, "--ca", tls.ca, "--require-client-cert",
                 "--permitted-peer", permitted_peer or tls.PERMITTED_PEER]
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
    """A throwaway CA, a server certificate for localhost and 127.0.0.1, and
    client certificates, made with the openssl command line. Test values only,
    created per test session and never committed.

    PERMITTED_PEER is the node name a collector permits (C6 0.2
    durable_ack.permitted_peer). The client certificates cover the V-S6
    refusals and both name paths of the peer check:

      client       CA-signed, CN a6-slice-node, no SAN: accepted (CN path)
      san_client   CA-signed, SAN DNS:a6-slice-node, CN a6-cn-other: accepted
                   (SAN path; the CN is not consulted when a SAN is present)
      san_shadow   CA-signed, SAN DNS:a6-other-node, CN a6-slice-node: refused
                   (a SAN is present and does not match; the CN is ignored)
      wrongname    CA-signed, CN a6-other-node: refused (V-S6, another name)
      impostor     self-signed, CN a6-slice-node: refused (V-S6, no chain)
      other        self-signed, CN a6-stranger: refused
    """

    PERMITTED_PEER = "a6-slice-node"

    def __init__(self, d):
        self.dir = d
        self.ca, self.ca_key = os.path.join(d, "ca.pem"), os.path.join(d, "ca.key")
        self.server_cert, self.server_key = os.path.join(d, "server.pem"), os.path.join(d, "server.key")
        self.client_cert, self.client_key = os.path.join(d, "client.pem"), os.path.join(d, "client.key")
        self.other_cert, self.other_key = os.path.join(d, "other.pem"), os.path.join(d, "other.key")
        self.impostor_cert, self.impostor_key = os.path.join(d, "impostor.pem"), os.path.join(d, "impostor.key")
        self.wrongname_cert, self.wrongname_key = os.path.join(d, "wrongname.pem"), os.path.join(d, "wrongname.key")
        self.san_client_cert, self.san_client_key = os.path.join(d, "san-client.pem"), os.path.join(d, "san-client.key")
        self.san_shadow_cert, self.san_shadow_key = os.path.join(d, "san-shadow.pem"), os.path.join(d, "san-shadow.key")

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
                 ext("client.ext", "extendedKeyUsage=clientAuth\n")),
                (self.wrongname_cert, self.wrongname_key, "a6-other-node",
                 ext("client.ext", "extendedKeyUsage=clientAuth\n")),
                (self.san_client_cert, self.san_client_key, "a6-cn-other",
                 ext("san-client.ext", "subjectAltName=DNS:a6-slice-node\nextendedKeyUsage=clientAuth\n")),
                (self.san_shadow_cert, self.san_shadow_key, "a6-slice-node",
                 ext("san-shadow.ext", "subjectAltName=DNS:a6-other-node\nextendedKeyUsage=clientAuth\n"))):
            csr = key + ".csr"
            run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", key, "-out", csr, "-subj", "/CN=" + cn)
            run("x509", "-req", "-in", csr, "-CA", self.ca, "-CAkey", self.ca_key, "-CAcreateserial",
                "-out", cert, "-days", "2", "-extfile", extfile)
        # A self-signed client certificate no CA here signed.
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", self.other_key, "-out", self.other_cert, "-days", "2", "-subj", "/CN=a6-stranger")
        # Self-signed, with the real client's name: only a chain check stops it.
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", self.impostor_key, "-out", self.impostor_cert, "-days", "2", "-subj", "/CN=a6-slice-node")
        return self


RSYSLOG_CONF = """\
# Upstream collector for the slice's Linux leg (A6). RELP over TLS with client
# certificates. The ruleset queue is Direct and omfile syncs, so imrelp
# answers 200 OK only after the message is written and fsynced: the durable
# acknowledgement C6 requires of a required target (V-S6).
# tls.authmode is "name": with librelp 1.11.0, "certvalid" accepted a
# self-signed client certificate no configured CA had signed (A6 test,
# 2026-10-24). "name" checks the chain and the peer name.
global(workDirectory="{dir}")
module(load="imrelp")
input(type="imrelp" port="{port}" address="127.0.0.1" ruleset="slice"
      tls="on" tls.cacert="{ca}" tls.mycert="{cert}" tls.myprivkey="{key}"
      tls.authmode="name" tls.permittedPeer=["{peer}"])
template(name="raw" type="string" string="%rawmsg%\\n")
ruleset(name="slice" queue.type="Direct") {{
  action(type="omfile" file="{out}" template="raw" asyncWriting="off"
         flushOnTXEnd="on" sync="on" ioBufferSize="4k")
}}
"""


_rsyslogd_copy = None


def rsyslogd():
    """The rsyslogd to run, or a false value when none is installed.

    Ubuntu's AppArmor profile for /usr/sbin/rsyslogd lets it read only its
    own configuration under /etc, so the installed binary cannot open a test
    configuration in a temporary directory ("could not open config file:
    Permission denied" on GitHub's runners). The profile is attached by path,
    so the harness runs a copy of the same binary from its own directory.
    The copy loads the same modules (imrelp included) from the compiled-in
    module directory; only the AppArmor confinement differs."""
    global _rsyslogd_copy
    path = shutil.which("rsyslogd") or (os.path.exists("/usr/sbin/rsyslogd") and "/usr/sbin/rsyslogd")
    if not path or sys.platform != "linux":
        return path
    if _rsyslogd_copy is None:
        import atexit
        import tempfile
        d = tempfile.mkdtemp(prefix="a6-rsyslogd-")
        atexit.register(shutil.rmtree, d, True)
        _rsyslogd_copy = os.path.join(d, "rsyslogd")
        shutil.copy2(os.path.realpath(path), _rsyslogd_copy)
    return _rsyslogd_copy


def free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Rsyslog:
    """rsyslogd in the foreground with RSYSLOG_CONF. imrelp cannot pick its
    own port, so the harness picks a free one and waits until it accepts."""

    def __init__(self, d, tls):
        self.dir, self.out = d, os.path.join(d, "rsyslog-out.log")
        self.port = free_port()
        self.conf = os.path.join(d, "rsyslog.conf")
        with open(self.conf, "w") as f:
            f.write(RSYSLOG_CONF.format(dir=d, port=self.port, ca=tls.ca, cert=tls.server_cert,
                                        key=tls.server_key, out=self.out, peer=tls.PERMITTED_PEER))
        self.p = subprocess.Popen([rsyslogd(), "-n", "-f", self.conf, "-i", os.path.join(d, "rsyslog.pid")],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        import socket

        def accepting():
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return True
            except OSError:
                return False

        if not wait_for(accepting, 10):
            self.stop()
            raise RuntimeError("rsyslogd did not open its RELP port: " + self.p.stdout.read().decode(errors="replace"))

    def lines(self):
        if not os.path.exists(self.out):
            return []
        with open(self.out, "rb") as f:
            return [l for l in f.read().split(b"\n") if l]

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(10)

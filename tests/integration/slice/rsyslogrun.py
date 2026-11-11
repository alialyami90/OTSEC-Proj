"""The slice with a stock rsyslog as its upstream collector (D6, P4-D6-H5).

This is GT-RX as docs/verification.md defines it: an upstream receiver that
is not project code, whose received-message log is the ground truth for
forwarding. RsyslogSlice is slicerun.Slice with one thing changed: the
node's required RELP/TLS target is rsyslogd with imrelp, the binary Ubuntu
packages, and not relp_receiver.py. Nothing of the project runs on the
receiving side, and relp_receiver.py is never started.

The collector is configured the way D2-9 commissions one, with the same
input, queue and action as harness.RSYSLOG_CONF, whose durable
acknowledgement and V-S6 refusals test_rsyslog_leg.py checks: imrelp over
TLS, tls.authmode "name" with the node's certificate name as the one
permitted peer, a Direct ruleset queue and omfile with sync="on", so imrelp
answers 200 OK only after the message is written and fsynced. Its parser
settings are rsyslog's defaults.

What rsyslog writes is the oracle. Each message is one JSON object, built
by rsyslog's own template: the message as received (rawmsg), and rsyslog's
own reading of it, which is the protocol version its parser chain settled
on (1 only when its RFC 5424 parser accepted the message) and the header
fields and STRUCTURED-DATA that parser found. records() reads the file
with the standard library's JSON parser. The messages are then read by
reconcile.py's RFC 5424 parser, which is D6's own.

A record cut short is not a message: rsyslog was killed while it wrote the
record, so it never acknowledged it. records() counts such a record as
torn and leaves it out.

Evidence class: simulated. Linux only: rsyslog does not run on Windows.
"""

import datetime
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess

import harness
from slicerun import Slice

# The collector's durable-acknowledgement check on record (C6 durable_ack):
# this configuration's delivery and refusals.
DURABLE_ACK_REF = "tests/integration/slice/test_rsyslog_leg.py"

CONF = """\
# The slice's upstream collector when it is a stock rsyslog (D6, P4-D6-H5).
# The input, the queue and the action's write settings are those of
# harness.RSYSLOG_CONF. The template differs: one JSON object for each
# message, with rsyslog's own reading of it beside the message as received.
global(workDirectory="{dir}")
module(load="imrelp")
input(type="imrelp" port="{port}" address="127.0.0.1" ruleset="slice"
      tls="on" tls.cacert="{ca}" tls.mycert="{cert}" tls.myprivkey="{key}"
      tls.authmode="name" tls.permittedPeer=["{peer}"])
template(name="rx" type="list" option.jsonf="on") {{
  property(outname="raw" name="rawmsg" format="jsonf")
  property(outname="pv" name="protocol-version" format="jsonf")
  property(outname="pri" name="pri" format="jsonf")
  property(outname="ts" name="timereported" dateFormat="rfc3339" format="jsonf")
  property(outname="host" name="hostname" format="jsonf")
  property(outname="app" name="app-name" format="jsonf")
  property(outname="procid" name="procid" format="jsonf")
  property(outname="msgid" name="msgid" format="jsonf")
  property(outname="sd" name="structured-data" format="jsonf")
}}
ruleset(name="slice" queue.type="Direct") {{
  action(type="omfile" file="{out}" template="rx" asyncWriting="off"
         flushOnTXEnd="on" sync="on" ioBufferSize="4k")
}}
"""

# Where a record starts. Inside a JSON string every quote is escaped, so
# these bytes are never part of a message.
_START = re.compile(rb'\{\s*"raw"\s*:\s*"')


def records(data, live=False):
    """(records, torn): the JSON objects rsyslog wrote, in order, and how
    many records were cut short. live: rsyslog may still be writing, so a
    last record that does not parse yet is left for the next read and is
    not counted."""
    starts = [m.start() for m in _START.finditer(data)]
    recs = []
    torn = 1 if data[:starts[0] if starts else len(data)].strip() else 0
    for i, at in enumerate(starts):
        last = i == len(starts) - 1
        chunk = data[at:len(data) if last else starts[i + 1]]
        try:
            recs.append(json.loads(chunk.decode("utf-8", "surrogateescape")))
        except ValueError:
            if not (live and last):
                torn += 1
    return recs, torn


def raw(rec):
    """The message as rsyslog received it, as bytes."""
    return rec["raw"].encode("utf-8", "surrogateescape")


def rfc5424_problems(recs):
    """Where rsyslog's own reading of a message is not an RFC 5424 reading
    of that message: its parser chain did not settle on protocol version 1,
    or a field it found is not the field at that place in the message."""
    problems = []
    for i, r in enumerate(recs):
        msg = r["raw"]
        if r.get("pv") != "1":
            problems.append(f"record {i}: rsyslog read protocol version {r.get('pv')!r}, not 1: {msg[:160]!r}")
            continue
        f = msg.split(" ", 6)
        if len(f) < 7:
            problems.append(f"record {i}: {len(f)} header fields: {msg[:160]!r}")
            continue
        want = {"pri": f[0][1:f[0].find(">")], "host": f[2], "app": f[3], "procid": f[4], "msgid": f[5]}
        for name, v in want.items():
            if r.get(name) != v:
                problems.append(f"record {i}: rsyslog read {name} {r.get(name)!r}, the message has {v!r}")
        if not f[6].startswith(r.get("sd") or "\0"):
            problems.append(f"record {i}: rsyslog read STRUCTURED-DATA {str(r.get('sd'))[:80]!r}, the message has {f[6][:80]!r}")
        try:
            same = datetime.datetime.fromisoformat(r["ts"]) == datetime.datetime.fromisoformat(f[1])
        except (KeyError, TypeError, ValueError):
            same = False
        if not same:
            problems.append(f"record {i}: rsyslog read the time {r.get('ts')!r}, the message has {f[1]!r}")
    return problems


def _sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def versions():
    """The installed collector, for the run's log: rsyslogd's own version
    line, and the Debian packages of rsyslog and librelp where dpkg has
    them."""
    out = [subprocess.run([harness.rsyslogd(), "-v"], capture_output=True, text=True).stdout.split("\n")[0].strip()]
    if shutil.which("dpkg-query"):
        q = subprocess.run(["dpkg-query", "-W", "-f", "${Package} ${Version}\n", "rsyslog", "rsyslog-relp", "librelp*"],
                           capture_output=True, text=True)
        out += [l for l in q.stdout.split("\n") if l.strip()]
    return out


class RsyslogSlice(Slice):
    """Slice, forwarding to a stock rsyslog."""

    def start(self, *args, setup_extra=(), **kw):
        self.rx_out = os.path.join(self.d, "rsyslog-rx.jsonl")
        self.torn = 0
        super().start(*args, setup_extra=(*setup_extra, "-durable-ack-ref", DURABLE_ACK_REF), **kw)

    def start_receiver(self):
        """rsyslogd in the foreground on the run's port, appending to
        rx_out: the first start, and every start after a kill."""
        l = self.layout
        conf = os.path.join(self.d, "rsyslog.conf")
        if not os.path.exists(conf):
            with open(conf, "w") as f:
                f.write(CONF.format(dir=self.d, port=self.relp_port, ca=l["ca"], cert=l["server_cert"],
                                    key=l["server_key"], peer=l["node_id"], out=self.rx_out))
            check = subprocess.run([harness.rsyslogd(), "-N1", "-f", conf], capture_output=True, text=True)
            assert check.returncode == 0, "rsyslogd refuses its configuration:\n" + check.stdout + check.stderr
        # A killed rsyslogd leaves its PID file.
        pid = os.path.join(self.d, "rsyslog.pid")
        if os.path.exists(pid):
            os.remove(pid)
        with open(os.path.join(self.d, "receiver.log"), "ab") as log:
            self.logs["receiver"] = log.name
            p = subprocess.Popen([harness.rsyslogd(), "-n", "-f", conf, "-i", pid], stdout=log, stderr=subprocess.STDOUT)
        self.procs["receiver"] = p

        def accepting():
            try:
                socket.create_connection(("127.0.0.1", self.relp_port), timeout=0.2).close()
                return True
            except OSError:
                return False

        if not harness.wait_for(accepting, 10):
            raise RuntimeError("rsyslogd did not open its RELP port:\n" + self.text("receiver"))
        return p

    def rx_records(self):
        """What rsyslog has written, in order. Sets torn."""
        if not os.path.exists(self.rx_out):
            return []
        with open(self.rx_out, "rb") as f:
            data = f.read()
        recs, self.torn = records(data, live=self.running("receiver"))
        return recs

    def received(self):
        return [raw(r) for r in self.rx_records()]

    def received_by_line(self):
        return list(enumerate(self.received()))

    def receiver_lines(self):
        return len(self.rx_records())


# Checks every rsyslog leg makes, imported by its test file. run is the
# file's own fixture, an RsyslogSlice.

def test_the_upstream_is_a_stock_rsyslog(run, capsys):
    recs = run.rx_records()
    with capsys.disabled():
        print(f"\nupstream collector: {'; '.join(versions())}; {len(recs)} records in its file, {run.torn} torn")
    # The process is the packaged binary: harness.rsyslogd() runs a copy of
    # it, only so that AppArmor's path-attached profile does not apply.
    exe = run.procs["receiver"].args[0]
    assert exe == harness.rsyslogd()
    assert _sha256(exe) == _sha256(os.path.realpath(shutil.which("rsyslogd") or "/usr/sbin/rsyslogd"))
    assert not os.path.exists(run.relp_log), "relp_receiver.py's log exists: D6's own receiver ran"
    assert recs, "rsyslog wrote nothing"


def test_rsyslog_reads_every_message_as_rfc5424(run):
    """R4.6: forwarded messages parse as valid RFC 5424 at an independent
    receiver. The parser is rsyslog's."""
    recs = run.rx_records()
    problems = rfc5424_problems(recs)
    assert recs and problems == [], problems[:10]

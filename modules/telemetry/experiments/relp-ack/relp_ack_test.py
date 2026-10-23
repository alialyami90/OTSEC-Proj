"""Does a RELP acknowledgement mean the collector kept the message?

A minimal RELP client (the bounded ack parser A3 asked about) sends N
messages to a stock rsyslog imrelp receiver, records which transaction
numbers were acknowledged with "200 OK", and kills the receiver (rsyslog and its output process) with SIGKILL part-way through. The receiver writes through a deliberately slow consumer
(slow_sink.sh) so that its queues hold messages when it is killed. Afterwards it compares acknowledged messages with what the
receiver wrote to disk. Run once with rsyslog's default in-memory main queue
and once with Direct queues and omprog confirmMessages="on", so that the ack can
only be sent after the output confirmed the write.

Usage: python3 -I relp_ack_test.py <work-dir> <results.md>
Throwaway experiment, not product code. No TLS: framing and ack semantics only.
"""
import os
import re
import signal
import socket
import subprocess
import sys
import time

N, KILL_AFTER, PORT, WINDOW = 3000, 1500, 20514, 128

CONF = """
global(workDirectory="{work}")
module(load="imrelp")
module(load="omprog")
{mainq}
template(name="m" type="string" string="%msg%\\n")
ruleset(name="r"{rsq}) {{ action(type="omprog" binary="{sink} {out}" template="m"{aq}) }}
input(type="imrelp" port="{port}" ruleset="r")
"""

FRAME = re.compile(rb"^([0-9]{1,9}) ([a-z]{1,32}) ([0-9]{1,9})[ \n]")
MAX_RSP = 4096


class AckParser:
    """Strict, bounded parser for server-to-client RELP frames. Its only
    output is the set of acknowledged transaction numbers. Anything else is
    counted as a violation and the connection should be dropped."""

    def __init__(self, outstanding):
        self.buf, self.outstanding, self.acked, self.violations = b"", outstanding, set(), 0

    def feed(self, data):
        self.buf += data
        while True:
            m = FRAME.match(self.buf)
            if not m:
                if len(self.buf) > 32 or (self.buf and not self.buf[:1].isdigit()):
                    self.violations += 1
                    self.buf = b""
                return
            txnr, cmd, length = int(m.group(1)), m.group(2), int(m.group(3))
            if length > MAX_RSP:
                self.violations += 1
                self.buf = b""
                return
            start = m.end() if self.buf[m.end() - 1:m.end()] == b" " else m.end() - 1
            end = start + length
            if len(self.buf) < end + 1:
                return
            data, trailer = self.buf[start:end], self.buf[end:end + 1]
            self.buf = self.buf[end + 1:]
            if trailer != b"\n" or cmd not in (b"rsp", b"serverclose"):
                self.violations += 1
                continue
            if cmd == b"rsp" and txnr in self.outstanding and data[:6] == b"200 OK":
                self.outstanding.discard(txnr)
                self.acked.add(txnr)
            elif cmd == b"rsp":
                self.violations += 1


def frame(txnr, cmd, data):
    return f"{txnr} {cmd} {len(data)} ".encode() + data + b"\n"


def trial(work, label, mainq, rsq, aq):
    os.makedirs(work, exist_ok=True)
    out = os.path.join(work, f"{label}.out")
    conf = os.path.join(work, f"{label}.conf")
    for p in (out,):
        if os.path.exists(p):
            os.remove(p)
    with open(conf, "w") as f:
        f.write(CONF.format(work=work, out=out, port=PORT, mainq=mainq, rsq=rsq, aq=aq,
                            sink=os.path.join(os.path.dirname(os.path.abspath(__file__)), "slow_sink.sh")))
    proc = subprocess.Popen(["rsyslogd", "-n", "-f", conf, "-i", os.path.join(work, f"{label}.pid")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(1.5)
    s = socket.create_connection(("127.0.0.1", PORT))
    s.settimeout(0.05)
    outstanding = set()
    parser = AckParser(outstanding)
    s.sendall(frame(1, "open", b"relp_version=0\nrelp_software=otsec-exp\ncommands=syslog"))
    outstanding.add(1)
    deadline = time.time() + 2
    while 1 not in parser.acked and time.time() < deadline:
        try:
            parser.feed(s.recv(65536))
        except socket.timeout:
            pass
    sent = []
    killed = False
    for i in range(N):
        txnr = i + 2
        msg = f"<134>1 2026-10-23T15:00:00Z node otsec - SER - seq={i:06d}".encode()
        try:
            s.sendall(frame(txnr, "syslog", msg))
        except OSError:
            break
        outstanding.add(txnr)
        sent.append((txnr, i))
        # Pipeline like a real forwarder: keep up to WINDOW frames in flight.
        while True:
            try:
                parser.feed(s.recv(65536, socket.MSG_DONTWAIT))
            except (BlockingIOError, OSError):
                pass
            if len(outstanding) < WINDOW or killed:
                break
            time.sleep(0.001)
        if i + 1 == KILL_AFTER and not killed:
            # Kill the whole receiver (rsyslog and its sink) as a crash would.
            os.killpg(proc.pid, signal.SIGKILL)
            killed = True
    end = time.time() + 1
    while time.time() < end:
        try:
            data = s.recv(65536)
            if not data:
                break
            parser.feed(data)
        except (socket.timeout, OSError):
            break
    s.close()
    proc.wait()
    time.sleep(1)
    stored = set()
    if os.path.exists(out):
        for line in open(out, errors="replace"):
            m = re.search(r"seq=(\d{6})", line)
            if m:
                stored.add(int(m.group(1)))
    acked = {i for txnr, i in sent if txnr in parser.acked}
    return {
        "trial": label, "sent": len(sent), "acked": len(acked), "stored": len(stored),
        "acked_not_stored": len(acked - stored), "stored_not_acked": len(stored - acked),
        "parser_violations": parser.violations,
    }


def main(work, results):
    rows = [
        trial(work, "default-queues", "", "", ""),
        trial(work, "direct-queues", 'main_queue(queue.type="Direct")',
              ' queue.type="Direct"', ' queue.type="Direct" confirmMessages="on"'),
    ]
    ver = subprocess.run(["rsyslogd", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    with open(results, "w") as f:
        f.write("# RELP acknowledgement vs. stored messages\n\n")
        f.write(f"Generated by `relp_ack_test.py` against {ver.split(' compiled')[0].replace('  ', ' ')} "
                f"(imrelp), {N} messages pipelined with a window of {WINDOW}, receiver process group SIGKILLed after message {KILL_AFTER} was sent. "
                "Do not edit by hand.\n\n")
        cols = list(rows[0])
        f.write("| " + " | ".join(cols) + " |\n| " + " | ".join("---" for _ in cols) + " |\n")
        for r in rows:
            f.write("| " + " | ".join(str(r[c]) for c in cols) + " |\n")
    print(open(results).read())


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

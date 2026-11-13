"""The test-only C13 source (D6, P4-4-R1 deliverable 3; GT-PCAP plan section 8).

It turns one GT-PCAP capture's label file into the C13 records a sensor
would send for it (`otsec.netobs/0.1`, docs/phase4/D4-c13-netobs.md), and
writes them with C13's framing to any byte stream: a file, a pipe or a
socket. It reads the labels and the capture's frames and nothing else. It
decodes no packet, so it is not a sensor, and it is never linked into
either binary: nothing under cmd/, platform/ or modules/ imports tests/.

It is written from C13's text, with its own field names and its own JSON,
and shares no code with contracts/netobs, so the product's decoder judges
it: tests/contract/c13_source_d6_test.go reads a committed stream of it
with netobs.DecodeChannel.

What it sends for a capture, in the order a sensor would see the frames:

- a heartbeat before the first frame and one after the last, so a counter
  is read as the difference between them (D1 on #548);
- for each `flow` row a `start` at its first frame and an `end` with the
  row's packets and bytes;
- for each `service` row a `service` with `basis: content`, its server at
  `ip.dst` whichever end sent the flow's first frame;
- for each `function` row a `function` with the row's code, objects, `sa`
  and `sa_error_from`, citing the row's frames.

Every first sight carries its cited frames' bytes. A result that used this
source ran without a sensor and is not V-M6 evidence (plan section 5).
"""

import base64
import datetime
import hashlib
import json
import struct

SCHEMA = "otsec.netobs/0.1"
SENSOR_ID = "5d6f0c1a-7b2e-4c3d-9a4f-6e8b0d2c4f61"  # made for GT-PCAP's replays; no sensor has it
RUN_ID = "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9"
MAX_CITED = 8
COVERAGE = {
    "sensor_version": "0.0.0-gt-pcap-source", "engine": {"name": "gt-pcap-labels", "version": "1"},
    "interfaces": [{"name": "mon0", "attachment": "unknown", "lan": "single"}],
    "prp": {"lans_seen": [], "duplicates_discarded": False}, "hsr": "not-decoded",
    "vlans_seen": [], "vlans_overflow": False, "untagged_seen": True,
    "decodes": ["dnp3"], "degraded": [],
    "settings": {"sa_reply_timeout_ms": 5000, "max_pending_dnp3": 4096, "flow_idle_s": 60},
}
COUNTERS = ("packets", "bytes", "drops_decoder", "drops_channel", "decoder_errors", "sessions_unparsed",
            "table_evictions", "dnp3_pending_overflows", "dnp3_seq_reused", "prp_discards", "redactions",
            "logins_not_placed")


def utc(ns):
    s, frac = divmod(ns, 1_000_000_000)
    return datetime.datetime.fromtimestamp(s, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{frac:09d}Z"


def mac(b):
    return ":".join(f"{x:02x}" for x in b)


class Source:
    """One run of the source over one capture."""

    def __init__(self, rows, frames, pcap_sha256, sensor_id=SENSOR_ID, run_id=RUN_ID):
        self.rows, self.frames, self.capture = rows, frames, "file:" + pcap_sha256
        self.ids, self.seq = {"sensor_id": sensor_id, "run_id": run_id}, 0
        self.coverage = dict(COVERAGE, since_utc=utc(frames[0].ns))

    def _head(self, kind):
        self.seq += 1
        return {"schema": SCHEMA, "type": kind, **self.ids, "seq": str(self.seq)}

    def heartbeat(self, ns, **counters):
        return {**self._head("heartbeat"), "at_utc": utc(ns), "coverage": self.coverage,
                "counters": {**dict.fromkeys(COUNTERS, 0), **counters},
                # No binding was read: the source reads a file, not an interface (D4 on #626).
                "interface_check": "unknown"}

    def _observation(self, kind, row, nums, total, first_sight, body):
        cited = nums[:MAX_CITED]
        fr = [self.frames[n - 1] for n in cited]
        obs = {
            **self._head("observation"), "kind": kind, "first_sight": first_sight,
            "first_utc": utc(fr[0].ns), "last_utc": utc(max(self.frames[n - 1].ns for n in nums)), "resolution_ns": 1,
            "l2": {"src_mac": mac(fr[0].data[6:12]), "dst_mac": mac(fr[0].data[0:6]),
                   "ethertype": "0x%04x" % struct.unpack("!H", fr[0].data[12:14])[0]},
            "ip": {"src": row["src"], "dst": row["dst"], "l4": row["l4"],
                   "sport": int(row["sport"]), "dport": int(row["dport"])},
            "direction": row["direction"], "protocol": row["protocol"],
            "citation": {"capture_id": self.capture, "frames_total": total, "frames": [
                {"n": n, "captured_len": len(f.data), "wire_len": len(f.data),
                 "sha256": hashlib.sha256(f.data).hexdigest()} for n, f in zip(cited, fr)]},
            "coverage": self.coverage, kind: body,
        }
        if first_sight:
            obs["frames"] = [{"n": n, "ts": utc(f.ns), "data": base64.b64encode(f.data).decode()}
                             for n, f in zip(cited, fr)]
        return obs

    def records(self):
        """Every record for the capture, heartbeats included, in order."""
        flows = [r for r in self.rows if r["kind"] == "flow"]
        events = []  # (frame number it is sent at, rank, builder)
        for r in flows:
            nums = [int(n) for n in r["frames"].split(",")]
            first = len(self.frames[nums[0] - 1].data)
            events.append((nums[0], 0, lambda r=r, nums=nums, first=first: self._observation(
                "flow", r, nums[:1], 1, True, {"phase": "start", "packets": 1, "bytes": first})))
            end = {"phase": "end", "packets": int(r["packets"]), "bytes": int(r["bytes"]),
                   "end": "fin" if r["l4"] == "tcp" else "idle"}
            if r["l4"] == "tcp":
                end["syn_only"] = False
            events.append((nums[-1], 3, lambda r=r, nums=nums, end=end: self._observation(
                "flow", r, nums, len(nums), False, end)))
        for r in self.rows:
            nums = [int(n) for n in r["frames"].split(",")] if r["frames"] else []
            if r["kind"] == "service":
                # The server is at ip.dst even where it sent the flow's first
                # frame (C13 0.2's CH-49: dnp3-udp-unsolicited).
                server = (r["dst"], r["dport"])
                flow = next(f for f in flows
                            if f["l4"] == r["l4"] and server in ((f["src"], f["sport"]), (f["dst"], f["dport"])))
                ends = [(flow["src"], flow["sport"]), (flow["dst"], flow["dport"])]
                other = ends[0] if ends[1] == server else ends[1]
                ip = dict(flow, src=other[0], sport=other[1], dst=server[0], dport=server[1])
                events.append((nums[0], 1, lambda ip=ip, nums=nums: self._observation(
                    "service", ip, nums, len(nums), True, {"basis": "content"})))
            elif r["kind"] == "function":
                body = {"code": int(r["code"]), "objects": [o for o in r["objects"].split(",") if o not in ("", "?")]}
                for k in ("sa", "sa_error_from"):
                    if r[k]:
                        body[k] = r[k]
                events.append((nums[-1], 2, lambda r=r, nums=nums, body=body: self._observation(
                    "function", r, nums, len(nums), True, body)))
        reused = sum(int(r["note"].split("=")[1]) for r in self.rows
                     if r["kind"] == "counter" and r["note"].startswith("dnp3_seq_reused="))
        out = [self.heartbeat(self.frames[0].ns)]
        out += [build() for _, _, build in sorted(events, key=lambda e: e[:2])]
        out.append(self.heartbeat(self.frames[-1].ns, packets=len(self.frames),
                                  bytes=sum(len(f.data) for f in self.frames), dnp3_seq_reused=reused))
        return out


def frame(record):
    """One record as C13 frames it: its length as four big-endian octets,
    then one JSON document in UTF-8."""
    body = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return struct.pack("!I", len(body)) + body


def write(stream, records):
    """Write the records to a byte stream: anything with write() or sendall()."""
    put = getattr(stream, "sendall", None) or stream.write
    for r in records:
        put(frame(r))


def read(data):
    """The records in a byte string of C13 frames (for the source's own tests)."""
    out, i = [], 0
    while i < len(data):
        n = struct.unpack("!I", data[i:i + 4])[0]
        out.append(json.loads(data[i + 4:i + 4 + n]))
        i += 4 + n
    return out

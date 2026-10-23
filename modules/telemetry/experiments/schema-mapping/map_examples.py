"""Map native timestamps taken from public captures, plus A2's documented SEL
SER excerpt, into the draft event schema (docs/phase0/A4-event-schema-draft.md)
and check the schema's invariants. Throwaway experiment, not product code.

Usage: python3 -I map_examples.py <capture-cache> <out.json>
"""
import datetime
import hashlib
import json
import subprocess
import sys

SCHEMA = "otsec.event/0.1-draft"


def raw_field(pcap, frame, field):
    """Return the hex bytes tshark reports for the first occurrence of a field."""
    out = subprocess.run(["tshark", "-r", pcap, "-Y", f"frame.number=={frame}", "-T", "json", "-x"],
                         capture_output=True, text=True, check=True).stdout

    # tshark's JSON repeats keys (e.g. "Point Number 0"), so keep every pair.
    def walk(node):
        if isinstance(node, tuple):
            node = [node]
        if isinstance(node, list) and node and all(isinstance(x, tuple) for x in node):
            for k, v in node:
                if k == field + "_raw":
                    return v[0] if isinstance(v[0], str) else v[0][0]
                r = walk(v)
                if r:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = walk(v)
                if r:
                    return r
        return None
    return walk(json.loads(out, object_pairs_hook=lambda pairs: pairs))


def iso_wall(dt, digits):
    s = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if digits:
        s += "." + f"{dt.microsecond:06d}"[:digits]
    return s


def cp56time2a(hexstr):
    b = bytes.fromhex(hexstr)
    ms = b[0] | b[1] << 8
    minute, iv = b[2] & 0x3F, bool(b[2] & 0x80)
    hour, su = b[3] & 0x1F, bool(b[3] & 0x80)
    day, month, year2 = b[4] & 0x1F, b[5] & 0x0F, b[6] & 0x7F
    # The two-digit year needs a century assumption; record that it is one.
    wall = datetime.datetime(2000 + year2, month, day, hour, minute, ms // 1000, (ms % 1000) * 1000)
    return {
        "native": hexstr, "native_encoding": "hex", "format": "iec60870-cp56time2a",
        "wall_clock": iso_wall(wall, 3), "offset": "unknown", "offset_basis": "none", "utc": None,
        "resolution_ns": 1_000_000, "accuracy_ns": None,
        "quality": {"invalid": iv, "summer_time": su, "scope": "record"},
        "flags": ["two-digit-year:century-assumed-2000"],
    }


def dnp3_cto_relative(cto_hex, rel_hex):
    cto_ms = int.from_bytes(bytes.fromhex(cto_hex), "little")
    rel_ms = int.from_bytes(bytes.fromhex(rel_hex), "little")
    wall = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=cto_ms + rel_ms)
    return {
        "native": f"g51v1={cto_hex};g2v3.rel={rel_hex}", "native_encoding": "hex",
        "format": "dnp3-g51v1-cto+g2v3-relative",
        "wall_clock": iso_wall(wall, 3),
        # IEEE 1815 defines DNP3 time as UTC, but the capture clock disagrees by
        # ~4 h (see notes), so the offset is not taken from the format here.
        "offset": "unknown", "offset_basis": "none", "utc": None,
        "resolution_ns": 1_000_000, "accuracy_ns": None,
        "quality": {"scope": "record"}, "flags": ["relative-to-cto"],
    }


def iec61850_utctime(hexstr):
    b = bytes.fromhex(hexstr)
    secs = int.from_bytes(b[0:4], "big")
    frac = int.from_bytes(b[4:7], "big")
    q = b[7]
    acc_bits = q & 0x1F
    ns = frac * 10**9 // 2**24
    acc_ns = 10**9 // 2**acc_bits if acc_bits <= 24 else None
    digits = max(0, min(6, len(str(10**9 // acc_ns)) - 1)) if acc_ns else 6
    # Round (not truncate) to the declared accuracy: the binary fraction of
    # .514 s is 0.51399999..., and truncation would report .513.
    step = 10 ** (9 - digits)
    ns = (ns + step // 2) // step * step
    wall = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=secs, microseconds=ns // 1000)
    return {
        "native": hexstr, "native_encoding": "hex", "format": "iec61850-utctime",
        "wall_clock": iso_wall(wall, digits), "offset": "+00:00", "offset_basis": "format",
        "utc": iso_wall(wall, digits) + "Z",
        "resolution_ns": 10**9 // 2**24, "accuracy_ns": acc_ns,
        "quality": {"leap_seconds_known": bool(q & 0x80), "clock_failure": bool(q & 0x40),
                    "sync": "unsynchronized" if q & 0x20 else "synchronized",
                    "time_accuracy_bits": acc_bits, "scope": "record"},
        "flags": [],
    }


def sel_ser_documented():
    """A2's documented excerpt (SEL-751 manual Figure 10.17, as quoted in
    A2-device-feasibility.md section 7). Row-level time columns were not read,
    so they are carried as unknown rather than invented."""
    header = "Date: 02/28/2007 Time: 16:34:28 Time Source: Internal"
    row = "51P1P Asserted"
    return header, row


def event(kind, asset, stream, seq, device_time, raw, fields, subject, value, evidence_class=None):
    return {
        "schema": SCHEMA,
        "event_id": f"(assigned at first durable write; example {seq})",
        # Digest of the native row bytes. Used to align consecutive snapshots
        # (C-13); it is not a uniqueness key, identical rows share it.
        "record_digest": hashlib.sha256(raw).hexdigest(),
        "origin": "device", "kind": kind,
        "source": {"asset_id": asset, "stream_id": stream, "stream_seq": seq},
        "received": {"utc": None, "resolution_ns": 1000, "clock": {"sync": "unknown"}},
        "device_time": device_time,
        "native": {"evidence": {"sha256": hashlib.sha256(raw).hexdigest(), "length": len(raw)},
                   "fields": fields},
        "normalized": {"subject": subject, "value": value, "category": "unmapped"},
        "evidence_class": evidence_class,
    }


def checks(e, raw):
    t = e["device_time"]
    out = []
    out.append(("native preserved", hashlib.sha256(raw).hexdigest() == e["native"]["evidence"]["sha256"]))
    out.append(("utc only when offset known", (t["utc"] is None) == (t["offset"] == "unknown")))
    frac = t["wall_clock"].split(".")[1] if "." in t["wall_clock"] else ""
    finest = min(x for x in (t["resolution_ns"], t["accuracy_ns"] or t["resolution_ns"]) if x)
    out.append(("no digits finer than declared resolution/accuracy", 10**9 // 10**len(frac) >= finest
                if frac else True))
    return out


def main(cache, out_path):
    results = []
    cp = raw_field(f"{cache}/iec104.pcap", 25, "iec60870_asdu.cp56time")
    t = cp56time2a(cp)
    results.append((event("protocol-event", "iec104:ca10", "iec104:ca10:ioa13", 1, t, bytes.fromhex(cp),
                          {"typeid": "M_SP_TB_1", "ioa": "13", "spi": "On"}, "ioa:13", "On"
                          ), bytes.fromhex(cp), "iec104.pcap frame 25"))
    cto = raw_field(f"{cache}/dnp3-digitalbond-part1.pcap", 40, "dnp3.al.timestamp")
    t = dnp3_cto_relative(cto, "0000")
    results.append((event("protocol-event", "dnp3:outstation", "dnp3:outstation:g2", 1, t, bytes.fromhex(cto),
                          {"group": "2", "variation": "3", "index": "1", "value": "1", "flags": "Online"},
                          "bi:1", "1"), bytes.fromhex(cto), "dnp3-digitalbond-part1.pcap frame 40"))
    ut = raw_field(f"{cache}/goose-normal.pcapng", 1, "goose.t")
    t = iec61850_utctime(ut)
    results.append((event("protocol-event", "goose:LIED10", "goose:LIED10CTRL/LLN0$Status", 1, t,
                          bytes.fromhex(ut), {"stNum": "1", "sqNum": "0"}, "LIED10CTRL/LLN0$Status",
                          "stNum=1"), bytes.fromhex(ut), "goose-normal.pcapng frame 1"))
    header, row = sel_ser_documented()
    raw = (header + "\n" + row).encode()
    t = {"native": None, "native_encoding": "text", "format": "sel-ascii-ser-row",
         "wall_clock": None, "offset": "unknown", "offset_basis": "none", "utc": None,
         "resolution_ns": None, "accuracy_ns": None,
         "quality": {"time_source": "Internal", "scope": "report"},
         "flags": ["row-time-columns-not-documented-yet"]}
    e = event("ser", "sel751:feeder1", "sel751:feeder1:ser", 1, t, raw,
              {"report.Date": "02/28/2007", "report.Time": "16:34:28", "report.Time Source": "Internal",
               "ELEMENT": "51P1P", "STATE": "Asserted"}, "51P1P", "Asserted", "documented-untested")
    e["native"]["context"] = {"report_header_sha256": hashlib.sha256(header.encode()).hexdigest()}
    results.append((e, raw, "A2 excerpt of SEL-751 manual Figure 10.17"))
    report = []
    for e, raw, src in results:
        if e["evidence_class"] is None:
            e["evidence_class"] = "public-capture (simulated or lab origin, see SOURCE.md)"
        c = checks(e, raw) if e["device_time"]["wall_clock"] else [
            ("native preserved", hashlib.sha256(raw).hexdigest() == e["native"]["evidence"]["sha256"]),
            ("utc only when offset known", e["device_time"]["utc"] is None)]
        report.append({"source": src, "event": e, "checks": {k: v for k, v in c}})
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    for r in report:
        print(r["source"], "->", r["event"]["device_time"]["format"], r["event"]["device_time"]["wall_clock"],
              r["event"]["device_time"]["offset"], r["checks"])
    sys.exit(0 if all(all(r["checks"].values()) for r in report) else 1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

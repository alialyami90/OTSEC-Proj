"""Map native timestamps taken from public captures, plus the SEL-751 manual's
example SER report (documented/sel751-fig10.16.txt), into the draft event schema (docs/phase0/A4-event-schema-draft.md)
and check the schema's invariants. Throwaway experiment, not product code.

Usage: python3 -I map_examples.py <capture-cache> <out.json>
"""
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

# -I drops the script's directory from sys.path; sel_ser.py is ours.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sel_ser  # noqa: E402

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


SEL_DOC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "documented", "sel751-fig10.16.txt")
# The Figure 10.16 report does not print DATE_F. The product reads it from
# SHO G (A1-approved); this example assumes MDY and flags every row.
SEL_DATE_F = "MDY"


def event(kind, asset, stream, seq, device_time, raw, fields, subject, value, evidence_class=None):
    # seq is this example's position only. The real stream_seq is assigned at
    # durable write and continues across reports of the same stream (A2 review
    # finding 4), so it is left as a placeholder here.
    return {
        "schema": SCHEMA,
        "event_id": f"(assigned at first durable write; example {seq})",
        # Digest of the native row bytes. Used to align consecutive snapshots
        # (C-13); it is not a uniqueness key, identical rows share it.
        "record_digest": hashlib.sha256(raw).hexdigest(),
        "origin": "device", "kind": kind,
        "source": {"asset_id": asset, "stream_id": stream, "stream_seq": "(assigned at durable write)"},
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
    raw = open(SEL_DOC, "rb").read()
    header, items = sel_ser.parse_report(raw, SEL_DATE_F)
    for seq, it in enumerate(items, start=1):
        line = it["line"]
        if it["type"] == "parse-error":
            results.append(({"kind": "ser", "parse_status": "failed", "reason": it["reason"],
                             "evidence_class": "documented-untested"}, line, f"SEL-751 manual line at {it['offset']}"))
            continue
        f = it["fields"]
        # "Time Source: Internal" means no time input is attached, so the
        # 1 ms figure is resolution only; accuracy to true time is unknown
        # (A2 review finding 3).
        t = {"native": f"{f['DATE']} {f['TIME']}", "native_encoding": "text", "format": "sel-ascii-ser-row",
             "wall_clock": f["wall_clock"], "offset": "unknown", "offset_basis": "none",
             "utc": None, "resolution_ns": 1_000_000, "accuracy_ns": None,
             "quality": {"time_source": "Internal", "scope": "report"},
             "flags": [f"date-format-assumed:DATE_F={SEL_DATE_F}"] + it.get("flags", [])}
        if it["type"] == "relay-message":
            subject, value = "relay", f["MESSAGE"]
        else:
            subject, value = f["ELEMENT"], f["STATE"]
        native = {k: v for k, v in f.items() if k != "wall_clock"}
        e = event("ser", "sel751:feeder-relay", "sel751:feeder-relay:ser", seq, t, line,
                  native, subject, value, "documented-untested")
        e["collection"] = {"native_position": f["#"], "parse_status": "ok"}
        e["native"]["span"] = {"offset": it["offset"], "length": len(line)}
        e["native"]["context"] = {"report_header_sha256": hashlib.sha256(header).hexdigest(),
                                  "report_header_length": len(header)}
        results.append((e, line, f"SEL-751 manual Figure 10.16 row #{f['#']}"))
    report = []
    for e, raw, src in results:
        if e.get("parse_status") == "failed":
            report.append({"source": src, "event": e, "checks": {"parse ok": False}})
            continue
        if e["evidence_class"] is None:
            e["evidence_class"] = "public-capture (simulated or lab origin, see SOURCE.md)"
        c = checks(e, raw)
        span = e["native"].get("span")
        if span:
            doc = open(SEL_DOC, "rb").read()
            c.append(("span resolves to native row", doc[span["offset"]:span["offset"] + span["length"]] == raw))
        report.append({"source": src, "event": e, "checks": {k: v for k, v in c}})
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    for r in report:
        if "device_time" not in r["event"]:
            print(r["source"], "-> PARSE ERROR", r["event"]["reason"])
            continue
        print(r["source"], "->", r["event"]["device_time"]["format"], r["event"]["device_time"]["wall_clock"],
              r["event"]["device_time"]["offset"], r["checks"])
    sel = [r for r in report if r["event"]["kind"] == "ser"]
    same_ms = [r for r in sel if r["event"]["device_time"]["native"] == "02/28/2007 13:54:09.602"]
    print(f"SEL rows mapped: {len(sel)}; rows sharing 13:54:09.602 kept separate: {len(same_ms)}")
    ok = all(all(r["checks"].values()) for r in report) and len(sel) == 8 and len(same_ms) == 2
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

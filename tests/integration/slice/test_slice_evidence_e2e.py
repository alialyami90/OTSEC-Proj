"""Raw device evidence is preserved, end to end on the real binaries (A6,
P3-A6; V-S8).

Two slices side by side:
  example    Figure 10.16 as documented: 8 SER rows.
  malformed  the same report with row 5's time corrupted ("13:5X:10.003"),
             a forced parser failure for that row (profile_sel751,
             ser="malformed"); the run is partial.parse_errors.

The ground truth is what the simulator sent (GT-REC: its "sent" records,
every byte in order), never the product's own parser. After one run the
processes are stopped and the node's evidence store is read directly
(C5's SQLite file, read-only). Checked:
  - every capture the store holds is whole: its key is the SHA-256 of its
    bytes, and its length is the one the events name;
  - every byte the simulator sent in a session that ran the SER read
    appears in that session's capture, chunk by chunk in the order sent
    (the transcript adds the collector's own lines and the redaction
    marker between them; nothing the device sent is altered or lost);
  - every SER event's record bytes hash to its record_sha256, equal its
    span of the capture, and are bytes the simulator sent;
  - every SER message the receiver got names, in rsha256, rlen and
    esha256, a stored record and capture, and its dtext hashes to rsha256;
  - the malformed row is kept: stored, hashed and forwarded byte for byte
    as sent, marked as not parsed, and the other 7 rows still arrive;
  - the recording check passes (V-S7).

Evidence class: simulated. Nothing device-specific is left to hardware
for V-S8 itself; real report layouts are V-S2's (H-07).
"""

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import threading

import pytest

import harness
import reconcile
from conftest import need
from slicerun import CHECK, REGISTER, SERVICE, Slice

CASES = {"example": (), "malformed": ("--profile-ser", "malformed")}
ROWS = 8
BAD_TIME = b"13:5X:10.003"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _run(name, s, out):
    try:
        s.start(sim_extra=CASES[name])
        ok = harness.wait_for(lambda: len(s.ser_received()) >= ROWS, 150.0, step=1.0)
        # The run's health report reaches the receiver a moment later.
        harness.wait_for(lambda: s.runs_reported(), 20.0, step=0.5)
        out[name] = {"ok": ok, "health": s.health(), "runs": s.runs_reported(),
                     "received": s.ser_received(), "count": len(s.ser_received())}
    except Exception as exc:  # reported by the tests below
        out[name] = {"ok": False, "error": repr(exc)}
    finally:
        s.stop()
    r = out[name]
    r["sim_logs"] = list(getattr(s, "sim_logs", []))
    r["sim"] = [harness.read_log(l) for l in r["sim_logs"] if os.path.exists(l)]
    store = getattr(s, "layout", {}).get("store_dir")
    if store:
        r["store"] = _read_store(os.path.join(store, "evidence.db"))


def _read_store(path):
    """The SER events and every capture, from C5's file, read-only."""
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        events = [json.loads(ev) for st, ev in
                  db.execute("SELECT stream, event FROM events WHERE stream LIKE 'ser/%' ORDER BY stream, seq")]
        captures = {sha: bytes(b) for sha, b in db.execute("SELECT sha256, bytes FROM captures")}
    finally:
        db.close()
    return {"events": events, "captures": captures}


def _sessions(logs):
    """Per simulator session, in order: the lines it received and the chunks
    it sent. Session numbers restart with each simulator log, so the key is
    (log index, session)."""
    out = {}
    for log, records in enumerate(logs):
        for r in records:
            sid = r.get("session")
            if sid is None:
                continue
            s = out.setdefault((log, sid), {"lines": [], "sent": []})
            if r["event"] == "line":
                s["lines"].append(r["text"])
            elif r["event"] == "sent" and not r.get("telnet"):
                s["sent"].append(base64.b64decode(r["b64"]))
    return out


def _in_order(chunks, capture):
    at = 0
    for c in chunks:
        k = capture.find(c, at)
        if k < 0:
            return False
        at = k + len(c)
    return True


def _record(ev, captures):
    n = ev["native"]
    cap = captures.get(n["evidence"]["sha256"], b"")
    if n.get("bytes") is not None:
        return base64.b64decode(n["bytes"]), cap
    sp = n["span"]
    return cap[sp["offset"]:sp["offset"] + sp["length"]], cap


@pytest.fixture(scope="module")
def got(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" or SERVICE, "the Windows leg of the end-to-end run is the PC run (D1-26)")
    base = str(tmp_path_factory.mktemp("slice-evidence"))
    first = Slice(os.path.join(base, "build"))
    first.build()
    out, threads = {}, []
    for name in CASES:
        t = threading.Thread(target=_run, args=(name, Slice(os.path.join(base, name), bin_dir=first.bin), out))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    for name, r in out.items():
        print(f"{name}: {r.get('count')} SER messages, runs {[x.get('status') for x in r.get('runs', [])]}, "
              f"{len(r.get('store', {}).get('events', []))} stored SER events, "
              f"{len(r.get('store', {}).get('captures', {}))} captures {r.get('error', '')}")
    return out


def _case(got, name):
    r = got[name]
    assert r.get("ok"), r.get("error") or r.get("health")
    return r


@pytest.mark.parametrize("name", list(CASES))
def test_every_capture_is_whole(got, name):
    r = _case(got, name)
    caps = r["store"]["captures"]
    assert caps
    for sha, b in caps.items():
        assert _sha(b) == sha, sha
    for ev in r["store"]["events"]:
        e = ev["native"]["evidence"]
        assert e["sha256"] in caps, e
        assert e["length"] == len(caps[e["sha256"]]), e
        assert e.get("ref") in (None, "sha256:" + e["sha256"]), e


@pytest.mark.parametrize("name", list(CASES))
def test_everything_the_device_sent_is_in_the_capture(got, name):
    r = _case(got, name)
    sessions = _sessions(r["sim"])
    ser = [s for s in sessions.values() if any(l.startswith("SER") for l in s["lines"])]
    assert ser, sessions.keys()
    used = {ev["native"]["evidence"]["sha256"] for ev in r["store"]["events"]}
    caps = [r["store"]["captures"][k] for k in used]
    for s in ser:
        assert s["sent"]
        assert any(_in_order(s["sent"], c) for c in caps), "a SER session's bytes are in no capture"


@pytest.mark.parametrize("name", list(CASES))
def test_every_record_is_bytes_the_device_sent(got, name):
    r = _case(got, name)
    sent = [b"".join(s["sent"]) for s in _sessions(r["sim"]).values()]
    events = r["store"]["events"]
    assert len(events) == ROWS, len(events)
    for ev in events:
        n = ev["native"]
        rec, cap = _record(ev, r["store"]["captures"])
        assert _sha(rec) == n["record_sha256"] and len(rec) == n["record_length"], ev["id"]
        if n.get("span"):
            sp = n["span"]
            assert cap[sp["offset"]:sp["offset"] + sp["length"]] == rec, ev["id"]
        assert any(rec in s for s in sent), (ev["id"], rec)


@pytest.mark.parametrize("name", list(CASES))
def test_forwarded_messages_name_the_stored_evidence(got, name):
    r = _case(got, name)
    stored = {ev["native"]["record_sha256"]: ev for ev in r["store"]["events"]}
    assert len(r["received"]) == ROWS
    for m in r["received"]:
        p = reconcile.parse_rfc5424(m)["sd"][reconcile.SDID]
        rsha, esha = reconcile.first(p, "rsha256"), reconcile.first(p, "esha256")
        assert rsha in stored, rsha
        n = stored[rsha]["native"]
        assert reconcile.first(p, "rlen") == str(n["record_length"])
        assert esha == n["evidence"]["sha256"] and esha in r["store"]["captures"]
        text = reconcile.first(p, "dtext")
        raw = text.encode() if text is not None else base64.b64decode(reconcile.first(p, "dtext_b64"))
        assert _sha(raw) == rsha


def test_the_row_that_failed_to_parse_is_kept_as_sent(got):
    r = _case(got, "malformed")
    assert [x.get("status") for x in r["runs"]][:1] == ["partial"], r["runs"]
    assert "last run partial.parse_errors" in r["health"], r["health"]
    sent = b"".join(c for s in _sessions(r["sim"]).values() for c in s["sent"])
    line = next(l for l in sent.split(b"\r\n") if BAD_TIME in l)
    bad = [ev for ev in r["store"]["events"] if BAD_TIME in _record(ev, r["store"]["captures"])[0]]
    assert len(bad) == 1, bad
    rec = _record(bad[0], r["store"]["captures"])[0]
    assert rec == line, (rec, line)
    assert bad[0]["collection"]["parse_status"] != "ok", bad[0]["collection"]
    fwd = [m for m in r["received"] if _sha(line).encode() in m]
    assert len(fwd) == 1
    ok = [ev for ev in r["store"]["events"] if ev["collection"]["parse_status"] == "ok"]
    assert len(ok) == ROWS - 1


@pytest.mark.parametrize("name", list(CASES))
def test_only_read_only_lines_reached_the_device(got, name):
    r = got[name]
    assert r["sim_logs"]
    for log in r["sim_logs"]:
        out = subprocess.run([sys.executable, CHECK, "--log", log, "--register", REGISTER],
                             capture_output=True, text=True)
        report = json.loads(out.stdout)
        assert out.returncode == 0 and report["pass"], (log, report)

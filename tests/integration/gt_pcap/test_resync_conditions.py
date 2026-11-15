"""HR-25's dnp3-resync-* cases and pass conditions are pinned (D6, brief P4-4-HR25, deliverable 2).

resync-cases.tsv and resync-conditions.tsv are what the counted run of HR-25's
fix is judged by, written before any build of Option A. A later edit must be
visible, so this test pins both files' SHA-256 (LF line endings, as Git
stores them), as pins.env pins them for the run. It also checks what the
pins must hold: each case names its transport, every route of HR-25's row has
its cases, every route case has its twins and its controls, every cause and
weird named is one of the design's, and the builder's solved headers do what
the cases say. dnp3.py is GT-PCAP's own writer (D6), not a product package.
"""

import csv
import hashlib
import os
import re

import dnp3

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "resync-cases.tsv")
CONDITIONS = os.path.join(HERE, "resync-conditions.tsv")
CASES_SHA256 = "05b52c6a27e308b6ffe95df97ec919d8c0027760ad6f4fc894ddd39c0babb809"
CONDITIONS_SHA256 = "d5bc7bee4959dc7a65b0cece8fdff82ff145b18e176aed158ccd2f67a4a3beb1"

# The closed set of causes and their weirds (design section 2.8).
WEIRDS = {
    "magic": "dnp3_header_lacks_magic",
    "header_crc": "dnp3_corrupt_header_checksum",
    "link_length": "dnp3_invalid_link_length",
    "chunk_crc": "dnp3_corrupt_app_chunk_checksum",
    "embedded_header": "dnp3_embedded_header",
    "first_chunk_missing": "dnp3_first_application_layer_chunk_missing",
    "fir_restart": "dnp3_fragment_restarted",
    "fragment_limit": "dnp3_max_application_layer_fragment_size_exceeded",
    "app_parse": "dnp3_app_parse_failed",
    "gap": "dnp3_content_gap",
    "truncated": "dnp3_truncated_frame",
    "budget": "dnp3_resync_budget_exhausted",
    "invariant": "dnp3_invariant",
}
ROUTES = {"R1", "R2", "R3", "R4"}
KINDS = ROUTES | {"trace", "insert", "budget", "benign", "invariant", "changed", "report", "bound", "fp"}
TWINS = {"nofail", "nowrite", "otherend"}


def content(path):
    with open(path, "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def rows(path):
    lines = [ln for ln in content(path).decode("utf-8").split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def tokens(cell):
    return [t.strip() for t in cell.split(";") if t.strip()]


def test_the_files_are_the_pinned_ones():
    assert hashlib.sha256(content(CASES)).hexdigest() == CASES_SHA256
    assert hashlib.sha256(content(CONDITIONS)).hexdigest() == CONDITIONS_SHA256


def test_every_case_is_whole_and_names_its_transport():
    rs = rows(CASES)
    assert list(rs[0]) == ["case", "route", "l4", "cause", "build", "a", "ctl", "twins"]
    assert len({r["case"] for r in rs}) == len(rs)
    for r in rs:
        assert None not in r and all(r.values()), r
        assert r["l4"] in ("udp", "tcp"), r
        # The prefix, then the transport (D1 6866534402 point 3), and none of the
        # strings table.py's summary columns key on (HR-23 note section 4).
        assert re.fullmatch(r"dnp3-resync-(udp|tcp)-[a-z0-9-]+", r["case"]), r["case"]
        assert r["case"].startswith(f"dnp3-resync-{r['l4']}-"), r["case"]
        assert not r["case"].endswith("-udp") and "moved-port" not in r["case"], r["case"]
        assert r["route"] in KINDS, r
        assert r["twins"] == "-" or set(r["twins"].split(",")) <= TWINS, r


def test_every_route_of_hr25_has_its_cases():
    # HR-25's "When it closes": at least one case for each of the four routes,
    # R1 and R4 over UDP and over TCP, the TCP keep-alive among R4's, R3 over TCP.
    rs = rows(CASES)
    by = {(r["route"], r["l4"]) for r in rs}
    for need in (("R1", "udp"), ("R1", "tcp"), ("R3", "tcp"), ("R4", "udp"), ("R4", "tcp")):
        assert need in by, need
    assert any(r["route"] == "R2" for r in rs)
    assert all(r["l4"] == "tcp" for r in rs if r["route"] == "R3")
    assert "dnp3-resync-tcp-keepalive" in {r["case"] for r in rs if r["route"] == "R4"}


def test_every_route_case_has_its_twins_and_its_controls():
    for r in rows(CASES):
        if r["route"] not in ROUTES:
            continue
        twins = set(r["twins"].split(","))
        assert {"nofail", "nowrite"} <= twins, r["case"]
        # The other end's twin is left out only where the failure and W share
        # one datagram or segment, so the failure cannot move to the other end.
        assert ("otherend" in twins) != ("+ W" in r["build"]), r["case"]
        assert r["ctl"].startswith("W=absent") or r["ctl"].startswith("report"), r["case"]


def test_every_cause_has_a_case_on_its_transport_and_invariant_none():
    rs = rows(CASES)
    named = {}
    for r in rs:
        for c in r["cause"].split(","):
            if c != "-":
                assert c in WEIRDS, (r["case"], c)
                named.setdefault(c, set()).add(r["l4"])
    assert set(named) == set(WEIRDS) - {"invariant"}
    assert named["gap"] == {"tcp"} and named["truncated"] == {"udp"}


def test_counts_weirds_and_rows_use_the_design_names():
    for r in rows(CASES):
        counted = set()
        for t in tokens(r["a"]):
            m = re.fullmatch(r"cnt\.([mo])\.([a-z_]+)=(\d+)", t)
            if m:
                assert m.group(2) in WEIRDS, (r["case"], t)
                counted.add(m.group(2))
            for w in re.findall(r"weird\.([a-z0-9_]+)=", t):
                assert w in WEIRDS.values(), (r["case"], w)
            assert not t.startswith("cnt.") or m, (r["case"], t)
        if counted:
            assert counted == set(r["cause"].split(",")), r["case"]
        if r["route"] != "report" and not r["a"].startswith("report"):
            assert any(t.startswith("rows=") for t in tokens(r["a"])), r["case"]


def test_the_conditions_are_whole_and_hold_the_values():
    rs = rows(CONDITIONS)
    assert list(rs[0]) == ["id", "subject", "op", "value", "rule"]
    assert len({r["id"] for r in rs}) == len(rs)
    for r in rs:
        assert None not in r and None not in r.values() and r["rule"], r
        assert (r["op"] == "") == (r["value"] == ""), r
        assert r["op"] in ("", "=", "<=", ">="), r
    v = {r["id"]: r["value"] for r in rs}
    assert int(v["val-F"]) == 8 and int(v["val-O"]) == 2048 and int(v["val-K"]) == 100
    assert int(v["val-interval"]) == 60 and int(v["val-limit"]) == 102400
    # -max_len holds O and a session (P R W R Q R: 18 + 14 + 35 + 14 + 24 + 14 octets).
    assert int(v["fuzz-max-len"]) >= int(v["val-O"]) + 119
    # F failures fit in FuzzBuffer's 64 chunks.
    assert int(v["val-F"]) <= 64
    for need in ("cov-causes", "cov-drop", "cov-delete", "cov-paths", "cov-udp", "cov-tcp", "cov-not", "cov-left",
                 "pin-files", "pin-builder", "judge-ctl", "judge-route", "judge-r3", "fp-counts", "rerun-ed403",
                 "report-no-new-field", "s5-inputs", "builder-s5-7", "static-control"):
        assert need in v, need


def test_the_solved_headers_put_05_64_in_their_crc():
    # D2's C1: a header of length 0 to 4 whose CRC octets are 05 64, so W's
    # frame starts at its octet 8 (builder facts, desk).
    v = {r["id"]: r["value"] for r in rows(CONDITIONS)}
    for l4, src in (("udp", 5), ("tcp", 1)):
        for k in range(5):
            h = bytes.fromhex(v[f"builder-c1-{l4}-{k}"])
            assert len(h) == 8 and h[:2] == b"\x05\x64" and h[2] == k and h[3] == 0xC4
            assert int.from_bytes(h[6:8], "little") == src
            assert dnp3.crc(h) == b"\x05\x64", (l4, k)
            # No 05 64 inside it, so the scan's first candidate is at octet 8.
            assert b"\x05\x64" not in h[1:]


def test_the_false_magic_fails_and_w_starts_two_octets_later():
    w = dnp3.link(10, 1, True, dnp3.tpdu(1, dnp3.request(1, dnp3.DIRECT_OPERATE, dnp3.crob(0))))
    false = b"\x05\x64" + w
    assert len(w) == 35 and false[2:4] == b"\x05\x64"
    assert dnp3.crc(false[:8]) != false[8:10]
    p = dnp3.link(10, 1, True, dnp3.tpdu(0, dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1))))
    q = dnp3.link(10, 1, True, dnp3.tpdu(2, dnp3.request(2, dnp3.READ, b"".join(
        dnp3.all_objects(60, v) for v in (2, 3, 4)))))
    assert (len(p), len(q)) == (18, 24)


def frame_len(user):
    return 10 + user + 2 * -(-user // 16)


def test_the_builder_arithmetic():
    # builder-limit: B400, B401 and overlimit's application octets.
    assert 2 + 3 * 34131 + 5 == 102400
    assert 2 + 3 * 34133 == 102401
    assert 2 + 3 * 34214 + 5 == 102649 == 102400 + 249
    assert 411 * 249 + 61 == 102400
    # The other end's overlimit: 129 and IIN, then the same object headers.
    assert 4 + 3 * 34215 == 102649
    # builder-join: 2,048 application octets in 8 frames of 292 and one of 75.
    assert 4 + 7 + 2037 == 2048 and 8 * 249 + 56 == 2048
    assert frame_len(250) == 292 and frame_len(57) == 75 and 7 * 292 + 75 == 2119
    # embed and embedtail: a frame of link length 53 is 64 octets, W5's 35 fit at 20.
    assert frame_len(53 - 5) == 64 and 20 + 35 <= 64
    # builder-msgs: W1 is the transport octet and W's application control, W2
    # the other 19 octets. Under the controls an inserted FIR frame follows W1
    # in one fragment, whose function code is then the inserted frame's own
    # application control, C0h to CFh: the request's default arm (arm-3bdata).
    w = dnp3.request(0, dnp3.DIRECT_OPERATE, dnp3.crob(0))
    assert len(w) == 20 and frame_len(1 + 1) == 14 and frame_len(1 + 19) == 34
    for s in range(16):
        code = dnp3.request(s, dnp3.READ, dnp3.all_objects(60, 1))[0]
        assert 34 <= code <= 255 and code not in (129, 130, 131)


def chunks(frame):
    out, i = [], 10
    while i < len(frame):
        n = min(16, len(frame) - i - 2)
        out.append((frame[i:i + n], frame[i + n:i + n + 2]))
        i += n + 2
    return out


def candidate(buf, i):
    # The design's candidate (2.1, 2.2): 05 64, a passing header CRC, a length of 5 to 255.
    h = buf[i:i + 10]
    return len(h) == 10 and h[:2] == b"\x05\x64" and dnp3.crc(h[:8]) == h[8:] and h[2] >= 5


def test_s5_input_7_has_one_candidate_per_frame_at_its_densest():
    # D3's N1 on #698: 05 64 repeated gives no candidate, since the CRC of
    # 05 64 05 64 05 64 05 64 is 82 E4. Input (7) ends each frame with that
    # header and its CRC (builder-s5-7).
    v = {r["id"]: r["value"] for r in rows(CONDITIONS)}
    tail = bytes.fromhex(v["builder-s5-7"])
    run = b"\x05\x64" * 4
    assert dnp3.crc(run) == b"\x82\xe4" and tail == run + dnp3.crc(run)
    for src in (5, 1):  # m's link address over UDP and over TCP (builder-msgs)
        hdr = b"\x05\x64" + bytes([255, 0xC4, 10, 0, src, 0])
        f = hdr + dnp3.crc(hdr) + b"\x05\x64" * 136 + tail
        assert len(f) == frame_len(250) == 292 and f[:10] == dnp3.link(10, src, True, bytes(250))[:10]
        assert len(chunks(f)) == 16 and all(dnp3.crc(d) != c for d, c in chunks(f))
        assert [i for i in range(1, 292) if f[i:i + 2] == b"\x05\x64"] == list(range(10, 290, 2))
        for after in (b"", f):
            assert [i for i in range(1, 292) if candidate(f + after, i)] == [282]
        # The last offset at which a whole candidate fits inside the frame.
        assert len(f) - 10 == 282


def sampled(n, threshold=25, rate=1000):
    # Reporter::PermitNetWeird at v9.0.1 (report-weird-sampling).
    return sum(1 for c in range(1, n + 1) if c <= threshold or (c - threshold) % rate == 0)


def test_the_weird_counts_follow_the_sampling_rule():
    a = {r["case"]: r["a"] for r in rows(CASES)}
    assert sampled(2000) == 26 and "passes as 26 events" in a["dnp3-resync-udp-weird-burst"]
    assert sampled(201) == 25 and "dnp3_corrupt_app_chunk_checksum=25" in a["dnp3-resync-udp-report-cap"]

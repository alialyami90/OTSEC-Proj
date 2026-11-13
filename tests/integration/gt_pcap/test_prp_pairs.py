"""Self-tests of GT-PCAP's PRP pairs (D6, P4-D6-GT2). Stdlib only and no
tshark, so they run in the pytest job. Tshark's half, which places the tag
and the RCT and checks every claim, runs in a6-gt-pcap.yml's prp-pairs job
(prp_pairs_label.py).

prp-pairs.tsv is the pass conditions of C13 0.2's test P-2 on these pairs,
written before any discard stage exists. A later edit must be visible, so
its SHA-256 is pinned here (LF line endings, as Git stores it)."""

import csv
import hashlib
import os
import struct

import prp_pairs
import prp_pairs_label as L

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "..", "fixtures", "network", "gt-pcap", "prp-pairs")
LABEL_SHA256 = "8fd6fced66469748698a19d05075517d6a87a9e5c9f2a7db7f090c40374b7baa"


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def label_rows():
    with open(os.path.join(FIX, "prp-pairs.tsv"), "rb") as f:
        text = f.read().replace(b"\r\n", b"\n").decode("utf-8")
    lines = [ln for ln in text.split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def test_the_writer_gives_the_pinned_capture(tmp_path):
    prp_pairs.main(str(tmp_path))
    with open(os.path.join(FIX, "prp-pairs.sha256"), encoding="ascii") as f:
        pins = {ln.split()[1]: ln.split()[0] for ln in f if ln.strip()}
    assert sorted(pins) == ["prp-pairs.json", "prp-pairs.pcap"]
    for name, want in pins.items():
        assert sha256((tmp_path / name).read_bytes()) == want, name


def test_the_pass_conditions_are_the_pinned_label():
    with open(os.path.join(FIX, "prp-pairs.tsv"), "rb") as f:
        assert sha256(f.read().replace(b"\r\n", b"\n")) == LABEL_SHA256


def test_the_label_rows_are_the_writers_claims():
    rows = label_rows()
    pairs = prp_pairs.pairs()
    got = [r for r in rows if r["kind"] == "pair"]
    assert [r["pair"] for r in got] == [n for n, _, _ in pairs]
    for r, (_, _, claim) in zip(got, pairs):
        assert r["verdict"] == claim["verdict"] and r["note"] == claim["note"]
        assert all(int(r[k]) == claim[k] for k in L.COUNTERS)
    total = next(r for r in rows if r["kind"] == "total")
    assert total["frames"] == "14" and total["verdict"] == "passed=9"
    assert [int(total[k]) for k in L.COUNTERS] == [5, 4, 1]
    assert len([r for r in rows if r["kind"] == "frame"]) == 14


def parts(data):
    """(header length, RCT offset) from the bytes: the TPID, and the IPv4
    total length, which the job takes from tshark's vlan.id and ip.len."""
    header = 18 if data[12:14] == b"\x81\x00" else 14
    return header, header + struct.unpack("!H", data[header + 2:header + 4])[0]


def outcomes(comparable=L.comparable, tag=L.tag, where=parts):
    """CH-28's outcome on every pair, with the parts of the reading given."""
    out = []
    for _, copies, _ in prp_pairs.pairs():
        forms = []
        for _, data in copies:
            header, at = where(data)
            seq, ls = struct.unpack("!HH", data[at:at + 4])
            forms.append((data[6:12], seq, ls >> 12, tag(data, header), comparable(data, header, at)))
        try:
            out.append(L.verdict(*forms))
        except ValueError:
            out.append(("both-passed", "not taken for copies"))
    return out


def test_every_claim_holds_on_the_bytes():
    claims = [(c["verdict"], {k: c[k] for k in L.COUNTERS}) for _, _, c in prp_pairs.pairs()]
    assert outcomes() == claims


def test_each_wrong_reading_of_the_comparison_is_caught_by_a_pair():
    """Mutants of CH-28 a discard stage could ship. Each must change the
    outcome of at least one pair, so that a stage built on it fails P-2."""
    right = outcomes()

    def masked(d, at):
        return d[at:at + 2] + bytes([d[at + 2] & 0x0F]) + d[at + 3:at + 6]

    mutants = {
        "the tag compared": dict(comparable=lambda d, h, at: d[:at] + masked(d, at)),
        "octets after the RCT compared": dict(comparable=lambda d, h, at: L.comparable(d, h, at) + d[at + 6:]),
        "the LAN ID not masked": dict(comparable=lambda d, h, at: d[:12] + d[h - 2:at + 6]),
        "the content not compared": dict(comparable=lambda d, h, at: b""),
        "only the VID taken as the tag": dict(tag=lambda d, h: bytes([d[14] & 0x0F, d[15]]) if h == 18 else None),
        "the RCT taken as the last six octets": dict(where=lambda d: (parts(d)[0], len(d) - 6)),
    }
    for name, how in mutants.items():
        assert outcomes(**how) != right, f"no pair catches: {name}"

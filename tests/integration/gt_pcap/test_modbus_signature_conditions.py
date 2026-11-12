"""The Modbus signature's pass conditions are pinned (D6, brief P4-4-E2).

modbus-signature-conditions.tsv is what P4-4-E2's counted run is judged by,
and it was written before any measurement of the signature. A later edit
must be visible, so this test pins the file's SHA-256 (with LF line
endings, as Git stores it), as pins.env pins it for the run. Its detection
rows must be exactly the Modbus rows of engine-pass-conditions.tsv, so a
change to those rows can't leave the two files describing different cases."""

import csv
import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = os.path.join(HERE, "modbus-signature-conditions.tsv")
SHA256 = "7b242b85a3387c3f591eb21cce2e3f036feb8c1c8799e02857548a2e5f6f4418"
COLUMNS = ["id", "subject", "op", "value", "rule"]


def content():
    with open(FILE, "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def rows():
    lines = [ln for ln in content().decode("utf-8").split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def test_the_conditions_are_the_pinned_file():
    assert hashlib.sha256(content()).hexdigest() == SHA256


def test_every_row_is_whole_and_named_once():
    rs = rows()
    assert list(rs[0]) == COLUMNS
    assert len({r["id"] for r in rs}) == len(rs)
    for r in rs:
        assert None not in r and None not in r.values() and r["rule"], r
        assert (r["op"] == "") == (r["value"] == ""), r
        assert r["op"] in ("", "=", "<=", ">="), r


def test_the_detection_rows_are_the_modbus_rows_of_the_engine_conditions():
    with open(os.path.join(HERE, "engine-pass-conditions.tsv"), encoding="utf-8") as f:
        engine = list(csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE))
    modbus = sorted(f"{r['capture']}/{r['condition']}" for r in engine if r["protocol"] == "modbus")
    assert modbus == ["modbus-moved-port/function", "modbus-moved-port/protocol", "modbus-moved-port/service"]
    assert sorted(r["subject"] for r in rows() if r["id"].startswith("det-")) == modbus

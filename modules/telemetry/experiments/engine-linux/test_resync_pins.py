"""HR25-B2 (D4-131 item 2.1; brief HR25-B2, acceptance test 4): pins.env's
RESYNC_CASES_SHA256 and RESYNC_CONDITIONS_SHA256 equal the values
tests/integration/gt_pcap/test_resync_conditions.py holds, and the SHA-256
of the two files as Git stores them (LF endings). Its control: with one row
of either file changed, the check refuses.

Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_resync_pins.py
"""
import hashlib
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
GT = os.path.join(HERE, "..", "..", "..", "..", "tests", "integration", "gt_pcap")
FILES = {"RESYNC_CASES_SHA256": ("resync-cases.tsv", "CASES_SHA256"),
         "RESYNC_CONDITIONS_SHA256": ("resync-conditions.tsv", "CONDITIONS_SHA256")}


def text(path):
    with open(path, "rb") as fh:
        return fh.read().replace(b"\r\n", b"\n")


def pins():
    out = {}
    for ln in text(os.path.join(HERE, "pins.env")).decode().split("\n"):
        if "=" in ln and not ln.startswith("#"):
            k, v = ln.split("=", 1)
            out[k] = v
    return out


def held():
    """The values test_resync_conditions.py holds."""
    t = text(os.path.join(GT, "test_resync_conditions.py")).decode()
    return {k: re.search(r'^%s = "([0-9a-f]{64})"$' % k, t, re.M).group(1) for _, k in FILES.values()}


def check(pinned, holds, contents):
    """Every problem: a pin missing, unequal to the test's value, or unequal
    to its file's SHA-256. `contents` maps each file name to its octets."""
    bad = []
    for pin, (name, var) in FILES.items():
        v = pinned.get(pin)
        if v is None:
            bad.append(f"{pin} missing")
            continue
        if v != holds[var]:
            bad.append(f"{pin} is not {var} of test_resync_conditions.py")
        if v != hashlib.sha256(contents[name]).hexdigest():
            bad.append(f"{pin} is not the SHA-256 of {name}")
    return bad


def contents():
    return {name: text(os.path.join(GT, name)) for name, _ in FILES.values()}


def test_the_pins_equal_the_tests_values_and_the_files():
    assert check(pins(), held(), contents()) == []


def changed_row(b):
    """b with the first character of its last row changed."""
    lines = b.split(b"\n")
    i = max(k for k, ln in enumerate(lines) if ln)
    lines[i] = (b"x" if lines[i][:1] != b"x" else b"y") + lines[i][1:]
    return b"\n".join(lines)


def test_the_check_refuses_a_changed_row_of_either_file():
    for name, _ in FILES.values():
        c = contents()
        c[name] = changed_row(c[name])
        assert check(pins(), held(), c) == [f"{[p for p, (n, _) in FILES.items() if n == name][0]} "
                                            f"is not the SHA-256 of {name}"]


def test_the_check_refuses_a_missing_pin_and_one_unequal_to_the_tests():
    p = pins()
    del p["RESYNC_CASES_SHA256"]
    assert check(p, held(), contents()) == ["RESYNC_CASES_SHA256 missing"]
    p = pins()
    p["RESYNC_CONDITIONS_SHA256"] = "0" * 64
    assert "RESYNC_CONDITIONS_SHA256 is not CONDITIONS_SHA256 of test_resync_conditions.py" in \
        check(p, held(), contents())

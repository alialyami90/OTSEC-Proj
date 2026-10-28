"""Writes replies.json: SHO replies as B6's recording simulator prints them,
each with the settings B6 reads from the bytes, for c9_b6_test.go.

Run from the repository root: python3 -I tests/contract/testdata/c9_b6/generate.py

The replies come from tests/safety/recording_simulator/profile_sel751.py
(#248), which prints Figure 7.43 (S22 p. 7.78) from B6's own transcription,
the General Global Settings and the Port 1 defaults (Table 4.104). The
settings are read with that module's Printed class: a cell is a name and
":=", and its value runs to the next cell or the line end. That reading is
B6's, written apart from contracts/config, so the Go test checks two readings
of the same bytes against each other. Nothing here was captured from a
device: the evidence class is documented-example, simulated.
"""
import json
import os
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "safety", "recording_simulator"))
import profile_sel751 as p  # noqa: E402


def responder(**kw):
    return p.SEL751DocResponder(None, **kw)


def case(text, **extra):
    s = text.decode("ascii")
    return dict(text=s, settings=[[n, v] for n, v in p.Printed(s.replace("\r\n", "\n")).settings().items()], **extra)


def main():
    out = {}
    for n in (1, 2, 3, 4):
        out[f"group{n}"] = case(responder()._show_group(n)[0])
    out["group1-one-per-line"] = case(responder(sho_layout="one-per-line")._show_group(1)[0])
    with tempfile.TemporaryDirectory() as d:
        inj = os.path.join(d, "settings.json")
        with open(inj, "w") as f:
            json.dump({"1": {"50P1P": "9.50"}}, f)
        out["group1-50P1P-9.50"] = case(responder(settings_file=inj)._show_group(1)[0], changed=["50P1P", "10.00", "9.50"])
        with open(inj, "w") as f:
            json.dump({"1": {"LL": None, "B6TEST": "7"}}, f)
        out["group1-LL-removed-B6TEST-added"] = case(responder(settings_file=inj)._show_group(1)[0])
    dup, _ = responder(sho_fault="duplicate")._show_group(1)
    out["group1-duplicate"] = dict(text=dup.decode("ascii"), duplicate="50P1P")
    # The hang fault's reply: cut before "Phase TOC", no ETX or prompt after.
    full, _ = responder()._show_group(1)
    out["group1-cut"] = case(full[:full.index(b"Phase TOC")])
    out["global"] = case(responder()._show_global())
    out["port1"] = case(responder()._show_port1())
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "replies.json"), "w", newline="\n") as f:
        json.dump(out, f, indent=1, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()

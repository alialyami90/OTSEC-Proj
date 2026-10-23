"""A6 adversarial cases for A4's GOOSE stNum/sqNum checks (goose_seq_check.py), PR #4.

A4's check() reads frames from tshark. Here frames() is replaced with
hand-built sequences, each labeled by construction (GT-HAND), so the rule
logic is scored without a capture. Cases are benign events the rules may call
attacks, and attacks the rules may miss. Frame tuples are
(number, gocbRef, stNum, sqNum, t_ns). Behaviour assumed from IEC 61850-8-1
as A4's README describes it (stNum increments on a state change and sqNum
restarts; sqNum increments on each retransmission); sqNum and stNum are
32-bit unsigned counters. Captures of real SEL GOOSE publishers do not exist
in this project, so these are `simulated`.

Run: python3 -I tests/integration/reviews/A4/goose_seq_cases.py <path to goose_seq_check.py>
"""

import importlib.util
import json
import sys

REF = "LIED10CTRL/LLN0$Status"
S = 10**9


def steady(start_frame, st, sq0, n, t, ref=REF):
    return [(start_frame + i, ref, st, sq0 + i, t) for i in range(n)]


def cases():
    t0 = 1_700_000_000 * S
    c = []
    # Benign: a frame lost by the sensor (SPAN drop) - a gap, not an attack.
    f = steady(1, 5, 0, 3, t0) + steady(5, 5, 4, 2, t0)
    c.append(("benign: one retransmission lost in capture", f, set()))
    # Benign: PRP - the sensor sees the LAN A and LAN B copies of every frame.
    f, n = [], 1
    for sq in range(4):
        f += [(n, REF, 5, sq, t0), (n + 1, REF, 5, sq, t0)]
        n += 2
    c.append(("benign: PRP duplicate copies (LAN A and LAN B on one sensor)", f, set()))
    # Benign: publisher reboot restarts stNum at 1.
    f = steady(1, 812, 10, 3, t0) + steady(4, 1, 0, 3, t0 + 60 * S)
    c.append(("benign: publishing IED restarted (stNum back to 1)", f, set()))
    # Benign: sqNum wraps after 2^32 - 1.
    f = [(1, REF, 5, 2**32 - 2, t0), (2, REF, 5, 2**32 - 1, t0), (3, REF, 5, 1, t0), (4, REF, 5, 2, t0)]
    c.append(("benign: sqNum 32-bit rollover", f, set()))
    # Attack: a well-formed injected state change (stNum+1, sqNum 0, fresh t).
    f = steady(1, 5, 0, 3, t0) + [(4, REF, 6, 0, t0 + S)] + steady(5, 5, 3, 2, t0)
    c.append(("attack: injected state change with correct stNum+1, sqNum 0, fresh t", f, {4}))
    # Attack: the injected frame is the first frame seen for its gocbRef.
    f = [(1, REF, 999, 0, t0)] + steady(2, 5, 0, 3, t0)
    c.append(("attack: injection before the first legitimate frame in the capture", f, {1}))
    # Attack: the attacker continues the sequence, taking over the stream.
    f = steady(1, 5, 0, 3, t0) + [(4, REF, 6, 0, t0 + S), (5, REF, 6, 1, t0 + S), (6, REF, 6, 2, t0 + S)]
    c.append(("attack: takeover; legitimate publisher silenced (no later legitimate frames)", f, {4, 5, 6}))
    # Attack: a forged control block name never seen before.
    f = steady(1, 5, 0, 3, t0) + [(4, "LIED99CTRL/LLN0$Trip", 1, 0, t0 + S)]
    c.append(("attack: new gocbRef not in any baseline", f, {4}))
    return c


def main(path):
    spec = importlib.util.spec_from_file_location("goose_seq_check", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = []
    for name, frames, truth in cases():
        mod.frames = lambda _pcap, frames=frames: iter(frames)
        flagged = mod.check("synthetic")
        fp = sorted(set(flagged) - truth)
        fn = sorted(truth - set(flagged))
        out.append({"case": name, "attack_frames": sorted(truth), "flagged": sorted(flagged),
                    "missed": fn, "false_alarms": fp,
                    "reasons": {str(k): v[1] for k, v in flagged.items()},
                    "pass": not fp and not fn})
    print(json.dumps({"reviewed": path, "classification": "simulated", "cases": out}, indent=2))


if __name__ == "__main__":
    main(sys.argv[1])

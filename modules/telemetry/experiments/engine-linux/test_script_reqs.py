"""CH-53's third requirement on the project's script, on its text: no
`connection_timing_out` hook (D4-102 item 6; D1's ruling 1 on #715), with
its control, a copy that defines one. And script_reqs.py's readers on
made-up logs, each with the reading that must fail. Run: python -m pytest
-q modules/telemetry/experiments/engine-linux/test_script_reqs.py"""
import os
import re

import script_reqs as sr

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = re.compile(r"\bconnection_timing_out\b")


def defines_timing_out_hook(text):
    return bool(HOOK.search(re.sub(r"#[^\n]*", "", text)))


def test_probe_defines_no_connection_timing_out_hook():
    with open(os.path.join(HERE, "probe.zeek"), encoding="utf-8") as fh:
        text = fh.read()
    assert not defines_timing_out_hook(text)
    # Control: the same script with a hook that can stop the engine's cut.
    assert defines_timing_out_hook(text + "\nhook connection_timing_out(c: connection) { break; }\n")


def row(n, ev, uid, orig_p, ts):
    return {"n": n, "ev": ev, "uid": uid, "orig_p": orig_p, "ts": ts}


def test_timer_cap_reading_needs_every_removal_before_the_new_flow():
    gone = [row(i + 1, "remove", f"U{i}", 31000 + i, 121.0) for i in range(600)]
    new = row(601, "new", "N", 5000, 121.0)
    assert sr.all_removed_first(gone + [new], [])
    # 300 removed after the new flow starts, as at max_timer_expires 300.
    late = gone[:300] + [dict(new, n=301)] + [dict(r, n=302 + i) for i, r in enumerate(gone[300:])]
    assert not sr.all_removed_first(late, [])


def test_idle_cut_reading_needs_the_removal_at_the_frame_at_60_010_s():
    t = [row(1, "new", "A", 40100, 0.001), row(2, "new", "O", 5001, 59.995), row(3, "remove", "A", 40100, 60.015)]
    assert sr.cut_at_flow_idle(t, [])
    t[2] = row(3, "remove", "A", 40100, 70.005)  # removed only at its next segment, as at 5 min
    assert not sr.cut_at_flow_idle(t, [])
    # Removed at the frame at 59.990 s, before the other flow starts, as at
    # any bound below 59.990 s (D6's N8 on #715).
    early = [row(1, "new", "A", 40100, 0.001), row(2, "remove", "A", 40100, 59.995), row(3, "new", "O", 5001, 59.995)]
    assert not sr.cut_at_flow_idle(early, [])


def test_timeout_reading_needs_the_first_frame_at_or_after_the_bound():
    t = [row(1, "new", "D", 20000, 1000.001)]
    assert sr.timeout_at_frame_after_bound(t, [{"seq": 1, "done": "timeout", "ts": 1005.011}])
    assert not sr.timeout_at_frame_after_bound(t, [{"seq": 1, "done": "timeout", "ts": 1004.991}])
    assert not sr.timeout_at_frame_after_bound(t, [{"seq": 1, "done": "response", "ts": 1005.011}])
    assert not sr.timeout_at_frame_after_bound(t, [])


def test_idle_readings_need_the_cut_and_the_right_completion():
    t = [row(1, "new", "A", 40200, 1000.001), row(2, "new", "B", 40300, 1000.006),
         row(3, "remove", "A", 40200, 1020.0), row(4, "remove", "B", 40300, 1020.0)]
    assert sr.not_discarded(t, [{"seq": 2, "done": "response", "ts": 1022.003}])
    assert not sr.not_discarded(t, [])  # discarded at the cut
    assert sr.not_completed(t, [{"seq": 3, "done": "timeout", "ts": 1031.0}])
    assert not sr.not_completed(t, [{"seq": 3, "done": "idle", "ts": 1020.0}])  # completed at the cut
    assert not sr.not_completed(t[:2], [{"seq": 3, "done": "timeout", "ts": 1031.0}])  # no cut seen


def test_the_captures_are_written(tmp_path):
    sr.write(str(tmp_path))
    assert sorted(os.listdir(tmp_path)) == ["req-dnp3-idle.pcap", "req-dnp3-timeout.pcap", "req-idle.pcap",
                                            "req-timer-cap.pcap"]

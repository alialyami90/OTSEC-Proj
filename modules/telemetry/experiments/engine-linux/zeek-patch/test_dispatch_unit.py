"""HR-23 (D4, brief P4-4-HR23 stage 3): dispatch_unit.py's verdicts on
made-up logs (D6's N3 on #715). Each row reads C2 against its control C1p;
a configuration that did not run makes the row unknown, and one whose Zeek
exited non-zero fails it, so a crash is never read as a silent stop. Run:
python -m pytest -q modules/telemetry/experiments/engine-linux/zeek-patch"""
import json

import dispatch_unit as du

MET = lambda m, l, v: m == []  # noqa: E731  (met when no header was logged)


def cfg_dir(tmp_path, cfg, rc="0", headers=0):
    d = tmp_path / cfg
    d.mkdir()
    if rc is not None:
        (d / "exit-code").write_text(rc + "\n")
    rows = [{"kind": "fc", "is_orig": True, "fc": 1, "ev": "dnp3_application_request_header"}] * headers
    (d / "otsec_probe.log").write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(d)


def test_state_reads_met_not_met_exit_and_not_run(tmp_path):
    assert du.state(cfg_dir(tmp_path, "a"), MET) == "met"
    assert du.state(cfg_dir(tmp_path, "b", headers=1), MET) == "not met"
    # A crash after partial logs: the logs alone would read `met`.
    assert du.state(cfg_dir(tmp_path, "c", rc="134"), MET) == "exit 134"
    assert du.state(cfg_dir(tmp_path, "d", rc=None), MET) == "not run"
    assert du.state(str(tmp_path / "missing"), MET) == "not run"


def test_fix_passes_only_when_c2_meets_it_and_the_control_does_not():
    assert du.verdict("fix", "met", "not met") == "pass"
    assert du.verdict("fix", "met", "met") == "fail"  # the control meets it too
    assert du.verdict("fix", "not met", "not met") == "fail"
    assert du.verdict("fix-negative", "met", "not met") == "pass"


def test_same_passes_only_when_both_meet_it():
    assert du.verdict("same", "met", "met") == "pass"
    assert du.verdict("same", "met", "not met") == "fail"  # the control column is read
    assert du.verdict("same", "not met", "met") == "fail"


def test_a_residual_is_never_a_pass_and_still_fails_on_a_crash():
    for c in ("met", "not met"):
        assert du.verdict("residual", c, c) == "residual (measured, not judged)"
    assert du.verdict("residual", "exit 139", "met") == "fail"


def test_a_residual_fails_when_c2_differs_from_its_control():
    # D6's N7 on #715: the residual input's code agrees with its side, so
    # the patch must leave its result as C1p's.
    assert du.verdict("residual", "not met", "met") == "fail"
    assert du.verdict("residual", "met", "not met") == "fail"


def test_not_run_is_unknown_and_a_non_zero_exit_fails():
    assert du.verdict("same", "not run", "met") == "unknown (not run)"
    assert du.verdict("fix", "met", "not run") == "unknown (not run)"
    assert du.verdict("same", "exit 134", "met") == "fail"
    assert du.verdict("fix", "met", "exit 1") == "fail"

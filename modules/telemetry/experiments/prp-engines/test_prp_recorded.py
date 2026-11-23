"""prp_recorded.py (P4-SENSOR-EVAL-GREEN, acceptance test 1): the recorded
result against itself passes, and each control fails. Run:
python -m pytest -q modules/telemetry/experiments/prp-engines/test_prp_recorded.py"""
import pytest

import prp_recorded as pr


def produced():
    """prp-engines.md as compare.py writes it, cut from the recorded file."""
    with open(pr.RECORDED, encoding="utf-8") as f:
        lines = f.read().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("|"))
    end = next(i for i, l in enumerate(lines) if pr.CLOSING.match(l))
    return "\n".join(lines[start:end + 1]) + "\n"


ROW = "| dnp3-read | zeek | 1 | 1 | 1 | 8 | 16 | yes | no | yes | 1 of 1 | no |"


def run(tmp_path, text, code=1):
    p = tmp_path / "prp-engines.md"
    p.write_text(text, encoding="utf-8")
    return pr.check(str(p), code)


def test_recorded_against_itself(tmp_path):
    assert ROW in produced()
    assert run(tmp_path, produced()) == []


@pytest.mark.parametrize("change, where", [
    # a failing row that now passes (and the count in the closing line with it)
    (lambda t: t.replace(ROW, ROW.replace("| yes | no | yes | 1 of 1 | no |", "| yes | yes | yes | 1 of 1 | yes |"))
     .replace("18 row(s)", "17 row(s)"), "row dnp3-read / zeek:"),
    # a row missing
    (lambda t: t.replace(ROW + "\n", ""), "row dnp3-read / zeek: missing"),
    # a row added
    (lambda t: t.replace(ROW, ROW + "\n" + ROW.replace("zeek", "zeek-other")), "row dnp3-read / zeek-other: added"),
])
def test_control_differs(tmp_path, change, where):
    d = run(tmp_path, change(produced()))
    assert any(l.startswith(where) for l in d), d


def test_passing_row_that_now_fails(tmp_path):
    # Every recorded row fails, so this control records one passing row and
    # then shows it failing.
    passing = ROW.replace("| yes | no | yes | 1 of 1 | no |", "| yes | yes | yes | 1 of 1 | yes |")
    rec = tmp_path / "recorded.md"
    rec.write_text(produced().replace(ROW, passing) + "\nrun.sh exit code: 1\n", encoding="utf-8")
    out = tmp_path / "prp-engines.md"
    out.write_text(produced(), encoding="utf-8")
    assert pr.check(str(out), 1, str(rec)) == [f"row dnp3-read / zeek: {ROW} (recorded {passing})"]


def test_other_exit_code(tmp_path):
    assert run(tmp_path, produced(), code=0) == ["run.sh exit code: 0 (recorded 1)"]


def test_missing_file(tmp_path):
    assert "missing or unreadable" in pr.check(str(tmp_path / "absent.md"), 1)[0]


def test_empty_file(tmp_path):
    assert run(tmp_path, "") == [f"{tmp_path / 'prp-engines.md'}: empty or has no table"]


def test_main_exit_codes(tmp_path, capsys):
    p = tmp_path / "prp-engines.md"
    p.write_text(produced(), encoding="utf-8")
    assert pr.main(["x", str(p), "1"]) == 0
    assert "same as the recorded result" in capsys.readouterr().out
    p.write_text("", encoding="utf-8")
    assert pr.main(["x", str(p), "1"]) == 1
    assert "DIFFERS:" in capsys.readouterr().out

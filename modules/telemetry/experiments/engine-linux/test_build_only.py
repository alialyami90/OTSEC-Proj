"""The `build_only` input of d4-engine-linux-eval.yml (HR25-B1; D1's ruling
(2) in D4-124): it builds and records the images and runs no engine over
any capture and no test, and uploads only the build record.

The workflow is read as text, step by step (no YAML library on CI's python
job). Each control edits the workflow so that one engine step, one job or
the upload would run under build_only, and the check must refuse it.

Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_build_only.py
"""
import os
import re

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "d4-engine-linux-eval.yml")
SKIP = "!inputs.build_only"
# The steps that may run under build_only, by their name or action.
ALLOWED = ("actions/checkout", "Free disk for the Zeek build", "build.sh refuses every changed input",
           "Build C1p, C2, C2A and the controls")


def jobs(wf):
    """{job: (job if, [step dicts])}; a step holds name, uses, if and run."""
    out, job, step, key = {}, None, None, None
    body = wf.split("\njobs:\n", 1)[1]
    for ln in body.split("\n"):
        m = re.match(r"^  ([a-z0-9-]+):$", ln)
        if m:
            job = m.group(1)
            out[job] = ["", []]
            step = None
            continue
        if job is None:
            continue
        m = re.match(r"^    if: (.*)$", ln)
        if m and step is None:
            out[job][0] = m.group(1)
            continue
        m = re.match(r"^      - (\w[\w-]*): ?(.*)$", ln)
        if m:
            step = {m.group(1): m.group(2)}
            out[job][1].append(step)
            key = m.group(1)
            continue
        m = re.match(r"^        (\w[\w-]*): ?(.*)$", ln)
        if m and step is not None:
            key = m.group(1)
            step[key] = m.group(2)
            continue
        if step is not None and ln.startswith("          ") and key in ("run", "with"):
            step[key] = step.get(key, "") + "\n" + ln.strip()
    return out


def runs_under_build_only(step):
    return SKIP not in step.get("if", "")


def check(wf):
    assert re.search(r"^      build_only:\n        description: .*\n        type: boolean\n        default: false$",
                     wf, re.M), "build_only is not a boolean input that defaults to false"
    js = jobs(wf)
    for name, (cond, _) in js.items():
        if name != "hr23":
            assert SKIP in cond, f"job {name} runs under build_only"
    cond, steps = js["hr23"]
    assert "inputs.build_only" in cond.replace(SKIP, ""), "the hr23 job does not run under build_only"
    uploads = 0
    for st in steps:
        label = st.get("name") or st.get("uses", "")
        if not runs_under_build_only(st):
            continue
        if "upload-artifact" in st.get("uses", ""):
            uploads += 1
            assert "inputs.build_only" in st.get("if", ""), "an upload that is not build_only's runs under it"
            paths = [p for p in st.get("with", "").split("\n") if p.startswith("${{ runner.temp }}")]
            assert paths == ["${{ runner.temp }}/e-d4-03/zeek-build.txt"], f"build_only uploads {paths}"
            continue
        assert label.startswith(ALLOWED), f"step '{label}' runs under build_only"
        run = st.get("run", "")
        assert "run.sh" not in run and "fetch_captures" not in run and "apt-get" not in run, \
            f"step '{label}' runs an engine, a fetch or an install under build_only"
    assert uploads == 1, "build_only does not upload exactly one artifact"


def read():
    with open(WORKFLOW, encoding="utf-8") as fh:
        return fh.read().replace("\r\n", "\n")


def test_build_only_skips_every_engine_step_and_uploads_only_the_record():
    check(read())


def test_build_only_still_builds():
    steps = jobs(read())["hr23"][1]
    build = [s for s in steps if s.get("name", "").startswith("Build C1p")]
    assert len(build) == 1 and runs_under_build_only(build[0]) and "build.sh build" in build[0]["run"]


CONTROLS = [
    ("an engine step without the skip", ("&& !inputs.build_only && !inputs.hr25_unit }}\n        run: sh modules/"
                                         "telemetry/experiments/engine-linux/run.sh dnp3",
                                         "&& !inputs.hr25_unit }}\n        run: sh modules/telemetry/experiments/"
                                         "engine-linux/run.sh dnp3")),
    ("the hr23 unit step without the skip", ("&& !inputs.build_only && !inputs.hr25_unit }}\n        run: sh modules/"
                                             "telemetry/experiments/engine-linux/run.sh hr23-unit",
                                             "}}\n        run: sh modules/telemetry/experiments/engine-linux/run.sh "
                                             "hr23-unit")),
    ("the hr25 unit step without the skip", ("inputs.hr25_unit && !inputs.build_only }}",
                                             "inputs.hr25_unit }}")),
    ("the dnp3-public job without the skip", ("  dnp3-public:\n    if: ${{ !inputs.build_only && !inputs.hr25_unit }}",
                                              "  dnp3-public:\n    if: ${{ !inputs.hr25_unit }}")),
    ("the full upload under build_only", ("if: ${{ always() && !inputs.build_only }}", "if: ${{ always() }}")),
    ("a second path in build_only's upload", ("            ${{ runner.temp }}/e-d4-03/zeek-build.txt\n"
                                              "          if-no-files-found: warn\n      - uses",
                                              "            ${{ runner.temp }}/e-d4-03/zeek-build.txt\n"
                                              "            ${{ runner.temp }}/hr23-selftest.md\n"
                                              "          if-no-files-found: warn\n      - uses")),
    ("the input missing", ("      build_only:\n", "      build_nothing:\n")),
]


@pytest.mark.parametrize("name,edit", CONTROLS, ids=[c[0] for c in CONTROLS])
def test_each_control_is_refused(name, edit):
    wf = read()
    assert wf.count(edit[0]) >= 1, f"control '{name}' no longer matches the workflow"
    with pytest.raises(AssertionError):
        check(wf.replace(edit[0], edit[1], 1))

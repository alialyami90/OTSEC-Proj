"""The `build_only` and `hr25_unit` inputs of d4-engine-linux-eval.yml
(HR25-B1; D1's ruling (2) in D4-124). Under `build_only` the job builds and
records the images, runs no engine over any capture and no test, and
uploads only the build record. Under `hr25_unit` it runs only the build
steps, the `hr25-unit` step and one upload: no job but `hr23`, and no other
engine, fetch or install.

The workflow is read as text, step by step (no YAML library on CI's python
job). Each condition is read as a conjunction (D3's N1 and D6's N2 on
#789): a step or job is skipped under an input only when its condition is
`${{ a && b && ... }}` with no `||` and no `always()`, and one conjunct is
`!inputs.<that input>` (or, under hr25_unit, `inputs.build_only`). Any
other condition counts as running. Each control edits the workflow so
that one engine step, one job or an upload would run under an input, and
the check must refuse it.

Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_build_only.py
"""
import os
import re

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "d4-engine-linux-eval.yml")
# The steps that may run under build_only, by their name or action.
ALLOWED = ("actions/checkout", "Free disk for the Zeek build", "build.sh refuses every changed input",
           "Build C1p, C2, C2A and the controls")
# hr25_unit's one engine step.
# The one form of an upload path under hr25_unit: a single report file.
UPLOAD_FILE = r"\$\{\{ runner\.temp \}\}/(e-d4-03/)?[\w.-]+\.(md|txt)"
HR25_STEP = "D4's unit tests of HR-25 option A's patch"


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


def conjuncts(cond):
    """The conjuncts of `${{ a && b }}`, or None when the condition is not a
    plain conjunction (it holds `||` or `always()`)."""
    e = cond.strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", e)
    if m:
        e = m.group(1)
    if "||" in e or "always()" in e:
        return None
    return [c.strip() for c in e.split("&&")]


def skipped(cond, inp):
    """True when `cond` is skipped under `inp`. build_only wins over the
    other inputs, so its skip is always `!inputs.build_only`; under
    hr25_unit a step may also be build_only's own (`inputs.build_only`)."""
    c = conjuncts(cond)
    if c is None:
        return False
    return f"!inputs.{inp}" in c or (inp == "hr25_unit" and "inputs.build_only" in c)


def runs_under_build_only(step):
    return not skipped(step.get("if", ""), "build_only")


def check_hr25_unit(js):
    for name, (cond, _) in js.items():
        if name != "hr23":
            assert skipped(cond, "hr25_unit"), f"job {name} runs under hr25_unit"
    uploads = 0
    for st in js["hr23"][1]:
        label = st.get("name") or st.get("uses", "")
        if skipped(st.get("if", ""), "hr25_unit"):
            continue
        if "upload-artifact" in st.get("uses", ""):
            uploads += 1
            # The engines' own output stays on the runner (D1's ruling on
            # D4-131 item 5.1; B3 and D6's re-review on #803): an allowlist,
            # each path one .md or .txt file, with no glob and no folder.
            for p in st.get("with", "").split("\n"):
                if not p or re.match(r"(name|path|if-no-files-found):", p):
                    continue
                assert re.fullmatch(UPLOAD_FILE, p), f"hr25_unit uploads {p}"
            continue
        assert label.startswith(ALLOWED + (HR25_STEP,)), f"step '{label}' runs under hr25_unit"
        run = st.get("run", "")
        if label.startswith(HR25_STEP):
            assert run.strip() == 'sh modules/telemetry/experiments/engine-linux/run.sh hr25-unit "$RUNNER_TEMP/e-d4-03"'
            continue
        assert "run.sh" not in run and "fetch_captures" not in run and "apt-get" not in run, \
            f"step '{label}' runs an engine, a fetch or an install under hr25_unit"
    assert uploads == 1, "hr25_unit does not upload exactly one artifact"


def check(wf):
    assert re.search(r"^      build_only:\n        description: .*\n        type: boolean\n        default: false$",
                     wf, re.M), "build_only is not a boolean input that defaults to false"
    js = jobs(wf)
    for name, (cond, _) in js.items():
        if name != "hr23":
            assert skipped(cond, "build_only"), f"job {name} runs under build_only"
    cond, steps = js["hr23"]
    m = re.fullmatch(r"\$\{\{(.*)\}\}", cond.strip())
    ors = [d.strip() for d in (m.group(1) if m else cond).split("||")]
    assert "inputs.build_only" in ors and "inputs.hr25_unit" in ors, \
        "the hr23 job does not run under build_only and hr25_unit"
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
    check_hr25_unit(js)


def read():
    with open(WORKFLOW, encoding="utf-8") as fh:
        return fh.read().replace("\r\n", "\n")


def test_build_only_skips_every_engine_step_and_uploads_only_the_record():
    check(read())


def test_build_only_still_builds():
    steps = jobs(read())["hr23"][1]
    build = [s for s in steps if s.get("name", "").startswith("Build C1p")]
    assert len(build) == 1 and runs_under_build_only(build[0]) and "build.sh build" in build[0]["run"]


HR25_MD = "            ${{ runner.temp }}/e-d4-03/hr25-unit.md\n"
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
    ("the full upload under build_only", ("if: ${{ !cancelled() && !inputs.build_only }}", "if: ${{ !cancelled() }}")),
    ("a second path in build_only's upload", ("            ${{ runner.temp }}/e-d4-03/zeek-build.txt\n"
                                              "          if-no-files-found: warn\n      - uses",
                                              "            ${{ runner.temp }}/e-d4-03/zeek-build.txt\n"
                                              "            ${{ runner.temp }}/hr23-selftest.md\n"
                                              "          if-no-files-found: warn\n      - uses")),
    ("the input missing", ("      build_only:\n", "      build_nothing:\n")),
    # D3's N1 (a) and D6's N2 (a) on #789: the skip inside a condition that
    # also holds `||` or `always()`.
    ("an engine step whose skip is or-ed", ("!cancelled() && steps.build.outcome == 'success' && !inputs.build_only "
                                            "&& !inputs.hr25_unit }}\n        run: sh modules/telemetry/experiments/"
                                            "engine-linux/run.sh dnp3",
                                            "!cancelled() && steps.build.outcome == 'success' || !inputs.build_only "
                                            "&& !inputs.hr25_unit }}\n        run: sh modules/telemetry/experiments/"
                                            "engine-linux/run.sh dnp3")),
    ("the prp job's skip or-ed", ("  prp:\n    if: ${{ !inputs.build_only && !inputs.hr25_unit }}",
                                  "  prp:\n    if: ${{ !inputs.build_only || inputs.hr23_build }}")),
    ("an engine step under always() or the skip", ("if: ${{ !cancelled() && steps.build.outcome == 'success' && "
                                                   "!inputs.build_only && !inputs.hr25_unit }}\n        run: sh "
                                                   "modules/telemetry/experiments/engine-linux/run.sh dnp3",
                                                   "if: ${{ always() || !inputs.build_only }}\n        run: sh "
                                                   "modules/telemetry/experiments/engine-linux/run.sh dnp3")),
    ("an engine step with always() beside the skip", ("if: ${{ !cancelled() && steps.build.outcome == 'success' && "
                                                      "!inputs.build_only && !inputs.hr25_unit }}\n        run: sh "
                                                      "modules/telemetry/experiments/engine-linux/run.sh dnp3",
                                                      "if: ${{ always() && !inputs.build_only && !inputs.hr25_unit }}"
                                                      "\n        run: sh modules/telemetry/experiments/engine-linux/"
                                                      "run.sh dnp3")),
    # D3's N1 (b) and D6's N2 (b): hr25_unit's skips.
    ("an engine step without hr25_unit's skip", ("&& !inputs.build_only && !inputs.hr25_unit }}\n        run: sh "
                                                 "modules/telemetry/experiments/engine-linux/run.sh dnp3",
                                                 "&& !inputs.build_only }}\n        run: sh modules/telemetry/"
                                                 "experiments/engine-linux/run.sh dnp3")),
    ("the dnp3-public job without hr25_unit's skip", ("  dnp3-public:\n    if: ${{ !inputs.build_only && "
                                                      "!inputs.hr25_unit }}",
                                                      "  dnp3-public:\n    if: ${{ !inputs.build_only }}")),
    ("the prp job without hr25_unit's skip", ("  prp:\n    if: ${{ !inputs.build_only && !inputs.hr25_unit }}",
                                              "  prp:\n    if: ${{ !inputs.build_only }}")),
    # B3 on #803: an upload under hr25_unit that names the unit mode's
    # folder, an output folder or engine.log.
    ("hr25_unit uploads its folder", (HR25_MD, HR25_MD + "            ${{ runner.temp }}/e-d4-03/hr25-unit/\n")),
    ("hr25_unit uploads an output folder", (HR25_MD, HR25_MD + "            ${{ runner.temp }}/e-d4-03/out/\n")),
    ("hr25_unit uploads engine.log", (HR25_MD, HR25_MD + "            ${{ runner.temp }}/engine.log\n")),
    ("hr25_unit uploads its folder without the slash",
     (HR25_MD, HR25_MD + "            ${{ runner.temp }}/e-d4-03/hr25-unit\n")),
    ("hr25_unit uploads the parent folder", (HR25_MD, HR25_MD + "            ${{ runner.temp }}/e-d4-03\n")),
    ("hr25_unit uploads a glob", (HR25_MD, HR25_MD + "            ${{ runner.temp }}/**/*.log\n")),
]


@pytest.mark.parametrize("name,edit", CONTROLS, ids=[c[0] for c in CONTROLS])
def test_each_control_is_refused(name, edit):
    wf = read()
    assert wf.count(edit[0]) >= 1, f"control '{name}' no longer matches the workflow"
    with pytest.raises(AssertionError):
        check(wf.replace(edit[0], edit[1], 1))

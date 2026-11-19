"""D6's B1 on #751: run.sh's own `public` block, from `counted=` to the `fi`
that closes the pubrc check, run under `sh -eu` with the real table.py over
made-up capture and output folders (header() is a stub; no engine runs). A
run on refs/heads/main with one capture missing fails, a run on any other
ref stays green, and a run on main with none missing passes. D6's mutants
R1 to R5 of the block are the controls: each must make the checks fail.
Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_run_counted.py"""
import os
import shutil
import subprocess
import sys

import pytest

import table

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
LISTS = [os.path.join(ROOT, "tests", "fixtures", "network", "public-ot-captures", "MANIFEST.tsv"),
         os.path.join(HERE, "extra-captures.tsv")]
SH = shutil.which("sh")
MISSING = "goose-disturbance-underfrequency"
ROW = "| not run (not fetched) |"

pytestmark = pytest.mark.skipif(SH is None, reason="no sh on PATH")


def block():
    """The block as run.sh holds it; CR is stripped for a Windows checkout."""
    with open(os.path.join(HERE, "run.sh"), encoding="utf-8") as f:
        lines = f.read().replace("\r", "").split("\n")
    start = lines.index("    counted=")
    end = lines.index("    fi", start)
    text = "\n".join(lines[start:end + 1]) + "\n"
    assert 'table.py" public' in text and "exit 1" in text, text
    return text


def fwd(p):
    return str(p).replace("\\", "/")


def run_block(work, text, ref, skip):
    """Every listed capture but those in SKIP is fetched, and each ran under
    every base configuration with exit code 0. Returns (exit code, public.md)."""
    os.makedirs(work / "public")
    os.makedirs(work / "out-public")
    for n, d in table.listed(LISTS):
        if d in skip:
            continue
        (work / "public" / n).write_bytes(b"")
        for cfg in table.CONFIGS:
            c = work / "out-public" / d / cfg
            c.mkdir(parents=True)
            (c / "exit-code").write_text("0\n")
    script = work / "probe.sh"
    script.write_text('set -eu\npython3() { "$PY" "$@"; }\nheader() { echo STUB-HEADER; }\n' + text
                      + 'echo "after the block" >&2\n', newline="\n")
    env = dict(os.environ, PY=fwd(sys.executable), here=fwd(HERE), root=fwd(ROOT), work=fwd(work))
    env.pop("GITHUB_REF", None)
    if ref is not None:
        env["GITHUB_REF"] = ref
    r = subprocess.run([SH, fwd(script)], env=env, capture_output=True, text=True)
    md = (work / "public.md").read_text() if (work / "public.md").exists() else ""
    return r.returncode, md


# (ref, captures not fetched, the run fails)
CASES = [("refs/heads/main", {MISSING}, True),
         ("refs/heads/agent/x", {MISSING}, False),
         (None, {MISSING}, False),
         ("refs/heads/main", set(), False)]


def failures(tmp_path, text):
    bad = []
    for i, (ref, skip, fails) in enumerate(CASES):
        rc, md = run_block(tmp_path / str(i), text, ref, skip)
        case = f"ref={ref} missing={sorted(skip)}"
        if (rc != 0) != fails:
            bad.append(f"{case}: exit {rc}")
        for part in ("STUB-HEADER", "# E-D4-03: public captures", "## HR-23's readings"):
            if part not in md:
                bad.append(f"{case}: public.md lacks {part!r}")
        if md.count(ROW) != len(skip) * len(table.CONFIGS):
            bad.append(f"{case}: {md.count(ROW)} not-fetched rows")
        if skip and ("This run is on refs/heads/main" in md) != fails:
            bad.append(f"{case}: closing line names the wrong ref")
    return bad


def test_counted_block_fails_only_a_main_run_with_a_capture_missing(tmp_path):
    assert failures(tmp_path, block()) == []


# D6's mutants R1 to R5 (review 6995083969 on #751): each turned a run on
# main with one capture missing green and survived every test before this one.
MUTANTS = {
    "R1-counted-dropped": (" $counted || pubrc=$?", " || pubrc=$?"),
    "R2-ref-is-main": ('= refs/heads/main ]', '= main ]'),
    "R3-exit-0": ("      exit 1\n", "      exit 0\n"),
    "R4-status-dropped": ("|| pubrc=$?", "|| true"),
    "R5-only-1-fails": ('[ "$pubrc" != 0 ]', '[ "$pubrc" = 1 ]'),
}


@pytest.mark.parametrize("old,new", MUTANTS.values(), ids=MUTANTS.keys())
def test_mutant_is_killed(tmp_path, old, new):
    text = block()
    assert text.count(old) == 1, old
    assert failures(tmp_path, text.replace(old, new)) != []

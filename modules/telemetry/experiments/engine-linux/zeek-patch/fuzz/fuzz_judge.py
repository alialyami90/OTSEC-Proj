"""HR-23's sanitizer fuzz run: the coverage condition and the summary
(brief P4-4-HR23-FUZZ; docs/phase4/D4-hr23-design.md, section 4.6).

Disclosure (section 4.6; D4-112 item 1). This is the only part of the run
whose output is printed. It reads the private files fuzz.sh keeps on the
runner and writes only fixed words, counts, durations and the pinned
hashes: never a log line, an input, an artifact's name or a report's kind.
Every value it prints is built here from an integer or a yes or no.
test_hr23_fuzz.py feeds it logs that hold a sanitizer trace and an input,
and checks that neither reaches its output.

`coverage F DNP3CC` reads F/private/cov-<target>/lcov.info, written by
llvm-cov from C2's final corpus of each target, and DNP3CC, the patched
DNP3.cc that C2 compiled; writes F/coverage.tsv and prints it. Each
condition is `yes` or `no`:
- `request-parser` and `response-parser`: DNP3_Request::Parse and
  DNP3_Response::Parse ran. Under option (i) each is reached only through
  the new dispatch in DNP3_PDU, so together they are its two arms;
- `is-response-code`: the dispatch's test, DNP3_Flow::is_response_code, ran;
- `bprime-catch`: the line of (B')'s catch that raises the violation ran;
- `replay-path`: in the `packet` target, PIA::ReplayPacketBuffer and
  DNP3_UDP_Analyzer::DeliverPacket both ran. Coverage does not show that the
  replay's target was the DNP3 analyzer, nor which caller reached the catch
  (section 4.6, the third target's limit; D6's N14).

`summary F` prints the run's result as Markdown: each campaign's seconds,
executions and report count; the replay's classes; the coverage
conditions; and the verdict. While any input reproduces on C1p (stock Zeek
9.0.1's source), it withholds every campaign's row and prints the totals
only, so that the summary does not show which target found it (D4-116 item
2.4 (b); D1's ruling 1 on #744). It withholds them too, failing closed,
while a report has no replay on C1p (it left no input, or was not
replayed). The verdict is:
- `fail` when an input reproduces on C2 and not on C1p;
- `unknown` when an input does not reproduce on its own build, a report
  left no input, a campaign left no result, a campaign stopped on a report
  before its pinned time (D6's B1 on #731: it did not fuzz its time), a
  coverage replay has no exit code or a non-zero one (D3's B2 on #731: a
  report there, or no coverage report from it), or a coverage condition is
  `no`;
- `pass` otherwise.
An input that reproduces on C1p (stock Zeek 9.0.1's source) is counted,
never netted out, and held for the owner's disclosure decision.

`flags NINJA SANITIZERS UBCHECKS` checks the build's own lines (D3's B1
on #731): every compile line in NINJA (build.ninja) of binpac's runtime
library and of DNP3.cc carries -fsanitize= with each of SANITIZERS
(fuzz.env's; `undefined` read as UBCHECKS) and -fno-sanitize-recover=
UBCHECKS. It prints only `ok` or the source file's name, and exits 1 on a
miss.

Usage: python -I fuzz_judge.py coverage F DNP3CC
       python -I fuzz_judge.py summary F
       python -I fuzz_judge.py flags NINJA SANITIZERS UBCHECKS
"""
import hashlib
import os
import re
import sys

TARGETS = ("dnp3_tcp", "dnp3_udp", "packet")
BUILDS = ("c1p", "c2")
CATCH_MARK = "OTSEC patch (HR-23, (B'))"
CATCH_LINE = 'AnalyzerViolation(util::fmt("Binpac exception: %s", e.what()));'
# Each function by its mangled or demangled name: every part must appear.
FUNCS = {
    "request-parser": (("12DNP3_Request5ParseE",), ("DNP3_Request::Parse(",)),
    "response-parser": (("13DNP3_Response5ParseE",), ("DNP3_Response::Parse(",)),
    "is-response-code": (("9DNP3_Flow16is_response_codeE",), ("DNP3_Flow::is_response_code(",)),
    "replay-buffer": (("3PIA18ReplayPacketBufferE",), ("PIA::ReplayPacketBuffer(",)),
    "udp-deliver": (("17DNP3_UDP_Analyzer13DeliverPacketE",), ("DNP3_UDP_Analyzer::DeliverPacket(",)),
}
CONDITIONS = ("request-parser", "response-parser", "is-response-code", "bprime-catch", "replay-path")


def lcov(path):
    """(functions hit, {source path: lines hit}) of one lcov file, or None."""
    if not os.path.exists(path):
        return None
    fns, lines, sf = set(), {}, None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            x = raw.rstrip("\n")
            if x.startswith("SF:"):
                sf = x[3:]
                lines.setdefault(sf, set())
            elif x.startswith("FNDA:"):
                n, _, name = x[5:].partition(",")
                if n.isdigit() and int(n) > 0:
                    fns.add(name)
            elif x.startswith("DA:") and sf is not None:
                parts = x[3:].split(",")
                if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit() and int(parts[1]) > 0:
                    lines[sf].add(int(parts[0]))
    return fns, lines


def hit(fns, key):
    return any(any(all(p in n for p in form) for form in FUNCS[key]) for n in fns)


def catch_line(dnp3cc):
    """The line number of (B')'s violation call, after its marker."""
    with open(dnp3cc, encoding="utf-8") as fh:
        src = fh.read().split("\n")
    marks = [i for i, x in enumerate(src) if CATCH_MARK in x]
    if len(marks) != 1:
        raise ValueError(f"{dnp3cc}: {len(marks)} (B') markers, want 1")
    for i in range(marks[0], min(marks[0] + 10, len(src))):
        if src[i].strip() == CATCH_LINE:
            return i + 1
    raise ValueError(f"{dnp3cc}: no violation call after the (B') marker")


def coverage(f, dnp3cc):
    line = catch_line(dnp3cc)
    per = {t: lcov(os.path.join(f, "private", "cov-" + t, "lcov.info")) for t in TARGETS}
    fns = set().union(*(p[0] for p in per.values() if p))
    catch = any(line in hits for p in per.values() if p for sf, hits in p[1].items()
                if sf.endswith("analyzer/protocol/dnp3/DNP3.cc"))
    pk = per["packet"]
    res = {
        "request-parser": hit(fns, "request-parser"),
        "response-parser": hit(fns, "response-parser"),
        "is-response-code": hit(fns, "is-response-code"),
        "bprime-catch": catch,
        "replay-path": bool(pk) and hit(pk[0], "replay-buffer") and hit(pk[0], "udp-deliver"),
    }
    out = "condition\tmet\n" + "".join(f"{c}\t{'yes' if res[c] else 'no'}\n" for c in CONDITIONS)
    out += "targets with a coverage report\t" + str(sum(1 for p in per.values() if p)) + "\n"
    with open(os.path.join(f, "coverage.tsv"), "w", encoding="ascii") as fh:
        fh.write(out)
    sys.stdout.write(out)
    return 0


def read_int(path):
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            v = fh.read().strip()
    except OSError:
        return None
    return int(v) if re.fullmatch(r"-?\d{1,10}", v) else None


def executions(log):
    """libFuzzer's final count of executed inputs (-print_final_stats=1)."""
    try:
        with open(log, encoding="utf-8", errors="replace") as fh:
            m = re.findall(r"^stat::number_of_executed_units: (\d{1,15})$", fh.read(), re.M)
    except OSError:
        return None
    return int(m[-1]) if m else None


def summary(f):
    priv = os.path.join(f, "private")
    rows, unknown, early, reports_no_input = [], 0, 0, 0
    seconds_pin = None
    env = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fuzz.env")
    with open(env, encoding="ascii") as fh:
        m = re.search(r"^HR23_FUZZ_SECONDS=(\d+)$", fh.read(), re.M)
        seconds_pin = int(m.group(1)) if m else None
    for t in TARGETS:
        for b in BUILDS:
            d = os.path.join(priv, b, t)
            rc = read_int(os.path.join(d, "exit-code"))
            secs = read_int(os.path.join(d, "seconds"))
            ex = executions(os.path.join(d, "log"))
            art = os.path.join(d, "artifacts")
            n = len([x for x in os.listdir(art) if os.path.isfile(os.path.join(art, x))]) if os.path.isdir(art) else 0
            reps = n
            if rc is None or ex is None:
                unknown += 1
                state = "no result"
            elif rc != 0 and n == 0:
                reports_no_input += 1
                reps = 1
                state = "ran"
            else:
                state = "ran"
            if rc not in (None, 0) and seconds_pin and secs is not None and secs < seconds_pin:
                early += 1
            rows.append((t, b, state, "-" if secs is None else str(secs), "-" if ex is None else str(ex), str(reps)))
    classes = {"against": 0, "both": 0, "c1p-only": 0, "unknown": 0}
    replayed, on_c1p = 0, 0
    rp = os.path.join(priv, "replay.tsv")
    if os.path.exists(rp):
        with open(rp, encoding="ascii", errors="replace") as fh:
            for x in fh:
                p = x.rstrip("\n").split("\t")
                if len(p) != 4 or p[1] not in BUILDS:
                    continue
                replayed += 1
                r1, r2 = p[-2] != "0", p[-1] != "0"
                on_c1p += r1
                own = r1 if p[1] == "c1p" else r2
                if not own:
                    classes["unknown"] += 1
                elif r2 and not r1:
                    classes["against"] += 1
                elif r1 and r2:
                    classes["both"] += 1
                else:
                    classes["c1p-only"] += 1
    total_reports = sum(int(r[5]) for r in rows)
    cov = {}
    cp = os.path.join(f, "coverage.tsv")
    if os.path.exists(cp):
        with open(cp, encoding="ascii", errors="replace") as fh:
            for x in fh:
                p = x.rstrip("\n").split("\t")
                if len(p) == 2 and p[0] in CONDITIONS:
                    cov[p[0]] = p[1] == "yes"
    cov_ok = all(cov.get(c, False) for c in CONDITIONS)
    # A coverage replay with no exit code, or a non-zero one, ended without
    # its coverage report, and may have stopped on a report.
    cov_bad = sum(1 for t in TARGETS if read_int(os.path.join(priv, "cov-" + t, "exit-code")) != 0)
    if classes["against"]:
        verdict = "fail"
    elif (unknown or early or cov_bad or classes["unknown"] or reports_no_input or not cov_ok
          or replayed + reports_no_input < total_reports):
        verdict = "unknown"
    else:
        verdict = "pass"
    corpus = "-"
    man = os.path.join(f, "seeds", "manifest.sha256")
    if os.path.exists(man):
        with open(man, "rb") as fh:
            corpus = hashlib.sha256(fh.read()).hexdigest()
    out = ["## HR-23 sanitizer fuzz run (design section 4.6)", "",
           f"Verdict: **{verdict}**", "",
           f"Corpus SHA-256: `{corpus}`", ""]
    if on_c1p or replayed < total_reports:
        out += ["Each campaign's row is withheld: an input reproduces on C1p (stock Zeek 9.0.1's source), "
                "or a report has no replay on C1p, and the rows would show its target. The totals follow."]
    else:
        out += ["| target | build | state | seconds | executions | reports |",
                "| --- | --- | --- | --- | --- | --- |"]
        out += [f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} |" for r in rows]
    out += ["",
            f"- Reports: {total_reports}; replayed alone on both builds: {replayed}; "
            f"reports that left no input: {reports_no_input}.",
            f"- Against the patch (reproduces on C2, not on C1p): {classes['against']}.",
            f"- Reproduces on both builds (stock Zeek 9.0.1's source; held for the owner's disclosure decision): "
            f"{classes['both']}.",
            f"- Reproduces on C1p only (held likewise): {classes['c1p-only']}.",
            f"- Does not reproduce on its own build (`unknown`, counted): {classes['unknown']}.",
            f"- Campaigns ended by a report before their time: {early}; campaigns with no result: {unknown}.",
            f"- Coverage replays with no exit code or a non-zero one: {cov_bad}.",
            "", "| coverage condition (C2's final corpus) | met |", "| --- | --- |"]
    out += [f"| {c} | {'-' if c not in cov else ('yes' if cov[c] else 'no')} |" for c in CONDITIONS]
    out += ["", "No input, trace or log leaves the runner (design section 4.6, Disclosure)."]
    sys.stdout.write("\n".join(out) + "\n")
    return 0


# binpac's runtime library, and the DNP3 analyzer as libzeek's reference.
FLAG_SOURCES = ("binpac_buffer.cc", "binpac_bytestring.cc", "binpac_regex.cc", "DNP3.cc")


def flags(ninja, sanitizers, ub):
    want = {s for s in sanitizers.split(",") if s != "undefined"} | set(ub.split(","))
    recover = "-fno-sanitize-recover=" + ub
    found = {s: [] for s in FLAG_SOURCES}
    cur = None
    with open(ninja, encoding="utf-8", errors="replace") as fh:
        for x in fh:
            if x.startswith("build "):
                out = x[6:].split(":", 1)[0].strip()
                name = out.rsplit("/", 1)[-1]
                cur = name[:-2] if name.endswith(".o") and name[:-2] in found else None
            elif cur and x.startswith("  FLAGS = "):
                toks = x.split()
                san = set()
                for k in toks:
                    if k.startswith("-fsanitize="):
                        san |= set(k[len("-fsanitize="):].split(","))
                found[cur].append(want <= san and recover in toks)
            elif not x.startswith(" "):
                cur = None
    bad = [s for s in FLAG_SOURCES if not found[s] or not all(found[s])]
    for s in bad:
        sys.stdout.write(f"flags: {s}: no compile line, or one without the run's sanitizer flags\n")
    if bad:
        return 1
    sys.stdout.write("flags: ok\n")
    return 0


def main(argv):
    if len(argv) == 3 and argv[0] == "coverage":
        return coverage(argv[1], argv[2])
    if len(argv) == 2 and argv[0] == "summary":
        return summary(argv[1])
    if len(argv) == 4 and argv[0] == "flags":
        return flags(argv[1], argv[2], argv[3])
    sys.stderr.write(__doc__.split("Usage:")[1])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

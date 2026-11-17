"""The script-hash check of docs/release.md section 8.4 item 3 (D4-115
item 5; D1's ruling 6933304617 on #723: option (c), host-side hashes of
everything mounted, before and after the run). D4's.

run.sh starts every Zeek container that has a mount through `run`, with
the arguments it gave `docker run` before, less `--rm`. The measured run is
unchanged: the same options, image and command, so the same container
(test_mountcheck.py; the rehearsal pair in the PR). `run`:

1. logs the whole `docker create` line, then makes the container from that
   same argument list;
2. reads the container with `docker inspect` (never run.sh's arguments),
   and the image's own `Env` and `zeek --help`, by image ID;
3. checks the rules below, and hashes on the host every file under every
   mount except the output folder `/out`;
4. starts the container (`docker start -a`), and after it exits hashes the
   same mounts again;
5. removes the container. A rule that fails writes DIR/FAILED, which
   run.sh reads after each container and stops the run on (exit 1).

The rules, each named in the message of a failure:
- `create-line`: the logged line, parsed, names the container `docker
  inspect` shows: its image, command, entrypoint, environment and every
  mount (condition 2: what was logged is what Docker made);
- `read-only`: every mount except `/out` is read-only, and `/out`, when
  present, is a bind mount (condition 1; D3's N8);
- `every-mount-hashed`: every mount except `/out` is a bind mount whose
  files the host hashed (condition 3);
- `env`: the container's environment equals its image's, so the search
  path read from the image's own `zeek --help` is the one the run has;
- `search-path`: every entry of `$ZEEKPATH` and `$ZEEK_PLUGIN_PATH`, as the
  image's own `zeek --help` prints them, is in the image (under no mount),
  under a hashed mount, or `.`; `.` is the working directory, which is a new
  output folder (`new-output-folder`) for in-container.sh, and must be
  under no mount for a direct `zeek` (condition 4);
- `absolute-args`: every argument of a Zeek container that names a file is
  an absolute path, and its only options are `-C` and `-r FILE`; a redef
  (`Name::id=value`) is not a file (condition 4);
- `command-line-coverage`: every absolute path on the command line is in
  the image (under no mount) or under a hashed mount (condition 4);
- `new-output-folder`: for in-container.sh, `/out/<capture>/<config>` does
  not exist, on the host, for any capture in `/pcaps`, before the container
  starts (condition 4);
- `equality`: the hashes after the run equal those before (the equality
  rule).

`/out` is the only exemption, by that name. Any other writable mount fails
`read-only`, and any mount that is not hashed fails `every-mount-hashed`.

Usage: python3 -I mountcheck.py run DIR [--] DOCKER-CREATE-ARGS...
       python3 -I mountcheck.py summary DIR
       python3 -I mountcheck.py selftest IMAGE EXPDIR DIR
`selftest` shows, on this runner's Docker, the pass case and one control
per rule, each failing on its own rule and no other; it exits 1 otherwise.
"""
import hashlib
import json
import os
import posixpath
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys

OUT = "/out"
R_LINE = "create-line"
R_RO = "read-only"
R_HASHED = "every-mount-hashed"
R_ENV = "env"
R_PATH = "search-path"
R_ABS = "absolute-args"
R_COVER = "command-line-coverage"
R_NEW = "new-output-folder"
R_EQ = "equality"
RULES = (R_LINE, R_RO, R_HASHED, R_ENV, R_PATH, R_ABS, R_COVER, R_NEW, R_EQ)
INC = "/exp/in-container.sh"
ZEEK_ENGINES = ("zeek", "zeek-pipe")
VALUE_OPTS = ("--network", "-v", "--volume", "--mount", "--tmpfs", "--cap-drop",
              "--security-opt", "--user", "-u", "--entrypoint", "-e", "--env")
REDEF = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*=.*")
CAPTURE = (".pcap", ".pcapng", ".cap")


def parse_line(argv):
    """The container a `docker create` argument list asks for."""
    mounts, env, ep, i = [], [], None, 0
    while i < len(argv) and argv[i].startswith("-"):
        a = argv[i]
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            i += 1
        elif a in VALUE_OPTS:
            if i + 1 >= len(argv):
                raise ValueError(f"{a} has no value")
            k, v = a, argv[i + 1]
            i += 2
        else:
            raise ValueError(f"option {a} is not one this check reads")
        if k not in VALUE_OPTS:
            raise ValueError(f"option {k} is not one this check reads")
        if k in ("-v", "--volume"):
            drive = re.match(r"^[A-Za-z]:[\\/]", v)
            head, rest = (v[:2], v[2:]) if drive else ("", v)
            p = rest.split(":")
            if len(p) not in (2, 3):
                raise ValueError(f"-v {v}: not SRC:DST[:OPTS]")
            src, dst, opts = head + p[0], p[1], (p[2] if len(p) == 3 else "")
            kind = "bind" if (drive or src.startswith("/")) else "volume"
            mounts.append((kind, src, dst, "ro" not in opts.split(",")))
        elif k == "--mount":
            f = {}
            for part in v.split(","):
                kk, _, vv = part.partition("=")
                f[kk] = vv if _ else "true"
            kind = f.get("type", "volume")
            dst = f.get("destination", f.get("dst", f.get("target")))
            ro = f.get("readonly", f.get("ro", "false")) in ("true", "1")
            if dst is None:
                raise ValueError(f"--mount {v}: no destination")
            mounts.append((kind, f.get("source", f.get("src", "")) if kind != "tmpfs" else "", dst, not ro))
        elif k == "--tmpfs":
            dst, _, opts = v.partition(":")
            mounts.append(("tmpfs", "", dst, "ro" not in opts.split(",")))
        elif k in ("-e", "--env"):
            if "=" not in v:
                raise ValueError(f"-e {v}: takes its value from the host")
            env.append(v)
        elif k == "--entrypoint":
            ep = v
    if i >= len(argv):
        raise ValueError("no image")
    return {"image": argv[i], "cmd": argv[i + 1:], "mounts": mounts, "env": env, "entrypoint": ep}


def mounts_of(ins):
    """Every mount of an inspected container: (type, source, destination, rw)."""
    out = []
    for m in ins.get("Mounts") or []:
        t = m.get("Type", "")
        src = m.get("Source", "") if t == "bind" else (m.get("Name", "") if t == "volume" else "")
        out.append((t, src, m.get("Destination", ""), bool(m.get("RW"))))
    for dst, opts in ((ins.get("HostConfig") or {}).get("Tmpfs") or {}).items():
        out.append(("tmpfs", "", dst, "ro" not in (opts or "").split(",")))
    return out


def under(path, dst):
    path, dst = posixpath.normpath(path), posixpath.normpath(dst)
    return path == dst or path.startswith(dst.rstrip("/") + "/")


def mount_at(path, mounts):
    """The mount a container path lies under (the deepest), or None."""
    best = None
    for m in mounts:
        if under(path, m[2]) and (best is None or len(m[2]) > len(best[2])):
            best = m
    return best


def hashed(m):
    return m[0] == "bind" and m[2] != OUT


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def hash_tree(src):
    """One line per entry under SRC: kind, relative name, mode, and the
    SHA-256 of a file or the target of a link. Raises OSError on any entry
    it cannot read."""
    st = os.lstat(src)
    if stat.S_ISREG(st.st_mode):
        return [f"F . {stat.S_IMODE(st.st_mode):o} {sha256(src)}"]
    if not stat.S_ISDIR(st.st_mode):
        raise OSError(f"{src}: not a file or folder")
    out = [f"D . {stat.S_IMODE(st.st_mode):o}"]

    def fail(e):
        raise e
    for dp, dns, fns in os.walk(src, onerror=fail):
        dns.sort()
        for n in sorted(dns + fns):
            p = os.path.join(dp, n)
            r = os.path.relpath(p, src).replace(os.sep, "/")
            s = os.lstat(p)
            mode = f"{stat.S_IMODE(s.st_mode):o}"
            if stat.S_ISLNK(s.st_mode):
                out.append(f"L {r} {mode} {os.readlink(p)}")
            elif stat.S_ISDIR(s.st_mode):
                out.append(f"D {r} {mode}")
            elif stat.S_ISREG(s.st_mode):
                out.append(f"F {r} {mode} {sha256(p)}")
            else:
                out.append(f"O {r} {mode}")
    return out


def hash_mounts(mounts):
    """({destination: lines}, problems) for every mount except /out."""
    rec, probs = {}, []
    for m in mounts:
        if m[2] == OUT:
            continue
        if not hashed(m):
            probs.append(f"{m[0]} mount at {m[2]} is not hashed: only a bind mount's files are read on the host")
            continue
        try:
            rec[m[2]] = hash_tree(m[1])
        except OSError as e:
            probs.append(f"could not hash {m[1]} (mounted at {m[2]}): {e}")
    return rec, probs


def search_path(help_text):
    """{'ZEEKPATH': [...], 'ZEEK_PLUGIN_PATH': [...]} from `zeek --help`."""
    got = {}
    for line in (help_text or "").splitlines():
        m = re.match(r"^\s*\$(ZEEKPATH|ZEEK_PLUGIN_PATH)\s*\|[^(]*\((.*)\)\s*$", line)
        if m:
            got[m.group(1)] = m.group(2).split(":")
    return got


def command(ins):
    """(kind, engine, config, args, full) of a container's command."""
    c = ins.get("Config") or {}
    full = list(c.get("Entrypoint") or []) + list(c.get("Cmd") or [])
    if full[:2] == ["sh", INC] and len(full) >= 4:
        return "in-container", full[2], full[3], full[4:], full
    if full and posixpath.basename(full[0]) == "zeek":
        return "zeek", "zeek", None, full[1:], full
    return None, None, None, [], full


def precheck(line_argv, ins, image_env, help_text):
    """Every rule that can be read before the container starts:
    ({rule: [messages]}, {destination: hash lines})."""
    p = {r: [] for r in RULES}
    mounts = mounts_of(ins)
    c = ins.get("Config") or {}
    # create-line (condition 2)
    try:
        want = parse_line(line_argv)
    except ValueError as e:
        p[R_LINE].append(f"the logged line does not parse: {e}")
        want = None
    if want is not None:
        if c.get("Image") != want["image"]:
            p[R_LINE].append(f"image {c.get('Image')!r}, the line says {want['image']!r}")
        if list(c.get("Cmd") or []) != want["cmd"]:
            p[R_LINE].append(f"command {c.get('Cmd')!r}, the line says {want['cmd']!r}")
        if want["entrypoint"] is not None and list(c.get("Entrypoint") or []) != [want["entrypoint"]]:
            p[R_LINE].append(f"entrypoint {c.get('Entrypoint')!r}, the line says {want['entrypoint']!r}")
        if sorted(mounts) != sorted(want["mounts"]):
            p[R_LINE].append(f"mounts {sorted(mounts)!r}, the line says {sorted(want['mounts'])!r}")
        for e in want["env"]:
            if e not in (c.get("Env") or []):
                p[R_LINE].append(f"the line sets {e!r}, the container does not")
    # read-only (condition 1)
    for m in mounts:
        if m[2] == OUT:
            if m[0] != "bind":
                p[R_RO].append(f"{OUT} is a {m[0]} mount, not a bind mount")
        elif m[3]:
            p[R_RO].append(f"{m[0]} mount at {m[2]} is writable")
    # every-mount-hashed (condition 3)
    rec, hp = hash_mounts(mounts)
    p[R_HASHED] += hp
    kind, eng, cfg, args, full = command(ins)
    if kind is None:
        p[R_LINE].append(f"command {full!r} is not one this check knows")
    is_zeek = kind == "zeek" or (kind == "in-container" and eng in ZEEK_ENGINES)
    # env, and search-path (condition 4)
    if list(c.get("Env") or []) != list(image_env or []):
        p[R_ENV].append(f"the container's Env {c.get('Env')!r} is not its image's {image_env!r}")
    if is_zeek:
        sp = search_path(help_text)
        for k in ("ZEEKPATH", "ZEEK_PLUGIN_PATH"):
            if k not in sp:
                p[R_PATH].append(f"the image's own zeek --help gives no ${k}; it begins "
                                 f"{(help_text or '')[:300]!r}")
            for e in sp.get(k, []):
                if e in ("", "."):
                    wd = c.get("WorkingDir") or "/"
                    if kind != "in-container" and mount_at(wd, mounts) is not None:
                        p[R_PATH].append(f"${k} holds {e!r}, and the working directory {wd} is under a mount")
                elif not e.startswith("/"):
                    p[R_PATH].append(f"${k} holds the relative entry {e!r}")
                else:
                    m = mount_at(e, mounts)
                    if m is not None and not hashed(m):
                        p[R_PATH].append(f"${k} holds {e}, under the {m[0]} mount at {m[2]}, which is not hashed")
    # absolute-args (condition 4)
    files = [x for x in full if x.startswith("/")]
    if is_zeek:
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-r" and i + 1 < len(args):
                if not args[i + 1].startswith("/"):
                    p[R_ABS].append(f"-r {args[i + 1]!r} is not an absolute path")
                i += 2
                continue
            if a == "-C" or REDEF.fullmatch(a):
                pass
            elif a.startswith("-"):
                p[R_ABS].append(f"option {a!r} is not one this check reads")
            elif not a.startswith("/"):
                p[R_ABS].append(f"argument {a!r} is not an absolute path")
            i += 1
    # command-line-coverage (condition 4)
    for f in files:
        m = mount_at(f, mounts)
        if m is not None and not hashed(m):
            p[R_COVER].append(f"{f} is under the {m[0]} mount at {m[2]}, which is not hashed")
    # new-output-folder (condition 4)
    if kind == "in-container":
        outm = [m for m in mounts if m[2] == OUT and m[0] == "bind"]
        pcm = [m for m in mounts if m[2] == "/pcaps" and m[0] == "bind"]
        if not outm or not pcm:
            p[R_NEW].append(f"in-container.sh needs bind mounts at {OUT} and /pcaps")
        elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", cfg or ""):
            p[R_NEW].append(f"configuration name {cfg!r} is not a plain folder name")
        else:
            try:
                names = sorted(os.listdir(pcm[0][1]))
            except OSError as e:
                names = []
                p[R_NEW].append(f"could not list {pcm[0][1]}: {e}")
            for n in names:
                if n.endswith(CAPTURE):
                    d = os.path.join(outm[0][1], n.rsplit(".", 1)[0], cfg)
                    if os.path.lexists(d):
                        p[R_NEW].append(f"the output folder {d} exists before its container starts")
    return {r: v for r, v in p.items() if v}, rec


def compare(before, after):
    """Messages for every hashed entry that differs (the equality rule)."""
    out = []
    for dst in sorted(set(before) | set(after)):
        b, a = set(before.get(dst, [])), set(after.get(dst, []))
        for x in sorted(b ^ a)[:20]:
            out.append(f"{dst}: {'before' if x in b else 'after'} only: {x}")
    return out


def docker(*args, check=True):
    r = subprocess.run(["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {args[0]} failed (exit {r.returncode}): {r.stderr.strip()}")
    return r


def image_facts(d, image_id, zeek):
    """The image's own Env and, for a Zeek container, its own `zeek --help`,
    by image ID, kept in D."""
    key = re.sub(r"[^A-Za-z0-9]", "_", image_id) + ("-zeek" if zeek else "")
    path = os.path.join(d, f"image-{key}.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    env = json.loads(docker("image", "inspect", image_id).stdout)[0]["Config"].get("Env") or []
    facts = {"env": env, "help": None}
    if zeek:
        h = docker("run", "--rm", "--network", "none", image_id, "zeek", "--help", check=False)
        facts["help"] = h.stdout + h.stderr
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(facts, fh)
    return facts


def say(msg):
    sys.stderr.write(f"mountcheck: {msg}\n")
    sys.stderr.flush()


def run(d, argv, log_argv=None, between=None):
    """One container under every rule. Returns (exit code, failed rules)."""
    os.makedirs(d, exist_ok=True)
    n = len([x for x in os.listdir(d) if x.isdigit()]) + 1
    rd = os.path.join(d, str(n))
    os.makedirs(rd)
    log_argv = argv if log_argv is None else log_argv
    say("docker create " + shlex.join(log_argv))
    with open(os.path.join(rd, "create.json"), "w", encoding="utf-8") as fh:
        json.dump(log_argv, fh)
    cid = docker("create", *argv).stdout.strip()
    try:
        ins = json.loads(docker("inspect", cid).stdout)[0]
        with open(os.path.join(rd, "inspect.json"), "w", encoding="utf-8") as fh:
            json.dump(ins, fh, indent=1)
        kind, eng = command(ins)[:2]
        facts = image_facts(d, ins["Image"], kind == "zeek" or (kind == "in-container" and eng in ZEEK_ENGINES))
        probs, before = precheck(log_argv, ins, facts["env"], facts["help"])
        rc = None
        if not probs:
            say(f"container {n} ({cid[:12]}, image {ins['Image']}): every rule held before the start; "
                f"hashed {', '.join(f'{k} ({len(v)} entries)' for k, v in sorted(before.items()))}")
            subprocess.run(["docker", "start", "-a", cid])
            if between:
                between()
            after, hp = hash_mounts(mounts_of(ins))
            eq = compare(before, after) + hp
            if eq:
                probs[R_EQ] = eq
            st = json.loads(docker("inspect", cid).stdout)[0]["State"]
            rc = st.get("ExitCode")
        with open(os.path.join(rd, "before.json"), "w", encoding="utf-8") as fh:
            json.dump(before, fh)
    finally:
        docker("rm", "-f", cid, check=False)
    if probs:
        text = "".join(f"mountcheck: rule {r} failed (container {n}): {m}\n" for r in RULES for m in probs.get(r, []))
        sys.stderr.write(text)
        with open(os.path.join(d, "FAILED"), "a", encoding="utf-8") as fh:
            fh.write(text)
        return 3, probs
    say(f"container {n}: exit {rc}; the hashes after the run equal those before")
    return (rc if isinstance(rc, int) else 1), {}


def summary(d):
    """One line per mount destination: the containers checked, and each
    distinct SHA-256 of its hash set, for versions.txt."""
    sets, n = {}, 0
    for x in sorted((x for x in (os.listdir(d) if os.path.isdir(d) else []) if x.isdigit()), key=int):
        p = os.path.join(d, x, "before.json")
        if not os.path.exists(p):
            continue
        n += 1
        with open(p, encoding="utf-8") as fh:
            rec = json.load(fh)
        for dst, lines in rec.items():
            h = hashlib.sha256("\n".join(lines).encode()).hexdigest()
            sets.setdefault(dst, {}).setdefault(h, 0)
            sets[dst][h] += 1
    failed = os.path.exists(os.path.join(d, "FAILED"))
    print(f"mount check (docs/release.md section 8.4 item 3): {n} container(s) checked; "
          f"{'a rule FAILED' if failed else 'every rule held'}")
    for dst in sorted(sets):
        print(f"mount check, {dst}: " + "; ".join(f"hash set {h} in {c} container(s)" for h, c in sorted(sets[dst].items())))
    return 1 if failed else 0


def append(path, text):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


def selftest(image, exp, d):
    """The pass case and one control per rule, on this runner's Docker."""
    if os.path.exists(d):
        shutil.rmtree(d)
    os.makedirs(d)
    work = os.path.join(d, "tree")
    x = os.path.join(work, "exp")
    shutil.copytree(exp, x, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    pc, out = os.path.join(work, "pcaps"), os.path.join(work, "out")
    os.makedirs(pc)
    os.makedirs(out)
    with open(os.path.join(pc, "t.pcap"), "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    user = f"{os.getuid()}:{os.getgid()}"

    def base(cfg, exp_ro=True, extra=(), args=()):
        return ["--network", "none", "--user", user, *extra, "-v", f"{pc}:/pcaps:ro", "-v", f"{out}:/out",
                "-v", f"{x}:/exp" + (":ro" if exp_ro else ""), image, "sh", INC, "zeek", cfg, *args]

    rows, ok = [], True
    committed = None
    vol = "otsec-mountcheck-selftest"
    try:
        cid = docker("create", image, "true").stdout.strip()
        try:
            committed = docker("commit", "--change", "ENV ZEEKPATH=/out", cid).stdout.strip()
        finally:
            docker("rm", "-f", cid, check=False)
        os.makedirs(os.path.join(out, "t", "st-new"))
        cases = [
            ("pass", None, base("st-pass"), {}),
            ("a hashed mount writable", R_RO, base("st-ro", exp_ro=False), {"why": "/exp is writable"}),
            ("the logged line without /pcaps's mount", R_LINE, base("st-line"),
             {"log": lambda a: [v for i, v in enumerate(a) if v != f"{pc}:/pcaps:ro" and
                                not (v == "-v" and i + 1 < len(a) and a[i + 1] == f"{pc}:/pcaps:ro")],
              "why": "mounts "}),
            ("an extra mount that is not hashed (a read-only volume)", R_HASHED,
             base("st-extra", extra=("--mount", f"type=volume,src={vol},dst=/extra,readonly")),
             {"why": "volume mount at /extra is not hashed"}),
            ("ZEEKPATH set on the container", R_ENV, base("st-env", extra=("-e", "ZEEKPATH=/out")),
             {"why": "ZEEKPATH=/out"}),
            ("an image whose ZEEKPATH is /out", R_PATH, base("st-path")[:-5] + [committed, "sh", INC, "zeek", "st-path"],
             {"why": "$ZEEKPATH holds /out, under the bind mount at /out"}),
            ("a relative script argument", R_ABS, base("st-abs", args=("probe.zeek",)),
             {"why": "'probe.zeek' is not an absolute path"}),
            ("a script argument under /out", R_COVER, base("st-cover", args=("/out/x.zeek",)),
             {"why": "/out/x.zeek is under the bind mount at /out"}),
            ("the output folder exists before the start", R_NEW, base("st-new"), {"why": "t/st-new exists"}),
            ("a file in /exp changed during the run", R_EQ, base("st-eq"),
             {"between": lambda: append(os.path.join(x, "probe.zeek"), "# changed by the equality control\n"),
              "why": "F probe.zeek "}),
        ]
        for name, rule, argv, k in cases:
            log = k["log"](argv) if "log" in k else None
            rc, probs = run(os.path.join(d, "checks"), argv, log_argv=log, between=k.get("between"))
            failed = set(probs)
            want = set() if rule is None else {rule}
            # Each control must fail on its own rule, and for its own reason.
            why = k.get("why")
            good = failed == want and (rule is not None or rc == 0) and \
                (why is None or any(why in m for m in probs.get(rule, [])))
            ok = ok and good
            rows.append(f"| {name} | {rule or '(none)'} | {', '.join(sorted(failed)) or '(none)'} | "
                        f"{'as expected' if good else 'NOT AS EXPECTED'} |")
    finally:
        if committed:
            docker("rmi", "-f", committed, check=False)
        docker("volume", "rm", "-f", vol, check=False)
    print("\n### Mount check controls (docs/release.md section 8.4 item 3), on this runner's Docker\n")
    print(f"Image: `{image}`. Each control must fail on its own rule and no other.\n")
    print("| control | rule that must fail | rules that failed | result |")
    print("| --- | --- | --- | --- |")
    print("\n".join(rows))
    print(f"\nMount check controls: {'all as expected' if ok else 'a control was NOT AS EXPECTED'}")
    return 0 if ok else 1


def main(argv):
    if len(argv) >= 3 and argv[0] == "run":
        rest = argv[2:]
        if rest and rest[0] == "--":
            rest = rest[1:]
        try:
            rc, _ = run(argv[1], rest)
        except Exception as e:  # any fault of the check fails the run, never passes it
            text = f"mountcheck: the check did not finish: {e!r}\n"
            sys.stderr.write(text)
            os.makedirs(argv[1], exist_ok=True)
            with open(os.path.join(argv[1], "FAILED"), "a", encoding="utf-8") as fh:
                fh.write(text)
            return 3
        return rc
    if len(argv) == 2 and argv[0] == "summary":
        return summary(argv[1])
    if len(argv) == 4 and argv[0] == "selftest":
        return selftest(argv[1], argv[2], argv[3])
    sys.stderr.write(__doc__.split("Usage:")[1])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

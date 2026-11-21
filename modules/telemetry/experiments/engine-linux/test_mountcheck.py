"""The script-hash check of docs/release.md section 8.4 item 3 (D4-115
item 5): mountcheck.py's rules on made-up `docker inspect` records and real
folders on the host. Each control breaks one rule and must fail on that
rule and no other. The same controls run on a runner's Docker in
mountcheck.py's selftest, which run.sh runs first in every mode. Run:
python -m pytest -q modules/telemetry/experiments/engine-linux/test_mountcheck.py"""
import importlib.util
import json
import os
import shutil
import sys
import types

import pytest

import mountcheck as mc

ENV = ["PATH=/usr/local/zeek/bin:/usr/bin:/bin"]
HELP = ("    $ZEEKPATH                       | file search path (.:/usr/local/zeek/share/zeek:"
        "/usr/local/zeek/share/zeek/policy)\n"
        "    $ZEEK_PLUGIN_PATH               | plugin search path (/usr/local/zeek/lib/zeek/plugins)\n")
IMG = "zeek/zeek@sha256:" + "0" * 64


@pytest.fixture
def tree(tmp_path):
    t = {k: str(tmp_path / k) for k in ("exp", "pcaps", "out", "pkgs")}
    for d in t.values():
        os.makedirs(d)
    for n, body in (("in-container.sh", "#!/bin/sh\n"), ("probe.zeek", "event zeek_init() {}\n")):
        with open(os.path.join(t["exp"], n), "w") as fh:
            fh.write(body)
    with open(os.path.join(t["pcaps"], "a.pcap"), "wb") as fh:
        fh.write(b"\xd4\xc3\xb2\xa1")
    with open(os.path.join(t["pcaps"], "notes.txt"), "w") as fh:
        fh.write("not a capture\n")
    os.makedirs(os.path.join(t["pkgs"], "icsnpp-dnp3", "scripts"))
    return t


def inspect(mounts, cmd, entry=None, env=ENV, image=IMG, tmpfs=None, workdir=""):
    """A made-up `docker inspect` record of a created container."""
    ms = []
    for kind, src, dst, rw in mounts:
        m = {"Type": kind, "Destination": dst, "RW": rw}
        if kind == "bind":
            m["Source"] = src
        elif kind == "volume":
            m["Name"] = src
            m["Source"] = "/var/lib/docker/volumes/" + src + "/_data"
        ms.append(m)
    return {"Image": "sha256:" + "1" * 64, "Mounts": ms, "HostConfig": {"Tmpfs": tmpfs},
            "Config": {"Image": image, "Cmd": cmd, "Entrypoint": entry, "Env": list(env), "WorkingDir": workdir}}


def zeek_run(t, cfg="zeek-probe", args=("/exp/probe.zeek", "OtsecProbe::log_dir=F"), exp_ro=True, extra=(),
             cap="/pcaps/a.pcap"):
    """run.sh's zeek_run, one capture: (the docker create line, the mounts,
    the command)."""
    line = ["--network", "none", *extra, "-v", f"{t['pcaps']}:/pcaps:ro", "-v", f"{t['out']}:/out",
            "-v", f"{t['exp']}:/exp" + (":ro" if exp_ro else ""), "-v", f"{t['pkgs']}:/pkgs:ro",
            IMG, "sh", "/exp/in-container.sh", "zeek", cfg, cap, *args]
    mounts = [("bind", t["pcaps"], "/pcaps", False), ("bind", t["out"], "/out", True),
              ("bind", t["exp"], "/exp", not exp_ro), ("bind", t["pkgs"], "/pkgs", False)]
    return line, mounts, ["sh", "/exp/in-container.sh", "zeek", cfg, cap, *args]


def check(line, mounts, cmd, help_text=HELP, image_env=ENV, **kw):
    probs, rec = mc.precheck(line, inspect(mounts, cmd, **kw), image_env, help_text)
    return set(probs), rec


# The pass cases: every form run.sh uses.

def test_zeek_run_passes_and_hashes_every_mount_but_out(tree):
    line, mounts, cmd = zeek_run(tree)
    failed, rec = check(line, mounts, cmd)
    assert failed == set()
    assert sorted(rec) == ["/exp", "/pcaps", "/pkgs"]
    assert any(x.startswith("F probe.zeek ") for x in rec["/exp"])


def test_the_pipe_case_options_pass(tree):
    extra = ("--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "1001:118")
    line, mounts, cmd = zeek_run(tree, cfg="zeek-probe-pipe", args=("/exp/probe.zeek",), extra=extra)
    line[line.index("zeek")] = "zeek-pipe"
    cmd[2] = "zeek-pipe"
    assert check(line, mounts, cmd)[0] == set()


def test_reqs_redefs_pass(tree):
    args = ("/exp/probe.zeek", "OtsecProbe::flow_idle=10sec", "tcp_inactivity_timeout=10sec", "max_timer_expires=300")
    assert check(*zeek_run(tree, cfg="req-short", args=args))[0] == set()


def test_every_script_reqs_configuration_passes(tree):
    import script_reqs
    # run.sh's reqs passes these words as Zeek arguments.
    for cfg, args in script_reqs.CONFIGS.items():
        assert check(*zeek_run(tree, cfg=cfg, args=("/exp/probe.zeek", *args.split())))[0] == set(), cfg


def test_direct_zeek_passes(tree):
    line = ["--network", "none", "-v", f"{tree['pcaps']}:/pcaps:ro", "-v", f"{tree['exp']}:/exp:ro", IMG,
            "zeek", "-C", "-r", "/pcaps/a.pcap", "/exp/probe.zeek", "/exp/ports.zeek"]
    mounts = [("bind", tree["pcaps"], "/pcaps", False), ("bind", tree["exp"], "/exp", False)]
    assert check(line, mounts, line[7:])[0] == set()


def test_a_file_mount_is_hashed_and_passes(tree):
    y = os.path.join(tree["exp"], "probe.zeek")
    line = ["--network", "none", "-v", f"{tree['pcaps']}:/pcaps:ro", "-v", f"{y}:/s/probe.zeek:ro", IMG,
            "zeek", "-C", "-r", "/pcaps/a.pcap", "/s/probe.zeek"]
    mounts = [("bind", tree["pcaps"], "/pcaps", False), ("bind", y, "/s/probe.zeek", False)]
    failed, rec = check(line, mounts, line[7:])
    assert failed == set()
    assert rec["/s/probe.zeek"][0].startswith("F . ")


# One control per rule: each fails on its own rule and no other.

def test_control_a_hashed_mount_writable_fails_read_only(tree):
    assert check(*zeek_run(tree, exp_ro=False))[0] == {mc.R_RO}


def test_control_out_writable_is_the_only_exemption(tree):
    line, mounts, cmd = zeek_run(tree)
    # The same writable mount, at a destination other than /out.
    line[line.index(f"{tree['out']}:/out")] = f"{tree['out']}:/out2"
    mounts[1] = ("bind", tree["out"], "/out2", True)
    failed, _ = check(line, mounts, cmd)
    assert mc.R_RO in failed


def test_control_logged_line_without_a_mount_fails_create_line(tree):
    line, mounts, cmd = zeek_run(tree)
    i = line.index(f"{tree['pcaps']}:/pcaps:ro")
    del line[i - 1:i + 1]
    assert check(line, mounts, cmd)[0] == {mc.R_LINE}


@pytest.mark.parametrize("what", ["image", "command", "option"])
def test_control_logged_line_differs_fails_create_line(tree, what):
    line, mounts, cmd = zeek_run(tree)
    if what == "image":
        line[line.index(IMG)] = "zeek/zeek:latest"
    elif what == "command":
        line[-1] = "OtsecProbe::log_dir=T"
    else:
        line[0:0] = ["--privileged"]
    assert check(line, mounts, cmd)[0] == {mc.R_LINE}


def test_control_an_extra_read_only_volume_fails_every_mount_hashed(tree):
    extra = ("--mount", "type=volume,src=v1,dst=/extra,readonly")
    line, mounts, cmd = zeek_run(tree, extra=extra)
    assert check(line, mounts + [("volume", "v1", "/extra", False)], cmd)[0] == {mc.R_HASHED}


def test_control_an_extra_read_only_tmpfs_fails_every_mount_hashed(tree):
    line, mounts, cmd = zeek_run(tree, extra=("--tmpfs", "/scratch:ro"))
    assert check(line, mounts, cmd, tmpfs={"/scratch": "ro"})[0] == {mc.R_HASHED}


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs a file the user cannot read")
def test_control_an_unreadable_file_fails_every_mount_hashed(tree):
    p = os.path.join(tree["pkgs"], "icsnpp-dnp3", "scripts", "main.zeek")
    with open(p, "w") as fh:
        fh.write("x\n")
    os.chmod(p, 0)
    try:
        assert check(*zeek_run(tree))[0] == {mc.R_HASHED}
    finally:
        os.chmod(p, 0o600)


def test_control_zeekpath_on_the_container_fails_env(tree):
    line, mounts, cmd = zeek_run(tree, extra=("-e", "ZEEKPATH=/out"))
    assert check(line, mounts, cmd, env=ENV + ["ZEEKPATH=/out"])[0] == {mc.R_ENV}


@pytest.mark.parametrize("path", ["/out", "/out/site", "share/zeek"])
def test_control_a_search_path_outside_the_image_fails_search_path(tree, path):
    h = HELP.replace("(.:/usr/local", f"(.:{path}:/usr/local")
    assert check(*zeek_run(tree), help_text=h)[0] == {mc.R_PATH}


def test_control_no_search_path_in_the_help_fails_search_path(tree):
    assert check(*zeek_run(tree), help_text="zeek: unknown option\n")[0] == {mc.R_PATH}


def test_a_search_path_under_a_hashed_mount_passes(tree):
    h = HELP.replace("(.:/usr/local", "(.:/exp:/usr/local")
    assert check(*zeek_run(tree), help_text=h)[0] == set()


def test_control_dot_with_the_working_directory_under_a_mount_fails_search_path(tree):
    line = ["--network", "none", "-v", f"{tree['pcaps']}:/pcaps:ro", IMG, "zeek", "-C", "-r", "/pcaps/a.pcap"]
    mounts = [("bind", tree["pcaps"], "/pcaps", False)]
    assert check(line, mounts, line[5:], workdir="/pcaps")[0] == {mc.R_PATH}
    assert check(line, mounts, line[5:], workdir="/")[0] == set()


@pytest.mark.parametrize("args", [("probe.zeek",), ("./probe.zeek",), ("-s", "/exp/x.sig"), ("~/x.zeek",)])
def test_control_a_relative_argument_or_unread_option_fails_absolute_args(tree, args):
    assert check(*zeek_run(tree, args=args))[0] == {mc.R_ABS}


def test_control_r_with_a_relative_capture_fails_absolute_args(tree):
    line = ["--network", "none", "-v", f"{tree['pcaps']}:/pcaps:ro", IMG, "zeek", "-C", "-r", "a.pcap"]
    assert check(line, [("bind", tree["pcaps"], "/pcaps", False)], line[5:])[0] == {mc.R_ABS}


def test_control_a_script_under_out_fails_command_line_coverage(tree):
    assert check(*zeek_run(tree, args=("/out/x.zeek",)))[0] == {mc.R_COVER}


def test_a_script_in_the_image_passes_and_the_prefix_is_a_path_boundary(tree):
    # /outx is not under /out: it is in the image, which its ID covers.
    assert check(*zeek_run(tree, args=("/outx/x.zeek", "/usr/local/zeek/share/zeek/site/local.zeek")))[0] == set()


def test_control_the_output_folder_exists_fails_new_output_folder(tree):
    os.makedirs(os.path.join(tree["out"], "a", "zeek-probe"))
    assert check(*zeek_run(tree))[0] == {mc.R_NEW}


def test_other_configurations_folders_do_not_count(tree):
    os.makedirs(os.path.join(tree["out"], "a", "zeek-probe-c0"))
    os.makedirs(os.path.join(tree["out"], "notes", "zeek-probe"))  # notes.txt is not a capture
    assert check(*zeek_run(tree))[0] == set()


def test_control_a_configuration_name_with_a_slash_fails_new_output_folder(tree):
    assert check(*zeek_run(tree, cfg="../x"))[0] == {mc.R_NEW}


def test_control_an_unknown_command_fails_create_line(tree):
    line = ["--network", "none", "-v", f"{tree['exp']}:/exp:ro", IMG, "bash", "/exp/x"]
    assert check(line, [("bind", tree["exp"], "/exp", False)], line[5:])[0] == {mc.R_LINE}


def test_control_a_file_changed_fails_equality(tree):
    line, mounts, cmd = zeek_run(tree)
    _, before = check(line, mounts, cmd)
    after, probs = mc.hash_mounts(mounts)
    assert probs == [] and mc.compare(before, after) == []
    with open(os.path.join(tree["exp"], "probe.zeek"), "a") as fh:
        fh.write("# changed\n")
    after, _ = mc.hash_mounts(mounts)
    assert any("probe.zeek" in m for m in mc.compare(before, after))


def test_control_a_file_added_fails_equality(tree):
    line, mounts, cmd = zeek_run(tree)
    _, before = check(line, mounts, cmd)
    with open(os.path.join(tree["pkgs"], "icsnpp-dnp3", "scripts", "__load__.zeek"), "w") as fh:
        fh.write("@load ./main\n")
    after, _ = mc.hash_mounts(mounts)
    assert any("__load__.zeek" in m for m in mc.compare(before, after))


def test_writes_to_out_are_left_out_of_the_equality_set(tree):
    line, mounts, cmd = zeek_run(tree)
    _, before = check(line, mounts, cmd)
    os.makedirs(os.path.join(tree["out"], "a", "zeek-probe"))
    after, _ = mc.hash_mounts(mounts)
    assert mc.compare(before, after) == []


def test_summary_without_containers(tmp_path, capsys):
    assert mc.summary(str(tmp_path / "none")) == 0
    assert "0 container(s) checked; every rule held" in capsys.readouterr().out


def test_summary_reads_failed(tmp_path, capsys):
    (tmp_path / "FAILED").write_text("mountcheck: rule equality failed\n")
    assert mc.summary(str(tmp_path)) == 1
    assert "a rule FAILED" in capsys.readouterr().out


# Review of #744 at f4b9ab7f (D3, D6, D7): one control per finding, each
# failing on its own rule and no other.

links = pytest.mark.skipif(sys.platform == "win32", reason="symbolic links need a privilege on Windows")


@pytest.mark.parametrize("arg", ["//out/x.zeek", "///out/x.zeek", "/exp/../out/x.zeek"])
def test_control_out_by_another_spelling_fails_command_line_coverage(tree, arg):
    # D3's B1 (normpath keeps two leading slashes) and D6's N2 (normpath).
    assert check(*zeek_run(tree, args=(arg,)))[0] == {mc.R_COVER}


def test_control_zeekpath_with_two_leading_slashes_fails_search_path(tree):
    h = HELP.replace("(.:/usr/local", "(//out:.:/usr/local")
    assert check(*zeek_run(tree), help_text=h)[0] == {mc.R_PATH}


def test_control_plugin_path_under_out_fails_search_path(tree):
    h = HELP.replace("(/usr/local/zeek/lib/zeek/plugins)", "(/out/plugins:/usr/local/zeek/lib/zeek/plugins)")
    assert h != HELP
    assert check(*zeek_run(tree), help_text=h)[0] == {mc.R_PATH}


@pytest.mark.parametrize("arg", ['Intel::read_files=set("/out/x.dat")', 'Intel::read_files=set("\\x2fout\\x2fx.dat")',
                                 "OtsecProbe::log_dir=/out"])
def test_control_a_path_inside_a_redef_fails_absolute_args(tree, arg):
    # D3's B3: a redef's value is a plain word or number.
    failed = check(*zeek_run(tree, args=("/exp/probe.zeek", arg)))[0]
    assert failed == {mc.R_ABS}


@pytest.mark.parametrize("path", ["/out/bin:/usr/bin:/bin", ".:/usr/bin:/bin", "/usr/bin::/bin", "bin:/usr/bin"])
def test_control_the_image_path_outside_the_image_fails_search_path(tree, path):
    # D3's N1: the image's PATH chooses sh, zeek, cat and the rest.
    env = [f"PATH={path}"]
    assert check(*zeek_run(tree), env=env, image_env=env)[0] == {mc.R_PATH}


def test_control_two_captures_sharing_a_folder_fail_new_output_folder(tree):
    # D3's N2: a.pcap and a.cap both write /out/a/<config>.
    with open(os.path.join(tree["pcaps"], "a.cap"), "wb") as fh:
        fh.write(b"\xd4\xc3\xb2\xa1")
    assert check(*zeek_run(tree))[0] == {mc.R_NEW}


def test_only_the_named_captures_folder_counts(tree):
    with open(os.path.join(tree["pcaps"], "b.pcap"), "wb") as fh:
        fh.write(b"\xd4\xc3\xb2\xa1")
    os.makedirs(os.path.join(tree["out"], "a", "zeek-probe"))
    assert check(*zeek_run(tree, cap="/pcaps/b.pcap"))[0] == set()
    # D6's N2: the rule reads the capture the command names, not the first.
    os.makedirs(os.path.join(tree["out"], "b", "zeek-probe"))
    assert check(*zeek_run(tree, cap="/pcaps/b.pcap"))[0] == {mc.R_NEW}


@pytest.mark.parametrize("cap", ["/pcaps/missing.pcap", "/pcaps/notes.txt", "/pcaps/../out/a.pcap", "a.pcap",
                                 "//pcaps/a.pcap", "all"])
def test_control_a_capture_that_is_not_one_plain_file_fails_new_output_folder(tree, cap):
    failed = check(*zeek_run(tree, cap=cap))[0]
    assert mc.R_NEW in failed and failed <= {mc.R_NEW, mc.R_COVER}


@links
def test_control_an_absolute_link_in_out_fails_new_output_folder(tree):
    # D6's B1: out/a -> /out/elsewhere, which the host does not resolve
    # inside out, and /out/elsewhere/zeek-probe made by an earlier container.
    os.makedirs(os.path.join(tree["out"], "elsewhere", "zeek-probe"))
    os.symlink("/out/elsewhere", os.path.join(tree["out"], "a"))
    failed, _ = mc.precheck(*zeek_run(tree)[:1], inspect(*zeek_run(tree)[1:]), ENV, HELP)
    assert set(failed) == {mc.R_NEW}
    assert any("is a symbolic link (to /out/elsewhere)" in m for m in failed[mc.R_NEW])


@links
def test_control_a_link_deep_in_out_fails_new_output_folder(tree):
    os.makedirs(os.path.join(tree["out"], "b", "zeek"))
    os.symlink("/etc", os.path.join(tree["out"], "b", "zeek", "x"))
    assert check(*zeek_run(tree))[0] == {mc.R_NEW}


@links
@pytest.mark.parametrize("target", ["/out/x.zeek", "../out/x.zeek", "probe.zeek"])
def test_control_a_link_in_a_hashed_mount_fails_every_mount_hashed(tree, target):
    # D3's B2, D6's N3, D7's N2: every link is refused, inside or not.
    os.symlink(target, os.path.join(tree["exp"], "x.zeek"))
    failed, _ = mc.precheck(*zeek_run(tree)[:1], inspect(*zeek_run(tree)[1:]), ENV, HELP)
    assert set(failed) == {mc.R_HASHED}
    assert any("x.zeek is a symbolic link" in m for m in failed[mc.R_HASHED])


@links
def test_control_a_link_made_during_the_run_fails_equality(tree):
    line, mounts, cmd = zeek_run(tree)
    _, before = check(line, mounts, cmd)
    os.symlink("/out/x.zeek", os.path.join(tree["exp"], "x.zeek"))
    after, probs = mc.hash_mounts(mounts)
    assert any("symbolic link" in m for m in mc.compare(before, after) + probs)


def test_control_out_as_a_named_volume_fails_read_only(tree):
    line = ["--network", "none", "-v", f"{tree['pcaps']}:/pcaps:ro", "-v", "vol1:/out", IMG,
            "zeek", "-C", "-r", "/pcaps/a.pcap"]
    mounts = [("bind", tree["pcaps"], "/pcaps", False), ("volume", "vol1", "/out", True)]
    assert check(line, mounts, line[7:])[0] == {mc.R_RO}


@pytest.mark.parametrize("what", ["env", "entrypoint", "source", "rw"])
def test_control_the_logged_line_differs_in_a_field_fails_create_line(tree, what):
    line, mounts, cmd = zeek_run(tree)
    entry = None
    if what == "env":
        line[0:0] = ["-e", "X=1"]
    elif what == "entrypoint":
        # The container runs sh as its entrypoint; the line says bash.
        line[0:0] = ["--entrypoint", "/bin/bash"]
        line.remove("sh")
        entry, cmd = ["sh"], cmd[1:]
    elif what == "source":
        line[line.index(f"{tree['exp']}:/exp:ro")] = f"{tree['pkgs']}:/exp:ro"
    else:
        line[line.index(f"{tree['pkgs']}:/pkgs:ro")] = f"{tree['pkgs']}:/pkgs"
    assert check(line, mounts, cmd, entry=entry)[0] == {mc.R_LINE}


class FakeDocker:
    """docker as `run` calls it, for one container made from INS."""

    def __init__(self, ins, start=None):
        self.ins, self.start = ins, start

    def __call__(self, *args, check=True):
        out = ""
        if args[0] == "create":
            out = "c" * 64
        elif args[:2] == ("image", "inspect"):
            out = json.dumps([{"Id": args[2], "Config": {"Env": ENV}}])
        elif args[0] == "inspect":
            out = json.dumps([dict(self.ins, State={"ExitCode": 0})])
        elif args[0] == "run":
            out = HELP
        return types.SimpleNamespace(stdout=out, stderr="", returncode=0)

    def subprocess_run(self, argv, *a, **k):
        assert argv[:2] == ["docker", "start"]
        if self.start:
            self.start()
        return types.SimpleNamespace(returncode=0)


def fake(monkeypatch, tree, start=None, **kw):
    line, mounts, cmd = zeek_run(tree, **kw)
    f = FakeDocker(inspect(mounts, cmd), start)
    monkeypatch.setattr(mc, "docker", f)
    monkeypatch.setattr(mc, "subprocess", types.SimpleNamespace(run=f.subprocess_run, PIPE=None))
    return line


def write_output(tree):
    d = os.path.join(tree["out"], "a", "zeek-probe")
    os.makedirs(d)
    with open(os.path.join(d, "conn.log"), "w") as fh:
        fh.write("{}\n")


def test_run_hashes_the_output_folder_and_summary_reads_it_again(tmp_path, tree, monkeypatch, capsys):
    # D3's N4: output-unchanged, read when the container exits and again at
    # the end of the mode.
    d = str(tmp_path / "checks")
    line = fake(monkeypatch, tree, start=lambda: write_output(tree))
    monkeypatch.setenv("MOUNTCHECK_LOG", str(tmp_path / "log"))
    assert mc.run(d, line) == (0, {})
    assert mc.output_changes(d) == []
    assert mc.summary(d) == 0
    out = capsys.readouterr().out
    assert "every rule held" in out and "container 1: exit 0; /exp " in out and "output " in out
    with open(os.path.join(tree["out"], "a", "zeek-probe", "conn.log"), "a") as fh:
        fh.write("{\"changed\": 1}\n")
    assert any(f"{mc.R_OUT} failed (container 1)" in m and "conn.log" in m for m in mc.output_changes(d))
    assert mc.summary(d) == 1
    assert "a rule FAILED" in capsys.readouterr().out


# `summary DIR --no-count` (run.sh's hr23-unit) prints each output folder's
# hash and no entry count (test); without it the count is printed (control),
# and the hash is the same in both.
def test_summary_no_count_prints_the_output_hash_without_its_entry_count(tmp_path, tree, monkeypatch, capsys):
    d = str(tmp_path / "checks")
    line = fake(monkeypatch, tree, start=lambda: write_output(tree))
    monkeypatch.setenv("MOUNTCHECK_LOG", str(tmp_path / "log"))
    assert mc.run(d, line) == (0, {})
    capsys.readouterr()
    assert mc.main(["summary", d]) == 0
    ctl = capsys.readouterr().out
    assert mc.main(["summary", d, "--no-count"]) == 0
    out = capsys.readouterr().out
    h = ctl.split("; output ")[1].split()[0]
    assert f"; output {h} (" in ctl and "entries)" in ctl
    assert f"; output {h}; " in out and "entries" not in out


def test_control_no_output_folder_when_the_container_exits_fails_output_unchanged(tmp_path, tree, monkeypatch):
    d = str(tmp_path / "checks")
    line = fake(monkeypatch, tree)
    monkeypatch.setenv("MOUNTCHECK_LOG", str(tmp_path / "log"))
    rc, probs = mc.run(d, line)
    assert rc == 3 and set(probs) == {mc.R_OUT}
    assert os.path.exists(os.path.join(d, "FAILED"))


def test_a_failed_rule_writes_failed_before_it_logs(tmp_path, tree, monkeypatch):
    # D6's N1: a log that cannot be written never leaves the run without FAILED.
    d = str(tmp_path / "checks")
    line = fake(monkeypatch, tree, exp_ro=False)
    calls = []

    def log(text):
        calls.append(text)
        if "rule read-only failed" in text:
            raise OSError("the log cannot be written")
    monkeypatch.setattr(mc, "log", log)
    with pytest.raises(OSError):
        mc.run(d, line)
    assert "rule read-only failed" in (tmp_path / "checks" / "FAILED").read_text()


def test_main_fails_closed_when_docker_fails(tmp_path, tree, monkeypatch):
    def broken(*args, check=True):
        raise RuntimeError("docker create failed (exit 125)")
    monkeypatch.setattr(mc, "docker", broken)
    monkeypatch.setenv("MOUNTCHECK_LOG", str(tmp_path / "log"))
    d = tmp_path / "checks"
    assert mc.main(["run", str(d), "--", *zeek_run(tree)[0]]) == 3
    assert "did not finish" in (d / "FAILED").read_text()


def test_main_fails_closed_when_the_log_cannot_be_opened(tmp_path, tree, monkeypatch):
    fake(monkeypatch, tree, exp_ro=False)
    monkeypatch.setenv("MOUNTCHECK_LOG", str(tmp_path / "missing" / "log"))
    d = tmp_path / "checks"
    assert mc.main(["run", str(d), "--", *zeek_run(tree, exp_ro=False)[0]]) == 3
    assert (d / "FAILED").exists()


# D1's ruling 2 on #769 (D3's N2, D6's N2): under --no-count, an
# output-unchanged failure, or an output folder that could not be hashed,
# names only the container, never the folder's entries. Each control is a
# named mutant of mountcheck.py's text, loaded as a module of its own, which
# must make the check fail.
ENTRY = "conn.log"
NO_COUNT_MUTANTS = {
    "changed-entries-printed": ("        if diff and not counts:\n", "        if False:\n"),
    "rehash-error-printed": ('else "could not hash its output folder again"',
                             'else f"could not hash {rec[\'path\']} again: {e}"'),
    "exit-hash-error-printed": ('if counts else "could not hash its output folder when it exited"',
                                'if True else ""'),
    "run-switch-ignored": ('counts = rest[:1] != ["--no-count"]\n', 'counts = True\n'),
}


def load(tmp_path, old=None, new=None):
    """mountcheck.py, or a mutant of it, as a module of its own."""
    with open(mc.__file__, encoding="utf-8") as fh:
        text = fh.read()
    if old is not None:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    p = tmp_path / "mutant_mountcheck.py"
    p.write_text(text, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(f"mutant_mountcheck_{abs(hash(old))}", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def no_count_leaks(m, tmp_path, tree, monkeypatch, capsys):
    """Where module M, under --no-count, names an output folder's entry."""
    line, mounts, cmd = zeek_run(tree)
    f = FakeDocker(inspect(mounts, cmd), lambda: write_output(tree))
    monkeypatch.setattr(m, "docker", f)
    monkeypatch.setattr(m, "subprocess", types.SimpleNamespace(run=f.subprocess_run, PIPE=None))
    monkeypatch.setenv("MOUNTCHECK_LOG", str(tmp_path / "log"))
    bad = []
    # An entry changed after the container exited.
    d = str(tmp_path / "changed")
    assert m.run(d, line, counts=False) == (0, {})
    with open(os.path.join(tree["out"], "a", "zeek-probe", ENTRY), "a") as fh:
        fh.write("{\"changed\": 1}\n")
    capsys.readouterr()
    assert m.summary(d, counts=False) == 1
    out = capsys.readouterr().out
    if f"{m.R_OUT} failed (container 1)" not in out or ENTRY in out:
        bad.append("changed: " + out)
    # The output folder could not be hashed again at the end of the mode.
    real = m.hash_tree

    def broken(p):
        raise OSError(f"{p}/{ENTRY} is a symbolic link (to /x); a hashed tree may hold none")
    monkeypatch.setattr(m, "hash_tree", broken)
    msgs = m.output_changes(d, counts=False)
    if not msgs or any(ENTRY in x or "container 1" not in x for x in msgs):
        bad.append(f"rehash: {msgs}")
    # The output folder could not be hashed when its container exited, by
    # `main run --no-count`, as run.sh's mc_run calls it.
    shutil.rmtree(os.path.join(tree["out"], "a"))

    def out_broken(p):
        if p.startswith(tree["out"]):
            raise OSError(f"{p}/{ENTRY} is a symbolic link (to /x); a hashed tree may hold none")
        return real(p)
    monkeypatch.setattr(m, "hash_tree", out_broken)
    d = tmp_path / "exited"
    assert m.main(["run", str(d), "--no-count", "--", *line]) == 3
    failed = (d / "FAILED").read_text()
    log = (tmp_path / "log").read_text()
    if f"rule {m.R_OUT} failed" not in failed or ENTRY in failed or ENTRY in log:
        bad.append("exited: " + failed)
    return bad


def test_no_count_names_only_the_container(tmp_path, tree, monkeypatch, capsys):
    assert no_count_leaks(mc, tmp_path, tree, monkeypatch, capsys) == []


def test_without_no_count_the_entry_is_named(tmp_path, tree, monkeypatch, capsys):
    # The other modes keep the detail: a changed entry is named.
    d = str(tmp_path / "checks")
    line = fake(monkeypatch, tree, start=lambda: write_output(tree))
    monkeypatch.setenv("MOUNTCHECK_LOG", str(tmp_path / "log"))
    assert mc.run(d, line) == (0, {})
    with open(os.path.join(tree["out"], "a", "zeek-probe", ENTRY), "a") as fh:
        fh.write("{\"changed\": 1}\n")
    assert any(ENTRY in x for x in mc.output_changes(d))


@pytest.mark.parametrize("old,new", NO_COUNT_MUTANTS.values(), ids=NO_COUNT_MUTANTS.keys())
def test_no_count_mutant_is_killed(tmp_path, tree, monkeypatch, capsys, old, new):
    assert no_count_leaks(load(tmp_path, old, new), tmp_path, tree, monkeypatch, capsys) != []

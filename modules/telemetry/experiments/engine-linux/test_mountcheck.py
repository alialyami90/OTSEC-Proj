"""The script-hash check of docs/release.md section 8.4 item 3 (D4-115
item 5): mountcheck.py's rules on made-up `docker inspect` records and real
folders on the host. Each control breaks one rule and must fail on that
rule and no other. The same controls run on a runner's Docker in
mountcheck.py's selftest, which run.sh runs first in every mode. Run:
python -m pytest -q modules/telemetry/experiments/engine-linux/test_mountcheck.py"""
import os
import sys

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


def zeek_run(t, cfg="zeek-probe", args=("/exp/probe.zeek", "OtsecProbe::log_dir=F"), exp_ro=True, extra=()):
    """run.sh's zeek_run: (the docker create line, the inspect record)."""
    line = ["--network", "none", *extra, "-v", f"{t['pcaps']}:/pcaps:ro", "-v", f"{t['out']}:/out",
            "-v", f"{t['exp']}:/exp" + (":ro" if exp_ro else ""), "-v", f"{t['pkgs']}:/pkgs:ro",
            IMG, "sh", "/exp/in-container.sh", "zeek", cfg, *args]
    mounts = [("bind", t["pcaps"], "/pcaps", False), ("bind", t["out"], "/out", True),
              ("bind", t["exp"], "/exp", not exp_ro), ("bind", t["pkgs"], "/pkgs", False)]
    return line, mounts, ["sh", "/exp/in-container.sh", "zeek", cfg, *args]


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

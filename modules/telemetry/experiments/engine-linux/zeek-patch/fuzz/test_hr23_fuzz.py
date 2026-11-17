"""HR-23's sanitizer fuzz run (D4, brief P4-4-HR23-FUZZ): unit tests of the
CRC fix-up (hr23-crc-mutator.cc), the seed conversion (seeds.py), the
judge (fuzz_judge.py) and the disclosure rule of design section 4.6.

Each rule has a control: a named mutation of the file under test, built
here, which the rule's own check must reject (`test_*_control_*`).

The fix-up is compiled with the host's C++ compiler into a shared library
(HR23_NO_LIBFUZZER, so that libFuzzer's LLVMFuzzerMutate is not needed) and
called through ctypes; with no compiler those tests skip. Run:
python -m pytest -q modules/telemetry/experiments/engine-linux/zeek-patch/fuzz
"""
import ctypes
import importlib.util
import os
import re
import shutil
import struct
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "integration", "gt_pcap"))
import dnp3  # noqa: E402
import pcapfile  # noqa: E402
import synth  # noqa: E402

MAGIC = b"\x01PKT"
MUTATOR = os.path.join(HERE, "hr23-crc-mutator.cc")
CXX = next((c for c in ("c++", "clang++", "g++") if shutil.which(c)), None)


def load(path, name, edit=None):
    """A module from a source file, after an optional (old, new) edit."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    if edit:
        assert src.count(edit[0]) == 1, edit[0]
        src = src.replace(*edit)
    spec = importlib.util.spec_from_loader(name, loader=None)
    mod = importlib.util.module_from_spec(spec)
    mod.__file__ = path
    exec(compile(src, path, "exec"), mod.__dict__)
    return mod


# --- The CRC fix-up --------------------------------------------------------

def build_fixup(tmp_path, edit=None):
    if CXX is None:
        pytest.skip("no C++ compiler on this host")
    with open(MUTATOR, encoding="utf-8") as fh:
        src = fh.read()
    if edit:
        assert src.count(edit[0]) == 1, edit[0]
        src = src.replace(*edit)
    cc = tmp_path / "m.cc"
    cc.write_text(src)
    so = tmp_path / "m.so"
    subprocess.run([CXX, "-std=c++17", "-O1", "-shared", "-fPIC", "-DHR23_NO_LIBFUZZER", "-o", str(so), str(cc)],
                   check=True)
    lib = ctypes.CDLL(str(so))
    lib.hr23_fix_buffer.restype = ctypes.c_size_t
    lib.hr23_fix_buffer.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int]

    def fix(data, ip=False):
        buf = ctypes.create_string_buffer(bytes(data), len(data))
        n = lib.hr23_fix_buffer(buf, len(data), 1 if ip else 0)
        return buf.raw, n
    return fix


def frame(user, dest=10, src=1):
    return dnp3.link(dest, src, True, user)


def crc_spans(fr):
    """(start, length) of every CRC-covered span of one whole frame."""
    spans = [(0, 8)]
    j, user = 10, fr[2] - 5
    while user > 0:
        b = min(16, user)
        spans.append((j, b))
        j += b + 2
        user -= b
    return spans


def corrupt(fr):
    out = bytearray(fr)
    for s, n in crc_spans(fr):
        out[s + n] ^= 0xFF
        out[s + n + 1] ^= 0x5A
    return bytes(out)


def fb(*chunks):
    return b"".join(MAGIC + bytes([o]) + c for o, c in chunks)


USER40 = bytes(range(40))  # three blocks: 16, 16 and 8 octets
F40 = frame(USER40)
F32 = frame(bytes(range(100, 132)))  # two whole blocks, the last at the chunk's end
F0 = frame(b"")  # a header alone, 10 octets


def stream_case():
    good = fb((1, F40), (0, F32 + F0), (1, F0))
    bad = fb((1, corrupt(F40)), (0, corrupt(F32) + corrupt(F0)), (1, corrupt(F0)))
    return good, bad


def check_stream(fix):
    good, bad = stream_case()
    out, n = fix(bad)
    assert out == good
    assert n == 4


def ip_udp(payload, proto=17, sport=20000):
    if proto == 17:
        l4 = synth.udp("192.0.2.14", "192.0.2.20", sport, 20000, payload)
    else:
        l4 = synth.tcp("192.0.2.14", "192.0.2.20", 41000, 20000, 1, 1, 0x18, payload)
    return synth.ipv4("192.0.2.14", "192.0.2.20", proto, l4, 7)


def check_ip(fix):
    # The CRCs are corrupted in place, so the UDP checksum, which the
    # fix-up leaves alone (the fuzzers set ignore_checksums), is unchanged.
    good = fb((1, ip_udp(F40)), (1, ip_udp(F32)))
    bad = fb((1, ip_udp(F40)[:28] + corrupt(F40)), (1, ip_udp(F32)[:28] + corrupt(F32)))
    out, n = fix(bad, ip=True)
    assert out == good and n == 2
    # A TCP packet in IP framing is left as it is.
    tcp_bad = fb((1, ip_udp(F40, proto=6)[:40] + corrupt(F40)))
    assert fix(tcp_bad, ip=True) == (tcp_bad, 0)
    # A source port of 1380 (05 64) is not taken for a frame's start: the
    # fix-up starts after the UDP header.
    odd = fb((1, ip_udp(F40, sport=0x0564)))
    assert fix(odd, ip=True) == (odd, 1)


def test_fixup_restores_every_crc_in_stream_framing(tmp_path):
    check_stream(build_fixup(tmp_path))


def test_fixup_makes_a_mutated_frame_valid(tmp_path):
    fix = build_fixup(tmp_path)
    fr = bytearray(F40)
    fr[3] ^= 0x01  # the control octet
    fr[10 + 5] ^= 0xFF  # an octet of the first block
    out, _ = fix(fb((1, bytes(fr))))
    got = out[5:]
    for s, n in crc_spans(got):
        assert got[s + n:s + n + 2] == dnp3.crc(got[s:s + n])


def test_fixup_leaves_a_block_cut_by_the_chunk_end(tmp_path):
    fix = build_fixup(tmp_path)
    cut = corrupt(F40)[:10 + 18 + 10]  # header, one whole block, 10 octets of the next
    out, n = fix(fb((1, cut)))
    assert n == 1
    got = out[5:]
    assert got[8:10] == dnp3.crc(got[:8]) and got[26:28] == dnp3.crc(got[10:26])
    assert got[28:] == cut[28:]


def test_fixup_stops_at_each_chunk_boundary(tmp_path):
    # A frame whose blocks run past its chunk: the next chunk's octets are
    # not taken as its blocks.
    fix = build_fixup(tmp_path)
    head = corrupt(F40)[:10]
    out, n = fix(fb((1, head), (0, b"\xAA" * 40)))
    assert n == 1 and out.endswith(MAGIC + b"\x00" + b"\xAA" * 40)


def test_fixup_ip_framing_fixes_udp_payload_only(tmp_path):
    check_ip(build_fixup(tmp_path))


def test_fixup_ignores_input_with_no_magic(tmp_path):
    fix = build_fixup(tmp_path)
    data = corrupt(F40)
    assert fix(data) == (data, 0)


# The controls: each mutant of the fix-up must fail the check named.
FIXUP_CONTROLS = [
    ("block-15", ("size_t b = user < 16 ? user : 16;", "size_t b = user < 15 ? user : 15;"), check_stream),
    ("poly", ("0xA6BC", "0xA6BD"), check_stream),
    ("header-bound-off-by-one", ("while ( i + 10 <= n ) {", "while ( i + 10 < n ) {"), check_stream),
    ("block-bound-off-by-one", ("if ( j + b + 2 > n )", "if ( j + b + 2 >= n )"), check_stream),
    ("ip-any-protocol", ("|| d[9] != 17 )", ")"), check_ip),
    ("ip-no-udp-header", ("return fix_octets(d + ihl + 8, n - ihl - 8);", "return fix_octets(d, n);"), check_ip),
]


@pytest.mark.parametrize("name,edit,check", FIXUP_CONTROLS, ids=[c[0] for c in FIXUP_CONTROLS])
def test_fixup_control_fails(tmp_path, name, edit, check):
    with pytest.raises(AssertionError):
        check(build_fixup(tmp_path, edit))


def test_mutator_calls_libfuzzer_then_the_fixup():
    with open(MUTATOR, encoding="utf-8") as fh:
        src = fh.read()
    body = src[src.index("LLVMFuzzerCustomMutator(uint8_t*"):]
    assert body.index("LLVMFuzzerMutate(data, size, max_size)") < body.index("hr23_fix_buffer(data, size, HR23_FRAMING_IP)")


# --- The seed conversion ---------------------------------------------------

SEEDS = os.path.join(HERE, "seeds.py")
M = synth.Host("02:00:00:00:00:0e", "192.0.2.14", 20000)
O = synth.Host("02:00:00:00:00:14", "192.0.2.20", 20000)


def chunks(data):
    """FuzzBuffer::Next's cut of one input, as (is_orig, octets)."""
    out = []
    pos = data.find(MAGIC)
    while pos != -1 and pos + 5 < len(data) + 1:
        flag = data[pos + 4]
        nxt = data.find(MAGIC, pos + 5)
        out.append((bool(flag & 1), data[pos + 5:nxt if nxt != -1 else len(data)]))
        pos = nxt
    return out


def udp_capture(tmp_path, msgs, name="u.pcap"):
    conv = synth.UDPConv(M, O, synth.Clock())
    for from_m, data in msgs:
        conv.send(from_m, data)
    p = tmp_path / name
    pcapfile.write(str(p), conv.frames)
    return str(p), conv.frames


def tcp_capture(tmp_path, msgs):
    conv = synth.TCPConv(synth.Host(M.mac, M.ip, 41000), O, synth.Clock())
    conv.handshake()
    for from_m, data in msgs:
        conv.send(from_m, data)
    conv.close()
    p = tmp_path / "t.pcap"
    pcapfile.write(str(p), conv.frames)
    return str(p)


MSGS = [(True, frame(dnp3.tpdu(0, dnp3.request(0, 1)))), (False, frame(dnp3.tpdu(0, dnp3.response(0)), 1, 10)),
        (True, frame(dnp3.tpdu(1, dnp3.request(1, 1))))]


def check_udp(seeds, tmp_path):
    path, frames = udp_capture(tmp_path, MSGS)
    out = seeds.convert(path, 8192)
    assert set(out) == {"dnp3_tcp", "dnp3_udp", "packet"}
    for t in ("dnp3_tcp", "dnp3_udp"):
        data, cut = out[t]
        assert not cut and chunks(data) == MSGS
    data, cut = out["packet"]
    got = chunks(data)
    assert len(got) == 3 and not cut
    for (_, ip), fr in zip(got, frames):
        # The IPv4 packet, from its header to its total length: no Ethernet
        # header and no padding.
        total = struct.unpack("!H", ip[2:4])[0]
        assert ip[0] == 0x45 and len(ip) == total and fr.data[14:14 + total] == ip


def test_seeds_udp_capture(tmp_path):
    check_udp(load(SEEDS, "seeds"), tmp_path)


def test_seeds_tcp_capture_has_no_packet_seed_and_no_empty_chunk(tmp_path):
    out = load(SEEDS, "seeds").convert(tcp_capture(tmp_path, MSGS), 8192)
    assert set(out) == {"dnp3_tcp", "dnp3_udp"}
    assert chunks(out["dnp3_tcp"][0]) == MSGS


def test_seeds_cut_at_64_chunks(tmp_path):
    seeds = load(SEEDS, "seeds")
    one = (True, frame(b"\x00" * 4))
    for n, want_cut in ((64, False), (65, True)):
        data, cut = seeds.fuzzbuffer([one] * n, 1 << 20)
        assert cut is want_cut and len(chunks(data)) == 64


def test_seeds_cut_at_max_len(tmp_path):
    seeds = load(SEEDS, "seeds")
    one = (True, b"\x05" * 95)  # 100 octets with its magic and flag
    data, cut = seeds.fuzzbuffer([one] * 3, 300)
    assert not cut and len(data) == 300
    data, cut = seeds.fuzzbuffer([one] * 3, 299)
    assert cut and len(data) == 200


def test_seeds_refuse_a_chunk_holding_the_magic(tmp_path):
    with pytest.raises(ValueError):
        load(SEEDS, "seeds").fuzzbuffer([(True, b"ab" + MAGIC)], 8192)


def test_seeds_main_is_deterministic(tmp_path):
    import zipfile
    seeds = load(SEEDS, "seeds")
    caps = tmp_path / "caps"
    caps.mkdir()
    udp_capture(caps, MSGS, "a.pcap")
    z = tmp_path / "c.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.pkt", fb((1, F0)))
    mans = []
    for k in range(2):
        out = tmp_path / f"o{k}"
        assert seeds.main(["--max-len", "8192", "--zeek-corpus", str(z), str(out), str(caps)]) == 0
        mans.append((out / "manifest.sha256").read_bytes())
    assert mans[0] == mans[1]
    names = [x.split(b"  ")[1] for x in mans[0].splitlines()]
    assert names == sorted(names) and b"packet/a.pkt" in names and b"dnp3_udp/zeek-x.pkt" in names
    assert b"packet/zeek-x.pkt" not in names


SEEDS_CONTROLS = [
    ("is-orig-inverted", ("gen = [(p[1] == first, p[4])", "gen = [(p[1] != first, p[4])"), check_udp),
    ("ethernet-kept", ("[(True, p[3]) for p in flow]", "[(True, b'\\x00' * 14 + p[3]) for p in flow]"), check_udp),
]


@pytest.mark.parametrize("name,edit,check", SEEDS_CONTROLS, ids=[c[0] for c in SEEDS_CONTROLS])
def test_seeds_control_fails(tmp_path, name, edit, check):
    with pytest.raises(AssertionError):
        check(load(SEEDS, "seeds_" + name.replace("-", "_"), edit), tmp_path)


def check_cut64(seeds):
    one = (True, frame(b"\x00" * 4))
    data, cut = seeds.fuzzbuffer([one] * 64, 1 << 20)
    assert not cut and len(chunks(data)) == 64


def test_seeds_cut_control_off_by_one(tmp_path):
    check_cut64(load(SEEDS, "seeds"))
    with pytest.raises(AssertionError):
        check_cut64(load(SEEDS, "seeds_cut", ("if n == MAX_CHUNKS or", "if n == MAX_CHUNKS - 1 or")))


# --- The judge, and the disclosure rule ------------------------------------

JUDGE = os.path.join(HERE, "fuzz_judge.py")
TRACE = "==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011"
INPUT_B64 = "Base64: AVBLVAEFZAUAAAAAAAA="
INPUT_HEX = "0x1,0x50,0x4b,0x54,0x1,0x5,0x64,"
ART = "crash-0123456789abcdef0123456789abcdef01234567"


def campaign(f, b, t, rc=0, secs=1800, execs=12345, artifacts=()):
    d = f / "private" / b / t
    (d / "artifacts").mkdir(parents=True)
    (d / "exit-code").write_text(f"{rc}\n")
    (d / "seconds").write_text(f"{secs}\n")
    (d / "log").write_text(f"INFO: Seed: 1\n{TRACE}\n{INPUT_HEX}\n{INPUT_B64}\n"
                           f"artifact_prefix='./'; Test unit written to ./{ART}\n"
                           f"stat::number_of_executed_units: {execs}\nstat::peak_rss_mb: 900\n")
    for a in artifacts:
        (d / "artifacts" / a).write_bytes(b"\x01PKT\x01\x05\x64secret-input")


def run_judge(f, *rows, cov=True):
    judge = load(JUDGE, "fuzz_judge")
    for t in judge.TARGETS:
        for b in judge.BUILDS:
            spec = next((r for r in rows if r[:2] == (b, t)), None)
            campaign(f, b, t, **(spec[2] if spec else {}))
    if cov is not None:
        (f / "coverage.tsv").write_text("condition\tmet\n" + "".join(
            f"{c}\t{'yes' if cov else 'no'}\n" for c in judge.CONDITIONS))
    return judge


def summary(judge, f, capsys):
    judge.summary(str(f))
    return capsys.readouterr().out


def write_replay(f, *rows):
    (f / "private" / "replay.tsv").write_text("".join("\t".join(r) + "\n" for r in rows))


def check_no_leak(out):
    """The disclosure rule on the judge's output: no trace, input, artifact
    name or log line of the private files reaches it."""
    for leak in (TRACE, "AddressSanitizer", "heap-buffer-overflow", INPUT_B64, "AVBLVAEF", INPUT_HEX, ART,
                 "crash-", "secret-input", "peak_rss"):
        assert leak not in out, leak


def test_judge_pass_and_its_output_holds_no_input_trace_or_name(tmp_path, capsys):
    judge = run_judge(tmp_path)
    out = summary(judge, tmp_path, capsys)
    assert "Verdict: **pass**" in out
    assert "| packet | c2 | ran | 1800 | 12345 | 0 |" in out
    check_no_leak(out)
    # With reports and their inputs on every campaign, too.
    judge = run_judge(tmp_path / "r", *[(b, t, {"rc": 77, "artifacts": (ART,)})
                                        for t in judge.TARGETS for b in judge.BUILDS])
    write_replay(tmp_path / "r", *[(t, b, "77", "77") for t in judge.TARGETS for b in judge.BUILDS])
    check_no_leak(summary(judge, tmp_path / "r", capsys))


# The disclosure controls: a judge that copies a private file into the
# summary must fail check_no_leak.
JUDGE_LEAK_CONTROLS = [
    ("log-in-table", ('"-" if ex is None else str(ex)',
                      'open(os.path.join(d, "log")).read()')),
    ("artifact-names", ('f"reports that left no input: {reports_no_input}."',
                        'f"reports that left no input: {reports_no_input}." + " ".join('
                        'os.listdir(os.path.join(priv, "c2", "dnp3_tcp", "artifacts")))')),
]


@pytest.mark.parametrize("name,edit", JUDGE_LEAK_CONTROLS, ids=[c[0] for c in JUDGE_LEAK_CONTROLS])
def test_judge_disclosure_control_fails(tmp_path, capsys, name, edit):
    run_judge(tmp_path, ("c2", "dnp3_tcp", {"rc": 77, "artifacts": (ART,)}))
    write_replay(tmp_path, ("dnp3_tcp", "c2", "77", "77"))
    judge = load(JUDGE, "fuzz_judge_leak_" + name.replace("-", "_"), edit)
    judge.summary(str(tmp_path))
    out = capsys.readouterr().out
    with pytest.raises(AssertionError):
        check_no_leak(out)


def test_judge_fail_on_a_report_against_the_patch(tmp_path, capsys):
    judge = run_judge(tmp_path, ("c2", "dnp3_udp", {"rc": 77, "secs": 40, "artifacts": (ART,)}))
    write_replay(tmp_path, ("dnp3_udp", "c2", "0", "77"))
    out = summary(judge, tmp_path, capsys)
    assert "Verdict: **fail**" in out and "Against the patch (reproduces on C2, not on C1p): 1." in out
    assert "ended by a report before their time: 1" in out
    assert ART not in out and TRACE not in out and "secret-input" not in out


def check_early_bound(judge, tmp_path, capsys):
    # A campaign that stopped on a report at exactly its pinned time ran its
    # whole time; one second short of it ended early.
    for secs, want in ((1800, 0), (1799, 1)):
        f = tmp_path / str(secs)
        run_judge(f, ("c2", "dnp3_tcp", {"rc": 77, "secs": secs, "artifacts": (ART,)}))
        write_replay(f, ("dnp3_tcp", "c2", "77", "77"))
        judge.summary(str(f))
        assert f"ended by a report before their time: {want};" in capsys.readouterr().out


def test_judge_early_stop_bound(tmp_path, capsys):
    check_early_bound(load(JUDGE, "fuzz_judge"), tmp_path, capsys)


def test_judge_early_stop_control_off_by_one_fails(tmp_path, capsys):
    judge = load(JUDGE, "fuzz_judge_early", ("secs < seconds_pin", "secs <= seconds_pin"))
    with pytest.raises(AssertionError):
        check_early_bound(judge, tmp_path, capsys)


def test_judge_stock_report_is_counted_not_netted_out(tmp_path, capsys):
    judge = run_judge(tmp_path, ("c1p", "dnp3_tcp", {"rc": 77, "artifacts": (ART,)}),
                      ("c2", "dnp3_tcp", {"rc": 77, "artifacts": (ART + "x",)}))
    write_replay(tmp_path, ("dnp3_tcp", "c1p", "77", "77"), ("dnp3_tcp", "c2", "77", "77"))
    out = summary(judge, tmp_path, capsys)
    assert "Verdict: **pass**" in out
    assert "held for the owner's disclosure decision): 2." in out


def test_judge_unknown_cases(tmp_path, capsys):
    # Not reproduced on its own build.
    judge = run_judge(tmp_path / "a", ("c2", "packet", {"rc": 70, "artifacts": (ART,)}))
    write_replay(tmp_path / "a", ("packet", "c2", "0", "0"))
    assert "Verdict: **unknown**" in summary(judge, tmp_path / "a", capsys)
    # A non-zero exit with no input.
    judge = run_judge(tmp_path / "b", ("c1p", "packet", {"rc": 1}))
    assert "Verdict: **unknown**" in summary(judge, tmp_path / "b", capsys)
    # A coverage condition not met, and no coverage at all.
    judge = run_judge(tmp_path / "c", cov=False)
    assert "Verdict: **unknown**" in summary(judge, tmp_path / "c", capsys)
    judge = run_judge(tmp_path / "d", cov=None)
    assert "Verdict: **unknown**" in summary(judge, tmp_path / "d", capsys)
    # A report whose input was never replayed.
    judge = run_judge(tmp_path / "e", ("c2", "dnp3_tcp", {"rc": 77, "artifacts": (ART,)}))
    assert "Verdict: **unknown**" in summary(judge, tmp_path / "e", capsys)


def test_judge_campaign_with_no_result_is_unknown(tmp_path, capsys):
    judge = run_judge(tmp_path)
    os.remove(tmp_path / "private" / "c1p" / "dnp3_udp" / "exit-code")
    out = summary(judge, tmp_path, capsys)
    assert "Verdict: **unknown**" in out and "| dnp3_udp | c1p | no result |" in out


def test_judge_control_netting_out_stock_reports_fails(tmp_path, capsys):
    # The control: a judge that counts a both-builds report against the
    # patch, or drops it, must not pass this check.
    judge = load(JUDGE, "fuzz_judge_ctl", ('classes["both"] += 1', 'pass'))
    run_judge(tmp_path, ("c1p", "dnp3_tcp", {"rc": 77, "artifacts": (ART,)}))
    write_replay(tmp_path, ("dnp3_tcp", "c1p", "77", "77"))
    judge.summary(str(tmp_path))
    out = capsys.readouterr().out
    assert "held for the owner's disclosure decision): 1." not in out


# The coverage condition.
DNP3CC = """    catch ( const binpac::Exception& e ) {
        DiscardFlowBuffer(orig);
        SetSkip(true);
        // OTSEC patch (HR-23, (B')): the violation is raised here, with
        // Analyzer::NextPacket's text, and the exception is not rethrown.
        // PIA::ReplayPacketBuffer calls DeliverPacket, not NextPacket, so a
        // rethrow there left no DNP3 violation. UDP only; TCP is unchanged.
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.what()));
    }
"""
FN = {
    "req": "_ZN6binpac4DNP312DNP3_Request5ParseEPKhS2_",
    "resp": "_ZN6binpac4DNP313DNP3_Response5ParseEPKhS2_",
    "isresp": "_ZN6binpac4DNP39DNP3_Flow16is_response_codeERKNS_9datastringIhEE",
    "replay": "_ZN4zeek8analyzer3pia3PIA18ReplayPacketBufferEPNS0_8AnalyzerE",
    "udp": "_ZN4zeek8plugin10Zeek_DNP317DNP3_UDP_Analyzer13DeliverPacketEiPKhbmPKNS_2IP_HdrEi",
}


def lcov_file(path, fns, catch=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    out = ["SF:/w/c2/zeek-9.0.1/src/analyzer/protocol/dnp3/DNP3.cc"]
    out += [f"FN:1,{FN[k]}" for k in FN] + [f"FNDA:{1 if k in fns else 0},{FN[k]}" for k in FN]
    out += ["DA:7,0", f"DA:8,{1 if catch else 0}", "end_of_record"]
    path.write_text("\n".join(out) + "\n")


def coverage(tmp_path, capsys, per, edit=None):
    judge = load(JUDGE, "fuzz_judge_cov", edit)
    cc = tmp_path / "DNP3.cc"
    cc.write_text(DNP3CC)
    for t, (fns, catch) in per.items():
        lcov_file(tmp_path / "private" / f"cov-{t}" / "lcov.info", fns, catch)
    judge.coverage(str(tmp_path), str(cc))
    capsys.readouterr()
    return dict(x.split("\t") for x in (tmp_path / "coverage.tsv").read_text().splitlines()[1:])


ALL = {"dnp3_tcp": ({"req", "resp", "isresp"}, False), "dnp3_udp": ({"req", "resp", "isresp", "udp"}, True),
       "packet": ({"req", "replay", "udp"}, False)}


def test_coverage_all_met(tmp_path, capsys):
    got = coverage(tmp_path, capsys, ALL)
    assert all(got[c] == "yes" for c in load(JUDGE, "j").CONDITIONS)


def test_coverage_replay_path_needs_the_packet_target(tmp_path, capsys):
    per = dict(ALL)
    per["packet"] = ({"req", "udp"}, False)
    per["dnp3_udp"] = ({"req", "resp", "isresp", "udp", "replay"}, True)
    assert coverage(tmp_path, capsys, per)["replay-path"] == "no"


def test_coverage_catch_line_not_reached(tmp_path, capsys):
    per = {t: (fns, False) for t, (fns, _) in ALL.items()}
    assert coverage(tmp_path, capsys, per)["bprime-catch"] == "no"


def test_coverage_one_arm_missing(tmp_path, capsys):
    per = {t: (fns - {"resp"}, c) for t, (fns, c) in ALL.items()}
    got = coverage(tmp_path, capsys, per)
    assert got["response-parser"] == "no" and got["request-parser"] == "yes"


def test_coverage_control_catch_line_off_by_one_fails(tmp_path, capsys):
    # The control: a judge that reads the line before the violation call
    # (the comment, which coverage never marks) must not find it reached.
    with pytest.raises(AssertionError):
        got = coverage(tmp_path, capsys, ALL, ("return i + 1", "return i"))
        assert got["bprime-catch"] == "yes"


def test_judge_catch_strings_match_the_pinned_patch():
    judge = load(JUDGE, "j")
    with open(os.path.join(HERE, "..", "hr23-fc-dispatch.patch"), encoding="utf-8") as fh:
        added = [x[1:] for x in fh.read().split("\n") if x.startswith("+") and not x.startswith("+++")]
    assert any(judge.CATCH_MARK in x for x in added)
    assert any(x.strip() == judge.CATCH_LINE for x in added)


# --- Disclosure, by the files that run -------------------------------------

WORKFLOW = os.path.join(ROOT, ".github", "workflows", "d4-zeek-dnp3-fuzz.yml")
FUZZ_SH = os.path.join(HERE, "fuzz.sh")


def check_workflow(wf):
    """The disclosure rule on the workflow: dispatch-only, nothing uploaded
    or cached, and no step names the private folder."""
    assert "upload-artifact" not in wf and "actions/cache" not in wf
    assert re.search(r"^on:\n  workflow_dispatch:\npermissions:", wf, re.M)
    assert "pull_request" not in wf and "push:" not in wf and "schedule:" not in wf
    assert "private" not in wf


def check_fuzz_sh(src):
    """The disclosure rule on fuzz.sh: every fuzzer run writes to a private
    file, and no command prints one."""
    lines = src.split("\n")
    calls = [x for x in lines if re.search(r"\bfuzzer (c1p|c2|\$b|\$rb) ", x)]
    assert len(calls) == 3  # campaign, replay, coverage
    for x in calls:
        assert re.search(r'> "\$(d|priv)/[^"]*" 2>&1', x), x
    for x in lines:
        assert not re.search(r'\b(cat|head|tail|sed|grep|less)\b[^|]*"\$(priv|d)/', x), x


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read().replace("\r\n", "\n")


def test_workflow_uploads_nothing_and_prints_no_private_file():
    check_workflow(read(WORKFLOW))


def test_fuzz_sh_sends_every_fuzzer_run_to_a_private_file():
    check_fuzz_sh(read(FUZZ_SH))


# The disclosure controls on the files that run: each mutant must fail.
WORKFLOW_CONTROLS = [
    ("upload-artifact", ("      - name: Summary and verdict\n",
                         "      - uses: actions/upload-artifact@v4\n        with:\n          path: ${{ runner.temp }}\n"
                         "      - name: Summary and verdict\n")),
    ("push-trigger", ("on:\n  workflow_dispatch:\n", "on:\n  workflow_dispatch:\n  push:\n")),
]
FUZZ_SH_CONTROLS = [
    ("campaign-to-the-job-log", ('"$d/corpus" > "$d/log" 2>&1 || rc=$?', '"$d/corpus" || rc=$?')),
    ("replay-log-printed", ('  rm -f "$priv/replay.log"', '  cat "$priv/replay.log"')),
]


@pytest.mark.parametrize("name,edit", WORKFLOW_CONTROLS, ids=[c[0] for c in WORKFLOW_CONTROLS])
def test_workflow_disclosure_control_fails(name, edit):
    wf = read(WORKFLOW)
    assert wf.count(edit[0]) == 1, edit[0]
    with pytest.raises(AssertionError):
        check_workflow(wf.replace(*edit))


@pytest.mark.parametrize("name,edit", FUZZ_SH_CONTROLS, ids=[c[0] for c in FUZZ_SH_CONTROLS])
def test_fuzz_sh_disclosure_control_fails(name, edit):
    src = read(FUZZ_SH)
    assert src.count(edit[0]) == 1, edit[0]
    with pytest.raises(AssertionError):
        check_fuzz_sh(src.replace(*edit))

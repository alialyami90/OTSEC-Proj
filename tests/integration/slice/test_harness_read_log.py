"""harness.read_log, live and after the writer stops (A6; #209's integration
job 122275033049, where a read right after a collector kill caught half of
the simulator's record of the close and failed test_slice_floor_e2e.py's
setup).

Evidence class: desk (the harness's own reader, on files written here).
"""
import json

import pytest

import harness

DONE = [{"event": "line", "text": "SHO P 1"}, {"event": "session_close", "session": 1}]
HALF = b'{"effect": "session closed at Access Level 1 without QUIT; relay stays elevated until TIDLE expir'


def write(tmp_path, data):
    p = tmp_path / "sim.jsonl"
    p.write_bytes(data)
    return str(p)


def records(newline=b"\n"):
    return b"".join(json.dumps(r).encode() + newline for r in DONE)


def test_live_leaves_a_half_written_last_line(tmp_path):
    assert harness.read_log(write(tmp_path, records() + HALF), live=True) == DONE


def test_after_the_writer_stops_a_truncated_record_fails(tmp_path):
    with pytest.raises(json.JSONDecodeError):
        harness.read_log(write(tmp_path, records() + HALF))


@pytest.mark.parametrize("live", [False, True])
def test_complete_records_read_either_way(tmp_path, live):
    assert harness.read_log(write(tmp_path, records()), live=live) == DONE


@pytest.mark.parametrize("live", [False, True])
def test_a_bad_complete_line_fails_either_way(tmp_path, live):
    with pytest.raises(json.JSONDecodeError):
        harness.read_log(write(tmp_path, HALF + b"\n" + records()), live=live)


@pytest.mark.parametrize("live", [False, True])
def test_windows_line_ends(tmp_path, live):
    # The simulator and the receiver write in text mode, so CRLF on Windows.
    assert harness.read_log(write(tmp_path, records(b"\r\n")), live=live) == DONE


def test_live_with_no_complete_line_is_empty(tmp_path):
    assert harness.read_log(write(tmp_path, HALF), live=True) == []
    assert harness.read_log(write(tmp_path, b""), live=True) == []

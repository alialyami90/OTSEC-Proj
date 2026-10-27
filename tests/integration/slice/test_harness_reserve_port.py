"""harness.reserve_port: the RELP receiver's port stays the slice's (B6;
#237, where #229's integration job 122366429930 lost 127.0.0.1:38793 to
another process between free_port and the receiver's bind, with seven
slices started side by side).

Evidence class: desk (the harness's own helper, on this host's loopback).
"""
import os
import socket
import sys

import pytest

import harness

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Windows releases the port at once (see reserve_port)")

# About three times the size of Linux's default ephemeral range, so a port
# that was not held would be handed out several times.
BINDS = 100_000


def ephemeral_hits(port, n=BINDS, stop_at_first=False):
    """How often n binds to port 0 are given port, bound as Go's net.Listen
    (which sets SO_REUSEADDR) and asyncio bind."""
    hits = 0
    for _ in range(n):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        hits += s.getsockname()[1] == port
        s.close()
        if hits and stop_at_first:
            break
    return hits


def test_a_held_port_is_not_handed_out():
    port, hold = harness.reserve_port()
    try:
        assert ephemeral_hits(port) == 0
    finally:
        hold.close()


def test_a_released_port_is_handed_out():
    # The control: without the holder, the same binds do reach the port, so
    # the test above can fail.
    # It binds until the port comes back (about once per half the range,
    # Linux's parity for bind), so it does not depend on luck within BINDS.
    port, hold = harness.reserve_port()
    hold.close()
    assert ephemeral_hits(port, n=20 * BINDS, stop_at_first=True) == 1


def test_the_receiver_binds_it_again_after_a_kill(tmp_path):
    port, hold = harness.reserve_port()
    try:
        for i in range(2):
            r = harness.Proc([sys.executable, harness.RECEIVER, "--port", str(port),
                              "--log", str(tmp_path / f"relp{i}.jsonl")])
            try:
                assert r.port == port
                socket.create_connection(("127.0.0.1", port), timeout=2).close()
            finally:
                r.kill()
        # Held, with nothing listening: refused, as when nothing is bound.
        with pytest.raises(ConnectionRefusedError):
            socket.create_connection(("127.0.0.1", port), timeout=2)
    finally:
        hold.close()

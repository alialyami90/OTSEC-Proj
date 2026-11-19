"""harness.reserve_port_with_udp: a port held for TCP and UDP (P4-D6-PORT1).

#751's integration-long job 135244642630: V-M1's fixture bound a UDP socket
to the SEL-751 simulator's port, the OS's TCP choice, and a UDP socket on
the runner already had that number (Errno 98), so every test of the module
errored. TCP and UDP ports are separate: a TCP choice holds nothing for UDP.

Evidence class: desk (the harness's own helpers, on this host's loopback).
"""
import errno
import socket

import pytest

import harness


def _udp(port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.bind(("127.0.0.1", port))
    except OSError:
        u.close()
        raise
    return u


def test_a_number_udp_already_has_is_given_up(monkeypatch):
    # The control: the first TCP choice's number is bound for UDP before
    # the helper binds it, as an agent's socket had the simulator's number
    # in #751. The pre-bind succeeds, so the TCP choice held nothing for
    # UDP, and a bind to that number, as V-M1's fixture made, fails.
    taken = []
    real = harness.reserve_port

    def first_taken():
        port, hold = real()
        if not taken:
            taken.append(_udp(port))
        return port, hold

    monkeypatch.setattr(harness, "reserve_port", first_taken)
    port, hold, udp = harness.reserve_port_with_udp()
    try:
        assert taken, "the control's pre-bind did not run"
        assert port != taken[0].getsockname()[1]
        assert udp.getsockname() == ("127.0.0.1", port)
    finally:
        udp.close()
        if hold:
            hold.close()
        for u in taken:
            u.close()


def test_the_port_is_held_for_udp_and_the_simulator_listens_on_it(tmp_path):
    port, hold, udp = harness.reserve_port_with_udp()
    try:
        with pytest.raises(OSError) as e:
            _udp(port).close()
        assert e.value.errno == errno.EADDRINUSE
        # The simulator binds the port with the TCP holder in place, as in
        # Slice.start(sim_port=port).
        sim = harness.start_simulator(str(tmp_path / "sim.jsonl"), "port1-test-pw", extra=("--port", str(port)))
        try:
            assert sim.port == port
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
        finally:
            sim.kill()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
            tx.sendto(b"to the SEL-751", ("127.0.0.1", port))
        udp.settimeout(2)
        assert udp.recvfrom(64)[0] == b"to the SEL-751"
    finally:
        udp.close()
        if hold:
            hold.close()

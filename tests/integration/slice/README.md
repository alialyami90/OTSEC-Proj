# Slice suite (A6, P2-A6)

The end-to-end test of the Phase 2 slice: the recording simulator as a
SEL-751, then the collector, the node store, the forwarder, and an upstream
RELP collector. Each runs as a separate process (D2-3). Evidence class:
`simulated`. Nothing here is hardware evidence (risk 3).

| File | What it is |
| --- | --- |
| `harness.py` | Starts processes that print a JSON `ready` line with their port (`--port 0`). Makes throwaway TLS material with the `openssl` command line. |
| `relp_receiver.py` | The upstream collector for the Windows leg, where rsyslog does not run. RELP over TLS. It accepts only a client certificate that chains to the CA and carries the permitted peer name (`--permitted-peer`: SAN dNSNames, or the CN when there is no SAN; there is no CA-only mode, D2-9). It acknowledges a frame only after fsyncing it, and enforces C6's session rules: open first and once, `commands=syslog` offered, TXNRs from 1 and strictly increasing, no leading zeros, at most 65535 octets. It can drop, reject or `serverclose` the Nth frame (V-S6). Standard library only, and no code shared with the forwarder. |
| `relp_client.py` | A minimal RELP sender used only to test the receiver itself. |
| `test_relp_receiver.py` | The receiver does what the forwarder tests rely on: offers, durable acknowledgement, a pipelined window, `close`, the frame grammar and session rules, fault injection at exactly the Nth frame, mutual TLS on both name paths, and the V-S6 refusals: no certificate, a self-signed one with the permitted name, a CA-signed one for another name, plus a stranger and a SAN that names another node. |
| `test_rsyslog_leg.py` | The Linux leg's collector (rsyslog, imrelp, `tls.authmode="name"`, Direct queue, `sync="on"`) delivers with a durable acknowledgement and makes the same V-S6 refusals. It also records a finding: librelp 1.11.0 accepts a CA-signed certificate whose CN is the permitted peer even when its SAN names another node. |
| `reconcile.py`, `test_reconcile.py` | The 1:1 reconciliation oracle: every SER row the simulator printed against the C6 messages a receiver stored (timestamps, order, no duplicate, no loss, `evc="simulated"`), with mutation tests showing each check fails on a broken input. |
| `conftest.py` | `need()`: a check that cannot run skips, or fails when `OTSEC_SLICE_REQUIRED=1`. |

The tests that drive the product binaries join as each component merges.

## Requirements

- Python 3.12 or later, with `pytest` and `asyncssh==2.24.1` (the simulator's SSH transport).
- `openssl` on `PATH` for the TLS tests. Git for Windows ships one.
- Go, to build the binaries, once they exist.
- The Linux leg also needs `rsyslog` with `imrelp` and TLS support (`rsyslog`, `rsyslog-relp`, and `rsyslog-openssl` or `rsyslog-gnutls`).

## Run

```
python -m pytest -q tests/integration/slice
OTSEC_SLICE_REQUIRED=1 python -m pytest -q tests/integration/slice   # integration job and exit-gate runs
```

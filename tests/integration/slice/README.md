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
| `test_slice_e2e.py`, `slicehelper/` | **The slice end to end on the real binaries.** The simulator as the SEL-751, then `otsec-collector`, then `otsec node`, then the RELP receiver over mutual TLS. `slicehelper` writes the node configuration through A5's `nodeconfigtest` (D2-6) and the collector's `collector.json` with the register on main, signed by a key made for the run. It also creates the collector's stores an hour in the past, so the fresh-state floor has passed, and stands in for the administrator who installs the credential: sealed to the published install key, sent over the socket, with the secret taken from the environment. Two scheduled runs. The checks: every Figure 10.16 row arrives exactly once, byte for byte, with its time text (reconcile); the second read forwards nothing new; the recording check passes (read-only lines only, one session at a time, one password, QUI last); the password is in no file, log, forwarded message or process argument. About 140 s. Linux; the Windows leg is the PC run. |
| `conftest.py` | `need()`: a check that cannot run skips, or fails when `OTSEC_SLICE_REQUIRED=1`. |

`test_slice_e2e.py` drives the product binaries; the fault cases (V-S6, V-S9, V-S12) join it next.

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

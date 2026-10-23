# A5 Phase 0 experiments

Throwaway investigation code for task P0-A5. Not production code, not a toolchain commitment (the toolchain ADR decides that). Findings and their interpretation are in [docs/phase0/A5-platform-feasibility.md](../../../docs/phase0/A5-platform-feasibility.md).

Everything here ran in a cloud container against local files and loopback sockets only. Nothing touched a device, a production network, or a credential. Every result is evidence class `simulated`.

## Reproduce

On Windows, `run.ps1` runs the same experiments and writes `results/windows-*.txt` (full-disk cases need an elevated prompt; see the script header). The `a5-windows-experiments` workflow runs it on a GitHub-hosted Windows runner.

```sh
sh platform/experiments/phase0/run.sh                  # all experiments, writes results/*.txt
ITERATIONS=20 sh platform/experiments/phase0/run.sh   # quicker crash run
```

Needs Go 1.24 or later on the path; `go.mod` requires 1.26 (the SQLite driver needs it), which Go fetches automatically unless `GOTOOLCHAIN=local`. The full-filesystem case mounts a 4 MiB tmpfs and needs root; without root it is skipped and the output says so. A full run takes about eight minutes, most of it the crash test.

## Experiments

| ID | Command | Question | Result file |
| --- | --- | --- | --- |
| E-A5-1 | `p0 crash-durability` | Does SQLite in WAL mode lose acknowledged events, leave gaps, or corrupt when the writer is SIGKILLed at a random point? | [results/crash-durability.txt](results/crash-durability.txt) |
| E-A5-2 | `p0 throughput` | What does `synchronous=FULL` and per-event commit cost against `NORMAL` and batching? | [results/throughput.txt](results/throughput.txt) |
| E-A5-3 | `p0 storage-limit` | What happens at an application quota and at a real full filesystem, can the store recover, and does recovery at startup survive repeated exhaustion? | [results/storage-limit.txt](results/storage-limit.txt) |
| E-A5-4 | `p0 syslog-loss` | How many events does a plain TCP syslog forwarder lose, without any error, when the collector dies? What does an application-level ack change? | [results/syslog-loss.txt](results/syslog-loss.txt) |
| E-A5-6 | `p0 write-amplification` | How many bytes does the store hand to the OS per stored event, by WAL settings and commit size (SSD endurance)? | [results/write-amplification.txt](results/write-amplification.txt) |
| E-A5-5 | `run.sh` cross-build step | Does the candidate stack produce static binaries for site hardware targets with no C toolchain? | [results/cross-build.txt](results/cross-build.txt) |

## What these experiments do not show

- **Power loss.** SIGKILL leaves the OS page cache intact, so E-A5-1 says nothing about a power cut or kernel panic. That needs a VM with forced power-off or a fault-injecting filesystem, on the actual site storage hardware. Handed to A6.
- **Real disks.** Throughput and fsync cost depend on the storage device. Only the ratios between modes travel.
- **Real collectors.** E-A5-4 uses a minimal receiver of my own, not rsyslog, syslog-ng, or a SIEM. A6's independent E-01 reached the same conclusion over TLS.
- **Durability at `synchronous=NORMAL`.** E-A5-1 passes in `NORMAL` mode only because SIGKILL leaves the page cache intact; A6's strace (E-02) shows acknowledgements there are not preceded by an fsync. Only the `FULL` runs count.
- **ext4 reserved blocks.** The full-filesystem cases use tmpfs and run as root. On ext4 a root process can use the reserved blocks, so production must run the store as non-root on a dedicated filesystem.
- **Multi-writer contention.** The writer is a single connection, which is the design proposed, not a property tested under contention.

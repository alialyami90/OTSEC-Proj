"""The timed replayer, and R6.4's latency measure (D6, P4-4-R1; plan section 5).

R6.4's latency is measured only under a timed replay onto a live interface:
the alert's time minus the triggering frame's send time, on one host clock.
The replayer sends each frame of a capture at its recorded offset and keeps,
for each frame, the offset it was due at and the time it was sent, on the
monotonic clock and on the wall clock. The wall clock is the one an alert's
time is compared with, and a report names it.

The replayer's timing is checked two ways, so a broken replayer can't pass:

- against its own clock: every frame was sent at or after its due offset,
  and no more than a tolerance late (check_log);
- against the receiver's clock: the gaps between arrivals at the other end
  of the pair equal the gaps in the capture, within the tolerance
  (check_arrivals). This does not read the replayer's own record of when it
  sent, so a replayer that records one schedule and sends another fails.

Stdlib only. Used by no product code. replay() needs only an object with
send(), so the scheduling is tested on any machine with a fake clock.
"""

import hashlib
import time


def schedule(frames, speed=1.0, max_gap_ns=None):
    """Each frame's due offset from the start of the replay, in ns. `speed`
    divides every gap. `max_gap_ns` shortens a longer gap to that length,
    for a capture with idle stretches; both are in the log's header, because
    a latency measured under them is not one measured at the recorded pace."""
    due, at, prev = [], 0, frames[0].ns if frames else 0
    for f in frames:
        gap = int((f.ns - prev) / speed)
        if max_gap_ns is not None:
            gap = min(gap, max_gap_ns)
        at, prev = at + gap, f.ns
        due.append(at)
    return due


def replay(sock, frames, speed=1.0, max_gap_ns=None, mono=time.monotonic_ns, wall=time.time_ns, sleep=time.sleep):
    """Send every frame at its due offset. Returns the log: one row per
    frame with its index (1-based, the capture's frame number), SHA-256,
    due offset, and the monotonic and wall times read just before the send."""
    due = schedule(frames, speed, max_gap_ns)
    log, t0 = [], mono()
    for i, (f, d) in enumerate(zip(frames, due), 1):
        wait = t0 + d - mono()
        if wait > 0:
            sleep(wait / 1e9)
        sent_mono, sent_wall = mono(), wall()
        sock.send(f.data)
        log.append({"n": i, "sha256": hashlib.sha256(f.data).hexdigest(), "due_ns": d,
                    "sent_ns": sent_mono - t0, "sent_wall_ns": sent_wall})
    return log


def check_log(log, tolerance_ns):
    """Problems in the replayer's own record: a frame sent before it was
    due, or more than the tolerance after."""
    bad = []
    for r in log:
        late = r["sent_ns"] - r["due_ns"]
        if late < 0 or late > tolerance_ns:
            bad.append(f"frame {r['n']}: sent {late} ns from its due offset, outside [0, {tolerance_ns}]")
    return bad


def check_arrivals(frames, arrivals, tolerance_ns, speed=1.0, max_gap_ns=None):
    """Problems seen from the receiving end. `arrivals` is (receipt time in
    ns, frame bytes) in the order received. Every frame must arrive once, in
    order and unchanged, and each gap between arrivals must equal the gap
    the capture asks for, within the tolerance."""
    bad = []
    if [a[1] for a in arrivals] != [f.data for f in frames]:
        bad.append(f"{len(arrivals)} frames arrived for {len(frames)} sent, or their bytes or order differ")
        return bad
    due = schedule(frames, speed, max_gap_ns)
    for i in range(1, len(frames)):
        want, got = due[i] - due[i - 1], arrivals[i][0] - arrivals[i - 1][0]
        if abs(got - want) > tolerance_ns:
            bad.append(f"frames {i} to {i + 1}: {got} ns apart on arrival, the capture says {want}")
    return bad


def latency_ns(log, frame_sha256, alert_wall_ns):
    """R6.4: the alert's time minus the triggering frame's send time, both
    on the host's wall clock. The triggering frame is found by its hash,
    never by its number in the product's own ring (plan section 1). Where
    the same bytes were sent more than once, it is the last send that is
    not after the alert."""
    sends = [r["sent_wall_ns"] for r in log if r["sha256"] == frame_sha256 and r["sent_wall_ns"] <= alert_wall_ns]
    if not sends:
        raise LookupError(f"no frame {frame_sha256} was sent before the alert")
    return alert_wall_ns - max(sends)


def summary(latencies_ns):
    """The median, the p90 and the maximum, as R6.4's report gives them per
    rule. The p90 is the nearest-rank one."""
    v = sorted(latencies_ns)
    if not v:
        raise ValueError("no latency to summarise")
    return {"count": len(v), "median_ns": v[(len(v) - 1) // 2], "p90_ns": v[-(-len(v) * 9 // 10) - 1], "max_ns": v[-1]}

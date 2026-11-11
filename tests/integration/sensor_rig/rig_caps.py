"""Does a running process hold a capability? (D6, P4-4-R1, deliverable 5)

Item 4's gate asks that the sensor hold no capability once its capture
socket is open (CAP_NET_RAW dropped). The check reads the kernel's own
record of the process, /proc/<pid>/status, while the process is capturing:

- its permitted, effective, inheritable and ambient sets are all empty, so
  it holds nothing now; and
- it can't get one back by running a program: NoNewPrivs is 1, or its
  bounding set is empty.

A process that fails either line is reported with the sets that hold a
capability. Linux only; reading another user's process needs root.
"""

CAP_NET_ADMIN, CAP_NET_RAW = 12, 13
SETS = ("CapInh", "CapPrm", "CapEff", "CapAmb")


def status(pid):
    out = {}
    with open(f"/proc/{pid}/status", encoding="ascii") as f:
        for ln in f:
            k, _, v = ln.partition(":")
            out[k] = v.strip()
    return out


def problems(st):
    """Why the process with this status does not meet the gate's line, or
    [] if it does. `st` is status()'s result, so the rule is testable on
    any machine."""
    bad = [f"{name} is {st[name]}: the process holds a capability" + (
        " (CAP_NET_RAW among them)" if int(st[name], 16) >> CAP_NET_RAW & 1 else "")
        for name in SETS if int(st[name], 16)]
    if st.get("NoNewPrivs") != "1" and int(st["CapBnd"], 16):
        bad.append(f"NoNewPrivs is {st.get('NoNewPrivs')} and CapBnd is {st['CapBnd']}: "
                   "a program it runs could give a capability back")
    return bad

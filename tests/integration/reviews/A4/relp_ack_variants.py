"""A6 re-run and variants of A4's E-A4-03 (RELP ack vs stored), PR #4. B-03.

Runs A4's relp_ack_test.trial() unchanged for its two configurations, then
with receiver configurations A4 did not try:

  direct-omfile          Direct queues, stock omfile output (the usual way a
                         receiver stores messages), default buffering
  direct-omfile-flush    the same with flushOnTXEnd="on" and asyncWriting off
  direct-confirm-early   A4's direct-queues case, killed after 300 messages
  direct-confirm-late    A4's direct-queues case, killed after 2900 messages

A4's client and ack parser are reused as the instrument; the pass condition
(acked_not_stored == 0) is A6's, from V-S6. A SIGKILL leaves the page cache
intact, so a pass here shows process-crash safety only, not power-loss
durability (same limit as E-02).

Run: python3 -I tests/integration/reviews/A4/relp_ack_variants.py <relp-ack dir> <work dir>
Classification: simulated.
"""

import importlib.util
import json
import os
import subprocess
import sys

OMFILE_CONF = """
global(workDirectory="{work}")
module(load="imrelp")
module(load="builtin:omfile"{modopts})
{mainq}
template(name="m" type="string" string="%msg%\\n")
ruleset(name="r"{rsq}) {{ action(type="omfile" file="{out}" template="m"{aq}) }}
input(type="imrelp" port="{port}" ruleset="r")
"""


def load(path):
    spec = importlib.util.spec_from_file_location("relp_ack_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(a4_dir, work):
    mod = load(os.path.join(a4_dir, "relp_ack_test.py"))
    omprog_conf = mod.CONF
    direct = ('main_queue(queue.type="Direct")', ' queue.type="Direct"')
    rows = []
    for rep in range(3):
        mod.CONF, mod.KILL_AFTER = omprog_conf, 1500
        rows.append({"rep": rep, **mod.trial(work, "default-queues", "", "", "")})
        rows.append({"rep": rep, **mod.trial(work, "direct-queues", *direct,
                                              ' queue.type="Direct" confirmMessages="on"')})
        for kill in (300, 2900):
            mod.KILL_AFTER = kill
            r = mod.trial(work, "direct-queues", *direct, ' queue.type="Direct" confirmMessages="on"')
            rows.append({"rep": rep, **r, "trial": f"direct-confirm-kill-after-{kill}"})
        mod.KILL_AFTER = 1500
        mod.CONF = OMFILE_CONF.replace("{modopts}", "")
        rows.append({"rep": rep, **mod.trial(work, "direct-omfile", *direct, ' queue.type="Direct"')})
        mod.CONF = OMFILE_CONF.replace("{modopts}", "")
        rows.append({"rep": rep, **mod.trial(work, "direct-omfile-flush", *direct,
                                              ' queue.type="Direct" flushOnTXEnd="on" asyncWriting="off"')})
    for r in rows:
        r["pass"] = r["acked_not_stored"] == 0 and r["parser_violations"] == 0
    ver = subprocess.run(["rsyslogd", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    print(json.dumps({"rsyslog": ver.split(" compiled")[0], "messages": mod.N, "window": mod.WINDOW,
                      "classification": "simulated", "rows": rows}, indent=2))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

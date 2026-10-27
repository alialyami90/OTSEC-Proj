"""Positive control for flush_latency.py: one write and os.fsync (the C
runtime's _commit, which calls FlushFileBuffers) on <dir>/control-<name>.bin.
Prints {"name": ..., "pid": ...} for run.json. Run: python -I control.py <dir> <begin|end>
"""

import json
import os
import sys

d, name = sys.argv[1], sys.argv[2]
fd = os.open(os.path.join(d, f"control-{name}.bin"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0))
try:
    os.write(fd, b"control")
    os.fsync(fd)
finally:
    os.close(fd)
print(json.dumps({"name": f"control-{name}", "pid": os.getpid()}))

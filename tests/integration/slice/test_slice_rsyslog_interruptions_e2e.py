"""V-S6 on the ground truth it names: randomized interruptions of the
slice with a stock rsyslog as the upstream collector (D6, P4-D6-H5; R4.7,
R8.6).

The run is test_slice_interruptions_e2e.py's own (its interrupted()), with
one thing changed: the receiver that the seeded scheduler kills and starts
again is rsyslogd with imrelp over mutual TLS (rsyslogrun.py), not
relp_receiver.py. So GT-RX here is what V-S6 names: the file a receiver
that is not project code wrote. The node, the simulator and the collector
are killed as before, and the simulator's buffer grows and renumbers every
row at every read.

The first two interruptions are set, so that no schedule leaves them out:
rsyslog killed mid-burst, which is V-S6's kill of the collector right
after it acknowledges, and then the node killed mid-burst. Their down
times are the seed's, and the other interruptions are the scheduler's own
seeded choices.

The checks are that file's as well, imported and run on this module's run,
and each reads rsyslog's file:
  - every row the buffer ever held is in the file under exactly one event
    ID, with its own bytes;
  - an event ID that is there more than once carries the same bytes;
  - for every stream, the file holds event 1 to the node's confirmed
    cursor with no gap: every event rsyslog acknowledged, it wrote, across
    its own kills;
  - the events written again after each break are at most the RELP window,
    and none without a break;
  - the recording check, and the password nowhere.
And rsyslog's own parser read every message as RFC 5424.

OTSEC_SLICE_INTERRUPTIONS and OTSEC_SLICE_SEED as in that file.

Evidence class: simulated. Linux only: rsyslog does not run on Windows.
"""

import os

import pytest

import harness
import test_slice_interruptions_e2e as vs6
from conftest import need
from rsyslogrun import (  # noqa: F401  the checks every rsyslog leg makes
    RsyslogSlice, test_rsyslog_reads_every_message_as_rfc5424, test_the_upstream_is_a_stock_rsyslog)
from test_slice_interruptions_e2e import (  # noqa: F401  V-S6's checks, on rsyslog's file
    test_every_confirmed_event_is_in_gt_rx, test_every_row_arrives_under_one_event_id, test_interruptions_happened,
    test_only_read_only_lines_reached_any_device, test_the_password_is_nowhere, test_the_unconfirmed_window)

FIRST = (("receiver", True), ("node", True))


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(os.name != "nt", "rsyslog does not run on Windows")
    need(harness.rsyslogd() and harness.imrelp(), "rsyslogd with imrelp not installed (rsyslog and rsyslog-relp)")
    yield from vs6.interrupted(tmp_path_factory, RsyslogSlice, FIRST)


def test_rsyslog_and_the_node_were_killed_mid_burst(run, capsys):
    """The kills this leg is for happened as set: neither was skipped, and
    each landed while a burst was in flight."""
    with capsys.disabled():
        print(f"\nseed {run.seed}: " + ", ".join(f"{k} {w}" for _, k, w in run.interruptions)
              + f"; {run.receiver_lines()} records in rsyslog's file, {run.torn} torn")
    done = [(kind, what.startswith("mid-burst")) for _, kind, what in run.interruptions[:len(FIRST)]]
    assert done == list(FIRST)[:vs6.COUNT], run.interruptions

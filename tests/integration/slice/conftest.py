import pytest

import harness

# The closing legs (P4-D6-H5) run where a job names the file: each has its
# own integration-long entry in ci.yml. A run of this directory, which is
# what the integration job makes, leaves them out, so that job keeps the
# tests and the time it had. pytest always collects a file that is named on
# its command line.
collect_ignore = [
    "test_slice_rsyslog_e2e.py",
    "test_slice_rsyslog_interruptions_e2e.py",
    "test_slice_rsyslog_store_full_e2e.py",
    "test_slice_framing_e2e.py",
]


def need(cond, reason):
    """Skip a check that cannot run here, or fail it when the run must be
    complete (OTSEC_SLICE_REQUIRED=1): a skipped check is not a pass."""
    if cond:
        return
    if harness.REQUIRED:
        pytest.fail("required but cannot run: " + reason)
    pytest.skip(reason)


@pytest.fixture(scope="session")
def tls(tmp_path_factory):
    need(harness.TLSMaterial.openssl(), "openssl not on PATH (needed to make test certificates)")
    return harness.TLSMaterial(str(tmp_path_factory.mktemp("tls"))).make()


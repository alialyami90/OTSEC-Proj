import os

import pytest

import harness


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


# The long end-to-end files (7 to 9 minutes each). Together with the rest
# they pass the 20-minute limit of ci.yml's integration job, so on GitHub
# Actions they run only in A6's a6-slice-long workflow, one job per file
# (OTSEC_SLICE_LONG=1). They are deselected there, not skipped, so required
# mode still fails any check that cannot run. Locally every file runs.
LONG = ("test_slice_interruptions_e2e.py", "test_slice_buffer_e2e.py", "test_slice_store_full_e2e.py")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("OTSEC_SLICE_LONG") == "1":
        return
    drop = [i for i in items if i.path.name in LONG]
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = [i for i in items if i.path.name not in LONG]

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

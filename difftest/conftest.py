import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import harness  # noqa: E402

# Pin the port under test to a git revision before anything imports it. Without this the baseline
# moves whenever somebody saves a file in src/.
_REV = os.environ.get("DIFFTEST_PORT_REV")
if _REV and not os.environ.get("DIFFTEST_PORT_SRC"):
    os.environ["DIFFTEST_PORT_SRC"] = harness.materialize_rev(_REV)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "mutation: differential over mutated proof bytes, not corpus cases"
    )


@pytest.fixture(scope="session")
def oracle():
    """One long-lived dnssec-prover 0.6.10 process, shared by the whole session."""
    try:
        o = harness.RustOracle()
    except harness.OracleMissing as exc:
        pytest.fail(str(exc), pytrace=False)
    yield o
    o.close()

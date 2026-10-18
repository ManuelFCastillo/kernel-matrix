"""The install, judged by qualify.py's own four checks, so a sensor run and a
qualification cell can never disagree about whether the package installed."""

import pytest


@pytest.mark.parametrize("check", ["pkg_installed", "driver_loaded", "service_active", "event_detected"])
def test_install(install, measure, check):
    if install["status"] == "unsupported":
        pytest.skip(install["reason"])
    probe = install["probe"]
    measure("driver", probe.get("driver"))
    measure("falco_version", probe.get("falco_version"))
    c = next((c for c in install["checks"] if c["name"] == check), None)
    assert c is not None, f"probe returned no qualification data: {install['reason']}"
    assert c["passed"], f"{check}: {c['observed']} ({install['reason']})"

"""
Stability over time. A qualification VM lives about two minutes; a sensor
lives for months. This keeps one running under light steady load for
soak.minutes and checks, once per interval, that it is the same process,
still detecting, and not growing.

The series is written to soak.json next to the junit file, so a slope that
passed the gate is still visible when it starts to creep.
"""

from __future__ import annotations

import json
import time

import pytest

from guest import growth_mb

pytestmark = pytest.mark.slow


def test_soak(km, guest, sensor, measure):
    cfg = km["settings"]["soak"]
    gates = cfg["gates"]
    if cfg["minutes"] <= 0:
        pytest.skip("soak.minutes is 0")
    pid0, restarts0 = sensor.pid(), sensor.nrestarts()
    sleep = 1 / cfg["background_exec_per_s"]
    guest.sh("systemctl stop km-soak-bg 2>/dev/null; systemctl reset-failed km-soak-bg 2>/dev/null; "
             f"systemd-run --unit km-soak-bg bash -c 'while :; do /bin/true; sleep {sleep}; done'",
             check=True)
    series = []
    try:
        end = time.time() + cfg["minutes"] * 60
        while True:
            t = time.time()
            alert = sensor.marker(timeout=30)
            series.append({"t": round(t), "pid": sensor.pid(), "restarts": sensor.nrestarts(),
                           "rss_kb": sensor.rss_kb(), "detected": alert is not None})
            if t >= end:
                break
            time.sleep(max(0.0, cfg["interval_s"] - (time.time() - t)))
    finally:
        guest.sh("systemctl stop km-soak-bg")
        (km["results"] / "soak.json").write_text(json.dumps(series, indent=2))

    rss = [s["rss_kb"] for s in series if s["rss_kb"]]
    missed = sum(1 for s in series if not s["detected"])
    restarts = series[-1]["restarts"] - restarts0
    grew = growth_mb(rss)
    measure("soak_minutes", cfg["minutes"])
    measure("soak_samples", len(series))
    measure("soak_markers_missed", missed)
    measure("soak_restarts", restarts)
    measure("soak_rss_growth_mb", grew)
    measure("soak_rss_first_mb", round(rss[0] / 1024, 1) if rss else None)
    measure("soak_rss_last_mb", round(rss[-1] / 1024, 1) if rss else None)

    pids = {s["pid"] for s in series}
    assert pids == {pid0}, f"Falco's PID changed during the soak: {pid0} -> {sorted(pids)}"
    assert restarts <= gates["restarts_max"], f"systemd restarted Falco {restarts} time(s)"
    assert missed <= gates["marker_loss_max"], f"{missed} of {len(series)} markers missed"
    assert grew <= gates["rss_growth_mb_max"], f"RSS grew {grew} MB over {cfg['minutes']} min"

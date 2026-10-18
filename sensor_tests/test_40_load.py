"""
Cost and correctness under load.

The probe records idle RSS and CPU once and gates on nothing. Here:

  test_idle_cost     idle CPU and RSS against sensor.yaml gates
  test_under_load    a syscall storm (exec + open loops) for duration_s,
                     with a marker event every marker_interval_s fired from
                     inside the storm. Gates: every marker arrives, kernel
                     drops stay under drop_ratio_max, Falco's CPU and peak
                     RSS stay under their gates.

Drops come from Falco's own metrics snapshots (cumulative kernel event and
drop counters), taken just before and just after the storm, plus any
"syscall event drop" alerts Falco raised itself.
"""

from __future__ import annotations

import time

import pytest

from guest import COV_DIR, drop_ratio, metric, token

pytestmark = pytest.mark.slow

LOAD_SH = r"""#!/bin/bash
# load.sh DURATION WORKERS INTERVAL PREFIX
end=$(( $(date +%s) + $1 ))
for w in $(seq 1 "$2"); do
    ( while [ "$(date +%s)" -lt "$end" ]; do
          for i in 1 2 3 4 5 6 7 8 9 10; do /bin/true; cat /etc/hostname > /dev/null; done
      done ) &
done
n=0
while [ "$(date +%s)" -lt "$end" ]; do
    n=$((n + 1))
    echo x > "$4-$n" && cat "$4-$n" > /dev/null
    echo "$n" > "$4.count"
    sleep "$3"
done
wait
"""


def test_idle_cost(km, sensor, measure):
    g = km["settings"]["idle"]
    time.sleep(30)                    # the outputs tests just restarted Falco
    cpu = sensor.cpu_percent(g["sample_s"])
    rss_mb = round(sensor.rss_kb() / 1024, 1)
    measure("idle_cpu_percent", cpu)
    measure("idle_rss_mb", rss_mb)
    assert cpu <= g["gates"]["cpu_percent_max"], f"idle CPU {cpu}% > {g['gates']['cpu_percent_max']}%"
    assert rss_mb <= g["gates"]["rss_mb_max"], f"idle RSS {rss_mb} MB > {g['gates']['rss_mb_max']} MB"


def test_under_load(km, guest, sensor, measure):
    cfg = km["settings"]["load"]
    gates = cfg["gates"]
    prefix = f"{COV_DIR}/{token('load')}"
    guest.write("/opt/km/load.sh", LOAD_SH, mode="0755")
    pid = sensor.pid()

    t0 = sensor.guest_now()
    before = sensor.latest_metrics(newer_than=t0 - 6, timeout=20)
    off = sensor.offset()
    j0 = int(guest.out(f"awk '{{print $14+$15}}' /proc/{pid}/stat"))
    hz = int(guest.out("getconf CLK_TCK"))
    guest.sh("systemctl reset-failed km-load 2>/dev/null; "
             f"systemd-run --unit km-load /opt/km/load.sh {cfg['duration_s']} {cfg['workers']} "
             f"{cfg['marker_interval_s']} {prefix}", check=True)

    rss_peak = 0
    start = time.time()
    while time.time() - start < cfg["duration_s"] + 60:
        rss_peak = max(rss_peak, sensor.rss_kb())
        if guest.sh("systemctl is-active -q km-load").returncode != 0:
            break
        time.sleep(3)
    j1 = int(guest.out(f"awk '{{print $14+$15}}' /proc/{pid}/stat"))
    cpu = round((j1 - j0) / hz / (time.time() - start) * 100, 1)
    t1 = sensor.guest_now()

    time.sleep(10)                     # let the queue drain before counting
    after = sensor.latest_metrics(newer_than=t1, timeout=30)
    sent = int(guest.out(f"cat {prefix}.count 2>/dev/null || echo 0"))
    alerts = sensor.alerts_since(off)
    got = {a["output_fields"].get("fd.name") for a in alerts
           if a.get("rule") == "KM cov open read"
           and str(a.get("output_fields", {}).get("fd.name", "")).startswith(prefix + "-")}
    drop_alerts = sum(1 for a in alerts if "drop" in (a.get("rule") or "").lower())
    ratio, events, drops = drop_ratio(before or {}, after or {})

    measure("load_markers_sent", sent)
    measure("load_markers_received", len(got))
    measure("load_kernel_events", events)
    measure("load_kernel_drops", drops)
    measure("load_drop_ratio", ratio)
    measure("load_drop_alerts", drop_alerts)
    measure("load_cpu_percent", cpu)
    measure("load_rss_peak_mb", round(rss_peak / 1024, 1))
    measure("load_alerts_total", len(alerts))

    assert sensor.pid() == pid, "Falco restarted during the load test"
    assert sent > 0, "load generator sent no markers"
    lost = sent - len(got)
    assert lost <= gates["marker_loss_max"], f"{lost} of {sent} marker events never alerted"
    assert ratio is not None, (f"no drop counters in the metrics snapshots; keys seen: "
                               f"{sorted((after or {}).get('output_fields', after or {}))[:40]}")
    assert events and events > 0, "metrics show no kernel events during the storm"
    assert ratio <= gates["drop_ratio_max"], f"dropped {drops} of {events} events ({ratio:.2%})"
    assert cpu <= gates["cpu_percent_max"], f"CPU under load {cpu}% > {gates['cpu_percent_max']}%"
    assert rss_peak / 1024 <= gates["rss_mb_max"], f"peak RSS {rss_peak / 1024:.0f} MB > {gates['rss_mb_max']} MB"


def test_metrics_report_resources(sensor, measure):
    """Falco's own resource metrics agree with /proc to within a factor of two:
    a fleet dashboard built on them would otherwise lie."""
    snap = sensor.latest_metrics(timeout=20)
    assert snap is not None, "no metrics snapshot written"
    rss_mb = metric(snap, "falco.memory_rss_mb", "falco.memory_rss")
    measure("metrics_memory_rss_mb", rss_mb)
    assert rss_mb is not None, f"no falco.memory_rss_mb in snapshot: {sorted(snap.get('output_fields', snap))[:40]}"
    proc_mb = sensor.rss_kb() / 1024
    assert proc_mb / 2 <= float(rss_mb) <= proc_mb * 2, f"metrics say {rss_mb} MB, /proc says {proc_mb:.0f} MB"

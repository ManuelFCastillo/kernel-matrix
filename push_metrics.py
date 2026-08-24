#!/usr/bin/env python3
"""
push_metrics.py -- publish a matrix run's results to a Prometheus Pushgateway.

WHY PUSH RATHER THAN EXPOSE
---------------------------
Prometheus scrapes. That is the right model for services that stay up, and
useless for batch jobs -- by the time the scraper arrives, the matrix run
has exited and taken its numbers with it.

Pushgateway exists for exactly this: the job pushes on completion, the
gateway holds the values, Prometheus scrapes the gateway. Metrics then
outlive the run, so Grafana can trend across builds rather than showing a
single snapshot.

WHAT GETS PUSHED
----------------
One label set per distro, so every series is queryable by distro, kernel and
driver:

    km_falco_started{distro,kernel,driver}       1 or 0
    km_falco_detected{distro,kernel,driver}      1 or 0
    km_falco_rss_bytes{distro,kernel,driver}     idle memory
    km_falco_cpu_percent{distro,kernel,driver}   idle cpu
    km_falco_start_seconds{...}                  time to become active
    km_falco_detect_seconds{...}                 time to first alert
    km_falco_install_seconds{...}                package install cost
    km_checks_passed{distro} / km_checks_total{distro}
    km_vm_booted{distro}                         did the VM come up at all
    km_run_timestamp                             when this run happened

USAGE
    ./push_metrics.py                                  # default localhost:9092
    ./push_metrics.py --gateway http://hardac2:9092
    ./push_metrics.py --dry-run                        # print, do not send
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Prometheus exposition format needs label values escaped: backslash, quote
# and newline. Getting this wrong produces a 400 from the gateway with a
# famously unhelpful message.
def esc(value: str) -> str:
    return (str(value).replace("\\", "\\\\")
                      .replace('"', '\\"')
                      .replace("\n", " "))


def build_payload(data: dict) -> str:
    lines: list[str] = []

    def metric(name: str, help_text: str, mtype: str = "gauge"):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")

    def sample(name: str, labels: dict, value) -> None:
        label_str = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
        lines.append(f"{name}{{{label_str}}} {value}")

    results = data.get("results", [])

    metric("km_vm_booted", "Whether the VM booted and became reachable")
    for r in results:
        sample("km_vm_booted", {"distro": r["distro"]}, 0 if r.get("error") else 1)

    metric("km_checks_passed", "Declarative checks that passed")
    metric("km_checks_total", "Declarative checks attempted")
    for r in results:
        checks = r.get("checks", [])
        passed = sum(1 for c in checks if c["passed"] and not c["skipped"])
        sample("km_checks_passed", {"distro": r["distro"]}, passed)
        sample("km_checks_total", {"distro": r["distro"]}, len(checks))

    # ---- falco characterisation ----
    falco_metrics = [
        ("km_falco_started", "Falco reached active state", lambda f: int(bool(f.get("started")))),
        ("km_falco_detected", "Falco fired on the synthetic event", lambda f: int(bool(f.get("detected")))),
        ("km_falco_rss_bytes", "Falco resident memory at idle", lambda f: int(f.get("rss_kb") or 0) * 1024),
        ("km_falco_cpu_percent", "Falco CPU percent at idle", lambda f: float(f.get("cpu_percent") or 0)),
        ("km_falco_start_seconds", "Seconds from start to active", lambda f: int(f.get("start_seconds") or 0)),
        ("km_falco_detect_seconds", "Seconds from trigger to alert", lambda f: int(f.get("detect_seconds") or 0)),
        ("km_falco_install_seconds", "Seconds to install the package", lambda f: int(f.get("install_seconds") or 0)),
    ]

    for name, help_text, extract in falco_metrics:
        metric(name, help_text)
        for r in results:
            falco = r.get("falco")
            if not falco or falco.get("error") and not falco.get("started"):
                # still emit a zero so the series exists and gaps are visible
                falco = falco or {}
            labels = {
                "distro": r["distro"],
                "kernel": r.get("kernel") or "unknown",
                "driver": falco.get("driver") or "none",
            }
            try:
                sample(name, labels, extract(falco))
            except (TypeError, ValueError):
                sample(name, labels, 0)

    metric("km_run_timestamp", "Unix time of this matrix run")
    lines.append(f"km_run_timestamp {int(time.time())}")

    # The exposition format REQUIRES a trailing newline. Omitting it is the
    # single most common cause of a silent 400 from the pushgateway.
    return "\n".join(lines) + "\n"


def push(gateway: str, payload: str, job: str = "kernel_matrix") -> None:
    url = f"{gateway.rstrip('/')}/metrics/job/{job}"
    req = urllib.request.Request(
        url, data=payload.encode(), method="PUT",
        headers={"Content-Type": "text/plain; version=0.0.4"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        if resp.status not in (200, 202):
            raise RuntimeError(f"pushgateway returned {resp.status}")
    print(f"pushed {len(payload.splitlines())} lines to {url}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=Path("results/results.json"))
    ap.add_argument("--gateway", default="http://localhost:9092")
    ap.add_argument("--job", default="kernel_matrix")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not args.results.exists():
        sys.exit(f"No results at {args.results}. Run provision.py first.")

    payload = build_payload(json.loads(args.results.read_text()))

    if args.dry_run:
        print(payload)
        return 0

    try:
        push(args.gateway, payload, args.job)
    except urllib.error.URLError as exc:
        # A missing gateway must not fail the build. Metrics are a nice-to-have
        # layered on top of the results, not the results themselves.
        print(f"WARNING: could not reach pushgateway at {args.gateway}: {exc}",
              file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())

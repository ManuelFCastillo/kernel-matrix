#!/usr/bin/env python3
"""
run.py -- the sensor suite over several cells, a few VMs at a time.

    ./sensor_tests/run.py --version 0.45.1-rc1                  # cells in sensor.yaml
    ./sensor_tests/run.py --version 0.45.1-rc1 --target ubuntu-24.04 --scenario fresh-kmod
    ./sensor_tests/run.py --version 0.45.1-rc1 --soak-minutes 60 --max-vms 2

Each cell is its own pytest process (one VM each), so a cell that hangs or
panics its guest cannot take the others with it. Like qualify.py, every
running VM on the host counts against --max-vms, including ones this script
did not start.

Writes, per cell, results/sensor/<version>/<cell>/{junit.xml,pytest.log,...}
and results/sensor/<version>/summary.json. Exit 0 when every cell passed,
1 when any test failed or errored, 2 on bad arguments.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import provision  # noqa: E402
import qualify  # noqa: E402
from provision import log  # noqa: E402


def junit_counts(path: Path) -> dict:
    if not path.exists():
        return {"tests": 0, "failures": 0, "errors": 1, "skipped": 0, "note": "no junit written"}
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    return {k: sum(int(s.get(k, 0)) for s in suites) for k in ("tests", "failures", "errors", "skipped")}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--version", required=True)
    p.add_argument("--target", action="append", help="matrix.yaml target; repeatable (default: sensor.yaml cells)")
    p.add_argument("--scenario", default="fresh-auto", help="with --target")
    p.add_argument("--max-vms", type=int, default=3)
    p.add_argument("--soak-minutes", type=float)
    p.add_argument("-k", dest="keyword", help="pytest -k expression, e.g. 'not soak'")
    args = p.parse_args()

    settings = yaml.safe_load((HERE / "sensor.yaml").read_text())
    cells = ([{"target": t, "scenario": args.scenario} for t in args.target] if args.target
             else settings["cells"])
    qual = qualify.load_qualification(ROOT / "qualification.yaml")
    distros = {d.name: d for d in provision.load_matrix(ROOT / "matrix.yaml")[0]}
    try:
        planned = [qualify.plan(qual, distros, [args.version], [c["target"]], [c["scenario"]])[0] for c in cells]
    except ValueError as exc:
        log(str(exc), "ERROR")
        return 2

    out_root = ROOT / "results" / "sensor" / args.version
    pending = list(planned)
    children: dict[int, tuple[subprocess.Popen, qualify.Cell, object]] = {}
    summary = {}
    while pending or children:
        for pid, (proc, cell, fh) in list(children.items()):
            if proc.poll() is None:
                continue
            fh.close()
            del children[pid]
            counts = junit_counts(out_root / cell.name / "junit.xml")
            summary[cell.name] = {"exit": proc.returncode, **counts}
            log(f"done {cell.name}: exit {proc.returncode} {counts}")
        while pending and qualify.free_slots(args.max_vms, children, qualify.running_domains()) > 0:
            cell = pending.pop(0)
            res = out_root / cell.name
            res.mkdir(parents=True, exist_ok=True)
            cmd = [sys.executable, "-m", "pytest", str(HERE), "-p", "no:cacheprovider", "-rfEs",
                   "--km-version", args.version, "--km-target", cell.distro.name,
                   "--km-scenario", cell.scenario.id, "--junitxml", str(res / "junit.xml"),
                   "-o", f"junit_suite_name=sensor.{cell.name}",
                   # xunit2 drops record_property, which carries every measurement
                   "-o", "junit_family=legacy"]
            if args.soak_minutes is not None:
                cmd += ["--km-soak-minutes", str(args.soak_minutes)]
            if args.keyword:
                cmd += ["-k", args.keyword]
            fh = (res / "pytest.log").open("w")
            proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=ROOT)
            children[proc.pid] = (proc, cell, fh)
            log(f"start {cell.name} (pid {proc.pid}, {len(pending)} queued)")
            time.sleep(20)              # let virt-install register the domain before recounting
        time.sleep(10)

    (out_root / "summary.json").write_text(json.dumps(summary, indent=2))
    log(f"{'cell':<44} {'tests':>5} {'fail':>5} {'err':>5} {'skip':>5}")
    for name, s in summary.items():
        log(f"{name:<44} {s['tests']:>5} {s['failures']:>5} {s['errors']:>5} {s['skipped']:>5}")
    return 1 if any(s["failures"] or s["errors"] or s["exit"] not in (0, 5) for s in summary.values()) else 0


if __name__ == "__main__":
    sys.exit(main())

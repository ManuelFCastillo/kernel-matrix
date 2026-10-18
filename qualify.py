#!/usr/bin/env python3
"""
qualify.py -- Falco package qualification: version x distro/kernel x scenario.

WHY THIS EXISTS
---------------
provision.py --falco answers "does Falco run on this kernel?". It installs
from the stable repo and, where a known packaging bug gets in the way,
repairs it so the driver can still be measured. That is the right call for a
compatibility matrix and the wrong one for release qualification, where the
packaging bug IS the finding.

This script installs a specific .deb/.rpm (stable or a release candidate)
through the package manager, so the maintainer scripts run, on real VMs,
in each way a fleet installs it, and lets deterministic code decide:

    pkg_installed    package manager exit 0, package fully configured, no
                     maintainer script reported failure, requested version
    driver_loaded    the falco module is in the kernel, or the running sensor
                     holds BPF programs (read from /sys and /proc, not logs)
    service_active   a Falco engine unit is running, stable for 3 samples,
                     started by the maintainer scripts alone
    event_detected   a read of /etc/shadow raised an alert

USAGE
-----
    ./qualify.py --dry-run                         # the plan and package URLs
    ./qualify.py                                   # everything in qualification.yaml
    ./qualify.py --version 0.45.1-rc1 --target ubuntu-20.04 --scenario fresh-auto
    ./qualify.py --resume                          # skip cells that already have a result
    ./qualify.py --matrix-only                     # rebuild matrix.json from cell results
    ./qualify.py --discover                        # release candidates not yet qualified
    ./qualify.py --gate 0.45.1-rc1                 # exit 1 only on red cells that are new
    ./qualify.py --version 0.45.1-rc1+fix-postinst-printenv   # a branch build (see BRANCH BUILDS)

At most --max-vms VMs run at once (default 4), counting VMs this script did
not start: hardac2's RAM is shared with other work.

OUTPUT
------
    results/qualification/<version>/<distro>--<kernel>--<scenario>.json
    results/qualification/<version>/evidence/<cell>/     evidence bundle
    results/qualification/<version>/logs/<cell>.log      the run's console
    results/qualification/matrix.json                    every cell, for a dashboard
    results/qualification/<version>/gate.json            new vs known red cells (--gate)

WATCHING PRE-RELEASES
---------------------
Jenkinsfile.qualify runs this nightly: --discover lists the dev repo and
prints each release candidate that is newer than the newest fully qualified
version, the job qualifies each one, and --gate turns the grid into a build
result. A red cell that was already red for the same distro, kernel and
scenario in an earlier version is known (falco#3994 on 18.04/20.04) and does
not fail the build; one that was green, or never ran, does.

BRANCH BUILDS
-------------
"Would this fix turn the grid green?" is a question to answer before the fix
merges. qualification.yaml's builds: section names a label, the release it
starts from and a patch to its maintainer scripts. build_branch_package.sh
makes the packages once (the release's own .deb/.rpm, payload untouched,
scripts patched) into results/builds/<label>/, and this script serves them
to the VMs over the libvirt bridge for the length of the run.

A branch build is its own grid, compared with its base release, so the
cells the fix repairs show as fixed. It is never discovered and never the
baseline for a release's gate: a fix that has not shipped cannot make a
release candidate's red cells look new.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import http.server
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import provision  # noqa: E402
from provision import Distro, RunResult, kernel_at_least, log  # noqa: E402

QUAL_RESULTS = provision.RESULTS / "qualification"
SCHEMA_VERSION = 1
CHECK_NAMES = ("pkg_installed", "driver_loaded", "service_active", "event_detected")


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Scenario:
    id: str
    driver_choice: str = ""
    upgrade: bool = False
    description: str = ""


@dataclass(frozen=True)
class Cell:
    version: str
    distro: Distro
    scenario: Scenario

    @property
    def name(self) -> str:
        return cell_name(self.distro, self.scenario.id)

    @property
    def dir(self) -> Path:
        return QUAL_RESULTS / self.version

    @property
    def result_path(self) -> Path:
        return self.dir / f"{self.name}.json"

    @property
    def evidence_dir(self) -> Path:
        return self.dir / "evidence" / self.name

    @property
    def log_path(self) -> Path:
        return self.dir / "logs" / f"{self.name}.log"


def cell_name(distro: Distro, scenario_id: str) -> str:
    """<distro>--<kernel>--<scenario>: the release, not the matrix entry, so a
    kernel variant sits in the same row family as its release."""
    return f"{distro.os_name}--{distro.kernel_label}--{scenario_id}"


@dataclass(frozen=True)
class Build:
    """A branch build: the base release's packages with a fix applied."""
    label: str
    base: str
    patch: Path
    source: str = ""

    @property
    def dir(self) -> Path:
        return provision.RESULTS / "builds" / self.label

    def package(self, fmt: str, arch: str = "x86_64") -> Path:
        return self.dir / f"falco-{self.base}-{arch}.{fmt}"


# Filled by load_qualification. channel(), expected_version() and probe_env()
# read it, so a branch build needs no extra argument through the call chain.
BUILDS: dict[str, Build] = {}


def load_qualification(path: Path) -> dict:
    data = yaml.safe_load(path.read_text())
    missing = {"download", "versions", "upgrade_from", "targets", "scenarios"} - set(data)
    if missing:
        raise ValueError(f"{path}: missing {', '.join(sorted(missing))}")
    data["scenarios"] = [Scenario(id=s["id"], driver_choice=s.get("driver_choice") or "",
                                  upgrade=bool(s.get("upgrade")),
                                  description=(s.get("description") or "").strip())
                         for s in data["scenarios"]]
    ids = [s.id for s in data["scenarios"]]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate scenario ids")
    builds = {}
    for label, b in (data.get("builds") or {}).items():
        label = str(label)
        if "+" not in label or not b.get("base") or not b.get("patch"):
            raise ValueError(f"{path}: build {label!r} needs a '+' in its label, a base and a patch")
        builds[label] = Build(label, str(b["base"]), (path.parent / b["patch"]).resolve(),
                              (b.get("source") or "").strip())
    data["builds"] = builds
    BUILDS.clear()
    BUILDS.update(builds)
    return data


def package_format(distro: Distro) -> str:
    return "deb" if distro.os_name.startswith(("ubuntu", "debian")) else "rpm"


def channel(version: str) -> str:
    """Release candidates and per-commit builds live in the dev repo; branch
    builds are ours, served from results/builds."""
    if version in BUILDS:
        return "branch"
    return "dev" if ("-rc" in version or "+" in version) else "stable"


def expected_version(version: str) -> str:
    """The version the package manager should report. A branch build keeps
    its base release's version: only its maintainer scripts differ."""
    return BUILDS[version].base if version in BUILDS else version


def package_url(download: str, version: str, fmt: str, arch: str = "x86_64") -> str:
    """
    The package file for a version, as download.falco.org lays it out:

        stable  packages/deb/stable/falco-0.45.0-x86_64.deb
                packages/rpm/falco-0.45.0-x86_64.rpm
        dev     packages/deb-dev/stable/falco-0.45.1-rc1-x86_64.deb
                packages/rpm-dev/falco-0.45.1-rc1-x86_64.rpm

    quote() matters for dev builds: their names carry a '+', which S3 reads
    as a space unless it is escaped.
    """
    dev = "-dev" if channel(version) == "dev" else ""
    if fmt == "deb":
        path = f"deb{dev}/stable/falco-{version}-{arch}.deb"
    elif fmt == "rpm":
        path = f"rpm{dev}/falco-{version}-{arch}.rpm"
    else:
        raise ValueError(f"unknown package format {fmt!r}")
    return f"{download.rstrip('/')}/{urllib.parse.quote(path)}"


def build_url(server: str, build: Build, fmt: str) -> str:
    return f"{server.rstrip('/')}/{urllib.parse.quote(build.label)}/{build.package(fmt).name}"


def probe_env(cell: Cell, download: str, upgrade_from: str) -> dict[str, str]:
    """What falco_probe.sh needs to run this cell in strict mode."""
    fmt = package_format(cell.distro)
    if cell.version in BUILDS:
        server = os.environ.get(BUILD_SERVER_ENV, "http://build-server.invalid")
        env = {"KM_PKG_URL": build_url(server, BUILDS[cell.version], fmt)}
    else:
        env = {"KM_PKG_URL": package_url(download, cell.version, fmt)}
    if cell.scenario.driver_choice:
        env["KM_DRIVER_CHOICE"] = cell.scenario.driver_choice
    if cell.scenario.upgrade:
        env["KM_BASE_PKG_URL"] = package_url(download, upgrade_from, fmt)
    return env


def plan(qual: dict, distros: dict[str, Distro], versions: list[str],
         targets: list[str], scenario_ids: list[str]) -> list[Cell]:
    unknown = [t for t in targets if t not in distros]
    if unknown:
        raise ValueError(f"not in matrix.yaml: {', '.join(unknown)}")
    by_id = {s.id: s for s in qual["scenarios"]}
    bad = [s for s in scenario_ids if s not in by_id]
    if bad:
        raise ValueError(f"unknown scenario(s): {', '.join(bad)}")
    return [Cell(v, distros[t], by_id[s]) for v in versions for t in targets for s in scenario_ids]


# ---------------------------------------------------------------------------
# Verdict: deterministic, from the probe's JSON
# ---------------------------------------------------------------------------
def version_key(version: str) -> tuple:
    """Release order: 0.45.0-rc3 < 0.45.0-rc4 < 0.45.0 < 0.45.1-rc1 < 0.45.1.
    A '+' build sorts right after the version it is built on:
    0.45.1-rc1 < 0.45.1-rc1+fix-postinst-printenv < 0.45.1."""
    version, plus, local = version.partition("+")
    base, _, pre = version.partition("-")
    return (provision.kernel_key(base, 3), 0 if pre else 1, provision.kernel_key(pre or "0", 2),
            local if plus else "")


def version_matches(installed: str, wanted: str) -> bool:
    """dpkg says '0.45.1-rc1'; rpm says '0.45.1_rc1-1' (no '-' allowed in an
    rpm version) and other packagers use '~'. All of them mean 0.45.1-rc1."""
    return installed.replace("~", "-").replace("_", "-").startswith(wanted)


def qualification_checks(falco: dict, version: str) -> list[dict]:
    """The four checks. Each carries what was observed, so a red cell says why."""
    state = falco.get("pkg_state") or "absent"
    installed_version = falco.get("pkg_version") or ""
    pkg_ok = (falco.get("pkg_exit") == 0 and state in ("install ok installed", "installed")
              and not falco.get("scriptlet_failed") and version_matches(installed_version, version))
    kmod = falco.get("kmod_loaded") is True
    progs = int(falco.get("bpf_prog_fds") or 0)
    started = falco.get("started") is True
    return [
        {"name": "pkg_installed", "passed": pkg_ok,
         "observed": f"exit {falco.get('pkg_exit')}, {state}, version {installed_version or '-'}"
                     + (", maintainer script failed" if falco.get("scriptlet_failed") else "")},
        {"name": "driver_loaded", "passed": kmod or progs > 0,
         "observed": f"kmod_loaded={kmod}, bpf_prog_fds={progs}"},
        {"name": "service_active", "passed": started,
         "observed": falco.get("active_unit") or "no engine unit running"},
        {"name": "event_detected", "passed": falco.get("detected") is True,
         "observed": falco.get("rule_matched") or ("not attempted" if not started else "no alert")},
    ]


def modern_ebpf_capable(kernel: str, host_checks: list[dict]) -> bool:
    """Modern eBPF needs BTF and roughly 5.8+. btf_available is informational
    in matrix.yaml, so a missing BTF shows up as skipped, not failed."""
    btf = any(c["name"] == "btf_available" and c["passed"] and not c["skipped"]
              for c in host_checks)
    return btf and bool(kernel) and kernel_at_least(kernel, "5.8")


def verdict(cell: Cell, result: RunResult, host_checks: list[dict],
            checks: list[dict]) -> tuple[str, str]:
    """
    pass         all four checks passed
    fail         a check failed; reason names the first one and what was seen
    unsupported  modern_ebpf on a kernel that cannot run it, and the package
                 still configured cleanly: the right behaviour, not a bug
    blocked      upgrade scenario whose N-1 package never installed cleanly,
                 so the upgrade was not attempted
    error        the harness could not ask the question (VM, probe, kernel)
    """
    if result.error:
        return "error", result.error[:300]
    kcheck = next((c for c in host_checks if c["name"] == "kernel_version_matches_expectation"), None)
    if kcheck and not kcheck["passed"]:
        return "error", f"wrong kernel: {kcheck['message']}"
    falco = result.falco or {}
    if "pkg_exit" not in falco:
        return "error", f"probe returned no qualification data: {falco.get('error', '')}"[:300]
    if cell.scenario.upgrade and (falco.get("base_exit") != 0
                                  or falco.get("base_state") not in ("install ok installed", "installed")):
        return "blocked", f"N-1 did not install: {falco.get('error') or falco.get('base_state')}"[:300]
    failed = [c for c in checks if not c["passed"]]
    if not failed:
        return "pass", ""
    pkg_ok = checks[0]["passed"]
    if (cell.scenario.driver_choice == "modern_ebpf" and pkg_ok
            and not modern_ebpf_capable(result.kernel, host_checks)):
        return "unsupported", "kernel cannot run modern eBPF; package configured cleanly"
    first = failed[0]
    return "fail", f"{first['name']}: {first['observed']}"


def cell_record(cell: Cell, result: RunResult, env: dict[str, str], upgrade_from: str,
                started: float, finished: float) -> dict:
    host_checks = [{"name": c.name, "passed": c.passed, "skipped": c.skipped, "message": c.message}
                   for c in result.checks if not c.name.startswith("falco_")]
    falco = result.falco or {}
    checks = qualification_checks(falco, expected_version(cell.version)) if "pkg_exit" in falco else []
    status, reason = verdict(cell, result, host_checks, checks)
    d = cell.distro
    build = BUILDS.get(cell.version)
    return {
        "schema_version": SCHEMA_VERSION,
        "cell": cell.name,
        "version": cell.version,
        "channel": channel(cell.version),
        "distro": d.os_name,
        "kernel": d.kernel_label,
        "kernel_variant": d.kernel_variant or None,
        "matrix_name": d.name,
        "kernel_observed": result.kernel,
        "scenario": {"id": cell.scenario.id,
                     "driver_choice": cell.scenario.driver_choice or None,
                     "upgrade_from": upgrade_from if cell.scenario.upgrade else None},
        "status": status,
        "reason": reason,
        "checks": checks,
        "modern_ebpf_capable": modern_ebpf_capable(result.kernel, host_checks),
        # Recorded, not judged: under Secure Boot an unsigned dkms module is
        # rejected by the kernel, so a red kmod cell may be the host's policy.
        "secure_boot": falco.get("secure_boot"),
        "driver": falco.get("driver"),
        "prereqs": result.prereqs or None,
        "package": {
            "format": package_format(d),
            "url": env["KM_PKG_URL"],
            "sha256": falco.get("pkg_sha256") or None,
            "installed_version": falco.get("pkg_version") or None,
            "state": falco.get("pkg_state") or None,
            "exit": falco.get("pkg_exit"),
            "base_url": env.get("KM_BASE_PKG_URL"),
            "base_version": falco.get("base_version") or None,
            "base_state": falco.get("base_state") or None,
        },
        "build": build_record(build, package_format(d)) if build else None,
        "error": result.error,
        "probe": result.falco,
        "host_checks": host_checks,
        "evidence": str(cell.evidence_dir.relative_to(cell.dir) / "manifest.json"),
        "log": str(cell.log_path.relative_to(cell.dir)),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "duration_s": round(finished - started),
        "git_sha": provision._git_sha(),
    }


# ---------------------------------------------------------------------------
# One cell, in this process (the orchestrator runs each as a child)
# ---------------------------------------------------------------------------
def run_cell(cell: Cell, checks: list[dict], download: str, upgrade_from: str) -> dict:
    env = probe_env(cell, download, upgrade_from)
    labels = {"qualification": {"version": cell.version, "channel": channel(cell.version),
                                "scenario": cell.scenario.id, "cell": cell.name,
                                "package_url": env["KM_PKG_URL"],
                                "base_package_url": env.get("KM_BASE_PKG_URL")}}
    log(f"QUALIFY {cell.version} {cell.name}  env={env}")
    started = time.time()
    result = provision.test_distro(cell.distro, checks, with_falco=True, probe_env=env,
                                   evidence_dir=cell.evidence_dir, labels=labels,
                                   build_prereqs=True)
    record = cell_record(cell, result, env, upgrade_from, started, time.time())
    cell.result_path.parent.mkdir(parents=True, exist_ok=True)
    cell.result_path.write_text(json.dumps(record, indent=2))
    log(f"RESULT {cell.version} {cell.name}: {record['status'].upper()} {record['reason']}")
    return record


def build_record(build: Build, fmt: str) -> dict:
    """What a branch-build cell installed and where it came from."""
    pkg = build.package(fmt)
    return {"label": build.label, "base": build.base, "source": build.source,
            "patch": build.patch.name,
            "package": str(pkg.relative_to(provision.RESULTS)),
            "package_sha256": hashlib.sha256(pkg.read_bytes()).hexdigest() if pkg.is_file() else None,
            "provenance": str((build.dir / "PROVENANCE.txt").relative_to(provision.RESULTS))}


def rejudge(record: dict) -> dict:
    """
    Recompute a stored cell's checks and verdict from the observations it
    already holds (probe JSON, host checks, kernel, error). The VM ran once;
    when a rule changes, every cell can be re-derived from its evidence
    instead of re-run, and a rule fix can never quietly need new data.
    """
    sc = record["scenario"]
    scenario = Scenario(sc["id"], sc.get("driver_choice") or "", upgrade=bool(sc.get("upgrade_from")))
    cell = Cell(record["version"], None, scenario)          # verdict never reads distro
    result = RunResult(distro=record["matrix_name"], kernel=record["kernel_observed"],
                       error=record["error"], falco=record["probe"])
    falco = record["probe"] or {}
    wanted = (record.get("build") or {}).get("base") or record["version"]
    checks = qualification_checks(falco, wanted) if "pkg_exit" in falco else []
    status, reason = verdict(cell, result, record["host_checks"], checks)
    return {**record, "checks": checks, "status": status, "reason": reason}


def error_record(cell: Cell, why: str, env: dict[str, str], upgrade_from: str) -> dict:
    """A child that died without writing its result still owes the grid a cell."""
    result = RunResult(distro=cell.distro.name, error=why)
    now = time.time()
    return cell_record(cell, result, env, upgrade_from, now, now)


# ---------------------------------------------------------------------------
# Branch builds: make the packages once, serve them to the VMs
# ---------------------------------------------------------------------------
BUILD_SERVER_ENV = "KM_BUILD_SERVER"
# The host's address on libvirt's default network, which every km VM is on.
BUILD_HOST = os.environ.get("KM_BUILD_HOST", "192.168.122.1")


def ensure_build(build: Build) -> None:
    """Packages for a branch build, made from its patch the first time."""
    if all(build.package(f).is_file() for f in ("deb", "rpm")) and (build.dir / "PROVENANCE.txt").is_file():
        return
    if not build.patch.is_file():
        raise FileNotFoundError(f"build {build.label}: patch {build.patch} not found")
    log(f"building {build.label} from {build.base} + {build.patch.name}")
    subprocess.run([str(HERE / "build_branch_package.sh"), build.base, build.label, str(build.patch)],
                   check=True, cwd=HERE)


class _BuildHandler(http.server.BaseHTTPRequestHandler):
    """GET/HEAD /<label>/<file> for the declared packages of declared builds, nothing else."""
    def _file(self) -> Path | None:
        parts = urllib.parse.unquote(urllib.parse.urlparse(self.path).path).strip("/").split("/")
        if len(parts) != 2 or parts[0] not in BUILDS:
            return None
        build = BUILDS[parts[0]]
        return next((p for p in (build.package("deb"), build.package("rpm"))
                     if p.name == parts[1] and p.is_file()), None)

    def _send(self, body: bool) -> None:
        path = self._file()
        if not path:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
        if body:
            with path.open("rb") as fh:
                while chunk := fh.read(1 << 20):
                    self.wfile.write(chunk)

    def do_GET(self):  # noqa: N802
        self._send(True)

    def do_HEAD(self):  # noqa: N802
        self._send(False)

    def log_message(self, fmt, *args):
        log(f"build server: {self.address_string()} {fmt % args}")


def start_build_server(host: str = BUILD_HOST) -> str:
    """Serve BUILDS' packages on the libvirt bridge until this process exits.
    The URL goes into the environment so --one children reuse it."""
    if os.environ.get(BUILD_SERVER_ENV):
        return os.environ[BUILD_SERVER_ENV]
    server = http.server.ThreadingHTTPServer((host, 0), _BuildHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://{host}:{server.server_address[1]}"
    os.environ[BUILD_SERVER_ENV] = url
    log(f"serving branch builds at {url}")
    return url


# ---------------------------------------------------------------------------
# The grid
# ---------------------------------------------------------------------------
def running_domains() -> list[str]:
    out = subprocess.run(["virsh", "list", "--name", "--state-running"],
                         capture_output=True, text=True).stdout
    return [n for n in out.split() if n]


def free_slots(max_vms: int, children: dict[int, object], domains: list[str]) -> int:
    """
    VMs this run may still start. Every running VM counts against the cap,
    including ones another session started: the cap protects the host's RAM,
    not this script's share of it. A child that has not booted yet has no
    domain, so it is counted by process instead.
    """
    mine = {pid for pid in children}
    foreign = [d for d in domains if not any(f"-{pid}-" in d for pid in mine)]
    return max_vms - len(foreign) - len(children)


def check_urls(cells: list[Cell], download: str, upgrade_from: str) -> list[str]:
    """Every package URL must exist before a single VM boots."""
    urls = sorted({u for c in cells for u in probe_env(c, download, upgrade_from).values()
                   if u.startswith("http")})
    missing = []
    for url in urls:
        req = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status != 200:
                    missing.append(f"{url} -> HTTP {resp.status}")
        except Exception as exc:  # noqa: BLE001
            missing.append(f"{url} -> {exc}")
    return missing


def orchestrate(cells: list[Cell], max_vms: int, matrix: Path, qual_path: Path,
                download: str, upgrade_from: str) -> None:
    pending = list(cells)
    children: dict[int, tuple[subprocess.Popen, Cell, object]] = {}
    while pending or children:
        for pid, (proc, cell, fh) in list(children.items()):
            if proc.poll() is None:
                continue
            fh.close()
            del children[pid]
            if not cell.result_path.exists():
                tail = cell.log_path.read_text(errors="replace").strip().splitlines()[-3:]
                record = error_record(cell, f"runner exited {proc.returncode}: {' | '.join(tail)}",
                                      probe_env(cell, download, upgrade_from), upgrade_from)
                cell.result_path.write_text(json.dumps(record, indent=2))
            record = json.loads(cell.result_path.read_text())
            log(f"done {cell.version} {cell.name}: {record['status']} {record['reason'][:90]}")
        while pending and free_slots(max_vms, children, running_domains()) > 0:
            cell = pending.pop(0)
            cell.log_path.parent.mkdir(parents=True, exist_ok=True)
            cell.result_path.unlink(missing_ok=True)
            fh = cell.log_path.open("w")
            proc = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--matrix", str(matrix),
                 "--qualification", str(qual_path),
                 "--one", cell.version, cell.distro.name, cell.scenario.id],
                stdout=fh, stderr=subprocess.STDOUT, cwd=HERE)
            children[proc.pid] = (proc, cell, fh)
            log(f"start {cell.version} {cell.name} (pid {proc.pid}, "
                f"{len(pending)} queued, {len(children)} running)")
            # Let virt-install register the domain before counting slots again.
            time.sleep(20)
        time.sleep(10)


def build_matrix(root: Path = QUAL_RESULTS) -> dict:
    """Every cell result under root, flattened for a dashboard."""
    cells = []
    for path in sorted(root.glob("*/*.json")):
        r = json.loads(path.read_text())
        if r.get("schema_version") != SCHEMA_VERSION or "cell" not in r:
            continue
        cells.append({
            "version": r["version"], "channel": r["channel"],
            "distro": r["distro"], "kernel": r["kernel"], "kernel_observed": r["kernel_observed"],
            "scenario": r["scenario"]["id"], "status": r["status"], "reason": r["reason"],
            "checks": {c["name"]: c["passed"] for c in r["checks"]},
            "driver": r["driver"],
            "secure_boot": r.get("secure_boot"),
            # Running but degraded: Falco opened its engine and still failed
            # to load some BPF programs. Green on the checks, worth a flag.
            "bpf_load_errors": (r.get("probe") or {}).get("bpf_load_errors", 0),
            "result": str(path.relative_to(root)),
            "evidence": str(Path(r["version"]) / r["evidence"]),
        })
    versions = sorted({c["version"] for c in cells}, key=version_key)
    targets = sorted({(c["distro"], c["kernel"]) for c in cells},
                     key=lambda t: (t[0], provision.kernel_key(t[1])))
    scenarios = list(dict.fromkeys(c["scenario"] for c in cells))
    summary = {v: {} for v in versions}
    for c in cells:
        summary[c["version"]][c["status"]] = summary[c["version"]].get(c["status"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_sha": provision._git_sha(),
        "checks": list(CHECK_NAMES),
        "axes": {"versions": versions,
                 "targets": [{"distro": d, "kernel": k} for d, k in targets],
                 "scenarios": scenarios},
        "summary": summary,
        "cells": cells,
    }


def grid_text(matrix: dict) -> str:
    """The matrix as plain text, one table per version."""
    short = {"pass": "PASS", "fail": "FAIL", "unsupported": "unsup", "blocked": "blocked", "error": "ERROR"}
    scen = matrix["axes"]["scenarios"]
    lines = []
    for v in matrix["axes"]["versions"]:
        lines.append(f"\n{v}")
        lines.append(f"{'distro--kernel':<26}" + "".join(f"{s:<19}" for s in scen))
        for t in matrix["axes"]["targets"]:
            row = f"{t['distro'] + '--' + t['kernel']:<26}"
            for s in scen:
                c = next((c for c in matrix["cells"] if c["version"] == v and c["distro"] == t["distro"]
                          and c["kernel"] == t["kernel"] and c["scenario"] == s), None)
                row += f"{(short.get(c['status'], c['status']) if c else '-'):<19}"
            lines.append(row)
    return "\n".join(lines)


def write_matrix() -> dict:
    QUAL_RESULTS.mkdir(parents=True, exist_ok=True)
    matrix = build_matrix()
    (QUAL_RESULTS / "matrix.json").write_text(json.dumps(matrix, indent=2))
    log(f"wrote {QUAL_RESULTS / 'matrix.json'} ({len(matrix['cells'])} cells)")
    return matrix


# ---------------------------------------------------------------------------
# Watching the dev repo for release candidates
# ---------------------------------------------------------------------------
# download.falco.org fronts this bucket, and the bucket answers ListObjectsV2.
DEV_INDEX = "https://falco-distribution.s3-eu-west-1.amazonaws.com/"
DEV_PREFIXES = {"deb": "packages/deb-dev/stable/", "rpm": "packages/rpm-dev/"}
RC_PACKAGE = re.compile(r"(?:^|/)falco-(\d+\.\d+\.\d+-rc\d+)-x86_64\.(deb|rpm)$")
_S3 = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def list_page_url(index: str, prefix: str, token: str | None = None) -> str:
    """
    One ListObjectsV2 page. The continuation token is opaque base64 and
    carries '+', '/' and '=', so it must be encoded: a raw '+' reaches S3 as
    a space and the next page comes back as an error.
    """
    query = {"list-type": "2", "prefix": prefix}
    if token:
        query["continuation-token"] = token
    return f"{index}?{urllib.parse.urlencode(query)}"


def parse_list_page(xml_text: str | bytes) -> tuple[list[str], str | None]:
    """(keys on this page, token for the next page or None when this is the last)."""
    root = ET.fromstring(xml_text)
    keys = [k.text for k in root.iter(f"{_S3}Key") if k.text]
    truncated = root.findtext(f"{_S3}IsTruncated") == "true"
    return keys, (root.findtext(f"{_S3}NextContinuationToken") if truncated else None)


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read()


def list_keys(index: str, prefix: str, fetch=_fetch) -> list[str]:
    """Every key under prefix. One page holds 1000; deb-dev alone is past 1100."""
    keys: list[str] = []
    token = None
    for _ in range(1000):                   # a token that never ends is a bug, not a listing
        page, token = parse_list_page(fetch(list_page_url(index, prefix, token)))
        keys += page
        if not token:
            return keys
    raise RuntimeError(f"{prefix}: listing never ended")


def rc_versions(keys: list[str], fmt: str) -> set[str]:
    """Release candidates among the keys. Per-commit builds (0.46.0-44+066991c),
    aarch64 and .asc signatures are not candidates."""
    found = set()
    for key in keys:
        m = RC_PACKAGE.search(key)
        if m and m.group(2) == fmt:
            found.add(m.group(1))
    return found


def complete_versions(root: Path, cell_names: list[str]) -> set[str]:
    """Versions with a result, of any status, for every planned cell. A run
    killed halfway leaves a partial grid, which --discover offers again so
    --resume can finish it. Branch builds are not releases and never count."""
    if not root.is_dir():
        return set()
    return {d.name for d in root.iterdir()
            if d.is_dir() and d.name not in BUILDS
            and all((d / f"{n}.json").exists() for n in cell_names)}


def discover_new(available: set[str], complete: set[str]) -> list[str]:
    """
    Release candidates to qualify, oldest first: those newer than the newest
    fully qualified version. Older candidates are history, not news: the
    dev repo still serves 0.39.0-rc1, and the grid is about what ships next.
    With nothing qualified yet, only the newest candidate, so a fresh
    workspace starts one grid, not twenty.
    """
    if not available:
        return []
    ordered = sorted(available, key=version_key)
    if not complete:
        return ordered[-1:]
    floor = version_key(max(complete, key=version_key))
    return [v for v in ordered if version_key(v) > floor]


def discover(qual: dict, distros: dict[str, Distro], index: str = DEV_INDEX,
             root: Path = QUAL_RESULTS, fetch=_fetch) -> list[str]:
    """New release candidates, published in both formats. The .deb and .rpm
    are uploaded separately; qualifying in the gap between them would stop
    on a missing package URL before a VM boots."""
    available = (rc_versions(list_keys(index, DEV_PREFIXES["deb"], fetch), "deb")
                 & rc_versions(list_keys(index, DEV_PREFIXES["rpm"], fetch), "rpm"))
    names = [cell_name(distros[t], s.id) for t in qual["targets"] for s in qual["scenarios"]]
    return discover_new(available, complete_versions(root, names))


# ---------------------------------------------------------------------------
# Gate: fail on red that is new, not on red that is known
# ---------------------------------------------------------------------------
RED = ("fail", "error")


def gate(cells: list[dict], version: str) -> dict:
    """
    Compare each cell of version with the same distro, kernel and scenario
    in the newest earlier version that ran it. Per cell, not per grid: an
    earlier grid that only ran a few rows (0.45.0-rc4) is still the baseline
    for those rows, and the rows it skipped fall back further.

        new      red now; green, blocked, unsupported or absent before
        known    red now and red before: already reported, keeps the build green
        fixed    red before, not red now

    A branch build is never a baseline: its fix has not shipped, so a
    release's red cells are judged against releases only. A branch build's
    own gate is judged against the releases before it, its base first.
    """
    def key(c: dict) -> tuple:
        return (c["distro"], c["kernel"], c["scenario"])

    vk = version_key(version)
    baseline: dict[tuple, dict] = {}
    for c in sorted((c for c in cells if version_key(c["version"]) < vk
                     and c.get("channel") != "branch"),
                    key=lambda c: version_key(c["version"])):
        baseline[key(c)] = c                # newest earlier version wins
    out = {"version": version, "new": [], "known": [], "fixed": []}
    for c in sorted((c for c in cells if c["version"] == version), key=key):
        before = baseline.get(key(c))
        row = {"cell": f"{c['distro']}--{c['kernel']}--{c['scenario']}",
               "status": c["status"], "reason": c["reason"],
               "baseline_version": before["version"] if before else None,
               "baseline_status": before["status"] if before else None}
        if c["status"] in RED:
            out["known" if before and before["status"] in RED else "new"].append(row)
        elif before and before["status"] in RED:
            out["fixed"].append(row)
    out["cells"] = sum(1 for c in cells if c["version"] == version)
    return out


def gate_text(result: dict) -> str:
    lines = [f"gate {result['version']}: {result['cells']} cells, {len(result['new'])} new red, "
             f"{len(result['known'])} known red, {len(result['fixed'])} fixed"]
    for label in ("new", "known", "fixed"):
        for r in result[label]:
            was = (f"{r['baseline_status']} in {r['baseline_version']}" if r["baseline_version"]
                   else "no earlier result")
            lines.append(f"  {label.upper():<6} {r['cell']:<44} {r['status']:<6} (was {was})"
                         + (f"  {r['reason'][:100]}" if label != "fixed" else ""))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=__doc__)
    parser.add_argument("--matrix", type=Path, default=HERE / "matrix.yaml")
    parser.add_argument("--qualification", type=Path, default=HERE / "qualification.yaml")
    parser.add_argument("--version", action="append", help="repeatable; default: the file's list")
    parser.add_argument("--target", action="append", help="matrix.yaml entry; repeatable")
    parser.add_argument("--scenario", action="append", help="scenario id; repeatable")
    parser.add_argument("--max-vms", type=int, default=4)
    parser.add_argument("--resume", action="store_true",
                        help="skip cells that already have a non-error result")
    parser.add_argument("--dry-run", action="store_true", help="print the plan and check URLs")
    parser.add_argument("--matrix-only", action="store_true", help="rebuild matrix.json and exit")
    parser.add_argument("--rejudge", action="store_true",
                        help="recompute every stored cell's verdict from its observations, "
                             "then rebuild matrix.json (no VMs)")
    parser.add_argument("--discover", action="store_true",
                        help="print release candidates in the dev repo not yet qualified, one per line")
    parser.add_argument("--gate", action="append", metavar="VERSION",
                        help="exit 1 if VERSION has red cells that were not red in an earlier "
                             "version; writes <version>/gate.json (no VMs)")
    parser.add_argument("--one", nargs=3, metavar=("VERSION", "TARGET", "SCENARIO"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.chdir(HERE)                      # results/ is relative, as in provision.py

    if args.rejudge:
        for path in sorted(QUAL_RESULTS.glob("*/*.json")):
            old = json.loads(path.read_text())
            if old.get("schema_version") != SCHEMA_VERSION or "cell" not in old:
                continue
            new = rejudge(old)
            if (new["status"], new["reason"]) != (old["status"], old["reason"]):
                log(f"rejudged {old['version']} {old['cell']}: {old['status']} -> {new['status']}")
            path.write_text(json.dumps(new, indent=2))
    if args.matrix_only or args.rejudge:
        print(grid_text(write_matrix()))
        return 0
    if args.gate:
        cells = build_matrix()["cells"]
        regressed = False
        for version in args.gate:
            if not any(c["version"] == version for c in cells):
                log(f"no results for {version} under {QUAL_RESULTS}", "ERROR")
                return 2
            result = gate(cells, version)
            (QUAL_RESULTS / version / "gate.json").write_text(json.dumps(result, indent=2))
            print(gate_text(result))
            regressed |= bool(result["new"])
        return 1 if regressed else 0

    qual = load_qualification(args.qualification)
    distros_list, checks = provision.load_matrix(args.matrix)
    distros = {d.name: d for d in distros_list}

    if args.discover:
        # stdout carries only the versions, so a pipeline can read it as a list.
        for version in discover(qual, distros):
            print(version)
        return 0

    if args.one:
        version, target, scenario = args.one
        cell = plan(qual, distros, [version], [target], [scenario])[0]
        if version in qual["builds"]:
            ensure_build(qual["builds"][version])
            start_build_server()            # the parent's, when it started one
        provision.ensure_dirs()
        provision.ensure_ssh_key()
        record = run_cell(cell, checks, qual["download"], qual["upgrade_from"])
        return 0 if record["status"] in ("pass", "unsupported") else 1

    cells = plan(qual, distros, args.version or [str(v) for v in qual["versions"]],
                 args.target or qual["targets"],
                 args.scenario or [s.id for s in qual["scenarios"]])
    if args.resume:
        def done(c: Cell) -> bool:
            return c.result_path.exists() and json.loads(c.result_path.read_text())["status"] != "error"
        cells = [c for c in cells if not done(c)]

    builds = {c.version: qual["builds"][c.version] for c in cells if c.version in qual["builds"]}
    for build in builds.values():
        ensure_build(build)
    if builds:
        start_build_server()
    for c in cells:
        env = probe_env(c, qual["download"], qual["upgrade_from"])
        log(f"plan {c.version:<12} {c.name:<44} {env['KM_PKG_URL'].rsplit('/', 1)[1]}"
            + (f" (from {env['KM_BASE_PKG_URL'].rsplit('/', 1)[1]})" if "KM_BASE_PKG_URL" in env else ""))
    missing = check_urls(cells, qual["download"], qual["upgrade_from"])
    for m in missing:
        log(f"missing package: {m}", "ERROR")
    if missing:
        return 2
    log(f"{len(cells)} cell(s), every package URL answers")
    if args.dry_run:
        return 0

    provision.preflight()
    provision.ensure_dirs()
    provision.ensure_ssh_key()
    for d in {c.distro.base or c.distro.name: c.distro for c in cells}.values():
        provision.ensure_base_image(d)      # once, before children race for it
    orchestrate(cells, args.max_vms, args.matrix, args.qualification,
                qual["download"], qual["upgrade_from"])
    matrix = write_matrix()
    print(grid_text(matrix))
    bad = [c for c in matrix["cells"] if c["status"] in ("fail", "error")]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())

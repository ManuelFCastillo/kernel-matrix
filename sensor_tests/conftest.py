"""
sensor_tests -- the questions a two-minute qualification VM cannot answer.

One pytest session = one cell (version x target x scenario) = one VM that
lives for the whole session:

    1. boot the target exactly as qualify.py does (kernel variant, build
       prerequisites) and install the package under test through the strict
       probe: the maintainer scripts start Falco, nobody rescues them
    2. test_00_install judges that install with qualify.py's own checks
    3. the `sensor` fixture adds what the tests read (JSON file output,
       metrics file, Prometheus endpoint, coverage rules), restarts Falco
       once, and proves an alert gets through before any test runs
    4. the test files run in name order; lifecycle is last because it ends
       with the package removed
    5. teardown copies the evidence out and destroys the VM

Run one cell:

    python3 -m pytest sensor_tests --km-version 0.45.1-rc1 --km-target ubuntu-24.04

Run the cells in sensor.yaml, several VMs at once: sensor_tests/run.py.

If the package does not install, test_00_install fails with the reason and
every test that needs a running sensor skips with a pointer to it: one red
test that names the cause, not a hundred that repeat it.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import provision  # noqa: E402
import qualify  # noqa: E402
from guest import (ASSETS, COV_DIR, COV_RULES, DROPIN, EVENTS_FILE, METRICS_FILE,  # noqa: E402
                   Guest, Sensor, log_step)

SENSOR_RESULTS = Path("results") / "sensor"

# What the tests read. Everything else stays as the package shipped it.
DROPIN_YAML = f"""\
# kernel-matrix sensor_tests: alerts and metrics as JSON lines the tests read
json_output: true
json_include_output_property: true
json_include_tags_property: true
file_output:
  enabled: true
  keep_alive: true
  filename: {EVENTS_FILE}
metrics:
  enabled: true
  interval: 5s
  output_rule: false
  output_file: {METRICS_FILE}
  rules_counters_enabled: true
  resource_utilization_enabled: true
  state_counters_enabled: true
  kernel_event_counters_enabled: true
  libbpf_stats_enabled: false
  convert_memory_to_mb: true
  include_empty_values: false
webserver:
  enabled: true
  threadiness: 0
  listen_port: 8765
  listen_address: 127.0.0.1
  k8s_healthz_endpoint: /healthz
  prometheus_metrics_enabled: true
  ssl_enabled: false
  ssl_certificate: /etc/falco/falco.pem
"""


def pytest_addoption(parser):
    g = parser.getgroup("kernel-matrix sensor")
    g.addoption("--km-version", help="Falco version under test, e.g. 0.45.1-rc1")
    g.addoption("--km-target", help="matrix.yaml target, e.g. ubuntu-24.04")
    g.addoption("--km-scenario", default="fresh-auto", help="qualification.yaml scenario id")
    g.addoption("--km-soak-minutes", type=float, default=None, help="override sensor.yaml soak.minutes")
    g.addoption("--km-keep", action="store_true", help="leave the VM running after the session")


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: soak and load, minutes each")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def km(pytestconfig) -> dict:
    version = pytestconfig.getoption("--km-version")
    target = pytestconfig.getoption("--km-target")
    if not version or not target:
        pytest.exit("sensor_tests needs --km-version and --km-target (or use sensor_tests/run.py)", 2)
    os.chdir(ROOT)                      # provision.py's results/ paths are relative
    qual = qualify.load_qualification(ROOT / "qualification.yaml")
    distros_list, checks = provision.load_matrix(ROOT / "matrix.yaml")
    distros = {d.name: d for d in distros_list}
    cell = qualify.plan(qual, distros, [version], [target],
                        [pytestconfig.getoption("--km-scenario")])[0]
    settings = yaml.safe_load((HERE / "sensor.yaml").read_text())
    soak = pytestconfig.getoption("--km-soak-minutes")
    if soak is not None:
        settings["soak"]["minutes"] = soak
    results = SENSOR_RESULTS / version / cell.name
    results.mkdir(parents=True, exist_ok=True)
    return {"version": version, "cell": cell, "qual": qual, "checks": checks,
            "settings": settings, "results": results, "keep": pytestconfig.getoption("--km-keep")}


@pytest.fixture(scope="session")
def measurements(km):
    """Every number a test measured, gated or not. Written at session end."""
    data: dict[str, dict] = {}
    yield data
    (km["results"] / "measurements.json").write_text(json.dumps(data, indent=2, sort_keys=True))


@pytest.fixture
def measure(request, measurements, record_property):
    """measure(name, value): into junit properties and measurements.json."""
    def _measure(name, value):
        record_property(name, value)
        measurements.setdefault(request.node.name, {})[name] = value
    return _measure


# ---------------------------------------------------------------------------
# The VM
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def guest(km) -> Guest:
    cell, d = km["cell"], km["cell"].distro
    # km-<target>-<pid>-<suffix>: Jenkins reaps a km-* domain only when the
    # pid in the second-to-last field is gone, so no '-' in the suffix.
    vm_name = f"km-{d.name}-{os.getpid()}-s{int(time.time()) % 100000}"
    provision.ensure_dirs()
    provision.ensure_ssh_key()
    provision.ensure_base_image(d)
    overlay = provision.create_overlay(d, vm_name)
    seed = provision.make_seed_iso(d, vm_name)
    g = None
    try:
        provision.boot_vm(d, vm_name, overlay, seed)
        ip = provision.get_vm_ip(vm_name, timeout=d.boot_timeout_sec)
        if not ip or not provision.wait_for_ssh(ip, d.ssh_user, timeout=d.boot_timeout_sec):
            pytest.fail(f"harness: {vm_name} never answered ssh", pytrace=False)
        if d.kernel_packages:
            ip, problem = provision.install_kernel_variant(d, ip, vm_name)
            if problem:
                pytest.fail(f"harness: {problem}", pytrace=False)
        ip, prereqs, problem = provision.ensure_build_prereqs(d, ip, vm_name)
        if problem:
            pytest.fail(f"harness: {problem}", pytrace=False)
        g = Guest(d, ip, vm_name)
        log_step(f"{vm_name} up at {ip}, {prereqs}")
        yield g
    finally:
        if g is not None:
            _collect(g, km["results"])
        if km["keep"]:
            log_step(f"--km-keep: leaving {vm_name} running "
                     f"(virsh destroy {vm_name}; virsh undefine {vm_name} --nvram)")
        else:
            provision.destroy_vm(vm_name, overlay, seed)


def _collect(g: Guest, results: Path) -> None:
    """What an engineer opens after a red test. Best effort: the VM may be
    the thing that broke."""
    ev = results / "evidence"
    try:
        for remote, name in ((EVENTS_FILE, "falco-events.json"), (METRICS_FILE, "falco-metrics.json"),
                             ("/var/log/km-http-sink.jsonl", "http-sink.jsonl"),
                             ("/var/log/km-program-output.jsonl", "program-output.jsonl"),
                             ("/var/log/km-lifecycle.log", "lifecycle.log"),
                             ("/var/log/km-pkg-install.log", "pkg-install.log")):
            g.fetch(remote, ev / name)
        g.sh("journalctl -u 'falco*' --no-pager -o short-iso > /tmp/km-falco-journal.txt 2>&1", timeout=120)
        g.fetch("/tmp/km-falco-journal.txt", ev / "falco-journal.txt")
        provision.collect_evidence(g.distro, g.ip, ev)
    except Exception as exc:  # noqa: BLE001 -- never mask the test result
        log_step(f"evidence collection incomplete: {exc}")


# ---------------------------------------------------------------------------
# The install, judged exactly as a qualification cell is
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def install(km, guest) -> dict:
    cell, qual = km["cell"], km["qual"]
    env = qualify.probe_env(cell, qual["download"], qual["upgrade_from"])
    ev = km["results"] / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    probe = provision.run_falco_probe(guest.distro, guest.ip, evidence_dir=ev, env=env)
    checks = qualify.qualification_checks(probe, cell.version) if "pkg_exit" in probe else []
    result = provision.RunResult(distro=guest.distro.name, kernel=guest.out("uname -r"), falco=probe)
    status, reason = qualify.verdict(cell, result, [], checks)
    (km["results"] / "install.json").write_text(json.dumps(
        {"status": status, "reason": reason, "checks": checks, "probe": probe}, indent=2))
    log_step(f"install: {status} {reason}")
    return {"status": status, "reason": reason, "checks": checks, "probe": probe, "env": env}


# ---------------------------------------------------------------------------
# The sensor, instrumented
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def sensor(km, guest, install) -> Sensor:
    if install["status"] != "pass":
        pytest.skip(f"sensor not running after install ({install['status']}: "
                    f"{install['reason'][:160]}); see test_00_install")
    s = Sensor(guest, alert_timeout=km["settings"]["alert_timeout_s"])
    if not s.wait_running(timeout=30):
        pytest.skip("no Falco engine unit running after install; see test_00_install")
    guest.sh(f"mkdir -p {COV_DIR}/bin /opt/km && rm -f {EVENTS_FILE} {METRICS_FILE}", check=True)
    guest.put(ASSETS / "kmcov.py", f"{COV_DIR}/kmcov.py")
    guest.put(ASSETS / "http_sink.py", "/opt/km/http_sink.py")
    guest.put(ASSETS / "km_coverage_rules.yaml", COV_RULES)
    guest.write(DROPIN, DROPIN_YAML)
    # A restart, not a hot reload, so setup never depends on the reload path
    # test_60_lifecycle is there to judge.
    pid = s.restart()
    log_step(f"instrumented {s.unit} (pid {pid}); waiting for the first alert")
    if s.marker(timeout=90) is None:
        tail = guest.sh(f"journalctl -u {s.unit} --no-pager -n 30").stdout
        pytest.fail("harness: Falco is running but no alert reached the JSON file output "
                    f"within 90s of instrumenting it.\n{tail}", pytrace=False)
    return s


@pytest.fixture(scope="session")
def python(guest, sensor) -> str:
    return guest.python()

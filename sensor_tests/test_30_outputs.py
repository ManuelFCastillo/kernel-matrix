"""
Outputs and integrations: an alert that fires and goes nowhere is a silent
sensor.

Each output is switched on in its own drop-in, Falco is restarted, one
marker is sent, and the alert must arrive at that output's far end. The
drop-in is removed afterwards so load and soak measure the baseline config.
"""

from __future__ import annotations

import json
import time

import pytest

import provision
from guest import COV_DIR, parse_json_lines, token

HTTP_PORT = 47201
SIDEKICK_PORT = 47202
HTTP_LOG = "/var/log/km-http-sink.jsonl"
PROGRAM_LOG = "/var/log/km-program-output.jsonl"
OUTPUT_DROPIN = "/etc/falco/config.d/zz-km-output-under-test.yaml"
# A marker writes its file then reads it: both events carry the token.
MARKER_RULES = ("KM cov open write", "KM cov open read")


@pytest.fixture
def output_config(guest, sensor):
    """Write an output drop-in, restart, and always remove it afterwards."""
    def apply(yaml_text: str) -> None:
        guest.write(OUTPUT_DROPIN, yaml_text)
        sensor.restart()
    yield apply
    guest.sh(f"rm -f {OUTPUT_DROPIN}")
    sensor.restart()


@pytest.fixture(scope="module")
def http_sink(guest, sensor, python):
    """A local HTTP endpoint that writes every POST it gets to HTTP_LOG."""
    guest.sh("systemctl stop km-http-sink 2>/dev/null; systemctl reset-failed km-http-sink 2>/dev/null; "
             f"rm -f {HTTP_LOG}")
    guest.sh(f"systemd-run --unit km-http-sink {python} /opt/km/http_sink.py {HTTP_PORT} {HTTP_LOG}",
             check=True)
    for _ in range(20):
        if guest.sh(f"curl -s -o /dev/null -X POST -d '{{}}' http://127.0.0.1:{HTTP_PORT}/ready").returncode == 0:
            break
        time.sleep(1)
    else:
        pytest.fail("harness: HTTP sink did not start", pytrace=False)
    yield HTTP_LOG
    guest.sh("systemctl stop km-http-sink")


def marker_script(t: str) -> str:
    return f"echo x > {COV_DIR}/{t} && cat {COV_DIR}/{t} > /dev/null"


def wait_in_file(guest, path: str, needle: str, timeout: int = 30) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = [r for r in parse_json_lines(guest.sh(f"cat {path} 2>/dev/null").stdout)
                if needle in json.dumps(r)]
        if rows:
            return rows
        guest.sh(marker_script(token()))         # keep events flowing while we wait
        time.sleep(2)
    return []


# ---------------------------------------------------------------------------
def test_json_file_output_schema(sensor):
    """The fields every downstream consumer parses are present and typed."""
    t = token()
    alert = sensor.trigger(marker_script(t), "KM cov open read", contains=t)
    assert alert is not None
    for key, typ in (("time", str), ("rule", str), ("priority", str), ("output", str),
                     ("source", str), ("output_fields", dict), ("tags", list), ("hostname", str)):
        assert isinstance(alert.get(key), typ), f"{key}: {alert.get(key)!r}"
    assert alert["source"] == "syscall"
    assert alert["priority"] == "Notice"
    assert "km_coverage" in alert["tags"]


def test_stdout_reaches_journal(guest, sensor):
    t = token()
    assert sensor.trigger(marker_script(t), "KM cov open read", contains=t) is not None
    deadline = time.time() + 20
    while time.time() < deadline:
        if t in guest.sh(f"journalctl -u {sensor.unit} --since '-2min' --no-pager -o cat").stdout:
            return
        time.sleep(2)
    pytest.fail(f"alert for {t} is in the file output but not in {sensor.unit}'s journal")


def test_syslog_output(guest, sensor):
    """syslog_output is on by default; on systemd hosts it lands in the
    journal under the falco syslog identifier, separately from stdout."""
    t = token()
    assert sensor.trigger(marker_script(t), "KM cov open read", contains=t) is not None
    deadline = time.time() + 20
    while time.time() < deadline:
        if t in guest.sh("journalctl SYSLOG_IDENTIFIER=falco --since '-2min' --no-pager -o cat").stdout:
            return
        time.sleep(2)
    pytest.fail(f"alert for {t} never reached syslog")


def test_http_output(guest, sensor, http_sink, output_config):
    output_config(f"""\
http_output:
  enabled: true
  url: http://127.0.0.1:{HTTP_PORT}/falco
  user_agent: kernel-matrix
  insecure: false
  keep_alive: false
  max_consecutive_timeouts: 5
""")
    t = token()
    sensor.guest.sh(marker_script(t))
    rows = wait_in_file(guest, http_sink, t)
    assert rows, "http_output never POSTed the alert"
    assert all(isinstance(r["body"], dict) and r["body"].get("rule") in MARKER_RULES for r in rows), rows


def test_program_output(guest, sensor, output_config):
    guest.sh(f"rm -f {PROGRAM_LOG}")
    output_config(f"""\
program_output:
  enabled: true
  keep_alive: true
  program: "cat >> {PROGRAM_LOG}"
""")
    t = token()
    guest.sh(marker_script(t))
    assert wait_in_file(guest, PROGRAM_LOG, t), "program_output never wrote the alert"


def test_webserver_healthz(guest, sensor):
    r = guest.sh("curl -s -w '\\n%{http_code}' http://127.0.0.1:8765/healthz")
    body, _, code = r.stdout.rpartition("\n")
    assert code == "200", r.stdout
    assert json.loads(body).get("status") == "ok", body


def test_prometheus_metrics(guest, sensor, measure):
    """The /metrics endpoint serves Falco's counters, and they move."""
    def scrape() -> dict[str, float]:
        text = guest.sh("curl -s http://127.0.0.1:8765/metrics").stdout
        out = {}
        for line in text.splitlines():
            if line.startswith("falcosecurity_") and " " in line:
                name, _, value = line.rpartition(" ")
                try:
                    out[name] = float(value)
                except ValueError:
                    pass
        return out
    first = scrape()
    assert first, "/metrics served no falcosecurity_* series"
    measure("series", len(first))
    time.sleep(6)
    second = scrape()
    evts = [k for k in second if k.startswith("falcosecurity_scap_n_evts")]
    assert evts, f"no falcosecurity_scap_n_evts* series; have {sorted(first)[:20]}"
    assert any(second[k] > first.get(k, 0) for k in evts), "event counter did not move in 6s"


def test_falcosidekick(km, guest, sensor, http_sink, output_config):
    """Falco -> falcosidekick -> webhook: the integration most fleets put in front of a SIEM."""
    sk = km["settings"]["falcosidekick"]
    cache = provision.LAB_ROOT / "tools" / f"falcosidekick-{sk['version']}"
    binary = cache / "falcosidekick"
    if not binary.exists():
        cache.mkdir(parents=True, exist_ok=True)
        tgz = cache / "falcosidekick.tgz"
        provision.run(["curl", "-fsSL", "-o", str(tgz), sk["url"]], timeout=300)
        got = provision.run(["sha256sum", str(tgz)]).stdout.split()[0]
        if got != sk["sha256"]:
            tgz.unlink()
            pytest.fail(f"harness: falcosidekick sha256 {got} != pinned {sk['sha256']}", pytrace=False)
        provision.run(["tar", "-xzf", str(tgz), "-C", str(cache), "falcosidekick"])
        tgz.unlink()
    guest.put(binary, "/opt/km/falcosidekick", mode="0755")
    guest.sh("systemctl stop km-sidekick 2>/dev/null; systemctl reset-failed km-sidekick 2>/dev/null")
    guest.sh(f"systemd-run --unit km-sidekick --setenv=LISTENADDRESS=127.0.0.1 "
             f"--setenv=LISTENPORT={SIDEKICK_PORT} "
             f"--setenv=WEBHOOK_ADDRESS=http://127.0.0.1:{HTTP_PORT}/sidekick "
             f"/opt/km/falcosidekick", check=True)
    try:
        for _ in range(20):
            if guest.sh(f"curl -sf http://127.0.0.1:{SIDEKICK_PORT}/healthz").returncode == 0:
                break
            time.sleep(1)
        else:
            pytest.fail("harness: falcosidekick did not come up: "
                        + guest.sh("journalctl -u km-sidekick --no-pager -n 20").stdout, pytrace=False)
        output_config(f"""\
json_output: true
http_output:
  enabled: true
  url: http://127.0.0.1:{SIDEKICK_PORT}/
  user_agent: falcosecurity/falco
  insecure: false
  keep_alive: false
  max_consecutive_timeouts: 5
""")
        t = token()
        guest.sh(marker_script(t))
        rows = [r for r in wait_in_file(guest, http_sink, t) if r["path"].startswith("/sidekick")]
        assert rows, ("falcosidekick never forwarded the alert to its webhook: "
                      + guest.sh("journalctl -u km-sidekick --no-pager -n 20").stdout)
        assert all(r["body"].get("rule") in MARKER_RULES for r in rows), rows
    finally:
        guest.sh("systemctl stop km-sidekick")


def test_grpc_output(guest, sensor):
    """
    gRPC server and output were deprecated in 0.43 and are gone from the
    0.45 falco.yaml. Kept as a test so the day a release ships them again (or
    an older one is qualified) it is checked, not forgotten.
    """
    if guest.sh("grep -qE '^grpc(_output)?:' /etc/falco/falco.yaml").returncode != 0:
        pytest.skip("this version ships no grpc / grpc_output configuration")
    guest.write(OUTPUT_DROPIN, "grpc:\n  enabled: true\n  bind_address: unix:///run/falco/falco.sock\n"
                               "  threadiness: 0\ngrpc_output:\n  enabled: true\n")
    try:
        sensor.restart()
        assert guest.sh("test -S /run/falco/falco.sock").returncode == 0, "gRPC socket not created"
    finally:
        guest.sh(f"rm -f {OUTPUT_DROPIN}")
        sensor.restart()

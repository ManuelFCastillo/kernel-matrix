"""
Detection beyond the one /etc/shadow rule.

Three questions, kept apart because they fail for different reasons:

  test_ruleset_*       does the shipped ruleset load, and does every rule in
                       it have a trigger here or a written reason it has none
  test_shipped_rule    does each stable rule fire on the event it describes
  test_syscall         does this driver deliver each syscall family, with its
                       arguments decoded (coverage rules, no exclusions)

A red test_syscall with a green test_shipped_rule for the same event is a
ruleset question; the other way round is a driver bug.
"""

from __future__ import annotations

import json
import random

import pytest

from guest import COV_DIR, shipped_rule_names, token

# ---------------------------------------------------------------------------
# Stable rules: a trigger for each, or the reason there is none.
# {t} is a fresh token, {cov} the coverage dir, {py} the guest's python.
# ---------------------------------------------------------------------------
SHIPPED_TRIGGERS = {
    "Read sensitive file untrusted": (
        "touch {cov}/{t} && cat /etc/shadow {cov}/{t} > /dev/null", "{t}"),
    "Search Private Keys or Passwords": (
        "find {cov}/{t} -name id_rsa 2>/dev/null; true", "{t}"),
    "Clear Log Activities": (
        ": > /var/log/km-{t}.log; rm -f /var/log/km-{t}.log", "km-{t}.log"),
    "Remove Bulk Data from Disk": (
        "echo x > {cov}/{t} && shred -u {cov}/{t}", "{t}"),
    "Create Symlink Over Sensitive Files": (
        "ln -s /etc/shadow {cov}/{t}", "{t}"),
    # /var/tmp, not /tmp: a hardlink cannot cross into a tmpfs /tmp.
    "Create Hardlink Over Sensitive Files": (
        "ln /etc/shadow /var/tmp/km-{t}; rm -f /var/tmp/km-{t}", "km-{t}"),
    # The rule ignores a shell parent, so `timeout` forks the reader.
    "Directory traversal monitored file read": (
        "touch {cov}/{t} && timeout 5 cat /etc/../../etc/passwd {cov}/{t} > /dev/null", "{t}"),
    "PTRACE anti-debug attempt": ("{py} {cov}/kmcov.py traceme", "kmcov.py traceme"),
    "PTRACE attached to process": ("{py} {cov}/kmcov.py attach", "kmcov.py attach"),
    "Find AWS Credentials": (
        "find {cov}/{t}/.aws/credentials 2>/dev/null; true", "{t}"),
    "Execution from /dev/shm": (
        "cp /bin/true /dev/shm/km-{t} && /dev/shm/km-{t}; rm -f /dev/shm/km-{t}", "km-{t}"),
    "Fileless execution via memfd_create": ("{py} {cov}/kmcov.py memfd-exec", None),
    # Outbound to a TEST-NET-2 address (RFC 5737, never routed); the rule
    # excludes loopback and RFC 1918, and only watches the ports in its
    # ssh_non_standard_ports list (4444 is one; 2222 is not).
    "Disallowed SSH Connection Non Standard Port": (
        "timeout 6 ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no "
        "-p 4444 km@198.51.100.7 true; true", "198.51.100.7"),
    "System user interactive": ("runuser -u nobody -- /bin/true", "nobody"),
}

# Rules covered in test_20_container.py.
CONTAINER_RULES = {
    "Terminal shell in container",
    "Drop and execute new binary in container",
    "Netcat Remote Code Execution in Container",
}

# Shipped rules with no trigger, and why. A new upstream rule fails
# test_ruleset_coverage until it lands in one of these three places.
NOT_TRIGGERED = {
    "Read sensitive file trusted after startup":
        "needs a trusted server process reading /etc/shadow minutes after it started",
    "Run shell untrusted":
        "needs a protected shell spawner (web server, database) as the parent",
    "Contact K8S API Server From Container": "needs a Kubernetes API server",
    "Packet socket created in container": "needs AF_PACKET tooling inside the test image",
    "Redirect STDOUT/STDIN to Network Connection in Container":
        "needs a shell that can dup a socket onto stdin inside the test image",
    "Linux Kernel Module Injection Detected":
        "needs a privileged container loading a real module into the guest kernel",
    "Debugfs Launched in Privileged Container": "needs debugfs inside a privileged container",
    "Detect release_agent File Container Escapes":
        "a cgroup v1 release_agent write from a privileged container: not run on purpose",
}


@pytest.fixture(scope="module")
def shipped(guest, sensor) -> list[str]:
    return shipped_rule_names(guest.out("cat /etc/falco/falco_rules.yaml"))


def fill(template: str | None, t: str, py: str) -> str | None:
    return template.format(t=t, cov=COV_DIR, py=py) if template else None


# ---------------------------------------------------------------------------
# The ruleset itself
# ---------------------------------------------------------------------------
def test_ruleset_validates(guest, sensor, measure):
    """The shipped rules file validates clean with the shipped config and plugins."""
    r = guest.sh("falco -c /etc/falco/falco.yaml -V /etc/falco/falco_rules.yaml 2>&1", timeout=180)
    measure("validate_output", r.stdout[-500:])
    assert r.returncode == 0, r.stdout[-1500:]
    assert "LOAD_ERR" not in r.stdout, r.stdout[-1500:]


def test_ruleset_coverage(km, shipped, measure):
    """Every shipped rule has a trigger here or a written reason it has none."""
    triggered = set(SHIPPED_TRIGGERS) | CONTAINER_RULES
    unaccounted = [r for r in shipped if r not in triggered and r not in NOT_TRIGGERED]
    gone = sorted(triggered - set(shipped))
    report = {"shipped": len(shipped),
              "with_trigger": sorted(set(shipped) & triggered),
              "not_triggered": {r: NOT_TRIGGERED[r] for r in shipped if r in NOT_TRIGGERED},
              "unaccounted": unaccounted,
              "trigger_for_rule_no_longer_shipped": gone}
    (km["results"] / "rule-coverage.json").write_text(json.dumps(report, indent=2))
    measure("rules_shipped", len(shipped))
    measure("rules_with_trigger", len(report["with_trigger"]))
    assert not unaccounted, (f"shipped rules with no trigger and no reason: {unaccounted}. "
                             "Add a trigger to SHIPPED_TRIGGERS or a reason to NOT_TRIGGERED.")


# ---------------------------------------------------------------------------
# Each stable rule on its own event
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("rule", sorted(SHIPPED_TRIGGERS))
def test_shipped_rule(guest, sensor, shipped, python, measure, rule):
    if rule not in shipped:
        pytest.skip(f"{rule!r} is not in this version's falco_rules.yaml")
    if rule == "Execution from /dev/shm" and "noexec" in guest.sh("findmnt -no OPTIONS /dev/shm").stdout:
        pytest.skip("/dev/shm is mounted noexec on this distro: nothing can execute there")
    script, contains = SHIPPED_TRIGGERS[rule]
    t = token()
    alert = sensor.trigger(fill(script, t, python), rule, contains=fill(contains, t, python))
    assert alert is not None, f"{rule!r} did not fire within {sensor.alert_timeout}s"
    measure("priority", alert.get("priority"))


# ---------------------------------------------------------------------------
# The driver, one syscall family at a time
# ---------------------------------------------------------------------------
PORT = random.randint(41000, 48999)      # per session: no TIME_WAIT from a previous run

SYSCALLS = {
    # name: (script, rule, contains, accepted evt.type values)
    "execve": ("ln -sf /bin/true {cov}/bin/kmcov-true && {cov}/bin/kmcov-true",
               "KM cov exec", "kmcov-true", {"execve", "execveat"}),
    "open_read": ("echo x > {cov}/{t} && cat {cov}/{t} > /dev/null",
                  "KM cov open read", "{cov}/{t}", {"open", "openat", "openat2"}),
    "open_write": ("echo x > {cov}/{t}", "KM cov open write", "{cov}/{t}",
                   {"open", "openat", "openat2"}),
    "unlink": ("touch {cov}/{t} && rm -f {cov}/{t}", "KM cov unlink", "{t}", {"unlink", "unlinkat"}),
    "rename": ("touch {cov}/{t} && mv {cov}/{t} {cov}/{t}.moved", "KM cov rename", "{t}",
               {"rename", "renameat", "renameat2"}),
    "mkdir": ("mkdir {cov}/{t}", "KM cov mkdir", "{t}", {"mkdir", "mkdirat"}),
    "chmod": ("touch {cov}/{t} && chmod 600 {cov}/{t}", "KM cov chmod", "{t}",
              {"chmod", "fchmod", "fchmodat"}),
    "symlink": ("ln -s /etc/hostname {cov}/{t}", "KM cov symlink", "{t}", {"symlink", "symlinkat"}),
    "tcp_listen": ("{py} {cov}/kmcov.py tcp %d" % PORT, "KM cov listen", None, {"listen"}),
    "tcp_connect": ("{py} {cov}/kmcov.py tcp %d" % (PORT + 1), "KM cov connect", str(PORT + 1),
                    {"connect"}),
    "tcp_accept": ("{py} {cov}/kmcov.py tcp %d" % (PORT + 2), "KM cov accept", str(PORT + 2),
                   {"accept", "accept4"}),
    "udp_sendto": ("{py} {cov}/kmcov.py udp %d" % (PORT + 3), "KM cov udp send", str(PORT + 3),
                   {"sendto", "sendmsg"}),
    "setuid": ("{py} {cov}/kmcov.py setuid", "KM cov setuid", None, {"setuid", "setresuid"}),
    "memfd_create": ("{py} {cov}/kmcov.py memfd", "KM cov memfd", "km-cov-memfd", {"memfd_create"}),
    "mount": ("mkdir -p {cov}/mnt && mount -t tmpfs km-cov {cov}/mnt && umount {cov}/mnt",
              "KM cov mount", "km-cov", {"mount"}),
}


@pytest.mark.parametrize("name", list(SYSCALLS))
def test_syscall(sensor, python, measure, name):
    script, rule, contains, evt_types = SYSCALLS[name]
    t = token()
    alert = sensor.trigger(fill(script, t, python), rule, contains=fill(contains, t, python))
    assert alert is not None, (f"no {rule!r} alert within {sensor.alert_timeout}s: the driver did "
                               f"not deliver {name}, or delivered it without the arguments")
    evt_type = (alert.get("output_fields") or {}).get("evt.type")
    measure("evt_type", evt_type)
    assert evt_type in evt_types, f"{name} arrived as evt.type={evt_type}, expected one of {evt_types}"

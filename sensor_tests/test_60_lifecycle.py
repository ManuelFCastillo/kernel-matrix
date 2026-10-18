"""
Everything after install day, in the order a host lives it. Runs last: the
final tests remove the package.

  restart              new PID, comes back on the same driver, detects
  hot reload           a rules file dropped into rules.d is live without a
                       restart (watch_config_files), same PID
  SIGHUP               reloads in place, same PID, detects
  bad rules push       a broken rules file, then the fix: the sensor must
                       be detecting again with no human running systemctl
  reboot               enabled unit starts on boot, driver back, detects
  downgrade            to upgrade_from (N-1): configures, starts, detects
  upgrade back         to the version under test again
  remove               no process, no module, no binary, no running unit
  purge / leftovers    no units, enable symlinks, dkms trees or /etc/falco

Each package step's full output is kept in evidence/lifecycle-<step>.log.
"""

from __future__ import annotations

import time

import pytest

import qualify
from guest import ASSETS, COV_DIR, COV_RULES, DROPIN, pkg_commands, scriptlet_failed, token


def keep_log(km, step: str, proc) -> str:
    out = f"$ exit {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    (km["results"] / "evidence" / f"lifecycle-{step}.log").write_text(out)
    return out


def driver_present(guest, sensor) -> bool:
    if guest.sh("test -d /sys/module/falco").returncode == 0:
        return True
    pid = sensor.pid()
    return pid > 0 and int(guest.out(f"ls -l /proc/{pid}/fd 2>/dev/null | grep -c 'anon_inode:bpf-prog' || true")
                           or 0) > 0


# ---------------------------------------------------------------------------
# Running sensor
# ---------------------------------------------------------------------------
def test_restart(guest, sensor):
    old = sensor.pid()
    new = sensor.restart()
    assert new and new != old, f"restart did not produce a new process ({old} -> {new})"
    assert driver_present(guest, sensor), "driver not loaded after restart"
    assert sensor.marker() is not None, "not detecting after restart"


def test_hot_reload_rules(guest, sensor):
    """watch_config_files: a new rules file is live without a restart."""
    t = token()
    path = f"/var/tmp/km-reload-{t}"              # outside /tmp/km-cov: no coverage rule shadows it
    rule = f"KM reload {t}"
    pid = sensor.pid()
    guest.write(f"/etc/falco/rules.d/km_reload_{t}.yaml",
                f"- rule: {rule}\n  desc: hot reload test\n"
                f"  condition: open_read and fd.name = \"{path}\"\n"
                f"  output: km reload | file=%fd.name\n  priority: NOTICE\n  tags: [km_coverage]\n")
    guest.sh(f"echo x > {path}")
    try:
        alert = sensor.trigger(f"cat {path} > /dev/null", rule, timeout=60, retry=True)
        assert alert is not None, "a new rules file in rules.d did not go live within 60s"
        assert sensor.wait_running(timeout=30), "Falco not running after the hot reload"
        assert sensor.pid() == pid, "the hot reload restarted the process instead of reloading in place"
    finally:
        guest.sh(f"rm -f /etc/falco/rules.d/km_reload_{t}.yaml {path}")
    time.sleep(5)                                 # let the removal's reload settle


def test_sighup_reload(guest, sensor):
    pid = sensor.pid()
    guest.sh(f"kill -HUP {pid}", check=True)
    time.sleep(5)
    assert sensor.wait_running(timeout=60), "Falco not running after SIGHUP"
    assert sensor.pid() == pid, "SIGHUP restarted the process instead of reloading in place"
    assert sensor.marker() is not None, "not detecting after SIGHUP"


def test_bad_rules_push_recovers(guest, sensor, measure):
    """
    A config management run pushes a broken rules file, notices, and pushes
    the fix. Whether Falco keeps the old rules or exits on the bad one is
    recorded, not judged; what is judged is that after the fix it is
    detecting again with nobody touching systemctl (a unit that hit its
    start limit while the bad file was in place would stay dead).
    """
    bad = "/etc/falco/rules.d/km_broken.yaml"
    guest.write(bad, "- rule: KM broken\n  condition: evt.type = not_a_syscall and\n")
    time.sleep(20)
    measure("running_with_bad_rules", bool(sensor.running_unit()))
    guest.sh(f"rm -f {bad}")
    deadline = time.time() + 120
    while time.time() < deadline and not sensor.wait_running(timeout=10):
        pass
    assert sensor.unit and sensor.running_unit(), (
        "Falco did not recover after the broken rules file was removed: "
        + guest.sh("systemctl status 'falco*' --no-pager -n 0 2>&1 | head -30").stdout)
    assert sensor.marker(timeout=60) is not None, "not detecting after recovering from a bad rules push"


def test_reboot(guest, sensor, measure):
    unit = sensor.unit
    guest.reboot()
    assert sensor.wait_running(timeout=240), f"no Falco engine running after reboot (was {unit})"
    measure("unit_after_reboot", sensor.unit)
    assert sensor.unit == unit, f"came back as {sensor.unit}, was {unit}: driver selection changed"
    assert driver_present(guest, sensor), "driver not loaded after reboot"
    guest.put(ASSETS / "kmcov.py", f"{COV_DIR}/kmcov.py")     # /tmp may be cleared on boot
    assert sensor.marker(timeout=60) is not None, "not detecting after reboot"


# ---------------------------------------------------------------------------
# Package transitions
# ---------------------------------------------------------------------------
def fetch_pkg(km, guest, version: str) -> str:
    url = qualify.package_url(km["qual"]["download"], version, guest.fmt)
    path = f"/var/tmp/km-pkg-{version}.{guest.fmt}"
    guest.sh(f"test -s {path} || curl -fsSL --retry 3 -o {path} '{url}'", timeout=600, check=True)
    return path


def installed(guest) -> tuple[str, str]:
    if guest.fmt == "deb":
        out = guest.sh("dpkg-query -W -f='${Status}|${Version}' falco 2>/dev/null").stdout
    else:
        out = guest.sh("rpm -q --qf 'installed|%{VERSION}-%{RELEASE}' falco 2>/dev/null").stdout
    state, _, version = out.partition("|")
    return state or "absent", version


def assert_transition(km, guest, sensor, step: str, command: str, want_version: str) -> None:
    proc = guest.sh(command, timeout=1500)
    out = keep_log(km, step, proc)
    state, version = installed(guest)
    assert proc.returncode == 0, f"{step}: package manager exited {proc.returncode}: {out[-800:]}"
    assert not scriptlet_failed(out), f"{step}: a maintainer script failed: {out[-800:]}"
    assert state in ("install ok installed", "installed"), f"{step}: package state {state!r}"
    assert qualify.version_matches(version, want_version), f"{step}: installed {version}, wanted {want_version}"
    assert sensor.wait_running(timeout=120), f"{step}: no Falco engine running afterwards"
    assert driver_present(guest, sensor), f"{step}: driver not loaded afterwards"
    assert sensor.marker(timeout=60) is not None, f"{step}: not detecting afterwards"


@pytest.fixture(scope="module")
def n_minus_1(km) -> str:
    base = str(km["qual"]["upgrade_from"])
    if qualify.version_key(base) >= qualify.version_key(km["version"]):
        pytest.skip(f"upgrade_from {base} is not older than {km['version']}")
    return base


def test_downgrade(km, guest, sensor, n_minus_1):
    path = fetch_pkg(km, guest, n_minus_1)
    assert_transition(km, guest, sensor, "downgrade",
                      pkg_commands(guest.fmt)["downgrade"].format(file=path), n_minus_1)


def test_upgrade_back(km, guest, sensor, n_minus_1):
    if installed(guest)[1] and qualify.version_matches(installed(guest)[1], km["version"]):
        pytest.skip("still on the version under test (the downgrade did not happen)")
    path = fetch_pkg(km, guest, km["version"])
    assert_transition(km, guest, sensor, "upgrade-back",
                      pkg_commands(guest.fmt)["install"].format(file=path), km["version"])


def test_remove(km, guest, sensor):
    proc = guest.sh(pkg_commands(guest.fmt)["remove"], timeout=900)
    out = keep_log(km, "remove", proc)
    assert proc.returncode == 0, f"remove exited {proc.returncode}: {out[-800:]}"
    assert not scriptlet_failed(out), f"a removal script failed: {out[-800:]}"
    time.sleep(5)
    problems = []
    if guest.sh("pgrep -x falco").returncode == 0:
        problems.append("a falco process is still running")
    if sensor.running_unit():
        problems.append(f"{sensor.running_unit()} still running")
    if guest.sh("test -d /sys/module/falco").returncode == 0:
        problems.append("the falco kernel module is still loaded")
    if guest.sh("test -e /usr/bin/falco").returncode == 0:
        problems.append("/usr/bin/falco still exists")
    assert not problems, "; ".join(problems)


def test_purge_leaves_nothing(km, guest, measure):
    # Only the package's own leftovers count: take ours out first.
    guest.sh(f"rm -f {DROPIN} {COV_RULES} /etc/falco/rules.d/km_*.yaml "
             "/etc/falco/config.d/zz-km-*.yaml")
    if guest.fmt == "deb":
        proc = guest.sh(pkg_commands("deb")["purge"], timeout=900)
        out = keep_log(km, "purge", proc)
        assert proc.returncode == 0, f"purge exited {proc.returncode}: {out[-800:]}"
        assert not scriptlet_failed(out), f"a purge script failed: {out[-800:]}"
    guest.sh("systemctl daemon-reload")

    leftovers = {
        "unit_files": guest.sh("systemctl list-unit-files 'falco*' --no-legend 2>/dev/null").stdout.strip(),
        "enable_links": guest.sh("find /etc/systemd/system -name 'falco*' 2>/dev/null").stdout.strip(),
        "dkms": guest.sh("dkms status 2>/dev/null | grep -i falco; ls -d /var/lib/dkms/falco 2>/dev/null")
                     .stdout.strip(),
        "etc_falco": guest.sh("find /etc/falco /etc/falcoctl -type f ! -name '*.rpmsave' 2>/dev/null")
                          .stdout.strip(),
        # Recorded, not gated: driver downloads falcoctl caches outside the
        # package's file list.
        "driver_cache": guest.sh("ls -d /root/.falco /usr/src/falco-* 2>/dev/null").stdout.strip(),
    }
    measure("leftovers", leftovers)
    gated = {k: v for k, v in leftovers.items() if v and k != "driver_cache"}
    assert not gated, f"left behind after {'purge' if guest.fmt == 'deb' else 'remove'}: {gated}"

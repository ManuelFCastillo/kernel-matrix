"""
guest.py -- talk to the VM under test and to the Falco running in it.

Two layers:

  pure helpers   parse alerts, metrics and rules; build package commands;
                 judge growth. No VM, so tests/test_sensor_guest.py covers
                 them in the unit-test stage before any VM boots.
  Guest          ssh/scp into one VM, as root, with keepalives so a guest
                 that panics fails a test instead of hanging the build.
  Sensor         the Falco on that guest: which unit runs it, its PID, and
                 "did this alert arrive" read from the JSON file output.

Every alert check reads the JSON file output from a byte offset taken
BEFORE the trigger, so an alert from an earlier test can never satisfy a
later one.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import provision
from provision import Distro, log

EVENTS_FILE = "/var/log/km-falco-events.json"
METRICS_FILE = "/var/log/km-falco-metrics.json"
COV_DIR = "/tmp/km-cov"                 # every coverage trigger lives under here
DROPIN = "/etc/falco/config.d/zz-km-sensor.yaml"
COV_RULES = "/etc/falco/rules.d/km_coverage_rules.yaml"
ASSETS = Path(__file__).resolve().parent / "assets"

# ServerAlive: an ssh to a guest that panicked otherwise waits forever.
SSH_OPTS = [*provision.SSH_OPTS, "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
            "-o", "BatchMode=yes"]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def token(prefix: str = "km") -> str:
    """A string no other event on the guest will contain."""
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def parse_json_lines(text: str) -> list[dict]:
    """
    One JSON object per line. The last line may be half written when the file
    is read mid-flush; anything that does not parse is skipped, not fatal.
    """
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def alert_matches(alert: dict, rules: tuple[str, ...] | list[str] | str,
                  contains: str | None = None, fields: dict | None = None) -> bool:
    """rule is one of `rules`; `contains` appears in the output line or any
    output field; every key in `fields` has that exact value."""
    if isinstance(rules, str):
        rules = (rules,)
    if alert.get("rule") not in rules:
        return False
    of = alert.get("output_fields") or {}
    if contains is not None:
        hay = (alert.get("output") or "") + " " + " ".join(str(v) for v in of.values())
        if contains not in hay:
            return False
    for k, v in (fields or {}).items():
        if of.get(k) != v:
            return False
    return True


def shipped_rule_names(rules_yaml: str) -> list[str]:
    """Rule names in a Falco rules file, in file order, without a YAML parser
    on the guest: '- rule: <name>' at column 0 is the only form Falco ships."""
    names = []
    for line in rules_yaml.splitlines():
        if line.startswith("- rule:"):
            names.append(line[len("- rule:"):].strip().strip("'\""))
    return names


def metric(snapshot: dict, *names: str):
    """
    First of `names` present in a metrics snapshot. Falco has renamed metric
    keys between releases (n_drops vs n_drops_buffer_total, with or without
    a scap./falco. prefix), so callers ask for every spelling they accept.
    A snapshot is either the output_file form {"output_fields": {...}} or
    the fields themselves.
    """
    fields = snapshot.get("output_fields", snapshot)
    for n in names:
        if n in fields and fields[n] is not None:
            return fields[n]
    return None


EVENTS_KEYS = ("scap.n_evts", "falco.n_evts", "n_evts")
DROPS_KEYS = ("scap.n_drops", "falco.n_drops", "n_drops")


def drop_ratio(before: dict, after: dict) -> tuple[float | None, int | None, int | None]:
    """(drops/events, events, drops) between two cumulative snapshots."""
    e0, e1 = metric(before, *EVENTS_KEYS), metric(after, *EVENTS_KEYS)
    d0, d1 = metric(before, *DROPS_KEYS), metric(after, *DROPS_KEYS)
    if None in (e0, e1, d0, d1):
        return None, None, None
    events, drops = int(e1) - int(e0), int(d1) - int(d0)
    return (drops / events if events > 0 else 0.0), events, drops


def growth_mb(samples_kb: list[int]) -> float:
    """Mean RSS of the last third minus the first third, in MB. Robust to the
    single spikes a regex compile or a rules reload produces; a leak moves
    the whole tail."""
    if len(samples_kb) < 3:
        return 0.0
    third = len(samples_kb) // 3
    first = sum(samples_kb[:third]) / third
    last = sum(samples_kb[-third:]) / third
    return round((last - first) / 1024, 1)


def pkg_commands(fmt: str) -> dict[str, str]:
    """
    Package-manager commands for the lifecycle tests, keyed by action. {file}
    is a local package file. Same frontend variables as falco_probe.sh, so
    no maintainer script ever waits on a dialog.
    """
    env = "FALCO_FRONTEND=noninteractive DEBIAN_FRONTEND=noninteractive"
    if fmt == "deb":
        apt = (f"env {env} apt-get -y -o Dpkg::Options::=--force-confdef "
               f"-o Dpkg::Options::=--force-confold")
        return {"downgrade": f"{apt} install --allow-downgrades {{file}}",
                "install": f"{apt} install {{file}}",
                "remove": f"{apt} remove falco",
                "purge": f"{apt} purge falco"}
    if fmt == "rpm":
        dnf = f"env {env} $(command -v dnf || command -v yum) -y"
        return {"downgrade": f"{dnf} downgrade {{file}}",
                "install": f"{dnf} install {{file}}",
                "remove": f"{dnf} remove falco",
                "purge": f"{dnf} remove falco"}
    raise ValueError(f"unknown package format {fmt!r}")


SCRIPTLET_FAILED = ("returned error exit status", "scriptlet failed", "scriptlet failure",
                    "error in prein scriptlet", "error in postin scriptlet",
                    "error in preun scriptlet", "error in postun scriptlet")


def scriptlet_failed(output: str) -> bool:
    """rpm and dnf exit 0 on a failed %post; only the text says so."""
    low = output.lower()
    return any(s in low for s in SCRIPTLET_FAILED)


# ---------------------------------------------------------------------------
# One VM
# ---------------------------------------------------------------------------
@dataclass
class Guest:
    distro: Distro
    ip: str
    vm_name: str

    @property
    def fmt(self) -> str:
        return "deb" if self.distro.os_name.startswith(("ubuntu", "debian")) else "rpm"

    def _target(self) -> str:
        return f"{self.distro.ssh_user}@{self.ip}"

    def sh(self, script: str, timeout: int = 120, check: bool = False) -> subprocess.CompletedProcess:
        """Run a bash script as root. stdout/stderr are text."""
        command = f"sudo -n bash -c {shlex.quote(script)}"
        try:
            proc = subprocess.run(["ssh", *SSH_OPTS, "-i", str(provision.SSH_KEY), self._target(), command],
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"guest command timed out after {timeout}s: {script[:200]}") from exc
        if check and proc.returncode != 0:
            raise AssertionError(f"guest command failed ({proc.returncode}): {script[:200]}\n"
                                 f"{(proc.stdout + proc.stderr)[-1500:]}")
        return proc

    def out(self, script: str, timeout: int = 120) -> str:
        return self.sh(script, timeout=timeout, check=True).stdout.strip()

    def put(self, local: Path, remote: str, mode: str = "0644") -> None:
        """Upload through /tmp then install as root, so remote can be anywhere."""
        tmp = f"/tmp/km-upload-{uuid.uuid4().hex[:8]}"
        up = subprocess.run(["scp", *SSH_OPTS, "-i", str(provision.SSH_KEY), str(local),
                             f"{self._target()}:{tmp}"], capture_output=True, text=True, timeout=300)
        if up.returncode != 0:
            raise AssertionError(f"scp {local} failed: {up.stderr.strip()[:300]}")
        self.sh(f"install -D -m {mode} {tmp} {shlex.quote(remote)} && rm -f {tmp}", check=True)

    def write(self, remote: str, text: str, mode: str = "0644") -> None:
        """Write a small text file as root. Base64 keeps quoting out of it."""
        import base64
        b64 = base64.b64encode(text.encode()).decode()
        self.sh(f"mkdir -p $(dirname {shlex.quote(remote)}) && echo {b64} | base64 -d > "
                f"{shlex.quote(remote)} && chmod {mode} {shlex.quote(remote)}", check=True)

    def fetch(self, remote: str, local: Path) -> bool:
        """Copy a guest file to the host. Root-only files go through a copy."""
        local.parent.mkdir(parents=True, exist_ok=True)
        tmp = f"/tmp/km-fetch-{uuid.uuid4().hex[:8]}"
        r = self.sh(f"cp {shlex.quote(remote)} {tmp} 2>/dev/null && chmod 0644 {tmp}")
        if r.returncode != 0:
            return False
        got = subprocess.run(["scp", *SSH_OPTS, "-i", str(provision.SSH_KEY),
                              f"{self._target()}:{tmp}", str(local)],
                             capture_output=True, text=True, timeout=300)
        self.sh(f"rm -f {tmp}")
        return got.returncode == 0

    def reboot(self) -> None:
        """Reboot and wait for the NEW boot (boot_id changes). The address may move."""
        ip, problem = provision.reboot_guest(self.distro, self.ip, self.vm_name)
        self.ip = ip
        if problem:
            raise AssertionError(problem)

    def python(self) -> str:
        """An interpreter that exists: Rocky 8 has only platform-python."""
        return self.out("command -v python3 || ls /usr/libexec/platform-python")


# ---------------------------------------------------------------------------
# The Falco on that VM
# ---------------------------------------------------------------------------
ENGINE_UNITS = ("falco-modern-bpf.service", "falco-bpf.service", "falco-kmod.service",
                "falco-custom.service", "falco.service")


@dataclass
class Sensor:
    guest: Guest
    alert_timeout: int = 30
    unit: str = ""
    seen: list[dict] = field(default_factory=list)   # every alert read, for evidence

    def running_unit(self) -> str:
        """The engine unit that is running (not falcoctl, not the kmod-inject oneshot)."""
        out = self.guest.sh("systemctl list-units 'falco*' --state=active --plain --no-legend").stdout
        for line in out.splitlines():
            cols = line.split()
            if len(cols) >= 4 and cols[3] == "running" and cols[0] in ENGINE_UNITS:
                return cols[0]
        return ""

    def wait_running(self, timeout: int = 90, stable: int = 3) -> str:
        """Same rule as the probe: running for `stable` consecutive 1s samples,
        so a crash loop caught mid-restart does not count as up."""
        deadline, streak, unit = time.time() + timeout, 0, ""
        while time.time() < deadline:
            now = self.running_unit()
            streak = streak + 1 if now and now == unit else (1 if now else 0)
            unit = now
            if streak >= stable:
                self.unit = unit
                return unit
            time.sleep(1)
        return ""

    def pid(self) -> int:
        if not self.unit:
            return 0
        return int(self.guest.out(f"systemctl show -p MainPID --value {self.unit}") or 0)

    def nrestarts(self) -> int:
        if not self.unit:
            return 0
        v = self.guest.sh(f"systemctl show -p NRestarts --value {self.unit}").stdout.strip()
        return int(v) if v.isdigit() else 0

    def restart(self) -> int:
        """systemctl restart, then wait for a stable engine. Returns the new PID."""
        self.guest.sh(f"systemctl restart {self.unit}", timeout=180, check=True)
        assert self.wait_running(), f"{self.unit} did not come back after restart"
        return self.pid()

    # --- alerts ------------------------------------------------------------
    def offset(self) -> int:
        """Current size of the events file: read alerts after this point."""
        v = self.guest.sh(f"stat -c %s {EVENTS_FILE} 2>/dev/null || echo 0").stdout.strip()
        return int(v or 0)

    def alerts_since(self, offset: int) -> list[dict]:
        text = self.guest.sh(f"tail -c +{offset + 1} {EVENTS_FILE} 2>/dev/null", timeout=120).stdout
        alerts = parse_json_lines(text)
        self.seen.extend(alerts)
        return alerts

    def wait_alert(self, offset: int, rules, contains: str | None = None,
                   fields: dict | None = None, timeout: int | None = None,
                   retrigger: str | None = None) -> dict | None:
        """
        The first alert after `offset` that matches. `retrigger` is re-run
        every 5s while waiting: a probe that is still attaching after a
        restart can miss the first event, and that is not what a detection
        test is asking about.
        """
        deadline = time.time() + (timeout or self.alert_timeout)
        last_retrigger = time.time()
        while time.time() < deadline:
            for a in self.alerts_since(offset):
                if alert_matches(a, rules, contains, fields):
                    return a
            if retrigger and time.time() - last_retrigger > 5:
                self.guest.sh(retrigger)
                last_retrigger = time.time()
            time.sleep(1)
        return None

    def trigger(self, script: str, rules, contains: str | None = None,
                fields: dict | None = None, timeout: int | None = None,
                retry: bool = False) -> dict | None:
        """Run `script` on the guest and return the alert it caused, or None."""
        off = self.offset()
        self.guest.sh(script, timeout=120)
        return self.wait_alert(off, rules, contains, fields, timeout,
                               retrigger=script if retry else None)

    def marker(self, timeout: int | None = None) -> dict | None:
        """A coverage-rule read of a fresh file: the cheapest end-to-end
        'is it still detecting' probe, with no default-rule exclusions in play."""
        t = token("mark")
        script = f"mkdir -p {COV_DIR} && echo x > {COV_DIR}/{t} && cat {COV_DIR}/{t} >/dev/null"
        return self.trigger(script, "KM cov open read", contains=t, timeout=timeout, retry=True)

    # --- cost ----------------------------------------------------------------
    def rss_kb(self) -> int:
        pid = self.pid()
        v = self.guest.sh(f"awk '/^VmRSS:/ {{print $2}}' /proc/{pid}/status 2>/dev/null").stdout.strip()
        return int(v or 0)

    def cpu_percent(self, seconds: int) -> float:
        """Falco's CPU over a measured window from /proc/<pid>/stat, in % of one core."""
        pid = self.pid()
        out = self.guest.out(
            f"hz=$(getconf CLK_TCK); a=$(awk '{{print $14+$15}}' /proc/{pid}/stat); "
            f"sleep {seconds}; b=$(awk '{{print $14+$15}}' /proc/{pid}/stat); "
            f"echo $a $b $hz", timeout=seconds + 60)
        a, b, hz = (float(x) for x in out.split())
        return round((b - a) / hz / seconds * 100, 2)

    def metrics_snapshots(self) -> list[dict]:
        return parse_json_lines(self.guest.sh(f"cat {METRICS_FILE} 2>/dev/null", timeout=120).stdout)

    def latest_metrics(self, newer_than: float = 0, timeout: int = 30) -> dict | None:
        """The newest metrics snapshot written after `newer_than` (guest epoch s)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            snaps = self.metrics_snapshots()
            if snaps:
                last = snaps[-1]
                ts = _snapshot_epoch(last)
                if ts is None or ts > newer_than:
                    return last
            time.sleep(2)
        return None

    def guest_now(self) -> float:
        return float(self.guest.out("date +%s.%N"))


def _snapshot_epoch(snap: dict) -> float | None:
    """Metrics snapshots carry evt.time in ns, or an ISO 'time'."""
    of = snap.get("output_fields", {})
    for k in ("evt.time", "evt.rawtime"):
        if k in of:
            try:
                return int(of[k]) / 1e9
            except (TypeError, ValueError):
                pass
    t = snap.get("time")
    if isinstance(t, str) and len(t) >= 19:
        import calendar
        try:
            # 2026-10-18T12:34:56.123456789Z: Falco prints nanoseconds,
            # which fromisoformat rejects; whole seconds are enough here.
            return float(calendar.timegm(time.strptime(t[:19], "%Y-%m-%dT%H:%M:%S")))
        except ValueError:
            return None
    return None


def log_step(msg: str) -> None:
    log(f"[sensor] {msg}")

"""
Unit tests for package qualification: qualify.py's plan and verdicts, the
kernel-variant step in provision.py, and the strict-mode shell helpers in
falco_probe.sh.

The VMs prove the grid; these prove the code that turns a probe's JSON into
a cell's colour. A wrong rule here paints a broken package green on every
row at once, which is the failure a qualification matrix exists to prevent.
"""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import provision
import qualify
from provision import CheckResult, Distro, RunResult

PROBE = ROOT / "falco_probe.sh"
DL = "https://download.falco.org/packages"


def distro(name="ubuntu-20.04", expect="5.4", **kw):
    return Distro(name=name, image_url="http://x/img", ssh_user="ubuntu",
                  expect_kernel=expect, **kw)


HWE = distro("ubuntu-20.04-hwe", "5.15", base="ubuntu-20.04", os="ubuntu-20.04",
             kernel_variant="hwe", kernel_packages=["linux-generic-hwe-20.04"])
FRESH_AUTO = qualify.Scenario("fresh-auto", "auto")
FRESH_EBPF = qualify.Scenario("fresh-modern_ebpf", "modern_ebpf")
UPGRADE = qualify.Scenario("upgrade", "", upgrade=True)


# ---------------------------------------------------------------------------
# package URLs: stable vs dev channel
# ---------------------------------------------------------------------------

def test_stable_urls():
    assert qualify.package_url(DL, "0.45.0", "deb") == f"{DL}/deb/stable/falco-0.45.0-x86_64.deb"
    assert qualify.package_url(DL, "0.45.0", "rpm") == f"{DL}/rpm/falco-0.45.0-x86_64.rpm"


def test_release_candidates_come_from_the_dev_repo():
    # 0.45.0-rc3/rc4 sat in the dev repo days before GA. Resolving them to
    # the stable path would 404 and quietly test nothing.
    assert qualify.channel("0.45.1-rc1") == "dev"
    assert qualify.package_url(DL, "0.45.1-rc1", "deb") == \
        f"{DL}/deb-dev/stable/falco-0.45.1-rc1-x86_64.deb"
    assert qualify.package_url(DL, "0.45.1-rc1", "rpm") == f"{DL}/rpm-dev/falco-0.45.1-rc1-x86_64.rpm"


def test_dev_build_plus_is_escaped():
    # S3 decodes a raw '+' in a path as a space.
    url = qualify.package_url(DL, "0.46.0-44+066991c", "deb")
    assert "%2B066991c" in url and "+" not in url
    assert qualify.channel("0.46.0-44+066991c") == "dev"


def test_release_candidates_sort_before_their_release():
    order = ["0.44.1", "0.45.0-rc3", "0.45.0-rc4", "0.45.0", "0.45.1-rc1", "0.45.1"]
    assert sorted(reversed(order), key=qualify.version_key) == order


def test_package_format_follows_the_release_not_the_entry_name():
    assert qualify.package_format(HWE) == "deb"
    assert qualify.package_format(distro("rocky-8", "4.18")) == "rpm"


# ---------------------------------------------------------------------------
# plan and naming
# ---------------------------------------------------------------------------

def test_cell_name_puts_a_variant_under_its_release():
    assert qualify.cell_name(distro(), "fresh-auto") == "ubuntu-20.04--5.4--fresh-auto"
    assert qualify.cell_name(HWE, "fresh-auto") == "ubuntu-20.04--5.15-hwe--fresh-auto"


def test_probe_env_fresh_install():
    env = qualify.probe_env(qualify.Cell("0.45.0", distro(), FRESH_AUTO), DL, "0.44.1")
    assert env == {"KM_PKG_URL": f"{DL}/deb/stable/falco-0.45.0-x86_64.deb",
                   "KM_DRIVER_CHOICE": "auto"}


def test_probe_env_upgrade_installs_n_minus_1_and_asks_no_driver_question():
    env = qualify.probe_env(qualify.Cell("0.45.1-rc1", distro("rocky-8", "4.18"), UPGRADE),
                            DL, "0.44.1")
    assert env["KM_BASE_PKG_URL"] == f"{DL}/rpm/falco-0.44.1-x86_64.rpm"
    assert env["KM_PKG_URL"].endswith("rpm-dev/falco-0.45.1-rc1-x86_64.rpm")
    assert "KM_DRIVER_CHOICE" not in env


def test_shipped_qualification_file_plans_against_the_shipped_matrix():
    qual = qualify.load_qualification(ROOT / "qualification.yaml")
    distros = {d.name: d for d in provision.load_matrix(ROOT / "matrix.yaml")[0]}
    cells = qualify.plan(qual, distros, ["0.45.0"], qual["targets"], [s.id for s in qual["scenarios"]])
    assert len(cells) == len(qual["targets"]) * len(qual["scenarios"])
    names = {c.name for c in cells}
    assert len(names) == len(cells), "two cells would write the same result file"
    assert "ubuntu-20.04--5.15-hwe--upgrade" in names


def test_plan_rejects_unknown_target_and_scenario():
    qual = qualify.load_qualification(ROOT / "qualification.yaml")
    with pytest.raises(ValueError, match="not in matrix.yaml"):
        qualify.plan(qual, {}, ["0.45.0"], ["nope-1"], ["fresh-auto"])
    with pytest.raises(ValueError, match="unknown scenario"):
        qualify.plan(qual, {"ubuntu-20.04": distro()}, ["0.45.0"], ["ubuntu-20.04"], ["sideways"])


# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------

def probe(**kw):
    """A healthy strict-mode probe result; override what a test breaks."""
    base = dict(installed=True, started=True, detected=True, driver="kmod",
                rule_matched="Read sensitive file untrusted", strict=True,
                pkg_exit=0, pkg_state="install ok installed", pkg_version="0.45.0",
                scriptlet_failed=False, base_exit=-1, base_state="", kmod_loaded=True,
                bpf_prog_fds=0, active_unit="falco-kmod.service", error="")
    base.update(kw)
    return base


def host_checks(kernel_ok=True, btf=False):
    return [
        CheckResult("kernel_version_matches_expectation", kernel_ok, 0.1,
                    message="kernel 5.4.0-216-generic" if kernel_ok else "expected '5.15', got '5.4.0'"),
        CheckResult("btf_available", True, 0.1, skipped=not btf),
    ]


def record(scenario=FRESH_AUTO, version="0.45.0", d=None, kernel="5.4.0-216-generic",
           btf=False, kernel_ok=True, vm_error=None, **falco):
    r = RunResult(distro=(d or distro()).name, kernel=kernel, error=vm_error,
                  checks=host_checks(kernel_ok, btf), falco=None if vm_error else probe(**falco))
    cell = qualify.Cell(version, d or distro(), scenario)
    env = qualify.probe_env(cell, DL, "0.44.1")
    return qualify.cell_record(cell, r, env, "0.44.1", 0.0, 1.0)


def test_healthy_cell_passes():
    rec = record()
    assert rec["status"] == "pass", rec["reason"]
    assert [c["name"] for c in rec["checks"]] == list(qualify.CHECK_NAMES)


def test_half_configured_package_fails_even_though_files_are_on_disk():
    # falco#3994 on Ubuntu 20.04: postinst dies, dpkg exits 100, the package
    # is "half-configured", and no unit was ever started.
    rec = record(installed=False, started=False, detected=False, pkg_exit=100,
                 pkg_state="install ok half-configured", kmod_loaded=False, active_unit="")
    assert rec["status"] == "fail"
    assert rec["reason"].startswith("pkg_installed: exit 100, install ok half-configured")


def test_rpm_scriptlet_failure_fails_despite_exit_zero():
    # dnf reports a failed %post as a warning and exits 0.
    rec = record(d=distro("rocky-8", "4.18"), pkg_version="0.45.0-1", pkg_state="installed",
                 scriptlet_failed=True)
    assert rec["status"] == "fail"
    assert "maintainer script failed" in rec["reason"]


def test_wrong_version_installed_fails():
    rec = record(version="0.45.1-rc1", pkg_version="0.45.0")
    assert rec["status"] == "fail" and "version 0.45.0" in rec["reason"]


def test_rpm_rc_versions_match():
    # Seen on rocky-8: rpm cannot carry '-' in a version, so rc1 is '0.45.1_rc1'.
    assert qualify.version_matches("0.45.1_rc1-1", "0.45.1-rc1")
    assert qualify.version_matches("0.45.1~rc1-1", "0.45.1-rc1")
    assert qualify.version_matches("0.45.0-1", "0.45.0")
    assert not qualify.version_matches("0.44.1", "0.45.0")


def test_running_without_any_driver_evidence_fails_driver_loaded():
    rec = record(kmod_loaded=False, bpf_prog_fds=0)
    assert rec["status"] == "fail" and rec["reason"].startswith("driver_loaded")


def test_modern_ebpf_unsupported_kernel_with_clean_package_is_not_a_failure():
    rec = record(scenario=FRESH_EBPF, started=False, detected=False, kmod_loaded=False,
                 active_unit="", driver="none")
    assert rec["status"] == "unsupported"
    assert rec["modern_ebpf_capable"] is False


def test_modern_ebpf_unsupported_kernel_with_broken_package_still_fails():
    # The kernel excuses the service, never the package manager.
    rec = record(scenario=FRESH_EBPF, started=False, detected=False, kmod_loaded=False,
                 pkg_exit=100, pkg_state="install ok half-configured")
    assert rec["status"] == "fail"


def test_modern_ebpf_on_capable_kernel_must_run():
    rec = record(scenario=FRESH_EBPF, d=HWE, kernel="5.15.0-139-generic", btf=True,
                 started=False, detected=False, kmod_loaded=False)
    assert rec["status"] == "fail"
    assert rec["modern_ebpf_capable"] is True


def test_upgrade_blocked_when_n_minus_1_never_installed():
    rec = record(scenario=UPGRADE, d=distro("centos-7", "3.10"), installed=False,
                 base_exit=1, base_state="absent", pkg_exit=-1, pkg_state="",
                 error="baseline (N-1) install did not complete: exit 1, absent")
    assert rec["status"] == "blocked"
    assert rec["package"]["base_url"].endswith("rpm/falco-0.44.1-x86_64.rpm")


def test_upgrade_passes_with_clean_baseline():
    rec = record(scenario=UPGRADE, base_exit=0, base_state="install ok installed",
                 base_version="0.44.1")
    assert rec["status"] == "pass"
    assert rec["scenario"]["upgrade_from"] == "0.44.1"


def test_vm_error_and_wrong_kernel_are_harness_errors():
    assert record(vm_error="VM never acquired an IP within 300s")["status"] == "error"
    rec = record(d=HWE, kernel="5.4.0-216-generic", kernel_ok=False)
    assert rec["status"] == "error" and "wrong kernel" in rec["reason"]


def test_non_strict_probe_output_is_an_error_not_a_pass():
    # A probe that ran without KM_PKG_URL measured the repo's package, not
    # the one under test.
    r = RunResult(distro="ubuntu-20.04", kernel="5.4.0", checks=host_checks(),
                  falco={"installed": True, "started": True, "detected": True})
    cell = qualify.Cell("0.45.0", distro(), FRESH_AUTO)
    rec = qualify.cell_record(cell, r, qualify.probe_env(cell, DL, "0.44.1"), "0.44.1", 0, 1)
    assert rec["status"] == "error"


def test_rejudge_reproduces_a_verdict_from_stored_observations():
    for rec in (record(), record(installed=False, started=False, pkg_exit=100,
                                 pkg_state="install ok half-configured", kmod_loaded=False),
                record(scenario=UPGRADE, base_exit=1, base_state="absent", pkg_exit=-1),
                record(scenario=FRESH_EBPF, started=False, detected=False, kmod_loaded=False),
                record(vm_error="SSH never became available")):
        stored = json.loads(json.dumps(rec))
        assert qualify.rejudge(stored) == stored


def test_rejudge_applies_a_fixed_rule():
    # A cell judged by an older rule (here: the rpm '_' version spelling was
    # read as a wrong version) flips when re-derived from the same probe data.
    rec = record(d=distro("rocky-8", "4.18"), version="0.45.1-rc1", pkg_state="installed",
                 pkg_version="0.45.1_rc1-1")
    stale = {**rec, "status": "fail", "reason": "pkg_installed: version 0.45.1_rc1-1"}
    assert qualify.rejudge(stale)["status"] == "pass"


def test_cell_record_links_evidence_and_log_relative_to_version_dir():
    rec = record()
    assert rec["evidence"] == "evidence/ubuntu-20.04--5.4--fresh-auto/manifest.json"
    assert rec["log"] == "logs/ubuntu-20.04--5.4--fresh-auto.log"
    json.dumps(rec)


# ---------------------------------------------------------------------------
# matrix.json and the VM cap
# ---------------------------------------------------------------------------

def test_build_matrix_reads_every_cell(tmp_path):
    for version, d, scenario, falco in [
        ("0.45.0", distro(), FRESH_AUTO, dict(pkg_exit=100, pkg_state="install ok half-configured",
                                               started=False, kmod_loaded=False)),
        ("0.45.0", HWE, FRESH_AUTO, {}),
        ("0.45.1-rc1", distro(), FRESH_AUTO, {}),
    ]:
        kernel = "5.15.0-1-generic" if d is HWE else "5.4.0-1-generic"
        rec = record(scenario=scenario, version=version, d=d, kernel=kernel,
                     pkg_version=version, **falco)
        out = tmp_path / version / f"{rec['cell']}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(rec))
    (tmp_path / "0.45.0" / "notes.json").write_text("{}")      # ignored: not a cell
    m = qualify.build_matrix(tmp_path)
    assert m["axes"]["versions"] == ["0.45.0", "0.45.1-rc1"]
    assert m["axes"]["targets"] == [{"distro": "ubuntu-20.04", "kernel": "5.4"},
                                    {"distro": "ubuntu-20.04", "kernel": "5.15-hwe"}]
    assert m["summary"]["0.45.0"] == {"fail": 1, "pass": 1}
    cell = next(c for c in m["cells"] if c["kernel"] == "5.4" and c["version"] == "0.45.0")
    assert cell["checks"]["pkg_installed"] is False
    assert cell["evidence"] == "0.45.0/evidence/ubuntu-20.04--5.4--fresh-auto/manifest.json"
    text = qualify.grid_text(m)
    assert "ubuntu-20.04--5.4" in text and "FAIL" in text and "PASS" in text


def test_free_slots_counts_vms_other_sessions_started():
    children = {111: object()}
    domains = ["km-ubuntu-20.04-111-42", "km-ubuntu-20.04-999-17"]   # one mine, one foreign
    assert qualify.free_slots(4, children, domains) == 2
    assert qualify.free_slots(4, {}, ["a", "b", "c", "d"]) == 0


# ---------------------------------------------------------------------------
# provision.py: kernel variants
# ---------------------------------------------------------------------------

def test_matrix_loads_the_hwe_variant_on_the_shared_base_image():
    distros = {d.name: d for d in provision.load_matrix(ROOT / "matrix.yaml")[0]}
    hwe = distros["ubuntu-20.04-hwe"]
    assert hwe.base_image == distros["ubuntu-20.04"].base_image
    assert hwe.os_name == "ubuntu-20.04" and hwe.kernel_label == "5.15-hwe"
    assert hwe.kernel_packages == ["linux-generic-hwe-20.04"]
    assert distros["ubuntu-20.04"].kernel_label == "5.4"


def test_kernel_install_command():
    cmd = provision.kernel_install_command(HWE)
    assert "apt-get update" in cmd and cmd.endswith("--no-install-recommends linux-generic-hwe-20.04")
    assert provision.kernel_install_command(distro("rocky-8", "4.18", kernel_packages=["kernel-ml"])) \
        == "sudo dnf install -y -q kernel-ml"


class FakeGuest:
    """ssh_exec stand-in: a guest that reboots onto `after` when told to."""

    def __init__(self, install_rc=0, after="5.15.0-139-generic", reboots=True):
        self.install_rc, self.after, self.reboots = install_rc, after, reboots
        self.boot, self.kernel, self.commands = "boot-1", "5.4.0-216-generic", []

    def __call__(self, ip, user, command, timeout=60):
        self.commands.append(command)
        out, rc = "", 0
        if "apt-get" in command:
            rc, out = self.install_rc, "E: Unable to locate package" if self.install_rc else ""
        elif command == provision.BOOT_ID:
            out = self.boot
        elif "reboot" in command:
            if self.reboots:
                self.boot, self.kernel = "boot-2", self.after
        elif command == "uname -r":
            out = self.kernel
        return SimpleNamespace(returncode=rc, stdout=out + "\n", stderr="")


@pytest.fixture
def guest(monkeypatch):
    def make(**kw):
        g = FakeGuest(**kw)
        monkeypatch.setattr(provision, "ssh_exec", g)
        monkeypatch.setattr(provision, "get_vm_ip", lambda name, timeout: None)
        monkeypatch.setattr(provision.time, "sleep", lambda s: None)
        return g
    return make


def test_kernel_variant_reboots_into_the_new_kernel(guest):
    g = guest()
    ip, err = provision.install_kernel_variant(HWE, "10.0.0.5", "km-x")
    assert err is None and ip == "10.0.0.5"
    assert any("reboot" in c for c in g.commands)


def test_kernel_variant_that_boots_the_old_kernel_is_an_error(guest):
    guest(after="5.4.0-216-generic")
    _, err = provision.install_kernel_variant(HWE, "10.0.0.5", "km-x")
    assert err and "rebooted into '5.4.0-216-generic'" in err


def test_kernel_variant_install_failure_never_reboots(guest):
    g = guest(install_rc=100)
    _, err = provision.install_kernel_variant(HWE, "10.0.0.5", "km-x")
    assert err.startswith("kernel variant install failed")
    assert not any("reboot" in c for c in g.commands)


def test_kernel_variant_reboot_that_never_returns_times_out(guest, monkeypatch):
    guest(reboots=False)
    clock = iter(range(0, 10_000, 50))
    monkeypatch.setattr(provision.time, "time", lambda: next(clock))
    _, err = provision.install_kernel_variant(HWE, "10.0.0.5", "km-x")
    assert "did not come back" in err


class PrereqGuest:
    """A guest whose build_prereqs.sh answers from a script of exit codes."""

    def __init__(self, codes):
        self.codes, self.boot, self.commands = list(codes), 1, []

    def __call__(self, ip, user, command, timeout=60):
        self.commands.append(command)
        if "build_prereqs.sh" in command:
            rc = self.codes.pop(0)
            line = {0: "prereqs: ready for 5.10.0-50-amd64", 10: "prereqs: reboot needed"}.get(
                rc, "prereqs: could not install linux-image-amd64 linux-headers-amd64")
            return SimpleNamespace(returncode=rc, stdout=f"noise\n{line}\n", stderr="")
        if command == provision.BOOT_ID:
            return SimpleNamespace(returncode=0, stdout=f"boot-{self.boot}\n", stderr="")
        if "reboot" in command:
            self.boot += 1
        return SimpleNamespace(returncode=0, stdout="", stderr="")


@pytest.fixture
def prereq_guest(monkeypatch):
    def make(codes):
        g = PrereqGuest(codes)
        monkeypatch.setattr(provision, "ssh_exec", g)
        monkeypatch.setattr(provision.subprocess, "run",
                            lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
        monkeypatch.setattr(provision, "get_vm_ip", lambda name, timeout: None)
        monkeypatch.setattr(provision.time, "sleep", lambda s: None)
        return g
    return make


def test_prereqs_ready_first_time_no_reboot(prereq_guest):
    g = prereq_guest([0])
    _, verdict, err = provision.ensure_build_prereqs(distro("debian-11", "5.10"), "ip", "vm")
    assert err is None and verdict.startswith("prereqs: ready")
    assert not any("reboot" in c for c in g.commands)


def test_prereqs_reboot_onto_archive_kernel_then_ready(prereq_guest):
    # debian-11: the image's kernel has no headers left in the archive.
    g = prereq_guest([10, 0])
    _, verdict, err = provision.ensure_build_prereqs(distro("debian-11", "5.10"), "ip", "vm")
    assert err is None and verdict.startswith("prereqs: ready")
    assert sum("systemctl reboot" in c for c in g.commands) == 1


def test_prereqs_that_cannot_be_met_are_a_harness_error(prereq_guest):
    prereq_guest([1])
    _, _, err = provision.ensure_build_prereqs(distro("centos-7", "3.10"), "ip", "vm")
    assert err.startswith("build prerequisites unavailable")


def test_prereqs_never_reboot_twice(prereq_guest):
    g = prereq_guest([10, 10])
    _, _, err = provision.ensure_build_prereqs(distro("debian-11", "5.10"), "ip", "vm")
    assert err.startswith("build prerequisites unavailable")
    assert sum("systemctl reboot" in c for c in g.commands) == 1


def test_build_prereqs_script_parses():
    assert subprocess.run(["bash", "-n", str(ROOT / "build_prereqs.sh")]).returncode == 0


def test_probe_env_reaches_the_guest_through_sudo(monkeypatch):
    seen = []
    monkeypatch.setattr(provision.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(provision, "ssh_exec", lambda ip, user, cmd, timeout=60: seen.append(cmd)
                        or SimpleNamespace(returncode=0, stdout='{"installed": true}', stderr=""))
    out = provision.run_falco_probe(distro(), "10.0.0.5",
                                    env={"KM_PKG_URL": "https://x/a b.deb", "KM_DRIVER_CHOICE": "kmod"})
    assert out == {"installed": True}
    assert seen == ["sudo env KM_DRIVER_CHOICE=kmod KM_PKG_URL='https://x/a b.deb' "
                    "bash /tmp/falco_probe.sh"]


# ---------------------------------------------------------------------------
# falco_probe.sh strict-mode helpers, run from the probe's own source
# ---------------------------------------------------------------------------

def run_fn(fn: str, body: str) -> subprocess.CompletedProcess:
    script = f"source <(sed -n '/^{fn}()/,/^}}/p' {PROBE}); {body}"
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)


@pytest.mark.parametrize("line", [
    # dpkg 1.20+ (Ubuntu 20.04+, Debian 11+)
    "dpkg: error processing package falco (--configure):\n"
    " installed falco package post-installation script subprocess returned error exit status 1",
    # dpkg 1.19 (Ubuntu 18.04)
    " subprocess installed post-installation script returned error exit status 1",
    # rpm and dnf: warnings, exit 0
    "warning: %post(falco-0.45.0-1.x86_64) scriptlet failed, exit status 1",
    "Non-fatal POSTIN scriptlet failure in rpm package falco-0.45.0-1.x86_64",
    "Error in POSTIN scriptlet in rpm package falco",
])
def test_scriptlet_failure_detected(tmp_path, line):
    log = tmp_path / "step.log"
    log.write_text(f"Setting up falco (0.45.0) ...\n{line}\n")
    assert run_fn("pkg_scriptlet_failed", f"pkg_scriptlet_failed {log}").returncode == 0


def test_clean_install_log_is_not_a_scriptlet_failure(tmp_path):
    log = tmp_path / "step.log"
    log.write_text("Setting up falco (0.45.0) ...\n[POST-INSTALL] Start 'falco-kmod.service':\n"
                   "Running scriptlet: falco-0.45.0-1.x86_64\n")
    assert run_fn("pkg_scriptlet_failed", f"pkg_scriptlet_failed {log}").returncode == 1


@pytest.mark.parametrize("state,ok", [
    ("install ok installed", True), ("installed", True),
    ("install ok half-configured", False), ("install ok unpacked", False), ("absent", False), ("", False),
])
def test_pkg_state_ok(state, ok):
    assert (run_fn("pkg_state_ok", f"pkg_state_ok '{state}'").returncode == 0) is ok


def test_strict_probe_json_carries_qualification_keys():
    # Pin the emitted key set: qualify.py reads these by name.
    src = PROBE.read_text()
    block = src[src.index("emit_and_exit() {"):src.index("JSON\n    exit 0")]
    for key in ("strict", "pkg_exit", "pkg_state", "pkg_version", "pkg_sha256",
                "scriptlet_failed", "base_exit", "base_state", "base_version",
                "kmod_loaded", "bpf_prog_fds", "active_unit", "secure_boot"):
        assert f'"{key}":' in block, key


# ---------------------------------------------------------------------------
# --discover: release candidates in the dev repo
# ---------------------------------------------------------------------------

def s3_page(keys, token=None):
    """A ListObjectsV2 page as S3 writes it, namespace and all."""
    contents = "".join(f"<Contents><Key>{k}</Key><Size>1</Size></Contents>" for k in keys)
    more = (f"<NextContinuationToken>{token}</NextContinuationToken><IsTruncated>true</IsTruncated>"
            if token else "<IsTruncated>false</IsTruncated>")
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            f"<Name>falco-distribution</Name>{more}{contents}</ListBucketResult>").encode()


DEB = "packages/deb-dev/stable/"
RPM = "packages/rpm-dev/"


def test_list_page_url_encodes_the_continuation_token():
    # Real tokens look like this. A raw '+' reaches S3 as a space.
    url = qualify.list_page_url(qualify.DEV_INDEX, DEB, "1+hGB/bR==")
    assert "continuation-token=1%2BhGB%2FbR%3D%3D" in url
    assert "list-type=2" in url and "prefix=packages%2Fdeb-dev%2Fstable%2F" in url
    assert "continuation-token" not in qualify.list_page_url(qualify.DEV_INDEX, DEB)


def test_list_keys_follows_every_page():
    pages = {None: s3_page([DEB + "falco-0.45.0-rc1-x86_64.deb"], token="t+1"),
             "t+1": s3_page([DEB + "falco-0.45.1-rc1-x86_64.deb"])}
    seen = []

    def fetch(url):
        token = dict(parse_qsl(url.split("?", 1)[1])).get("continuation-token")
        seen.append(token)
        return pages[token]

    keys = qualify.list_keys(qualify.DEV_INDEX, DEB, fetch)
    assert seen == [None, "t+1"]
    assert keys == [DEB + "falco-0.45.0-rc1-x86_64.deb", DEB + "falco-0.45.1-rc1-x86_64.deb"]


def test_last_page_ends_the_listing_even_if_a_token_is_present():
    xml = s3_page(["a"]).replace(b"<IsTruncated>false</IsTruncated>",
                                 b"<NextContinuationToken>x</NextContinuationToken>"
                                 b"<IsTruncated>false</IsTruncated>")
    assert qualify.parse_list_page(xml) == (["a"], None)


def test_rc_versions_skips_dev_builds_other_arches_and_signatures():
    keys = [DEB + "falco-0.45.1-rc1-x86_64.deb",
            DEB + "falco-0.45.1-rc1-x86_64.deb.asc",
            DEB + "falco-0.45.1-rc1-aarch64.deb",
            DEB + "falco-0.46.0-44+066991c-x86_64.deb",
            DEB + "falco-0.45.0-x86_64.deb",
            RPM + "falco-0.45.0-rc4-x86_64.rpm"]
    assert qualify.rc_versions(keys, "deb") == {"0.45.1-rc1"}
    assert qualify.rc_versions(keys, "rpm") == {"0.45.0-rc4"}


def test_discover_new_offers_only_candidates_past_the_newest_qualified_version():
    available = {"0.39.0-rc1", "0.45.0-rc4", "0.45.1-rc1", "0.45.1-rc2", "0.46.0-rc1"}
    # 0.45.1-rc1 is done; rc2 and the next minor's rc1 are news, in order.
    assert qualify.discover_new(available, {"0.45.0", "0.45.1-rc1"}) == ["0.45.1-rc2", "0.46.0-rc1"]
    # An rc of a release that already shipped GA is history.
    assert qualify.discover_new({"0.45.0-rc4"}, {"0.45.0"}) == []
    assert qualify.discover_new(available, {"0.46.0-rc1"}) == []


def test_discover_new_on_a_fresh_workspace_starts_one_grid():
    assert qualify.discover_new({"0.39.0-rc1", "0.45.0-rc4", "0.45.1-rc1"}, set()) == ["0.45.1-rc1"]
    assert qualify.discover_new(set(), set()) == []


def test_complete_versions_needs_every_planned_cell(tmp_path):
    names = ["ubuntu-20.04--5.4--fresh-auto", "ubuntu-20.04--5.4--upgrade"]
    for version, cells in [("0.45.0", names), ("0.45.1-rc2", names[:1]), ("0.45.1-rc1", names)]:
        (tmp_path / version).mkdir()
        for n in cells:
            (tmp_path / version / f"{n}.json").write_text("{}")
    (tmp_path / "matrix.json").write_text("{}")
    assert qualify.complete_versions(tmp_path, names) == {"0.45.0", "0.45.1-rc1"}
    assert qualify.complete_versions(tmp_path / "missing", names) == set()


def test_half_run_candidate_is_offered_again():
    # rc2 was killed midway: rc1 is the newest complete grid, so rc2 comes back
    # and --resume finishes it.
    assert qualify.discover_new({"0.45.1-rc1", "0.45.1-rc2"}, {"0.45.1-rc1"}) == ["0.45.1-rc2"]


def test_discover_needs_both_formats_published(tmp_path):
    qual = {"targets": ["ubuntu-20.04"], "scenarios": [FRESH_AUTO]}
    listing = {DEB: [DEB + "falco-0.45.1-rc1-x86_64.deb", DEB + "falco-0.45.1-rc2-x86_64.deb"],
               RPM: [RPM + "falco-0.45.1-rc1-x86_64.rpm"]}          # rc2 rpm not uploaded yet

    def fetch(url):
        prefix = DEB if "deb-dev" in url else RPM
        return s3_page(listing[prefix])

    (tmp_path / "0.45.0").mkdir()
    (tmp_path / "0.45.0" / "ubuntu-20.04--5.4--fresh-auto.json").write_text("{}")
    assert qualify.discover(qual, {"ubuntu-20.04": distro()}, root=tmp_path, fetch=fetch) == ["0.45.1-rc1"]


# ---------------------------------------------------------------------------
# --gate: new red fails the build, known red does not
# ---------------------------------------------------------------------------

def gcell(version, status, distro_name="ubuntu-20.04", kernel="5.4", scenario="fresh-auto"):
    return {"version": version, "distro": distro_name, "kernel": kernel, "scenario": scenario,
            "status": status, "reason": f"{status} reason"}


def test_known_red_rows_do_not_fail_the_gate():
    # falco#3994: red on 20.04 in 0.45.0 and still red in 0.45.1-rc1.
    cells = [gcell("0.45.0", "fail"), gcell("0.45.1-rc1", "fail"),
             gcell("0.45.0", "pass", kernel="5.15-hwe"), gcell("0.45.1-rc1", "pass", kernel="5.15-hwe")]
    g = qualify.gate(cells, "0.45.1-rc1")
    assert g["new"] == [] and [r["cell"] for r in g["known"]] == ["ubuntu-20.04--5.4--fresh-auto"]
    assert g["known"][0]["baseline_version"] == "0.45.0" and g["cells"] == 2


def test_green_row_turning_red_fails_the_gate():
    cells = [gcell("0.45.0", "pass", "debian-12", "6.1"), gcell("0.45.1-rc1", "fail", "debian-12", "6.1")]
    g = qualify.gate(cells, "0.45.1-rc1")
    assert [(r["cell"], r["baseline_status"]) for r in g["new"]] == [("debian-12--6.1--fresh-auto", "pass")]


def test_harness_error_is_red_both_ways():
    # error before, fail now: still red, already known. pass before, error now: new.
    cells = [gcell("0.45.0", "error"), gcell("0.45.1-rc1", "fail"),
             gcell("0.45.0", "pass", scenario="upgrade"), gcell("0.45.1-rc1", "error", scenario="upgrade")]
    g = qualify.gate(cells, "0.45.1-rc1")
    assert [r["cell"] for r in g["known"]] == ["ubuntu-20.04--5.4--fresh-auto"]
    assert [r["cell"] for r in g["new"]] == ["ubuntu-20.04--5.4--upgrade"]


def test_red_row_with_no_earlier_result_is_new():
    g = qualify.gate([gcell("0.45.1-rc1", "fail", "fedora-45", "6.20")], "0.45.1-rc1")
    assert g["new"][0]["baseline_version"] is None


def test_blocked_or_unsupported_before_is_not_a_known_failure():
    cells = [gcell("0.45.0", "blocked", scenario="upgrade"), gcell("0.45.1-rc1", "fail", scenario="upgrade"),
             gcell("0.45.0", "unsupported", scenario="fresh-modern_ebpf"),
             gcell("0.45.1-rc1", "fail", scenario="fresh-modern_ebpf")]
    assert len(qualify.gate(cells, "0.45.1-rc1")["new"]) == 2


def test_baseline_is_per_cell_newest_earlier_version_that_ran_it():
    # 0.45.0-rc4 only ran 20.04 fresh-auto (green). 0.45.0 ran it red. For
    # 0.45.1-rc1 the baseline is 0.45.0, not rc4; a row rc4 never ran falls
    # back to whatever earlier version did.
    cells = [gcell("0.45.0-rc4", "pass"), gcell("0.45.0", "fail"), gcell("0.45.1-rc1", "fail"),
             gcell("0.44.1", "fail", scenario="upgrade"), gcell("0.45.1-rc1", "fail", scenario="upgrade"),
             gcell("0.45.2", "pass", scenario="upgrade")]       # later versions are not a baseline
    g = qualify.gate(cells, "0.45.1-rc1")
    assert g["new"] == []
    assert {r["cell"]: r["baseline_version"] for r in g["known"]} == {
        "ubuntu-20.04--5.4--fresh-auto": "0.45.0", "ubuntu-20.04--5.4--upgrade": "0.44.1"}


def test_red_row_turning_green_is_reported_as_fixed():
    g = qualify.gate([gcell("0.45.0", "fail"), gcell("0.45.1-rc1", "pass")], "0.45.1-rc1")
    assert g["new"] == g["known"] == [] and g["fixed"][0]["baseline_status"] == "fail"
    assert "1 fixed" in qualify.gate_text(g)


def test_gate_reads_the_shipped_matrix_shape(tmp_path):
    # build_matrix's cells are what --gate feeds gate(); keep the two in step.
    rec = record(version="0.45.0", pkg_exit=100, pkg_state="install ok half-configured",
                 started=False, kmod_loaded=False)
    new = record(version="0.45.1-rc1", pkg_version="0.45.1-rc1", pkg_exit=100,
                 pkg_state="install ok half-configured", started=False, kmod_loaded=False)
    for r in (rec, new):
        (tmp_path / r["version"]).mkdir()
        (tmp_path / r["version"] / f"{r['cell']}.json").write_text(json.dumps(r))
    (tmp_path / "0.45.0" / "gate.json").write_text(json.dumps({"version": "0.45.0", "new": []}))
    g = qualify.gate(qualify.build_matrix(tmp_path)["cells"], "0.45.1-rc1")
    assert (len(g["new"]), len(g["known"])) == (0, 1)

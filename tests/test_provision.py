"""
Unit tests for provision.py's pure logic: version comparison, matrix
loading, and the JUnit writer that Jenkins trends are built on.

Everything that talks to libvirt or SSH is exercised by the matrix itself;
these tests cover the decisions made BEFORE and AFTER that talking, which
is where a wrong answer silently corrupts every downstream report.
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import provision
from provision import CheckResult, RunResult


# ---------------------------------------------------------------------------
# kernel version ordering -- the classic 5.9 vs 5.10 trap
# ---------------------------------------------------------------------------

def test_kernel_key_basic():
    assert provision.kernel_key("5.15.0-91-generic") == (5, 15, 0, 91)


def test_kernel_numeric_not_lexicographic():
    # Sorted as text, 5.9 lands after 5.10. On a matrix spanning 2.6 to 7.x
    # that bug quietly corrupts every compatibility claim downstream.
    assert provision.kernel_key("5.9.16") < provision.kernel_key("5.10.0")


def test_kernel_at_least_only_as_deep_as_minimum():
    assert provision.kernel_at_least("5.10.0-21-amd64", "5.10")
    assert provision.kernel_at_least("6.1.0-13-amd64", "5.10")
    assert not provision.kernel_at_least("5.9.16-200.fc33", "5.10")


def test_kernel_at_least_el7_era():
    assert not provision.kernel_at_least("3.10.0-1160.el7.x86_64", "5.10")
    assert provision.kernel_at_least("3.10.0-1160.el7.x86_64", "2.6.32")


# ---------------------------------------------------------------------------
# JUnit output -- what Jenkins actually consumes
# ---------------------------------------------------------------------------

def _result(**kw):
    defaults = dict(distro="testland-1", kernel="5.10.0", error=None,
                    checks=[], falco=None)
    defaults.update(kw)
    r = RunResult(distro=defaults["distro"])
    r.kernel = defaults["kernel"]
    r.error = defaults["error"]
    r.checks = defaults["checks"]
    r.falco = defaults["falco"]
    return r


def _check(name="a_check", passed=True, skipped=False, message="", duration=0.1):
    return CheckResult(name=name, passed=passed, skipped=skipped,
                       message=message, duration=duration)


def test_junit_pass_and_fail_counts(tmp_path):
    r = _result(checks=[_check(), _check(name="b", passed=False)])
    out = tmp_path / "out.xml"
    provision.write_junit(r, out)
    suite = ET.parse(out).getroot()
    assert suite.get("tests") == "2"
    assert suite.get("failures") == "1"
    assert suite.get("errors") == "0"


def test_junit_vm_error_is_error_not_failure(tmp_path):
    # The distinction matters: failure = the system under test misbehaved,
    # error = the harness could not even ask the question. Conflating them
    # makes a broken lab look like a broken kernel.
    r = _result(error="vm never got an IP")
    out = tmp_path / "out.xml"
    provision.write_junit(r, out)
    suite = ET.parse(out).getroot()
    assert suite.get("errors") == "1"
    assert suite.get("failures") == "0"


def test_junit_skip_is_recorded(tmp_path):
    r = _result(checks=[_check(skipped=True, passed=False)])
    out = tmp_path / "out.xml"
    provision.write_junit(r, out)
    suite = ET.parse(out).getroot()
    assert suite.get("skipped") == "1"


def test_junit_is_wellformed_with_hostile_text(tmp_path):
    # Error text comes straight from journalctl and yum; it has quotes,
    # angle brackets, and ANSI leftovers. The XML must survive it.
    r = _result(checks=[_check(passed=False,
                               message='<oops> & "quotes" \x1b[1;32mgreen')])
    out = tmp_path / "out.xml"
    provision.write_junit(r, out)
    ET.parse(out)   # raises if malformed


# ---------------------------------------------------------------------------
# matrix loading -- the file everyone edits by hand
# ---------------------------------------------------------------------------

MATRIX_YAML = """
defaults:
  memory_mb: 2048
  vcpus: 2
  ssh_user: root
checks:
  - name: a_check
    command: uname -r
    expect: ""
distros:
  - name: testland-1
    tier: fast
    image_url: http://example.invalid/img.qcow2
    expect_kernel: "6.8"
    ssh_user: ubuntu
"""


def test_load_matrix_applies_defaults_and_overrides(tmp_path):
    p = tmp_path / "matrix.yaml"
    p.write_text(MATRIX_YAML)
    distros, checks = provision.load_matrix(p)
    assert len(distros) == 1
    d = distros[0]
    assert d.ssh_user == "ubuntu"        # per-distro override wins
    assert d.memory_mb == 2048           # default applies
    assert len(checks) == 1


# ---------------------------------------------------------------------------
# results merging -- Jenkins runs one provision.py per distro in parallel
# ---------------------------------------------------------------------------

def test_merge_combines_every_parallel_branch(tmp_path, monkeypatch):
    # Each matrix branch used to write results.json itself, so the last one
    # to finish overwrote the rest and every dashboard showed one distro.
    monkeypatch.setattr(provision, "RESULTS", tmp_path)
    for name in ("debian-12", "ubuntu-22.04", "rocky-9"):
        r = RunResult(distro=name)
        (tmp_path / f"{name}.result.json").write_text(
            provision.json.dumps(provision.result_to_dict(r)))
    (tmp_path / "upstream_cache.json").write_text("{}")   # must be ignored

    assert provision.merge_results() == 0
    merged = provision.json.loads((tmp_path / "results.json").read_text())
    assert [r["distro"] for r in merged["results"]] == ["debian-12", "rocky-9", "ubuntu-22.04"]


def test_merge_with_nothing_to_merge_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(provision, "RESULTS", tmp_path)
    assert provision.merge_results() == 0
    assert not (tmp_path / "results.json").exists()


def test_load_matrix_firmware_defaults_to_bios(tmp_path):
    p = tmp_path / "matrix.yaml"
    p.write_text(
        "distros:\n"
        "  - {name: a, image_url: u, ssh_user: x, expect_kernel: 5}\n"
        "  - {name: b, image_url: u, ssh_user: x, expect_kernel: 5, firmware: uefi}\n"
        "checks: []\n")
    distros, _ = provision.load_matrix(p)
    assert [d.firmware for d in distros] == ["bios", "uefi"]


# ---------------------------------------------------------------------------
# Falco probe -> checks: the probe result must reach JUnit, not just the log
# ---------------------------------------------------------------------------

def _by_name(checks):
    return {c.name: c for c in checks}


def test_falco_healthy_is_three_passes():
    checks = provision.falco_checks({"installed": True, "started": True,
                                     "detected": True, "error": ""})
    assert [c.name for c in checks] == ["falco_installs", "falco_starts",
                                        "falco_detects_event"]
    assert all(c.passed and not c.skipped for c in checks)


def test_falco_install_failure_fails_once_and_skips_the_rest():
    # ubuntu-18.04/20.04 in nightlies 57-61: one root failure, not three.
    probe = {"installed": False, "started": False, "detected": False,
             "error": "dpkg: error processing package falco (--configure):",
             "error_detail": "Setting up falco | post-installation script returned error exit status 1"}
    c = _by_name(provision.falco_checks(probe))
    assert not c["falco_installs"].passed and not c["falco_installs"].skipped
    assert "dpkg" in c["falco_installs"].message
    assert "post-installation" in c["falco_installs"].output
    assert c["falco_starts"].skipped and c["falco_detects_event"].skipped


def test_falco_running_but_blind_is_a_failure():
    # The quiet failure mode: started, no error string, never alerted.
    c = _by_name(provision.falco_checks({"installed": True, "started": True,
                                         "detected": False, "error": ""}))
    assert c["falco_starts"].passed
    assert not c["falco_detects_event"].passed and not c["falco_detects_event"].skipped


def test_falco_probe_harness_error_fails_install_check():
    # A timeout or unparseable probe output has no "installed" key at all.
    c = _by_name(provision.falco_checks({"error": "probe timed out after 15 minutes"}))
    assert not c["falco_installs"].passed
    assert "timed out" in c["falco_installs"].message


def test_falco_failure_reaches_junit_and_counts(tmp_path):
    r = _result(checks=[_check()] + provision.falco_checks(
        {"installed": False, "error": "dpkg: error processing package falco"}))
    out = tmp_path / "out.xml"
    provision.write_junit(r, out)
    suite = ET.parse(out).getroot()
    assert suite.get("tests") == "4"
    assert suite.get("failures") == "1"
    assert suite.get("skipped") == "2"
    assert r.failed == 1


# ---------------------------------------------------------------------------
# Evidence bundles: safe unpacking and a manifest that can be audited
# ---------------------------------------------------------------------------

def _tgz_with(tmp_path, members):
    """members: list of (name, kind, payload) with kind 'file' or 'symlink'."""
    import io
    import tarfile
    tgz = tmp_path / "bundle.tgz"
    with tarfile.open(tgz, "w:gz") as tar:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tar.addfile(info)
            else:
                data = payload.encode()
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return tgz


def test_extract_flat_keeps_only_plain_files_inside_dest(tmp_path):
    # The tarball comes out of a guest that just ran a package's install
    # scripts as root. Nothing in it may land outside dest.
    tgz = _tgz_with(tmp_path, [
        ("km-evidence/journal.log", "file", "J1\n"),
        ("km-evidence/../../escape.txt", "file", "nope"),
        ("km-evidence/passwd", "symlink", "/etc/passwd"),
        ("km-evidence/.hidden", "file", "x"),
    ])
    dest = tmp_path / "dest"
    dest.mkdir()
    names = provision._extract_flat(tgz, dest)
    assert names == ["escape.txt", "journal.log"]
    assert not (tmp_path / "escape.txt").exists()
    assert not (dest / "passwd").exists()
    assert (dest / "journal.log").read_text() == "J1\n"


def test_manifest_records_outcome_hashes_and_failed_checks(tmp_path):
    import hashlib
    (tmp_path / "journal.log").write_text("a\nb\n")
    (tmp_path / "manifest.json").write_text("{}")      # never hashes itself
    r = _result(kernel="5.4.0-216-generic",
                checks=[_check()] + provision.falco_checks(
                    {"installed": False, "error": "dpkg: error"}),
                falco={"falco_version": "unknown"})
    d = provision.Distro(name="ubuntu-20.04", image_url="x", ssh_user="ubuntu",
                         expect_kernel="5.4", tier="legacy")
    m = provision.build_manifest(r, d, tmp_path, collected=True)
    assert m["outcome"] == "fail"
    assert m["failed_checks"] == ["falco_installs"]
    assert m["kernel"] == "5.4.0-216-generic" and m["tier"] == "legacy"
    assert list(m["files"]) == ["journal.log"]
    assert m["files"]["journal.log"] == {
        "sha256": hashlib.sha256(b"a\nb\n").hexdigest(), "bytes": 4, "lines": 2}
    assert m["collected_at"].endswith("Z")


def test_manifest_vm_error_outranks_checks(tmp_path):
    r = _result(error="SSH never became available")
    d = provision.Distro(name="x", image_url="x", ssh_user="u", expect_kernel="5")
    assert provision.build_manifest(r, d, tmp_path, collected=False)["outcome"] == "error"

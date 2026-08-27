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

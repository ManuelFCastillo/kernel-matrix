"""
Tests for the shell logic inside falco_probe.sh -- run by feeding fixture
text through the EXACT pipelines the probe uses, via bash.

WHY TEST SHELL WITH PYTEST
--------------------------
The probe runs inside throwaway guests, so its bugs only surface after a
2-minute VM boot, and they surface as *wrong data*, not crashes. Both bugs
below shipped wrong dashboards before being caught:

  * the unit-selection pipeline grabbed falco-kmod-inject.service (a oneshot
    helper, "active exited") instead of falco-kmod.service, because it
    filtered on state=active and took head -1 of an alphabetical list
  * json_safe let control characters through once, silently destroying two
    distros' results at json.loads() time on the host

These tests pin the pipelines without needing a VM.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROBE = Path(__file__).resolve().parent.parent / "falco_probe.sh"


def bash(script: str, stdin: str = "") -> str:
    return subprocess.run(["bash", "-c", script], input=stdin,
                          capture_output=True, text=True, timeout=10).stdout


# ---------------------------------------------------------------------------
# unit selection: the exact awk|grep pipeline from the probe
# ---------------------------------------------------------------------------
SELECT = ("awk '$4 == \"running\" {print $1}' | grep -v falcoctl | head -1")

# systemctl list-units --plain --no-legend fixture: UNIT LOAD ACTIVE SUB DESC
UNITS_KMOD_HEALTHY = """\
falco-kmod-inject.service loaded active exited Falco kmod inject helper
falco-kmod.service loaded active running Falco with kmod
falcoctl-artifact-follow.service loaded active running Falcoctl updater
"""

UNITS_CRASH_LOOP = """\
falco-kmod-inject.service loaded active exited Falco kmod inject helper
falcoctl-artifact-follow.service loaded active running Falcoctl updater
"""


def test_selects_running_unit_not_oneshot_helper():
    # REGRESSION: the helper sorts first alphabetically and is 'active', but
    # its sub-state is 'exited'. Selecting it produced driver=unknown, rss=0
    # and detected=false on ubuntu-20.04 while Falco ran fine underneath.
    out = bash(SELECT, UNITS_KMOD_HEALTHY).strip()
    assert out == "falco-kmod.service"


def test_crash_loop_with_only_helper_selects_nothing():
    # If only the helper and the rule-updater are up, the sensor is NOT
    # running and the pipeline must say so rather than grab a bystander.
    out = bash(SELECT, UNITS_CRASH_LOOP).strip()
    assert out == ""


def test_falcoctl_never_wins_even_when_running():
    only_falcoctl = "falcoctl-artifact-follow.service loaded active running x\n"
    assert bash(SELECT, only_falcoctl).strip() == ""


# ---------------------------------------------------------------------------
# json_safe: everything it emits must survive json.loads on the host
# ---------------------------------------------------------------------------

def json_safe(text: str) -> str:
    # Extract and run the real function from the probe itself, so the test
    # cannot drift out of sync with the implementation.
    script = (f"source <(sed -n '/^json_safe()/,/^}}/p' {PROBE}); "
              f"json_safe \"$(cat)\"")
    return bash(script, text)


@pytest.mark.parametrize("hostile", [
    'plain text',
    'quotes " everywhere " again',
    'backslash \\ soup \\n',
    'ansi \x1b[1;32mgreen\x1b[0m text',
    'control \x01 chars \x07 galore',
    'newlines\nand\ttabs',
])
def test_json_safe_output_always_parses(hostile):
    # rstrip: the trailing newline comes from the test's echo, not json_safe.
    out = json_safe(hostile).rstrip("\n")
    parsed = json.loads(f'{{"v": "{out}"}}')   # raises if not JSON-safe
    assert isinstance(parsed["v"], str)


def test_json_safe_truncates_runaway_output():
    out = json_safe("x" * 5000)
    assert len(out) <= 201   # 200 chars + trailing newline from echo


# ---------------------------------------------------------------------------
# the probe as a whole: syntax must hold on every distro's bash
# ---------------------------------------------------------------------------

def test_probe_passes_bash_syntax_check():
    r = subprocess.run(["bash", "-n", str(PROBE)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

"""Unit tests for sensor_tests/guest.py: the parts that decide a sensor test's
colour without a VM, so they run in the Unit tests stage first."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "sensor_tests"))

import guest  # noqa: E402

ALERT = {"rule": "Read sensitive file untrusted", "priority": "Warning",
         "output": "Sensitive file opened | file=/etc/shadow command=cat /etc/shadow /tmp/km-cov/kmabc",
         "output_fields": {"fd.name": "/etc/shadow", "proc.name": "cat", "container.id": "host"}}


def test_parse_json_lines_skips_partial_and_noise():
    text = '{"rule": "a"}\nnot json\n\n{"rule": "b"}\n{"rule": "c", "outp'
    assert [a["rule"] for a in guest.parse_json_lines(text)] == ["a", "b"]


@pytest.mark.parametrize("rules, contains, fields, want", [
    ("Read sensitive file untrusted", None, None, True),
    (("Other", "Read sensitive file untrusted"), None, None, True),
    ("Other", None, None, False),
    ("Read sensitive file untrusted", "kmabc", None, True),          # in the output line
    ("Read sensitive file untrusted", "cat", None, True),            # in a field
    ("Read sensitive file untrusted", "kmzzz", None, False),
    ("Read sensitive file untrusted", None, {"fd.name": "/etc/shadow"}, True),
    ("Read sensitive file untrusted", None, {"container.id": "abc"}, False),
])
def test_alert_matches(rules, contains, fields, want):
    assert guest.alert_matches(ALERT, rules, contains, fields) is want


def test_shipped_rule_names_reads_only_top_level_rules():
    text = ("- macro: open_read\n  condition: x\n"
            "- rule: Read sensitive file untrusted\n  desc: y\n"
            "- list: shell_binaries\n  items: []\n"
            "- rule: 'Quoted name'\n"
            "  # - rule: commented example\n")
    assert guest.shipped_rule_names(text) == ["Read sensitive file untrusted", "Quoted name"]


def test_metric_accepts_both_snapshot_shapes_and_spellings():
    assert guest.metric({"output_fields": {"scap.n_drops": 3}}, "scap.n_drops") == 3
    assert guest.metric({"falco.n_drops": 4}, "scap.n_drops", "falco.n_drops") == 4
    assert guest.metric({"output_fields": {}}, "scap.n_drops") is None


def test_drop_ratio():
    before = {"output_fields": {"scap.n_evts": 1000, "scap.n_drops": 0}}
    after = {"output_fields": {"scap.n_evts": 11000, "scap.n_drops": 50}}
    assert guest.drop_ratio(before, after) == (0.005, 10000, 50)
    assert guest.drop_ratio({}, after) == (None, None, None)
    same = {"output_fields": {"scap.n_evts": 5, "scap.n_drops": 0}}
    assert guest.drop_ratio(same, same) == (0.0, 0, 0)


def test_growth_mb_ignores_a_single_spike_but_sees_a_trend():
    flat_with_spike = [100_000] * 4 + [400_000] + [100_000] * 4
    assert guest.growth_mb(flat_with_spike) == 0.0
    leak = [100_000 + i * 10_240 for i in range(9)]               # +10 MB per sample
    assert guest.growth_mb(leak) == 60.0
    assert guest.growth_mb([1, 2]) == 0.0


def test_pkg_commands_keep_config_and_never_prompt():
    deb = guest.pkg_commands("deb")
    assert "--allow-downgrades" in deb["downgrade"]
    assert all("--force-confold" in deb[k] for k in ("downgrade", "install"))
    assert deb["purge"].endswith("purge falco")
    rpm = guest.pkg_commands("rpm")
    assert rpm["remove"] == rpm["purge"]                          # rpm has no purge
    assert all("FALCO_FRONTEND=noninteractive" in c for c in list(deb.values()) + list(rpm.values()))
    with pytest.raises(ValueError):
        guest.pkg_commands("apk")


@pytest.mark.parametrize("output, failed", [
    ("dpkg: error processing package falco (--configure):\n installed falco package post-installation "
     "script subprocess returned error exit status 1", True),
    ("warning: %post(falco-0.45.1-1.x86_64) scriptlet failed, exit status 1", True),
    ("Non-fatal POSTIN scriptlet failure in rpm package falco", True),
    ("Setting up falco (0.45.1-rc1) ...", False),
])
def test_scriptlet_failed(output, failed):
    assert guest.scriptlet_failed(output) is failed


def test_snapshot_epoch():
    assert guest._snapshot_epoch({"output_fields": {"evt.time": 1_700_000_000_000_000_000}}) == 1_700_000_000
    assert guest._snapshot_epoch({"time": "2023-11-14T22:13:20.123456789Z"}) == 1_700_000_000
    assert guest._snapshot_epoch({}) is None

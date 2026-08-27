"""
Unit tests for report.py -- the drift detection and version logic.

WHY THESE EXIST
---------------
This lab's own history is the argument. The probe once reported a
crash-looping Falco as started (driver guessed from a unit name), and once
read a oneshot helper's journal instead of the running sensor's -- both
were logic bugs in TEST infrastructure that confidently published wrong
results. The functions below are the ones that decide what the dashboard
claims, so they get tested like production code.

Several cases here are regression tests for real bugs, marked as such.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import report


# ---------------------------------------------------------------------------
# version_tuple: the thing that decides "is upstream newer than what we tested"
# ---------------------------------------------------------------------------

def test_version_tuple_basic():
    assert report.version_tuple("0.44.1") == (0, 44, 1)


def test_version_tuple_orders_numerically_not_lexically():
    # The classic trap: "0.9" must sort BELOW "0.10", which string
    # comparison gets backwards.
    assert report.version_tuple("0.9.0") < report.version_tuple("0.10.0")


def test_version_tuple_strips_v_prefix_digits_only():
    assert report.version_tuple("v0.44.1") == (0, 44, 1)


def test_version_tuple_garbage_sorts_oldest():
    assert report.version_tuple("") == (0,)
    assert report.version_tuple(None) == (0,)
    assert report.version_tuple("unknown") == (0,)


# ---------------------------------------------------------------------------
# diff_runs: the regression canary itself
# ---------------------------------------------------------------------------

def _run(distro="ubuntu-20.04", **falco):
    base = {"driver": "kmod", "started": True, "detected": True,
            "falco_version": "0.44.1", "rss_kb": 14000}
    base.update(falco)
    return {"generated_at": "T", "results": [{"distro": distro, "falco": base}]}


def test_no_previous_run_means_no_changes():
    assert report.diff_runs(None, _run()) == {}


def test_identical_runs_show_no_drift():
    assert report.diff_runs(_run(), _run()) == {}


def test_detection_loss_is_flagged_bad():
    changes = report.diff_runs(_run(), _run(detected=False))
    tones = [t for t, _ in changes["ubuntu-20.04"]]
    texts = [x for _, x in changes["ubuntu-20.04"]]
    assert "bad" in tones
    assert any("STOPPED detecting" in t for t in texts)


def test_driver_flip_is_flagged():
    changes = report.diff_runs(_run(), _run(driver="modern_ebpf"))
    assert any("kmod" in t and "modern_ebpf" in t
               for _, t in changes["ubuntu-20.04"])


def test_version_change_is_flagged():
    changes = report.diff_runs(_run(), _run(falco_version="0.45.0"))
    assert any("0.44.1" in t and "0.45.0" in t
               for _, t in changes["ubuntu-20.04"])


def test_rss_swing_over_threshold_is_flagged():
    changes = report.diff_runs(_run(rss_kb=14000), _run(rss_kb=28000))
    assert any("rss" in t for _, t in changes["ubuntu-20.04"])


def test_rss_swing_under_threshold_is_quiet():
    changes = report.diff_runs(_run(rss_kb=14000), _run(rss_kb=15000))
    assert changes == {}


def test_rss_zero_never_divides():
    # REGRESSION GUARD: centos-7 reports rss_kb=0 (sampler misses on Falco
    # 0.40/EL7). A naive percentage diff would divide by zero.
    assert report.diff_runs(_run(rss_kb=0), _run(rss_kb=14000)) == {}
    assert report.diff_runs(_run(rss_kb=14000), _run(rss_kb=0)) == {}


def test_new_distro_is_marked_new_not_diffed():
    prev = _run(distro="debian-11")
    cur = _run(distro="centos-7")
    changes = report.diff_runs(prev, cur)
    assert changes["centos-7"] == [("warn", "new in matrix")]


# ---------------------------------------------------------------------------
# run history: archive / load_previous
# ---------------------------------------------------------------------------

def test_history_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(report, "RUNS_DIR", tmp_path / "runs")
    old = _run();  old["generated_at"] = "2026-08-25T00:00:00"
    new = _run();  new["generated_at"] = "2026-08-26T00:00:00"

    report.archive_run(old)
    report.archive_run(new)

    prev = report.load_previous(new["generated_at"])
    assert prev["generated_at"] == old["generated_at"]


def test_archive_is_idempotent(tmp_path, monkeypatch):
    # Re-rendering a report must not create duplicate history entries.
    monkeypatch.setattr(report, "RUNS_DIR", tmp_path / "runs")
    run = _run()
    report.archive_run(run)
    report.archive_run(run)
    assert len(list((tmp_path / "runs").glob("run-*.json"))) == 1


def test_first_run_has_no_previous(tmp_path, monkeypatch):
    # The current run's own archive must never be offered as its "previous",
    # or every report would diff against itself and show zero drift forever.
    monkeypatch.setattr(report, "RUNS_DIR", tmp_path / "runs")
    run = _run()
    report.archive_run(run)
    assert report.load_previous(run["generated_at"]) is None


# ---------------------------------------------------------------------------
# render: smoke, offline behaviour, and escaping
# ---------------------------------------------------------------------------

def test_render_smoke_offline():
    # upstream={} simulates no network: the page must still render, with the
    # banner degraded rather than the render crashing in a nightly job.
    html_out = report.render(_run(), prev=None, upstream={})
    assert "upstream check unavailable" in html_out
    assert "0.44.1" in html_out


def test_render_flags_untested_upstream():
    html_out = report.render(
        _run(), upstream={"tag": "v0.99.0", "published": "2026-08-25"})
    assert "UNTESTED" in html_out


def test_render_escapes_hostile_error_text():
    run = _run()
    run["results"][0]["falco"] = {
        "started": False, "driver": "none",
        "error": '<script>alert(1)</script>'}
    html_out = report.render(run, upstream={})
    assert "<script>alert(1)</script>" not in html_out


# ---------------------------------------------------------------------------
# plugin_mode drift: the fix-landing detector
# ---------------------------------------------------------------------------

def test_plugin_mode_flip_to_stock_is_flagged_good():
    # The day upstream ships the container-plugin fix, rows flip from
    # workaround to stock -- the single event this feature exists to catch.
    changes = report.diff_runs(_run(plugin_mode="workaround"),
                               _run(plugin_mode="stock"))
    assert ("good", "plugin workaround → stock") in changes["ubuntu-20.04"]


def test_plugin_mode_absent_defaults_to_stock_no_false_drift():
    # Runs recorded before the plugin_mode field existed must not diff as
    # changed against new runs that say "stock" explicitly.
    old = _run()
    old["results"][0]["falco"].pop("plugin_mode", None)
    new = _run(plugin_mode="stock")
    assert report.diff_runs(old, new) == {}

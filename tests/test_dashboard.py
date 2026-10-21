"""
Tests for dashboard/server.py: the code that turns qualification results on
disk into what Kestrel QA shows. The page draws whatever this hands it, so a
wrong group, a stale "running" cell or a served file outside the results is
decided here, not in the browser.
"""

import json
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "dashboard"))

import server  # noqa: E402

CHECKS_OK = [{"name": n, "passed": True, "observed": "ok"} for n in
             ("pkg_installed", "driver_loaded", "service_active", "event_detected")]


def record(version, cell, status="pass", reason="", checks=None, upgrade_from=None):
    distro, kernel, scenario = cell.split("--")
    return {
        "schema_version": 1, "cell": cell, "version": version,
        "channel": "dev" if "-rc" in version else "stable",
        "distro": distro, "kernel": kernel, "kernel_variant": None, "matrix_name": distro,
        "kernel_observed": kernel + ".0-1", "scenario": {"id": scenario, "driver_choice": None,
                                                        "upgrade_from": upgrade_from},
        "status": status, "reason": reason, "checks": CHECKS_OK if checks is None else checks,
        "modern_ebpf_capable": False, "secure_boot": False, "driver": "kmod", "prereqs": "ready",
        "package": {"url": f"https://x/falco-{version}.deb"}, "error": None,
        "probe": {"rss_kb": 14000, "bpf_load_errors": 0}, "host_checks": [],
        "evidence": f"evidence/{cell}/manifest.json", "log": f"logs/{cell}.log",
        "started_at": "2026-10-17T17:00:00Z", "duration_s": 120, "git_sha": "1581f99",
    }


def write_cell(root, rec, evidence=None):
    vdir = root / rec["version"]
    edir = vdir / "evidence" / rec["cell"]
    edir.mkdir(parents=True, exist_ok=True)
    files = {}
    for name, text in (evidence or {"install.log": "Setting up falco\n[exit 0]\n"}).items():
        (edir / name).write_text(text)
        files[name] = {"sha256": "0" * 64, "bytes": len(text), "lines": text.count("\n")}
    (edir / "manifest.json").write_text(json.dumps({"files": files, "collected_at": "2026-10-17T17:02:00Z"}))
    (vdir / "logs").mkdir(exist_ok=True)
    (vdir / "logs" / f"{rec['cell']}.log").write_text("RESULT done\n")
    (vdir / f"{rec['cell']}.json").write_text(json.dumps(rec))


HALF = [{"name": "pkg_installed", "passed": False, "observed": "exit 100, install ok half-configured"},
        {"name": "driver_loaded", "passed": False, "observed": "kmod_loaded=False"},
        {"name": "service_active", "passed": False, "observed": "no engine unit running"},
        {"name": "event_detected", "passed": False, "observed": "not attempted"}]
NO_DRIVER = ("Setting up falco (0.45.0) ...\n[POST-INSTALL] Disable all possible 'falco' services:\n"
             "dpkg: error processing package falco (--configure):\n[exit 100]\n")
FALCO_TXT = ("$ test -f /etc/falcoctl/falcoctl.yaml && falcoctl driver printenv\n"
             "\x1b[90m2026-10-17\x1b[0m ERROR no supported driver found for distro: ubuntu-generic, kernelrelease 5.4.0-216-generic\n"
             "[exit 1]\n")


# ---------------------------------------------------------------------------
# signatures
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("file,line,sig", [
    ("falco.txt", "ERROR no supported driver found for distro: ubuntu-generic", "falcoctl-no-driver"),
    ("install.log", "  ERROR: Kernel configuration is invalid.", "kmod-downloaded-headers"),
    ("install.log", "Makefile:1118: /tmp/x/scripts/Makefile.debug: No such file or directory", "kmod-downloaded-headers"),
    ("dmesg.log", "[  231.7] Loading of module with unavailable key is rejected", "secure-boot-unsigned-module"),
    ("install.log", "Failed to start falco-kmod.service: Unit falco-kmod.service is not loaded properly: Exec format error.", "unit-exec-format"),
    ("install.log", "           Requires: libc.so.6(GLIBC_2.28)(64bit)", "glibc-floor"),
])
def test_known_signatures_cite_file_and_line(tmp_path, file, line, sig):
    (tmp_path / file).write_text(f"first line\n{line}\nlast line\n")
    found = server.find_signature(tmp_path)
    assert found["id"] == sig and found["file"] == file and found["line"] == 2


def test_signature_text_has_ansi_stripped(tmp_path):
    (tmp_path / "falco.txt").write_text(FALCO_TXT)
    found = server.find_signature(tmp_path)
    assert "\x1b" not in found["text"] and found["text"].startswith("2026-10-17 ERROR no supported driver")
    assert found["known"].endswith("/pull/3994")


def test_signature_order_decides_between_two_matches(tmp_path):
    # A #3994 cell can also carry an unrelated warning further down; the
    # catalog order, not file order, decides what the cell is.
    (tmp_path / "install.log").write_text("Requires: libc.so.6(GLIBC_2.28)\n")
    (tmp_path / "falco.txt").write_text("ERROR no supported driver found for distro: x\n")
    assert server.find_signature(tmp_path)["id"] == "falcoctl-no-driver"


def test_unmatched_failures_group_across_kernel_versions():
    a = server.fallback_signature({"reason": "service_active: unit died after 12s on 5.4.0-216"})
    b = server.fallback_signature({"reason": "service_active: unit died after 3s on 5.15.0-139"})
    c = server.fallback_signature({"reason": "event_detected: no alert"})
    assert a["id"] == b["id"] != c["id"]
    assert a["file"] is None


def test_key_lines_put_the_match_first_with_its_neighbours(tmp_path):
    (tmp_path / "falco.txt").write_text(FALCO_TXT)
    (tmp_path / "install.log").write_text(NO_DRIVER)
    sig = server.find_signature(tmp_path)
    lines = server.key_lines(tmp_path, sig)
    assert [l["match"] for l in lines[:3]] == [False, True, False]
    assert lines[1]["file"] == "falco.txt" and lines[1]["line"] == 2
    (tmp_path / "falco.txt").write_text("\n" + FALCO_TXT + "\n")
    spaced = server.key_lines(tmp_path, server.find_signature(tmp_path))
    assert all(l["text"].strip() for l in spaced if l["file"] == "falco.txt")
    assert any(l["file"] == "install.log" and "error processing" in l["text"] for l in lines)
    assert any(l["text"] == "[exit 100]" for l in lines)
    assert len(server.key_lines(tmp_path, sig, limit=2)) == 2


# ---------------------------------------------------------------------------
# running cells
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("last,phase", [
    ("[12:00:01] EXEC  $ virt-install --name km-x", "booting VM"),
    ("[12:01:00] INFO  kernel variant: rebooting into the new kernel", "switching kernel"),
    ("[12:02:00] INFO  build prerequisites: prereqs: ready for 5.4", "preparing build tools"),
    ("[12:03:00] INFO  falco: installing and characterising (this takes a few minutes)", "installing Falco"),
    ("[12:04:00] INFO  evidence: 11 file(s) -> results/x", "collecting evidence"),
    ("", "starting"),
])
def test_phase_from_console_log(last, phase):
    assert server.phase(f"[11:59:00] INFO  QUALIFY 0.45.0 x\n{last}\n") == phase


def test_running_means_fresh_log_and_no_result(tmp_path):
    logs = tmp_path / "0.46.0-rc1" / "logs"
    logs.mkdir(parents=True)
    (logs / "debian-12--6.1--fresh-kmod.log").write_text("INFO  check: kernel_version\n")
    (logs / "ubuntu-24.04--6.8--upgrade.log").write_text("RESULT pass\n")
    (tmp_path / "0.46.0-rc1" / "ubuntu-24.04--6.8--upgrade.json").write_text("{}")
    stale = logs / "rocky-9--5.14--fresh-auto.log"
    stale.write_text("INFO  check: x\n")
    old = time.time() - server.RUNNING_STALE_S - 60
    os.utime(stale, (old, old))
    run = server.running_cells(tmp_path, time.time())
    assert [r["cell"] for r in run] == ["debian-12--6.1--fresh-kmod"]
    assert run[0]["phase"] == "checking the host"


# ---------------------------------------------------------------------------
# evidence serving: only what a manifest lists
# ---------------------------------------------------------------------------

def test_resolve_evidence_serves_manifest_files_only(tmp_path):
    rec = record("0.45.0", "ubuntu-20.04--5.4--fresh-auto")
    write_cell(tmp_path, rec, {"install.log": NO_DRIVER})
    (tmp_path / "0.45.0" / "evidence" / rec["cell"] / "_bundle.tgz").write_text("not listed")
    r = server.resolve_evidence
    assert r(tmp_path, "0.45.0", rec["cell"], "install.log").name == "install.log"
    assert r(tmp_path, "0.45.0", rec["cell"], "manifest.json").name == "manifest.json"
    assert r(tmp_path, "0.45.0", rec["cell"], "console.log").name == f"{rec['cell']}.log"
    assert r(tmp_path, "0.45.0", rec["cell"], "_bundle.tgz") is None
    assert r(tmp_path, "0.45.0", rec["cell"], "../../../qualify.py") is None
    assert r(tmp_path, "..", rec["cell"], "install.log") is None
    assert r(tmp_path, "0.45.0", "../0.45.0", "install.log") is None
    assert r(tmp_path, "0.45.0", "no-such--cell--x", "install.log") is None


# ---------------------------------------------------------------------------
# state: grouping, gate, rollup, export
# ---------------------------------------------------------------------------

@pytest.fixture
def grid(tmp_path):
    """Two releases. rc4 ran two cells; 0.45.0 ran four, one of which regressed."""
    write_cell(tmp_path, record("0.45.0-rc4", "ubuntu-20.04--5.4--fresh-auto", "fail",
                                "pkg_installed: exit 100", HALF), {"falco.txt": FALCO_TXT, "install.log": NO_DRIVER})
    write_cell(tmp_path, record("0.45.0-rc4", "ubuntu-22.04--5.15--fresh-kmod"))
    write_cell(tmp_path, record("0.45.0", "ubuntu-20.04--5.4--fresh-auto", "fail",
                                "pkg_installed: exit 100", HALF), {"falco.txt": FALCO_TXT, "install.log": NO_DRIVER})
    write_cell(tmp_path, record("0.45.0", "ubuntu-20.04--5.4--fresh-kmod", "fail",
                                "pkg_installed: exit 100", HALF), {"falco.txt": FALCO_TXT, "install.log": NO_DRIVER})
    write_cell(tmp_path, record("0.45.0", "ubuntu-22.04--5.15--fresh-kmod", "fail", "pkg_installed: exit 100", HALF),
               {"install.log": "  ERROR: Kernel configuration is invalid.\n[exit 100]\n"})
    write_cell(tmp_path, record("0.45.0", "centos-7--3.10--upgrade", "blocked", "N-1 did not install", []))
    return tmp_path


def build(root):
    return server.build_state(root, qual_path=root / "missing.yaml", matrix_path=root / "missing.yaml")


def test_state_versions_in_release_order_and_counts(grid):
    s = build(grid)
    assert s["versions"] == ["0.45.0-rc4", "0.45.0"]
    assert s["per_version"]["0.45.0"]["counts"] == {"fail": 3, "blocked": 1}
    assert s["per_version"]["0.45.0-rc4"]["channel"] == "dev"


def test_one_signature_is_one_failure_however_many_cells(grid):
    groups = build(grid)["per_version"]["0.45.0"]["groups"]
    by_id = {g["id"]: g for g in groups}
    assert set(by_id) == {"falcoctl-no-driver", "kmod-downloaded-headers"}
    assert len(by_id["falcoctl-no-driver"]["cells"]) == 2
    # fresh-auto was red in rc4 (known); fresh-kmod has no earlier result (new)
    assert (by_id["falcoctl-no-driver"]["new_count"], by_id["falcoctl-no-driver"]["known_count"]) == (1, 1)
    # the counters never clobber the signature's issue link
    assert by_id["falcoctl-no-driver"]["known"].endswith("/pull/3994")
    assert by_id["kmod-downloaded-headers"]["known"] is None
    assert by_id["falcoctl-no-driver"]["known_since"] == "0.45.0-rc4"
    # new cells first, then size: both groups have one new cell, #3994 has more
    assert [g["id"] for g in groups] == ["falcoctl-no-driver", "kmod-downloaded-headers"]


def test_gate_in_state_matches_qualify_gate(grid):
    g = build(grid)["per_version"]["0.45.0"]["gate"]
    regressed = [r for r in g["new"] if r["baseline_status"] == "pass"]
    assert [r["cell"] for r in regressed] == ["ubuntu-22.04--5.15--fresh-kmod"]
    assert [r["cell"] for r in g["known"]] == ["ubuntu-20.04--5.4--fresh-auto"]


def test_green_and_blocked_cells_carry_no_signature(grid):
    cells = {(c["version"], c["cell"]): c for c in build(grid)["cells"]}
    assert cells[("0.45.0-rc4", "ubuntu-22.04--5.15--fresh-kmod")]["signature"] is None
    assert cells[("0.45.0", "centos-7--3.10--upgrade")]["signature"] is None
    red = cells[("0.45.0", "ubuntu-20.04--5.4--fresh-auto")]
    assert red["signature"]["file"] == "falco.txt" and red["key_lines"]
    assert red["evidence"][0]["name"] == "falco.txt" and len(red["evidence"][0]["sha256"]) == 64


def test_check_rollup_leaves_out_unjudged_cells(grid):
    rollup = {k["name"]: k for k in build(grid)["per_version"]["0.45.0"]["checks"]}
    assert rollup["pkg_installed"] == {"name": "pkg_installed", "passed": 0, "ran": 3}


def test_grid_axes_come_from_results_when_the_plan_is_unreadable(grid):
    s = build(grid)
    assert s["expected"] == []
    assert {"distro": "ubuntu-20.04", "kernel": "5.4"} in s["targets"]
    assert s["scenarios"][0] == "fresh-auto"


def test_shipped_plan_supplies_expected_cells(grid):
    s = server.build_state(grid, qual_path=ROOT / "qualification.yaml", matrix_path=ROOT / "matrix.yaml")
    assert "ubuntu-20.04--5.15-hwe--upgrade" in s["expected"]
    assert {"distro": "ubuntu-20.04", "kernel": "5.15-hwe"} in s["targets"]


def test_fingerprint_changes_when_a_cell_lands(grid):
    before = server.fingerprint(grid)
    write_cell(grid, record("0.45.0", "debian-12--6.1--fresh-auto"))
    assert server.fingerprint(grid) != before


def test_half_written_result_is_skipped_not_fatal(grid):
    (grid / "0.45.0" / "debian-12--6.1--upgrade.json").write_text('{"schema_version": 1, "cel')
    assert len(build(grid)["cells"]) == 6


# ---------------------------------------------------------------------------
# triage: advisory sentences beside the signature, never part of the verdict
# ---------------------------------------------------------------------------

RED_CELL = ("0.45.0", "ubuntu-20.04--5.4--fresh-auto")


def write_triage(troot, version, cell, manifest_root, **over):
    manifest = json.loads((manifest_root / version / "evidence" / cell / "manifest.json").read_text())
    t = {"schema": "kestrel-triage/1", "version": version, "cell": cell, "cell_status": "fail",
         "evidence_sha256": server.evidence_sha256(manifest), "provider": "ollama",
         "model": "beam:cloud", "outcome": "diagnosed", "grounded": True,
         "root_cause_code": "PACKAGE_SCRIPT_FAILED",
         "summary": "Unguarded falcoctl driver printenv under set -e aborts configuration.",
         "diagnosis": "The postinst exited non-zero. It runs printenv unguarded under set -e.",
         "confidence": 0.9, "generated_at": "2026-10-19T15:57:10Z",
         "citations": [{"ref": "falco.txt:2", "text": "ERROR no supported driver found"}]}
    t.update(over)
    (troot / version).mkdir(parents=True, exist_ok=True)
    (troot / version / f"{cell}.json").write_text(json.dumps(t))
    return t


def triaged(grid, troot):
    s = server.build_state(grid, qual_path=grid / "missing.yaml", matrix_path=grid / "missing.yaml",
                           triage=[troot])
    return s, {(c["version"], c["cell"]): c for c in s["cells"]}


def test_evidence_digest_matches_the_triage_writer():
    # The same vector through the writer's evidence_sha256: if either side
    # changes how it hashes, every sentence silently disappears.
    m = {"files": {"install.log": {"sha256": "ab" * 32}, "falco.txt": {"sha256": "cd" * 32}}}
    assert server.evidence_sha256(m) == "575fa08f32e4336698607cddc31a39ba793feb6d18c5f7b29bb07a40c0ae74f7"


def test_grounded_triage_shows_under_its_signature(grid, tmp_path):
    troot = tmp_path / "tri"
    write_triage(troot, *RED_CELL, grid)
    write_triage(troot, "0.45.0", "ubuntu-20.04--5.4--fresh-kmod", grid)
    s, cells = triaged(grid, troot)
    assert cells[RED_CELL]["triage"]["summary"].startswith("Unguarded falcoctl")
    assert cells[RED_CELL]["triage"]["citations"][0]["ref"] == "falco.txt:2"
    group = next(g for g in s["per_version"]["0.45.0"]["groups"] if g["id"] == "falcoctl-no-driver")
    # two cells, one sentence: one line on the card
    assert [(t["summary"][:10], len(t["cells"])) for t in group["triage"]] == [("Unguarded ", 2)]


@pytest.mark.parametrize("over", [
    {"grounded": False},
    {"outcome": "provider_error", "summary": None},
    {"evidence_sha256": "f" * 64},          # explains evidence this cell no longer has
    {"schema": "something-else/1"},
])
def test_triage_not_shown_unless_grounded_and_current(grid, tmp_path, over):
    troot = tmp_path / "tri"
    write_triage(troot, *RED_CELL, grid, **over)
    s, cells = triaged(grid, troot)
    assert cells[RED_CELL]["triage"] is None
    group = next(g for g in s["per_version"]["0.45.0"]["groups"] if g["id"] == "falcoctl-no-driver")
    assert "triage" not in group


def test_triage_never_changes_the_verdict(grid, tmp_path):
    troot = tmp_path / "tri"
    without, _ = triaged(grid, troot)
    for cell in ("ubuntu-20.04--5.4--fresh-auto", "ubuntu-20.04--5.4--fresh-kmod",
                 "ubuntu-22.04--5.15--fresh-kmod"):
        write_triage(troot, "0.45.0", cell, grid)
    with_t, cells = triaged(grid, troot)
    assert all(cells[("0.45.0", c)]["triage"] for c in ("ubuntu-20.04--5.4--fresh-auto",))
    for v in ("0.45.0-rc4", "0.45.0"):
        a, b = without["per_version"][v], with_t["per_version"][v]
        assert (a["gate"], a["counts"], a["checks"]) == (b["gate"], b["counts"], b["checks"])
    assert [c["status"] for c in without["cells"]] == [c["status"] for c in with_t["cells"]]


def test_blocked_cell_shows_triage_in_its_drawer_only(grid, tmp_path):
    troot = tmp_path / "tri"
    blocked = ("0.45.0", "centos-7--3.10--upgrade")
    write_triage(troot, *blocked, grid, cell_status="blocked")
    s, cells = triaged(grid, troot)
    assert cells[blocked]["triage"] and cells[blocked]["signature"] is None
    assert all("triage" not in g for g in s["per_version"]["0.45.0"]["groups"])


def test_triage_read_from_the_results_roots_sibling(tmp_path):
    # The Jenkins job writes results/triage beside results/qualification;
    # the dashboard finds it with no flag.
    results = tmp_path / "results" / "qualification"
    rec = record("0.45.0", "ubuntu-20.04--5.4--fresh-auto", "fail", "pkg_installed: exit 100", HALF)
    write_cell(results, rec, {"falco.txt": FALCO_TXT, "install.log": NO_DRIVER})
    write_triage(tmp_path / "results" / "triage", *RED_CELL, results)
    s = server.build_state(results, qual_path=tmp_path / "x.yaml", matrix_path=tmp_path / "x.yaml")
    assert s["cells"][0]["triage"]["root_cause_code"] == "PACKAGE_SCRIPT_FAILED"


def test_fingerprint_changes_when_triage_lands(grid, tmp_path):
    troot = tmp_path / "tri"
    before = server.fingerprint(grid, [troot])
    write_triage(troot, *RED_CELL, grid)
    assert server.fingerprint(grid, [troot]) != before


def test_page_labels_triage_advisory():
    page = server.PAGE.read_text()
    assert "Model triage · advisory" in page and "not part of the gate" in page


def test_export_embeds_state_and_cannot_close_its_script_tag(grid):
    state = build(grid)
    state["cells"][0]["reason"] = "</script><script>alert(1)</script>"
    html = server.export_fragment(state)
    assert "<!--KESTREL_DATA-->" not in html
    assert html.count("</script>") == server.page_fragment().count("</script>") + 1
    blob = html.split("window.KESTREL_SNAPSHOT = ", 1)[1].split(";</script>", 1)[0]
    data = json.loads(blob.replace("<\\/", "</"))
    assert data["mode"] == "snapshot" and data["versions"] == ["0.45.0-rc4", "0.45.0"]


def test_page_has_a_title_and_one_data_slot():
    page = server.page_fragment()
    assert page.startswith("<title>Kestrel QA</title>")
    assert page.count("<!--KESTREL_DATA-->") == 1


# ---------------------------------------------------------------------------
# export menu: HTML, JSON, PDF
# ---------------------------------------------------------------------------

def test_pdf_opens_the_snapshot_on_the_asked_release(tmp_path):
    cmd = server.pdf_command("chrome", tmp_path / "page.html", "0.45.1-rc1+fix-postinst-printenv",
                             tmp_path / "out.pdf", tmp_path / "profile")
    # The page reads #v_<version> raw: a '+' escaped to %2B would pick no release.
    assert cmd[-1].endswith("page.html#v_0.45.1-rc1+fix-postinst-printenv")
    assert f"--print-to-pdf={tmp_path / 'out.pdf'}" in cmd and "--no-pdf-header-footer" in cmd
    assert "--password-store=basic" in cmd          # else a 25 s D-Bus keyring wait per PDF


def test_page_has_print_styles_and_an_export_menu():
    page = server.page_fragment()
    assert "@media print" in page and "@page" in page
    for href in ('href="/export"', 'href="/export.json"', 'href="/export.pdf"'):
        assert href in page


@pytest.mark.skipif(not server.find_chrome(), reason="no Chrome on this host")
def test_pdf_renders_a_real_pdf(grid):
    pdf = server.render_pdf(build(grid), "0.45.0")
    assert pdf.startswith(b"%PDF-") and len(pdf) > 10_000


def test_page_has_the_logo_with_a_name_and_a_print_image():
    page = server.page_fragment()
    assert "<span class=\"logo\" role=\"img\" aria-label=\"Kestrel QA\">" in page
    assert page.count("<link rel=\"icon\"") == 1
    # Masks can print as a solid block; print must swap in a plain image.
    print_css = page[page.index("@media print"):]
    assert ".logo { background: url(data:image/png" in print_css


# ---------------------------------------------------------------------------
# sensor suite: shown beside the gate, never part of it
# ---------------------------------------------------------------------------

JUNIT_FAIL = """<?xml version="1.0" encoding="utf-8"?>
<testsuites name="pytest tests"><testsuite name="sensor.x" errors="1" failures="2" skipped="1" tests="6">
<testcase classname="sensor_tests.test_00_install" name="test_install[pkg_installed]" time="1"/>
<testcase classname="sensor_tests.test_10_detection" name="test_syscall[mount]" time="1">
  <failure message="AssertionError: no 'KM cov mount' alert within 30s&#10;assert False">trace</failure></testcase>
<testcase classname="sensor_tests.test_60_lifecycle" name="test_purge_leaves_nothing" time="1">
  <failure message="&#10;#x1B[90mAssertionError: purge exited 100#x1B[0m: .&#10;  [PRE-REMOVE] Stop">trace</failure></testcase>
<testcase classname="sensor_tests.test_30_outputs" name="test_grpc_output" time="1">
  <error message="failed on setup with &quot;TimeoutError&quot;">trace</error></testcase>
<testcase classname="sensor_tests.test_50_soak" name="test_soak" time="0"><skipped message="soak off"/></testcase>
<testcase classname="sensor_tests.test_60_lifecycle" name="test_restart" time="1"/>
</testsuite></testsuites>
"""
JUNIT_PURGE = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="sensor.y" errors="0" failures="1" skipped="0" tests="3">
<testcase classname="sensor_tests.test_00_install" name="test_install[pkg_installed]"/>
<testcase classname="sensor_tests.test_60_lifecycle" name="test_purge_leaves_nothing">
  <failure message="AssertionError: left behind after purge">trace</failure></testcase>
<testcase classname="sensor_tests.test_60_lifecycle" name="test_restart"/>
</testsuite></testsuites>
"""
JUNIT_OK = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="sensor.z" errors="0" failures="0" skipped="0" tests="2">
<testcase classname="sensor_tests.test_00_install" name="test_install[pkg_installed]"/>
<testcase classname="sensor_tests.test_60_lifecycle" name="test_restart"/>
</testsuite></testsuites>
"""


def write_sensor(sensor_root, version, cells):
    """cells: {cell: (summary entry, junit text or None)}, as run.py leaves them."""
    vdir = sensor_root / version
    vdir.mkdir(parents=True, exist_ok=True)
    for cell, (_, junit) in cells.items():
        (vdir / cell).mkdir(exist_ok=True)
        (vdir / cell / "pytest.log").write_text(f"{cell}: collected\n")
        if junit is not None:
            (vdir / cell / "junit.xml").write_text(junit)
    (vdir / "summary.json").write_text(json.dumps({c: s for c, (s, _) in cells.items()}, indent=2))


SENSOR_CELLS = {
    "ubuntu-20.04--5.4--fresh-auto": ({"exit": 1, "tests": 6, "failures": 2, "errors": 1, "skipped": 1}, JUNIT_FAIL),
    "ubuntu-22.04--5.15--fresh-kmod": ({"exit": 1, "tests": 3, "failures": 1, "errors": 0, "skipped": 0}, JUNIT_PURGE),
    "debian-12--6.1--fresh-auto": ({"exit": 0, "tests": 2, "failures": 0, "errors": 0, "skipped": 0}, JUNIT_OK),
}


@pytest.fixture
def results(tmp_path):
    """A results dir as the lab lays it out: qualification/ and sensor/ side
    by side. The grid fixture's root is tmp_path itself, whose parent is
    shared across tests, so sensor tests get their own pair."""
    qual = tmp_path / "results" / "qualification"
    qual.mkdir(parents=True)
    for rec in [record("0.45.0-rc4", "ubuntu-20.04--5.4--fresh-auto", "fail", "pkg_installed: exit 100", HALF),
                record("0.45.0", "ubuntu-20.04--5.4--fresh-auto", "fail", "pkg_installed: exit 100", HALF),
                record("0.45.0", "ubuntu-22.04--5.15--fresh-kmod")]:
        write_cell(qual, rec, {"falco.txt": FALCO_TXT, "install.log": NO_DRIVER} if rec["status"] == "fail" else None)
    write_sensor(tmp_path / "results" / "sensor", "0.45.0", SENSOR_CELLS)
    return qual


def test_sensor_dir_sits_beside_the_qualification_root(results):
    assert server.sensor_dir(results) == results.parent / "sensor"


def test_sensor_block_counts_cells_and_tests_from_summary(results):
    sn = build(results)["per_version"]["0.45.0"]["sensor"]
    assert sn["totals"] == {"cells": 3, "cells_passed": 1, "tests": 11, "passed": 6,
                            "failures": 3, "errors": 1, "skipped": 1}
    by = {c["cell"]: c for c in sn["cells"]}
    assert by["debian-12--6.1--fresh-auto"]["status"] == "pass"
    assert by["ubuntu-20.04--5.4--fresh-auto"]["status"] == "fail"
    assert by["ubuntu-20.04--5.4--fresh-auto"]["passed"] == 2
    assert (by["ubuntu-22.04--5.15--fresh-kmod"]["distro"], by["ubuntu-22.04--5.15--fresh-kmod"]["kernel"],
            by["ubuntu-22.04--5.15--fresh-kmod"]["scenario"]) == ("ubuntu-22.04", "5.15", "fresh-kmod")
    assert all(c["log"] for c in sn["cells"])
    assert sn["ran_at"].endswith("Z")


def test_sensor_failing_tests_named_from_junit_with_clean_messages(results):
    sn = build(results)["per_version"]["0.45.0"]["sensor"]
    cell = next(c for c in sn["cells"] if c["cell"] == "ubuntu-20.04--5.4--fresh-auto")
    assert [(f["name"], f["kind"]) for f in cell["failing"]] == [
        ("test_10_detection::test_syscall[mount]", "failure"),
        ("test_60_lifecycle::test_purge_leaves_nothing", "failure"),
        ("test_30_outputs::test_grpc_output", "error")]
    # First non-blank line only, pytest's #x1B stand-ins for ESC removed.
    assert cell["failing"][0]["message"] == "AssertionError: no 'KM cov mount' alert within 30s"
    assert cell["failing"][1]["message"] == "AssertionError: purge exited 100: ."


def test_sensor_failing_tests_roll_up_across_cells(results):
    ft = build(results)["per_version"]["0.45.0"]["sensor"]["failing_tests"]
    assert ft[0]["name"] == "test_60_lifecycle::test_purge_leaves_nothing"
    assert sorted(ft[0]["cells"]) == ["ubuntu-20.04--5.4--fresh-auto", "ubuntu-22.04--5.15--fresh-kmod"]
    assert [len(t["cells"]) for t in ft] == [2, 1, 1]


@pytest.mark.parametrize("entry,status", [
    ({"exit": 0, "tests": 2, "failures": 0, "errors": 0, "skipped": 0}, "pass"),
    ({"exit": 5, "tests": 0, "failures": 0, "errors": 0, "skipped": 0}, "pass"),     # -k selected nothing
    ({"exit": 1, "tests": 2, "failures": 1, "errors": 1, "skipped": 0}, "fail"),
    ({"exit": 1, "tests": 2, "failures": 0, "errors": 1, "skipped": 0}, "error"),
    ({"exit": -9, "tests": 0, "failures": 0, "errors": 0, "skipped": 0}, "error"),   # killed mid-run
    ({"exit": 1, "tests": 0, "failures": 0, "errors": 1, "skipped": 0, "note": "no junit written"}, "error"),
])
def test_sensor_cell_status_follows_run_py_exit_rule(tmp_path, entry, status):
    write_sensor(tmp_path, "0.45.0", {"debian-12--6.1--fresh-auto": (entry, None)})
    cell = server.sensor_block(tmp_path, "0.45.0")["cells"][0]
    assert cell["status"] == status and cell["failing"] == []
    assert cell["note"] == entry.get("note")


def test_sensor_never_changes_the_gate(results):
    with_sensor = build(results)["per_version"]
    shutil.rmtree(results.parent / "sensor")
    without = build(results)["per_version"]
    assert without["0.45.0"]["sensor"] is None
    for v in without:
        assert {k: x for k, x in with_sensor[v].items() if k != "sensor"} == \
               {k: x for k, x in without[v].items() if k != "sensor"}
    # A red sensor run on a version whose gate is clear stays clear.
    assert with_sensor["0.45.0"]["gate"]["new"] == []


def test_sensor_missing_or_half_written_is_none_not_fatal(results):
    s = build(results)
    assert s["per_version"]["0.45.0-rc4"]["sensor"] is None
    (results.parent / "sensor" / "0.45.0" / "summary.json").write_text('{"ubuntu-20.04--5.4--fre')
    assert build(results)["per_version"]["0.45.0"]["sensor"] is None
    write_sensor(results.parent / "sensor", "0.45.0", {"debian-12--6.1--fresh-auto": SENSOR_CELLS["debian-12--6.1--fresh-auto"]})
    (results.parent / "sensor" / "0.45.0" / "debian-12--6.1--fresh-auto" / "junit.xml").write_text("<testsuites><test")
    cell = build(results)["per_version"]["0.45.0"]["sensor"]["cells"][0]
    assert cell["failing"] == [] and cell["status"] == "pass"


def test_sensor_read_from_first_root_that_has_it(tmp_path):
    # Jenkins qualified the version; the sensor run was by hand in a clone.
    jenkins, clone = tmp_path / "ws" / "results" / "qualification", tmp_path / "km" / "results" / "qualification"
    write_cell(jenkins, record("0.45.0", "debian-12--6.1--fresh-auto"))
    clone.mkdir(parents=True)
    write_sensor(clone.parent / "sensor", "0.45.0", {"debian-12--6.1--fresh-auto": SENSOR_CELLS["debian-12--6.1--fresh-auto"]})
    roots = [jenkins, clone]
    plan = dict(qual_path=tmp_path / "missing.yaml", matrix_path=tmp_path / "missing.yaml")
    s = server.build_state(roots, **plan)
    assert s["per_version"]["0.45.0"]["sensor"]["totals"]["cells"] == 1
    assert server.resolve_sensor(roots, "0.45.0", "debian-12--6.1--fresh-auto", "pytest.log") \
        == clone.parent / "sensor" / "0.45.0" / "debian-12--6.1--fresh-auto" / "pytest.log"
    write_sensor(jenkins.parent / "sensor", "0.45.0", {"ubuntu-20.04--5.4--fresh-auto": SENSOR_CELLS["ubuntu-20.04--5.4--fresh-auto"]})
    assert [c["cell"] for c in server.build_state(roots, **plan)["per_version"]["0.45.0"]["sensor"]["cells"]] \
        == ["ubuntu-20.04--5.4--fresh-auto"]


def test_resolve_sensor_serves_listed_cells_log_and_junit_only(results):
    r, cell = server.resolve_sensor, "ubuntu-20.04--5.4--fresh-auto"
    vdir = results.parent / "sensor" / "0.45.0"
    (vdir / cell / "measurements.json").write_text("{}")
    (vdir / "rocky-9--5.14--fresh-auto").mkdir()
    (vdir / "rocky-9--5.14--fresh-auto" / "pytest.log").write_text("not in the summary")
    assert r(results, "0.45.0", cell, "pytest.log") == vdir / cell / "pytest.log"
    assert r(results, "0.45.0", cell, "junit.xml") == vdir / cell / "junit.xml"
    assert r(results, "0.45.0", cell, "measurements.json") is None
    assert r(results, "0.45.0", cell, "../../summary.json") is None
    assert r(results, "0.45.0", "rocky-9--5.14--fresh-auto", "pytest.log") is None
    assert r(results, "..", cell, "pytest.log") is None
    assert r(results, "0.45.0", "..", "pytest.log") is None
    assert r(results, "0.45.0", f"../0.45.0/{cell}", "pytest.log") is None
    assert r(results, "0.45.0-rc4", cell, "pytest.log") is None


def test_fingerprint_changes_when_a_sensor_run_lands(results):
    before = server.fingerprint(results)
    write_sensor(results.parent / "sensor", "0.45.0-rc4",
                 {"debian-12--6.1--fresh-auto": SENSOR_CELLS["debian-12--6.1--fresh-auto"]})
    assert server.fingerprint(results) != before


def test_http_serves_sensor_state_and_log_as_text(results):
    from http.server import ThreadingHTTPServer
    from threading import Thread
    from urllib.error import HTTPError
    from urllib.request import urlopen

    handler = type("H", (server.Handler,), {"root": [results]})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        state = json.loads(urlopen(base + "/api/state").read())
        assert state["per_version"]["0.45.0"]["sensor"]["totals"]["cells_passed"] == 1
        resp = urlopen(base + "/sensor/0.45.0/ubuntu-20.04--5.4--fresh-auto/junit.xml")
        assert resp.headers["Content-Type"].startswith("text/plain") and b"<testsuites" in resp.read()
        with pytest.raises(HTTPError) as err:
            urlopen(base + "/sensor/0.45.0/ubuntu-20.04--5.4--fresh-auto/..%2F..%2Fsummary.json")
        assert err.value.code == 404
    finally:
        srv.shutdown()
        srv.server_close()


def test_page_shows_the_sensor_suite_as_informational():
    page = server.page_fragment()
    panel = page[page.index('<h2 id="senTitle">'):]
    panel = panel[:panel.index("</section>")]
    assert "informational" in panel and "not part of the gate" in panel and "UNSTABLE" in panel
    assert "renderSensor()" in page and "/sensor/${encodeURIComponent(version)}" in page
    # The verdict tile reads the gate only.
    tiles = page[page.index("function renderTiles()"):page.index("function cellAt(")]
    assert "sensor" not in tiles


def test_falcoctl_signature_names_the_regression_and_its_fix():
    sig = next(s for s in server.SIGNATURES if s["id"] == "falcoctl-no-driver")
    assert sig["known"].endswith("/pull/3994") and sig["known_label"] == "regression from"
    assert sig["fixed"].endswith("/pull/4037")


def test_red_cell_hover_has_signature_gate_and_grounded_triage_lines():
    page = server.page_fragment()
    # one place builds the hover; the grid uses it
    assert "function cellTip(c, gs)" in page and "cellTip(x.c, gs)" in page
    # line 1 deterministic (signature + new/known), line 2 only from a triage
    # the server already matched to this evidence
    assert "NEW in this release" in page and "known since" in page
    assert "c.triage?.summary" in page

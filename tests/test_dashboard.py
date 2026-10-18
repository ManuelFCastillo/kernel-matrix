"""
Tests for dashboard/server.py: the code that turns qualification results on
disk into what Kestrel QA shows. The page draws whatever this hands it, so a
wrong group, a stale "running" cell or a served file outside the results is
decided here, not in the browser.
"""

import json
import os
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
    assert found["known"].endswith("/issues/3994")


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
    assert by_id["falcoctl-no-driver"]["known"].endswith("/issues/3994")
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

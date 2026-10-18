#!/usr/bin/env python3
"""
dashboard/server.py -- Kestrel QA, the live view of package qualification.

qualify.py writes one JSON per cell as each VM finishes, plus a console log
the moment a cell starts. This server reads that directory on every poll, so
the grid fills in while a run is still going: no database, no push step, and
nothing a crashed run can leave half-written except files qualify.py already
owns.

    python3 dashboard/server.py                      # http://hardac2:8099
    python3 dashboard/server.py --export kestrel.html  # frozen snapshot page
    python3 dashboard/server.py --results A --results B  # several result roots

The page's Export menu downloads the same data three ways: /export (the
snapshot page as a standalone .html), /export.json (the state, every
release) and /export.pdf?version=V (one release, printed by headless Chrome
from the snapshot page with the page's print styles).

Several --results roots show as one grid, so the grid of record (the Jenkins
workspace) and a hand-run branch build sit in the same Release picker. Each
version is read from the first root that has it.

Read-only by construction. The only files it serves are cell results, cell
logs and the files a cell's evidence manifest lists, each resolved against
the cell it belongs to.

What the page shows, and where each number comes from:

    gate        qualify.gate(): red cells that are new against the newest
                earlier version that ran the same distro/kernel/scenario
    grid        one cell per target x scenario, from the cell JSONs; cells in
                qualification.yaml with no result yet are queued or running
    signatures  each red cell matched against known failure patterns in its
                own evidence, with the file and line that matched. Cells with
                the same signature are one failure, not many
    evidence    the manifest qualify.py wrote (sha256 per file), served as is
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

import qualify  # noqa: E402

PAGE = HERE / "kestrel.html"
RESULTS = REPO / "results" / "qualification"
RUNNING_STALE_S = 45 * 60      # a log older than any cell can take is a dead run

# ---------------------------------------------------------------------------
# Failure signatures: what a red cell's own evidence says went wrong
# ---------------------------------------------------------------------------
# Matched in order against the cell's evidence files; the first pattern that
# hits names the failure and cites the line. Patterns quote the evidence
# literally, so a signature is something an engineer can grep for, never an
# interpretation of it. `known` links a public issue when one exists.
SIGNATURES = [
    {"id": "falcoctl-no-driver",
     "pattern": r"no supported driver found for distro",
     "title": "falcoctl: no supported driver found",
     "summary": "The postinst asks falcoctl for a driver before it allows kmod, "
                "fails under set -e, and leaves the package half-configured.",
     "known": "https://github.com/falcosecurity/falco/issues/3994"},
    {"id": "kmod-downloaded-headers",
     "pattern": r"Kernel configuration is invalid|scripts/Makefile\.debug: No such file",
     "title": "kmod build against falcoctl's downloaded headers failed",
     "summary": "falcoctl builds against headers it downloads into /tmp/kernel-download "
                "instead of the installed ones, and the downloaded tree cannot build a module.",
     "known": None},
    {"id": "secure-boot-unsigned-module",
     "pattern": r"Loading of module with unavailable key is rejected",
     "title": "Kernel rejected the unsigned module (Secure Boot)",
     "summary": "The dkms module built, and the kernel refused to load it under Secure Boot.",
     "known": None},
    {"id": "unit-exec-format",
     "pattern": r"not loaded properly: Exec format error",
     "title": "systemd rejected the shipped unit file",
     "summary": "systemd 237 refuses a unit whose ExecReload is not an absolute path; "
                "the postinst ignores the failed start.",
     "known": None},
    {"id": "glibc-floor",
     "pattern": r"Requires: libc\.so\.6\(GLIBC_2\.\d+\)",
     "title": "Package requires a newer glibc",
     "summary": "The package's glibc floor is above what this distro ships.",
     "known": None},
]
EVIDENCE_ORDER = ("install.log", "falco.txt", "dmesg.log", "journal.log", "probe.log", "prereqs.log")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def clean(line: str) -> str:
    return _ANSI.sub("", line).rstrip()


def find_signature(evidence_dir: Path) -> dict | None:
    """First known pattern in the cell's evidence, with file, line and text."""
    for sig in SIGNATURES:
        rx = re.compile(sig["pattern"])
        for name in EVIDENCE_ORDER:
            path = evidence_dir / name
            if not path.is_file():
                continue
            for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if rx.search(line):
                    return {**{k: sig[k] for k in ("id", "title", "summary", "known")},
                            "file": name, "line": n, "text": clean(line)[:240]}
    return None


def fallback_signature(record: dict) -> dict:
    """No known pattern: group by the first failed check and its observation,
    with digits blanked so kernel versions and timings do not split groups."""
    reason = record.get("reason") or record.get("status")
    norm = re.sub(r"\d+", "N", reason.split(":", 1)[0] + ":" + reason.split(":", 1)[-1])[:80]
    return {"id": "unmatched-" + hashlib.sha1(norm.encode()).hexdigest()[:8],
            "title": reason[:90], "summary": "No known failure pattern matched this cell's evidence.",
            "known": None, "file": None, "line": None, "text": None}


def key_lines(evidence_dir: Path, sig: dict | None, limit: int = 8) -> list[dict]:
    """The lines worth reading first: the signature match with its neighbours,
    then error lines from the install log."""
    out: list[dict] = []
    if sig and sig.get("file"):
        lines = (evidence_dir / sig["file"]).read_text(errors="replace").splitlines()
        for n in range(max(1, sig["line"] - 2), min(len(lines), sig["line"] + 2) + 1):
            if n != sig["line"] and not clean(lines[n - 1]).strip():
                continue                 # a blank neighbour says nothing
            out.append({"file": sig["file"], "line": n, "text": clean(lines[n - 1])[:240],
                        "match": n == sig["line"]})
    install = evidence_dir / "install.log"
    if install.is_file():
        seen = {(o["file"], o["line"]) for o in out}
        for n, line in enumerate(install.read_text(errors="replace").splitlines(), 1):
            if len(out) >= limit:
                break
            if re.search(r"(?i)^E:|error|scriptlet failed|\[exit [1-9]", line) and ("install.log", n) not in seen:
                out.append({"file": "install.log", "line": n, "text": clean(line)[:240], "match": False})
    return out[:limit]


# ---------------------------------------------------------------------------
# State: everything the page needs, rebuilt from disk
# ---------------------------------------------------------------------------
def load_records(root: Path) -> list[dict]:
    out = []
    for path in sorted(root.glob("*/*.json")):
        try:
            r = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue                     # a result mid-write: next poll gets it
        if r.get("schema_version") == qualify.SCHEMA_VERSION and "cell" in r:
            out.append(r)
    return out


def as_roots(root: Path | list[Path]) -> list[Path]:
    return [root] if isinstance(root, Path) else list(root)


def owners(roots: list[Path]) -> dict[str, Path]:
    """Version -> the root it is read from: the first root that has it."""
    out: dict[str, Path] = {}
    for root in roots:
        if root.is_dir():
            for d in sorted(root.iterdir()):
                if d.is_dir():
                    out.setdefault(d.name, root)
    return out


def fingerprint(root: Path | list[Path]) -> str:
    """Changes whenever a result, log or evidence file lands or grows."""
    h = hashlib.sha1()
    for r in as_roots(root):
        for path in sorted(r.glob("*/*.json")) + sorted(r.glob("*/logs/*.log")):
            try:
                st = path.stat()
            except OSError:
                continue
            h.update(f"{r}:{path.relative_to(r)}:{st.st_mtime_ns}:{st.st_size}".encode())
    return h.hexdigest()[:16]


def phase(log_text: str) -> str:
    """What a running cell is doing, from the last line of its console log."""
    steps = [("RESULT", "finishing"), ("evidence:", "collecting evidence"),
             ("[probe] detected", "detecting the event"), ("[probe] idle cost", "measuring"),
             ("[probe]", "installing Falco"), ("installing and characterising", "installing Falco"),
             ("build prerequisites", "preparing build tools"), ("kernel variant", "switching kernel"),
             ("check:", "checking the host"), ("ssh ready", "booted"), ("virt-install", "booting VM")]
    for line in reversed(log_text.splitlines()[-40:]):
        for needle, label in steps:
            if needle in line:
                return label
    return "starting"


def running_cells(root: Path, now: float) -> list[dict]:
    """A cell whose log exists and is fresh but whose result does not."""
    out = []
    for log in sorted(root.glob("*/logs/*.log")):
        version, name = log.parent.parent.name, log.stem
        if (root / version / f"{name}.json").exists():
            continue
        age = now - log.stat().st_mtime
        if age > RUNNING_STALE_S:
            continue
        text = log.read_text(errors="replace")
        started = log.stat().st_ctime
        out.append({"version": version, "cell": name, "phase": phase(text),
                    "elapsed_s": round(now - started)})
    return out


def compact(record: dict, root: Path) -> dict:
    """One cell as the page needs it: verdict, checks, package, evidence."""
    vdir = root / record["version"]
    edir = vdir / Path(record["evidence"]).parent
    manifest = {}
    if (edir / "manifest.json").is_file():
        try:
            manifest = json.loads((edir / "manifest.json").read_text())
        except json.JSONDecodeError:
            manifest = {}
    red = record["status"] in qualify.RED
    sig = (find_signature(edir) or fallback_signature(record)) if red else None
    probe = record.get("probe") or {}
    return {
        "version": record["version"], "cell": record["cell"], "channel": record["channel"],
        "distro": record["distro"], "kernel": record["kernel"],
        "kernel_observed": record["kernel_observed"], "scenario": record["scenario"]["id"],
        "upgrade_from": record["scenario"].get("upgrade_from"),
        "status": record["status"], "reason": record["reason"], "checks": record["checks"],
        "driver": record.get("driver"), "secure_boot": record.get("secure_boot"),
        "modern_ebpf_capable": record.get("modern_ebpf_capable"),
        "prereqs": record.get("prereqs"), "package": record.get("package") or {},
        "error": record.get("error"),
        "sensor": {k: probe.get(k) for k in ("rss_kb", "cpu_percent", "install_seconds",
                                             "start_seconds", "detect_seconds", "bpf_load_errors",
                                             "rule_matched", "active_unit")},
        "started_at": record.get("started_at"), "duration_s": record.get("duration_s"),
        "git_sha": record.get("git_sha"),
        "build": record.get("build"),
        "signature": sig,
        "key_lines": key_lines(edir, sig) if red else [],
        "evidence": [{"name": n, "bytes": f["bytes"], "lines": f["lines"], "sha256": f["sha256"]}
                     for n, f in sorted((manifest.get("files") or {}).items())],
        "collected_at": manifest.get("collected_at"),
    }


def failure_groups(cells: list[dict], gate: dict) -> list[dict]:
    """Red cells of one version, grouped by signature, new before known."""
    status_of = {r["cell"]: "new" for r in gate["new"]} | {r["cell"]: "known" for r in gate["known"]}
    since = {r["cell"]: r["baseline_version"] for r in gate["known"]}
    groups: dict[str, dict] = {}
    for c in cells:
        sig = c.get("signature")
        if not sig:
            continue
        key = f"{c['distro']}--{c['kernel']}--{c['scenario']}"
        # *_count, not "known": the signature's "known" is its issue link.
        g = groups.setdefault(sig["id"], {**sig, "cells": [], "new_count": 0, "known_count": 0,
                                          "known_since": None})
        g["cells"].append(c["cell"])
        state = status_of.get(key, "new")
        g[f"{state}_count"] += 1
        if state == "known":
            g["known_since"] = g["known_since"] or since.get(key)
    return sorted(groups.values(), key=lambda g: (-g["new_count"], -len(g["cells"]), g["title"]))


def check_rollup(cells: list[dict]) -> list[dict]:
    """Per check: cells that ran it, and how many passed. Cells the harness
    could not judge (error, blocked) have no checks and are left out."""
    out = []
    for name in qualify.CHECK_NAMES:
        ran = [c for c in cells for k in c["checks"] if k["name"] == name]
        passed = sum(1 for c in cells for k in c["checks"] if k["name"] == name and k["passed"])
        out.append({"name": name, "passed": passed, "ran": len(ran)})
    return out


def expected_cells(qual_path: Path, matrix_path: Path) -> list[str]:
    """Cell names qualification.yaml asks for, so a grid can show its gaps."""
    try:
        qual = qualify.load_qualification(qual_path)
        distros = {d.name: d for d in qualify.provision.load_matrix(matrix_path)[0]}
        return [qualify.cell_name(distros[t], s.id) for t in qual["targets"] for s in qual["scenarios"]
                if t in distros]
    except Exception:  # noqa: BLE001 -- the grid still renders from results alone
        return []


def build_state(root: Path | list[Path] = RESULTS, qual_path: Path = REPO / "qualification.yaml",
                matrix_path: Path = REPO / "matrix.yaml", now: float | None = None) -> dict:
    now = now or time.time()
    roots = as_roots(root)
    owner = owners(roots)
    records, cells, running = [], [], []
    for r_root in roots:
        mine = [r for r in load_records(r_root) if owner.get(r["version"]) == r_root]
        records += mine
        cells += [compact(r, r_root) for r in mine]
        running += [r for r in running_cells(r_root, now) if owner.get(r["version"]) == r_root]
    flat = [{"version": r["version"], "distro": r["distro"], "kernel": r["kernel"],
             "scenario": r["scenario"]["id"], "status": r["status"], "reason": r["reason"],
             "channel": r["channel"]}
            for r in records]
    versions = sorted({c["version"] for c in cells} | {r["version"] for r in running},
                      key=qualify.version_key)
    per_version = {}
    for v in versions:
        vcells = [c for c in cells if c["version"] == v]
        g = qualify.gate(flat, v)
        counts: dict[str, int] = {}
        for c in vcells:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        build = next((c["build"] for c in vcells if c.get("build")), None)
        per_version[v] = {
            # The cells say what they were; the plan only knows its own builds.
            "channel": vcells[0]["channel"] if vcells else qualify.channel(v),
            "build": build and {k: build.get(k) for k in ("label", "base", "source", "patch")},
            "gate": {k: g[k] for k in ("new", "known", "fixed", "cells")},
            "counts": counts,
            "running": sum(1 for r in running if r["version"] == v),
            "groups": failure_groups(vcells, g),
            "checks": check_rollup(vcells),
            "baseline": sorted({r["baseline_version"] for r in g["new"] + g["known"] + g["fixed"]
                                if r["baseline_version"]}, key=qualify.version_key),
        }
    expected = expected_cells(qual_path, matrix_path)
    names = list(dict.fromkeys(expected + [c["cell"] for c in cells]))
    # The plan's order when it is readable; otherwise fresh installs before
    # the upgrade, the order a fleet meets them.
    canon = ["fresh-auto", "fresh-kmod", "fresh-modern_ebpf", "upgrade"]
    planned = list(dict.fromkeys(n.rsplit("--", 1)[1] for n in expected))
    seen = {n.rsplit("--", 1)[1] for n in names} - set(planned)
    scenario_order = planned + sorted(seen, key=lambda x: (canon.index(x) if x in canon else 99, x))
    targets = sorted({tuple(n.rsplit("--", 1)[0].split("--", 1)) for n in names},
                     key=lambda t: (t[0], qualify.provision.kernel_key(t[1])))
    return {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "fingerprint": fingerprint(roots),
        "versions": versions,
        "targets": [{"distro": d, "kernel": k} for d, k in targets],
        "scenarios": scenario_order,
        "expected": expected,
        "per_version": per_version,
        "cells": cells,
        "running": running,
    }


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------
def page_fragment() -> str:
    return PAGE.read_text()


def wrap(fragment: str) -> str:
    """The live page: the same fragment the exported artifact publishes,
    inside a document skeleton the artifact host would otherwise supply."""
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">"
            "</head><body>" + fragment + "</body></html>")


def export_fragment(state: dict) -> str:
    """The page with its data inside it: a frozen snapshot that needs no server."""
    data = json.dumps({**state, "mode": "snapshot"}, separators=(",", ":")).replace("</", "<\\/")
    return page_fragment().replace("<!--KESTREL_DATA-->",
                                   f"<script>window.KESTREL_SNAPSHOT = {data};</script>", 1)


CHROMES = ("google-chrome-stable", "google-chrome", "chromium", "chromium-browser")


def find_chrome() -> str | None:
    found = os.environ.get("KESTREL_CHROME")
    return found if found else next((c for c in map(shutil.which, CHROMES) if c), None)


def pdf_command(chrome: str, page: Path, version: str, out: Path, profile: Path) -> list[str]:
    """Headless Chrome printing the snapshot page open on one release. The
    page picks the release from #v_<version>; the virtual time budget lets
    its script render and the web fonts arrive before the print.
    --password-store=basic: otherwise Chrome asks the desktop keyring over
    D-Bus and, with no keyring in the service's session, waits out D-Bus's
    25 s timeout on every PDF (0.6 s with it, same bytes)."""
    url = page.as_uri() + "#v_" + quote(version, safe="+._-")
    return [chrome, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
            "--password-store=basic", "--disable-background-networking",
            "--hide-scrollbars", f"--user-data-dir={profile}", "--no-pdf-header-footer",
            "--run-all-compositor-stages-before-draw", "--virtual-time-budget=5000",
            f"--print-to-pdf={out}", url]


def render_pdf(state: dict, version: str, timeout: int = 120) -> bytes:
    chrome = find_chrome()
    if not chrome:
        raise RuntimeError("no Chrome or Chromium on this host (set KESTREL_CHROME)")
    with tempfile.TemporaryDirectory(prefix="kestrel-pdf-") as tmp:
        page, out = Path(tmp) / "page.html", Path(tmp) / "out.pdf"
        page.write_text(wrap(export_fragment(state)))
        proc = subprocess.run(pdf_command(chrome, page, version, out, Path(tmp) / "profile"),
                              capture_output=True, text=True, timeout=timeout)
        if not out.is_file() or out.stat().st_size == 0:
            raise RuntimeError(f"chrome exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
        return out.read_bytes()


def resolve_evidence(root: Path | list[Path], version: str, cell: str, name: str) -> Path | None:
    """A served file must be one the cell's own manifest lists, or its log."""
    if not re.fullmatch(r"[0-9A-Za-z.+_-]+", version) or not re.fullmatch(r"[0-9A-Za-z._-]+", cell):
        return None
    root = owners(as_roots(root)).get(version)
    if root is None:
        return None
    vdir = root / version
    if name == "console.log":
        path = vdir / "logs" / f"{cell}.log"
        return path if path.is_file() else None
    manifest = vdir / "evidence" / cell / "manifest.json"
    if name == "manifest.json":
        return manifest if manifest.is_file() else None
    try:
        files = json.loads(manifest.read_text()).get("files", {})
    except (OSError, json.JSONDecodeError):
        return None
    if name not in files:
        return None
    path = vdir / "evidence" / cell / name
    return path if path.is_file() else None


class Handler(BaseHTTPRequestHandler):
    root: list[Path] = [RESULTS]
    server_version = "KestrelQA/1"

    def log_message(self, fmt, *args):  # quieter than the default per-request line
        if os.environ.get("KESTREL_VERBOSE"):
            super().log_message(fmt, *args)

    def send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        url = urlparse(self.path)
        parts = [unquote(p) for p in url.path.split("/") if p]
        if not parts:
            return self.send(200, wrap(page_fragment()).encode(), "text/html; charset=utf-8")
        if parts == ["api", "state"]:
            since = parse_qs(url.query).get("since", [""])[0]
            fp = fingerprint(self.root)
            if since and since == fp and not any(running_cells(r, time.time()) for r in self.root):
                return self.send(200, b'{"unchanged":true}', "application/json")
            body = json.dumps({**build_state(self.root), "mode": "live"}).encode()
            return self.send(200, body, "application/json")
        stamp = time.strftime("%Y%m%d-%H%M")
        if parts == ["export.json"]:
            body = json.dumps({**build_state(self.root), "mode": "snapshot"}, indent=2).encode()
            return self.send(200, body, "application/json",
                             {"Content-Disposition": f'attachment; filename="kestrel-{stamp}.json"'})
        if parts == ["export.pdf"]:
            state = build_state(self.root)
            version = parse_qs(url.query).get("version", [""])[0] or (state["versions"] or [""])[-1]
            if version not in state["versions"]:
                return self.send(HTTPStatus.NOT_FOUND, b"no such release\n", "text/plain")
            try:
                body = render_pdf(state, version)
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                return self.send(HTTPStatus.SERVICE_UNAVAILABLE, f"PDF failed: {exc}\n".encode(), "text/plain")
            name = re.sub(r"[^0-9A-Za-z._-]", "_", version)
            return self.send(200, body, "application/pdf",
                             {"Content-Disposition": f'attachment; filename="kestrel-{name}-{stamp}.pdf"'})
        if parts == ["export"]:
            # A download is opened from disk, where nothing adds the document
            # skeleton the artifact host would: without <meta charset> the
            # browser reads the UTF-8 as Latin-1 and renders in quirks mode.
            body = wrap(export_fragment(build_state(self.root))).encode()
            return self.send(200, body, "text/html; charset=utf-8",
                             {"Content-Disposition": f'attachment; filename="kestrel-{stamp}.html"'})
        if len(parts) == 4 and parts[0] == "evidence":
            path = resolve_evidence(self.root, parts[1], parts[2], parts[3])
            if path:
                ctype = "application/json" if path.suffix == ".json" else "text/plain; charset=utf-8"
                return self.send(200, path.read_bytes(), ctype)
        self.send(HTTPStatus.NOT_FOUND, b"not found\n", "text/plain")


def main() -> int:
    ap = argparse.ArgumentParser(description="Kestrel QA dashboard for qualify.py results")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--results", type=Path, action="append",
                    help=f"result root, repeatable; first wins per version (default {RESULTS})")
    ap.add_argument("--export", type=Path, metavar="FILE",
                    help="write a self-contained snapshot page and exit")
    args = ap.parse_args()
    args.results = args.results or [RESULTS]
    if args.export:
        args.export.write_text(export_fragment(build_state(args.results)))
        print(f"wrote {args.export}")
        return 0
    Handler.root = args.results
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Kestrel QA on http://{args.host}:{args.port} reading "
          f"{', '.join(map(str, args.results))}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

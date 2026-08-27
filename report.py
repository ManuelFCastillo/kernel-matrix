#!/usr/bin/env python3
"""
report.py -- turn results/results.json into a self-contained HTML page.

WHY A SEPARATE SCRIPT
---------------------
The provisioner's job is to gather facts. Presenting them is a different
concern with a different audience: provision.py writes for machines (JUnit
for Jenkins, JSON for anything downstream), this writes for humans.

Keeping them apart means you can re-render the report from an old results
file without re-running a two-hour matrix, and it means the report can get
prettier without anyone touching provisioning code.

WHY SELF-CONTAINED
------------------
No CDN, no external CSS, no build step. One file you can email, archive as a
Jenkins artifact, or open from a USB stick in five years. Dashboards that
depend on a running server stop being readable the moment the server moves.

USAGE
    ./report.py                      # results/results.json -> results/report.html
    ./report.py --out /tmp/x.html
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# How each Falco driver should read at a glance. The ordering here is the
# actual quality ordering: modern eBPF is the good path, a kernel module is
# the fallback of last resort.
DRIVER_STYLE = {
    "modern_ebpf": ("good", "modern eBPF", "CO-RE. Needs BTF and a recent kernel. The good path."),
    "ebpf":        ("warn", "legacy eBPF", "Older probe. Works, but not CO-RE."),
    "kmod":        ("bad",  "kernel module", "Most invasive fallback. Compiled per kernel."),
    "unknown":     ("warn", "unknown", "Started, but the driver could not be determined."),
    "none":        ("bad",  "none", "Never started."),
}


def tile(value: str, label: str, tone: str = "") -> str:
    return (f'<div class="tile {tone}"><span class="v">{html.escape(str(value))}</span>'
            f'<span class="l">{html.escape(label)}</span></div>')


def version_tuple(v: str) -> tuple:
    """'0.44.1' -> (0, 44, 1). Non-numeric junk sorts as oldest."""
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums) if nums else (0,)


# ---------------------------------------------------------------------------
# Upstream check: is the version we tested still the version that exists?
# ---------------------------------------------------------------------------
# A compatibility matrix is a statement about ONE sensor version. The moment
# upstream ships a newer one, every green cell here is a claim about the
# past. The report should know that about itself, so it asks the GitHub API
# for the latest release and caches the answer -- the cache means an offline
# or rate-limited re-render degrades to slightly stale instead of broken.
UPSTREAM_CACHE = Path("results/upstream_cache.json")


def fetch_upstream() -> dict:
    req = urllib.request.Request(
        "https://api.github.com/repos/falcosecurity/falco/releases/latest",
        headers={"User-Agent": "kernel-matrix-report",
                 "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            rel = json.loads(resp.read())
        info = {"tag": rel.get("tag_name", ""),
                "published": (rel.get("published_at") or "")[:10],
                "url": rel.get("html_url", "")}
        UPSTREAM_CACHE.parent.mkdir(parents=True, exist_ok=True)
        UPSTREAM_CACHE.write_text(json.dumps(info))
        return info
    except (urllib.error.URLError, OSError, ValueError):
        if UPSTREAM_CACHE.exists():
            try:
                info = json.loads(UPSTREAM_CACHE.read_text())
                info["stale"] = True
                return info
            except ValueError:
                pass
        return {}


# ---------------------------------------------------------------------------
# Run history: every render archives the results it drew from, and the diff
# against the previous archive is what turns this page from a snapshot into
# a regression canary. "ubuntu-20.04 stopped detecting overnight" is the
# single most valuable sentence this report can produce, and it can only
# produce it if it remembers yesterday.
# ---------------------------------------------------------------------------
RUNS_DIR = Path("results/runs")


def archive_run(data: dict) -> None:
    stamp = re.sub(r"[^0-9T]", "-", data.get("generated_at", "unknown"))
    path = RUNS_DIR / f"run-{stamp}.json"
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    if not path.exists():                     # re-rendering must be idempotent
        path.write_text(json.dumps(data, indent=1))


def load_previous(current_generated: str) -> dict | None:
    if not RUNS_DIR.is_dir():
        return None
    stamp = re.sub(r"[^0-9T]", "-", current_generated or "unknown")
    older = sorted(p for p in RUNS_DIR.glob("run-*.json")
                   if p.name != f"run-{stamp}.json")
    if not older:
        return None
    try:
        return json.loads(older[-1].read_text())
    except ValueError:
        return None


def diff_runs(prev: dict | None, cur: dict) -> dict[str, list[tuple[str, str]]]:
    """Per-distro changes as (tone, text) pairs. Empty dict = nothing moved."""
    if not prev:
        return {}
    prev_by = {r["distro"]: (r.get("falco") or {}) for r in prev.get("results", [])}
    changes: dict[str, list[tuple[str, str]]] = {}

    for r in cur.get("results", []):
        distro, f = r["distro"], (r.get("falco") or {})
        if distro not in prev_by:
            changes[distro] = [("warn", "new in matrix")]
            continue
        p = prev_by[distro]
        out = []
        if p.get("driver") != f.get("driver"):
            out.append(("warn", f"driver {p.get('driver') or '?'} → {f.get('driver') or '?'}"))
        if (p.get("plugin_mode") or "stock") != (f.get("plugin_mode") or "stock"):
            out.append(("good" if f.get("plugin_mode") == "stock" else "warn",
                        f"plugin {p.get('plugin_mode') or 'stock'} → {f.get('plugin_mode') or 'stock'}"))
        if p.get("falco_version") != f.get("falco_version"):
            out.append(("warn", f"falco {p.get('falco_version') or '?'} → {f.get('falco_version') or '?'}"))
        if bool(p.get("detected")) != bool(f.get("detected")):
            out.append(("good", "now detecting") if f.get("detected")
                       else ("bad", "STOPPED detecting"))
        elif bool(p.get("started")) != bool(f.get("started")):
            out.append(("good", "now running") if f.get("started")
                       else ("bad", "STOPPED running"))
        prss, crss = p.get("rss_kb") or 0, f.get("rss_kb") or 0
        if prss and crss:
            delta = (crss - prss) / prss
            if abs(delta) >= 0.25:
                out.append(("warn", f"rss {delta:+.0%}"))
        if out:
            changes[distro] = out
    return changes


def render(data: dict, prev: dict | None = None, upstream: dict | None = None,
           variant: str = "") -> str:
    results = data.get("results", [])
    changes = diff_runs(prev, data)

    # ---- what version is this report a statement about? ------------------
    tested = sorted({(r.get("falco") or {}).get("falco_version")
                     for r in results
                     if (r.get("falco") or {}).get("falco_version")
                     not in (None, "", "unknown")},
                    key=version_tuple, reverse=True)
    tested_label = " / ".join(tested) if tested else "?"

    upstream = upstream or {}
    up_ver = (upstream.get("tag") or "").lstrip("v")
    if not up_ver:
        banner = '<span class="pill">upstream check unavailable</span>'
    elif tested and version_tuple(up_ver) > version_tuple(tested[0]):
        banner = (f'<span class="pill bad">upstream {html.escape(up_ver)} '
                  f'released {html.escape(upstream.get("published", "?"))} '
                  f'&mdash; UNTESTED</span>')
    else:
        stale = " (cached)" if upstream.get("stale") else ""
        banner = (f'<span class="pill good">up to date with upstream '
                  f'{html.escape(up_ver)}{stale}</span>')

    variant_pill = (f' &nbsp; <span class="pill warn">{html.escape(variant)}</span>'
                    if variant else "")

    if prev:
        n = sum(len(v) for v in changes.values())
        prev_when = prev.get("generated_at", "?")
        drift = (f'<span class="pill warn">{n} change(s) vs {html.escape(prev_when)}</span>'
                 if n else
                 f'<span class="pill good">no drift vs {html.escape(prev_when)}</span>')
    else:
        drift = '<span class="pill">first recorded run</span>'

    # ---- summary numbers -------------------------------------------------
    total = len(results)
    booted = sum(1 for r in results if not r.get("error"))
    falco_started = sum(1 for r in results
                        if (r.get("falco") or {}).get("started"))
    falco_detected = sum(1 for r in results
                         if (r.get("falco") or {}).get("detected"))
    drivers = {}
    for r in results:
        d = (r.get("falco") or {}).get("driver")
        if d:
            drivers[d] = drivers.get(d, 0) + 1

    rows = []
    for r in sorted(results, key=lambda x: x["distro"]):
        falco = r.get("falco") or {}
        driver = falco.get("driver", "none")
        tone, driver_label, driver_help = DRIVER_STYLE.get(
            driver, ("warn", driver, ""))

        if r.get("error"):
            status = '<span class="pill bad">vm failed</span>'
            detail = html.escape(r["error"][:110])
        elif falco.get("error"):
            status = '<span class="pill bad">probe failed</span>'
            detail = html.escape(str(falco["error"])[:110])
        elif falco.get("detected"):
            status = '<span class="pill good">detecting</span>'
            detail = html.escape(falco.get("rule_matched", "") or "")
        elif falco.get("started"):
            status = '<span class="pill warn">running, no detection</span>'
            detail = "started but never fired on the synthetic event"
        elif falco:
            status = '<span class="pill bad">not running</span>'
            detail = html.escape(str(falco.get("error", ""))[:110])
        else:
            status = '<span class="pill">not probed</span>'
            detail = "run with --falco to characterise"

        checks = r.get("checks", [])
        passed = sum(1 for c in checks if c["passed"] and not c["skipped"])
        skipped = sum(1 for c in checks if c["skipped"])

        rss = falco.get("rss_kb") or 0
        rss_txt = f"{rss/1024:.0f} MB" if rss else "&mdash;"
        cpu = falco.get("cpu_percent")
        cpu_txt = f"{cpu}%" if cpu not in (None, 0, "0") else "&mdash;"

        pmode = falco.get("plugin_mode") or ("stock" if falco else "")
        pmode_tone = {"stock": "good", "patched": "warn", "workaround": "bad"}.get(pmode, "")
        pmode_cell = (f'<span class="pill {pmode_tone}">{html.escape(pmode)}</span>'
                      if pmode and falco.get("installed") else '<span class="unit">&mdash;</span>')

        ver = falco.get("falco_version")
        ver_txt = html.escape(ver) if ver and ver != "unknown" else "&mdash;"

        row_changes = changes.get(r["distro"], [])
        if row_changes:
            change_html = "<br>".join(
                f'<span class="pill {t}">{html.escape(txt)}</span>'
                for t, txt in row_changes)
        else:
            change_html = '<span class="unit">&mdash;</span>'

        rows.append(f"""
        <tr>
          <td class="distro">{html.escape(r['distro'])}</td>
          <td class="mono">{html.escape(r.get('kernel') or '&mdash;')}</td>
          <td class="mono">{ver_txt}</td>
          <td><span class="pill {tone}" title="{html.escape(driver_help)}">{driver_label}</span></td>
          <td>{pmode_cell}</td>
          <td>{status}<div class="sub">{detail}</div></td>
          <td class="num">{rss_txt}</td>
          <td class="num">{cpu_txt}</td>
          <td class="num">{falco.get('start_seconds', '&mdash;')}<span class="unit">s</span></td>
          <td class="num">{falco.get('detect_seconds', '&mdash;')}<span class="unit">s</span></td>
          <td class="num">{passed}/{len(checks)}{f' <span class="unit">+{skipped} skip</span>' if skipped else ''}</td>
          <td>{change_html}</td>
        </tr>""")

    driver_summary = " · ".join(
        f"{DRIVER_STYLE.get(d, ('', d, ''))[1]}: {n}" for d, n in sorted(drivers.items())
    ) or "not probed"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kernel Matrix &mdash; Falco characterisation</title>
<style>
  :root {{
    --bg:#F3F3F6; --surface:#fff; --line:#D6D8E0; --text:#1B1C23;
    --dim:#5A5D6B; --faint:#8A8D9B;
    --good:#1F7A5C; --good-bg:#DBEEE6;
    --warn:#8A6410; --warn-bg:#F6E9CC;
    --bad:#AB3F2C;  --bad-bg:#F7DFDA;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  }}
  @media (prefers-color-scheme:dark) {{
    :root {{
      --bg:#14151C; --surface:#1C1E27; --line:#31343F; --text:#E9E7E3;
      --dim:#A2A4B2; --faint:#767989;
      --good:#57B896; --good-bg:#173A31;
      --warn:#D8A551; --warn-bg:#3A2F1A;
      --bad:#E0705A;  --bad-bg:#3B2220;
    }}
  }}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);
       font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased}}
  .wrap{{max-width:1080px;margin:0 auto;padding:34px 20px 70px}}
  h1{{font-size:25px;margin:0 0 4px;letter-spacing:-.02em}}
  .sub-head{{color:var(--dim);font-size:13.5px;margin:0 0 24px}}
  .mono{{font-family:var(--mono);font-size:12.5px}}

  .tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
          gap:1px;background:var(--line);border:1px solid var(--line);
          border-radius:5px;overflow:hidden;margin-bottom:26px}}
  .tile{{background:var(--surface);padding:15px 17px;display:flex;flex-direction:column;gap:3px}}
  .tile .v{{font-family:var(--mono);font-size:25px;line-height:1;
           font-variant-numeric:tabular-nums;color:var(--text)}}
  .tile .l{{font-family:var(--mono);font-size:9.5px;letter-spacing:.13em;
           text-transform:uppercase;color:var(--faint)}}
  .tile.good .v{{color:var(--good)}} .tile.warn .v{{color:var(--warn)}}
  .tile.bad .v{{color:var(--bad)}}

  .tablewrap{{overflow-x:auto;border:1px solid var(--line);border-radius:5px;background:var(--surface)}}
  table{{border-collapse:collapse;width:100%;min-width:900px}}
  th{{font-family:var(--mono);font-size:9.5px;letter-spacing:.12em;text-transform:uppercase;
     color:var(--faint);font-weight:500;text-align:left;padding:11px 13px;
     background:var(--bg);border-bottom:1px solid var(--line);white-space:nowrap}}
  td{{padding:12px 13px;border-bottom:1px solid var(--line);vertical-align:top}}
  tr:last-child td{{border-bottom:0}}
  td.distro{{font-weight:600;white-space:nowrap}}
  td.num{{font-family:var(--mono);font-variant-numeric:tabular-nums;
         text-align:right;white-space:nowrap;font-size:13px}}
  .unit{{color:var(--faint);font-size:10.5px}}
  .sub{{color:var(--faint);font-size:11.5px;margin-top:4px;max-width:34ch;line-height:1.35}}

  .pill{{display:inline-block;font-family:var(--mono);font-size:10.5px;letter-spacing:.04em;
        padding:3px 8px;border-radius:3px;background:var(--bg);color:var(--dim);white-space:nowrap}}
  .pill.good{{background:var(--good-bg);color:var(--good)}}
  .pill.warn{{background:var(--warn-bg);color:var(--warn)}}
  .pill.bad{{background:var(--bad-bg);color:var(--bad)}}

  .legend{{margin-top:24px;padding:16px 18px;background:var(--surface);
          border:1px solid var(--line);border-radius:5px;font-size:13px;color:var(--dim)}}
  .legend b{{color:var(--text)}}
  .legend p{{margin:0 0 9px}} .legend p:last-child{{margin:0}}
</style></head>
<body><div class="wrap">

  <h1>Kernel compatibility matrix</h1>
  <p class="sub-head">
    <b>Falco {html.escape(tested_label)}</b> characterised across {total} Linux kernels &middot;
    host running <span class="mono">{html.escape(data.get('host_kernel','?'))}</span> &middot;
    generated {html.escape(data.get('generated_at','?'))}
  </p>
  <p class="sub-head" style="margin-top:-14px">{banner} &nbsp; {drift}{variant_pill}</p>

  <div class="tiles">
    {tile(f"{booted}/{total}", "vms booted", "good" if booted == total else "bad")}
    {tile(f"{falco_started}/{total}", "falco running", "good" if falco_started == total else "warn")}
    {tile(f"{falco_detected}/{total}", "actually detecting", "good" if falco_detected == total else "warn")}
    {tile(len(drivers), "distinct drivers", "warn" if len(drivers) > 1 else "good")}
  </div>

  <div class="tablewrap">
    <table>
      <thead><tr>
        <th>distro</th><th>kernel</th><th>falco</th><th>driver</th><th>plugin</th><th>status</th>
        <th>rss</th><th>cpu</th><th>start</th><th>detect</th><th>checks</th><th>vs last run</th>
      </tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>

  <div class="legend">
    <p><b>Why the driver column is the interesting one.</b> Falco picks its engine at
    runtime based on what the kernel supports, and the fallback is silent.
    <b>modern eBPF</b> is CO-RE and needs BTF plus a recent kernel; <b>legacy eBPF</b>
    still works but is not portable across kernels; a <b>kernel module</b> is the most
    invasive path. A matrix reporting only pass/fail would show all of these as green
    while hiding three very different realities.</p>
    <p><b>Driver spread across this run:</b> {html.escape(driver_summary)}</p>
    <p><b>Cost columns matter at fleet scale.</b> RSS and CPU are measured at idle,
    eight seconds after start so the numbers reflect steady state rather than startup
    churn. On a hundred thousand hosts, a percent of CPU is a budget line.</p>
  </div>

</div></body></html>"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=Path("results/results.json"))
    ap.add_argument("--out", type=Path, default=Path("results/report.html"))
    ap.add_argument("--variant", default="",
                    help="label shown in the header (e.g. 'patched plugin build')")
    args = ap.parse_args()

    if not args.results.exists():
        sys.exit(f"No results at {args.results}. Run provision.py first.")

    data = json.loads(args.results.read_text())

    # Order matters: find the previous run BEFORE archiving this one, or the
    # report would always be diffing against itself.
    prev = load_previous(data.get("generated_at", ""))
    archive_run(data)
    upstream = fetch_upstream()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(data, prev=prev, upstream=upstream,
                               variant=args.variant))
    n_runs = len(list(RUNS_DIR.glob("run-*.json"))) if RUNS_DIR.is_dir() else 0
    print(f"wrote {args.out}  ({args.out.stat().st_size/1024:.0f} KB, "
          f"{n_runs} run(s) in history)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

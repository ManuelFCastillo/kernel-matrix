# Findings: Falco 0.44.1 across the legacy kernel tier

A record of what the matrix actually found on the five legacy distros, what
was fixed versus worked around, and what belongs upstream. The one-line
summary: **none of the five failures were kernel incompatibilities** — they
were packaging, build-toolchain, and harness bugs wearing kernel-incompatibility
costumes. Telling those apart is the reason this lab exists.

Before: 0/5 distros running Falco, 0/5 detecting.
After: 5/5 running, 5/5 detecting.

---

## The failure map

Failures were stacked — several distros had more than one problem, and the
first barrier hid the ones behind it.

| Distro | Kernel | glibc | Barrier 1 | Barrier 2 | Now running via |
|---|---|---|---|---|---|
| debian-11 | 5.10 | 2.31 | container plugin crash | — | modern_ebpf |
| rocky-8 | 4.18 | 2.28 | container plugin crash | — | modern_ebpf |
| ubuntu-20.04 | 5.4 | 2.31 | container plugin crash | harness misread the unit | kmod |
| ubuntu-18.04 | 4.15 | 2.27 | systemd refuses unit files | container plugin crash | kmod |
| centos-7 | 3.10 | 2.17 | package will not install | — | kmod (Falco 0.40.0) |

A side finding from the working matrix: the kernel module idles at ~14 MB RSS
where modern eBPF idles at ~90 MB — a 6x memory difference between driver
paths that a pass/fail matrix would never surface.

---

## Finding 1 — container plugin fails to load on glibc < 2.34

**The bug.** Falco 0.44.1's packaged container-enrichment plugin
(`/usr/share/falco/plugins/libcontainer.so`) fails to `dlopen` with
`undefined symbol: __res_search` on any host with glibc older than 2.34 —
which includes Debian 11 (2.31), the entire RHEL/Rocky/Alma 8 line (2.28),
and Ubuntu 20.04 (2.31).

**The mechanism (verified, not guessed).** The plugin links a Go static
library whose cgo DNS resolver calls `res_search` from libresolv. In the
plugin's CMake (`go-worker.cmake`), the `-lresolv` dependency is added only
inside an `if(APPLE)` branch — there is no Linux equivalent. The shipped
`.so` therefore carries an undefined `__res_search` with **no `DT_NEEDED`
entry for `libresolv.so.2`** (its only NEEDED entries are `libc.so.6` and
the loader — confirmed with `readelf -d`). On glibc ≥ 2.34, libresolv is
merged into libc, which papers over the hole; on older glibc the symbol
lives only in `libresolv.so.2`, which is never loaded. Upstream even builds
on `debian:bullseye` specifically to keep old-glibc compatibility — this
one missing link flag defeats that entire effort.

**The smoking gun.** On a stock Debian 11 install, the same command run
twice: plain `falco` exits with the symbol error; with
`LD_PRELOAD=/lib/x86_64-linux-gnu/libresolv.so.2` it starts cleanly and
opens the modern BPF probe. One environment variable — forcing exactly the
library a `DT_NEEDED` entry would have loaded — flips broken to working.
(The preload is also a usable stopgap for stock installs on affected
distros, via a systemd drop-in.)

**The compounding bug.** The default ruleset hard-requires the plugin
(`required_plugin_versions: container`), and its rules reference
`container.*` fields through shared macros. So the failure mode is not
"degraded container info" — it is **Falco cannot start at all with its
shipped default configuration**. It crash-loops under systemd forever.

**Upstream status.** Known since 0.42.0 and unfixed: falco#3719 (AlmaLinux
8.10, closed as lifecycle/rotten with no resolution) and falco#3728 (same
symbol, tarball install). Still present in 0.44.1, verified live here on
two distro families.

**What this repo has: a workaround, not a fix.** `falco_probe.sh` deletes
the plugin's drop-in config after install and replaces the default ruleset
with one self-contained detection rule, then starts the service. Applied
fresh on every run. The green matrix cells mean "runs and detects *with the
container plugin disabled*" — stock 0.44.1 on these distros still crash-loops.

**The fix — built and verified end to end.** Two small CMake changes
(`upstream-container-plugin-resolv.patch` in this repo):

1. `go-worker.cmake`: a Linux branch setting `WORKER_DEP` to `resolv`,
   mirroring the existing APPLE branch (whose comment already cites the
   Go ≥ 1.20 cgo-resolver requirement — only the macOS half was written).
2. `CMakeLists.txt`: link `${WORKER_LIB} ${WORKER_DEP}` in that order.
   With the reverse order GNU ld discards `-lresolv` (nothing needs it yet
   when it is processed) and the fix silently doesn't take — verified from
   the generated link line. macOS never noticed because ld64 is
   order-insensitive.

Verified by rebuilding plugin v0.7.1 in upstream's own build baseline
(`debian:bullseye`, glibc 2.31): the rebuilt `.so` gains
`NEEDED: libresolv.so.2` and a properly versioned `__res_search@GLIBC_2.2.5`.
Swapped onto a stock Falco 0.44.1 install on Debian 11 with everything else
untouched: default ruleset validates, service runs under systemd, the stock
sensitive-file rule fires, and the alert carries `container_id=host` —
the plugin itself working, not merely not crashing.

**Regression surface, checked empirically.** The patch changes zero lines
of code — both hunks are linkage metadata, declaring a dependency the code
always had. Verified:

- glibc 2.31 (Debian 11, x86_64): broken → fixed, end to end under systemd,
  stock rules firing, plugin enriching events
- glibc 2.39 (Ubuntu 24.04, x86_64): stock plugin already worked; patched
  plugin behaves identically — no regression
- Linux arm64 (bullseye aarch64 container, built natively on Apple
  Silicon): builds clean, same `NEEDED: libresolv.so.2`, symbol properly
  versioned as `__res_search@GLIBC_2.17`
- macOS and Windows: untouched by construction — the APPLE branch is
  unchanged, ld64 ignores link order, and `WORKER_DEP` is never set on
  Windows

As of this writing the plugins repo has zero issues or PRs mentioning the
problem: the fix is unclaimed.

## Finding 2 — shipped unit files will not load on systemd < 239

**The bug.** Falco's systemd unit files contain
`ExecReload=kill -1 $MAINPID` — a non-absolute executable path. systemd
239+ resolves bare names from `$PATH`; systemd 237 (Ubuntu 18.04) refuses
to load the **entire unit** with `Exec format error`. Not just reload:
start, stop, everything. All three engine units die identically, which
looks exactly like "this kernel is unsupported" until you read the journal.

The line itself is the least critical thing in the file — SIGHUP-based
config reload, a convenience path — with the maximum possible blast radius.

**What this repo has: a workaround.** The probe seds installed unit files
to `ExecReload=/bin/kill` before starting anything. (A drop-in override
cannot rescue it — the base file still fails to parse.)

**Where the real fix lives:** upstream packaging. A one-line change to
`/bin/kill` is a no-op on modern systemd and a full fix on old — a clean,
low-risk PR.

## Finding 3 — Falco 0.41.0+ requires GLIBC_2.28; EL7 cutoff is 0.40.0

Not a bug — a support-lifecycle boundary, mapped. `yum install falco` on
CentOS 7 (glibc 2.17) fails on `Requires: libc.so.6(GLIBC_2.28)`. Walking
the repo's full version history down: **0.40.0 is the last release that
installs on EL7**; 0.41.0 is the cutoff. The probe now falls back
automatically and the matrix reports the pinned version per row — turning
"install failed" into the genuinely useful answer: the last known good
sensor version per platform. (Also: `dkms` lives in EPEL on EL7, not base —
without it the kmod can never be built, which reads as a Falco failure and
is really a missing toolchain.)

Falco 0.40.0 + kmod runs and detects on kernel 3.10.

---


## Finding 4 — the plugin's own glibc floor is 2.28 (independent of the resolv fix)

Discovered while validating the fix: on Ubuntu 18.04 (glibc 2.27) the plugin
fails differently — `version 'GLIBC_2.28' not found (required by
libcontainer.so)`. That is the build-baseline floor of the plugin binary
itself, and no linkage fix can lower it: even with PR #1501 merged, the
shipped plugin cannot run on Ubuntu 18.04 or Amazon Linux 2 (2.26) — distros
the Falco package itself still installs on. Same class of finding as the
EL7 cutoff: a support boundary to document, not a bug to fix.

## The probe's three plugin modes

The probe no longer applies its workaround unconditionally — that would blind
the matrix to exactly the bug it found. Each run now:

1. tries **stock** first (what a customer gets),
2. falls back to the **workaround** only on a libcontainer load failure
   (either flavor), and records `plugin_mode` in the JSON,
3. optionally runs **patched** (`provision.py --plugin-so <fixed .so>`) to
   preview the post-fix world.

Two dashboards are published: `report.html` (reality today: four distros on
workaround, centos-7 stock on 0.40) and `report-patched.html` (the fix
applied: three distros green on the patched plugin; 18.04 honestly still on
workaround due to Finding 4). When upstream ships the fix, the main
dashboard's rows flip workaround → stock on their own and the drift column
reports it — the matrix detecting its own fix landing.

Bonus cost datum from the patched runs: container enrichment costs roughly
**35–50 MB RSS** per host (modern_ebpf: ~90 → ~130-140 MB; kmod: ~14 →
~49 MB) — fleet-relevant, and invisible until the plugin actually ran.

## Harness bugs found and fixed (in our code, actual fixes)

The matrix originally reported all five distros down. Three of those rows
were wrong or half-wrong because of bugs in the lab itself:

1. **Crash-loop reported as started.** The probe polled
   `systemctl list-units --state=active` once a second; a crash-looping
   unit shows "active" for a fraction of a second between restarts, and one
   lucky sample marked it running — with the driver guessed from the unit
   name. Now requires three consecutive running samples.
2. **Wrong unit selected.** `falco-kmod-inject.service` (a oneshot helper,
   permanently "active (exited)") sorts alphabetically before
   `falco-kmod.service` and was grabbed by `head -1`. Every downstream
   measurement — journal, PID, RSS, detection — then read the wrong unit.
   Now filters on sub-state `running`, and knows the full 0.44 unit family.
3. **JUnit XML corruption.** Check messages carry ANSI colour escapes from
   journalctl/apt; ElementTree writes them, and every conforming parser
   (including Jenkins' junit ingestion) rejects the file. Found by the new
   unit tests on their first run. Fixed with an XML-1.0 sanitizer.

Plus: build prerequisites now include `gcc` explicitly, and error capture
keeps the first meaningful line instead of ANSI-soaked noise.

## Who tests the tests

`tests/` holds 39 pytest cases (~0.1 s) covering the harness's own logic:
version ordering (the 5.9 < 5.10 trap), the drift detector's semantics
(detection loss, driver flips, rss-zero guard, never diff a run against
itself), JUnit error-vs-failure semantics, and the probe's real shell
pipelines driven with fixture text — the kmod-inject oneshot must never
win, and `json_safe` output must always survive `json.loads`. The
Jenkinsfile runs them as a stage before any VM boots. Several cases are
regression tests for the harness bugs above; the XML sanitizer exists
because this suite caught the bug in its first 100 ms.

## Dashboard

The report is a statement about one sensor version, and now says so: tested
version(s) in the header and per row, a live check against upstream's
latest release ("up to date" vs "UNTESTED release available"), and run
history with a vs-last-run drift column (driver flips, detection loss,
RSS swings ≥25%, version changes). Every render archives its run;
the nightly Jenkins tier accumulates the history.

## Open items

- centos-7 reports rss 0 — the idle-cost sampler misses on Falco 0.40/EL7
  (MainPID resolution differs). Driver and detection data are solid.
- Verify the nightly Jenkins job's `results/runs/` history lands where the
  nginx-served report reads from (workspace vs checkout path).
- Upstream: file the container-plugin issue with the mechanism and
  still-broken-in-0.44.1 reproduction; PR the one-line ExecReload fix.
- Candidate next dimension: a `dev`-channel row (Falco's pre-release
  packages) so breakage is caught before release, not after.

# Package qualification: Falco 0.45.0 and 0.45.1-rc1

The first real run of `qualify.py` (see README, "Package qualification"), 2026-10-17 on
hardac2: the actual `.deb`/`.rpm` installed through the package manager, maintainer scripts
running, on 12 distro/kernel targets x 4 scenarios, for 0.45.0 (stable) and 0.45.1-rc1
(dev repo, published 2026-10-05). 96 real VMs, at most 4 at a time, about 70 minutes.
Plus 4 cells of 0.45.0-rc4 to answer one question (finding 3).

The one-line summary: **falcosecurity/falco#3994 is still in 0.45.1-rc1, it follows the
kernel and not the distro, it hits every driver choice and not only auto, and in-place
upgrades miss it.** The grid also turned up a second kmod install failure on Ubuntu 22.04 and
Debian 12 that is not #3994.

Every cell has a result JSON, a console log and an evidence bundle (install log with the
maintainer scripts' own output, falcoctl config and `printenv`, journal, dmesg, kernel
capabilities, sha256 manifest). `results/qualification/matrix.json` links all of them.

---

## The grid

0.45.0 and 0.45.1-rc1 produced **identical grids**: 34 pass, 13 fail, 1 blocked each.

| distro--kernel | fresh-auto | fresh-kmod | fresh-modern_ebpf | upgrade from 0.44.1 |
|---|---|---|---|---|
| ubuntu-18.04--4.15 | FAIL (#3994) | FAIL (#3994) | FAIL (#3994) | FAIL (unit will not load) |
| ubuntu-20.04--5.4 | FAIL (#3994) | FAIL (#3994) | FAIL (#3994) | PASS |
| ubuntu-20.04--5.15-hwe | PASS | PASS | PASS | PASS |
| ubuntu-22.04--5.15 | PASS | FAIL (kmod headers) | PASS | PASS |
| ubuntu-24.04--6.8 | PASS | PASS | PASS | PASS |
| debian-11--5.10 | PASS | PASS | PASS | PASS |
| debian-12--6.1 | PASS | FAIL (kmod headers) | PASS | PASS |
| rocky-8--4.18 | PASS | PASS | PASS | PASS |
| rocky-9--5.14 | PASS | FAIL (Secure Boot) | PASS | PASS |
| almalinux-9--5.14 | PASS | PASS | PASS | PASS |
| fedora-44--6.19 | PASS | PASS | PASS | PASS |
| centos-7--3.10 | FAIL (glibc) | FAIL (glibc) | FAIL (glibc) | blocked |

The checks behind each cell, all decided by code from what the guest reported:
`pkg_installed` (exit 0, fully configured, no maintainer script failure, requested version),
`driver_loaded` (`/sys/module/falco`, or BPF programs held by the sensor), `service_active`
(started by the maintainer scripts alone, stable for 3 samples), `event_detected`.

---

## Finding 1: #3994 hits every driver choice, not only auto

On Ubuntu 18.04 (4.15) and 20.04 (5.4), a fresh install of 0.45.0 fails with
`FALCO_DRIVER_CHOICE` set to auto, kmod **and** modern_ebpf: dpkg exits 100, the package is
left `install ok half-configured`, and no unit is ever started.

The cause is visible in every bundle (`falco.txt`, guarded `falcoctl driver printenv`):

    ERROR no supported driver found for distro: ubuntu-generic, kernelrelease 5.4.0-216-generic

`package_driver_version` in the postinst runs `falcoctl driver printenv` under `set -e`
**before** the postinst widens the allowed driver types. The shipped `falcoctl.yaml` allows
only modern_ebpf, so on a kernel that cannot run it, printenv exits 1 and the postinst dies.
Choosing kmod explicitly does not help, because `package_driver_version` runs for any
non-empty choice before the kmod is configured. The staged fix in `~/dev/falco` (branch
`fix/postinst-printenv-without-modern-ebpf`) addresses exactly this call.

## Finding 2: the failure follows the kernel, not the distro

`ubuntu-20.04--5.15-hwe` is the same Ubuntu 20.04 image (same userspace, glibc 2.31, dpkg),
booted on its HWE kernel: `linux-generic-hwe-20.04` installed in the VM and rebooted into
(5.15.0-139), with `kernel_version_matches_expectation` proving the reboot took. All four
scenarios pass there, on both versions, with modern eBPF running (198 BPF program fds) and
the event detected. Same packages, same distro, different kernel: green.

## Finding 3: a pre-release matrix would have caught it before GA

0.45.0-rc4 sat in the dev repo on 2026-09-18, three days before the 0.45.0 package reached
the stable repo (2026-09-21).
Run against the same pair it gives the same answer: Ubuntu 20.04 on 5.4 fails fresh-auto and
fresh-kmod (half-configured, same printenv error), and on HWE 5.15 both pass.

And it is not fixed in the next pre-release: **0.45.1-rc1 fails the same 13 cells as 0.45.0**,
all six #3994 cells among them.
Its postinst differs from 0.45.0's only in the pinned driver version string
(`11.0.0+driver` -> `11.0.1-rc1+driver`).

## Finding 4: in-place upgrades do not see #3994

On Ubuntu 20.04 (5.4), upgrading from 0.44.1 to 0.45.0 or 0.45.1-rc1 with
`--force-confdef --force-confold` **passes**: package configured, kmod built and loaded,
service running, event detected. `falcoctl.yaml` is a conffile, so confold keeps the
driver configuration the 0.44.1 postinst wrote for this host (the upgraded host's file lists
`type: [kmod]`), and printenv resolves kmod instead of failing. Fleets upgrading in place stay green while new
hosts provisioned with the same release fail: an upgrade-only test plan would have shipped
this bug.

## Finding 5: kmod on Ubuntu 22.04 and Debian 12 fails with matching headers installed

Not #3994. On both versions, `fresh-kmod` leaves the package half-configured on Ubuntu 22.04
(5.15.0-187) and Debian 12 (6.1.0-54), even though the build prerequisites gate confirmed
dkms, gcc and the running kernel's headers were present.

`falcoctl driver install` (called from `package_install_kmod`) ignores
`/lib/modules/$(uname -r)/build`, downloads its own headers into `/tmp/kernel-download`, and
builds against those. The downloaded trees cannot build a module:

- Ubuntu 22.04: `include/config/auto.conf` is missing ("Kernel configuration is invalid")
- Debian 12: `scripts/Makefile.debug` is missing from the `-common` tree's relative path

The postinst does have a dkms fallback, but it only runs **after** falcoctl returns success,
so `set -e` ends the script first.

Control, on a fresh Ubuntu 22.04 VM: the same 0.45.0 kmod install fails the same way. Then
on the same VM, `dkms build -m falco -v 11.0.0+driver -k $(uname -r)` against the installed
headers exits 0. After it, `dpkg --configure -a` completes, falco-kmod.service is active and
the module is loaded. The headers on the host were fine. The downloaded ones were not.

Scope: auto picks modern_ebpf on these kernels, so only hosts that ask for kmod explicitly
are affected. Why kmod passes on the other rows (download failed and fell back to local
headers, or the downloaded tree was complete) is not yet distinguished.

## Finding 6: Ubuntu 18.04 upgrades report success with no sensor running

On 18.04 the upgrade cell's package is fully configured (dpkg exit 0) and the service never
runs: systemd 237 rejects the shipped `falco-kmod.service` over a non-absolute
`ExecReload=kill` ("Exec format error"), and the postinst's `systemctl start ... || true`
swallows it. This is the same unit-file bug the legacy tier found under 0.44.1 (FINDINGS.md,
finding 2). Strict mode shows it still ships in 0.45.0 and 0.45.1-rc1. The fresh 18.04 cells
fail earlier, on #3994.

## Finding 7: Secure Boot rejects the kmod on rocky-9, and dnf calls it success

The rocky-9 VM boots UEFI (its image hangs under SeaBIOS), and libvirt's firmware
autoselection enforces Secure Boot. The dkms module builds, the kernel rejects it
(`Loading of module with unavailable key is rejected`), `%posttrans` fails, and dnf prints
`Error in POSTTRANS scriptlet` and **exits 0** with the package listed as installed. This is
expected without MOK enrollment, and AlmaLinux 9 (same kernel line, BIOS boot) passes kmod.
The general lesson is about rpm: a check that trusted the package manager's exit code would
have painted this cell green. `pkg_installed` reads the scriptlet output for that reason,
and cells now record `secure_boot`.

## Finding 8: CentOS 7 cannot install 0.45.x (expected)

`Requires: libc.so.6(GLIBC_2.28)`. EL7 ships 2.17. 0.40.0 remains the last release that
installs there (FINDINGS.md, finding 3). The upgrade cell is `blocked`: 0.44.1 cannot install
either, so no upgrade was attempted.

## Side observation: running but degraded

Cells that passed every check still logged BPF program load failures (2 to 4) on debian-11
(5.10), rocky-8 (4.18), ubuntu-20.04 HWE (5.15) and ubuntu-22.04 (5.15). Falco opens its
engine and runs with reduced coverage. Flagged as `bpf_load_errors` in matrix.json, not yet
investigated.

---

## Harness problems found during the run (fixed before the reported grid)

Each would have put a wrong colour in the grid. All three were caught by reading evidence
bundles rather than trusting the summary.

| Symptom | Cause | Fix |
|---|---|---|
| apt "installed the local file" but fetched it from the repo | given a local `.deb` whose version the configured repo also carries, apt downloads the repo's copy | strict mode never configures the Falco repo |
| kmod red on debian-11 and rocky-8 in the first grid | missing prerequisites, not Falco: dkms is in EPEL on EL8/9, and Debian 11's security repo 404s the headers for the image kernel since its LTS ended | `build_prereqs.sh` gate: EPEL, archive.debian.org for bullseye-security, or move to the archive's current kernel and reboot. Unmet prerequisites are now `error`, never `fail` |
| every rocky-8 rc1 cell red on "wrong version" | rpm spells the RC `0.45.1_rc1-1` | version match normalizes `_` and `~`; the 4 cells were re-derived from their stored observations with `qualify.py --rejudge`, no re-run |

A debugging boot (`provision.py --distro debian-11 --keep`) also overwrote the local, gitignored
`results/debian-11.*` and `results/results.json`. Jenkins builds in its own workspace, so the
nightly is unaffected. `results.json` was rebuilt with `--merge-results`, and its debian-11 row
is now that no-Falco boot until the next local run.

---

## Open items

- File nothing upstream from here. Candidates for Manny: finding 5 (falcoctl's header download
  preferred over working local headers, and the postinst fallback ordering), with the control
  as the reproduction. Finding 1 is #3994 itself.
- Wire `qualify.py` into Jenkins as a job that watches the dev repo and qualifies each new
  `-rcN` as it appears. The RC listing is a public S3 bucket, so discovery is a single GET.
- Decide whether rocky-9 should stay a Secure Boot host (useful coverage) or boot UEFI with
  Secure Boot off, and add Secure Boot as a deliberate axis instead of an accident.
- Investigate the degraded rows (`bpf_load_errors`).

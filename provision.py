#!/usr/bin/env python3
"""
provision.py -- boot a real VM for one distro, run checks against it, tear it down.

WHY THIS EXISTS
---------------
Containers share the host kernel. If the thing you are testing depends on the
kernel -- a kernel module, an eBPF program, a syscall hook -- then a container
tells you nothing, because you are testing the host's kernel wearing another
distro's userspace as a costume.

So: real VMs, each with its own kernel. That is the whole reason this script
uses libvirt/KVM instead of Docker.

THE LIFECYCLE (borrowed from Molecule, which borrowed it from common sense)
---------------------------------------------------------------------------
    create   -- make a thin disk from a cached base image, boot a VM
    prepare  -- wait until SSH answers
    converge -- run the thing under test
    verify   -- assert on the results
    destroy  -- always, even when things fail

USAGE
-----
    ./provision.py --distro ubuntu-22.04
    ./provision.py --distro ubuntu-22.04 --keep        # leave the VM running to poke at
    ./provision.py --tier fast --all                   # every distro in the fast tier
    ./provision.py --list                              # what is in the matrix

Results land in ./results/<distro>.xml as JUnit XML, which is what Jenkins
consumes to draw its test trend graphs.

REQUIREMENTS
------------
    sudo apt install -y libvirt-daemon-system libvirt-clients virtinst \
                        qemu-kvm cloud-image-utils genisoimage python3-yaml
    sudo usermod -aG libvirt,kvm $USER     # then log out and back in

Verify with:  virsh list --all      (should work without sudo)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Missing PyYAML.  Install with:  sudo apt install python3-yaml")


# ---------------------------------------------------------------------------
# libvirt connection URI -- PIN THIS EXPLICITLY. Do not inherit it.
#
# virsh has two worlds:
#
#   qemu:///system   the machine-wide libvirt instance. Has the 'default'
#                    network, runs VMs as the libvirt-qemu user, and is what
#                    you almost always want.
#
#   qemu:///session  a per-user instance. No default network, no DHCP, cannot
#                    see system VMs. Fine for desktop toys, useless here.
#
# The trap: an interactive login shell often ends up on 'system' (via polkit,
# desktop session integration, or a shell profile), while a NON-interactive
# context -- ssh commands, cron, and crucially Jenkins -- silently falls back
# to 'session'. So a thing that works when you type it by hand fails inside
# CI, with an error that blames the network rather than the URI.
#
# Setting the environment variable here means every virsh and virt-install
# child process inherits the right answer, regardless of who invoked us.
# ---------------------------------------------------------------------------
LIBVIRT_URI = os.environ.get("LIBVIRT_DEFAULT_URI") or "qemu:///system"
os.environ["LIBVIRT_DEFAULT_URI"] = LIBVIRT_URI

# ---------------------------------------------------------------------------
# Paths. Everything lives under one directory so cleanup is trivial and so the
# whole lab can be relocated to another disk by changing one variable.
# ---------------------------------------------------------------------------
LAB_ROOT = Path(os.environ.get("KMATRIX_ROOT", Path.home() / "kernel-matrix-lab"))
BASE_IMAGES = LAB_ROOT / "base"       # downloaded once, read-only afterwards
OVERLAYS = LAB_ROOT / "overlays"      # per-run thin disks, deleted after
SEEDS = LAB_ROOT / "seeds"            # cloud-init ISOs
RESULTS = Path("results")             # JUnit XML for Jenkins

SSH_KEY = Path.home() / ".ssh" / "id_ed25519_kmatrix"

# SSH options used everywhere. StrictHostKeyChecking=no because every VM is
# brand new and will never have a known host key; UserKnownHostsFile=/dev/null
# stops us polluting the real known_hosts with throwaway entries.
SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=5",
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def log(msg: str, level: str = "INFO") -> None:
    """Timestamped output. Jenkins console logs are much easier to read with these."""
    print(f"[{time.strftime('%H:%M:%S')}] {level:<5} {msg}", flush=True)


def run(cmd: list[str], check: bool = True, capture: bool = True, timeout: int = 300):
    """Thin wrapper around subprocess so every call logs the same way."""
    log(f"$ {' '.join(cmd)}", "EXEC")
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Distro:
    name: str
    image_url: str
    ssh_user: str
    expect_kernel: str
    tier: str = "full"
    memory_mb: int = 2048
    vcpus: int = 2
    boot_timeout_sec: int = 300

    @property
    def base_image(self) -> Path:
        # Name the cached file after the distro, not the URL, so a changed URL
        # for the same distro replaces rather than accumulates.
        return BASE_IMAGES / f"{self.name}.qcow2"


@dataclass
class CheckResult:
    name: str
    passed: bool
    duration: float
    output: str = ""
    message: str = ""
    skipped: bool = False
    detail: str = ""


@dataclass
class RunResult:
    distro: str
    kernel: str = ""               # the kernel we actually observed
    checks: list[CheckResult] = field(default_factory=list)
    falco: dict | None = None      # characterisation from falco_probe.sh
    error: str | None = None       # set when the VM never came up at all

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if not c.passed and not c.skipped)


# ---------------------------------------------------------------------------
# Kernel version comparison
# ---------------------------------------------------------------------------
# Lexicographic sorting puts 5.9 AFTER 5.10, which silently corrupts any
# report built on it. Convert to a tuple of ints and let Python compare
# element by element.
# ---------------------------------------------------------------------------
_NUMBERS = re.compile(r"\d+")


def kernel_key(version: str, width: int = 4) -> tuple[int, ...]:
    """'5.15.0-91-generic' -> (5, 15, 0, 91)"""
    parts = [int(n) for n in _NUMBERS.findall(version)][:width]
    return tuple(parts + [0] * (width - len(parts)))


def kernel_at_least(candidate: str, minimum: str) -> bool:
    """Compare only as deep as `minimum` specifies: '5.15.0-91' >= '5.10' is True."""
    depth = len(_NUMBERS.findall(minimum))
    return kernel_key(candidate, depth) >= kernel_key(minimum, depth)


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
def preflight() -> None:
    """
    Fail early and legibly, rather than three minutes into a boot.

    Every check here corresponds to a real failure mode that produces a
    confusing error message if you let it happen naturally.
    """
    problems = []

    if not Path("/dev/kvm").exists():
        problems.append("/dev/kvm is missing -- no hardware virtualization available")

    # Confirm we can actually reach the URI we pinned, and that it is the
    # system one. Session URIs have no default network and will fail later
    # with a misleading 'network not found'.
    result = subprocess.run(["virsh", "uri"], capture_output=True, text=True)
    actual_uri = result.stdout.strip()
    if result.returncode != 0:
        problems.append(f"cannot reach libvirt at {LIBVIRT_URI}: {result.stderr.strip()}")
    elif "session" in actual_uri:
        problems.append(
            f"virsh resolved to {actual_uri}, not a system URI. "
            "Session URIs have no default network. "
            "Fix: export LIBVIRT_DEFAULT_URI=qemu:///system"
        )

    # The default network provides DHCP. Without it a VM boots fine and then
    # never gets an address, which looks like a broken image rather than a
    # missing network.
    nets = subprocess.run(["virsh", "net-list", "--name"], capture_output=True, text=True)
    if "default" not in nets.stdout.split():
        problems.append(
            "the libvirt 'default' network is not active. Fix:\n"
            "      sudo virsh net-start default && sudo virsh net-autostart default"
        )

    # cloud-init seed ISOs need one of these two tools.
    if not (shutil.which("cloud-localds") or shutil.which("genisoimage")):
        problems.append(
            "neither cloud-localds nor genisoimage is installed. Fix:\n"
            "      sudo apt install -y cloud-image-utils genisoimage"
        )

    # ---------------------------------------------------------------------
    # Can the hypervisor actually REACH our disk images?
    #
    # System libvirt runs qemu as the 'libvirt-qemu' user. That user needs
    # execute (traverse) permission on every directory between / and the
    # image. Home directories are commonly mode 750, which blocks it.
    #
    # Left undetected this surfaces as a Permission denied on the storage
    # file three steps into provisioning, long after the overlay and seed
    # have been built -- so check it here, cheaply, using only stat().
    # ---------------------------------------------------------------------
    blocked = []
    probe = LAB_ROOT.absolute()
    for parent in [probe, *probe.parents]:
        if not parent.exists():
            continue
        mode = parent.stat().st_mode
        if not mode & 0o001:                       # no world-execute bit
            # An ACL may still grant it. getfacl is cheap and definitive.
            acl = subprocess.run(["getfacl", "-p", str(parent)],
                                 capture_output=True, text=True)
            if "user:libvirt-qemu:--x" not in acl.stdout.replace(" ", ""):
                blocked.append(str(parent))

    if blocked:
        problems.append(
            "the libvirt-qemu user cannot traverse into the lab directory.\n"
            f"      blocked at: {', '.join(blocked)}\n"
            "      Fix (grants traverse to libvirt-qemu only, nobody else):\n"
            + "\n".join(f"      sudo setfacl -m u:libvirt-qemu:x {p}" for p in blocked)
        )

    if problems:
        log("preflight failed:", "ERROR")
        for p in problems:
            log(f"  - {p}", "ERROR")
        sys.exit(2)

    log(f"preflight OK (libvirt: {actual_uri})")


def ensure_dirs() -> None:
    for d in (BASE_IMAGES, OVERLAYS, SEEDS, RESULTS):
        d.mkdir(parents=True, exist_ok=True)


def ensure_ssh_key() -> None:
    """
    A dedicated throwaway keypair for the lab.

    Using a separate key rather than your personal one means the public half can
    be baked into disposable VM images without a second thought, and revoking it
    is just deleting two files.
    """
    if SSH_KEY.exists():
        return
    log(f"generating lab SSH key at {SSH_KEY}")
    run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "kernel-matrix-lab",
         "-f", str(SSH_KEY)])


def ensure_base_image(distro: Distro) -> None:
    """
    Download the cloud image once, then never touch it again.

    This is the foundation of the disk-space story: the base is read-only and
    shared, and each VM gets a thin overlay that stores only its differences.
    Ten VMs from one 600MB base cost roughly 600MB + (10 x a few hundred MB),
    not 6GB.
    """
    if distro.base_image.exists():
        size_mb = distro.base_image.stat().st_size / 1e6
        log(f"base image cached: {distro.base_image.name} ({size_mb:.0f} MB)")
        return

    log(f"downloading base image for {distro.name} (one time only)")
    tmp = distro.base_image.with_suffix(".partial")

    def progress(block_num, block_size, total_size):
        if total_size > 0 and block_num % 200 == 0:
            pct = min(100, block_num * block_size * 100 / total_size)
            print(f"\r    {pct:5.1f}%", end="", flush=True)

    urllib.request.urlretrieve(distro.image_url, tmp, reporthook=progress)
    print()
    tmp.rename(distro.base_image)   # atomic: a partial download never looks complete
    log(f"cached {distro.base_image.name}")


def make_seed_iso(distro: Distro, vm_name: str) -> Path:
    """
    Build a cloud-init 'seed' ISO.

    Cloud images boot with no users and no SSH keys. On first boot, cloud-init
    looks for a small ISO labelled 'cidata' and reads its configuration from
    there. That is how we inject our public key without ever mounting or
    modifying the disk image itself.
    """
    seed = SEEDS / f"{vm_name}-seed.iso"
    pubkey = SSH_KEY.with_suffix(".pub").read_text().strip()

    user_data = f"""#cloud-config
hostname: {vm_name}
users:
  - name: {distro.ssh_user}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - {pubkey}
ssh_pwauth: false
# Speed matters: every second here is multiplied by the size of the matrix.
package_update: false
package_upgrade: false
"""
    meta_data = f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n"

    ud = SEEDS / f"{vm_name}-user-data"
    md = SEEDS / f"{vm_name}-meta-data"
    ud.write_text(user_data)
    md.write_text(meta_data)

    # cloud-localds is the friendly wrapper; genisoimage is the fallback.
    if shutil.which("cloud-localds"):
        run(["cloud-localds", str(seed), str(ud), str(md)])
    else:
        run(["genisoimage", "-output", str(seed), "-volid", "cidata",
             "-joliet", "-rock", str(ud), str(md)])

    ud.unlink(missing_ok=True)
    md.unlink(missing_ok=True)
    return seed


def create_overlay(distro: Distro, vm_name: str) -> Path:
    """
    Create a copy-on-write disk backed by the shared base image.

    qemu-img with -b makes a disk that reads through to the base and only
    stores writes. Creating it is instant regardless of the base image size,
    which is what makes spinning up ten VMs cheap.

    The base image is never modified, so a corrupted VM is fixed by deleting
    its overlay.
    """
    overlay = OVERLAYS / f"{vm_name}.qcow2"
    run([
        "qemu-img", "create",
        "-f", "qcow2",
        "-F", "qcow2",                       # format of the BACKING file
        "-b", str(distro.base_image.absolute()),
        str(overlay),
        "20G",                               # virtual ceiling, not allocated up front
    ])
    return overlay


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------
def boot_vm(distro: Distro, vm_name: str, overlay: Path, seed: Path) -> None:
    """
    Boot the VM with virt-install.

    --import          use the disk as-is; do not run an installer
    --noautoconsole   do not attach a console; this is unattended
    --network         default NAT network, so the VM gets a DHCP address
    --os-variant      lets libvirt pick sensible virtual hardware
    """
    run([
        "virt-install",
        "--name", vm_name,
        "--memory", str(distro.memory_mb),
        "--vcpus", str(distro.vcpus),
        "--import",
        "--disk", f"path={overlay},format=qcow2,bus=virtio",
        "--disk", f"path={seed},device=cdrom",
        "--network", "network=default,model=virtio",
        "--graphics", "none",
        "--noautoconsole",
        "--os-variant", "linux2022",
    ], timeout=120)


def get_vm_ip(vm_name: str, timeout: int) -> str | None:
    """
    Poll libvirt's DHCP leases until the VM appears.

    virsh domifaddr reads from the DHCP server that libvirt runs on the default
    network. The address shows up a few seconds after the VM's network comes up,
    which is well before SSH is ready.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = subprocess.run(
            ["virsh", "domifaddr", vm_name, "--source", "lease"],
            capture_output=True, text=True,
        )
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+", result.stdout)
        if match:
            return match.group(1)
        time.sleep(3)
    return None


def wait_for_ssh(ip: str, user: str, timeout: int) -> bool:
    """
    Poll SSH until it answers.

    An IP address does not mean the machine is ready -- cloud-init still has to
    create the user and install the key. This is the single most common place
    for a naive harness to produce flaky results: it connects too early, fails,
    and blames the system under test.
    """
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        result = subprocess.run(
            ["ssh", *SSH_OPTS, "-i", str(SSH_KEY), f"{user}@{ip}", "true"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            log(f"ssh ready after {attempt} attempt(s)")
            return True
        time.sleep(4)
    return False


def ssh_exec(ip: str, user: str, command: str, timeout: int = 60):
    """Run one command on the VM and hand back the completed process."""
    return subprocess.run(
        ["ssh", *SSH_OPTS, "-i", str(SSH_KEY), f"{user}@{ip}", command],
        capture_output=True, text=True, timeout=timeout,
    )


def destroy_vm(vm_name: str, overlay: Path, seed: Path) -> None:
    """
    Tear everything down.

    Called from a finally block so it runs even when checks fail or the script
    is interrupted. A harness that leaks VMs will quietly consume the host over
    a few weeks and nobody will connect the two events.

    destroy = power off (ungraceful, which is fine for a disposable VM)
    undefine = remove it from libvirt's config
    """
    subprocess.run(["virsh", "destroy", vm_name], capture_output=True, text=True)
    subprocess.run(["virsh", "undefine", vm_name, "--nvram"], capture_output=True, text=True)
    overlay.unlink(missing_ok=True)
    seed.unlink(missing_ok=True)
    log(f"destroyed {vm_name} and removed its disks")


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------
def run_checks(distro: Distro, ip: str, checks: list[dict]) -> list[CheckResult]:
    """Execute each declared check over SSH and turn it into a CheckResult."""
    results: list[CheckResult] = []

    for check in checks:
        name = check["name"]
        started = time.time()
        log(f"check: {name}")

        try:
            proc = ssh_exec(ip, distro.ssh_user, check["command"])
        except subprocess.TimeoutExpired:
            results.append(CheckResult(name, False, time.time() - started,
                                       message="command timed out"))
            continue

        output = (proc.stdout + proc.stderr).strip()
        duration = time.time() - started
        passed = proc.returncode == 0
        message = ""

        # --- special assertion: does the kernel match what we expected? ----
        if check.get("expect_kernel_prefix"):
            actual = proc.stdout.strip()
            passed = actual.startswith(distro.expect_kernel)
            if not passed:
                message = (f"expected kernel starting with {distro.expect_kernel!r}, "
                           f"got {actual!r}")
            else:
                message = f"kernel {actual}"

        # --- special assertion: numeric kernel comparison -----------------
        elif "min_kernel" in check:
            actual = proc.stdout.strip()
            passed = kernel_at_least(actual, check["min_kernel"])
            message = (f"{actual} {'>=' if passed else '<'} {check['min_kernel']}")

        # --- ordinary assertion: substring in output ----------------------
        elif check.get("expect_contains"):
            needle = check["expect_contains"]
            passed = passed and needle in output
            if not passed:
                message = f"expected {needle!r} in output"

        # allow_failure turns a hard failure into a recorded skip. Useful for
        # informational checks that legitimately do not apply everywhere.
        skipped = False
        if not passed and check.get("allow_failure"):
            skipped, passed = True, True
            message = f"informational only: {message or 'check did not pass'}"

        results.append(CheckResult(
            name=name,
            passed=passed,
            duration=duration,
            output=output[:2000],           # keep XML from exploding
            message=message,
            skipped=skipped,
            detail=check.get("description", "").strip(),
        ))

        status = "SKIP" if skipped else ("PASS" if passed else "FAIL")
        log(f"  -> {status}  {message or output[:70]}", status)

    return results


# ---------------------------------------------------------------------------
# Falco: install a real eBPF security agent and characterise it
# ---------------------------------------------------------------------------
def run_falco_probe(distro: Distro, ip: str) -> dict:
    """
    Push falco_probe.sh to the guest, run it as root, parse its JSON.

    This is the step that turns the lab from "does this host look capable"
    into "does a real sensor actually work here, which driver did it pick,
    and what did it cost". A failure is a RESULT, not an exception -- an old
    kernel that cannot load the modern eBPF probe is precisely the finding
    the matrix exists to surface.
    """
    probe = Path(__file__).parent / "falco_probe.sh"
    if not probe.exists():
        return {"error": "falco_probe.sh not found next to provision.py"}

    log("falco: uploading probe")
    scp = subprocess.run(
        ["scp", *SSH_OPTS, "-i", str(SSH_KEY), str(probe),
         f"{distro.ssh_user}@{ip}:/tmp/falco_probe.sh"],
        capture_output=True, text=True, timeout=60,
    )
    if scp.returncode != 0:
        return {"error": f"scp failed: {scp.stderr.strip()[:200]}"}

    log("falco: installing and characterising (this takes a few minutes)")
    try:
        proc = ssh_exec(
            ip, distro.ssh_user,
            "sudo bash /tmp/falco_probe.sh",
            timeout=900,                     # package install over the network is slow
        )
    except subprocess.TimeoutExpired:
        return {"error": "probe timed out after 15 minutes"}

    # The probe prints progress to stderr and exactly one JSON object to
    # stdout, so we can parse stdout without filtering.
    for line in proc.stderr.splitlines():
        log(f"  {line}")

    try:
        start = proc.stdout.index("{")
        return json.loads(proc.stdout[start:])
    except (ValueError, json.JSONDecodeError) as exc:
        return {"error": f"could not parse probe output: {exc}",
                "raw": proc.stdout[-400:]}


# ---------------------------------------------------------------------------
# JUnit XML output
# ---------------------------------------------------------------------------
def write_junit(result: RunResult, path: Path) -> None:
    """
    Emit JUnit XML.

    Every CI system on earth reads this format. Producing it is what turns a
    script that prints things into a job Jenkins can graph, trend, and gate on.
    Do not invent your own results format.
    """
    suite = ET.Element("testsuite", {
        "name": f"kernel-matrix.{result.distro}",
        "tests": str(len(result.checks)),
        "failures": str(result.failed),
        "errors": "1" if result.error else "0",
        "skipped": str(sum(1 for c in result.checks if c.skipped)),
        "time": f"{sum(c.duration for c in result.checks):.2f}",
    })

    # A VM that never booted is an ERROR, not a FAILURE. The distinction
    # matters: failure means the system under test misbehaved, error means our
    # harness could not even ask the question.
    if result.error:
        case = ET.SubElement(suite, "testcase", {
            "name": "vm_provisioning", "classname": result.distro, "time": "0",
        })
        ET.SubElement(case, "error", {"message": result.error}).text = result.error

    for check in result.checks:
        case = ET.SubElement(suite, "testcase", {
            "name": check.name,
            "classname": f"kernel-matrix.{result.distro}",
            "time": f"{check.duration:.2f}",
        })
        if check.skipped:
            ET.SubElement(case, "skipped", {"message": check.message})
        elif not check.passed:
            failure = ET.SubElement(case, "failure", {"message": check.message or "check failed"})
            failure.text = f"{check.detail}\n\nOutput:\n{check.output}"
        if check.output:
            ET.SubElement(case, "system-out").text = check.output

    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
    log(f"wrote {path}")


# ---------------------------------------------------------------------------
# One distro, end to end
# ---------------------------------------------------------------------------
def test_distro(distro: Distro, checks: list[dict], keep: bool = False,
                with_falco: bool = False) -> RunResult:
    """
    The full lifecycle for a single distro.

    Everything after boot lives inside try/finally so the VM is always cleaned
    up, including on Ctrl-C.
    """
    # A unique name per run means two concurrent runs never collide on a
    # libvirt domain name -- which matters the moment Jenkins runs stages in
    # parallel.
    vm_name = f"km-{distro.name}-{os.getpid()}-{int(time.time()) % 10000}"
    result = RunResult(distro=distro.name)

    log("=" * 70)
    log(f"START {distro.name}  (vm: {vm_name})")
    log("=" * 70)

    overlay = seed = None
    try:
        ensure_base_image(distro)
        overlay = create_overlay(distro, vm_name)
        seed = make_seed_iso(distro, vm_name)

        boot_vm(distro, vm_name, overlay, seed)

        ip = get_vm_ip(vm_name, timeout=distro.boot_timeout_sec)
        if not ip:
            result.error = f"VM never acquired an IP within {distro.boot_timeout_sec}s"
            return result
        log(f"VM address: {ip}")

        if not wait_for_ssh(ip, distro.ssh_user, timeout=distro.boot_timeout_sec):
            result.error = f"SSH never became available at {ip}"
            return result

        result.checks = run_checks(distro, ip, checks)

        # capture the kernel we actually saw, for the report
        for c in result.checks:
            if c.name == "kernel_version_matches_expectation" and c.output:
                result.kernel = c.output.strip().splitlines()[0]
                break

        if with_falco:
            result.falco = run_falco_probe(distro, ip)
            f = result.falco
            if f.get("error"):
                log(f"falco: {f['error']}", "FAIL")
            else:
                log(f"falco: driver={f.get('driver')} "
                    f"started={f.get('started')} detected={f.get('detected')} "
                    f"rss={f.get('rss_kb')}KB", "PASS")

        return result

    except subprocess.CalledProcessError as exc:
        # Print the real error immediately and in full. Burying a subprocess
        # failure in a truncated summary line at the end is how you end up
        # re-running things by hand just to find out what actually broke.
        log(f"command failed: {' '.join(exc.cmd)}", "ERROR")
        for line in (exc.stderr or exc.stdout or "<no output>").strip().splitlines():
            log(f"  | {line}", "ERROR")
        result.error = (exc.stderr or exc.stdout or "command failed").strip()
        return result
    except Exception as exc:                       # noqa: BLE001 -- harness must not die
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        if keep:
            log(f"--keep set: leaving {vm_name} running. "
                f"Destroy it with: virsh destroy {vm_name} && virsh undefine {vm_name}")
        elif overlay and seed:
            destroy_vm(vm_name, overlay, seed)


# ---------------------------------------------------------------------------
# Matrix loading
# ---------------------------------------------------------------------------
def load_matrix(path: Path) -> tuple[list[Distro], list[dict]]:
    data = yaml.safe_load(path.read_text())
    defaults = data.get("defaults", {})
    distros = []
    for entry in data["distros"]:
        merged = {**defaults, **entry}
        distros.append(Distro(
            name=merged["name"],
            image_url=merged["image_url"],
            ssh_user=merged["ssh_user"],
            expect_kernel=merged["expect_kernel"],
            tier=merged.get("tier", "full"),
            memory_mb=merged.get("memory_mb", 2048),
            vcpus=merged.get("vcpus", 2),
            boot_timeout_sec=merged.get("boot_timeout_sec", 300),
        ))
    return distros, data["checks"]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Boot real VMs across a distro matrix and assert on their kernels.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--matrix", type=Path, default=Path("matrix.yaml"))
    parser.add_argument("--distro", help="run a single distro by name")
    parser.add_argument("--tier", choices=["fast", "full", "legacy"],
                        help="run every distro in a tier")
    parser.add_argument("--all", action="store_true", help="run every distro in the matrix")
    parser.add_argument("--list", action="store_true", help="print the matrix and exit")
    parser.add_argument("--keep", action="store_true", help="do not destroy the VM afterwards")
    parser.add_argument("--falco", action="store_true",
                        help="install Falco on each VM and characterise it (slow, ~5 min/distro)")
    args = parser.parse_args()

    distros, checks = load_matrix(args.matrix)

    if args.list:
        print(f"\n{'DISTRO':<18}{'TIER':<8}{'EXPECT KERNEL':<16}{'SSH USER'}")
        print("-" * 62)
        for d in distros:
            print(f"{d.name:<18}{d.tier:<8}{d.expect_kernel:<16}{d.ssh_user}")
        print(f"\n{len(checks)} checks defined\n")
        return 0

    # Choose which distros to run
    if args.distro:
        selected = [d for d in distros if d.name == args.distro]
        if not selected:
            sys.exit(f"No distro named {args.distro!r}. Try --list.")
    elif args.tier:
        selected = [d for d in distros if d.tier == args.tier]
    elif args.all:
        selected = distros
    else:
        sys.exit("Pick one of --distro NAME, --tier fast|full, or --all. See --help.")

    preflight()
    ensure_dirs()
    ensure_ssh_key()

    results = [test_distro(d, checks, keep=args.keep, with_falco=args.falco)
               for d in selected]

    for result in results:
        write_junit(result, RESULTS / f"{result.distro}.xml")

    # A single JSON file feeds both the HTML report and the metrics exporter.
    # JUnit is for Jenkins; this is for everything else.
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "host_kernel": subprocess.run(["uname", "-r"], capture_output=True,
                                      text=True).stdout.strip(),
        "results": [
            {
                "distro": r.distro,
                "kernel": r.kernel,
                "error": r.error,
                "checks": [
                    {"name": c.name, "passed": c.passed, "skipped": c.skipped,
                     "message": c.message, "duration": round(c.duration, 2)}
                    for c in r.checks
                ],
                "falco": r.falco,
            }
            for r in results
        ],
    }
    (RESULTS / "results.json").write_text(json.dumps(payload, indent=2))
    log(f"wrote {RESULTS / 'results.json'}")

    # ---- summary -------------------------------------------------------
    print()
    log("=" * 70)
    log("SUMMARY")
    log("=" * 70)
    exit_code = 0
    for result in results:
        if result.error:
            log(f"  {result.distro:<18} ERROR  {result.error[:60]}", "ERROR")
            exit_code = 1
        elif result.failed:
            log(f"  {result.distro:<18} {result.failed} check(s) failed", "FAIL")
            exit_code = 1
        else:
            log(f"  {result.distro:<18} all {len(result.checks)} checks passed", "PASS")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
# =============================================================================
#  build_prereqs.sh -- make the guest able to build a kmod for its RUNNING kernel
# =============================================================================
#
#  Runs inside the guest as root, before falco_probe.sh, on qualification runs
#  (provision.py ensure_build_prereqs). A kmod scenario that fails because the
#  host had no compiler or headers says nothing about the package; it is a
#  false negative, and a qualification grid full of them is worse than none.
#
#  The probe's own prerequisite step is best effort and stays that way. This
#  one is a gate, and it found two gaps the probe had been warning about:
#
#    * Debian's archive drops headers for superseded kernel ABIs at point
#      releases, so the cloud image's kernel (debian-11: 5.10.0-46) has no
#      installable headers. The fix is the kernel the archive does carry.
#    * dkms is not in the base repos of EL8/EL9 at all; it lives in EPEL.
#
#  Exit codes, read by provision.py:
#     0   ready: dkms, make, gcc and the running kernel's headers are present
#    10   installed the archive's current kernel with headers: reboot, re-run
#     1   cannot satisfy the prerequisites (message on the last line)
# =============================================================================

set -u
krel=$(uname -r)
# Everything also goes to a log collect_evidence.sh picks up.
exec > >(tee -a /var/log/km-build-prereqs.log) 2>&1
echo "prereqs: $(date -u +%FT%TZ) running kernel $krel"

have_headers() { [ -e "/lib/modules/$krel/build/Makefile" ]; }
ready() { have_headers && command -v dkms >/dev/null && command -v gcc >/dev/null \
          && command -v make >/dev/null; }

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    # Debian 11's LTS ended in August 2026. security.debian.org still serves
    # its index but 404s the packages in it, headers for the image's kernel
    # included; archive.debian.org has them. Same move as CentOS 7's vault.
    # Valid-Until is off because archived Release files have expired.
    if grep -q '^VERSION_CODENAME=bullseye' /etc/os-release 2>/dev/null; then
        sed -i -E 's#https?://(security|deb)\.debian\.org/debian-security#http://archive.debian.org/debian-security#' \
            /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null
        echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99km-archive
        echo "prereqs: bullseye is EOL; bullseye-security now from archive.debian.org"
    fi
    apt-get update -qq
    apt-get install -y -qq dkms make gcc
    have_headers || apt-get install -y -qq "linux-headers-$krel"
    if ! have_headers; then
        # Debian: the kernel the archive carries now, and its headers.
        if grep -qi '^ID=debian' /etc/os-release; then
            meta="linux-image-amd64 linux-headers-amd64"
        else
            meta="linux-image-generic linux-headers-generic"
        fi
        echo "prereqs: no headers for $krel in the archive; installing $meta"
        apt-get install -y -qq $meta && { echo "prereqs: reboot needed"; exit 10; }
        echo "prereqs: could not install $meta"; exit 1
    fi
else
    pm=dnf
    command -v dnf >/dev/null 2>&1 || pm=yum
    # CentOS 7 is EOL and its mirrors moved to the vault (same fix as the probe).
    if grep -qi "centos.*7" /etc/os-release 2>/dev/null; then
        sed -i -e 's/^mirrorlist/#mirrorlist/' \
               -e 's|^#\?baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' \
               /etc/yum.repos.d/CentOS-*.repo 2>/dev/null
    fi
    # EPEL carries dkms on EL. Fedora has it in the main repos.
    if ! grep -qi '^ID=fedora' /etc/os-release && ! rpm -q epel-release >/dev/null 2>&1; then
        $pm install -y -q epel-release
    fi
    $pm install -y -q dkms make gcc elfutils-libelf-devel
    have_headers || $pm install -y -q "kernel-devel-$krel"
    if ! have_headers; then
        echo "prereqs: no kernel-devel for $krel in the repos; installing kernel kernel-devel"
        $pm install -y -q kernel kernel-devel && { echo "prereqs: reboot needed"; exit 10; }
        echo "prereqs: could not install kernel kernel-devel"; exit 1
    fi
fi

if ready; then
    echo "prereqs: ready for $krel (dkms $(dkms --version 2>/dev/null | head -1), $(gcc --version | head -1))"
    exit 0
fi
missing=""
have_headers || missing="$missing headers-$krel"
for t in dkms gcc make; do command -v "$t" >/dev/null || missing="$missing $t"; done
echo "prereqs: still missing:$missing"
exit 1

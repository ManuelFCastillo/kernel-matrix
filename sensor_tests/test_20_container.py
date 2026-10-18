"""
Container events: the event carries the container's identity, and the
container rules fire.

Falco 0.41+ gets container metadata from the container plugin
(libcontainer.so), which is exactly what broke on glibc < 2.34 hosts
(plugins#1500). A host-only test can pass while every container alert comes
out with container.id=host or an empty image: that is the regression these
tests exist for.

The runtime is whatever the distro ships: docker.io on Debian/Ubuntu, podman
on the RPM family. Installing it is setup, so a distro with no runtime
package skips; a runtime that installs and then cannot run a container is a
harness error, not a Falco result.
"""

from __future__ import annotations

import shlex

import pytest



@pytest.fixture(scope="module")
def runtime(km, guest, sensor) -> str:
    if guest.fmt == "deb":
        cmd, install = "docker", ("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io "
                                  "&& systemctl enable --now docker")
    else:
        # The plugin reads podman metadata from its API socket, which the
        # package installs but does not start.
        cmd, install = "podman", ("$(command -v dnf || command -v yum) install -y -q podman "
                                  "&& systemctl enable --now podman.socket")
    r = guest.sh(install, timeout=900)
    if r.returncode != 0:
        pytest.skip(f"no container runtime package on {guest.distro.name}: {r.stderr.strip()[-200:]}")
    image = km["settings"]["container"]["image"]
    pull = guest.sh(f"{cmd} pull -q {image}", timeout=600)
    if pull.returncode != 0:
        pytest.fail(f"harness: {cmd} cannot pull {image}: {(pull.stdout + pull.stderr)[-400:]}",
                    pytrace=False)
    # The plugin reads metadata from the runtime's socket. Restart Falco once
    # the runtime exists, as a fleet's config management would after adding
    # docker to a host that already had Falco.
    sensor.restart()
    return cmd


def run(guest, runtime, image, inner: str, flags: str = "") -> None:
    guest.sh(f"{runtime} run --rm {flags} {image} sh -c {shlex.quote(inner)}", timeout=180)


def test_container_identity(km, guest, sensor, runtime, measure):
    """A host rule fired inside a container names the container and its image."""
    image = km["settings"]["container"]["image"]
    off = sensor.offset()
    # The sleep lets the plugin fetch metadata before the event: a container
    # that lives 50 ms is a race test, not an identity test.
    run(guest, runtime, image, f"sleep 3; cat /etc/shadow > /dev/null")
    alert = sensor.wait_alert(off, "Read sensitive file untrusted",
                              fields={"fd.name": "/etc/shadow"}, timeout=60)
    assert alert is not None, "no alert for /etc/shadow read inside a container"
    of = alert.get("output_fields") or {}
    cid = of.get("container.id")
    measure("container.id", cid)
    measure("container.image.repository", of.get("container.image.repository"))
    measure("container.name", of.get("container.name"))
    assert cid and cid != "host" and len(cid) == 12, f"event not attributed to a container: {of}"
    repo = of.get("container.image.repository") or ""
    assert repo.endswith("alpine"), f"container metadata missing or wrong: {of}"


def test_terminal_shell_in_container(km, guest, sensor, runtime):
    image = km["settings"]["container"]["image"]
    off = sensor.offset()
    # -t without -i: a tty in the container, no stdin needed from ssh.
    run(guest, runtime, image, "sleep 2; exit 0", flags="-t")
    assert sensor.wait_alert(off, "Terminal shell in container", timeout=60) is not None


def test_drop_and_execute_in_container(km, guest, sensor, runtime):
    """A binary written to the container's upper layer, then executed."""
    image = km["settings"]["container"]["image"]
    off = sensor.offset()
    run(guest, runtime, image, "sleep 2; cp /bin/busybox /tmp/echo && /tmp/echo km")
    assert sensor.wait_alert(off, "Drop and execute new binary in container", timeout=60) is not None


def test_netcat_rce_in_container(km, guest, sensor, runtime):
    image = km["settings"]["container"]["image"]
    off = sensor.offset()
    run(guest, runtime, image, "sleep 2; nc -w 1 -e /bin/true 127.0.0.1 9 ; true")
    assert sensor.wait_alert(off, "Netcat Remote Code Execution in Container", timeout=60) is not None

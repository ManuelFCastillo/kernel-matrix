"""
kmcov.py -- syscall triggers the shell cannot make on its own.

Runs on the guest as /tmp/km-cov/kmcov.py, so every command line that runs
it contains "km-cov" and matches the coverage rules. Python 3.6 compatible
(Rocky 8 has only platform-python 3.6), standard library only.

    kmcov.py tcp PORT        listen, connect to it, accept, close
    kmcov.py udp PORT        one datagram to 127.0.0.1:PORT
    kmcov.py setuid          fork; the child drops to uid 65534
    kmcov.py memfd           memfd_create, nothing executed
    kmcov.py memfd-exec      memfd_create, copy /bin/true in, exec it
    kmcov.py traceme         ptrace(PTRACE_TRACEME) in a child
    kmcov.py attach          ptrace(PTRACE_ATTACH) to a child, then detach
"""

import ctypes
import os
import socket
import sys

libc = ctypes.CDLL(None, use_errno=True)


def tcp(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", port))
    conn, _ = srv.accept()
    conn.sendall(b"km")
    cli.recv(2)
    for s in (conn, cli, srv):
        s.close()


def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"km", ("127.0.0.1", port))
    s.close()


def setuid():
    pid = os.fork()
    if pid == 0:
        os.setuid(65534)
        os._exit(0)
    os.waitpid(pid, 0)


MFD_CLOEXEC = 1
SYS_MEMFD_CREATE = 319          # x86_64; os.memfd_create is 3.8+


def memfd_create(name):
    if hasattr(os, "memfd_create"):
        return os.memfd_create(name, 0)
    fd = libc.syscall(SYS_MEMFD_CREATE, name.encode(), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "memfd_create")
    return fd


def memfd(execute):
    fd = memfd_create("km-cov-memfd")
    if not execute:
        os.close(fd)
        return
    with open("/bin/true", "rb") as src:
        os.write(fd, src.read())
    pid = os.fork()
    if pid == 0:
        os.execv("/proc/self/fd/%d" % fd, ["kmcov-memfd"])
    os.waitpid(pid, 0)


def traceme():
    pid = os.fork()
    if pid == 0:
        libc.ptrace(0, 0, None, None)      # PTRACE_TRACEME
        os._exit(0)
    os.waitpid(pid, 0)


def attach():
    """PTRACE_ATTACH to our own sleeping child, then detach and reap it."""
    import signal
    import time
    pid = os.fork()
    if pid == 0:
        time.sleep(5)
        os._exit(0)
    libc.ptrace(16, pid, None, None)       # PTRACE_ATTACH
    os.waitpid(pid, 0)                     # the attach stops the child
    libc.ptrace(17, pid, None, None)       # PTRACE_DETACH
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "tcp":
        tcp(int(sys.argv[2]))
    elif cmd == "udp":
        udp(int(sys.argv[2]))
    elif cmd == "setuid":
        setuid()
    elif cmd == "memfd":
        memfd(execute=False)
    elif cmd == "memfd-exec":
        memfd(execute=True)
    elif cmd == "traceme":
        traceme()
    elif cmd == "attach":
        attach()
    else:
        sys.exit("unknown command " + cmd)

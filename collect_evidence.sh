#!/usr/bin/env bash
# =============================================================================
#  collect_evidence.sh -- snapshot what an engineer would look at after a run
# =============================================================================
#
#  Runs inside the guest as root, AFTER falco_probe.sh, whether Falco passed
#  or failed. Strictly read-only: it starts, stops and installs nothing.
#
#  Output: /tmp/km-evidence.tgz, a flat directory of text files. Every command
#  is written as a "$ command" header line followed by its raw output and an
#  "[exit N]" line, so a reader (human or model) can cite file + line number
#  and see what produced it.
#
#  Why a separate script and not more probe code: the probe MEASURES and its
#  JSON is the result; this RECORDS the context around that result. Keeping
#  them apart means a collection bug can never change a measurement.
#
#  Must run on everything in the matrix down to CentOS 7 (bash 4.2,
#  systemd 219), so nothing fancier than coreutils, awk and sed.
# =============================================================================

set -u
OUT=/tmp/km-evidence
MAX_BYTES=262144            # per file; a runaway journal must not fill the VM
rm -rf "$OUT" /tmp/km-evidence.tgz
mkdir -p "$OUT"

# cap FILE COMMAND... : append "$ COMMAND", its output, and its exit code.
cap() {
    local file="$OUT/$1"; shift
    {
        echo "\$ $*"
        timeout 30 bash -c "$*" 2>&1
        echo "[exit $?]"
        echo
    } >> "$file"
}

# --- the host the sensor ran on ----------------------------------------------
cap system.txt "cat /etc/os-release"
cap system.txt "uname -a"
cap system.txt "ldd --version | head -1"
cap system.txt "systemctl --version | head -2"
cap system.txt "cat /proc/cmdline"
cap system.txt "nproc; free -m"

# --- kernel capabilities a sensor depends on ----------------------------------
cap kernel.txt "ls -l /sys/kernel/btf/vmlinux"
cap kernel.txt "cat /sys/kernel/security/lsm"
cap kernel.txt "sysctl kernel.unprivileged_bpf_disabled net.core.bpf_jit_enable kernel.perf_event_paranoid"
cap kernel.txt "grep -E '^CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|HAVE_EBPF_JIT|BPF_EVENTS|KPROBES|TRACEPOINTS|FTRACE_SYSCALLS)=' /boot/config-\$(uname -r)"
cap kernel.txt "lsmod | grep -iE 'falco|scap' || echo 'no falco kernel module loaded'"
cap kernel.txt "ls /lib/modules/\$(uname -r)/build >/dev/null && echo headers present || echo headers missing"

# --- the package and how it was installed --------------------------------------
if command -v dpkg >/dev/null 2>&1; then
    cap package.txt "dpkg -s falco"
    cap package.txt "grep -i falco /var/log/dpkg.log | tail -n 60"
    cap package.txt "tail -n 120 /var/log/apt/term.log"
    cap scripts.txt "cat /var/lib/dpkg/info/falco.postinst"
    cap scripts.txt "cat /var/lib/dpkg/info/falco.prerm"
else
    cap package.txt "rpm -q falco"
    cap package.txt "tail -n 120 /var/log/dnf.log 2>/dev/null || tail -n 120 /var/log/yum.log"
    cap scripts.txt "rpm -q --scripts falco"
fi

# --- the sensor itself ---------------------------------------------------------
cap falco.txt "falco --version"
cap falco.txt "systemctl list-unit-files 'falco*'"
cap falco.txt "systemctl status 'falco*' --no-pager -l"
cap falco.txt "ls -l /usr/share/falco/plugins"
# The plugins#1500 lesson: an unresolved DT_NEEDED only shows up at dlopen,
# and `ldd` shows it statically.
cap falco.txt "for so in /usr/share/falco/plugins/*.so; do echo \"== \$so\"; ldd -r \"\$so\" 2>&1 | grep -E 'not found|undefined|libresolv|libc.so'; done"
cap falco.txt "grep -vE '^\s*(#|$)' /etc/falco/falco.yaml | head -n 80"
cap falco.txt "tail -n 15 /etc/falco/falco.yaml"
cap falco.txt "ls -l /etc/falco /etc/falco/rules.d /etc/falco/config.d"
cap falco.txt "cat /etc/falco/falco_rules.local.yaml /etc/falco/rules.d/*.yaml"
# systemctl cat prints each unit WITH its drop-ins, which is where a changed
# limit or ExecStart hides.
cap falco.txt "systemctl cat falco-modern-bpf.service falco-bpf.service falco-kmod.service"

cap journal.log "journalctl -u 'falco*' --no-pager -o short-iso -n 400"
cap dmesg.log "dmesg | tail -n 200"

for f in "$OUT"/*; do
    if [ "$(wc -c < "$f")" -gt "$MAX_BYTES" ]; then
        head -c "$MAX_BYTES" "$f" > "$f.cut" && mv "$f.cut" "$f"
        printf '\n[truncated at %s bytes]\n' "$MAX_BYTES" >> "$f"
    fi
done

tar -C /tmp -czf /tmp/km-evidence.tgz km-evidence
chmod 0644 /tmp/km-evidence.tgz
echo "/tmp/km-evidence.tgz"

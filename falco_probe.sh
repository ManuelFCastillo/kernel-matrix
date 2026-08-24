#!/usr/bin/env bash
# ============================================================================
#  falco_probe.sh -- install Falco on this host, then characterise it.
# ============================================================================
#
#  Runs INSIDE the guest VM. Emits a single JSON object on stdout describing
#  what actually happened. Everything else goes to stderr so the JSON stays
#  parseable.
#
#  WHY THIS SCRIPT EXISTS
#  ----------------------
#  Checking "did the sensor start" is a binary and not very interesting.
#  The interesting questions for an endpoint agent are all about WHICH path
#  it took and WHAT it cost:
#
#    * Which driver did it select?  Falco can run on modern eBPF (needs BTF
#      and a recent kernel), legacy eBPF, or a kernel module. Which one it
#      lands on is a direct function of kernel version, and the fallback is
#      silent. A matrix that only reports pass/fail hides this completely.
#
#    * How long did it take to become useful?  Boot-to-first-event is a real
#      customer-facing number.
#
#    * What does it cost at idle?  On a fleet of a hundred thousand hosts,
#      a percent of CPU is a budget line.
#
#    * Does it actually DETECT anything?  A sensor that starts but never
#      fires is worse than one that fails loudly.
#
#  Failures here are DATA, not errors. An old kernel that cannot load the
#  modern probe is exactly the finding a compatibility matrix exists to
#  surface, so this script records that and exits 0.
# ============================================================================

set -uo pipefail    # deliberately NOT -e: we want to record failures, not abort

say() { echo "[probe] $*" >&2; }

# --- results, filled in as we go -------------------------------------------
INSTALLED=false
STARTED=false
DRIVER="none"
FALCO_VERSION="unknown"
INSTALL_SECONDS=0
START_SECONDS=0
RSS_KB=0
CPU_PERCENT=0
DETECTED=false
DETECT_SECONDS=0
RULE_MATCHED=""
BPF_ERRORS=0
ERROR=""

emit_and_exit() {
    # One JSON object. Keep key names stable: the report and the metrics
    # exporter both depend on them.
    cat <<JSON
{
  "installed": $INSTALLED,
  "started": $STARTED,
  "driver": "$DRIVER",
  "falco_version": "$FALCO_VERSION",
  "install_seconds": $INSTALL_SECONDS,
  "start_seconds": $START_SECONDS,
  "rss_kb": $RSS_KB,
  "cpu_percent": $CPU_PERCENT,
  "detected": $DETECTED,
  "detect_seconds": $DETECT_SECONDS,
  "rule_matched": "$RULE_MATCHED",
  "bpf_load_errors": ${BPF_ERRORS:-0},
  "error": "$ERROR"
}
JSON
    exit 0
}

# ---------------------------------------------------------------------------
# 1. INSTALL
# ---------------------------------------------------------------------------
say "kernel: $(uname -r)"
install_start=$(date +%s)

if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive

    # Preseed the debconf answers so the package never prompts. Without this
    # the install hangs forever waiting for a driver choice that nobody is
    # there to give -- a classic unattended-install trap.
    echo "falco falco/dkms note" | debconf-set-selections 2>/dev/null
    echo "falco falco/driver_choice select Modern eBPF" | debconf-set-selections 2>/dev/null
    echo "falco falco/unified_deb_multi_install boolean true" | debconf-set-selections 2>/dev/null

    # Store the ASCII-armored key AS-IS rather than dearmoring it.
    #
    # Every guide online pipes the .asc through `gpg --dearmor`, which fails
    # outright on minimal images: Ubuntu's cloud image ships gnupg, Debian's
    # does not, so the same command works on one and dies with "gpg: command
    # not found" on the other.
    #
    # apt has accepted armored keys in signed-by since apt 1.4, so the
    # dearmor step is unnecessary and the dependency on gnupg disappears.
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
        -o /etc/apt/keyrings/falcosecurity.asc 2>/dev/null
    chmod 0644 /etc/apt/keyrings/falcosecurity.asc
    echo "deb [signed-by=/etc/apt/keyrings/falcosecurity.asc] https://download.falco.org/packages/deb stable main" \
        > /etc/apt/sources.list.d/falcosecurity.list

    apt-get update -qq >/dev/null 2>&1
    if APT_ERR=$(apt-get install -y -qq falco 2>&1); then
        INSTALLED=true
    else
        # Keep the actual failure. "apt install failed" told us nothing and
        # cost a debugging round-trip.
        ERROR=$(echo "$APT_ERR" | grep -iE "^E:|error|not found" | head -1 \
                | tr -d '"' | cut -c1-160)
        ERROR=${ERROR:-"apt install falco failed"}
    fi

elif command -v dnf >/dev/null 2>&1; then
    rpm --import https://falco.org/repo/falcosecurity-packages.asc >/dev/null 2>&1
    curl -fsSL -o /etc/yum.repos.d/falcosecurity.repo \
        https://falco.org/repo/falcosecurity-rpm.repo >/dev/null 2>&1
    if dnf install -y -q falco >/dev/null 2>&1; then
        INSTALLED=true
    else
        ERROR="dnf install falco failed"
    fi

elif command -v zypper >/dev/null 2>&1; then
    rpm --import https://falco.org/repo/falcosecurity-packages.asc >/dev/null 2>&1
    zypper --non-interactive addrepo https://falco.org/repo/falcosecurity-rpm.repo >/dev/null 2>&1
    if zypper --non-interactive install -y falco >/dev/null 2>&1; then
        INSTALLED=true
    else
        ERROR="zypper install falco failed"
    fi
else
    ERROR="no supported package manager found"
fi

INSTALL_SECONDS=$(( $(date +%s) - install_start ))
say "install: $INSTALLED (${INSTALL_SECONDS}s)"
[ "$INSTALLED" = "true" ] || emit_and_exit

FALCO_VERSION=$(falco --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
FALCO_VERSION=${FALCO_VERSION:-unknown}
say "version: $FALCO_VERSION"

# ---------------------------------------------------------------------------
# 2. START, and find out WHICH DRIVER it chose
# ---------------------------------------------------------------------------
# This is the heart of the probe. Falco has three engines:
#
#   modern_ebpf  CO-RE eBPF. Needs a recent kernel plus BTF. The good path.
#   ebpf         legacy eBPF probe, compiled or downloaded per kernel.
#   kmod         a kernel module. Oldest path, most invasive.
#
# Which one it lands on is decided at runtime based on what the kernel can
# support, and the fallback is silent. Recording it is the single most
# useful thing this whole lab does.
# ---------------------------------------------------------------------------
# Falco ships SEVERAL units and only one of them runs:
#
#   falco-modern-bpf.service   modern CO-RE eBPF
#   falco-bpf.service          legacy eBPF probe
#   falco.service              kernel module (or a dispatcher, version dependent)
#   falcoctl-artifact-*        NOT falco itself; the rule updater. Must be excluded.
#
# Guessing from which unit FILES exist is wrong, because several exist on
# every install. Ask systemd which one is actually ACTIVE.
start_ts=$(date +%s)

# Nudge whichever ones are installed; only the viable one will stay up.
for candidate in falco-modern-bpf.service falco-bpf.service falco.service; do
    systemctl list-unit-files "$candidate" >/dev/null 2>&1 && \
        systemctl enable --now "$candidate" >/dev/null 2>&1
done

UNIT=""
for _ in $(seq 1 30); do
    UNIT=$(systemctl list-units 'falco*' --state=active --plain --no-legend 2>/dev/null \
           | awk '{print $1}' | grep -v falcoctl | head -1)
    if [ -n "$UNIT" ]; then STARTED=true; break; fi
    sleep 1
done
UNIT=${UNIT:-falco.service}
START_SECONDS=$(( $(date +%s) - start_ts ))
say "started: $STARTED as $UNIT (${START_SECONDS}s)"

if [ "$STARTED" != "true" ]; then
    ERROR=$(systemctl status "$UNIT" 2>&1 | grep -iE 'error|failed' | head -1 | tr -d '"' | cut -c1-160)
    ERROR=${ERROR:-"$UNIT did not become active"}
    emit_and_exit
fi

# Falco announces its engine on one specific line, e.g.
#   "Opening 'syscall' source with modern BPF probe."
#   "Opening 'syscall' source with BPF probe."
#   "Opening 'syscall' source with Kernel module."
# Match that line rather than grepping loosely, since the word "bpf" appears
# all over the startup log regardless of which engine actually opened.
JOURNAL=$(journalctl -u "$UNIT" --no-pager -n 300 2>/dev/null)
ENGINE_LINE=$(echo "$JOURNAL" | grep -i "Opening .* source with" | tail -1)

if   echo "$ENGINE_LINE" | grep -qi 'modern BPF';    then DRIVER="modern_ebpf"
elif echo "$ENGINE_LINE" | grep -qi 'BPF probe';     then DRIVER="ebpf"
elif echo "$ENGINE_LINE" | grep -qi 'kernel module'; then DRIVER="kmod"
else
    case "$UNIT" in
        falco-modern-bpf.service) DRIVER="modern_ebpf" ;;
        falco-bpf.service)        DRIVER="ebpf" ;;
        falco.service)            DRIVER="kmod" ;;
        *)                        DRIVER="unknown" ;;
    esac
fi
say "unit: $UNIT"
say "driver: $DRIVER"

# Partial degradation is worth recording. Falco can open its engine and still
# fail to load individual BPF programs -- it keeps running with reduced
# visibility, which a binary started/not-started check would never surface.
BPF_ERRORS=$(echo "$JOURNAL" | grep -ciE "BPF program load failed|failed to load BPF skeleton" || true)
BPF_ERRORS=${BPF_ERRORS:-0}
[ "$BPF_ERRORS" -gt 0 ] && say "WARNING: $BPF_ERRORS bpf program load failure(s) -- degraded but running"

# ---------------------------------------------------------------------------
# 3. COST AT IDLE
# ---------------------------------------------------------------------------
# Settle before measuring. The first measurement attempt used 8 seconds and
# `ps %cpu`, which reported 21% -- but `ps %cpu` is the average over the
# process's ENTIRE lifetime, so a few seconds after start it is dominated by
# rule compilation and BPF loading. That is startup churn reported as though
# it were steady state.
#
# Fix: settle for 30s, then sample CPU over a measured interval using
# /proc/<pid>/stat, which gives a true instantaneous rate.
sleep 30
PID=$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null)
if [ -n "$PID" ] && [ "$PID" != "0" ] && [ -r "/proc/$PID/stat" ]; then
    RSS_KB=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')

    HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)
    read_jiffies() { awk '{print $14+$15}' "/proc/$1/stat" 2>/dev/null; }
    J1=$(read_jiffies "$PID"); sleep 10; J2=$(read_jiffies "$PID")
    if [ -n "$J1" ] && [ -n "$J2" ]; then
        CPU_PERCENT=$(awk -v a="$J1" -v b="$J2" -v hz="$HZ" \
            'BEGIN { printf "%.2f", ((b-a)/hz/10)*100 }')
    fi
fi
RSS_KB=${RSS_KB:-0}
CPU_PERCENT=${CPU_PERCENT:-0}
say "idle cost: ${RSS_KB}KB RSS, ${CPU_PERCENT}% CPU"

# ---------------------------------------------------------------------------
# 4. DOES IT ACTUALLY DETECT ANYTHING?
# ---------------------------------------------------------------------------
# Reading /etc/shadow trips a default Falco rule ("Read sensitive file
# untrusted"). It is harmless, deterministic, and requires no custom rules --
# which makes it a good synthetic event.
#
# A sensor that starts but never fires is worse than one that fails loudly,
# so this is the check that separates "running" from "working".
# ---------------------------------------------------------------------------
detect_start=$(date +%s)
cat /etc/shadow >/dev/null 2>&1

# The real alert looks like:
#   "01:48:18.176919716: Warning Sensitive file opened for reading by
#    non-trusted program | file=/etc/shadow ..."
# so match on the priority word plus the rule text, and read the journal of
# the unit that is ACTUALLY running -- reading the wrong unit's journal was
# the original bug here and produced a confident, wrong "not detecting".
for _ in $(seq 1 25); do
    HIT=$(journalctl -u "$UNIT" --since "-90s" --no-pager 2>/dev/null \
          | grep -iE "(Warning|Notice|Critical|Error) .*Sensitive file" | tail -1)
    if [ -n "$HIT" ]; then
        DETECTED=true
        # Pull just the rule name: between the priority word and the first pipe.
        RULE_MATCHED=$(echo "$HIT" \
            | sed -E 's/.*(Warning|Notice|Critical|Error) ([^|]+)\|.*/\2/' \
            | sed 's/[[:space:]]*$//' | tr -d '"' | cut -c1-90)
        RULE_MATCHED=${RULE_MATCHED:-"rule fired"}
        break
    fi
    cat /etc/shadow >/dev/null 2>&1   # retry the trigger; the probe may still be attaching
    sleep 2
done
DETECT_SECONDS=$(( $(date +%s) - detect_start ))
say "detected: $DETECTED (${DETECT_SECONDS}s)"

emit_and_exit

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

    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc 2>/dev/null \
        | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
        > /etc/apt/sources.list.d/falcosecurity.list

    apt-get update -qq >/dev/null 2>&1
    if apt-get install -y -qq falco >/dev/null 2>&1; then
        INSTALLED=true
    else
        ERROR="apt install falco failed"
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
systemctl list-unit-files 2>/dev/null | grep -q 'falco-modern-bpf' \
    && UNIT=falco-modern-bpf.service || UNIT=falco.service

start_ts=$(date +%s)
systemctl enable --now "$UNIT" >/dev/null 2>&1

for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$UNIT"; then STARTED=true; break; fi
    sleep 1
done
START_SECONDS=$(( $(date +%s) - start_ts ))
say "started: $STARTED as $UNIT (${START_SECONDS}s)"

if [ "$STARTED" != "true" ]; then
    ERROR=$(systemctl status "$UNIT" 2>&1 | grep -iE 'error|failed' | head -1 | tr -d '"' | cut -c1-160)
    ERROR=${ERROR:-"$UNIT did not become active"}
    emit_and_exit
fi

# Ask the journal what engine it reported opening.
JOURNAL=$(journalctl -u "$UNIT" --no-pager -n 200 2>/dev/null)
if   echo "$JOURNAL" | grep -qi 'modern bpf\|modern_ebpf\|modern-bpf'; then DRIVER="modern_ebpf"
elif echo "$JOURNAL" | grep -qi 'bpf probe\|ebpf'; then                    DRIVER="ebpf"
elif echo "$JOURNAL" | grep -qi 'kernel module\|kmod\|scap device'; then   DRIVER="kmod"
else
    # Fall back to inferring from the unit name.
    case "$UNIT" in
        falco-modern-bpf.service) DRIVER="modern_ebpf" ;;
        *) DRIVER="unknown" ;;
    esac
fi
say "driver: $DRIVER"

# ---------------------------------------------------------------------------
# 3. COST AT IDLE
# ---------------------------------------------------------------------------
# Let it settle before measuring, otherwise you capture startup churn rather
# than steady state.
sleep 8
PID=$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null)
if [ -n "$PID" ] && [ "$PID" != "0" ]; then
    RSS_KB=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
    CPU_PERCENT=$(ps -o %cpu= -p "$PID" 2>/dev/null | tr -d ' ')
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

for _ in $(seq 1 20); do
    HIT=$(journalctl -u "$UNIT" --since "-60s" --no-pager 2>/dev/null \
          | grep -iE 'sensitive file|Warning|Notice' | head -1)
    if [ -n "$HIT" ]; then
        DETECTED=true
        RULE_MATCHED=$(echo "$HIT" | sed 's/.*(\(.*\)).*/\1/' | tr -d '"' | cut -c1-90)
        RULE_MATCHED=${RULE_MATCHED:-"rule fired"}
        break
    fi
    sleep 1
done
DETECT_SECONDS=$(( $(date +%s) - detect_start ))
say "detected: $DETECTED (${DETECT_SECONDS}s)"

emit_and_exit

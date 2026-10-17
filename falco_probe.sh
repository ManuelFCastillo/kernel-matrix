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

# Anything that ends up inside a JSON string must survive json.loads().
# systemctl and journalctl output carry newlines, tabs and quotes, and dropping
# those straight into the payload produces "Invalid control character at line N"
# on the far side -- which silently destroyed two distros' results before this
# existed. Strip control characters, collapse whitespace, escape backslashes
# and quotes, then truncate (to $2 characters, default 200).
json_safe() {
    printf '%s' "$1" \
        | sed -E 's/\x1b\[[0-9;]*[a-zA-Z]//g' \
        | sed -E 's/\[[0-9;]+m//g' \
        | tr -d '\000-\037' \
        | sed 's/\\/\\\\/g; s/"/\\"/g' \
        | tr -s ' ' \
        | cut -c1-"${2:-200}"
}

# The last lines of a failed install, joined with " | " because json_safe
# strips newlines. ERROR keeps the one-line headline; this keeps the reason.
# "dpkg: error processing package falco (--configure)" alone said WHAT failed
# on ubuntu-18.04/20.04 for five nightlies and never WHY.
tail_detail() {
    printf '%s\n' "$1" | grep -v -e '^[[:space:]]*$' -e '^(Reading database' \
        | tail -n 20 \
        | awk 'BEGIN { ORS = " | " } { print }' | sed 's/ | $//'
}

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
PLUGIN_MODE="stock"     # stock | patched | workaround -- how the container
                        # plugin situation was handled on this host
ERROR=""
ERROR_DETAIL=""          # tail of the failing command, see tail_detail

# ---------------------------------------------------------------------------
# Package qualification mode (qualify.py). Set by the host, never by hand.
#
#   KM_PKG_URL        install THIS .deb/.rpm through the package manager
#                     instead of the repo's latest, so a release candidate
#                     can be tested before it reaches the stable repo
#   KM_BASE_PKG_URL   upgrade scenario: install this one first (N-1)
#   KM_DRIVER_CHOICE  passed to the maintainer scripts as FALCO_DRIVER_CHOICE;
#                     empty leaves it unset, which is what an upgrade sees
#
# Setting KM_PKG_URL makes the probe STRICT: it observes and never repairs.
# No unit-file patching, no enabling units by hand, no plugin workaround.
# Those rescues exist so the characterisation can measure drivers on hosts
# with known packaging bugs; a qualification run exists to find exactly
# those bugs, and one rescue would hide the thing it is looking for.
# ---------------------------------------------------------------------------
KM_PKG_URL=${KM_PKG_URL:-}
KM_BASE_PKG_URL=${KM_BASE_PKG_URL:-}
KM_DRIVER_CHOICE=${KM_DRIVER_CHOICE:-}
STRICT=false
[ -n "$KM_PKG_URL" ] && STRICT=true
PKG_LOG=/var/log/km-pkg-install.log     # every package-manager word, for evidence
PKG_EXIT=-1             # package manager exit code for the package under test
PKG_STATE=""            # dpkg Status, or "installed"/"absent" from rpm -q
PKG_VERSION=""
PKG_SHA256=""
SCRIPTLET_FAILED=false  # a maintainer script (postinst, %post) reported failure
BASE_EXIT=-1            # same three for the N-1 package in an upgrade
BASE_STATE=""
BASE_VERSION=""
KMOD_LOADED=false       # kernel-side driver evidence, independent of any log
SECURE_BOOT=false       # an unsigned dkms module cannot load under Secure Boot
BPF_PROG_FDS=0
ACTIVE_UNIT=""

emit_and_exit() {
    # One JSON object. Keep key names stable: the report and the metrics
    # exporter both depend on them.
    cat <<JSON
{
  "installed": $INSTALLED,
  "started": $STARTED,
  "driver": "$(json_safe "$DRIVER")",
  "falco_version": "$(json_safe "$FALCO_VERSION")",
  "install_seconds": $INSTALL_SECONDS,
  "start_seconds": $START_SECONDS,
  "rss_kb": $RSS_KB,
  "cpu_percent": $CPU_PERCENT,
  "detected": $DETECTED,
  "detect_seconds": $DETECT_SECONDS,
  "rule_matched": "$(json_safe "$RULE_MATCHED")",
  "bpf_load_errors": ${BPF_ERRORS:-0},
  "plugin_mode": "$(json_safe "$PLUGIN_MODE")",
  "strict": $STRICT,
  "pkg_exit": $PKG_EXIT,
  "pkg_state": "$(json_safe "$PKG_STATE")",
  "pkg_version": "$(json_safe "$PKG_VERSION")",
  "pkg_sha256": "$(json_safe "$PKG_SHA256")",
  "scriptlet_failed": $SCRIPTLET_FAILED,
  "base_exit": $BASE_EXIT,
  "base_state": "$(json_safe "$BASE_STATE")",
  "base_version": "$(json_safe "$BASE_VERSION")",
  "kmod_loaded": $KMOD_LOADED,
  "bpf_prog_fds": ${BPF_PROG_FDS:-0},
  "active_unit": "$(json_safe "$ACTIVE_UNIT")",
  "secure_boot": $SECURE_BOOT,
  "error": "$(json_safe "$ERROR")",
  "error_detail": "$(json_safe "$ERROR_DETAIL" 2000)"
}
JSON
    exit 0
}

# ---------------------------------------------------------------------------
# Strict package install (qualification mode only)
# ---------------------------------------------------------------------------
# pkg_scriptlet_failed LOG: did a maintainer script report failure? dpkg fails
# the whole command, but rpm and dnf only WARN and exit 0 ("Non-fatal POSTIN
# scriptlet failure"), so the exit code alone would call a broken %post a
# clean install.
pkg_scriptlet_failed() {
    grep -qiE -- "-(installation|removal) script.*returned error exit status|scriptlet failed|scriptlet failure|Error in [A-Z]+ scriptlet" "$1"
}

# pkg_query: "STATE|VERSION" for the installed falco package. dpkg reports a
# postinst that died as "install ok half-configured", which is the state
# falcosecurity/falco#3994 leaves behind.
pkg_query() {
    local out
    if command -v dpkg-query >/dev/null 2>&1; then
        out=$(dpkg-query -W -f='${Status}|${Version}' falco 2>/dev/null) || out="absent|"
    else
        out=$(rpm -q --qf 'installed|%{VERSION}-%{RELEASE}' falco 2>/dev/null) || out="absent|"
    fi
    printf '%s\n' "$out"
}

pkg_state_ok() {
    [ "$1" = "install ok installed" ] || [ "$1" = "installed" ]
}

# pkg_install FILE STEPLOG: install one local package file through the package
# manager, so its maintainer scripts run exactly as they would for a customer.
# Returns the package manager's exit code.
pkg_install() {
    local file=$1 steplog=$2 choice_env=""
    [ -n "$KM_DRIVER_CHOICE" ] && choice_env="FALCO_DRIVER_CHOICE=$KM_DRIVER_CHOICE"
    {
        echo "\$ install $(basename "$file") (FALCO_DRIVER_CHOICE=${KM_DRIVER_CHOICE:-<unset>})"
        if command -v apt-get >/dev/null 2>&1; then
            # confdef/confold answer conffile prompts the way an unattended
            # fleet upgrade does: keep the configuration already on the host.
            env $choice_env FALCO_FRONTEND=noninteractive DEBIAN_FRONTEND=noninteractive \
                apt-get install -y -o Dpkg::Options::=--force-confdef \
                -o Dpkg::Options::=--force-confold "$file"
        elif command -v dnf >/dev/null 2>&1; then
            env $choice_env FALCO_FRONTEND=noninteractive dnf install -y "$file"
        else
            env $choice_env FALCO_FRONTEND=noninteractive yum install -y "$file"
        fi
    } > "$steplog" 2>&1
    local rc=$?
    echo "[exit $rc]" >> "$steplog"
    return $rc
}

# pkg_qualify: the install step of a qualification run. Optionally installs
# the N-1 package first (upgrade scenario), then the package under test.
# A baseline that does not install cleanly sets BLOCKED: the upgrade was never
# attempted, which is not the same finding as an upgrade that failed.
BLOCKED=""
pkg_qualify() {
    local ext=deb dir=/var/tmp/km-pkg step=/var/tmp/km-pkg/step.log
    command -v apt-get >/dev/null 2>&1 || ext=rpm
    mkdir -p "$dir"
    : > "$PKG_LOG"
    if [ -n "$KM_BASE_PKG_URL" ]; then
        if ! curl -fsSL --retry 3 -o "$dir/base.$ext" "$KM_BASE_PKG_URL" >> "$PKG_LOG" 2>&1; then
            ERROR="could not download baseline package $KM_BASE_PKG_URL"; BLOCKED=1; return
        fi
        pkg_install "$dir/base.$ext" "$step"
        BASE_EXIT=$?
        cat "$step" >> "$PKG_LOG"
        IFS='|' read -r BASE_STATE BASE_VERSION <<EOF
$(pkg_query)
EOF
        say "baseline install: exit $BASE_EXIT, ${BASE_STATE:-absent} ${BASE_VERSION}"
        if [ "$BASE_EXIT" -ne 0 ] || pkg_scriptlet_failed "$step" || ! pkg_state_ok "$BASE_STATE"; then
            ERROR="baseline (N-1) install did not complete: exit $BASE_EXIT, ${BASE_STATE:-absent}"
            ERROR_DETAIL=$(tail_detail "$(cat "$step")")
            BLOCKED=1
            return
        fi
    fi
    if ! curl -fsSL --retry 3 -o "$dir/target.$ext" "$KM_PKG_URL" >> "$PKG_LOG" 2>&1; then
        ERROR="could not download $KM_PKG_URL"; return
    fi
    PKG_SHA256=$(sha256sum "$dir/target.$ext" | cut -d' ' -f1)
    pkg_install "$dir/target.$ext" "$step"
    PKG_EXIT=$?
    cat "$step" >> "$PKG_LOG"
    pkg_scriptlet_failed "$step" && SCRIPTLET_FAILED=true
    IFS='|' read -r PKG_STATE PKG_VERSION <<EOF
$(pkg_query)
EOF
    say "package install: exit $PKG_EXIT, ${PKG_STATE:-absent} ${PKG_VERSION}, scriptlet_failed=$SCRIPTLET_FAILED"
    if [ "$PKG_EXIT" -eq 0 ] && [ "$SCRIPTLET_FAILED" = false ] && pkg_state_ok "$PKG_STATE"; then
        INSTALLED=true
    else
        ERROR=$(grep -iE "^E:|error|scriptlet" "$step" | head -1 | tr -d '"' | cut -c1-160)
        ERROR=${ERROR:-"package install did not complete: exit $PKG_EXIT, ${PKG_STATE:-absent}"}
        ERROR_DETAIL=$(tail_detail "$(cat "$step")")
    fi
}

# driver_evidence PID: is a driver actually in the kernel? Read from the
# kernel, not from a log line: the falco module in /sys/module, or BPF
# programs held open by the running sensor.
driver_evidence() {
    [ -d /sys/module/falco ] && KMOD_LOADED=true
    if [ -n "${1:-}" ] && [ "$1" != "0" ] && [ -d "/proc/$1/fd" ]; then
        BPF_PROG_FDS=$(ls -l "/proc/$1/fd" 2>/dev/null | grep -c 'anon_inode:bpf-prog')
    fi
    BPF_PROG_FDS=${BPF_PROG_FDS:-0}
}

# ---------------------------------------------------------------------------
# 1. INSTALL
# ---------------------------------------------------------------------------
say "kernel: $(uname -r)"
# The last byte of the SecureBoot EFI variable is 1 when it is enforced.
SB_VAR=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)
if [ -n "$SB_VAR" ] && [ "$(od -An -t u1 "$SB_VAR" 2>/dev/null | awk '{print $NF}')" = "1" ]; then
    SECURE_BOOT=true
    say "secure boot: enforced"
fi
install_start=$(date +%s)

# ---------------------------------------------------------------------------
# Build prerequisites for the FALLBACK drivers.
#
# On a recent kernel Falco loads a prebuilt CO-RE eBPF probe and needs nothing
# else. On an older one it has to fall back to the legacy eBPF probe or to a
# kernel module, and BOTH may need compiling against the running kernel --
# which needs dkms, make, and the matching kernel headers.
#
# Minimal cloud images ship none of those. Without this step the old distros
# fail with "dkms not found", which looks like a Falco incompatibility and is
# really a missing toolchain. That is a false negative, and a matrix that
# produces false negatives is worse than no matrix: it tells you a platform is
# unsupported when it is merely unprepared.
# ---------------------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    say "installing build prerequisites for fallback drivers"
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq dkms make gcc "linux-headers-$(uname -r)" >/dev/null 2>&1 \
        || say "WARNING: could not install headers/dkms; kmod fallback will be unavailable"


    # Strict mode installs a package FILE (pkg_qualify) and must not see the
    # Falco repo at all: given a local .deb whose version the repo also
    # carries, apt downloads the repo's copy instead, and the run would test
    # whatever the repo serves rather than the file it named.
    if [ "$STRICT" != true ]; then
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
    fi
    if [ "$STRICT" = true ]; then
        pkg_qualify
    elif APT_ERR=$(apt-get install -y -qq falco 2>&1); then
        INSTALLED=true
    else
        # Keep the actual failure. "apt install failed" told us nothing and
        # cost a debugging round-trip.
        ERROR=$(echo "$APT_ERR" | grep -iE "^E:|error|not found" | head -1 \
                | tr -d '"' | cut -c1-160)
        ERROR=${ERROR:-"apt install falco failed"}
        ERROR_DETAIL=$(tail_detail "$APT_ERR")
    fi

elif command -v yum >/dev/null 2>&1 && ! command -v dnf >/dev/null 2>&1; then
    # CentOS 7 and friends. Note this branch must come BEFORE the dnf one and
    # exclude dnf explicitly, because RHEL 8+ ships a `yum` that is a symlink
    # to dnf -- testing for yum first would misroute modern systems here.
    #
    # CentOS 7 went EOL in June 2024 and its mirrors moved to vault.centos.org,
    # so a plain `yum install` fails on mirror resolution before it ever gets
    # to Falco. Repoint at the vault first.
    if grep -qi "centos.*7" /etc/os-release 2>/dev/null; then
        sed -i -e 's/^mirrorlist/#mirrorlist/' \
               -e 's|^#\?baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' \
               /etc/yum.repos.d/CentOS-*.repo 2>/dev/null
    fi
    say "installing build prerequisites for fallback drivers"
    # dkms is not in the EL7 base repos -- it lives in EPEL. Without this the
    # prereq install half-fails and the kmod can never be built.
    yum install -y -q epel-release >/dev/null 2>&1
    yum install -y -q dkms make gcc "kernel-devel-$(uname -r)" >/dev/null 2>&1 \
        || say "WARNING: could not install headers/dkms"
    if [ "$STRICT" != true ]; then     # strict: the file, never the repo (see apt)
        rpm --import https://falco.org/repo/falcosecurity-packages.asc >/dev/null 2>&1
        curl -fsSL -o /etc/yum.repos.d/falcosecurity.repo \
            https://falco.org/repo/falcosecurity-rpm.repo >/dev/null 2>&1
    fi
    # No 0.40.0 fallback in strict mode: "cannot install here" is the finding.
    if [ "$STRICT" = true ]; then
        pkg_qualify
    elif YUM_ERR=$(yum install -y -q falco 2>&1); then
        INSTALLED=true
    elif echo "$YUM_ERR" | grep -q "GLIBC"; then
        # Falco 0.41.0+ links against GLIBC_2.28; EL7 ships 2.17. The repo
        # keeps every old release, and 0.40.0 is the newest that still links
        # against old glibc -- found by walking versions down until the
        # depsolve stopped demanding GLIBC_2.28. Pinning it turns this row
        # from "install failed" into the actually useful finding: the last
        # known good sensor version for this platform. falco_version in the
        # JSON will read 0.40.0, which is the matrix telling that story.
        say "latest falco needs GLIBC_2.28; falling back to 0.40.0 (last EL7-compatible)"
        yum install -y -q falco-0.40.0-1 >/dev/null 2>&1
        # 0.40's %post scriptlet throws a harmless no-job-control warning on
        # EL7 that can fail the transaction's exit code, so trust rpm -q
        # rather than yum's return status.
        if rpm -q falco >/dev/null 2>&1; then
            INSTALLED=true
        else
            ERROR="falco 0.40.0 fallback install failed"
        fi
    else
        ERROR=$(echo "$YUM_ERR" | grep -iE "error|cannot|failed|No package" | head -1)
        ERROR=${ERROR:-"yum install falco failed"}
        ERROR_DETAIL=$(tail_detail "$YUM_ERR")
    fi

elif command -v dnf >/dev/null 2>&1; then
    say "installing build prerequisites for fallback drivers"
    dnf install -y -q dkms make gcc "kernel-devel-$(uname -r)" >/dev/null 2>&1 \
        || say "WARNING: could not install headers/dkms"
    if [ "$STRICT" != true ]; then     # strict: the file, never the repo (see apt)
        rpm --import https://falco.org/repo/falcosecurity-packages.asc >/dev/null 2>&1
        curl -fsSL -o /etc/yum.repos.d/falcosecurity.repo \
            https://falco.org/repo/falcosecurity-rpm.repo >/dev/null 2>&1
    fi
    if [ "$STRICT" = true ]; then
        pkg_qualify
    elif DNF_ERR=$(dnf install -y -q falco 2>&1); then
        INSTALLED=true
    else
        ERROR=$(echo "$DNF_ERR" | grep -iE "error|cannot|conflict|nothing provides" | head -1)
        ERROR=${ERROR:-"dnf install falco failed"}
        ERROR_DETAIL=$(tail_detail "$DNF_ERR")
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
if [ "$INSTALLED" != "true" ]; then
    # Strict mode keeps observing while the binary is on disk: a package left
    # half-configured may still have started a service, or failed to, and
    # which of those happened is part of the finding.
    if [ "$STRICT" != true ] || [ -n "$BLOCKED" ] || ! command -v falco >/dev/null 2>&1; then
        emit_and_exit
    fi
fi

FALCO_VERSION=$(falco --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
FALCO_VERSION=${FALCO_VERSION:-unknown}
say "version: $FALCO_VERSION"

# ---------------------------------------------------------------------------
# The container plugin situation, in three modes.
#
# Falco's bundled container plugin fails to dlopen on glibc < 2.34 (missing
# -lresolv at link time -> no DT_NEEDED for libresolv.so.2; upstream:
# falcosecurity/plugins#1500, fix PR #1501). Since the default ruleset
# requires the plugin, stock Falco cannot start at all on those hosts.
#
#   stock       try the shipped package exactly as a customer gets it.
#               ALWAYS attempted first: the probe must measure reality, and
#               the day upstream ships the fix, rows flip to stock on their
#               own -- which is precisely the event the matrix should catch.
#   patched     /tmp/libcontainer-override.so was provided (a locally built
#               plugin with the fix): install it over the shipped one, then
#               proceed exactly as stock. Used to preview the fixed world.
#   workaround  the stock attempt failed WITH the known symbol error:
#               disable the plugin and swap in a self-contained ruleset so
#               the rest of the characterisation can still run. Recorded in
#               the JSON so the dashboard shows which rows needed it.
# ---------------------------------------------------------------------------
# Replace, never introduce: only install the override where a shipped
# libcontainer.so already exists. Falco 0.40 (the EL7 fallback) predates the
# plugin entirely -- copying one in would label the row "patched" for a
# binary nothing ever loads.
if [ -f /tmp/libcontainer-override.so ] && [ -f /usr/share/falco/plugins/libcontainer.so ]; then
    cp /tmp/libcontainer-override.so /usr/share/falco/plugins/libcontainer.so
    PLUGIN_MODE="patched"
    say "installed override container plugin (patched build)"
fi

apply_plugin_workaround() {
    # The default falco_rules.yaml doesn't just gate on the plugin at the top
    # of the file -- rule conditions reference container.* fields through
    # shared macros, so with the plugin disabled, rule compilation fails
    # outright ("nonexistent field container.id"). Replace the ruleset with
    # one self-contained rule; the probe only needs a /etc/shadow read to fire.
    rm -f /etc/falco/config.d/falco.container_plugin.yaml
    cat > /etc/falco/probe_rules.yaml <<'RULES'
- rule: Sensitive File Read Probe
  desc: Detect a read of /etc/shadow (synthetic trigger for kernel-matrix characterisation)
  condition: (evt.type in (open, openat, openat2)) and fd.name=/etc/shadow
  output: "Sensitive file opened for reading by non-trusted program (user=%user.name command=%proc.cmdline file=%fd.name)"
  priority: WARNING
  tags: [filesystem, probe]
RULES
    # sed, not python3/perl: minimal cloud images can't be trusted to have
    # either interpreter (Rocky ships no perl), but GNU sed is base everywhere.
    sed -i '/^rules_files:/,/^$/c\
rules_files:\
  - /etc/falco/probe_rules.yaml
' /etc/falco/falco.yaml
    PLUGIN_MODE="workaround"
    say "applied plugin workaround (disabled container plugin, self-contained ruleset)"
}

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
#   falco-modern-bpf.service    modern CO-RE eBPF
#   falco-bpf.service           legacy eBPF probe
#   falco-kmod.service          kernel module (0.38+ name; falco.service is legacy)
#   falco-kmod-inject.service   oneshot HELPER that insmods the module. Shows
#                               "active (exited)" forever, sorts BEFORE
#                               falco-kmod alphabetically, and reading its
#                               journal instead of the real unit's produced a
#                               confident driver=unknown/rss=0/detected=false
#                               row on ubuntu-20.04. Filter by sub-state
#                               "running", not just "active", to skip it.
#   falcoctl-artifact-*         NOT falco itself; the rule updater. Excluded.
#
# Guessing from which unit FILES exist is wrong, because several exist on
# every install. Ask systemd which one is actually ACTIVE -- and running.
# Deliberate breakage for labelled triage cases (faults.yaml, provision.py
# --fault). Applied here, after install and before start, and SILENTLY: the
# probe log and JSON are evidence a model reads, and a line saying what was
# broken would hand it the answer. The snippet is deleted once sourced.
FAULT_ACTIVE=""
if [ -f /tmp/km-fault.sh ]; then
    # Debian's postinst has already STARTED falco-modern-bpf by now. A fault
    # aimed at startup (exec bit, config, limits) applied under a running
    # process changes nothing, and try_start below would just find it
    # running: the first fault runs all came back "ineffective" for exactly
    # this reason. Stop everything so the fault meets a real start.
    systemctl stop 'falco*' >/dev/null 2>&1
    systemctl reset-failed 'falco*' >/dev/null 2>&1
    # shellcheck disable=SC1091
    . /tmp/km-fault.sh >/dev/null 2>&1
    rm -f /tmp/km-fault.sh
    FAULT_ACTIVE=1
fi

start_ts=$(date +%s)

# Falco's shipped unit files say "ExecReload=kill -1 $MAINPID" -- a
# non-absolute path. systemd 239+ resolves that from $PATH; systemd 237
# (ubuntu 18.04) refuses to LOAD the entire unit over it ("Exec format
# error"), which took out all three engines at once and looked exactly like
# "this kernel is unsupported". A drop-in cannot rescue it because the base
# file still fails to parse, so patch the unit files themselves. Normalising
# to /bin/kill is a no-op on modern systemd and a full fix on old.
# Not in strict mode: there the shipped unit files are what is under test.
if [ "$STRICT" != true ]; then
    sed -i 's|^ExecReload=kill|ExecReload=/bin/kill|' \
        /usr/lib/systemd/system/falco*.service \
        /lib/systemd/system/falco*.service 2>/dev/null
    systemctl daemon-reload 2>/dev/null
fi

try_start() {
    # Nudge whichever ones are installed; only the viable one will stay up.
    # Strict mode only watches: whether the maintainer scripts enabled and
    # started the right unit is the thing being qualified.
    if [ "$STRICT" != true ]; then
        for candidate in falco-modern-bpf.service falco-bpf.service falco-kmod.service falco.service; do
            systemctl list-unit-files "$candidate" >/dev/null 2>&1 && \
                systemctl enable --now "$candidate" >/dev/null 2>&1
        done
    fi

    UNIT=""
    STABLE=0
    for _ in $(seq 1 30); do
        # Columns are UNIT LOAD ACTIVE SUB DESC; $4=="running" excludes oneshot
        # helpers stuck in "exited" as well as crash-loopers mid-restart.
        CANDIDATE=$(systemctl list-units 'falco*' --state=active --plain --no-legend 2>/dev/null \
               | awk '$4 == "running" {print $1}' | grep -v falcoctl | head -1)
        if [ -n "$CANDIDATE" ]; then
            # A unit can show "active (running)" for a fraction of a second in
            # the middle of a crash loop -- systemd restarts it, it dies again
            # a moment later, and a single snapshot cannot tell the two apart.
            # Require three consecutive 1s samples before trusting it; a
            # genuine crash loop never survives that window, a real start does.
            UNIT="$CANDIDATE"
            STABLE=$((STABLE + 1))
            if [ "$STABLE" -ge 3 ]; then STARTED=true; return 0; fi
        else
            STABLE=0
        fi
        sleep 1
    done
    return 1
}

try_start || true

# Stock (or patched) didn't come up. If the journals show the known
# container-plugin symbol error, this is upstream bug plugins#1500, not a
# kernel incompatibility: fall back to the workaround so the rest of the
# characterisation still happens, and record that we did. Any OTHER failure
# is left alone -- it is a finding, and papering over it here would put the
# blind spot right back.
# Never under an injected fault: the workaround would "fix" a deliberately
# broken plugin and report the row healthy.
if [ "$STARTED" != "true" ] && [ "$PLUGIN_MODE" != "workaround" ] && [ -z "$FAULT_ACTIVE" ] \
   && [ "$STRICT" != true ]; then
    # Query the engine units explicitly and deep: a bare 'falco*' glob also
    # matches falcoctl-artifact-follow, whose download chatter can push the
    # actual load error out of a shallow tail window -- which made this
    # fallback fire on rocky-8 but silently miss on both ubuntus and debian.
    # Match ANY libcontainer load failure, not one specific symbol: the same
    # plugin fails with "undefined symbol: __res_search" on glibc 2.28-2.33
    # (missing -lresolv, plugins#1500) and with "version GLIBC_2.28 not
    # found" on glibc < 2.28 (the plugin's build-baseline floor; Ubuntu
    # 18.04, Amazon Linux 2). Both are the plugin blocking Falco, both get
    # the same workaround, and grepping for just one of them cost a rerun.
    if journalctl -u falco-modern-bpf -u falco-bpf -u falco-kmod -u falco.service \
                  --no-pager -n 600 2>/dev/null | grep -q "cannot load plugin.*libcontainer"; then
        say "stock start failed with the known plugin symbol error; retrying with workaround"
        systemctl stop 'falco-modern-bpf' 'falco-bpf' 'falco-kmod' 'falco' >/dev/null 2>&1
        systemctl reset-failed 'falco*' >/dev/null 2>&1
        apply_plugin_workaround
        try_start || true
    fi
fi

UNIT=${UNIT:-falco.service}
START_SECONDS=$(( $(date +%s) - start_ts ))
say "started: $STARTED as $UNIT (${START_SECONDS}s, plugin: $PLUGIN_MODE)"

if [ "$STARTED" != "true" ]; then
    # Nothing came up. Report WHICH engines were attempted and how each one
    # failed, rather than a bare "none" -- on an old kernel the whole point is
    # knowing that modern eBPF was tried and rejected, and that the fallbacks
    # were tried too. "none" alone cannot distinguish "never attempted" from
    # "attempted and impossible", and only one of those is a finding.
    ATTEMPTS=""
    for candidate in falco-modern-bpf falco-bpf falco-kmod falco; do
        systemctl list-unit-files "${candidate}.service" >/dev/null 2>&1 || continue
        why=$(journalctl -u "$candidate" --no-pager -n 60 2>/dev/null \
              | grep -iE "error|failed|unable|cannot|not supported|no such" \
              | grep -viE "INFO |Skipping|Deactivated|Stopped" \
              | tail -1 | sed 's/^.*]: //')
        ATTEMPTS="${ATTEMPTS}${candidate}: ${why:-did not start}; "
    done
    # Keep a package-install error as the headline: it is the cause.
    [ "$STRICT" = true ] && [ -n "$ERROR" ] || ERROR="${ATTEMPTS:-no falco unit became active}"
    DRIVER="none"
    driver_evidence ""
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
        falco-kmod.service)       DRIVER="kmod" ;;
        falco.service)            DRIVER="kmod" ;;
        *)                        DRIVER="unknown" ;;
    esac
fi
ACTIVE_UNIT="$UNIT"
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
driver_evidence "$PID"
say "driver evidence: kmod_loaded=$KMOD_LOADED bpf_prog_fds=$BPF_PROG_FDS"
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

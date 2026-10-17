// ===========================================================================
//  Jenkinsfile -- kernel compatibility matrix
// ===========================================================================
//
//  READ THIS FIRST IF IT HAS BEEN A WHILE
//  --------------------------------------
//  Modern Jenkins pipelines are DECLARATIVE: one file, checked into the repo,
//  describing the whole build. This replaced the old freestyle jobs you
//  configured by clicking around in the web UI. The web UI is now mostly for
//  watching builds and debugging them, not for defining them.
//
//  The shape is always the same:
//
//      pipeline {
//          agent      -- WHERE it runs
//          options    -- global behaviour (timeouts, log rotation)
//          parameters -- inputs a human can set when clicking Build
//          triggers   -- what starts it automatically
//          environment-- variables available everywhere
//          stages {
//              stage('Name') { steps { ...do things... } }
//          }
//          post       -- what always happens at the end, pass or fail
//      }
//
//  Two words that trip people up:
//    AGENT     the machine (or container, or k8s pod) that runs the work.
//              Modern setups spin these up per build instead of keeping pets.
//    STAGE     a named phase. Stages are what you see as boxes in the UI, and
//              what per-stage timing and logs attach to.
//
//  THE DESIGN OF THIS PARTICULAR PIPELINE
//  --------------------------------------
//  Real VMs cost real time and real money. So the pipeline is TIERED:
//
//     Lint          seconds, free       -> runs on every build, gates the rest
//     Fast matrix   ~3 min, 3 VMs       -> runs on every build
//     All tiers     11 VMs + Falco      -> nightly, or when asked
//
//  That ordering is the whole point. You do not spend eight minutes of VM time
//  discovering something a two-second syntax check would have caught.
// ===========================================================================

// ---------------------------------------------------------------------------
// Nightly override
//
// A cron-triggered build gets the parameter DEFAULTS, and the defaults are
// the cheap ones (fast tier, no Falco). Left alone, that meant the nightly
// build booted three modern VMs and never installed Falco at all: green every
// night while testing none of the thing this project exists to test.
//
// So a timer-triggered build ignores the parameters and runs everything with
// Falco on. A human clicking "Build with Parameters" still gets exactly what
// they picked.
// ---------------------------------------------------------------------------
def isNightly() {
    return !currentBuild.getBuildCauses('hudson.triggers.TimerTrigger$TimerTriggerCause').isEmpty()
}

def effectiveTier() {
    return isNightly() ? 'all' : params.TIER
}

def falcoEnabled() {
    return isNightly() || params.RUN_FALCO
}

pipeline {

    // -----------------------------------------------------------------------
    // agent: where this runs.
    //
    // 'any' means any available executor. For this project that is hardac2
    // itself, because the VMs need /dev/kvm and that lives on the metal.
    //
    // If you later add build agents, give this box a label like 'kvm' and
    // change this to:   agent { label 'kvm' }
    // so that only machines that can actually boot VMs pick up this job.
    // -----------------------------------------------------------------------
    agent any

    // -----------------------------------------------------------------------
    // options: global behaviour for the whole pipeline
    // -----------------------------------------------------------------------
    options {
        // A hung VM must never block an executor forever. Without this, one
        // stuck boot ties up the machine until somebody notices.
        // Sized for the nightly: 11 VMs in parallel with Falco, where the
        // slowest (centos-7) needs ~7 min to boot and ~5 more for Falco.
        timeout(time: 60, unit: 'MINUTES')

        // Keep 30 builds of history. Test result trends need history to be
        // useful, but unbounded history eats the Jenkins home directory.
        buildDiscarder(logRotator(numToKeepStr: '30'))

        // NOTE: timestamps() was removed -- the Timestamper plugin is not
        // available in this update center. provision.py prints its own
        // timestamps on every line, so little is lost.

        // Do not run two of these at once. They would fight over libvirt
        // domain names, disk space, and RAM.
        disableConcurrentBuilds()
    }

    // -----------------------------------------------------------------------
    // parameters: inputs a human can set from "Build with Parameters"
    //
    // The first build after adding these will use the defaults and IGNORE the
    // UI, because Jenkins only learns the parameters by running the file once.
    // This confuses everyone exactly once.
    // -----------------------------------------------------------------------
    parameters {
        choice(
            name: 'TIER',
            choices: ['fast', 'full', 'legacy', 'all'],
            description: 'fast = 3 modern distros. full = adds RHEL family + Fedora. legacy = the old kernels where the interesting failures live (3.10 to 5.10). all = everything, 11 distros.'
        )
        booleanParam(
            name: 'RUN_FALCO',
            defaultValue: false,
            description: 'Install Falco on each VM and characterise it. Adds ~5 min per distro, and is where the interesting data comes from.'
        )
        booleanParam(
            name: 'KEEP_VMS',
            defaultValue: false,
            description: 'Leave VMs running after the build so you can SSH in and poke around. Remember to clean them up.'
        )
    }

    // -----------------------------------------------------------------------
    // triggers: what starts this build without a human
    // -----------------------------------------------------------------------
    triggers {
        // Nightly at 02:00. The H is important: it tells Jenkins to pick a
        // consistent-but-arbitrary minute, so that a hundred jobs all set to
        // "2am" do not stampede at exactly 02:00:00.
        cron('H 2 * * *')
    }

    // -----------------------------------------------------------------------
    // environment: available to every stage
    // -----------------------------------------------------------------------
    environment {
        // Where base images, overlays and seed ISOs live. Point this at a
        // bigger disk by changing one line here.
        KMATRIX_ROOT = "${env.HOME}/kernel-matrix-lab"

        // ------------------------------------------------------------------
        // THE ONE THAT WILL BITE YOU IF YOU OMIT IT
        //
        // virsh has two worlds: qemu:///system (machine-wide, has the default
        // network, what you want) and qemu:///session (per-user, no network,
        // useless here).
        //
        // An interactive shell often lands on 'system'. A NON-interactive one
        // -- ssh, cron, and Jenkins -- silently falls back to 'session'. So a
        // command that works when you type it by hand fails inside CI with an
        // error that blames the network instead of the connection.
        //
        // Pin it. Never inherit it.
        // ------------------------------------------------------------------
        LIBVIRT_DEFAULT_URI = 'qemu:///system'

        // Where the metrics go. Prometheus scrapes this gateway rather than
        // scraping us, because a batch job has already exited by the time a
        // scraper comes looking.
        PUSHGATEWAY = 'http://localhost:9092'

        // Where Publish copies the report for the km-report container to
        // serve. observability/docker-compose.yml mounts this path.
        KM_PUBLISH_DIR = "${env.HOME}/km-published"

        // Never buffer python output. Without this, Jenkins shows you nothing
        // for eight minutes and then dumps everything at once, which makes a
        // running build indistinguishable from a hung one.
        PYTHONUNBUFFERED = '1'
    }

    stages {

        // ===================================================================
        // STAGE 1 -- Preflight
        //
        // Fail fast and fail clearly. If KVM is missing or libvirt is not
        // reachable, say so in five seconds rather than failing mysteriously
        // three minutes into a boot.
        // ===================================================================
        stage('Preflight') {
            steps {
                echo "tier=${effectiveTier()} falco=${falcoEnabled()} nightly=${isNightly()}"

                // The workspace persists between builds. Without this, a
                // distro skipped this build would still have last build's
                // JSON sitting in results/ and get merged into tonight's
                // report as if it had run. results/runs/ is kept: it is the
                // history the report diffs against. Evidence bundles go
                // too, for the same reason: a stale bundle would describe a
                // VM that did not run tonight.
                sh 'mkdir -p results && rm -f results/*.xml results/*.result.json results/results.json results/report.html && rm -rf results/evidence'

                sh '''
                    set -eu

                    echo "--- host ---"
                    uname -a
                    echo

                    echo "--- virtualization ---"
                    test -e /dev/kvm && echo "/dev/kvm present" || {
                        echo "ERROR: /dev/kvm missing. KVM acceleration unavailable."
                        exit 1
                    }

                    echo "--- libvirt reachable without sudo? ---"
                    virsh list --all >/dev/null 2>&1 || {
                        echo "ERROR: cannot talk to libvirt."
                        echo "Fix: sudo usermod -aG libvirt,kvm \\$USER  (then restart the agent)"
                        exit 1
                    }
                    virsh list --all
                    echo

                    echo "--- disk headroom ---"
                    df -h "${KMATRIX_ROOT%/*}" || df -h "$HOME"
                    echo

                    echo "--- leftover VMs from previous runs ---"
                    # A previous build that died hard can leave domains behind.
                    # Reap only those whose owning process is gone: names are
                    # km-<distro>-<pid>-<suffix>, and the qualify job and
                    # interactive provision.py/qualify.py runs share this host.
                    for dom in $(virsh list --all --name | grep "^km-" || true); do
                        pid=$(echo "$dom" | awk -F- '{print $(NF-1)}')
                        [ -d "/proc/$pid" ] && continue
                        echo "  reaping orphaned domain: $dom (pid $pid is gone)"
                        virsh destroy "$dom"  2>/dev/null || true
                        virsh undefine "$dom" --nvram 2>/dev/null || true
                        rm -f "${KMATRIX_ROOT}/overlays/${dom}.qcow2" "${KMATRIX_ROOT}/seeds/${dom}"-*
                    done
                    echo "preflight OK"
                '''
            }
        }

        // ===================================================================
        // STAGE 2 -- Lint
        //
        // The cheap gate. Seconds, no VMs, catches typos before we spend
        // minutes booting machines to discover them.
        // ===================================================================
        stage('Lint') {
            steps {
                sh '''
                    set -eu

                    echo "--- python syntax ---"
                    python3 -m py_compile provision.py
                    echo "provision.py compiles"

                    echo "--- matrix.yaml parses, and every field is present ---"
                    python3 - <<'EOF'
import sys, yaml
data = yaml.safe_load(open("matrix.yaml"))
required = {"name", "image_url", "expect_kernel"}
problems = []
for entry in data["distros"]:
    missing = required - set(entry) - set(data.get("defaults", {}))
    if missing:
        problems.append(f"{entry.get('name','<unnamed>')}: missing {sorted(missing)}")
if problems:
    print("MATRIX PROBLEMS:"); [print("  " + p) for p in problems]; sys.exit(1)
print(f"matrix OK: {len(data['distros'])} distros, {len(data['checks'])} checks")
EOF
                '''
            }
        }

        // ===================================================================
        // STAGE 2.5 -- Unit tests for the lab's own code
        //
        // The matrix tests kernels; nothing here tested the code that DECIDES
        // what those results mean. That gap shipped three confident-but-wrong
        // dashboards (a crash loop reported as started, a oneshot helper's
        // journal read as the sensor's, ANSI escapes corrupting JUnit XML).
        // These run in under a second, before any VM boots: wrong logic
        // should never get as far as spending two minutes of qemu time.
        // ===================================================================
        stage('Unit tests') {
            steps {
                sh '''
                    set -eu

                    # Provision the test dependency here rather than assuming
                    # the agent has it: Jenkins runs as its own user, so a
                    # pip --user install done by a human account is invisible
                    # to CI. A workspace venv with system site packages keeps
                    # PyYAML from the OS and adds pytest locally.
                    [ -d .venv ] || python3 -m venv --system-site-packages .venv
                    ./.venv/bin/python -m pip install -q --disable-pip-version-check pytest
                    ./.venv/bin/python -m pytest tests/ -q --junitxml=results/unit-tests.xml
                '''
            }
            post {
                always {
                    junit testResults: 'results/unit-tests.xml',
                          allowEmptyResults: true
                }
            }
        }

        // ===================================================================
        // STAGE 3 -- The matrix itself
        //
        // 'matrix' is declarative Jenkins' built-in fan-out. It generates one
        // parallel branch per axis value, so adding a distro to the axis adds
        // a column to the UI with no other change.
        //
        // Compare with the older way of doing this -- building a map of
        // closures and passing it to parallel() -- which works but is scripted
        // Groovy and much harder to read six months later.
        // ===================================================================
        stage('Kernel matrix') {
            matrix {
                axes {
                    axis {
                        name 'DISTRO'
                        // Every distro in the file. The when{} block below
                        // decides which actually run for this build's tier,
                        // so the UI still shows the skipped ones as skipped
                        // rather than hiding them.
                        values 'ubuntu-22.04', 'ubuntu-24.04', 'debian-12',
                               'rocky-9', 'almalinux-9', 'fedora-44',
                               'ubuntu-20.04', 'debian-11', 'rocky-8',
                               'ubuntu-18.04', 'centos-7'
                    }
                }

                // NOTE ON CONCURRENCY
                //
                // There is no built-in way to cap matrix parallelism in a
                // declarative pipeline; the usual answer is the Throttle
                // Concurrent Builds plugin, which is not installed here.
                // Three VMs at 2GB against 62GB of RAM is nowhere near a
                // limit, so this is fine as-is on this host.

                // ---------------------------------------------------------------
                // when{}: skip full-tier distros unless the user asked for them.
                //
                // A skipped stage still appears in the UI greyed out, which is
                // much better than silently not existing -- you can see at a
                // glance what did and did not run.
                // ---------------------------------------------------------------
                // Tier membership mirrored from matrix.yaml. Duplication is
                // unfortunate but declarative Jenkins cannot read the YAML to
                // build its axis, so the axis is static and this filters it.
                when {
                    anyOf {
                        expression { effectiveTier() == 'all' }
                        expression {
                            effectiveTier() == 'fast' &&
                            ['ubuntu-22.04', 'ubuntu-24.04', 'debian-12'].contains(env.DISTRO)
                        }
                        expression {
                            effectiveTier() == 'full' &&
                            ['ubuntu-22.04', 'ubuntu-24.04', 'debian-12',
                             'rocky-9', 'almalinux-9', 'fedora-44'].contains(env.DISTRO)
                        }
                        expression {
                            effectiveTier() == 'legacy' &&
                            ['ubuntu-20.04', 'debian-11', 'rocky-8',
                             'ubuntu-18.04', 'centos-7'].contains(env.DISTRO)
                        }
                    }
                }

                stages {
                    stage('Provision and verify') {
                        steps {
                            // Give each distro its own timeout. Without this a
                            // single wedged boot would eat the whole pipeline
                            // budget and starve the others. Falco adds ~5 min on
                            // top of a boot that takes up to 7 on centos-7.
                            //
                            // catchError: a failed distro marks its stage and
                            // the build red but lets the pipeline carry on to
                            // Publish. Without it, one 404'd image skipped
                            // Publish and the whole night's results were lost.
                            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                                timeout(time: falcoEnabled() ? 25 : 12, unit: 'MINUTES') {
                                    sh """
                                        set -eu
                                        python3 provision.py \\
                                            --distro '${DISTRO}' \\
                                            ${falcoEnabled() ? '--falco' : ''} \\
                                            ${params.KEEP_VMS ? '--keep' : ''}
                                    """
                                }
                            }
                        }
                        post {
                            // Runs whether the stage passed or failed. Results
                            // from a FAILING distro are the ones you most want
                            // to keep, so collect them unconditionally.
                            always {
                                junit(
                                    testResults: "results/${DISTRO}.xml",
                                    allowEmptyResults: true,
                                    // Do not mark the whole build UNSTABLE just
                                    // because one distro failed -- the junit
                                    // step already records it, and we want the
                                    // matrix view to show which one.
                                    skipMarkingBuildUnstable: false
                                )
                            }
                        }
                    }
                }
            }
        }

        // ===================================================================
        // STAGE 4 -- Publish
        //
        // Turn the raw results into things humans and dashboards consume.
        // Separate from the matrix on purpose: this must run even when some
        // distros failed, because a partial matrix is still worth reporting
        // on -- arguably MORE worth reporting on.
        // ===================================================================
        stage('Publish') {
            steps {
                sh '''
                    set -eu

                    # Merge the per-distro JSON that each matrix branch wrote.
                    # Matrix branches run in parallel and each writes its own
                    # results/<distro>.result.json, so the merge happens here rather
                    # than in any one branch. (Each branch used to write
                    # results.json directly; the last one to finish won, and
                    # the report and Grafana only ever saw one distro.)
                    python3 provision.py --merge-results
                    python3 report.py || echo "no results.json to render"

                    # Metrics are best-effort. A missing pushgateway must not
                    # fail a build whose actual job was testing kernels.
                    python3 push_metrics.py --gateway "${PUSHGATEWAY}" || true

                    # Hand the finished report to the km-report nginx container
                    # (http://hardac2:8087). The workspace is not a stable path
                    # to mount, so publish to a fixed directory Jenkins owns.
                    mkdir -p "${KM_PUBLISH_DIR}"
                    cp results/*.xml results/results.json "${KM_PUBLISH_DIR}/" 2>/dev/null || true
                    cp results/report.html "${KM_PUBLISH_DIR}/" 2>/dev/null || true
                '''
            }
            post {
                always {
                    // publishHTML would be nicer but needs the HTML Publisher
                    // plugin; archiving works everywhere and the report is
                    // deliberately self-contained so it opens fine from the
                    // artifact link.
                    archiveArtifacts artifacts: 'results/report.html, results/results.json',
                                     allowEmptyArchive: true
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // post: always runs, in a defined order, regardless of outcome
    //
    //   always   -- every time
    //   success  -- only when green
    //   unstable -- tests failed but the build itself did not error
    //   failure  -- the build errored
    //   cleanup  -- dead last, after all of the above
    // -----------------------------------------------------------------------
    post {
        always {
            // Keep the XML as build artifacts so you can diff results between
            // builds even after Jenkins ages out the console log.
            archiveArtifacts(
                artifacts: 'results/*.xml',
                allowEmptyArchive: true,
                fingerprint: true
            )
            // Evidence bundles (journal, package logs, install scripts,
            // kernel capabilities) for every distro that ran Falco. Archived
            // here, not in Publish, so a failed Publish cannot lose the
            // evidence for the failure. A few hundred KB per distro; the
            // 30-build logRotator bounds the total.
            archiveArtifacts(
                artifacts: 'results/evidence/**',
                allowEmptyArchive: true
            )
        }

        failure {
            echo """
            ============================================================
            BUILD FAILED

            Most common causes, in the order they actually happen:

              1. Agent cannot reach libvirt without sudo
                   sudo usermod -aG libvirt,kvm jenkins
                   sudo systemctl restart jenkins

              2. Out of disk. Base images are ~600MB each.
                   df -h \\$KMATRIX_ROOT

              3. A base image URL 404'd because the distro moved it.
                   Check the failing stage's log for the download step.

              4. VM booted but SSH never came up -- usually cloud-init
                   Re-run with KEEP_VMS to keep it alive, then:
                     virsh list
                     virsh console <name>
            ============================================================
            """.stripIndent()
        }

        cleanup {
            // Belt and braces. provision.py cleans up in its own finally block,
            // but if the process was killed outright (timeout, agent restart)
            // nothing in Python got the chance to run. Same rule as Preflight:
            // only domains whose process is gone, and only their own files.
            sh '''
                for dom in $(virsh list --all --name 2>/dev/null | grep "^km-" || true); do
                    pid=$(echo "$dom" | awk -F- '{print $(NF-1)}')
                    [ -d "/proc/$pid" ] && continue
                    echo "post-build cleanup: $dom"
                    virsh destroy "$dom"  2>/dev/null || true
                    virsh undefine "$dom" --nvram 2>/dev/null || true
                    rm -f "${KMATRIX_ROOT}/overlays/${dom}.qcow2" "${KMATRIX_ROOT}/seeds/${dom}"-*
                done
            '''
        }
    }
}

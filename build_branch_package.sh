#!/usr/bin/env bash
# ============================================================================
#  build_branch_package.sh -- a release's packages with a fix branch's scripts
# ============================================================================
#
#  To see a packaging fix on the qualification grid before it merges, we need
#  the .deb and .rpm that fix would ship. A full Falco build from the branch
#  would differ from the release in a hundred ways (version, toolchain, driver
#  build, bundled deps), so its grid would not say what the FIX changed.
#
#  For a fix that only touches the maintainer scripts this builds the exact
#  answer: the official BASE packages with the branch's diff applied to every
#  rendered maintainer script, and nothing else changed.
#
#     deb   control.tar is rebuilt; data.tar is copied byte for byte
#     rpm   rpmrebuild with the scriptlets patched; file digests compared
#           before and after (the official GPG signature is gone)
#
#  Every step is checked, and PROVENANCE.txt keeps the proof: input and output
#  sha256, the script diff per format, and the payload comparison.
#
#  USAGE
#     ./build_branch_package.sh BASE_VERSION LABEL FIX.patch
#     ./build_branch_package.sh 0.45.1-rc1 0.45.1-rc1+fix-postinst-printenv fix.patch
#
#  FIX.patch is `git diff` of scripts/packaging/functions.sh.in in a falco
#  checkout. Output: results/builds/<LABEL>/, which qualification.yaml's
#  builds: section points at.
# ============================================================================
set -euo pipefail

BASE=${1:?base version, e.g. 0.45.1-rc1}
LABEL=${2:?label, e.g. 0.45.1-rc1+fix-postinst-printenv}
PATCH=$(realpath "${3:?patch file}")
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/results/builds/$LABEL"
DOWNLOAD=${KM_DOWNLOAD:-https://download.falco.org/packages}
IMAGE=${KM_RPM_IMAGE:-fedora:44}

case "$BASE" in *-rc*|*+*) dev=-dev ;; *) dev= ;; esac
DEB_URL="$DOWNLOAD/deb$dev/stable/falco-$BASE-x86_64.deb"
RPM_URL="$DOWNLOAD/rpm$dev/falco-$BASE-x86_64.rpm"

rm -rf "$OUT"
mkdir -p "$OUT"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$PATCH" "$OUT/fix.patch"
cp "$HERE/apply_script_patch.py" "$work/"
cp "$PATCH" "$work/fix.patch"

echo "== download $BASE"
curl -fsSL --retry 3 -o "$work/base.deb" "$DEB_URL"
curl -fsSL --retry 3 -o "$work/base.rpm" "$RPM_URL"

# ---------------------------------------------------------------- deb ----
echo "== deb: patch the maintainer scripts, keep data.tar"
mkdir "$work/deb" "$work/deb/control" "$work/deb/control.orig"
( cd "$work/deb" && ar x ../base.deb )
members=$(ar t "$work/base.deb" | tr '\n' ' ')
control=$(cd "$work/deb" && ls control.tar.*)
data=$(cd "$work/deb" && ls data.tar.*)
[ "$members" = "debian-binary $control $data " ] || { echo "unexpected deb layout: $members"; exit 1; }
case "$control" in
    *.xz)  comp=(-J) ;;
    *.zst) comp=(--zstd) ;;
    *.gz)  comp=(-z) ;;
    *) echo "unsupported control member $control"; exit 1 ;;
esac
tar -C "$work/deb/control" -xf "$work/deb/$control"
tar -C "$work/deb/control.orig" -xf "$work/deb/$control"
order=$(tar -tf "$work/deb/$control")
scripts=$(cd "$work/deb/control" && ls preinst postinst prerm postrm 2>/dev/null)
( cd "$work/deb/control" && python3 "$work/apply_script_patch.py" --format deb "$work/fix.patch" $scripts )
# Same member order, root ownership and modes as the original.
tar -C "$work/deb/control" --owner=0 --group=0 --numeric-owner --no-recursion \
    "${comp[@]}" -cf "$work/deb/new-$control" $order
( cd "$work/deb" && mv "new-$control" "$control" && rm -f ../out.deb \
    && ar rcD ../out.deb debian-binary "$control" "$data" )
deb_out="$OUT/falco-$BASE-x86_64.deb"
mv "$work/out.deb" "$deb_out"
dpkg-deb --info "$deb_out" >/dev/null
dpkg-deb --fsys-tarfile "$deb_out" | sha256sum | cut -d' ' -f1 > "$work/deb.data.new"
dpkg-deb --fsys-tarfile "$work/base.deb" | sha256sum | cut -d' ' -f1 > "$work/deb.data.old"
cmp -s "$work/deb.data.old" "$work/deb.data.new" || { echo "deb payload changed"; exit 1; }
deb_diff=$(cd "$work/deb" && diff -ru control.orig control || true)

# ---------------------------------------------------------------- rpm ----
echo "== rpm: rpmrebuild in $IMAGE with the scriptlets patched"
docker run --rm -v "$work:/w" "$IMAGE" bash -euc '
    dnf -y -q install rpmrebuild python3 cpio >/dev/null
    rpmrebuild --package --notest-install --directory=/w/rpmout \
        --change-spec-whole="python3 /w/apply_script_patch.py --format rpm /w/fix.patch -" /w/base.rpm
    out=$(find /w/rpmout -name "*.rpm" | head -1)
    cp "$out" /w/out.rpm
    rpm -qp --scripts /w/base.rpm > /w/rpm.scripts.old
    rpm -qp --scripts /w/out.rpm  > /w/rpm.scripts.new
    # path, size, mode, digest, owner, group, flags: everything but mtime-free noise
    rpm -qp --dump /w/base.rpm | cut -d" " -f1,2,4,5,6,7,8 > /w/rpm.dump.old
    rpm -qp --dump /w/out.rpm  | cut -d" " -f1,2,4,5,6,7,8 > /w/rpm.dump.new
    rpm -qp --qf "%{NEVRA}\n" /w/base.rpm /w/out.rpm > /w/rpm.nevra
    chown -R '"$(id -u):$(id -g)"' /w
'
cmp -s "$work/rpm.dump.old" "$work/rpm.dump.new" || { echo "rpm payload changed:"; diff "$work/rpm.dump.old" "$work/rpm.dump.new" | head; exit 1; }
[ "$(sort -u "$work/rpm.nevra" | wc -l)" = 1 ] || { echo "rpm NEVRA changed: $(cat "$work/rpm.nevra")"; exit 1; }
rpm_out="$OUT/falco-$BASE-x86_64.rpm"
mv "$work/out.rpm" "$rpm_out"
rpm_diff=$(diff -u "$work/rpm.scripts.old" "$work/rpm.scripts.new" || true)
[ -n "$rpm_diff" ] || { echo "rpm scriptlets unchanged: the patch did not apply"; exit 1; }

sha() { sha256sum "$1" | cut -d' ' -f1; }
{
    echo "label        $LABEL"
    echo "base         $BASE"
    echo "built        $(date -u +%Y-%m-%dT%H:%M:%SZ) by build_branch_package.sh ($(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo '?'))"
    echo
    echo "deb in       $DEB_URL"
    echo "             sha256 $(sha "$work/base.deb")"
    echo "deb out      $(basename "$deb_out")  sha256 $(sha "$deb_out")"
    echo "deb payload  data.tar identical (fsys tar sha256 $(cat "$work/deb.data.new"))"
    echo "rpm in       $RPM_URL"
    echo "             sha256 $(sha "$work/base.rpm")"
    echo "rpm out      $(basename "$rpm_out")  sha256 $(sha "$rpm_out")"
    echo "rpm payload  $(wc -l < "$work/rpm.dump.new") files, path/size/mode/digest/owner identical; NEVRA $(head -1 "$work/rpm.nevra"); unsigned"
    echo
    echo "== fix.patch"
    cat "$PATCH"
    echo
    echo "== deb maintainer scripts, release -> build"
    echo "$deb_diff"
    echo
    echo "== rpm scriptlets, release -> build"
    echo "$rpm_diff"
} > "$OUT/PROVENANCE.txt"
echo "== wrote $OUT"
ls -l "$OUT"

#!/bin/sh
# Package and push the ocidex Helm charts.
#
# Authored as a standalone, shellcheck-able file and wired in via
# tektonic's scriptFromFile(). tektonic injects the exit-code capture and
# status reporting, so this just needs to exit non-zero on failure — `set -e`
# aborts on the first failing helm command. `$(params.revision)` is substituted
# by Tekton at run time.
set -e

SHORT_SHA=$(echo "$(params.revision)" | cut -c1-8)
# Monotonic prerelease so Flux's ">=0.0.0-0" range always selects the newest
# build. A bare 0.1.0-<sha> ordered by sha string, not time, so Flux stuck on
# whichever sha sorted highest and dev never updated. The "main" identifier keeps
# these above any legacy 0.1.0-<hexsha> chart (letters outrank hex digits), and
# the build epoch (numeric identifier) orders builds chronologically; the sha
# stays for traceability.
#
# The prerelease is based on the patch AFTER the chart's `version`, which
# scripts/release.sh sets to the released version in each release commit. A
# prerelease of X.Y.Z sorts below X.Y.Z itself, so 0.1.0-main.* lost to the
# released 0.1.0 and dev stopped following main (ocidex-sijt). The first build
# after vX.Y.Z (or vX.Y.Z-rc.N) is X.Y.(Z+1)-main.*, which outranks it.
CHART_VERSION=$(awk '/^version:/ { print $2; exit }' charts/ocidex/Chart.yaml)
BASE_VERSION=$(echo "$CHART_VERSION" | sed 's/-.*//' | awk -F. '{ printf "%d.%d.%d", $1, $2, $3 + 1 }')
BUILD_EPOCH=$(date -u +%s)
VERSION="${BASE_VERSION}-main.${BUILD_EPOCH}.${SHORT_SHA}"

helm package charts/ocidex \
  --version "${VERSION}" \
  --app-version "sha-${SHORT_SHA}"

helm package charts/ocidex-operator \
  --version "${VERSION}" \
  --app-version "sha-${SHORT_SHA}"

helm package charts/ocidex-k8s-agent \
  --version "${VERSION}" \
  --app-version "sha-${SHORT_SHA}"

helm push "ocidex-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
helm push "ocidex-operator-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
helm push "ocidex-k8s-agent-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts

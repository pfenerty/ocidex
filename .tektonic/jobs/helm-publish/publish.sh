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
BUILD_EPOCH=$(date -u +%s)
VERSION="0.1.0-main.${BUILD_EPOCH}.${SHORT_SHA}"

helm package charts/ocidex \
  --version "${VERSION}" \
  --app-version "sha-${SHORT_SHA}"

helm package charts/ocidex-operator \
  --version "${VERSION}" \
  --app-version "sha-${SHORT_SHA}"

helm push "ocidex-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
helm push "ocidex-operator-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts

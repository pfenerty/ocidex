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
VERSION="0.1.0-${SHORT_SHA}"

helm package charts/ocidex \
  --version "${VERSION}" \
  --app-version "sha-${SHORT_SHA}"

helm package charts/ocidex-operator \
  --version "${VERSION}" \
  --app-version "sha-${SHORT_SHA}"

helm push "ocidex-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
helm push "ocidex-operator-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts

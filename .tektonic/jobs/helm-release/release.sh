#!/bin/sh
# Package and push the ocidex Helm charts for a tagged release.
# `set -e` fails fast on the first failing helm command; synth captures the exit
# code. `$(params.source-branch)` is substituted by Tekton at run time.
set -e
TAG="$(params.source-branch)"
TAG="${TAG#refs/tags/}"
VERSION="${TAG#v}"

helm package charts/ocidex --version "${VERSION}" --app-version "${TAG}"
helm package charts/ocidex-operator --version "${VERSION}" --app-version "${TAG}"
helm push "ocidex-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts
helm push "ocidex-operator-${VERSION}.tgz" oci://ghcr.io/pfenerty/charts

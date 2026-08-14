#!/bin/sh
# CI entry point for the Helm chart lint + PodSecurity policy check.
#
# Deliberately a thin wrapper. The real work lives in scripts/helm-policy-check.sh in the
# repo, so `make helm-check` and this task run byte-identical logic. Pointing
# scriptFromFile() at that script instead would copy it into .tekton/ at synth time, and an
# edit to the script that wasn't re-synthed would silently run the stale copy — tekton-check
# is gated on .tektonic/**|.tekton/** so it wouldn't fire on that PR to catch it.
#
# `set -e` is all the failure handling needed: tektonic wraps this in a subshell and
# persists $? for the report-status step (see the generated YAML).
set -e

sh scripts/helm-policy-check.sh

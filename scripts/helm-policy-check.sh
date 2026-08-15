#!/bin/sh
# Lint the Helm charts, render them, and validate the result against the PodSecurity
# "restricted" profile plus the chart's own writable-path invariants (policy/).
#
# One implementation for both `make helm-check` and the CI helm-check task — the task runs
# this same file out of the checkout, using ghcr.io/pfenerty/apko-cicd/kyverno:<ver>-helm4,
# which carries both binaries. Authored as a standalone, shellcheck-able POSIX sh file for
# the same reason as .tektonic/jobs/helm-publish/publish.sh; `set -e` aborts on the first
# failing command, and `exit 1` is safe here (the "raise, never exit" rule applies to
# nushell task bodies, whose wrapper needs to catch the error).
#
# ocidex-9yq4. Prior art for why this exists: ocidex-1d9 (restricted violations shipped),
# ocidex-gsip (read-only root without a writable /tmp, six days of scan outage).
set -e

OUT=${1:-${TMPDIR:-/tmp}/ocidex-helm-policy-check}
APP_CHART=charts/ocidex
OPERATOR_CHART=charts/ocidex-operator
POLICIES="policy/pod-security-restricted.yaml policy/ocidex-writable-paths.yaml"

command -v helm >/dev/null 2>&1 || {
    echo "ERROR: helm not on PATH (locally: run inside 'flox activate')"
    exit 1
}

# Wolfi's kyverno-cli package installs the CLI as a kubectl plugin, so the binary in the CI
# image is kubectl-kyverno; the nixpkgs build Flox provides calls it kyverno. Same program,
# so resolve whichever is present instead of pinning one and breaking the other environment.
if command -v kyverno >/dev/null 2>&1; then
    KYVERNO=kyverno
elif command -v kubectl-kyverno >/dev/null 2>&1; then
    KYVERNO=kubectl-kyverno
else
    echo "ERROR: neither kyverno nor kubectl-kyverno on PATH (locally: run inside 'flox activate')"
    exit 1
fi

rm -rf "$OUT"
mkdir -p "$OUT"

echo "==> helm lint"
helm lint --strict "$APP_CHART" "$OPERATOR_CHART"

# Render a matrix, not just the defaults: the optional features add and remove whole
# templates, and a chart that only renders cleanly with its defaults is not verified.
echo "==> helm template"
helm template ocidex "$APP_CHART" >"$OUT/app-defaults.yaml"
helm template ocidex "$APP_CHART" \
    --set keda.enabled=true \
    --set monitoring.enabled=true \
    --set cilium.enabled=true \
    --set gatewayApi.enabled=true \
    --set gatewayApi.gatewayName=gateway \
    --set gatewayApi.gatewayNamespace=gateway-system \
    --set gatewayApi.apiHostname=api.example.com \
    --set gatewayApi.webHostname=example.com \
    >"$OUT/app-all-features.yaml"
helm template ocidex "$APP_CHART" \
    --set migrate.enabled=false \
    --set vulnWorker.enabled=false \
    --set nats.storage.emptyDir=true \
    >"$OUT/app-minimal.yaml"
helm template ocidex-operator "$OPERATOR_CHART" >"$OUT/operator-defaults.yaml"

echo "==> kyverno apply (rendered manifests must satisfy every policy)"
for manifest in "$OUT"/*.yaml; do
    echo "--- $manifest"
    # shellcheck disable=SC2086 # POLICIES is a deliberate multi-arg list
    "$KYVERNO" apply $POLICIES --resource "$manifest"
done

# Asserts each rule PASSES on a compliant fixture and FAILS on one that violates exactly
# it, so a rule that stops matching cannot hide behind a green "0 failures" above.
echo "==> kyverno test (rule-level both-polarity assertions)"
"$KYVERNO" test policy/tests

# Chart-level negative control: strip the security contexts the chart supplies and prove
# the check rejects the result. This runs on every invocation, so one green run of this
# script is evidence the policies still have teeth against the real chart — not just
# against fixtures.
echo "==> negative control (chart rendered with securityContext removed must be REJECTED)"
helm template ocidex "$APP_CHART" \
    --set securityContext=null \
    --set podSecurityContext=null \
    --set nats.securityContext=null \
    --set nats.podSecurityContext=null \
    >"$OUT/negative-no-security-context.yaml"
# shellcheck disable=SC2086
if "$KYVERNO" apply $POLICIES --resource "$OUT/negative-no-security-context.yaml" \
    >"$OUT/negative-control.log" 2>&1; then
    echo "ERROR: negative control PASSED — the policies are not enforcing anything."
    echo "       A silently-passing check is worse than no check; fix policy/ before merging."
    exit 1
fi
echo "OK: negative control rejected (see $OUT/negative-control.log)"

echo "==> helm charts pass lint and policy validation"

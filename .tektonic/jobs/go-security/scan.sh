#!/bin/sh
# grype exits non-zero on any low+ severity match against the binary-derived SBOM —
# reported as this task's GitHub check (see spec.ts). Also emit SARIF for upload to the
# GitHub Security tab (uploadSarifStep). Both -o outputs come from one scan.
set -u

echo "── grype: scanning SBOM for known vulnerabilities ──────────────"
grype sbom:sbom.json --fail-on low -o table -o sarif=grype-go.sarif

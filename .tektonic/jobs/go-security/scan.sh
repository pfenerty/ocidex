#!/bin/sh
# grype exits non-zero on any low+ severity match against the SBOM the sbom step
# produced — reported as this task's GitHub check (see spec.ts comment).
set -u

echo "── grype: scanning SBOM for known vulnerabilities ──────────────"
grype sbom:sbom.json --fail-on low

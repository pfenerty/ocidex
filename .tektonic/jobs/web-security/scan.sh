#!/bin/sh
# grype exits non-zero on any low+ severity match against the web SBOM — reported as this
# task's GitHub check. Also emit SARIF for upload to the GitHub Security tab.
set -u

echo "── grype: scanning web SBOM for known vulnerabilities ──────────"
grype sbom:sbom-web.json --fail-on low -o table -o sarif=grype-web.sarif

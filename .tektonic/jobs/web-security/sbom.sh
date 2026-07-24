#!/bin/sh
# Catalog the frontend npm dependency graph straight from the lockfile — no `npm install`,
# no network. syft's javascript lock cataloger reads package-lock.json.
set -eu

echo "── syft: cataloging web/ npm dependency graph ─────────────────"
syft file:web/package-lock.json -o json --file sbom-web.json

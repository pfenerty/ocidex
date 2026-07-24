#!/bin/sh
# Catalog the built binaries: syft's go-binary cataloger reads the exact module versions
# the Go linker embedded — one per module. .sbom-bins/ holds no go.mod/go.sum, so the go
# *file* cataloger finds nothing and the phantom-version flood from go.sum is eliminated.
set -eu

echo "── syft: cataloging built Go binaries (.sbom-bins) ─────────────"
syft dir:.sbom-bins --select-catalogers go -o json --file sbom.json

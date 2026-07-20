#!/bin/sh
# Catalog the Go module graph straight from go.sum/go.mod — no toolchain, no
# network needed (unlike the old `go run govulncheck@latest`).
set -eu

echo "── syft: generating SBOM (Go dependency graph) ────────────────"
syft dir:. --select-catalogers go -o json --file sbom.json

#!/usr/bin/env nu
# Build every command binary so syft catalogs the ACTUAL linked module set (one version
# per module) instead of go.sum's full historical version graph — see spec.ts.
log $"pwd=(pwd) uid=(id -u) go=(go version)"
^git config --global --add safe.directory (pwd)
rm -rf .sbom-bins
mkdir .sbom-bins
log "Building ./cmd/... into .sbom-bins/"
^go build -o .sbom-bins/ ./cmd/...
log $"built: (ls .sbom-bins | get name | path basename | str join ', ')"

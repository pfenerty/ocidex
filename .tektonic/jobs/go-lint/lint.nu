#!/usr/bin/env nu
# golangci-lint is pinned in tools/go.mod (ocidex-gyr0.1). `go tool -n` builds it into
# GOCACHE on first use and prints its path; it needs GOWORK=off because -modfile is refused
# in workspace mode. The linter itself then runs in workspace mode, the same as `make lint`.
log "Resolving pinned golangci-lint"
let lint = (with-env {GOWORK: "off"} { ^go tool -modfile=tools/go.mod -n golangci-lint } | str trim)
^$lint version
log "Running golangci-lint"
# pkg/client is a separate workspace module that ./... does not cover.
^$lint run ./... ./pkg/client/...
log "OK: lint clean"

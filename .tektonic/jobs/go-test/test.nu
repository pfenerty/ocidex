#!/usr/bin/env nu
mkdir $env.GOTMPDIR  # see goTmpEnv in shared.ts
log "Running go test (race detector on)"
# pkg/client is a separate workspace module that ./... does not cover.
^go test -v -race -short -p 2 ./... ./pkg/client/...
log "OK: tests passed"

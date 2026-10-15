#!/usr/bin/env nu
log "Running go test"
# pkg/client is a separate workspace module that ./... does not cover.
^go test -v -short -p 2 ./... ./pkg/client/...
log "OK: tests passed"

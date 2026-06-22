#!/usr/bin/env nu
log "Running go test"
^go test -v -short -p 2 ./...
log "OK: tests passed"

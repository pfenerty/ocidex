#!/usr/bin/env nu
log $"pwd=(pwd) uid=(id -u) go=(go version)"
log $".git exists=('.git' | path exists)"
^git config --global --add safe.directory (pwd)
log "Generating OpenAPI spec"
^go run ./cmd/specgen out> /tmp/openapi-check.json
log "Diffing against committed spec"
^diff web/openapi.json /tmp/openapi-check.json
log "OK: spec is up to date"

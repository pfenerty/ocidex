#!/usr/bin/env nu
log $"pwd=(pwd) uid=(id -u) go=(go version)"
log $"GOMODCACHE=($env.GOMODCACHE) GOCACHE=($env.GOCACHE)"
log $".git exists=('.git' | path exists) go-mod exists=('go-mod' | path exists)"
^git config --global --add safe.directory (pwd)
log $"git rev-parse HEAD: (^git rev-parse --short HEAD)"
log "Building ocidex binaries"
for cmd in ["./cmd/ocidex", "./cmd/scanner-worker", "./cmd/enrichment-worker"] {
  log $"Building ($cmd)"
  ^go build -o /dev/null $cmd
}
log "OK: all binaries built"

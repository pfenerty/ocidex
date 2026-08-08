#!/usr/bin/env nu
log "Running integration tests"
# -p 1: the tests package shares one Postgres and one NATS server (the sidecars),
# and isolates itself with a database-per-test — which only holds while packages
# don't run concurrently. -race is omitted to match go-test's memory posture.
^go test -v -p 1 -timeout 25m ./tests/...
log "OK: integration tests passed"

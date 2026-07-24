#!/usr/bin/env nu
# Reachability-aware Go vuln scan against the MVS-selected module versions — see spec.ts.
# Non-zero exit = at least one vuln is reachable from ocidex's code; the report-only
# reporter surfaces that as this task's GitHub check.
log $"pwd=(pwd) uid=(id -u) go=(go version)"
^git config --global --add safe.directory (pwd)
log "Running govulncheck ./..."
^govulncheck ./...
log "OK: no reachable vulnerabilities"

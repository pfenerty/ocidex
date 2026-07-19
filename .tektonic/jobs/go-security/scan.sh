#!/bin/sh
# Report-only Go security scan: run both tools regardless of individual outcome,
# then exit non-zero if either found something so the GitHub check reflects it.
# Tekton `$()` interpolation collides with shell command substitution, so no `$(...)`
# is used here; `go run <pkg>@latest` avoids needing GOPATH/bin on PATH.
set -u
rc=0

echo "── govulncheck ─────────────────────────────────────────────"
go run golang.org/x/vuln/cmd/govulncheck@latest ./... || rc=1

echo "── gosec ───────────────────────────────────────────────────"
go run github.com/securego/gosec/v2/cmd/gosec@latest -fmt text ./... || rc=1

exit $rc

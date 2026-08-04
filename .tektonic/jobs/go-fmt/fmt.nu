#!/usr/bin/env nu
log "Checking gofmt"
# Not `gofmt -l .` — gofmt's isGoFile skips dot-*files* but filepath.WalkDir still descends
# into dot-*directories*, and goEnv puts GOMODCACHE/GOCACHE at .go-mod/.go-build inside this
# same shared workspace. So a bare `.` reports every third-party file in the module cache as
# unformatted the moment a concurrent task has populated it (ocidex-kmx). nushell's `ls`
# omits dot-entries, which is exactly the set to skip; node_modules is third-party too.
# Directories only — gofmt parses explicitly-named files regardless of extension, so passing
# go.mod or a Makefile would be a parse error rather than a skip.
let targets = (ls | where type == dir | where name != "node_modules" | get name)
let unformatted = (^gofmt -l ...$targets | complete | get stdout | str trim)
if ($unformatted | str length) > 0 {
  print "Unformatted files:"; print $unformatted
  error make {msg: "gofmt: formatting issues found"}
}
log "OK: all files formatted"

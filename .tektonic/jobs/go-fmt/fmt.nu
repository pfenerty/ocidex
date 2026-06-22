#!/usr/bin/env nu
log "Checking gofmt"
let unformatted = (^gofmt -l . | complete | get stdout | str trim)
if ($unformatted | str length) > 0 {
  print "Unformatted files:"; print $unformatted
  error make {msg: "gofmt: formatting issues found"}
}
log "OK: all files formatted"

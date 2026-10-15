#!/usr/bin/env nu
let tag = ("$(params.source-branch)" | str replace "refs/tags/" "")
let is_prerelease = ($tag | str contains "-")

# The release body is this tag's CHANGELOG.md section, from its "## [X.Y.Z]" heading up to
# the next "## " heading. No section means the tag bypassed scripts/release.sh: refuse to
# publish rather than ship a release whose notes don't exist.
let heading = $"## [($tag | str replace --regex '^v' '')]"
let lines = (open --raw "CHANGELOG.md" | lines)
let start = ($lines | enumerate | where {|l| $l.item | str starts-with $heading } | get index | first 1)
if ($start | is-empty) {
  error make { msg: $"CHANGELOG.md has no '($heading)' section; cut releases with `make release VERSION=($tag)`" }
}
let body_text = ($lines
  | skip ($start.0 + 1)
  | take while {|l| not ($l | str starts-with "## ") }
  | str join "\n"
  | str trim)

log $"creating release ($tag) prerelease=($is_prerelease)"

let url = $"https://api.github.com/repos/$(params.repo-full-name)/releases"
let payload = { tag_name: $tag, name: $tag, body: $body_text, prerelease: $is_prerelease, draft: false }

http post $url $payload -t application/json -H [
  Authorization $"token ($env.GH_TOKEN)"
  Accept "application/vnd.github+json"
  X-GitHub-Api-Version "2022-11-28"
]
log "release created"

#!/usr/bin/env nu
let tag = ("$(params.source-branch)" | str replace "refs/tags/" "")
let is_prerelease = ($tag | str contains "-")
let body_text = try { open --raw "CHANGELOG.md" } catch { "" }

log $"creating release ($tag) prerelease=($is_prerelease)"

let url = $"https://api.github.com/repos/$(params.repo-full-name)/releases"
let payload = { tag_name: $tag, name: $tag, body: $body_text, prerelease: $is_prerelease, draft: false }

http post $url $payload -t application/json -H [
  Authorization $"token ($env.GH_TOKEN)"
  Accept "application/vnd.github+json"
  X-GitHub-Api-Version "2022-11-28"
]
log "release created"

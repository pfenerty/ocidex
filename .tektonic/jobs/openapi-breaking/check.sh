#!/bin/sh
# Fail the PR when web/openapi.json breaks the /api/v1 contract of the last release
# (ADR-052, docs/API_VERSIONING.md). Breaks listed in web/openapi-breaking-accepted.txt
# are accepted; that file is the reviewed override.
set -e

# The workspace is owned by another uid, and git-clone fetched only the PR's target
# branch, so release tags have to be fetched here.
g() { git -c safe.directory='*' "$@"; }
g fetch -q --no-tags origin 'refs/tags/v*:refs/tags/v*'

# Newest release by version, prereleases sorting before their release. Not `git
# describe`: v0.0.1-rc.1..v0.0.2 are not ancestors of main (ocidex-tkn9.8).
TAG=$(g -c versionsort.suffix=- tag -l 'v[0-9]*' --sort=-v:refname | head -n 1)
if [ -z "$TAG" ]; then
  echo "no release tag yet; nothing to compare against"
  exit 0
fi

g show "$TAG:web/openapi.json" > /tmp/openapi-base.json
echo "comparing web/openapi.json against $TAG"
oasdiff breaking /tmp/openapi-base.json web/openapi.json \
  --fail-on ERR \
  --err-ignore web/openapi-breaking-accepted.txt
echo "OK: no unaccepted breaking changes against $TAG"

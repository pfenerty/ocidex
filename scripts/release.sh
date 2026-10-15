#!/usr/bin/env bash
# Cut a release: regenerate CHANGELOG.md, commit, and tag.
#
# Usage: scripts/release.sh vX.Y.Z[-prerelease]
#        scripts/release.sh pkg/client/vX.Y.Z[-prerelease]
# Set DRY_RUN=1 to preview without committing or tagging.
#
# A pkg/client/ tag releases the Go SDK module (ADR-052). It only tags: the Go proxy
# serves the module from the tag, and the tag pipeline ignores it.
set -euo pipefail

VERSION="${1:-}"
DRY_RUN="${DRY_RUN:-0}"

die() { echo "release: $*" >&2; exit 1; }

[[ -n "$VERSION" ]] || die "missing VERSION argument (e.g. v0.1.0)"
[[ "$VERSION" =~ ^(pkg/client/)?v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] \
  || die "VERSION must match [pkg/client/]vX.Y.Z[-prerelease], got: $VERSION"

SDK=0
[[ "$VERSION" == pkg/client/* ]] && SDK=1

if [[ "$SDK" == "0" ]]; then
  command -v git-cliff >/dev/null 2>&1 || die "git-cliff not on PATH (install via 'cargo install git-cliff' or your package manager)"
fi

cd "$(git rev-parse --show-toplevel)"

current_branch=$(git rev-parse --abbrev-ref HEAD)
[[ "$current_branch" == "main" ]] || die "must be on main, currently on '$current_branch'"

git diff --quiet && git diff --cached --quiet \
  || die "working tree has uncommitted changes; commit or stash first"

git fetch origin main --quiet
local_sha=$(git rev-parse HEAD)
remote_sha=$(git rev-parse origin/main)
[[ "$local_sha" == "$remote_sha" ]] \
  || die "local main ($local_sha) is not in sync with origin/main ($remote_sha)"

if git rev-parse "$VERSION" >/dev/null 2>&1; then
  die "tag $VERSION already exists"
fi

if [[ "$SDK" == "1" ]]; then
  echo "release: testing pkg/client as a standalone module"
  (cd pkg/client && GOWORK=off go test ./...) || die "pkg/client does not build and test on its own"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "release: DRY_RUN=1, would run:"
    echo "  git tag -a '$VERSION' -m 'Release $VERSION'"
    echo "  git push origin '$VERSION'"
    exit 0
  fi
  git tag -a "$VERSION" -m "Release $VERSION"
  cat <<EOF

release: tagged $VERSION at $(git rev-parse --short HEAD)

Next: push the tag, then point the root module at it:

  git push origin $VERSION
  GOWORK=off go get github.com/pfenerty/ocidex/pkg/client@${VERSION#pkg/client/} && GOWORK=off go mod tidy
EOF
  exit 0
fi

# go.work joins the root module to the local SDK, so a normal build cannot tell whether the
# SDK version go.mod requires actually has what the binaries use. `go install ...@VERSION`
# ignores go.work, so check the way it will build.
echo "release: building the root module without go.work"
GOWORK=off go build ./... \
  || die "root module does not build against the pkg/client version in go.mod; release the SDK first (scripts/release.sh pkg/client/vX.Y.Z) and require it"

echo "release: regenerating CHANGELOG.md for $VERSION"
git cliff --tag "$VERSION" --output CHANGELOG.md

if [[ "$DRY_RUN" == "1" ]]; then
  echo "release: DRY_RUN=1, showing planned changes:"
  git --no-pager diff CHANGELOG.md
  git checkout -- CHANGELOG.md
  echo "release: would run:"
  echo "  git add CHANGELOG.md"
  echo "  git commit -m 'chore(release): $VERSION'"
  echo "  git tag -a '$VERSION' -m 'Release $VERSION'"
  echo "  git push origin main '$VERSION'"
  exit 0
fi

git add CHANGELOG.md
git commit -m "chore(release): $VERSION"
git tag -a "$VERSION" -m "Release $VERSION"

cat <<EOF

release: prepared $VERSION on main ($(git rev-parse --short HEAD))

Next: review the diff, then push:

  git push origin main $VERSION

This triggers the release workflow which builds images and creates the GitHub Release.
EOF

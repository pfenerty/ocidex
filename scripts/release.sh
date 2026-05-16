#!/usr/bin/env bash
# Cut a release: regenerate CHANGELOG.md, commit, and tag.
#
# Usage: scripts/release.sh vX.Y.Z[-prerelease]
# Set DRY_RUN=1 to preview without committing or tagging.
set -euo pipefail

VERSION="${1:-}"
DRY_RUN="${DRY_RUN:-0}"

die() { echo "release: $*" >&2; exit 1; }

[[ -n "$VERSION" ]] || die "missing VERSION argument (e.g. v0.1.0)"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] \
  || die "VERSION must match vX.Y.Z[-prerelease], got: $VERSION"

command -v git-cliff >/dev/null 2>&1 || die "git-cliff not on PATH (install via 'cargo install git-cliff' or your package manager)"

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

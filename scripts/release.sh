#!/usr/bin/env bash
# Cut a release: add the version's CHANGELOG.md section, commit, and tag.
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

# The new section covers the commits since the previous release. Older sections are kept
# as they are, not regenerated. v0.0.1-rc.1..v0.0.2 were tagged on a history that main
# was later rewritten from, so git cliff on main cannot see them. The base is that tag
# when it is an ancestor of HEAD, otherwise the commit on HEAD with the same tree.
prev_tag=$(git -c versionsort.suffix=- tag -l 'v[0-9]*' --sort=-v:refname | head -1)
if [[ -z "$prev_tag" ]]; then
  range="HEAD"
elif git merge-base --is-ancestor "$prev_tag" HEAD; then
  range="$prev_tag..HEAD"
else
  prev_tree=$(git rev-parse "$prev_tag^{tree}")
  base=$(git log --format='%H %T' HEAD | awk -v t="$prev_tree" '$2 == t { print $1; exit }')
  [[ -n "$base" ]] || die "$prev_tag is not on this branch and no commit here has its tree"
  echo "release: $prev_tag is off this history; using its tree twin ${base:0:10} as the base"
  range="$base..HEAD"
fi

echo "release: adding the $VERSION section to CHANGELOG.md ($range)"
section=$(git cliff "$range" --tag "$VERSION" --strip all)
[[ -n "$section" ]] || die "no changelog entries for $range"
# Keep the header (everything before the first "## "), drop the old [unreleased] section,
# put the new section in its place, and keep every released section after it.
SECTION="$section" awk '
  /^## / { if (!done) { print ENVIRON["SECTION"]; print ""; done = 1 } skip = /^## \[unreleased\]/ }
  !skip { print }
' CHANGELOG.md > CHANGELOG.md.new
mv CHANGELOG.md.new CHANGELOG.md

# Main-build charts are versioned from the patch after this (.tektonic/jobs/helm-publish/
# publish.sh), so it must track the latest release or main builds sort below it.
CHARTS=(charts/ocidex/Chart.yaml charts/ocidex-operator/Chart.yaml charts/ocidex-k8s-agent/Chart.yaml)
echo "release: setting chart version to ${VERSION#v}"
for chart in "${CHARTS[@]}"; do
  sed "s/^version: .*/version: ${VERSION#v}/" "$chart" > "$chart.new"
  mv "$chart.new" "$chart"
done

if [[ "$DRY_RUN" == "1" ]]; then
  echo "release: DRY_RUN=1, showing planned changes:"
  git --no-pager diff CHANGELOG.md "${CHARTS[@]}"
  git checkout -- CHANGELOG.md "${CHARTS[@]}"
  echo "release: would run:"
  echo "  git add CHANGELOG.md charts/*/Chart.yaml"
  echo "  git commit -m 'chore(release): $VERSION'"
  echo "  git tag -a '$VERSION' -m 'Release $VERSION'"
  echo "  git push origin main '$VERSION'"
  exit 0
fi

git add CHANGELOG.md "${CHARTS[@]}"
git commit -m "chore(release): $VERSION"
git tag -a "$VERSION" -m "Release $VERSION"

cat <<EOF

release: prepared $VERSION on main ($(git rev-parse --short HEAD))

Next: review the diff, then push:

  git push origin main $VERSION

This triggers the release workflow which builds images and creates the GitHub Release.
EOF

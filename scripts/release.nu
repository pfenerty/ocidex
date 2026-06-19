#!/usr/bin/env nu
# Cut a release: regenerate CHANGELOG.md, commit, tag, and push.
#
# Usage: nu scripts/release.nu v1.2.3
#        nu scripts/release.nu v1.2.3-rc.1 --dry-run

def main [
  version: string  # Semver tag to release (e.g. v1.2.3 or v1.2.3-rc.1)
  --dry-run        # Preview changes without committing or pushing
] {
  if not ($version =~ '^v\d+\.\d+\.\d+(-[A-Za-z0-9.]+)?$') {
    error make { msg: $"VERSION must match vX.Y.Z[-prerelease], got: ($version)" }
  }

  let branch = (^git rev-parse --abbrev-ref HEAD | str trim)
  if $branch != "main" {
    error make { msg: $"must be on main, currently on '($branch)'" }
  }

  if (^git status --porcelain | str trim) != "" {
    error make { msg: "working tree has uncommitted changes; commit or stash first" }
  }

  ^git fetch origin main --quiet
  let local = (^git rev-parse HEAD | str trim)
  let remote = (^git rev-parse origin/main | str trim)
  if $local != $remote {
    error make { msg: $"local main is not in sync with origin/main" }
  }

  if (do { ^git rev-parse $version } | complete).exit_code == 0 {
    error make { msg: $"tag ($version) already exists" }
  }

  print $"release: regenerating CHANGELOG.md for ($version)"
  ^git cliff --tag $version --output CHANGELOG.md

  if $dry_run {
    ^git --no-pager diff CHANGELOG.md
    ^git checkout -- CHANGELOG.md
    print "release: dry run complete — no changes made"
    return
  }

  ^git add CHANGELOG.md
  ^git commit -m $"chore\(release\): ($version)"
  ^git tag -a $version -m $"Release ($version)"
  ^git push origin HEAD:main
  ^git push origin $version

  print $"release: ($version) pushed — TAG pipeline will start shortly"
}

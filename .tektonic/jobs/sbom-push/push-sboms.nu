#!/usr/bin/env nu
if ($env.OCIDEX_API_KEY? | is-empty) {
  log "OCIDEX_API_KEY is unset - skipping SBOM upload"
  exit 0
}

# A tag build is the released version; a push to main is not, so it gets a version
# that sorts below every release and still names the commit it came from.
let ref = "$(params.source-branch)"
let rev = "$(params.revision)"
let version = if ($ref | str starts-with "refs/tags/") {
  $ref | str replace "refs/tags/" ""
} else {
  $"0.0.0-($rev | str substring 0..7)"
}

# Written by the build step. Absent only if that step failed, in which case the
# flag is simply omitted rather than guessed — a wrong architecture would be
# recorded as fact against every binary.
let arch = if (".sbom-bins/.goarch" | path exists) {
  open .sbom-bins/.goarch | str trim
} else {
  ""
}

let binaries = ($env.OCIDEX_BINARIES | split row " ")
log $"pushing ($binaries | length) SBOMs as version ($version) to ($env.OCIDEX_URL)"

mut failed = []
for b in $binaries {
  # The subject is declared rather than inferred: a syft scan of a binary names the
  # file it read, and the purl it derives is the Go *module*, which all nine binaries
  # share. Group + name are what keep them distinct artifacts.
  #
  # Built as a list and spread, because a bare multi-line external invocation is a
  # separate command per line in nushell.
  let args = [
    "sbom" "push" $".sbom-out/($b).cdx.json"
    "--source" $env.OCIDEX_SOURCE
    "--artifact-file" $".sbom-bins/($b)"
    "--subject-type" "application"
    "--subject-name" $b
    "--subject-group" "github.com/pfenerty/ocidex"
    "--subject-purl" $"pkg:golang/github.com/pfenerty/ocidex/cmd/($b)@($version)"
    "--version" $version
  ] | append (if ($arch | is-empty) { [] } else { ["--arch" $arch] })
  let result = (do { ^.sbom-bins/ocidex-cli ...$args } | complete)

  if $result.exit_code == 0 {
    log $"pushed ($b): ($result.stdout | str trim)"
  } else {
    log $"FAILED ($b): ($result.stdout | str trim) ($result.stderr | str trim)"
    $failed = ($failed | append $b)
  }
}

if not ($failed | is-empty) {
  log $"($failed | length) of ($binaries | length) uploads failed: ($failed | str join ', ')"
  exit 1
}
log "OK: all SBOMs pushed"

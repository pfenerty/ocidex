#!/usr/bin/env nu
# Pushes one SBOM per shipped binary using the ocidex-cli that build-binaries just
# compiled from this commit (ocidex-qzz2). See spec.ts for why the workspace binary
# is used rather than the published ghcr.io/pfenerty/ocidex-cli image.
if ($env.OCIDEX_API_KEY? | is-empty) {
  log "OCIDEX_API_KEY is unset - skipping SBOM upload"
  exit 0
}

# Both files are written by build-binaries. They are passed as --version-file /
# --arch-file rather than read and expanded here: the CLI errors on a missing or
# blank file, so a failed build step surfaces as a refusal instead of a versionless
# SBOM nobody notices. This read is for the log line only, hence the guard.
let version = if (".sbom-bins/.version" | path exists) {
  open .sbom-bins/.version | str trim
} else {
  "<unwritten>"
}

let binaries = ($env.OCIDEX_BINARIES | split row " ")
log $"pushing ($binaries | length) SBOMs as version ($version) to ($env.OCIDEX_URL)"

mut failed = []
for b in $binaries {
  # The subject is declared rather than inferred: a syft scan of a binary names the
  # file it read, and the purl it derives is the Go *module*, which every binary
  # shares. Group + name are what keep them distinct artifacts.
  #
  # The purl carries no @version. artifact.purl is an attribute, not part of the
  # artifact's identity — UpsertArtifact conflicts on (type, name, group) — so a
  # versioned purl only churned the stored value on every push while the version
  # that matters lives on sbom.subject_version. It also keys the same way ADR-019
  # Rule 1 and ADR-041 do, on the purl base.
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
    "--subject-purl" $"pkg:golang/github.com/pfenerty/ocidex/cmd/($b)"
    "--version-file" ".sbom-bins/.version"
    "--arch-file" ".sbom-bins/.goarch"
  ]
  let result = (do { ^.sbom-bins/ocidex-cli ...$args } | complete)

  if $result.exit_code == 0 {
    log $"pushed ($b): ($result.stdout | str trim)"
  } else {
    log $"FAILED ($b): ($result.stdout | str trim) ($result.stderr | str trim)"
    $failed = ($failed | append $b)
  }
}

if not ($failed | is-empty) {
  # `error make`, never `exit 1` (ocidex-es6): nushell's `exit` kills the process
  # before tektonic's try/catch can persist the code to /tekton/home/.exit-code,
  # which — with onError: continue on this step — reports a real failure as green.
  # That is exactly how this task hid nine broken uploads (ocidex-qzz2).
  #
  # Raising cannot gate a release: reportOnlyStatusReporter is failOnError: false,
  # so this marks the sbom-push check red and leaves the pipeline succeeding.
  error make {
    msg: $"($failed | length) of ($binaries | length) uploads failed: ($failed | str join ', ')"
  }
}
log $"OK: all ($binaries | length) SBOMs pushed"

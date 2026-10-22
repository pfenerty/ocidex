import { nu } from "@tektonic-ci/core";
import {
  govulncheckImage,
  goEnv,
  goCacheConsumer,
  sarifScanTask,
  uploadSarifStep,
} from "../../shared";
import { goBuild } from "../go-build/spec";
import { goSetup, memoryWatchdog } from "../../script-lib";

// Repo-root allowlist of accepted OSV IDs, read from the checkout at runtime so editing it
// needs no `make tekton-synth`. See docs/DEVELOPMENT.md "Accepting a govulncheck finding".
const acceptFile = ".govulncheck-accepted.json";

// Binaries that link grype/syft. Each needs more live heap for a symbol-level (call graph) scan
// than the step's 6Gi allows (5.5GiB+ at the watchdog, vs 0.2-4.1GiB for every other binary), so
// they get `-scan package`: vulns they import are still reported, but never as "called", so one
// reachable only through grype/syft can't fail the check. Restoring the symbol scan for them
// waits on more memory for the CI node (ocidex-l865).
const packageScanBins = ["scanner-worker", "vuln-parity", "vuln-worker"];

// Reachability-aware Go vuln scan. Unlike grype-on-SBOM, govulncheck resolves the
// MVS-selected module versions and walks the call graph to report only vulns actually
// reachable from ocidex's code — no phantom-version noise. Go-only + needs the toolchain, so
// it's its own task. Report-only: an unaccepted finding becomes this task's GitHub check
// while the PipelineRun stays green.
export const goVulncheck = sarifScanTask({
  name: "govulncheck-scan",
  // Ordered after goBuild so the shared workspace Go cache is already populated when this
  // task starts, which is the precondition the goCache consumer's skipped restore relies on. It
  // also stops the two tasks racing each other's restore at t=0. On PRs both are gated on
  // detect-go, so they always run or skip together.
  needs: [goBuild],
  caches: [goCacheConsumer],
  stepTemplate: {
    env: goEnv,
  },
  steps: [
    {
      name: "govulncheck-scan",
      image: govulncheckImage,
      env: [
        // govulncheck's whole-program SSA call graph is memory-hungry and grows with the dep
        // tree (grype/syft/AWS-SDK/k8s/cosign/sigstore-go) — it OOMKilled at 2Gi, 4Gi, 6Gi,
        // then 10Gi (ocidex-2w2), before the scan was narrowed to ./cmd/... and wrapped in the
        // watchdog below. GOMEMLIMIT gives the Go GC a soft target below the hard cgroup ceiling
        // so it collects proactively instead of growing heap until the kernel OOM-kills it.
        //
        // It must sit well under the node's spare memory, not just under this step's limit: at
        // 8GiB the heap grew to ~2x its live set (8.3GB RSS) on talos-jlf-6ro, the only
        // schedulable node, next to ocidex-pg, and Talos's OOM controller took the node down
        // (ocidex-kt3x, homelab-ctd). Scanned one binary at a time (below), the largest
        // symbol-level scan peaks at ~4.1GiB of working set.
        { name: "GOMEMLIMIT", value: "5GiB" },
      ],
      // The request is as high as the node allows: after the kubelet reservation the always-on
      // services already request ~7.6Gi of x86-01's ~13Gi, and Tekton sums every step's request,
      // so a 5Gi scan step (5.6Gi pod) never schedules. 4Gi still keeps a second concurrent scan
      // off the node. The limit is homelab's 6Gi per-container cap for CI namespaces; if the live
      // set outgrows it, the watchdog fails the report-only check rather than the node.
      computeResources: {
        limits: { cpu: "2", memory: "6Gi", "ephemeral-storage": "4Gi" },
        requests: { cpu: "500m", memory: "4Gi", "ephemeral-storage": "2Gi" },
      },
      // Scan from the command entry points (./cmd/...) rather than ./... : it still follows every
      // import the binaries actually use (so no production vuln is missed), but drops test files
      // and unreachable internal packages — a smaller call graph, and a more accurate "reachable
      // in what we ship" than including _test.go entry points.
      //
      // One govulncheck per binary, not one over ./cmd/...: a single call graph spanning every
      // binary's deps grew past 6Gi of live heap in-cluster (ocidex-kt3x), while each binary's
      // own graph is a fraction of that, so peak memory is the largest binary's rather than the
      // union's. Per-binary SARIFs merge into one run keeping each vuln at its most severe
      // level across binaries, which is what the ./cmd/... scan reported.
      //
      // GOMEMLIMIT only prevents OOM from reclaimable garbage — if the live working set itself
      // exceeds the 6Gi limit, the kernel still OOM-kills the container, and OOMKilled bypasses
      // this step's `onError: continue` entirely (Tekton treats it as an infrastructure failure,
      // not a script exit code), hard-failing the TaskRun/PipelineRun despite the report-only
      // design. So govulncheck runs as a child process under a watchdog that polls this cgroup's
      // own working set against memory.max and self-terminates it before the kernel's
      // OOM-killer does — turning a would-be OOMKilled into a normal non-zero exit, which
      // `onError: continue` (this step) and `failOnError: false` (reportOnlyStatusReporter's
      // report-status step) already handle correctly. The watchdog itself now lives in
      // script-lib so semgrep-sast can reuse it (ocidex-im4o.3).
      //
      // `-format sarif` rather than the default text output. Two reasons: it is the only
      // machine-readable shape with one result per vulnerability carrying a `level` that
      // distinguishes *called* (error) from merely imported (warning) or required (note); and
      // it always exits 0, so this wrapper owns the verdict outright instead of decoding
      // govulncheck's exit 3. govulncheck has no native ignore mechanism — filtering here is
      // the only way to accept a finding that has no upstream fix.
      script: nu`
${goSetup}
let bins = (ls cmd | where type == dir | get name | each {|d| $d | path basename} | sort)
let package_bins = [${packageScanBins.map((b) => `"${b}"`).join(" ")}]
mut failed = []
for bin in $bins {
  # The watchdog's command is sh, so the binary and scan mode cross over as env vars.
  $env.VULN_BIN = $bin
  $env.VULN_SCAN = (if $bin in $package_bins { "package" } else { "symbol" })
  log $"Running govulncheck -scan ($env.VULN_SCAN) -format sarif ./cmd/($bin)"
  # try yields a value rather than mutating $failed: catch is a closure and can't capture it.
  let ok = (try {
    ${memoryWatchdog("govulncheck", 'govulncheck -scan "$VULN_SCAN" -format sarif "./cmd/$VULN_BIN" > "govulncheck-$VULN_BIN.sarif"')}
    true
  } catch {|e| log $"govulncheck ($bin): ($e.msg)"; false })
  if not $ok { $failed = ($failed | append $bin) }
}

# Most severe level per vuln across binaries: called in one binary (error) beats merely
# imported (warning) or required (note) in another.
let rank = {error: 3, warning: 2, note: 1}
# A package scan reports any imported vulnerable package at level error, though it never looked
# at calls. Only a symbol scan can say "called", so package-scan errors count as warnings.
let docs = ($bins | where {|b| $b not-in $failed} | each {|b|
  let doc = (open --raw $"govulncheck-($b).sarif" | from json)
  if $b in $package_bins {
    let demoted = ($doc | get -o runs.0.results | default []
      | each {|r| if $r.level == "error" { $r | update level "warning" } else { $r } })
    $doc | update runs.0.results $demoted
  } else { $doc }
})
if ($docs | is-not-empty) {
  let merged_results = ($docs | each {|d| $d | get -o runs.0.results | default []} | flatten
    | group-by ruleId | values
    | each {|g| $g | sort-by --reverse {|r| $rank | get -o $r.level | default 0} | first})
  let merged_rules = ($docs | each {|d| $d | get -o runs.0.tool.driver.rules | default []} | flatten | uniq-by id)
  $docs | first | update runs.0.results $merged_results | update runs.0.tool.driver.rules $merged_rules
    | to json | save -f govulncheck.sarif
}
# A binary the watchdog stopped has no findings to report, so the scan as a whole is incomplete.
# Fail after merging so the Security tab still gets every binary that did finish.
if ($failed | is-not-empty) {
  error make {msg: $"govulncheck: scan did not finish for ($failed | str join ', ') (memory watchdog or error)"}
}

let accepted = (if ("${acceptFile}" | path exists) { open --raw "${acceptFile}" | from json } else { [] })
let accepted_ids = ($accepted | get -o id | default [])
let results = (open --raw govulncheck.sarif | from json | get -o runs.0.results | default [])
# level == error is govulncheck's "your code calls this" — the only level worth failing on.
let called = ($results | where level == "error" | get ruleId | uniq)
let reported = ($results | get ruleId | uniq)
let unexpected = ($called | where {|id| $id not-in $accepted_ids})
let stale = ($accepted_ids | where {|id| $id not-in $reported})

log $"govulncheck: ($results | length) findings, ($called | length) reachable, ($accepted_ids | length) accepted"
if ($results | is-not-empty) {
  print ($results | each {|r| {
    id: $r.ruleId
    level: $r.level
    accepted: (if $r.ruleId in $accepted_ids { "yes" } else { "" })
    summary: ($r.message.text | str replace --all (char newline) " ")
  } } | sort-by level id | table --width 160)
}

# A stale entry is a red check on purpose: it is the only thing stopping the allowlist
# decaying into blanket suppression once upstream ships a fix.
if ($stale | is-not-empty) {
  for id in $stale {
    let e = ($accepted | where id == $id | first)
    log $"STALE: ($id) is accepted but no longer reported. ($e.review)"
  }
  error make {msg: $"govulncheck: remove ($stale | str join ', ') from ${acceptFile} — no longer reported"}
}

# error make, never exit: nushell's exit kills the process before tektonic's try/catch can
# persist the code to /tekton/home/.exit-code, and report-status would call this green.
if ($unexpected | is-not-empty) {
  error make {msg: $"govulncheck: ($unexpected | length) unaccepted reachable vulnerabilities: ($unexpected | str join ', ')"}
}

log $"OK: no unaccepted reachable vulnerabilities; ($accepted_ids | length) accepted"
`,
    },
    // Unfiltered SARIF — the Security tab should show the full picture and has its own
    // dismissal UI; the allowlist governs only this task's pass/fail verdict.
    uploadSarifStep("govulncheck.sarif", "govulncheck"),
  ],
});

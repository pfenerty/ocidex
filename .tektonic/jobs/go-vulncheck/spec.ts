import { Task, nu } from "@pfenerty/tektonic";
import {
  govulncheckImage,
  goEnv,
  goCacheVulncheck,
  reportOnlyStatusReporter,
  sourceBranchParam,
  uploadSarifStep,
} from "../../shared";
import { goBuild } from "../go-build/spec";
import { goSetup, memoryWatchdog } from "../../script-lib";

// Repo-root allowlist of accepted OSV IDs, read from the checkout at runtime so editing it
// needs no `make tekton-synth`. See docs/DEVELOPMENT.md "Accepting a govulncheck finding".
const acceptFile = ".govulncheck-accepted.json";

// Reachability-aware Go vuln scan. Unlike grype-on-SBOM, govulncheck resolves the
// MVS-selected module versions and walks the call graph to report only vulns actually
// reachable from ocidex's code — no phantom-version noise. Go-only + needs the toolchain, so
// it's its own task. Report-only: an unaccepted finding becomes this task's GitHub check
// while the PipelineRun stays green.
export const goVulncheck = new Task({
  name: "govulncheck-scan",
  // For uploadSarifStep's code-scanning call; tektonic wires it from the pipeline's
  // `source-branch`, as it already does for grype-vuln-web and semgrep-sast.
  params: [sourceBranchParam],
  // Ordered after goBuild so the shared workspace Go cache is already populated when this
  // task starts, which is the precondition goCacheVulncheck's skip-restore relies on. It
  // also stops the two tasks racing each other's restore at t=0. goBuild runs ungated on
  // every pipeline (it is pulled in via `needs`), so this never leaves the task orphaned.
  needs: [goBuild],
  statusReporter: reportOnlyStatusReporter,
  caches: [goCacheVulncheck],
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
        // then 10Gi (ocidex-2w2). Confirmed NOT a scheduling issue: the cluster's other three
        // nodes are control-plane-tainted and have never been schedulable for this pod;
        // talos-jlf-6ro (the only schedulable node) has always had ample free memory when this
        // OOMKilled. GOMEMLIMIT gives the Go GC a soft target below the hard cgroup ceiling so
        // it collects proactively instead of growing heap until the kernel OOM-kills it.
        { name: "GOMEMLIMIT", value: "8GiB" },
      ],
      // Reflects realistic usage (~3.2GB measured locally), not a scheduling hint — there's
      // only one schedulable node, so an inflated request just crowds out sibling pipeline
      // tasks (go-build, go-test, etc.) competing for the same node during a PR run.
      computeResources: {
        limits: { cpu: "2", memory: "10Gi", "ephemeral-storage": "4Gi" },
        requests: { cpu: "500m", memory: "4Gi", "ephemeral-storage": "2Gi" },
      },
      // Scan from the command entry points (./cmd/...) rather than ./... : it still follows every
      // import the binaries actually use (so no production vuln is missed), but drops test files
      // and unreachable internal packages — a smaller call graph, and a more accurate "reachable
      // in what we ship" than including _test.go entry points.
      //
      // GOMEMLIMIT only prevents OOM from reclaimable garbage — if the live working set itself
      // exceeds the 10Gi limit, the kernel still OOM-kills the container, and OOMKilled bypasses
      // this step's `onError: continue` entirely (Tekton treats it as an infrastructure failure,
      // not a script exit code), hard-failing the TaskRun/PipelineRun despite the report-only
      // design. So govulncheck runs as a child process under a watchdog that polls this cgroup's
      // own memory.current against memory.max and self-terminates it before the kernel's
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
log "Running govulncheck -format sarif ./cmd/..."
${memoryWatchdog("govulncheck", "govulncheck -format sarif ./cmd/... > govulncheck.sarif")}

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

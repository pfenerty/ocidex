import { Task, nu } from "@pfenerty/tektonic";
import { govulncheckImage, goEnv, goCache, reportOnlyStatusReporter } from "../../shared";
import { goSetup } from "../../script-lib";

// Reachability-aware Go vuln scan. Unlike grype-on-SBOM (jobs/go-security), govulncheck
// resolves the MVS-selected module versions and walks the call graph to report only vulns
// actually reachable from ocidex's code — no phantom-version noise. Go-only + needs the
// toolchain, so it's its own task. Report-only: non-zero exit (reachable vulns) becomes this
// task's GitHub check while the PipelineRun stays green.
export const goVulncheck = new Task({
  name: "govulncheck-scan",
  statusReporter: reportOnlyStatusReporter,
  caches: [goCache],
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
      // report-status step) already handle correctly.
      script: nu`
${goSetup}
log "Running govulncheck ./cmd/..."
let watchdog = r#'
govulncheck ./cmd/... &
pid=$!
max_file=/sys/fs/cgroup/memory.max
cur_file=/sys/fs/cgroup/memory.current
[ -f "$max_file" ] || max_file=/sys/fs/cgroup/memory/memory.limit_in_bytes
[ -f "$cur_file" ] || cur_file=/sys/fs/cgroup/memory/memory.usage_in_bytes
mem_max=$(cat "$max_file" 2>/dev/null || echo 0)
if [ "$mem_max" != "max" ] && [ "$mem_max" -gt 0 ] 2>/dev/null; then
  threshold=$((mem_max * 92 / 100))
  while kill -0 "$pid" 2>/dev/null; do
    cur=$(cat "$cur_file" 2>/dev/null || echo 0)
    if [ "$cur" -gt "$threshold" ] 2>/dev/null; then
      echo "govulncheck: usage $cur bytes exceeded 92% of cgroup limit $mem_max - self-terminating before kernel OOM-kill" >&2
      kill -TERM "$pid" 2>/dev/null
      sleep 2
      kill -KILL "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      exit 99
    fi
    sleep 1
  done
fi
wait "$pid"
'#
^sh -c $watchdog
log "OK: no reachable vulnerabilities"
`,
    },
  ],
});

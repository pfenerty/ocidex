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
      // govulncheck builds the whole-module SSA call graph for reachability analysis, which is
      // memory-hungry — OOMKilled at 2Gi on the full push scan. 4Gi matches semgrep's ceiling.
      computeResources: {
        limits: { cpu: "2", memory: "4Gi", "ephemeral-storage": "4Gi" },
        requests: { cpu: "500m", memory: "1Gi", "ephemeral-storage": "2Gi" },
      },
      script: nu`
${goSetup}
log "Running govulncheck ./..."
^govulncheck ./...
log "OK: no reachable vulnerabilities"
`,
    },
  ],
});

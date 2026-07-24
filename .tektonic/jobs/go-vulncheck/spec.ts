import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { govulncheckImage, goEnv, goCache, reportOnlyStatusReporter } from "../../shared";

// Reachability-aware Go vuln scan. Unlike grype-on-SBOM (jobs/go-security), govulncheck
// resolves the MVS-selected module versions and walks the call graph to report only vulns
// actually reachable from ocidex's code — no phantom-version noise, far fewer false
// positives. Go-only + needs the toolchain, so it's its own task rather than a step in the
// fast syft/grype task. Report-only: the reporter posts govulncheck's exit code (non-zero
// = reachable vulns) as this task's GitHub check while the PipelineRun stays green.
export const goVulncheck = new Task({
  name: "go-vulncheck",
  statusReporter: reportOnlyStatusReporter,
  caches: [goCache],
  stepTemplate: {
    env: goEnv,
  },
  steps: [
    {
      name: "govulncheck",
      image: govulncheckImage,
      computeResources: {
        limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
        requests: { cpu: "500m", memory: "1Gi", "ephemeral-storage": "2Gi" },
      },
      script: scriptFromFile(path.join(__dirname, "scan.nu")),
    },
  ],
});

import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { goImage, goCache, goEnv, statusReporter } from "../../shared";

// Go SAST + dependency-vuln scan: govulncheck (known CVEs in deps/stdlib) + gosec
// (static analysis). Report-only — `onError: continue` keeps the PipelineRun green;
// the statusReporter still posts the real exit code as this task's own GitHub check,
// so findings surface as a red check + logs without blocking. Reuses the Go module
// cache so `go run <tool>@latest` stays fast on reruns.
export const goSecurity = new Task({
  name: "go-security",
  caches: [goCache],
  statusReporter,
  stepTemplate: {
    env: goEnv,
  },
  steps: [
    {
      name: "scan",
      image: goImage,
      computeResources: {
        limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
        requests: { cpu: "500m", memory: "1Gi", "ephemeral-storage": "2Gi" },
      },
      script: scriptFromFile(path.join(__dirname, "scan.sh")),
      onError: "continue",
    },
  ],
});

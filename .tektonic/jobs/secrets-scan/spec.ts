import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { reportOnlyStatusReporter } from "../../shared";

// Secrets detection with gitleaks. Runs unconditionally (secrets can land in any
// file, and the scan is cheap) — no change-gate. Report-only: `onError: continue`
// keeps the PipelineRun green while the reportOnlyStatusReporter posts findings as
// this task's own GitHub check. Docker Hub image (cluster ghcr auth only covers
// pfenerty/*, so third-party ghcr images 403).
export const secretsScan = new Task({
  name: "secrets-scan",
  statusReporter: reportOnlyStatusReporter,
  steps: [
    {
      name: "gitleaks",
      image: "zricethezav/gitleaks:latest",
      computeResources: {
        limits: { cpu: "1", memory: "512Mi" },
        requests: { cpu: "100m", memory: "128Mi" },
      },
      script: scriptFromFile(path.join(__dirname, "scan.sh")),
      onError: "continue",
    },
  ],
});

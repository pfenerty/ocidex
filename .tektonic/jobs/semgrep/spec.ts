import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { statusReporter } from "../../shared";

// Multi-language SAST with Semgrep (Go + TypeScript frontend + generic secrets
// rulesets). Report-only: `onError: continue` keeps the PipelineRun green while the
// statusReporter posts findings as this task's own GitHub check. Docker Hub image.
export const semgrep = new Task({
  name: "semgrep",
  statusReporter,
  steps: [
    {
      name: "semgrep",
      image: "semgrep/semgrep:latest",
      // Runs as uid 1024 with no home dir, so $HOME defaults to `/` and semgrep
      // can't create its ~/.semgrep settings/log dir. Point HOME at world-writable /tmp.
      env: [{ name: "HOME", value: "/tmp" }],
      computeResources: {
        limits: { cpu: "2", memory: "2Gi" },
        requests: { cpu: "500m", memory: "1Gi" },
      },
      script: scriptFromFile(path.join(__dirname, "scan.sh")),
      onError: "continue",
    },
  ],
});

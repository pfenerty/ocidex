import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { kyvernoImage, statusReporter } from "../../shared";

// Nothing rendered the Helm charts before this task, so chart defects reached the live
// cluster: ocidex-1d9 shipped PodSecurity `restricted` violations (caught only by a manual
// server-side dry-run), and ocidex-gsip gave scanner-worker a read-only root with no
// writable /tmp, breaking every image scan for six days.
//
// Blocking, not report-only (same posture as tekton-check): the check is seconds of work,
// it is green against the charts as they stand today, and its whole value is failing the
// moment that stops being true. The driver script ends with a negative control — it renders
// the chart with the security contexts stripped and fails if the policies *accept* that —
// so a green run here is also evidence the policies still bite (ocidex-9yq4).
export const helmCheck = new Task({
  name: "helm-check",
  statusReporter,
  steps: [
    {
      name: "lint-and-validate",
      image: kyvernoImage,
      workingDir: "$(workspaces.workspace.path)",
      computeResources: {
        limits: { cpu: "1", memory: "1Gi" },
        requests: { cpu: "200m", memory: "256Mi" },
      },
      script: scriptFromFile(path.join(__dirname, "run.sh")),
    },
  ],
});

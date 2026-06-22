import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { goImage, nodeImage, goEnv, nodeEnv, statusReporter } from "../../shared";
import { goBuild } from "../go-build/spec";
import { frontendLint } from "../frontend-lint/spec";

export const openapiCheck = new Task({
  name: "openapi-check",
  needs: [goBuild, frontendLint],
  statusReporter,
  stepTemplate: {
    env: [...goEnv, ...nodeEnv],
  },
  steps: [
    {
      name: "check-spec",
      image: goImage,
      script: scriptFromFile(path.join(__dirname, "check-spec.nu")),
      onError: "continue",
    },
    {
      name: "check-types",
      image: nodeImage,
      workingDir: "$(workspaces.workspace.path)/web",
      computeResources: {
        limits: { cpu: "2", memory: "3Gi" },
        requests: { cpu: "100m", memory: "2Gi" },
      },
      // No manual prev-exit-code handling: synth's exit-code contract keeps the
      // worst code across both steps of this task automatically, so a check-spec
      // failure already propagates to the reporter even if check-types passes.
      script: scriptFromFile(path.join(__dirname, "check-types.nu")),
      onError: "continue",
    },
  ],
});
